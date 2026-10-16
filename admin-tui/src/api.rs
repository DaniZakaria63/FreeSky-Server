//! Admin API client.
//!
//! The TUI runs on the admin's machine and reaches the server's admin API
//! through the Cloudflare Tunnel (Zero Trust). Every request carries
//! `X-App-Key`; when the tunnel is protected by Access, the Cloudflare
//! service-token headers are attached as well.

use anyhow::{Context, Result, bail};
use freesky_shared::types::{
    AdminBanResult, AdminCommunity, AdminDevice, AdminKeyRotate, AdminReportRow, AdminStats,
    ApiResponse,
};
use reqwest::Method;
use serde::de::DeserializeOwned;
use std::time::Duration;

/// Cloudflare Zero Trust Access service token.
pub(crate) struct CfAccessToken {
    pub client_id: String,
    pub client_secret: String,
}

/// Connection settings for the admin API.
pub(crate) struct AdminConfig {
    /// Base URL, e.g. `https://admin.example.com` (tunnel) or
    /// `http://127.0.0.1:3001` (local).
    pub base_url: String,
    /// Trusted APK signing key SHA-1, sent as `X-App-Key`.
    pub app_key: String,
    /// Service token, required when Access protects the tunnel hostname.
    pub cf_access: Option<CfAccessToken>,
}

pub(crate) struct AdminApi {
    client: reqwest::blocking::Client,
    config: AdminConfig,
}

impl AdminApi {
    pub fn new(config: AdminConfig) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            // Do not follow redirects: Cloudflare Access answers an
            // unauthenticated request with a 302 to its login page, and we
            // want to surface that clearly instead of parsing HTML.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("freesky-admin-tui/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self { client, config })
    }

    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Send a request and return the `data` field of the API envelope.
    ///
    /// Returns `Ok(None)` for endpoints whose success payload is `null`
    /// (unit responses like health/resolve).
    fn call(&self, method: Method, path: &str) -> Result<Option<serde_json::Value>> {
        let url = format!("{}{}", self.config.base_url, path);

        let mut request = self
            .client
            .request(method, &url)
            .header("X-App-Key", &self.config.app_key);
        if let Some(token) = &self.config.cf_access {
            request = request
                .header("CF-Access-Client-Id", &token.client_id)
                .header("CF-Access-Client-Secret", &token.client_secret);
        }

        let response = request
            .send()
            .with_context(|| format!("cannot reach admin API at {url}"))?;
        let status = response.status();
        let body = response.text().unwrap_or_default();

        let envelope: ApiResponse<serde_json::Value> = match serde_json::from_str(&body) {
            Ok(envelope) => envelope,
            Err(_) => {
                let hint = match status.as_u16() {
                    301 | 302 | 303 | 307 | 308 => {
                        " — blocked by Cloudflare Access? \
                         Set CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET"
                    }
                    403 => {
                        " — forbidden; if Zero Trust Access is enabled, \
                         check the service-token policy for this hostname"
                    }
                    _ => "",
                };
                bail!("HTTP {status} from {url}: not a Freesky admin API response{hint}");
            }
        };

        if envelope.message == "success" {
            Ok(envelope.data)
        } else if status.is_success() {
            bail!("{}", envelope.message)
        } else {
            bail!("{} (HTTP {status})", envelope.message)
        }
    }

    /// Like [`Self::call`], but deserializes `data` into `T`.
    fn call_json<T: DeserializeOwned>(&self, method: Method, path: &str) -> Result<T> {
        let data = self
            .call(method, path)?
            .context("malformed response: success without data")?;
        serde_json::from_value(data).context("malformed response payload")
    }

    pub fn stats(&self) -> Result<AdminStats> {
        self.call_json(Method::GET, "/admin/stats")
    }

    pub fn reports(&self) -> Result<Vec<AdminReportRow>> {
        self.call_json(Method::GET, "/admin/reports")
    }

    pub fn community(&self) -> Result<AdminCommunity> {
        self.call_json(Method::GET, "/admin/community")
    }

    pub fn search_devices(&self, query: &str) -> Result<Vec<AdminDevice>> {
        self.call_json(
            Method::GET,
            &format!("/admin/devices?q={}", urlencode(query)),
        )
    }

    pub fn ban(&self, pk_hex: &str) -> Result<AdminBanResult> {
        self.call_json(Method::POST, &format!("/admin/ban/{pk_hex}"))
    }

    pub fn unban(&self, pk_hex: &str) -> Result<AdminBanResult> {
        self.call_json(Method::POST, &format!("/admin/unban/{pk_hex}"))
    }

    pub fn key_rotate(&self) -> Result<AdminKeyRotate> {
        self.call_json(Method::POST, "/admin/key-rotate")
    }

    pub fn kick_member(&self, pk_hex: &str) -> Result<String> {
        let _ = self.call(Method::POST, &format!("/admin/kick/{pk_hex}"))?;
        Ok("kick accepted".to_string())
    }

    pub fn resolve_report(&self, report_id: i64) -> Result<()> {
        self.call(Method::POST, &format!("/admin/reports/{report_id}/resolve"))
            .map(|_| ())
    }
}

/// Percent-encode a query-string value (RFC 3986 unreserved characters kept).
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
