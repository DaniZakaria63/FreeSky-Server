use anyhow::Result;
use std::time::Duration;

const ADMIN_API_BASE: &str = "http://127.0.0.1:3001";

pub(crate) struct AdminApi {
    client: reqwest::blocking::Client,
    app_key: String,
}

impl AdminApi {
    pub fn new(app_key: String) -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            app_key,
        }
    }

    pub fn health(&self) -> Result<String> {
        let resp = self
            .client
            .get(format!("{}/admin/health", ADMIN_API_BASE))
            .header("X-App-Key", &self.app_key)
            .send()?;
        let body: serde_json::Value = resp.json()?;
        Ok(body.to_string())
    }

    pub fn key_rotate(&self) -> Result<String> {
        let resp = self
            .client
            .post(format!("{}/admin/key-rotate", ADMIN_API_BASE))
            .header("X-App-Key", &self.app_key)
            .send()?;
        let body: serde_json::Value = resp.json()?;
        Ok(body.to_string())
    }

    pub fn kick_member(&self, pk_hex: &str) -> Result<String> {
        let resp = self
            .client
            .post(format!("{}/admin/kick/{}", ADMIN_API_BASE, pk_hex))
            .header("X-App-Key", &self.app_key)
            .send()?;
        let body: serde_json::Value = resp.json()?;
        Ok(body.to_string())
    }
}
