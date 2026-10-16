mod api;
mod app;
mod event;
mod ui;

use anyhow::Result;
use ratatui::backend::CrosstermBackend;
use std::io;
use std::time::Duration;

use crate::api::{AdminApi, AdminConfig, CfAccessToken};
use crate::app::App;

/// Parse and validate the APK signing key SHA-1 from CLI arg or env var.
fn load_app_key() -> Result<String> {
    let raw = std::env::args()
        .position(|a| a == "--app-key")
        .and_then(|pos| std::env::args().nth(pos + 1))
        .or_else(|| std::env::var("APP_KEY").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing app key\n  usage: {} --app-key <SHA1> [--api-base <URL>]\n  env:   APP_KEY, ADMIN_API_BASE, CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET",
                std::env::args().next().as_deref().unwrap_or("admin-tui")
            )
        })?;

    let normalized = raw.trim().to_uppercase().replace(':', "");
    if normalized.len() != 40 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("invalid app key: expected 40 hex chars (SHA-1), got {raw:?}");
    }
    Ok(normalized)
}

/// Resolve the admin API base URL from `--api-base` or `ADMIN_API_BASE`.
///
/// Defaults to localhost (server and TUI on the same machine). For a remote
/// server behind the Cloudflare Tunnel, set e.g.
/// `ADMIN_API_BASE=https://admin.example.com`.
fn load_api_base() -> String {
    std::env::args()
        .position(|a| a == "--api-base")
        .and_then(|pos| std::env::args().nth(pos + 1))
        .or_else(|| std::env::var("ADMIN_API_BASE").ok())
        .unwrap_or_else(|| "http://127.0.0.1:3001".to_string())
        .trim()
        .trim_end_matches('/')
        .to_string()
}

/// Load the Cloudflare Access service token from the environment.
///
/// Both halves are required together; a lone half is almost certainly a
/// misconfiguration and would surface later as an opaque 302 from Access.
fn load_cf_access() -> Result<Option<CfAccessToken>> {
    let client_id = std::env::var("CF_ACCESS_CLIENT_ID")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let client_secret = std::env::var("CF_ACCESS_CLIENT_SECRET")
        .ok()
        .filter(|v| !v.trim().is_empty());

    match (client_id, client_secret) {
        (Some(client_id), Some(client_secret)) => Ok(Some(CfAccessToken {
            client_id,
            client_secret,
        })),
        (None, None) => Ok(None),
        _ => anyhow::bail!(
            "CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET must be set together \
             (create a service token in the Zero Trust dashboard)"
        ),
    }
}

fn main() -> Result<()> {
    let config = AdminConfig {
        base_url: load_api_base(),
        app_key: load_app_key()?,
        cf_access: load_cf_access()?,
    };
    let api = AdminApi::new(config)?;
    let mut app = App::new(api);

    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;
    terminal.clear()?;

    while app.running {
        if app.last_refresh.elapsed() >= Duration::from_secs(5) {
            app.refresh();
            app.last_refresh = std::time::Instant::now();
        }

        terminal.draw(|f| ui::render(&mut app, f))?;
        event::handle_event(&mut app)?;
    }

    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(io::stdout(), crossterm::terminal::LeaveAlternateScreen)?;
    terminal.clear()?;
    println!("Goodbye.");
    Ok(())
}
