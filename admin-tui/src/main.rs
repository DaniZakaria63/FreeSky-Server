mod api;
mod app;
mod event;
mod ui;

use anyhow::Result;
use ratatui::backend::CrosstermBackend;
use std::io;
use std::time::Duration;

use crate::api::{AdminApi, AdminConfig};
use crate::app::App;

/// Parse and validate the APK signing key SHA-1 from CLI arg or env var.
fn load_app_key() -> Result<String> {
    let raw = std::env::args()
        .position(|a| a == "--app-key")
        .and_then(|pos| std::env::args().nth(pos + 1))
        .or_else(|| std::env::var("APP_KEY").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing app key\n  usage: {} --app-key <SHA1> [--api-base <URL>]\n  env:   APP_KEY, ADMIN_API_BASE",
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
/// Defaults to localhost, which is where the admin API lives: the TUI runs on
/// the server itself and the API is never published anywhere.
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

fn main() -> Result<()> {
    let config = AdminConfig {
        base_url: load_api_base(),
        app_key: load_app_key()?,
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
