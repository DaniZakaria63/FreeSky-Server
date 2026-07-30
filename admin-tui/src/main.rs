mod api;
mod app;
mod db;
mod event;
mod ui;

use anyhow::Result;
use ratatui::backend::CrosstermBackend;
use std::io;
use std::time::Duration;

use crate::app::App;

/// Parse and validate the APK signing key SHA-1 from CLI arg or env var.
fn load_app_key() -> Result<String> {
    let raw = std::env::args()
        .position(|a| a == "--app-key")
        .and_then(|pos| std::env::args().nth(pos + 1))
        .or_else(|| std::env::var("APP_KEY").ok())
        .ok_or_else(|| anyhow::anyhow!(
            "missing app key\n  usage: {} --app-key <SHA1>\n  or set APP_KEY env var",
            std::env::args().next().as_deref().unwrap_or("admin-tui")
        ))?;

    let normalized = raw.trim().to_uppercase().replace(':', "");
    if normalized.len() != 40 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("invalid app key: expected 40 hex chars (SHA-1), got {raw:?}");
    }
    Ok(normalized)
}

/// Resolve database path from TURSO_URL env or default to community.db.
fn resolve_db_path() -> String {
    std::env::var("TURSO_URL")
        .ok()
        .and_then(|url| {
            if url.starts_with("file://") {
                Some(url[7..].to_string())
            } else if !url.contains("://") {
                Some(url)
            } else {
                None
            }
        })
        .unwrap_or_else(|| "community.db".to_string())
}

fn main() -> Result<()> {
    let app_key = load_app_key()?;
    let db_path = resolve_db_path();

    let mut app = App::new(&db_path, app_key)?;

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
