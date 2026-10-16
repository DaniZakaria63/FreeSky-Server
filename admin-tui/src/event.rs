use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use std::time::Duration;

use crate::app::{App, Mode};

pub fn handle_event(app: &mut App) -> Result<()> {
    if !event::poll(Duration::from_millis(200))? {
        return Ok(());
    }

    if let Event::Key(key) = event::read()? {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }

        match app.mode {
            Mode::Dashboard => match key.code {
                KeyCode::Char('q') | KeyCode::Char('Q') => {
                    app.running = false;
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    app.refresh();
                    app.log("↻ Refreshed".to_string());
                }
                KeyCode::Char('1') => {
                    app.mode = Mode::SearchUser;
                    app.search_query.clear();
                    app.devices.clear();
                    app.selected_device = None;
                }
                KeyCode::Char('2') => {
                    if let Some(idx) = app.selected_device {
                        if idx < app.devices.len() {
                            let device = &app.devices[idx];
                            let pk_hex = device.pk_hex.clone();
                            let name = device.user_name.clone();
                            let was_banned = device.banned_at.is_some();
                            let short = short_pk(&pk_hex);

                            let result = if was_banned {
                                app.api.unban(&pk_hex)
                            } else {
                                app.api.ban(&pk_hex)
                            };
                            match result {
                                Ok(_) if was_banned => {
                                    app.log(format!("[ok] Unbanned {name} ({short})"));
                                }
                                Ok(_) => {
                                    app.log(format!("[ok] Banned {name} ({short})"));
                                }
                                Err(e) => {
                                    app.log(format!("[err] Ban/unban failed: {e}"));
                                }
                            }
                            app.refresh();
                        }
                    } else {
                        app.log("! No user selected — use [1] to search first".to_string());
                    }
                }
                KeyCode::Char('3') => {
                    if app.server_connected {
                        match app.api.key_rotate() {
                            Ok(result) => {
                                app.log(format!(
                                    "[ok] Key rotated: {} devices updated",
                                    result.devices_updated
                                ));
                                app.refresh();
                            }
                            Err(e) => app.log(format!("[err] Key rotate failed: {e}")),
                        }
                    } else {
                        app.log("! Admin API unreachable".to_string());
                    }
                }
                KeyCode::Char('4') => {
                    if let Some(idx) = app.selected_device {
                        if idx < app.devices.len() {
                            let user_name = app.devices[idx].user_name.clone();
                            let pk_hex = app.devices[idx].pk_hex.clone();
                            match app.api.kick_member(&pk_hex) {
                                Ok(resp) => {
                                    app.log(format!("[ok] Kicked {user_name}: {resp}"));
                                    if let Err(e) = app.api.ban(&pk_hex) {
                                        app.log(format!("[err] Ban after kick failed: {e}"));
                                    }
                                    app.refresh();
                                }
                                Err(e) => app.log(format!("[err] Kick failed: {e}")),
                            }
                        }
                    } else {
                        app.log("! No user selected — use [1] to search first".to_string());
                    }
                }
                KeyCode::Char('5') => {
                    if let Some(idx) = app.selected_report {
                        if idx < app.reports.len() {
                            let report_id = app.reports[idx].id;
                            let user_name = app.reports[idx].user_name.clone();
                            match app.api.resolve_report(report_id) {
                                Ok(()) => {
                                    app.log(format!(
                                        "[ok] Resolved report #{report_id} ({user_name})"
                                    ));
                                }
                                Err(e) => {
                                    app.log(format!("[err] Resolve report failed: {e}"));
                                }
                            }
                            app.refresh();
                        }
                    } else {
                        app.log("! No report selected — use ↑↓ to select".to_string());
                    }
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if let Some(idx) = &mut app.selected_report {
                        if *idx > 0 {
                            *idx -= 1;
                        }
                    } else if !app.reports.is_empty() {
                        app.selected_report = Some(0);
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if let Some(idx) = &mut app.selected_report {
                        if *idx + 1 < app.reports.len() {
                            *idx += 1;
                        }
                    } else if !app.reports.is_empty() {
                        app.selected_report = Some(0);
                    }
                }
                KeyCode::Tab => {
                    app.mode = Mode::SearchUser;
                    app.search_query.clear();
                    app.devices.clear();
                }
                _ => {}
            },
            Mode::SearchUser => match key.code {
                KeyCode::Esc => {
                    app.mode = Mode::Dashboard;
                }
                KeyCode::Enter => {
                    if app.devices.is_empty() {
                        match app.api.search_devices(&app.search_query) {
                            Ok(results) => {
                                app.devices = results;
                                if app.devices.is_empty() {
                                    app.log("! No users found".to_string());
                                }
                            }
                            Err(e) => {
                                app.log(format!("[err] Search failed: {e}"));
                            }
                        }
                        app.selected_device = None;
                    } else if let Some(idx) = app.selected_device
                        && idx < app.devices.len()
                    {
                        app.device_detail = Some(app.devices[idx].clone());
                        app.mode = Mode::UserDetail;
                    }
                }
                KeyCode::Backspace => {
                    app.search_query.pop();
                }
                KeyCode::Char(c) => {
                    app.search_query.push(c);
                }
                KeyCode::Up => {
                    if let Some(idx) = &mut app.selected_device {
                        if *idx > 0 {
                            *idx -= 1;
                        }
                    } else if !app.devices.is_empty() {
                        app.selected_device = Some(0);
                    }
                }
                KeyCode::Down => {
                    if let Some(idx) = &mut app.selected_device {
                        if *idx + 1 < app.devices.len() {
                            *idx += 1;
                        }
                    } else if !app.devices.is_empty() {
                        app.selected_device = Some(0);
                    }
                }
                _ => {}
            },
            Mode::UserDetail => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    app.mode = Mode::SearchUser;
                    app.device_detail = None;
                }
                KeyCode::Char('b') => {
                    if let Some(device) = app.device_detail.clone() {
                        let result = if device.banned_at.is_some() {
                            app.api.unban(&device.pk_hex)
                        } else {
                            app.api.ban(&device.pk_hex)
                        };
                        match result {
                            Ok(_) if device.banned_at.is_some() => {
                                app.log(format!("[ok] Unbanned {}", device.user_name));
                            }
                            Ok(_) => {
                                app.log(format!("[ok] Banned {}", device.user_name));
                            }
                            Err(e) => {
                                app.log(format!("[err] Ban/unban failed: {e}"));
                            }
                        }
                        app.refresh();
                        if let Some(idx) = app.selected_device
                            && let Some(updated) = app.devices.get(idx)
                        {
                            app.device_detail = Some(updated.clone());
                        }
                    }
                }
                _ => {}
            },
        }
    }
    Ok(())
}

/// First 12 hex chars of a `pk_dev` (6 bytes) for compact log lines.
fn short_pk(pk_hex: &str) -> &str {
    &pk_hex[..pk_hex.len().min(12)]
}
