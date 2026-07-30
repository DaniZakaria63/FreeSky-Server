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
                            if device.banned_at.is_some() {
                                if let Err(e) = app.db.unban_user(&device.pk_dev) {
                                    app.log(format!("[err] Unban failed: {e}"));
                                } else {
                                    app.log(format!(
                                        "[ok] Unbanned {} ({})",
                                        device.user_name,
                                        hex::encode(&device.pk_dev[..6])
                                    ));
                                }
                            } else {
                                if let Err(e) = app.db.ban_user(&device.pk_dev) {
                                    app.log(format!("[err] Ban failed: {e}"));
                                } else {
                                    app.log(format!(
                                        "[ok] Banned {} ({})",
                                        device.user_name,
                                        hex::encode(&device.pk_dev[..6])
                                    ));
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
                            Ok(resp) => {
                                app.log(format!("[ok] Key rotate: {resp}"));
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
                            let pk = app.devices[idx].pk_dev.clone();
                            let pk_hex = hex::encode(&pk);
                            match app.api.kick_member(&pk_hex) {
                                Ok(resp) => {
                                    app.log(format!("[ok] Kicked {}: {resp}", user_name));
                                    app.db.ban_user(&pk).ok();
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
                            let report = &app.reports[idx];
                            if let Err(e) = app.db.resolve_report(report.id, "resolved") {
                                app.log(format!("[err] Resolve report failed: {e}"));
                            } else {
                                app.log(format!(
                                    "[ok] Resolved report #{} ({})",
                                    report.id, report.user_name
                                ));
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
                        let results = app.db.search_devices(&app.search_query).unwrap_or_default();
                        app.devices = results;
                        app.selected_device = None;
                        if app.devices.is_empty() {
                            app.log("! No users found".to_string());
                        }
                    } else if let Some(idx) = app.selected_device {
                        if idx < app.devices.len() {
                            app.device_detail = Some(app.devices[idx].clone());
                            app.mode = Mode::UserDetail;
                        }
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
                    if let Some(ref device) = app.device_detail.clone() {
                        if device.banned_at.is_some() {
                            app.db.unban_user(&device.pk_dev).ok();
                            app.log(format!("[ok] Unbanned {}", device.user_name));
                        } else {
                            app.db.ban_user(&device.pk_dev).ok();
                            app.log(format!("[ok] Banned {}", device.user_name));
                        }
                        app.refresh();
                        app.device_detail =
                            Some(app.devices[app.selected_device.unwrap_or(0)].clone());
                    }
                }
                _ => {}
            },
        }
    }
    Ok(())
}
