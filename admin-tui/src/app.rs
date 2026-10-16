use std::collections::VecDeque;
use std::time::Instant;

use freesky_shared::types::{AdminCommunity, AdminDevice, AdminReportRow, AdminStats};

use crate::api::AdminApi;

const LOG_LINES: usize = 100;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Mode {
    Dashboard,
    SearchUser,
    UserDetail,
}

pub(crate) struct App {
    pub api: AdminApi,
    pub stats: AdminStats,
    pub reports: Vec<AdminReportRow>,
    pub community: AdminCommunity,
    pub devices: Vec<AdminDevice>,
    pub logs: VecDeque<String>,
    pub last_refresh: Instant,
    pub running: bool,
    pub selected_report: Option<usize>,
    pub selected_device: Option<usize>,
    pub mode: Mode,
    pub search_query: String,
    pub server_connected: bool,
    pub device_detail: Option<AdminDevice>,
}

impl App {
    pub fn new(api: AdminApi) -> Self {
        let mut app = Self {
            api,
            stats: empty_stats(),
            reports: Vec::new(),
            community: empty_community(),
            devices: Vec::new(),
            logs: VecDeque::new(),
            last_refresh: Instant::now(),
            running: true,
            selected_report: None,
            selected_device: None,
            mode: Mode::Dashboard,
            search_query: String::new(),
            server_connected: false,
            device_detail: None,
        };

        match app.api.stats() {
            Ok(stats) => {
                app.stats = stats;
                app.server_connected = true;
                app.log(format!(
                    "[ok] Connected to admin API at {}",
                    app.api.base_url()
                ));
                if let Ok(reports) = app.api.reports() {
                    app.reports = reports;
                }
                if let Ok(community) = app.api.community() {
                    app.community = community;
                }
            }
            Err(e) => {
                app.log(format!(
                    "[err] Admin API unreachable at {}",
                    app.api.base_url()
                ));
                app.log(format!("[err] {e}"));
            }
        }

        app
    }

    pub fn refresh(&mut self) {
        let was_connected = self.server_connected;
        match self.api.stats() {
            Ok(stats) => {
                self.stats = stats;
                if let Ok(reports) = self.api.reports() {
                    self.reports = reports;
                }
                if let Ok(community) = self.api.community() {
                    self.community = community;
                }
                if !was_connected {
                    self.log(format!(
                        "[ok] Admin API reconnected at {}",
                        self.api.base_url()
                    ));
                }
                self.server_connected = true;
            }
            Err(e) => {
                if was_connected {
                    self.log(format!("[err] Admin API unreachable: {e}"));
                }
                self.server_connected = false;
            }
        }
        self.selected_report = None;
    }

    pub fn log(&mut self, msg: String) {
        self.logs.push_back(msg);
        while self.logs.len() > LOG_LINES {
            self.logs.pop_front();
        }
    }
}

fn empty_stats() -> AdminStats {
    AdminStats {
        total_users: 0,
        active_users: 0,
        banned_users: 0,
        total_posts: 0,
        today_posts: 0,
        total_reports: 0,
        unresolved_reports: 0,
    }
}

fn empty_community() -> AdminCommunity {
    AdminCommunity {
        member_count: 0,
        created_at: 0,
        has_group_key: false,
    }
}
