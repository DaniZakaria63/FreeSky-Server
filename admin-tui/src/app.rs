use std::collections::VecDeque;
use std::time::Instant;

use crate::api::AdminApi;
use crate::db::{AdminDb, CommunityInfo, DeviceInfo, ReportRow, Stats};

const LOG_LINES: usize = 100;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Mode {
    Dashboard,
    SearchUser,
    UserDetail,
}

pub(crate) struct App {
    pub db: AdminDb,
    pub api: AdminApi,
    pub stats: Stats,
    pub reports: Vec<ReportRow>,
    pub community: CommunityInfo,
    pub devices: Vec<DeviceInfo>,
    pub logs: VecDeque<String>,
    pub last_refresh: Instant,
    pub running: bool,
    pub selected_report: Option<usize>,
    pub selected_device: Option<usize>,
    pub mode: Mode,
    pub search_query: String,
    pub server_connected: bool,
    pub device_detail: Option<DeviceInfo>,
}

impl App {
    pub fn new(db_path: &str, app_key: String) -> anyhow::Result<Self> {
        let db = AdminDb::open(db_path)
            .map_err(|e| anyhow::anyhow!("failed to open DB at {}: {}", db_path, e))?;
        let api = AdminApi::new(app_key);
        let stats = db.stats().unwrap_or(Stats {
            total_users: 0,
            active_users: 0,
            banned_users: 0,
            total_posts: 0,
            today_posts: 0,
            total_reports: 0,
            unresolved_reports: 0,
        });
        let reports = db.reports().unwrap_or_default();
        let community = db.community_info().unwrap_or(CommunityInfo {
            member_count: 0,
            created_at: 0,
            has_group_key: false,
        });
        let mut logs = VecDeque::new();
        logs.push_back(format!(
            "[ok] Connected to {} ({} users, {} posts)",
            db_path, stats.total_users, stats.total_posts
        ));

        let server_connected = api.health().is_ok();
        logs.push_back(if server_connected {
            "[ok] Admin API reachable at 127.0.0.1:3001".to_string()
        } else {
            "[err] Admin API unreachable - key-rotate/kick disabled".to_string()
        });

        Ok(Self {
            db,
            api,
            stats,
            reports,
            community,
            devices: Vec::new(),
            logs,
            last_refresh: Instant::now(),
            running: true,
            selected_report: None,
            selected_device: None,
            mode: Mode::Dashboard,
            search_query: String::new(),
            server_connected,
            device_detail: None,
        })
    }

    pub fn refresh(&mut self) {
        if let Ok(stats) = self.db.stats() {
            self.stats = stats;
        }
        if let Ok(reports) = self.db.reports() {
            self.reports = reports;
        }
        if let Ok(community) = self.db.community_info() {
            self.community = community;
        }
        self.server_connected = self.api.health().is_ok();
        self.selected_report = None;
    }

    pub fn log(&mut self, msg: String) {
        self.logs.push_back(msg);
        while self.logs.len() > LOG_LINES {
            self.logs.pop_front();
        }
    }
}
