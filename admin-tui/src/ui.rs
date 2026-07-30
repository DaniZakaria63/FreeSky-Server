use chrono::{DateTime, Utc};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::app::{App, Mode};

const COLORS: [Color; 16] = [
    Color::Red,
    Color::Green,
    Color::Yellow,
    Color::Blue,
    Color::Magenta,
    Color::Cyan,
    Color::White,
    Color::LightRed,
    Color::LightGreen,
    Color::LightYellow,
    Color::LightBlue,
    Color::LightMagenta,
    Color::LightCyan,
    Color::Gray,
    Color::DarkGray,
    Color::Reset,
];

fn format_ts(ts: i64) -> String {
    let dt = DateTime::from_timestamp(ts, 0).unwrap();
    let now = Utc::now();
    let dur = now - dt;
    if dur.num_minutes() < 60 {
        format!("{}m ago", dur.num_minutes())
    } else if dur.num_hours() < 24 {
        format!("{}h ago", dur.num_hours())
    } else if dur.num_days() < 7 {
        format!("{}d ago", dur.num_days())
    } else {
        dt.format("%Y-%m-%d").to_string()
    }
}

pub fn render(app: &mut App, frame: &mut Frame) {
    let area = frame.area();

    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(7),
            Constraint::Min(10),
            Constraint::Length(4),
            Constraint::Length(3),
        ])
        .split(area);

    render_header(app, frame, main_layout[0]);
    render_stats(app, frame, main_layout[1]);

    match app.mode {
        Mode::Dashboard | Mode::SearchUser => {
            render_main_panels(app, frame, main_layout[2]);
        }
        Mode::UserDetail => {
            render_user_detail(app, frame, main_layout[2]);
        }
    }

    render_actions(frame, main_layout[3]);
    render_log(app, frame, main_layout[4]);
}

fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let connected = if app.server_connected {
        Span::styled("● connected", Style::new().green())
    } else {
        Span::styled("● disconnected", Style::new().red())
    };
    let text = Line::from(vec![
        Span::styled(" FreeSky Admin ", Style::new().bold()),
        Span::raw("  "),
        connected,
        Span::raw("  "),
        Span::styled("Q:quit", Style::new().dim()),
        Span::raw("  "),
        Span::styled("R:refresh", Style::new().dim()),
        Span::raw("  "),
        Span::styled("1:user", Style::new().dim()),
    ]);
    frame.render_widget(Paragraph::new(text), area);
}

fn render_stats(app: &App, frame: &mut Frame, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ])
        .split(area);

    let s = &app.stats;
    render_stat_box(
        frame,
        layout[0],
        "Users",
        &[
            format!("Total users:  {}", s.total_users),
            format!("Active users: {}", s.active_users),
            format!("Banned users: {}", s.banned_users),
        ],
        Color::Cyan,
    );

    render_stat_box(
        frame,
        layout[1],
        "Posts",
        &[
            format!("Total posts: {}", s.total_posts),
            format!("Posts today: {}", s.today_posts),
            String::new(),
        ],
        Color::Green,
    );

    render_stat_box(
        frame,
        layout[2],
        "Reports",
        &[
            format!("Total reports:     {}", s.total_reports),
            format!("Unresolved reports: {}", s.unresolved_reports),
            String::new(),
        ],
        Color::Yellow,
    );
}

fn render_stat_box(frame: &mut Frame, area: Rect, title: &str, lines: &[String], color: Color) {
    let inner = area.inner(Margin::new(1, 0));
    let text = Text::from(
        lines
            .iter()
            .map(|l| Line::from(Span::raw(l.as_str())))
            .collect::<Vec<_>>(),
    );
    let block = Block::default()
        .title(title)
        .title_style(Style::new().fg(color).bold())
        .borders(Borders::ALL);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(text), inner);
}

fn render_main_panels(app: &App, frame: &mut Frame, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(3, 5), Constraint::Ratio(2, 5)])
        .split(area);

    render_reports_panel(app, frame, layout[0]);
    render_community_panel(app, frame, layout[1]);
}

fn render_reports_panel(app: &App, frame: &mut Frame, area: Rect) {
    let items: Vec<ListItem> = app
        .reports
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let prefix = if Some(i) == app.selected_report {
                " ▸ "
            } else {
                "   "
            };
            let reason = r.reason.as_deref().unwrap_or("no reason");
            ListItem::new(format!(
                "{}{}  {}  {}",
                prefix,
                r.user_name,
                reason,
                format_ts(r.reported_at)
            ))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Unresolved Reports ")
                .title_style(Style::new().fg(Color::Yellow).bold())
                .borders(Borders::ALL),
        )
        .highlight_style(Style::new().bg(Color::DarkGray));

    frame.render_widget(list, area);
}

fn render_community_panel(app: &App, frame: &mut Frame, area: Rect) {
    let c = &app.community;
    let key_status = if c.has_group_key {
        "[ok] Key exists"
    } else {
        "[err] No key — run [3] Key rotate"
    };
    let created = if c.created_at > 0 {
        format_ts(c.created_at)
    } else {
        "N/A".to_string()
    };

    let mut text = vec![
        Line::from(vec![Span::styled("Community Key", Style::new().bold())]),
        Line::from(vec![Span::styled(
            key_status,
            Style::new().fg(if c.has_group_key {
                Color::Green
            } else {
                Color::Red
            }),
        )]),
        Line::from(Span::raw("")),
        Line::from(Span::raw(format!("Members: {}", c.member_count))),
        Line::from(Span::raw(format!("Created: {}", created))),
    ];

    if app.mode == Mode::SearchUser {
        text.push(Line::from(Span::raw("")));
        text.push(Line::from(Span::styled(
            "── Search Users ──",
            Style::new().dim(),
        )));
        text.push(Line::from(Span::raw(format!(
            "Query: {}█",
            app.search_query
        ))));

        for (i, d) in app.devices.iter().enumerate() {
            let cursor = if Some(i) == app.selected_device {
                "▸ "
            } else {
                "  "
            };
            let status = if d.banned_at.is_some() { " BANNED" } else { "" };
            text.push(Line::from(Span::raw(format!(
                "{}{}  {} posts{}",
                cursor, d.user_name, d.post_count, status
            ))));
        }
    }

    let block = Block::default()
        .title(" Community ")
        .title_style(Style::new().fg(Color::Cyan).bold())
        .borders(Borders::ALL);

    let inner = area.inner(Margin::new(1, 0));
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(Text::from(text)), inner);
}

fn render_user_detail(app: &App, frame: &mut Frame, area: Rect) {
    if let Some(ref d) = app.device_detail {
        let color_idx = d.user_color as usize % 16;
        let lines = vec![
            Line::from(vec![Span::styled("User Detail", Style::new().bold())]),
            Line::from(Span::raw("")),
            Line::from(vec![
                Span::styled("Name: ", Style::new().dim()),
                Span::styled(&d.user_name, Style::new().fg(COLORS[color_idx])),
            ]),
            Line::from(Span::raw(format!("pk_dev: {}", hex::encode(&d.pk_dev)))),
            Line::from(Span::raw(format!(
                "Registered: {}",
                format_ts(d.registered_at)
            ))),
            Line::from(Span::raw(format!(
                "Banned: {}",
                d.banned_at
                    .map(format_ts)
                    .unwrap_or_else(|| "No".to_string())
            ))),
            Line::from(Span::raw(format!(
                "Last seen: {}",
                d.last_seen_at
                    .map(format_ts)
                    .unwrap_or_else(|| "Never".to_string())
            ))),
            Line::from(Span::raw(format!("Posts: {}", d.post_count))),
            Line::from(Span::raw("")),
            Line::from(vec![
                Span::styled("B: Ban/Unban  ", Style::new().dim()),
                Span::styled("Esc: Back", Style::new().dim()),
            ]),
        ];
        let block = Block::default()
            .title(" User Detail ")
            .title_style(Style::new().fg(Color::Cyan).bold())
            .borders(Borders::ALL);
        let inner = area.inner(Margin::new(1, 0));
        frame.render_widget(block, area);
        frame.render_widget(Paragraph::new(Text::from(lines)), inner);
    } else {
        frame.render_widget(
            Paragraph::new("No user selected").block(
                Block::default()
                    .title(" User Detail ")
                    .borders(Borders::ALL),
            ),
            area,
        );
    }
}

fn render_actions(frame: &mut Frame, area: Rect) {
    let actions = vec![
        "[1] Search user  [2] Ban/Unban  [3] Key rotate  [4] Kick member",
        "[5] Resolve report  [↑↓] Select  [Tab] Search  [Q] Quit",
    ];
    let text = Text::from(
        actions
            .iter()
            .map(|l| Line::from(Span::styled(*l, Style::new().dim())))
            .collect::<Vec<_>>(),
    );
    frame.render_widget(Paragraph::new(text), area);
}

fn render_log(app: &App, frame: &mut Frame, area: Rect) {
    let log_text: Vec<Line> = app
        .logs
        .iter()
        .rev()
        .take(3)
        .rev()
        .map(|l| {
            let style = if l.starts_with("[ok]") {
                Style::new().green()
            } else if l.starts_with("[err]") || l.starts_with('!') {
                Style::new().red()
            } else {
                Style::new().dim()
            };
            Line::from(Span::styled(l.as_str(), style))
        })
        .collect();

    let block = Block::default()
        .title(" Log ")
        .title_style(Style::new().dim())
        .borders(Borders::ALL);

    let inner = area.inner(Margin::new(1, 0));
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(Text::from(log_text)), inner);
}
