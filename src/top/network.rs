//! The Network tab: remote hosts, grouped.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Row, Table, TableState};

use crate::top::app::App;
use crate::top::data;
use crate::top::ui::selected_style;

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    let hosts = app.hosts();
    let rows = hosts.iter().map(|h| {
        let mut flags = Vec::new();
        if h.new {
            flags.push("new host");
        }
        if h.raw_ip {
            flags.push("raw IP");
        }
        if app.config.host_blocked(&h.host) {
            flags.push("blocked");
        } else if app.config.host_trusted(&h.host, None, None, app.now) {
            flags.push("trusted");
        }
        let bytes = if h.bytes_out + h.bytes_in > 0 {
            format!(
                "{} out, {} in",
                data::human_bytes(h.bytes_out),
                data::human_bytes(h.bytes_in)
            )
        } else {
            String::new()
        };
        Row::new(vec![
            h.host.clone(),
            h.first_seen
                .map(|t| format!("{} ago", data::ago(t, app.now)))
                .unwrap_or_default(),
            h.who.iter().cloned().collect::<Vec<_>>().join(", "),
            h.requests.to_string(),
            h.conns.to_string(),
            bytes,
            flags.join(", "),
        ])
    });
    let widths = [
        Constraint::Fill(2),
        Constraint::Length(10),
        Constraint::Fill(1),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(20),
        Constraint::Length(18),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new([
                "host",
                "first seen",
                "who",
                "requests",
                "conns",
                "bytes",
                "flags",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(selected_style(app.color))
        .block(crate::top::ui::panel(app.color, true, " Network "));
    let mut state = TableState::default().with_selected(Some(app.selected(hosts.len())));
    f.render_stateful_widget(table, area, &mut state);
}
