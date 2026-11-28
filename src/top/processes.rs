//! The Agents tab: the tree of agent processes, with a CPU activity bar refreshed every 2 s.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Row, Table, TableState};

use crate::text::term_safe;
use crate::top::app::App;
use crate::top::calls;
use crate::top::ui::selected_style;

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    let rows = app.snap.rows.iter().map(|r| {
        let indent = if r.depth == 0 {
            String::new()
        } else {
            format!("{}└ ", "  ".repeat(r.depth - 1))
        };
        let remote = r
            .last_remote
            .map(|a| format!("{}:{}", app.host_of(a.ip()), a.port()))
            .unwrap_or_default();
        Row::new(vec![
            r.proc.pid.to_string(),
            format!("{indent}{}", term_safe(&r.proc.name)),
            format!("{:.1}", r.proc.cpu),
            calls::bar(r.proc.cpu / 100.0, 8),
            r.conns.to_string(),
            remote,
        ])
    });
    let widths = [
        Constraint::Length(8),
        Constraint::Fill(1),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Fill(1),
    ];
    let title = if app.snap.rows.is_empty() {
        " Agents: no agent running "
    } else {
        " Agents "
    };
    let table = Table::new(rows, widths)
        .header(
            Row::new(["pid", "name", "cpu%", "activity", "conns", "last remote"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(selected_style(app.color))
        .block(crate::top::ui::panel(app.color, true, title));
    let mut state = TableState::default().with_selected(Some(app.selected(app.snap.rows.len())));
    f.render_stateful_widget(table, area, &mut state);
}
