//! `guard top` (live terminal view) and `guard statusline`.

mod app;
mod calls;
pub mod data;
mod events;
mod network;
mod processes;
pub mod procs;
mod theme;
mod ui;

use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, KeyEventKind};

use crate::audit::Event;
use crate::config::{self, Config, TrustedHost};
use crate::{audit, home, pause};
use app::{Action, App};
use procs::{Monitor, Resolver};

const TAIL_EVERY: Duration = Duration::from_millis(500);
const PROCS_EVERY: Duration = Duration::from_secs(2);

/// Runs the live view until the user quits. The terminal is restored on exit and on panic.
pub fn run(theme: Option<&str>) -> anyhow::Result<()> {
    theme::init(theme);
    let path = audit::path()?;
    let now = home::now();
    let (events, end) = data::read_back(&path, now.saturating_sub(data::DAY), |e: &Event| e.ts)?;
    let mut app = App::new(events, now, !no_color(), local_offset());
    let mut tailer = data::Tailer::new(path, end);
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal, &mut app, &mut tailer);
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    tailer: &mut data::Tailer,
) -> anyhow::Result<()> {
    let mut monitor = Monitor::new();
    let mut resolver = Resolver::new();
    let hosts_file = home::dir()?.join("hosts.json");
    let mut last_tail: Option<Instant> = None;
    let mut last_procs: Option<Instant> = None;
    while !app.quit {
        if last_tail.is_none_or(|t| t.elapsed() >= TAIL_EVERY) {
            app.now = home::now();
            app.tick += 1;
            match tailer.poll() {
                Ok(new) => app.push(new),
                Err(e) => app.status = format!("Could not read the log: {e}"),
            }
            app.paused_until = pause::active(app.now);
            for (host, ips) in resolver.poll() {
                for ip in ips {
                    app.ip_hosts.insert(ip, host.clone());
                }
            }
            last_tail = Some(Instant::now());
        }
        if last_procs.is_none_or(|t| t.elapsed() >= PROCS_EVERY) {
            app.snap = monitor.refresh();
            app.first_seen = data::load_first_seen(&hosts_file);
            app.config = config::load().config;
            let since = app.now.saturating_sub(data::HOUR);
            for e in app.events().iter().rev().take_while(|e| e.ts >= since) {
                for h in data::hosts_of(e) {
                    resolver.ask(&h);
                }
            }
            last_procs = Some(Instant::now());
        }
        terminal.draw(|f| ui::draw(f, app))?;
        if event::poll(Duration::from_millis(200))?
            && let event::Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
            && let Some(action) = app.on_key(k)
        {
            apply(action, app, &monitor);
        }
    }
    Ok(())
}

/// Runs a side effect asked for by a key, and reports the outcome in the footer.
fn apply(action: Action, app: &mut App, monitor: &Monitor) {
    let mut config = config::load().config;
    let (saved, done) = match action {
        Action::Kill(pid) => {
            app.status = if monitor.kill(pid) {
                format!("Asked pid {pid} to stop.")
            } else {
                format!("Could not stop pid {pid}.")
            };
            return;
        }
        Action::Trust(host) => {
            trust(&mut config, &host);
            (config.save(), format!("Whitelisted {host}."))
        }
        Action::Block(host) => {
            block(&mut config, &host);
            (config.save(), format!("Blocked {host}."))
        }
    };
    app.status = match saved {
        Ok(()) => done,
        Err(e) => format!("Could not save the config: {e}"),
    };
    app.config = config;
}

/// Trusts `host` for every agent, forever (like `guard trust add <host>`).
fn trust(c: &mut Config, host: &str) {
    c.trust.hosts.retain(|t| t.host != host);
    c.trust.hosts.push(TrustedHost {
        host: host.to_string(),
        agent: None,
        process: None,
        expires_at: None,
    });
}

/// Blocks `host` (like `guard trust block <host>`).
fn block(c: &mut Config, host: &str) {
    if !c.trust.blocked.iter().any(|b| b == host) {
        c.trust.blocked.push(host.to_string());
    }
}

/// The local zone offset from `date +%z`, or UTC when it cannot be read.
fn local_offset() -> i64 {
    std::process::Command::new("date")
        .arg("+%z")
        .output()
        .ok()
        .and_then(|o| data::parse_offset(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or(0)
}

/// Whether colors are off (`NO_COLOR` set to anything non-empty).
pub fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_and_block_do_not_duplicate() {
        let mut c = Config::default();
        trust(&mut c, "paste.ee");
        trust(&mut c, "paste.ee");
        block(&mut c, "1.2.3.4");
        block(&mut c, "1.2.3.4");
        assert_eq!(c.trust.hosts.len(), 1);
        assert!(c.host_trusted("paste.ee", Some("claude"), None, 0));
        assert_eq!(c.trust.blocked, ["1.2.3.4"]);
        assert!(c.host_blocked("1.2.3.4"));
    }
}
