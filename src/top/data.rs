//! The pure data side of `guard top` and `guard statusline`: reading the log (from the end, and
//! as it grows), counting, filtering and grouping. No terminal code here.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::audit::Event;
use crate::checks::dest;
use crate::level::Level;

/// One hour, in seconds.
pub const HOUR: u64 = 3600;
/// One day, in seconds.
pub const DAY: u64 = 86_400;

/// The level an event counts as: no level is green, and a hard block counts as red.
pub fn bucket(level: Option<Level>) -> Level {
    match level {
        None | Some(Level::Green) => Level::Green,
        Some(Level::Yellow) => Level::Yellow,
        Some(Level::Red | Level::HardBlock) => Level::Red,
    }
}

/// How many events of each level.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub red: usize,
    pub yellow: usize,
    pub green: usize,
}

impl Counts {
    /// Counts one event of `level`.
    pub fn add(&mut self, level: Option<Level>) {
        match bucket(level) {
            Level::Red => self.red += 1,
            Level::Yellow => self.yellow += 1,
            _ => self.green += 1,
        }
    }
}

/// Counts the events at or after `since`.
pub fn count<'a>(events: impl IntoIterator<Item = &'a Event>, since: u64) -> Counts {
    let mut c = Counts::default();
    for e in events.into_iter().filter(|e| e.ts >= since) {
        c.add(e.level);
    }
    c
}

const CHUNK: u64 = 64 * 1024;

/// Reads the log at `path` backwards and returns the entries stamped at or after `since`, oldest
/// first, and the file length (where a [`Tailer`] should continue). It stops at the first older
/// entry, so the cost depends on the window, not on the size of the log. Unreadable lines are
/// skipped; a missing file is empty.
pub fn read_back<T: DeserializeOwned>(
    path: &Path,
    since: u64,
    ts: impl Fn(&T) -> u64,
) -> io::Result<(Vec<T>, u64)> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e),
    };
    let len = f.metadata()?.len();
    let mut out = Vec::new();
    let mut pos = len;
    // The start of a line that began before `pos`, carried to the next (earlier) chunk.
    let mut carry: Vec<u8> = Vec::new();
    'chunks: while pos > 0 {
        let start = pos.saturating_sub(CHUNK);
        let mut buf = vec![0; usize::try_from(pos - start).map_err(io::Error::other)?];
        f.seek(SeekFrom::Start(start))?;
        f.read_exact(&mut buf)?;
        buf.extend_from_slice(&carry);
        let mut parts = buf.split(|&b| b == b'\n');
        // Unless this chunk starts the file, its first piece is the tail of an earlier line.
        let head = if start > 0 { parts.next() } else { None };
        let lines: Vec<&[u8]> = parts.collect();
        for line in lines.into_iter().rev() {
            if line.is_empty() {
                continue;
            }
            if let Ok(item) = serde_json::from_slice::<T>(line) {
                if ts(&item) < since {
                    break 'chunks;
                }
                out.push(item);
            }
        }
        carry = head.unwrap_or_default().to_vec();
        pos = start;
    }
    out.reverse();
    Ok((out, len))
}

/// The two fields the status line needs; the rest of each line is skipped unparsed.
#[derive(Deserialize)]
struct Stamp {
    ts: u64,
    #[serde(default)]
    level: Option<Level>,
    #[serde(default)]
    source: String,
}

/// Counts of the calls at or after `since`, read from the end of the log. A call logs a
/// PreToolUse and a PostToolUse entry; the PostToolUse one counts only when it found something
/// (a cleaned or flagged result), so a call is counted once, as in `guard top`.
pub fn recent_counts(path: &Path, since: u64) -> io::Result<Counts> {
    let (stamps, _) = read_back(path, since, |s: &Stamp| s.ts)?;
    let mut c = Counts::default();
    for s in &stamps {
        if s.source == "PostToolUse" && bucket(s.level) == Level::Green {
            continue;
        }
        c.add(s.level);
    }
    Ok(c)
}

/// Follows the log as it grows: each [`Tailer::poll`] returns the complete lines added since the
/// last one. A truncated or replaced log is read again from the start.
pub struct Tailer {
    path: PathBuf,
    pos: u64,
    partial: Vec<u8>,
}

impl Tailer {
    /// Starts following `path` at byte offset `pos`.
    pub fn new(path: PathBuf, pos: u64) -> Self {
        Tailer {
            path,
            pos,
            partial: Vec::new(),
        }
    }

    /// The events appended since the last poll, oldest first.
    pub fn poll(&mut self) -> io::Result<Vec<Event>> {
        let mut f = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let len = f.metadata()?.len();
        if len < self.pos {
            self.pos = 0;
            self.partial.clear();
        }
        if len == self.pos {
            return Ok(Vec::new());
        }
        f.seek(SeekFrom::Start(self.pos))?;
        let read = f.take(len - self.pos).read_to_end(&mut self.partial)?;
        self.pos += read as u64;
        let Some(cut) = self.partial.iter().rposition(|&b| b == b'\n') else {
            return Ok(Vec::new());
        };
        let rest = self.partial.split_off(cut + 1);
        let done = std::mem::replace(&mut self.partial, rest);
        Ok(done
            .split(|&b| b == b'\n')
            .filter_map(|l| serde_json::from_slice(l).ok())
            .collect())
    }
}

/// The kind of tool an event is about, for the Live tab.
pub fn kind(e: &Event) -> &'static str {
    let tool = e.tool.as_str();
    if tool == "net" || e.source.starts_with("net") {
        return "Net";
    }
    if tool.starts_with("mcp__") {
        return "MCP";
    }
    match tool {
        "Bash" if e.target == "git" || e.target.starts_with("git ") => "Git",
        "Bash" => "Bash",
        "WebFetch" | "WebSearch" => "Web",
        "Read" | "Write" | "Edit" | "MultiEdit" | "NotebookEdit" | "Glob" | "Grep" | "LS" => "File",
        "" => match e.source.as_str() {
            "UserPromptSubmit" => "Prompt",
            "SessionStart" => "Session",
            _ => "Other",
        },
        _ => "Other",
    }
}

/// The first 8 characters of a session id.
pub fn short_session(s: &str) -> String {
    s.chars().take(8).collect()
}

/// What the event views show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    pub green: bool,
    pub yellow: bool,
    pub red: bool,
    /// Case-insensitive text to find in the agent, subagent type, session, tool, target, rules or
    /// message.
    pub text: String,
    /// Only this agent, if set.
    pub agent: Option<String>,
}

impl Default for Filter {
    fn default() -> Self {
        Filter {
            green: true,
            yellow: true,
            red: true,
            text: String::new(),
            agent: None,
        }
    }
}

impl Filter {
    /// Whether `e` passes the filter.
    pub fn matches(&self, e: &Event) -> bool {
        let level_ok = match bucket(e.level) {
            Level::Red => self.red,
            Level::Yellow => self.yellow,
            _ => self.green,
        };
        if !level_ok || self.agent.as_ref().is_some_and(|a| *a != e.agent) {
            return false;
        }
        if self.text.is_empty() {
            return true;
        }
        let needle = self.text.to_lowercase();
        [&e.agent, &e.session, &e.tool, &e.target, &e.message]
            .into_iter()
            .chain(&e.agent_type)
            .chain(&e.rules)
            .any(|s| s.to_lowercase().contains(&needle))
    }
}

/// The agents named in `events`, sorted.
pub fn agents(events: &[Event]) -> Vec<String> {
    let set: BTreeSet<&str> = events.iter().map(|e| e.agent.as_str()).collect();
    set.into_iter()
        .filter(|a| !a.is_empty())
        .map(str::to_string)
        .collect()
}

/// The next agent filter after `current`: all, then each agent in turn, then all again.
pub fn next_agent(current: Option<&str>, agents: &[String]) -> Option<String> {
    let next = match current {
        None => 0,
        Some(c) => agents.iter().position(|a| a == c).map_or(0, |i| i + 1),
    };
    agents.get(next).cloned()
}

/// Whether an event belongs in the Alerts tab: red until acknowledged, yellow for an hour.
pub fn is_alert(level: Option<Level>, ts: u64, acked: bool, now: u64) -> bool {
    match bucket(level) {
        Level::Red => !acked,
        Level::Yellow => ts + HOUR >= now,
        _ => false,
    }
}

/// `host:port` or `[v6]:port` to the host alone, lowercased.
pub fn strip_port(s: &str) -> String {
    let s = s.trim().to_ascii_lowercase();
    if let Some(end) = s.strip_prefix('[').and_then(|r| r.find(']')) {
        return s[..end + 2].to_string();
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.bytes().all(|b| b.is_ascii_digit()) => h.to_string(),
        _ => s,
    }
}

/// The hosts an event names: URLs in its target, or the `host:port` of a network event.
pub fn hosts_of(e: &Event) -> Vec<String> {
    let hosts = dest::hosts_in(&e.target);
    if hosts.is_empty() && kind(e) == "Net" && !e.target.is_empty() {
        return vec![strip_port(&e.target)];
    }
    hosts
}

/// One remote host in the Network tab.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostRow {
    pub host: String,
    /// From `hosts.json`, if the network proxy has seen it.
    pub first_seen: Option<u64>,
    /// Agents (from events) and processes (from open connections) that talk to it.
    pub who: BTreeSet<String>,
    /// Events that name it.
    pub requests: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    /// Open connections now.
    pub conns: usize,
    /// Latest activity, Unix seconds.
    pub last: u64,
    /// First seen in the last day.
    pub new: bool,
    pub raw_ip: bool,
}

/// One open connection: the remote host (a name when known, else the IP) and the process name.
pub struct LiveConn {
    pub host: String,
    pub process: String,
}

/// Groups events and open connections by remote host, most recently active first.
pub fn group_hosts(
    events: &[Event],
    conns: &[LiveConn],
    first_seen: &HashMap<String, u64>,
    now: u64,
) -> Vec<HostRow> {
    let mut rows: HashMap<String, HostRow> = HashMap::new();
    fn row<'a>(rows: &'a mut HashMap<String, HostRow>, host: &str) -> &'a mut HostRow {
        rows.entry(host.to_string()).or_insert_with(|| HostRow {
            host: host.to_string(),
            ..HostRow::default()
        })
    }
    for e in events {
        for h in hosts_of(e) {
            let r = row(&mut rows, &h);
            r.requests += 1;
            r.bytes_out += e.bytes_out.unwrap_or(0);
            r.bytes_in += e.bytes_in.unwrap_or(0);
            r.last = r.last.max(e.ts);
            if !e.agent.is_empty() {
                r.who.insert(e.agent.clone());
            }
        }
    }
    for c in conns {
        let r = row(&mut rows, &c.host);
        r.conns += 1;
        r.last = now;
        r.who.insert(c.process.clone());
    }
    let mut out: Vec<HostRow> = rows.into_values().collect();
    for r in &mut out {
        r.first_seen = first_seen.get(&r.host).copied();
        r.new = r.first_seen.is_some_and(|t| t + DAY > now);
        r.raw_ip = dest::is_ip(&r.host);
    }
    out.sort_by(|a, b| b.last.cmp(&a.last).then_with(|| a.host.cmp(&b.host)));
    out
}

#[derive(Deserialize)]
struct Seen {
    first_seen: u64,
}

/// When each host was first seen, from `hosts.json` (written by the network proxy). A missing
/// or unreadable file gives an empty map.
pub fn load_first_seen(path: &Path) -> HashMap<String, u64> {
    std::fs::read(path)
        .ok()
        .and_then(|d| serde_json::from_slice::<HashMap<String, Seen>>(&d).ok())
        .map(|m| m.into_iter().map(|(h, s)| (h, s.first_seen)).collect())
        .unwrap_or_default()
}

/// Bytes as `512 B`, `3.4 KB`, `12.0 MB`.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

/// A past time as `12s`, `5m`, `3h` or `2d` ago.
pub fn ago(ts: u64, now: u64) -> String {
    let d = now.saturating_sub(ts);
    match d {
        0..60 => format!("{d}s"),
        60..3600 => format!("{}m", d / 60),
        3600..86_400 => format!("{}h", d / 3600),
        _ => format!("{}d", d / 86_400),
    }
}

/// A Unix time as `HH:MM:SS` UTC offset by `offset` seconds (the local zone, when known).
pub fn clock(ts: u64, offset: i64) -> String {
    let t = (ts as i64 + offset).rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", t / 3600, t / 60 % 60, t % 60)
}

/// A zone offset like `+0700` or `-0330` (as printed by `date +%z`) in seconds.
pub fn parse_offset(s: &str) -> Option<i64> {
    let s = s.trim();
    let (sign, digits) = match s.as_bytes().first()? {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let h: i64 = digits[..2].parse().ok()?;
    let m: i64 = digits[2..].parse().ok()?;
    Some(sign * (h * 3600 + m * 60))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn ev(ts: u64, level: Level) -> Event {
        Event {
            ts,
            agent: "claude".into(),
            session: "abcdef123456".into(),
            source: "PreToolUse".into(),
            tool: "Bash".into(),
            target: "ls".into(),
            level: Some(level),
            ..Event::default()
        }
    }

    fn write_log(path: &Path, events: &[Event]) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        for e in events {
            writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
        }
    }

    #[test]
    fn the_status_line_counts_each_call_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let done = |e: Event, level: Level| Event {
            source: "PostToolUse".into(),
            level: Some(level),
            ..e
        };
        write_log(
            &p,
            &[
                ev(10, Level::Green),
                done(ev(11, Level::Green), Level::Green),
                ev(12, Level::Red),
                done(ev(13, Level::Red), Level::Green),
                // A result that had to be cleaned is its own finding.
                done(ev(14, Level::Green), Level::Yellow),
            ],
        );
        assert_eq!(
            recent_counts(&p, 0).unwrap(),
            Counts {
                red: 1,
                yellow: 1,
                green: 1
            }
        );
    }

    #[test]
    fn counts_by_level_since() {
        let es = [
            ev(10, Level::Red),
            ev(20, Level::HardBlock),
            ev(30, Level::Yellow),
            ev(40, Level::Green),
            Event {
                level: None,
                ..ev(50, Level::Green)
            },
        ];
        assert_eq!(
            count(&es, 0),
            Counts {
                red: 2,
                yellow: 1,
                green: 2
            }
        );
        assert_eq!(
            count(&es, 25),
            Counts {
                red: 0,
                yellow: 1,
                green: 2
            }
        );
    }

    #[test]
    fn read_back_stops_at_the_window_across_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        // Many old events, then garbage, then recent ones: enough to span several chunks.
        let old: Vec<Event> = (0..3000).map(|i| ev(i, Level::Red)).collect();
        write_log(&p, &old);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .unwrap()
            .write_all(b"not json\n\n")
            .unwrap();
        let recent: Vec<Event> = (0..2000)
            .map(|i| {
                let mut e = ev(10_000 + i, Level::Green);
                e.target = "x".repeat(i as usize % 50);
                e
            })
            .collect();
        write_log(&p, &recent);
        let (got, end) = read_back(&p, 10_000, |e: &Event| e.ts).unwrap();
        assert_eq!(got, recent);
        assert_eq!(end, std::fs::metadata(&p).unwrap().len());
        let (all, _) = read_back(&p, 0, |e: &Event| e.ts).unwrap();
        assert_eq!(all.len(), 5000);
        assert_eq!(all[0].ts, 0);
        assert_eq!(
            recent_counts(&p, 9_000).unwrap(),
            Counts {
                red: 0,
                yellow: 0,
                green: 2000
            }
        );
    }

    #[test]
    fn read_back_of_a_missing_log_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let (got, end) = read_back(&dir.path().join("none"), 0, |e: &Event| e.ts).unwrap();
        assert!(got.is_empty());
        assert_eq!(end, 0);
    }

    #[test]
    fn tailer_returns_whole_new_lines_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let mut t = Tailer::new(p.clone(), 0);
        assert!(t.poll().unwrap().is_empty());
        write_log(&p, &[ev(1, Level::Green)]);
        let line = serde_json::to_string(&ev(2, Level::Red)).unwrap();
        let (a, b) = line.split_at(10);
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(a.as_bytes()).unwrap();
        assert_eq!(t.poll().unwrap(), [ev(1, Level::Green)]);
        f.write_all(format!("{b}\n").as_bytes()).unwrap();
        assert_eq!(t.poll().unwrap(), [ev(2, Level::Red)]);
        assert!(t.poll().unwrap().is_empty());
        // Truncated: read again from the start.
        std::fs::write(&p, "").unwrap();
        write_log(&p, &[ev(3, Level::Yellow)]);
        assert_eq!(t.poll().unwrap(), [ev(3, Level::Yellow)]);
    }

    #[test]
    fn kinds() {
        let mut e = ev(0, Level::Green);
        assert_eq!(kind(&e), "Bash");
        e.target = "git push origin main".into();
        assert_eq!(kind(&e), "Git");
        e.target = "gitk".into();
        assert_eq!(kind(&e), "Bash");
        e.tool = "mcp__github__create_issue".into();
        assert_eq!(kind(&e), "MCP");
        e.tool = "WebFetch".into();
        assert_eq!(kind(&e), "Web");
        e.tool = "Edit".into();
        assert_eq!(kind(&e), "File");
        e.tool = "net".into();
        assert_eq!(kind(&e), "Net");
        e.tool = String::new();
        e.source = "UserPromptSubmit".into();
        assert_eq!(kind(&e), "Prompt");
    }

    #[test]
    fn filter_by_level_agent_and_text() {
        let mut f = Filter::default();
        let mut e = ev(0, Level::Green);
        e.rules = vec!["secrets.outbound".into()];
        assert!(f.matches(&e));
        f.green = false;
        assert!(!f.matches(&e));
        assert!(f.matches(&ev(0, Level::HardBlock)));
        f.green = true;
        f.text = "SECRETS".into();
        assert!(f.matches(&e));
        f.text = "paste.ee".into();
        assert!(!f.matches(&e));
        f.text.clear();
        f.agent = Some("codex".into());
        assert!(!f.matches(&e));
    }

    #[test]
    fn agent_filter_cycles() {
        let es = [
            Event {
                agent: "codex".into(),
                ..ev(0, Level::Green)
            },
            ev(0, Level::Green),
            ev(0, Level::Green),
        ];
        let a = agents(&es);
        assert_eq!(a, ["claude", "codex"]);
        assert_eq!(next_agent(None, &a).as_deref(), Some("claude"));
        assert_eq!(next_agent(Some("claude"), &a).as_deref(), Some("codex"));
        assert_eq!(next_agent(Some("codex"), &a), None);
        assert_eq!(next_agent(Some("gone"), &a).as_deref(), Some("claude"));
        assert_eq!(next_agent(None, &[]), None);
    }

    #[test]
    fn alerts_keep_red_until_acked() {
        let now = 10 * HOUR;
        let red = Some(Level::Red);
        assert!(is_alert(red, 0, false, now));
        assert!(!is_alert(red, 0, true, now));
        assert!(is_alert(Some(Level::Yellow), now - 60, false, now));
        assert!(!is_alert(Some(Level::Yellow), now - 2 * HOUR, false, now));
        assert!(!is_alert(Some(Level::Green), now, false, now));
    }

    #[test]
    fn hosts_are_grouped_with_flags() {
        let now = 100 * DAY;
        let mut fetch = ev(now - 10, Level::Green);
        fetch.tool = "WebFetch".into();
        fetch.target = "https://Docs.rs/serde".into();
        let net = Event {
            agent: "net".into(),
            source: "net-proxy".into(),
            tool: "net".into(),
            target: "paste.ee:443".into(),
            bytes_out: Some(2048),
            bytes_in: Some(10),
            ..ev(now - 5, Level::Yellow)
        };
        let conns = [LiveConn {
            host: "1.2.3.4".into(),
            process: "node".into(),
        }];
        let seen = HashMap::from([
            ("paste.ee".to_string(), now - 60),
            ("docs.rs".to_string(), now - 30 * DAY),
        ]);
        let rows = group_hosts(&[fetch.clone(), fetch, net], &conns, &seen, now);
        let hosts: Vec<&str> = rows.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, ["1.2.3.4", "paste.ee", "docs.rs"]);
        assert!(rows[0].raw_ip && rows[0].conns == 1 && rows[0].first_seen.is_none());
        assert!(rows[1].new && rows[1].bytes_out == 2048 && rows[1].who.contains("net"));
        assert!(!rows[2].new && !rows[2].raw_ip && rows[2].requests == 2);
    }

    #[test]
    fn ports_are_stripped() {
        assert_eq!(strip_port("Paste.ee:443"), "paste.ee");
        assert_eq!(strip_port("[::1]:80"), "[::1]");
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("::1"), "::1");
    }

    #[test]
    fn first_seen_reads_the_proxy_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hosts.json");
        assert!(load_first_seen(&p).is_empty());
        std::fs::write(
            &p,
            r#"{"paste.ee":{"first_seen":5,"last_seen":9,"count":2}}"#,
        )
        .unwrap();
        assert_eq!(load_first_seen(&p)["paste.ee"], 5);
        std::fs::write(&p, "broken").unwrap();
        assert!(load_first_seen(&p).is_empty());
    }

    #[test]
    fn formatting() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(3 * 1024 + 512), "3.5 KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(ago(100, 130), "30s");
        assert_eq!(ago(0, 7200), "2h");
        assert_eq!(clock(3661, 0), "01:01:01");
        assert_eq!(clock(0, -3600), "23:00:00");
        assert_eq!(parse_offset("+0700\n"), Some(25_200));
        assert_eq!(parse_offset("-0330"), Some(-12_600));
        assert_eq!(parse_offset("UTC"), None);
    }
}
