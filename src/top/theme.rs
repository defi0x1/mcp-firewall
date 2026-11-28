//! Colors for `guard top`: Dracula on a dark terminal, Alucard (Dracula's light palette) on a
//! light one. Terminals without 24-bit color get the nearest of the 256 indexed colors.

use std::sync::OnceLock;

use ratatui::style::Color;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub bg: Color,
    /// The selected row.
    pub line: Color,
    pub fg: Color,
    /// Dim text and quiet borders.
    pub comment: Color,
    pub red: Color,
    /// Warnings: Dracula's yellow is too pale next to plain text.
    pub orange: Color,
    pub green: Color,
    /// Tool icons and hosts.
    pub cyan: Color,
    /// The focus: selected tab, focused border, keys, the chart.
    pub purple: Color,
    /// Subagents.
    pub pink: Color,
}

const DRACULA: [u32; 10] = [
    0x282a36, 0x44475a, 0xf8f8f2, 0x6272a4, 0xff5555, 0xffb86c, 0x50fa7b, 0x8be9fd, 0xbd93f9,
    0xff79c6,
];
const ALUCARD: [u32; 10] = [
    0xfffbeb, 0xcfcfde, 0x1f1f1f, 0x635d97, 0xcb3a2a, 0xa34d14, 0x14710a, 0x036a96, 0x644ac9,
    0xa3144d,
];

impl Theme {
    pub fn new(light: bool, truecolor: bool) -> Self {
        let rgb = if light { ALUCARD } else { DRACULA };
        let c = |i: usize| {
            let v = rgb[i];
            let (r, g, b) = ((v >> 16) as u8, (v >> 8) as u8, v as u8);
            if truecolor {
                Color::Rgb(r, g, b)
            } else {
                Color::Indexed(nearest_256(r, g, b))
            }
        };
        Theme {
            bg: c(0),
            line: c(1),
            fg: c(2),
            comment: c(3),
            red: c(4),
            orange: c(5),
            green: c(6),
            cyan: c(7),
            purple: c(8),
            pink: c(9),
        }
    }
}

static THEME: OnceLock<Theme> = OnceLock::new();

/// Picks the theme once, before drawing. `choice` is `--theme` (`light` or `dark`).
pub fn init(choice: Option<&str>) {
    let light = match choice.map(str::to_ascii_lowercase).as_deref() {
        Some("light") => true,
        Some("dark") => false,
        _ => detect_light(),
    };
    let _ = THEME.set(Theme::new(light, truecolor()));
}

/// The theme in use; Dracula when `init` was not called (tests).
pub fn get() -> &'static Theme {
    THEME.get_or_init(|| Theme::new(false, true))
}

/// Whether the terminal has a light background: `AGENT_GUARD_THEME`, then `COLORFGBG` (set by
/// iTerm2, Konsole, rxvt), then the macOS appearance. Dark when nothing says.
fn detect_light() -> bool {
    if let Ok(t) = std::env::var("AGENT_GUARD_THEME") {
        return t.eq_ignore_ascii_case("light");
    }
    if let Some(light) = std::env::var("COLORFGBG")
        .ok()
        .as_deref()
        .and_then(fgbg_light)
    {
        return light;
    }
    if cfg!(target_os = "macos") {
        // `defaults` prints `Dark` in dark mode and fails in light mode.
        return std::process::Command::new("defaults")
            .args(["read", "-g", "AppleInterfaceStyle"])
            .output()
            .is_ok_and(|o| !String::from_utf8_lossy(&o.stdout).contains("Dark"));
    }
    false
}

/// `COLORFGBG` is `fg;bg` (sometimes `fg;x;bg`); background 7 or 9-15 is light.
fn fgbg_light(v: &str) -> Option<bool> {
    let bg: u8 = v.rsplit(';').next()?.trim().parse().ok()?;
    Some(bg == 7 || bg >= 9)
}

fn truecolor() -> bool {
    let env = |k: &str| std::env::var(k).unwrap_or_default().to_ascii_lowercase();
    matches!(env("COLORTERM").as_str(), "truecolor" | "24bit")
        || matches!(
            env("TERM_PROGRAM").as_str(),
            "iterm.app" | "wezterm" | "ghostty" | "vscode" | "warpterminal"
        )
        || env("TERM").contains("kitty")
}

/// The nearest color in the xterm 256-color table: the 6x6x6 cube or the gray ramp.
fn nearest_256(r: u8, g: u8, b: u8) -> u8 {
    const STEPS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let idx = |v: u8| {
        (0..6)
            .min_by_key(|&i| (i32::from(STEPS[i]) - i32::from(v)).abs())
            .unwrap_or(0)
    };
    let (ri, gi, bi) = (idx(r), idx(g), idx(b));
    let cube = (STEPS[ri], STEPS[gi], STEPS[bi]);
    let gray_level = ((u32::from(r) + u32::from(g) + u32::from(b)) / 3) as u8;
    let gi_ramp = (gray_level.saturating_sub(8) / 10).min(23);
    let gray = 8 + 10 * gi_ramp;
    let dist = |(a, b2, c): (u8, u8, u8)| {
        let d = |x: u8, y: u8| (i32::from(x) - i32::from(y)).pow(2);
        d(a, r) + d(b2, g) + d(c, b)
    };
    if dist((gray, gray, gray)) < dist(cube) {
        232 + gi_ramp
    } else {
        16 + 36 * ri as u8 + 6 * gi as u8 + bi as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palettes_and_fallback() {
        let d = Theme::new(false, true);
        assert_eq!(d.bg, Color::Rgb(0x28, 0x2a, 0x36));
        assert_eq!(Theme::new(true, true).fg, Color::Rgb(0x1f, 0x1f, 0x1f));
        // Pure colors land on the cube, grays on the ramp.
        assert_eq!(nearest_256(255, 0, 0), 196);
        assert_eq!(nearest_256(0x28, 0x2a, 0x36), 235);
        assert!(matches!(Theme::new(false, false).purple, Color::Indexed(_)));
    }

    #[test]
    fn colorfgbg() {
        assert_eq!(fgbg_light("15;0"), Some(false));
        assert_eq!(fgbg_light("0;15"), Some(true));
        assert_eq!(fgbg_light("0;default;7"), Some(true));
        assert_eq!(fgbg_light("junk"), None);
    }
}
