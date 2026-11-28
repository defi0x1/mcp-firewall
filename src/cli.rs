//! The `guard` command line.

use clap::{Parser, Subcommand};

use crate::config::{self, Preset, TrustedHost};
use crate::text::term_safe;
use crate::{doctor, home, hook, install, pause, proxy, report, scan, top, vault};

#[derive(Parser)]
#[command(
    name = "guard",
    version,
    about = "A local security layer for AI coding agents."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Claude Code hook entry point (reads the event as JSON on stdin).
    #[command(hide = true)]
    Hook,
    /// Live view of every agent's tool calls, processes and connections.
    Top {
        /// `dark` (Dracula) or `light` (Alucard). Follows the terminal if not set.
        #[arg(long)]
        theme: Option<String>,
    },
    /// One line for Claude Code's status line.
    #[command(hide = true)]
    Statusline {
        /// Also run the status line `guard install` wrapped, below Agent Guard's line.
        #[arg(long)]
        wrap: bool,
    },
    /// Check this machine's agent setup and fix what is unsafe.
    Doctor {
        /// Fix one finding by id (for example D03), or `all`.
        #[arg(long)]
        fix: Option<String>,
        /// Undo the last fix.
        #[arg(long)]
        undo: bool,
    },
    /// Scan installed plugins, skills, MCP servers and hooks; label each green, yellow or red.
    Scan,
    /// Run an MCP server through Agent Guard: `guard proxy -- npx some-server`.
    Proxy {
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Trusted repositories, blocked hosts, and a review of hosts seen recently.
    #[command(subcommand)]
    Trust(TrustCmd),
    /// Keys kept in the OS keychain instead of config files.
    #[command(subcommand)]
    Secret(vault::SecretCmd),
    /// Run a command with keys from the keychain: `guard run --secret GH=GITHUB_TOKEN -- cmd`.
    Run {
        #[arg(long = "secret", value_name = "NAME=ENV")]
        secrets: Vec<String>,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Summary of recent decisions.
    Report {
        /// How far back, for example `24h` or `7d`.
        #[arg(long, default_value = "24h")]
        since: String,
    },
    /// Explain a rule in plain words.
    Explain { rule: String },
    /// Set the default strictness.
    Level { preset: Preset },
    /// Whitelist a domain you know is safe, so it stops warning. No domain: show the whitelist.
    Whitelist {
        domain: Option<String>,
        /// Take the domain off the whitelist.
        #[arg(long)]
        remove: bool,
        /// How long, for example `1h` or `7d`. Forever if not set.
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Turn Agent Guard back on.
    On,
    /// Turn Agent Guard off until `guard on` (run this yourself; agents are blocked from it).
    Off,
    /// Show whether Agent Guard is on, the level, and today's counts.
    Status,
    /// Add Agent Guard to Claude Code (hooks and status line).
    Install {
        /// Lock the hooks and the sandbox in root-owned managed settings (run with sudo).
        #[arg(long)]
        hardened: bool,
    },
    /// Remove Agent Guard from Claude Code.
    Uninstall {
        /// Remove hardened mode (run with sudo).
        #[arg(long)]
        hardened: bool,
    },
    /// Check that the hooks really block, ask and clean on this Claude Code version.
    Selftest,
}

#[derive(Subcommand)]
enum TrustCmd {
    /// Same as `guard whitelist <host>`, kept for older scripts.
    #[command(hide = true)]
    Add {
        host: String,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        process: Option<String>,
        /// How long, for example `1h` or `7d`. Forever if not set.
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Same as `guard whitelist --remove <host>`.
    #[command(hide = true)]
    Rm { host: String },
    /// List whitelisted hosts, trusted repositories and blocked hosts.
    List,
    /// Trust a repository's git hooks and config (default: the current directory).
    Repo { path: Option<std::path::PathBuf> },
    /// Block a host: calls to it are red.
    Block { host: String },
    /// Review hosts seen recently and whitelist the ones you recognise.
    Review,
}

pub fn run() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Hook => hook::run(),
        Cmd::Top { theme } => top::run(theme.as_deref()),
        Cmd::Statusline { wrap } => crate::statusline::run(wrap),
        Cmd::Doctor { fix, undo } => doctor::run(fix.as_deref(), undo),
        Cmd::Scan => scan::run(),
        Cmd::Proxy { command } => proxy::run(&command),
        Cmd::Trust(t) => {
            require_root_if_hardened("trust")?;
            trust(t)
        }
        Cmd::Secret(s) => vault::run(s),
        Cmd::Run { secrets, command } => vault::exec(&secrets, &command),
        Cmd::Report { since } => report::run(&since),
        Cmd::Explain { rule } => report::explain(&rule),
        Cmd::Level { preset } => {
            require_root_if_hardened("level")?;
            let mut c = config::load().config;
            c.preset = preset;
            c.save()?;
            println!("level set to {preset:?}");
            Ok(())
        }
        Cmd::Whitelist {
            domain,
            remove,
            ttl,
        } => {
            require_root_if_hardened("whitelist")?;
            trust(match (domain, remove) {
                (None, _) => TrustCmd::List,
                (Some(host), true) => TrustCmd::Rm { host },
                (Some(host), false) => TrustCmd::Add {
                    host,
                    agent: None,
                    process: None,
                    ttl,
                },
            })
        }
        Cmd::On => {
            pause::resume()?;
            println!("Agent Guard is on.");
            Ok(())
        }
        Cmd::Off => {
            pause::pause_until(pause::OFF)?;
            println!(
                "Agent Guard is off: tool calls are not checked. `guard on` turns it back on."
            );
            Ok(())
        }
        Cmd::Status => report::status(),
        Cmd::Install { hardened: true } => install::install_hardened(),
        Cmd::Install { hardened: false } => install::install(),
        Cmd::Uninstall { hardened: true } => install::uninstall_hardened(),
        Cmd::Uninstall { hardened: false } => install::uninstall(),
        Cmd::Selftest => install::selftest(),
    }
}

/// In hardened mode, policy changes need root so an agent running as the user cannot make them.
fn require_root_if_hardened(what: &str) -> anyhow::Result<()> {
    let hp = crate::hardened::Paths::system();
    crate::hardened::require_root(&hp, what, crate::hardened::is_root())
}

fn trust(cmd: TrustCmd) -> anyhow::Result<()> {
    let mut c = config::load().config;
    match cmd {
        TrustCmd::Add {
            host,
            agent,
            process,
            ttl,
        } => {
            let expires_at = match ttl {
                Some(t) => Some(
                    home::now()
                        + pause::parse_duration(&t)
                            .ok_or_else(|| anyhow::anyhow!("bad ttl {t:?}; try 1h or 7d"))?,
                ),
                None => None,
            };
            c.trust.hosts.retain(|t| t.host != host);
            c.trust.hosts.push(TrustedHost {
                host: host.clone(),
                agent,
                process,
                expires_at,
            });
            c.save()?;
            println!("trusted {}", term_safe(&host));
        }
        TrustCmd::Rm { host } => {
            let before = c.trust.hosts.len();
            c.trust.hosts.retain(|t| t.host != host);
            if c.trust.hosts.len() == before {
                anyhow::bail!("{host} is not in the trusted list");
            }
            c.save()?;
            println!("removed {}", term_safe(&host));
        }
        TrustCmd::List => {
            if c.trust.hosts.is_empty() {
                println!("no trusted hosts");
            }
            for t in &c.trust.hosts {
                let mut extra = Vec::new();
                if let Some(a) = &t.agent {
                    extra.push(format!("agent={}", term_safe(a)));
                }
                if let Some(p) = &t.process {
                    extra.push(format!("process={}", term_safe(p)));
                }
                if let Some(e) = t.expires_at {
                    extra.push(format!(
                        "expires in {}m",
                        e.saturating_sub(home::now()) / 60
                    ));
                }
                println!("{}  {}", term_safe(&t.host), extra.join(" "));
            }
            for r in &c.trust.repos {
                println!("repo {}", term_safe(r));
            }
            for b in &c.trust.blocked {
                println!("blocked {}", term_safe(b));
            }
        }
        TrustCmd::Repo { path } => {
            let p = match path {
                Some(p) => p,
                None => std::env::current_dir()?,
            };
            let p = std::fs::canonicalize(&p)?.to_string_lossy().into_owned();
            if !c.trust.repos.contains(&p) {
                c.trust.repos.push(p.clone());
            }
            c.save()?;
            println!("trusted repository {}", term_safe(&p));
        }
        TrustCmd::Block { host } => {
            if !c.trust.blocked.contains(&host) {
                c.trust.blocked.push(host.clone());
            }
            c.save()?;
            println!("blocked {}", term_safe(&host));
        }
        TrustCmd::Review => crate::checks::net::review(&mut c)?,
    }
    // Hardened mode keeps the sandbox allowlist in root-owned files; keep it in step.
    let hp = crate::hardened::Paths::system();
    if crate::hardened::installed(&hp) {
        let c = config::load().config;
        crate::hardened::set_trusted_hosts(&hp, &crate::hardened::trusted_from_config(&c))?;
    }
    Ok(())
}
