# Threat model

## What it protects against

The attacker is text the agent reads: an MCP server, a skill, a plugin, a web page, a file in a
cloned repo, or an issue comment. That text tries to make Claude leak keys, run code, or
switch Agent Guard off. The user and the machine are trusted.

| Attack | What Agent Guard does |
|---|---|
| A key sent to a host that isn't its provider | Red: Claude asks first (`secrets.outbound`) |
| Reading `~/.ssh`, `~/.aws`, browser profiles, keychains | Red (`paths.*`); in hardened mode the sandbox and deny rules refuse it |
| Cloud metadata IP, raw IPs, `/dev/tcp` | Red or yellow (`net.*`) |
| `curl ... \| sh`, new hosts | Yellow, and the host is listed in `guard trust review` |
| Writing to shell profiles, launch agents, cron, git hooks | Red (`paths.persistence`) |
| Prompt injection, invisible text and terminal codes in tool results | Stripped from MCP and web results, keys masked (`sanitize.*`) |
| An MCP tool that changes after you approved it | Hidden when run through `guard proxy` |
| A repo whose git config runs commands | Flagged, and git runs with those options off (`git.*`) |
| The agent turning Agent Guard off, or editing its files or binary | Always refused (the only hard block) |

## Two modes

**Light** (`guard install`). The hooks live in `~/.claude/settings.json`. Anything running as
you can edit that file, so a command the shell parser misses could remove the hooks.
The status line and `guard doctor` show it when that happens.

**Hardened** (`sudo guard install --hardened`). The hooks, the sandbox, deny rules for secret
paths and the allowed network hosts go into Claude Code's managed settings, which root owns.
The binary and policy are root-owned too. The sandbox, not the parser, then stops Bash and its
child processes from reading secrets or reaching unknown hosts. Deny rules cover the Read and
Edit tools, which the sandbox does not.

## Out of scope

- A user who wants to turn it off. `guard off` and `guard uninstall` are theirs to run.
- Malware already running as the user (light mode) or as root (both modes).
- Agents other than Claude Code. `guard top` shows them but doesn't stop them.
- Prompt injection that changes what Claude decides without calling a tool.
- Shell commands built at run time to dodge the parser, in light mode. Hardened mode exists
  for this.

## Failure behaviour

PreToolUse and PostToolUse hooks fail closed: if the binary times out or crashes, the call is
blocked. Reinstall from a terminal, or run `guard uninstall`, to recover.

Light-mode parser bypasses are public bypass reports; anything past hardened mode or against the guard itself is
reported privately. Both are described in [SECURITY.md](SECURITY.md).
