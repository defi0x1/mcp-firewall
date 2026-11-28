# Agent Guard plugin

This plugin wires Agent Guard into Claude Code without editing your settings. It is the
alternative to running `guard install`. Use one or the other, not both, or every hook runs twice.

## Requirements

The hooks run `guard hook`, so the `guard` binary must be on the `PATH` that Claude Code sees.
Install it first (the install script in the main [README](../README.md#install), or
`cargo install --locked --git https://github.com/defi0x1/agent-guard`) and check it with
`guard --version`.

The PreToolUse hook sets `onFailure: "block"`: if `guard` is missing, crashes or times out, the
tool call is blocked instead of running unchecked. If every tool call is suddenly blocked with a
"failed; blocking" error, `guard` is not on your `PATH`.

The plugin does not set a status line. To show Agent Guard's, add this to
`~/.claude/settings.json`:

```json
"statusLine": { "type": "command", "command": "guard statusline" }
```

## Install

```
/plugin marketplace add defi0x1/agent-guard
/plugin install agent-guard@agent-guard
```

Then restart Claude Code and run `guard selftest` and `guard status`.
