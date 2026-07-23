# Wiring mcp-firewall into your agent

mcp-firewall wraps an existing MCP server. Wherever your MCP client (Claude
Code, Cursor, Windsurf, Cline, …) currently launches a server, you insert the
firewall in front of the original command.

This project isn't published to npm — you run it from your local clone. Build it
once (`pnpm install && pnpm build`), then refer to it by the absolute path to
`dist/cli.js`. In the examples below, `<REPO>` means the absolute path to your
mcp-firewall checkout (e.g. `/Users/you/Documents/mcp-firewall`).

The general transformation:

```
BEFORE:  <server-command> <server-args...>
AFTER:   node <REPO>/dist/cli.js wrap --policy <REPO>/policies/examples/<policy>.yaml -- <server-command> <server-args...>
```

Everything after `--` is the original server command, untouched. (If you ran
`pnpm link --global`, you can write `mcp-firewall wrap …` instead of
`node <REPO>/dist/cli.js wrap …`.)

---

## Claude Code

Claude Code reads MCP servers from `.mcp.json` (project) or your user config.
A typical filesystem server entry looks like:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
    }
  }
}
```

Wrap it with the firewall:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": [
        "<REPO>/dist/cli.js", "wrap",
        "--policy", "<REPO>/policies/examples/filesystem.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"
      ]
    }
  }
}
```

That's the whole change: `command` becomes `node <REPO>/dist/cli.js wrap …`, and
your original command moves after `--`. Use **absolute paths** for both the CLI
and the `--policy` file (the server's working directory may not be your project
root).

You can also add it with the CLI:

```bash
claude mcp add filesystem -- node <REPO>/dist/cli.js wrap \
  --policy <REPO>/policies/examples/filesystem.yaml -- \
  npx -y @modelcontextprotocol/server-filesystem /path/to/project
```

## Cursor / Windsurf / Cline

These use the same `mcpServers` JSON shape (in `~/.cursor/mcp.json`,
Windsurf's `mcp_config.json`, etc.). Apply the identical transformation: prepend
`node <REPO>/dist/cli.js wrap --policy <file> --` to the existing command/args.

---

## What you'll see

- **Audit** — every tool call is appended to `.mcp-firewall/audit.jsonl` in the
  server's working directory. Read it with `node <REPO>/dist/cli.js log`.
- **Deny** — a blocked call returns a tool error to the agent
  (`⛔ Blocked by mcp-firewall policy …`); the agent sees it and adapts.
- **Ask** — a browser tab opens with an Approve/Deny prompt. The call is held
  until you decide (or it auto-denies after the timeout).
- **Redact** — secrets detected in results are replaced with
  `[REDACTED:<detector>]` before the agent sees them.

## Flags

| Flag | Effect |
|---|---|
| `--policy <file>` | Load allow/deny/ask rules (without it, everything is allowed but still audited) |
| `--no-redact` | Don't redact secrets from results (still detected + logged) |
| `--no-open` | Don't auto-open the browser for approvals (headless/remote) |
| `--verbose` | Also log every JSON-RPC message to stderr |

## Notes & limitations (v0.1)

- **stdio transport only.** Remote (Streamable HTTP) MCP servers aren't wrapped
  yet — see the roadmap.
- **One server per firewall.** Wrap each server entry separately.
- **Approvals need a browser on the same machine.** For fully headless use,
  `--no-open` + open the printed URL yourself, or rely on deny/allow rules only.
