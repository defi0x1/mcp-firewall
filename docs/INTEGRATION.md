# Wiring mcp-firewall into your agent

mcp-firewall wraps an existing MCP server. Wherever your MCP client (Claude
Code, Cursor, Windsurf, Cline, …) currently launches a server, you insert
`mcp-firewall wrap … --` in front of the original command.

The general transformation:

```
BEFORE:  <server-command> <server-args...>
AFTER:   npx -y mcp-firewall wrap --policy <policy.yaml> -- <server-command> <server-args...>
```

Everything after `--` is the original server command, untouched.

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
      "command": "npx",
      "args": [
        "-y", "mcp-firewall", "wrap",
        "--policy", "/absolute/path/to/policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"
      ]
    }
  }
}
```

That's the whole change: the `command` becomes `npx`/`mcp-firewall wrap …`, and
your original command moves after `--`. Use an **absolute path** for `--policy`
(the server's working directory may not be your project root).

You can also add it with the CLI:

```bash
claude mcp add filesystem -- npx -y mcp-firewall wrap \
  --policy /absolute/path/to/policy.yaml -- \
  npx -y @modelcontextprotocol/server-filesystem /path/to/project
```

## Cursor / Windsurf / Cline

These use the same `mcpServers` JSON shape (in `~/.cursor/mcp.json`,
Windsurf's `mcp_config.json`, etc.). Apply the identical transformation: prepend
`npx -y mcp-firewall wrap --policy <file> --` to the existing command/args.

---

## What you'll see

- **Audit** — every tool call is appended to `.mcp-firewall/audit.jsonl` in the
  server's working directory. Read it with `npx mcp-firewall log`.
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
