# mcp-firewall 🛡️

**A local-first security proxy for AI agents.** It sits between any
[MCP](https://modelcontextprotocol.io) client (Claude Code, Cursor, Windsurf, …)
and the MCP servers it uses, and gives you three things:

- **🔍 Audit** — every tool call and result recorded to a replayable JSONL log
- **🚦 Policy** — allow / deny / ask rules in plain YAML (`deny: bash("rm -rf …")`)
- **🕵️ Detect** — secrets leaking through tool results are redacted before they
  ever reach the model

Think *"Little Snitch for AI agents."* Because MCP is a standard protocol, one
proxy works with every MCP-speaking agent — no per-tool integration.

```
Agent ──→ 🛡️ mcp-firewall ──→ MCP server (filesystem, github, shell, …)
                 │
                 ├─ policy engine   (allow / deny / ask)
                 ├─ detectors        (secrets, …)
                 └─ audit log         (JSONL, replayable)
```

---

## Why

AI agents are being wired up to shells, filesystems, and APIs through MCP — and
almost nothing sits between the model and those tools. An agent can be
prompt-injected into running `rm -rf`, reading your `.env`, or exfiltrating a
key it found in a file. mcp-firewall is a thin, auditable layer that watches and
gates that traffic on *your* machine, without you having to trust the agent or
the server.

## Quick start

```bash
# Wrap any MCP server. Everything after `--` is the real server command.
npx -y mcp-firewall wrap --policy policies/examples/filesystem.yaml -- \
  npx -y @modelcontextprotocol/server-filesystem /path/to/project

# In another terminal, see what your agent has been doing:
npx -y mcp-firewall log
```

To use it with your agent permanently, wrap the server in your MCP config — see
[docs/INTEGRATION.md](docs/INTEGRATION.md) for Claude Code / Cursor / Windsurf.

## Demo

> 📹 _A recorded demo (asciinema/GIF) goes here._

A denied call, as the agent experiences it — the dangerous command never reaches
the server, and the model gets a clear error it can adapt to:

```console
$ mcp-firewall wrap --policy policies/examples/filesystem.yaml -- <fs-server>
[mcp-firewall] wrapping: <fs-server>
[mcp-firewall] policy: policies/examples/filesystem.yaml
[mcp-firewall] redaction: on
[mcp-firewall] approvals: http://127.0.0.1:54467
[mcp-firewall] BLOCKED run_bash (0ms) [block-destructive-shell]
[mcp-firewall] ALLOW  read_file (12ms)
[mcp-firewall] ALLOW  read_file (9ms) ⚠ 1 finding(s)      ← a secret was redacted
[mcp-firewall] APPROVAL NEEDED: write_file — decide at http://127.0.0.1:54467
[mcp-firewall] APPROVED write_file (18ms) [confirm-writes-outside-cwd]
```

```console
$ mcp-firewall log
2026-07-23 10:38:18Z  [DENY] run_bash  (0ms)
  args:   {"command":"rm -rf /important/data"}
2026-07-23 10:38:19Z  [ALLOW] read_file  (9ms)
  args:   {"path":".env"}
  result: {"content":[{"type":"text","text":"AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key]…
  findings: 1
    - [high] aws-access-key: AWS access key ID
```

## How it works

MCP is a standardized JSON-RPC protocol between an agent and a tool server.
mcp-firewall speaks that protocol on both sides: to your agent it looks like the
server; to the real server it looks like the agent. Every message flows through
it, so it can log, gate, and rewrite tool calls — for **any** MCP client,
without integrating with that client.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full picture and
[docs/DESIGN.md](docs/DESIGN.md) for the reasoning behind the design.

## Policies

Rules are plain YAML, evaluated top to bottom (first match wins):

```yaml
version: 1
default: allow

rules:
  - name: block-destructive-shell
    action: deny                       # deny | allow | ask
    match:
      tool: "*bash*"                   # glob on the tool name
      args_regex: "rm\\s+-rf|mkfs"     # regex over the arguments
    reason: "Destructive shell command blocked by policy."

  - name: confirm-writes-outside-cwd
    action: ask                        # holds the call for your approval
    match:
      tool: "*write*"
      path_outside: "."                # a path argument escapes the project dir
    reason: "Write outside the project directory — confirm first."
```

`ask` rules pause the call and open a local web page where you click Approve or
Deny. Ready-made policies live in [`policies/examples/`](policies/examples/):
`read-only.yaml`, `filesystem.yaml`, `paranoid.yaml`.

## CLI

```
mcp-firewall wrap [--policy <file>] [--no-redact] [--no-open] [--verbose] -- <server-command...>
mcp-firewall log  [--file <path>]
```

| Flag | Effect |
|---|---|
| `--policy <file>` | Load allow/deny/ask rules (default: allow all, still audited) |
| `--no-redact` | Detect secrets but don't redact them from results |
| `--no-open` | Don't auto-open the browser for approvals (headless) |
| `--verbose` | Also log every JSON-RPC message to stderr |

The audit log never stores raw secrets, regardless of `--no-redact`.

## Status

**v0.1 — early but usable.** Working today: transparent stdio proxy, audit log,
YAML policy engine (allow/deny/ask), secret detection + redaction, and a
web-UI approval flow. On the roadmap: prompt-injection detection in results,
MCP-server scanning, remote (HTTP) transport, and a trace-viewer UI. See
[docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). This is a
security tool, so the bar is: pure, tested detectors; a small dependency
surface; and never logging the secrets we detect.

## License

[MIT](LICENSE)
