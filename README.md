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

## Install (from source — not on npm)

```bash
git clone https://github.com/defi0x1/mcp-firewall.git
cd mcp-firewall
pnpm install
pnpm build          # produces dist/cli.js
```

Optionally expose a global `mcp-firewall` command backed by your local build:

```bash
pnpm link --global  # now `mcp-firewall …` runs this repo
```

Throughout the docs, `mcp-firewall` and `node /abs/path/to/mcp-firewall/dist/cli.js`
are interchangeable — use the global command if you linked it, otherwise the
absolute `node …/dist/cli.js` path.

## Two ways to use it

### 1. Manual / developer use

Run the firewall around any MCP server yourself. Everything after `--` is the
real server command:

```bash
node dist/cli.js wrap --policy policies/examples/filesystem.yaml -- \
  npx -y @modelcontextprotocol/server-filesystem /path/to/project

# during development you can skip the build step and run from source:
pnpm dev wrap --policy policies/examples/filesystem.yaml -- <server-command…>

# see what your agent has been doing:
node dist/cli.js log
```

To make it permanent, point your MCP client (Claude Code / Cursor / Windsurf) at
the firewall instead of the raw server, using **absolute paths**:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": [
        "/abs/path/to/mcp-firewall/dist/cli.js", "wrap",
        "--policy", "/abs/path/to/mcp-firewall/policies/examples/filesystem.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"
      ]
    }
  }
}
```

Full per-client instructions: [docs/INTEGRATION.md](docs/INTEGRATION.md).

### 2. Let an AI agent set it up for you (prompt)

Don't want to edit configs by hand? Paste the prompt below into **Claude Code**
(or any capable coding agent) and it will build the firewall and wrap every MCP
server in your config for you. Fill in the one bracketed path first:

> Set up **mcp-firewall** (an MCP security proxy) to protect my AI agent's tool calls.
>
> The repo is at: `[/absolute/path/to/mcp-firewall]` — clone it from
> https://github.com/defi0x1/mcp-firewall first if it isn't there.
>
> Do this:
> 1. In that repo, run `pnpm install` and `pnpm build` so `dist/cli.js` exists.
> 2. Read its `docs/INTEGRATION.md` and list the policies in `policies/examples/`.
> 3. Find my MCP client config (`.mcp.json` in this project, or `~/.claude.json` /
>    `~/.cursor/mcp.json`) and list the MCP servers I currently have configured.
> 4. Wrap each server with the firewall by changing its launch command to:
>    `"command": "node"`, `"args": ["<REPO>/dist/cli.js", "wrap", "--policy",
>    "<REPO>/policies/examples/<policy>.yaml", "--", <the server's ORIGINAL command and args>]`.
>    Pick the policy per server: `read-only.yaml` if it should only read,
>    `filesystem.yaml` for filesystem/shell servers, `paranoid.yaml` to approve
>    everything. Ask me if you're unsure which.
> 5. Show me the before/after diff of my config and wait for my confirmation
>    before writing it. Use absolute paths everywhere.
> 6. After I confirm, tell me how to watch the audit log
>    (`node <REPO>/dist/cli.js log`) and that `ask` rules open a browser tab for
>    approval.

That single prompt is the full setup — the agent does the clone/build, chooses
policies, and rewires your config with your sign-off.

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
