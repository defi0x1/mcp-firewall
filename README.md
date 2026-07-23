# mcp-firewall 🛡️

A local-first security proxy for AI agents. It sits between any [MCP](https://modelcontextprotocol.io) client (Claude Code, Cursor, Windsurf, …) and the MCP servers it uses, giving you:

- **Audit** — every tool call and result recorded to a replayable JSONL log
- **Policy** — allow / deny / ask rules in plain YAML (`deny: bash("rm -rf *")`)
- **Detect** — flag secrets leaking through tool results, prompt-injection payloads in fetched content, and dangerous commands

Think *"Little Snitch for AI agents."* Because MCP is a standard protocol, one proxy works with every MCP-speaking agent — no per-tool integration.

```
Agent ──→ 🛡️ mcp-firewall ──→ MCP server (filesystem, github, shell, …)
                 │
                 ├─ policy engine   (allow / deny / ask)
                 ├─ detectors        (secrets, injection, dangerous ops)
                 └─ audit log         (JSONL, replayable)
```

## Status

🚧 Early development. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the milestone plan.

## Quick start

```bash
pnpm install
pnpm dev            # runs the proxy against an example server
```

## Docs

- [Architecture](docs/ARCHITECTURE.md) — how the proxy is wired
- [Design decisions](docs/DESIGN.md) — why it's built this way
- [Roadmap](docs/ROADMAP.md) — milestones and task checklist

## License

MIT
