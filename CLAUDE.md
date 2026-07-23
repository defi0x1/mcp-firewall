# CLAUDE.md

Instructions for any Claude session working on this project.

## What this is

`mcp-firewall` — a local-first security proxy for AI agents. It sits between an MCP client and an MCP server and provides audit logging, policy enforcement (allow/deny/ask), and detectors (secrets, injection, dangerous ops). Read `README.md` for the pitch, `docs/ARCHITECTURE.md` for how it's wired, `docs/DESIGN.md` for why.

**This is a learning project for the maintainer.** When you implement something non-obvious, leave a short comment explaining *why*, and prefer clear code over clever code. The maintainer is learning how AI agents and MCP work by building this — favor explanations that teach.

## How to resume work

1. Read this file, then `docs/ROADMAP.md`.
2. Find the first milestone that isn't fully checked; do its **next unchecked task**.
3. Run that task's **Verify** step. Don't check the box until it actually passes.
4. Commit with a message referencing the milestone (e.g. `M2: audit log writes JSONL`).
5. If a design decision changes, update `docs/DESIGN.md` (edit the entry, don't delete history).

Do one milestone task at a time. Show your work. Don't jump ahead — the roadmap order is intentional (the proxy core must exist before anything hooks into it).

## Conventions

- **Language/runtime:** TypeScript, Node 25, pnpm. ESM (`"type": "module"`) — no `__dirname`; use `import.meta.url`.
- **MCP:** use `@modelcontextprotocol/sdk` (`Client`, `Server`, transports). Don't hand-roll JSON-RPC.
- **Detectors are pure functions:** `(input) => Finding[]`, no I/O. All I/O lives in the interceptor.
- **Tests:** vitest, colocated as `*.test.ts`. Every detector and policy matcher gets tests.
- **Validation:** zod for parsing external data (config files, message args).
- **Security code must be correct.** For the policy engine and detectors, write the test first or alongside.

## Commands

```bash
pnpm install
pnpm dev        # run the CLI (src/cli.ts via tsx)
pnpm test       # vitest
pnpm build      # tsc → dist/
```

## Guardrails

- Don't add dependencies casually — this is a security tool; every dep is attack surface. Justify new deps in the commit message.
- Don't commit real secrets or real audit logs. `.mcp-firewall/` is gitignored.
- Keep `docs/ROADMAP.md` truthful — it's the single source of progress. If reality diverges from the plan, fix the plan.
- When unsure between two approaches, check `docs/DESIGN.md` Open Questions; if it's not there, ask the maintainer rather than guessing on a security-relevant choice.

## Current state

M0–M4 complete (44 tests passing). Full pipeline works:
- `src/proxy.ts` — transparent client↔server bridge; `hooks` array + `HookContext` (`replyToClient`). Hooks may be async.
- `src/interceptor.ts` — audit + policy + detectors, correlating `tools/call` request↔response by id.
- `src/policy/engine.ts` — YAML allow/deny/ask rules (3 matchers).
- `src/detectors/` — pure secret detectors + `scanToolResult` (findings + redacted copy).
- `src/approval/server.ts` — local web UI for `ask` approvals (auto-opens browser, timeout auto-deny).
- Audit log (`.mcp-firewall/audit.jsonl`) never stores raw secrets (D9).

CLI: `mcp-firewall wrap [--policy <f>] [--no-redact] [--no-open] [--verbose] -- <server>` and `mcp-firewall log`.

**M5 is release-ready.** Done: README landing page, `docs/INTEGRATION.md`, example policies, LICENSE, CONTRIBUTING, package.json v0.1.0 metadata, `prepublishOnly` gate, verified built artifact. `npm pack --dry-run` is clean.

**Remaining M5 items need the maintainer** (credentials / browser / a real server) — see `docs/ROADMAP.md` M5 unchecked boxes: record a demo GIF, set the real GitHub URL (replace `YOUR_USERNAME` in package.json), run a real-server smoke test in Claude Code, `npm publish`, and `git tag v0.1.0`. After v0.1 ships, the backlog (injection detector, MCP-server scanner, HTTP transport, trace-viewer UI) is at the bottom of `docs/ROADMAP.md`.
