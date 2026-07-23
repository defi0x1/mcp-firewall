# CLAUDE.md

Instructions for any Claude session working on this project.

## What this is

`mcp-firewall` — a local-first security proxy for AI agents. It sits between an MCP client and an MCP server and provides audit logging, policy enforcement (allow/deny/ask), and detectors (secrets, injection, dangerous ops). Read `README.md` for the pitch, `docs/ARCHITECTURE.md` for how it's wired, `docs/DESIGN.md` for why.

**This is a learning project for the maintainer.** When you implement something non-obvious, leave a short comment explaining *why*, and prefer clear code over clever code. The maintainer is learning how AI agents and MCP work by building this — favor explanations that teach.

## How to work on this

1. Read this file, then `docs/ARCHITECTURE.md` and `docs/DESIGN.md`.
2. Make one focused change at a time; run `pnpm typecheck && pnpm test` before committing.
3. Add/extend tests for anything security-relevant (policy matchers, detectors).
4. Commit with a clear, scoped message describing the change and its reasoning.
5. If a design decision changes, update `docs/DESIGN.md` (edit the entry, don't delete history).

Show your work. The core is layered — the proxy is the foundation, and audit /
policy / detectors / approvals all plug into its `hooks` array; keep that shape.

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
- When unsure between two approaches, check `docs/DESIGN.md` Open Questions; if it's not there, ask the maintainer rather than guessing on a security-relevant choice.

## Current state — v0.1, feature-complete

The full pipeline works (44 tests passing):
- `src/proxy.ts` — transparent client↔server bridge; `hooks` array + `HookContext` (`replyToClient`). Hooks may be async.
- `src/interceptor.ts` — audit + policy + detectors, correlating `tools/call` request↔response by id.
- `src/policy/engine.ts` — YAML allow/deny/ask rules (3 matchers).
- `src/detectors/` — pure secret detectors + `scanToolResult` (findings + redacted copy).
- `src/approval/server.ts` — local web UI for `ask` approvals (auto-opens browser, timeout auto-deny).
- Audit log (`.mcp-firewall/audit.jsonl`) never stores raw secrets (D9).

CLI: `mcp-firewall wrap [--policy <f>] [--no-redact] [--no-open] [--verbose] -- <server>` and `mcp-firewall log`.

**Distribution: GitHub-only, run from source — NOT npm.** `package.json` has `private: true`. Users clone `github.com/defi0x1/mcp-firewall`, `pnpm install && pnpm build`, then run `node <REPO>/dist/cli.js …` (or `pnpm link --global` for a global `mcp-firewall` command). README documents two paths: (1) manual/dev use, (2) an AI-agent setup prompt that does the whole thing. Do NOT re-add npm-publish steps or make it public without the maintainer asking.

**Maintainer to-dos before tagging v0.1:** record a demo GIF for the README, push to GitHub (`defi0x1`), run a real-server smoke test in Claude Code, then `git tag v0.1.0`.

**Ideas for later** (not scheduled): prompt-injection detection in tool results, MCP-server scanning at connect-time, remote (Streamable HTTP) transport, a trace-viewer UI over the JSONL log, multiplexing several upstream servers behind one proxy (DESIGN OQ3).
