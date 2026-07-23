# Roadmap

The plan a future session follows to build this to a working v0.1 and beyond. Work top to bottom. Check boxes as you go (`- [x]`). Each milestone ends in something demoable. Keep this file honest: if a task turns out wrong, edit it.

**How to resume this project (for Claude):** read `CLAUDE.md`, then this file. Find the first unchecked milestone, do the next unchecked task, run its verification, check the box, commit. Update `docs/DESIGN.md` when a decision changes.

---

## M0 — Project skeleton ✅ DONE

- [x] Repo + git init
- [x] README, ARCHITECTURE, DESIGN, ROADMAP, CLAUDE.md
- [x] `package.json`, `tsconfig.json`, `.gitignore`
- [x] Install deps: `@modelcontextprotocol/sdk`, `zod`, `yaml`, `tsx`, `typescript`, `vitest`, `@types/node`
- [x] `src/cli.ts` stub that prints usage
- [x] First commit

**Verify:** ✅ `pnpm install` succeeds; `pnpm dev` prints usage; `pnpm typecheck` passes.

**→ Next session starts at M1.**

---

## M1 — Transparent stdio proxy (the core)

Goal: real Claude Code ↔ MCP traffic flows *through our code*, unmodified. This is the foundation; everything else hooks into it.

- [ ] `src/proxy.ts`: spawn the real server as a subprocess; create an MCP `Server` facing the client and an MCP `Client` facing the upstream
- [ ] Forward every request/response/notification in both directions untouched
- [ ] `src/cli.ts`: `mcp-firewall wrap -- <server-cmd...>` launches the proxy
- [ ] Manual test: wrap the official `@modelcontextprotocol/server-filesystem`, point Claude Code (or MCP Inspector) at the firewall, confirm tools work end-to-end
- [ ] Log a one-line "passthrough: <method>" to stderr for every message (temporary, proves flow)

**Verify:** Using MCP Inspector, `tools/list` and a `tools/call` against a wrapped filesystem server return correct results, and stderr shows the passthrough lines.

**Milestone demo:** "The agent can't tell the firewall is there — yet."

---

## M2 — Audit log

Goal: every tool call is recorded.

- [ ] `src/audit/log.ts`: append `AuditRecord` (see ARCHITECTURE) as JSONL to `./.mcp-firewall/audit.jsonl`
- [ ] `src/interceptor.ts`: intercept `tools/call`, capture args + result + duration, write a record
- [ ] Wire the interceptor into the proxy
- [ ] `mcp-firewall log` command: pretty-print the audit log
- [ ] Unit test: interceptor produces a correct record for a mock call

**Verify:** After a session, `mcp-firewall log` shows each tool call with args, result summary, and timing.

**Milestone demo:** "Here's every tool your agent called, replayable."

---

## M3 — Policy engine

Goal: allow / deny rules from YAML actually block calls.

- [ ] `policies/default.yaml`: starter rules (deny destructive shell, ask on writes outside cwd)
- [ ] `src/policy/engine.ts`: load YAML, evaluate a `ToolCall` → `allow | deny | ask`
- [ ] Matchers: tool-name glob, arg substring/regex, path-scope predicate
- [ ] On `deny`: interceptor returns an MCP error result (D6), still audits
- [ ] `--policy <file>` CLI flag
- [ ] Unit tests: each matcher; deny path returns a proper error

**Verify:** A rule `deny bash("rm *")` blocks that call (agent gets a clear error) while other calls pass; the block is in the audit log with `decision: "deny"`.

**Milestone demo:** "Watch the firewall block `rm -rf` in real time."

---

## M4 — Secrets detector + approval flow

Goal: catch secrets leaking through results; add the human-in-the-loop `ask` path.

- [ ] `src/detectors/secrets.ts`: pure fn detecting API keys/tokens (AWS, GitHub, generic high-entropy) in tool results
- [ ] Interceptor runs detectors on results; findings go into the audit record
- [ ] Redaction per OQ2 (default: redact-and-annotate before returning to agent)
- [ ] Resolve OQ1: approval UI for `ask` (local web UI on a port — spike first)
- [ ] `ask` decisions recorded with `approved: true/false`
- [ ] Unit tests: secrets detector true/false positives; redaction

**Verify:** A tool result containing a fake AWS key is flagged, redacted before the agent sees it, and logged; an `ask` rule prompts and records the human's choice.

**Milestone demo:** "The firewall stopped Claude from reading my `.env` back into its context."

---

## M5 — Ship v0.1

- [ ] README with a real GIF/asciinema demo
- [ ] `npx mcp-firewall` works (bin entry, build step)
- [ ] Config docs: how to add the firewall to Claude Code / Cursor MCP config
- [ ] Handful of realistic example policies
- [ ] LICENSE (MIT), CONTRIBUTING, publish to npm
- [ ] Tag `v0.1.0`

**Verify:** A fresh machine can `npx mcp-firewall wrap -- <server>`, add it to Claude Code, and see audit + policy working.

---

## Later (backlog, not scheduled)

- Injection detector: scan tool *results* (fetched web pages, file contents) for prompt-injection payloads
- MCP server scanner: analyze tool descriptions at connect-time for tool-poisoning
- Streamable HTTP transport
- Trace-viewer web UI over the JSONL log
- Multiplex multiple upstream servers behind one proxy (OQ3)
- Policy rule packs (shareable, per-ecosystem)
