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

## M1 — Transparent stdio proxy (the core) ✅ DONE

Goal: real Claude Code ↔ MCP traffic flows *through our code*, unmodified. This is the foundation; everything else hooks into it.

- [x] `src/proxy.ts`: spawn the real server as a subprocess; bridge two stdio transports (server-facing + client-facing)
- [x] Forward every request/response/notification in both directions untouched
- [x] `src/cli.ts`: `mcp-firewall wrap -- <server-cmd...>` launches the proxy
- [x] End-to-end test with a mock server (`test-support/mock-server.ts`) instead of MCP Inspector — repeatable, no network dep (`src/proxy.e2e.test.ts`)
- [x] Log a one-line passthrough entry to stderr for every message (temporary, proves flow)

**Verify:** ✅ `pnpm test` drives a full handshake (`initialize` → `tools/list` → `tools/call`) through the proxy and asserts correct responses; stderr shows passthrough lines; proxy exits cleanly on stdin EOF.

**Implementation notes for the next session:**
- Built at the **transport** layer (two `Stdio*Transport`s wired together), *not* the high-level `Server`/`Client` classes — this keeps forwarding truly transparent (no per-method schema parsing). See the header comment in `src/proxy.ts`.
- `Proxy` takes a `hooks: ProxyHook[]` array. **The audit interceptor (M2) and policy (M3) plug in here** — a hook is `(message, direction) => message | null`; returning `null` drops the message (that's how a policy `deny` will answer the client directly). The M1 passthrough logger in `cli.ts` is the example to replace/augment.
- Gotcha fixed: the SDK's `StdioServerTransport` never fires `onclose` on stdin EOF (only listens for `data`/`error`). The proxy adds its own `process.stdin.on("end"/"close")` handlers so it shuts down when the client disconnects. Don't remove those.

**Milestone demo:** "The agent can't tell the firewall is there — yet."

**→ Next session starts at M2 (audit log).**

---

## M2 — Audit log ✅ DONE

Goal: every tool call is recorded.

- [x] `src/audit/log.ts`: append `AuditRecord` as JSONL to `./.mcp-firewall/audit.jsonl` (serialized writes; `read()` for the log command)
- [x] `src/interceptor.ts`: intercept `tools/call`, correlate request↔response by id, capture args + result + duration, write a record
- [x] Wire the interceptor into the proxy (default hook on `wrap`; `--verbose` adds the M1 passthrough logger)
- [x] `mcp-firewall log` command: pretty-print the audit log
- [x] Unit test: interceptor produces correct records (`src/interceptor.test.ts` — 5 cases incl. errors, non-tool traffic, out-of-order correlation)

**Verify:** ✅ Ran a 3-call session; `mcp-firewall log` shows each call with args, result preview, decision, and timing. `pnpm test` (6 tests) + `pnpm typecheck` clean.

**Implementation notes for the next session:**
- Shared data shapes now live in `src/types.ts` (`Decision`, `Finding`, `AuditRecord`) — the source of truth; ARCHITECTURE.md mirrors it.
- The interceptor is a **stateful hook**: it keys pending calls by JSON-RPC id on the request and completes the record on the response. This request↔response correlation is the machinery M3/M4 build on. `decision` is hardcoded `"allow"` and `findings` is `[]` until then.
- `AuditRecord` gained `resultPreview` (truncated, never the full payload — secrets/size) and `isError`. These extend the ARCHITECTURE sketch; both docs updated.
- The interceptor takes injectable `sink` and `now` (see the unit test) — keep that seam; it's what makes the security logic testable without disk or wall-clock.

**Milestone demo:** "Here's every tool your agent called, replayable." (The `leak_secret` call's result preview already shows a fake AWS key — M4's detector target.)

**→ Next session starts at M3 (policy engine).**

---

## M3 — Policy engine ✅ DONE

Goal: allow / deny rules from YAML actually block calls.

- [x] `policies/default.yaml`: starter rules (deny destructive shell, ask on secret reads/writes) — matcher vocabulary now finalized
- [x] `src/policy/engine.ts`: load + zod-validate YAML, evaluate a tool call → `allow | deny | ask`
- [x] Matchers: tool-name glob (`globToRegex`), `args_regex`, `path_outside` (path-scope)
- [x] On `deny`: interceptor synthesizes an MCP `isError` result (D6), replies to client, blocks forwarding, and audits `decision: "deny"`
- [x] `--policy <file>` CLI flag (bad policy = refuse to start)
- [x] Unit tests: each matcher + eval order (`src/policy/engine.test.ts`, 12); deny/allow paths (`src/interceptor.test.ts`); deny path end-to-end (`src/proxy.e2e.test.ts`)

**Verify:** ✅ Demo run: `rm -rf` blocked (client gets "⛔ Blocked by mcp-firewall policy…", never reaches server), `ls`/`echo` pass; audit log shows `[DENY]`. `pnpm test` (21) + typecheck clean.

**Implementation notes for the next session:**
- The proxy gained a **`HookContext`** (`replyToClient` / `sendToServer`) — this is how a hook answers the client without forwarding. M4's approval flow reuses `replyToClient` the same way.
- **`ask` is NOT yet enforced.** In M3 an `ask` rule is recorded with `decision: "ask"` and the call is *still forwarded* (there's no approval UI yet). M4 makes `ask` actually block until the human approves. When you build M4, the change is in `AuditInterceptor.onOutbound`: the `ask` branch currently falls through to "pend + forward"; it needs to hold the call and wait for a decision (resolve OQ1 first — how the prompt reaches the human).
- Matchers live in `src/policy/engine.ts` and are exported (`globToRegex`, `matchesPathOutside`) for direct unit testing. Keep new matchers pure + exported.
- The interceptor's deny path writes the audit record **eagerly** (no response will come); allow/ask records are written on the response. Don't "unify" these — they're genuinely different lifecycles.

**Milestone demo:** "Watch the firewall block `rm -rf` in real time." ✅

**→ Next session starts at M4 (secrets detector + approval flow).**

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
