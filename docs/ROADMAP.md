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

## M4 — Secrets detector + approval flow ✅ DONE

Goal: catch secrets leaking through results; add the human-in-the-loop `ask` path.

- [x] `src/detectors/secrets.ts`: pure fn detecting AWS/GitHub/Slack tokens, private keys, generic secret assignments
- [x] `src/detectors/scan.ts`: aggregate detectors + `scanToolResult` (findings + redacted copy)
- [x] Interceptor runs detectors on results; findings go into the audit record
- [x] Redaction (OQ2): redact-and-annotate before returning to agent (`--no-redact` to disable); **audit log never stores raw secrets** (preview redacted, finding matches masked)
- [x] Resolve OQ1: approval via a **local web UI** (`src/approval/server.ts`) — auto-opens the browser, polls pending, click Approve/Deny, auto-denies on timeout
- [x] `ask` decisions recorded with `approved: true/false`; `deny`-by-human blocks like a policy deny
- [x] Unit tests: detector (8), scan/redact (6), approval server (3); interceptor ask+redaction (12 total); approval flow end-to-end (`proxy.e2e.test.ts`)

**Verify:** ✅ leak_secret result reaches agent redacted (`[REDACTED:aws-access-key]`), raw key absent from `audit.jsonl` on disk; ask-on-echo call held until approved via the web API, then forwarded. `pnpm test` (44) + typecheck clean.

**Implementation notes for the next session:**
- The approval flow works because **the proxy hook may be async** — the interceptor `await`s `Approver.request()`. Each c2s message is forwarded independently (`void this.forward(...)`), so one pending approval doesn't block other traffic.
- Approvals reuse `HookContext.replyToClient` (from M3) for the deny path — same synthetic `isError` result.
- Security refinement discovered mid-build: the audit log was storing raw secrets (in `resultPreview` and `Finding.match`). Fixed — the log always uses the redacted view and `maskFinding` truncates matches to `AKI…LE`. `--no-redact` only affects what the *agent* sees, never the on-disk log. (DESIGN OQ2 updated.)
- `--no-open` disables browser auto-open (headless/CI); tests pass `autoOpen: false`.
- Detectors are pure `(text) => Finding[]` and pattern-based (best-effort). Adding the **injection detector** (backlog) = a new `detect*` fn wired into `detectAll` in `scan.ts`; everything else already runs it.

**Milestone demo:** "The firewall stopped Claude from reading my `.env` back into its context — and asked me before writing outside the project." ✅

**→ Next session starts at M5 (ship v0.1).**

---

## M5 — Ship v0.1 🚧 (release-ready; a few maintainer steps remain)

**Distribution model:** NOT published to npm (`private: true`). Users run it from
a local clone of `github.com/defi0x1/mcp-firewall` (`pnpm install && pnpm build`,
then `node <REPO>/dist/cli.js …` or an optional `pnpm link --global`). The README
documents two paths: manual/dev use, and an AI-agent setup prompt.

- [x] README rewritten as a landing page — install-from-source + the two usage paths (manual, AI-agent prompt); **GIF/asciinema still to record** (placeholder in README)
- [x] Runs from the built artifact — `node dist/cli.js` blocks a call end-to-end; `bin` + `pnpm link --global` give a global `mcp-firewall` command
- [x] Config docs: `docs/INTEGRATION.md` (Claude Code / Cursor / Windsurf) using `node <REPO>/dist/cli.js`
- [x] Example policies: `policies/examples/{read-only,filesystem,paranoid}.yaml` (all validated against the schema)
- [x] LICENSE (MIT, © Cristian) + CONTRIBUTING.md
- [x] `package.json`: v0.1.0, `private: true`, author, GitHub repo/homepage/bugs (defi0x1)
- [ ] **Record a demo GIF/asciinema** and drop it in the README (maintainer)
- [ ] **Push to GitHub**: create `github.com/defi0x1/mcp-firewall` and `git push -u origin main` (maintainer)
- [ ] **Real-world smoke test**: `node <REPO>/dist/cli.js wrap --policy <REPO>/policies/examples/filesystem.yaml -- npx -y @modelcontextprotocol/server-filesystem <dir>` inside Claude Code; confirm audit/deny/redact/approve against a *real* server (all tests so far use the mock) (maintainer)
- [ ] **Tag `v0.1.0`**: `git tag v0.1.0 && git push --tags` (maintainer)

**Verify:** ✅ built artifact blocks a call; ✅ 44 tests + typecheck pass. Remaining: push to GitHub + the real-server smoke test, which needs a browser + a live MCP server (maintainer).

**Implementation notes:**
- `dist/` is gitignored — users build it themselves after cloning. If you ever want a zero-build install, either commit `dist/` or add a `prepare` script; for now the README's `pnpm build` step covers it.
- `private: true` blocks `npm publish` (intentional — GitHub-only distribution). It does **not** affect `pnpm link --global` or GitHub.
- The audit log lands in the *server's cwd* (`.mcp-firewall/`), which under an MCP client is wherever the client launches the server — mention this to users who "can't find the log".

---

## Later (backlog, not scheduled)

- Injection detector: scan tool *results* (fetched web pages, file contents) for prompt-injection payloads
- MCP server scanner: analyze tool descriptions at connect-time for tool-poisoning
- Streamable HTTP transport
- Trace-viewer web UI over the JSONL log
- Multiplex multiple upstream servers behind one proxy (OQ3)
- Policy rule packs (shareable, per-ecosystem)
