# Design decisions

Each entry: the decision, the reasoning, and the alternatives we rejected. When a future session revisits a choice, update the entry rather than deleting it.

## D1. Intercept at the MCP protocol layer, not the LLM API layer

**Decision:** Sit between MCP client and MCP server, not between the agent and the model.

**Why:** MCP is a single standardized protocol. One proxy works with every MCP client (Claude Code, Cursor, Windsurf, Cline, …) with zero per-client integration. Intercepting at the LLM API layer (e.g. wrapping `messages.create`) would tie us to one SDK and one vendor, and would miss tool calls routed through MCP anyway.

**Rejected:** LLM-API-level proxy (vendor lock-in); per-framework plugins (N integrations to maintain).

## D2. stdio transport first

**Decision:** Implement the stdio transport before Streamable HTTP.

**Why:** Local stdio servers are how Claude Code and Cursor run filesystem/shell/git tools today — the highest-risk, most-common case. HTTP is for remote servers and can follow.

## D3. TypeScript + official MCP SDK

**Decision:** Build in TypeScript on `@modelcontextprotocol/sdk`.

**Why:** The MCP SDK is TypeScript-first and best-maintained; the MCP ecosystem and its users live in npm. The maintainer (you) already works in TS. Using the official SDK's `Client` and `Server` classes means we speak protocol correctly instead of hand-rolling JSON-RPC.

**Rejected:** Python (SDK exists but ecosystem tooling is TS-centric); hand-rolled JSON-RPC (correctness risk, wasted effort).

## D4. Detectors are pure functions

**Decision:** Every detector is `(input) => Finding[]` with no side effects.

**Why:** Trivially unit-testable, composable, and safe to run in any order. The interceptor owns all I/O (forwarding, logging, prompting); detectors only analyze. This keeps the security logic — the part that must be correct — isolated and easy to reason about.

## D5. Policy as declarative YAML

**Decision:** Security rules live in a YAML file, not in code.

**Why:** Users must be able to read, review, and version-control their security policy without editing TypeScript. Declarative rules also make the "why was this blocked?" question answerable by pointing at a line in a file. Start with a small matcher vocabulary (tool name globs, arg predicates) and grow it.

**Rejected:** Rules-as-code (not user-editable); a full policy DSL (over-engineering for v0.1).

## D6. Fail-safe defaults, but don't break the agent silently

**Decision:** On `deny`, return a well-formed MCP error result to the client (so the agent *sees* it was blocked and can adapt), rather than dropping the message or crashing.

**Why:** A silently swallowed tool call makes the agent hang or hallucinate success. A clear error ("blocked by policy: rule X") lets the agent explain to the user and try another path. Security tools that break the workflow get uninstalled.

## D7. Audit log is append-only JSONL

**Decision:** One JSON object per line, append-only.

**Why:** Streamable, greppable, replayable, and trivial to build a trace-viewer UI on later. No schema migrations, no database dependency for v0.1.

## D8. Bridge at the transport layer, not the high-level Client/Server classes

**Decision (M1):** The proxy wires two SDK `Transport`s together directly (`StdioServerTransport` ↔ `StdioClientTransport`) and forwards raw `JSONRPCMessage`s, rather than instantiating the SDK's high-level `Server`/`Client` classes with registered per-method handlers.

**Why:** The high-level classes parse and validate each method against its schema and expect you to *handle* requests. For a transparent proxy we want the opposite — forward every message (including methods and future protocol extensions we don't know about) untouched. The `Transport` interface (`send` / `onmessage`) is exactly a byte-faithful pipe. This makes the proxy forward-compatible with protocol additions and keeps the security logic (hooks) separate from protocol plumbing.

**Consequence / gotcha:** `StdioServerTransport` only listens for stdin `data`/`error`, so it never fires `onclose` on EOF. The proxy adds its own `process.stdin` end/close handlers to shut down when the client disconnects. (Recorded here so it isn't "cleaned up" later as dead code.)

## D9. The audit log must never store raw secrets (M4)

**Decision:** The on-disk audit log (`.mcp-firewall/audit.jsonl`) never contains a raw detected secret. `resultPreview` is computed from the *redacted* result, and each `Finding.match` is masked (`maskFinding`: `AKI…LE`) before the record is written. This holds even under `--no-redact`.

**Why:** A security tool that writes the very secrets it detects into a plaintext log on disk is a leak vector, not a mitigation. Discovered during M4 (the first draft previewed the raw key). `--no-redact` controls only what the *agent* sees — the log is redacted unconditionally. The interceptor still uses the raw match internally to *perform* redaction; masking happens only at the persistence boundary.

## Resolved questions

- **OQ1 (resolved M4): local web UI.** Under stdio the MCP client owns the terminal, so we can't prompt there. `ApprovalServer` (`src/approval/server.ts`) serves a self-contained page on a random localhost port, auto-opens the browser on the first pending approval (`--no-open` to disable), and auto-denies on timeout so the agent never hangs. Plain `node:http`, no web framework (minimal attack surface).
- **OQ2 (resolved M4): redact-and-annotate, on by default.** Detected secrets are replaced with `[REDACTED:<detector>]` before the agent sees the result. `--no-redact` downgrades to warn-only (findings still recorded). See also D9 for the audit-log side.

## Open questions (decide as we build)

- **OQ3.** Multiple upstream servers behind one proxy, or one proxy per server? — *Leaning: one-per-server for v0.1 (simpler), multiplex later.*
