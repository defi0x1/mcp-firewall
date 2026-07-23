# Architecture

## The one big idea

MCP (Model Context Protocol) is a **standardized JSON-RPC protocol** between an agent ("client") and a tool provider ("server"). Every MCP client speaks the same wire format. That gives us a single universal interception point: if we build a program that is *an MCP server to the client* and *an MCP client to the real server*, we can sit in the middle of any agent's tool use without integrating with the agent at all.

```
┌─────────────┐   MCP    ┌──────────────────────────┐   MCP    ┌─────────────┐
│  MCP client │ ───────► │       mcp-firewall        │ ───────► │  MCP server │
│ (Claude Code│ ◄─────── │  (server side | client    │ ◄─────── │ (filesystem,│
│  Cursor, …) │          │   side, wired together)   │          │  shell, …)  │
└─────────────┘          └──────────────────────────┘          └─────────────┘
```

To the agent, `mcp-firewall` *is* the server. To the real server, `mcp-firewall` *is* the client. Everything flows through us.

## Transports

MCP runs over two transports; we support both because different clients use different ones:

- **stdio** — the server is a subprocess; messages are newline-delimited JSON-RPC over stdin/stdout. This is what Claude Code / Cursor use for local servers. **We implement this first.**
- **Streamable HTTP** — the server is a URL; used for remote/hosted servers. Added later.

For stdio, our proxy is launched by the client as *the* server command, and we in turn spawn the real server as our own subprocess.

## Message flow

Every JSON-RPC message is one of: a **request** (has `id` + `method`), a **response** (has `id` + `result`/`error`), or a **notification** (has `method`, no `id`). We care most about two request methods:

- `tools/list` — the server advertises its tools. We pass through, but may *inspect* tool descriptions (injection / tool-poisoning checks live here later).
- `tools/call` — the agent invokes a tool. **This is the security-critical path.** Here the policy engine and detectors run.

```
                       tools/call request
   client ──────────────────────────────────────────► firewall
                                                          │
                                                 ┌────────▼─────────┐
                                                 │  1. POLICY check  │  allow / deny / ask
                                                 └────────┬─────────┘
                                    deny │ ask(denied)     │ allow / ask(approved)
                          ┌───────────────┘                 │
                          ▼                                  ▼
              synth. error response              forward request to real server
                          │                                  │
                          │                          real result comes back
                          │                                  │
                          │                         ┌────────▼─────────┐
                          │                         │  2. DETECTORS     │  scan result
                          │                         │  (secrets, etc.)  │  redact / annotate
                          │                         └────────┬─────────┘
                          │                                  │
                          └──────────────► AUDIT LOG ◄───────┘
                                                │
                          both paths write a record, then the (possibly
                          modified) response is returned to the client
```

## Components

| Component | Responsibility | File (planned) |
|---|---|---|
| **Proxy core** | Wire client transport ↔ server transport; route messages | `src/proxy.ts` |
| **Interceptor** | Hook `tools/call` (and `tools/list`); orchestrate policy → forward → detect → audit | `src/interceptor.ts` |
| **Policy engine** | Evaluate YAML rules against a tool call → `allow` / `deny` / `ask` | `src/policy/engine.ts` |
| **Detectors** | Pure functions: `(text) → findings[]`. Secrets, injection, dangerous ops | `src/detectors/*.ts` |
| **Audit log** | Append structured records to JSONL | `src/audit/log.ts` |
| **Approval UI** | For `ask`: prompt the human (terminal first, richer later) | `src/approval/*.ts` |
| **CLI** | `mcp-firewall wrap <server-cmd>` entry point | `src/cli.ts` |

## Data shapes

**The source of truth is `src/types.ts`.** This mirror is kept in sync for readers who don't want to open the code.

```ts
// A detector's output
interface Finding {
  detector: string;      // "secrets" | "injection" | "dangerous-op"
  severity: "low" | "medium" | "high";
  message: string;
  match?: string;        // the offending substring (may be redacted in logs)
}

// One audit record (one JSONL line)
interface AuditRecord {
  ts: string;            // ISO 8601, when the call was initiated
  server: string;        // identifier of the wrapped upstream server
  tool: string;
  args: unknown;
  decision: "allow" | "deny" | "ask";
  approved?: boolean;    // for `ask`
  findings: Finding[];
  durationMs?: number;   // request → response wall time
  resultPreview?: string; // short, truncated result summary — NEVER the full payload
  isError?: boolean;     // the tool result carried an MCP error
  error?: string;        // proxy-level error text
}
```

> Note on how the interceptor works with a tool call: it does **not** hold a single `ToolCall` object end-to-end. A call is two wire messages (request + response) correlated by JSON-RPC `id`; the interceptor keeps a small pending-map keyed by id and emits the `AuditRecord` when the response arrives. See `src/interceptor.ts`.

## Non-goals (for now)

- Not a cloud service. Local-first, runs on the developer's machine.
- Not model-specific. It operates on the MCP protocol, not on any LLM API.
- Not a sandbox. It observes and gates tool calls; it does not isolate the server's process. (Sandboxing may come later as an optional layer.)
