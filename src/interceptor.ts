/**
 * Audit interceptor (ROADMAP M2).
 *
 * A stateful `ProxyHook` that records every `tools/call`. The catch: a tool
 * call is TWO messages — a request going client→server, and a response coming
 * server→client, correlated by JSON-RPC `id`. So we:
 *
 *   1. On the `tools/call` request (c2s): remember tool, args, and start time,
 *      keyed by id.
 *   2. On the matching response (s2c): compute duration, summarize the result,
 *      and write one AuditRecord.
 *
 * In M2 we forward everything untouched — `decision` is always "allow" and
 * `findings` is empty. Policy (M3) and detectors (M4) will extend this without
 * changing the correlation machinery.
 */

import type { ProxyHook } from "./proxy.js";
import type { AuditRecord } from "./types.js";

/** Where completed records go. `AuditLog.append` fits this shape. */
export type AuditSink = (record: AuditRecord) => void;

interface PendingCall {
  tool: string;
  args: unknown;
  startedAt: number; // ms epoch
  ts: string; // ISO 8601 of initiation
}

export interface AuditInterceptorOptions {
  sink: AuditSink;
  /** Identifier for the upstream server (recorded on every record). */
  server: string;
  /** Injectable clock for testing; defaults to Date.now. */
  now?: () => number;
}

export class AuditInterceptor {
  private readonly pending = new Map<string, PendingCall>();
  private readonly sink: AuditSink;
  private readonly server: string;
  private readonly now: () => number;

  constructor(options: AuditInterceptorOptions) {
    this.sink = options.sink;
    this.server = options.server;
    this.now = options.now ?? (() => Date.now());
  }

  /** The hook to register on the proxy. Always forwards the message unchanged. */
  readonly hook: ProxyHook = (message, direction) => {
    if (direction === "c2s") {
      this.onOutbound(message);
    } else {
      this.onInbound(message);
    }
    return message; // M2: never block; just observe
  };

  private onOutbound(message: unknown): void {
    const call = asToolCallRequest(message);
    if (!call) return;
    this.pending.set(idKey(call.id), {
      tool: call.tool,
      args: call.args,
      startedAt: this.now(),
      ts: new Date(this.now()).toISOString(),
    });
  }

  private onInbound(message: unknown): void {
    const resp = asResponse(message);
    if (!resp) return;
    const key = idKey(resp.id);
    const call = this.pending.get(key);
    if (!call) return; // a response to something that wasn't a tracked tool call
    this.pending.delete(key);

    this.sink({
      ts: call.ts,
      server: this.server,
      tool: call.tool,
      args: call.args,
      decision: "allow",
      findings: [],
      durationMs: this.now() - call.startedAt,
      resultPreview: resp.isError ? undefined : summarize(resp.result),
      isError: resp.isError,
      error: resp.isError ? summarize(resp.error) : undefined,
    });
  }
}

// ── Message shape helpers ────────────────────────────────────────────────────
// JSON-RPC messages are an untyped union on the wire; narrow defensively.

type JsonRpcId = string | number;

function idKey(id: JsonRpcId): string {
  return String(id);
}

/** A `tools/call` request, if this message is one. */
function asToolCallRequest(
  message: unknown,
): { id: JsonRpcId; tool: string; args: unknown } | null {
  if (typeof message !== "object" || message === null) return null;
  const m = message as Record<string, unknown>;
  if (m.method !== "tools/call") return null;
  if (m.id === undefined) return null;
  const params = (m.params ?? {}) as Record<string, unknown>;
  const tool = typeof params.name === "string" ? params.name : "<unknown>";
  return { id: m.id as JsonRpcId, tool, args: params.arguments };
}

/** A response (result or error) with an id, if this message is one. */
function asResponse(
  message: unknown,
): { id: JsonRpcId; isError: boolean; result?: unknown; error?: unknown } | null {
  if (typeof message !== "object" || message === null) return null;
  const m = message as Record<string, unknown>;
  if (m.id === undefined || typeof m.method === "string") return null; // requests/notifications have a method
  if ("error" in m) return { id: m.id as JsonRpcId, isError: true, error: m.error };
  if ("result" in m) return { id: m.id as JsonRpcId, isError: false, result: m.result };
  return null;
}

/**
 * A short, safe preview of a value for the audit log. We never store the full
 * payload (it can be large and may contain secrets); a truncated JSON string is
 * enough for a human to recognize the call. Detectors (M4) scan the full result
 * live and store structured findings instead.
 */
const PREVIEW_MAX = 200;
function summarize(value: unknown): string {
  let s: string;
  try {
    s = typeof value === "string" ? value : JSON.stringify(value);
  } catch {
    s = String(value);
  }
  if (s === undefined) return "";
  return s.length > PREVIEW_MAX ? s.slice(0, PREVIEW_MAX) + "…" : s;
}
