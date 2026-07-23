/**
 * Audit + policy interceptor (ROADMAP M2 + M3).
 *
 * A stateful `ProxyHook` that (a) enforces the policy on each `tools/call` and
 * (b) records every call to the audit log.
 *
 * A tool call is TWO messages — a request (client→server) and a response
 * (server→client), correlated by JSON-RPC `id`. So we:
 *
 *   1. On the `tools/call` request (c2s): evaluate the policy.
 *        - deny → reply to the client with a synthetic "blocked" tool error,
 *                 write a deny record, and DON'T forward (return null).
 *        - allow/ask → remember tool/args/decision keyed by id, forward.
 *   2. On the matching response (s2c): compute duration, summarize the result,
 *      and write the record with the decision we stashed.
 *
 * M3 note: `ask` currently behaves like allow-and-record (it's logged with
 * decision "ask" but still forwarded) — the human approval flow that actually
 * blocks on `ask` lands in M4. Deny fully blocks now.
 */

import type { ProxyHook, HookContext } from "./proxy.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { AuditRecord, Decision } from "./types.js";
import type { PolicyEngine } from "./policy/engine.js";

/** Where completed records go. `AuditLog.append` fits this shape. */
export type AuditSink = (record: AuditRecord) => void;

interface PendingCall {
  tool: string;
  args: unknown;
  startedAt: number; // ms epoch
  ts: string; // ISO 8601 of initiation
  decision: Decision; // "allow" | "ask" (deny never pends — no response expected)
  rule?: string;
  reason?: string;
}

export interface AuditInterceptorOptions {
  sink: AuditSink;
  /** Identifier for the upstream server (recorded on every record). */
  server: string;
  /** Optional policy. Without one, every call is allowed. */
  policy?: PolicyEngine;
  /** Optional notification when a call is decided (for stderr UX). */
  onDecision?: (record: AuditRecord) => void;
  /** Injectable clock for testing; defaults to Date.now. */
  now?: () => number;
}

export class AuditInterceptor {
  private readonly pending = new Map<string, PendingCall>();
  private readonly sink: AuditSink;
  private readonly server: string;
  private readonly policy?: PolicyEngine;
  private readonly onDecision?: (record: AuditRecord) => void;
  private readonly now: () => number;

  constructor(options: AuditInterceptorOptions) {
    this.sink = options.sink;
    this.server = options.server;
    this.policy = options.policy;
    this.onDecision = options.onDecision;
    this.now = options.now ?? (() => Date.now());
  }

  /** The hook to register on the proxy. */
  readonly hook: ProxyHook = (message, direction, ctx) => {
    if (direction === "c2s") {
      const forward = this.onOutbound(message, ctx);
      return forward ? message : null;
    }
    this.onInbound(message);
    return message;
  };

  /** Returns true if the message should be forwarded to the server. */
  private onOutbound(message: unknown, ctx: HookContext): boolean {
    const call = asToolCallRequest(message);
    if (!call) return true; // not a tool call — pass through untouched

    const verdict = this.policy?.evaluate({ tool: call.tool, args: call.args }) ?? {
      decision: "allow" as Decision,
    };

    if (verdict.decision === "deny") {
      // Block: answer the client directly with a tool error so the agent sees
      // it was denied and can adapt (DESIGN D6), and never touch the server.
      ctx.replyToClient(blockedResult(call.id, verdict.rule, verdict.reason));
      const record: AuditRecord = {
        ts: new Date(this.now()).toISOString(),
        server: this.server,
        tool: call.tool,
        args: call.args,
        decision: "deny",
        rule: verdict.rule,
        reason: verdict.reason,
        findings: [],
        durationMs: 0,
      };
      this.sink(record);
      this.onDecision?.(record);
      return false; // do not forward
    }

    // allow or ask: remember it and let it through. The record is written when
    // the response comes back.
    this.pending.set(idKey(call.id), {
      tool: call.tool,
      args: call.args,
      startedAt: this.now(),
      ts: new Date(this.now()).toISOString(),
      decision: verdict.decision,
      rule: verdict.rule,
      reason: verdict.reason,
    });
    return true;
  }

  private onInbound(message: unknown): void {
    const resp = asResponse(message);
    if (!resp) return;
    const key = idKey(resp.id);
    const call = this.pending.get(key);
    if (!call) return; // a response to something that wasn't a tracked tool call
    this.pending.delete(key);

    const record: AuditRecord = {
      ts: call.ts,
      server: this.server,
      tool: call.tool,
      args: call.args,
      decision: call.decision,
      rule: call.rule,
      reason: call.reason,
      findings: [],
      durationMs: this.now() - call.startedAt,
      resultPreview: resp.isError ? undefined : summarize(resp.result),
      isError: resp.isError,
      error: resp.isError ? summarize(resp.error) : undefined,
    };
    this.sink(record);
    this.onDecision?.(record);
  }
}

// ── Synthetic responses ───────────────────────────────────────────────────────

/**
 * A CallToolResult with `isError: true`. Per the MCP spec, tool *execution*
 * failures are reported this way (not as JSON-RPC protocol errors) so the model
 * sees the error content and can react — exactly what we want for a policy block.
 */
function blockedResult(id: JsonRpcId, rule?: string, reason?: string): JSONRPCMessage {
  const ruleText = rule ? ` (rule: ${rule})` : "";
  const reasonText = reason ? ` — ${reason}` : "";
  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [
        {
          type: "text",
          text: `⛔ Blocked by mcp-firewall policy${ruleText}${reasonText}`,
        },
      ],
      isError: true,
    },
  } as JSONRPCMessage;
}

// ── Message shape helpers ────────────────────────────────────────────────────

type JsonRpcId = string | number;

function idKey(id: JsonRpcId): string {
  return String(id);
}

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

function asResponse(
  message: unknown,
): { id: JsonRpcId; isError: boolean; result?: unknown; error?: unknown } | null {
  if (typeof message !== "object" || message === null) return null;
  const m = message as Record<string, unknown>;
  if (m.id === undefined || typeof m.method === "string") return null;
  if ("error" in m) return { id: m.id as JsonRpcId, isError: true, error: m.error };
  if ("result" in m) return { id: m.id as JsonRpcId, isError: false, result: m.result };
  return null;
}

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
