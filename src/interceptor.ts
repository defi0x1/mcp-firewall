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
import type { Approver } from "./approval/types.js";
import { scanToolResult } from "./detectors/scan.js";

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
  approved?: boolean; // set for `ask` calls once the human decides
}

export interface AuditInterceptorOptions {
  sink: AuditSink;
  /** Identifier for the upstream server (recorded on every record). */
  server: string;
  /** Optional policy. Without one, every call is allowed. */
  policy?: PolicyEngine;
  /** Optional approver for `ask` decisions. Without one, `ask` behaves as allow. */
  approver?: Approver;
  /** Redact detected secrets from results before the agent sees them (default true). */
  redactSecrets?: boolean;
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
  private readonly approver?: Approver;
  private readonly redactSecrets: boolean;
  private readonly onDecision?: (record: AuditRecord) => void;
  private readonly now: () => number;

  constructor(options: AuditInterceptorOptions) {
    this.sink = options.sink;
    this.server = options.server;
    this.policy = options.policy;
    this.approver = options.approver;
    this.redactSecrets = options.redactSecrets ?? true;
    this.onDecision = options.onDecision;
    this.now = options.now ?? (() => Date.now());
  }

  /** The hook to register on the proxy. Async so `ask` can await a human. */
  readonly hook: ProxyHook = async (message, direction, ctx) => {
    if (direction === "c2s") {
      const forward = await this.onOutbound(message, ctx);
      return forward ? message : null;
    }
    return this.onInbound(message); // may be redacted
  };

  /** Returns true if the message should be forwarded to the server. */
  private async onOutbound(message: unknown, ctx: HookContext): Promise<boolean> {
    const call = asToolCallRequest(message);
    if (!call) return true; // not a tool call — pass through untouched

    const verdict = this.policy?.evaluate({ tool: call.tool, args: call.args }) ?? {
      decision: "allow" as Decision,
    };

    if (verdict.decision === "deny") {
      // Block: answer the client directly with a tool error so the agent sees
      // it was denied and can adapt (DESIGN D6), and never touch the server.
      ctx.replyToClient(blockedResult(call.id, verdict.rule, verdict.reason));
      this.emit({
        ts: new Date(this.now()).toISOString(),
        server: this.server,
        tool: call.tool,
        args: call.args,
        decision: "deny",
        rule: verdict.rule,
        reason: verdict.reason,
        findings: [],
        durationMs: 0,
      });
      return false; // do not forward
    }

    // `ask`: block on a human decision if we have an approver. Without one,
    // `ask` degrades to allow-and-record (M3 behavior).
    let approved: boolean | undefined;
    if (verdict.decision === "ask" && this.approver) {
      approved = await this.approver.request({
        server: this.server,
        tool: call.tool,
        args: call.args,
        rule: verdict.rule,
        reason: verdict.reason,
      });
      if (!approved) {
        ctx.replyToClient(
          blockedResult(call.id, verdict.rule, verdict.reason ?? "Denied by operator"),
        );
        this.emit({
          ts: new Date(this.now()).toISOString(),
          server: this.server,
          tool: call.tool,
          args: call.args,
          decision: "ask",
          approved: false,
          rule: verdict.rule,
          reason: verdict.reason,
          findings: [],
          durationMs: 0,
        });
        return false; // human denied
      }
    }

    // allow, or approved ask: remember it and let it through. The record is
    // written when the response comes back (so it includes result findings).
    this.pending.set(idKey(call.id), {
      tool: call.tool,
      args: call.args,
      startedAt: this.now(),
      ts: new Date(this.now()).toISOString(),
      decision: verdict.decision,
      rule: verdict.rule,
      reason: verdict.reason,
      approved,
    });
    return true;
  }

  /** Handle a server→client message; may return a redacted copy. */
  private onInbound(message: unknown): JSONRPCMessage {
    const resp = asResponse(message);
    if (!resp) return message as JSONRPCMessage;
    const key = idKey(resp.id);
    const call = this.pending.get(key);
    if (!call) return message as JSONRPCMessage; // not a tracked tool call
    this.pending.delete(key);

    let outMessage = message as JSONRPCMessage;
    let findings: AuditRecord["findings"] = [];
    // What we PREVIEW/persist in the audit log. Always a redacted view when
    // secrets are present — the on-disk log must never contain raw secrets,
    // regardless of the --no-redact flag (which only affects the agent's copy).
    let previewSource: unknown = resp.result;

    if (!resp.isError) {
      // Always compute the redacted view; use it for the log and (unless
      // --no-redact) for what the agent receives.
      const scan = scanToolResult(resp.result, true);
      findings = scan.findings.map(maskFinding);
      if (scan.findings.length > 0) {
        previewSource = scan.redacted;
        if (this.redactSecrets) {
          outMessage = { ...(message as object), result: scan.redacted } as JSONRPCMessage;
        }
      }
    }

    this.emit({
      ts: call.ts,
      server: this.server,
      tool: call.tool,
      args: call.args,
      decision: call.decision,
      rule: call.rule,
      reason: call.reason,
      approved: call.approved,
      findings,
      durationMs: this.now() - call.startedAt,
      resultPreview: resp.isError ? undefined : summarize(previewSource),
      isError: resp.isError,
      error: resp.isError ? summarize(resp.error) : undefined,
    });
    return outMessage;
  }

  private emit(record: AuditRecord): void {
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

/**
 * Mask a finding's raw secret before it's persisted to the audit log. Keeps
 * enough to recognize *which* secret (first 3 + last 2 chars) but never the
 * whole value — the on-disk log must not be a secret store. The raw `match` is
 * used for redaction *before* this, so redaction is unaffected.
 */
function maskFinding(f: AuditRecord["findings"][number]): AuditRecord["findings"][number] {
  if (!f.match) return f;
  const m = f.match;
  const masked = m.length >= 8 ? `${m.slice(0, 3)}…${m.slice(-2)}` : "•••";
  return { ...f, match: masked };
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
