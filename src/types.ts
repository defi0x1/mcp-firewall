/**
 * Shared data shapes for mcp-firewall. Mirrors the "Data shapes" section of
 * docs/ARCHITECTURE.md — keep the two in sync when either changes.
 */

/** What the policy engine decides for a tool call. */
export type Decision = "allow" | "deny" | "ask";

/** One thing a detector flagged in a tool call's args or result. */
export interface Finding {
  detector: string; // "secrets" | "injection" | "dangerous-op" | …
  severity: "low" | "medium" | "high";
  message: string;
  /** The offending substring. May be redacted before being written to disk. */
  match?: string;
}

/**
 * One audit record = one line of the JSONL audit log. Written when a tool
 * call completes (or is denied). M2 fills in ts/server/tool/args/duration and
 * a result preview; `decision` is always "allow" until M3, and `findings` is
 * empty until M4.
 */
export interface AuditRecord {
  ts: string; // ISO 8601, when the call was initiated
  server: string; // identifier of the upstream server being wrapped
  tool: string;
  args: unknown;
  decision: Decision;
  rule?: string; // name of the policy rule that decided this (if any matched)
  reason?: string; // human explanation for a deny/ask
  approved?: boolean; // set only for `ask` decisions
  findings: Finding[];
  durationMs?: number; // request → response wall time
  resultPreview?: string; // short, truncated summary of the result (never the full payload)
  isError?: boolean; // the tool result carried an MCP error
  error?: string; // proxy-level error (e.g. no response correlated)
}
