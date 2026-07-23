/**
 * Detector aggregation + result scanning/redaction (ROADMAP M4).
 *
 * `detectAll` runs every detector over a string. `scanToolResult` walks an MCP
 * tool result's text blocks, collects findings, and (optionally) returns a
 * redacted copy where each detected secret is replaced with a `[REDACTED:…]`
 * annotation — the "redact-and-annotate" default from DESIGN OQ2.
 *
 * Detectors stay pure (text → Finding[]); the walking/redaction lives here so
 * the interceptor can call one function. New detectors (e.g. injection at M4
 * backlog) get added to `detectAll`.
 */

import type { Finding } from "../types.js";
import { detectSecrets } from "./secrets.js";

/** Run all detectors over a piece of text. */
export function detectAll(text: string): Finding[] {
  return [...detectSecrets(text)];
}

/** Replace every finding's matched substring with a redaction annotation. */
export function redactText(text: string, findings: Finding[]): string {
  let out = text;
  // Dedup by the exact matched string so we don't replace the same secret twice.
  const seen = new Set<string>();
  for (const f of findings) {
    if (!f.match || seen.has(f.match)) continue;
    seen.add(f.match);
    out = out.split(f.match).join(`[REDACTED:${f.detector}]`);
  }
  return out;
}

export interface ScanResult {
  findings: Finding[];
  /** The result with secrets redacted (a copy). Equals the input if `redact` is false. */
  redacted: unknown;
}

/**
 * Scan an MCP tool result (`{ content: [{ type: "text", text }] }`) for secrets.
 * When `redact` is true, returns a deep copy with the text blocks redacted.
 */
export function scanToolResult(result: unknown, redact: boolean): ScanResult {
  const findings: Finding[] = [];
  if (typeof result !== "object" || result === null) {
    return { findings, redacted: result };
  }

  const content = (result as { content?: unknown }).content;
  if (!Array.isArray(content)) {
    return { findings, redacted: result };
  }

  // Clone only if we might redact, so the non-redact path is zero-copy.
  const redactedContent = redact ? structuredClone(content) : content;

  for (let i = 0; i < content.length; i++) {
    const block = content[i] as { type?: unknown; text?: unknown };
    if (block?.type !== "text" || typeof block.text !== "string") continue;
    const blockFindings = detectAll(block.text);
    if (blockFindings.length === 0) continue;
    findings.push(...blockFindings);
    if (redact) {
      (redactedContent[i] as { text: string }).text = redactText(block.text, blockFindings);
    }
  }

  if (!redact || findings.length === 0) {
    return { findings, redacted: result };
  }
  return { findings, redacted: { ...(result as object), content: redactedContent } };
}
