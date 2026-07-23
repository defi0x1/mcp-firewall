/**
 * Secrets detector.
 *
 * A pure function `(text) => Finding[]` — no I/O, no state (DESIGN D4). It scans
 * text (typically a tool *result* like a fetched web page or a file's contents)
 * for things that look like credentials. Each finding carries the exact matched
 * substring so the interceptor can redact it before the agent ever sees it.
 *
 * This is pattern-based, so it's best-effort: it will miss novel secret formats
 * and can false-positive on secret-shaped-but-harmless strings. That's an
 * acceptable tradeoff for a warn-and-redact tool — better a redacted false
 * positive than a leaked real key. Tune patterns as real usage surfaces gaps.
 */

import type { Finding } from "../types.js";

interface SecretPattern {
  detector: string;
  severity: Finding["severity"];
  message: string;
  regex: RegExp; // must be global (/g) for matchAll
  /** Which capture group holds the secret to redact (0 = whole match). */
  group?: number;
}

const PATTERNS: SecretPattern[] = [
  {
    detector: "aws-access-key",
    severity: "high",
    message: "AWS access key ID",
    // AKIA (long-term) or ASIA (temporary) + 16 uppercase alphanumerics.
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    detector: "github-token",
    severity: "high",
    message: "GitHub token",
    regex: /\bgh[opsu]_[A-Za-z0-9]{36,}\b/g,
  },
  {
    detector: "github-pat",
    severity: "high",
    message: "GitHub fine-grained personal access token",
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  },
  {
    detector: "slack-token",
    severity: "high",
    message: "Slack token",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    detector: "private-key",
    severity: "high",
    message: "Private key block",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    detector: "generic-secret",
    severity: "medium",
    message: "Possible hard-coded secret assignment",
    // e.g. api_key="...", SECRET: '...', access-key = ... — redact the VALUE (group 1).
    regex:
      /(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+_-]{16,})/gi,
    group: 1,
  },
];

export function detectSecrets(text: string): Finding[] {
  const findings: Finding[] = [];
  for (const p of PATTERNS) {
    for (const m of text.matchAll(p.regex)) {
      const match = p.group ? m[p.group] : m[0];
      if (!match) continue;
      findings.push({
        detector: p.detector,
        severity: p.severity,
        message: p.message,
        match,
      });
    }
  }
  return findings;
}
