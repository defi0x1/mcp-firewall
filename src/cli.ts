#!/usr/bin/env node
/**
 * mcp-firewall CLI entry point.
 *
 * Subcommands (see docs/ROADMAP.md):
 *   - `wrap`  (M1/M2) ✅ — start the proxy around a real MCP server, auditing calls
 *   - `log`   (M2)    ✅ — pretty-print the audit log
 */

import { Proxy, type ProxyHook } from "./proxy.js";
import { AuditInterceptor } from "./interceptor.js";
import { AuditLog, defaultAuditPath } from "./audit/log.js";
import { PolicyEngine } from "./policy/engine.js";
import { ApprovalServer } from "./approval/server.js";
import { logStderr, describeMessage } from "./log.js";
import type { AuditRecord } from "./types.js";

const USAGE = `mcp-firewall — a security proxy for AI agents (MCP)

Usage:
  mcp-firewall wrap [--policy <file>] [--verbose] -- <server-command...>
      Run an MCP server behind the firewall. Every tool call is checked against
      the policy (if given) and recorded to the audit log (.mcp-firewall/
      audit.jsonl). Everything after '--' is the command that launches the real
      server.

      Example:
        mcp-firewall wrap --policy policies/default.yaml -- \\
          npx -y @modelcontextprotocol/server-filesystem /tmp

      --policy <file>  YAML policy of allow/deny/ask rules (default: allow all)
      --no-redact      don't redact detected secrets from results (warn only)
      --no-open        don't auto-open the browser for approvals (headless)
      --verbose        also log every JSON-RPC message to stderr (passthrough)

      When the policy says "ask", a local web page opens for you to approve or
      deny the call. Detected secrets in results are redacted before the agent
      sees them (unless --no-redact).

  mcp-firewall log [--file <path>]
      Pretty-print the audit log (default: .mcp-firewall/audit.jsonl).

Docs: see docs/ROADMAP.md for what's built and what's next.
`;

function main(argv: string[]): void {
  const [command, ...rest] = argv;

  switch (command) {
    case "wrap":
      void runWrap(rest);
      break;
    case "log":
      void runLog(rest);
      break;
    case undefined:
    case "-h":
    case "--help":
    case "help":
      console.log(USAGE);
      break;
    default:
      console.error(`Unknown command: ${command}\n`);
      console.log(USAGE);
      process.exit(1);
  }
}

/**
 * `wrap [--policy <file>] [--verbose] -- <server-command...>` — start the proxy
 * with the audit + policy interceptor. `--verbose` adds the passthrough logger.
 */
async function runWrap(args: string[]): Promise<void> {
  const verbose = args.includes("--verbose");
  const redactSecrets = !args.includes("--no-redact");
  const autoOpen = !args.includes("--no-open");
  const policyFlag = args.indexOf("--policy");
  const policyPath = policyFlag !== -1 ? args[policyFlag + 1] : undefined;
  const sepIndex = args.indexOf("--");
  const serverCmd = sepIndex === -1 ? [] : args.slice(sepIndex + 1);

  if (serverCmd.length === 0) {
    console.error("wrap: missing server command after '--'\n");
    console.log(USAGE);
    process.exit(1);
  }

  const [command, ...serverArgs] = serverCmd;
  const serverName = serverCmd.join(" ");

  // Load the policy if one was given. A bad policy file is fatal — better to
  // refuse to start than to run a security proxy that silently enforces nothing.
  let policy: PolicyEngine | undefined;
  if (policyPath) {
    try {
      policy = await PolicyEngine.load(policyPath);
    } catch (err) {
      logStderr(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  }

  // If we have a policy (which may contain `ask` rules), stand up the approval
  // web UI so a human can approve/deny those calls.
  let approval: ApprovalServer | undefined;
  if (policy) {
    approval = new ApprovalServer({ autoOpen });
    await approval.start();
  }

  // Audit + policy interceptor: enforce the policy, record every call, and
  // print a concise one-liner to stderr per decision.
  const audit = new AuditLog(defaultAuditPath());
  const interceptor = new AuditInterceptor({
    server: serverName,
    policy,
    approver: approval,
    redactSecrets,
    sink: (record) => void audit.append(record),
    onDecision: (record) => {
      const status = record.isError ? "error" : `${record.durationMs}ms`;
      const tag =
        record.decision === "deny"
          ? "BLOCKED"
          : record.decision === "ask"
            ? record.approved
              ? "APPROVED"
              : "DENIED"
            : record.decision.toUpperCase();
      const ruleText = record.rule ? ` [${record.rule}]` : "";
      const flags = record.findings.length > 0 ? ` ⚠ ${record.findings.length} finding(s)` : "";
      logStderr(`${tag} ${record.tool} (${status})${ruleText}${flags}`);
    },
  });

  const hooks: ProxyHook[] = [interceptor.hook];

  if (verbose) {
    hooks.unshift((message, direction) => {
      const arrow = direction === "c2s" ? "→" : "←";
      logStderr(`${arrow} ${describeMessage(message)}`);
      return message;
    });
  }

  const proxy = new Proxy({
    upstream: { command: command!, args: serverArgs },
    hooks,
    onClose: () => {
      logStderr("upstream closed; shutting down");
      void approval?.stop();
      process.exit(0);
    },
  });

  proxy.start().catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    logStderr(`failed to start: ${msg}`);
    process.exit(1);
  });

  logStderr(`wrapping: ${serverName}`);
  logStderr(`policy: ${policyPath ?? "(none — allowing all)"}`);
  logStderr(`redaction: ${redactSecrets ? "on" : "off"}`);
  if (approval) logStderr(`approvals: ${approval.url}`);
  logStderr(`audit log: ${defaultAuditPath()}`);
}

/** `log [--file <path>]` — pretty-print the audit log to stdout. */
async function runLog(args: string[]): Promise<void> {
  const fileFlag = args.indexOf("--file");
  const filePath =
    fileFlag !== -1 && args[fileFlag + 1] ? args[fileFlag + 1]! : defaultAuditPath();

  const records = await new AuditLog(filePath).read();

  if (records.length === 0) {
    console.log(`No audit records in ${filePath}.`);
    return;
  }

  console.log(`Audit log: ${filePath} (${records.length} record(s))\n`);
  for (const rec of records) {
    console.log(formatRecord(rec));
  }
}

/** One human-readable block per audit record. */
function formatRecord(rec: AuditRecord): string {
  const time = rec.ts.replace("T", " ").replace(/\.\d+Z$/, "Z");
  const decision = rec.decision.toUpperCase();
  const status = rec.isError ? "ERROR" : `${rec.durationMs ?? "?"}ms`;
  const args = truncate(safeJson(rec.args), 80);

  const lines = [
    `${time}  [${decision}] ${rec.tool}  (${status})`,
    `  server: ${rec.server}`,
    `  args:   ${args}`,
  ];
  if (rec.resultPreview !== undefined) lines.push(`  result: ${truncate(rec.resultPreview, 80)}`);
  if (rec.error !== undefined) lines.push(`  error:  ${truncate(rec.error, 80)}`);
  if (rec.findings.length > 0) {
    lines.push(`  findings: ${rec.findings.length}`);
    for (const f of rec.findings) {
      lines.push(`    - [${f.severity}] ${f.detector}: ${f.message}`);
    }
  }
  return lines.join("\n");
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + "…" : s;
}

main(process.argv.slice(2));
