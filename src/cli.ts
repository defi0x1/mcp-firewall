#!/usr/bin/env node
/**
 * mcp-firewall CLI entry point.
 *
 * Subcommands (see docs/ROADMAP.md):
 *   - `wrap`  (M1) ✅ — start the transparent proxy around a real MCP server
 *   - `log`   (M2)    — pretty-print the audit log (not implemented yet)
 */

import { Proxy, type ProxyHook } from "./proxy.js";
import { logStderr, describeMessage } from "./log.js";

const USAGE = `mcp-firewall — a security proxy for AI agents (MCP)

Usage:
  mcp-firewall wrap -- <server-command...>
      Run an MCP server behind the firewall. Everything after '--' is the
      command that launches the real server.

      Example:
        mcp-firewall wrap -- npx -y @modelcontextprotocol/server-filesystem /tmp

  mcp-firewall log [--file <path>]
      Pretty-print the audit log. (M2 — not implemented yet)

Docs: see docs/ROADMAP.md for what's built and what's next.
`;

function main(argv: string[]): void {
  const [command, ...rest] = argv;

  switch (command) {
    case "wrap":
      runWrap(rest);
      break;
    case "log":
      console.error(`"log" is not implemented yet. See docs/ROADMAP.md.`);
      process.exit(1);
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
 * `wrap -- <server-command...>` — split the args on the `--` separator, then
 * start the proxy. The command after `--` becomes the upstream server.
 */
function runWrap(args: string[]): void {
  const sepIndex = args.indexOf("--");
  const serverCmd = sepIndex === -1 ? [] : args.slice(sepIndex + 1);

  if (serverCmd.length === 0) {
    console.error("wrap: missing server command after '--'\n");
    console.log(USAGE);
    process.exit(1);
  }

  const [command, ...serverArgs] = serverCmd;

  // M1 passthrough hook: log every message to stderr and forward it untouched.
  // This is temporary proof-of-flow; the audit interceptor replaces it at M2.
  const passthroughLogger: ProxyHook = (message, direction) => {
    const arrow = direction === "c2s" ? "→" : "←";
    logStderr(`${arrow} ${describeMessage(message)}`);
    return message;
  };

  const proxy = new Proxy({
    upstream: { command: command!, args: serverArgs },
    hooks: [passthroughLogger],
    onClose: () => {
      logStderr("upstream closed; shutting down");
      process.exit(0);
    },
  });

  proxy.start().catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    logStderr(`failed to start: ${msg}`);
    process.exit(1);
  });

  logStderr(`wrapping: ${serverCmd.join(" ")}`);
}

main(process.argv.slice(2));
