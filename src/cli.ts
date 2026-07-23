#!/usr/bin/env node
/**
 * mcp-firewall CLI entry point.
 *
 * M0: this is a stub that prints usage. The real subcommands land in later
 * milestones:
 *   - `wrap`  (M1) — start the proxy around a real MCP server
 *   - `log`   (M2) — pretty-print the audit log
 *
 * See docs/ROADMAP.md.
 */

const USAGE = `mcp-firewall — a security proxy for AI agents (MCP)

Usage:
  mcp-firewall wrap [--policy <file>] -- <server-command...>
      Run an MCP server behind the firewall. (M1 — not implemented yet)

  mcp-firewall log [--file <path>]
      Pretty-print the audit log. (M2 — not implemented yet)

Docs: see docs/ROADMAP.md for what's built and what's next.
`;

function main(argv: string[]): void {
  const [command] = argv;

  switch (command) {
    case "wrap":
    case "log":
      // Placeholder until the milestone implements it.
      console.error(`"${command}" is not implemented yet. See docs/ROADMAP.md.`);
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

main(process.argv.slice(2));
