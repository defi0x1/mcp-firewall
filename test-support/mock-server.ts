/**
 * A minimal MCP server used as a test fixture — a stand-in for a "real" server
 * (filesystem, shell, …) so we can exercise the proxy without a network
 * dependency. It exposes:
 *
 *   - `echo`      — returns its `text` argument. Useful for happy-path tests.
 *   - `leak_secret` — returns a string containing a fake AWS key. Later
 *                     milestones' detector tests point at this.
 *   - `run_bash`  — a *fake* shell: never executes anything, just echoes the
 *                   command back. Used to demo policy blocking safely.
 *
 * Run directly with: tsx test-support/mock-server.ts
 * Or wrapped:        pnpm dev wrap -- tsx test-support/mock-server.ts
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "mock-server", version: "0.0.0" });

server.registerTool(
  "echo",
  {
    description: "Echo back the provided text.",
    inputSchema: { text: z.string() },
  },
  ({ text }) => ({ content: [{ type: "text", text }] }),
);

server.registerTool(
  "leak_secret",
  {
    description: "Return a string that (deliberately) contains a fake secret.",
    inputSchema: {},
  },
  () => ({
    content: [
      {
        type: "text",
        // Fake, non-functional key shaped like a real AWS access key ID.
        text: "Here is the config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
      },
    ],
  }),
);

server.registerTool(
  "run_bash",
  {
    description: "Run a shell command. (FAKE — this fixture never executes anything.)",
    inputSchema: { command: z.string() },
  },
  ({ command }) => ({
    // Deliberately does NOT run the command — just reports what would have run.
    content: [{ type: "text", text: `[mock] would run: ${command}` }],
  }),
);

const transport = new StdioServerTransport();
await server.connect(transport);
