/**
 * End-to-end test for the transparent proxy.
 *
 * Spawns the real CLI wrapping the mock server, drives a full MCP handshake
 * over stdin, and asserts the client gets correct responses back — proving
 * traffic flows through the proxy untouched. This also guards later milestones:
 * if the interceptor ever corrupts the passthrough, this test fails.
 */

import { describe, it, expect } from "vitest";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const tsxBin = resolve(repoRoot, "node_modules/.bin/tsx");
const cli = resolve(repoRoot, "src/cli.ts");
const mockServer = resolve(repoRoot, "test-support/mock-server.ts");
const defaultPolicy = resolve(repoRoot, "policies/default.yaml");

const PROTOCOL_VERSION = "2025-11-25";

interface JsonRpcResponse {
  id: number;
  result?: Record<string, unknown>;
  error?: unknown;
}

/**
 * Run the proxy, feed it the given JSON-RPC messages, and collect the
 * newline-delimited responses printed to stdout. Resolves when the process
 * exits (we close stdin, which triggers the proxy's clean shutdown).
 */
function runProxy(messages: object[], wrapArgs: string[] = []): Promise<JsonRpcResponse[]> {
  return new Promise((resolvePromise, reject) => {
    // Run in a throwaway cwd so the audit log (.mcp-firewall/) doesn't land in
    // the repo. Absolute paths above mean cwd doesn't affect resolution.
    const child = spawn(tsxBin, [cli, "wrap", ...wrapArgs, "--", tsxBin, mockServer], {
      cwd: mkdtempSync(resolve(tmpdir(), "mcp-fw-e2e-")),
      stdio: ["pipe", "pipe", "inherit"],
    });

    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.on("error", reject);
    child.on("close", () => {
      const responses = stdout
        .split("\n")
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as JsonRpcResponse);
      resolvePromise(responses);
    });

    for (const msg of messages) {
      child.stdin.write(JSON.stringify(msg) + "\n");
    }
    // Give the upstream a moment to answer, then close stdin → clean shutdown.
    setTimeout(() => child.stdin.end(), 1500);
  });
}

describe("transparent proxy (M1)", () => {
  it("forwards a full MCP handshake and tool call untouched", async () => {
    const responses = await runProxy([
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: { name: "e2e", version: "0.0.0" },
        },
      },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "echo", arguments: { text: "hello through the firewall" } },
      },
    ]);

    const byId = new Map(responses.map((r) => [r.id, r]));

    // initialize → server info from the mock server made it back to the client
    const init = byId.get(1);
    expect(init?.result?.serverInfo).toMatchObject({ name: "mock-server" });

    // tools/list → both mock tools are visible, unmodified
    const list = byId.get(2);
    const tools = (list?.result?.tools ?? []) as Array<{ name: string }>;
    expect(tools.map((t) => t.name).sort()).toEqual(["echo", "leak_secret", "run_bash"]);

    // tools/call echo → argument round-trips through the proxy verbatim
    const call = byId.get(3);
    const content = (call?.result?.content ?? []) as Array<{ type: string; text: string }>;
    expect(content[0]).toMatchObject({
      type: "text",
      text: "hello through the firewall",
    });
  }, 30_000);
});

describe("approval flow end-to-end (M4)", () => {
  it("holds an ask call until the operator approves it via the web UI", async () => {
    const dir = mkdtempSync(resolve(tmpdir(), "mcp-fw-ask-"));
    // A policy that asks on `echo`. JSON is valid YAML, so this parses fine.
    const policyPath = join(dir, "policy.yaml");
    writeFileSync(
      policyPath,
      JSON.stringify({
        version: 1,
        default: "allow",
        rules: [{ name: "ask-echo", action: "ask", match: { tool: "echo" }, reason: "Confirm echo." }],
      }),
    );

    const child: ChildProcessWithoutNullStreams = spawn(
      tsxBin,
      [cli, "wrap", "--no-open", "--policy", policyPath, "--", tsxBin, mockServer],
      { cwd: dir, stdio: ["pipe", "pipe", "pipe"] },
    );

    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (c: string) => (stdout += c));
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (c: string) => (stderr += c));

    const send = (msg: object) => child.stdin.write(JSON.stringify(msg) + "\n");
    const waitFor = async (pred: () => boolean | Promise<boolean>, timeoutMs = 8000) => {
      const start = Date.now();
      while (!(await pred())) {
        if (Date.now() - start > timeoutMs) throw new Error("timeout waiting for condition");
        await new Promise((r) => setTimeout(r, 50));
      }
    };

    try {
      // Wait for the approval server URL to appear on stderr.
      await waitFor(() => /approvals: (http:\/\/\S+)/.test(stderr));
      const approvalsUrl = stderr.match(/approvals: (http:\/\/\S+)/)![1]!;

      send({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "e2e-ask", version: "0" } },
      });
      send({ jsonrpc: "2.0", method: "notifications/initialized" });
      send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { text: "gated" } } });

      // The call should be held — no id:2 response yet, and it shows as pending.
      let pending: Array<{ id: string; tool: string }> = [];
      await waitFor(async () => {
        pending = (await (await fetch(`${approvalsUrl}/api/pending`)).json()) as typeof pending;
        return pending.length === 1;
      });
      expect(pending[0]!.tool).toBe("echo");
      expect(stdout).not.toContain('"id":2'); // still gated

      // Approve it.
      await fetch(`${approvalsUrl}/api/decide`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: pending[0]!.id, approved: true }),
      });

      // Now the echo response should be forwarded to the client.
      await waitFor(() => stdout.includes('"id":2'));
      expect(stdout).toContain("gated");
    } finally {
      child.stdin.end();
      await new Promise((r) => child.on("close", r));
    }
  }, 30_000);
});

describe("policy enforcement end-to-end (M3)", () => {
  it("blocks a denied call and lets others through", async () => {
    const responses = await runProxy(
      [
        {
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: {},
            clientInfo: { name: "e2e-policy", version: "0.0.0" },
          },
        },
        { jsonrpc: "2.0", method: "notifications/initialized" },
        // denied by policies/default.yaml (block-destructive-shell)
        {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "run_bash", arguments: { command: "rm -rf /data" } },
        },
        // allowed — same tool, harmless command
        {
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: { name: "run_bash", arguments: { command: "ls -la" } },
        },
      ],
      ["--policy", defaultPolicy],
    );

    const byId = new Map(responses.map((r) => [r.id, r]));

    // The denied call gets a synthetic isError result — the agent sees the block
    const denied = byId.get(2);
    expect(denied?.result?.isError).toBe(true);
    const deniedContent = (denied?.result?.content ?? []) as Array<{ text: string }>;
    expect(deniedContent[0]!.text).toContain("Blocked by mcp-firewall");

    // The allowed call reached the mock server and came back normally
    const allowed = byId.get(3);
    expect(allowed?.result?.isError).toBeFalsy();
    const allowedContent = (allowed?.result?.content ?? []) as Array<{ text: string }>;
    expect(allowedContent[0]!.text).toContain("would run: ls -la");
  }, 30_000);
});
