import { describe, it, expect } from "vitest";
import { AuditInterceptor } from "./interceptor.js";
import { PolicyEngine } from "./policy/engine.js";
import type { HookContext } from "./proxy.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { AuditRecord } from "./types.js";

/** A fake HookContext that captures what the interceptor sends back. */
function fakeCtx() {
  const toClient: JSONRPCMessage[] = [];
  const toServer: JSONRPCMessage[] = [];
  const ctx: HookContext = {
    replyToClient: (m) => toClient.push(m),
    sendToServer: (m) => toServer.push(m),
  };
  return { ctx, toClient, toServer };
}

/** Build an interceptor with a controllable clock and an array sink. */
function setup(policy?: PolicyEngine) {
  const records: AuditRecord[] = [];
  let clock = 1_000;
  const interceptor = new AuditInterceptor({
    sink: (r) => records.push(r),
    server: "test-server",
    policy,
    now: () => clock,
  });
  return {
    records,
    hook: interceptor.hook,
    tick: (ms: number) => {
      clock += ms;
    },
  };
}

describe("AuditInterceptor (M2)", () => {
  const { ctx } = fakeCtx();

  it("records a completed tool call with args, duration, and result preview", () => {
    const { records, hook, tick } = setup();
    hook(
      { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "echo", arguments: { text: "hi" } } },
      "c2s",
      ctx,
    );
    tick(42);
    hook({ jsonrpc: "2.0", id: 7, result: { content: [{ type: "text", text: "hi" }] } }, "s2c", ctx);

    expect(records).toHaveLength(1);
    const rec = records[0]!;
    expect(rec.tool).toBe("echo");
    expect(rec.args).toEqual({ text: "hi" });
    expect(rec.decision).toBe("allow");
    expect(rec.durationMs).toBe(42);
    expect(rec.isError).toBe(false);
    expect(rec.resultPreview).toContain("hi");
    expect(rec.ts).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("records error responses with isError and no preview", () => {
    const { records, hook } = setup();
    hook({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "boom", arguments: {} } }, "c2s", ctx);
    hook({ jsonrpc: "2.0", id: 1, error: { code: -32000, message: "kaboom" } }, "s2c", ctx);

    expect(records[0]!.isError).toBe(true);
    expect(records[0]!.resultPreview).toBeUndefined();
    expect(records[0]!.error).toContain("kaboom");
  });

  it("ignores non-tool-call traffic", () => {
    const { records, hook } = setup();
    hook({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, "c2s", ctx);
    hook({ jsonrpc: "2.0", id: 1, result: { tools: [] } }, "s2c", ctx);
    hook({ jsonrpc: "2.0", method: "notifications/initialized" }, "c2s", ctx);
    expect(records).toHaveLength(0);
  });

  it("correlates concurrent calls by id, not by order", () => {
    const { records, hook } = setup();
    hook({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "a", arguments: {} } }, "c2s", ctx);
    hook({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "b", arguments: {} } }, "c2s", ctx);
    hook({ jsonrpc: "2.0", id: 2, result: { ok: true } }, "s2c", ctx);
    hook({ jsonrpc: "2.0", id: 1, result: { ok: true } }, "s2c", ctx);
    expect(records.map((r) => r.tool)).toEqual(["b", "a"]);
  });

  it("forwards allowed messages unchanged (no policy = allow all)", () => {
    const { hook } = setup();
    const msg = { jsonrpc: "2.0" as const, id: 1, method: "tools/call", params: { name: "x", arguments: {} } };
    expect(hook(msg, "c2s", ctx)).toBe(msg);
  });
});

describe("AuditInterceptor policy enforcement (M3)", () => {
  const policy = PolicyEngine.fromPolicy({
    version: 1,
    default: "allow",
    rules: [
      { name: "block-rm", action: "deny", match: { tool: "*bash*", args_regex: "rm\\s+-rf" }, reason: "Destructive." },
    ],
  });

  it("blocks a denied call: does not forward, replies to client, records deny", () => {
    const { records, hook } = setup(policy);
    const { ctx, toClient } = fakeCtx();

    const denied = hook(
      { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "run_bash", arguments: { command: "rm -rf /" } } },
      "c2s",
      ctx,
    );

    // Not forwarded to the server
    expect(denied).toBeNull();

    // A synthetic blocked result was sent back to the client
    expect(toClient).toHaveLength(1);
    const reply = toClient[0] as { id: number; result: { isError: boolean; content: Array<{ text: string }> } };
    expect(reply.id).toBe(5);
    expect(reply.result.isError).toBe(true);
    expect(reply.result.content[0]!.text).toContain("Blocked by mcp-firewall");

    // A deny record was written immediately (no response will ever come)
    expect(records).toHaveLength(1);
    expect(records[0]!.decision).toBe("deny");
    expect(records[0]!.rule).toBe("block-rm");
  });

  it("lets a non-matching call through and audits it as allow", () => {
    const { records, hook } = setup(policy);
    const { ctx, toClient } = fakeCtx();

    const forwarded = hook(
      { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "run_bash", arguments: { command: "ls" } } },
      "c2s",
      ctx,
    );
    hook({ jsonrpc: "2.0", id: 6, result: { content: [] } }, "s2c", ctx);

    expect(forwarded).not.toBeNull(); // forwarded
    expect(toClient).toHaveLength(0); // no synthetic reply
    expect(records[0]!.decision).toBe("allow");
  });
});
