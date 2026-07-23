import { describe, it, expect } from "vitest";
import { AuditInterceptor } from "./interceptor.js";
import { PolicyEngine } from "./policy/engine.js";
import type { HookContext } from "./proxy.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { AuditRecord } from "./types.js";
import type { Approver } from "./approval/types.js";

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

interface SetupOptions {
  policy?: PolicyEngine;
  approver?: Approver;
  redactSecrets?: boolean;
}

/** Build an interceptor with a controllable clock and an array sink. */
function setup(opts: SetupOptions = {}) {
  const records: AuditRecord[] = [];
  let clock = 1_000;
  const interceptor = new AuditInterceptor({
    sink: (r) => records.push(r),
    server: "test-server",
    policy: opts.policy,
    approver: opts.approver,
    redactSecrets: opts.redactSecrets,
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

function toolCall(id: number, name: string, args: unknown): JSONRPCMessage {
  return { jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } } as JSONRPCMessage;
}
function response(id: number, result: unknown): JSONRPCMessage {
  return { jsonrpc: "2.0", id, result } as JSONRPCMessage;
}

describe("AuditInterceptor (M2)", () => {
  const { ctx } = fakeCtx();

  it("records a completed tool call with args, duration, and result preview", async () => {
    const { records, hook, tick } = setup();
    await hook(toolCall(7, "echo", { text: "hi" }), "c2s", ctx);
    tick(42);
    await hook(response(7, { content: [{ type: "text", text: "hi" }] }), "s2c", ctx);

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

  it("records error responses with isError and no preview", async () => {
    const { records, hook } = setup();
    await hook(toolCall(1, "boom", {}), "c2s", ctx);
    await hook({ jsonrpc: "2.0", id: 1, error: { code: -32000, message: "kaboom" } } as JSONRPCMessage, "s2c", ctx);
    expect(records[0]!.isError).toBe(true);
    expect(records[0]!.resultPreview).toBeUndefined();
    expect(records[0]!.error).toContain("kaboom");
  });

  it("ignores non-tool-call traffic", async () => {
    const { records, hook } = setup();
    await hook({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} } as JSONRPCMessage, "c2s", ctx);
    await hook(response(1, { tools: [] }), "s2c", ctx);
    await hook({ jsonrpc: "2.0", method: "notifications/initialized" } as JSONRPCMessage, "c2s", ctx);
    expect(records).toHaveLength(0);
  });

  it("correlates concurrent calls by id, not by order", async () => {
    const { records, hook } = setup();
    await hook(toolCall(1, "a", {}), "c2s", ctx);
    await hook(toolCall(2, "b", {}), "c2s", ctx);
    await hook(response(2, { ok: true }), "s2c", ctx);
    await hook(response(1, { ok: true }), "s2c", ctx);
    expect(records.map((r) => r.tool)).toEqual(["b", "a"]);
  });

  it("forwards allowed messages unchanged (no policy = allow all)", async () => {
    const { hook } = setup();
    const msg = toolCall(1, "x", {});
    expect(await hook(msg, "c2s", ctx)).toBe(msg);
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

  it("blocks a denied call: does not forward, replies to client, records deny", async () => {
    const { records, hook } = setup({ policy });
    const { ctx, toClient } = fakeCtx();
    const denied = await hook(toolCall(5, "run_bash", { command: "rm -rf /" }), "c2s", ctx);

    expect(denied).toBeNull();
    expect(toClient).toHaveLength(1);
    const reply = toClient[0] as { id: number; result: { isError: boolean; content: Array<{ text: string }> } };
    expect(reply.id).toBe(5);
    expect(reply.result.isError).toBe(true);
    expect(reply.result.content[0]!.text).toContain("Blocked by mcp-firewall");
    expect(records).toHaveLength(1);
    expect(records[0]!.decision).toBe("deny");
    expect(records[0]!.rule).toBe("block-rm");
  });

  it("lets a non-matching call through and audits it as allow", async () => {
    const { records, hook } = setup({ policy });
    const { ctx, toClient } = fakeCtx();
    const forwarded = await hook(toolCall(6, "run_bash", { command: "ls" }), "c2s", ctx);
    await hook(response(6, { content: [] }), "s2c", ctx);
    expect(forwarded).not.toBeNull();
    expect(toClient).toHaveLength(0);
    expect(records[0]!.decision).toBe("allow");
  });
});

describe("AuditInterceptor approval flow (M4)", () => {
  const policy = PolicyEngine.fromPolicy({
    version: 1,
    default: "allow",
    rules: [{ name: "ask-write", action: "ask", match: { tool: "*write*" }, reason: "Confirm write." }],
  });

  const approve: Approver = { request: async () => true };
  const deny: Approver = { request: async () => false };

  it("forwards an approved ask and records approved: true", async () => {
    const { records, hook } = setup({ policy, approver: approve });
    const { ctx, toClient } = fakeCtx();
    const forwarded = await hook(toolCall(1, "write_file", { path: "/etc/x" }), "c2s", ctx);
    await hook(response(1, { content: [] }), "s2c", ctx);

    expect(forwarded).not.toBeNull();
    expect(toClient).toHaveLength(0);
    expect(records[0]!.decision).toBe("ask");
    expect(records[0]!.approved).toBe(true);
  });

  it("blocks a denied ask and records approved: false", async () => {
    const { records, hook } = setup({ policy, approver: deny });
    const { ctx, toClient } = fakeCtx();
    const forwarded = await hook(toolCall(1, "write_file", { path: "/etc/x" }), "c2s", ctx);

    expect(forwarded).toBeNull();
    expect(toClient).toHaveLength(1);
    expect(records[0]!.decision).toBe("ask");
    expect(records[0]!.approved).toBe(false);
  });

  it("degrades ask to allow-and-record when no approver is configured", async () => {
    const { records, hook } = setup({ policy }); // no approver
    const { ctx } = fakeCtx();
    const forwarded = await hook(toolCall(1, "write_file", { path: "/etc/x" }), "c2s", ctx);
    await hook(response(1, { content: [] }), "s2c", ctx);
    expect(forwarded).not.toBeNull();
    expect(records[0]!.decision).toBe("ask");
    expect(records[0]!.approved).toBeUndefined();
  });
});

describe("AuditInterceptor secret detection + redaction (M4)", () => {
  const secretResult = {
    content: [{ type: "text", text: "config AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" }],
  };

  it("records findings and redacts the result before forwarding (default)", async () => {
    const { records, hook } = setup(); // redactSecrets defaults to true
    const { ctx } = fakeCtx();
    await hook(toolCall(1, "leak", {}), "c2s", ctx);
    const out = (await hook(response(1, secretResult), "s2c", ctx)) as {
      result: { content: Array<{ text: string }> };
    };

    expect(records[0]!.findings.length).toBeGreaterThan(0);
    expect(out.result.content[0]!.text).toContain("[REDACTED:aws-access-key]");
    expect(out.result.content[0]!.text).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("records findings but does not redact when redactSecrets is false", async () => {
    const { records, hook } = setup({ redactSecrets: false });
    const { ctx } = fakeCtx();
    await hook(toolCall(1, "leak", {}), "c2s", ctx);
    const out = (await hook(response(1, secretResult), "s2c", ctx)) as {
      result: { content: Array<{ text: string }> };
    };
    expect(records[0]!.findings.length).toBeGreaterThan(0);
    expect(out.result.content[0]!.text).toContain("AKIAIOSFODNN7EXAMPLE"); // not redacted
  });
});
