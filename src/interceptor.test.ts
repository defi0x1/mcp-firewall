import { describe, it, expect } from "vitest";
import { AuditInterceptor } from "./interceptor.js";
import type { AuditRecord } from "./types.js";

/** Build an interceptor with a controllable clock and an array sink. */
function setup() {
  const records: AuditRecord[] = [];
  let clock = 1_000;
  const interceptor = new AuditInterceptor({
    sink: (r) => records.push(r),
    server: "test-server",
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
  it("records a completed tool call with args, duration, and result preview", () => {
    const { records, hook, tick } = setup();

    // client → server: the tool call
    hook(
      {
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: { name: "echo", arguments: { text: "hi" } },
      },
      "c2s",
    );
    tick(42); // 42ms pass before the response

    // server → client: the response
    hook(
      { jsonrpc: "2.0", id: 7, result: { content: [{ type: "text", text: "hi" }] } },
      "s2c",
    );

    expect(records).toHaveLength(1);
    const rec = records[0]!;
    expect(rec.server).toBe("test-server");
    expect(rec.tool).toBe("echo");
    expect(rec.args).toEqual({ text: "hi" });
    expect(rec.decision).toBe("allow");
    expect(rec.findings).toEqual([]);
    expect(rec.durationMs).toBe(42);
    expect(rec.isError).toBe(false);
    expect(rec.resultPreview).toContain("hi");
    expect(rec.ts).toMatch(/^\d{4}-\d{2}-\d{2}T/); // ISO 8601
  });

  it("records error responses with isError and no preview", () => {
    const { records, hook } = setup();
    hook(
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "boom", arguments: {} } },
      "c2s",
    );
    hook({ jsonrpc: "2.0", id: 1, error: { code: -32000, message: "kaboom" } }, "s2c");

    expect(records).toHaveLength(1);
    expect(records[0]!.isError).toBe(true);
    expect(records[0]!.resultPreview).toBeUndefined();
    expect(records[0]!.error).toContain("kaboom");
  });

  it("ignores non-tool-call traffic (initialize, tools/list, notifications)", () => {
    const { records, hook } = setup();
    hook({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, "c2s");
    hook({ jsonrpc: "2.0", id: 1, result: { protocolVersion: "x" } }, "s2c");
    hook({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, "c2s");
    hook({ jsonrpc: "2.0", id: 2, result: { tools: [] } }, "s2c");
    hook({ jsonrpc: "2.0", method: "notifications/initialized" }, "c2s");

    expect(records).toHaveLength(0);
  });

  it("correlates concurrent calls by id, not by order", () => {
    const { records, hook } = setup();
    hook({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "a", arguments: {} } }, "c2s");
    hook({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "b", arguments: {} } }, "c2s");
    // responses arrive out of order
    hook({ jsonrpc: "2.0", id: 2, result: { ok: true } }, "s2c");
    hook({ jsonrpc: "2.0", id: 1, result: { ok: true } }, "s2c");

    expect(records.map((r) => r.tool)).toEqual(["b", "a"]);
  });

  it("always forwards the message unchanged (M2 observes, never blocks)", () => {
    const { hook } = setup();
    const msg = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "x", arguments: {} } };
    expect(hook(msg, "c2s")).toBe(msg);
  });
});
