import { describe, it, expect, afterEach } from "vitest";
import { ApprovalServer } from "./server.js";

let server: ApprovalServer | undefined;

afterEach(async () => {
  await server?.stop();
  server = undefined;
});

describe("ApprovalServer (M4)", () => {
  it("exposes a pending approval and resolves it when decided", async () => {
    server = new ApprovalServer({ autoOpen: false });
    const url = await server.start();

    // Kick off a request (don't await yet — it resolves on decision).
    const decision = server.request({ server: "s", tool: "write_file", args: { path: "/etc/x" } });

    // The pending approval shows up in the API.
    const pending = (await (await fetch(`${url}/api/pending`)).json()) as Array<{ id: string; tool: string }>;
    expect(pending).toHaveLength(1);
    expect(pending[0]!.tool).toBe("write_file");

    // Approve it via the decide endpoint.
    const res = await fetch(`${url}/api/decide`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: pending[0]!.id, approved: true }),
    });
    expect((await res.json()).ok).toBe(true);

    await expect(decision).resolves.toBe(true);

    // No longer pending.
    const after = (await (await fetch(`${url}/api/pending`)).json()) as unknown[];
    expect(after).toHaveLength(0);
  });

  it("auto-denies after the timeout", async () => {
    server = new ApprovalServer({ autoOpen: false, timeoutMs: 50 });
    await server.start();
    const decision = server.request({ server: "s", tool: "slow", args: {} });
    await expect(decision).resolves.toBe(false);
  });

  it("serves the approval HTML page", async () => {
    server = new ApprovalServer({ autoOpen: false });
    const url = await server.start();
    const html = await (await fetch(url)).text();
    expect(html).toContain("mcp-firewall");
    expect(html).toContain("Approve");
  });
});
