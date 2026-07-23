/**
 * Proxy core — the heart of mcp-firewall (ROADMAP M1).
 *
 * We sit between an MCP *client* (Claude Code, Cursor, …) and a real MCP
 * *server* (filesystem, shell, …). To make this work we hold TWO transports:
 *
 *   - `serverTransport`: a StdioServerTransport reading our own stdin / writing
 *     our own stdout. To the client that launched us, WE look like the server.
 *
 *   - `clientTransport`: a StdioClientTransport that SPAWNS the real server as a
 *     child process. To that server, WE look like the client.
 *
 * We wire the two together so every JSON-RPC message flows across:
 *
 *     client ──stdin──►  serverTransport.onmessage ──► clientTransport.send ──► real server
 *     client ◄─stdout──  serverTransport.send      ◄── clientTransport.onmessage ◄─ real server
 *
 * Working at the *transport* layer (not the high-level Client/Server classes)
 * keeps us truly transparent: we forward the raw messages without parsing every
 * method's schema. The `hooks` give later milestones a place to inspect or
 * modify messages (audit at M2, policy at M3) without touching this file.
 *
 * ⚠️ stdout is the protocol channel to the client. NEVER write logs to stdout —
 * it would corrupt the JSON-RPC stream. All diagnostics go to stderr.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

/** How to launch the real MCP server we're wrapping. */
export interface UpstreamServer {
  command: string;
  args?: string[];
  /** Extra env for the child; merged over the inherited default environment. */
  env?: Record<string, string>;
  cwd?: string;
}

/**
 * Hooks let later milestones observe or transform traffic. A hook receives a
 * message and returns the message to forward (possibly modified), or `null` to
 * drop it (e.g. a policy `deny` that answers the client directly instead).
 *
 * `direction` tells the hook which way the message is going:
 *   - "c2s" — from client toward the server (requests / notifications)
 *   - "s2c" — from server toward the client (responses / notifications)
 *
 * M1 uses only a passthrough logger. The interceptor (M2+) plugs in here.
 */
export type ProxyHook = (
  message: JSONRPCMessage,
  direction: "c2s" | "s2c",
) => JSONRPCMessage | null | Promise<JSONRPCMessage | null>;

export interface ProxyOptions {
  upstream: UpstreamServer;
  hooks?: ProxyHook[];
  /** Called when either side closes, so the CLI can exit cleanly. */
  onClose?: () => void;
}

export class Proxy {
  private readonly serverTransport: StdioServerTransport;
  private readonly clientTransport: StdioClientTransport;
  private readonly hooks: ProxyHook[];
  private readonly onClose?: () => void;
  private closed = false;

  constructor(options: ProxyOptions) {
    this.hooks = options.hooks ?? [];
    this.onClose = options.onClose;

    // Faces the client: reads our stdin, writes our stdout (SDK defaults).
    this.serverTransport = new StdioServerTransport();

    // Faces (and spawns) the real server. "inherit" sends the child's stderr to
    // our stderr so the user still sees the real server's own diagnostics.
    this.clientTransport = new StdioClientTransport({
      command: options.upstream.command,
      args: options.upstream.args,
      env: options.upstream.env,
      cwd: options.upstream.cwd,
      stderr: "inherit",
    });

    // client → server
    this.serverTransport.onmessage = (message) => {
      void this.forward(message, "c2s", this.clientTransport);
    };
    // server → client
    this.clientTransport.onmessage = (message) => {
      void this.forward(message, "s2c", this.serverTransport);
    };

    // If either side drops, tear the whole thing down — a half-open proxy is
    // worse than a closed one (the agent would hang waiting for replies).
    this.serverTransport.onclose = () => this.shutdown();
    this.clientTransport.onclose = () => this.shutdown();
    this.serverTransport.onerror = (err) => this.reportError("client-side", err);
    this.clientTransport.onerror = (err) => this.reportError("server-side", err);

    // The SDK's StdioServerTransport only listens for stdin 'data'/'error' — it
    // never fires onclose on stdin EOF. So when the client disconnects (closes
    // stdin), we'd hang forever. Detect EOF ourselves and shut down.
    process.stdin.on("end", () => this.shutdown());
    process.stdin.on("close", () => this.shutdown());
  }

  /** Start both transports. The client transport spawns the real server. */
  async start(): Promise<void> {
    // Start the upstream (real server) first so it's ready to receive the
    // client's `initialize` the moment we start reading stdin.
    await this.clientTransport.start();
    await this.serverTransport.start();
  }

  /**
   * Run the message through every hook, then hand it to the destination
   * transport. A hook returning `null` drops the message (no forward).
   */
  private async forward(
    message: JSONRPCMessage,
    direction: "c2s" | "s2c",
    destination: StdioServerTransport | StdioClientTransport,
  ): Promise<void> {
    try {
      let current: JSONRPCMessage | null = message;
      for (const hook of this.hooks) {
        current = await hook(current, direction);
        if (current === null) return; // hook consumed/dropped the message
      }
      await destination.send(current);
    } catch (err) {
      this.reportError(`forward:${direction}`, err);
    }
  }

  private reportError(where: string, err: unknown): void {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[mcp-firewall] error (${where}): ${message}\n`);
  }

  /** Idempotent teardown: close both transports and notify the CLI once. */
  private shutdown(): void {
    if (this.closed) return;
    this.closed = true;
    void this.serverTransport.close().catch(() => {});
    void this.clientTransport.close().catch(() => {});
    this.onClose?.();
  }
}
