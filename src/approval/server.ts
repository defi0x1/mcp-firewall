/**
 * Approval web UI (ROADMAP M4, resolves DESIGN OQ1).
 *
 * When a policy rule says `ask`, the interceptor calls `request()` and awaits a
 * human decision. This server surfaces pending calls in a local web page:
 *
 *   - `GET /`            → a self-contained HTML page that polls for pending
 *                          approvals and shows Approve/Deny buttons.
 *   - `GET /api/pending` → JSON list of pending approvals.
 *   - `POST /api/decide` → { id, approved } resolves one pending call.
 *
 * Why a web UI and not a terminal prompt: under stdio the MCP *client* owns the
 * terminal, so we can't prompt there. A local page is a reliable, click-to-
 * decide surface. We auto-open the browser on the first pending approval so the
 * user notices even when the firewall's stderr is buried in client logs.
 *
 * No web framework — plain node:http keeps the dependency surface (and thus the
 * attack surface) small, which matters for a security tool.
 */

import { createServer, type Server } from "node:http";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Approver, ApprovalRequest } from "./types.js";
import { logStderr } from "../log.js";

interface Pending extends ApprovalRequest {
  id: string;
  createdAt: number;
  resolve: (approved: boolean) => void;
  timer: NodeJS.Timeout;
}

export interface ApprovalServerOptions {
  /** Auto-deny after this many ms so the agent never hangs forever. */
  timeoutMs?: number;
  /** Open the browser on the first pending approval. Disable in tests. */
  autoOpen?: boolean;
}

export class ApprovalServer implements Approver {
  private readonly pending = new Map<string, Pending>();
  private server?: Server;
  private baseUrl = "";
  private openedBrowser = false;
  private readonly timeoutMs: number;
  private readonly autoOpen: boolean;

  constructor(options: ApprovalServerOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 120_000;
    this.autoOpen = options.autoOpen ?? true;
  }

  /** Start listening. `port = 0` picks a free port. Returns the base URL. */
  start(port = 0): Promise<string> {
    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => this.handle(req, res));
      this.server.on("error", reject);
      this.server.listen(port, "127.0.0.1", () => {
        const { port: actual } = this.server!.address() as AddressInfo;
        this.baseUrl = `http://127.0.0.1:${actual}`;
        resolve(this.baseUrl);
      });
    });
  }

  get url(): string {
    return this.baseUrl;
  }

  async stop(): Promise<void> {
    // Resolve anything still pending as denied, so awaiters don't hang.
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.resolve(false);
    }
    this.pending.clear();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }

  /** Approver interface — awaited by the interceptor on an `ask` decision. */
  request(input: ApprovalRequest): Promise<boolean> {
    return new Promise((resolve) => {
      const id = randomUUID();
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) {
          logStderr(`approval timed out (${this.timeoutMs}ms) — denying: ${input.tool}`);
          resolve(false);
        }
      }, this.timeoutMs);
      // Don't let a pending approval keep the process alive on its own.
      timer.unref?.();

      this.pending.set(id, { ...input, id, createdAt: Date.now(), resolve, timer });
      logStderr(`APPROVAL NEEDED: ${input.tool} — decide at ${this.baseUrl}`);
      this.maybeOpenBrowser();
    });
  }

  private settle(id: string, approved: boolean): boolean {
    const p = this.pending.get(id);
    if (!p) return false;
    clearTimeout(p.timer);
    this.pending.delete(id);
    p.resolve(approved);
    return true;
  }

  // ── HTTP ───────────────────────────────────────────────────────────────────

  private handle(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse): void {
    const url = req.url ?? "/";
    if (req.method === "GET" && (url === "/" || url.startsWith("/?"))) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(PAGE_HTML);
      return;
    }
    if (req.method === "GET" && url === "/api/pending") {
      const list = [...this.pending.values()].map((p) => ({
        id: p.id,
        server: p.server,
        tool: p.tool,
        args: p.args,
        rule: p.rule,
        reason: p.reason,
        ageMs: Date.now() - p.createdAt,
      }));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(list));
      return;
    }
    if (req.method === "POST" && url === "/api/decide") {
      void this.readBody(req).then((body) => {
        let ok = false;
        try {
          const { id, approved } = JSON.parse(body) as { id: string; approved: boolean };
          ok = this.settle(id, Boolean(approved));
        } catch {
          ok = false;
        }
        res.writeHead(ok ? 200 : 400, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok }));
      });
      return;
    }
    res.writeHead(404).end();
  }

  private readBody(req: import("node:http").IncomingMessage): Promise<string> {
    return new Promise((resolve) => {
      let data = "";
      req.on("data", (chunk) => {
        data += chunk;
        if (data.length > 1_000_000) req.destroy(); // guard against oversized bodies
      });
      req.on("end", () => resolve(data));
    });
  }

  private maybeOpenBrowser(): void {
    if (!this.autoOpen || this.openedBrowser || !this.baseUrl) return;
    this.openedBrowser = true;
    const cmd =
      process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
    try {
      const child = spawn(cmd, [this.baseUrl], { stdio: "ignore", detached: true, shell: process.platform === "win32" });
      child.on("error", () => {}); // no browser available — the stderr URL still works
      child.unref();
    } catch {
      // ignore — user can open the URL from the stderr log
    }
  }
}

/** Self-contained approval page: polls /api/pending and posts decisions. */
const PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>mcp-firewall — approvals</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 -apple-system, system-ui, sans-serif; margin: 0; padding: 2rem; background: #0f1115; color: #e6e6e6; }
  h1 { font-size: 1.2rem; display: flex; align-items: center; gap: .5rem; }
  .empty { opacity: .6; margin-top: 2rem; }
  .card { background: #1a1d24; border: 1px solid #2a2f3a; border-radius: 10px; padding: 1rem 1.25rem; margin: 1rem 0; }
  .tool { font-weight: 600; font-size: 1.05rem; }
  .rule { color: #f5a623; font-size: .85rem; }
  .reason { opacity: .85; margin: .35rem 0; }
  pre { background: #0c0e12; border-radius: 6px; padding: .6rem .8rem; overflow-x: auto; font-size: .85rem; margin: .5rem 0; }
  .actions { display: flex; gap: .75rem; margin-top: .75rem; }
  button { border: 0; border-radius: 8px; padding: .5rem 1.1rem; font-size: .95rem; font-weight: 600; cursor: pointer; }
  .allow { background: #1f8f4e; color: #fff; }
  .deny { background: #b3341f; color: #fff; }
  .age { opacity: .5; font-size: .8rem; }
</style>
</head>
<body>
<h1>🛡️ mcp-firewall — pending approvals</h1>
<div id="list"><p class="empty">Waiting for tool calls that need approval…</p></div>
<script>
async function poll() {
  let items = [];
  try { items = await (await fetch('/api/pending')).json(); } catch {}
  const list = document.getElementById('list');
  if (!items.length) {
    list.innerHTML = '<p class="empty">No pending approvals. This tab updates automatically.</p>';
  } else {
    list.innerHTML = items.map(function (it) {
      var rule = it.rule ? '<div class="rule">rule: ' + it.rule + '</div>' : '';
      var reason = it.reason ? '<div class="reason">' + escapeHtml(it.reason) + '</div>' : '';
      var args = escapeHtml(JSON.stringify(it.args, null, 2));
      return '<div class="card">'
        + '<div class="tool">' + escapeHtml(it.tool) + ' <span class="age">' + Math.round(it.ageMs/1000) + 's ago</span></div>'
        + rule + reason
        + '<pre>' + args + '</pre>'
        + '<div class="reason age">server: ' + escapeHtml(it.server) + '</div>'
        + '<div class="actions">'
        + '<button class="allow" onclick="decide(\\'' + it.id + '\\', true)">Approve</button>'
        + '<button class="deny" onclick="decide(\\'' + it.id + '\\', false)">Deny</button>'
        + '</div></div>';
    }).join('');
  }
}
async function decide(id, approved) {
  await fetch('/api/decide', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: id, approved: approved }) });
  poll();
}
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, function (c) { return ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[c]; }); }
poll();
setInterval(poll, 1000);
</script>
</body>
</html>`;
