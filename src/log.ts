/**
 * Tiny stderr logger. stdout is reserved for the MCP protocol stream, so every
 * diagnostic in this project goes to stderr through here.
 */

export function logStderr(line: string): void {
  process.stderr.write(`[mcp-firewall] ${line}\n`);
}

/**
 * Describe a JSON-RPC message in one short line for passthrough logging.
 * Defensive about shape: a message may be a request (method + id), a
 * notification (method, no id), or a response (id + result/error).
 */
export function describeMessage(message: unknown): string {
  if (typeof message !== "object" || message === null) return "<non-object>";
  const m = message as Record<string, unknown>;

  const hasId = "id" in m && m.id !== undefined;
  const hasMethod = typeof m.method === "string";

  if (hasMethod && hasId) return `request  ${m.method as string} (id=${String(m.id)})`;
  if (hasMethod && !hasId) return `notify   ${m.method as string}`;
  if (hasId && "error" in m) return `response error (id=${String(m.id)})`;
  if (hasId) return `response ok    (id=${String(m.id)})`;
  return "<unknown message shape>";
}
