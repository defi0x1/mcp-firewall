/**
 * Audit log — append-only JSONL.
 *
 * One JSON object per line. Append-only means it's streamable, greppable, and
 * trivial to build a trace-viewer on later (backlog). We serialize writes
 * through an internal promise chain so concurrent appends can't interleave and
 * corrupt a line.
 */

import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { AuditRecord } from "../types.js";

/** Default location: `<cwd>/.mcp-firewall/audit.jsonl` (gitignored). */
export function defaultAuditPath(cwd: string = process.cwd()): string {
  return join(cwd, ".mcp-firewall", "audit.jsonl");
}

export class AuditLog {
  private writeChain: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  /**
   * Append a record. Returns a promise that resolves once *this* record is on
   * disk, but callers may fire-and-forget: writes are queued in order, so the
   * proxy never blocks message forwarding on disk I/O.
   */
  append(record: AuditRecord): Promise<void> {
    const line = JSON.stringify(record) + "\n";
    this.writeChain = this.writeChain.then(async () => {
      await mkdir(dirname(this.filePath), { recursive: true });
      await appendFile(this.filePath, line, "utf8");
    });
    return this.writeChain;
  }

  /** Read and parse every record. Skips blank/corrupt lines defensively. */
  async read(): Promise<AuditRecord[]> {
    let raw: string;
    try {
      raw = await readFile(this.filePath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const records: AuditRecord[] = [];
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.length === 0) continue;
      try {
        records.push(JSON.parse(trimmed) as AuditRecord);
      } catch {
        // A partially-written or hand-edited line — skip rather than crash.
      }
    }
    return records;
  }
}
