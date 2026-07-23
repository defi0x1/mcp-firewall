/**
 * The interface the interceptor depends on for `ask` decisions. Kept separate
 * so the interceptor doesn't import the HTTP server directly, and tests can
 * inject a fake approver.
 */

export interface ApprovalRequest {
  server: string;
  tool: string;
  args: unknown;
  rule?: string;
  reason?: string;
}

export interface Approver {
  /** Resolve true to allow the call, false to deny it. */
  request(input: ApprovalRequest): Promise<boolean>;
}
