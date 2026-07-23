import { describe, it, expect } from "vitest";
import { detectSecrets } from "./secrets.js";

describe("detectSecrets", () => {
  it("flags an AWS access key id", () => {
    const f = detectSecrets("key is AKIAIOSFODNN7EXAMPLE here");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ detector: "aws-access-key", severity: "high", match: "AKIAIOSFODNN7EXAMPLE" });
  });

  it("flags GitHub tokens", () => {
    const f = detectSecrets("token=ghp_" + "a".repeat(36));
    expect(f.some((x) => x.detector === "github-token")).toBe(true);
  });

  it("flags a Slack token", () => {
    const f = detectSecrets("xoxb-123456789012-abcdefABCDEF");
    expect(f.some((x) => x.detector === "slack-token")).toBe(true);
  });

  it("flags a private key block", () => {
    const f = detectSecrets("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n");
    expect(f.some((x) => x.detector === "private-key")).toBe(true);
  });

  it("flags a generic secret assignment and captures the value", () => {
    const f = detectSecrets('api_key = "sk_live_abcdefghijklmnop"');
    const generic = f.find((x) => x.detector === "generic-secret");
    expect(generic).toBeDefined();
    expect(generic!.match).toBe("sk_live_abcdefghijklmnop");
  });

  it("does not flag ordinary prose", () => {
    expect(detectSecrets("The quick brown fox jumps over the lazy dog.")).toHaveLength(0);
  });

  it("does not flag a short non-secret assignment", () => {
    // Below the 16-char minimum for the generic matcher.
    expect(detectSecrets("password = short")).toHaveLength(0);
  });

  it("finds multiple secrets in one text", () => {
    const f = detectSecrets("AKIAIOSFODNN7EXAMPLE and ghp_" + "b".repeat(36));
    expect(f.length).toBeGreaterThanOrEqual(2);
  });
});
