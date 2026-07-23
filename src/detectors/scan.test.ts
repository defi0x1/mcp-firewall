import { describe, it, expect } from "vitest";
import { redactText, scanToolResult } from "./scan.js";
import type { Finding } from "../types.js";

describe("redactText", () => {
  it("replaces each finding's match with an annotation", () => {
    const findings: Finding[] = [
      { detector: "aws-access-key", severity: "high", message: "AWS", match: "AKIAIOSFODNN7EXAMPLE" },
    ];
    const out = redactText("key AKIAIOSFODNN7EXAMPLE end", findings);
    expect(out).toBe("key [REDACTED:aws-access-key] end");
  });

  it("redacts every occurrence of the same secret once per unique value", () => {
    const findings: Finding[] = [
      { detector: "token", severity: "high", message: "t", match: "SECRETVALUE12345" },
    ];
    const out = redactText("a SECRETVALUE12345 b SECRETVALUE12345", findings);
    expect(out).toBe("a [REDACTED:token] b [REDACTED:token]");
  });
});

describe("scanToolResult", () => {
  const resultWithSecret = {
    content: [{ type: "text", text: "config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" }],
  };

  it("finds secrets and returns a redacted copy when redact=true", () => {
    const { findings, redacted } = scanToolResult(resultWithSecret, true);
    expect(findings.length).toBeGreaterThan(0);
    const text = (redacted as typeof resultWithSecret).content[0]!.text;
    expect(text).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(text).toContain("[REDACTED:aws-access-key]");
    // original is untouched (we returned a copy)
    expect(resultWithSecret.content[0]!.text).toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("finds secrets but leaves the result intact when redact=false", () => {
    const { findings, redacted } = scanToolResult(resultWithSecret, false);
    expect(findings.length).toBeGreaterThan(0);
    expect(redacted).toBe(resultWithSecret); // same reference, unmodified
  });

  it("returns no findings for a clean result", () => {
    const clean = { content: [{ type: "text", text: "all good here" }] };
    const { findings, redacted } = scanToolResult(clean, true);
    expect(findings).toHaveLength(0);
    expect(redacted).toBe(clean);
  });

  it("tolerates non-standard result shapes", () => {
    expect(scanToolResult(null, true).findings).toHaveLength(0);
    expect(scanToolResult({ notContent: 1 }, true).findings).toHaveLength(0);
  });
});
