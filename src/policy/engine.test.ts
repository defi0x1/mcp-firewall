import { describe, it, expect } from "vitest";
import { PolicyEngine, globToRegex, matchesPathOutside, type Policy } from "./engine.js";

describe("globToRegex", () => {
  it("matches with * wildcards, case-insensitively", () => {
    expect(globToRegex("*bash*").test("run_bash")).toBe(true);
    expect(globToRegex("*bash*").test("BASH")).toBe(true);
    expect(globToRegex("*write*").test("read_file")).toBe(false);
    expect(globToRegex("echo").test("echo")).toBe(true);
    expect(globToRegex("echo").test("echoes")).toBe(false); // anchored
  });

  it("treats regex specials literally except *", () => {
    expect(globToRegex("get.weather").test("getXweather")).toBe(false); // . is literal
    expect(globToRegex("get.weather").test("get.weather")).toBe(true);
  });
});

describe("matchesPathOutside", () => {
  const base = "/home/user/project";

  it("matches absolute paths outside the base", () => {
    expect(matchesPathOutside({ path: "/etc/passwd" }, base)).toBe(true);
  });

  it("matches ../ traversal escaping the base", () => {
    expect(matchesPathOutside({ path: "../secrets/keys.txt" }, base)).toBe(true);
  });

  it("does not match paths inside the base", () => {
    expect(matchesPathOutside({ path: "src/index.ts" }, base)).toBe(false);
    expect(matchesPathOutside({ path: "./README.md" }, base)).toBe(false);
  });

  it("ignores non-path strings", () => {
    expect(matchesPathOutside({ text: "hello world" }, base)).toBe(false);
  });

  it("scans nested args", () => {
    expect(matchesPathOutside({ opts: { files: ["ok.txt", "/etc/shadow"] } }, base)).toBe(true);
  });
});

describe("PolicyEngine.evaluate", () => {
  const policy: Policy = {
    version: 1,
    default: "allow",
    rules: [
      {
        name: "block-destructive-shell",
        action: "deny",
        match: { tool: "*bash*", args_regex: "rm\\s+-rf" },
        reason: "Destructive shell command.",
      },
      {
        name: "ask-secrets",
        action: "ask",
        match: { tool: "*read*", args_regex: "\\.env" },
        reason: "Reading a secrets file.",
      },
    ],
  };
  const engine = PolicyEngine.fromPolicy(policy);

  it("denies a matching destructive shell call", () => {
    const r = engine.evaluate({ tool: "run_bash", args: { command: "rm -rf /tmp/x" } });
    expect(r.decision).toBe("deny");
    expect(r.rule).toBe("block-destructive-shell");
    expect(r.reason).toContain("Destructive");
  });

  it("requires ALL matchers in a rule (AND semantics)", () => {
    // tool matches *bash* but args don't contain rm -rf → rule does not fire
    const r = engine.evaluate({ tool: "run_bash", args: { command: "ls -la" } });
    expect(r.decision).toBe("allow"); // falls through to default
    expect(r.rule).toBeUndefined();
  });

  it("returns ask for a matching ask rule", () => {
    const r = engine.evaluate({ tool: "read_file", args: { path: "/app/.env" } });
    expect(r.decision).toBe("ask");
    expect(r.rule).toBe("ask-secrets");
  });

  it("first matching rule wins", () => {
    const ordered = PolicyEngine.fromPolicy({
      version: 1,
      default: "allow",
      rules: [
        { name: "first", action: "deny", match: { tool: "x" } },
        { name: "second", action: "allow", match: { tool: "x" } },
      ],
    });
    expect(ordered.evaluate({ tool: "x", args: {} }).rule).toBe("first");
  });

  it("applies the default when nothing matches", () => {
    const denyByDefault = PolicyEngine.fromPolicy({ version: 1, default: "deny", rules: [] });
    expect(denyByDefault.evaluate({ tool: "anything", args: {} }).decision).toBe("deny");
  });
});
