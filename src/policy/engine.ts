/**
 * Policy engine (ROADMAP M3).
 *
 * Loads declarative allow/deny/ask rules from YAML and evaluates a tool call
 * against them. Rules are checked top to bottom; the FIRST rule whose matchers
 * all pass wins. If nothing matches, the policy's `default` action applies.
 *
 * The vocabulary is deliberately small (three matchers) — a human must be able
 * to read their whole security posture in the YAML file (DESIGN D5). Grow it
 * only when a real rule needs it.
 */

import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import type { Decision } from "../types.js";

// ── Schema ────────────────────────────────────────────────────────────────────

const decisionSchema = z.enum(["allow", "deny", "ask"]);

const matchSpecSchema = z
  .object({
    /** Glob on the tool name. `*` matches any run of characters. */
    tool: z.string().optional(),
    /** Regex tested against the JSON-serialized arguments. */
    args_regex: z.string().optional(),
    /** Matches if any path-like argument resolves outside this base directory. */
    path_outside: z.string().optional(),
  })
  .strict();

const ruleSchema = z
  .object({
    name: z.string(),
    action: decisionSchema,
    match: matchSpecSchema,
    reason: z.string().optional(),
  })
  .strict();

const policySchema = z
  .object({
    version: z.number(),
    default: decisionSchema.default("allow"),
    rules: z.array(ruleSchema).default([]),
  })
  .strict();

export type MatchSpec = z.infer<typeof matchSpecSchema>;
export type PolicyRule = z.infer<typeof ruleSchema>;
export type Policy = z.infer<typeof policySchema>;

// ── Evaluation ──────────────────────────────────────────────────────────────

/** The tool call being evaluated. */
export interface EvalInput {
  tool: string;
  args: unknown;
}

export interface EvalResult {
  decision: Decision;
  rule?: string; // name of the matched rule, if any
  reason?: string;
}

export class PolicyEngine {
  constructor(private readonly policy: Policy) {}

  /** Parse + validate a YAML policy file and build an engine. */
  static async load(filePath: string): Promise<PolicyEngine> {
    const raw = await readFile(filePath, "utf8");
    const parsed = parseYaml(raw);
    const result = policySchema.safeParse(parsed);
    if (!result.success) {
      const issues = result.error.issues.map((i) => `  - ${i.path.join(".")}: ${i.message}`).join("\n");
      throw new Error(`Invalid policy file ${filePath}:\n${issues}`);
    }
    return new PolicyEngine(result.data);
  }

  /** Build directly from an already-parsed policy (used in tests). */
  static fromPolicy(policy: Policy): PolicyEngine {
    return new PolicyEngine(policySchema.parse(policy));
  }

  evaluate(input: EvalInput): EvalResult {
    for (const rule of this.policy.rules) {
      if (matches(rule.match, input)) {
        return { decision: rule.action, rule: rule.name, reason: rule.reason };
      }
    }
    return { decision: this.policy.default };
  }
}

// ── Matchers ──────────────────────────────────────────────────────────────────

/** A rule matches when EVERY specified matcher passes (AND semantics). */
function matches(spec: MatchSpec, input: EvalInput): boolean {
  if (spec.tool !== undefined && !globToRegex(spec.tool).test(input.tool)) return false;
  if (spec.args_regex !== undefined && !new RegExp(spec.args_regex).test(safeJson(input.args))) {
    return false;
  }
  if (spec.path_outside !== undefined && !matchesPathOutside(input.args, spec.path_outside)) {
    return false;
  }
  // An empty match ({}) matches everything — that's intentional (a catch-all rule).
  return true;
}

/** Convert a `*`-glob to an anchored, case-insensitive regex. */
export function globToRegex(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "i");
}

/**
 * True if any path-like string argument, resolved relative to `base`, escapes
 * `base`. "Path-like" = contains a slash (so ordinary words aren't treated as
 * paths). Absolute paths and `../` traversal both resolve outside naturally.
 */
export function matchesPathOutside(args: unknown, base: string): boolean {
  const baseResolved = resolve(base);
  for (const value of stringValues(args)) {
    if (!looksLikePath(value)) continue;
    const resolved = resolve(baseResolved, value);
    if (resolved !== baseResolved && !resolved.startsWith(baseResolved + sep)) {
      return true;
    }
  }
  return false;
}

function looksLikePath(value: string): boolean {
  return value.includes("/") || value.includes("\\");
}

/** Recursively collect every string value in a JSON-ish structure. */
function stringValues(value: unknown): string[] {
  const out: string[] = [];
  const walk = (v: unknown): void => {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.values(v).forEach(walk);
  };
  walk(value);
  return out;
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return String(value);
  }
}
