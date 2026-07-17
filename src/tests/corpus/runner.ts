/**
 * Executes RuleCase corpus entries against the real CHECKS registry.
 *
 * Each case gets its own throwaway workspace (mkdtemp) containing exactly one
 * file — the positive or negative sample — so a check's file discovery
 * (scopedFg/searchRepo, both workspace-root-scoped) never sees anything else.
 * We call the check's run() directly, bypassing its surface `when()` gate
 * (surfaces are forced all-true in the shared ctx), since a corpus case targets
 * one named check regardless of what surface auto-detection would infer from a
 * single-file temp directory.
 */
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path, { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CHECKS, loadPolicy, type CheckCtx, type Policy } from "../../gate/policy.js";
import { withWorkspace } from "../../repo/workspace.js";
import type { RuleCase } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
// dist/tests/corpus/runner.js -> repo root is three levels up.
const PKG_ROOT = resolve(__dirname, "../../..");

/** Load the shipped default policy, scoped to the package root so its relative path resolves. */
export async function loadCorpusPolicy(): Promise<Policy> {
  return withWorkspace(PKG_ROOT, () => loadPolicy(join("defaults", "security-policy.json")));
}

function baseCtx(policy: Policy): CheckCtx {
  return {
    policy,
    changedFiles: [],
    targets: [],
    surfaces: { web: true, api: true, infra: true, mobileIos: true, mobileAndroid: true, ai: true, agentic: true },
    scannerReadiness: { findings: [], configured: [], missing: [] },
    evidenceCoverage: { findings: [] },
    stagingUrl: undefined
  };
}

async function fires(
  checkName: string,
  policy: Policy,
  sample: { file: string; content: string },
  ruleId: string
): Promise<boolean> {
  const def = CHECKS.find((d) => d.name === checkName);
  if (!def) throw new Error(`Unknown check "${checkName}" (no CHECKS entry) referenced by rule ${ruleId}`);

  const tmp = mkdtempSync(path.join(tmpdir(), "rule-corpus-"));
  try {
    const target = path.join(tmp, sample.file);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, sample.content, "utf-8");
    const findings = await withWorkspace(tmp, () => def.run({ ...baseCtx(policy), changedFiles: [sample.file] }));
    return findings.some((f) => f.id === ruleId);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

export type CaseResult = {
  ruleId: string;
  check: string;
  /** Did the rule fire on the positive (vulnerable) sample? Should be true. */
  truePositive: boolean;
  /** Did the rule ALSO fire on the negative (safe) sample? Should be false. */
  falsePositive: boolean;
};

export async function runCase(policy: Policy, kase: RuleCase): Promise<CaseResult> {
  const [truePositive, falsePositive] = await Promise.all([
    fires(kase.check, policy, kase.positive, kase.ruleId),
    fires(kase.check, policy, kase.negative, kase.ruleId)
  ]);
  return { ruleId: kase.ruleId, check: kase.check, truePositive, falsePositive };
}

export type RuleQualityReport = {
  generatedAt: string;
  totalCases: number;
  tpRate: number;
  fpRate: number;
  failures: Array<{ ruleId: string; check: string; issue: "did-not-fire-on-positive" | "fired-on-negative" }>;
};

export function summarize(results: CaseResult[]): RuleQualityReport {
  const totalCases = results.length;
  const tpHits = results.filter((r) => r.truePositive).length;
  const fpHits = results.filter((r) => r.falsePositive).length;
  const failures: RuleQualityReport["failures"] = [];
  for (const r of results) {
    if (!r.truePositive) failures.push({ ruleId: r.ruleId, check: r.check, issue: "did-not-fire-on-positive" });
    if (r.falsePositive) failures.push({ ruleId: r.ruleId, check: r.check, issue: "fired-on-negative" });
  }
  return {
    generatedAt: new Date().toISOString(),
    totalCases,
    tpRate: totalCases > 0 ? tpHits / totalCases : 0,
    fpRate: totalCases > 0 ? fpHits / totalCases : 0,
    failures
  };
}
