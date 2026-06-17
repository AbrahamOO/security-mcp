import { writeFile } from "node:fs/promises";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";
import { applyEnsures } from "./hcl.js";
import { detectTerraform, Violation } from "./detect.js";
import { CloudRule, loadCloudRules } from "./types.js";

const TF_GLOBS = ["**/*.tf"];
const IGNORE = ["**/node_modules/**", "**/.git/**", "**/dist/**", "**/.claude/**", "src/gate/**"];
const MAX_ITERATIONS = 500;

export type AppliedFix = { ruleId: string; file: string; resource: string; frameworks: string[] };
export type ManualFix = { ruleId: string; file: string; resource: string; reason: string; snippet?: string };

export type HardenReport = {
  applied: AppliedFix[];
  manual: ManualFix[];
  filesChanged: string[];
};

function violationKey(v: Violation): string {
  return `${v.rule.ruleId}@@${v.file}@@${v.block?.name ?? "?"}`;
}

function isAutoApplicable(rule: CloudRule): boolean {
  const s = rule.remediate.strategy;
  if (s === "manual") return false;
  if (s === "companion-resource") return Boolean(rule.remediate.companion);
  return Boolean(rule.remediate.ensure); // set-attr | insert-block
}

/** Apply a single violation's remediation to the document, returning new text (or unchanged). */
function applyOne(text: string, v: Violation): string {
  const { remediate } = v.rule;
  if (remediate.strategy === "companion-resource" && remediate.companion && v.block) {
    const snippet = remediate.companion.replaceAll("${name}", v.block.name);
    const sep = text.endsWith("\n") ? "\n" : "\n\n";
    return text + sep + snippet.trimEnd() + "\n";
  }
  if (remediate.ensure && v.block) {
    return applyEnsures(text, v.block, remediate.ensure);
  }
  return text;
}

/** Harden one Terraform document. Returns new text + per-violation outcomes. */
function hardenText(
  file: string,
  original: string,
  rules: CloudRule[]
): { text: string; applied: Violation[]; manual: Violation[] } {
  let text = original;
  const applied: Violation[] = [];
  const manualMap = new Map<string, Violation>();
  const skip = new Set<string>();

  for (let iter = 0; iter < MAX_ITERATIONS; iter++) {
    const violations = detectTerraform(file, text, rules);
    // Record manual / non-applicable violations once.
    for (const v of violations) {
      if (!isAutoApplicable(v.rule)) manualMap.set(violationKey(v), v);
    }
    const target = violations.find((v) => isAutoApplicable(v.rule) && !skip.has(violationKey(v)));
    if (!target) break;

    const key = violationKey(target);
    const candidate = applyOne(text, target);
    if (candidate === text) {
      skip.add(key);
      manualMap.set(key, target);
      continue;
    }
    // Verify the fix actually cleared this violation; otherwise revert + flag manual.
    const after = detectTerraform(file, candidate, rules);
    if (after.some((v) => violationKey(v) === key)) {
      skip.add(key);
      manualMap.set(key, target);
      continue;
    }
    text = candidate;
    applied.push(target);
  }

  return { text, applied, manual: Array.from(manualMap.values()) };
}

/**
 * Auto-harden every Terraform file in the working tree against the FSBP/CIS
 * ruleset. Writes changes in place when `write` is true (default). Each applied
 * edit is verified by re-running its own detector before being kept; edits that
 * cannot be applied safely are reported as manual.
 */
export async function autoHardenTree(opts?: { write?: boolean }): Promise<HardenReport> {
  const write = opts?.write !== false;
  const rules = await loadCloudRules();
  const report: HardenReport = { applied: [], manual: [], filesChanged: [] };
  if (rules.length === 0) return report;

  const files = await fg(TF_GLOBS, { dot: true, followSymbolicLinks: false, ignore: IGNORE });
  for (const file of files) {
    let original = "";
    try {
      original = await readFileSafe(file);
    } catch {
      continue;
    }
    const { text, applied, manual } = hardenText(file, original, rules);

    for (const v of applied) {
      report.applied.push({
        ruleId: v.rule.ruleId,
        file,
        resource: `${v.rule.detect.resourceType}.${v.block?.name ?? "?"}`,
        frameworks: v.rule.frameworks
      });
    }
    for (const v of manual) {
      report.manual.push({
        ruleId: v.rule.ruleId,
        file,
        resource: `${v.rule.detect.resourceType}.${v.block?.name ?? "?"}`,
        reason: v.reason,
        snippet: v.rule.remediate.snippet
      });
    }
    if (text !== original) {
      report.filesChanged.push(file);
      if (write) await writeFile(file, text, "utf-8");
    }
  }
  return report;
}
