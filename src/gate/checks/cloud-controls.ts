import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";
import { Finding } from "../result.js";
import { detectTerraform, Violation } from "../cloud-controls/detect.js";
import { CloudRule, loadCloudRules } from "../cloud-controls/types.js";

const TF_GLOBS = ["**/*.tf"];
const IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/.claude/**",
  "src/gate/**"
];

const MAX_EVIDENCE = 20;

function toFinding(ruleId: string, rule: CloudRule, violations: Violation[]): Finding {
  const files = Array.from(new Set(violations.map((v) => v.file)));
  return {
    id: ruleId,
    title: `${rule.title} — ${rule.threat}`,
    severity: rule.severity,
    evidence: violations
      .slice(0, MAX_EVIDENCE)
      .map((v) => `${v.file}:${v.line}: ${rule.detect.resourceType} — ${v.reason}`),
    files,
    requiredActions: rule.requiredActions
  };
}

/**
 * Threat-detection pass over the FSBP/CIS cloud-control ruleset. Pure — emits
 * Findings, never mutates files. Auto-remediation lives in cloud-controls/apply.ts
 * and is invoked explicitly (CLI `autoharden`), not during the read-only gate.
 */
export async function checkCloudControls(opts: { changedFiles: string[] }): Promise<Finding[]> {
  void opts; // matching scans the whole working tree, consistent with checkIac
  const rules = await loadCloudRules();
  if (rules.length === 0) return [];

  const files = await fg(TF_GLOBS, { dot: true, followSymbolicLinks: false, ignore: IGNORE });
  const byRule = new Map<string, Violation[]>();

  for (const file of files) {
    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue;
    }
    for (const v of detectTerraform(file, text, rules)) {
      const list = byRule.get(v.rule.ruleId);
      if (list) list.push(v);
      else byRule.set(v.rule.ruleId, [v]);
    }
  }

  const findings: Finding[] = [];
  for (const [ruleId, violations] of byRule) {
    findings.push(toFinding(ruleId, violations[0].rule, violations));
  }
  return findings;
}
