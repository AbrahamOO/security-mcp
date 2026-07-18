import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";
import { Finding } from "../result.js";
import { detectBicep, detectCloudFormation, detectTerraform, Violation } from "../cloud-controls/detect.js";
import { CloudRule, loadCloudRulesWithStatus } from "../cloud-controls/types.js";

// .tf = Terraform (HCL); .bicep = Bicep; json/yaml/template are CloudFormation/SAM
// candidates (gated by a content check so arbitrary JSON/YAML is skipped cheaply).
const GLOBS = ["**/*.tf", "**/*.bicep", "**/*.json", "**/*.yaml", "**/*.yml", "**/*.template"];
const IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/.claude/**",
  "src/gate/**"
];

function detectForFile(file: string, text: string, rules: CloudRule[]): Violation[] {
  if (file.endsWith(".tf")) return detectTerraform(file, text, rules);
  if (file.endsWith(".bicep")) return detectBicep(file, text, rules);
  return detectCloudFormation(file, text, rules);
}

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
  const { rules, failedProviders } = await loadCloudRulesWithStatus();

  const findings: Finding[] = [];
  if (failedProviders.length > 0) {
    const scope = failedProviders.length === 3 ? "all providers" : failedProviders.join("/");
    findings.push({
      id: "EVAL_UNAVAILABLE_CLOUD_CONTROLS",
      title: `Cloud-control ruleset failed to load for ${failedProviders.join(", ")} — IaC misconfiguration status for ${scope} is UNKNOWN, not clean`,
      severity: "HIGH",
      evidence: failedProviders.map((p) => `defaults/cloud-controls/${p}.json could not be read`),
      requiredActions: [
        "Verify the security-mcp package installation is complete and not corrupted (reinstall with npm install).",
        `Confirm ${failedProviders.map((p) => `defaults/cloud-controls/${p}.json`).join(", ")} exist and are readable.`,
        "Do not treat this run as evidence that infrastructure-as-code for the affected provider(s) is free of misconfigurations."
      ]
    });
  }
  if (rules.length === 0) return findings;

  const files = await fg(GLOBS, { dot: true, followSymbolicLinks: false, ignore: IGNORE });
  const byRule = new Map<string, Violation[]>();

  for (const file of files) {
    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue;
    }
    for (const v of detectForFile(file, text, rules)) {
      const list = byRule.get(v.rule.ruleId);
      if (list) list.push(v);
      else byRule.set(v.rule.ruleId, [v]);
    }
  }

  for (const [ruleId, violations] of byRule) {
    findings.push(toFinding(ruleId, violations[0].rule, violations));
  }
  return findings;
}
