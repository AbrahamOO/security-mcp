import { readFile } from "node:fs/promises";
import fg from "fast-glob";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "./result.js";
import type { Policy } from "./policy.js";
import type { CatalogControl, SurfaceScope } from "./catalog.js";
import { loadControlCatalog, controlApplies } from "./catalog.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "../..");

type EvidenceMap = Record<string, string[]>;

export type ControlStatus = {
  id: string;
  description: string;
  automation: "workflow" | "evidence" | "tooling" | "approval";
  frameworks: string[];
  status: "satisfied" | "missing" | "risk_accepted" | "not_applicable";
  details: string[];
};

async function loadEvidenceMap(): Promise<EvidenceMap> {
  const overridePath = process.env["SECURITY_GATE_EVIDENCE_MAP"];
  if (overridePath) {
    const raw = await readFile(join(process.cwd(), overridePath), "utf-8");
    return JSON.parse(raw) as EvidenceMap;
  }

  try {
    const raw = await readFile(join(process.cwd(), ".mcp", "mappings", "evidence-map.json"), "utf-8");
    return JSON.parse(raw) as EvidenceMap;
  } catch {
    const raw = await readFile(join(PKG_ROOT, "defaults", "evidence-map.json"), "utf-8");
    return JSON.parse(raw) as EvidenceMap;
  }
}

function getPolicyControl(policy: Policy, control: CatalogControl) {
  return policy.requirements.find((requirement) => requirement.id === control.id);
}

export async function evaluateEvidenceCoverage(opts: {
  policy: Policy;
  surfaces: SurfaceScope;
}): Promise<{ findings: Finding[]; controls: ControlStatus[] }> {
  const evidenceMap = await loadEvidenceMap();
  const catalog = await loadControlCatalog();
  const findings: Finding[] = [];
  const controls: ControlStatus[] = [];

  for (const control of catalog.controls) {
    if (!controlApplies(control, opts.surfaces)) {
      controls.push({
        id: control.id,
        description: control.description,
        automation: control.automation,
        frameworks: control.frameworks,
        status: "not_applicable",
        details: ["Surface not in scope for this review."]
      });
      continue;
    }

    if (control.automation !== "evidence") {
      controls.push({
        id: control.id,
        description: control.description,
        automation: control.automation,
        frameworks: control.frameworks,
        status: "not_applicable",
        details: ["Resolved outside evidence coverage evaluation."]
      });
      continue;
    }

    const policyControl = getPolicyControl(opts.policy, control);
    const evidenceIds = policyControl?.evidence ?? control.evidence ?? [];
    const missingMappings = evidenceIds.filter((evidenceId) => !evidenceMap[evidenceId]);

    if (missingMappings.length > 0) {
      findings.push({
        id: "EVIDENCE_MAPPING_MISSING",
        title: `Evidence mapping missing for control ${control.id}`,
        severity: "HIGH",
        evidence: missingMappings,
        requiredActions: [
          "Add the missing evidence IDs to .mcp/mappings/evidence-map.json.",
          "Map each control to file globs that prove the control exists."
        ]
      });
    }

    const matchedEvidence: string[] = [];
    const missingEvidence: string[] = [];
    for (const evidenceId of evidenceIds) {
      const globs = evidenceMap[evidenceId] ?? [];
      const matches = await fg(globs, {
        dot: true,
        onlyFiles: true,
        ignore: ["**/node_modules/**", "**/.git/**", "**/dist/**"]
      });
      if (matches.length === 0) {
        missingEvidence.push(evidenceId);
      } else {
        matchedEvidence.push(`${evidenceId}: ${matches[0]}`);
      }
    }

    if (missingEvidence.length > 0) {
      findings.push({
        id: "CONTROL_EVIDENCE_MISSING",
        title: `Required evidence missing for control ${control.id}`,
        severity: "HIGH",
        evidence: missingEvidence,
        requiredActions: [
          `Implement or surface evidence for control ${control.id}.`,
          "Add or update code, tests, or config so the evidence globs resolve."
        ]
      });
      controls.push({
        id: control.id,
        description: control.description,
        automation: control.automation,
        frameworks: control.frameworks,
        status: "missing",
        details: missingEvidence
      });
      continue;
    }

    controls.push({
      id: control.id,
      description: control.description,
      automation: control.automation,
      frameworks: control.frameworks,
      status: "satisfied",
      details: matchedEvidence
    });
  }

  return { findings, controls };
}
