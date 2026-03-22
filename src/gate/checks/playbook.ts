/**
 * IR Playbook enforcement checks.
 * Verifies incident response playbooks exist and contain required sections.
 */
import { stat } from "node:fs/promises";
import { join } from "node:path";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";
import { Finding } from "../result.js";
import { SurfaceScope } from "../catalog.js";

const PLAYBOOK_BASE = "security/playbooks";

interface PlaybookRequirement {
  surface: keyof SurfaceScope | "payments";
  path: string;
  description: string;
}

const REQUIRED_PLAYBOOKS: PlaybookRequirement[] = [
  { surface: "web", path: "web-compromise.md", description: "Web compromise" },
  { surface: "api", path: "api-compromise.md", description: "API compromise" },
  { surface: "ai", path: "llm-prompt-injection.md", description: "LLM prompt injection" },
  { surface: "ai", path: "model-data-poisoning.md", description: "Model data poisoning" },
  { surface: "infra", path: "cloud-misconfiguration.md", description: "Cloud misconfiguration" },
  { surface: "infra", path: "ransomware.md", description: "Ransomware" },
  { surface: "mobileIos", path: "mobile-credential-theft.md", description: "Mobile credential theft" },
  { surface: "mobileAndroid", path: "mobile-credential-theft.md", description: "Mobile credential theft" },
  { surface: "payments", path: "payment-fraud.md", description: "Payment fraud" },
  { surface: "payments", path: "pci-breach.md", description: "PCI breach" }
];

const REQUIRED_SECTIONS = [
  { key: "detection", patterns: [/detection criteria/i, /how to detect/i, /indicators of compromise/i, /detection/i] },
  { key: "escalation", patterns: [/escalation/i, /incident commander/i, /security lead/i, /on-call/i] },
  { key: "containment", patterns: [/containment/i, /contain/i, /isolat/i] },
  { key: "eradication", patterns: [/eradication/i, /eradicate/i, /root cause/i] },
  { key: "recovery", patterns: [/recovery/i, /restore/i, /recover/i] },
  { key: "communication", patterns: [/communication/i, /notification/i, /stakeholder/i, /template/i] },
  { key: "post-incident", patterns: [/post.incident/i, /lessons learned/i, /review/i, /retrospective/i] },
  { key: "mttd-mttr", patterns: [/mttd|mttr|mean time/i, /target.{0,30}time/i, /response time/i] }
];

const STALE_THRESHOLD_MS = 180 * 24 * 60 * 60 * 1000; // 180 days

function surfaceActive(
  surface: PlaybookRequirement["surface"],
  surfaces: SurfaceScope,
  activeSurfaces: Set<string>
): boolean {
  if (surface === "payments") return activeSurfaces.has("payments");
  if (surface === "mobileIos") return surfaces.mobileIos;
  if (surface === "mobileAndroid") return surfaces.mobileAndroid;
  return surfaces[surface as keyof SurfaceScope] === true;
}

async function validatePlaybook(playbookPath: string): Promise<{ missingSections: string[]; isStale: boolean }> {
  const missingSections: string[] = [];
  let content = "";
  let isStale = false;

  try {
    content = await readFileSafe(playbookPath);
  } catch {
    return { missingSections: REQUIRED_SECTIONS.map((s) => s.key), isStale: false };
  }

  for (const section of REQUIRED_SECTIONS) {
    const found = section.patterns.some((pattern) => pattern.test(content));
    if (!found) {
      missingSections.push(section.key);
    }
  }

  try {
    const s = await stat(playbookPath);
    if (Date.now() - s.mtimeMs > STALE_THRESHOLD_MS) {
      isStale = true;
    }
  } catch { /* ignore */ }

  return { missingSections, isStale };
}

/**
 * Checks that IR playbooks exist and contain required sections for active surfaces.
 */
export async function runPlaybookChecks(opts: {
  changedFiles: string[];
  surfaces: SurfaceScope;
}): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Detect if payments surface is active via file patterns
  const activeSurfaces = new Set<string>();
  const paymentPatterns = /payment|stripe|braintree|adyen|checkout|pci/i;
  if (opts.changedFiles.some((f) => paymentPatterns.test(f))) {
    activeSurfaces.add("payments");
  }
  // Also scan repo for payment references
  try {
    const paymentFiles = await fg(["**/payment*.ts", "**/stripe*.ts", "**/checkout*.ts"], {
      dot: true,
      ignore: ["**/node_modules/**", "**/dist/**"]
    });
    if (paymentFiles.length > 0) activeSurfaces.add("payments");
  } catch { /* ignore */ }

  // Deduplicate required playbooks per surface
  const checked = new Set<string>();

  for (const req of REQUIRED_PLAYBOOKS) {
    if (!surfaceActive(req.surface, opts.surfaces, activeSurfaces)) continue;

    const playbookPath = join(PLAYBOOK_BASE, req.path);
    if (checked.has(playbookPath)) continue;
    checked.add(playbookPath);

    // Check if playbook exists
    let exists = false;
    try {
      const matches = await fg([playbookPath], { dot: true });
      exists = matches.length > 0;
    } catch { /* ignore */ }

    if (!exists) {
      findings.push({
        id: "IR_PLAYBOOK_MISSING",
        title: `IR playbook missing: ${req.description} (${playbookPath})`,
        severity: "HIGH",
        evidence: [`Expected path: ${playbookPath}`, `Surface: ${req.surface}`],
        requiredActions: [
          `Create the IR playbook at ${playbookPath}.`,
          "Include all required sections: detection criteria, escalation path, containment, eradication, recovery, communication, post-incident review, and MTTD/MTTR targets."
        ]
      });
      continue;
    }

    const { missingSections, isStale } = await validatePlaybook(playbookPath);

    if (missingSections.length > 0) {
      findings.push({
        id: "IR_PLAYBOOK_INCOMPLETE",
        title: `IR playbook incomplete: ${playbookPath}`,
        severity: "MEDIUM",
        evidence: [`Missing sections: ${missingSections.join(", ")}`, `Path: ${playbookPath}`],
        requiredActions: [
          `Add the missing sections to ${playbookPath}: ${missingSections.join(", ")}.`,
          "Ensure each section has actionable steps, not just headers."
        ]
      });
    }

    if (isStale) {
      findings.push({
        id: "IR_PLAYBOOK_STALE",
        title: `IR playbook not updated in 180+ days: ${playbookPath}`,
        severity: "LOW",
        evidence: [`Path: ${playbookPath}`],
        requiredActions: [
          `Review and update ${playbookPath} to reflect current infrastructure and contacts.`,
          "Schedule quarterly playbook reviews."
        ]
      });
    }
  }

  return findings;
}

/**
 * Validate a single playbook file and return missing sections.
 */
export async function validateSinglePlaybook(playbookPath: string): Promise<{
  path: string;
  exists: boolean;
  missingSections: string[];
  isStale: boolean;
}> {
  let exists = false;
  try {
    const matches = await fg([playbookPath], { dot: true });
    exists = matches.length > 0;
  } catch { /* ignore */ }

  if (!exists) {
    return { path: playbookPath, exists: false, missingSections: REQUIRED_SECTIONS.map((s) => s.key), isStale: false };
  }

  const { missingSections, isStale } = await validatePlaybook(playbookPath);
  return { path: playbookPath, exists: true, missingSections, isStale };
}
