import fg from "fast-glob";
import picomatch from "picomatch";
import { Finding } from "../result.js";
import { Policy } from "../policy.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Return true if at least one file matching any of the given glob patterns
 *  exists on disk. */
async function anyExists(patterns: string[]): Promise<boolean> {
  const hits = await fg(patterns, { dot: true });
  return hits.length > 0;
}

/** Return true if any of the changedFiles matches at least one picomatch
 *  pattern from `patterns`. */
function anyChanged(changedFiles: string[], patterns: string[]): boolean {
  const matchers = patterns.map((p) => picomatch(p, { dot: true }));
  return changedFiles.some((f) => matchers.some((m) => m(f)));
}

// ---------------------------------------------------------------------------
// Static check helpers — each returns 0 or 1 Finding(s)
// ---------------------------------------------------------------------------

async function checkThreatModel(): Promise<Finding[]> {
  const found = await anyExists([
    ".mcp/threat-model.json",
    ".mcp/threat-model.md",
    "docs/threat-model.json",
    "docs/threat-model.md",
    "security/threat-model.json",
    "security/threat-model.md",
    "**/threat-model.json",
    "**/threat-model.md"
  ]);
  if (found) return [];
  return [
    {
      id: "ARTIFACTS_NO_THREAT_MODEL",
      title: "No threat model file found in .mcp/, docs/, or security/",
      severity: "HIGH",
      evidence: [
        "Searched for: threat-model.json, threat-model.md under .mcp/, docs/, security/",
        "No match found."
      ],
      requiredActions: [
        "Create a threat model document (threat-model.json or threat-model.md) in .mcp/, docs/, or security/.",
        "Include STRIDE analysis, OWASP Top-10 mapping, MITRE ATT&CK mapping, trust boundaries, and data flow diagrams.",
        "Reference the threat model from your PR description and link it to changed components."
      ],
      sla: "7d"
    }
  ];
}

async function checkSbom(): Promise<Finding[]> {
  const found = await anyExists([
    "**/*.cdx.json",
    "**/*.spdx",
    "**/*.spdx.json",
    "**/sbom.json",
    "**/sbom.xml",
    "**/bom.json",
    "**/bom.xml"
  ]);
  if (found) return [];
  return [
    {
      id: "ARTIFACTS_NO_SBOM",
      title: "No SBOM (Software Bill of Materials) found in repository",
      severity: "HIGH",
      evidence: [
        "Searched for CycloneDX (.cdx.json, bom.json, bom.xml) and SPDX (.spdx, .spdx.json) files.",
        "No match found."
      ],
      requiredActions: [
        "Generate an SBOM in CycloneDX or SPDX format and commit it to the repository.",
        "For Node.js: `npx @cyclonedx/cyclonedx-npm --output-file sbom.json`.",
        "For Python: `cyclonedx-bom -o sbom.json`.",
        "Automate SBOM generation in CI so it stays current with every dependency change.",
        "Ensure the SBOM is included in any artifact upload to your registry (SLSA Level 2+)."
      ],
      sla: "7d"
    }
  ];
}

async function checkPentestSignoff(changedFiles: string[]): Promise<Finding[]> {
  const triggerPatterns = ["**/*payment*", "**/*auth*", "**/*checkout*", "**/*stripe*"];
  if (!anyChanged(changedFiles, triggerPatterns)) return [];

  const found = await anyExists([
    ".mcp/pentest-report*",
    "security/pentest-report*",
    ".mcp/*pentest*",
    "security/*pentest*"
  ]);
  if (found) return [];

  const triggeredFiles = changedFiles.filter((f) => anyChanged([f], triggerPatterns));
  return [
    {
      id: "ARTIFACTS_NO_PENTEST_SIGNOFF",
      title: "Payment/auth files changed but no pentest report or sign-off found",
      severity: "MEDIUM",
      evidence: [
        `Changed files triggering this check: ${triggeredFiles.slice(0, 10).join(", ")}`,
        "Searched .mcp/ and security/ for pentest-report* — no match found."
      ],
      requiredActions: [
        "Obtain a pentest sign-off for payment and authentication flows before shipping.",
        "Place the report as pentest-report-<date>.md (or .pdf) in .mcp/ or security/.",
        "The report must cover OWASP Top-10 auth/session flaws, insecure direct object references, and PCI DSS requirements 6.3-6.5.",
        "If a full pentest is not yet complete, document interim risk acceptance with CISO sign-off."
      ],
      sla: "30d"
    }
  ];
}

async function checkRedteamResults(changedFiles: string[]): Promise<Finding[]> {
  const triggerPatterns = ["**/*llm*", "**/*openai*", "**/*anthropic*", "**/*langchain*", "**/*rag*"];
  if (!anyChanged(changedFiles, triggerPatterns)) return [];

  const found = await anyExists([
    ".mcp/agent-runs/ai-findings*",
    ".mcp/agent-runs/redteam*",
    "security/ai-findings*",
    "security/redteam*",
    ".mcp/ai-findings*",
    ".mcp/redteam*"
  ]);
  if (found) return [];

  const triggeredFiles = changedFiles.filter((f) => anyChanged([f], triggerPatterns));
  return [
    {
      id: "ARTIFACTS_NO_REDTEAM_RESULTS",
      title: "AI/LLM files changed but no AI red team results found",
      severity: "MEDIUM",
      evidence: [
        `Changed files triggering this check: ${triggeredFiles.slice(0, 10).join(", ")}`,
        "Searched .mcp/agent-runs/ and security/ for ai-findings* or redteam* — no match found."
      ],
      requiredActions: [
        "Run an AI red team exercise covering prompt injection, indirect prompt injection, jailbreak attempts, and data exfiltration via LLM outputs.",
        "Document results in .mcp/agent-runs/redteam-<date>.md or security/ai-findings-<date>.md.",
        "Address any HIGH/CRITICAL findings before merging LLM-touching changes.",
        "Reference OWASP LLM Top 10 (LLM01–LLM10) and MITRE ATLAS tactics."
      ],
      sla: "30d"
    }
  ];
}

async function checkComplianceGap(changedFiles: string[]): Promise<Finding[]> {
  const triggerPatterns = ["**/*hipaa*", "**/*pci*", "**/*gdpr*", "**/*compliance*", "**/*policy*"];
  if (!anyChanged(changedFiles, triggerPatterns)) return [];

  const found = await anyExists([
    ".mcp/compliance-gap*",
    ".mcp/compliance-findings*",
    "security/compliance-gap*",
    "security/compliance-findings*",
    "docs/compliance-gap*",
    "docs/compliance-findings*"
  ]);
  if (found) return [];

  const triggeredFiles = changedFiles.filter((f) => anyChanged([f], triggerPatterns));
  return [
    {
      id: "ARTIFACTS_COMPLIANCE_GAP",
      title: "Compliance-related files changed but no compliance gap analysis found",
      severity: "MEDIUM",
      evidence: [
        `Changed files triggering this check: ${triggeredFiles.slice(0, 10).join(", ")}`,
        "Searched .mcp/, security/, and docs/ for compliance-gap* or compliance-findings* — no match found."
      ],
      requiredActions: [
        "Produce a compliance gap analysis document before merging compliance/policy changes.",
        "Place it as compliance-gap-<date>.md in .mcp/, security/, or docs/.",
        "The gap analysis must map each changed control to its framework requirement (HIPAA §164, PCI DSS 4.0, GDPR Art. 32, etc.).",
        "Document any residual risk and obtain sign-off from the compliance owner."
      ],
      sla: "30d"
    }
  ];
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function checkRequiredArtifacts(opts: {
  policy: Policy;
  changedFiles: string[];
}): Promise<Finding[]> {
  const findings: Finding[] = [];

  // 1. Policy-driven artifacts check (existing behaviour — do not change)
  for (const req of opts.policy.artifacts_required ?? []) {
    const matchers = req.on_changes.map((pattern) => picomatch(pattern, { dot: true }));
    const touched = opts.changedFiles.some((file) => matchers.some((match) => match(file)));
    if (!touched) continue;

    const matches = await fg(req.pattern, { dot: true });
    if (matches.length === 0) {
      findings.push({
        id: "ARTIFACTS_MISSING",
        title: `Missing required artifact(s) for changes affecting: ${req.on_changes.join(", ")}`,
        severity: "HIGH",
        evidence: [`Expected at least one file matching: ${req.pattern}`],
        requiredActions: [
          `Add required artifact(s) matching "${req.pattern}" (e.g., threat model for the changed flow).`,
          `Include STRIDE + OWASP mapping + MITRE mapping + required logging and tests.`
        ]
      });
    }
  }

  // 2–6. Static checks (parallel — order of results is deterministic via spread)
  const [threatModel, sbom, pentest, redteam, compliance] = await Promise.all([
    checkThreatModel(),
    checkSbom(),
    checkPentestSignoff(opts.changedFiles),
    checkRedteamResults(opts.changedFiles),
    checkComplianceGap(opts.changedFiles)
  ]);

  findings.push(...threatModel, ...sbom, ...pentest, ...redteam, ...compliance);

  return findings;
}
