import { z } from "zod";
import { createHmac, timingSafeEqual, randomUUID } from "node:crypto";
import fg from "fast-glob";
import { GateResult, Finding, FindingSeverity, ControlCoverage, sanitizeErrorMessage } from "./result.js";
import { getChangedFiles } from "./diff.js";
import { detectSurfaces } from "./findings.js";
import { checkRequiredArtifacts } from "./checks/required-artifacts.js";
import { checkSecrets } from "./checks/secrets.js";
import { checkDependencies } from "./checks/dependencies.js";
import { checkWebNextjs } from "./checks/web-nextjs.js";
import { checkApi } from "./checks/api.js";
import { checkInfra } from "./checks/infra.js";
import { checkMobileIos } from "./checks/mobile-ios.js";
import { checkMobileAndroid } from "./checks/mobile-android.js";
import { checkAi } from "./checks/ai.js";
import { checkScannerReadiness, runScanners } from "./checks/scanners.js";
import { evaluateEvidenceCoverage } from "./evidence.js";
import { applySecurityExceptions } from "./exceptions.js";
import { controlApplies, loadControlCatalog } from "./catalog.js";
import { readFileSafe } from "../repo/fs.js";
import { checkGraphQL } from "./checks/graphql.js";
import { checkKubernetes } from "./checks/k8s.js";
import { checkDatabase } from "./checks/database.js";
import { checkCrypto } from "./checks/crypto.js";
import { checkDlp } from "./checks/dlp.js";
import { runSbomChecks } from "./checks/sbom.js";
import { runPlaybookChecks } from "./checks/playbook.js";
import { runAiRedteamChecks } from "./checks/ai-redteam.js";
import { runRuntimeChecks, runDockerChecks } from "./checks/runtime.js";
import { runCiPipelineChecks } from "./checks/ci-pipeline.js";
import { runNucleiChecks } from "./checks/nuclei.js";
import { getCommitHash, loadBaseline, saveBaseline, compareBaseline } from "./baseline.js";
import { checkInjectionDeep } from "./checks/injection-deep.js";
import { checkAuthDeep } from "./checks/auth-deep.js";
import { checkSupplyChainDeep } from "./checks/supply-chain-deep.js";
import { checkBusinessLogic } from "./checks/business-logic.js";
import { checkAgenticInstructions } from "./checks/agentic-instructions.js";
import { checkAiGovernance } from "./checks/ai-governance.js";
import { checkIac } from "./checks/iac.js";
import { checkGitOps } from "./checks/gitops.js";
import { checkDataPlatform } from "./checks/data-platform.js";
import { checkDockerDeep } from "./checks/docker-deep.js";
import { checkCloudControls } from "./checks/cloud-controls.js";

const PolicySchema = z.object({
  name: z.string(),
  version: z.string(),
  artifacts_required: z
    .array(
      z.object({
        pattern: z.string(),
        on_changes: z.array(z.string())
      })
    )
    .default([]),
  required_checks: z.record(z.any()).default({}),
  requirements: z
    .array(
      z.object({
        id: z.string(),
        type: z.enum(["gate", "control"]).default("gate"),
        evidence: z.array(z.string()).default([])
      })
    )
    .default([]),
  // Fix 6: configurable severity blocking list
  severity_block: z.array(z.string()).optional(),
  // Fix 7: exceptions config with require_ticket
  exceptions: z
    .object({
      require_ticket: z.boolean().optional(),
      approval_roles: z.array(z.string()).optional()
    })
    .optional()
});

export type Policy = z.infer<typeof PolicySchema>;

export type GateMode = "recent_changes" | "folder_by_folder" | "file_by_file";

export type ChangeType = "docs" | "config" | "auth" | "payment" | "infra" | "ai" | "general";

export type GateResultWithBaseline = GateResult & {
  changeType: ChangeType;
};

const SCOPE_IGNORE_GLOBS = ["**/node_modules/**", "**/.git/**", "**/dist/**"];
const SAFE_SCOPE_TARGET_RE = /^[a-zA-Z0-9_./-]+$/;

function validateScopeTarget(target: string): void {
  if (!target || target.includes("..") || target.startsWith("/") || !SAFE_SCOPE_TARGET_RE.test(target)) {
    throw new Error(
      `Invalid scope target "${target}". Use a relative file/folder path with alphanumerics, "_", "-", ".", "/".`
    );
  }
}

function normalizeTargets(targets: string[] | undefined): string[] {
  return (targets ?? []).map((t) => t.trim()).filter(Boolean);
}

async function resolveScopedFiles(opts: {
  mode: GateMode;
  targets?: string[];
  baseRef: string;
  headRef: string;
}): Promise<string[]> {
  if (opts.mode === "recent_changes") {
    return await getChangedFiles({ baseRef: opts.baseRef, headRef: opts.headRef });
  }

  const targets = normalizeTargets(opts.targets);
  if (targets.length === 0) {
    throw new Error(
      `Scan mode "${opts.mode}" requires "targets". ` +
      `Provide one or more relative paths (folders for folder_by_folder, files for file_by_file).`
    );
  }

  for (const target of targets) validateScopeTarget(target);

  if (opts.mode === "file_by_file") {
    const files = await fg(targets, {
      onlyFiles: true,
      dot: true,
      ignore: SCOPE_IGNORE_GLOBS,
      followSymbolicLinks: false
    });
    return Array.from(new Set(files)).sort((a, b) => a.localeCompare(b));
  }

  const folderGlobs = targets.map((target) => `${target.replace(/\/+$/, "")}/**/*`);
  const files = await fg(folderGlobs, {
    onlyFiles: true,
    dot: true,
    ignore: SCOPE_IGNORE_GLOBS,
    followSymbolicLinks: false
  });
  return Array.from(new Set(files)).sort((a, b) => a.localeCompare(b));
}

// POC-8 fix: HMAC-SHA256 verification of the policy file on load.
// Minimal tamper that bypasses all HIGH/CRITICAL findings: change
//   "severity_block": ["HIGH", "CRITICAL"]  →  "severity_block": []
// With HMAC verification that tampered file is detected and rejected.
const POLICY_HMAC_MIN_KEY_BYTES = 32;

function getPolicyHmacKey(): string | null {
  const key = process.env["SECURITY_POLICY_HMAC_KEY"];
  if (!key) return null;
  if (Buffer.byteLength(key, "utf-8") < POLICY_HMAC_MIN_KEY_BYTES) {
    throw new Error(
      `SECURITY_POLICY_HMAC_KEY is too short (${Buffer.byteLength(key, "utf-8")} bytes). ` +
      `Minimum ${POLICY_HMAC_MIN_KEY_BYTES} bytes required.`
    );
  }
  return key;
}

/**
 * Write the HMAC signature for a policy file to <policyPath>.hmac.
 * Call this after generating or updating the policy. Not exported from the
 * module — callers use the CLI helper `security-mcp sign-policy`.
 */
export function signPolicyFile(raw: string, key: string): string {
  return createHmac("sha256", key).update(raw, "utf-8").digest("hex");
}

export async function loadPolicy(policyPath: string): Promise<Policy> {
  const raw = await readFileSafe(policyPath);

  // POC-8: verify HMAC when a key is configured
  const hmacKey = getPolicyHmacKey();
  // TM-001: warn when HMAC protection is absent so operators know the policy file
  // can be silently tampered (e.g. severity_block cleared) without detection.
  // Non-blocking — allows operation without the key — but makes the risk visible.
  // Only warn in non-gate contexts — in gate mode stdout is JSON and mixing
  // stderr into the output file (via 2>&1 hooks) would corrupt JSON parsing.
  if (!hmacKey && !process.env["SECURITY_GATE_POLICY"]) {
    console.warn(
      "[loadPolicy] WARNING: SECURITY_POLICY_HMAC_KEY is not set. " +
      "Policy file integrity is NOT verified — a local attacker could silently edit " +
      `"${policyPath}" (e.g. clear severity_block) without detection. ` +
      "Set SECURITY_POLICY_HMAC_KEY (≥32 bytes) and run `security-mcp sign-policy` to enable tamper protection."
    );
  }
  if (hmacKey) {
    let storedSig: string | null = null;
    try {
      storedSig = (await readFileSafe(`${policyPath}.hmac`)).trim();
    } catch {
      // .hmac sidecar missing — reject to prevent stripping the sig to bypass verification
      throw new Error(
        `[loadPolicy] Policy file "${policyPath}" has no .hmac sidecar but ` +
        `SECURITY_POLICY_HMAC_KEY is set. Generate a signature with: security-mcp sign-policy`
      );
    }
    const expected = createHmac("sha256", hmacKey).update(raw, "utf-8").digest("hex");
    const storedBuf   = Buffer.from(storedSig, "hex");
    const expectedBuf = Buffer.from(expected,  "hex");
    const valid = storedBuf.length === expectedBuf.length && timingSafeEqual(storedBuf, expectedBuf);
    if (!valid) {
      throw new Error(
        `[loadPolicy] HMAC verification failed for "${policyPath}" — policy file may have been tampered. ` +
        `Re-sign with: security-mcp sign-policy`
      );
    }
  }

  const parsed = JSON.parse(raw);
  return PolicySchema.parse(parsed);
}

// Fix 8: pattern to detect security-relevant config files that must not get docs-tier bypass
const SECURITY_CONFIG_RE = /security-exceptions|security-policy|security-tools|\.checkov\.yaml|\.github\/workflows\//i;

/**
 * Classify the change type based on file paths to apply appropriate gate tier.
 */
function classifyChangeType(files: string[]): ChangeType {
  if (files.length === 0) return "general";

  const allMatch = (pattern: RegExp) => files.every((f) => pattern.test(f));
  const anyMatch = (pattern: RegExp) => files.some((f) => pattern.test(f));

  if (allMatch(/\.(md|txt|rst)$|\/docs\/|README/i)) {
    // Fix 8: override docs tier when security config files are in the changeset
    if (anyMatch(SECURITY_CONFIG_RE)) {
      console.warn("[policy] Docs-tier override: security configuration file detected in changed files");
      return "config";
    }
    return "docs";
  }
  if (anyMatch(/\/payment|\/stripe|\/checkout|\/billing|\/invoice/i)) return "payment";
  if (anyMatch(/\/auth|\/login|\/session|\/token|\/jwt|\/oauth|\/permission/i)) return "auth";
  if (anyMatch(/\.tf$|Dockerfile|\.yaml$|\.yml$|\/k8s\/|\/helm\//)) return "infra";
  if (anyMatch(/\/ai\/|\/llm\/|\/agent\/|\/prompt/i)) return "ai";
  if (allMatch(/\.(json|env|config\..+|toml|yaml|yml)$/)) return "config";

  return "general";
}

const SLA_MAP: Record<FindingSeverity, Finding["sla"]> = {
  CRITICAL: "24h",
  HIGH: "7d",
  MEDIUM: "30d",
  LOW: "90d"
};

function assignRiskSlas(findings: Finding[]): Finding[] {
  const now = new Date().toISOString();
  return findings.map((f) => ({ ...f, sla: SLA_MAP[f.severity], slaAssignedAt: now }));
}

// ---------------------------------------------------------------------------
// runPrGate helpers — extracted to keep cognitive complexity within limits
// ---------------------------------------------------------------------------

type ScannerReadiness = Awaited<ReturnType<typeof checkScannerReadiness>>;
type Surfaces = ReturnType<typeof detectSurfaces>;

// Names aligned with check array order in runAllChecks — used for GATE_CHECK_CRASHED findings
const CHECK_NAMES = [
  "required-artifacts",
  "secrets",
  "dependencies",
  "scanner-readiness",
  "evidence-coverage",
  "web-nextjs",
  "api",
  "infra",
  "mobile-ios",
  "mobile-android",
  "ai",
  "graphql",
  "kubernetes",
  "database",
  "crypto",
  "dlp",
  "sbom",
  "playbook",
  "ai-redteam",
  "runtime",
  "ci-pipeline",
  "nuclei",
  "injection-deep",
  "auth-deep",
  "supply-chain-deep",
  "business-logic",
  "docker",
  "scanners-run",
  "agentic-instructions",
  "ai-governance",
  "iac",
  "gitops",
  "data-platform",
  "docker-deep",
  "cloud-controls"
] as const;

/** Run every applicable security check in parallel and collect findings. */
async function runAllChecks(opts: {
  policy: Policy;
  changedFiles: string[];
  targets: string[];
  surfaces: Surfaces;
  scannerReadiness: ScannerReadiness;
  evidenceCoverage: { findings: Finding[] };
}): Promise<Finding[]> {
  const { policy, changedFiles, targets, surfaces, scannerReadiness, evidenceCoverage } = opts;
  const stagingUrl = process.env["SECURITY_STAGING_URL"];
  const isApiOrWeb = surfaces.api || surfaces.web;

  const settled = await Promise.allSettled([
    checkRequiredArtifacts({ policy, changedFiles }),
    checkSecrets({ changedFiles }),
    checkDependencies({ changedFiles }),
    Promise.resolve(scannerReadiness.findings),
    Promise.resolve(evidenceCoverage.findings),
    surfaces.web          ? checkWebNextjs({ changedFiles })                : Promise.resolve([]),
    surfaces.api          ? checkApi({ changedFiles })                      : Promise.resolve([]),
    surfaces.infra        ? checkInfra({ changedFiles })                    : Promise.resolve([]),
    surfaces.mobileIos    ? checkMobileIos({ changedFiles })                : Promise.resolve([]),
    surfaces.mobileAndroid ? checkMobileAndroid({ changedFiles })           : Promise.resolve([]),
    surfaces.ai           ? checkAi({ changedFiles })                       : Promise.resolve([]),
    checkGraphQL({ changedFiles }),
    checkKubernetes({ changedFiles }),
    checkDatabase({ changedFiles }),
    checkCrypto({ changedFiles }),
    checkDlp({ changedFiles }),
    runSbomChecks({ changedFiles, targets }),
    runPlaybookChecks({ changedFiles, surfaces }),
    surfaces.ai  ? runAiRedteamChecks({ changedFiles })                     : Promise.resolve([]),
    stagingUrl   ? runRuntimeChecks({ targets, changedFiles })              : Promise.resolve([]),
    runCiPipelineChecks({ changedFiles }),
    stagingUrl   ? runNucleiChecks({ changedFiles })                        : Promise.resolve([]),
    isApiOrWeb   ? checkInjectionDeep({ changedFiles })                     : Promise.resolve([]),
    isApiOrWeb   ? checkAuthDeep({ changedFiles })                          : Promise.resolve([]),
    checkSupplyChainDeep({ changedFiles }),
    checkBusinessLogic({ changedFiles }),
    runDockerChecks({ changedFiles }),
    runScanners({ surfaces, changedFiles }),
    surfaces.agentic ? checkAgenticInstructions({ changedFiles }) : Promise.resolve([]),
    surfaces.ai       ? checkAiGovernance({ changedFiles })        : Promise.resolve([]),
    checkIac({ changedFiles }),
    checkGitOps({ changedFiles }),
    checkDataPlatform({ changedFiles }),
    checkDockerDeep({ changedFiles }),
    checkCloudControls({ changedFiles })
  ]);

  const findings: Finding[] = [];
  // Fix 5: crashed check modules generate HIGH findings instead of silent console.warn
  for (let i = 0; i < settled.length; i++) {
    const r = settled[i];
    if (r.status === "fulfilled") {
      findings.push(...r.value);
    } else {
      const checkName = CHECK_NAMES[i] ?? `check-${i}`;
      // CWE-200: sanitize error message before embedding in gate findings —
      // raw Error.message can contain absolute filesystem paths that reveal
      // internal directory structure to callers of the gate result.
      const rawErrorMessage = r.reason instanceof Error ? r.reason.message : String(r.reason);
      const errorMessage = sanitizeErrorMessage(rawErrorMessage);
      findings.push({
        id: "GATE_CHECK_CRASHED",
        title: "Security check module crashed — coverage gap",
        severity: "HIGH",
        evidence: [`Check module: ${checkName}`, `Error: ${errorMessage}`],
        requiredActions: [
          `The ${checkName} check module threw an unhandled error: ${errorMessage}. Findings from this module are unavailable, which may constitute a false negative.`
        ]
      });
    }
  }
  return findings;
}

/** Build tooling-based control coverage from the catalog. */
function buildToolingCoverage(
  catalog: Awaited<ReturnType<typeof loadControlCatalog>>,
  surfaces: Surfaces,
  scannerReadiness: ScannerReadiness
): ControlCoverage[] {
  return catalog.controls
    .filter((c) => c.automation === "tooling" && controlApplies(c, surfaces))
    .map((c) => {
      const required = c.required_scanners ?? [];
      const missing = required.filter(
        (id) => !scannerReadiness.configured.includes(id) || scannerReadiness.missing.includes(id)
      );
      return {
        id: c.id,
        description: c.description,
        automation: c.automation,
        frameworks: c.frameworks,
        status: missing.length > 0 ? "missing" : "satisfied",
        details: missing.length > 0 ? missing : required
      } satisfies ControlCoverage;
    });
}

type ConfidenceMetrics = {
  automatedCoverage: number;
  scannerScore: number;
  confidenceScore: number;
  missingControls: number;
  riskAcceptedControls: number;
};

/** Compute coverage and confidence scores from control coverage + scanner readiness. */
function computeConfidence(
  controlCoverage: ControlCoverage[],
  scannerReadiness: ScannerReadiness
): ConfidenceMetrics {
  const relevant = controlCoverage.filter((c) => c.status !== "not_applicable");
  const satisfied = relevant.filter((c) => c.status === "satisfied").length;
  const riskAccepted = relevant.filter((c) => c.status === "risk_accepted").length;
  const missing = relevant.filter((c) => c.status === "missing").length;

  const automatedCoverage = relevant.length === 0
    ? 100
    : Math.round((satisfied + riskAccepted * 0.5) / relevant.length * 100);

  const { configured, missing: scanMissing } = scannerReadiness;
  const scannerScore = configured.length === 0
    ? 0
    : Math.round((configured.length - scanMissing.length) / configured.length * 100);

  const confidenceScore = Math.max(0, Math.min(100,
    Math.round(automatedCoverage * 0.7 + scannerScore * 0.3)
  ));

  return { automatedCoverage, scannerScore, confidenceScore, missingControls: missing, riskAcceptedControls: riskAccepted };
}

/** Inject regression findings when a baseline exists and controls have regressed. */
function applyBaselineDiff(
  findings: Finding[],
  controlCoverage: ControlCoverage[],
  previousBaseline: GateResult,
  changedFiles: string[],
  surfaces: Surfaces,
  confidence: { automatedCoverage: number }
): { findings: Finding[]; diff: ReturnType<typeof compareBaseline> } {
  const snapshot: GateResult = {
    findings,
    controlCoverage,
    confidence: { automatedCoverage: confidence.automatedCoverage, score: 0, missingControls: 0, scannerReadiness: 0, summary: "" },
    status: "PASS",
    policyVersion: "",
    evaluatedAt: "",
    scope: { changedFiles, surfaces }
  };
  const diff = compareBaseline(snapshot, previousBaseline);

  if (diff.regressions.length === 0) return { findings, diff };

  const regressionFindings: Finding[] = diff.regressions.map((r) => ({
    id: "BASELINE_REGRESSION",
    title: `Security regression: control "${r.controlId}" was previously satisfied but is now missing`,
    severity: "HIGH" as const,
    evidence: [`Control ${r.controlId}: "satisfied" → "missing" since last gate run`],
    requiredActions: [
      `Restore control "${r.controlId}" to a satisfied state.`,
      "Investigate what change caused this regression and revert or remediate."
    ]
  }));

  return { findings: [...regressionFindings, ...findings], diff };
}

// ---------------------------------------------------------------------------
// Main gate entry point
// ---------------------------------------------------------------------------

export async function runPrGate(opts: {
  baseRef?: string;
  headRef?: string;
  policyPath: string;
  mode?: GateMode;
  targets?: string[];
}): Promise<GateResult> {
  const [policy, commitHash, previousBaseline] = await Promise.all([
    loadPolicy(opts.policyPath),
    getCommitHash(),
    loadBaseline()
  ]);
  const mode = opts.mode ?? "recent_changes";
  const targets = normalizeTargets(opts.targets);

  const changedFiles = await resolveScopedFiles({
    mode, targets,
    baseRef: opts.baseRef ?? "origin/main",
    headRef: opts.headRef ?? "HEAD"
  });

  const changeType = classifyChangeType(changedFiles);
  const surfaces = detectSurfaces(changedFiles);

  const [catalog, scannerReadiness, evidenceCoverage] = await Promise.all([
    loadControlCatalog(),
    checkScannerReadiness({ surfaces }),
    evaluateEvidenceCoverage({ policy, surfaces })
  ]);

  // Collect raw findings — docs tier runs secrets-only to reduce overhead
  const rawChecked = changeType === "docs"
    ? await checkSecrets({ changedFiles })
    : await runAllChecks({ policy, changedFiles, targets, surfaces, scannerReadiness, evidenceCoverage });

  const rawFindings = assignRiskSlas(rawChecked);

  // Build control coverage
  const toolingCoverage = buildToolingCoverage(catalog, surfaces, scannerReadiness);
  const controlCoverage: ControlCoverage[] = [
    ...evidenceCoverage.controls.filter((c) => c.automation === "evidence"),
    ...toolingCoverage
  ];

  // Apply exceptions — Fix 7: pass require_ticket from policy config
  const requireTicket = policy.exceptions?.require_ticket ?? false;
  const exceptionResult = await applySecurityExceptions(rawFindings, { requireTicket });
  const controlCoverageWithExceptions = controlCoverage.map((control) => {
    const excepted = exceptionResult.activeControlExceptionIds.includes(control.id);
    if (excepted && control.status === "missing") {
      return { ...control, status: "risk_accepted" as const, details: [...control.details, "Covered by an active approved control exception."] };
    }
    return control;
  });

  // Include exception warnings (e.g. CI_EXCEPTIONS_IN_LOCAL_SCAN, EXCEPTIONS_FILE_UNSIGNED) in findings
  const baseFindings = [...exceptionResult.findings, ...exceptionResult.exceptionFindings, ...exceptionResult.warnings];

  // Confidence metrics
  const cm = computeConfidence(controlCoverageWithExceptions, scannerReadiness);

  // Baseline regression injection
  let effectiveFindings = baseFindings;
  let baselineDiff: ReturnType<typeof compareBaseline> | undefined;
  if (previousBaseline) {
    const br = applyBaselineDiff(baseFindings, controlCoverageWithExceptions, previousBaseline, changedFiles, surfaces, cm);
    effectiveFindings = br.findings;
    baselineDiff = br.diff;
  }

  // Fix 6: read severity_block from policy instead of hardcoding HIGH/CRITICAL
  let blockedSeverities: string[] = policy.severity_block ?? ["HIGH", "CRITICAL"];
  // SECURITY (silent-bypass hardening): when the policy file is NOT integrity-verified
  // (no SECURITY_POLICY_HMAC_KEY — the default), an attacker who can edit the unsigned
  // .mcp/policies/security-policy.json could set "severity_block": [] and force every
  // verdict to PASS with unlimited HIGH/CRITICAL findings. Refuse to let an unverified
  // policy RELAX the gate below the safe HIGH/CRITICAL floor. To intentionally weaken it,
  // operators must sign the policy (SECURITY_POLICY_HMAC_KEY + `security-mcp sign-policy`).
  // When a key IS set, loadPolicy has already HMAC-verified the file (or thrown), so the
  // operator's configured severity_block is trusted as-is.
  const policyIntegrityVerified = !!process.env["SECURITY_POLICY_HMAC_KEY"];
  if (!policyIntegrityVerified) {
    for (const floor of ["HIGH", "CRITICAL"]) {
      if (!blockedSeverities.includes(floor)) blockedSeverities = [...blockedSeverities, floor];
    }
  }
  const status = effectiveFindings.some((f) => blockedSeverities.includes(f.severity))
    ? "FAIL" : "PASS";

  const result: GateResult = {
    status,
    policyVersion: policy.version,
    evaluatedAt: new Date().toISOString(),
    scope: { mode, targets, changedFiles, surfaces },
    findings: effectiveFindings,
    suppressedFindings: exceptionResult.suppressed,
    controlCoverage: controlCoverageWithExceptions,
    scannerReadiness: { configured: scannerReadiness.configured, missing: scannerReadiness.missing },
    confidence: {
      score: cm.confidenceScore,
      automatedCoverage: cm.automatedCoverage,
      missingControls: cm.missingControls,
      riskAcceptedControls: cm.riskAcceptedControls,
      scannerReadiness: cm.scannerScore,
      summary: `Automated coverage ${cm.automatedCoverage}%, scanner readiness ${cm.scannerScore}%, missing controls ${cm.missingControls}, risk-accepted controls ${cm.riskAcceptedControls}. Change type: ${changeType}.`
    },
    baselineDiff
  };

  // Persist as new baseline — fire-and-forget, never blocks the gate result
  saveBaseline(randomUUID(), result, commitHash).catch(() => { /* best-effort */ });

  return result;
}
