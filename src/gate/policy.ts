import { z } from "zod";
import fg from "fast-glob";
import { GateResult, Finding, FindingSeverity, ControlCoverage } from "./result.js";
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
import { checkScannerReadiness } from "./checks/scanners.js";
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
import { runRuntimeChecks } from "./checks/runtime.js";
import { runCiPipelineChecks } from "./checks/ci-pipeline.js";
import { runNucleiChecks } from "./checks/nuclei.js";
import { getCommitHash, loadBaseline, saveBaseline, compareBaseline } from "./baseline.js";
import { checkInjectionDeep } from "./checks/injection-deep.js";
import { checkAuthDeep } from "./checks/auth-deep.js";
import { randomUUID } from "node:crypto";

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
    .default([])
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
      ignore: SCOPE_IGNORE_GLOBS
    });
    return Array.from(new Set(files)).sort();
  }

  const folderGlobs = targets.map((target) => `${target.replace(/\/+$/, "")}/**/*`);
  const files = await fg(folderGlobs, {
    onlyFiles: true,
    dot: true,
    ignore: SCOPE_IGNORE_GLOBS
  });
  return Array.from(new Set(files)).sort();
}

export async function loadPolicy(policyPath: string): Promise<Policy> {
  const raw = await readFileSafe(policyPath);
  const parsed = JSON.parse(raw);
  return PolicySchema.parse(parsed);
}

/**
 * Classify the change type based on file paths to apply appropriate gate tier.
 */
function classifyChangeType(files: string[]): ChangeType {
  if (files.length === 0) return "general";

  const allMatch = (pattern: RegExp) => files.every((f) => pattern.test(f));
  const anyMatch = (pattern: RegExp) => files.some((f) => pattern.test(f));

  if (allMatch(/\.(md|txt|rst)$|\/docs\/|README/i)) return "docs";
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
    mode,
    targets,
    baseRef: opts.baseRef ?? "origin/main",
    headRef: opts.headRef ?? "HEAD"
  });

  // Classify the change type to apply appropriate gate tier
  const changeType = classifyChangeType(changedFiles);

  const surfaces = detectSurfaces(changedFiles);
  const catalog = await loadControlCatalog();
  const scannerReadiness = await checkScannerReadiness({ surfaces });
  const evidenceCoverage = await evaluateEvidenceCoverage({ policy, surfaces });

  let rawFindings: Finding[];

  // "docs" tier: only run secrets check to avoid unnecessary overhead
  if (changeType === "docs") {
    rawFindings = await checkSecrets({ changedFiles });
  } else {
    // Run all independent checks in parallel
    const checkResults = await Promise.allSettled([
      checkRequiredArtifacts({ policy, changedFiles }),
      checkSecrets({ changedFiles }),
      checkDependencies({ changedFiles }),
      Promise.resolve(scannerReadiness.findings),
      Promise.resolve(evidenceCoverage.findings),
      surfaces.web ? checkWebNextjs({ changedFiles }) : Promise.resolve([]),
      surfaces.api ? checkApi({ changedFiles }) : Promise.resolve([]),
      surfaces.infra ? checkInfra({ changedFiles }) : Promise.resolve([]),
      surfaces.mobileIos ? checkMobileIos({ changedFiles }) : Promise.resolve([]),
      surfaces.mobileAndroid ? checkMobileAndroid({ changedFiles }) : Promise.resolve([]),
      surfaces.ai ? checkAi({ changedFiles }) : Promise.resolve([]),
      checkGraphQL({ changedFiles }),
      checkKubernetes({ changedFiles }),
      checkDatabase({ changedFiles }),
      checkCrypto({ changedFiles }),
      checkDlp({ changedFiles }),
      runSbomChecks({ changedFiles, targets }),
      runPlaybookChecks({ changedFiles, surfaces }),
      surfaces.ai ? runAiRedteamChecks({ changedFiles }) : Promise.resolve([]),
      process.env["SECURITY_STAGING_URL"] ? runRuntimeChecks({ targets, changedFiles }) : Promise.resolve([]),
      runCiPipelineChecks({ changedFiles }),
      process.env["SECURITY_STAGING_URL"] ? runNucleiChecks({ changedFiles }) : Promise.resolve([]),
      (surfaces.api || surfaces.web) ? checkInjectionDeep({ changedFiles }) : Promise.resolve([]),
      (surfaces.api || surfaces.web) ? checkAuthDeep({ changedFiles }) : Promise.resolve([])
    ]);

    rawFindings = [];
    for (const result of checkResults) {
      if (result.status === "fulfilled") {
        rawFindings.push(...result.value);
      } else {
        console.warn("[policy] Check failed:", result.reason);
      }
    }
  }

  rawFindings = assignRiskSlas(rawFindings);

  const toolingCoverage: ControlCoverage[] = catalog.controls
    .filter((control) => control.automation === "tooling" && controlApplies(control, surfaces))
    .map((control) => {
      const required = control.required_scanners ?? [];
      const missing = required.filter(
        (scannerId) => !scannerReadiness.configured.includes(scannerId) || scannerReadiness.missing.includes(scannerId)
      );
      return {
        id: control.id,
        description: control.description,
        automation: control.automation,
        frameworks: control.frameworks,
        status: missing.length > 0 ? "missing" : "satisfied",
        details: missing.length > 0 ? missing : required
      };
    });

  const controlCoverage: ControlCoverage[] = [
    ...evidenceCoverage.controls.filter((control) => control.automation === "evidence"),
    ...toolingCoverage
  ];

  const exceptionResult = await applySecurityExceptions(rawFindings);
  const controlCoverageWithExceptions: ControlCoverage[] = controlCoverage.map((control) => {
    if (exceptionResult.activeControlExceptionIds.includes(control.id) && control.status === "missing") {
      return {
        ...control,
        status: "risk_accepted",
        details: [...control.details, "Covered by an active approved control exception."]
      };
    }
    return control;
  });
  const findings = [...exceptionResult.findings, ...exceptionResult.exceptionFindings];

  // Apply risk-based adaptive gating tier overrides
  let effectiveFindings = findings;

  if (changeType === "payment") {
    // Payment changes: treat as prod-equivalent — block on all HIGH+
    effectiveFindings = findings;
  } else if (changeType === "auth") {
    // Auth changes: always block on HIGH+ even in dev
    effectiveFindings = findings;
  }

  const relevantControls = controlCoverageWithExceptions.filter((control) => control.status !== "not_applicable");
  const satisfiedControls = relevantControls.filter((control) => control.status === "satisfied").length;
  const riskAcceptedControls = relevantControls.filter((control) => control.status === "risk_accepted").length;
  const automatedCoverage = relevantControls.length === 0
    ? 100
    : Math.round((((satisfiedControls) + (riskAcceptedControls * 0.5)) / relevantControls.length) * 100);
  const scannerScore = scannerReadiness.configured.length === 0
    ? 0
    : Math.round(((scannerReadiness.configured.length - scannerReadiness.missing.length) / scannerReadiness.configured.length) * 100);
  const confidenceScore = Math.max(0, Math.min(100, Math.round((automatedCoverage * 0.7) + (scannerScore * 0.3))));
  const missingControls = relevantControls.filter((control) => control.status === "missing").length;

  // Baseline regression detection: compare current run against previous baseline
  let baselineDiff: ReturnType<typeof compareBaseline> | undefined;
  if (previousBaseline) {
    baselineDiff = compareBaseline(
      { findings: effectiveFindings, controlCoverage: controlCoverageWithExceptions, confidence: { automatedCoverage, score: 0, missingControls: 0, scannerReadiness: 0, summary: "" }, status: "PASS", policyVersion: "", evaluatedAt: "", scope: { changedFiles, surfaces } },
      previousBaseline
    );
    if (baselineDiff.regressions.length > 0) {
      const regressionFindings: Finding[] = baselineDiff.regressions.map((r) => ({
        id: "BASELINE_REGRESSION",
        title: `Security regression: control "${r.controlId}" was previously satisfied but is now missing`,
        severity: "HIGH" as const,
        evidence: [`Control ${r.controlId}: "satisfied" → "missing" since last gate run`],
        requiredActions: [
          `Restore control "${r.controlId}" to a satisfied state.`,
          "Investigate what change caused this regression and revert or remediate."
        ]
      }));
      effectiveFindings = [...regressionFindings, ...effectiveFindings];
    }
  }

  const status = effectiveFindings.some((f) => f.severity === "HIGH" || f.severity === "CRITICAL")
    ? "FAIL"
    : "PASS";

  const result: GateResult = {
    status,
    policyVersion: policy.version,
    evaluatedAt: new Date().toISOString(),
    scope: { mode, targets, changedFiles, surfaces },
    findings: effectiveFindings,
    suppressedFindings: exceptionResult.suppressed,
    controlCoverage: controlCoverageWithExceptions,
    scannerReadiness: {
      configured: scannerReadiness.configured,
      missing: scannerReadiness.missing
    },
    confidence: {
      score: confidenceScore,
      automatedCoverage,
      missingControls,
      riskAcceptedControls,
      scannerReadiness: scannerScore,
      summary: `Automated coverage ${automatedCoverage}%, scanner readiness ${scannerScore}%, missing controls ${missingControls}, risk-accepted controls ${riskAcceptedControls}. Change type: ${changeType}.`
    },
    baselineDiff
  };

  // Persist as new baseline — fire-and-forget, never blocks the gate result
  saveBaseline(randomUUID(), result, commitHash).catch(() => { /* best-effort */ });

  return result;
}
