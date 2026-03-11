import { z } from "zod";
import fg from "fast-glob";
import { GateResult, Finding, ControlCoverage } from "./result.js";
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

export async function runPrGate(opts: {
  baseRef?: string;
  headRef?: string;
  policyPath: string;
  mode?: GateMode;
  targets?: string[];
}): Promise<GateResult> {
  const policy = await loadPolicy(opts.policyPath);
  const mode = opts.mode ?? "recent_changes";
  const targets = normalizeTargets(opts.targets);

  const changedFiles = await resolveScopedFiles({
    mode,
    targets,
    baseRef: opts.baseRef ?? "origin/main",
    headRef: opts.headRef ?? "HEAD"
  });

  const surfaces = detectSurfaces(changedFiles);
  const catalog = await loadControlCatalog();
  const scannerReadiness = await checkScannerReadiness({ surfaces });
  const evidenceCoverage = await evaluateEvidenceCoverage({ policy, surfaces });

  const rawFindings: Finding[] = [
    // Required artifacts first: threat models/checklists.
    ...(await checkRequiredArtifacts({ policy, changedFiles })),
    // Baseline scans / checks
    ...(await checkSecrets({ changedFiles })),
    ...(await checkDependencies({ changedFiles })),
    ...scannerReadiness.findings,
    ...evidenceCoverage.findings,
    // Surface-specific checks (only run if that surface is impacted or exists)
    ...(surfaces.web ? await checkWebNextjs({ changedFiles }) : []),
    ...(surfaces.api ? await checkApi({ changedFiles }) : []),
    ...(surfaces.infra ? await checkInfra({ changedFiles }) : []),
    ...(surfaces.mobileIos ? await checkMobileIos({ changedFiles }) : []),
    ...(surfaces.mobileAndroid ? await checkMobileAndroid({ changedFiles }) : []),
    ...(surfaces.ai ? await checkAi({ changedFiles }) : [])
  ];

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

  const status = findings.some((f) => f.severity === "HIGH" || f.severity === "CRITICAL")
    ? "FAIL"
    : "PASS";

  return {
    status,
    policyVersion: policy.version,
    evaluatedAt: new Date().toISOString(),
    scope: { mode, targets, changedFiles, surfaces },
    findings,
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
      summary: `Automated coverage ${automatedCoverage}%, scanner readiness ${scannerScore}%, missing controls ${missingControls}, risk-accepted controls ${riskAcceptedControls}.`
    }
  };
}
