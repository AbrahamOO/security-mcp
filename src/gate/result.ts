import type { BaselineDiff } from "./baseline.js";
export type { BaselineDiff };

// CWE-209: strip absolute file system paths from error messages before logging
// to prevent leaking internal directory structure to observers of stderr/stdout.
export function sanitizeErrorMessage(msg: string): string {
  return msg
    .replace(/\/[^\s:'"]+/g, "[path]")         // Unix: /foo/bar/baz
    .replace(/[A-Za-z]:\\[^\s:'"]+/g, "[path]"); // Windows: C:\Users\...
}

export type GateStatus = "PASS" | "FAIL";

export type FindingSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type Finding = {
  id: string;
  title: string;
  severity: FindingSeverity;
  evidence?: string[];
  files?: string[];
  requiredActions: string[];
  sla?: "24h" | "7d" | "30d" | "90d";
  slaAssignedAt?: string;
};

/**
 * Runs a check module's rules so one failing rule costs one rule, not the module.
 *
 * `Promise.all` rejects on the first failure and abandons every other result, so a
 * module that wrapped it in `try { ... } catch { return [] }` reported "no findings"
 * — indistinguishable from a clean repository — whenever any single rule threw. Two
 * modules did exactly that, and one of them (injection-deep) carried a query that
 * throws in any Perl repository, silently disabling 40 unrelated rules there.
 *
 * Rules that succeed are kept. Rules that throw are reported as GATE_CHECK_CRASHED,
 * the same id policy.ts emits when a whole module rejects, so the coverage gap
 * reaches the gate result instead of a console warning.
 */
export async function settleRules(
  moduleName: string,
  rules: Array<Promise<Finding | Finding[] | null>>
): Promise<Finding[]> {
  const settled = await Promise.allSettled(rules);
  const findings: Finding[] = [];
  const failures: string[] = [];
  for (const r of settled) {
    if (r.status === "fulfilled") {
      if (Array.isArray(r.value)) findings.push(...r.value);
      else if (r.value) findings.push(r.value);
    } else {
      failures.push(sanitizeErrorMessage(r.reason instanceof Error ? r.reason.message : String(r.reason)));
    }
  }
  if (failures.length > 0) {
    findings.push({
      id: "GATE_CHECK_CRASHED",
      title: "Security check module crashed — coverage gap",
      severity: "HIGH",
      evidence: [`Check module: ${moduleName}`, ...[...new Set(failures)].slice(0, 5).map((f) => `Error: ${f}`)],
      requiredActions: [
        `${failures.length} rule(s) in the ${moduleName} module threw and produced no result. The remaining rules ran, so this report is partial: absence of a finding from a failed rule is not evidence that the vulnerability is absent.`,
        "Check the gate logs for the underlying error and file a bug if it reproduces."
      ]
    });
  }
  return findings;
}

export type SuppressedFinding = {
  finding: Finding;
  exceptionId: string;
  expiresOn: string;
};

export type ControlCoverage = {
  id: string;
  description: string;
  automation: "workflow" | "evidence" | "tooling" | "approval";
  frameworks: string[];
  status: "satisfied" | "missing" | "risk_accepted" | "not_applicable";
  details: string[];
};

export type ConfidenceSummary = {
  score: number;
  automatedCoverage: number;
  missingControls: number;
  riskAcceptedControls?: number;
  scannerReadiness: number;
  summary: string;
};

export type GateResult = {
  status: GateStatus;
  policyVersion: string;
  evaluatedAt: string;
  scope: {
    mode?: "recent_changes" | "folder_by_folder" | "file_by_file";
    targets?: string[];
    changedFiles: string[];
    surfaces: {
      web: boolean;
      api: boolean;
      infra: boolean;
      mobileIos: boolean;
      mobileAndroid: boolean;
      ai: boolean;
      agentic: boolean;
    };
  };
  findings: Finding[];
  suppressedFindings?: SuppressedFinding[];
  controlCoverage?: ControlCoverage[];
  confidence?: ConfidenceSummary;
  scannerReadiness?: {
    configured: string[];
    missing: string[];
  };
  baselineDiff?: BaselineDiff;
};
