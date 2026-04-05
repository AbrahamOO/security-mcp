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
