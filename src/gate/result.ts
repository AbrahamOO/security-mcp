export type GateStatus = "PASS" | "FAIL";

export type FindingSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type Finding = {
  id: string;
  title: string;
  severity: FindingSeverity;
  evidence?: string[];
  files?: string[];
  requiredActions: string[];
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
};
