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

export type GateResult = {
  status: GateStatus;
  policyVersion: string;
  evaluatedAt: string;
  scope: {
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
};