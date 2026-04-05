/**
 * Types for the multi-agent orchestration system.
 *
 * Agent runs are coordinated via a manifest stored at
 * .mcp/agent-runs/{agentRunId}/manifest.json. Each specialist agent
 * writes its findings to a dedicated file in that directory.
 */

// ---------------------------------------------------------------------------
// Agent identifiers
// ---------------------------------------------------------------------------

export type AgentName =
  // Phase 1 leads
  | "threat-modeler"
  | "appsec-code-auditor"
  | "cloud-infra-specialist"
  | "supply-chain-devsecops"
  | "ai-llm-redteam"
  | "mobile-security-specialist"
  | "crypto-pki-specialist"
  // Phase 1 sub-agents
  | "stride-pasta-analyst"
  | "attack-navigator"
  | "business-logic-attacker"
  | "privacy-flow-analyst"
  | "injection-specialist"
  | "auth-session-hacker"
  | "logic-race-fuzzer"
  | "serialization-memory-attacker"
  | "aws-penetration-tester"
  | "gcp-penetration-tester"
  | "azure-penetration-tester"
  | "k8s-container-escaper"
  | "dependency-confusion-attacker"
  | "cicd-pipeline-hijacker"
  | "artifact-integrity-analyst"
  | "prompt-injection-specialist"
  | "model-extraction-attacker"
  | "rag-poisoning-specialist"
  | "agentic-loop-exploiter"
  | "ios-security-auditor"
  | "android-penetration-tester"
  | "mobile-api-network-attacker"
  | "tls-certificate-auditor"
  | "algorithm-implementation-reviewer"
  | "key-management-lifecycle-analyst"
  // Phase 2 leads + sub-agents
  | "pentest-team"
  | "pentest-web-api"
  | "pentest-infra"
  | "pentest-social"
  | "compliance-grc"
  | "evidence-collector"
  | "compliance-gap-analyst"
  // Phase 2 P0 — zero-coverage gap agents
  | "incident-responder"
  | "kill-switch-engineer"
  | "credential-stuffing-specialist"
  | "capec-code-mapper"
  | "waf-rule-lifecycle-agent"
  | "dos-resilience-tester"
  | "ai-model-supply-chain-agent"
  | "iam-privesc-graph-builder"
  | "device-integrity-aggregator"
  | "bot-detection-specialist"
  // Phase 3a — Auth & Identity micro-specialists
  | "trike-risk-modeler"
  | "csf2-governance-mapper"
  | "anti-replay-tester"
  | "oauth-pkce-specialist"
  | "step-up-auth-enforcer"
  | "session-timeout-tester"
  | "token-reuse-detector"
  | "samm-assessor"
  | "csa-ccm-mapper"
  // Phase 3b — Input Validation + Mobile
  | "unicode-homograph-tester"
  | "file-upload-attacker"
  | "multipart-abuse-tester"
  | "parser-exhaustion-tester"
  | "json-ambiguity-tester"
  | "cert-pin-rotation-specialist"
  | "mobile-binary-hardener"
  | "mobile-webview-auditor"
  | "deep-link-fuzzer"
  // Phase 3c — Cloud + Supply Chain + Observability
  | "egress-policy-enforcer"
  | "advanced-dos-tester"
  | "binary-auth-validator"
  | "secrets-mask-bypass-tester"
  | "git-history-secret-scanner"
  | "slsa-provenance-enforcer"
  | "registry-mirror-enforcer"
  | "webhook-security-tester"
  | "rotation-validation-agent"
  | "compliance-lifecycle-tracker"
  | "ssrf-detection-validator"
  // Phase 4 — Beyond-policy P2 agents
  | "linddun-privacy-analyst"
  | "dread-scorer"
  | "threat-infrastructure-analyst"
  | "slsa-level3-enforcer"
  | "quantum-migration-planner"
  | "zero-trust-architect";

export type AgentStatus = "pending" | "running" | "completed" | "completed_partial" | "failed";

// ---------------------------------------------------------------------------
// Stack context — built by orchestrator at startup
// ---------------------------------------------------------------------------

export type StackContext = {
  languages: string[];
  frameworks: string[];
  databases: string[];
  cloudProvider: ("aws" | "gcp" | "azure" | "unknown")[];
  paymentProcessor: string[];
  hasAI: boolean;
  hasMobile: boolean;
  hasPII: boolean;
  hasPayments: boolean;
  packageManagers: string[];
  ciPlatform: string[];
};

// ---------------------------------------------------------------------------
// Per-agent status record within the manifest
// ---------------------------------------------------------------------------

export type AgentRecord = {
  status: AgentStatus;
  startedAt: string | null;
  completedAt: string | null;
  findingsPath: string | null;
  summary: string | null;
};

// ---------------------------------------------------------------------------
// Manifest — written to .mcp/agent-runs/{agentRunId}/manifest.json
// ---------------------------------------------------------------------------

export type AgentRunPhase = 0 | 1 | 2 | 3;

export type AgentRunManifest = {
  agentRunId: string;
  runId: string;
  createdAt: string;
  updatedAt: string;
  phase: AgentRunPhase;
  internetPermitted: boolean;
  stackContext: StackContext;
  scope: {
    mode: "recent_changes" | "folder_by_folder" | "file_by_file";
    targets: string[];
    baseRef: string;
    headRef: string;
  };
  agents: Record<AgentName, AgentRecord>;
};

// ---------------------------------------------------------------------------
// Individual finding — all agents produce this shape
// ---------------------------------------------------------------------------

export type AgentFindingSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ComplianceImpact = {
  pciDss?: string[];
  soc2?: string[];
  nist80053?: string[];
  iso27001?: string[];
  gdpr?: string[];
  hipaa?: string[];
};

export type AgentFinding = {
  id: string;
  title: string;
  severity: AgentFindingSeverity;
  cwe?: string;
  attackTechnique?: string;
  cvssV4?: number;
  exploitChain?: string[];
  files?: string[];
  evidence?: string[];
  remediated: boolean;
  remediationSummary?: string;
  requiredActions: string[];
  complianceImpact?: ComplianceImpact;
  beyondSkillMd?: boolean;
};

// ---------------------------------------------------------------------------
// Per-agent findings file — written by each agent on completion
// ---------------------------------------------------------------------------

export type AgentFindingsFile = {
  agentName: AgentName;
  agentRunId: string;
  completedAt: string;
  internetUsed: boolean;
  memoryUpdated: boolean;
  skillMdSectionsCovered: string[];
  beyondSkillMd: string[];
  summary: string;
  findings: AgentFinding[];
  remediatedCount: number;
  openCount: number;
};

// ---------------------------------------------------------------------------
// Merged findings — produced by orchestration.merge_agent_findings
// ---------------------------------------------------------------------------

export type MergedFindings = {
  agentRunId: string;
  runId: string;
  mergedAt: string;
  agentsCovered: AgentName[];
  agentsPartial: AgentName[];
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  skillMdSectionsCovered: string[];
  uncoveredSections: string[];
  findings: AgentFinding[];
};

// ---------------------------------------------------------------------------
// Update check result
// ---------------------------------------------------------------------------

export type UpdateCheckResult = {
  hasUpdate: boolean;
  currentMcpVersion: string;
  latestMcpVersion: string | null;
  skillUpdates: Array<{
    skillName: string;
    currentVersion: string;
    latestVersion: string;
  }>;
  changelog: string;
};
