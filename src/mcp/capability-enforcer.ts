/**
 * Capability Enforcer — turns the "all agents always operate at their fullest
 * capability" mandate into an enforced, gate-blocking invariant.
 *
 * The rest of the platform *routes* work to full-power models (model-router.ts)
 * and *records* what each agent did (orchestration.ts writes the run manifest and
 * each agent writes a findings file). This module is the CHECK on the back end:
 * given a completed agent run, it re-derives what each spawned agent *should* have
 * done at full capability and asserts each one actually met its FLOOR.
 *
 * Four floors are asserted per agent:
 *   (a) Model tier — the agent must have executed at (or above) the capability tier
 *       that TASK_CAPABILITY_MAP assigns to its task type. A task in
 *       PROTECTED_MAX_POWER_TASKS that ran below "advanced" is a hard violation:
 *       the whole point of the protected set is that it can NEVER be downgraded.
 *   (b) Tool floor — the agent must have had (or invoked) the security-critical
 *       tools declared in its SKILL.md `allowed-tools` frontmatter. An auditor with
 *       no Grep/Read cannot have read the code; that is a violation, not a style nit.
 *   (c) Evidence depth — the agent must have produced non-empty findings/evidence OR
 *       an explicit, justified "clean" attestation. A silent empty result from a
 *       high-risk lead is treated as under-performance.
 *   (d) Coverage — reuses orchestration.verifySkillCoverage as the single source of
 *       truth for SKILL.md section coverage; we do NOT reimplement coverage here.
 *
 * Emission model (matches the gate's Finding[] contract from src/gate/result.ts):
 *   - Per under-performing agent: one HIGH `CAPABILITY_DEGRADED` finding whose title
 *     names the agent and which floor(s) it missed, with concrete requiredActions.
 *   - If ANY agent is degraded: one run-level CRITICAL `CAPABILITY_FLOOR_NOT_MET`
 *     finding. Because the gate fails on any CRITICAL/HIGH (see
 *     orchestration.mergeAgentFindings gateStatus logic), emitting this forces FAIL.
 *
 * GRACEFUL DEGRADATION: the manifest's AgentRecord and the AgentFindingsFile do NOT
 * currently record the model actually used, the task type, or the tools invoked (see
 * the TODOs below). Where a floor cannot be evaluated because the metadata was never
 * recorded, we DO NOT crash and we DO NOT silently pass — we emit a MEDIUM advisory
 * naming exactly what orchestration needs to start recording, and treat that floor as
 * "unknown" rather than "met". Only floors we can affirmatively evaluate can produce
 * a HIGH violation.
 *
 * File-reading / error-handling conventions mirror orchestration.ts: read run state
 * from .mcp/agent-runs/{agentRunId}, validate the agentRunId against the same 32-char
 * hex pattern, tolerate missing/corrupt per-agent files, and never throw on a single
 * bad file — degrade to partial instead.
 */

import { readFile, readdir } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

import type { Finding } from "../gate/result.js";
import type {
  AgentName,
  AgentRecord,
  AgentRunManifest
} from "../types/agent-run.js";
import {
  TASK_CAPABILITY_MAP,
  PROTECTED_MAX_POWER_TASKS,
  MODEL_REGISTRY,
  type TaskType,
  type CapabilityTier
} from "./model-router.js";
import { verifySkillCoverage } from "./orchestration.js";

// ---------------------------------------------------------------------------
// Constants — kept in lock-step with orchestration.ts
// ---------------------------------------------------------------------------

// Same on-disk layout orchestration.ts uses. We resolve relative to process.cwd()
// exactly like orchestration.agentRunDir so both modules read the same run state.
const AGENT_RUNS_DIR = join(".mcp", "agent-runs");

// CWE-22: agentRunId is used as a path component. Mirror orchestration.ts's pattern
// (the 32-char hex digest produced by createAgentRun) so a crafted id can't escape
// the agent-runs directory.
const SAFE_AGENT_RUN_ID_RE = /^[0-9a-f]{32}$/;

// Skills ship INSIDE the npm package (package.json `files` includes "skills/"), and
// orchestration.ts already treats the bundled copy as the trust root. We read each
// agent's SKILL.md `allowed-tools` frontmatter from the SAME bundled dir so the tool
// floor is derived from the trusted, shipped skill rather than a network copy.
const BUNDLED_SKILLS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../skills");

// Highest-quality capability tier. An agent at this tier can never be "degraded" on
// the model floor. Used only for readability in comparisons below.
const MAX_TIER: CapabilityTier = "advanced";

// Rank capability tiers so we can compare "did the agent run at >= required tier".
// Mirrors model-router.capabilityTierRank (kept local to avoid exporting internals).
const CAPABILITY_TIER_RANK: Record<CapabilityTier, number> = {
  light: 0,
  standard: 1,
  advanced: 2
};

// The security-critical tool floor. If a SKILL.md declares any of these in its
// `allowed-tools`, the agent MUST have had them available to do real work. An
// auditor/grep-less agent is the canonical "silently degraded" failure this catches.
// This is intentionally a small, high-signal set — not every tool in every skill.
const SECURITY_CRITICAL_TOOLS: ReadonlySet<string> = new Set([
  "Read",
  "Grep",
  "Glob",
  "Bash"
]);

// High-risk leads (borrowed from orchestration.HIGH_RISK_LEADS semantics): a
// "completed" agent on one of these that produced zero evidence and no explicit
// clean attestation is under-performing on the evidence-depth floor.
const HIGH_RISK_LEADS: ReadonlySet<AgentName> = new Set<AgentName>([
  "appsec-code-auditor",
  "crypto-pki-specialist",
  "supply-chain-devsecops",
  "cloud-infra-specialist",
  "ai-llm-redteam",
  "pentest-team",
  "threat-modeler"
]);

// Recognise an explicit, justified "clean" attestation in a summary so a genuinely
// clean surface isn't punished for having no findings. Mirrors the regex used in
// orchestration.mergeAgentFindings for WEAK_AGENT_OUTPUT detection.
const CLEAN_ATTESTATION_RE =
  /\b(no (issues?|findings?|vulnerabilit\w+) (found|identified|detected)|clean|nothing to report)\b/;

// ---------------------------------------------------------------------------
// Agent → TaskType mapping
// ---------------------------------------------------------------------------

/**
 * Map each agent to the model-router TaskType whose capability floor it must meet.
 *
 * This is the bridge between the orchestration agent registry (AgentName) and the
 * model-router capability model (TaskType). It is deliberately conservative: every
 * security-reasoning agent maps to a PROTECTED_MAX_POWER_TASKS entry so its floor is
 * "advanced" and can never be legitimately downgraded. Genuinely light, mechanical
 * agents (evidence collection, manifest/lockfile parsing) map to light task types.
 *
 * Agents not listed here fall back to a conservative "advanced" default (see
 * taskTypeForAgent) — we would rather over-require capability than silently let an
 * unmapped security agent run weak.
 *
 * TODO(orchestration): the AUTHORITATIVE task type an agent actually routed under
 * should be recorded per-agent (see AgentCapabilityMetadataSchema.taskType). Until
 * then this static map is the source of truth; once recorded, prefer the recorded
 * value so the enforcer checks the real routing decision, not an inferred one.
 */
const AGENT_TASK_TYPE: Partial<Record<AgentName, TaskType>> = {
  // ── Threat modelling leads/sub-agents → threat_model (protected/advanced) ──
  "threat-modeler": "threat_model",
  "stride-pasta-analyst": "threat_model",
  "attack-navigator": "threat_model",
  "business-logic-attacker": "threat_model",
  "privacy-flow-analyst": "threat_model",
  "trike-risk-modeler": "threat_model",
  "linddun-privacy-analyst": "threat_model",
  "dread-scorer": "risk_scoring",
  "threat-infrastructure-analyst": "threat_model",

  // ── AppSec code audit → code_review (advanced) / injection → exploit_chain ──
  "appsec-code-auditor": "code_review",
  "injection-specialist": "exploit_chain",
  "auth-session-hacker": "auth_analysis",
  "logic-race-fuzzer": "exploit_chain",
  "serialization-memory-attacker": "exploit_chain",

  // ── Supply chain / DevSecOps → code_review (advanced) ──────────────────────
  "supply-chain-devsecops": "code_review",
  "dependency-confusion-attacker": "exploit_chain",
  "cicd-pipeline-hijacker": "exploit_chain",
  "artifact-integrity-analyst": "code_review",

  // ── Crypto / PKI → crypto_analysis (protected/advanced) ────────────────────
  "crypto-pki-specialist": "crypto_analysis",
  "tls-certificate-auditor": "crypto_analysis",
  "algorithm-implementation-reviewer": "crypto_analysis",
  "key-management-lifecycle-analyst": "crypto_analysis",
  "quantum-migration-planner": "crypto_analysis",

  // ── Cloud / infra → code_review; cloud pentesters → pentest (protected) ─────
  "cloud-infra-specialist": "code_review",
  "aws-penetration-tester": "pentest",
  "gcp-penetration-tester": "pentest",
  "azure-penetration-tester": "pentest",
  "k8s-container-escaper": "pentest",

  // ── AI / LLM red team → ai_redteam (protected/advanced) ────────────────────
  "ai-llm-redteam": "ai_redteam",
  "prompt-injection-specialist": "ai_redteam",
  "model-extraction-attacker": "ai_redteam",
  "rag-poisoning-specialist": "ai_redteam",
  "agentic-loop-exploiter": "ai_redteam",
  "ai-model-supply-chain-agent": "ai_redteam",

  // ── Mobile → code_review; mobile pentesters → pentest ──────────────────────
  "mobile-security-specialist": "code_review",
  "ios-security-auditor": "code_review",
  "android-penetration-tester": "pentest",
  "mobile-api-network-attacker": "pentest",

  // ── Phase 2: pentest team → pentest (protected/advanced) ───────────────────
  "pentest-team": "pentest",
  "pentest-web-api": "pentest",
  "pentest-infra": "pentest",
  "pentest-social": "pentest",

  // ── Compliance / evidence → compliance_analysis (advanced) / light collect ─
  "compliance-grc": "compliance_analysis",
  "compliance-gap-analyst": "compliance_analysis",
  "compliance-lifecycle-tracker": "compliance_analysis",
  "evidence-collector": "evidence_collection", // genuinely light/mechanical

  // ── Phase 2 P0 gap agents ──────────────────────────────────────────────────
  "incident-responder": "incident_response",
  "kill-switch-engineer": "incident_response",
  "credential-stuffing-specialist": "auth_analysis",
  "capec-code-mapper": "code_review",
  "waf-rule-lifecycle-agent": "code_review",
  "dos-resilience-tester": "pentest",
  "iam-privesc-graph-builder": "pentest",
  "device-integrity-aggregator": "code_review",
  "bot-detection-specialist": "auth_analysis"
};

/**
 * Resolve the TaskType for an agent. Falls back to a conservative "code_review"
 * (advanced tier) for any unmapped agent — we prefer to OVER-require capability for
 * an unknown security agent rather than let it slip below the floor unnoticed.
 */
function taskTypeForAgent(agent: AgentName): TaskType {
  return AGENT_TASK_TYPE[agent] ?? "code_review";
}

// ---------------------------------------------------------------------------
// Optional per-agent capability metadata (forward-compatible)
// ---------------------------------------------------------------------------

/**
 * Forward-compatible schema for capability metadata that a findings file MAY carry.
 * NONE of these fields are currently written by orchestration.ts — this is the
 * "graceful degradation" contract. When present, we enforce the real floor; when
 * absent, we emit a MEDIUM advisory and treat the floor as "unknown".
 *
 * TODO(orchestration): start recording this block per agent. The two cleanest homes:
 *   1. On the manifest AgentRecord (add `capability?: AgentCapabilityMetadata`), set
 *      by updateAgentStatus when the agent reports completion; OR
 *   2. Inside each per-agent findings file under a top-level `capability` key.
 * The enforcer already reads BOTH locations (findings file wins if both are present).
 * Minimum fields needed for full model-floor + tool-floor enforcement:
 *   - modelUsed:   the concrete modelId the agent actually executed under
 *                  (e.g. "claude-opus-4-8"); lets us look up its capabilityTier.
 *   - taskType:    the TaskType the agent routed under (authoritative vs. inferred).
 *   - toolsUsed:   the tools the agent actually invoked (for tool-floor enforcement
 *                  beyond "was allowed"); at minimum the security-critical subset.
 */
const AgentCapabilityMetadataSchema = z.object({
  // The concrete model id the agent executed under (matches a MODEL_REGISTRY.modelId).
  modelUsed: z.string().min(1).max(128).optional(),
  // The capability tier the agent executed at, if the caller recorded it directly.
  capabilityTierUsed: z.enum(["light", "standard", "advanced"]).optional(),
  // The task type the agent actually routed under (authoritative over inference).
  taskType: z.string().min(1).max(64).optional(),
  // Tools the agent actually invoked during the run.
  toolsUsed: z.array(z.string().max(64)).max(128).optional(),
  // Tools the agent had available (superset of toolsUsed). Either satisfies the floor.
  toolsAvailable: z.array(z.string().max(64)).max(128).optional()
}).passthrough();

type AgentCapabilityMetadata = z.infer<typeof AgentCapabilityMetadataSchema>;

/**
 * Loose schema for the parts of a per-agent findings file we care about here. We do
 * NOT re-validate the full finding shape (orchestration.mergeAgentFindings already
 * owns that trust boundary); we only need agent identity, evidence signal, and any
 * optional capability metadata.
 */
const AgentFindingsFileLiteSchema = z.object({
  agentName: z.string().max(128).optional(),
  summary: z.string().max(8000).optional(),
  findings: z.array(z.unknown()).max(5000).optional(),
  capability: AgentCapabilityMetadataSchema.optional()
}).passthrough();

// ---------------------------------------------------------------------------
// Internal helpers — file reading (mirrors orchestration.ts conventions)
// ---------------------------------------------------------------------------

function agentRunDir(agentRunId: string): string {
  // CWE-22: identical guard to orchestration.agentRunDir.
  if (!SAFE_AGENT_RUN_ID_RE.test(agentRunId)) {
    throw new Error(`Invalid agentRunId "${agentRunId}"`);
  }
  return join(process.cwd(), AGENT_RUNS_DIR, agentRunId);
}

function manifestPath(agentRunId: string): string {
  return join(agentRunDir(agentRunId), "manifest.json");
}

async function readManifest(agentRunId: string): Promise<AgentRunManifest> {
  const raw = await readFile(manifestPath(agentRunId), "utf-8");
  return JSON.parse(raw) as AgentRunManifest;
}

/**
 * Parse the `allowed-tools:` line out of a SKILL.md YAML frontmatter block and return
 * the declared tool names. Frontmatter looks like:
 *
 *   ---
 *   name: appsec-code-auditor
 *   allowed-tools: Read, Glob, Grep, Bash, Agent, Edit, WebSearch, WebFetch
 *   ---
 *
 * Returns null when the skill file is absent or has no allowed-tools line, so callers
 * can distinguish "no tool floor known" (degrade to advisory) from "empty floor".
 */
function readAllowedToolsForAgent(agent: AgentName): string[] | null {
  const skillPath = join(BUNDLED_SKILLS_DIR, agent, "SKILL.md");
  if (!existsSync(skillPath)) return null;

  let content: string;
  try {
    content = readFileSync(skillPath, "utf-8");
  } catch {
    return null;
  }

  // Only look inside the leading frontmatter block (between the first two `---`),
  // so a mention of "allowed-tools" in prose can't spoof the floor.
  const fmMatch = content.match(/^---\s*\n([\s\S]*?)\n---/);
  const frontmatter = fmMatch ? fmMatch[1] : content;

  const line = frontmatter.split("\n").find((l) => /^\s*allowed-tools\s*:/i.test(l));
  if (!line) return null;

  const rhs = line.replace(/^\s*allowed-tools\s*:/i, "").trim();
  if (!rhs) return [];

  return rhs
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

/** Look up the capability tier of a concrete model id from the registry. */
function tierForModel(modelId: string): CapabilityTier | null {
  const model = MODEL_REGISTRY.find((m) => m.modelId === modelId);
  return model ? model.capabilityTier : null;
}

/**
 * Read each present per-agent findings file and index it by agentName. Corrupt or
 * schema-invalid files are skipped (mirrors mergeAgentFindings' tolerant loop) — a
 * single bad file must never crash enforcement.
 */
async function loadAgentFindingsFiles(
  dir: string
): Promise<Map<string, z.infer<typeof AgentFindingsFileLiteSchema>>> {
  const byAgent = new Map<string, z.infer<typeof AgentFindingsFileLiteSchema>>();

  let files: string[] = [];
  try {
    const entries = await readdir(dir);
    files = entries.filter(
      (f) => f.endsWith(".json") && f !== "manifest.json" && f !== "merged-findings.json" && f !== "attestation-chain.json"
    );
  } catch {
    return byAgent;
  }

  for (const file of files) {
    try {
      const raw = await readFile(join(dir, file), "utf-8");
      const parsed = AgentFindingsFileLiteSchema.parse(JSON.parse(raw));
      const key = parsed.agentName ?? file.replace(/\.json$/, "");
      byAgent.set(key, parsed);
    } catch {
      // Skip corrupt/invalid file — evidence-depth check will treat this agent's
      // output as absent, which is itself a signal (handled per-agent below).
      continue;
    }
  }

  return byAgent;
}

// ---------------------------------------------------------------------------
// Per-floor evaluation result
// ---------------------------------------------------------------------------

/** One floor's verdict for one agent. */
type FloorVerdict = "met" | "violation" | "unknown";

type AgentEvaluation = {
  agent: AgentName;
  taskType: TaskType;
  requiredTier: CapabilityTier;
  protected: boolean;
  // Per-floor verdicts.
  modelFloor: FloorVerdict;
  toolFloor: FloorVerdict;
  evidenceFloor: FloorVerdict;
  // Human-readable reasons for each missed/unknown floor (used to build findings).
  missedFloors: string[];   // → HIGH CAPABILITY_DEGRADED
  unknownFloors: string[];  // → MEDIUM advisory (metadata not recorded)
};

// ---------------------------------------------------------------------------
// Core per-agent floor evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate all four floors for a single spawned agent. Pure given its inputs; does no
 * IO. `coverageBelowThreshold` is passed in from the run-level coverage check so the
 * coverage floor is sourced ONLY from verifySkillCoverage (never reimplemented here).
 */
function evaluateAgent(
  agent: AgentName,
  record: AgentRecord | undefined,
  findingsFile: z.infer<typeof AgentFindingsFileLiteSchema> | undefined,
  allowedTools: string[] | null,
  recordCapability: AgentCapabilityMetadata | undefined
): AgentEvaluation {
  const taskType = taskTypeForAgent(agent);
  const requiredTier = TASK_CAPABILITY_MAP[taskType];
  const isProtected = PROTECTED_MAX_POWER_TASKS.has(taskType);

  const missedFloors: string[] = [];
  const unknownFloors: string[] = [];

  // Findings-file capability block wins over manifest-record capability block if both
  // exist (the findings file is written last, closest to the agent's actual work).
  const capability: AgentCapabilityMetadata | undefined =
    findingsFile?.capability ?? recordCapability;

  // ── Floor (a): MODEL TIER ────────────────────────────────────────────────
  // Determine the tier the agent actually executed at, preferring an explicit
  // capabilityTierUsed, then deriving from a recorded modelUsed, else unknown.
  let modelFloor: FloorVerdict;
  let executedTier: CapabilityTier | null = null;
  if (capability?.capabilityTierUsed) {
    executedTier = capability.capabilityTierUsed;
  } else if (capability?.modelUsed) {
    executedTier = tierForModel(capability.modelUsed);
    if (executedTier === null) {
      // Model id recorded but not in the registry — can't rank it. Treat as unknown
      // rather than guessing; surface which id was unrecognised.
      unknownFloors.push(
        `model tier: recorded model "${capability.modelUsed}" is not in MODEL_REGISTRY, cannot rank its capability tier`
      );
    }
  }

  if (executedTier === null && !unknownFloors.some((u) => u.startsWith("model tier"))) {
    // No model/tier metadata recorded at all → cannot affirmatively check this floor.
    modelFloor = "unknown";
    unknownFloors.push(
      "model tier: no modelUsed/capabilityTierUsed recorded for this agent " +
      "(orchestration does not yet persist the model an agent executed under)"
    );
  } else if (executedTier === null) {
    modelFloor = "unknown";
  } else {
    const ran = CAPABILITY_TIER_RANK[executedTier];
    const need = CAPABILITY_TIER_RANK[requiredTier];
    if (ran >= need) {
      modelFloor = "met";
    } else {
      modelFloor = "violation";
      // A protected task below advanced is the flagship violation this enforcer exists
      // to catch; call it out explicitly in the message.
      const protectedNote = isProtected && requiredTier === MAX_TIER
        ? " — this is a PROTECTED_MAX_POWER task that must NEVER be downgraded below advanced"
        : "";
      missedFloors.push(
        `model tier: executed at "${executedTier}" but task "${taskType}" requires "${requiredTier}"${protectedNote}`
      );
    }
  }

  // ── Floor (b): TOOL FLOOR ────────────────────────────────────────────────
  // The security-critical subset of the agent's declared allowed-tools is its floor.
  // We can affirmatively check this only if we know what the agent actually had/used.
  let toolFloor: FloorVerdict;
  if (allowedTools === null) {
    // No SKILL.md / no allowed-tools line — we don't know this agent's tool floor.
    toolFloor = "unknown";
    unknownFloors.push(
      "tool floor: could not read allowed-tools from the agent's SKILL.md frontmatter"
    );
  } else {
    // Required security-critical tools this agent is supposed to wield.
    const requiredCritical = allowedTools.filter((t) => SECURITY_CRITICAL_TOOLS.has(t));

    const actualTools =
      capability?.toolsUsed ?? capability?.toolsAvailable ?? null;

    if (requiredCritical.length === 0) {
      // Skill declares no security-critical tools (rare) — nothing to enforce.
      toolFloor = "met";
    } else if (actualTools === null) {
      // We know what it SHOULD have, but not what it DID have. Degrade to advisory:
      // absence of recorded tool usage is a metadata gap, not proof of a violation.
      toolFloor = "unknown";
      unknownFloors.push(
        `tool floor: SKILL.md requires security-critical tools [${requiredCritical.join(", ")}] ` +
        "but no toolsUsed/toolsAvailable were recorded for this agent"
      );
    } else {
      const actualSet = new Set(actualTools);
      const missing = requiredCritical.filter((t) => !actualSet.has(t));
      if (missing.length === 0) {
        toolFloor = "met";
      } else {
        toolFloor = "violation";
        missedFloors.push(
          `tool floor: missing security-critical tool(s) [${missing.join(", ")}] the SKILL.md declares as required`
        );
      }
    }
  }

  // ── Floor (c): EVIDENCE DEPTH ────────────────────────────────────────────
  // A terminal agent must have produced non-empty findings/evidence OR an explicit,
  // justified clean attestation. This is evaluable from data we DO have today.
  let evidenceFloor: FloorVerdict;
  const status = record?.status;
  const isTerminal = status === "completed" || status === "completed_partial";

  if (!record || !isTerminal) {
    // Not a completed agent — evidence depth is not this floor's concern (missing/
    // ghost leads are handled by orchestration.mergeAgentFindings). Mark unknown so we
    // neither pass nor fail it here.
    evidenceFloor = "unknown";
    if (record && status && status !== "pending") {
      unknownFloors.push(`evidence depth: agent status is "${status}" (not a terminal completion) — evidence not assessed here`);
    }
  } else {
    const findingCount = findingsFile?.findings?.length ?? 0;
    const summary = (findingsFile?.summary ?? record.summary ?? "").toLowerCase();
    const hasCleanAttestation = CLEAN_ATTESTATION_RE.test(summary);

    if (findingCount > 0) {
      evidenceFloor = "met";
    } else if (hasCleanAttestation) {
      // Zero findings but an explicit, justified clean note — acceptable.
      evidenceFloor = "met";
    } else if (!findingsFile) {
      // Completed, but no findings file present at all → cannot see any evidence.
      // For a high-risk lead this is a HIGH violation; for others a MEDIUM advisory.
      if (HIGH_RISK_LEADS.has(agent)) {
        evidenceFloor = "violation";
        missedFloors.push(
          "evidence depth: completed with no findings file and no clean attestation (high-risk lead)"
        );
      } else {
        evidenceFloor = "unknown";
        unknownFloors.push("evidence depth: completed but no findings file was found for this agent");
      }
    } else {
      // Findings file present, zero findings, no clean note.
      if (HIGH_RISK_LEADS.has(agent)) {
        evidenceFloor = "violation";
        missedFloors.push(
          "evidence depth: high-risk lead reported completed with zero findings and no explicit " +
          "\"no issues found\" attestation — silent empty result"
        );
      } else {
        // Non-critical agent with a silent empty result — advisory only.
        evidenceFloor = "unknown";
        unknownFloors.push(
          "evidence depth: completed with zero findings and no explicit clean attestation"
        );
      }
    }
  }

  return {
    agent,
    taskType,
    requiredTier,
    protected: isProtected,
    modelFloor,
    toolFloor,
    evidenceFloor,
    missedFloors,
    unknownFloors
  };
}

// ---------------------------------------------------------------------------
// Finding builders
// ---------------------------------------------------------------------------

/**
 * Build the per-agent HIGH `CAPABILITY_DEGRADED` finding. Called only when the agent
 * has at least one affirmatively-missed floor.
 */
function buildDegradedFinding(evaluation: AgentEvaluation): Finding {
  const floorsList = evaluation.missedFloors.join("; ");
  return {
    id: `CAPABILITY_DEGRADED::${evaluation.agent}`,
    title:
      `Agent "${evaluation.agent}" operated below its capability floor ` +
      `(task "${evaluation.taskType}", required tier "${evaluation.requiredTier}"): ${floorsList}`,
    severity: "HIGH",
    evidence: [
      ...evaluation.missedFloors.map((m) => `MISSED — ${m}`),
      ...evaluation.unknownFloors.map((u) => `UNVERIFIED — ${u}`)
    ],
    requiredActions: [
      `Re-run agent "${evaluation.agent}" at its required "${evaluation.requiredTier}" capability tier` +
        (evaluation.protected ? " (this is a protected max-power task — downgrade is never permitted)." : "."),
      "Ensure the agent has every security-critical tool declared in its SKILL.md allowed-tools before re-running.",
      "Confirm the agent produces non-empty findings or an explicit, justified clean attestation."
    ]
  };
}

/**
 * Build the per-agent MEDIUM advisory finding for floors we could not evaluate because
 * the required metadata was never recorded. This is the "graceful degrade" path — it
 * makes the enforcement gap visible without pretending a violation occurred.
 */
function buildAdvisoryFinding(evaluation: AgentEvaluation): Finding {
  return {
    id: `CAPABILITY_UNVERIFIED::${evaluation.agent}`,
    title:
      `Capability floor for agent "${evaluation.agent}" could not be fully verified ` +
      `(${evaluation.unknownFloors.length} floor(s) lack recorded metadata)`,
    severity: "MEDIUM",
    evidence: evaluation.unknownFloors.map((u) => `UNVERIFIED — ${u}`),
    requiredActions: [
      "Have orchestration record per-agent capability metadata (modelUsed, taskType, toolsUsed) " +
        "so the model and tool floors can be enforced rather than advised.",
      "See AgentCapabilityMetadataSchema in capability-enforcer.ts for the exact fields expected."
    ]
  };
}

/**
 * Build the run-level CRITICAL `CAPABILITY_FLOOR_NOT_MET` finding. Emitting this forces
 * the gate to FAIL (mergeAgentFindings fails on any CRITICAL/HIGH). Only emitted when
 * at least one agent had an affirmatively-missed floor.
 */
function buildRunLevelFinding(degradedAgents: string[]): Finding {
  return {
    id: "CAPABILITY_FLOOR_NOT_MET",
    title:
      `Capability floor not met: ${degradedAgents.length} agent(s) operated below full power ` +
      `— ${degradedAgents.join(", ")}. The "all agents at fullest capability" mandate is violated; gate must FAIL.`,
    severity: "CRITICAL",
    evidence: degradedAgents.map((a) => `Degraded agent: ${a}`),
    requiredActions: [
      "Do not pass this gate until every degraded agent is re-run at its required capability tier.",
      "Investigate why full-power routing was not applied (budget valve misconfiguration, forced-standard policy, " +
        "circuit-breaker fallback, or missing tools).",
      "Protected max-power tasks (exploit_chain, pentest, ai_redteam, crypto_analysis, auth_analysis, " +
        "threat_model, remediation) must never be downgraded — verify none were."
    ]
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export const EnforceCapabilityFloorSchema = z.object({
  agentRunId: z
    .string()
    .describe("Agent run ID from orchestration.create_agent_run (32-char hex digest).")
});

/**
 * Enforce the capability floor for every spawned agent in a run.
 *
 * @returns
 *   - findings:        Finding[] — per-agent HIGH CAPABILITY_DEGRADED, per-agent MEDIUM
 *                      advisories for unverifiable floors, and (if any agent is degraded)
 *                      one run-level CRITICAL CAPABILITY_FLOOR_NOT_MET.
 *   - degradedAgents:  names of agents with at least one affirmatively-missed floor.
 *   - passed:          true iff no agent was affirmatively degraded (advisories alone do
 *                      NOT flip this to false — they are metadata gaps, not violations).
 */
export async function enforceCapabilityFloor(args: {
  agentRunId: string;
}): Promise<{ findings: Finding[]; degradedAgents: string[]; passed: boolean }> {
  const { agentRunId } = args;
  const dir = agentRunDir(agentRunId); // throws on malformed id (CWE-22), matching orchestration

  // Read the manifest (source of truth for which agents were spawned + their status).
  // If the manifest is unreadable there is nothing to enforce against; surface that as
  // a single advisory rather than throwing, so the caller can still make a decision.
  let manifest: AgentRunManifest;
  try {
    manifest = await readManifest(agentRunId);
  } catch {
    return {
      findings: [
        {
          id: "CAPABILITY_MANIFEST_UNREADABLE",
          title: `Capability floor could not be enforced: manifest for run ${agentRunId} is missing or unreadable`,
          severity: "MEDIUM",
          requiredActions: [
            "Verify the agent run exists and its manifest.json is present and valid before enforcing the capability floor."
          ]
        }
      ],
      degradedAgents: [],
      passed: true // no manifest → nothing to affirmatively fail on
    };
  }

  // Load every present per-agent findings file (tolerant of corrupt files).
  const findingsByAgent = await loadAgentFindingsFiles(dir);

  // Coverage floor (d): reuse verifySkillCoverage as the single source of truth. We do
  // NOT reimplement coverage. A below-threshold result is emitted as its own HIGH finding
  // and counts as a run-level degradation signal. (mergeAgentFindings also enforces
  // coverage independently; emitting here keeps the enforcer's report self-contained.)
  let coverageFinding: Finding | null = null;
  let coverageDegraded = false;
  try {
    const coverage = await verifySkillCoverage({ agentRunId });
    if (coverage.status !== "PASS" && coverage.uncovered.length > 0) {
      // Treat material under-coverage as a degradation. We key off verifySkillCoverage's
      // own PASS/WARN status so the threshold stays owned by orchestration.
      coverageDegraded = true;
      coverageFinding = {
        id: "CAPABILITY_COVERAGE_INCOMPLETE",
        title:
          `SKILL.md coverage incomplete at ${coverage.coveragePercent}% ` +
          `(${coverage.uncovered.length} section(s) uncovered) — agents did not exercise full skill depth`,
        severity: "HIGH",
        evidence: [`Uncovered sections: ${coverage.uncovered.join(", ")}`],
        requiredActions: [
          "Ensure every spawned agent reports the SKILL.md sections it covered so coverage reaches the required threshold.",
          "Re-run the uncovered surfaces at full capability before passing the gate."
        ]
      };
    }
  } catch {
    // verifySkillCoverage failing is itself a signal, but not a hard violation — advise.
    coverageFinding = {
      id: "CAPABILITY_COVERAGE_UNVERIFIED",
      title: `SKILL.md coverage could not be verified for run ${agentRunId}`,
      severity: "MEDIUM",
      requiredActions: ["Confirm agent findings files record skillMdSectionsCovered so coverage can be verified."]
    };
  }

  // Evaluate each spawned agent against floors (a)–(c).
  const findings: Finding[] = [];
  const degradedAgents: string[] = [];

  const agentNames = Object.keys(manifest.agents) as AgentName[];
  for (const agent of agentNames) {
    const record = manifest.agents[agent];

    // Only evaluate agents that actually did (or were meant to do) work this run. We
    // skip agents still "pending" that never started — a never-spawned optional agent
    // is an orchestration concern, not a capability-degradation one. Terminal and
    // running agents are all evaluated.
    if (!record || record.status === "pending") continue;

    const findingsFile = findingsByAgent.get(agent);
    const allowedTools = readAllowedToolsForAgent(agent);
    // TODO(orchestration): also read a per-agent capability block off the AgentRecord
    // once persisted. Today AgentRecord carries none, so recordCapability is undefined
    // and only the findings-file `capability` block (if any) is consulted.
    const recordCapability = (record as AgentRecord & { capability?: AgentCapabilityMetadata }).capability;

    const evaluation = evaluateAgent(agent, record, findingsFile, allowedTools, recordCapability);

    // Affirmatively-missed floor(s) → HIGH degraded finding + mark degraded.
    if (evaluation.missedFloors.length > 0) {
      findings.push(buildDegradedFinding(evaluation));
      degradedAgents.push(agent);
    } else if (evaluation.unknownFloors.length > 0) {
      // No hard violation, but floors we couldn't verify → MEDIUM advisory only.
      findings.push(buildAdvisoryFinding(evaluation));
    }
  }

  // Fold in the coverage floor finding, if any.
  if (coverageFinding) findings.push(coverageFinding);
  if (coverageDegraded) degradedAgents.push("skill-coverage");

  // Run-level CRITICAL only when at least one agent (or coverage) was AFFIRMATIVELY
  // degraded. Advisories alone never flip the gate — they flag a metadata gap to close.
  const passed = degradedAgents.length === 0;
  if (!passed) {
    findings.unshift(buildRunLevelFinding(degradedAgents));
  }

  return { findings, degradedAgents, passed };
}
