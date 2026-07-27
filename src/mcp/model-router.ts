/**
 * Model Router — multi-provider smart routing with automatic failover and cost-based selection.
 *
 * Providers: Anthropic (Claude), OpenAI (GPT), Google (Gemini), Cohere, Local (Ollama/Llama).
 *
 * Routing logic:
 *   1. Map task type to minimum capability tier (light | standard | advanced).
 *   2. Collect all provider models meeting that capability floor.
 *   3. Filter out providers whose circuit breaker is open (recent failures).
 *   4. Sort candidates by combined input+output pricing — cheapest first.
 *   5. Return cheapest healthy candidate.
 *   6. If ALL providers are unhealthy, fall back best-effort (circuit ignored).
 *
 * Failover: provider-level circuit breaker opens after 3 consecutive failures,
 * stays open for 60 seconds. Closed automatically after the cooldown expires.
 *
 * Budget circuit breaker: reads max_total_cost_usd from security-policy.json.
 *
 * Backward compatibility: ModelTier ("haiku" | "sonnet") is preserved for
 * UsageRecord and existing callers. light → haiku, standard/advanced → sonnet.
 *
 * Usage and health state persist to:
 *   .mcp/memory/model-usage.json    — token usage + spend
 *   .mcp/memory/provider-health.json — circuit breaker state
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { getWorkspaceRoot } from "../repo/workspace.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const HAIKU_MODEL = "claude-haiku-4-5-20251001";
export const SONNET_MODEL = "claude-sonnet-5";
export const OPUS_MODEL = "claude-opus-4-8";

// Resolved at call time against the workspace root, never as module-level relative
// constants. A bare join(".mcp", ...) resolves against process.cwd(), which diverges from
// the workspace whenever the server is started outside it (e.g. the supervisor's detached
// child inherits the server's cwd). That divergence is silent: the budget policy is never
// read so the circuit breaker runs on the default, and spend is written to the wrong tree.
// This is the same defect that made audit-chain report correctly-attested agents as
// unattested. See src/mcp/audit-chain.ts.
const MEMORY_DIR = () => join(getWorkspaceRoot(), ".mcp", "memory");
const USAGE_FILE = () => join(MEMORY_DIR(), "model-usage.json");
const HEALTH_FILE = () => join(MEMORY_DIR(), "provider-health.json");
const POLICY_FILE = () => join(getWorkspaceRoot(), ".mcp", "policies", "security-policy.json");

const DEFAULT_BUDGET_USD = 5;
const CIRCUIT_BREAKER_THRESHOLD = 3;   // failures before circuit opens
const CIRCUIT_BREAKER_COOLDOWN_MS = 60_000; // 60 seconds

// Budget safety valve — the ONLY mechanism allowed to reduce an agent below full
// power. When spend utilization crosses this threshold, NON-critical tasks may be
// downgraded advanced→standard. The protected set (see PROTECTED_MAX_POWER_TASKS)
// is NEVER downgraded regardless of budget.
const DEFAULT_DOWNGRADE_THRESHOLD_PCT = 80;

// Tasks that must ALWAYS run at their full advanced-tier capability — the budget
// circuit-breaker may never downgrade these. This is the security-critical core:
// active exploitation, adversarial AI, cryptography, authentication, and the
// threat-model/remediation reasoning that everything else depends on.
export const PROTECTED_MAX_POWER_TASKS: ReadonlySet<TaskType> = new Set<TaskType>([
  "exploit_chain",
  "pentest",
  "ai_redteam",
  "crypto_analysis",
  "auth_analysis",
  "threat_model",
  "remediation"
]);

// ---------------------------------------------------------------------------
// Rate limiting — recordProviderFailure to prevent circuit-breaker manipulation
// ---------------------------------------------------------------------------

const _providerFailureSubmissions = new Map<string, { count: number; windowStart: number }>();
const FAILURE_RATE_LIMIT = 5;     // max 5 failure reports per provider per window
const FAILURE_WINDOW_MS = 300_000; // 5 minute window

export function recordProviderFailureRateLimited(providerName: string): { allowed: boolean; reason?: string } {
  const now = Date.now();
  const entry = _providerFailureSubmissions.get(providerName);

  if (!entry || now - entry.windowStart > FAILURE_WINDOW_MS) {
    _providerFailureSubmissions.set(providerName, { count: 1, windowStart: now });
    return { allowed: true };
  }

  if (entry.count >= FAILURE_RATE_LIMIT) {
    return { allowed: false, reason: `Rate limit exceeded: max ${FAILURE_RATE_LIMIT} failure reports per provider per 5 minutes` };
  }

  entry.count++;
  return { allowed: true };
}

// ---------------------------------------------------------------------------
// Provider & Model Registry
// ---------------------------------------------------------------------------

export type Provider = "anthropic" | "openai" | "google" | "cohere" | "local";

/** Capability tier: maps to quality floor a task requires. */
export type CapabilityTier = "light" | "standard" | "advanced";

/** Backward-compatible tier label used in UsageRecord. */
export type ModelTier = "haiku" | "sonnet";

export type ProviderModel = {
  modelId: string;
  provider: Provider;
  capabilityTier: CapabilityTier;
  /** Input pricing per 1M tokens in USD. 0 for local/free models. */
  inputPer1M: number;
  /** Output pricing per 1M tokens in USD. 0 for local/free models. */
  outputPer1M: number;
  /** Human-readable label. */
  label: string;
  /** Optional base URL override — required for local/self-hosted models. */
  baseUrl?: string;
};

/**
 * Full model registry across all providers.
 * Pricing sourced from public pricing pages (approximate, for routing decisions only).
 * Local models cost $0 but require Ollama running at localhost:11434.
 */
export const MODEL_REGISTRY: ProviderModel[] = [
  // Anthropic — Claude
  {
    modelId: "claude-haiku-4-5-20251001",
    provider: "anthropic",
    capabilityTier: "light",
    inputPer1M: 0.25,
    outputPer1M: 1.25,
    label: "Claude Haiku 4.5"
  },
  {
    modelId: "claude-sonnet-5",
    provider: "anthropic",
    capabilityTier: "standard",
    inputPer1M: 3,
    outputPer1M: 15,
    label: "Claude Sonnet 5"
  },

  // OpenAI — GPT
  {
    modelId: "gpt-4o-mini",
    provider: "openai",
    capabilityTier: "light",
    inputPer1M: 0.15,
    outputPer1M: 0.6,
    label: "GPT-4o Mini"
  },
  {
    modelId: "gpt-4o",
    provider: "openai",
    capabilityTier: "standard",
    inputPer1M: 2.5,
    outputPer1M: 10,
    label: "GPT-4o"
  },

  // Google — Gemini
  {
    modelId: "gemini-1.5-flash",
    provider: "google",
    capabilityTier: "light",
    inputPer1M: 0.075,
    outputPer1M: 0.3,
    label: "Gemini 1.5 Flash"
  },
  {
    modelId: "gemini-1.5-pro",
    provider: "google",
    capabilityTier: "standard",
    inputPer1M: 1.25,
    outputPer1M: 5,
    label: "Gemini 1.5 Pro"
  },

  // Cohere — Command R
  {
    modelId: "command-r",
    provider: "cohere",
    capabilityTier: "light",
    inputPer1M: 0.15,
    outputPer1M: 0.6,
    label: "Command R"
  },
  {
    modelId: "command-r-plus",
    provider: "cohere",
    capabilityTier: "standard",
    inputPer1M: 2.5,
    outputPer1M: 10,
    label: "Command R+"
  },

  // Anthropic — Claude Opus (advanced tier). Max-power-by-default: security-critical
  // reasoning tasks prefer this tier automatically. Downgrade is opt-OUT via
  // model_budget.force_standard_tier_for and the budget safety valve only.
  {
    modelId: "claude-opus-4-8",
    provider: "anthropic",
    capabilityTier: "advanced",
    inputPer1M: 15,
    outputPer1M: 75,
    label: "Claude Opus 4.8"
  },

  // OpenAI — o1 (advanced tier)
  {
    modelId: "o1",
    provider: "openai",
    capabilityTier: "advanced",
    inputPer1M: 15,
    outputPer1M: 60,
    label: "OpenAI o1"
  },

  // Google — Gemini 2.0 Flash (advanced tier)
  {
    modelId: "gemini-2.0-flash-thinking-exp",
    provider: "google",
    capabilityTier: "advanced",
    inputPer1M: 0,
    outputPer1M: 0,
    label: "Gemini 2.0 Flash Thinking (experimental)"
  },

  // Local — Ollama (zero cost, requires Ollama at localhost:11434)
  {
    modelId: "llama3",
    provider: "local",
    capabilityTier: "light",
    inputPer1M: 0,
    outputPer1M: 0,
    label: "Llama 3 8B (local)",
    baseUrl: "http://localhost:11434"
  },
  {
    modelId: "llama3:70b",
    provider: "local",
    capabilityTier: "standard",
    inputPer1M: 0,
    outputPer1M: 0,
    label: "Llama 3 70B (local)",
    baseUrl: "http://localhost:11434"
  }
];

// ---------------------------------------------------------------------------
// Task types and capability requirements
// ---------------------------------------------------------------------------

export type TaskType =
  // Light — read-only, pattern matching
  | "pattern_match"
  | "manifest_scan"
  | "evidence_collection"
  | "lockfile_parse"
  | "dlp_scan"
  | "config_read"
  | "dependency_scan"
  | "secret_scan"
  // Standard — analysis, remediation, reasoning
  | "code_review"
  | "remediation"
  | "threat_model"
  | "compliance_analysis"
  | "exploit_chain"
  | "ai_redteam"
  | "pentest"
  | "crypto_analysis"
  | "auth_analysis"
  | "incident_response"
  | "risk_scoring"
  | "report_generation";

/**
 * Minimum capability tier required per task — MAX-POWER-BY-DEFAULT posture.
 *
 * Security-critical reasoning tasks default to "advanced" so every agent runs at
 * its fullest capability out of the box. Genuinely light, mechanical tasks stay at
 * "light"; report/summary style tasks stay at "standard". Downgrade of an advanced
 * task only ever happens via the budget safety valve (spend >= threshold) and never
 * for the PROTECTED_MAX_POWER_TASKS set.
 */
export const TASK_CAPABILITY_MAP: Record<TaskType, CapabilityTier> = {
  // Light — read-only, mechanical, no reasoning required.
  pattern_match: "light",
  manifest_scan: "light",
  evidence_collection: "light",
  lockfile_parse: "light",
  dlp_scan: "light",
  config_read: "light",
  dependency_scan: "light",
  secret_scan: "light",
  // Advanced — security-critical reasoning; full power by default.
  code_review: "advanced",
  remediation: "advanced",
  threat_model: "advanced",
  compliance_analysis: "advanced",
  exploit_chain: "advanced",
  ai_redteam: "advanced",
  pentest: "advanced",
  crypto_analysis: "advanced",
  auth_analysis: "advanced",
  incident_response: "advanced",
  risk_scoring: "advanced",
  // Standard — report/summary generation.
  report_generation: "standard"
};

/**
 * Legacy map — kept for backward compatibility with existing callers.
 * Maps task type to ModelTier label.
 */
export const TASK_TIER_MAP: Record<TaskType, ModelTier> = {
  pattern_match: "haiku",
  manifest_scan: "haiku",
  evidence_collection: "haiku",
  lockfile_parse: "haiku",
  dlp_scan: "haiku",
  config_read: "haiku",
  dependency_scan: "haiku",
  secret_scan: "haiku",
  code_review: "sonnet",
  remediation: "sonnet",
  threat_model: "sonnet",
  compliance_analysis: "sonnet",
  exploit_chain: "sonnet",
  ai_redteam: "sonnet",
  pentest: "sonnet",
  crypto_analysis: "sonnet",
  auth_analysis: "sonnet",
  incident_response: "sonnet",
  risk_scoring: "sonnet",
  report_generation: "sonnet"
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ModelAssignment = {
  model: string;
  provider: Provider;
  tier: ModelTier;
  capabilityTier: CapabilityTier;
  taskType: TaskType;
  rationale: string;
  estimatedInputCostPer1MTokens: number;
  estimatedOutputCostPer1MTokens: number;
  budgetStatus: "ok" | "warning" | "exceeded";
  remainingBudgetUsd: number | null;
  failoverUsed: boolean;
  baseUrl?: string;
};

export type UsageRecord = {
  taskType: TaskType;
  model: string;
  provider: Provider;
  tier: ModelTier;
  inputTokens: number;
  outputTokens: number;
  estimatedCostUsd: number;
  /**
   * Cost as REPORTED by the executing CLI, when it reports one. Preferred over the
   * estimate, because the estimate is computed from MODEL_REGISTRY prices keyed on
   * model IDs the local CLIs never actually use. On a subscription plan this figure
   * is API-equivalent, not money charged — see AgentExecutionRecord.costIsNotional.
   */
  actualCostUsd?: number;
  reportedBy?: "cli" | "estimate";
  agentName?: string;
  agentRunId?: string;
  timestamp: string;
};

/** Input to trackUsage: cost fields are computed or passed through, never required. */
export type UsageInput =
  Omit<UsageRecord, "timestamp" | "estimatedCostUsd" | "reportedBy"> & { estimatedCostUsd?: number };

export type BudgetStatus = {
  maxBudgetUsd: number;
  spentUsd: number;
  remainingUsd: number;
  utilizationPct: number;
  status: "ok" | "warning" | "exceeded";
  haikuCalls: number;
  sonnetCalls: number;
  totalCalls: number;
  breakdownByTaskType: Record<string, { calls: number; estimatedCostUsd: number }>;
  breakdownByProvider: Record<string, { calls: number; estimatedCostUsd: number }>;
  recentUsage: UsageRecord[];
};

export type ProviderHealth = {
  provider: Provider;
  healthy: boolean;
  consecutiveFailures: number;
  lastFailureAt: string | null;
  circuitOpenUntil: string | null;
  totalCallsTracked: number;
};

type UsageStore = {
  version: 1;
  updatedAt: string;
  totalSpentUsd: number;
  records: UsageRecord[];
};

type ProviderHealthStore = {
  version: 1;
  updatedAt: string;
  providers: Record<string, {
    consecutiveFailures: number;
    lastFailureAt: string | null;
    circuitOpenUntil: string | null;
    totalCallsTracked: number;
  }>;
};

type SecurityPolicy = {
  model_budget?: {
    max_total_cost_usd?: number;
    preferred_providers?: Provider[];
    fallback_on_budget_exceeded?: string;
    /**
     * LEGACY (opt-IN) — kept for backward compatibility only. Task types that should
     * prefer the advanced capability tier. The DEFAULT posture is now max-power:
     * advanced-tier tasks (per TASK_CAPABILITY_MAP) already prefer advanced without
     * appearing in this list. Entries here are simply unioned in as extra advanced
     * preferences and never reduce power.
     */
    advanced_task_preference?: TaskType[];
    /**
     * OPT-OUT list. Task types named here are forced DOWN to standard tier regardless
     * of the max-power default. Empty by default so every advanced task runs at full
     * power. Tasks in PROTECTED_MAX_POWER_TASKS ignore this list and always run advanced.
     */
    force_standard_tier_for?: TaskType[];
    /**
     * Budget safety valve threshold (percent, 0–100). When spend utilization reaches
     * or exceeds this value, NON-critical advanced tasks may be downgraded to standard.
     * Defaults to DEFAULT_DOWNGRADE_THRESHOLD_PCT (80). Protected tasks are never downgraded.
     */
    downgrade_threshold_pct?: number;
  };
};

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

async function ensureMemoryDir(): Promise<void> {
  await mkdir(MEMORY_DIR(), { recursive: true, mode: 0o700 });
}

async function loadUsageStore(): Promise<UsageStore> {
  try {
    const raw = await readFile(USAGE_FILE(), "utf-8");
    return JSON.parse(raw) as UsageStore;
  } catch {
    return { version: 1, updatedAt: new Date().toISOString(), totalSpentUsd: 0, records: [] };
  }
}

async function saveUsageStore(store: UsageStore): Promise<void> {
  await ensureMemoryDir();
  store.updatedAt = new Date().toISOString();
  await writeFile(USAGE_FILE(), JSON.stringify(store, null, 2) + "\n", { encoding: "utf-8", mode: 0o600 });
}

async function loadHealthStore(): Promise<ProviderHealthStore> {
  try {
    const raw = await readFile(HEALTH_FILE(), "utf-8");
    return JSON.parse(raw) as ProviderHealthStore;
  } catch {
    return { version: 1, updatedAt: new Date().toISOString(), providers: {} };
  }
}

async function saveHealthStore(store: ProviderHealthStore): Promise<void> {
  await ensureMemoryDir();
  store.updatedAt = new Date().toISOString();
  await writeFile(HEALTH_FILE(), JSON.stringify(store, null, 2) + "\n", { encoding: "utf-8", mode: 0o600 });
}

async function loadMaxBudget(): Promise<number> {
  try {
    const raw = await readFile(POLICY_FILE(), "utf-8");
    const policy = JSON.parse(raw) as SecurityPolicy;
    return policy.model_budget?.max_total_cost_usd ?? DEFAULT_BUDGET_USD;
  } catch {
    return DEFAULT_BUDGET_USD;
  }
}

async function loadPreferredProviders(): Promise<Provider[] | null> {
  try {
    const raw = await readFile(POLICY_FILE(), "utf-8");
    const policy = JSON.parse(raw) as SecurityPolicy;
    return policy.model_budget?.preferred_providers ?? null;
  } catch {
    return null;
  }
}

async function loadAdvancedTaskPreferences(): Promise<TaskType[]> {
  try {
    const raw = await readFile(POLICY_FILE(), "utf-8");
    const policy = JSON.parse(raw) as SecurityPolicy;
    return policy.model_budget?.advanced_task_preference ?? [];
  } catch {
    return [];
  }
}

/** Opt-out list: task types forced down to standard tier. Never crashes on missing files. */
async function loadForceStandardTierFor(): Promise<TaskType[]> {
  try {
    const raw = await readFile(POLICY_FILE(), "utf-8");
    const policy = JSON.parse(raw) as SecurityPolicy;
    return policy.model_budget?.force_standard_tier_for ?? [];
  } catch {
    return [];
  }
}

/** Budget safety-valve threshold (percent). Never crashes on missing files. */
async function loadDowngradeThresholdPct(): Promise<number> {
  try {
    const raw = await readFile(POLICY_FILE(), "utf-8");
    const policy = JSON.parse(raw) as SecurityPolicy;
    const pct = policy.model_budget?.downgrade_threshold_pct;
    return typeof pct === "number" && pct >= 0 && pct <= 100 ? pct : DEFAULT_DOWNGRADE_THRESHOLD_PCT;
  } catch {
    return DEFAULT_DOWNGRADE_THRESHOLD_PCT;
  }
}

// ---------------------------------------------------------------------------
// Circuit breaker helpers
// ---------------------------------------------------------------------------

function isCircuitOpen(
  state: ProviderHealthStore["providers"][string] | undefined
): boolean {
  if (!state) return false;
  if (!state.circuitOpenUntil) return false;
  return new Date(state.circuitOpenUntil) > new Date();
}

function capabilityTierRank(tier: CapabilityTier): number {
  return { light: 0, standard: 1, advanced: 2 }[tier];
}

function meetsCapabilityFloor(model: ProviderModel, required: CapabilityTier): boolean {
  return capabilityTierRank(model.capabilityTier) >= capabilityTierRank(required);
}

function combinedCost(model: ProviderModel): number {
  // Weighted: input 80%, output 20% — typical for security scan workloads.
  return model.inputPer1M * 0.8 + model.outputPer1M * 0.2;
}

/**
 * Capability/power ranking used to pick the MOST capable model within the advanced
 * tier for security-critical reasoning. This is the core of the "fullest power"
 * mandate: for advanced tasks we optimise for capability first and treat cost only
 * as a tiebreak, so flagship security reasoning is never silently downgraded to a
 * cheaper-but-weaker advanced model (e.g. a small "flash" reasoning model) just
 * because it prices lower. Higher = more capable.
 */
const MODEL_POWER_RANK: Record<string, number> = {
  "claude-opus-4-8": 100,
  o1: 92,
  "claude-sonnet-5": 78,
  "gpt-4o": 70,
  "gemini-2.0-flash-thinking-exp": 62
};

function powerRank(model: ProviderModel): number {
  if (model.modelId in MODEL_POWER_RANK) return MODEL_POWER_RANK[model.modelId];
  // Unknown model: rank by tier so advanced > standard > light, with a small
  // Anthropic bias to prefer the security-tuned frontier family on ties.
  const tierBase = { light: 10, standard: 40, advanced: 80 }[model.capabilityTier];
  return tierBase + (model.provider === "anthropic" ? 5 : 0);
}

/**
 * Order advanced-tier candidates for maximum capability: highest power rank first,
 * cheapest as the tiebreak among equally capable models.
 */
function byPowerThenCost(a: ProviderModel, b: ProviderModel): number {
  const dp = powerRank(b) - powerRank(a);
  return dp !== 0 ? dp : combinedCost(a) - combinedCost(b);
}

function legacyTier(capTier: CapabilityTier): ModelTier {
  return capTier === "light" ? "haiku" : "sonnet";
}

// ---------------------------------------------------------------------------
// Core routing function
// ---------------------------------------------------------------------------

/**
 * Select the cheapest healthy model that meets the capability requirement for
 * the given task type. Respects preferred_providers policy and circuit breakers.
 *
 * @param requiredTier    Minimum capability tier for the task.
 * @param health          Current provider health store.
 * @param preferred       Optional ordered list of preferred providers.
 * @param preferAdvanced  If true, try advanced-tier models first, fall back to standard.
 * @param taskType        Task type — used only for the degradation audit log.
 * @returns               [chosen model, failoverUsed]
 */
function selectModel(
  requiredTier: CapabilityTier,
  health: ProviderHealthStore,
  preferred: Provider[] | null,
  preferAdvanced = false,
  taskType?: TaskType
): [ProviderModel, boolean] {
  // If advanced is preferred, try advanced-tier models first. Fall back gracefully to
  // standard if none are healthy or registered rather than failing the routing call.
  if (preferAdvanced) {
    const advancedCandidates = MODEL_REGISTRY.filter((m) => m.capabilityTier === "advanced");
    const healthyAdvanced = advancedCandidates.filter(
      (m) => !isCircuitOpen(health.providers[m.provider])
    );
    if (healthyAdvanced.length > 0) {
      // FULLEST POWER: within the advanced tier, choose the most capable model
      // (Opus 4.8 first), not the cheapest. Preferred providers still win ties.
      const pool = preferred
        ? [
            ...healthyAdvanced.filter((m) => preferred.includes(m.provider)).sort(byPowerThenCost),
            ...healthyAdvanced.filter((m) => !preferred.includes(m.provider)).sort(byPowerThenCost)
          ]
        : [...healthyAdvanced].sort(byPowerThenCost);
      if (pool.length > 0) return [pool[0], false];
    }
    // No advanced model available/healthy — degrade gracefully to standard and emit a
    // structured audit line so operators can see when full power was unavailable.
    console.warn(JSON.stringify({
      event: "MODEL_ADVANCED_UNAVAILABLE",
      timestamp: new Date().toISOString(),
      taskType: taskType ?? null,
      reason: advancedCandidates.length === 0
        ? "NO_ADVANCED_MODEL_REGISTERED"
        : "ALL_ADVANCED_PROVIDERS_CIRCUIT_OPEN",
      degradedTo: "standard",
      severity: "MEDIUM"
    }));
  }

  // Candidates: all models meeting the capability floor.
  const candidates = MODEL_REGISTRY.filter((m) => meetsCapabilityFloor(m, requiredTier));

  // Separate healthy vs. circuit-open providers.
  const healthy = candidates.filter((m) => !isCircuitOpen(health.providers[m.provider]));
  const pool = healthy.length > 0 ? healthy : candidates; // fallback: ignore circuit if all unhealthy
  const failoverUsed = healthy.length > 0 && healthy.length < candidates.length;

  // Apply preferred provider ordering if set in policy.
  let sorted: ProviderModel[];
  if (preferred && preferred.length > 0) {
    // Among preferred providers first, then others; within each group sort by cost.
    const preferredPool = pool.filter((m) => preferred.includes(m.provider));
    const otherPool = pool.filter((m) => !preferred.includes(m.provider));
    preferredPool.sort((a, b) => combinedCost(a) - combinedCost(b));
    otherPool.sort((a, b) => combinedCost(a) - combinedCost(b));
    sorted = [...preferredPool, ...otherPool];
  } else {
    // Default: pure cost-based sort (cheapest first).
    sorted = [...pool].sort((a, b) => combinedCost(a) - combinedCost(b));
  }

  // Should always have at least one candidate given the registry.
  const chosen = sorted[0] ?? MODEL_REGISTRY.find((m) => m.provider === "anthropic" && m.capabilityTier === "standard")!;
  return [chosen, failoverUsed];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Return the recommended model for a given task type using multi-provider smart routing.
 * Selects the cheapest healthy provider model meeting the capability requirement.
 * Falls back to next-cheapest provider on circuit breaker open.
 */
export async function getModelForTask(taskType: TaskType, _opts?: {
  agentName?: string;
  agentRunId?: string;
}): Promise<ModelAssignment> {
  const [store, health, maxBudget, preferred, advancedPrefs, forceStandardFor, downgradeThresholdPct] = await Promise.all([
    loadUsageStore(),
    loadHealthStore(),
    loadMaxBudget(),
    loadPreferredProviders(),
    loadAdvancedTaskPreferences(),
    loadForceStandardTierFor(),
    loadDowngradeThresholdPct()
  ]);

  // Base tier from the max-power-by-default map.
  let requiredTier = TASK_CAPABILITY_MAP[taskType];

  const spent = store.totalSpentUsd;
  const remaining = maxBudget - spent;
  const utilizationPct = maxBudget > 0 ? (spent / maxBudget) * 100 : 0;

  // ── MAX-POWER-BY-DEFAULT posture ─────────────────────────────────────────
  // Advanced-tier tasks prefer advanced automatically. The legacy opt-IN list is
  // still honored (union) but never reduces power. This is the DEFAULT for an
  // empty policy.
  const isProtected = PROTECTED_MAX_POWER_TASKS.has(taskType);
  const baseIsAdvanced = requiredTier === "advanced";

  // ── OPT-OUT downgrade ────────────────────────────────────────────────────
  // A task explicitly listed in force_standard_tier_for is dropped to standard —
  // unless it is in the protected set, which always runs at full power.
  let downgradeReason: "policy_opt_out" | "budget_valve" | null = null;
  if (baseIsAdvanced && !isProtected && forceStandardFor.includes(taskType)) {
    requiredTier = "standard";
    downgradeReason = "policy_opt_out";
  }

  // ── BUDGET SAFETY VALVE ──────────────────────────────────────────────────
  // When spend utilization reaches the configured threshold, non-critical advanced
  // tasks are downgraded to standard to preserve the remaining budget. The protected
  // set is NEVER downgraded — those agents always run at full power.
  const budgetValveTripped =
    requiredTier === "advanced" &&
    !isProtected &&
    maxBudget > 0 &&
    utilizationPct >= downgradeThresholdPct;
  if (budgetValveTripped) {
    requiredTier = "standard";
    downgradeReason = "budget_valve";
    console.warn(JSON.stringify({
      event: "MODEL_BUDGET_DOWNGRADE",
      timestamp: new Date().toISOString(),
      taskType,
      utilizationPct: Math.round(utilizationPct),
      remainingUsd: Math.round(Math.max(0, remaining) * 10000) / 10000,
      thresholdPct: downgradeThresholdPct,
      degradedTo: "standard",
      severity: "MEDIUM"
    }));
  }

  // preferAdvanced is true whenever the (possibly-downgraded) required tier is still
  // advanced, or the legacy opt-in list names this task. Protected tasks are always
  // advanced. This keeps full power on by default.
  const preferAdvanced =
    requiredTier === "advanced" || isProtected || advancedPrefs.includes(taskType);
  if (isProtected) requiredTier = "advanced"; // protected tasks can never be dropped below advanced

  const [chosen, failoverUsed] = selectModel(requiredTier, health, preferred, preferAdvanced, taskType);

  let budgetStatus: "ok" | "warning" | "exceeded";
  if (remaining <= 0) {
    budgetStatus = "exceeded";
  } else if (utilizationPct >= 80) {
    budgetStatus = "warning";
  } else {
    budgetStatus = "ok";
  }
  void downgradeReason; // retained for future telemetry; downgrade already logged above

  const rationale = buildRationale(taskType, requiredTier, chosen, failoverUsed, preferred);

  // Determine whether all providers were circuit-open (best-effort fallback path).
  const allProviders: Provider[] = ["anthropic", "openai", "google", "cohere", "local"];
  const allCircuitsOpen = allProviders.every((p) => isCircuitOpen(health.providers[p]));

  // ISO 42001 §9.1 — emit structured audit log for every routing decision.
  let routingReason: "circuit_open_fallback" | "capability_match" | "max_power_advanced" | "cost_optimized";
  if (allCircuitsOpen) {
    routingReason = "circuit_open_fallback";
  } else if (failoverUsed) {
    routingReason = "capability_match";
  } else if (chosen.capabilityTier === "advanced") {
    // Advanced tasks are selected capability-first (Opus 4.8 preferred), not by cost.
    routingReason = "max_power_advanced";
  } else {
    routingReason = "cost_optimized";
  }
  console.log(JSON.stringify({
    event: "MODEL_ROUTING_DECISION",
    timestamp: new Date().toISOString(),
    taskType,
    selectedModel: chosen.modelId,
    selectedProvider: chosen.provider,
    reason: routingReason,
    circuitState: allCircuitsOpen ? "FALLBACK" : "NORMAL",
  }));

  // Additional high-severity audit entry for the circuit-breaker fallback path.
  if (allCircuitsOpen) {
    console.warn(JSON.stringify({
      event: "MODEL_ROUTING_CIRCUIT_FALLBACK",
      timestamp: new Date().toISOString(),
      reason: "ALL_PROVIDERS_CIRCUIT_OPEN",
      fallbackModel: chosen.modelId,
      severity: "HIGH",
    }));
  }

  return {
    model: chosen.modelId,
    provider: chosen.provider,
    tier: legacyTier(chosen.capabilityTier),
    capabilityTier: chosen.capabilityTier,
    taskType,
    rationale,
    estimatedInputCostPer1MTokens: chosen.inputPer1M,
    estimatedOutputCostPer1MTokens: chosen.outputPer1M,
    budgetStatus,
    remainingBudgetUsd: maxBudget > 0 ? Math.max(0, remaining) : null,
    failoverUsed,
    ...(chosen.baseUrl ? { baseUrl: chosen.baseUrl } : {})
  };
}

function buildRationale(
  taskType: TaskType,
  required: CapabilityTier,
  chosen: ProviderModel,
  failoverUsed: boolean,
  preferred: Provider[] | null
): string {
  const costNote = chosen.inputPer1M === 0
    ? "free (local)"
    : `$${chosen.inputPer1M}/$${chosen.outputPer1M} per 1M in/out`;
  const prefNote = preferred ? ` (preferred: ${preferred.join(", ")})` : "";
  const failNote = failoverUsed ? " [failover — primary provider circuit open]" : "";
  return (
    `Task "${taskType}" requires "${required}" tier${prefNote}. ` +
    `Selected ${chosen.label} (${chosen.provider}): ${costNote}, cheapest healthy match.${failNote}`
  );
}

/**
 * Record actual token usage after a model call completes.
 * Updates the running total and per-provider spend breakdown.
 * Resets circuit breaker failure count for successful provider calls.
 */
export async function trackUsage(usage: UsageInput & { actualCostUsd?: number }): Promise<void> {
  const [store, health] = await Promise.all([loadUsageStore(), loadHealthStore()]);

  const model = MODEL_REGISTRY.find((m) => m.modelId === usage.model);
  const inputRate = model?.inputPer1M ?? (usage.tier === "haiku" ? 0.25 : 3);
  const outputRate = model?.outputPer1M ?? (usage.tier === "haiku" ? 1.25 : 15);

  const estimatedCost =
    (usage.inputTokens / 1_000_000) * inputRate +
    (usage.outputTokens / 1_000_000) * outputRate;

  // A cost the CLI actually reported beats one derived from registry prices keyed on
  // model IDs that no local CLI accepts. Without this, real spend data is discarded.
  const reportedBy: "cli" | "estimate" = usage.actualCostUsd !== undefined ? "cli" : "estimate";
  const record: UsageRecord = {
    ...usage,
    estimatedCostUsd: usage.actualCostUsd ?? usage.estimatedCostUsd ?? estimatedCost,
    reportedBy,
    timestamp: new Date().toISOString()
  };

  store.records.push(record);
  store.totalSpentUsd = store.records.reduce((sum, r) => sum + r.estimatedCostUsd, 0);

  if (store.records.length > 500) {
    store.records = store.records.slice(-500);
  }

  // Successful call: reset consecutive failures for this provider.
  const providerKey = usage.provider ?? "anthropic";
  const providerState = health.providers[providerKey] ?? {
    consecutiveFailures: 0,
    lastFailureAt: null,
    circuitOpenUntil: null,
    totalCallsTracked: 0
  };
  providerState.consecutiveFailures = 0;
  providerState.circuitOpenUntil = null;
  providerState.totalCallsTracked = (providerState.totalCallsTracked ?? 0) + 1;
  health.providers[providerKey] = providerState;

  await Promise.all([saveUsageStore(store), saveHealthStore(health)]);
}

/**
 * Record a provider failure (connection error, rate limit, auth failure).
 * Opens circuit breaker after CIRCUIT_BREAKER_THRESHOLD consecutive failures.
 * Rate-limited to prevent deliberate circuit-breaker manipulation (max 5 per provider per 5 min).
 */
export async function recordProviderFailure(provider: Provider): Promise<{ recorded: boolean; reason?: string }> {
  const rateCheck = recordProviderFailureRateLimited(provider);
  if (!rateCheck.allowed) {
    return { recorded: false, reason: rateCheck.reason };
  }

  const health = await loadHealthStore();
  const now = new Date();

  const state = health.providers[provider] ?? {
    consecutiveFailures: 0,
    lastFailureAt: null,
    circuitOpenUntil: null,
    totalCallsTracked: 0
  };

  state.consecutiveFailures += 1;
  state.lastFailureAt = now.toISOString();

  if (state.consecutiveFailures >= CIRCUIT_BREAKER_THRESHOLD) {
    const openUntil = new Date(now.getTime() + CIRCUIT_BREAKER_COOLDOWN_MS);
    state.circuitOpenUntil = openUntil.toISOString();
  }

  health.providers[provider] = state;
  await saveHealthStore(health);

  // Circuit-state audit: warn and emit structured audit record if all known providers are circuit-open.
  // Deliberate manipulation requires only CIRCUIT_BREAKER_THRESHOLD (3) failures per provider × 5 providers
  // = 15 calls, constrained to max 5 per provider per 5-min window. Log at ERROR level so SIEM picks this up.
  // MITRE ATLAS AML.T0040 (ML Model Inference API) — circuit-breaker exhaustion attack.
  const allProviders: Provider[] = ["anthropic", "openai", "google", "cohere", "local"];
  const allProvidersDown = allProviders.every((p) => isCircuitOpen(health.providers[p]));
  if (allProvidersDown) {
    // Determine which fallback model will be used (cheapest in registry, circuit ignored).
    const fallbackCandidates = MODEL_REGISTRY.filter((m) => m.provider === "anthropic" && m.capabilityTier === "standard");
    const fallbackModel = fallbackCandidates[0]?.modelId ?? "unknown";
    console.error(
      JSON.stringify({
        severity: "CRITICAL",
        event: "ALL_PROVIDERS_CIRCUIT_OPEN",
        message: "All AI providers are circuit-open. Routing to fallback model. This may indicate deliberate circuit-breaker manipulation.",
        fallbackModel,
        timestamp: new Date().toISOString(),
        failingProvider: provider,
        mitre: "AML.T0040",
        action: "Manual investigation required. Call security.reset_provider_circuit after confirming provider health."
      })
    );
  }

  return { recorded: true };
}

/**
 * Return health status for all providers — circuit breaker state and call counts.
 */
export async function getProviderHealth(): Promise<ProviderHealth[]> {
  const [health, usageStore] = await Promise.all([loadHealthStore(), loadUsageStore()]);

  const providers: Provider[] = ["anthropic", "openai", "google", "cohere", "local"];

  return providers.map((p) => {
    const state = health.providers[p];
    const circuitOpen = isCircuitOpen(state);
    const calls = usageStore.records.filter((r) => r.provider === p).length;
    return {
      provider: p,
      healthy: !circuitOpen,
      consecutiveFailures: state?.consecutiveFailures ?? 0,
      lastFailureAt: state?.lastFailureAt ?? null,
      circuitOpenUntil: state?.circuitOpenUntil ?? null,
      totalCallsTracked: state?.totalCallsTracked ?? calls
    };
  });
}

/**
 * Manually reset (close) the circuit breaker for a provider.
 */
export async function resetProviderCircuit(provider: Provider): Promise<void> {
  const health = await loadHealthStore();
  if (health.providers[provider]) {
    health.providers[provider].consecutiveFailures = 0;
    health.providers[provider].circuitOpenUntil = null;
  }
  await saveHealthStore(health);
}

/**
 * Return a full budget status report, including per-provider breakdown.
 */
export async function getBudgetStatus(): Promise<BudgetStatus> {
  const store = await loadUsageStore();
  const maxBudget = await loadMaxBudget();

  const spent = store.totalSpentUsd;
  const remaining = Math.max(0, maxBudget - spent);
  const utilizationPct = maxBudget > 0 ? Math.round((spent / maxBudget) * 100) : 0;

  let status: "ok" | "warning" | "exceeded";
  if (remaining <= 0) {
    status = "exceeded";
  } else if (utilizationPct >= 80) {
    status = "warning";
  } else {
    status = "ok";
  }

  const haikuCalls = store.records.filter((r) => r.tier === "haiku").length;
  const sonnetCalls = store.records.filter((r) => r.tier === "sonnet").length;

  const breakdownByTaskType: Record<string, { calls: number; estimatedCostUsd: number }> = {};
  const breakdownByProvider: Record<string, { calls: number; estimatedCostUsd: number }> = {};

  for (const record of store.records) {
    // By task type
    const byTask = breakdownByTaskType[record.taskType] ?? { calls: 0, estimatedCostUsd: 0 };
    byTask.calls += 1;
    byTask.estimatedCostUsd += record.estimatedCostUsd;
    breakdownByTaskType[record.taskType] = byTask;

    // By provider
    const provKey = record.provider ?? "anthropic";
    const byProv = breakdownByProvider[provKey] ?? { calls: 0, estimatedCostUsd: 0 };
    byProv.calls += 1;
    byProv.estimatedCostUsd += record.estimatedCostUsd;
    breakdownByProvider[provKey] = byProv;
  }

  for (const key of Object.keys(breakdownByTaskType)) {
    breakdownByTaskType[key].estimatedCostUsd =
      Math.round(breakdownByTaskType[key].estimatedCostUsd * 10000) / 10000;
  }
  for (const key of Object.keys(breakdownByProvider)) {
    breakdownByProvider[key].estimatedCostUsd =
      Math.round(breakdownByProvider[key].estimatedCostUsd * 10000) / 10000;
  }

  return {
    maxBudgetUsd: maxBudget,
    spentUsd: Math.round(spent * 10000) / 10000,
    remainingUsd: Math.round(remaining * 10000) / 10000,
    utilizationPct,
    status,
    haikuCalls,
    sonnetCalls,
    totalCalls: store.records.length,
    breakdownByTaskType,
    breakdownByProvider,
    recentUsage: store.records.slice(-10)
  };
}

// ---------------------------------------------------------------------------
// Zod schemas for MCP tool params
// ---------------------------------------------------------------------------

const TASK_TYPE_VALUES = [
  "pattern_match", "manifest_scan", "evidence_collection", "lockfile_parse",
  "dlp_scan", "config_read", "dependency_scan", "secret_scan",
  "code_review", "remediation", "threat_model", "compliance_analysis",
  "exploit_chain", "ai_redteam", "pentest", "crypto_analysis",
  "auth_analysis", "incident_response", "risk_scoring", "report_generation"
] as [TaskType, ...TaskType[]];

export const GetModelForTaskParams = {
  taskType: z
    .enum(TASK_TYPE_VALUES)
    .describe(
      "Task type to route. Max-power-by-default: security-critical reasoning tasks " +
      "(remediation, threat_model, exploit_chain, ai_redteam, pentest, crypto_analysis, " +
      "auth_analysis, code_review, etc.) route to the advanced tier automatically. " +
      "Read-only/pattern tasks → cheapest light-tier model. Report generation → standard. " +
      "Within a tier, routing picks the cheapest healthy provider meeting the floor. " +
      "The budget safety valve may downgrade NON-protected advanced tasks to standard when " +
      "spend crosses the threshold."
    ),
  agentName: z.string().min(1).max(128).optional().describe("Optional agent name for usage tracking."),
  agentRunId: z.string().optional().describe("Optional agent run ID for correlating usage to a run.")
};
export const GetModelForTaskSchema = z.object(GetModelForTaskParams);

export const TrackUsageParams = {
  taskType: z.enum(TASK_TYPE_VALUES).describe("Task type that was executed."),
  model: z.string().describe("Model ID used (e.g. claude-opus-4-8, claude-sonnet-5, gpt-4o, gemini-1.5-pro)."),
  provider: z
    .enum(["anthropic", "openai", "google", "cohere", "local"] as [Provider, ...Provider[]])
    .describe("Provider that handled the call."),
  tier: z.enum(["haiku", "sonnet"]).describe("Legacy model tier label (haiku=light, sonnet=standard)."),
  inputTokens: z.number().int().min(0).describe("Input tokens consumed."),
  outputTokens: z.number().int().min(0).describe("Output tokens produced."),
  agentName: z.string().optional().describe("Agent that made the call."),
  agentRunId: z.string().optional().describe("Agent run ID for correlation.")
};
export const TrackUsageSchema = z.object(TrackUsageParams);

export const RecordProviderFailureParams = {
  provider: z
    .enum(["anthropic", "openai", "google", "cohere", "local"] as [Provider, ...Provider[]])
    .describe("Provider that failed. Increments consecutive failure count; opens circuit after 3 failures.")
};
export const RecordProviderFailureSchema = z.object(RecordProviderFailureParams);

export const ResetProviderCircuitParams = {
  provider: z
    .enum(["anthropic", "openai", "google", "cohere", "local"] as [Provider, ...Provider[]])
    .describe("Provider whose circuit breaker to reset (close).")
};
export const ResetProviderCircuitSchema = z.object(ResetProviderCircuitParams);
