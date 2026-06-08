/**
 * Learning Engine — pattern memory and agent routing.
 *
 * Tracks which agents resolve which finding types most successfully.
 * Routes future findings to the highest-performing agent automatically.
 * Persists to .mcp/memory/patterns.json (per-project, gitignore-safe).
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MEMORY_DIR = join(".mcp", "memory");
const PATTERNS_FILE = join(MEMORY_DIR, "patterns.json");
const PATTERNS_HASH_FILE = join(MEMORY_DIR, "patterns.sha256");
const MIN_SAMPLE_SIZE = 10;      // need ≥10 outcomes before routing is trusted (was 3 — too easy to manipulate)
const HIGH_CONFIDENCE = 0.85;   // route automatically above this success rate
const LOW_CONFIDENCE = 0.40;    // escalate below this success rate

// ---------------------------------------------------------------------------
// Suppression safety caps (OWASP LLM04 / LLM08 — Excessive Agency)
// ---------------------------------------------------------------------------

/**
 * Maximum number of distinct finding IDs that may be simultaneously suppressed
 * via false-positive rate. Prevents an attacker from suppressing ALL finding
 * types by flooding the learning engine with false-positive reports across many IDs.
 * MITRE ATLAS AML.T0043 (Craft Adversarial Data) mitigation.
 */
const MAX_SUPPRESSED_FINDING_TYPES = 5;

/**
 * Maximum cumulative false-positive count any single finding ID may accumulate
 * before further FP submissions are rejected regardless of rate-limit window.
 * Prevents an attacker who controls multiple agents from slowly poisoning a
 * finding type by spreading FP reports across many hourly windows.
 */
const MAX_FP_COUNT_PER_FINDING = 20;

// ---------------------------------------------------------------------------
// Rate limiting — false-positive submissions per finding
// ---------------------------------------------------------------------------

const _falsePositiveSubmissions = new Map<string, { count: number; windowStart: number; cumulative: number }>();
const FP_RATE_LIMIT = 5;      // max 5 false-positive reports per finding per window
const FP_WINDOW_MS = 3_600_000; // 1 hour window

/**
 * Returns true (allowed) only when:
 *   1. The per-hour sliding window has not been exhausted.
 *   2. The cumulative all-time FP count for this finding has not reached MAX_FP_COUNT_PER_FINDING.
 * CWE-799 / OWASP LLM04 (Model Denial of Service via learning system abuse).
 */
function checkFalsePositiveRateLimit(findingId: string): { allowed: boolean; reason?: string } {
  const now = Date.now();
  const entry = _falsePositiveSubmissions.get(findingId);

  if (!entry || now - entry.windowStart > FP_WINDOW_MS) {
    // Check cumulative cap even when opening a new window.
    const cumulative = entry?.cumulative ?? 0;
    if (cumulative >= MAX_FP_COUNT_PER_FINDING) {
      return { allowed: false, reason: `Cumulative false-positive cap reached for finding ${findingId} (max ${MAX_FP_COUNT_PER_FINDING} all-time). Investigate scanner accuracy before submitting more.` };
    }
    _falsePositiveSubmissions.set(findingId, { count: 1, windowStart: now, cumulative: cumulative + 1 });
    return { allowed: true };
  }

  if (entry.cumulative >= MAX_FP_COUNT_PER_FINDING) {
    return { allowed: false, reason: `Cumulative false-positive cap reached for finding ${findingId} (max ${MAX_FP_COUNT_PER_FINDING} all-time). Investigate scanner accuracy before submitting more.` };
  }

  if (entry.count >= FP_RATE_LIMIT) {
    return { allowed: false, reason: `Rate limit exceeded for false-positive submissions on ${findingId}. Max ${FP_RATE_LIMIT} per hour per finding.` };
  }

  entry.count++;
  entry.cumulative++;
  return { allowed: true };
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const OutcomeSchema = z.object({
  findingId: z.string().min(1).max(128).regex(/^[A-Z][A-Z0-9_]{0,127}$/,
    "findingId must be SCREAMING_SNAKE_CASE"),
  agentName: z.string().min(1).max(128),
  resolved: z.boolean(),
  falsePositive: z.boolean().default(false),
  remediationTemplate: z.string().max(512).optional(),
  durationMs: z.number().int().min(0).optional()
});

export type Outcome = z.infer<typeof OutcomeSchema>;

export type PatternRecord = {
  findingId: string;
  bestAgent: string;
  sampleSize: number;
  successRate: number;
  falsePositiveRate: number;
  avgDurationMs: number;
  remediationTemplate: string;
  lastSeen: string;
  agentStats: Record<string, AgentStat>;
};

type AgentStat = {
  attempts: number;
  successes: number;
  falsePositives: number;
  totalDurationMs: number;
  remediationTemplates: string[];
};

type PatternsStore = {
  version: 1;
  updatedAt: string;
  patterns: Record<string, PatternRecord>;
};

export type RoutingDecision = {
  findingId: string;
  recommendation: "route" | "escalate" | "insufficient_data";
  bestAgent: string | null;
  successRate: number | null;
  sampleSize: number;
  reason: string;
};

export type PatternReport = {
  totalPatterns: number;
  highConfidence: number;
  lowConfidence: number;
  insufficientData: number;
  topAgents: { agentName: string; findingsCovered: number; avgSuccessRate: number }[];
  patterns: PatternRecord[];
};

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

async function ensureMemoryDir(): Promise<void> {
  await mkdir(MEMORY_DIR, { recursive: true });
}

async function loadStore(): Promise<PatternsStore> {
  try {
    const raw = await readFile(PATTERNS_FILE, "utf-8");

    // Integrity check: compare SHA-256 of file content against stored sidecar hash.
    // If the sidecar exists and the hash mismatches, the file may have been tampered with.
    try {
      const storedHash = (await readFile(PATTERNS_HASH_FILE, "utf-8")).trim();
      const actualHash = createHash("sha256").update(raw).digest("hex");
      // Use timingSafeEqual to prevent timing-oracle inference of the stored hash (CWE-208).
      const storedBuf = Buffer.from(storedHash, "hex");
      const actualBuf = Buffer.from(actualHash, "hex");
      const hashMatch = storedBuf.length === actualBuf.length && timingSafeEqual(storedBuf, actualBuf);
      if (!hashMatch) {
        console.warn("[security-mcp] Agent memory patterns.json may have been tampered with. Resetting to empty state.");
        return { version: 1, updatedAt: new Date().toISOString(), patterns: {} };
      }
    } catch (hashErr: any) {
      // Sidecar doesn't exist yet (first run after upgrade) — allow and create on next save.
      if (hashErr.code !== "ENOENT") throw hashErr;
    }

    return JSON.parse(raw) as PatternsStore;
  } catch {
    return { version: 1, updatedAt: new Date().toISOString(), patterns: {} };
  }
}

async function saveStore(store: PatternsStore): Promise<void> {
  await ensureMemoryDir();
  store.updatedAt = new Date().toISOString();
  const content = JSON.stringify(store, null, 2) + "\n";
  const hash = createHash("sha256").update(content).digest("hex");

  // Write patterns + sidecar atomically: write to temp files first, then rename
  // both into place. This prevents a TOCTOU window where an attacker could replace
  // patterns.json between the two writes and pass integrity on the next load.
  // CWE-367 (TOCTOU Race Condition) / CAPEC-29.
  const tmpPatterns = PATTERNS_FILE + ".tmp";
  const tmpHash    = PATTERNS_HASH_FILE + ".tmp";
  await writeFile(tmpPatterns, content, { encoding: "utf-8", mode: 0o600 });
  await writeFile(tmpHash, hash + "\n", { encoding: "utf-8", mode: 0o600 });
  await rename(tmpPatterns, PATTERNS_FILE);
  await rename(tmpHash, PATTERNS_HASH_FILE);
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/**
 * Record the outcome of an agent resolving (or failing to resolve) a finding.
 * Called after every agent completes work on a specific finding.
 */
export async function recordOutcome(outcome: Outcome): Promise<{ recorded: boolean; pattern: PatternRecord; warning?: string }> {
  const validated = OutcomeSchema.parse(outcome);

  // Rate-limit false-positive submissions to prevent learning-system abuse (OWASP LLM04 / CWE-799).
  if (validated.falsePositive) {
    const rlCheck = checkFalsePositiveRateLimit(validated.findingId);
    if (!rlCheck.allowed) {
      return {
        recorded: false,
        pattern: {} as PatternRecord,
        warning: rlCheck.reason ?? "Rate limit exceeded for false-positive submissions on this finding."
      };
    }
  }

  const store = await loadStore();

  const existing = store.patterns[validated.findingId] ?? {
    findingId: validated.findingId,
    bestAgent: validated.agentName,
    sampleSize: 0,
    successRate: 0,
    falsePositiveRate: 0,
    avgDurationMs: 0,
    remediationTemplate: "",
    lastSeen: new Date().toISOString(),
    agentStats: {}
  };

  // Update agent-specific stats
  const agentStat: AgentStat = existing.agentStats[validated.agentName] ?? {
    attempts: 0,
    successes: 0,
    falsePositives: 0,
    totalDurationMs: 0,
    remediationTemplates: []
  };

  agentStat.attempts += 1;
  if (validated.resolved && !validated.falsePositive) agentStat.successes += 1;
  if (validated.falsePositive) agentStat.falsePositives += 1;
  if (validated.durationMs) agentStat.totalDurationMs += validated.durationMs;
  if (validated.remediationTemplate && !agentStat.remediationTemplates.includes(validated.remediationTemplate)) {
    agentStat.remediationTemplates.push(validated.remediationTemplate);
  }

  existing.agentStats[validated.agentName] = agentStat;

  // Recompute aggregate stats
  let totalAttempts = 0;
  let totalSuccesses = 0;
  let totalFalsePositives = 0;
  let totalDuration = 0;
  let bestAgentName = validated.agentName;
  let bestRate = 0;

  for (const [name, stat] of Object.entries(existing.agentStats)) {
    totalAttempts += stat.attempts;
    totalSuccesses += stat.successes;
    totalFalsePositives += stat.falsePositives;
    totalDuration += stat.totalDurationMs;

    const rate = stat.attempts > 0 ? stat.successes / stat.attempts : 0;
    if (rate > bestRate || (rate === bestRate && stat.attempts > (existing.agentStats[bestAgentName]?.attempts ?? 0))) {
      bestRate = rate;
      bestAgentName = name;
    }
  }

  // Best remediation template comes from the best agent
  const bestStat = existing.agentStats[bestAgentName];
  const template = bestStat?.remediationTemplates[0] ?? existing.remediationTemplate;

  const updated: PatternRecord = {
    ...existing,
    bestAgent: bestAgentName,
    sampleSize: totalAttempts,
    successRate: totalAttempts > 0 ? totalSuccesses / totalAttempts : 0,
    falsePositiveRate: totalAttempts > 0 ? totalFalsePositives / totalAttempts : 0,
    avgDurationMs: totalAttempts > 0 ? Math.round(totalDuration / totalAttempts) : 0,
    remediationTemplate: template,
    lastSeen: new Date().toISOString(),
    agentStats: existing.agentStats
  };

  // Global suppression cap: count how many distinct finding IDs currently have
  // falsePositiveRate > 0.8 AND sampleSize >= MIN_SAMPLE_SIZE (i.e., are "suppressed").
  // If this update would push us over MAX_SUPPRESSED_FINDING_TYPES, reject it.
  // Prevents an attacker from suppressing ALL finding types simultaneously
  // (OWASP LLM08 — Excessive Agency / MITRE ATLAS AML.T0043).
  if (validated.falsePositive && updated.falsePositiveRate > 0.8 && updated.sampleSize >= MIN_SAMPLE_SIZE) {
    const suppressedCount = Object.values(store.patterns).filter(
      (p) => p.findingId !== validated.findingId && p.falsePositiveRate > 0.8 && p.sampleSize >= MIN_SAMPLE_SIZE
    ).length;
    if (suppressedCount >= MAX_SUPPRESSED_FINDING_TYPES) {
      console.error(`[security-mcp] SECURITY_ALERT: Global suppression cap reached. ${suppressedCount} finding types already suppressed. Rejecting FP update for ${validated.findingId}. Possible learning-system attack.`);
      return {
        recorded: false,
        pattern: updated,
        warning: `GLOBAL_SUPPRESSION_CAP_EXCEEDED: ${suppressedCount} finding types are already suppressed (max ${MAX_SUPPRESSED_FINDING_TYPES}). Investigate potential learning-system manipulation before submitting more false-positives.`
      };
    }
  }

  store.patterns[validated.findingId] = updated;
  await saveStore(store);

  // Anomaly detection: flag unusually high false-positive rate for this finding.
  let warning: string | undefined;
  if (updated.sampleSize > MIN_SAMPLE_SIZE && updated.falsePositiveRate > 0.8) {
    warning = `LEARNING_ANOMALY_HIGH_FP_RATE: Finding ${validated.findingId} has a false-positive rate of ${Math.round(updated.falsePositiveRate * 100)}% across ${updated.sampleSize} samples. Investigate scanner accuracy.`;
    console.warn(`[security-mcp] ${warning}`);
  }

  return { recorded: true, pattern: updated, ...(warning ? { warning } : {}) };
}

/**
 * Get the routing recommendation for a finding type.
 * Returns which agent to use, or signals escalation if confidence is low.
 */
export async function getRouting(findingId: string): Promise<RoutingDecision> {
  if (!findingId || !/^[A-Z][A-Z0-9_]{0,127}$/.test(findingId)) {
    return {
      findingId,
      recommendation: "insufficient_data",
      bestAgent: null,
      successRate: null,
      sampleSize: 0,
      reason: "Invalid findingId format — no routing data available."
    };
  }

  const store = await loadStore();
  const pattern = store.patterns[findingId];

  if (!pattern || pattern.sampleSize < MIN_SAMPLE_SIZE) {
    return {
      findingId,
      recommendation: "insufficient_data",
      bestAgent: null,
      successRate: null,
      sampleSize: pattern?.sampleSize ?? 0,
      reason: `Fewer than ${MIN_SAMPLE_SIZE} outcomes recorded — using standard agent selection.`
    };
  }

  if (pattern.successRate >= HIGH_CONFIDENCE) {
    return {
      findingId,
      recommendation: "route",
      bestAgent: pattern.bestAgent,
      successRate: pattern.successRate,
      sampleSize: pattern.sampleSize,
      reason: `${Math.round(pattern.successRate * 100)}% success rate across ${pattern.sampleSize} runs — routing to ${pattern.bestAgent}.`
    };
  }

  if (pattern.successRate < LOW_CONFIDENCE) {
    return {
      findingId,
      recommendation: "escalate",
      bestAgent: pattern.bestAgent,
      successRate: pattern.successRate,
      sampleSize: pattern.sampleSize,
      reason: `Low success rate (${Math.round(pattern.successRate * 100)}%) — escalate to senior-security-engineer or manual review.`
    };
  }

  return {
    findingId,
    recommendation: "route",
    bestAgent: pattern.bestAgent,
    successRate: pattern.successRate,
    sampleSize: pattern.sampleSize,
    reason: `Moderate confidence (${Math.round(pattern.successRate * 100)}%) — routing to ${pattern.bestAgent} with monitoring.`
  };
}

/**
 * Generate a full report of learned patterns and agent performance.
 */
export async function getPatternReport(): Promise<PatternReport> {
  const store = await loadStore();
  const patterns = Object.values(store.patterns);

  const agentMap = new Map<string, { count: number; totalRate: number }>();

  for (const p of patterns) {
    const existing = agentMap.get(p.bestAgent) ?? { count: 0, totalRate: 0 };
    agentMap.set(p.bestAgent, {
      count: existing.count + 1,
      totalRate: existing.totalRate + p.successRate
    });
  }

  const topAgents = Array.from(agentMap.entries())
    .map(([agentName, stats]) => ({
      agentName,
      findingsCovered: stats.count,
      avgSuccessRate: stats.count > 0 ? stats.totalRate / stats.count : 0
    }))
    .sort((a, b) => b.findingsCovered - a.findingsCovered)
    .slice(0, 10);

  return {
    totalPatterns: patterns.length,
    highConfidence: patterns.filter((p) => p.successRate >= HIGH_CONFIDENCE && p.sampleSize >= MIN_SAMPLE_SIZE).length,
    lowConfidence: patterns.filter((p) => p.successRate < LOW_CONFIDENCE && p.sampleSize >= MIN_SAMPLE_SIZE).length,
    insufficientData: patterns.filter((p) => p.sampleSize < MIN_SAMPLE_SIZE).length,
    topAgents,
    patterns: patterns.sort((a, b) => b.sampleSize - a.sampleSize)
  };
}

// ---------------------------------------------------------------------------
// Zod schemas for MCP tool params
// ---------------------------------------------------------------------------

export const RecordOutcomeParams = {
  findingId: z.string().min(1).max(128).describe("Finding ID in SCREAMING_SNAKE_CASE (e.g. CI_UNPINNED_ACTION)."),
  agentName: z.string().min(1).max(128).describe("Name of the agent that worked on this finding."),
  resolved: z.boolean().describe("True if the finding was successfully remediated."),
  falsePositive: z.boolean().optional().describe("True if this was a false positive. Default false."),
  remediationTemplate: z.string().max(512).optional().describe("One-line description of what was done to fix it."),
  durationMs: z.number().int().min(0).optional().describe("Time taken to resolve in milliseconds.")
};
export const RecordOutcomeSchema = z.object(RecordOutcomeParams);

export const GetRoutingParams = {
  findingId: z.string().min(1).max(128).describe("Finding ID to look up routing recommendation for.")
};
export const GetRoutingSchema = z.object(GetRoutingParams);
