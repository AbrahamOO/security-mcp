/**
 * Learning Engine — pattern memory and agent routing.
 *
 * Tracks which agents resolve which finding types most successfully.
 * Routes future findings to the highest-performing agent automatically.
 * Persists to .mcp/memory/patterns.json (per-project, gitignore-safe).
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MEMORY_DIR = join(".mcp", "memory");
const PATTERNS_FILE = join(MEMORY_DIR, "patterns.json");
const MIN_SAMPLE_SIZE = 3;       // need ≥3 outcomes before routing is trusted
const HIGH_CONFIDENCE = 0.85;   // route automatically above this success rate
const LOW_CONFIDENCE = 0.40;    // escalate below this success rate

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
    return JSON.parse(raw) as PatternsStore;
  } catch {
    return { version: 1, updatedAt: new Date().toISOString(), patterns: {} };
  }
}

async function saveStore(store: PatternsStore): Promise<void> {
  await ensureMemoryDir();
  store.updatedAt = new Date().toISOString();
  await writeFile(PATTERNS_FILE, JSON.stringify(store, null, 2) + "\n", "utf-8");
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/**
 * Record the outcome of an agent resolving (or failing to resolve) a finding.
 * Called after every agent completes work on a specific finding.
 */
export async function recordOutcome(outcome: Outcome): Promise<{ recorded: boolean; pattern: PatternRecord }> {
  const validated = OutcomeSchema.parse(outcome);
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

  store.patterns[validated.findingId] = updated;
  await saveStore(store);

  return { recorded: true, pattern: updated };
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
