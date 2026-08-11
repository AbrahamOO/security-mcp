/**
 * MCP-facing surface for the agent executor.
 *
 * Kept out of server.ts so the executor stays testable without booting the MCP server.
 */
import { z } from "zod";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getWorkspaceRoot } from "../repo/workspace.js";
import { CONFIG } from "../config.js";
import { TERMINAL_AGENT_STATUSES, type AgentName, type AgentRunManifest } from "../types/agent-run.js";
import { detectProviders, loadAdapterRegistry } from "./adapter.js";
import { buildQueue } from "./queue.js";
import {
  launchSupervisor, readSupervisorState, checkLiveness, reapStaleRuns, reapIfStale, requestCancel
} from "./supervisor.js";

const AGENT_RUN_ID = z.string().regex(/^[0-9a-f]{32}$/, "agentRunId must be a 32-char hex id");

function readManifest(agentRunId: string): AgentRunManifest {
  return JSON.parse(
    readFileSync(join(getWorkspaceRoot(), ".mcp", "agent-runs", agentRunId, "manifest.json"), "utf-8")
  ) as AgentRunManifest;
}

// ---------------------------------------------------------------------------
// executor_status
// ---------------------------------------------------------------------------

export const ExecutorStatusSchema = z.object({
  refresh: z.boolean().default(false).describe("Re-probe binaries instead of using the 1-hour detection cache.")
});

/** Per-agent wall-clock assumptions used for the pre-run estimate. */
const MINUTES_PER_AGENT = { advanced: 9, standard: 5 };

export async function executorStatus(args: z.infer<typeof ExecutorStatusSchema>): Promise<Record<string, unknown>> {
  const blockers: string[] = [];
  if (CONFIG.offline) blockers.push("SECURITY_OFFLINE is set — driving a local CLI makes an outbound model call");
  if (CONFIG.strict) blockers.push("SECURITY_STRICT is set (implies offline)");
  if (Number(process.env["SECURITY_MCP_AGENT_DEPTH"] ?? "0") >= 1) blockers.push("nested execution is refused (SECURITY_MCP_AGENT_DEPTH >= 1)");

  const registry = await loadAdapterRegistry({ force: args.refresh });
  const providers = blockers.length === 0 ? await detectProviders({ force: args.refresh }) : [];
  const usable = providers.filter((p) => p.available);
  if (blockers.length === 0 && usable.length === 0) {
    blockers.push("no authenticated local LLM CLI was detected");
  }

  const totalConcurrency = usable.reduce((n, p) => n + p.maxConcurrent, 0);
  const anyDegraded = usable.some((p) => p.degraded.length > 0);
  const allClassB = usable.length > 0 && usable.every((p) => p.class === "B");

  // A run that will fail the capability floor should be knowable BEFORE committing
  // hours to it, not discovered from the gate result afterwards.
  const willGatePass = allClassB
    ? "no — Class B execution reports capabilityTierUsed=light, below the advanced floor every protected task requires. There is no override: install an agentic CLI (claude, codex, or copilot) to clear the floor."
    : usable.length === 0 ? "no — nothing can execute"
      : "possible — depends on findings";

  const quality = usable.length === 0 ? "NONE — no usable provider"
    : allClassB ? "LOW — single completion over a completion-only CLI, with no tools and no file access. Useful for smoke-testing the pipeline; not a competent security review."
      : anyDegraded ? "GOOD — agentic CLI with file tools; some capabilities degraded (see per-provider 'degraded')."
        : "FULL — agentic CLI with file tools, tiered models, and sandboxed execution.";

  return {
    ready: blockers.length === 0 && usable.length > 0,
    blockers,
    offline: CONFIG.offline,
    strict: CONFIG.strict,
    configSource: process.env["SECURITY_AGENT_CLIS"] ?? ".mcp/agent-clis/agent-clis.json | defaults/agent-clis.json",
    registryVersion: registry.version,
    providers: providers.map((p) => ({
      id: p.id, label: p.label, class: p.class, available: p.available,
      binaryPath: p.binaryPath, version: p.version,
      auth: { ok: p.auth.ok, mode: p.auth.mode, presumed: p.auth.presumed, ...p.auth.detail, ...(p.auth.reason ? { reason: p.auth.reason } : {}) },
      maxConcurrent: p.maxConcurrent,
      degraded: p.degraded,
      // Surfaced verbatim so a reviewer never has to guess which adapter fields were
      // actually measured against a real binary and which are best-effort guesses.
      unverifiedAdapterFields: p.unverifiedFields,
      notes: p.notes
    })),
    effectiveConcurrency: totalConcurrency,
    expectedQuality: quality,
    willGatePass,
    // Concrete numbers for the two roster sizes that matter, so the time cost is known
    // before starting rather than discovered an hour in.
    estimatedWallClock: {
      fullRoster84: estimateRun(84, totalConcurrency),
      typicalRoster26: estimateRun(26, totalConcurrency)
    },
    costNote: usable.some((p) => p.auth.detail["subscriptionType"])
      ? "Costs are drawn from your existing subscription quota. Any dollar figure reported per agent is API-equivalent, not money charged."
      : "Cost depends on the plan backing each CLI."
  };
}

/** Wall-clock estimate for a roster, given the concurrency actually available. */
export function estimateRun(agentCount: number, concurrency: number): {
  minutesLow: number; minutesHigh: number; note: string;
} {
  const c = Math.max(1, concurrency);
  const low = Math.round((agentCount / c) * MINUTES_PER_AGENT.standard);
  const high = Math.round((agentCount / c) * MINUTES_PER_AGENT.advanced);
  return {
    minutesLow: low, minutesHigh: high,
    note: `${agentCount} agents at ~${MINUTES_PER_AGENT.standard}-${MINUTES_PER_AGENT.advanced} min each, ` +
      `${c} concurrent across all providers. Phase barriers and throttling add to this.`
  };
}

// ---------------------------------------------------------------------------
// start / progress / cancel / assert
// ---------------------------------------------------------------------------

export const StartAgentRunSchema = z.object({
  agentRunId: AGENT_RUN_ID,
  runId: z.string().uuid(),
  remediationMode: z.enum(["detection_only", "auto_apply"]).default("detection_only"),
  concurrency: z.number().int().min(1).max(16).optional()
});

export async function startAgentRun(args: z.infer<typeof StartAgentRunSchema>): Promise<Record<string, unknown>> {
  reapStaleRuns();
  const result = await launchSupervisor(args);
  const manifest = readManifest(args.agentRunId);
  const roster = Object.keys(manifest.agents) as AgentName[];
  const providers = (await detectProviders()).filter((p) => p.available);
  const concurrency = providers.reduce((n, p) => n + p.maxConcurrent, 0);

  return {
    ...result,
    agentRunId: args.agentRunId,
    providers: providers.map((p) => p.id),
    estimate: estimateRun(result.queue.pending, concurrency),
    next_steps: result.started
      ? [
        "Poll orchestration.get_run_progress until state is done.",
        "Then orchestration.assert_run_complete — it throws while any agent is pending.",
        "Then orchestration.merge_agent_findings, security.run_pr_gate, security.attest_review."
      ]
      : ["Executor did not start. See `reason`. orchestration.executor_status explains what is missing."],
    rosterSize: roster.length
  };
}

export const RunProgressSchema = z.object({ agentRunId: AGENT_RUN_ID });

export function getRunProgress(args: z.infer<typeof RunProgressSchema>): Record<string, unknown> {
  reapIfStale(args.agentRunId);
  const manifest = readManifest(args.agentRunId);
  const state = readSupervisorState(args.agentRunId);
  const live = checkLiveness(state);

  const counts: Record<string, number> = { pending: 0, running: 0, completed: 0, completed_partial: 0, completed_na: 0, failed: 0 };
  for (const rec of Object.values(manifest.agents)) counts[rec.status] = (counts[rec.status] ?? 0) + 1;

  const nodes = buildQueue(Object.keys(manifest.agents) as AgentName[]);
  const total = Object.keys(manifest.agents).length;
  const terminal = Object.values(manifest.agents).filter((r) => TERMINAL_AGENT_STATUSES.includes(r.status)).length;

  return {
    agentRunId: args.agentRunId,
    phase: manifest.phase,
    counts,
    total,
    terminal,
    percentComplete: total > 0 ? Math.round((terminal / total) * 100) : 0,
    supervisor: state
      ? { alive: live.alive, stale: live.stale, reason: live.reason, pid: state.pid, state: state.state, providers: state.providers, heartbeatAt: state.heartbeatAt }
      : null,
    waves: Array.from(new Set(nodes.map((n) => n.wave))).length,
    agents: Object.entries(manifest.agents).map(([name, rec]) => ({
      name, status: rec.status,
      startedAt: rec.startedAt, completedAt: rec.completedAt,
      findingsPath: rec.findingsPath,
      failureCount: rec.failureCount ?? 0,
      escalationRequired: rec.escalationRequired ?? false,
      ...(rec.execution ? {
        provider: rec.execution.adapterId, model: rec.execution.model,
        tier: rec.execution.capabilityTier, durationMs: rec.execution.durationMs,
        degradationReasons: rec.execution.degradationReasons,
        transcriptPaths: rec.execution.transcriptPaths
      } : {}),
      ...(rec.naEvidence ? { naEvidence: rec.naEvidence } : {})
    }))
  };
}

export const CancelRunSchema = z.object({
  agentRunId: AGENT_RUN_ID,
  reason: z.string().max(500).default("cancelled by operator")
});

export function cancelAgentRun(args: z.infer<typeof CancelRunSchema>): Record<string, unknown> {
  requestCancel(args.agentRunId, args.reason);
  const state = readSupervisorState(args.agentRunId);
  return {
    agentRunId: args.agentRunId,
    requested: true,
    supervisorPid: state?.pid ?? null,
    note: "The supervisor checks for cancellation every tick and after every agent completes. " +
      "In-flight agents are given 10s to stop; their records return to pending, not failed."
  };
}

export const AssertCompleteSchema = z.object({
  agentRunId: AGENT_RUN_ID,
  dryRun: z.boolean().default(false).describe("Return the status instead of throwing when incomplete.")
});

/**
 * The explicit completion gate.
 *
 * THROWS while anything is pending or running, so a caller cannot read past it and
 * report a partial run as finished. `completed_na` counts as executed because it
 * carries recorded evidence; `pending` does not.
 */
export function assertRunComplete(args: z.infer<typeof AssertCompleteSchema>): Record<string, unknown> {
  const manifest = readManifest(args.agentRunId);
  const entries = Object.entries(manifest.agents);
  const pending = entries.filter(([, r]) => r.status === "pending").map(([n]) => n);
  const running = entries.filter(([, r]) => r.status === "running").map(([n]) => n);
  const escalated = entries.filter(([, r]) => r.escalationRequired).map(([n]) => n);
  const state = readSupervisorState(args.agentRunId);
  const live = checkLiveness(state);

  const complete = pending.length === 0 && running.length === 0;
  const result = {
    agentRunId: args.agentRunId,
    complete,
    total: entries.length,
    terminal: entries.length - pending.length - running.length,
    pending, running, escalated,
    supervisor: state ? { alive: live.alive, state: state.state, pid: state.pid } : null,
    blocker: complete
      ? null
      : `${pending.length + running.length} agent(s) have not reached a terminal status. This run is NOT reportable.`
  };

  if (!complete && !args.dryRun) {
    throw new Error(
      `Agent run ${args.agentRunId} is incomplete: ${pending.length} pending, ${running.length} running ` +
      `(${[...pending, ...running].slice(0, 8).join(", ")}${pending.length + running.length > 8 ? ", …" : ""}). ` +
      `Run orchestration.start_agent_run and wait for it to finish. Pass dryRun:true to inspect without throwing.`
    );
  }
  return result;
}
