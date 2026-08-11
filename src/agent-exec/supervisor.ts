/**
 * Detached run supervisor.
 *
 * Owns the whole roster from first dispatch to completion, across every detected
 * provider concurrently. Runs as its own process so a full sweep survives the MCP
 * session ending, and is safely resumable after a crash.
 *
 * Also runnable as a module entry point: `node dist/agent-exec/supervisor.js --agent-run-id X --workspace Y`.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, unlinkSync, readdirSync, openSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { hostname, uptime } from "node:os";
import { spawn } from "node:child_process";
import { withWorkspace, getWorkspaceRoot } from "../repo/workspace.js";
import { CONFIG } from "../config.js";
import type { AgentName, AgentRunManifest } from "../types/agent-run.js";
import { detectProviders, loadAdapterRegistry, type ProviderStatus } from "./adapter.js";
import { ProviderLimiter } from "./limiter.js";
import { buildQueue, readyAgents, subAgentsOf, buildRepoIndex, prefilterScope, determineNotApplicable, type QueueNode, type RepoIndex } from "./queue.js";
import { buildContextPack } from "./context-pack.js";
import { runAgent, type RemediationMode } from "./executor.js";
import { updateAgentStatus, readAgentMemory } from "../mcp/orchestration.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const HEARTBEAT_INTERVAL_MS = 5000;
const HEARTBEAT_STALE_MS = 30_000;
const TICK_MS = 1000;

// ---------------------------------------------------------------------------
// Supervisor state file
// ---------------------------------------------------------------------------

export type SupervisorState = {
  pid: number;
  token: string;
  startedAt: string;
  heartbeatAt: string;
  hostname: string;
  /** Machine boot time, bucketed. A PID from before the last boot is always dead. */
  bootTime: string;
  providers: string[];
  phase: number;
  running: string[];
  completed: number;
  total: number;
  state: "starting" | "running" | "paused" | "throttled_stalled" | "auth_lost" | "cancelled" | "done" | "orphaned";
  note?: string;
  takeoverRequest?: { token: string; at: string };
  takeoverDenied?: string;
};

export function runDir(agentRunId: string): string {
  return join(getWorkspaceRoot(), ".mcp", "agent-runs", agentRunId);
}
function statePath(agentRunId: string): string { return join(runDir(agentRunId), "supervisor.json"); }
function cancelPath(agentRunId: string): string { return join(runDir(agentRunId), "cancel.request"); }
function manifestPathFor(agentRunId: string): string { return join(runDir(agentRunId), "manifest.json"); }

function bootTimeBucket(): string {
  // Bucketed to 10s so small clock drift does not make the same boot look different.
  return String(Math.floor((Date.now() - uptime() * 1000) / 10_000));
}

export function readSupervisorState(agentRunId: string): SupervisorState | null {
  try {
    return JSON.parse(readFileSync(statePath(agentRunId), "utf-8")) as SupervisorState;
  } catch {
    return null;
  }
}

function writeSupervisorState(agentRunId: string, s: SupervisorState): void {
  const p = statePath(agentRunId);
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  const tmp = `${p}.tmp-${randomBytes(6).toString("hex")}`;
  writeFileSync(tmp, JSON.stringify(s, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, p);
}

function readManifestSync(agentRunId: string): AgentRunManifest {
  return JSON.parse(readFileSync(manifestPathFor(agentRunId), "utf-8")) as AgentRunManifest;
}

function writeManifestSync(m: AgentRunManifest): void {
  const p = manifestPathFor(m.agentRunId);
  m.updatedAt = new Date().toISOString();
  const tmp = `${p}.tmp-${randomBytes(6).toString("hex")}`;
  writeFileSync(tmp, JSON.stringify(m, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, p);
}

// ---------------------------------------------------------------------------
// Liveness
// ---------------------------------------------------------------------------

export type Liveness = { alive: boolean; stale: boolean; reason: string };

/**
 * Is the recorded supervisor still alive?
 *
 * `process.kill(pid, 0)` succeeding does NOT prove liveness, because PIDs are reused.
 * Two extra guards: a boot-time mismatch is conclusive death, and otherwise a fencing
 * handshake (below) distinguishes a live holder from a coincidental PID collision.
 */
export function checkLiveness(s: SupervisorState | null, now = Date.now()): Liveness {
  if (!s) return { alive: false, stale: false, reason: "no supervisor state" };
  if (s.state === "done" || s.state === "cancelled") return { alive: false, stale: false, reason: s.state };

  const age = now - Date.parse(s.heartbeatAt);
  if (age <= HEARTBEAT_STALE_MS) return { alive: true, stale: false, reason: "heartbeat fresh" };

  if (s.bootTime !== bootTimeBucket()) {
    return { alive: false, stale: true, reason: "pid predates last boot" };
  }
  try {
    process.kill(s.pid, 0);
    return { alive: false, stale: true, reason: "pid exists but heartbeat stale (may be PID reuse)" };
  } catch {
    return { alive: false, stale: true, reason: "process gone (ESRCH)" };
  }
}

/**
 * Reclaim a run whose supervisor died.
 *
 * Any `running` agent is reset to `pending` DIRECTLY in the manifest rather than
 * through updateAgentStatus("failed"), which would burn one of MAX_AGENT_RETRIES for a
 * crash the agent had no part in.
 */
export function reapIfStale(agentRunId: string): { reaped: boolean; requeued: string[] } {
  const s = readSupervisorState(agentRunId);
  const live = checkLiveness(s);
  if (!s || live.alive || !live.stale) return { reaped: false, requeued: [] };

  let manifest: AgentRunManifest;
  try { manifest = readManifestSync(agentRunId); } catch { return { reaped: false, requeued: [] }; }

  const requeued: string[] = [];
  for (const [name, rec] of Object.entries(manifest.agents)) {
    if (rec.status === "running") {
      rec.status = "pending";
      rec.startedAt = null;
      requeued.push(name);
    }
  }
  if (requeued.length > 0) writeManifestSync(manifest);
  writeSupervisorState(agentRunId, { ...s, state: "orphaned", note: live.reason, heartbeatAt: new Date().toISOString() });
  console.error(JSON.stringify({
    event: "SUPERVISOR_ORPHAN_REAPED", agentRunId, reason: live.reason, requeued, severity: "MEDIUM"
  }));
  return { reaped: true, requeued };
}

/** Sweep every run directory. Cheap enough to call at the top of any tool handler. */
export function reapStaleRuns(): string[] {
  const base = join(getWorkspaceRoot(), ".mcp", "agent-runs");
  if (!existsSync(base)) return [];
  const reaped: string[] = [];
  try {
    for (const entry of readdirSafe(base)) {
      if (!/^[0-9a-f]{32}$/.test(entry)) continue;
      if (!existsSync(statePath(entry))) continue;
      if (reapIfStale(entry).reaped) reaped.push(entry);
    }
  } catch { /* reaping is best-effort */ }
  return reaped;
}

function readdirSafe(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------

export type LaunchResult = {
  started: boolean;
  supervisorPid: number | null;
  reason?: string;
  queue: { total: number; pending: number; waves: number };
};

/**
 * Spawn the supervisor detached.
 *
 * `detached:true` + `.unref()` + `cleanup:false` is the trio that lets the run outlive
 * the MCP session. stdio goes to a log file rather than "ignore", because a detached
 * process with no output is undiagnosable when it misbehaves.
 */
export async function launchSupervisor(opts: {
  agentRunId: string; runId: string; remediationMode: RemediationMode; concurrencyOverride?: number;
}): Promise<LaunchResult> {
  const { agentRunId } = opts;

  if (CONFIG.offline || CONFIG.strict) {
    return {
      started: false, supervisorPid: null,
      reason: "Refusing to execute agents: SECURITY_OFFLINE/SECURITY_STRICT is set and driving a local CLI necessarily makes an outbound model call.",
      queue: { total: 0, pending: 0, waves: 0 }
    };
  }
  if (Number(process.env["SECURITY_MCP_AGENT_DEPTH"] ?? "0") >= 1) {
    return {
      started: false, supervisorPid: null,
      reason: "Refusing to start a nested agent run (SECURITY_MCP_AGENT_DEPTH >= 1).",
      queue: { total: 0, pending: 0, waves: 0 }
    };
  }

  reapIfStale(agentRunId);
  const existing = readSupervisorState(agentRunId);
  if (existing && checkLiveness(existing).alive) {
    return {
      started: false, supervisorPid: existing.pid,
      reason: "A live supervisor already owns this run.",
      queue: { total: existing.total, pending: existing.total - existing.completed, waves: 0 }
    };
  }

  const manifest = readManifestSync(agentRunId);
  const roster = Object.keys(manifest.agents) as AgentName[];
  const nodes = buildQueue(roster);
  const pending = roster.filter((a) => manifest.agents[a]?.status === "pending").length;

  const supervisorPath = resolve(__dirname, "supervisor.js");
  const logPath = join(runDir(agentRunId), "supervisor.log");
  mkdirSync(dirname(logPath), { recursive: true, mode: 0o700 });
  const outFd = openSync(logPath, "a", 0o600);

  const args = [
    supervisorPath,
    "--agent-run-id", agentRunId,
    "--run-id", opts.runId,
    "--workspace", getWorkspaceRoot(),
    "--remediation-mode", opts.remediationMode
  ];
  if (opts.concurrencyOverride) args.push("--concurrency", String(opts.concurrencyOverride));

  // node:child_process rather than execa here: execa's types reject raw file
  // descriptors in stdio, and detached + unref + real fds is exactly what lets the run
  // outlive the MCP session while staying diagnosable. "ignore" would discard the only
  // record of why a multi-hour run misbehaved.
  const child = spawn(process.execPath, args, {
    detached: true,
    stdio: ["ignore", outFd, outFd],
    env: { ...process.env, SECURITY_MCP_SUPERVISOR: "1", SECURITY_MCP_AGENT_DEPTH: "0" }
  });
  child.unref();

  return {
    started: true,
    supervisorPid: child.pid ?? null,
    queue: { total: roster.length, pending, waves: new Set(nodes.map((n) => n.wave)).size }
  };
}

export function requestCancel(agentRunId: string, reason: string): void {
  mkdirSync(runDir(agentRunId), { recursive: true, mode: 0o700 });
  writeFileSync(cancelPath(agentRunId), JSON.stringify({ requestedAt: new Date().toISOString(), reason }), { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

type ProviderSlot = { provider: ProviderStatus; limiter: ProviderLimiter };

export async function superviseRun(opts: {
  agentRunId: string; runId: string; remediationMode: RemediationMode; concurrencyOverride?: number;
}): Promise<void> {
  const { agentRunId, runId, remediationMode } = opts;
  const token = randomBytes(16).toString("hex");
  const startedAt = new Date().toISOString();

  const registry = await loadAdapterRegistry({ force: true });
  const providers = (await detectProviders({ force: true })).filter((p) => p.available);
  if (providers.length === 0) {
    console.error(JSON.stringify({ event: "SUPERVISOR_NO_PROVIDERS", agentRunId, severity: "HIGH" }));
    return;
  }

  const slots: ProviderSlot[] = providers.map((p) => {
    const cfg = registry.adapters[p.id];
    const maxC = opts.concurrencyOverride ?? cfg?.limits.maxConcurrent ?? 2;
    return { provider: p, limiter: new ProviderLimiter(p.id, maxC, cfg?.rateLimit.backoff ?? { baseMs: 30000, maxMs: 900000, factor: 2, jitter: 0.25 }) };
  });

  let manifest = readManifestSync(agentRunId);
  const roster = Object.keys(manifest.agents) as AgentName[];
  const nodes: QueueNode[] = buildQueue(roster);

  // Acquire the lock, then reclaim anything a previous supervisor left mid-flight. No
  // live child can exist for this run once we hold the lock, so `running` is stale.
  for (const rec of Object.values(manifest.agents)) {
    if (rec.status === "running") { rec.status = "pending"; rec.startedAt = null; }
  }
  if (manifest.phase === 0) manifest.phase = 1;
  writeManifestSync(manifest);

  const state: SupervisorState = {
    pid: process.pid, token, startedAt, heartbeatAt: startedAt, hostname: hostname(),
    bootTime: bootTimeBucket(), providers: providers.map((p) => p.id),
    phase: manifest.phase, running: [], completed: 0, total: roster.length, state: "starting"
  };
  writeSupervisorState(agentRunId, state);

  // ── Deterministic pre-pass, once for the whole roster ──────────────────────
  const index: RepoIndex = await buildRepoIndex();
  let contextPack = "";
  try {
    contextPack = (await buildContextPack({ agentRunId, stackContext: manifest.stackContext, index })).markdown;
  } catch (err) {
    console.error(JSON.stringify({ event: "CONTEXT_PACK_FAILED", agentRunId, error: String(err), severity: "LOW" }));
  }

  // ── Evidenced N/A sweep, before any session is spent ───────────────────────
  for (const agent of roster) {
    if (manifest.agents[agent]?.status !== "pending") continue;
    const verdict = determineNotApplicable(agent, manifest.stackContext, index);
    if (!verdict.notApplicable) continue;
    await updateAgentStatus({ agentRunId, agentName: agent, status: "completed_na", summary: verdict.rationale.slice(0, 500) });
    manifest = readManifestSync(agentRunId);
    const rec = manifest.agents[agent];
    if (rec) {
      rec.naEvidence = { signalsSearched: verdict.signalsSearched, matched: verdict.matched, rationale: verdict.rationale };
      writeManifestSync(manifest);
    }
  }

  const priorFindings: string[] = [];
  const inFlight = new Map<AgentName, Promise<void>>();
  let cancelled = false;
  let rr = 0;

  const heartbeat = setInterval(() => {
    const s = readSupervisorState(agentRunId);
    // Honour a takeover handshake: a reaper that thinks we are dead waits for this.
    if (s?.takeoverRequest && s.takeoverRequest.token !== token) {
      writeSupervisorState(agentRunId, { ...s, takeoverDenied: token, heartbeatAt: new Date().toISOString() });
      return;
    }
    writeSupervisorState(agentRunId, {
      ...state,
      heartbeatAt: new Date().toISOString(),
      running: [...inFlight.keys()],
      phase: manifest.phase,
      completed: Object.values(manifest.agents).filter((r) => r.status !== "pending" && r.status !== "running").length
    });
  }, HEARTBEAT_INTERVAL_MS);

  const stop = (why: SupervisorState["state"]): void => { cancelled = true; state.state = why; };
  process.on("SIGTERM", () => stop("cancelled"));
  process.on("SIGINT", () => stop("cancelled"));

  state.state = "running";

  try {
    for (;;) {
      if (existsSync(cancelPath(agentRunId))) { stop("cancelled"); }
      if (cancelled) break;

      manifest = readManifestSync(agentRunId);
      const ready = readyAgents(nodes, manifest).filter((a) => !inFlight.has(a));
      const remaining = Object.values(manifest.agents).some((r) => r.status === "pending" || r.status === "running");
      if (!remaining && inFlight.size === 0) break;

      let dispatched = 0;
      for (const agent of ready) {
        // Round-robin across providers so all three fleets stay busy and the quota cost
        // is split rather than falling entirely on one subscription.
        let slot: ProviderSlot | null = null;
        for (let i = 0; i < slots.length; i++) {
          const cand = slots[(rr + i) % slots.length] as ProviderSlot;
          if (cand.limiter.availableSlots() > 0) { slot = cand; rr = (rr + i + 1) % slots.length; break; }
        }
        if (!slot) break;

        const cfg = registry.adapters[slot.provider.id];
        if (!cfg) continue;

        slot.limiter.acquire();
        dispatched++;
        const chosen = slot;
        const node = nodes.find((n) => n.agent === agent);

        const p = (async (): Promise<void> => {
          try {
            const memory = await readAgentMemory({ agentName: agent }).catch(() => null);
            const rawFps: unknown = memory?.falsePositives ?? [];
            const falsePositives = Array.isArray(rawFps)
              ? rawFps.slice(0, 20).map((x) => (typeof x === "string" ? x : JSON.stringify(x)))
              : [];
            const outcome = await runAgent({
              agent, agentRunId, runId,
              adapterId: chosen.provider.id, adapter: cfg,
              binaryPath: chosen.provider.binaryPath as string,
              adapterVersion: chosen.provider.version,
              remediationMode, internetPermitted: manifest.internetPermitted,
              scope: manifest.scope, stackContext: manifest.stackContext,
              scheduledSubAgents: node?.tier === "lead" ? subAgentsOf(agent, roster) : [],
              contextPack,
              priorFindings: priorFindings.slice(-40),
              targetFiles: prefilterScope(agent, index),
              knownFalsePositives: falsePositives
            });

            if (outcome.kind === "failed" && outcome.rateLimited) {
              const r = chosen.limiter.recordRateLimit();
              console.error(JSON.stringify({
                event: "SUPERVISOR_THROTTLED", agentRunId, provider: chosen.provider.id,
                pausedMs: r.pausedMs, concurrency: r.concurrency, stalled: r.stalled, severity: "MEDIUM"
              }));
              if (r.stalled) state.state = "throttled_stalled";
            } else if (outcome.kind === "failed") {
              chosen.limiter.recordFailure();
            } else {
              chosen.limiter.recordSuccess();
              if (outcome.kind !== "completed_na") {
                for (const f of outcome.findings.slice(0, 10)) {
                  priorFindings.push(`${f.severity} | ${f.title} | ${(f.files ?? []).slice(0, 2).join(",")}`);
                }
              }
            }

            // Persist execution provenance onto the manifest record.
            const m2 = readManifestSync(agentRunId);
            const rec = m2.agents[agent];
            if (rec) {
              rec.execution = outcome.execution;
              if (outcome.kind === "completed_na") rec.naEvidence = outcome.evidence;
              writeManifestSync(m2);
            }
          } catch (err) {
            console.error(JSON.stringify({
              event: "AGENT_EXECUTION_ERROR", agentRunId, agent, error: String(err), severity: "HIGH"
            }));
            await updateAgentStatus({ agentRunId, agentName: agent, status: "failed", summary: String(err).slice(0, 400) }).catch(() => undefined);
          } finally {
            chosen.limiter.release();
            inFlight.delete(agent);
          }
        })();
        inFlight.set(agent, p);
      }

      if (dispatched === 0 && inFlight.size === 0) {
        // Nothing ready and nothing running: either every provider is paused, or the
        // remaining agents are blocked on dependencies that can no longer complete.
        const waits = slots.map((s) => s.limiter.msUntilResume()).filter((m) => m > 0);
        if (waits.length === 0) break;
        await sleep(Math.min(...waits, 30_000));
        continue;
      }

      await Promise.race([...inFlight.values(), sleep(TICK_MS)]);
    }
  } finally {
    clearInterval(heartbeat);
    if (inFlight.size > 0) await Promise.allSettled(inFlight.values());

    manifest = readManifestSync(agentRunId);
    if (cancelled) {
      for (const rec of Object.values(manifest.agents)) {
        if (rec.status === "running") { rec.status = "pending"; rec.startedAt = null; }
      }
      writeManifestSync(manifest);
      try { unlinkSync(cancelPath(agentRunId)); } catch { /* already gone */ }
    }

    const done = Object.values(manifest.agents).filter((r) => r.status !== "pending" && r.status !== "running").length;
    writeSupervisorState(agentRunId, {
      ...state,
      heartbeatAt: new Date().toISOString(),
      running: [],
      phase: manifest.phase,
      completed: done,
      state: finalState(cancelled, state.state)
    });
  }
}

/** Cancellation wins; a stalled-by-throttling run must not be reported as done. */
function finalState(cancelled: boolean, current: SupervisorState["state"]): SupervisorState["state"] {
  if (cancelled) return "cancelled";
  if (current === "throttled_stalled" || current === "auth_lost") return current;
  return "done";
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function argOf(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const agentRunId = argOf("--agent-run-id");
  const runId = argOf("--run-id");
  const workspace = argOf("--workspace");
  const remediationMode = (argOf("--remediation-mode") ?? "detection_only") as RemediationMode;
  const concurrency = argOf("--concurrency");
  if (!agentRunId || !runId || !workspace) {
    console.error("usage: supervisor --agent-run-id <id> --run-id <uuid> --workspace <path> [--remediation-mode m] [--concurrency n]");
    process.exit(2);
  }
  // Every getWorkspaceRoot() consumer depends on this scope, and a detached process's
  // cwd is not a safe substitute for it.
  await withWorkspace(workspace, () => superviseRun({
    agentRunId, runId, remediationMode,
    ...(concurrency ? { concurrencyOverride: Number(concurrency) } : {})
  }));
}

const isMain = process.argv[1]?.endsWith("supervisor.js") || process.argv[1]?.endsWith("supervisor.ts");
if (isMain) {
  main().catch((err) => { console.error("supervisor crashed:", err); process.exit(1); });
}

export { statePath as supervisorStatePath, cancelPath as supervisorCancelPath };
