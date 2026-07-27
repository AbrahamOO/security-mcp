/**
 * Single-agent execution.
 *
 * Spawns one local CLI as one specialist agent, then writes a schema-valid findings
 * file, self-attests it, and moves the manifest record to a terminal state.
 *
 * The ordering at the end of runAgent() is load-bearing and must not be rearranged —
 * see the comment above the write block.
 */
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve, relative, sep } from "node:path";
import { randomUUID } from "node:crypto";
import { execa } from "execa";
import { getWorkspaceRoot } from "../repo/workspace.js";
import { updateAgentStatus } from "../mcp/orchestration.js";
import { attestAgent, computeFindingsHash } from "../mcp/audit-chain.js";
import { taskTypeForAgent } from "../mcp/capability-enforcer.js";
import { getModelForTask, trackUsage, recordProviderFailure } from "../mcp/model-router.js";
import type { UsageInput } from "../mcp/model-router.js";
import type { AgentExecutionRecord, AgentFinding, AgentName } from "../types/agent-run.js";
import {
  renderArgv, joinTools, modelForTier, effortForTier, compileConfigRegex,
  type CapabilityTier
} from "./adapter.js";
import type { AdapterConfig } from "./adapter-schema.js";
import {
  AGENT_OUTPUT_JSON_SCHEMA, buildSystemPrompt, buildUserPrompt, loadPersona,
  normalizeAgentOutput, salvageJsonObject, type NormalizedOutput, type PromptContext
} from "./agent-prompt.js";

export type RemediationMode = "detection_only" | "auto_apply";

export type AgentOutcome =
  | { kind: "completed"; findingsPath: string; findings: AgentFinding[]; execution: AgentExecutionRecord; summary: string }
  | { kind: "completed_partial"; findingsPath: string | null; findings: AgentFinding[]; execution: AgentExecutionRecord; summary: string }
  | { kind: "completed_na"; execution: AgentExecutionRecord; evidence: { signalsSearched: string[]; matched: string[]; rationale: string } }
  | { kind: "failed"; execution: AgentExecutionRecord; reason: string; rateLimited: boolean };

export type RunAgentOptions = {
  agent: AgentName;
  agentRunId: string;
  runId: string;
  adapterId: string;
  adapter: AdapterConfig;
  binaryPath: string;
  adapterVersion: string | null;
  remediationMode: RemediationMode;
  internetPermitted: boolean;
  scope: { mode: string; targets: string[]; baseRef: string; headRef: string };
  stackContext: PromptContext["stackContext"];
  scheduledSubAgents: string[];
  contextPack?: string;
  priorFindings?: string[];
  targetFiles?: string[];
  knownFalsePositives?: string[];
  timeoutMs?: number;
  maxBudgetUsd?: number;
  /** Injected for tests; defaults to real execa. */
  spawn?: typeof execa;
};

// ---------------------------------------------------------------------------
// Tool resolution
// ---------------------------------------------------------------------------

export type ResolvedTools = {
  allowed: string[];
  denied: string[];
  available: string[];
  excluded: string[];
  sandbox: string;
};

/**
 * Least privilege per adapter.
 *
 * Two adapters express this in opposite directions. Claude and Codex allow-list;
 * Copilot must be given --allow-all-tools for non-interactive mode and can only be
 * constrained by EXCLUDING tools. Both shapes are emitted so the argv template picks
 * whichever flags it declares.
 */
export function resolveTools(cfg: AdapterConfig, opts: {
  remediationMode: RemediationMode; internetPermitted: boolean;
}): ResolvedTools {
  const readOnly = [...cfg.tools.readOnly];
  const write = [...cfg.tools.write];
  const network = [...cfg.tools.network];
  // Sub-agent spawning is never grantable: it is the one capability that would let a
  // child defeat the recursion guard from inside.
  const forbidden = [...cfg.tools.forbidden];

  const applying = opts.remediationMode === "auto_apply";
  const allowed = applying ? [...readOnly, ...write] : [...readOnly];
  const denied = [...forbidden, ...(applying ? [] : write), ...(opts.internetPermitted ? [] : network)];

  const sandbox = applying
    ? (cfg.permission.applyValue ?? "")
    : (cfg.permission.auditValue ?? "");

  return {
    allowed,
    denied,
    available: allowed,
    excluded: denied,
    sandbox
  };
}

// ---------------------------------------------------------------------------
// Child environment
// ---------------------------------------------------------------------------

const BASE_ENV_ALLOWLIST = [
  "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "TMPDIR", "TERM",
  "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
  "CLAUDE_CONFIG_DIR", "CODEX_HOME", "NODE_OPTIONS"
];

/** Provider credentials that must never leak into a DIFFERENT provider's child. */
const ALL_PROVIDER_CREDENTIALS = [
  "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
  "OPENAI_API_KEY",
  "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN",
  "GEMINI_API_KEY", "GOOGLE_API_KEY"
];

/**
 * Build the child env with `extendEnv:false` semantics.
 *
 * Credential passthrough is PER ADAPTER. A blanket strip of GITHUB_TOKEN would break
 * Copilot, whose documented headless precedence is COPILOT_GITHUB_TOKEN > GH_TOKEN >
 * GITHUB_TOKEN — while a Claude child has no business seeing a GitHub token at all.
 * Everything else is dropped: the parent's HMAC/attestation keys, webhook and ticketing
 * credentials, cloud keys. These children read untrusted repo content with tool access.
 */
export function buildChildEnv(cfg: AdapterConfig, extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of BASE_ENV_ALLOWLIST) {
    const v = process.env[key];
    if (v !== undefined) env[key] = v;
  }

  const permitted = new Set(cfg.auth.childCredentialEnv);
  for (const key of ALL_PROVIDER_CREDENTIALS) {
    if (!permitted.has(key)) continue;
    const v = process.env[key];
    if (v !== undefined && v.length > 0) env[key] = v;
  }

  for (const [k, v] of Object.entries(cfg.recursionGuard.env)) env[k] = v;
  for (const [k, v] of Object.entries(cfg.invoke.env)) env[k] = v;
  for (const [k, v] of Object.entries(extra)) env[k] = v;

  env["CLAUDE_CODE_ENTRYPOINT"] = "security-mcp-executor";
  return env;
}

// ---------------------------------------------------------------------------
// Output extraction
// ---------------------------------------------------------------------------

function getPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, k) => {
    if (acc && typeof acc === "object") return (acc as Record<string, unknown>)[k];
    return undefined;
  }, obj);
}

export type ParsedCliOutput = {
  result: unknown;
  isError: boolean;
  errorText: string;
  usage: { inputTokens?: number; outputTokens?: number; costUsd?: number; sessionId?: string; durationMs?: number; actualModel?: string };
  permissionDenials: string[];
  /** Whether the payload came from the declared path or a salvage parse. */
  salvaged: boolean;
};

/** Parse stdout per the adapter's declared shape. Never throws on shape drift. */
export function parseCliOutput(cfg: AdapterConfig, stdout: string, outputFileText: string | null): ParsedCliOutput {
  const empty: ParsedCliOutput = {
    result: null, isError: false, errorText: "", usage: {}, permissionDenials: [], salvaged: false
  };

  // A dedicated output file (Codex --output-last-message) is the most reliable source:
  // no interleaved log lines, no truncation from stdout buffering.
  if (outputFileText && outputFileText.trim().length > 0) {
    try {
      return { ...empty, result: JSON.parse(outputFileText) as unknown };
    } catch {
      const salvaged = salvageJsonObject(outputFileText);
      if (salvaged) return { ...empty, result: salvaged, salvaged: true };
    }
  }

  const fmt = cfg.outputParse.format;
  let envelope: unknown = null;

  if (fmt === "json") {
    try { envelope = JSON.parse(stdout) as unknown; } catch { envelope = null; }
  } else if (fmt === "jsonl") {
    const events: unknown[] = [];
    for (const line of stdout.split("\n")) {
      const t = line.trim();
      if (!t.startsWith("{")) continue;
      try { events.push(JSON.parse(t) as unknown); } catch { /* non-JSON log line */ }
    }
    const sel = cfg.outputParse.jsonlSelector;
    if (sel) {
      // Last match wins: the final completed item is the agent's answer.
      for (const e of events) if (String(getPath(e, sel.path) ?? "") === sel.equals) envelope = e;
    }
    if (!envelope && events.length > 0) envelope = events[events.length - 1];
  } else {
    let text = stdout;
    for (const p of cfg.outputParse.stripPrefixes) text = text.split(p).join("");
    const salvaged = salvageJsonObject(text);
    return { ...empty, result: salvaged, salvaged: salvaged !== null };
  }

  if (envelope === null) {
    const salvaged = salvageJsonObject(stdout);
    return { ...empty, result: salvaged, salvaged: salvaged !== null };
  }

  const usage: ParsedCliOutput["usage"] = {};
  const u = cfg.usage;
  const num = (p?: string): number | undefined => {
    if (!p) return undefined;
    const v = getPath(envelope, p);
    return typeof v === "number" ? v : undefined;
  };
  usage.inputTokens = num(u.inputTokensPath);
  usage.outputTokens = num(u.outputTokensPath);
  usage.costUsd = num(u.costUsdPath);
  usage.durationMs = num(u.durationMsPath);
  if (u.sessionIdPath) {
    const s = getPath(envelope, u.sessionIdPath);
    if (typeof s === "string") usage.sessionId = s;
  }
  if (u.modelPath) {
    const m = getPath(envelope, u.modelPath);
    if (typeof m === "string" && m.length > 0) usage.actualModel = m;
  }

  let denials: string[] = [];
  if (u.permissionDenialsPath) {
    const d = getPath(envelope, u.permissionDenialsPath);
    if (Array.isArray(d)) denials = d.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).slice(0, 50);
  }

  // The real model id the provider served, which is NOT the alias we asked for.
  // "opus" is a request; "claude-opus-4-8" is what actually answered.
  if (u.modelUsagePath) {
    const mu = getPath(envelope, u.modelUsagePath);
    if (mu && typeof mu === "object") {
      const keys = Object.keys(mu as Record<string, unknown>);
      if (keys[0]) usage.actualModel = keys[0];
      const first = (mu as Record<string, Record<string, unknown>>)[keys[0] ?? ""];
      const cost = first?.["costUSD"];
      if (usage.costUsd === undefined && typeof cost === "number") usage.costUsd = cost;
    }
  }

  const isError = cfg.outputParse.isErrorPath ? getPath(envelope, cfg.outputParse.isErrorPath) === true : false;
  const errorRaw = cfg.outputParse.errorPath ? getPath(envelope, cfg.outputParse.errorPath) : "";
  const errorText = typeof errorRaw === "string" ? errorRaw : JSON.stringify(errorRaw ?? "");

  // When a schema was supplied the payload usually lands in a DIFFERENT field than the
  // free-text result. Claude leaves `result` as "" and fills `structured_output`, so
  // reading `result` looks exactly like an agent that produced nothing at all.
  const structuredPath = cfg.structuredOutput.mode !== "none" ? cfg.structuredOutput.resultPath : null;
  let result: unknown = structuredPath ? getPath(envelope, structuredPath) : undefined;
  if (result === undefined || result === null) {
    result = cfg.outputParse.resultPath ? getPath(envelope, cfg.outputParse.resultPath) : envelope;
  }
  let salvaged = false;
  if (typeof result === "string") {
    // Claude returns `result` as a JSON-encoded string when --json-schema is used.
    const asText = result;
    try {
      result = JSON.parse(asText) as unknown;
    } catch {
      const rescued = salvageJsonObject(asText);
      result = rescued;
      salvaged = rescued !== null;
    }
  }

  return { result, isError, errorText, usage, permissionDenials: denials, salvaged };
}

/** Does this failure look like provider throttling rather than an agent error? */
export function isRateLimited(cfg: AdapterConfig, exitCode: number | null, text: string): boolean {
  if (exitCode !== null && cfg.rateLimit.exitCodes.includes(exitCode)) return true;
  for (const p of [...cfg.rateLimit.stderrPatterns, ...cfg.rateLimit.jsonErrorPatterns]) {
    try {
      if (compileConfigRegex(p).test(text)) return true;
    } catch { /* a bad pattern must not break failure handling */ }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

async function tierFor(agent: AgentName, agentRunId: string): Promise<{
  tier: CapabilityTier; taskType: string; providerMismatch: boolean;
}> {
  const taskType = taskTypeForAgent(agent);
  try {
    const assignment = await getModelForTask(taskType, { agentName: agent, agentRunId });
    return {
      tier: assignment.capabilityTier as CapabilityTier,
      taskType,
      // The router sorts by cost and can pick a non-Anthropic provider that the local
      // CLI cannot honour. We run on the CLI anyway (that is the whole design) but
      // record the divergence rather than pretending the router was obeyed.
      providerMismatch: assignment.provider !== "anthropic" && assignment.provider !== "openai"
    };
  } catch {
    return { tier: "advanced", taskType, providerMismatch: false };
  }
}

export async function runAgent(opts: RunAgentOptions): Promise<AgentOutcome> {
  const {
    agent, agentRunId, runId, adapter: cfg, binaryPath, remediationMode, internetPermitted
  } = opts;
  const spawn = opts.spawn ?? execa;
  const workspaceRoot = getWorkspaceRoot();
  const runDir = join(workspaceRoot, ".mcp", "agent-runs", agentRunId);
  const workDir = join(runDir, "agents", agent);
  await mkdir(workDir, { recursive: true, mode: 0o700 });

  const degradation = new Set<string>();
  const startedAt = new Date();

  const persona = loadPersona(agent) ?? `You are the ${agent} security specialist.`;
  if (loadPersona(agent) === null) degradation.add("persona_missing");

  const maxPersonaChars = cfg.class === "B"
    ? Math.floor(cfg.models.contextTokens * 0.25 * 3.6)
    : undefined;

  const promptCtx: PromptContext = {
    agent, agentRunId, runId, remediationMode,
    scope: opts.scope, stackContext: opts.stackContext, internetPermitted,
    scheduledSubAgents: opts.scheduledSubAgents,
    ...(opts.contextPack ? { contextPack: opts.contextPack } : {}),
    ...(opts.priorFindings ? { priorFindings: opts.priorFindings } : {}),
    ...(opts.targetFiles ? { targetFiles: opts.targetFiles } : {}),
    ...(opts.knownFalsePositives ? { knownFalsePositives: opts.knownFalsePositives } : {}),
    ...(maxPersonaChars !== undefined ? { maxPersonaChars } : {})
  };

  const { text: systemPrompt, personaTruncated } = buildSystemPrompt(promptCtx, persona);
  if (personaTruncated) degradation.add("persona_truncated");
  const userPrompt = buildUserPrompt(promptCtx);

  const { tier, taskType, providerMismatch } = await tierFor(agent, agentRunId);
  if (providerMismatch) degradation.add("router_provider_unavailable_on_local_cli");

  const tools = resolveTools(cfg, { remediationMode, internetPermitted });
  const model = modelForTier(cfg, tier);
  const effort = effortForTier(cfg, tier);
  const sessionId = randomUUID();

  // Adapters that deliver these via file rather than argv.
  const schemaFile = join(workDir, "output-schema.json");
  const outputFile = join(workDir, "last-message.json");
  const transcriptFile = join(workDir, "transcript.md");
  const logDir = join(workDir, "logs");
  await mkdir(logDir, { recursive: true, mode: 0o700 });
  if (cfg.structuredOutput.mode === "jsonSchemaFlag") {
    await writeFile(schemaFile, JSON.stringify(AGENT_OUTPUT_JSON_SCHEMA), { mode: 0o600 });
  } else {
    degradation.add("no_structured_output");
  }

  const argv = renderArgv(cfg, {
    "{model}": model,
    "{effort}": effort,
    "{sandbox}": tools.sandbox,
    "{systemPrompt}": cfg.systemPrompt.mode === "append" || cfg.systemPrompt.mode === "flag" ? systemPrompt : "",
    "{prompt}": cfg.prompt.delivery === "argv"
      ? (cfg.systemPrompt.mode === "prepend"
        ? cfg.systemPrompt.prependTemplate.replace("{systemPrompt}", systemPrompt).replace("{prompt}", userPrompt)
        : userPrompt)
      : "",
    "{workspaceRoot}": workspaceRoot,
    "{runDir}": runDir,
    "{allowedTools}": tools.allowed.length > 0 ? joinTools(cfg, tools.allowed) : "",
    "{disallowedTools}": tools.denied.length > 0 ? joinTools(cfg, tools.denied) : "",
    "{availableTools}": cfg.tools.availableFlag && tools.available.length > 0 ? joinTools(cfg, tools.available) : "",
    "{excludedTools}": cfg.tools.excludedFlag && tools.excluded.length > 0 ? joinTools(cfg, tools.excluded) : "",
    "{jsonSchema}": cfg.structuredOutput.schemaDelivery === "argv" && cfg.structuredOutput.mode === "jsonSchemaFlag"
      ? JSON.stringify(AGENT_OUTPUT_JSON_SCHEMA) : "",
    "{jsonSchemaFile}": cfg.structuredOutput.schemaDelivery === "file" && cfg.structuredOutput.mode === "jsonSchemaFlag"
      ? schemaFile : "",
    "{outputFile}": cfg.structuredOutput.outputFileFlag ? outputFile : "",
    "{transcriptFile}": transcriptFile,
    "{logDir}": logDir,
    "{sessionId}": sessionId,
    "{maxBudgetUsd}": opts.maxBudgetUsd !== undefined ? String(opts.maxBudgetUsd) : "",
    "{maxCredits}": "",
    "{denyUrls}": internetPermitted ? "" : "*",
    "{secretEnvVars}": cfg.auth.childCredentialEnv.join(","),
    "{agentName}": agent,
    "{agentRunId}": agentRunId
  });

  const stdinBody = cfg.prompt.delivery === "stdin"
    ? (cfg.systemPrompt.mode === "prepend"
      ? cfg.systemPrompt.prependTemplate.replace("{systemPrompt}", systemPrompt).replace("{prompt}", userPrompt)
      : userPrompt)
    : undefined;

  const env = buildChildEnv(cfg, {
    SECURITY_MCP_AGENT_RUN_ID: agentRunId,
    SECURITY_MCP_AGENT_NAME: agent,
    SECURITY_MCP_TOOL_PROFILE: "child_readonly"
  });

  const timeoutMs = opts.timeoutMs ?? cfg.limits.timeoutMs;
  let stdout = "", stderr = "", exitCode: number | null = null, timedOut = false;

  try {
    const child = await spawn(binaryPath, argv, {
      cwd: workspaceRoot,
      env,
      extendEnv: false,
      ...(stdinBody !== undefined ? { input: stdinBody } : {}),
      timeout: timeoutMs,
      killSignal: "SIGTERM",
      forceKillAfterDelay: 5000,
      maxBuffer: cfg.limits.maxOutputBytes,
      reject: false,
      stripFinalNewline: false
    });
    stdout = String(child.stdout ?? "");
    stderr = String(child.stderr ?? "");
    exitCode = child.exitCode ?? null;
    timedOut = child.timedOut === true;
  } catch (err) {
    stderr = err instanceof Error ? err.message : String(err);
    exitCode = null;
  }

  const endedAt = new Date();
  const outputFileText = existsSync(outputFile) ? await readFile(outputFile, "utf-8").catch(() => null) : null;
  const parsed = parseCliOutput(cfg, stdout, outputFileText);
  // Extracting JSON from a fenced block is the DESIGNED path for an adapter with no
  // structured-output support (Copilot), and a genuine warning sign for one that
  // promised it. Only the latter counts as degradation.
  const promisedStructured = cfg.structuredOutput.mode !== "none";
  if (parsed.salvaged && promisedStructured) degradation.add("output_salvaged_from_free_text");
  if (parsed.permissionDenials.length > 0) degradation.add("permission_denied_tools");

  const transcriptPaths = [transcriptFile, outputFile, logDir].filter((p) => existsSync(p));

  const execution: AgentExecutionRecord = {
    adapterId: opts.adapterId,
    adapterVersion: opts.adapterVersion,
    adapterClass: cfg.class,
    binaryPath,
    // Prefer what the provider says it served over the alias we requested.
    model: parsed.usage.actualModel ?? model ?? "(adapter default)",
    capabilityTier: tier,
    taskType,
    ...(effort ? { effort } : {}),
    ...(tools.sandbox ? { sandbox: tools.sandbox } : {}),
    toolsAllowed: tools.allowed,
    toolsDenied: tools.denied,
    startedAt: startedAt.toISOString(),
    endedAt: endedAt.toISOString(),
    durationMs: endedAt.getTime() - startedAt.getTime(),
    exitCode,
    ...(parsed.usage.sessionId ? { sessionId: parsed.usage.sessionId } : { sessionId }),
    ...(parsed.usage.inputTokens !== undefined ? { inputTokens: parsed.usage.inputTokens } : {}),
    ...(parsed.usage.outputTokens !== undefined ? { outputTokens: parsed.usage.outputTokens } : {}),
    ...(parsed.usage.costUsd !== undefined ? { notionalCostUsd: parsed.usage.costUsd } : {}),
    // On a subscription plan the CLI's cost figure is API-EQUIVALENT, not money
    // charged. Labelling it prevents a report claiming spend that never happened.
    costIsNotional: true,
    transcriptPaths,
    permissionDenials: parsed.permissionDenials,
    degradationReasons: []
  };

  const combined = `${stderr}\n${parsed.errorText}`;
  const rateLimited = isRateLimited(cfg, exitCode, combined);

  // ── Failure paths ────────────────────────────────────────────────────────
  const hardFailure =
    timedOut || exitCode === null || (exitCode !== 0 && parsed.result === null) || parsed.isError;
  if (hardFailure && parsed.result === null) {
    execution.degradationReasons = [...degradation, timedOut ? "timeout" : "cli_error"];
    if (rateLimited) {
      try { await recordProviderFailure(providerFor(opts.adapterId)); } catch { /* advisory */ }
    }
    await updateAgentStatus({ agentRunId, agentName: agent, status: "failed", summary: truncate(combined, 500) });
    return {
      kind: "failed", execution, rateLimited,
      reason: timedOut ? `timed out after ${timeoutMs}ms` : truncate(combined || `exit ${String(exitCode)}`, 500)
    };
  }

  // ── Normalise ────────────────────────────────────────────────────────────
  const normalized: NormalizedOutput | null = normalizeAgentOutput(parsed.result, {
    agent,
    personaBody: persona,
    remediationMode,
    resolveFile: (raw) => {
      // Containment check first: a model can emit "../../etc/passwd" as a finding path,
      // and resolve() happily accepts an absolute path as-is.
      const abs = resolve(workspaceRoot, raw);
      if (abs !== workspaceRoot && !abs.startsWith(workspaceRoot + sep)) return null;
      if (!existsSync(abs)) return null;
      return relative(workspaceRoot, abs) || raw;
    }
  });

  if (!normalized) {
    execution.degradationReasons = [...degradation, "unparseable_output"];
    // completed_partial, NOT failed: `failed` burns a retry via MAX_AGENT_RETRIES, and
    // re-running a model that cannot produce the output shape is wasted quota.
    await updateAgentStatus({
      agentRunId, agentName: agent, status: "completed_partial",
      summary: "Agent produced no parseable structured output."
    });
    return { kind: "completed_partial", findingsPath: null, findings: [], execution, summary: "no parseable output" };
  }

  for (const r of normalized.degradationReasons) degradation.add(r);
  execution.degradationReasons = [...degradation];

  // ── Evidenced N/A ────────────────────────────────────────────────────────
  if (normalized.notApplicable && normalized.findings.length === 0) {
    await updateAgentStatus({
      agentRunId, agentName: agent, status: "completed_na",
      summary: truncate(normalized.notApplicable.rationale, 500)
    });
    return {
      kind: "completed_na", execution,
      evidence: {
        signalsSearched: normalized.notApplicable.signalsSearched,
        matched: [],
        rationale: normalized.notApplicable.rationale
      }
    };
  }

  // ── Write, attest, report ────────────────────────────────────────────────
  // ORDER IS LOAD-BEARING. mergeAgentFindings in enforced mode recomputes
  // computeFindingsHash(JSON.parse(file).findings) and compares it to the attested
  // hash. Attesting the exact array we are about to serialise makes those two hashes
  // equal by construction. Nothing may mutate `findings` between these two calls.
  const findings = normalized.findings as unknown as AgentFinding[];

  // Every value the file asserts about this agent's own work is computed BEFORE the
  // attestation and then reused verbatim when the file is written, so the signature covers
  // exactly the bytes that land on disk. Attesting first and constructing the payload
  // afterwards left section coverage, the summary, and the capability record outside the
  // signature entirely, which is how a run could be rewritten to claim 100% coverage after
  // the fact without breaking the chain.
  const attestedSections = normalized.skillMdSectionsCovered;
  const attestedSummary = normalized.summary || `${findings.length} finding(s) reported by ${agent}.`;
  const attestedCapability = {
    modelUsed: execution.model,
    capabilityTierUsed: tier,
    taskType,
    toolsAvailable: tools.allowed,
    toolsUsed: tools.allowed
  };
  await attestAgent({
    agentRunId, agentName: agent, findings,
    skillMdSectionsCovered: attestedSections,
    summary: attestedSummary,
    capability: attestedCapability
  });

  const partial = (parsed.salvaged && promisedStructured) || parsed.permissionDenials.length > 0;
  const fileName = `${agent}.json`;
  const findingsPath = join(runDir, fileName);
  const payload = {
    agentName: agent,
    agentRunId,
    completedAt: endedAt.toISOString(),
    internetUsed: internetPermitted,
    memoryUpdated: false,
    skillMdSectionsCovered: attestedSections,
    summary: attestedSummary,
    remediatedCount: findings.filter((f) => f.remediated).length,
    openCount: findings.filter((f) => !f.remediated).length,
    findings,
    // Read by capability-enforcer.ts, which until now could never find it and so
    // always degraded to a "capability unknown" advisory. Same object that was attested.
    capability: attestedCapability,
    executionProvenance: execution
  };
  await writeFile(findingsPath, JSON.stringify(payload, null, 2) + "\n", { mode: 0o600 });

  // Guard the one invariant the whole attestation scheme rests on: the hash of the
  // array we attested must survive a JSON round-trip, because that is exactly what
  // mergeAgentFindings does when it re-derives the hash from the file on disk.
  const roundTripped = JSON.parse(JSON.stringify(findings)) as AgentFinding[];
  if (computeFindingsHash(roundTripped) !== computeFindingsHash(findings)) {
    execution.degradationReasons.push("findings_hash_unstable");
  }

  const status = partial ? "completed_partial" : "completed";
  await updateAgentStatus({
    agentRunId, agentName: agent, status,
    findingsPath: fileName,
    summary: truncate(payload.summary, 500)
  });

  try {
    await trackUsage({
      taskType: taskType as UsageInput["taskType"],
      model: execution.model,
      provider: providerFor(opts.adapterId),
      tier: tier === "light" ? "haiku" : "sonnet",
      inputTokens: execution.inputTokens ?? 0,
      outputTokens: execution.outputTokens ?? 0,
      ...(execution.notionalCostUsd !== undefined ? { actualCostUsd: execution.notionalCostUsd } : {}),
      agentName: agent,
      agentRunId
    });
  } catch { /* usage accounting is advisory, never fatal to a run */ }

  return {
    kind: partial ? "completed_partial" : "completed",
    findingsPath, findings, execution, summary: payload.summary
  };
}

/** Map an adapter to the provider bucket the model-router tracks health against. */
function providerFor(adapterId: string): UsageInput["provider"] {
  if (adapterId === "codex" || adapterId === "copilot") return "openai";
  if (adapterId === "gemini") return "google";
  if (adapterId === "ollama" || adapterId === "generic") return "local";
  return "anthropic";
}

function truncate(s: string, n: number): string {
  const t = s.trim().replace(/\s+/g, " ");
  return t.length <= n ? t : `${t.slice(0, n - 1)}…`;
}
