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

import { createHash } from "node:crypto";
import * as https from "node:https";
import {
  mkdir,
  readFile,
  writeFile,
  readdir
} from "node:fs/promises";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { z } from "zod";
import { updateReviewStep } from "../review/store.js";
import type {
  AgentName,
  AgentRunManifest,
  AgentRecord,
  AgentStatus,
  AgentFindingsFile,
  AgentFinding,
  MergedFindings,
  StackContext,
  UpdateCheckResult
} from "../types/agent-run.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AGENT_RUNS_DIR = join(".mcp", "agent-runs");
const MEMORY_DIR = join(homedir(), ".security-mcp", "agent-memory");
const SKILL_VERSIONS_PATH = join(homedir(), ".security-mcp", "skill-versions.json");
const SKILLS_MANIFEST_URL =
  "https://raw.githubusercontent.com/AbrahamOO/security-mcp/main/skills-manifest.json";
const CLAUDE_SKILLS_DIR = join(homedir(), ".claude", "skills");
const NPM_REGISTRY_URL = "https://registry.npmjs.org/security-mcp/latest";

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

// All SKILL.md sections that must be covered per run
const SKILL_MD_SECTIONS = [
  "§1", "§2", "§3", "§4", "§5", "§6", "§7", "§8",
  "§9", "§10", "§11", "§12", "§13", "§14", "§15",
  "§16", "§17", "§18", "§19", "§20", "§21", "§22",
  "§23", "§24"
];

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function ensureDir(p: string): Promise<void> {
  await mkdir(p, { recursive: true });
}

function agentRunDir(agentRunId: string): string {
  // CWE-22: agentRunId must be the 32-char hex digest produced by createAgentRun
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

async function writeManifest(manifest: AgentRunManifest): Promise<void> {
  manifest.updatedAt = new Date().toISOString();
  await writeFile(manifestPath(manifest.agentRunId), JSON.stringify(manifest, null, 2) + "\n", "utf-8");
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
function buildInitialAgents(stackContext: StackContext): Record<AgentName, AgentRecord> {
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

  const record = {} as Record<AgentName, AgentRecord>;
  for (const name of names) {
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
  }).describe("Tech stack context derived from project scan.")
});

export async function createAgentRun(args: z.infer<typeof CreateAgentRunSchema>): Promise<{
  agentRunId: string;
  manifestPath: string;
}> {
  const { runId, scope, internetPermitted, stackContext } = args;
  const agentRunId = createHash("sha256")
    .update(`${runId}:${Date.now()}`)
    .digest("hex")
    .slice(0, 32);

  await ensureDir(agentRunDir(agentRunId));

  const manifest: AgentRunManifest = {
    agentRunId,
    runId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    phase: 0,
    internetPermitted,
    stackContext: stackContext as StackContext,
    scope,
    agents: buildInitialAgents(stackContext as StackContext)
  };

  await writeManifest(manifest);

  return { agentRunId, manifestPath: manifestPath(agentRunId) };
}

// 2. update_agent_status
// ---------------------------------------------------------------------------

export const UpdateAgentStatusSchema = z.object({
  agentRunId: z.string().describe("Agent run ID from orchestration.create_agent_run."),
  agentName: z.string().describe("Name of the agent updating its status."),
  status: z.enum(["running", "completed", "completed_partial", "failed"]),
  findingsPath: z.string().optional().describe("Relative path to the agent findings JSON file."),
  summary: z.string().optional().describe("One-line outcome summary.")
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

  record.status = status as AgentStatus;
  if (status === "running") record.startedAt = new Date().toISOString();
  if (status === "completed" || status === "completed_partial" || status === "failed") {
    record.completedAt = new Date().toISOString();
  }
  if (findingsPath) record.findingsPath = findingsPath;
  if (summary) record.summary = summary;

  // Advance phase when all phase-1 leads complete
  const phase1Leads: AgentName[] = [
    "threat-modeler", "appsec-code-auditor", "cloud-infra-specialist",
    "supply-chain-devsecops", "ai-llm-redteam", "mobile-security-specialist",
    "crypto-pki-specialist"
  ];
  const phase2Leads: AgentName[] = ["pentest-team", "compliance-grc"];

  const allPhase1Done = phase1Leads.every((n) => {
    const s = manifest.agents[n].status;
    return s === "completed" || s === "completed_partial" || s === "failed";
  });
  const allPhase2Done = phase2Leads.every((n) => {
    const s = manifest.agents[n].status;
    return s === "completed" || s === "completed_partial" || s === "failed";
  });

  if (manifest.phase === 1 && allPhase1Done) manifest.phase = 2;
  if (manifest.phase === 2 && allPhase2Done) manifest.phase = 3;

  await writeManifest(manifest);
  return { manifest };
}

// 3. merge_agent_findings
// ---------------------------------------------------------------------------

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
    files = entries.filter((f) => f.endsWith(".json") && f !== "manifest.json" && f !== "merged-findings.json");
  } catch {
    files = [];
  }

  const allFindings: AgentFinding[] = [];
  const agentsCovered: AgentName[] = [];
  const agentsPartial: AgentName[] = [];
  const sectionsSeen = new Set<string>();
  const beyondSkillMdNotes: string[] = [];

  for (const file of files) {
    try {
      const raw = await readFile(join(dir, file), "utf-8");
      const parsed = JSON.parse(raw) as AgentFindingsFile;
      allFindings.push(...parsed.findings);
      if (parsed.agentName) {
        const manifest = await readManifest(agentRunId);
        const rec = manifest.agents[parsed.agentName];
        if (rec?.status === "completed_partial") {
          agentsPartial.push(parsed.agentName);
        } else {
          agentsCovered.push(parsed.agentName);
        }
      }
      for (const s of (parsed.skillMdSectionsCovered ?? [])) sectionsSeen.add(s);
      for (const n of (parsed.beyondSkillMd ?? [])) beyondSkillMdNotes.push(n);
    } catch {
      // Corrupted file — skip, note partial
      agentsPartial.push(file.replace(".json", "") as AgentName);
    }
  }

  // Deduplicate by id (first occurrence wins)
  const seen = new Set<string>();
  const deduped = allFindings.filter((f) => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });

  // Sort: CRITICAL > HIGH > MEDIUM > LOW
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  deduped.sort((a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3));

  const uncoveredSections = SKILL_MD_SECTIONS.filter((s) => !sectionsSeen.has(s));

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
    findings: deduped
  };

  // Write merged-findings.json
  const mergedPath = join(dir, "merged-findings.json");
  await writeFile(mergedPath, JSON.stringify(merged, null, 2) + "\n", "utf-8");

  // Hook into existing attestation flow
  const hasCritical = merged.critical > 0;
  const hasHigh = merged.high > 0;
  const gateStatus = hasCritical || hasHigh ? "FAIL" : "PASS";
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
    gateStatus
  });

  return merged;
}

// 4. ensure_skill
// ---------------------------------------------------------------------------

export const EnsureSkillSchema = z.object({
  skillName: z.string().describe("Name of the skill to ensure is installed (e.g. 'threat-modeler')."),
  version: z.string().optional().describe("Required version; re-downloads if installed version differs.")
});

export async function ensureSkill(args: z.infer<typeof EnsureSkillSchema>): Promise<{
  downloaded: boolean;
  version: string;
  path: string;
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
    return { downloaded: false, version: installed.version, path: skillPath };
  }

  // Fetch manifest
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

  // Write skill
  mkdirSync(dirname(skillPath), { recursive: true });
  writeFileSync(skillPath, content, "utf-8");

  // Update version cache
  versions[skillName] = { version: entry.version, installedAt: new Date().toISOString(), path: skillPath };
  mkdirSync(dirname(SKILL_VERSIONS_PATH), { recursive: true });
  writeFileSync(SKILL_VERSIONS_PATH, JSON.stringify(versions, null, 2) + "\n", "utf-8");

  return { downloaded: true, version: entry.version, path: skillPath };
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

export const WriteAgentMemorySchema = z.object({
  agentName: z.string().describe("Agent name whose memory to update."),
  data: z.object({
    patterns: z.array(z.unknown()).optional(),
    falsePositives: z.array(z.unknown()).optional(),
    remediations: z.array(z.unknown()).optional(),
    intel: z.unknown().optional(),
    errors: z.array(z.unknown()).optional()
  })
});

export async function writeAgentMemory(args: z.infer<typeof WriteAgentMemorySchema>): Promise<{ written: string[] }> {
  const { agentName, data } = args;
  // CWE-22: validate agentName before using it as a directory component
  if (!SAFE_AGENT_NAME_RE.test(agentName)) {
    throw new Error(`Invalid agent name "${agentName}"`);
  }
  const dir = join(MEMORY_DIR, agentName);
  mkdirSync(dir, { recursive: true });

  const written: string[] = [];
  const append = (file: string, newItems: unknown[] | undefined, existing: unknown[]) => {
    if (!newItems?.length) return;
    const merged = [...existing, ...newItems];
    const p = join(dir, file);
    writeFileSync(p, JSON.stringify(merged, null, 2) + "\n", "utf-8");
    written.push(p);
  };

  append("patterns.json", data.patterns, readJson(join(dir, "patterns.json"), []));
  append("false-positives.json", data.falsePositives, readJson(join(dir, "false-positives.json"), []));
  append("remediations.json", data.remediations, readJson(join(dir, "remediations.json"), []));
  append("errors.json", data.errors, readJson(join(dir, "errors.json"), []));

  if (data.intel !== undefined) {
    const p = join(dir, "intel.json");
    writeFileSync(p, JSON.stringify({ ...data.intel as object, fetchedAt: new Date().toISOString() }, null, 2) + "\n", "utf-8");
    written.push(p);
  }

  return { written };
}

// 7. check_updates
// ---------------------------------------------------------------------------

export const CheckUpdatesSchema = z.object({
  currentMcpVersion: z.string().describe("Currently installed security-mcp version (from package.json).")
});

export async function checkUpdates(args: z.infer<typeof CheckUpdatesSchema>): Promise<UpdateCheckResult> {
  const { currentMcpVersion } = args;

  // Check npm for MCP update
  let latestMcpVersion: string | null = null;
  const npmRaw = await httpsGet(NPM_REGISTRY_URL, MAX_NPM_BYTES, 3000);
  if (npmRaw) {
    try {
      latestMcpVersion = (JSON.parse(npmRaw) as { version?: string }).version ?? null;
    } catch { /* ignore */ }
  }

  // Check skills manifest for skill updates
  const skillUpdates: UpdateCheckResult["skillUpdates"] = [];
  const versions = readJson<Record<string, { version: string }>>(SKILL_VERSIONS_PATH, {});
  const manifestRaw = await httpsGet(SKILLS_MANIFEST_URL, MAX_MANIFEST_BYTES, 3000);
  if (manifestRaw) {
    try {
      interface SkillEntry { version: string; }
      const manifest = JSON.parse(manifestRaw) as { skills: Record<string, SkillEntry> };
      for (const [name, entry] of Object.entries(manifest.skills)) {
        const current = versions[name]?.version;
        if (current && current !== entry.version) {
          skillUpdates.push({ skillName: name, currentVersion: current, latestVersion: entry.version });
        }
      }
    } catch { /* ignore */ }
  }

  const hasUpdate =
    (latestMcpVersion !== null && latestMcpVersion !== currentMcpVersion) ||
    skillUpdates.length > 0;

  let changelog = "";
  if (latestMcpVersion && latestMcpVersion !== currentMcpVersion) {
    changelog += `security-mcp: ${currentMcpVersion} → ${latestMcpVersion}\n`;
  }
  if (skillUpdates.length > 0) {
    changelog += `Skills with updates: ${skillUpdates.map((s) => s.skillName).join(", ")}`;
  }

  return { hasUpdate, currentMcpVersion, latestMcpVersion, skillUpdates, changelog };
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
    commands.push(`npm install -g security-mcp@${latestMcpVersion}`);
    commands.push(`security-mcp install`);
  }

  if (skillUpdates?.length) {
    commands.push(
      `# Re-download updated skills (handled automatically next time /ciso-orchestrator runs)`,
      ...skillUpdates.map((s) => `# skill: ${s.skillName} will be refreshed via orchestration.ensure_skill`)
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

export async function verifySkillCoverage(args: z.infer<typeof VerifySkillCoverageSchema>): Promise<{
  covered: string[];
  uncovered: string[];
  coveragePercent: number;
  status: "PASS" | "WARN";
}> {
  const dir = agentRunDir(args.agentRunId);
  const sectionsSeen = new Set<string>();

  let files: string[] = [];
  try {
    const entries = await readdir(dir);
    files = entries.filter((f) => f.endsWith(".json") && f !== "manifest.json");
  } catch { /* empty */ }

  for (const file of files) {
    try {
      const raw = await readFile(join(dir, file), "utf-8");
      const parsed = JSON.parse(raw) as Partial<AgentFindingsFile>;
      for (const s of (parsed.skillMdSectionsCovered ?? [])) sectionsSeen.add(s);
    } catch { /* skip */ }
  }

  const covered = SKILL_MD_SECTIONS.filter((s) => sectionsSeen.has(s));
  const uncovered = SKILL_MD_SECTIONS.filter((s) => !sectionsSeen.has(s));
  const coveragePercent = Math.round((covered.length / SKILL_MD_SECTIONS.length) * 100);

  return {
    covered,
    uncovered,
    coveragePercent,
    status: uncovered.length === 0 ? "PASS" : "WARN"
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
