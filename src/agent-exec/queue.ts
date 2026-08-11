/**
 * Work-queue construction: the scheduling DAG, per-agent scope prefilter, and the
 * cheap not-applicable determination.
 *
 * Everything here is derived from skills-manifest.json, which already carries `phase`
 * for all 91 skills, `subAgents` for the 11 leads, and `routingTriggers` /
 * `detectionSignals` / `edgeCaseDomains` for every entry — and is sha256-pinned, so the
 * relationships sit inside the integrity boundary. Parsing the prose in SKILL.md would
 * put a scheduling decision downstream of a sentence an LLM wrote, and that prose is
 * inconsistent anyway (cloud-infra-specialist says it "spawns cloud-specific sub-agents
 * based on the detected provider" and names none).
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import fg from "fast-glob";
import { getWorkspaceRoot } from "../repo/workspace.js";
import { TERMINAL_AGENT_STATUSES, type AgentName, type AgentRunManifest, type StackContext } from "../types/agent-run.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "../..");

export type SkillManifestEntry = {
  phase?: number;
  subAgents?: string[];
  routingTriggers?: string[];
  detectionSignals?: string[];
  edgeCaseDomains?: string[];
  description?: string;
};

let cachedSkills: Record<string, SkillManifestEntry> | null = null;

export function loadSkillsManifest(): Record<string, SkillManifestEntry> {
  if (cachedSkills) return cachedSkills;
  const raw = JSON.parse(readFileSync(join(PKG_ROOT, "skills-manifest.json"), "utf-8")) as {
    skills?: Record<string, SkillManifestEntry>;
  };
  cachedSkills = raw.skills ?? {};
  return cachedSkills;
}

// ---------------------------------------------------------------------------
// DAG
// ---------------------------------------------------------------------------

export type QueueTier = "lead" | "sub" | "specialist";

export type QueueNode = {
  agent: AgentName;
  phase: 1 | 2;
  tier: QueueTier;
  parent: AgentName | null;
  dependsOn: AgentName[];
  /** Wave index; agents in the same wave may run concurrently. */
  wave: number;
};

const PHASE1_LEAD_ORDER = [
  "threat-modeler", "appsec-code-auditor", "cloud-infra-specialist", "supply-chain-devsecops",
  "ai-llm-redteam", "mobile-security-specialist", "crypto-pki-specialist"
];

/**
 * Build the scheduling DAG for a roster.
 *
 * Edges:
 *  - a sub depends on its lead, so appsec-code-auditor produces its taint map before
 *    its four sub-agents run (in parallel with each other);
 *  - a phase-1 specialist depends on all phase-1 leads, since threat-model.json is its
 *    most useful input;
 *  - every phase-2 agent depends on every phase-1 roster agent. pentest-team/SKILL.md
 *    states it "reads threat-model.json from Phase 1 as attack brief... Runs in Phase 2
 *    after all Phase 1 agents complete", so a lead-only gate would violate its contract.
 */
export function buildQueue(roster: AgentName[]): QueueNode[] {
  const skills = loadSkillsManifest();
  const inRoster = new Set(roster);

  const parentOf = new Map<AgentName, AgentName>();
  const leads = new Set<AgentName>();
  for (const [name, entry] of Object.entries(skills)) {
    const subs = entry.subAgents ?? [];
    if (subs.length === 0) continue;
    if (!inRoster.has(name as AgentName)) continue;
    // Phase-0 orchestrator personas (ciso-orchestrator, senior-security-engineer) are
    // the host-facing entry points, not schedulable specialists.
    if ((entry.phase ?? 1) === 0) continue;
    leads.add(name as AgentName);
    for (const sub of subs) {
      if (inRoster.has(sub as AgentName)) parentOf.set(sub as AgentName, name as AgentName);
    }
  }

  const phaseOf = (a: AgentName): 1 | 2 => {
    const p = skills[a]?.phase;
    return p === 2 ? 2 : 1;
  };

  const phase1Agents = roster.filter((a) => phaseOf(a) === 1);
  const phase1Leads = roster.filter((a) => leads.has(a) && phaseOf(a) === 1);

  const nodes: QueueNode[] = roster.map((agent) => {
    const phase = phaseOf(agent);
    const parent = parentOf.get(agent) ?? null;
    const tier: QueueTier = leads.has(agent) ? "lead" : parent ? "sub" : "specialist";

    let dependsOn: AgentName[] = [];
    let wave: number;
    if (phase === 1) {
      if (tier === "lead") { dependsOn = []; wave = 0; }
      else if (tier === "sub") { dependsOn = [parent as AgentName]; wave = 1; }
      else { dependsOn = phase1Leads; wave = 2; }
    } else if (tier === "lead") { dependsOn = phase1Agents; wave = 3; }
    else if (tier === "sub") { dependsOn = [parent as AgentName, ...phase1Agents]; wave = 4; }
    else { dependsOn = phase1Agents; wave = 5; }

    return { agent, phase, tier, parent, dependsOn, wave };
  });

  return nodes.sort((a, b) => {
    if (a.wave !== b.wave) return a.wave - b.wave;
    // Within a wave, dispatch the most consequential agents first so their results land
    // before anything else if the run is cancelled or throttled.
    const ai = PHASE1_LEAD_ORDER.indexOf(a.agent), bi = PHASE1_LEAD_ORDER.indexOf(b.agent);
    if (ai !== bi) return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    return a.agent.localeCompare(b.agent);
  });
}

/**
 * Agents whose dependencies are all terminal and which are still pending.
 *
 * A `failed` record that updateAgentStatus requeued to `pending` is deliberately NOT
 * terminal: a phase-2 pentest must not run against a threat model that is currently
 * being regenerated.
 */
export function readyAgents(nodes: QueueNode[], manifest: AgentRunManifest): AgentName[] {
  const statusOf = (a: AgentName): string | undefined => manifest.agents[a]?.status;
  const isTerminal = (a: AgentName): boolean => {
    const s = statusOf(a);
    if (s === undefined) return true; // not in the roster at all: cannot block anyone
    if (s === "failed") return manifest.agents[a]?.escalationRequired === true;
    return TERMINAL_AGENT_STATUSES.includes(s as never);
  };
  return nodes
    .filter((n) => statusOf(n.agent) === "pending")
    .filter((n) => n.dependsOn.every(isTerminal))
    .map((n) => n.agent);
}

/** Sub-agents the supervisor will schedule after `lead`, restricted to the roster. */
export function subAgentsOf(lead: AgentName, roster: AgentName[]): string[] {
  const subs = loadSkillsManifest()[lead]?.subAgents ?? [];
  const inRoster = new Set(roster);
  return subs.filter((s) => inRoster.has(s as AgentName));
}

// ---------------------------------------------------------------------------
// Scope prefilter
// ---------------------------------------------------------------------------

const CODE_GLOB = ["**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,rb,java,kt,kts,swift,cs,php,rs,scala,c,cc,cpp,h,hpp}"];
const CONFIG_GLOB = ["**/*.{json,yaml,yml,toml,tf,tfvars,ini,conf,env,properties}", "**/Dockerfile*", "**/*.gradle"];
const IGNORE = [
  "**/node_modules/**", "**/dist/**", "**/build/**", "**/.git/**", "**/vendor/**",
  "**/.next/**", "**/coverage/**", "**/*.min.js", "**/.mcp/**"
];

/** Keyword sets derived per agent from the manifest's own routing metadata. */
export function agentKeywords(agent: AgentName): string[] {
  const e = loadSkillsManifest()[agent];
  if (!e) return [];
  const raw = [...(e.routingTriggers ?? []), ...(e.detectionSignals ?? []), ...(e.edgeCaseDomains ?? [])];
  const words = new Set<string>();
  for (const item of raw) {
    if (item === "*") continue; // a wildcard trigger carries no discriminating signal
    for (const w of item.toLowerCase().split(/[^a-z0-9+#.]+/)) {
      if (w.length >= 3) words.add(w);
    }
  }
  return Array.from(words);
}

export type RepoIndex = { files: string[]; lowerNames: string[] };

export async function buildRepoIndex(): Promise<RepoIndex> {
  const files = await fg([...CODE_GLOB, ...CONFIG_GLOB], {
    cwd: getWorkspaceRoot(), ignore: IGNORE, onlyFiles: true, followSymbolicLinks: false,
    dot: false, suppressErrors: true
  });
  files.sort();
  return { files, lowerNames: files.map((f) => f.toLowerCase()) };
}

/**
 * Candidate files for one agent, by matching its manifest keywords against paths.
 *
 * A starting point, not a boundary — the prompt says so explicitly. Handing every agent
 * the whole tree wastes most of its turns re-deriving what is relevant.
 */
export function prefilterScope(agent: AgentName, index: RepoIndex, limit = 300): string[] {
  const keywords = agentKeywords(agent);
  if (keywords.length === 0) return [];
  const hits: string[] = [];
  for (let i = 0; i < index.files.length && hits.length < limit; i++) {
    const name = index.lowerNames[i] ?? "";
    if (keywords.some((k) => name.includes(k))) hits.push(index.files[i] as string);
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Not-applicable determination
// ---------------------------------------------------------------------------

export type NaVerdict = { notApplicable: boolean; signalsSearched: string[]; matched: string[]; rationale: string };

/**
 * Domains that are structurally absent-or-present, where running an advanced-tier
 * session to conclude "no Kubernetes here" is pure waste. Keyed on StackContext flags
 * the caller already detected, never on guesswork.
 */
const DOMAIN_GATES: { agents: string[]; requires: (s: StackContext) => boolean; domain: string }[] = [
  {
    domain: "AI/LLM",
    agents: ["ai-llm-redteam", "prompt-injection-specialist", "model-extraction-attacker",
      "rag-poisoning-specialist", "agentic-loop-exploiter", "ai-model-supply-chain-agent"],
    requires: (s) => s.hasAI
  },
  {
    domain: "mobile",
    agents: ["mobile-security-specialist", "ios-security-auditor", "android-penetration-tester",
      "mobile-api-network-attacker"],
    requires: (s) => s.hasMobile
  },
  {
    domain: "cloud",
    agents: ["aws-penetration-tester", "gcp-penetration-tester", "azure-penetration-tester"],
    requires: (s) => s.cloudProvider.length > 0
  },
  {
    domain: "payments",
    agents: ["pci-dss-specialist"],
    requires: (s) => s.hasPayments
  }
];

/**
 * Decide cheaply whether an agent's domain is absent.
 *
 * This is NOT skipping. It returns evidence (which signals were searched, what matched)
 * and the caller records `completed_na`, a terminal state the completion gate accepts
 * and `pending` is not. Several skills mandate exactly this behaviour for themselves —
 * ai-llm-redteam's SKILL.md says "If no AI/LLM stack detected, reports N/A immediately".
 */
export function determineNotApplicable(
  agent: AgentName, stack: StackContext, index: RepoIndex
): NaVerdict {
  const gate = DOMAIN_GATES.find((g) => g.agents.includes(agent));
  if (!gate) return { notApplicable: false, signalsSearched: [], matched: [], rationale: "" };

  const keywords = agentKeywords(agent);
  const matched: string[] = [];
  for (const k of keywords) {
    if (index.lowerNames.some((n) => n.includes(k))) matched.push(k);
    if (matched.length >= 10) break;
  }

  // Belt and braces: the stack flag AND a filename sweep must both come up empty. A
  // stale or under-detected StackContext must not silently suppress a real domain.
  if (gate.requires(stack) || matched.length > 0) {
    return { notApplicable: false, signalsSearched: keywords.slice(0, 50), matched, rationale: "" };
  }

  return {
    notApplicable: true,
    signalsSearched: keywords.slice(0, 50),
    matched: [],
    rationale:
      `No ${gate.domain} surface detected: stack detection reported none, and no file path ` +
      `among ${index.files.length} scanned matched any of ${keywords.length} ${gate.domain} signals.`
  };
}
