/**
 * Pure logic behind security.fortify: turns a free-text "fortify X" / "lock down X"
 * request into (a) a concrete review scope and (b) a specialist agent subset, with no
 * fixed feature-name table. Users name arbitrary surfaces ("forms", "payment flow",
 * "admin panel", ...) — an open-ended set — so agent selection is split into two axes:
 * a generic core app-security team dispatched for any named surface, plus additions
 * gated on a small, closed set of genuine technology-domain signals (cloud/crypto/
 * mobile/AI/supply-chain), not on the feature's name.
 */

import { dirname } from "node:path";
import { searchRepo, type RepoMatch } from "../repo/search.js";
import type { AgentName, StackContext } from "../types/agent-run.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type FortifyMode = "recent_changes" | "folder_by_folder" | "file_by_file";

export type FortifyScopeOverrides = {
  mode?: FortifyMode;
  targets?: string[];
  baseRef?: string;
  headRef?: string;
};

export type FortifyScope = {
  mode: FortifyMode;
  targets: string[];
  baseRef?: string;
  headRef?: string;
  resolvedFrom: "override" | "whole_codebase" | "search" | "search_empty_fallback";
  searchTerms: string[];
  notes: string[];
};

export type FortifySelection = {
  wholeCodebase: boolean;
  agents: AgentName[];
  domainsMatched: string[];
  notes: string[];
};

type SearchFn = (query: string) => Promise<RepoMatch[]>;

// ---------------------------------------------------------------------------
// Whole-codebase / stopword handling
// ---------------------------------------------------------------------------

// Generic verbs/fillers that carry no surface-identifying meaning. Stripped before
// deciding whole-codebase vs. a named surface, and before extracting search terms.
const FORTIFY_STOPWORDS = new Set([
  "lock", "locks", "locking", "down", "secure", "securing", "harden", "hardening",
  "fortify", "fortifying", "protect", "protecting", "make", "highest", "level",
  "grade", "production", "enterprise", "my", "our", "the", "of", "for", "to", "on",
  "and", "with", "at", "a", "an", "is", "are", "be", "please", "can", "you", "up"
]);

const WHOLE_CODEBASE_WORDS = new Set([
  "whole", "entire", "everything", "codebase", "code", "base", "repo", "repository",
  "project", "app", "application", "site", "website"
]);

function tokenize(target: string): string[] {
  return target
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .map((w) => w.trim())
    .filter(Boolean);
}

function significantWords(target: string): string[] {
  return tokenize(target).filter((w) => !FORTIFY_STOPWORDS.has(w));
}

export function isWholeCodebaseTarget(target: string): boolean {
  const words = significantWords(target);
  if (words.length === 0) return true;
  return words.every((w) => WHOLE_CODEBASE_WORDS.has(w));
}

/**
 * Generic word extraction for repo search — not a feature-name lookup. Any phrasing
 * ("payment flow", "file uploads", "admin panel") reduces to its own significant
 * words, so scope resolution generalizes without a maintained category list.
 */
export function extractSearchTerms(target: string): string[] {
  const seen = new Set<string>();
  const terms: string[] = [];
  for (const w of significantWords(target)) {
    if (w.length < 3) continue;
    if (WHOLE_CODEBASE_WORDS.has(w)) continue;
    if (seen.has(w)) continue;
    seen.add(w);
    terms.push(w);
  }
  return terms;
}

// ---------------------------------------------------------------------------
// Agent selection: generic core team + domain-signal additions
// ---------------------------------------------------------------------------

// Dispatched for ANY named (non-whole-codebase) surface, regardless of what it's
// called — these attack classes (injection, auth/session, business logic, race
// conditions, serialization, privacy) apply to essentially every feature.
export const CORE_TARGETED_TEAM: AgentName[] = [
  "threat-modeler",
  "attack-navigator",
  "appsec-code-auditor",
  "injection-specialist",
  "auth-session-hacker",
  "business-logic-attacker",
  "logic-race-fuzzer",
  "serialization-memory-attacker",
  "privacy-flow-analyst"
];

type DomainRow = {
  domain: string;
  keywords: string[];
  agents: AgentName[];
};

// A small, closed set of genuine technology domains — unlike arbitrary product
// feature names, these legitimately need specialists no generic scan covers.
const DOMAIN_SIGNALS: DomainRow[] = [
  {
    domain: "cloud",
    keywords: ["cloud", "aws", "gcp", "azure", "terraform", "iam", "kubernetes", "k8s", "infra", "infrastructure"],
    agents: ["cloud-infra-specialist"]
  },
  {
    domain: "crypto",
    keywords: ["encryption", "encrypt", "tls", "ssl", "certificate", "kms", "jwt", "hash", "hashing"],
    agents: [
      "crypto-pki-specialist",
      "tls-certificate-auditor",
      "algorithm-implementation-reviewer",
      "key-management-lifecycle-analyst"
    ]
  },
  {
    domain: "supply-chain",
    keywords: ["dependency", "dependencies", "npm", "pip", "ci", "pipeline", "sbom", "workflow", "build"],
    agents: [
      "supply-chain-devsecops",
      "dependency-confusion-attacker",
      "cicd-pipeline-hijacker",
      "artifact-integrity-analyst"
    ]
  },
  {
    domain: "ai-llm",
    keywords: ["ai", "llm", "prompt", "rag", "agent", "chatbot", "embedding", "model"],
    agents: [
      "ai-llm-redteam",
      "prompt-injection-specialist",
      "model-extraction-attacker",
      "rag-poisoning-specialist",
      "agentic-loop-exploiter"
    ]
  },
  {
    domain: "mobile",
    keywords: ["mobile", "ios", "android", "flutter", "swift", "kotlin"],
    agents: [
      "mobile-security-specialist",
      "ios-security-auditor",
      "android-penetration-tester",
      "mobile-api-network-attacker"
    ]
  }
];

function domainStackSignal(domain: string, stackContext: StackContext): boolean {
  switch (domain) {
    case "cloud":
      return stackContext.cloudProvider.some((p) => p !== "unknown");
    case "ai-llm":
      return stackContext.hasAI;
    case "mobile":
      return stackContext.hasMobile;
    default:
      return false;
  }
}

function cloudPentesters(target: string, stackContext: StackContext): AgentName[] {
  const t = target.toLowerCase();
  const matched: AgentName[] = [];
  const wantsAWS = t.includes("aws") || stackContext.cloudProvider.includes("aws");
  const wantsGCP = t.includes("gcp") || stackContext.cloudProvider.includes("gcp");
  const wantsAzure = t.includes("azure") || stackContext.cloudProvider.includes("azure");
  if (wantsAWS) matched.push("aws-penetration-tester");
  if (wantsGCP) matched.push("gcp-penetration-tester");
  if (wantsAzure) matched.push("azure-penetration-tester");
  return matched;
}

function dedupe(names: AgentName[]): AgentName[] {
  const seen = new Set<AgentName>();
  const out: AgentName[] = [];
  for (const n of names) {
    if (seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

export function selectFortifyAgents(
  target: string,
  stackContext: StackContext,
  buildInitialAgentNames: (stackContext: StackContext) => AgentName[]
): FortifySelection {
  if (isWholeCodebaseTarget(target)) {
    return {
      wholeCodebase: true,
      agents: buildInitialAgentNames(stackContext),
      domainsMatched: [],
      notes: []
    };
  }

  const targetLower = target.toLowerCase();
  const words = new Set(significantWords(target));
  let agents: AgentName[] = [...CORE_TARGETED_TEAM];
  const domainsMatched: string[] = [];

  for (const row of DOMAIN_SIGNALS) {
    const keywordHit = row.keywords.some((kw) => (kw.includes(" ") ? targetLower.includes(kw) : words.has(kw)));
    const stackHit = domainStackSignal(row.domain, stackContext);
    if (!keywordHit && !stackHit) continue;
    domainsMatched.push(row.domain);
    agents.push(...row.agents);
    if (row.domain === "cloud") {
      agents.push(...cloudPentesters(target, stackContext));
    }
  }

  agents = dedupe(agents);

  return {
    wholeCodebase: false,
    agents,
    domainsMatched,
    notes: []
  };
}

// ---------------------------------------------------------------------------
// Scope resolution
// ---------------------------------------------------------------------------

const FILE_BY_FILE_THRESHOLD = 12;
const MAX_FILES = 200;

// eslint-disable-next-line no-control-regex -- intentional: neutralize control bytes in untrusted repo-derived paths
const CONTROL_CHARS_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

function sanitizeTargetPath(p: string): string {
  return p.replace(CONTROL_CHARS_RE, "").replace(/[\r\n\t]+/g, " ").slice(0, 1000);
}

const defaultSearchFn: SearchFn = (query) => searchRepo({ query, isRegex: false, maxMatches: 200 });

export async function resolveFortifyScope(
  target: string,
  overrides: FortifyScopeOverrides = {},
  searchFn: SearchFn = defaultSearchFn
): Promise<FortifyScope> {
  if (overrides.mode) {
    return {
      mode: overrides.mode,
      targets: (overrides.targets ?? []).map(sanitizeTargetPath),
      baseRef: overrides.baseRef,
      headRef: overrides.headRef,
      resolvedFrom: "override",
      searchTerms: [],
      notes: []
    };
  }

  if (isWholeCodebaseTarget(target)) {
    return {
      mode: "recent_changes",
      targets: [],
      baseRef: overrides.baseRef,
      headRef: overrides.headRef,
      resolvedFrom: "whole_codebase",
      searchTerms: [],
      notes: []
    };
  }

  const searchTerms = extractSearchTerms(target);
  const files = new Set<string>();
  for (const term of searchTerms) {
    const matches = await searchFn(term);
    for (const m of matches) {
      if (files.size >= MAX_FILES) break;
      files.add(sanitizeTargetPath(m.file));
    }
  }

  if (files.size === 0) {
    return {
      mode: "recent_changes",
      targets: [],
      baseRef: overrides.baseRef,
      headRef: overrides.headRef,
      resolvedFrom: "search_empty_fallback",
      searchTerms,
      notes: [
        `No files matched the named surface ("${searchTerms.join(", ")}") — falling back to ` +
          "recent_changes scope. Widen the search or pass explicit targets if this misses the intended surface."
      ]
    };
  }

  const fileList = [...files];
  if (fileList.length <= FILE_BY_FILE_THRESHOLD) {
    return {
      mode: "file_by_file",
      targets: fileList,
      baseRef: overrides.baseRef,
      headRef: overrides.headRef,
      resolvedFrom: "search",
      searchTerms,
      notes: []
    };
  }

  // dirname() of a root-level file is "." — including it as a "folder" target would
  // mean "scan the entire repo root", defeating the point of narrowing scope. Split
  // root-level matches out instead of collapsing them into a whole-tree folder.
  const rootFiles = fileList.filter((f) => dirname(f) === ".");
  const folders = [...new Set(fileList.filter((f) => dirname(f) !== ".").map((f) => dirname(f)))];

  if (folders.length === 0) {
    // Every match was a root-level file — file_by_file on just those files is more
    // precise than folder_by_folder on ".".
    return {
      mode: "file_by_file",
      targets: rootFiles,
      baseRef: overrides.baseRef,
      headRef: overrides.headRef,
      resolvedFrom: "search",
      searchTerms,
      notes: []
    };
  }

  return {
    mode: "folder_by_folder",
    targets: folders,
    baseRef: overrides.baseRef,
    headRef: overrides.headRef,
    resolvedFrom: "search",
    searchTerms,
    notes: rootFiles.length > 0
      ? [
          `${rootFiles.length} matched file(s) at the repo root (${rootFiles.join(", ")}) were not ` +
            "included in the folder scope above — pass explicit targets if they need to be scanned too."
        ]
      : []
  };
}
