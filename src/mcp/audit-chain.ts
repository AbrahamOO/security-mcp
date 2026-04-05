/**
 * Audit Chain — per-agent attestation with SHA-256 hash chaining.
 *
 * Each agent that completes work on an agent run produces an AttestationRecord
 * that:
 *   1. Hashes the agent's findings output
 *   2. Includes the hash of the previous link in the chain (parent hash)
 *   3. Signs both together to produce a chain hash
 *
 * This creates a tamper-evident audit log: if any prior attestation is modified,
 * all subsequent chain hashes become invalid and `verifyChain()` will detect it.
 *
 * Chain is persisted to .mcp/agent-runs/{agentRunId}/attestation-chain.json.
 *
 * The genesis block (link 0) contains only the agentRunId and a timestamp —
 * its parent hash is all-zeros.
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { AgentFinding } from "../types/agent-run.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AGENT_RUNS_DIR = join(".mcp", "agent-runs");
const GENESIS_PARENT_HASH = "0".repeat(64);

// CWE-22: agentRunId used as a path component — must be the 32-char hex digest
// produced by orchestration.createAgentRun, or a UUID (36-char with hyphens).
const SAFE_AGENT_RUN_ID_RE = /^[0-9a-f]{32}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function validateAgentRunId(agentRunId: string): void {
  if (!agentRunId || !SAFE_AGENT_RUN_ID_RE.test(agentRunId)) {
    throw new Error(`Invalid agentRunId "${agentRunId}" — must be a 32-char hex digest or UUID`);
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AttestationRecord = {
  link: number;
  agentRunId: string;
  agentName: string;
  completedAt: string;
  findingsHash: string;      // SHA-256 of the serialized findings array
  parentHash: string;        // chain hash of the previous link (or genesis zeros)
  chainHash: string;         // SHA-256(agentRunId + agentName + completedAt + findingsHash + parentHash)
  findingCount: number;
  criticalCount: number;
  highCount: number;
};

export type AttestationChain = {
  agentRunId: string;
  createdAt: string;
  updatedAt: string;
  links: AttestationRecord[];
};

export type ChainVerification = {
  agentRunId: string;
  valid: boolean;
  linkCount: number;
  verifiedAt: string;
  broken: null | {
    linkIndex: number;
    agentName: string;
    reason: string;
  };
};

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

function sha256(data: string): string {
  return createHash("sha256").update(data, "utf-8").digest("hex");
}

function hashFindings(findings: AgentFinding[]): string {
  return sha256(JSON.stringify(findings));
}

function computeChainHash(record: Omit<AttestationRecord, "chainHash">): string {
  const payload = [
    record.agentRunId,
    record.agentName,
    record.completedAt,
    record.findingsHash,
    record.parentHash
  ].join("|");
  return sha256(payload);
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

async function ensureRunDir(agentRunId: string): Promise<void> {
  const dir = join(AGENT_RUNS_DIR, agentRunId);
  await mkdir(dir, { recursive: true });
}

function chainPath(agentRunId: string): string {
  return join(AGENT_RUNS_DIR, agentRunId, "attestation-chain.json");
}

async function loadChain(agentRunId: string): Promise<AttestationChain> {
  validateAgentRunId(agentRunId);  // CWE-22: guard before any path operation
  try {
    const raw = await readFile(chainPath(agentRunId), "utf-8");
    return JSON.parse(raw) as AttestationChain;
  } catch {
    const now = new Date().toISOString();
    return { agentRunId, createdAt: now, updatedAt: now, links: [] };
  }
}

async function saveChain(chain: AttestationChain): Promise<void> {
  await ensureRunDir(chain.agentRunId);
  chain.updatedAt = new Date().toISOString();
  await writeFile(chainPath(chain.agentRunId), JSON.stringify(chain, null, 2) + "\n", "utf-8");
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/**
 * Initialise the attestation chain for a new agent run.
 * Creates the genesis block (link 0) with all-zero parent hash.
 * Idempotent — returns the existing chain if already initialised.
 */
export async function initChain(agentRunId: string): Promise<AttestationChain> {
  const chain = await loadChain(agentRunId);
  if (chain.links.length > 0) return chain;  // already initialised

  const completedAt = new Date().toISOString();
  const genesis: Omit<AttestationRecord, "chainHash"> = {
    link: 0,
    agentRunId,
    agentName: "genesis",
    completedAt,
    findingsHash: sha256("genesis:" + agentRunId),
    parentHash: GENESIS_PARENT_HASH,
    findingCount: 0,
    criticalCount: 0,
    highCount: 0
  };

  const record: AttestationRecord = {
    ...genesis,
    chainHash: computeChainHash(genesis)
  };

  chain.links.push(record);
  await saveChain(chain);
  return chain;
}

/**
 * Append a new attestation to the chain for the named agent.
 * The parent hash is taken from the last link already in the chain.
 * If the chain hasn't been initialised, `initChain` is called first.
 */
export async function attestAgent(params: {
  agentRunId: string;
  agentName: string;
  findings: AgentFinding[];
}): Promise<AttestationRecord> {
  const chain = await loadChain(params.agentRunId);
  if (chain.links.length === 0) {
    await initChain(params.agentRunId);
    return attestAgent(params);  // retry after init
  }

  // length === 0 is already guarded above; this satisfies TypeScript narrowing
  const parent = chain.links.at(-1) ?? chain.links[0];
  const completedAt = new Date().toISOString();

  const partial: Omit<AttestationRecord, "chainHash"> = {
    link: parent.link + 1,
    agentRunId: params.agentRunId,
    agentName: params.agentName,
    completedAt,
    findingsHash: hashFindings(params.findings),
    parentHash: parent.chainHash,
    findingCount: params.findings.length,
    criticalCount: params.findings.filter((f) => f.severity === "CRITICAL").length,
    highCount: params.findings.filter((f) => f.severity === "HIGH").length
  };

  const record: AttestationRecord = {
    ...partial,
    chainHash: computeChainHash(partial)
  };

  chain.links.push(record);
  await saveChain(chain);
  return record;
}

/**
 * Verify the integrity of the entire attestation chain for an agent run.
 * Recomputes every chain hash from scratch and checks parent linkage.
 * Returns `valid: true` only if every link is intact.
 */
export async function verifyChain(agentRunId: string): Promise<ChainVerification> {
  const chain = await loadChain(agentRunId);
  const verifiedAt = new Date().toISOString();

  if (chain.links.length === 0) {
    return {
      agentRunId,
      valid: false,
      linkCount: 0,
      verifiedAt,
      broken: {
        linkIndex: 0,
        agentName: "genesis",
        reason: "Chain is empty — no genesis block found."
      }
    };
  }

  // Verify genesis parent hash
  if (chain.links[0].parentHash !== GENESIS_PARENT_HASH) {
    return {
      agentRunId,
      valid: false,
      linkCount: chain.links.length,
      verifiedAt,
      broken: {
        linkIndex: 0,
        agentName: chain.links[0].agentName,
        reason: "Genesis block has non-zero parent hash — chain has been tampered."
      }
    };
  }

  for (let i = 0; i < chain.links.length; i++) {
    const link = chain.links[i];

    // Recompute chain hash
    const { chainHash: _stored, ...rest } = link;
    const recomputed = computeChainHash(rest);
    if (recomputed !== link.chainHash) {
      return {
        agentRunId,
        valid: false,
        linkCount: chain.links.length,
        verifiedAt,
        broken: {
          linkIndex: i,
          agentName: link.agentName,
          reason: `Chain hash mismatch at link ${i} — findings or metadata may have been modified.`
        }
      };
    }

    // Verify parent linkage
    if (i > 0 && link.parentHash !== chain.links[i - 1].chainHash) {
      return {
        agentRunId,
        valid: false,
        linkCount: chain.links.length,
        verifiedAt,
        broken: {
          linkIndex: i,
          agentName: link.agentName,
          reason: `Parent hash at link ${i} does not match chain hash of link ${i - 1} — chain is broken.`
        }
      };
    }
  }

  return {
    agentRunId,
    valid: true,
    linkCount: chain.links.length,
    verifiedAt,
    broken: null
  };
}

/**
 * Read the attestation chain for inspection (without verification).
 */
export async function getChain(agentRunId: string): Promise<AttestationChain> {
  return loadChain(agentRunId);
}

// ---------------------------------------------------------------------------
// Zod schemas for MCP tool params
// ---------------------------------------------------------------------------

export const InitChainParams = {
  agentRunId: z.string().min(1).max(128).describe("Agent run ID to initialise the attestation chain for.")
};
export const InitChainSchema = z.object(InitChainParams);

export const AttestAgentParams = {
  agentRunId: z.string().min(1).max(128).describe("Agent run ID this attestation belongs to."),
  agentName: z.string().min(1).max(128).describe("Name of the agent completing its work."),
  findings: z.array(z.object({
    id: z.string(),
    title: z.string(),
    severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    remediated: z.boolean(),
    requiredActions: z.array(z.string())
  }).passthrough()).describe("Agent findings to attest. Must match AgentFinding shape.")
};
export const AttestAgentSchema = z.object(AttestAgentParams);

export const VerifyChainParams = {
  agentRunId: z.string().min(1).max(128).describe("Agent run ID whose chain should be verified.")
};
export const VerifyChainSchema = z.object(VerifyChainParams);

export const GetChainParams = {
  agentRunId: z.string().min(1).max(128).describe("Agent run ID to retrieve the attestation chain for.")
};
export const GetChainSchema = z.object(GetChainParams);
