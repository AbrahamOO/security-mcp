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

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
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
// HMAC key reader
// ---------------------------------------------------------------------------

const AUDIT_HMAC_MIN_KEY_BYTES = 32;

function getAuditHmacKey(): Buffer | null {
  const key = process.env.SECURITY_AUDIT_HMAC_KEY ?? process.env.SECURITY_POLICY_HMAC_KEY;
  if (!key) return null;
  const buf = Buffer.from(key, "hex");
  // Guard against invalid hex strings (Buffer.from silently drops non-hex chars,
  // potentially producing a 0-length key) and keys that are too short.
  if (buf.length < AUDIT_HMAC_MIN_KEY_BYTES) {
    throw new Error(
      `SECURITY_AUDIT_HMAC_KEY decoded to ${buf.length} bytes — minimum ${AUDIT_HMAC_MIN_KEY_BYTES} bytes required. ` +
      `Ensure the value is a valid hex-encoded string of at least ${AUDIT_HMAC_MIN_KEY_BYTES * 2} hex characters.`
    );
  }
  return buf;
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
  hmacSha256?: string;       // HMAC-SHA256 of the chain payload, present when signed
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
  warning?: string;
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

function hmacSha256(key: Buffer, data: string): string {
  return createHmac("sha256", key).update(data, "utf-8").digest("hex");
}

function hashFindings(findings: AgentFinding[]): string {
  return sha256(JSON.stringify(findings));
}

/**
 * Public helper: compute the canonical SHA-256 of a findings array exactly as
 * `attestAgent` does. Used by orchestration.mergeAgentFindings to verify that an
 * agent's findings file matches the hash that agent attested to — i.e. that the
 * inter-agent payload was not tampered with between attestation and merge.
 */
export function computeFindingsHash(findings: AgentFinding[]): string {
  return hashFindings(findings);
}

function buildChainPayload(record: Omit<AttestationRecord, "chainHash" | "hmacSha256">): string {
  return [
    record.agentRunId,
    record.agentName,
    record.completedAt,
    record.findingsHash,
    record.parentHash
  ].join("|");
}

function computeChainHash(record: Omit<AttestationRecord, "chainHash" | "hmacSha256">): { chainHash: string; hmacSha256?: string } {
  const payload = buildChainPayload(record);
  const key = getAuditHmacKey();
  if (key) {
    const mac = hmacSha256(key, payload);
    return { chainHash: mac, hmacSha256: mac };
  }
  return { chainHash: sha256(payload) };
}

// ---------------------------------------------------------------------------
// Atomic write helper
// ---------------------------------------------------------------------------

async function atomicWrite(targetPath: string, data: string): Promise<void> {
  const tmpPath = join(tmpdir(), `audit-chain-${Date.now()}-${randomBytes(8).toString("hex")}.tmp`);
  try {
    await writeFile(tmpPath, data, { encoding: "utf-8", mode: 0o600 });
    await rename(tmpPath, targetPath); // atomic on same filesystem
  } catch (e) {
    try { await unlink(tmpPath); } catch { /* ignore cleanup errors */ }
    throw e;
  }
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

async function ensureRunDir(agentRunId: string): Promise<void> {
  const dir = join(AGENT_RUNS_DIR, agentRunId);
  await mkdir(dir, { mode: 0o700, recursive: true });
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
  await atomicWrite(chainPath(chain.agentRunId), JSON.stringify(chain, null, 2) + "\n");
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
  const genesisPartial: Omit<AttestationRecord, "chainHash" | "hmacSha256"> = {
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

  const { chainHash, hmacSha256: mac } = computeChainHash(genesisPartial);
  const record: AttestationRecord = {
    ...genesisPartial,
    chainHash,
    ...(mac !== undefined ? { hmacSha256: mac } : {})
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

  const partial: Omit<AttestationRecord, "chainHash" | "hmacSha256"> = {
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

  const { chainHash, hmacSha256: mac } = computeChainHash(partial);
  const record: AttestationRecord = {
    ...partial,
    chainHash,
    ...(mac !== undefined ? { hmacSha256: mac } : {})
  };

  chain.links.push(record);
  await saveChain(chain);
  return record;
}

/**
 * Verify the integrity of the entire attestation chain for an agent run.
 * Recomputes every chain hash from scratch and checks parent linkage.
 * Returns `valid: true` only if every link is intact.
 *
 * HMAC behaviour:
 *  - Key present + links signed: verifies HMAC on every link.
 *  - Key absent + links signed: returns valid=false (cannot verify).
 *  - Key absent + links unsigned: returns valid=true with a warning.
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

  const hmacKey = getAuditHmacKey();
  const chainIsSigned = chain.links.some((l) => l.hmacSha256 !== undefined);

  // Key absent but chain is signed — cannot verify
  if (!hmacKey && chainIsSigned) {
    return {
      agentRunId,
      valid: false,
      linkCount: chain.links.length,
      verifiedAt,
      broken: {
        linkIndex: 0,
        agentName: chain.links[0].agentName,
        reason: "Chain is signed but SECURITY_AUDIT_HMAC_KEY is not set — cannot verify integrity."
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

    // Recompute chain hash (HMAC if key present, SHA-256 otherwise)
    const { chainHash: _stored, hmacSha256: _mac, ...rest } = link;
    const payload = buildChainPayload(rest);
    const recomputed = hmacKey ? hmacSha256(hmacKey, payload) : sha256(payload);
    // CWE-208: use constant-time comparison to prevent timing oracle on HMAC values
    const recomputedBuf = Buffer.from(recomputed, "hex");
    const storedBuf = Buffer.from(link.chainHash, "hex");
    const hashMismatch =
      recomputedBuf.length !== storedBuf.length ||
      !timingSafeEqual(recomputedBuf, storedBuf);
    if (hashMismatch) {
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

    // Verify parent linkage (CWE-208: constant-time comparison)
    if (i > 0) {
      const parentBuf = Buffer.from(link.parentHash, "hex");
      const prevChainBuf = Buffer.from(chain.links[i - 1].chainHash, "hex");
      const parentMismatch =
        parentBuf.length !== prevChainBuf.length ||
        !timingSafeEqual(parentBuf, prevChainBuf);
      if (parentMismatch) {
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
  }

  // Key absent and chain unsigned — warn but pass
  if (!hmacKey && !chainIsSigned) {
    return {
      agentRunId,
      valid: true,
      linkCount: chain.links.length,
      verifiedAt,
      warning: "Chain integrity is hash-only, not cryptographically signed. Set SECURITY_AUDIT_HMAC_KEY for tamper protection.",
      broken: null
    };
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
