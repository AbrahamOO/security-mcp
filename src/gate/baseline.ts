/**
 * Baseline regression tracking.
 * Saves and compares gate results to detect security regressions.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { createHmac, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { GateResult, Finding } from "./result.js";

// ---------------------------------------------------------------------------
// HMAC integrity helpers — TM-013 fix
// ---------------------------------------------------------------------------

// HMAC-SHA256 requires at least 32 bytes (256 bits) per NIST SP 800-107 §5.3.4.
const HMAC_MIN_KEY_BYTES = 32;

/**
 * Returns the HMAC key from env, or null if not configured.
 * Throws if the key is present but too short.
 */
function getHmacKey(): string | null {
  const key = process.env["SECURITY_POLICY_HMAC_KEY"];
  if (!key) return null;
  if (Buffer.byteLength(key, "utf-8") < HMAC_MIN_KEY_BYTES) {
    throw new Error(
      `SECURITY_POLICY_HMAC_KEY is too short (${Buffer.byteLength(key, "utf-8")} bytes). ` +
      `Provide at least ${HMAC_MIN_KEY_BYTES} bytes — generate one with: ` +
      `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
    );
  }
  return key;
}

function signBaseline(json: string, key: string): string {
  return createHmac("sha256", key).update(json, "utf-8").digest("hex");
}

function verifyBaselineHmac(json: string, stored: string, key: string): boolean {
  const expected = createHmac("sha256", key).update(json, "utf-8").digest("hex");
  const storedBuf   = Buffer.from(stored,   "hex");
  const expectedBuf = Buffer.from(expected, "hex");
  if (storedBuf.length !== expectedBuf.length) return false;
  return timingSafeEqual(storedBuf, expectedBuf);
}

const execFileAsync = promisify(execFile);
const BASELINE_DIR = join(process.cwd(), ".mcp", "baselines");

async function ensureDir(dir: string): Promise<void> {
  try {
    await mkdir(dir, { recursive: true });
  } catch { /* ignore */ }
}

export type ControlRegression = {
  controlId: string;
  was: "satisfied";
  now: "missing";
};

export type ControlImprovement = {
  controlId: string;
  was: "missing";
  now: "satisfied";
};

export type BaselineDiff = {
  regressions: ControlRegression[];
  improvements: ControlImprovement[];
  newFindings: Finding[];
  resolvedFindings: Finding[];
  coverageChange: number;
};

/**
 * Gets the current git commit hash. Returns "unknown" if git is unavailable.
 */
export async function getCommitHash(): Promise<string> {
  try {
    const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], {
      cwd: process.cwd(),
      timeout: 5000
    });
    return stdout.trim() || "unknown";
  } catch {
    return "unknown";
  }
}

/**
 * Saves a gate result as baseline for the given commit hash.
 * Also updates the latest baseline copy.
 *
 * TM-013 fix: When SECURITY_POLICY_HMAC_KEY is set, the serialised payload is
 * HMAC-SHA256 signed and the signature is stored in the envelope. Unsigned
 * writes are still permitted when no key is configured (graceful degradation),
 * but loadBaseline will reject a previously-signed file whose signature no
 * longer matches (tamper detection).
 */
export async function saveBaseline(
  runId: string,
  result: GateResult,
  commitHash: string
): Promise<void> {
  await ensureDir(BASELINE_DIR);

  const payload = { runId, commitHash, savedAt: new Date().toISOString(), result };
  const json = JSON.stringify(payload, null, 2);

  // Sign if a key is available
  const hmacKey = getHmacKey();
  const envelope = hmacKey
    ? JSON.stringify({ payload, hmacSha256: signBaseline(json, hmacKey) }, null, 2)
    : json;

  // Write to temp file then rename (atomic)
  const safehash = commitHash.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
  const targetPath = join(BASELINE_DIR, `${safehash}.json`);
  const latestPath = join(BASELINE_DIR, "latest.json");
  const tmpPath = `${targetPath}.tmp`;

  try {
    await writeFile(tmpPath, envelope, "utf-8");
    await rename(tmpPath, targetPath);
  } catch {
    // fallback: write directly
    await writeFile(targetPath, envelope, "utf-8").catch(() => { /* ignore */ });
  }

  // Update latest (best-effort atomic)
  const latestTmp = `${latestPath}.tmp`;
  try {
    await writeFile(latestTmp, envelope, "utf-8");
    await rename(latestTmp, latestPath);
  } catch {
    await writeFile(latestPath, envelope, "utf-8").catch(() => { /* ignore */ });
  }
}

interface BaselinePayload {
  runId: string;
  commitHash: string;
  savedAt: string;
  result: GateResult;
}

interface BaselineEnvelope {
  payload: BaselinePayload;
  hmacSha256: string;
}

/**
 * Loads a baseline by commit hash, or the latest baseline if no hash given.
 * Returns null if no baseline exists or it's corrupted.
 *
 * TM-013 fix: If the file is stored in the HMAC envelope format AND
 * SECURITY_POLICY_HMAC_KEY is configured, the HMAC is verified before the
 * payload is returned. A tampered baseline (missing or wrong HMAC) is
 * rejected — the gate will run without a baseline rather than trust forged data.
 */
export async function loadBaseline(commitHash?: string): Promise<GateResult | null> {
  await ensureDir(BASELINE_DIR);

  let filePath: string;
  if (commitHash) {
    const safehash = commitHash.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
    filePath = join(BASELINE_DIR, `${safehash}.json`);
  } else {
    filePath = join(BASELINE_DIR, "latest.json");
  }

  try {
    const raw = await readFile(filePath, "utf-8");
    const top = JSON.parse(raw) as Record<string, unknown>;

    // Detect envelope format (has both "payload" and "hmacSha256")
    if ("payload" in top && "hmacSha256" in top) {
      const envelope = top as unknown as BaselineEnvelope;
      const hmacKey = getHmacKey();
      if (hmacKey) {
        // Re-serialise the inner payload the same way saveBaseline did
        const expectedInput = JSON.stringify(envelope.payload, null, 2);
        if (!verifyBaselineHmac(expectedInput, envelope.hmacSha256, hmacKey)) {
          console.error("[baseline] HMAC verification failed — baseline may have been tampered. Ignoring.");
          return null;
        }
      } else {
        // Key not configured: we can't verify, but we can warn
        console.warn("[baseline] Baseline is signed but SECURITY_POLICY_HMAC_KEY is not set — skipping HMAC verification.");
      }
      return envelope.payload.result ?? null;
    }

    // Legacy format (unsigned) — parse directly
    const parsed = top as unknown as BaselinePayload;
    const hmacKey = getHmacKey();
    if (hmacKey) {
      // A key is configured but the file is unsigned — reject it to prevent
      // an attacker from stripping the HMAC wrapper to bypass verification.
      console.error("[baseline] SECURITY_POLICY_HMAC_KEY is set but baseline is unsigned — ignoring to prevent tampering bypass.");
      return null;
    }
    return parsed.result ?? null;
  } catch {
    return null;
  }
}

/**
 * Compares current gate result against a baseline.
 * Returns a diff including regressions, improvements, new/resolved findings.
 */
export function compareBaseline(current: GateResult, baseline: GateResult): BaselineDiff {
  // Compare control coverage
  const baselineControls = new Map(
    (baseline.controlCoverage ?? []).map((c) => [c.id, c.status])
  );
  const currentControls = new Map(
    (current.controlCoverage ?? []).map((c) => [c.id, c.status])
  );

  const regressions: ControlRegression[] = [];
  const improvements: ControlImprovement[] = [];

  for (const [id, currentStatus] of currentControls) {
    const baselineStatus = baselineControls.get(id);
    if (baselineStatus === "satisfied" && currentStatus === "missing") {
      regressions.push({ controlId: id, was: "satisfied", now: "missing" });
    } else if (baselineStatus === "missing" && currentStatus === "satisfied") {
      improvements.push({ controlId: id, was: "missing", now: "satisfied" });
    }
  }

  // Compare findings by ID
  const baselineFindingIds = new Set((baseline.findings ?? []).map((f) => f.id));
  const currentFindingIds = new Set((current.findings ?? []).map((f) => f.id));

  const newFindings = (current.findings ?? []).filter((f) => !baselineFindingIds.has(f.id));
  const resolvedFindings = (baseline.findings ?? []).filter((f) => !currentFindingIds.has(f.id));

  // Coverage change
  const baselineCoverage = baseline.confidence?.automatedCoverage ?? 0;
  const currentCoverage = current.confidence?.automatedCoverage ?? 0;
  const coverageChange = currentCoverage - baselineCoverage;

  return { regressions, improvements, newFindings, resolvedFindings, coverageChange };
}
