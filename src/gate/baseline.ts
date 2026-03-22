/**
 * Baseline regression tracking.
 * Saves and compares gate results to detect security regressions.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { GateResult, Finding } from "./result.js";

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
 */
export async function saveBaseline(
  runId: string,
  result: GateResult,
  commitHash: string
): Promise<void> {
  await ensureDir(BASELINE_DIR);

  const payload = { runId, commitHash, savedAt: new Date().toISOString(), result };
  const json = JSON.stringify(payload, null, 2);

  // Write to temp file then rename (atomic)
  const safehash = commitHash.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
  const targetPath = join(BASELINE_DIR, `${safehash}.json`);
  const latestPath = join(BASELINE_DIR, "latest.json");
  const tmpPath = `${targetPath}.tmp`;

  try {
    await writeFile(tmpPath, json, "utf-8");
    await rename(tmpPath, targetPath);
  } catch {
    // fallback: write directly
    await writeFile(targetPath, json, "utf-8").catch(() => { /* ignore */ });
  }

  // Update latest (best-effort atomic)
  const latestTmp = `${latestPath}.tmp`;
  try {
    await writeFile(latestTmp, json, "utf-8");
    await rename(latestTmp, latestPath);
  } catch {
    await writeFile(latestPath, json, "utf-8").catch(() => { /* ignore */ });
  }
}

interface BaselinePayload {
  runId: string;
  commitHash: string;
  savedAt: string;
  result: GateResult;
}

/**
 * Loads a baseline by commit hash, or the latest baseline if no hash given.
 * Returns null if no baseline exists or it's corrupted.
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
    const parsed = JSON.parse(raw) as BaselinePayload;
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
