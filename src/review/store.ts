import { createHash, createHmac, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export type ReviewStepStatus = "pending" | "completed" | "approved";

export type ReviewStepRecord = {
  status: ReviewStepStatus;
  updatedAt: string;
  details?: Record<string, unknown>;
};

export type ReviewRun = {
  id: string;
  createdAt: string;
  updatedAt: string;
  mode: "recent_changes" | "folder_by_folder" | "file_by_file";
  targets: string[];
  baseRef?: string;
  headRef?: string;
  requiredSteps: string[];
  steps: Record<string, ReviewStepRecord>;
};

const REVIEW_DIR = path.join(".mcp", "reviews");
const REPORT_DIR = path.join(".mcp", "reports");

async function ensureDir(dirPath: string): Promise<void> {
  await mkdir(dirPath, { recursive: true });
}

function reviewPath(runId: string): string {
  return path.join(process.cwd(), REVIEW_DIR, `${runId}.json`);
}

function reportPath(runId: string): string {
  return path.join(process.cwd(), REPORT_DIR, `${runId}.attestation.json`);
}

async function writeJson(filePath: string, value: unknown): Promise<void> {
  await ensureDir(path.dirname(filePath));
  await writeFile(filePath, JSON.stringify(value, null, 2) + "\n", "utf-8");
}

export async function createReviewRun(opts: {
  mode: "recent_changes" | "folder_by_folder" | "file_by_file";
  targets?: string[];
  baseRef?: string;
  headRef?: string;
}): Promise<ReviewRun> {
  const now = new Date().toISOString();
  const cleanTargets = (opts.targets ?? []).map((target) => target.trim()).filter(Boolean);
  const run: ReviewRun = {
    id: randomUUID(),
    createdAt: now,
    updatedAt: now,
    mode: opts.mode,
    targets: cleanTargets,
    baseRef: opts.baseRef,
    headRef: opts.headRef,
    requiredSteps: ["scan_strategy", "threat_model", "checklist", "run_pr_gate"],
    steps: {
      start_review: {
        status: "completed",
        updatedAt: now,
        details: {
          mode: opts.mode,
          targets: cleanTargets,
          baseRef: opts.baseRef,
          headRef: opts.headRef
        }
      }
    }
  };

  await writeJson(reviewPath(run.id), run);
  return run;
}

export async function readReviewRun(runId: string): Promise<ReviewRun> {
  const raw = await readFile(reviewPath(runId), "utf-8");
  return JSON.parse(raw) as ReviewRun;
}

export async function updateReviewStep(
  runId: string,
  step: string,
  status: ReviewStepStatus,
  details?: Record<string, unknown>
): Promise<ReviewRun> {
  const run = await readReviewRun(runId);
  run.steps[step] = {
    status,
    updatedAt: new Date().toISOString(),
    details
  };
  run.updatedAt = new Date().toISOString();
  await writeJson(reviewPath(run.id), run);
  return run;
}

export async function createReviewAttestation(
  runId: string,
  payload: Record<string, unknown>,
  signatureKey?: string
): Promise<{ path: string; sha256: string; hmacSha256?: string }> {
  const digestInput = JSON.stringify(payload);
  const sha256 = createHash("sha256").update(digestInput).digest("hex");
  const hmacSha256 = signatureKey
    ? createHmac("sha256", signatureKey).update(digestInput).digest("hex")
    : undefined;

  await writeJson(reportPath(runId), {
    ...payload,
    integrity: {
      sha256,
      ...(hmacSha256 ? { hmacSha256 } : {})
    }
  });

  return {
    path: reportPath(runId),
    sha256,
    hmacSha256
  };
}
