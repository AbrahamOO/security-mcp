import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

// ---------------------------------------------------------------------------
// Checklist types
// ---------------------------------------------------------------------------

export type ChecklistItemStatus = "pending" | "completed" | "na" | "failed";

export type ChecklistItem = {
  id: string;
  surface: string;
  description: string;
  critical: boolean;
  status: ChecklistItemStatus;
  completedBy?: string;
  completedAt?: string;
  evidence?: string;
  runId: string;
};

export type ChecklistState = {
  runId: string;
  surface: string;
  items: ChecklistItem[];
  signedOffBy?: string;
  signedOffAt?: string;
  allCriticalComplete: boolean;
};

interface ChecklistTemplate {
  surface: string;
  items: Array<{
    id: string;
    description: string;
    critical: boolean;
  }>;
}

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
const CHECKLIST_DEFAULTS_DIR = path.join(
  path.dirname(path.dirname(path.dirname(new URL(import.meta.url).pathname))),
  "defaults",
  "checklists"
);

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

function checklistPath(runId: string): string {
  return path.join(process.cwd(), REVIEW_DIR, `${runId}-checklist.json`);
}

async function readChecklistRaw(runId: string): Promise<ChecklistState | null> {
  try {
    const raw = await readFile(checklistPath(runId), "utf-8");
    return JSON.parse(raw) as ChecklistState;
  } catch {
    return null;
  }
}

function computeAllCriticalComplete(items: ChecklistItem[]): boolean {
  return items
    .filter((i) => i.critical)
    .every((i) => i.status === "completed" || i.status === "na");
}

// CWE-22: surface names used as filenames — restrict to safe alphanumeric slug
const SAFE_SURFACE_RE = /^[a-z][a-z0-9_-]{0,63}$/;

/**
 * Initialize a checklist for a run from the surface template.
 */
export async function initChecklist(runId: string, surface: string): Promise<ChecklistState> {
  assertRunId(runId); // CWE-22: validate UUID format before using as filename component
  if (!SAFE_SURFACE_RE.test(surface)) {
    throw new Error(`Invalid surface name "${surface}"`);
  }
  // Load template from defaults/checklists/{surface}.json
  let template: ChecklistTemplate;
  try {
    const raw = await readFile(path.join(CHECKLIST_DEFAULTS_DIR, `${surface}.json`), "utf-8");
    template = JSON.parse(raw) as ChecklistTemplate;
  } catch {
    // Fallback to empty template
    template = { surface, items: [] };
  }

  const items: ChecklistItem[] = template.items.map((item) => ({
    id: item.id,
    surface,
    description: item.description,
    critical: item.critical,
    status: "pending",
    runId
  }));

  const state: ChecklistState = {
    runId,
    surface,
    items,
    allCriticalComplete: false
  };

  await writeJson(checklistPath(runId), state);
  return state;
}

/**
 * Mark a checklist item as completed.
 */
export async function completeChecklistItem(
  runId: string,
  itemId: string,
  completedBy: string,
  evidence?: string
): Promise<ChecklistState> {
  assertRunId(runId); // CWE-22
  const state = await readChecklistRaw(runId);
  if (!state) throw new Error(`No checklist found for runId: ${runId}`);

  const item = state.items.find((i) => i.id === itemId);
  if (!item) throw new Error(`Checklist item not found: ${itemId}`);

  item.status = "completed";
  item.completedBy = completedBy;
  item.completedAt = new Date().toISOString();
  if (evidence) item.evidence = evidence;

  state.allCriticalComplete = computeAllCriticalComplete(state.items);
  await writeJson(checklistPath(runId), state);
  return state;
}

/**
 * Mark a checklist item as not applicable.
 */
export async function markChecklistItemNA(
  runId: string,
  itemId: string,
  completedBy: string,
  reason: string
): Promise<ChecklistState> {
  assertRunId(runId); // CWE-22
  const state = await readChecklistRaw(runId);
  if (!state) throw new Error(`No checklist found for runId: ${runId}`);

  const item = state.items.find((i) => i.id === itemId);
  if (!item) throw new Error(`Checklist item not found: ${itemId}`);

  item.status = "na";
  item.completedBy = completedBy;
  item.completedAt = new Date().toISOString();
  item.evidence = reason;

  state.allCriticalComplete = computeAllCriticalComplete(state.items);
  await writeJson(checklistPath(runId), state);
  return state;
}

/**
 * Mark a checklist item as failed.
 */
export async function failChecklistItem(
  runId: string,
  itemId: string,
  completedBy: string,
  reason: string
): Promise<ChecklistState> {
  assertRunId(runId); // CWE-22
  const state = await readChecklistRaw(runId);
  if (!state) throw new Error(`No checklist found for runId: ${runId}`);

  const item = state.items.find((i) => i.id === itemId);
  if (!item) throw new Error(`Checklist item not found: ${itemId}`);

  item.status = "failed";
  item.completedBy = completedBy;
  item.completedAt = new Date().toISOString();
  item.evidence = reason;

  state.allCriticalComplete = computeAllCriticalComplete(state.items);
  await writeJson(checklistPath(runId), state);
  return state;
}

/**
 * Sign off on a checklist. Requires all non-NA critical items to be completed.
 */
export async function signOffChecklist(
  runId: string,
  signedOffBy: string
): Promise<ChecklistState> {
  assertRunId(runId); // CWE-22
  const state = await readChecklistRaw(runId);
  if (!state) throw new Error(`No checklist found for runId: ${runId}`);

  const blockers = state.items.filter(
    (i) => i.critical && (i.status === "pending" || i.status === "failed")
  );

  if (blockers.length > 0) {
    const list = blockers.map((b) => `${b.id}: ${b.description} (${b.status})`).join("; ");
    throw new Error(`Cannot sign off: ${blockers.length} critical item(s) are not completed: ${list}`);
  }

  state.signedOffBy = signedOffBy;
  state.signedOffAt = new Date().toISOString();
  state.allCriticalComplete = true;

  await writeJson(checklistPath(runId), state);
  return state;
}

/**
 * Read checklist state for a run.
 */
export async function readChecklist(runId: string): Promise<ChecklistState | null> {
  assertRunId(runId); // CWE-22
  return readChecklistRaw(runId);
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

// CWE-22: validate UUID format before using runId as a filename component.
// Defense-in-depth — the MCP tool schemas also validate, but the function must
// be safe regardless of call site.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertRunId(runId: string): void {
  if (!runId || !UUID_RE.test(runId)) {
    throw new Error(`Invalid runId "${runId}" — must be a UUID`);
  }
}

export async function readReviewRun(runId: string): Promise<ReviewRun> {
  assertRunId(runId);
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

// HMAC-SHA256 requires a key of at least 32 bytes (256 bits) to provide full
// security. Keys shorter than the hash output degrade HMAC to effectively a
// keyed hash with reduced security margin (NIST SP 800-107 §5.3.4).
const HMAC_MIN_KEY_BYTES = 32;

export async function createReviewAttestation(
  runId: string,
  payload: Record<string, unknown>,
  signatureKey?: string
): Promise<{ path: string; sha256: string; hmacSha256?: string }> {
  if (signatureKey !== undefined && Buffer.byteLength(signatureKey, "utf-8") < HMAC_MIN_KEY_BYTES) {
    throw new Error(
      `HMAC signature key is too short (${Buffer.byteLength(signatureKey, "utf-8")} bytes). ` +
      `Provide a key of at least ${HMAC_MIN_KEY_BYTES} bytes (256 bits) — ` +
      `generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
    );
  }

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

/**
 * Verify a stored attestation HMAC using a timing-safe comparison.
 * Returns true only if the stored hmacSha256 matches the recomputed value.
 * Uses timingSafeEqual to prevent timing oracle attacks on the comparison.
 */
export async function verifyAttestationHmac(
  runId: string,
  signatureKey: string
): Promise<{ valid: boolean; reason?: string }> {

  if (Buffer.byteLength(signatureKey, "utf-8") < HMAC_MIN_KEY_BYTES) {
    return { valid: false, reason: "Signature key too short — cannot verify." };
  }

  let stored: Record<string, unknown>;
  try {
    const raw = await readFile(reportPath(runId), "utf-8");
    stored = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return { valid: false, reason: "Attestation file not found or unreadable." };
  }

  const integrity = stored["integrity"] as Record<string, unknown> | undefined;
  const storedHmac = typeof integrity?.["hmacSha256"] === "string" ? integrity["hmacSha256"] : null;
  if (!storedHmac) {
    return { valid: false, reason: "Attestation was not signed — no hmacSha256 field." };
  }

  // Recompute HMAC over payload (everything except the integrity wrapper)
  const { integrity: _stripped, ...payloadOnly } = stored;
  const digestInput = JSON.stringify(payloadOnly);
  const expected = createHmac("sha256", signatureKey).update(digestInput).digest("hex");

  // Timing-safe comparison — prevents oracle attacks that leak the correct HMAC
  // byte-by-byte via response timing differences (CWE-208).
  const storedBuf = Buffer.from(storedHmac, "hex");
  const expectedBuf = Buffer.from(expected, "hex");
  if (storedBuf.length !== expectedBuf.length) {
    return { valid: false, reason: "HMAC length mismatch." };
  }
  const match = timingSafeEqual(storedBuf, expectedBuf);
  return match ? { valid: true } : { valid: false, reason: "HMAC mismatch — attestation may have been tampered." };
}
