import { createHmac, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { Finding } from "./result.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "../..");

const ExceptionSchema = z.object({
  id: z.string(),
  finding_ids: z.array(z.string()).default([]),
  control_ids: z.array(z.string()).default([]),
  justification: z.string(),
  ticket: z.string().optional(),
  owner: z.string(),
  approver: z.string(),
  approval_role: z.string(),
  // Fix 1: enforce YYYY-MM-DD format and max 365-day TTL
  expires_on: z.string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, "expires_on must be YYYY-MM-DD")
    .refine((val) => {
      const expiry = new Date(val);
      const maxExpiry = new Date();
      maxExpiry.setDate(maxExpiry.getDate() + 365);
      return expiry <= maxExpiry;
    }, { message: "expires_on cannot be more than 365 days in the future" })
})
// Fix 2: prevent self-approval (owner === approver)
.superRefine((data, ctx) => {
  if (data.owner.toLowerCase() === data.approver.toLowerCase()) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `Exception self-approval is not permitted: owner and approver must be different (got '${data.owner}')`,
      path: ["approver"]
    });
  }
});

const ExceptionFileSchema = z.object({
  version: z.string(),
  exceptions: z.array(ExceptionSchema).default([]),
  hmacSha256: z.string().optional()
});

export type SecurityException = z.infer<typeof ExceptionSchema>;

export type SuppressedFinding = {
  finding: Finding;
  exceptionId: string;
  expiresOn: string;
};

// Fix 3: HMAC helper — sign the exceptions array for tamper detection
export function signExceptionsFile(exceptions: unknown[], key: string): string {
  const canonical = JSON.stringify(
    exceptions,
    (_, v) => (v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v as Record<string, unknown>).sort())
      : v)
  );
  return createHmac("sha256", key).update(canonical, "utf-8").digest("hex");
}

const EXCEPTIONS_HMAC_MIN_KEY_BYTES = 32;

function getExceptionsHmacKey(): string | null {
  const key = process.env["SECURITY_POLICY_HMAC_KEY"];
  if (!key) return null;
  if (Buffer.byteLength(key, "utf-8") < EXCEPTIONS_HMAC_MIN_KEY_BYTES) {
    throw new Error(
      `SECURITY_POLICY_HMAC_KEY is too short (${Buffer.byteLength(key, "utf-8")} bytes). ` +
      `Minimum ${EXCEPTIONS_HMAC_MIN_KEY_BYTES} bytes required.`
    );
  }
  return key;
}

async function readExceptionsJson(): Promise<{ raw: string; isCiFile: boolean; isOverride: boolean; source: string; warnings: Finding[] }> {
  const warnings: Finding[] = [];
  const overridePath = process.env["SECURITY_GATE_EXCEPTIONS"];

  if (overridePath) {
    // CWE-22: ensure path stays within the project directory
    const resolved = resolve(process.cwd(), overridePath);
    if (!resolved.startsWith(process.cwd() + "/") && resolved !== process.cwd()) {
      throw new Error(`SECURITY_GATE_EXCEPTIONS path '${overridePath}' escapes the project directory`);
    }
    const raw = await readFile(resolved, "utf-8");
    return { raw, isCiFile: false, isOverride: true, source: overridePath, warnings };
  }

  // Project-level CI exceptions file (suppresses self-scan false positives)
  try {
    const raw = await readFile(join(process.cwd(), ".github", "security-exceptions-ci.json"), "utf-8");
    // Fix 4: warn when CI exceptions are loaded outside CI context
    const isCI = !!(process.env["CI"] || process.env["GITHUB_ACTIONS"]);
    if (!isCI) {
      const count = (() => {
        try {
          const parsed = JSON.parse(raw) as { exceptions?: unknown[] };
          return Array.isArray(parsed.exceptions) ? parsed.exceptions.length : 0;
        } catch {
          return 0;
        }
      })();
      warnings.push({
        id: "CI_EXCEPTIONS_IN_LOCAL_SCAN",
        title: "CI self-scan exceptions applied to local scan",
        severity: "HIGH",
        evidence: [
          "CI exceptions file: .github/security-exceptions-ci.json",
          `Suppressed controls: ${count}`,
          "CI env var not set — this appears to be a local scan"
        ],
        requiredActions: [
          `CI self-scan exceptions (.github/security-exceptions-ci.json) are being applied to a local scan. This suppresses ${count} controls. Set SECURITY_GATE_EXCEPTIONS to point to your project's exceptions file.`
        ]
      });
    }
    return { raw, isCiFile: true, isOverride: false, source: ".github/security-exceptions-ci.json", warnings };
  } catch { /* not present — continue */ }

  try {
    const raw = await readFile(join(process.cwd(), ".mcp", "exceptions", "security-exceptions.json"), "utf-8");
    return { raw, isCiFile: false, isOverride: false, source: ".mcp/exceptions/security-exceptions.json", warnings };
  } catch {
    const raw = await readFile(join(PKG_ROOT, "defaults", "security-exceptions.json"), "utf-8");
    return { raw, isCiFile: false, isOverride: false, source: "defaults/security-exceptions.json", warnings };
  }
}

export interface ExceptionsIntegrity {
  /** True only when an HMAC key is set AND the file carried a matching hmacSha256. */
  verified: boolean;
  /** True when the file came from the SECURITY_GATE_EXCEPTIONS override (lowest trust). */
  isOverride: boolean;
  /** True for the .github/security-exceptions-ci.json self-scan file. */
  isCiFile: boolean;
  /** Human-readable source path of the exceptions file. */
  source: string;
}

export async function loadSecurityExceptions(): Promise<{ exceptions: SecurityException[]; warnings: Finding[]; integrity: ExceptionsIntegrity }> {
  const { raw, warnings, isOverride, isCiFile, source } = await readExceptionsJson();
  const parsed = ExceptionFileSchema.parse(JSON.parse(raw));

  // Fix 3: HMAC verification of exceptions file
  const hmacKey = getExceptionsHmacKey();
  const extraWarnings: Finding[] = [];

  // #9 fix — opt-in fail-closed: when SECURITY_REQUIRE_SIGNED_EXCEPTIONS is set, an
  // unsigned (or unverifiable) exceptions file is REJECTED rather than trusted. This
  // closes the blanket-suppression bypass (an attacker editing an unsigned exceptions
  // file to silence findings) for operators who enable it. Default-off preserves the
  // backwards-compatible behavior (and self-scan workflows that use unsigned CI files).
  const requireSigned =
    process.env["SECURITY_REQUIRE_SIGNED_EXCEPTIONS"] === "1" ||
    process.env["SECURITY_REQUIRE_SIGNED_EXCEPTIONS"] === "true";
  if (requireSigned) {
    if (!hmacKey) {
      throw new Error(
        "[loadSecurityExceptions] SECURITY_REQUIRE_SIGNED_EXCEPTIONS is set but SECURITY_POLICY_HMAC_KEY " +
        "is not configured — cannot verify exceptions integrity. Set a ≥32-byte key and sign the exceptions file."
      );
    }
    if (!parsed.hmacSha256) {
      throw new Error(
        "[loadSecurityExceptions] SECURITY_REQUIRE_SIGNED_EXCEPTIONS is set but the exceptions file is unsigned " +
        "(no hmacSha256). Refusing to apply unsigned exceptions. Sign it with the signExceptionsFile helper."
      );
    }
  }

  if (hmacKey) {
    if (!parsed.hmacSha256) {
      extraWarnings.push({
        id: "EXCEPTIONS_FILE_UNSIGNED",
        title: "Security exceptions file is not integrity-protected",
        severity: "MEDIUM",
        evidence: [
          "SECURITY_POLICY_HMAC_KEY is set but exceptions file has no hmacSha256 field"
        ],
        requiredActions: [
          "Security exceptions file is not integrity-protected. Set SECURITY_POLICY_HMAC_KEY and re-save exceptions to enable tamper detection."
        ]
      });
    } else {
      const expected = signExceptionsFile(parsed.exceptions as unknown[], hmacKey);
      const storedBuf   = Buffer.from(parsed.hmacSha256, "hex");
      const expectedBuf = Buffer.from(expected, "hex");
      const valid =
        storedBuf.length === expectedBuf.length &&
        timingSafeEqual(storedBuf, expectedBuf);
      if (!valid) {
        throw new Error(
          "[loadSecurityExceptions] HMAC verification failed for exceptions file — file may have been tampered. " +
          "Re-sign exceptions with the signExceptionsFile helper and store the result in hmacSha256."
        );
      }
    }
  }

  return {
    exceptions: parsed.exceptions,
    warnings: [...warnings, ...extraWarnings],
    integrity: { verified: Boolean(hmacKey && parsed.hmacSha256), isOverride, isCiFile, source }
  };
}

export async function applySecurityExceptions(
  findings: Finding[],
  opts?: { requireTicket?: boolean }
): Promise<{
  findings: Finding[];
  suppressed: SuppressedFinding[];
  exceptionFindings: Finding[];
  activeControlExceptionIds: string[];
  warnings: Finding[];
}> {
  const { exceptions, warnings, integrity } = await loadSecurityExceptions();
  const active: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  const exceptionFindings: Finding[] = [];
  const activeControlExceptionIds = new Set<string>();
  const HIGH_SEVERITIES = new Set(["HIGH", "CRITICAL"]);

  for (const entry of exceptions) {
    const expiresAt = new Date(entry.expires_on);
    if (!Number.isNaN(expiresAt.getTime()) && expiresAt.getTime() >= Date.now()) {
      for (const controlId of entry.control_ids) {
        activeControlExceptionIds.add(controlId);
      }
    }
  }

  for (const finding of findings) {
    const match = exceptions.find((entry) => entry.finding_ids.includes(finding.id));
    if (!match) {
      active.push(finding);
      continue;
    }

    const expiresAt = new Date(match.expires_on);
    if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() < Date.now()) {
      active.push(finding);
      exceptionFindings.push({
        id: "SECURITY_EXCEPTION_EXPIRED",
        title: `Security exception ${match.id} is expired or invalid`,
        severity: "HIGH",
        evidence: [`Finding: ${finding.id}`, `Owner: ${match.owner}`, `Expires: ${match.expires_on}`],
        requiredActions: [
          "Renew or remove the expired exception.",
          "Resolve the underlying finding or obtain a new approved exception."
        ]
      });
      continue;
    }

    // Fix 7: enforce require_ticket when set in policy
    if (opts?.requireTicket && !match.ticket) {
      active.push(finding);
      exceptionFindings.push({
        id: "EXCEPTION_MISSING_TICKET",
        title: `Exception ${match.id} is missing a required ticket reference`,
        severity: "MEDIUM",
        evidence: [`Finding: ${finding.id}`, `Exception: ${match.id}`, `Owner: ${match.owner}`],
        requiredActions: [
          `Exception ${match.id} for finding ${finding.id} is missing a required ticket reference. Set require_ticket: false in policy or add a ticket field.`
        ]
      });
      continue;
    }

    // #9 fix C/F — DEFAULT POSTURE: an unsigned/unverified exceptions file may NOT suppress
    // HIGH/CRITICAL findings (it may still suppress LOW/MEDIUM noise). This makes the
    // dangerous bypass — silently hiding a HIGH/CRITICAL by editing an unsigned file —
    // fail by default on the override, default (defaults/...), and project (.mcp/...) paths.
    //   Exemption: the named CI self-scan file `.github/security-exceptions-ci.json` (isCiFile)
    //   is the project suppressing its OWN intentional test fixtures; its use is already
    //   surfaced loudly (CI_EXCEPTIONS_IN_LOCAL_SCAN + EXCEPTIONS_UNSIGNED_SUPPRESSION), so it
    //   stays allowed to avoid breaking self-scan workflows. Sign it to remove the exemption.
    //   Break-glass: SECURITY_ALLOW_UNSIGNED_HIGH_SUPPRESSION=1 restores the legacy behavior
    //   on all paths (use only for scanning intentionally-vulnerable fixtures).
    const allowUnsignedHigh =
      process.env["SECURITY_ALLOW_UNSIGNED_HIGH_SUPPRESSION"] === "1" ||
      process.env["SECURITY_ALLOW_UNSIGNED_HIGH_SUPPRESSION"] === "true";
    if (!integrity.verified && !allowUnsignedHigh && !integrity.isCiFile && HIGH_SEVERITIES.has(finding.severity)) {
      active.push(finding);
      exceptionFindings.push({
        id: "EXCEPTION_UNSIGNED_HIGH_BLOCKED",
        title: `Unsigned exceptions may not suppress ${finding.severity} finding ${finding.id}`,
        severity: finding.severity,
        evidence: [
          `Finding: ${finding.id} (${finding.severity})`,
          `Exception: ${match.id}`,
          `Source: ${integrity.source}${integrity.isOverride ? " (SECURITY_GATE_EXCEPTIONS override)" : ""} — not integrity-verified`
        ],
        requiredActions: [
          `Sign the exceptions file (set SECURITY_POLICY_HMAC_KEY ≥32 bytes + store its hmacSha256) to suppress ${finding.severity} findings, or resolve the finding. Break-glass for fixtures: SECURITY_ALLOW_UNSIGNED_HIGH_SUPPRESSION=1.`
        ]
      });
      continue;
    }

    suppressed.push({
      finding,
      exceptionId: match.id,
      expiresOn: match.expires_on
    });
  }

  // #9 fix B — loud, unsuppressible visibility (default-on, ZERO breakage). When an
  // UNSIGNED exceptions file suppressed anything, emit one finding (emitted here, AFTER
  // the suppression loop, so it can never itself be suppressed) so the bypass is never
  // silent. Severity is intentionally MEDIUM — visible in every report without auto-failing
  // the gate (which would break legitimate unsigned self-scan workflows). To make unsigned
  // suppression actually BLOCK, set SECURITY_REQUIRE_SIGNED_EXCEPTIONS=1 (fail-closed).
  if (!integrity.verified && suppressed.length > 0) {
    const highHidden = suppressed.filter((s) => HIGH_SEVERITIES.has(s.finding.severity));
    exceptionFindings.push({
      id: "EXCEPTIONS_UNSIGNED_SUPPRESSION",
      title: `${suppressed.length} finding(s) suppressed by an unsigned exceptions file`,
      severity: "MEDIUM",
      evidence: [
        `Source: ${integrity.source}${integrity.isOverride ? " (SECURITY_GATE_EXCEPTIONS override)" : ""}${integrity.isCiFile ? " (CI self-scan)" : ""}`,
        "File is not integrity-protected (no verified hmacSha256) — its suppressions are not tamper-evident.",
        `Total suppressed: ${suppressed.length}; HIGH/CRITICAL hidden: ${highHidden.length}`,
        ...(highHidden.length > 0 ? [`Hidden HIGH/CRITICAL: ${highHidden.map((s) => `${s.finding.id} (${s.finding.severity})`).slice(0, 20).join(", ")}`] : [])
      ],
      requiredActions: [
        "Sign the exceptions file (set SECURITY_POLICY_HMAC_KEY ≥32 bytes and store its hmacSha256) so suppressions are tamper-evident, or set SECURITY_REQUIRE_SIGNED_EXCEPTIONS=1 to reject unsigned exceptions entirely."
      ]
    });
  }

  return {
    findings: active,
    suppressed,
    exceptionFindings,
    activeControlExceptionIds: Array.from(activeControlExceptionIds),
    warnings
  };
}
