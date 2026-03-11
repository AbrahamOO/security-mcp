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
  expires_on: z.string()
});

const ExceptionFileSchema = z.object({
  version: z.string(),
  exceptions: z.array(ExceptionSchema).default([])
});

export type SecurityException = z.infer<typeof ExceptionSchema>;

export type SuppressedFinding = {
  finding: Finding;
  exceptionId: string;
  expiresOn: string;
};

async function readExceptionsJson(): Promise<string> {
  const overridePath = process.env["SECURITY_GATE_EXCEPTIONS"];
  if (overridePath) {
    return await readFile(join(process.cwd(), overridePath), "utf-8");
  }

  try {
    return await readFile(join(process.cwd(), ".mcp", "exceptions", "security-exceptions.json"), "utf-8");
  } catch {
    return await readFile(join(PKG_ROOT, "defaults", "security-exceptions.json"), "utf-8");
  }
}

export async function loadSecurityExceptions(): Promise<SecurityException[]> {
  const raw = await readExceptionsJson();
  return ExceptionFileSchema.parse(JSON.parse(raw)).exceptions;
}

export async function applySecurityExceptions(findings: Finding[]): Promise<{
  findings: Finding[];
  suppressed: SuppressedFinding[];
  exceptionFindings: Finding[];
  activeControlExceptionIds: string[];
}> {
  const exceptions = await loadSecurityExceptions();
  const active: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  const exceptionFindings: Finding[] = [];
  const activeControlExceptionIds = new Set<string>();

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

    suppressed.push({
      finding,
      exceptionId: match.id,
      expiresOn: match.expires_on
    });
  }

  return {
    findings: active,
    suppressed,
    exceptionFindings,
    activeControlExceptionIds: Array.from(activeControlExceptionIds)
  };
}
