/**
 * Report persistence with a defined on-disk schema.
 *
 * `security.generate_compliance_report` previously returned markdown in the tool
 * response and wrote nothing. Every compliance-report.json / pentest-report.json /
 * threat-model.json found on disk had therefore been hand-authored by an LLM following
 * a skill prompt, which is why two of them carry mutually incompatible schemas and
 * `"generatedAt": "...T00:00:00.000Z"` — a midnight timestamp no clock ever produced.
 *
 * Reports are written to .mcp/reports/, never into an agent-run directory: merge globs
 * `*.json` out of the run dir, so a report living there gets parsed as agent findings.
 */
import { writeFile, mkdir } from "node:fs/promises";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { rename } from "node:fs/promises";
import { join } from "node:path";
import { getWorkspaceRoot } from "../repo/workspace.js";

export const REPORT_SCHEMA_VERSION = 1;

export type ReportKind = "compliance-report" | "pentest-report" | "threat-model" | "coverage-report";

export type ReportEnvelope<K extends ReportKind, B> = {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  kind: K;
  /** Real process clock. The fabricated midnight stamps came from model invention. */
  generatedAt: string;
  generator: { name: "security-mcp"; version: string; tool: string };
  runId: string | null;
  agentRunId: string | null;
  caveat: string;
  body: B;
  integrity: { sha256: string; hmacSha256?: string };
};

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf-8").digest("hex");
}

export function reportsDir(): string {
  return join(getWorkspaceRoot(), ".mcp", "reports");
}

async function atomicWrite(path: string, data: string): Promise<void> {
  // Temp file beside the target: rename() is only atomic within a filesystem.
  const tmp = `${path}.tmp-${randomBytes(8).toString("hex")}`;
  await writeFile(tmp, data, { encoding: "utf-8", mode: 0o600 });
  await rename(tmp, path);
}

export type WriteReportOptions = {
  kind: ReportKind;
  basename: string;
  runId: string | null;
  agentRunId: string | null;
  caveat: string;
  body: unknown;
  version: string;
  tool: string;
  markdown?: string;
  /** Env var holding an HMAC key; without one the digest is only tamper-EVIDENT. */
  signatureEnvVar?: string;
};

export async function writeReport(opts: WriteReportOptions): Promise<{
  jsonPath: string; markdownPath: string | null; sha256: string; signed: boolean;
}> {
  const dir = reportsDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });

  const bodyJson = JSON.stringify(opts.body);
  const digest = sha256(bodyJson);
  const key = opts.signatureEnvVar ? process.env[opts.signatureEnvVar] : undefined;
  // Use the key string directly, as every other HMAC site does (gate/policy.ts,
  // gate/baseline.ts, mcp/audit-chain.ts, review/store.ts). Buffer.from(key, "hex")
  // silently yields a ZERO-BYTE key for any non-hex value, and this function would then
  // report signed:true for a MAC anyone can forge without knowing the key.
  const mac = key && key.length >= 32 ? createHmac("sha256", key).update(bodyJson).digest("hex") : undefined;

  const envelope: ReportEnvelope<ReportKind, unknown> = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    kind: opts.kind,
    generatedAt: new Date().toISOString(),
    generator: { name: "security-mcp", version: opts.version, tool: opts.tool },
    runId: opts.runId,
    agentRunId: opts.agentRunId,
    caveat: opts.caveat,
    body: opts.body,
    integrity: { sha256: digest, ...(mac ? { hmacSha256: mac } : {}) }
  };

  const jsonPath = join(dir, `${opts.basename}.json`);
  await atomicWrite(jsonPath, JSON.stringify(envelope, null, 2) + "\n");

  let markdownPath: string | null = null;
  if (opts.markdown) {
    markdownPath = join(dir, `${opts.basename}.md`);
    await atomicWrite(markdownPath, opts.markdown.endsWith("\n") ? opts.markdown : `${opts.markdown}\n`);
  }

  return { jsonPath, markdownPath, sha256: digest, signed: mac !== undefined };
}
