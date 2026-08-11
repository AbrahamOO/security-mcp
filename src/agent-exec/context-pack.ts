/**
 * Deterministic pre-pass, computed ONCE per run and shared by every agent.
 *
 * Without this, 84 agents each independently rediscover the same regex hits and the
 * same repo layout, and every finding rests on model recall rather than on evidence a
 * reviewer can re-run. The pack is byte-identical across agents, so it also sits in the
 * prompt-cache prefix and costs a fraction after the first hit.
 */
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { getWorkspaceRoot } from "../repo/workspace.js";
import { runScanners } from "../gate/checks/scanners.js";
import type { Finding } from "../gate/result.js";
import type { RepoIndex } from "./queue.js";
import type { StackContext } from "../types/agent-run.js";

export type ContextPack = {
  generatedAt: string;
  fileCount: number;
  scannerFindings: number;
  /** Scanners that were not installed. Stated, never silently treated as "clean". */
  scannersUnavailable: string[];
  markdown: string;
};

const MAX_SCANNER_LINES = 120;
const MAX_TREE_LINES = 150;

function topDirectories(files: string[], limit: number): string[] {
  const counts = new Map<string, number>();
  for (const f of files) {
    const dir = f.includes("/") ? f.slice(0, f.lastIndexOf("/")) : ".";
    counts.set(dir, (counts.get(dir) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([dir, n]) => `${dir}/ (${n} files)`);
}

/**
 * Run the real scanners once and render everything agents should not re-derive.
 *
 * Scanner failure is never fatal: a missing binary is recorded in `scannersUnavailable`
 * and surfaced in the run's coverage report, because "we did not run gitleaks" and
 * "gitleaks found nothing" must never look the same to a reviewer.
 */
export async function buildContextPack(opts: {
  agentRunId: string;
  stackContext: StackContext;
  index: RepoIndex;
  changedFiles?: string[];
}): Promise<ContextPack> {
  const root = getWorkspaceRoot();
  const generatedAt = new Date().toISOString();

  let findings: Finding[] = [];
  const unavailable: string[] = [];
  // Every surface: this pack feeds the whole roster, so narrowing here would silently
  // starve whichever specialist needed the surface we dropped.
  const surfaces = { web: true, api: true, infra: true, mobileIos: true, mobileAndroid: true, ai: true };
  try {
    findings = await runScanners({ surfaces, changedFiles: opts.changedFiles ?? [] });
  } catch (err) {
    unavailable.push(`scanner sweep failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  const scannerLines: string[] = [];
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
    for (const f of findings.filter((x) => x.severity === sev)) {
      if (scannerLines.length >= MAX_SCANNER_LINES) break;
      const loc = f.files && f.files.length > 0 ? f.files.slice(0, 3).join(", ") : "(repo)";
      scannerLines.push(`- [${sev}] ${f.title} — ${loc}`);
    }
  }

  const stack = opts.stackContext;
  const stackBits = [
    stack.languages.length > 0 ? `languages: ${stack.languages.join(", ")}` : "",
    stack.frameworks.length > 0 ? `frameworks: ${stack.frameworks.join(", ")}` : "",
    stack.databases.length > 0 ? `databases: ${stack.databases.join(", ")}` : "",
    stack.cloudProvider.length > 0 ? `cloud: ${stack.cloudProvider.join(", ")}` : "",
    stack.packageManagers.length > 0 ? `package managers: ${stack.packageManagers.join(", ")}` : "",
    stack.ciPlatform.length > 0 ? `CI: ${stack.ciPlatform.join(", ")}` : ""
  ].filter(Boolean);

  const md = [
    `### Repository map (${opts.index.files.length} source/config files)`,
    ...topDirectories(opts.index.files, MAX_TREE_LINES).map((l) => `- ${l}`),
    "",
    stackBits.length > 0 ? `### Detected stack\n${stackBits.map((b) => `- ${b}`).join("\n")}` : "",
    "",
    opts.changedFiles && opts.changedFiles.length > 0
      ? `### Changed files in scope (${opts.changedFiles.length})\n` +
        opts.changedFiles.slice(0, 100).map((f) => `- ${f}`).join("\n")
      : "",
    "",
    `### Scanner results (already executed — do not re-run, cite these)`,
    scannerLines.length > 0
      ? scannerLines.join("\n") + (findings.length > scannerLines.length
        ? `\n- ...and ${findings.length - scannerLines.length} more` : "")
      : "- No scanner findings reported.",
    unavailable.length > 0
      ? `\n### Scanners UNAVAILABLE (absence of findings here proves nothing)\n${unavailable.map((u) => `- ${u}`).join("\n")}`
      : ""
  ].filter((s) => s !== "").join("\n");

  const dir = join(root, ".mcp", "agent-runs", opts.agentRunId, "context");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(join(dir, "context-pack.md"), md + "\n", { mode: 0o600 });
  await writeFile(join(dir, "scanner-findings.json"), JSON.stringify(findings, null, 2) + "\n", { mode: 0o600 });

  return {
    generatedAt,
    fileCount: opts.index.files.length,
    scannerFindings: findings.length,
    scannersUnavailable: unavailable,
    markdown: md
  };
}
