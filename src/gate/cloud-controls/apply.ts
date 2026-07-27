import { copyFile, rename, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";
import { getWorkspaceRoot } from "../../repo/workspace.js";
import { applyEnsures } from "./hcl.js";
import { detectTerraform, Violation } from "./detect.js";
import { CloudRule, loadCloudRules } from "./types.js";

/**
 * Structural damage check, deliberately independent of the regex rules that produced the
 * edit. It does not aim to be a Terraform parser. It catches the corruption classes that
 * were actually observed, each of which makes the file stop loading entirely:
 *
 *   - an attribute glued to a block's opening brace (the CRLF bug)
 *   - unbalanced braces
 *   - a duplicated `resource "type" "name"` address (breaks every terraform command)
 *   - the file emptied or truncated
 *
 * Returns a reason string when the rewrite is unsafe, or null when it looks structurally
 * sound. Verification that shares the edit's assumptions is not verification.
 */
function detectStructuralDamage(original: string, rewritten: string): string | null {
  if (rewritten.trim().length === 0 && original.trim().length > 0) {
    return "output is empty";
  }
  // Something must be left of the original. A rewrite that loses most of the file is a bug,
  // not a remediation.
  if (rewritten.length < original.length * 0.5) {
    return `output shrank from ${original.length} to ${rewritten.length} bytes`;
  }
  // An opening brace must be followed by end-of-line (allowing trailing spaces or a
  // comment). `{  attr = true` on the header line is invalid HCL.
  const GLUED_BRACE_RE = new RegExp(String.raw`^[^\n#/]*\{[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*=`, "m");
  const gluedBrace = GLUED_BRACE_RE.exec(rewritten);
  if (gluedBrace && !GLUED_BRACE_RE.test(original)) {
    return `an attribute was inserted on a block header line: ${gluedBrace[0].trim().slice(0, 60)}`;
  }
  // Brace balance, ignoring braces inside quoted strings and comments.
  const balance = (text: string): number => {
    let depth = 0, inStr = false, inComment = false, prev = "";
    for (const ch of text) {
      if (inComment) { if (ch === "\n") inComment = false; prev = ch; continue; }
      if (inStr) { if (ch === '"' && prev !== "\\") inStr = false; prev = ch; continue; }
      if (ch === '"') inStr = true;
      else if (ch === "#" || (ch === "/" && prev === "/")) inComment = true;
      else if (ch === "{") depth++;
      else if (ch === "}") depth--;
      prev = ch;
    }
    return depth;
  };
  const before = balance(original);
  const after = balance(rewritten);
  if (after !== before) return `brace balance changed from ${before} to ${after}`;
  // Duplicate resource addresses.
  const addresses = (text: string): string[] =>
    [...text.matchAll(/^\s*resource\s+"([^"]+)"\s+"([^"]+)"/gm)].map((m) => `${m[1]}.${m[2]}`);
  const afterAddrs = addresses(rewritten);
  const dupes = afterAddrs.filter((a, i) => afterAddrs.indexOf(a) !== i);
  if (dupes.length > 0 && new Set(dupes).size > 0) {
    const beforeAddrs = addresses(original);
    const newDupes = [...new Set(dupes)].filter((d) => beforeAddrs.filter((b) => b === d).length < afterAddrs.filter((a) => a === d).length);
    if (newDupes.length > 0) return `duplicate resource address introduced: ${newDupes.join(", ")}`;
  }
  return null;
}

/**
 * Write the hardened file atomically, keeping a one-shot `.orig` backup.
 *
 * The previous implementation was a bare in-place `writeFile`, i.e. truncate-then-write on
 * the user's infrastructure code, with no backup. A crash between truncate and write left
 * the file empty. Both audit-chain.ts and reports.ts already use sibling-temp + rename for
 * far less valuable data.
 */
async function writeIacFileSafely(absPath: string, original: string, text: string): Promise<void> {
  const backup = `${absPath}.orig`;
  try {
    // First write only. Never clobber an existing .orig, which would destroy the last known
    // good copy on a second run.
    await copyFile(absPath, backup, 1 /* COPYFILE_EXCL */);
  } catch { /* backup already exists — keep the older, more original one */ }

  // Temp file beside the target: rename() throws EXDEV across filesystems.
  const tmp = `${absPath}.tmp-${randomBytes(6).toString("hex")}`;
  await writeFile(tmp, text, "utf-8");
  try {
    await rename(tmp, absPath);
  } catch (e) {
    // Leave the original in place and take the temp file with us.
    await writeFile(absPath, original, "utf-8").catch(() => undefined);
    throw e;
  }
}

const TF_GLOBS = ["**/*.tf"];
const IGNORE = ["**/node_modules/**", "**/.git/**", "**/dist/**", "**/.claude/**", "src/gate/**"];
const MAX_ITERATIONS = 500;

export type AppliedFix = { ruleId: string; file: string; resource: string; frameworks: string[] };
export type ManualFix = { ruleId: string; file: string; resource: string; reason: string; snippet?: string };

export type HardenReport = {
  applied: AppliedFix[];
  manual: ManualFix[];
  filesChanged: string[];
};

function violationKey(v: Violation): string {
  return `${v.rule.ruleId}@@${v.file}@@${v.block?.name ?? "?"}`;
}

function isAutoApplicable(rule: CloudRule): boolean {
  const s = rule.remediate.strategy;
  if (s === "manual") return false;
  if (s === "companion-resource") return Boolean(rule.remediate.companion);
  return Boolean(rule.remediate.ensure); // set-attr | insert-block
}

/** Apply a single violation's remediation to the document, returning new text (or unchanged). */
function applyOne(text: string, v: Violation): string {
  const { remediate } = v.rule;
  if (remediate.strategy === "companion-resource" && remediate.companion && v.block) {
    const snippet = remediate.companion.replaceAll("${name}", v.block.name);
    const sep = text.endsWith("\n") ? "\n" : "\n\n";
    return text + sep + snippet.trimEnd() + "\n";
  }
  if (remediate.ensure && v.block) {
    return applyEnsures(text, v.block, remediate.ensure);
  }
  return text;
}

/** Harden one Terraform document. Returns new text + per-violation outcomes. */
function hardenText(
  file: string,
  original: string,
  rules: CloudRule[]
): { text: string; applied: Violation[]; manual: Violation[] } {
  let text = original;
  const applied: Violation[] = [];
  const manualMap = new Map<string, Violation>();
  const skip = new Set<string>();

  for (let iter = 0; iter < MAX_ITERATIONS; iter++) {
    const violations = detectTerraform(file, text, rules);
    // Record manual / non-applicable violations once.
    for (const v of violations) {
      if (!isAutoApplicable(v.rule)) manualMap.set(violationKey(v), v);
    }
    const target = violations.find((v) => isAutoApplicable(v.rule) && !skip.has(violationKey(v)));
    if (!target) break;

    const key = violationKey(target);
    const candidate = applyOne(text, target);
    if (candidate === text) {
      skip.add(key);
      manualMap.set(key, target);
      continue;
    }
    // Verify the fix actually cleared this violation; otherwise revert + flag manual.
    const after = detectTerraform(file, candidate, rules);
    if (after.some((v) => violationKey(v) === key)) {
      skip.add(key);
      manualMap.set(key, target);
      continue;
    }
    text = candidate;
    applied.push(target);
  }

  return { text, applied, manual: Array.from(manualMap.values()) };
}

/**
 * Auto-harden every Terraform file in the working tree against the FSBP/CIS
 * ruleset. Writes changes in place when `write` is true (default). Each applied
 * edit is verified by re-running its own detector before being kept; edits that
 * cannot be applied safely are reported as manual.
 */
export async function autoHardenTree(opts?: { write?: boolean }): Promise<HardenReport> {
  const write = opts?.write !== false;
  const rules = await loadCloudRules();
  const report: HardenReport = { applied: [], manual: [], filesChanged: [] };
  if (rules.length === 0) return report;

  const files = await fg(TF_GLOBS, { dot: true, followSymbolicLinks: false, ignore: IGNORE });
  for (const file of files) {
    let original = "";
    try {
      original = await readFileSafe(file);
    } catch {
      continue;
    }
    const { text, applied, manual } = hardenText(file, original, rules);

    for (const v of applied) {
      report.applied.push({
        ruleId: v.rule.ruleId,
        file,
        resource: `${v.rule.detect.resourceType}.${v.block?.name ?? "?"}`,
        frameworks: v.rule.frameworks
      });
    }
    for (const v of manual) {
      report.manual.push({
        ruleId: v.rule.ruleId,
        file,
        resource: `${v.rule.detect.resourceType}.${v.block?.name ?? "?"}`,
        reason: v.reason,
        snippet: v.rule.remediate.snippet
      });
    }
    if (text !== original) {
      // Verify the REWRITE independently of the regex detector that produced it. The
      // detector is syntax-blind, so hardenText's own self-check accepted output it had
      // just broken: a CRLF file whose attribute was glued to the opening brace still
      // "passed" because the rule no longer matched. Structural damage must be caught by
      // something that does not share the edit's assumptions.
      const damage = detectStructuralDamage(original, text);
      if (damage) {
        report.manual.push({
          ruleId: "APPLY_STRUCTURAL_GUARD",
          file,
          resource: file,
          reason: `Refused to write: the rewrite would have damaged the file (${damage}). Original left untouched.`,
          snippet: ""
        });
        continue;
      }

      report.filesChanged.push(file);
      // `file` is workspace-relative (fg resolves against getWorkspaceRoot()), so the
      // write must be re-anchored to the same root. Resolving it against process.cwd()
      // would read from the workspace but write to the process directory.
      if (write) {
        const abs = join(getWorkspaceRoot(), file);
        try {
          await writeIacFileSafely(abs, original, text);
        } catch (e) {
          report.manual.push({
            ruleId: "APPLY_WRITE_FAILED",
            file,
            resource: file,
            reason: `Could not write the hardened file: ${e instanceof Error ? e.message : String(e)}. Original preserved.`,
            snippet: ""
          });
          // Keep going. A single unwritable file must not abort the sweep and leave the
          // caller with a stack trace and no record of the files already modified.
          report.filesChanged.pop();
        }
      }
    }
  }
  return report;
}
