import { execa } from "execa";
import { access } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";

// Allowlist for git ref strings. Blocks option injection (e.g. --upload-pack=…)
// and git pathspec magic characters. CWE-88 / MITRE ATT&CK T1059.
// Note: ~ and ^ are intentionally included — they are safe because { and } are NOT
// in the allowlist, which blocks ^{} tag-dereferencing and $(...) command substitution.
const SAFE_REF_RE = /^[a-zA-Z0-9_./~^-]+$/;

function validateRef(name: string, value: string): void {
  if (!value || !SAFE_REF_RE.test(value)) {
    throw new Error(`Invalid git ref for ${name}: must contain only alphanumerics, _, ., -, /, ~, ^`);
  }
}

// Files that git reported as changed but that we could not find on disk. Absence of
// findings in a dropped file is not evidence that it is clean, so the gate reports the
// difference rather than silently narrowing its own scope. Mirrors the
// consumeSearchSkips() ledger in repo/search.ts.
type DiffDrop = { file: string; reason: string };
let diffDrops: DiffDrop[] = [];

/** Drain the dropped-file ledger. Callers surface these as a finding. */
export function consumeDiffDrops(): DiffDrop[] {
  const out = diffDrops;
  diffDrops = [];
  return out;
}

/**
 * Absolute path to the repository root.
 *
 * `git diff --name-only` always emits paths relative to the repo root, never to the
 * process cwd. Resolving them against cwd silently dropped every changed file whenever
 * the gate ran from a subdirectory — the standard monorepo pattern
 * (`defaults.run.working-directory` in GitHub Actions). That turned a scoped scan into
 * an empty one with no record, so a PR carrying CRITICAL findings reported clean.
 */
async function repoRoot(): Promise<string> {
  const { stdout } = await execa("git", ["rev-parse", "--show-toplevel"], {
    stdio: ["ignore", "pipe", "pipe"]
  });
  return stdout.trim();
}

export async function getChangedFiles(opts: { baseRef: string; headRef: string }): Promise<string[]> {
  validateRef("baseRef", opts.baseRef);
  validateRef("headRef", opts.headRef);

  // Fix 9: --diff-filter=ACMRT excludes deleted-only files; -M detects renames
  // so renamed files appear as renames rather than delete+add pairs.
  const { stdout } = await execa(
    "git",
    ["diff", "--diff-filter=ACMRT", "-M", "--name-only", `${opts.baseRef}...${opts.headRef}`],
    { stdio: ["ignore", "pipe", "pipe"] }
  );

  const candidates = stdout
    .split("\n")
    .map((s: string) => s.trim())
    .filter(Boolean);

  const root = await repoRoot();

  // Fix 9: skip any file that no longer exists on disk (deleted/moved away edge cases).
  // --diff-filter=ACMRT already excludes deletions, so a miss here is anomalous rather
  // than routine — record it instead of dropping it silently.
  const results: string[] = [];
  for (const file of candidates) {
    const abs = isAbsolute(file) ? file : resolve(root, file);
    try {
      await access(abs);
      results.push(file);
    } catch {
      diffDrops.push({
        file,
        reason: `git reported the file as changed but it was not readable at ${abs}`
      });
    }
  }
  return results;
}
