import { execa } from "execa";
import { access } from "node:fs/promises";

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

  // Fix 9: skip any file that no longer exists on disk (deleted/moved away edge cases)
  const results: string[] = [];
  for (const file of candidates) {
    try {
      await access(file);
      results.push(file);
    } catch {
      // file does not exist on disk — skip gracefully
    }
  }
  return results;
}
