import { execa } from "execa";

// Allowlist for git ref strings. Blocks option injection (e.g. --upload-pack=…)
// and git pathspec magic characters. CWE-88 / MITRE ATT&CK T1059.
const SAFE_REF_RE = /^[a-zA-Z0-9_./~^-]+$/;

function validateRef(name: string, value: string): void {
  if (!value || !SAFE_REF_RE.test(value)) {
    throw new Error(`Invalid git ref for ${name}: must contain only alphanumerics, _, ., -, /, ~, ^`);
  }
}

export async function getChangedFiles(opts: { baseRef: string; headRef: string }): Promise<string[]> {
  validateRef("baseRef", opts.baseRef);
  validateRef("headRef", opts.headRef);

  // Uses git diff in CI. Assumes checkout has full history for baseRef.
  const { stdout } = await execa("git", ["diff", "--name-only", `${opts.baseRef}...${opts.headRef}`], {
    stdio: ["ignore", "pipe", "pipe"]
  });

  return stdout
    .split("\n")
    .map((s: string) => s.trim())
    .filter(Boolean);
}
