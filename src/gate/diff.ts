import { execa } from "execa";

export async function getChangedFiles(opts: { baseRef: string; headRef: string }): Promise<string[]> {
  // Uses git diff in CI. Assumes checkout has full history for baseRef.
  const { stdout } = await execa("git", ["diff", "--name-only", `${opts.baseRef}...${opts.headRef}`], {
    stdio: ["ignore", "pipe", "pipe"]
  });

  return stdout
    .split("\n")
    .map((s: string) => s.trim())
    .filter(Boolean);
}