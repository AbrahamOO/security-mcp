// Bumps package.json by exactly +0.0.1 under the odometer rule (carry at 10).
// Usage: node scripts/bump-version.mjs [--dry-run]
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { bump } from "./version-rule.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkgPath = join(root, "package.json");
const dryRun = process.argv.includes("--dry-run");

const raw = readFileSync(pkgPath, "utf8");
const current = JSON.parse(raw).version;
const next = bump(current);

if (dryRun) {
  console.log(`${current} -> ${next} (dry run; package.json unchanged)`);
  process.exit(0);
}

// Targeted replace preserves the file's existing formatting.
const updated = raw.replace(/("version"\s*:\s*")[^"]+(")/, `$1${next}$2`);
if (updated === raw) {
  throw new Error('Could not locate the "version" field in package.json.');
}
writeFileSync(pkgPath, updated);

console.log(`Bumped version: ${current} -> ${next}`);
console.log(`Next: commit, then tag with  git tag v${next} && git push --tags`);
