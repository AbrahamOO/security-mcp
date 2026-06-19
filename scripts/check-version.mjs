// Enforces the odometer versioning rule. Fails (exit 1) if package.json's
// version has a minor or patch segment >= 10. When TAG_REF is set (e.g. the
// pushed git ref refs/tags/v1.2.3 in CI) it also asserts the tag matches
// package.json, so a release tag can never diverge from the published version.
// Usage: node scripts/check-version.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { violation } from "./version-rule.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const version = pkg.version;

let failed = false;

const reason = violation(version);
if (reason) {
  console.error(`::error::Version ${version} violates the odometer rule: ${reason}`);
  console.error("Bump with:  npm run version:bump   (patch +1, carry at 10: 1.0.9 -> 1.1.0)");
  failed = true;
}

const tagRef = process.env.TAG_REF || process.env.GITHUB_REF || "";
const tagMatch = tagRef.match(/refs\/tags\/v(.+)$/);
if (tagMatch && tagMatch[1] !== version) {
  console.error(
    `::error::Release tag v${tagMatch[1]} does not match package.json version ${version}.`
  );
  failed = true;
}

if (failed) {
  process.exit(1);
}
console.log(`Version ${version} conforms to the odometer rule.`);
