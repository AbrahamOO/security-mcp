// Detects documentation drift against the bindings in docs/doc-map.json.
// Usage: node scripts/check-doc-drift.mjs [--staged | --range <A..B>]
//
// Two rules, both deterministic. Neither uses a heuristic and neither reads dates.
//
//   Rule 1 — anchor presence (always checked, independent of any change set):
//     every `anchor` in a binding must appear as a substring in every one of its `docs`.
//     This is what catches "ARCHITECTURE.md never mentions agent-exec". It has no false
//     positives by construction: the anchor is either in the file or it is not.
//
//   Rule 2 — scoped freshness (only when a change set is supplied):
//     if the change set touches a binding's `source`, the change set must also touch that
//     binding's `docs`. Scoping to the current change set is what keeps this precise. A
//     doc is never flagged for a source edit made three commits ago.
//
// `advisory: true` bindings report but never fail the run. That is how known debt (the
// hand-rendered SVGs) stays visible without blocking every commit.
//
// Deliberately NOT checked: whether the prose is correct. Nothing can check that. A clean
// run means no doc was left untouched, not that the docs are right.
import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const map = JSON.parse(readFileSync(join(ROOT, "docs/doc-map.json"), "utf8"));

// Returns { files } when a change set was requested and resolved, { files: null } when
// none was requested, and { error } when one was requested but git could not resolve it.
// Those three are deliberately distinct. A range that fails to resolve (shallow clone, no
// origin/main) must never be reported the same way as "no drift", because an unresolvable
// range means Rule 2 did not run, not that it passed.
function changeSet() {
  const argv = process.argv.slice(2);
  const rangeIdx = argv.indexOf("--range");
  const args =
    rangeIdx !== -1 && argv[rangeIdx + 1]
      ? ["diff", "--name-only", argv[rangeIdx + 1]]
      : argv.includes("--staged")
        ? ["diff", "--name-only", "--cached"]
        : null;
  if (!args) return { files: null };
  try {
    const files = execFileSync("git", args, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    return { files };
  } catch (err) {
    return { error: `git ${args.join(" ")} failed: ${String(err.message || err).split("\n")[0]}` };
  }
}

const touches = (files, prefix) => files.some((f) => f === prefix || f.startsWith(prefix));

const failures = [];
const advisories = [];
const { files = null, error: rangeError } = changeSet();

for (const b of map.bindings) {
  const report = b.advisory ? advisories : failures;

  // Rule 1: anchor presence.
  for (const doc of b.docs) {
    const abs = join(ROOT, doc);
    if (!existsSync(abs)) {
      report.push({ id: b.id, doc, detail: "bound doc does not exist" });
      continue;
    }
    if (!b.anchors.length) continue;
    const text = readFileSync(abs, "utf8");
    for (const anchor of b.anchors) {
      if (!text.includes(anchor)) {
        report.push({ id: b.id, doc, detail: `missing anchor "${anchor}"` });
      }
    }
  }

  // Rule 2: scoped freshness.
  if (files && touches(files, b.source)) {
    const stale = b.docs.filter((d) => !files.includes(d));
    if (stale.length) {
      report.push({
        id: b.id,
        doc: stale.join(", "),
        detail: `this change set touches ${b.source} but not these bound doc(s)`
      });
    }
  }
}

let scope;
if (rangeError) scope = "anchor rules only — CHANGE SET UNRESOLVED";
else if (files) scope = `${files.length} changed file(s)`;
else scope = "anchor rules only (no change set requested)";
console.log(`[docs:check] doc-map v${map.version}, ${map.bindings.length} bindings, scope: ${scope}.`);

// A requested-but-unresolvable range means the freshness rule did not run. Say so loudly and
// exit non-zero. Reporting it as clean would be the same defect this project fails other
// people's code for: treating "could not evaluate" as "nothing found".
if (rangeError) {
  console.log(`[docs:check] ${rangeError}`);
  console.log("[docs:check] Rule 2 (scoped freshness) DID NOT RUN. This is not a clean result.");
  console.log("In CI, ensure the checkout has enough history (fetch-depth: 0) and the base ref exists.");
  process.exit(2);
}

for (const a of advisories) console.log(`  ADVISORY ${a.id}: ${a.doc} — ${a.detail}`);

if (failures.length) {
  console.log(`[docs:check] ${failures.length} drift issue(s):`);
  for (const f of failures) {
    const why = map.bindings.find((b) => b.id === f.id)?.why;
    console.log(`  FAIL ${f.id}: ${f.doc} — ${f.detail}`);
    if (why) console.log(`       why: ${why}`);
  }
  console.log("");
  console.log("Fix by updating the doc(s) above, then re-run `npm run docs:check`.");
  console.log("Persona and method: .claude/agents/doc-sync-writer.md");
  console.log("The detector proves a doc was not updated. It cannot prove the prose is correct.");
  process.exit(2);
}

console.log("[docs:check] no drift. (Anchor presence and scoped freshness only — prose correctness is not checked.)");
