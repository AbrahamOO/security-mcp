// Verifies every claim in claims/registry.json against the live, built codebase.
// Usage: node scripts/verify-claims.mjs [--strict]
//   --strict also runs the unregistered-number scan (see below) and treats any
//   SCOPED claim missing its rewrite text in the doc as a failure (same as without
//   --strict — SCOPED claims are always checked; --strict only adds the scan).
//
// Five claim types, five strategies:
//   QUANTITY  — the doc must contain `verbatim`, and a formatted probe() value must
//               appear inside that same verbatim string.
//   COVERAGE  — set-diff (or bulk-integrity-check) against the live registry/manifest.
//   GUARANTEE — an adversarial test: arrange the violation, act, assert the defense held.
//   CAPABILITY / GUARANTEE-by-delegation — some guarantees are already proven by the
//               existing e2e suite (dist/tests/run.js); those delegate rather than
//               reimplement, and pass iff that run's exit code is 0 (run once, shared).
//   SCOPED    — the doc must contain `rewrite.newVerbatim`, not the original `verbatim`
//               (or at least the rewrite must be present — a scoped claim's whole point
//               is that the doc no longer makes the old, false, claim).
//
// Unregistered-number scan (--strict): every `<number> (rules|skills|templates|
// controls|agents|sections|checks|frameworks|patterns)` occurrence in the three core
// product docs (README.md, docs/WIKI.md, docs/ARCHITECTURE.md) must be covered by some
// registered claim's verbatim text for that file — this is what stops a new number from
// entering those docs unregistered, not just what audits the numbers that already exist.
import { readFileSync, mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import * as probes from "./claim-probes.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const STRICT = process.argv.includes("--strict");
const registry = JSON.parse(readFileSync(join(ROOT, "claims/registry.json"), "utf8"));

const normalize = (s) => String(s).replace(/\s+/g, " ").trim();
const readDoc = (relPath) => readFileSync(join(ROOT, relPath), "utf8");

const results = []; // { id, ok, detail }
function record(id, ok, detail) {
  results.push({ id, ok, detail });
}

// ---------------------------------------------------------------------------
// QUANTITY
// ---------------------------------------------------------------------------
async function verifyQuantity(claim) {
  const doc = normalize(readDoc(claim.source.file));
  const verbatim = normalize(claim.verbatim);
  if (!doc.includes(verbatim)) {
    return record(claim.id, false, `verbatim not found in ${claim.source.file}: "${claim.verbatim}"`);
  }

  // A null probe marks a point-in-time historical fact (a superseded baseline number,
  // e.g. "up from just 71 templates before this release") — nothing in the live
  // codebase should equal it, so there is nothing to probe. The verbatim-presence
  // check above is the whole claim; this just keeps it out of the unregistered-number
  // scan's flagged list.
  if (claim.probe === null) return record(claim.id, true);

  const probeFn = probes[claim.probe];
  if (!probeFn) return record(claim.id, false, `unknown probe "${claim.probe}"`);
  const raw = await probeFn(...(claim.probeArgs ?? []));

  const fields = claim.probeField === undefined ? [null] : [].concat(claim.probeField);
  for (const field of fields) {
    const value = field === null ? raw : raw[field];
    const asPlain = String(value);
    const asComma = typeof value === "number" ? value.toLocaleString("en-US") : asPlain;
    if (!verbatim.includes(asPlain) && !verbatim.includes(asComma)) {
      return record(
        claim.id, false,
        `probe "${claim.probe}"${field ? `.${field}` : ""} = ${asPlain} (or "${asComma}") not found inside verbatim "${claim.verbatim}"`
      );
    }
  }
  record(claim.id, true);
}

// ---------------------------------------------------------------------------
// COVERAGE
// ---------------------------------------------------------------------------
async function verifyCoverage(claim) {
  if (claim.mode === "set-equal") {
    const a = await Promise.resolve(probes[claim.probeA]());
    const b = await Promise.resolve(probes[claim.probeB]());
    const setA = a instanceof Set ? a : new Set(a);
    const setB = b instanceof Set ? b : new Set(b);
    const aOnly = [...setA].filter((x) => !setB.has(x));
    const bOnly = [...setB].filter((x) => !setA.has(x));
    if (aOnly.length || bOnly.length) {
      return record(
        claim.id, false,
        `${claim.probeA} vs ${claim.probeB} mismatch — only in ${claim.probeA}: [${aOnly.join(", ")}]; only in ${claim.probeB}: [${bOnly.join(", ")}]`
      );
    }
    return record(claim.id, true);
  }

  if (claim.mode === "skill-manifest-integrity") {
    const { readdirSync, statSync } = await import("node:fs");
    const { createHash } = await import("node:crypto");
    const manifest = JSON.parse(readDoc("skills-manifest.json"));
    const manifestNames = new Set(Object.keys(manifest.skills));
    const dirNames = new Set(
      readdirSync(join(ROOT, "skills"))
        .filter((name) => name !== "_TEMPLATE")
        .filter((name) => {
          try { return statSync(join(ROOT, "skills", name, "SKILL.md")).isFile(); }
          catch { return false; }
        })
    );
    const missingFromManifest = [...dirNames].filter((n) => !manifestNames.has(n));
    const missingFromDisk = [...manifestNames].filter((n) => !dirNames.has(n));
    if (missingFromManifest.length || missingFromDisk.length) {
      return record(
        claim.id, false,
        `directory/manifest set mismatch — shipped but unregistered: [${missingFromManifest.join(", ")}]; registered but missing on disk: [${missingFromDisk.join(", ")}]`
      );
    }
    const badHashes = [];
    for (const name of manifestNames) {
      const content = readFileSync(join(ROOT, "skills", name, "SKILL.md"));
      const actual = createHash("sha256").update(content).digest("hex");
      if (actual !== manifest.skills[name].sha256) badHashes.push(name);
    }
    if (badHashes.length) {
      return record(claim.id, false, `stale sha256 for: ${badHashes.join(", ")} (manifest wasn't regenerated after the SKILL.md was last edited)`);
    }
    return record(claim.id, true);
  }

  record(claim.id, false, `unknown COVERAGE mode "${claim.mode}"`);
}

// ---------------------------------------------------------------------------
// GUARANTEE
// ---------------------------------------------------------------------------
let delegatedRunCache = null;
function runDelegatedSuite() {
  if (delegatedRunCache !== null) return delegatedRunCache;
  try {
    execFileSync(process.execPath, ["dist/tests/run.js"], { cwd: ROOT, stdio: "pipe" });
    delegatedRunCache = { ok: true };
  } catch (err) {
    delegatedRunCache = { ok: false, detail: String(err.stderr ?? err.message ?? err).slice(0, 500) };
  }
  return delegatedRunCache;
}

async function verifyGuaranteeDelegated(claim) {
  const res = runDelegatedSuite();
  record(claim.id, res.ok, res.ok ? undefined : `delegated suite (${claim.delegatesTo.file}) failed: ${res.detail}`);
}

async function attemptEmptySeverityBlockUnsignedIsRejected() {
  const savedKey = process.env["SECURITY_POLICY_HMAC_KEY"];
  delete process.env["SECURITY_POLICY_HMAC_KEY"];
  const tmp = mkdtempSync(join(tmpdir(), "claims-guarantee-"));
  try {
    const { runPrGate } = await import(join(ROOT, "dist/gate/policy.js"));
    const { withWorkspace } = await import(join(ROOT, "dist/repo/workspace.js"));

    const policyPath = ".mcp/policies/security-policy.json";
    mkdirSync(join(tmp, ".mcp/policies"), { recursive: true });
    writeFileSync(
      join(tmp, policyPath),
      JSON.stringify({ name: "claims-test-policy", version: "1.0.0", severity_block: [] }, null, 2)
    );
    // A CRITICAL-triggering sample (OpenSSH private key — SECRET_OPENSSH_PRIVATE_KEY).
    const targetFile = "src/config.ts";
    mkdirSync(join(tmp, "src"), { recursive: true });
    writeFileSync(
      join(tmp, targetFile),
      `const key = \`-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n-----END OPENSSH PRIVATE KEY-----\`;\n`
    );

    const result = await withWorkspace(tmp, () =>
      runPrGate({ policyPath, mode: "file_by_file", targets: [targetFile] })
    );

    if (result.status !== "FAIL") {
      return { ok: false, detail: `expected FAIL with severity_block:[] unsigned + a CRITICAL secret, got ${result.status}` };
    }
    return { ok: true };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    if (savedKey !== undefined) process.env["SECURITY_POLICY_HMAC_KEY"] = savedKey;
  }
}

async function attemptNpmAuditUnavailableDoesNotReportClean() {
  const savedPath = process.env["PATH"];
  const tmp = mkdtempSync(join(tmpdir(), "claims-guarantee-"));
  try {
    const { runPrGate } = await import(join(ROOT, "dist/gate/policy.js"));
    const { withWorkspace } = await import(join(ROOT, "dist/repo/workspace.js"));

    const policyPath = ".mcp/policies/security-policy.json";
    mkdirSync(join(tmp, ".mcp/policies"), { recursive: true });
    writeFileSync(join(tmp, policyPath), JSON.stringify({ name: "claims-test-policy", version: "1.0.0" }, null, 2));
    // A minimal manifest + lockfile so checkDependencies doesn't early-return on
    // LOCKFILE_MISSING before ever reaching checkCveExploitation.
    writeFileSync(join(tmp, "package.json"), JSON.stringify({ name: "t", version: "1.0.0", dependencies: {} }, null, 2));
    writeFileSync(join(tmp, "package-lock.json"), JSON.stringify({ name: "t", lockfileVersion: 3, packages: {} }, null, 2));

    // Empty PATH makes `npm audit` fail with ENOENT and no stdout — simulating
    // "npm unavailable," the same evaluability gap a real broken PATH or a
    // container missing npm would produce. checkCveExploitation reads
    // process.env["PATH"] itself (with `?? fallback`, which only applies to
    // null/undefined, not ""), so this reliably forces the failure path.
    process.env["PATH"] = "";

    const result = await withWorkspace(tmp, () =>
      runPrGate({ policyPath, mode: "file_by_file", targets: ["package.json"] })
    );

    const hasEvalFinding = result.findings.some((f) => f.id === "EVAL_UNAVAILABLE_NPM_AUDIT");
    if (!hasEvalFinding) {
      return { ok: false, detail: "expected EVAL_UNAVAILABLE_NPM_AUDIT when npm is unavailable, but it did not fire — the gate would silently report dependency CVE status as clean" };
    }
    return { ok: true };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    if (savedPath !== undefined) process.env["PATH"] = savedPath;
  }
}

const GUARANTEE_TESTS = {
  attempt_empty_severity_block_unsigned__is_rejected: attemptEmptySeverityBlockUnsignedIsRejected,
  attempt_npm_audit_unavailable__does_not_report_clean: attemptNpmAuditUnavailableDoesNotReportClean
};

async function verifyGuarantee(claim) {
  if (claim.delegatesTo) return verifyGuaranteeDelegated(claim);
  const fn = GUARANTEE_TESTS[claim.test];
  if (!fn) return record(claim.id, false, `unknown GUARANTEE test "${claim.test}"`);
  const res = await fn();
  record(claim.id, res.ok, res.ok ? undefined : res.detail);
}

// ---------------------------------------------------------------------------
// SCOPED
// ---------------------------------------------------------------------------
async function verifyScoped(claim) {
  if (!claim.rewrite || !claim.rewrite.newVerbatim) {
    return record(claim.id, false, "SCOPED claim missing rewrite.newVerbatim");
  }
  const doc = normalize(readDoc(claim.source.file));
  const newText = normalize(claim.rewrite.newVerbatim);
  if (!doc.includes(newText)) {
    return record(
      claim.id, false,
      `rewrite.newVerbatim not found in ${claim.source.file} — the doc must actually carry the walked-back claim: "${claim.rewrite.newVerbatim}"`
    );
  }
  record(claim.id, true);
}

// ---------------------------------------------------------------------------
// Unregistered-number scan (--strict)
// ---------------------------------------------------------------------------
const SCANNED_DOCS = ["README.md", "docs/WIKI.md", "docs/ARCHITECTURE.md"];
const NUMBER_UNIT_RE = /\b(\d[\d,]*)\+?\s+(rules|skills|templates|controls|agents|sections|checks|frameworks|patterns)\b/gi;

function unregisteredNumberScan() {
  const registeredByFile = new Map();
  for (const claim of registry.claims) {
    const file = claim.source?.file;
    if (!file) continue;
    const text = normalize(claim.verbatim ?? "") + " " + normalize(claim.rewrite?.newVerbatim ?? "");
    if (!registeredByFile.has(file)) registeredByFile.set(file, []);
    registeredByFile.get(file).push(text);
  }

  const unregistered = [];
  for (const file of SCANNED_DOCS) {
    const doc = readDoc(file);
    const covered = registeredByFile.get(file) ?? [];
    for (const m of doc.matchAll(NUMBER_UNIT_RE)) {
      const hit = normalize(m[0]);
      const isCovered = covered.some((c) => c.includes(hit) || c.includes(normalize(m[1])));
      if (!isCovered) unregistered.push({ file, hit });
    }
  }
  return unregistered;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  for (const claim of registry.claims) {
    switch (claim.type) {
      case "QUANTITY": await verifyQuantity(claim); break;
      case "COVERAGE": await verifyCoverage(claim); break;
      case "GUARANTEE": await verifyGuarantee(claim); break;
      case "SCOPED": await verifyScoped(claim); break;
      default: record(claim.id, false, `unknown claim type "${claim.type}"`);
    }
  }

  let unregistered = [];
  if (STRICT) unregistered = unregisteredNumberScan();

  const failures = results.filter((r) => !r.ok);
  console.log(`[verify-claims] ${results.length - failures.length}/${results.length} claims verified.`);
  for (const f of failures) console.log(`  FAIL ${f.id}: ${f.detail}`);
  if (unregistered.length) {
    console.log(`[verify-claims] ${unregistered.length} unregistered number(s) found in scanned docs:`);
    for (const u of unregistered) console.log(`  ${u.file}: "${u.hit}"`);
  }

  if (failures.length > 0 || unregistered.length > 0) {
    process.exit(1);
  }
  console.log("[verify-claims] all claims TRUE or correctly SCOPED. No unregistered numbers found.".concat(STRICT ? "" : " (run with --strict to also scan for unregistered numbers)"));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
