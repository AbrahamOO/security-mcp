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
//               existing e2e suite (dist/tests/legacy.test.js, run via `node --test`);
//               those delegate rather than
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

  // Every numeric token in the verbatim, comma separators stripped. The probe value must
  // EQUAL one of them.
  //
  // This used to be `verbatim.includes(String(value))`, i.e. "does the probe value appear
  // anywhere inside the sentence". A substring test cannot detect an order-of-magnitude
  // error, and it fails open on exactly the maintenance action that matters: edit the doc,
  // edit the registry verbatim to match, both move together. Measured: with zero cloud rules
  // on disk (total = 0), the claim "ships 1,002 rules" verified, because "1,002 rules"
  // contains "0". Also passing were 400-vs-40, 910-vs-91, and 9000-vs-900.
  const numericTokens = (verbatim.match(/\b[\d,]*\d\b/g) ?? []).map((t) => t.replace(/,/g, ""));

  const fields = claim.probeField === undefined ? [null] : [].concat(claim.probeField);
  for (const field of fields) {
    const value = field === null ? raw : raw[field];
    const asPlain = String(value);
    if (typeof value === "number" || /^\d+$/.test(asPlain)) {
      if (!numericTokens.includes(asPlain)) {
        return record(
          claim.id, false,
          `probe "${claim.probe}"${field ? `.${field}` : ""} = ${asPlain}; verbatim asserts [${numericTokens.join(", ") || "no number"}] in "${claim.verbatim}"`
        );
      }
    } else if (!verbatim.includes(asPlain)) {
      // Non-numeric probe values (version strings, names) still use containment.
      return record(
        claim.id, false,
        `probe "${claim.probe}"${field ? `.${field}` : ""} = "${asPlain}" not found inside verbatim "${claim.verbatim}"`
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

/**
 * Run the delegated suite once and parse its TAP output into per-subtest results.
 *
 * This used to record `ok = (exit code === 0)` for every delegated claim without ever
 * reading `delegatesTo.testFunction`. Five GUARANTEE claims were therefore one assertion
 * ("the suite is green") wearing five names: deleting the registration for all five tests
 * the claims named still produced exit 0, and all five still reported as verified. A claim
 * that cannot fail is worse than no claim, because it is read as evidence.
 *
 * Node's node:test TAP output names each top-level test on an `ok N - <name>` line, so the
 * registered test NAME is what we can match. Claims therefore also carry `testName` (the
 * string passed to `test(...)`); when absent we fall back to matching the function name as a
 * substring of the test names, and if that finds nothing we FAIL rather than pass.
 */
function runDelegatedSuite() {
  if (delegatedRunCache !== null) return delegatedRunCache;
  let stdout = "";
  let exitOk = true;
  try {
    stdout = execFileSync(process.execPath, ["--test", "dist/tests/legacy.test.js"], {
      cwd: ROOT, stdio: "pipe", encoding: "utf8", maxBuffer: 64 * 1024 * 1024
    });
  } catch (err) {
    exitOk = false;
    stdout = String(err.stdout ?? "") + String(err.stderr ?? "");
  }
  // "ok 12 - name" / "not ok 12 - name"
  const results = new Map();
  for (const line of stdout.split("\n")) {
    const m = /^(not ok|ok)\s+\d+\s+-\s+(.+?)\s*$/.exec(line.trim());
    if (m) results.set(m[2], m[1] === "ok");
  }
  delegatedRunCache = { exitOk, results, raw: stdout.slice(-2000) };
  return delegatedRunCache;
}

async function verifyGuaranteeDelegated(claim) {
  const res = runDelegatedSuite();
  const want = claim.delegatesTo?.testName;
  const fn = claim.delegatesTo?.testFunction;

  if (res.results.size === 0) {
    return record(claim.id, false, `delegated suite (${claim.delegatesTo.file}) produced no parseable TAP results`);
  }

  let matched = null;
  if (want && res.results.has(want)) {
    matched = want;
  } else if (fn) {
    // Fallback: derive a search key from the function name, e.g.
    // runCompletionGateTests -> "completion gate".
    const key = fn.replace(/^run/, "").replace(/Tests$/, "").replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase();
    for (const name of res.results.keys()) {
      if (name.toLowerCase().includes(key)) { matched = name; break; }
    }
  }

  if (!matched) {
    // Fail CLOSED. A claim whose named test cannot be located is unverified, not verified.
    return record(
      claim.id, false,
      `no test matching ${want ? `testName "${want}"` : `testFunction "${fn}"`} was found in the suite output — ` +
      `the claim delegates to a test that does not exist or is not registered`
    );
  }

  const passed = res.results.get(matched);
  record(
    claim.id, passed,
    passed ? undefined : `delegated test "${matched}" FAILED in ${claim.delegatesTo.file}`
  );
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

async function attemptStrictModeWithoutKeysIsRejected() {
  // config.js computes CONFIG at import time, so this must run in a child process
  // (module caching would otherwise make a second import in this same process a
  // no-op regardless of env vars).
  try {
    execFileSync(process.execPath, ["-e", "import('./dist/config.js')"], {
      cwd: ROOT,
      env: { ...process.env, SECURITY_STRICT: "1", SECURITY_POLICY_HMAC_KEY: "", SECURITY_AUDIT_HMAC_KEY: "" },
      stdio: "pipe"
    });
    return { ok: false, detail: "expected SECURITY_STRICT=1 with no HMAC keys set to throw at import time, but the process exited 0" };
  } catch (err) {
    const stderr = String(err.stderr ?? "");
    if (!stderr.includes("SECURITY_STRICT=1 requires")) {
      return { ok: false, detail: `process failed as expected but not with the strict-mode error: ${stderr.slice(0, 300)}` };
    }
    return { ok: true };
  }
}

const GUARANTEE_TESTS = {
  attempt_empty_severity_block_unsigned__is_rejected: attemptEmptySeverityBlockUnsignedIsRejected,
  attempt_npm_audit_unavailable__does_not_report_clean: attemptNpmAuditUnavailableDoesNotReportClean,
  attempt_strict_mode_without_keys__is_rejected: attemptStrictModeWithoutKeysIsRejected
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
