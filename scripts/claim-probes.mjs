// One probe = one function = one live number (or set). Each probe reads the
// actual built artifact or source file a claim is about, never a cached/copied
// value — so a claim can never drift silently from what the code really does.
// Used by scripts/verify-claims.mjs. Probes that need runtime behavior (not
// just static counts) import compiled output from dist/, matching what a real
// user's installed package runs; run `npm run build` before verifying.
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const readJson = (relPath) => JSON.parse(readFileSync(join(ROOT, relPath), "utf8"));
const readText = (relPath) => readFileSync(join(ROOT, relPath), "utf8");

/** Total IaC/cloud-posture rules across the three provider registries. */
export function cloudRuleCount() {
  const providers = ["aws", "gcp", "azure"];
  const byProvider = Object.fromEntries(
    providers.map((p) => [p, readJson(`defaults/cloud-controls/${p}.json`).rules.length])
  );
  const total = Object.values(byProvider).reduce((a, b) => a + b, 0);
  return { total, byProvider };
}

/** Shipped specialist skills — the manifest is authoritative (excludes _TEMPLATE). */
export function skillCount() {
  return Object.keys(readJson("skills-manifest.json").skills).length;
}

/** Skill names as shipped in the manifest, for skill-level COVERAGE claims. */
export function skillNames() {
  return Object.keys(readJson("skills-manifest.json").skills);
}

/** A single skill's manifest entry (description, etc.), or undefined if absent. */
export function skillManifestEntry(name) {
  return readJson("skills-manifest.json").skills[name];
}

/** Distinct remediation-template keys in the merged REMEDIATION_MAP. */
export async function remediationTemplateIds() {
  const mod = await import(join(ROOT, "dist/gate/remediation-map.js"));
  return new Set(Object.keys(mod.REMEDIATION_MAP));
}

export async function remediationTemplateCount() {
  return (await remediationTemplateIds()).size;
}

/**
 * Distinct finding ids the gate can emit, from source (not dist) since this is a
 * static-literal scan, not a runtime call. Excludes the 3 known runtime-templated
 * ids (NUCLEI_*, SEMGREP_*, CHECKOV_*) which aren't string literals and can't be
 * enumerated without executing the scanner.
 *
 * Covers src/gate/checks/** AND the gate's own modules (policy.ts, baseline.ts,
 * exceptions.ts). This probe used to read the check modules only, so the ids the
 * gate itself emits — BASELINE_REGRESSION, every exceptions-integrity finding,
 * GATE_CHECK_CRASHED — were outside the coverage claim entirely: nine of them had no
 * remediation template and the claim still measured 100%. They are findings a report
 * can contain, so they are findings the claim has to count.
 */
export function ruleIds() {
  const ids = new Set();
  const collect = (relDir) => {
    for (const file of readdirSync(join(ROOT, relDir))) {
      if (!file.endsWith(".ts")) continue;
      const text = readText(`${relDir}/${file}`);
      for (const m of text.matchAll(/id:\s*"([A-Z][A-Z0-9_]+)"/g)) ids.add(m[1]);
    }
  };
  collect("src/gate/checks");
  collect("src/gate");
  return ids;
}

export function ruleIdCount() {
  return ruleIds().size;
}

/**
 * Distinct rule ids defined in one specific check-module file, e.g. "k8s.ts". Not the
 * same as filtering ruleIds() by id prefix — some prefixes (K8S_, IAC_) are also used
 * by other modules (emerging-cloud.ts) for a handful of newer rules, so a prefix filter
 * over-counts relative to what a doc means by "the Kubernetes module has N checks".
 */
export function ruleIdCountByFile(fileName) {
  const text = readText(`src/gate/checks/${fileName}`);
  const ids = new Set();
  for (const m of text.matchAll(/id:\s*"([A-Z][A-Z0-9_]+)"/g)) ids.add(m[1]);
  return ids.size;
}

/** Number of remediation-template keys defined directly in one remediation-parts file. */
export function remediationPartTemplateCount(partFile) {
  const text = readText(`src/gate/remediation-parts/${partFile}`);
  return (text.match(/^\s*"?[A-Z][A-Z0-9_]+"?\s*:\s*\{$/gm) ?? []).length;
}

/** Number of entries in the CHECKS registry (src/gate/policy.ts), from dist. */
export async function checkModuleCount() {
  const mod = await import(join(ROOT, "dist/gate/policy.js"));
  return mod.CHECKS.length;
}

/** Total controls in the compliance control catalog. */
export function controlCatalogCount() {
  return readJson("defaults/control-catalog.json").controls.length;
}

/**
 * Maximum agents buildInitialAgentNames() can name in one run: every conditional
 * branch enabled. This is the static-spawn-tree ceiling the README states, not the
 * AgentName type's full universe (which includes agents outside the spawn tree).
 *
 * Every signal set must be populated. Leaving languages/frameworks/ciPlatform empty
 * skipped the web branch (11 agents) and the CI branch (4), so this probe returned 74
 * while the real ceiling is 89, and verify:claims confirmed the README against a number
 * the probe itself was under-measuring. A probe that reproduces the documented figure
 * rather than measuring the system verifies nothing.
 */
export async function maxAgentCount() {
  const mod = await import(join(ROOT, "dist/mcp/orchestration.js"));
  const names = mod.buildInitialAgentNames({
    languages: ["typescript", "python", "go", "java"],
    frameworks: ["kubernetes", "react", "express", "django", "spring"],
    databases: ["postgres", "mongodb", "redis"],
    cloudProvider: ["aws", "gcp", "azure"],
    paymentProcessor: ["stripe"],
    hasAI: true, hasMobile: true, hasPII: true, hasPayments: true,
    packageManagers: ["npm", "pip"],
    ciPlatform: ["github-actions", "gitlab-ci"]
  });
  return new Set(names).size;
}

/** skills-manifest.json's top-level version (the skill-registry version, distinct from package.json's npm version). */
export function manifestVersion() {
  return readJson("skills-manifest.json").version;
}

/** npm package version (package.json), distinct from manifestVersion(). */
export function packageVersion() {
  return readJson("package.json").version;
}

/** Total SKILL.md sections (24 numbered + 4 universal) that coverage tracking enforces. */
export async function skillSectionCount() {
  const mod = await import(join(ROOT, "dist/mcp/orchestration.js"));
  return mod.SKILL_MD_SECTIONS.length;
}

/** Pre-release checklist item/section counts, parsed from its source-of-truth template literal. */
export function checklistCounts() {
  const text = readText("src/mcp/server.ts");
  const m = /const CHECKLIST_ALL = `([\s\S]*?)`;/.exec(text);
  if (!m) throw new Error("CHECKLIST_ALL template literal not found in src/mcp/server.ts");
  const body = m[1];
  const items = (body.match(/^- \[ \]/gm) ?? []).length;
  const sections = (body.match(/^## /gm) ?? []).length;
  return { items, sections };
}
