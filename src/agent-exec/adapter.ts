/**
 * Adapter loading, CLI detection, auth probing, and argv rendering.
 *
 * Precedence mirrors src/gate/checks/scanners.ts:41-61 exactly (env override, then
 * project file, then shipped default) so operators only learn one pattern.
 */
import { readFile } from "node:fs/promises";
import { existsSync, readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { execa } from "execa";
import fg from "fast-glob";
import { z } from "zod";
import { getWorkspaceRoot } from "../repo/workspace.js";
import {
  AdapterRegistrySchema, assertKnownTokens, tokensIn,
  type AdapterConfig, type AdapterRegistry
} from "./adapter-schema.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "../..");

export type CapabilityTier = "light" | "standard" | "advanced";

// ---------------------------------------------------------------------------
// Registry loading
// ---------------------------------------------------------------------------

/** Deep-merge so an operator can fix ONE flag without restating a whole adapter. */
function deepMerge<T>(base: T, override: unknown): T {
  if (override === undefined || override === null) return base;
  if (Array.isArray(override) || typeof override !== "object") return override as T;
  if (typeof base !== "object" || base === null || Array.isArray(base)) return override as T;
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [k, v] of Object.entries(override as Record<string, unknown>)) {
    // Arrays replace wholesale — element-wise merging of a flag list is surprising
    // and would make it impossible to REMOVE a default flag.
    out[k] = deepMerge((base as Record<string, unknown>)[k], v);
  }
  return out as T;
}

/**
 * Adapter fields an in-workspace override file may NOT set.
 *
 * Both override sources live inside the workspace root, which is the repository under
 * review. That content is untrusted: a repo can ship `.mcp/agent-clis/agent-clis.json`.
 * Before this guard, such a file could set `detect.extraSearchGlobs` to a script in the
 * repo, and `detectProviders` would execute it with `--version` on a bare
 * `orchestration.executor_status` or `security.fortify` call. It could also grant `Task`
 * and `Bash` via `tools.forbidden`, select a permissive `permission.applyValue`, empty
 * `permission.bannedArgs`, rewrite `invoke.argv`, or widen `auth.childCredentialEnv` so one
 * child receives every provider's credentials.
 *
 * Tuning that cannot change WHAT is executed, WITH what privileges, or WITH whose secrets
 * stays overridable. Everything else must come from the shipped defaults.
 */
const UNTRUSTED_OVERRIDE_DENIED_FIELDS = new Set([
  "detect",          // chooses the binary that gets executed
  "auth",            // childCredentialEnv decides which secrets cross into the child
  "invoke",          // the argv template itself
  "tools",           // the forbidden list backing "sub-agent tools are never grantable"
  "permission",      // sandbox mode and the banned-argument blocklist
  "recursionGuard",  // the depth/profile markers that stop an agent spawning agents
  "class"            // A vs B changes which execution path runs
]);

/**
 * Strip execution-affecting fields from an override that came from inside the workspace.
 * Returns the sanitized value plus the dotted paths that were dropped, so the caller can
 * log them rather than silently ignoring an operator's edit.
 */
function sanitizeUntrustedOverride(raw: unknown): { value: unknown; dropped: string[] } {
  const dropped: string[] = [];
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return { value: raw, dropped };
  const src = raw as Record<string, unknown>;
  const out: Record<string, unknown> = { ...src };

  const adapters = src["adapters"];
  if (adapters && typeof adapters === "object" && !Array.isArray(adapters)) {
    const cleanAdapters: Record<string, unknown> = {};
    for (const [id, cfg] of Object.entries(adapters as Record<string, unknown>)) {
      if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
        cleanAdapters[id] = cfg;
        continue;
      }
      const cleanCfg: Record<string, unknown> = {};
      for (const [field, v] of Object.entries(cfg as Record<string, unknown>)) {
        if (UNTRUSTED_OVERRIDE_DENIED_FIELDS.has(field)) dropped.push(`adapters.${id}.${field}`);
        else cleanCfg[field] = v;
      }
      cleanAdapters[id] = cleanCfg;
    }
    out["adapters"] = cleanAdapters;
  }
  return { value: out, dropped };
}

async function readJsonIfPresent(path: string): Promise<unknown | null> {
  try {
    return JSON.parse(await readFile(path, "utf-8")) as unknown;
  } catch {
    return null;
  }
}

let cachedRegistry: AdapterRegistry | null = null;

export async function loadAdapterRegistry(opts?: { force?: boolean }): Promise<AdapterRegistry> {
  if (cachedRegistry && !opts?.force) return cachedRegistry;

  const shipped = JSON.parse(await readFile(join(PKG_ROOT, "defaults", "agent-clis.json"), "utf-8")) as unknown;
  let merged: unknown = shipped;

  // Both override sources below resolve INSIDE the workspace root, i.e. inside the
  // repository under review. Their content is untrusted input, not configuration, so
  // execution-affecting fields are stripped before the merge. Without this, a file
  // committed in a scanned repo achieves code execution on the reviewer's machine through
  // orchestration.executor_status or security.fortify, with no agent run and no LLM
  // involved. See UNTRUSTED_OVERRIDE_DENIED_FIELDS.
  const dropped: string[] = [];

  const project = await readJsonIfPresent(join(getWorkspaceRoot(), ".mcp", "agent-clis", "agent-clis.json"));
  if (project) {
    const clean = sanitizeUntrustedOverride(project);
    dropped.push(...clean.dropped);
    merged = deepMerge(merged, clean.value);
  }

  const overridePath = process.env["SECURITY_AGENT_CLIS"];
  if (overridePath) {
    // CWE-22: an override path must not escape the workspace, same guard scanners.ts uses.
    const root = getWorkspaceRoot();
    const resolved = resolve(root, overridePath);
    if (!resolved.startsWith(root + sep) && resolved !== root) {
      throw new Error(`SECURITY_AGENT_CLIS path '${overridePath}' escapes the project directory`);
    }
    const override = await readJsonIfPresent(resolved);
    if (!override) throw new Error(`SECURITY_AGENT_CLIS path '${overridePath}' is not readable JSON`);
    // Confined to the workspace by the check above, which is exactly why it is untrusted too.
    const clean = sanitizeUntrustedOverride(override);
    dropped.push(...clean.dropped);
    merged = deepMerge(merged, clean.value);
  }

  if (dropped.length > 0) {
    console.log(JSON.stringify({
      event: "ADAPTER_OVERRIDE_FIELDS_REJECTED",
      severity: "HIGH",
      timestamp: new Date().toISOString(),
      dropped,
      reason: "an in-workspace adapter override may not set execution, credential, tool, or permission fields"
    }));
  }

  const registry = AdapterRegistrySchema.parse(merged);
  assertKnownTokens(registry); // fail at load, not mid-run with a literal "{foo}" in argv
  cachedRegistry = registry;
  return registry;
}

/** Test seam. */
export function resetAdapterRegistryCache(): void {
  cachedRegistry = null;
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

export type DetectedAdapter = {
  id: string;
  config: AdapterConfig;
  binaryPath: string;
  version: string | null;
  source: "env" | "path" | "glob";
};

export type AuthState = {
  mode: "none" | "probe" | "env";
  ok: boolean;
  /** True when we could not actually confirm auth (e.g. Copilot has no status cmd). */
  presumed: boolean;
  detail: Record<string, string>;
  reason?: string;
};

function expandHome(p: string): string {
  return p.startsWith("~/") ? join(homedir(), p.slice(2)) : p;
}

const BASE_ENV_ALLOWLIST = [
  "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "TMPDIR", "TERM",
  "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
  "CLAUDE_CONFIG_DIR", "CODEX_HOME", "NODE_OPTIONS"
];

/** Provider credentials that must never leak into a DIFFERENT provider's child. */
const ALL_PROVIDER_CREDENTIALS = [
  "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
  "OPENAI_API_KEY",
  "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN",
  "GEMINI_API_KEY", "GOOGLE_API_KEY"
];

/**
 * Build the child env with `extendEnv:false` semantics.
 *
 * Credential passthrough is PER ADAPTER. A blanket strip of GITHUB_TOKEN would break
 * Copilot, whose documented headless precedence is COPILOT_GITHUB_TOKEN > GH_TOKEN >
 * GITHUB_TOKEN — while a Claude child has no business seeing a GitHub token at all.
 * Everything else is dropped: the parent's HMAC/attestation keys, webhook and ticketing
 * credentials, cloud keys. These children read untrusted repo content with tool access.
 *
 * Lives here rather than in executor.ts so the detection probes below can share it:
 * they spawn the same third-party binaries and must not hand them the parent's secrets.
 */
export function buildChildEnv(cfg: AdapterConfig, extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of BASE_ENV_ALLOWLIST) {
    const v = process.env[key];
    if (v !== undefined) env[key] = v;
  }

  const permitted = new Set(cfg.auth.childCredentialEnv);
  for (const key of ALL_PROVIDER_CREDENTIALS) {
    if (!permitted.has(key)) continue;
    const v = process.env[key];
    if (v !== undefined && v.length > 0) env[key] = v;
  }

  for (const [k, v] of Object.entries(cfg.recursionGuard.env)) env[k] = v;
  for (const [k, v] of Object.entries(cfg.invoke.env)) env[k] = v;
  for (const [k, v] of Object.entries(extra)) env[k] = v;

  env["CLAUDE_CODE_ENTRYPOINT"] = "security-mcp-executor";
  return env;
}

async function probeVersion(bin: string, cfg: AdapterConfig): Promise<string | null> {
  try {
    // extendEnv:false + the adapter allowlist. These probes run on every
    // executor_status and every security.fortify call; inheriting the parent env handed
    // the vendor binary the attestation HMAC key, cloud keys, and every provider token.
    const r = await execa(bin, cfg.detect.versionArgs, {
      timeout: 10_000, reject: false, all: true,
      extendEnv: false, env: buildChildEnv(cfg, {})
    });
    const text = `${r.stdout ?? ""}\n${r.stderr ?? ""}`;
    const m = compileConfigRegex(cfg.detect.versionRegex).exec(text);
    return m?.[1] ?? (r.exitCode === 0 ? "" : null);
  } catch {
    return null;
  }
}

function versionAtLeast(actual: string, min: string): boolean {
  const a = actual.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const b = min.split(".").map((n) => Number.parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0, y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return true;
}

/**
 * Resolve a binary for one adapter.
 *
 * Searches PATH, then declared globs (extension bundles, npm/pnpm global roots).
 * A PATH-only scan is NOT sufficient discovery: on the development machine `codex`
 * lived inside a VS Code extension bundle and `copilot` was an npm global symlink,
 * and both were invisible to `command -v`.
 */
export async function resolveBinary(id: string, cfg: AdapterConfig): Promise<{ path: string; source: "path" | "glob" } | null> {
  for (const bin of cfg.detect.binaries) {
    try {
      const which = await execa(process.platform === "win32" ? "where" : "which", [bin], { timeout: 5000, reject: false });
      const first = String(which.stdout ?? "").split("\n").map((s) => s.trim()).filter(Boolean)[0];
      if (which.exitCode === 0 && first && existsSync(first)) return { path: first, source: "path" };
    } catch { /* fall through to globs */ }
  }

  const globs = cfg.detect.extraSearchGlobs.map(expandHome);
  const literals = globs.filter((g) => !g.includes("*"));
  for (const lit of literals) {
    if (existsSync(lit)) return { path: lit, source: "glob" };
  }
  const patterns = globs.filter((g) => g.includes("*"));
  if (patterns.length > 0) {
    const hits = await fg(patterns, { onlyFiles: true, followSymbolicLinks: true, suppressErrors: true, absolute: true });
    // Newest first: extension bundles keep several versions side by side and the
    // most recently written one is the one the editor is actually using.
    const sorted = hits.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
    if (sorted[0]) return { path: sorted[0], source: "glob" };
  }
  void id;
  return null;
}

/** Probe auth without spending model tokens. */
export async function probeAuth(cfg: AdapterConfig, binaryPath: string): Promise<AuthState> {
  if (cfg.auth.mode === "none") {
    return { mode: "none", ok: true, presumed: false, detail: {} };
  }

  if (cfg.auth.mode === "env") {
    const found = cfg.auth.envVars.find((v) => (process.env[v] ?? "").trim().length > 0);
    // Copilot stores an OAuth token in the system credential store, which we cannot
    // read. Absence of an env var therefore does NOT prove logged-out — it means
    // unknown. Report presumed=true so the run aborts on the FIRST agent failure with
    // auth_unknown rather than burning the whole roster.
    return {
      mode: "env",
      ok: true,
      presumed: found === undefined,
      detail: found ? { source: found } : { source: "credential-store (unverifiable)" },
      ...(found ? {} : { reason: "no auth env var set; credential store cannot be inspected" })
    };
  }

  if (cfg.auth.probeArgv.length === 0) {
    return { mode: "probe", ok: true, presumed: true, detail: {}, reason: "adapter declares no auth probe" };
  }

  try {
    // Same isolation as probeVersion. The adapter's own childCredentialEnv still comes
    // through, which is what an auth probe legitimately needs to report login state.
    const r = await execa(binaryPath, cfg.auth.probeArgv, {
      timeout: 15_000, reject: false, all: true,
      extendEnv: false, env: buildChildEnv(cfg, {})
    });
    const parse = cfg.auth.probeParse;
    const text = `${r.stdout ?? ""}\n${r.stderr ?? ""}`;
    if (!parse) return { mode: "probe", ok: r.exitCode === 0, presumed: false, detail: {} };

    if (parse.format === "json") {
      const obj = JSON.parse(String(r.stdout ?? "{}")) as Record<string, unknown>;
      const ok = parse.loggedInPath ? getPath(obj, parse.loggedInPath) === (parse.expect ?? true) : r.exitCode === 0;
      const detail: Record<string, string> = {};
      for (const [k, p] of Object.entries(parse.detailPaths)) {
        const v = getPath(obj, p);
        // Never surface identity fields (email/orgId) into logs or tool output.
        if (typeof v === "string" || typeof v === "number") detail[k] = String(v);
      }
      return { mode: "probe", ok, presumed: false, detail, ...(ok ? {} : { reason: "probe reported logged out" }) };
    }

    const re = typeof parse.expect === "string" ? compileConfigRegex(parse.expect) : null;
    const ok = re ? re.test(text) : r.exitCode === 0;
    return { mode: "probe", ok, presumed: false, detail: {}, ...(ok ? {} : { reason: "probe output did not match expected pattern" }) };
  } catch (err) {
    return { mode: "probe", ok: false, presumed: false, detail: {}, reason: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Compile a regex written in config.
 *
 * Config authors reach for Perl/Python inline flags like `(?i)foo`, which JavaScript's
 * RegExp does not support — it silently fails to match rather than throwing, which is
 * the worst possible failure mode for an auth probe. Translate a leading inline flag
 * group into real RegExp flags so the config format behaves the way its authors expect.
 */
export function compileConfigRegex(source: string): RegExp {
  const m = /^\(\?([imsux]+)\)/.exec(source);
  if (!m) return new RegExp(source);
  const flags = (m[1] ?? "").replace(/[xu]/g, ""); // x (extended) has no JS equivalent
  return new RegExp(source.slice(m[0].length), flags);
}

function getPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, k) => {
    if (acc && typeof acc === "object") return (acc as Record<string, unknown>)[k];
    return undefined;
  }, obj);
}

// ---------------------------------------------------------------------------
// Detection cache — 84 agent launches must not run 84 version probes
// ---------------------------------------------------------------------------

type CacheEntry = { id: string; binaryPath: string; version: string | null; mtimeMs: number; at: number };

const CACHE_TTL_MS = 60 * 60 * 1000;

const CacheEntrySchema = z.object({
  id: z.string().min(1),
  binaryPath: z.string().min(1),
  version: z.string().nullable(),
  mtimeMs: z.number().finite(),
  at: z.number().finite()
});

/**
 * The cache lives under the user's home directory, never under the workspace.
 *
 * It records which binary each adapter id resolved to, and `detectProviders` executes
 * that path. Anything able to write the cache therefore chooses what gets executed, so
 * the file must sit outside the repository under review. This is the same reasoning that
 * puts `detect` in UNTRUSTED_OVERRIDE_DENIED_FIELDS: the sibling override file is
 * sanitized rather than trusted, and a cache inside the workspace would reintroduce the
 * identical path by another name.
 */
function cachePath(): string {
  return join(homedir(), ".security-mcp", "agent-clis", "detected.json");
}

/**
 * Entries are validated individually. A malformed or partially corrupt cache degrades to
 * a miss and a fresh probe, never to an unchecked path handed to execa.
 */
function readCache(): CacheEntry[] {
  try {
    const raw: unknown = JSON.parse(readFileSync(cachePath(), "utf-8"));
    if (!Array.isArray(raw)) return [];
    const out: CacheEntry[] = [];
    for (const item of raw) {
      const parsed = CacheEntrySchema.safeParse(item);
      if (parsed.success) out.push(parsed.data);
    }
    return out;
  } catch {
    return [];
  }
}

function writeCache(entries: CacheEntry[]): void {
  try {
    mkdirSync(dirname(cachePath()), { recursive: true, mode: 0o700 });
    writeFileSync(cachePath(), JSON.stringify(entries, null, 2) + "\n", { mode: 0o600 });
  } catch { /* cache is an optimisation; never fatal */ }
}

/** True when `p` resolves to the workspace root or anything beneath it. */
function isInsideWorkspace(p: string): boolean {
  const root = resolve(getWorkspaceRoot());
  const target = resolve(p);
  return target === root || target.startsWith(root + sep);
}

function cacheHit(entries: CacheEntry[], id: string): CacheEntry | null {
  const e = entries.find((x) => x.id === id);
  if (!e) return null;
  // Two-sided, so a future timestamp expires rather than never expiring.
  if (Math.abs(Date.now() - e.at) > CACHE_TTL_MS) return null;
  // An agent CLI is installed on the machine, not shipped by the repository under
  // review. A cached path inside the workspace is never a legitimate hit, and honouring
  // one would let scanned content choose the binary that detectProviders executes.
  if (isInsideWorkspace(e.binaryPath)) return null;
  if (!existsSync(e.binaryPath)) return null;
  // Invalidate when the binary is replaced (extension update, npm upgrade).
  try {
    if (statSync(e.binaryPath).mtimeMs !== e.mtimeMs) return null;
  } catch {
    return null;
  }
  return e;
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

export type ProviderStatus = {
  id: string;
  label: string;
  class: "A" | "B";
  available: boolean;
  binaryPath: string | null;
  version: string | null;
  auth: AuthState;
  unverifiedFields: string[];
  maxConcurrent: number;
  degraded: string[];
  notes: string;
};

/** Capability shortfalls a reviewer should see BEFORE committing to a long run. */
export function degradationsFor(cfg: AdapterConfig, auth: AuthState): string[] {
  const out: string[] = [];
  if (cfg.class === "B") out.push("no_agentic_loop");
  if (!cfg.tools.supportsFileTools && cfg.class === "A") out.push("class_a_without_file_tools");
  if (cfg.structuredOutput.mode === "none") out.push("no_structured_output");
  if (!cfg.usage.inputTokensPath && !cfg.usage.costUsdPath) out.push("no_usage_accounting");
  if (!cfg.tools.denyFlag && !cfg.tools.excludedFlag && !cfg.tools.availableFlag) out.push("no_tool_control");
  if (!cfg.permission.flag && !cfg.permission.addDirFlag) out.push("no_sandbox_control");
  if (Object.keys(cfg.models.tiers).length === 0 && !cfg.models.default) out.push("no_model_tiers");
  if (cfg.rateLimit.stderrPatterns.length === 0 && cfg.rateLimit.exitCodes.length === 0) out.push("no_rate_limit_detection");
  if (auth.presumed) out.push("auth_unverified");
  if (cfg._unverified.length > 0) out.push("adapter_config_unverified");
  return out;
}

/**
 * Detect every usable provider.
 *
 * Returns ALL of them, not just the first: running Claude, Codex, and Copilot fleets
 * concurrently is the single biggest throughput lever available, since each has its
 * own subscription, rate limit, and auth, and three model families find different
 * defects than one does.
 */
export async function detectProviders(opts?: { force?: boolean }): Promise<ProviderStatus[]> {
  const registry = await loadAdapterRegistry(opts);
  const override = process.env[registry.selection.overrideEnv]?.trim();

  let ids = registry.selection.order.filter((id) => registry.adapters[id]);
  if (override) {
    if (registry.adapters[override]) {
      ids = [override];
    } else {
      // An explicit override that names an unknown binary binds to `generic`. It must
      // FAIL LOUDLY rather than silently falling back to auto-detection — otherwise a
      // typo silently runs a different provider than the operator asked for.
      const generic = registry.adapters[registry.selection.fallback];
      if (!generic) throw new Error(`SECURITY_AGENT_CLI='${override}' is unknown and no fallback adapter is defined`);
      const cfg: AdapterConfig = { ...generic, detect: { ...generic.detect, binaries: [override] } };
      const bin = await resolveBinary("generic", cfg);
      if (!bin) throw new Error(`SECURITY_AGENT_CLI='${override}' was not found on PATH or in any known install location`);
      const version = await probeVersion(bin.path, cfg);
      const auth = await probeAuth(cfg, bin.path);
      return [{
        id: "generic", label: `${generic.label} (${override})`, class: cfg.class, available: true,
        binaryPath: bin.path, version, auth, unverifiedFields: cfg._unverified,
        maxConcurrent: cfg.limits.maxConcurrent, degraded: degradationsFor(cfg, auth), notes: cfg.notes
      }];
    }
  }

  const cache = readCache();
  const nextCache: CacheEntry[] = [];
  const out: ProviderStatus[] = [];

  for (const id of ids) {
    const cfg = registry.adapters[id];
    if (!cfg) continue;

    const hit = opts?.force ? null : cacheHit(cache, id);
    let binaryPath: string | null = hit?.binaryPath ?? null;
    let version: string | null = hit?.version ?? null;

    if (!hit) {
      const found = await resolveBinary(id, cfg);
      if (found) {
        binaryPath = found.path;
        version = await probeVersion(found.path, cfg);
      }
    }

    if (!binaryPath || version === null) continue;
    // Belt and braces with the cacheHit guard: whichever way the path was produced, a
    // binary inside the repository under review is never executed as an agent CLI.
    if (isInsideWorkspace(binaryPath)) continue;
    if (cfg.detect.minVersion && version && !versionAtLeast(version, cfg.detect.minVersion)) continue;

    try {
      nextCache.push({ id, binaryPath, version, mtimeMs: statSync(binaryPath).mtimeMs, at: hit?.at ?? Date.now() });
    } catch { /* binary vanished mid-scan */ }

    const auth = await probeAuth(cfg, binaryPath);
    out.push({
      id, label: cfg.label, class: cfg.class,
      // A logged-out provider is not available, but it does NOT abort detection —
      // a logged-out claude must lose to a working copilot rather than sink the run.
      available: auth.ok,
      binaryPath, version, auth,
      unverifiedFields: cfg._unverified,
      maxConcurrent: cfg.limits.maxConcurrent,
      degraded: degradationsFor(cfg, auth),
      notes: cfg.notes
    });
  }

  writeCache(nextCache);
  return out;
}

// ---------------------------------------------------------------------------
// argv rendering — pure, exhaustively unit-tested
// ---------------------------------------------------------------------------

export type RenderContext = Partial<Record<string, string>>;

/**
 * Render an adapter invocation.
 *
 * Two invariants that must never be relaxed:
 *  1. A token is substituted INSIDE a single argv element. It never splits into
 *     multiple elements, and `shell` is never enabled anywhere, so a value
 *     containing spaces or quotes cannot become extra arguments.
 *  2. An optionalGroup is emitted only when EVERY token in it resolves non-empty.
 *     That is what turns "this CLI has no budget flag" into a config fact.
 */
export function renderArgv(cfg: AdapterConfig, ctx: RenderContext): string[] {
  const substitute = (s: string): string =>
    s.replace(/\{[a-zA-Z][a-zA-Z0-9]*\}/g, (tok) => ctx[tok] ?? "");

  const argv: string[] = [];
  for (const part of cfg.invoke.argv) {
    const tokens = tokensIn(part);
    // A base-argv element whose token is empty would emit "" — a real empty argument
    // some CLIs treat as a positional. Drop the element and its preceding flag.
    if (tokens.length > 0 && tokens.some((t) => !(ctx[t] ?? "").length)) {
      if (argv.length > 0 && argv[argv.length - 1]?.startsWith("-")) argv.pop();
      continue;
    }
    argv.push(substitute(part));
  }

  for (const [, group] of Object.entries(cfg.invoke.optionalGroups)) {
    const resolvable = group.every((part) => tokensIn(part).every((t) => (ctx[t] ?? "").length > 0));
    if (!resolvable) continue;
    for (const part of group) argv.push(substitute(part));
  }

  const banned = new Set(cfg.permission.bannedArgs);
  for (const a of argv) {
    if (banned.has(a)) {
      throw new Error(`Adapter '${cfg.label}' emitted banned argument '${a}' — this flag disables the security boundary`);
    }
  }
  return argv;
}

/** Join a tool list the way this CLI expects. Repeat-style is handled by the caller. */
export function joinTools(cfg: AdapterConfig, tools: string[]): string {
  return cfg.tools.separator === "comma" ? tools.join(",") : tools.join(" ");
}

/** Map a capability tier to this CLI's model alias. Registry IDs are never passed. */
export function modelForTier(cfg: AdapterConfig, tier: CapabilityTier): string {
  return cfg.models.tiers[tier] ?? cfg.models.default ?? "";
}

export function effortForTier(cfg: AdapterConfig, tier: CapabilityTier): string {
  return cfg.models.effortTiers[tier] ?? "";
}
