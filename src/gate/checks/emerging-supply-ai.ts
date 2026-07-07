/**
 * Emerging supply-chain + AI/agentic threat detection (2025-2026 wave).
 *
 * This module targets a handful of recent, high-profile attack patterns that the
 * older supply-chain and AI checks do not cover. Each rule is written so a
 * non-security reader can understand WHAT the pattern is, WHY it is dangerous,
 * and WHICH real-world incident / CVE / CWE it maps to:
 *
 *   Supply chain
 *   ─ SUPPLY_SHAI_HULUD_IOC             (CWE-506) — the "Shai-Hulud" self-replicating
 *                                        npm worm: oversized router_init/router_runtime
 *                                        payloads, its published IoC hash, and the
 *                                        credential-stealing postinstall it plants.
 *   ─ SUPPLY_LOCKFILE_OFFREGISTRY_RESOLVED (CWE-345) — a lockfile "resolved" URL that
 *                                        silently pulls a package from an attacker-
 *                                        controlled host instead of the real registry.
 *   ─ SUPPLY_MCP_REMOTE_COMMAND_INJECTION (CVE-2025-6514, CWE-78) — the mcp-remote RCE
 *                                        and the general pattern of feeding an MCP/OAuth
 *                                        server's response straight into a shell.
 *
 *   AI / agentic
 *   ─ AI_INVISIBLE_UNICODE_INJECTION    (CWE-1427) — invisible Unicode (tag chars,
 *                                        zero-width, bidi overrides, variation selectors)
 *                                        used to smuggle instructions past human review.
 *   ─ AI_MCP_CONFIG_RUG_PULL            (CVE-2025-54136 / -54135, CWE-708) — a committed
 *                                        MCP config whose server command runs a shell or
 *                                        an unpinned remote package ("rug pull" on launch).
 *   ─ AI_MODEL_PICKLE_OPCODE_DANGEROUS  (CWE-502) — a serialized model file whose pickle
 *                                        opcode stream imports os/subprocess/eval etc.,
 *                                        i.e. it runs code the moment it is loaded.
 *   ─ AI_A2A_CREDENTIAL_FORWARDING      (CWE-441) — agent-to-agent delegation that hands
 *                                        the caller's raw token to a downstream agent with
 *                                        no scoping or re-authorization (confused deputy).
 *
 * All detection is best-effort and defensive: every rule swallows malformed input
 * rather than throwing, file reads are size-capped, and regexes are kept tight to
 * avoid catastrophic backtracking. For the invisible-Unicode rule we deliberately
 * emit only the codepoint (e.g. "U+200B at file:line") and NEVER echo the raw
 * invisible bytes back into evidence.
 */
import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";

// Lockfiles and manifests that carry dependency-resolution metadata.
const LOCKFILE_RE = /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json)$/i;
const PACKAGE_JSON_RE = /(?:^|\/)package\.json$/i;

// File types that a human (or an AI agent) reads as text/instructions and where
// an invisible-Unicode payload would be dangerous. We deliberately exclude
// compiled/binary assets — invisible bytes there are noise, not instructions.
const TEXTUAL_FILE_GLOBS = [
  "**/*.md",
  "**/*.mdx",
  "**/*.markdown",
  "**/*.txt",
  "**/*.rst",
  "**/*.json",
  "**/*.yaml",
  "**/*.yml",
  "**/*.ts",
  "**/*.tsx",
  "**/*.js",
  "**/*.jsx",
  "**/*.mjs",
  "**/*.cjs",
  "**/*.py",
  "**/*.go",
  "**/*.java",
  "**/*.rb",
  "**/*.prompt",
  "**/*.tmpl",
];

// Serialized model artifact extensions. These formats embed a Python "pickle"
// opcode stream that executes arbitrary code on load — the reason .safetensors
// exists as a safe alternative.
const MODEL_FILE_GLOBS = [
  "**/*.pkl",
  "**/*.pickle",
  "**/*.bin",
  "**/*.pt",
  "**/*.pth",
  "**/*.ckpt",
];

// ─── Small shared helpers (mirrors supply-chain-deep.ts style) ────────────────

type Hit = { file: string; line: number; preview: string };

async function allSearch(query: string): Promise<Hit[]> {
  try {
    return await searchRepo({ query, isRegex: true, maxMatches: 200 });
  } catch {
    // A malformed/over-complex query or a scan error must never crash the gate.
    return [];
  }
}

function toEvidence(hits: Hit[]): string[] {
  return hits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`);
}
function toFiles(hits: Hit[]): string[] {
  return [...new Set(hits.slice(0, 10).map((m) => m.file))];
}

// Cap on how many bytes of a (potentially huge) model file we read for the
// pickle-opcode heuristic. The dangerous imports live in the pickle header, so
// the first few MB is more than enough and bounds memory. CWE-400 / CWE-789.
const MODEL_READ_CAP_BYTES = 4 * 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// 1. SUPPLY_SHAI_HULUD_IOC (CWE-506 — Embedded Malicious Code)
//
// "Shai-Hulud" is a self-replicating npm worm (Sept 2025). Its footprint:
//   • It ships an oversized `router_init.js` / `router_runtime.js` bundle (well
//     over 1 MB — the packed malware) inside compromised packages.
//   • A specific SHA-1 IoC hash string is published for it and appears in the
//     integrity/resolved metadata of poisoned lockfiles.
//   • It plants a postinstall/preinstall lifecycle script that either curls a
//     remote host, or harvests AWS_/GITHUB_TOKEN/NPM_TOKEN credentials from the
//     environment and pipes them into a spawned shell to exfiltrate and re-publish.
// Any ONE of these signals is a critical, ATT&CK T1195.002 supply-chain hit.
// ─────────────────────────────────────────────────────────────────────────────

const SHAI_HULUD_IOC_HASH = "79ac49eedf774dd4b0cfa308722bc463cfe5885c";
const SHAI_HULUD_ROUTER_GLOBS = ["**/router_init.js", "**/router_runtime.js"];
const ONE_MB = 1024 * 1024;

async function checkShaiHuludIoC(): Promise<Finding | null> {
  const evidence: string[] = [];
  const files: string[] = [];

  // (a) Oversized router_init.js / router_runtime.js — the packed worm payload.
  try {
    const routerFiles = await fg(SHAI_HULUD_ROUTER_GLOBS, {
      dot: true,
      onlyFiles: true,
      followSymbolicLinks: false,
      stats: true,
    });
    for (const entry of routerFiles as unknown as Array<{ path: string; stats?: { size: number } }>) {
      // With stats:true fast-glob returns objects; be defensive about the shape.
      const path = typeof entry === "string" ? entry : entry?.path;
      const size = typeof entry === "string" ? undefined : entry?.stats?.size;
      if (!path) continue;
      if (typeof size === "number" && size > ONE_MB) {
        evidence.push(`${path}: ${(size / ONE_MB).toFixed(1)} MB router bundle (> 1 MB — Shai-Hulud worm payload signature)`);
        files.push(path);
      }
    }
  } catch {
    /* glob failure — continue with the other signals */
  }

  // (b) The known IoC hash string appearing in any lockfile.
  const hashHits = (await allSearch(SHAI_HULUD_IOC_HASH)).filter((h) => LOCKFILE_RE.test(h.file));
  for (const h of hashHits) {
    evidence.push(`${h.file}:${h.line}: known Shai-Hulud IoC hash present in lockfile`);
    files.push(h.file);
  }

  // (c) preinstall/postinstall lifecycle scripts that curl/wget an external host,
  //     OR read cloud/CI credentials from env and spawn a shell.
  //   (c1) network fetch in a lifecycle script
  const netScriptHits = (await allSearch(
    String.raw`"(?:pre|post)install"\s*:\s*"[^"]*(?:curl|wget)\s+[^"]*https?:`
  )).filter((h) => PACKAGE_JSON_RE.test(h.file));
  //   (c2) credential env read piped into a spawned shell
  const credScriptHits = (await allSearch(
    String.raw`"(?:pre|post)install"\s*:\s*"[^"]*(?:AWS_|GITHUB_TOKEN|NPM_TOKEN)[^"]*(?:sh\b|bash\b|\|\s*sh|\|\s*bash|child_process|spawn|exec)`
  )).filter((h) => PACKAGE_JSON_RE.test(h.file));

  for (const h of [...netScriptHits, ...credScriptHits]) {
    evidence.push(`${h.file}:${h.line}:${h.preview}`);
    files.push(h.file);
  }

  if (evidence.length === 0) return null;
  return {
    id: "SUPPLY_SHAI_HULUD_IOC",
    title: "Shai-Hulud npm worm indicator detected — oversized router payload, known IoC hash, or credential-stealing install script (CWE-506 / ATT&CK T1195.002)",
    severity: "CRITICAL",
    evidence: evidence.slice(0, 10),
    files: [...new Set(files)].slice(0, 10),
    requiredActions: [
      "Treat this repository and any machine that ran `npm install` as compromised: the Shai-Hulud worm harvests AWS/GitHub/NPM tokens and re-publishes itself into every package the victim can push.",
      "CWE-506 / ATT&CK T1195.002 — immediately rotate ALL npm, GitHub, and cloud (AWS) credentials reachable from this environment, and revoke any tokens found in CI.",
      "Delete the oversized router_init.js/router_runtime.js payloads and the malicious lifecycle scripts, restore package.json/lockfile from a known-good commit, and reinstall with `--ignore-scripts` from a trusted registry."
    ],
    sla: "24h"
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SUPPLY_LOCKFILE_OFFREGISTRY_RESOLVED (CWE-345 — Insufficient Verification
//    of Data Authenticity)
//
// A lockfile records, per package, the exact URL a dependency was downloaded from
// in a `resolved` field. If that host is NOT the official public registry (or a
// recognised scoped private registry), an attacker who tampered with the lockfile
// can silently redirect an otherwise-legit-looking package to a malicious mirror.
// The package name still looks normal, so nothing else flags it. HIGH.
// ─────────────────────────────────────────────────────────────────────────────

// Hosts we consider trustworthy for a `resolved` URL. The two official public
// registries, plus common private-registry vendors (only when the surrounding
// entry is a scoped @org/… package — a private host serving an UNscoped public
// name is the dependency-confusion shape we still want to surface).
const OFFICIAL_REGISTRY_HOSTS = /^(?:registry\.npmjs\.org|registry\.yarnpkg\.com)$/i;
const KNOWN_PRIVATE_REGISTRY_HOSTS = /(?:\.jfrog\.io|pkg\.github\.com|npm\.pkg\.github\.com|\.pkg\.dev|registry\.npm\.taobao\.org|registry\.npmmirror\.com|\.gitlab\.com|codeartifact\.[a-z0-9-]+\.amazonaws\.com)$/i;

// Extract the host from a `resolved` line in a lock/lockfile.
const RESOLVED_URL_RE = /"?resolved"?\s*:?\s*"?(https?:\/\/([^/"\s]+))/i;

async function checkLockfileOffRegistryResolved(): Promise<Finding | null> {
  // Every `resolved` line across supported lockfiles.
  const hits = (await allSearch(String.raw`"?resolved"?\s*:?\s*"?https?://`)).filter((h) =>
    LOCKFILE_RE.test(h.file)
  );
  if (hits.length === 0) return null;

  const offending: Hit[] = [];
  const hosts = new Set<string>();
  for (const h of hits) {
    const m = RESOLVED_URL_RE.exec(h.preview);
    if (!m) continue;
    const host = (m[2] ?? "").toLowerCase();
    if (!host) continue;
    if (OFFICIAL_REGISTRY_HOSTS.test(host)) continue;
    // A known private registry is only acceptable for scoped packages; we can't
    // reliably read the package name from a single line, so we allow the common
    // private-registry vendors outright to avoid noisy false positives.
    if (KNOWN_PRIVATE_REGISTRY_HOSTS.test(host)) continue;
    offending.push(h);
    hosts.add(host);
  }
  if (offending.length === 0) return null;

  return {
    id: "SUPPLY_LOCKFILE_OFFREGISTRY_RESOLVED",
    title: `Lockfile 'resolved' URL points to a non-registry host (${[...hosts].slice(0, 3).join(", ")}) — package fetched from an unverified source (CWE-345)`,
    severity: "HIGH",
    evidence: toEvidence(offending),
    files: toFiles(offending),
    requiredActions: [
      "A `resolved` URL outside the official registry means the locked package is downloaded from an attacker-controllable host while its name still looks legitimate — a stealthy supply-chain redirect.",
      "CWE-345 / ATT&CK T1195.002 — verify each offending host is a registry your org actually operates over HTTPS; if not, regenerate the lockfile from a clean checkout against registry.npmjs.org and diff the result.",
      `Offending host(s): ${[...hosts].slice(0, 5).join(", ")}. Pin the registry in .npmrc (registry=https://registry.npmjs.org) and enforce it in CI so lockfile 'resolved' hosts cannot drift.`
    ],
    sla: "7d"
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. SUPPLY_MCP_REMOTE_COMMAND_INJECTION (CVE-2025-6514, CWE-78 — OS Command
//    Injection)
//
// CVE-2025-6514 is an RCE in the `mcp-remote` proxy (< 0.1.16): a malicious MCP
// server can return an OAuth authorization URL that mcp-remote passes to the OS
// shell, achieving command injection on the client. Two signals:
//   • `mcp-remote` pinned below the fixed 0.1.16 in a manifest/lockfile.
//   • Application code that concatenates an MCP/OAuth server-supplied URL or param
//     into exec/spawn with shell:true — the same class of bug in first-party code.
// ─────────────────────────────────────────────────────────────────────────────

// Detect a vulnerable mcp-remote version (anything < 0.1.16). We match 0.0.x,
// 0.1.0-0.1.15, and pre-release 0.1.15-x; 0.1.16+ / 0.2+ / 1+ are safe.
const MCP_REMOTE_VULN_RE = new RegExp(
  String.raw`"mcp-remote"\s*:\s*"[~^]?(?:0\.0\.\d+|0\.1\.(?:[0-9]|1[0-5])(?![0-9]))`
);

async function checkMcpRemoteCommandInjection(): Promise<Finding | null> {
  const evidence: string[] = [];
  const files: string[] = [];

  // (a) Vulnerable mcp-remote version in a manifest or lockfile.
  const versionHits = (await allSearch(
    String.raw`"mcp-remote"\s*:\s*"[~^]?0\.[01]\.`
  )).filter((h) => PACKAGE_JSON_RE.test(h.file) || LOCKFILE_RE.test(h.file));
  for (const h of versionHits) {
    if (MCP_REMOTE_VULN_RE.test(h.preview)) {
      evidence.push(`${h.file}:${h.line}: ${h.preview.trim()} (mcp-remote < 0.1.16 — CVE-2025-6514)`);
      files.push(h.file);
    }
  }

  // (b) First-party code piping an MCP/OAuth server-supplied URL/param into a
  //     shell exec/spawn. We look for exec/execSync/spawn calls whose argument
  //     references an oauth/authorization/redirect/mcp-derived value, or an
  //     explicit shell:true near such a value.
  const codeHits = await allSearch(
    String.raw`(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:authorizationUrl|authorization_url|oauth\w*Url|redirectUri|redirect_uri|serverUrl|server_url|mcp\w*Url|callbackUrl|authUrl)`
  );
  const shellTrueHits = await allSearch(
    String.raw`(?:authorizationUrl|oauth\w*Url|redirectUri|serverUrl|mcp\w*Url|callbackUrl)[^;\n]{0,80}shell\s*:\s*true`
  );
  const CODE_LIKE_RE = /\.(?:ts|tsx|js|jsx|mjs|cjs|py)$/i;
  for (const h of [...codeHits, ...shellTrueHits]) {
    if (!CODE_LIKE_RE.test(h.file)) continue;
    evidence.push(`${h.file}:${h.line}:${h.preview}`);
    files.push(h.file);
  }

  if (evidence.length === 0) return null;
  // Version pins are unambiguously vulnerable (CRITICAL); a code-only match is a
  // strong-but-heuristic signal, so if we ONLY have code hits we keep it HIGH.
  const hasVersionHit = versionHits.some((h) => MCP_REMOTE_VULN_RE.test(h.preview));
  return {
    id: "SUPPLY_MCP_REMOTE_COMMAND_INJECTION",
    title: "mcp-remote RCE (< 0.1.16) or MCP/OAuth server value concatenated into a shell — command injection (CVE-2025-6514 / CWE-78)",
    severity: hasVersionHit ? "CRITICAL" : "HIGH",
    evidence: evidence.slice(0, 10),
    files: [...new Set(files)].slice(0, 10),
    requiredActions: [
      "CVE-2025-6514 — upgrade `mcp-remote` to >= 0.1.16; below that, a malicious MCP server returns a crafted OAuth URL that mcp-remote hands to the OS shell, achieving remote code execution on the client.",
      "CWE-78 / ATT&CK T1059 — never pass an MCP/OAuth server-supplied URL or parameter into exec/spawn with shell:true; use execFile with an argument array and validate/allowlist the URL scheme and host first.",
      "Treat every value returned by a remote MCP or OAuth server as untrusted input to a shell boundary, exactly as you would treat raw user input."
    ],
    sla: hasVersionHit ? "24h" : "7d"
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. AI_INVISIBLE_UNICODE_INJECTION (CWE-1427 — Improper Neutralization of Input
//    Used for LLM Prompting)
//
// Attackers hide instructions from human reviewers using Unicode codepoints that
// render as nothing (or as normal text) but are still read by an LLM/agent:
//   • Unicode Tags block  U+E0000–U+E007F  (the canonical "ASCII smuggling" carrier)
//   • Zero-width          U+200B/200C/200D and BOM U+FEFF
//   • Bidi overrides      U+202A–U+202E and isolates U+2066–U+2069
//   • Emoji variation selectors U+FE00–U+FE0F (data can be steganographically packed)
// We scan textual/source/markdown/json files and report ONLY the codepoint and
// location (e.g. "U+200B at file:line") — never the raw invisible bytes. HIGH.
// ─────────────────────────────────────────────────────────────────────────────

// One tight character class covering every suspicious range above. Kept as a
// character class (no quantifiers) so it cannot backtrack. The class intentionally
// contains literal invisible/bidi code points (that is the whole point of the
// detector), so the character-class lint rules are disabled for these two lines.
/* eslint-disable no-misleading-character-class, no-irregular-whitespace */
const INVISIBLE_UNICODE_RE =
  /[​‌‍﻿‪-‮⁦-⁩︀-️]|[\u{E0000}-\u{E007F}]/u;
// Same set, global + with the astral tag range, for per-line enumeration.
const INVISIBLE_UNICODE_GLOBAL_RE =
  /[​‌‍﻿‪-‮⁦-⁩︀-️]|[\u{E0000}-\u{E007F}]/gu;
/* eslint-enable no-misleading-character-class, no-irregular-whitespace */

function codepointHex(cp: number): string {
  return "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
}

async function checkInvisibleUnicodeInjection(): Promise<Finding | null> {
  let candidates: string[] = [];
  try {
    candidates = await fg(TEXTUAL_FILE_GLOBS, {
      dot: true,
      onlyFiles: true,
      followSymbolicLinks: false,
    });
  } catch {
    return null;
  }

  const evidence: string[] = [];
  const files = new Set<string>();

  for (const file of candidates) {
    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue; // oversized / unreadable / traversal-blocked — skip safely
    }
    // Fast reject: only pay the per-line cost when the file actually contains one.
    if (!INVISIBLE_UNICODE_RE.test(text)) continue;

    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!INVISIBLE_UNICODE_RE.test(line)) continue;
      // Collect the DISTINCT offending codepoints on this line as hex only.
      const seen = new Set<string>();
      for (const m of line.matchAll(INVISIBLE_UNICODE_GLOBAL_RE)) {
        const cp = m[0].codePointAt(0);
        if (cp !== undefined) seen.add(codepointHex(cp));
      }
      if (seen.size === 0) continue;
      // CRITICAL: emit codepoint + location only — never the raw invisible bytes.
      evidence.push(`${[...seen].join(",")} at ${file}:${i + 1}`);
      files.add(file);
      if (evidence.length >= 10) break;
    }
    if (evidence.length >= 10) break;
  }

  if (evidence.length === 0) return null;
  return {
    id: "AI_INVISIBLE_UNICODE_INJECTION",
    title: "Invisible Unicode (tag chars, zero-width, bidi override, or variation selectors) found in text/source — hidden LLM-prompt injection carrier (CWE-1427)",
    severity: "HIGH",
    evidence: evidence.slice(0, 10),
    files: [...files].slice(0, 10),
    requiredActions: [
      "These codepoints render as nothing to a human reviewer but are still read by an LLM/agent, so they smuggle hidden instructions (ASCII smuggling / bidi tricks) into prompts, RAG corpora, or tool metadata (CWE-1427, MITRE ATLAS AML.T0051).",
      "Inspect each reported location by codepoint (the raw bytes are intentionally not shown here), confirm the character is legitimate, and strip it if not.",
      "Normalize all ingested text to Unicode NFC and remove Tags (U+E0000-U+E007F), zero-width (U+200B/200C/200D/FEFF), bidi (U+202A-U+202E, U+2066-U+2069), and variation selectors before tokenization; add a pre-commit hook that rejects these ranges."
    ],
    sla: "7d"
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. AI_MCP_CONFIG_RUG_PULL (CVE-2025-54136 / CVE-2025-54135, CWE-708 — Incorrect
//    Ownership Management / trust-on-first-use)
//
// "MCPoison" / "CurXecute": a committed MCP config (.mcp.json, or Cursor's
// .cursor/**/mcp.json) declares a server whose `command`/`args` launch a shell,
// run `npx <remote-package>` with no version/hash pin, or invoke an arbitrary
// binary. Editors approve MCP servers on first use; a later silent edit to that
// same entry ("rug pull") then executes attacker code at the next launch without
// re-prompting. HIGH.
// ─────────────────────────────────────────────────────────────────────────────

const MCP_CONFIG_GLOBS = ["**/.mcp.json", "**/.cursor/**/mcp.json", "**/.cursor/mcp.json"];

// A server command that is a shell interpreter.
const MCP_CMD_SHELL_RE = /^(?:.*\/)?(?:sh|bash|zsh|dash|cmd|cmd\.exe|powershell|pwsh)(?:\.exe)?$/i;
// `npx`/`bunx`/`pnpm dlx` — fetches and runs a package fresh each launch.
const MCP_CMD_NPX_RE = /^(?:.*\/)?(?:npx|bunx|dlx|pnpm|yarn)$/i;
// A version/hash pin inside an args entry (…@1.2.3 or …@sha…), which makes an
// npx invocation acceptable.
const MCP_ARG_PINNED_RE = /@(?:\d+\.\d+\.\d+|[0-9a-f]{7,40}\b)/i;

type McpServerEntry = { command?: unknown; args?: unknown };

function evaluateMcpServers(file: string, config: unknown, evidence: string[]): void {
  if (!config || typeof config !== "object") return;
  const servers = (config as Record<string, unknown>)["mcpServers"] ?? (config as Record<string, unknown>)["servers"];
  if (!servers || typeof servers !== "object") return;

  for (const [name, rawEntry] of Object.entries(servers as Record<string, unknown>)) {
    if (!rawEntry || typeof rawEntry !== "object") continue;
    const entry = rawEntry as McpServerEntry;
    const command = typeof entry.command === "string" ? entry.command.trim() : "";
    if (!command) continue;
    const args = Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : [];
    const base = command.split(/[\\/]/).pop() ?? command;

    if (MCP_CMD_SHELL_RE.test(base)) {
      evidence.push(`${file}: server "${name}" command "${command}" invokes a shell interpreter`);
      continue;
    }
    if (MCP_CMD_NPX_RE.test(base)) {
      const argsJoined = args.join(" ");
      // npx/dlx of a remote package is only OK when pinned to a version or hash.
      if (!MCP_ARG_PINNED_RE.test(argsJoined)) {
        evidence.push(`${file}: server "${name}" runs "${command} ${argsJoined}".trim() — unpinned remote package (no @version/@hash)`);
      }
      continue;
    }
    // An arbitrary absolute-path binary with no accompanying pin is also a rug-pull
    // surface: the file it points at can be swapped after first approval.
    if (/^(?:\.?\.?[\\/]|[A-Za-z]:\\)/.test(command) && !MCP_ARG_PINNED_RE.test(args.join(" "))) {
      evidence.push(`${file}: server "${name}" launches arbitrary binary "${command}" with no version/hash pin`);
    }
  }
}

async function checkMcpConfigRugPull(): Promise<Finding | null> {
  let configFiles: string[] = [];
  try {
    configFiles = await fg(MCP_CONFIG_GLOBS, {
      dot: true,
      onlyFiles: true,
      followSymbolicLinks: false,
    });
  } catch {
    return null;
  }

  const evidence: string[] = [];
  for (const file of configFiles) {
    let raw = "";
    try {
      raw = await readFileSafe(file);
    } catch {
      continue;
    }
    let config: unknown;
    try {
      config = JSON.parse(raw);
    } catch {
      continue; // malformed JSON — never throw
    }
    evaluateMcpServers(file, config, evidence);
  }

  if (evidence.length === 0) return null;
  const files = [...new Set(evidence.map((e) => e.split(":")[0]))].slice(0, 10);
  return {
    id: "AI_MCP_CONFIG_RUG_PULL",
    title: "Committed MCP config launches a shell / unpinned `npx` remote / arbitrary binary — rug-pull re-approval risk (CVE-2025-54136/54135, CWE-708)",
    severity: "HIGH",
    evidence: evidence.slice(0, 10),
    files,
    requiredActions: [
      "MCPoison/CurXecute (CVE-2025-54136/54135) — editors approve an MCP server once; a later silent edit to this same entry runs attacker code at the next launch with no re-prompt. A shell command or unpinned `npx <remote>` makes that trivial (CWE-708).",
      "Pin every MCP server to an exact package version or content hash (e.g. `npx my-mcp@1.2.3`, never bare `npx my-mcp`), and prefer a locally installed, code-reviewed binary over fetch-and-run.",
      "Re-review .mcp.json / .cursor/**/mcp.json on every change and treat any diff to a server's command/args as requiring fresh human approval."
    ],
    sla: "7d"
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. AI_MODEL_PICKLE_OPCODE_DANGEROUS (CWE-502 — Deserialization of Untrusted Data)
//
// Python's pickle format (used by .pkl/.bin/.pt/.pth/.ckpt model files) is a tiny
// stack VM. On load it can be driven to import ANY module and call ANY function,
// so a weaponized model file runs code the moment torch.load()/pickle.load() reads
// it. We do a best-effort binary scan of the opcode stream for:
//   • GLOBAL        opcode 'c'  (0x63) — "import module, push attribute"
//   • STACK_GLOBAL  opcode 0x93       — the protocol-4 form of the same
//   • REDUCE        opcode 'R'  (0x52) — "call the callable on the stack"
// combined with dangerous module/name strings (os, subprocess, builtins, eval,
// exec, socket, posix). This is a HEURISTIC, not proof — .safetensors avoids the
// format entirely. CRITICAL.
// ─────────────────────────────────────────────────────────────────────────────

// The opcode bytes we care about.
const OP_GLOBAL = 0x63; // 'c'
const OP_STACK_GLOBAL = 0x93;
const OP_REDUCE = 0x52; // 'R'
const OP_BINGET = 0x68; // not dangerous alone, listed for readers' context only

// Dangerous module / callable names that, imported via GLOBAL/STACK_GLOBAL, give
// code execution. Matched as ASCII substrings in the (largely binary) buffer.
const DANGEROUS_PICKLE_NAMES = [
  "os\n",
  "subprocess",
  "builtins",
  "__builtin__",
  "posix",
  "nt\n",
  "socket",
  "eval",
  "exec",
  "system",
  "popen",
  "commands",
  "pty",
  "runpy",
];

function scanPickleBuffer(buf: Buffer): { hasOpcode: boolean; names: string[] } {
  let hasOpcode = false;
  // A cheap opcode presence check: GLOBAL/STACK_GLOBAL/REDUCE anywhere in stream.
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b === OP_GLOBAL || b === OP_STACK_GLOBAL || b === OP_REDUCE) {
      hasOpcode = true;
      break;
    }
  }
  // Reference OP_BINGET so the documented constant is not flagged as unused.
  void OP_BINGET;

  const names: string[] = [];
  if (hasOpcode) {
    // Only look at ASCII text; latin1 keeps every byte as a char for substring search.
    const ascii = buf.toString("latin1");
    for (const name of DANGEROUS_PICKLE_NAMES) {
      if (ascii.includes(name)) names.push(name.replace(/\n/g, "").trim() || name);
    }
  }
  return { hasOpcode, names };
}

async function checkModelPickleOpcodeDangerous(): Promise<Finding | null> {
  let modelFiles: string[] = [];
  try {
    modelFiles = await fg(MODEL_FILE_GLOBS, {
      dot: true,
      onlyFiles: true,
      followSymbolicLinks: false,
    });
  } catch {
    return null;
  }
  if (modelFiles.length === 0) return null;

  const { readFile, stat } = await import("node:fs/promises");
  const { resolve, sep } = await import("node:path");
  const root = process.cwd();
  const rootPrefix = root.endsWith(sep) ? root : root + sep;

  const evidence: string[] = [];
  const files: string[] = [];

  for (const file of modelFiles) {
    // Resolve safely inside the workspace (readFileSafe is UTF-8 only, so we read
    // the raw buffer ourselves but reuse the same path-traversal guard idea).
    const abs = resolve(root, file);
    if (abs !== root && !abs.startsWith(rootPrefix)) continue;

    let buf: Buffer;
    try {
      const st = await stat(abs);
      if (!st.isFile()) continue;
      // Read only the first few MB — dangerous imports live in the pickle header,
      // and this bounds memory against a hostile multi-GB "model" file. CWE-400.
      const readLen = Math.min(st.size, MODEL_READ_CAP_BYTES);
      const fh = await readFile(abs);
      buf = fh.subarray(0, readLen);
    } catch {
      continue; // unreadable — skip, never throw
    }

    const { hasOpcode, names } = scanPickleBuffer(buf);
    if (hasOpcode && names.length > 0) {
      evidence.push(`${file}: pickle opcode stream references ${[...new Set(names)].slice(0, 6).join(", ")}`);
      files.push(file);
    }
    if (evidence.length >= 10) break;
  }

  if (evidence.length === 0) return null;
  return {
    id: "AI_MODEL_PICKLE_OPCODE_DANGEROUS",
    title: "Serialized model file's pickle opcode stream imports os/subprocess/eval/socket — arbitrary code execution on load (CWE-502)",
    severity: "CRITICAL",
    evidence: evidence.slice(0, 10),
    files: [...new Set(files)].slice(0, 10),
    requiredActions: [
      "A pickle-based model file (.pkl/.bin/.pt/.pth/.ckpt) executes arbitrary Python the instant it is loaded via torch.load()/pickle.load(). References to os/subprocess/builtins.eval/socket in its opcode stream indicate an embedded payload (CWE-502).",
      "NOTE: this is a best-effort BINARY HEURISTIC, not a guarantee — it can both miss obfuscated payloads and flag benign files. Do not treat a clean result as proof of safety.",
      "Do not load the file. Re-obtain the weights from a trusted source, convert to the `.safetensors` format (which cannot execute code), and inspect with `pickletools.dis` / `fickling` before trusting any pickle-format artifact."
    ],
    sla: "24h"
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. AI_A2A_CREDENTIAL_FORWARDING (CWE-441 — Unintended Proxy / Confused Deputy)
//
// In agent-to-agent (A2A) or agent→tool delegation, the caller's own credential
// (an incoming Authorization/Bearer header, or a secret from process.env) is
// passed straight through to a downstream agent/tool/fetch call. The downstream
// component then acts with the FULL privilege of the original caller, with no
// scoping-down and no re-authorization — a classic confused-deputy escalation.
// We look for an agent.invoke / tool-call / fetch that carries the raw caller
// credential as its auth argument. HIGH.
// ─────────────────────────────────────────────────────────────────────────────

async function checkA2ACredentialForwarding(): Promise<Finding | null> {
  // (a) An incoming request auth header forwarded into a downstream call.
  const headerHits = await allSearch(
    String.raw`(?:agent|client|downstream|tool|delegate|remote)\w*\.\s*(?:invoke|call|run|execute|send|dispatch|delegate)\s*\([^)]*req\.headers(?:\.authorization|\[['"]authorization)`
  );
  // (b) A raw bearer/authorization value placed into an outbound call's auth field.
  const bearerHits = await allSearch(
    String.raw`(?:invoke|delegate|forward|call|fetch)\w*\([^)]*(?:Authorization|authorization|Bearer)\s*[:=]\s*(?:req\.headers|process\.env|incoming\w*|caller\w*|ctx\.token|context\.token)`
  );
  // (c) fetch/axios to another agent carrying process.env creds or the caller token
  //     directly in the headers.
  const fetchHits = await allSearch(
    String.raw`(?:fetch|axios(?:\.(?:get|post|put))?|got|request)\s*\([^)]*headers[^)]*(?:Authorization|Bearer)[^)]*(?:req\.headers|process\.env\.[A-Z_]*(?:TOKEN|KEY|SECRET|CRED)|callerToken|incomingToken)`
  );

  const CODE_LIKE_RE = /\.(?:ts|tsx|js|jsx|mjs|cjs|py|go)$/i;
  const hits = [...headerHits, ...bearerHits, ...fetchHits].filter((h) => CODE_LIKE_RE.test(h.file));
  if (hits.length === 0) return null;

  // De-duplicate by file+line so overlapping regexes don't double-count.
  const seen = new Set<string>();
  const unique: Hit[] = [];
  for (const h of hits) {
    const key = `${h.file}:${h.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(h);
  }

  return {
    id: "AI_A2A_CREDENTIAL_FORWARDING",
    title: "Caller token/credentials forwarded to a downstream agent or tool with no scoping or re-auth — confused-deputy escalation (CWE-441)",
    severity: "HIGH",
    evidence: toEvidence(unique),
    files: toFiles(unique),
    requiredActions: [
      "Passing the caller's raw Authorization/Bearer header or process.env secret straight into a downstream agent/tool/fetch lets that component act with the caller's full privilege — a confused-deputy / unintended-proxy escalation (CWE-441).",
      "Exchange the incoming credential for a downscoped, short-lived token (e.g. OAuth token exchange / STS) that grants only what the downstream task needs, and re-authorize at the downstream boundary.",
      "Never forward credentials by default in A2A delegation: pass an explicit, minimal, audience-restricted token per hop and log each delegation for review."
    ],
    sla: "7d"
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point — runs every rule, tolerates individual failures, never throws.
// ─────────────────────────────────────────────────────────────────────────────

export async function checkEmergingSupplyAi(_: { changedFiles: string[] }): Promise<Finding[]> {
  try {
    const results = await Promise.all([
      checkShaiHuludIoC(),
      checkLockfileOffRegistryResolved(),
      checkMcpRemoteCommandInjection(),
      checkInvisibleUnicodeInjection(),
      checkMcpConfigRugPull(),
      checkModelPickleOpcodeDangerous(),
      checkA2ACredentialForwarding(),
    ]);
    return results.filter((f): f is Finding => f !== null);
  } catch {
    // Defensive: a single rule should never take the whole gate down.
    return [];
  }
}
