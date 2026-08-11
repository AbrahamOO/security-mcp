/**
 * security-mcp install command
 *
 * Auto-detects installed editors and writes MCP server config + Claude Code skill.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync, renameSync, unlinkSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { homedir, platform } from "node:os";
import { fileURLToPath } from "node:url";
import {
  runOnboarding,
  installSecurityTools,
  commandExists,
  SECURITY_TOOLS
} from "./onboarding.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "../..");

// Client selection groups. Each maps to one --flag (Cursor covers two writers).
type ClientGroup = "claude" | "cursor" | "vscode" | "windsurf" | "codex";

interface InstallOptions {
  claudeCode: boolean;
  cursor: boolean;
  vscode: boolean;
  windsurf: boolean;
  codex: boolean;
  all: boolean;
  dryRun: boolean;
  useGlobalBinary: boolean;
  interactive: boolean;
}

// Whether the launch entry carries an explicit `"type": "stdio"`. Claude Code,
// Cursor and VS Code accept it; Windsurf and Codex expect a bare command/args.
type EntryStyle = "with-type" | "no-type";

interface ClientWriter {
  name: string;
  group: ClientGroup;
  detect(): boolean;
  configPath(): string;
  write(dryRun: boolean, useGlobalBinary: boolean): string;
}

function resolveHome(p: string): string {
  return p.replace(/^~/, homedir());
}

// VS Code user settings dir (used only for detection — configs are written to the
// project-scoped .vscode/mcp.json, which is unambiguous and shareable).
function getVsCodeUserDir(): string {
  const os = platform();
  if (os === "win32") return join(process.env["APPDATA"] ?? "", "Code", "User");
  if (os === "darwin") return join(homedir(), "Library", "Application Support", "Code", "User");
  return join(homedir(), ".config", "Code", "User");
}

/**
 * Strip comments and trailing commas so JSONC parses.
 *
 * `~/.claude/settings.json` and `.vscode/mcp.json` are both officially JSONC: VS Code
 * documents comments in `mcp.json`, and a hand-edited settings file routinely has a
 * trailing comma. Treating those as unparseable is what turned a stray comma into total
 * config loss.
 */
function stripJsonc(text: string): string {
  let out = "";
  let inStr = false, inLine = false, inBlock = false, prev = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    const next = text[i + 1];
    if (inLine) { if (ch === "\n") { inLine = false; out += ch; } continue; }
    if (inBlock) { if (ch === "*" && next === "/") { inBlock = false; i++; } continue; }
    if (inStr) {
      out += ch;
      if (ch === '"' && prev !== "\\") inStr = false;
      prev = prev === "\\" && ch === "\\" ? "" : ch;
      continue;
    }
    if (ch === '"') { inStr = true; out += ch; prev = ch; continue; }
    if (ch === "/" && next === "/") { inLine = true; i++; continue; }
    if (ch === "/" && next === "*") { inBlock = true; i++; continue; }
    out += ch;
    prev = ch;
  }
  // Trailing commas before } or ]
  return out.replace(/,(\s*[}\]])/g, "$1");
}

/** Thrown when a config file exists but cannot be understood. Never silently discarded. */
export class UnparseableConfigError extends Error {
  constructor(public readonly filePath: string, cause: unknown) {
    super(`"${filePath}" exists but is not valid JSON/JSONC: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "UnparseableConfigError";
  }
}

/**
 * Read an existing config, distinguishing ABSENT from UNPARSEABLE.
 *
 * This previously returned `{}` for both. The caller then serialized that empty object over
 * the user's file, so a single trailing comma in `~/.claude/settings.json` silently deleted
 * their model, permissions, and hooks, reported "updated", and exited 0. Absence means
 * "start fresh". Failure to parse means "stop", because the alternative is deriving a
 * destructive write from a failed read.
 */
function readJsonSafe(filePath: string): Record<string, unknown> {
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf-8");
  } catch {
    return {}; // genuinely absent — this is the only safe empty case
  }
  if (raw.trim() === "") return {};
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch (strictErr) {
    try {
      return JSON.parse(stripJsonc(raw)) as Record<string, unknown>;
    } catch {
      throw new UnparseableConfigError(filePath, strictErr);
    }
  }
}

function getMcpEntry(useGlobalBinary: boolean, style: EntryStyle): Record<string, unknown> {
  const base = useGlobalBinary
    ? { command: "security-mcp", args: ["serve"] }
    : { command: "npx", args: ["-y", "security-mcp@latest", "serve"] };
  return style === "with-type" ? { type: "stdio", ...base } : base;
}

// Merge-preserving JSON writer: sets only servers[key]["security-mcp"], keeps every
// other key. `serversKey` is "mcpServers" (Claude/Cursor/Windsurf) or "servers" (VS Code).
// Exported for tests.
export function writeJsonServers(
  configPath: string,
  serversKey: string,
  style: EntryStyle,
  dryRun: boolean,
  useGlobalBinary: boolean
): string {
  const existing = readJsonSafe(configPath);
  const servers = (existing[serversKey] as Record<string, unknown>) ?? {};
  servers["security-mcp"] = getMcpEntry(useGlobalBinary, style);
  existing[serversKey] = servers;

  const content = JSON.stringify(existing, null, 2) + "\n";
  if (!dryRun) {
    mkdirSync(dirname(configPath), { recursive: true });
    writeConfigSafely(configPath, content);
  }
  return configPath;
}

/**
 * Back up once, then write atomically.
 *
 * The previous implementation was a bare `writeFileSync` onto the live path, so an
 * interrupt or a full disk truncated the user's editor config with nothing to restore from.
 */
export function writeConfigSafely(configPath: string, content: string): void {
  if (existsSync(configPath)) {
    const backup = `${configPath}.bak`;
    // First write only: never clobber an existing .bak, which would replace the last known
    // good copy with an already-modified one.
    if (!existsSync(backup)) {
      try { copyFileSync(configPath, backup); } catch { /* best effort, never block the write */ }
    }
  }
  const tmp = `${configPath}.tmp-${randomBytes(6).toString("hex")}`;
  writeFileSync(tmp, content, "utf-8");
  try {
    renameSync(tmp, configPath);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* ignore */ }
    throw e;
  }
}

// Encode a JS string[] as a TOML array of basic strings.
function tomlStringArray(items: string[]): string {
  return "[" + items.map((s) => JSON.stringify(s)).join(", ") + "]";
}

function buildCodexBlock(useGlobalBinary: boolean): string {
  const entry = getMcpEntry(useGlobalBinary, "no-type") as { command: string; args?: string[] };
  const lines = ["[mcp_servers.security-mcp]", `command = ${JSON.stringify(entry.command)}`];
  if (entry.args && entry.args.length > 0) lines.push(`args = ${tomlStringArray(entry.args)}`);
  return lines.join("\n");
}

// Codex uses TOML (~/.codex/config.toml or project .codex/config.toml). No TOML
// dependency: manage only the [mcp_servers.security-mcp] table, preserving all
// other content and comments. Appends when absent; replaces the table slice (up to
// the next top-level table) when present. Idempotent. Exported for tests.
export function writeCodexTomlConfig(configPath: string, dryRun: boolean, useGlobalBinary: boolean): string {
  const existing = existsSync(configPath) ? readFileSync(configPath, "utf-8") : "";
  const block = buildCodexBlock(useGlobalBinary);
  // A trailing comment is valid TOML after a table header. Requiring only whitespace meant
  // `[mcp_servers.security-mcp]   # installed 2026-01` did not match, the writer took the
  // "absent" branch, and appended a SECOND table. TOML rejects a duplicated table, so the
  // whole config became unloadable — every Codex setting, not just the MCP entry — and
  // re-running the installer could not repair it.
  const headerRe = /^\[mcp_servers\.security-mcp\][ \t]*(#.*)?$/m;
  const m = headerRe.exec(existing);

  let next: string;
  if (!m) {
    const trimmed = existing.replace(/\s*$/, "");
    next = (trimmed.length > 0 ? trimmed + "\n\n" : "") + block + "\n";
  } else {
    const afterHeader = m.index + m[0].length;
    const rest = existing.slice(afterHeader);
    const nextTable = /\n\[[^\n]*\]/.exec(rest); // next top-level table header, if any
    const end = nextTable ? afterHeader + nextTable.index : existing.length;
    next = existing.slice(0, m.index) + block + existing.slice(end);
    if (!next.endsWith("\n")) next += "\n";
  }

  if (!dryRun) {
    mkdirSync(dirname(configPath), { recursive: true });
    writeFileSync(configPath, next, "utf-8");
  }
  return configPath;
}

// The full client roster. Codex/Windsurf use no-type entries; VS Code uses the
// `servers` key in .vscode/mcp.json (NOT the legacy flat `mcp.servers`).
const CLIENT_WRITERS: ClientWriter[] = [
  {
    name: "Claude Code",
    group: "claude",
    detect: () => existsSync(resolveHome("~/.claude")),
    configPath: () => resolveHome("~/.claude/settings.json"),
    write: (d, g) => writeJsonServers(resolveHome("~/.claude/settings.json"), "mcpServers", "with-type", d, g)
  },
  {
    name: "Cursor (global)",
    group: "cursor",
    detect: () => existsSync(resolveHome("~/.cursor")),
    configPath: () => resolveHome("~/.cursor/mcp.json"),
    write: (d, g) => writeJsonServers(resolveHome("~/.cursor/mcp.json"), "mcpServers", "with-type", d, g)
  },
  {
    name: "Cursor (workspace)",
    group: "cursor",
    detect: () => existsSync(".cursor"),
    configPath: () => ".cursor/mcp.json",
    write: (d, g) => writeJsonServers(join(".cursor", "mcp.json"), "mcpServers", "with-type", d, g)
  },
  {
    name: "VS Code",
    group: "vscode",
    detect: () => existsSync(".vscode") || existsSync(getVsCodeUserDir()),
    configPath: () => join(".vscode", "mcp.json"),
    write: (d, g) => writeJsonServers(join(".vscode", "mcp.json"), "servers", "with-type", d, g)
  },
  {
    name: "Windsurf",
    group: "windsurf",
    detect: () => existsSync(resolveHome("~/.codeium/windsurf")) || existsSync(resolveHome("~/.codeium")),
    configPath: () => resolveHome("~/.codeium/windsurf/mcp_config.json"),
    write: (d, g) => writeJsonServers(resolveHome("~/.codeium/windsurf/mcp_config.json"), "mcpServers", "no-type", d, g)
  },
  {
    name: "Codex (global)",
    group: "codex",
    detect: () => existsSync(resolveHome("~/.codex")),
    configPath: () => resolveHome("~/.codex/config.toml"),
    write: (d, g) => writeCodexTomlConfig(resolveHome("~/.codex/config.toml"), d, g)
  },
  {
    name: "Codex (workspace)",
    group: "codex",
    detect: () => existsSync(".codex"),
    configPath: () => join(".codex", "config.toml"),
    write: (d, g) => writeCodexTomlConfig(join(".codex", "config.toml"), d, g)
  }
];

function getSelectedWriters(opts: InstallOptions): ClientWriter[] {
  if (opts.all) return CLIENT_WRITERS.filter((w) => w.detect());
  const enabled: Record<ClientGroup, boolean> = {
    claude: opts.claudeCode,
    cursor: opts.cursor,
    vscode: opts.vscode,
    windsurf: opts.windsurf,
    codex: opts.codex
  };
  return CLIENT_WRITERS.filter((w) => enabled[w.group]);
}

function installPolicy(dryRun: boolean): void {
  const policySrc = join(PKG_ROOT, "defaults", "security-policy.json");
  const policyDest = join(process.cwd(), ".mcp", "policies", "security-policy.json");
  const evidenceSrc = join(PKG_ROOT, "defaults", "evidence-map.json");
  const evidenceDest = join(process.cwd(), ".mcp", "mappings", "evidence-map.json");
  const catalogSrc = join(PKG_ROOT, "defaults", "control-catalog.json");
  const catalogDest = join(process.cwd(), ".mcp", "catalog", "control-catalog.json");
  const scannersSrc = join(PKG_ROOT, "defaults", "security-tools.json");
  const scannersDest = join(process.cwd(), ".mcp", "scanners", "security-tools.json");
  const exceptionsSrc = join(PKG_ROOT, "defaults", "security-exceptions.json");
  const exceptionsDest = join(process.cwd(), ".mcp", "exceptions", "security-exceptions.json");

  for (const { src, dest } of [
    { src: policySrc, dest: policyDest },
    { src: evidenceSrc, dest: evidenceDest },
    { src: catalogSrc, dest: catalogDest },
    { src: scannersSrc, dest: scannersDest },
    { src: exceptionsSrc, dest: exceptionsDest }
  ]) {
    if (!existsSync(src)) {
      process.stdout.write(`  [skip] ${src} not found in package\n`);
      continue;
    }
    if (existsSync(dest)) {
      process.stdout.write(`  [skip] already exists: ${dest}\n`);
      continue;
    }
    if (!dryRun) {
      mkdirSync(dirname(dest), { recursive: true });
      copyFileSync(src, dest);
    }
    process.stdout.write(`  ${dryRun ? "[dry-run] would copy" : "installed"}: ${dest}\n`);
  }
}

function installSkill(dryRun: boolean): void {
  const skillSrc = join(PKG_ROOT, "skills", "senior-security-engineer", "SKILL.md");
  const skillDest = resolveHome("~/.claude/skills/senior-security-engineer/SKILL.md");

  if (!existsSync(skillSrc)) {
    process.stdout.write("  [skip] skills/senior-security-engineer/SKILL.md not found in package\n");
    return;
  }

  if (!dryRun) {
    mkdirSync(dirname(skillDest), { recursive: true });
    copyFileSync(skillSrc, skillDest);
  }
  process.stdout.write(`  ${dryRun ? "[dry-run] would copy" : "installed"} skill: ${skillDest}\n`);
}

/**
 * Download a skill SKILL.md from a remote URL and save it to ~/.claude/skills/{skillName}/SKILL.md.
 * Used for lazy on-demand skill installation — all sub-agents are downloaded this way at first use.
 * Mirrors the same pattern used for security tool binary downloads in onboarding.ts.
 */
// CWE-22: only alphanumeric, hyphens, and dots allowed in skill names
// REMOVED downloadSkill(): an unused, integrity-free network skill installer
// (no sha256, no content sanitization) that, if ever wired up, would bypass every
// protection in orchestration.ensureSkill. Skills are bundled in the package and
// resolved locally by ensureSkill; there is no need for an unauthenticated fetcher.

/**
 * Eagerly install the orchestrator skill (bundled in the package) plus record
 * its version so orchestration.ensure_skill can detect future updates.
 */
function installOrchestratorSkill(dryRun: boolean): void {
  const skillName = "ciso-orchestrator";
  const skillSrc = join(PKG_ROOT, "skills", skillName, "SKILL.md");
  const skillDest = resolveHome(`~/.claude/skills/${skillName}/SKILL.md`);

  if (!existsSync(skillSrc)) {
    process.stdout.write(`  [skip] skills/${skillName}/SKILL.md not found in package\n`);
    return;
  }

  if (!dryRun) {
    mkdirSync(dirname(skillDest), { recursive: true });
    copyFileSync(skillSrc, skillDest);
  }
  process.stdout.write(`  ${dryRun ? "[dry-run] would copy" : "installed"} skill: ${skillDest}\n`);
}

// Per-client instruction files. These tell each non-Claude host how to run the full
// agentic flow (invoke the senior-security-engineer / ciso-orchestrator MCP prompt,
// load any specialist persona via orchestration.ensure_skill or skill://<name>). They
// are copied into the project with skip-if-exists so an existing file is never clobbered.
interface ClientInstruction {
  group: ClientGroup;
  src: string;
  dest: string;
}

const CLIENT_INSTRUCTIONS: ClientInstruction[] = [
  { group: "cursor", src: join("cursor", "security-mcp.mdc"), dest: join(".cursor", "rules", "security-mcp.mdc") },
  { group: "vscode", src: "copilot-instructions.md", dest: join(".github", "copilot-instructions.md") },
  { group: "windsurf", src: join("windsurf", "security-mcp.md"), dest: join(".windsurf", "rules", "security-mcp.md") },
  { group: "codex", src: "AGENTS.md", dest: "AGENTS.md" }
];

function installClientInstructions(dryRun: boolean, groups: Set<ClientGroup>): void {
  const templateRoot = join(PKG_ROOT, "client-templates");
  const selected = CLIENT_INSTRUCTIONS.filter((c) => groups.has(c.group));
  if (selected.length === 0) return;

  process.stdout.write("\nInstalling client instruction files...\n");
  for (const c of selected) {
    const src = join(templateRoot, c.src);
    const dest = join(process.cwd(), c.dest);
    if (!existsSync(src)) {
      process.stdout.write(`  [skip] ${src} not found in package\n`);
      continue;
    }
    if (existsSync(dest)) {
      process.stdout.write(`  [skip] already exists: ${c.dest}\n`);
      continue;
    }
    if (!dryRun) {
      mkdirSync(dirname(dest), { recursive: true });
      copyFileSync(src, dest);
    }
    process.stdout.write(`  ${dryRun ? "[dry-run] would copy" : "installed"}: ${c.dest}\n`);
  }
}

export async function runInstall(opts: InstallOptions): Promise<void> {
  const dryRun = opts.dryRun;

  // ── Interactive onboarding (skipped when --yes or non-TTY) ──────────────
  if (opts.interactive && !dryRun) {
    const onboarding = await runOnboarding();

    if (onboarding?.installTools) {
      const toInstall = SECURITY_TOOLS.filter((t) => !commandExists(t.id));
      process.stdout.write("\nInstalling security scanning tools...\n");
      await installSecurityTools(toInstall);
      process.stdout.write("\n");
    }
  }

  process.stdout.write(`\nsecurity-mcp installer${dryRun ? " (dry-run)" : ""}\n`);
  process.stdout.write("=".repeat(40) + "\n\n");

  const writers = getSelectedWriters(opts);

  if (writers.length === 0) {
    process.stdout.write(
      "No supported editors detected automatically.\n" +
      "Target one explicitly with --claude-code, --cursor, --vscode, --windsurf, or --codex.\n" +
      "Replit uses remote MCP only — add security-mcp via its Integrations UI (see README).\n" +
      'Or add the config manually (run "npx -y security-mcp@latest config" for the snippet).\n\n'
    );
    return;
  }

  const selectedGroups = new Set<ClientGroup>();
  for (const writer of writers) {
    selectedGroups.add(writer.group);
    process.stdout.write(`Installing for ${writer.name}...\n`);
    try {
      const written = writer.write(dryRun, opts.useGlobalBinary);
      process.stdout.write(`  ${dryRun ? "[dry-run] would update" : "updated"}: ${written}\n`);
    } catch (err) {
      process.stdout.write(`  [error] ${err instanceof Error ? err.message : String(err)}\n`);
      if (err instanceof UnparseableConfigError) {
        process.stdout.write(
          "          Your file was NOT modified. Fix the syntax error and re-run, or move the\n" +
          "          file aside to start fresh. This installer will not overwrite a config it\n" +
          "          cannot read.\n"
        );
      }
    }
  }

  // Install Claude Code skills if Claude Code is in scope
  if (selectedGroups.has("claude") || opts.all) {
    process.stdout.write("\nInstalling Claude Code skills...\n");
    installSkill(dryRun);
    installOrchestratorSkill(dryRun);
  }

  // Install per-client instruction files for the other hosts.
  installClientInstructions(dryRun, selectedGroups);

  process.stdout.write("\nInstalling security policy...\n");
  installPolicy(dryRun);

  process.stdout.write("\n");
  if (dryRun) {
    process.stdout.write("Dry-run complete. Re-run without --dry-run to apply.\n\n");
    return;
  }

  process.stdout.write("Installation complete!\n");
  process.stdout.write(`Install mode: ${opts.useGlobalBinary ? "global binary (security-mcp serve)" : "npx (npx -y security-mcp@latest serve)"}\n`);
  process.stdout.write("\nNext steps:\n");
  process.stdout.write("  1. Restart your editor (fully quit and reopen — not just reload window).\n");
  process.stdout.write("  2. Verify the server loaded:\n");
  process.stdout.write("       Claude Code: type /mcp and confirm security-mcp is listed as Connected.\n");
  process.stdout.write("       Cursor:       Settings > MCP > security-mcp should show as active.\n");
  process.stdout.write("  3. Run your first security review:\n");
  process.stdout.write("       /senior-security-engineer\n");
  process.stdout.write("     The agent will ask you to choose a scan scope (recent changes / full codebase / specific files).\n");
  process.stdout.write("  4. For a deep 39-agent audit before a release:\n");
  process.stdout.write("       /ciso-orchestrator\n");
  process.stdout.write("\nVerify this install at any time:\n");
  process.stdout.write("  npx -y security-mcp@latest --version\n\n");
}
