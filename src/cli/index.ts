#!/usr/bin/env node
/**
 * security-mcp CLI
 *
 * Subcommands:
 *   serve    Start the MCP server over stdio (used by editors)
 *   install  Auto-detect editors and write MCP + skill configs
 *   config   Print MCP config JSON for manual editor setup
 *   --version
 *   --help
 */

import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { homedir, platform } from "node:os";
import { runInstall } from "./install.js";
import { main as runServer } from "../mcp/server.js";
import { notifyIfUpdateAvailable } from "./update.js";
import { autoHardenTree } from "../gate/cloud-controls/apply.js";
import { runGateFromEnv } from "../ci/pr-gate.js";
import { signPolicyFile } from "../gate/policy.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function getVersion(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(resolve(__dirname, "../../package.json"), "utf8")
    ) as { version: string };
    return pkg.version;
  } catch {
    return "unknown";
  }
}

const VERSION = getVersion();

function getConfigSnippet(useGlobalBinary: boolean): Record<string, unknown> {
  return {
    mcpServers: {
      "security-mcp": useGlobalBinary
        ? {
            command: "security-mcp",
            args: ["serve"]
          }
        : {
            command: "npx",
            args: ["-y", "security-mcp@latest", "serve"]
          }
    }
  };
}

const HELP = `
security-mcp v${VERSION}

  AI security MCP server and gate for Claude Code, Cursor, Copilot, Codex, Replit, and any MCP-compatible editor.

USAGE
  npx -y security-mcp@latest <command> [options]

COMMANDS
  serve            Start the MCP server over stdio (default for editors)
  install          Auto-detect installed editors and write MCP configs
  install-global   Install using the globally installed security-mcp binary
  config           Print MCP config JSON for manual editor setup
  doctor           Verify the installation is working correctly
  autoharden       Auto-apply FSBP/CIS hardening fixes to Terraform (use --dry-run to preview)
  ci:pr-gate       Run the policy gate against the current diff (for CI/pre-commit)
  sign-policy      Sign the policy file with SECURITY_POLICY_HMAC_KEY for tamper protection

OPTIONS (install)
  --claude-code        Write config for Claude Code only
  --cursor             Write config for Cursor only
  --vscode             Write config for VS Code / GitHub Copilot only
  --windsurf           Write config for Windsurf only
  --codex              Write config for Codex only
  --global             Write to global editor config (default)
  --use-global-binary  Write configs that execute "security-mcp serve" instead of npx
  --dry-run            Print what would change without writing
  --yes                Skip interactive setup questions (install with defaults)
  --non-interactive    Same as --yes (for CI environments)

OPTIONS (general)
  --version        Print version
  --help           Print this help

EXAMPLES
  # Start MCP server (called automatically by editors):
  npx -y security-mcp@latest serve

  # Install into all detected editors:
  npx -y security-mcp@latest install

  # Install globally once, then configure editors to use the global binary:
  npm install -g security-mcp@latest
  security-mcp install-global

  # Install into Claude Code only:
  npx -y security-mcp@latest install --claude-code

  # Preview install without writing:
  npx -y security-mcp@latest install --dry-run

  # Verify installation health:
  npx -y security-mcp@latest doctor

  # Run the policy gate in CI (fails the build on HIGH/CRITICAL findings):
  npx -y security-mcp@latest ci:pr-gate

  # Sign the policy file so tampering is detected at gate startup:
  export SECURITY_POLICY_HMAC_KEY="$(openssl rand -hex 32)"
  npx -y security-mcp@latest sign-policy

  # Print JSON config snippet:
  npx -y security-mcp@latest config
  security-mcp config --use-global-binary

EDITOR CONFIG (add manually if install fails):
  JSON clients use the "mcpServers" key (VS Code uses "servers" in .vscode/mcp.json):
  {
    "mcpServers": {
      "security-mcp": {
        "command": "npx",
        "args": ["-y", "security-mcp@latest", "serve"]
      }
    }
  }

  Claude Code:  ~/.claude/settings.json                         (key: mcpServers)
  Cursor:       ~/.cursor/mcp.json  or  .cursor/mcp.json        (key: mcpServers)
  VS Code:      .vscode/mcp.json                                (key: servers)
  Windsurf:     ~/.codeium/windsurf/mcp_config.json             (key: mcpServers)
  Codex:        ~/.codex/config.toml  or  .codex/config.toml    (TOML [mcp_servers.security-mcp])
  Replit:       remote MCP only — add via the Integrations UI (no local config)

MORE INFO
  https://github.com/AbrahamOO/security-mcp
`;

function resolveHome(p: string): string {
  return p.replace(/^~/, homedir());
}

// VS Code user settings dir — used only to detect whether VS Code is installed.
// MCP config is written to the project-scoped .vscode/mcp.json (key "servers").
function getVsCodeUserDir(): string {
  const os = platform();
  if (os === "win32") return `${process.env["APPDATA"] ?? ""}\\Code\\User`;
  if (os === "darwin") return `${homedir()}/Library/Application Support/Code/User`;
  return `${homedir()}/.config/Code/User`;
}

const VSCODE_MCP_CONFIG = ".vscode/mcp.json";
const WINDSURF_MCP_CONFIG = "~/.codeium/windsurf/mcp_config.json";

// Compare two dotted versions. Returns <0 if a<b, 0 if equal, >0 if a>b.
// Prerelease/build suffixes are stripped; only major.minor.patch are compared.
function compareSemver(a: string, b: string): number {
  const parse = (v: string): number[] =>
    (v.split("-")[0] ?? v).split(".").map((n) => Number(n) || 0);
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

type DoctorCheck = { label: string; ok: boolean; hint?: string };

// A globally installed security-mcp older than the running build shadows
// `npx security-mcp` (npx prefers an existing global over downloading), so the
// editor launches a stale server missing newer tools like the orchestration
// control plane. Detect it and tell the user to remove it.
function checkStaleGlobalShadow(): DoctorCheck | null {
  try {
    const root = execFileSync("npm", ["root", "-g"], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    if (!root) return null;
    const pkgPath = join(root, "security-mcp", "package.json");
    if (!existsSync(pkgPath)) return null; // no global install — nothing to shadow
    const globalVer = (JSON.parse(readFileSync(pkgPath, "utf-8")) as { version?: string }).version;
    if (!globalVer) return null;
    if (compareSemver(globalVer, VERSION) < 0) {
      return {
        label: `Global security-mcp ${globalVer} is older than ${VERSION} and can shadow npx`,
        ok: false,
        hint: "Remove the stale global so npx resolves the latest: npm rm -g security-mcp"
      };
    }
    return { label: `Global security-mcp ${globalVer} (not stale)`, ok: true };
  } catch {
    return null; // npm unavailable or errored — skip silently
  }
}

// An MCP config entry that launches `npx security-mcp` without a version tag can
// resolve to a stale npx cache or a global install, pinning the editor to an old
// server. Entries pinned to `security-mcp@latest` (or an explicit version), or the
// intentional global-binary mode (`command: "security-mcp"`), are fine.
function checkPinnedConfig(configPath: string, serversKey: string, label: string): DoctorCheck | null {
  if (!existsSync(configPath)) return null;
  try {
    const json = JSON.parse(readFileSync(configPath, "utf-8")) as Record<string, unknown>;
    const servers = json[serversKey] as Record<string, unknown> | undefined;
    const entry = servers?.["security-mcp"] as { command?: string; args?: unknown[] } | undefined;
    if (!entry) return null; // no security-mcp entry here
    if (entry.command === "security-mcp") return null; // global-binary mode, intentional
    if (entry.command !== "npx") return null;
    const args = Array.isArray(entry.args) ? entry.args : [];
    const pkgTok = args.find(
      (a): a is string => typeof a === "string" && a.startsWith("security-mcp")
    );
    const pinned = !!pkgTok && pkgTok.includes("@");
    if (!pinned) {
      return {
        label: `${label} security-mcp launch is unpinned (${pkgTok ?? "security-mcp"})`,
        ok: false,
        hint: `Pin to @latest so npx never uses a stale build — re-run: npx -y security-mcp@latest install`
      };
    }
    return { label: `${label} security-mcp launch pinned (${pkgTok})`, ok: true };
  } catch {
    return null; // unreadable/invalid JSON — skip silently
  }
}

// Codex config is TOML. Isolate the [mcp_servers.security-mcp] table and apply the
// same pinned/unpinned logic as checkPinnedConfig (no TOML parser needed).
function checkPinnedTomlConfig(configPath: string, label: string): DoctorCheck | null {
  if (!existsSync(configPath)) return null;
  try {
    const raw = readFileSync(configPath, "utf-8");
    const header = /^\[mcp_servers\.security-mcp\][ \t]*$/m.exec(raw);
    if (!header) return null; // no security-mcp table here
    const afterHeader = header.index + header[0].length;
    const rest = raw.slice(afterHeader);
    const nextTable = /\n\[[^\n]*\]/.exec(rest);
    const block = rest.slice(0, nextTable ? nextTable.index : rest.length);
    const commandMatch = /^\s*command\s*=\s*"([^"]*)"/m.exec(block);
    const command = commandMatch?.[1];
    if (command === "security-mcp") return null; // global-binary mode, intentional
    if (command !== "npx") return null;
    const pkgTok = (block.match(/"(security-mcp[^"]*)"/g) ?? [])
      .map((s) => s.replace(/"/g, ""))
      .find((s) => s.startsWith("security-mcp"));
    const pinned = !!pkgTok && pkgTok.includes("@");
    if (!pinned) {
      return {
        label: `${label} security-mcp launch is unpinned (${pkgTok ?? "security-mcp"})`,
        ok: false,
        hint: `Pin to @latest so npx never uses a stale build — re-run: npx -y security-mcp@latest install --codex`
      };
    }
    return { label: `${label} security-mcp launch pinned (${pkgTok})`, ok: true };
  } catch {
    return null;
  }
}

// Build the list of editor config-presence checks (files the installer writes).
function collectConfigPresenceChecks(): DoctorCheck[] {
  const claudeConfig = resolveHome("~/.claude/settings.json");
  const skillPath = resolveHome("~/.claude/skills/senior-security-engineer/SKILL.md");
  const cursorConfig = resolveHome("~/.cursor/mcp.json");
  const windsurfConfig = resolveHome(WINDSURF_MCP_CONFIG);
  const codexConfig = resolveHome("~/.codex/config.toml");

  const candidates: Array<DoctorCheck | null> = [
    { label: `Claude Code config (${claudeConfig})`, ok: existsSync(claudeConfig), hint: existsSync(claudeConfig) ? undefined : "Run: npx -y security-mcp@latest install --claude-code" },
    { label: `senior-security-engineer skill (${skillPath})`, ok: existsSync(skillPath), hint: existsSync(skillPath) ? undefined : "Run: npx -y security-mcp@latest install --claude-code" },
    existsSync(resolveHome("~/.cursor"))
      ? { label: `Cursor config (${cursorConfig})`, ok: existsSync(cursorConfig), hint: existsSync(cursorConfig) ? undefined : "Run: npx -y security-mcp@latest install --cursor" }
      : null,
    existsSync(".vscode") || existsSync(getVsCodeUserDir())
      ? { label: `VS Code config (${VSCODE_MCP_CONFIG})`, ok: existsSync(VSCODE_MCP_CONFIG), hint: existsSync(VSCODE_MCP_CONFIG) ? undefined : "Run: npx -y security-mcp@latest install --vscode" }
      : null,
    existsSync(resolveHome("~/.codeium/windsurf")) || existsSync(resolveHome("~/.codeium"))
      ? { label: `Windsurf config (${windsurfConfig})`, ok: existsSync(windsurfConfig), hint: existsSync(windsurfConfig) ? undefined : "Run: npx -y security-mcp@latest install --windsurf" }
      : null,
    existsSync(resolveHome("~/.codex"))
      ? { label: `Codex config (${codexConfig})`, ok: existsSync(codexConfig), hint: existsSync(codexConfig) ? undefined : "Run: npx -y security-mcp@latest install --codex" }
      : null
  ];

  return candidates.filter((c): c is DoctorCheck => c !== null);
}

function collectDoctorChecks(): DoctorCheck[] {
  const nodeVer = process.versions.node.split(".").map(Number);
  const nodeOk = (nodeVer[0] ?? 0) >= 20;
  const nodeCheck: DoctorCheck = { label: `Node.js ${process.versions.node}`, ok: nodeOk, hint: nodeOk ? undefined : "Node.js 20+ required. Download from https://nodejs.org" };

  const candidates: Array<DoctorCheck | null> = [
    nodeCheck,
    // Editor config + skill presence
    ...collectConfigPresenceChecks(),
    // Stale global install that shadows npx (old server, missing tools)
    checkStaleGlobalShadow(),
    // Unpinned launch entries across editor configs (resolve to stale caches)
    checkPinnedConfig(resolveHome("~/.claude/settings.json"), "mcpServers", "Claude Code (settings.json):"),
    checkPinnedConfig(resolveHome("~/.claude.json"), "mcpServers", "Claude Code (~/.claude.json):"),
    checkPinnedConfig(resolveHome("~/.cursor/mcp.json"), "mcpServers", "Cursor:"),
    checkPinnedConfig(VSCODE_MCP_CONFIG, "servers", "VS Code (.vscode/mcp.json):"),
    checkPinnedConfig(resolveHome(WINDSURF_MCP_CONFIG), "mcpServers", "Windsurf:"),
    checkPinnedTomlConfig(resolveHome("~/.codex/config.toml"), "Codex (~/.codex/config.toml):"),
    checkPinnedTomlConfig(".codex/config.toml", "Codex (.codex/config.toml):")
  ];

  return candidates.filter((c): c is DoctorCheck => c !== null);
}

function runDoctor(): void {
  const checks = collectDoctorChecks();

  process.stdout.write(`\nsecurity-mcp doctor v${VERSION}\n`);
  process.stdout.write("=".repeat(40) + "\n\n");

  let allOk = true;
  for (const check of checks) {
    const status = check.ok ? "PASS" : "FAIL";
    process.stdout.write(`  [${status}] ${check.label}\n`);
    if (!check.ok) {
      allOk = false;
      if (check.hint) process.stdout.write(`         Fix: ${check.hint}\n`);
    }
  }

  process.stdout.write("\n");
  if (allOk) {
    process.stdout.write("All checks passed. security-mcp is installed correctly.\n");
    process.stdout.write("Restart your editor if you haven't already, then type /senior-security-engineer.\n\n");
  } else {
    process.stdout.write("Some checks failed. Run the suggested fix commands above, then re-run: npx -y security-mcp@latest doctor\n\n");
    process.exit(1);
  }
}

async function runAutoHarden(dryRun: boolean): Promise<void> {
  const report = await autoHardenTree({ write: !dryRun });
  const verb = dryRun ? "Would apply" : "Applied";
  process.stdout.write(`\nsecurity-mcp autoharden v${VERSION}\n`);
  process.stdout.write("=".repeat(40) + "\n\n");
  process.stdout.write(`${verb} ${report.applied.length} fix(es) across ${report.filesChanged.length} file(s).\n`);
  for (const fix of report.applied) {
    process.stdout.write(`  [FIX]    ${fix.ruleId}  ${fix.resource}  (${fix.file})\n`);
  }
  for (const m of report.manual) {
    process.stdout.write(`  [MANUAL] ${m.ruleId}  ${m.resource}  (${m.file}) — ${m.reason}\n`);
    if (m.snippet) process.stdout.write(`           ${m.snippet}\n`);
  }
  if (dryRun) process.stdout.write("\nDry run — no files were modified. Re-run without --dry-run to apply.\n");
  process.stdout.write("\n");
}

// Minimum HMAC key length, mirrors POLICY_HMAC_MIN_KEY_BYTES in src/gate/policy.ts.
const POLICY_HMAC_MIN_KEY_BYTES = 32;

function runSignPolicy(): void {
  const key = process.env["SECURITY_POLICY_HMAC_KEY"];
  if (!key || Buffer.byteLength(key, "utf-8") < POLICY_HMAC_MIN_KEY_BYTES) {
    process.stderr.write(
      `Error: SECURITY_POLICY_HMAC_KEY must be set and at least ${POLICY_HMAC_MIN_KEY_BYTES} bytes.\n` +
        "Generate one with: openssl rand -hex 32\n"
    );
    process.exit(1);
  }

  const policyPath = process.env["SECURITY_GATE_POLICY"] || ".mcp/policies/security-policy.json";
  if (!existsSync(policyPath)) {
    process.stderr.write(
      `Error: policy file not found at "${policyPath}".\n` +
        "Create one first (cp node_modules/security-mcp/defaults/security-policy.json .mcp/policies/), " +
        "or set SECURITY_GATE_POLICY to its path.\n"
    );
    process.exit(1);
  }

  const raw = readFileSync(policyPath, "utf-8");
  const signature = signPolicyFile(raw, key);
  // 0o600 — keep the sidecar non-world-readable, consistent with data-at-rest hardening.
  writeFileSync(`${policyPath}.hmac`, signature + "\n", { mode: 0o600 });

  process.stdout.write(`\nsecurity-mcp sign-policy v${VERSION}\n`);
  process.stdout.write("=".repeat(40) + "\n\n");
  process.stdout.write(`  [SIGNED] ${policyPath}\n`);
  process.stdout.write(`  [WROTE]  ${policyPath}.hmac\n\n`);
  process.stdout.write("Commit both files so CI can verify policy integrity at gate startup.\n\n");
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const useGlobalBinary = args.includes("--use-global-binary");

  if (args.includes("--version") || args.includes("-v")) {
    process.stdout.write(`security-mcp v${VERSION}\n`);
    process.exit(0);
  }

  if (args.includes("--help") || args.includes("-h")) {
    process.stdout.write(HELP);
    process.exit(0);
  }

  const command = args[0] ?? "serve";

  if (command === "serve" || command === "ci:pr-gate") {
    // Non-blocking: keep stdout reserved for protocol/JSON output.
    void notifyIfUpdateAvailable(VERSION);
  } else {
    await notifyIfUpdateAvailable(VERSION);
  }

  switch (command) {
    case "serve": {
      // MCP stdio server - never write to stdout except via MCP protocol
      await runServer();
      break;
    }

    case "install": {
      const noEditorFlag =
        !args.includes("--claude-code") && !args.includes("--cursor") && !args.includes("--vscode") &&
        !args.includes("--windsurf") && !args.includes("--codex");
      const options = {
        claudeCode: args.includes("--claude-code"),
        cursor: args.includes("--cursor"),
        vscode: args.includes("--vscode"),
        windsurf: args.includes("--windsurf"),
        codex: args.includes("--codex"),
        dryRun: args.includes("--dry-run"),
        useGlobalBinary,
        all: noEditorFlag,
        interactive: !args.includes("--yes") && !args.includes("--non-interactive")
      };
      await runInstall(options);
      break;
    }

    case "install-global": {
      const noEditorFlag =
        !args.includes("--claude-code") && !args.includes("--cursor") && !args.includes("--vscode") &&
        !args.includes("--windsurf") && !args.includes("--codex");
      const options = {
        claudeCode: args.includes("--claude-code"),
        cursor: args.includes("--cursor"),
        vscode: args.includes("--vscode"),
        windsurf: args.includes("--windsurf"),
        codex: args.includes("--codex"),
        dryRun: args.includes("--dry-run"),
        useGlobalBinary: true,
        all: noEditorFlag,
        interactive: !args.includes("--yes") && !args.includes("--non-interactive")
      };
      await runInstall(options);
      break;
    }

    case "config": {
      process.stdout.write(JSON.stringify(getConfigSnippet(useGlobalBinary), null, 2) + "\n");
      process.stdout.write("\nAdd the above to your editor's MCP config file.\n");
      process.stdout.write("  Claude Code:  ~/.claude/settings.json                (key: mcpServers)\n");
      process.stdout.write("  Cursor:       ~/.cursor/mcp.json                     (key: mcpServers)\n");
      process.stdout.write("  VS Code:      .vscode/mcp.json                       (key: servers)\n");
      process.stdout.write("  Windsurf:     ~/.codeium/windsurf/mcp_config.json    (key: mcpServers)\n");
      process.stdout.write("  Codex:        ~/.codex/config.toml  (TOML: [mcp_servers.security-mcp] command/args)\n");
      process.stdout.write("  Replit:       remote MCP only — add via the Integrations UI\n");
      break;
    }

    case "doctor":
    case "verify": {
      runDoctor();
      break;
    }

    case "autoharden": {
      await runAutoHarden(args.includes("--dry-run"));
      break;
    }

    case "ci:pr-gate": {
      // Reads SECURITY_GATE_* env vars; exits non-zero when the gate fails.
      await runGateFromEnv();
      break;
    }

    case "sign-policy": {
      runSignPolicy();
      break;
    }

    default: {
      process.stderr.write(`Unknown command: ${command}\nRun with --help for usage.\n`);
      process.exit(1);
    }
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
