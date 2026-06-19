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
import { dirname, resolve } from "node:path";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
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
  --vscode             Write config for VS Code only
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
  {
    "mcpServers": {
      "security-mcp": {
        "command": "npx",
        "args": ["-y", "security-mcp@latest", "serve"]
      }
    }
  }

  Claude Code:  ~/.claude/settings.json
  Cursor:       ~/.cursor/mcp.json  or  .cursor/mcp.json
  VS Code:      User settings.json  (via Preferences > Open User Settings JSON)
  Windsurf:     ~/.windsurf/mcp.json

MORE INFO
  https://github.com/AbrahamOO/security-mcp
`;

function resolveHome(p: string): string {
  return p.replace(/^~/, homedir());
}

function getVsCodeSettingsPath(): string {
  const os = platform();
  if (os === "win32") return `${process.env["APPDATA"] ?? ""}\\Code\\User\\settings.json`;
  if (os === "darwin") return `${homedir()}/Library/Application Support/Code/User/settings.json`;
  return `${homedir()}/.config/Code/User/settings.json`;
}

function runDoctor(): void {
  const checks: Array<{ label: string; ok: boolean; hint?: string }> = [];

  // Node.js version
  const nodeVer = process.versions.node.split(".").map(Number);
  const nodeOk = (nodeVer[0] ?? 0) >= 20;
  checks.push({ label: `Node.js ${process.versions.node}`, ok: nodeOk, hint: nodeOk ? undefined : "Node.js 20+ required. Download from https://nodejs.org" });

  // Claude Code config
  const claudeConfig = resolveHome("~/.claude/settings.json");
  const claudeOk = existsSync(claudeConfig);
  checks.push({ label: `Claude Code config (${claudeConfig})`, ok: claudeOk, hint: claudeOk ? undefined : "Run: npx -y security-mcp@latest install --claude-code" });

  // Claude Code skill
  const skillPath = resolveHome("~/.claude/skills/senior-security-engineer/SKILL.md");
  const skillOk = existsSync(skillPath);
  checks.push({ label: `senior-security-engineer skill (${skillPath})`, ok: skillOk, hint: skillOk ? undefined : "Run: npx -y security-mcp@latest install --claude-code" });

  // Cursor global config
  const cursorConfig = resolveHome("~/.cursor/mcp.json");
  if (existsSync(resolveHome("~/.cursor"))) {
    const cursorOk = existsSync(cursorConfig);
    checks.push({ label: `Cursor config (${cursorConfig})`, ok: cursorOk, hint: cursorOk ? undefined : "Run: npx -y security-mcp@latest install --cursor" });
  }

  // VS Code config
  const vscodePath = getVsCodeSettingsPath();
  if (existsSync(vscodePath)) {
    checks.push({ label: `VS Code config (${vscodePath})`, ok: true });
  }

  // Windsurf config
  const windsurfConfig = resolveHome("~/.windsurf/mcp.json");
  if (existsSync(resolveHome("~/.windsurf"))) {
    const windsurfOk = existsSync(windsurfConfig);
    checks.push({ label: `Windsurf config (${windsurfConfig})`, ok: windsurfOk, hint: windsurfOk ? undefined : "Run: npx -y security-mcp@latest install" });
  }

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
        !args.includes("--claude-code") && !args.includes("--cursor") && !args.includes("--vscode");
      const options = {
        claudeCode: args.includes("--claude-code"),
        cursor: args.includes("--cursor"),
        vscode: args.includes("--vscode"),
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
        !args.includes("--claude-code") && !args.includes("--cursor") && !args.includes("--vscode");
      const options = {
        claudeCode: args.includes("--claude-code"),
        cursor: args.includes("--cursor"),
        vscode: args.includes("--vscode"),
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
      process.stdout.write("  Claude Code:  ~/.claude/settings.json\n");
      process.stdout.write("  Cursor:       ~/.cursor/mcp.json\n");
      process.stdout.write("  VS Code:      User settings.json (Preferences > Open User Settings JSON)\n");
      process.stdout.write("  Windsurf:     ~/.windsurf/mcp.json\n");
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
