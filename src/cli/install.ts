/**
 * security-mcp install command
 *
 * Auto-detects installed editors and writes MCP server config + Claude Code skill.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync } from "fs";
import { dirname, join, resolve } from "path";
import { homedir, platform } from "os";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "../..");

const MCP_ENTRY = {
  command: "npx",
  args: ["-y", "security-mcp", "serve"]
};

interface InstallOptions {
  claudeCode: boolean;
  cursor: boolean;
  vscode: boolean;
  all: boolean;
  dryRun: boolean;
}

interface EditorTarget {
  name: string;
  configPath: string;
  type: "mcp-servers-json" | "vscode-settings";
  detected: boolean;
}

function resolveHome(p: string): string {
  return p.replace(/^~/, homedir());
}

function getVsCodeSettingsPath(): string {
  const os = platform();
  if (os === "win32") {
    return join(process.env["APPDATA"] ?? "", "Code", "User", "settings.json");
  }
  if (os === "darwin") {
    return join(homedir(), "Library", "Application Support", "Code", "User", "settings.json");
  }
  return join(homedir(), ".config", "Code", "User", "settings.json");
}

function getEditorTargets(opts: InstallOptions): EditorTarget[] {
  const claudeCodePath = resolveHome("~/.claude/settings.json");
  const cursorGlobalPath = resolveHome("~/.cursor/mcp.json");
  const cursorLocalPath = ".cursor/mcp.json";
  const vscodePath = getVsCodeSettingsPath();

  const all: EditorTarget[] = [
    {
      name: "Claude Code",
      configPath: claudeCodePath,
      type: "mcp-servers-json",
      detected: existsSync(resolveHome("~/.claude"))
    },
    {
      name: "Cursor (global)",
      configPath: cursorGlobalPath,
      type: "mcp-servers-json",
      detected: existsSync(resolveHome("~/.cursor"))
    },
    {
      name: "Cursor (workspace)",
      configPath: cursorLocalPath,
      type: "mcp-servers-json",
      detected: existsSync(".cursor")
    },
    {
      name: "VS Code",
      configPath: vscodePath,
      type: "vscode-settings",
      detected: existsSync(vscodePath)
    }
  ];

  if (opts.all) {
    return all.filter((t) => t.detected);
  }

  return all.filter((t) => {
    if (opts.claudeCode && t.name.startsWith("Claude Code")) return true;
    if (opts.cursor && t.name.startsWith("Cursor")) return true;
    if (opts.vscode && t.name === "VS Code") return true;
    return false;
  });
}

function readJsonSafe(filePath: string): Record<string, unknown> {
  try {
    return JSON.parse(readFileSync(filePath, "utf-8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function writeMcpServersJson(configPath: string, dryRun: boolean): string {
  const existing = readJsonSafe(configPath);
  const servers = (existing["mcpServers"] as Record<string, unknown>) ?? {};
  servers["security-mcp"] = MCP_ENTRY;
  existing["mcpServers"] = servers;

  const content = JSON.stringify(existing, null, 2) + "\n";
  if (!dryRun) {
    mkdirSync(dirname(configPath), { recursive: true });
    writeFileSync(configPath, content, "utf-8");
  }
  return configPath;
}

function writeVsCodeSettings(configPath: string, dryRun: boolean): string {
  const existing = readJsonSafe(configPath);
  const servers = (existing["mcp.servers"] as Record<string, unknown>) ?? {};
  servers["security-mcp"] = MCP_ENTRY;
  existing["mcp.servers"] = servers;

  const content = JSON.stringify(existing, null, 2) + "\n";
  if (!dryRun) {
    mkdirSync(dirname(configPath), { recursive: true });
    writeFileSync(configPath, content, "utf-8");
  }
  return configPath;
}

function installPolicy(dryRun: boolean): void {
  const policySrc = join(PKG_ROOT, "defaults", "security-policy.json");
  const policyDest = join(process.cwd(), ".mcp", "policies", "security-policy.json");
  const evidenceSrc = join(PKG_ROOT, "defaults", "evidence-map.json");
  const evidenceDest = join(process.cwd(), ".mcp", "mappings", "evidence-map.json");

  for (const { src, dest } of [{ src: policySrc, dest: policyDest }, { src: evidenceSrc, dest: evidenceDest }]) {
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

export async function runInstall(opts: InstallOptions): Promise<void> {
  const dryRun = opts.dryRun;

  process.stdout.write(`\nsecurity-mcp installer${dryRun ? " (dry-run)" : ""}\n`);
  process.stdout.write("=".repeat(40) + "\n\n");

  const targets = getEditorTargets(opts);

  if (targets.length === 0) {
    process.stdout.write(
      "No supported editors detected automatically.\n" +
      "Run with --claude-code, --cursor, or --vscode to target a specific editor.\n" +
      'Or add the config manually (run "npx security-mcp config" for the snippet).\n\n'
    );
    return;
  }

  for (const target of targets) {
    process.stdout.write(`Installing for ${target.name}...\n`);
    try {
      let written: string;
      if (target.type === "vscode-settings") {
        written = writeVsCodeSettings(target.configPath, dryRun);
      } else {
        written = writeMcpServersJson(target.configPath, dryRun);
      }
      process.stdout.write(`  ${dryRun ? "[dry-run] would update" : "updated"}: ${written}\n`);
    } catch (err) {
      process.stdout.write(`  [error] ${err instanceof Error ? err.message : String(err)}\n`);
    }
  }

  // Install Claude Code skill if Claude Code is in scope
  const hasClaudeCode = targets.some((t) => t.name.startsWith("Claude Code"));
  if (hasClaudeCode || opts.all) {
    process.stdout.write("\nInstalling Claude Code skill...\n");
    installSkill(dryRun);
  }

  process.stdout.write("\nInstalling security policy...\n");
  installPolicy(dryRun);

  process.stdout.write("\n");
  process.stdout.write(
    dryRun
      ? "Dry-run complete. Re-run without --dry-run to apply.\n"
      : "Done! Restart your editor to activate the security-mcp server.\n"
  );
  process.stdout.write("\nNext steps:\n");
  process.stdout.write("  1. Restart your editor.\n");
  process.stdout.write('  2. In Claude Code, type /senior-security-engineer to activate the security persona.\n');
  process.stdout.write('  3. Ask your AI: "Run security.run_pr_gate" to check your current diff.\n\n');
}
