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

import { createRequire } from "module";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";
import { runInstall } from "./install.js";
import { main as runServer } from "../mcp/server.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function getVersion(): string {
  try {
    const pkg = require(resolve(__dirname, "../../package.json")) as { version: string };
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
            args: ["-y", "security-mcp", "serve"]
          }
    }
  };
}

const HELP = `
security-mcp v${VERSION}

  AI security MCP server and gate for Claude Code, Cursor, Copilot, Codex, Replit, and any MCP-compatible editor.

USAGE
  npx security-mcp <command> [options]

COMMANDS
  serve            Start the MCP server over stdio (default for editors)
  install          Auto-detect installed editors and write MCP configs
  install-global   Install using the globally installed security-mcp binary
  config           Print MCP config JSON for manual editor setup

OPTIONS (install)
  --claude-code    Write config for Claude Code only
  --cursor         Write config for Cursor only
  --vscode         Write config for VS Code only
  --global         Write to global editor config (default)
  --use-global-binary  Write configs that execute "security-mcp serve" instead of npx
  --dry-run        Print what would change without writing

OPTIONS (general)
  --version        Print version
  --help           Print this help

EXAMPLES
  # Start MCP server (called automatically by editors):
  npx -y security-mcp serve

  # Install into all detected editors:
  npx security-mcp install

  # Install globally once, then configure editors to use the global binary:
  npm install -g security-mcp
  security-mcp install-global

  # Install into Claude Code only:
  npx security-mcp install --claude-code

  # Preview install without writing:
  npx security-mcp install --dry-run

  # Print JSON config snippet:
  npx security-mcp config
  security-mcp config --use-global-binary

EDITOR CONFIG (add manually if install fails):
  {
    "mcpServers": {
      "security-mcp": {
        "command": "npx",
        "args": ["-y", "security-mcp", "serve"]
      }
    }
  }

  Claude Code:  ~/.claude.json
  Cursor:       ~/.cursor/mcp.json  or  .cursor/mcp.json
  VS Code:      .vscode/mcp.json   (workspace)

MORE INFO
  https://github.com/AbrahamOO/security-mcp
`;

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

  switch (command) {
    case "serve": {
      // MCP stdio server - never write to stdout except via MCP protocol
      await runServer();
      break;
    }

    case "install": {
      const options = {
        claudeCode: args.includes("--claude-code"),
        cursor: args.includes("--cursor"),
        vscode: args.includes("--vscode"),
        dryRun: args.includes("--dry-run"),
        useGlobalBinary,
        // If no editor flag specified, install to all detected
        all: !args.includes("--claude-code") && !args.includes("--cursor") && !args.includes("--vscode")
      };
      await runInstall(options);
      break;
    }

    case "install-global": {
      const options = {
        claudeCode: args.includes("--claude-code"),
        cursor: args.includes("--cursor"),
        vscode: args.includes("--vscode"),
        dryRun: args.includes("--dry-run"),
        useGlobalBinary: true,
        all: !args.includes("--claude-code") && !args.includes("--cursor") && !args.includes("--vscode")
      };
      await runInstall(options);
      break;
    }

    case "config": {
      process.stdout.write(JSON.stringify(getConfigSnippet(useGlobalBinary), null, 2) + "\n");
      process.stdout.write("\nAdd the above to your editor's MCP config file.\n");
      process.stdout.write("  Claude Code:  ~/.claude.json\n");
      process.stdout.write("  Cursor:       ~/.cursor/mcp.json\n");
      process.stdout.write("  VS Code:      .vscode/mcp.json\n");
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
