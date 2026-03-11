import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { execa } from "execa";
import { Finding } from "../result.js";
import { SurfaceScope } from "../catalog.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "../../..");

const ScannerSchema = z.object({
  command: z.string(),
  args: z.array(z.string()).default(["--version"]),
  required_for: z.array(z.string()).default(["all"])
});

const ScannerConfigSchema = z.object({
  version: z.string(),
  fail_closed: z.boolean().default(true),
  scanners: z.record(ScannerSchema)
});

type ScannerConfig = z.infer<typeof ScannerConfigSchema>;

async function loadScannerConfig(): Promise<ScannerConfig> {
  const overridePath = process.env["SECURITY_GATE_SCANNERS"];
  if (overridePath) {
    const raw = await readFile(join(process.cwd(), overridePath), "utf-8");
    return ScannerConfigSchema.parse(JSON.parse(raw));
  }

  try {
    const raw = await readFile(join(process.cwd(), ".mcp", "scanners", "security-tools.json"), "utf-8");
    return ScannerConfigSchema.parse(JSON.parse(raw));
  } catch {
    const raw = await readFile(join(PKG_ROOT, "defaults", "security-tools.json"), "utf-8");
    return ScannerConfigSchema.parse(JSON.parse(raw));
  }
}

function scannerApplies(requiredFor: string[], surfaces: SurfaceScope): boolean {
  const mobile = surfaces.mobileIos || surfaces.mobileAndroid;
  if (requiredFor.includes("all")) return true;
  if (requiredFor.includes("web") && surfaces.web) return true;
  if (requiredFor.includes("api") && surfaces.api) return true;
  if (requiredFor.includes("infra") && surfaces.infra) return true;
  if (requiredFor.includes("ai") && surfaces.ai) return true;
  if (requiredFor.includes("mobile") && mobile) return true;
  return false;
}

async function commandExists(command: string, args: string[]): Promise<boolean> {
  try {
    const result = await execa(command, args, { reject: false });
    return result.exitCode === 0;
  } catch {
    return false;
  }
}

export async function checkScannerReadiness(opts: { surfaces: SurfaceScope }): Promise<{
  findings: Finding[];
  configured: string[];
  missing: string[];
}> {
  const config = await loadScannerConfig();
  const configured: string[] = [];
  const missing: string[] = [];
  const findings: Finding[] = [];

  for (const [scannerId, scanner] of Object.entries(config.scanners)) {
    if (!scannerApplies(scanner.required_for, opts.surfaces)) continue;
    configured.push(scannerId);
    if (!(await commandExists(scanner.command, scanner.args))) {
      missing.push(scannerId);
    }
  }

  if (missing.length > 0 && config.fail_closed) {
    findings.push({
      id: "SCANNER_TOOLCHAIN_INCOMPLETE",
      title: "Required security scanners are not installed or not runnable",
      severity: "HIGH",
      evidence: missing,
      requiredActions: [
        "Install the missing scanners or adjust the approved scanner config intentionally.",
        "Do not rely on heuristic checks alone when fail-closed scanner enforcement is enabled."
      ]
    });
  }

  return { findings, configured, missing };
}
