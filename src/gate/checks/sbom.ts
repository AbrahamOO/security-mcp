/**
 * SBOM generation and SLSA provenance checks.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import fg from "fast-glob";
import { Finding } from "../result.js";

const execFileAsync = promisify(execFile);
const SBOM_DIR = join(process.cwd(), ".mcp", "sbom");
const ATTESTATION_DIR = join(process.cwd(), ".mcp", "attestations");
const SBOM_PATH = join(SBOM_DIR, "latest.json");
const SBOM_MAX_AGE_MS = 24 * 60 * 60 * 1000;

async function ensureDir(dir: string): Promise<void> {
  try {
    await mkdir(dir, { recursive: true });
  } catch { /* ignore */ }
}

async function commandExists(cmd: string): Promise<boolean> {
  try {
    await execFileAsync(cmd, ["version"], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

async function getSbomAge(): Promise<number | null> {
  try {
    const s = await stat(SBOM_PATH);
    return Date.now() - s.mtimeMs;
  } catch {
    return null;
  }
}

interface CycloneDxComponent {
  name?: string;
  version?: string;
  purl?: string;
}
interface CycloneDxSbom {
  components?: CycloneDxComponent[];
}

async function readSbom(): Promise<CycloneDxSbom | null> {
  try {
    const raw = await readFile(SBOM_PATH, "utf-8");
    return JSON.parse(raw) as CycloneDxSbom;
  } catch {
    return null;
  }
}

async function getPackageJsonDeps(): Promise<string[]> {
  const manifests = await fg(["package.json", "**/package.json"], {
    dot: true,
    ignore: ["**/node_modules/**", "**/dist/**"]
  });

  const deps: string[] = [];
  for (const manifest of manifests.slice(0, 5)) {
    try {
      const raw = await readFile(manifest, "utf-8");
      const pkg = JSON.parse(raw) as Record<string, unknown>;
      const allDeps = {
        ...((pkg["dependencies"] as Record<string, string> | undefined) ?? {}),
        ...((pkg["devDependencies"] as Record<string, string> | undefined) ?? {})
      };
      deps.push(...Object.keys(allDeps));
    } catch { /* skip */ }
  }
  return [...new Set(deps)];
}

async function hasAttestation(): Promise<boolean> {
  try {
    const files = await fg(["**/*.sig", "**/*.bundle", "**/*.att"], {
      cwd: ATTESTATION_DIR,
      dot: true
    });
    return files.length > 0;
  } catch {
    return false;
  }
}

/**
 * Run SBOM and SLSA provenance checks.
 */
export async function runSbomChecks(_opts: {
  changedFiles: string[];
  targets: string[];
}): Promise<Finding[]> {
  const findings: Finding[] = [];

  await ensureDir(SBOM_DIR);
  await ensureDir(ATTESTATION_DIR);

  const syftAvailable = await commandExists("syft");
  const cosignAvailable = await commandExists("cosign");
  const autoSbom = process.env["SECURITY_AUTO_SBOM"] === "true";

  const sbomAge = await getSbomAge();

  // Auto-generate SBOM if enabled and Syft is available
  if (autoSbom && syftAvailable && (sbomAge === null || sbomAge > SBOM_MAX_AGE_MS)) {
    try {
      await execFileAsync(
        "syft",
        [".", `-o`, `cyclonedx-json=${SBOM_PATH}`],
        { cwd: process.cwd(), timeout: 120_000, maxBuffer: 50 * 1024 * 1024 }
      );
    } catch (err) {
      findings.push({
        id: "SBOM_MISSING",
        title: "SBOM generation failed",
        severity: "HIGH",
        evidence: [String(err)],
        requiredActions: [
          "Investigate Syft installation and run it manually: syft . -o cyclonedx-json=.mcp/sbom/latest.json",
          "Ensure the .mcp/sbom/ directory is writable."
        ]
      });
    }
  }

  // Re-check age after potential generation
  const currentSbomAge = await getSbomAge();

  if (currentSbomAge === null) {
    if (syftAvailable) {
      findings.push({
        id: "SBOM_MISSING",
        title: "No SBOM found. Syft is available — run it to generate one.",
        severity: "HIGH",
        evidence: [`Expected at: ${SBOM_PATH}`],
        requiredActions: [
          "Run: syft . -o cyclonedx-json=.mcp/sbom/latest.json",
          "Or set SECURITY_AUTO_SBOM=true to auto-generate on each gate run."
        ]
      });
    }
    // If syft not available, skip SBOM checks gracefully
  } else {
    if (currentSbomAge > SBOM_MAX_AGE_MS) {
      findings.push({
        id: "SBOM_STALE",
        title: "SBOM is stale (older than 24 hours)",
        severity: "MEDIUM",
        evidence: [`SBOM age: ${Math.round(currentSbomAge / 3600000)}h`, `Path: ${SBOM_PATH}`],
        requiredActions: [
          "Regenerate the SBOM: syft . -o cyclonedx-json=.mcp/sbom/latest.json",
          "Or set SECURITY_AUTO_SBOM=true to auto-regenerate."
        ]
      });
    }

    // Check cosign attestation
    if (!cosignAvailable) {
      // Skip cosign checks gracefully
    } else {
      const attested = await hasAttestation();
      if (!attested) {
        findings.push({
          id: "SBOM_UNSIGNED",
          title: "SBOM exists but no cosign attestation found",
          severity: "MEDIUM",
          evidence: [`Attestation dir: ${ATTESTATION_DIR}`],
          requiredActions: [
            "Sign the SBOM with cosign: cosign attest --predicate .mcp/sbom/latest.json ...",
            "Store attestation in .mcp/attestations/"
          ]
        });
      }
    }

    // Cross-reference package.json deps vs SBOM components
    const sbom = await readSbom();
    if (sbom) {
      const pkgDeps = await getPackageJsonDeps();
      const sbomNames = new Set(
        (sbom.components ?? []).map((c) => c.name?.toLowerCase() ?? "")
      );

      const missing = pkgDeps.filter((dep) => !sbomNames.has(dep.toLowerCase())).slice(0, 20);
      if (missing.length > 0) {
        findings.push({
          id: "SBOM_COMPONENT_MISMATCH",
          title: "Dependencies in package.json not found in SBOM",
          severity: "HIGH",
          evidence: missing,
          requiredActions: [
            "Regenerate the SBOM to include all current dependencies.",
            "Ensure Syft has access to node_modules when generating the SBOM."
          ]
        });
      }
    }
  }

  // SLSA provenance check
  try {
    const provenanceFiles = await fg(["**/*.intoto.jsonl", "**/provenance.json", "**/*.provenance"], {
      cwd: ATTESTATION_DIR,
      dot: true
    });
    if (provenanceFiles.length === 0) {
      findings.push({
        id: "PROVENANCE_MISSING",
        title: "No SLSA provenance attestation found",
        severity: "HIGH",
        evidence: [`Attestation dir: ${ATTESTATION_DIR}`],
        requiredActions: [
          "Generate SLSA provenance during CI/CD build.",
          "Use slsa-github-generator or equivalent to produce .intoto.jsonl attestations.",
          "Store provenance in .mcp/attestations/"
        ]
      });
    }
  } catch { /* directory doesn't exist yet */ }

  return findings;
}
