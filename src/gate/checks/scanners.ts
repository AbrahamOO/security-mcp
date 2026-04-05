/**
 * Scanner execution module.
 * Runs real security scanners and parses their JSON output into Finding[].
 */
import { readFile, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { z } from "zod";
import { Finding, FindingSeverity, sanitizeErrorMessage } from "../result.js";
import { SurfaceScope } from "../catalog.js";

const execFileAsync = promisify(execFile);

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "../../..");

const SECRET_SANITIZE_RE =
  /\b(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{35}|xoxb-[0-9A-Za-z-]{20,}|-----BEGIN[^-]*PRIVATE KEY-----)/g;

function sanitize(s: string): string {
  return s.replace(SECRET_SANITIZE_RE, "[REDACTED]");
}

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
    // CWE-22: resolve to absolute path and ensure it stays within cwd
    const resolved = resolve(process.cwd(), overridePath);
    if (!resolved.startsWith(process.cwd() + "/") && resolved !== process.cwd()) {
      throw new Error(`SECURITY_GATE_SCANNERS path '${overridePath}' escapes the project directory`);
    }
    const raw = await readFile(resolved, "utf-8");
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

async function commandExists(command: string): Promise<boolean> {
  try {
    await execFileAsync(command, ["--version"], { timeout: 5000 });
    return true;
  } catch {
    try {
      await execFileAsync(command, ["-version"], { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }
}


type DedupeKey = string;
function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<DedupeKey>();
  return findings.filter((f) => {
    const key = `${f.id}:${(f.files ?? []).join(",")}:${(f.evidence ?? []).slice(0, 1).join(",")}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Run a command and capture JSON output file, with timeout. */
async function runScannerToFile(
  command: string,
  args: string[],
  timeoutMs: number
): Promise<void> {
  await execFileAsync(command, args, {
    timeout: timeoutMs,
    maxBuffer: 50 * 1024 * 1024, // 50MB
    cwd: process.cwd()
  });
}

async function readJsonFile(path: string): Promise<unknown> {
  const raw = await readFile(path, "utf-8");
  return JSON.parse(raw);
}

// ---------------------------------------------------------------------------
// Gitleaks
// ---------------------------------------------------------------------------
interface GitleaksLeak {
  Description?: string;
  StartLine?: number;
  File?: string;
  Match?: string;
  Secret?: string;
  RuleID?: string;
}

async function runGitleaks(
  timeoutMs: number,
  changedFiles: string[]
): Promise<Finding[]> {
  const outFile = join(tmpdir(), `gl-report-${Date.now()}.json`);
  try {
    await runScannerToFile(
      "gitleaks",
      [
        "detect",
        "--source",
        process.cwd(),
        "--report-format",
        "json",
        "--report-path",
        outFile,
        "--no-git",
        "--exit-code",
        "0"
      ],
      timeoutMs
    );
  } catch {
    // gitleaks exits non-zero when it finds leaks — that's expected, try to read output
  }

  let data: unknown;
  try {
    data = await readJsonFile(outFile);
  } catch {
    return [];
  }

  if (!Array.isArray(data)) return [];

  const findings: Finding[] = [];
  const leaks = data as GitleaksLeak[];

  // Filter to changedFiles if provided
  const changedSet = new Set(changedFiles.map((f) => f.replace(/^\.\//, "")));

  for (const leak of leaks) {
    const file = sanitize(leak.File ?? "");
    if (changedFiles.length > 0 && !changedSet.has(file) && !changedSet.has(`./${file}`)) continue;

    findings.push({
      id: "POSSIBLE_SECRET",
      title: `Secret detected by Gitleaks: ${sanitize(leak.Description ?? leak.RuleID ?? "unknown")}`,
      severity: "CRITICAL",
      files: file ? [file] : undefined,
      evidence: [
        `Line: ${leak.StartLine ?? "unknown"}`,
        `Rule: ${sanitize(leak.RuleID ?? "unknown")}`
      ],
      requiredActions: [
        "Remove the secret from source code immediately.",
        "Rotate any exposed credentials.",
        "Store secrets only in a dedicated secret manager."
      ]
    });
  }

  return dedupeFindings(findings);
}

// ---------------------------------------------------------------------------
// Semgrep
// ---------------------------------------------------------------------------
interface SemgrepResult {
  results?: Array<{
    check_id?: string;
    path?: string;
    start?: { line?: number };
    extra?: {
      severity?: string;
      message?: string;
      metadata?: { cwe?: string[]; owasp?: string[] };
    };
  }>;
}

function semgrepSeverity(sev: string | undefined): FindingSeverity {
  switch ((sev ?? "").toUpperCase()) {
    case "ERROR":
    case "CRITICAL":
      return "CRITICAL";
    case "WARNING":
    case "HIGH":
      return "HIGH";
    case "INFO":
    case "LOW":
      return "LOW";
    default:
      return "MEDIUM";
  }
}

async function runSemgrep(timeoutMs: number, changedFiles: string[]): Promise<Finding[]> {
  const outFile = join(tmpdir(), `semgrep-${Date.now()}.json`);
  try {
    const args = [
      "--config=p/owasp-top-ten",
      "--config=p/secrets",
      "--json",
      `--output=${outFile}`,
      "."
    ];
    await runScannerToFile("semgrep", args, timeoutMs);
  } catch {
    // non-zero exit is fine
  }

  let data: unknown;
  try {
    data = await readJsonFile(outFile);
  } catch {
    return [];
  }

  const parsed = data as SemgrepResult;
  const results = parsed.results ?? [];
  const changedSet = new Set(changedFiles.map((f) => f.replace(/^\.\//, "")));
  const findings: Finding[] = [];

  for (const r of results) {
    const file = r.path ?? "";
    if (changedFiles.length > 0 && !changedSet.has(file) && !changedSet.has(`./${file}`)) continue;

    const sev = semgrepSeverity(r.extra?.severity);
    findings.push({
      id: `SEMGREP_${(r.check_id ?? "FINDING").replace(/[^A-Z0-9_]/gi, "_").toUpperCase()}`,
      title: sanitize(r.extra?.message ?? r.check_id ?? "Semgrep finding"),
      severity: sev,
      files: file ? [sanitize(file)] : undefined,
      evidence: [
        `Line: ${r.start?.line ?? "unknown"}`,
        ...(r.extra?.metadata?.cwe ?? []),
        ...(r.extra?.metadata?.owasp ?? [])
      ],
      requiredActions: [
        "Review the semgrep finding and apply the recommended fix.",
        "See semgrep documentation for the rule for remediation guidance."
      ]
    });
  }

  return dedupeFindings(findings);
}

// ---------------------------------------------------------------------------
// Trivy
// ---------------------------------------------------------------------------
interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  Severity?: string;
  CVSS?: Record<string, { V3Score?: number }>;
  Title?: string;
}
interface TrivyResult {
  Results?: Array<{
    Target?: string;
    Vulnerabilities?: TrivyVuln[];
  }>;
}

function trivyGetCvss(vuln: TrivyVuln): number {
  const cvss = vuln.CVSS ?? {};
  let max = 0;
  for (const source of Object.values(cvss)) {
    if (source.V3Score && source.V3Score > max) max = source.V3Score;
  }
  return max;
}

async function runTrivy(timeoutMs: number): Promise<Finding[]> {
  const outFile = join(tmpdir(), `trivy-${Date.now()}.json`);
  try {
    await runScannerToFile(
      "trivy",
      ["fs", "--format", "json", "--output", outFile, "."],
      timeoutMs
    );
  } catch {
    // non-zero is fine
  }

  let data: unknown;
  try {
    data = await readJsonFile(outFile);
  } catch {
    return [];
  }

  const parsed = data as TrivyResult;
  const findings: Finding[] = [];

  for (const result of parsed.Results ?? []) {
    for (const vuln of result.Vulnerabilities ?? []) {
      const cvss = trivyGetCvss(vuln);
      const sev = (vuln.Severity ?? "").toUpperCase();
      let severity: FindingSeverity;
      let findingId: string;

      if (cvss >= 9.0 || sev === "CRITICAL") {
        severity = "CRITICAL";
        findingId = "SCANNER_CRITICAL_CVE";
      } else if (cvss >= 7.0 || sev === "HIGH") {
        severity = "HIGH";
        findingId = "SCANNER_HIGH_CVE";
      } else {
        continue; // skip MEDIUM/LOW from scanner results
      }

      findings.push({
        id: findingId,
        title: `Trivy: ${sanitize(vuln.Title ?? vuln.VulnerabilityID ?? "CVE")} in ${vuln.PkgName ?? "unknown"}`,
        severity,
        evidence: [
          `CVE: ${vuln.VulnerabilityID ?? "unknown"}`,
          `Package: ${vuln.PkgName ?? "unknown"}@${vuln.InstalledVersion ?? "unknown"}`,
          `CVSS: ${cvss}`,
          `Target: ${sanitize(result.Target ?? "")}`
        ],
        requiredActions: [
          "Update the affected package to a patched version.",
          "If no patch is available, apply mitigations and add a security exception with justification."
        ]
      });
    }
  }

  return dedupeFindings(findings);
}

// ---------------------------------------------------------------------------
// Checkov
// ---------------------------------------------------------------------------
interface CheckovFailed {
  check_id?: string;
  check_type?: string;
  file_path?: string;
  resource?: string;
  check?: { name?: string };
  severity?: string;
}
interface CheckovOutput {
  results?: {
    failed_checks?: CheckovFailed[];
  };
}

async function runCheckov(timeoutMs: number): Promise<Finding[]> {
  const outFile = join(tmpdir(), `checkov-${Date.now()}.json`);
  try {
    await runScannerToFile(
      "checkov",
      ["-d", ".", "--output", "json", "--output-file", outFile, "--quiet"],
      timeoutMs
    );
  } catch {
    // non-zero exit is expected when findings exist
  }

  let data: unknown;
  try {
    data = await readJsonFile(outFile);
  } catch {
    return [];
  }

  // Checkov can return array or object
  const parsed: CheckovOutput = Array.isArray(data)
    ? { results: { failed_checks: (data as CheckovOutput[]).flatMap((d) => d.results?.failed_checks ?? []) } }
    : (data as CheckovOutput);

  const failed = parsed.results?.failed_checks ?? [];
  const findings: Finding[] = [];

  for (const check of failed) {
    const sev = (check.severity ?? "").toUpperCase();
    const severity: FindingSeverity =
      sev === "CRITICAL" ? "CRITICAL" : sev === "HIGH" ? "HIGH" : "MEDIUM";

    findings.push({
      id: `CHECKOV_${(check.check_id ?? "FINDING").replace(/[^A-Z0-9_]/gi, "_").toUpperCase()}`,
      title: sanitize(
        `Checkov: ${check.check?.name ?? check.check_id ?? "IaC misconfiguration"} in ${check.resource ?? ""}`
      ),
      severity,
      files: check.file_path ? [sanitize(check.file_path)] : undefined,
      evidence: [
        `Check: ${check.check_id ?? "unknown"}`,
        `Type: ${check.check_type ?? "unknown"}`
      ],
      requiredActions: [
        "Fix the IaC misconfiguration identified by Checkov.",
        "See Checkov documentation for the check rule for remediation guidance."
      ]
    });
  }

  return dedupeFindings(findings);
}

// ---------------------------------------------------------------------------
// OSV-Scanner
// ---------------------------------------------------------------------------
interface OsvGroup {
  ids?: string[];
  packages?: Array<{ package?: { name?: string; version?: string } }>;
}
interface OsvOutput {
  results?: Array<{
    packages?: Array<{ groups?: OsvGroup[] }>;
  }>;
}

async function runOsvScanner(timeoutMs: number): Promise<Finding[]> {
  const outFile = join(tmpdir(), `osv-${Date.now()}.json`);
  try {
    await runScannerToFile("osv-scanner", ["--format", "json", "--output", outFile, "."], timeoutMs);
  } catch {
    // non-zero when vulns found
  }

  let data: unknown;
  try {
    data = await readJsonFile(outFile);
  } catch {
    return [];
  }

  const parsed = data as OsvOutput;
  const findings: Finding[] = [];

  for (const result of parsed.results ?? []) {
    for (const pkg of result.packages ?? []) {
      for (const group of pkg.groups ?? []) {
        const ids = group.ids ?? [];
        const pkgName = group.packages?.[0]?.package?.name ?? "unknown";
        const pkgVer = group.packages?.[0]?.package?.version ?? "unknown";

        // Assume HIGH severity for OSV findings (no CVSS in basic output)
        findings.push({
          id: "SCANNER_HIGH_CVE",
          title: `OSV-Scanner: vulnerability in ${pkgName}@${pkgVer}`,
          severity: "HIGH",
          evidence: ids.slice(0, 5),
          requiredActions: [
            "Update the affected package to a non-vulnerable version.",
            "Check OSV.dev for patch availability and workarounds."
          ]
        });
      }
    }
  }

  return dedupeFindings(findings);
}

// ---------------------------------------------------------------------------
// Main export: checkScannerReadiness (backwards compatible) + runScanners
// ---------------------------------------------------------------------------

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
    if (!(await commandExists(scanner.command))) {
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

/**
 * Actually execute scanners and parse their output into Finding[].
 * Uses Promise.allSettled so one scanner failure doesn't kill others.
 */
export async function runScanners(opts: {
  surfaces: SurfaceScope;
  changedFiles: string[];
  timeoutMs?: number;
}): Promise<Finding[]> {
  const config = await loadScannerConfig();
  const timeout = opts.timeoutMs ?? 120_000;

  // Ensure tmp dir exists for output files
  try {
    await mkdir(tmpdir(), { recursive: true });
  } catch {
    // already exists
  }

  type ScannerTask = () => Promise<Finding[]>;
  const tasks: Array<{ id: string; task: ScannerTask }> = [];

  if (config.scanners["gitleaks"] && scannerApplies(config.scanners["gitleaks"].required_for, opts.surfaces)) {
    if (await commandExists("gitleaks")) {
      tasks.push({ id: "gitleaks", task: () => runGitleaks(timeout, opts.changedFiles) });
    }
  }

  if (config.scanners["semgrep"] && scannerApplies(config.scanners["semgrep"].required_for, opts.surfaces)) {
    if (await commandExists("semgrep")) {
      tasks.push({ id: "semgrep", task: () => runSemgrep(timeout, opts.changedFiles) });
    }
  }

  if (config.scanners["trivy"] && scannerApplies(config.scanners["trivy"].required_for, opts.surfaces)) {
    if (await commandExists("trivy")) {
      tasks.push({ id: "trivy", task: () => runTrivy(timeout) });
    }
  }

  if (config.scanners["checkov"] && scannerApplies(config.scanners["checkov"].required_for, opts.surfaces)) {
    if (await commandExists("checkov")) {
      tasks.push({ id: "checkov", task: () => runCheckov(timeout) });
    }
  }

  if (config.scanners["osv-scanner"] && scannerApplies(config.scanners["osv-scanner"].required_for, opts.surfaces)) {
    if (await commandExists("osv-scanner")) {
      tasks.push({ id: "osv-scanner", task: () => runOsvScanner(timeout) });
    }
  }

  const results = await Promise.allSettled(tasks.map((t) => t.task()));
  const allFindings: Finding[] = [];

  for (let i = 0; i < results.length; i++) {
    const res = results[i];
    const taskId = tasks[i]?.id ?? "unknown";
    if (res.status === "fulfilled") {
      allFindings.push(...res.value);
    } else {
      console.warn(`[scanners] Scanner ${taskId} failed: ${sanitizeErrorMessage(String(res.reason))}`);
      allFindings.push({
        id: "SCANNER_EXECUTION_ERROR",
        title: `Security scanner '${taskId}' failed unexpectedly`,
        severity: "MEDIUM",
        evidence: [sanitize(String(res.reason))],
        requiredActions: [
          `Investigate why scanner '${taskId}' failed.`,
          "Check scanner installation and permissions."
        ]
      });
    }
  }

  return dedupeFindings(allFindings);
}
