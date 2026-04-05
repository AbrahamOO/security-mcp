/**
 * security-mcp interactive onboarding
 *
 * Asks plain-English questions about the project, explains what each
 * security tool does, and installs gitleaks / semgrep / osv-scanner /
 * trivy / syft using every available method before giving up.
 *
 * Install priority per platform:
 *   macOS   → brew → pip (semgrep) → go install → official script → GitHub binary
 *   Linux   → apt/dnf/yum → pip → go install → official script → GitHub binary
 *   Windows → winget → choco → scoop → pip → go install → manual link
 */

import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { spawnSync } from "node:child_process";
import { platform, arch, homedir, tmpdir } from "node:os";
import { mkdirSync, createWriteStream, chmodSync, existsSync, writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";
import { createHash } from "node:crypto";
import { readFile as readFileAsync } from "node:fs/promises";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface OnboardingResult {
  projectTypes: string[];
  hasCiCd: boolean;
  ciPlatform?: string;
  sensitiveData: string[];
  installTools: boolean;
}

type OsType = "macos" | "linux" | "windows";

interface GitHubRelease {
  tag_name: string;
  assets: Array<{ name: string; browser_download_url: string }>;
}

interface SecurityTool {
  id: string;
  displayName: string;
  what_it_does: string;
  /** GitHub "owner/repo" for binary fallback */
  github?: string;
  /** Asset name patterns per platform (substring match, case-insensitive) */
  assetPatterns?: {
    macos_x64?: string;
    macos_arm64?: string;
    linux_x64?: string;
    linux_arm64?: string;
    windows_x64?: string;
  };
  /** Binary is a tarball (extract before moving) vs plain executable */
  tarball?: boolean;
  /** Brew formula name */
  brew?: string;
  /** pip / pip3 package name */
  pip?: string;
  /** go install path (e.g. github.com/org/repo/cmd/tool@latest) */
  goInstall?: string;
  /** apt package name (needs repo added first for some tools) */
  apt?: string;
  /** Official install script (piped to sh) */
  installScript?: string;
  /** Winget package id */
  winget?: string;
  /** Chocolatey package name */
  choco?: string;
  /** Scoop bucket/package */
  scoop?: string;
  manual_url: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const PROJECT_TYPES = [
  {
    key: "1",
    label: "Web application",
    examples: "React, Next.js, Vue, Angular, SvelteKit, plain HTML/CSS",
    value: "web"
  },
  {
    key: "2",
    label: "API or backend service",
    examples: "REST API, GraphQL, gRPC, Node.js, Python Flask/FastAPI, Go, Java Spring",
    value: "api"
  },
  {
    key: "3",
    label: "Mobile app",
    examples: "iOS (Swift/Objective-C), Android (Kotlin/Java), React Native, Flutter, Expo",
    value: "mobile"
  },
  {
    key: "4",
    label: "AI / machine learning",
    examples: "LLM integrations, OpenAI/Anthropic API, embeddings, RAG pipelines, AI agents",
    value: "ai"
  },
  {
    key: "5",
    label: "Infrastructure / cloud",
    examples: "Terraform, Kubernetes, Docker, AWS CDK, Helm charts, Ansible, Pulumi",
    value: "infra"
  },
  {
    key: "6",
    label: "A mix — all of the above",
    examples: "full-stack product, platform team, monorepo with multiple surfaces",
    value: "all"
  }
] as const;

const CI_PLATFORMS = [
  { key: "1", label: "GitHub Actions", examples: ".github/workflows/*.yml", value: "github-actions" },
  { key: "2", label: "GitLab CI", examples: ".gitlab-ci.yml", value: "gitlab-ci" },
  { key: "3", label: "CircleCI", examples: ".circleci/config.yml", value: "circleci" },
  { key: "4", label: "Jenkins", examples: "Jenkinsfile", value: "jenkins" },
  { key: "5", label: "Bitbucket Pipelines", examples: "bitbucket-pipelines.yml", value: "bitbucket" },
  { key: "6", label: "AWS CodePipeline", examples: "CodeBuild, CodeDeploy", value: "aws-codepipeline" },
  { key: "7", label: "Azure DevOps", examples: "azure-pipelines.yml", value: "azure-devops" },
  { key: "8", label: "Not sure yet / Other", examples: "TeamCity, Drone, Buildkite, etc.", value: "other" }
] as const;

const SENSITIVE_DATA_OPTIONS = [
  {
    key: "1",
    label: "Payment card data",
    examples: "credit/debit cards, billing, Stripe, PayPal — PCI DSS 4.0 applies",
    value: "payments"
  },
  {
    key: "2",
    label: "Health or medical data",
    examples: "patient records, lab results, prescriptions, mental health — HIPAA applies",
    value: "hipaa"
  },
  {
    key: "3",
    label: "Personal user data",
    examples: "names, emails, addresses, IP addresses, login history — GDPR / CCPA apply",
    value: "gdpr"
  },
  {
    key: "4",
    label: "None of the above",
    examples: "internal tooling, open-source, no PII stored",
    value: "none"
  }
] as const;

export const SECURITY_TOOLS: SecurityTool[] = [
  {
    id: "gitleaks",
    displayName: "Gitleaks",
    what_it_does:
      "Scans your code and git history for accidentally committed passwords, API keys, and tokens",
    github: "gitleaks/gitleaks",
    assetPatterns: {
      macos_x64: "darwin_x64",
      macos_arm64: "darwin_arm64",
      linux_x64: "linux_x64",
      linux_arm64: "linux_arm64",
      windows_x64: "windows_x64"
    },
    tarball: true,
    brew: "gitleaks",
    goInstall: "github.com/gitleaks/gitleaks/v8@latest",
    winget: "Gitleaks.Gitleaks",
    choco: "gitleaks",
    manual_url: "https://github.com/gitleaks/gitleaks#installation"
  },
  {
    id: "semgrep",
    displayName: "Semgrep",
    what_it_does:
      "Analyzes your source code for security bugs like SQL injection, XSS, and broken authentication",
    brew: "semgrep",
    pip: "semgrep",
    winget: "Semgrep.Semgrep",
    choco: "semgrep",
    manual_url: "https://semgrep.dev/docs/getting-started"
  },
  {
    id: "osv-scanner",
    displayName: "OSV-Scanner",
    what_it_does:
      "Checks every library your project depends on against Google's open-source vulnerability database",
    github: "google/osv-scanner",
    assetPatterns: {
      macos_x64: "darwin_amd64",
      macos_arm64: "darwin_arm64",
      linux_x64: "linux_amd64",
      linux_arm64: "linux_arm64",
      windows_x64: "windows_amd64"
    },
    tarball: false,
    brew: "osv-scanner",
    goInstall: "github.com/google/osv-scanner/cmd/osv-scanner@latest",
    winget: "Google.OSVScanner",
    choco: "osv-scanner",
    manual_url: "https://google.github.io/osv-scanner/installation"
  },
  {
    id: "trivy",
    displayName: "Trivy",
    what_it_does:
      "Scans Docker containers, Kubernetes manifests, and cloud infrastructure configs for misconfigurations",
    github: "aquasecurity/trivy",
    assetPatterns: {
      macos_x64: "macOS-64bit",
      macos_arm64: "macOS-ARM64",
      linux_x64: "Linux-64bit",
      linux_arm64: "Linux-ARM64",
      windows_x64: "windows-64bit"
    },
    tarball: true,
    brew: "trivy",
    apt: "trivy",
    installScript:
      "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin",
    winget: "AquaSecurity.Trivy",
    choco: "trivy",
    manual_url: "https://aquasecurity.github.io/trivy/latest/getting-started/installation"
  },
  {
    id: "syft",
    displayName: "Syft",
    what_it_does:
      "Creates a software bill of materials — a complete inventory of every library inside your application",
    github: "anchore/syft",
    assetPatterns: {
      macos_x64: "darwin_amd64",
      macos_arm64: "darwin_arm64",
      linux_x64: "linux_amd64",
      linux_arm64: "linux_arm64",
      windows_x64: "windows_amd64"
    },
    tarball: true,
    brew: "syft",
    installScript:
      "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin",
    winget: "Anchore.Syft",
    choco: "syft",
    scoop: "syft",
    manual_url: "https://github.com/anchore/syft#installation"
  }
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function print(msg = ""): void {
  process.stdout.write(msg + "\n");
}

function hr(): void {
  print("─".repeat(56));
}

function getOsType(): OsType {
  const p = platform();
  if (p === "darwin") return "macos";
  if (p === "linux") return "linux";
  return "windows";
}

/** Returns 'x64' or 'arm64' */
function getCpuArch(): "x64" | "arm64" {
  const a = arch();
  return a === "arm64" || a === "arm" ? "arm64" : "x64";
}

export function commandExists(cmd: string): boolean {
  try {
    // Use spawnSync (not execSync) to avoid shell injection — cmd is never interpolated into a shell string
    if (process.platform === "win32") {
      return spawnSync("where", [cmd], { stdio: "pipe" }).status === 0;
    } else {
      return spawnSync("which", [cmd], { stdio: "pipe" }).status === 0;
    }
  } catch {
    return false;
  }
}

function run(cmd: string, args: string[]): boolean {
  const result = spawnSync(cmd, args, { stdio: "inherit" });
  return result.status === 0;
}

// ─── Binary integrity helpers ─────────────────────────────────────────────────

// CWE-494: verify downloaded binary against publisher SHA-256 checksum before install.

async function fetchChecksumFile(assets: GitHubRelease["assets"]): Promise<string | null> {
  const checksumAsset = assets.find((a) =>
    /checksums?\.txt$/i.test(a.name) || /\.sha256(sums?)?$/i.test(a.name)
  );
  if (!checksumAsset) return null;
  try {
    const res = await fetch(checksumAsset.browser_download_url);
    if (!res.ok) return null;
    return await res.text();
  } catch { return null; }
}

function parseExpectedHash(checksumContent: string, filename: string): string | null {
  for (const line of checksumContent.split("\n")) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2) {
      const hash = parts[0];
      const name = (parts.at(-1) ?? "").replace(/^\*/, "");
      if (name === filename && /^[0-9a-f]{64}$/i.test(hash)) {
        return hash.toLowerCase();
      }
    }
  }
  return null;
}

async function verifyIntegrity(filePath: string, expectedHash: string): Promise<boolean> {
  const content = await readFileAsync(filePath);
  return createHash("sha256").update(content).digest("hex") === expectedHash;
}

// ─── GitHub binary download ───────────────────────────────────────────────────

async function fetchLatestRelease(repo: string): Promise<GitHubRelease | null> {
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "security-mcp-installer/1.0"
      }
    });
    if (!res.ok) return null;
    return (await res.json()) as GitHubRelease;
  } catch {
    return null;
  }
}

function pickAsset(
  assets: GitHubRelease["assets"],
  pattern: string
): string | undefined {
  return assets.find((a) =>
    a.name.toLowerCase().includes(pattern.toLowerCase())
  )?.browser_download_url;
}

async function downloadBinary(url: string, dest: string): Promise<boolean> {
  try {
    const res = await fetch(url);
    if (!res.ok || !res.body) return false;
    const ws = createWriteStream(dest);
    await pipeline(res.body as unknown as NodeJS.ReadableStream, ws);
    return true;
  } catch {
    return false;
  }
}

async function installFromGitHub(tool: SecurityTool, os: OsType): Promise<boolean> {
  if (!tool.github || !tool.assetPatterns) return false;

  const cpuArch = getCpuArch();
  const patternKey = `${os}_${cpuArch}` as keyof typeof tool.assetPatterns;
  const pattern = tool.assetPatterns[patternKey];
  if (!pattern) return false;

  print(`     Fetching latest ${tool.displayName} release from GitHub...`);
  const release = await fetchLatestRelease(tool.github);
  if (!release) {
    print(`     Could not reach GitHub API. Check your internet connection.`);
    return false;
  }

  const downloadUrl = pickAsset(release.assets, pattern);
  if (!downloadUrl) {
    print(`     No matching binary found for ${os}/${cpuArch} in ${release.tag_name}.`);
    return false;
  }

  const tmpDir = join(homedir(), ".cache", "security-mcp-install");
  mkdirSync(tmpDir, { recursive: true });
  const fileName = downloadUrl.split("/").pop() ?? `${tool.id}-download`;
  const tmpFile = join(tmpDir, fileName);

  print(`     Downloading ${fileName}...`);
  const downloaded = await downloadBinary(downloadUrl, tmpFile);
  if (!downloaded) {
    print(`     Download failed.`);
    return false;
  }

  // CWE-494: verify SHA-256 integrity before executing anything
  const checksumContent = await fetchChecksumFile(release.assets);
  if (checksumContent) {
    const expectedHash = parseExpectedHash(checksumContent, fileName);
    if (expectedHash) {
      const valid = await verifyIntegrity(tmpFile, expectedHash);
      if (!valid) {
        print(`     Integrity check FAILED for ${fileName} — aborting install.`);
        try { unlinkSync(tmpFile); } catch { /* ignore cleanup failure */ }
        return false;
      }
      print(`     Integrity verified (SHA-256 matched).`);
    } else {
      print(`     Warning: checksum file found but no entry for ${fileName} — proceeding without verification.`);
    }
  } else {
    print(`     Warning: no checksum file in release assets — cannot verify binary integrity.`);
  }

  const destDir = "/usr/local/bin";
  if (tool.tarball) {
    // Extract the binary from the archive
    const extracted = run("tar", ["xzf", tmpFile, "-C", tmpDir, tool.id]);
    if (!extracted) return false;
    const binSrc = join(tmpDir, tool.id);
    if (!existsSync(binSrc)) return false;
    chmodSync(binSrc, 0o755);
    // Try with sudo if we can't write directly
    return (
      run("mv", [binSrc, join(destDir, tool.id)]) ||
      run("sudo", ["mv", binSrc, join(destDir, tool.id)])
    );
  } else {
    // Plain executable
    chmodSync(tmpFile, 0o755);
    return (
      run("mv", [tmpFile, join(destDir, tool.id)]) ||
      run("sudo", ["mv", tmpFile, join(destDir, tool.id)])
    );
  }
}

// ─── Per-platform install strategies ─────────────────────────────────────────

async function tryBrew(tool: SecurityTool): Promise<boolean> {
  if (!tool.brew || !commandExists("brew")) return false;
  print(`     brew install ${tool.brew}`);
  return run("brew", ["install", tool.brew]);
}

async function tryPip(tool: SecurityTool): Promise<boolean> {
  if (!tool.pip) return false;
  const pip = commandExists("pip3") ? "pip3" : commandExists("pip") ? "pip" : null;
  if (!pip) return false;
  print(`     ${pip} install ${tool.pip}`);
  return run(pip, ["install", "--user", tool.pip]);
}

async function tryGoInstall(tool: SecurityTool): Promise<boolean> {
  if (!tool.goInstall || !commandExists("go")) return false;
  print(`     go install ${tool.goInstall}`);
  return run("go", ["install", tool.goInstall]);
}

async function tryApt(tool: SecurityTool): Promise<boolean> {
  if (!tool.apt || !commandExists("apt-get")) return false;
  // For trivy: add Aqua Security apt repo first
  if (tool.id === "trivy") {
    print(`     Setting up Aqua Security apt repository for Trivy...`);
    const setup =
      "sudo apt-get install -y wget gnupg lsb-release && " +
      "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add - && " +
      'echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" ' +
      "| sudo tee /etc/apt/sources.list.d/trivy.list && " +
      "sudo apt-get update -qq";
    run("bash", ["-c", setup]);
  }
  print(`     sudo apt-get install -y ${tool.apt}`);
  return run("sudo", ["apt-get", "install", "-y", tool.apt]);
}

async function tryDnf(tool: SecurityTool): Promise<boolean> {
  if (tool.id !== "trivy") return false;
  const mgr = commandExists("dnf") ? "dnf" : commandExists("yum") ? "yum" : null;
  if (!mgr) return false;

  // CWE-78: avoid bash -c shell construction — write repo file to a temp path
  // then move it into place with sudo (no shell, no injection surface).
  const repoLines = [
    "[trivy]",
    "name=Trivy repository",
    "baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/",
    "gpgcheck=0",
    "enabled=1"
  ];
  const tmpRepoFile = join(tmpdir(), `trivy-${Date.now()}.repo`);
  print(`     Adding Aqua Security yum/dnf repository...`);
  try {
    writeFileSync(tmpRepoFile, repoLines.join("\n") + "\n", "utf-8");
  } catch {
    return false;
  }
  run("sudo", ["mv", tmpRepoFile, "/etc/yum.repos.d/trivy.repo"]);

  print(`     sudo ${mgr} install -y trivy`);
  return run("sudo", [mgr, "install", "-y", "trivy"]);
}

async function tryInstallScript(tool: SecurityTool): Promise<boolean> {
  if (!tool.installScript || !commandExists("curl") || !commandExists("sh")) return false;
  print(`     Running official install script for ${tool.displayName}...`);
  return run("bash", ["-c", tool.installScript]);
}

async function tryWinget(tool: SecurityTool): Promise<boolean> {
  if (!tool.winget || !commandExists("winget")) return false;
  print(`     winget install --id ${tool.winget}`);
  return run("winget", ["install", "--id", tool.winget, "--silent", "--accept-source-agreements"]);
}

async function tryChoco(tool: SecurityTool): Promise<boolean> {
  if (!tool.choco || !commandExists("choco")) return false;
  print(`     choco install ${tool.choco} -y`);
  return run("choco", ["install", tool.choco, "-y"]);
}

async function tryScoop(tool: SecurityTool): Promise<boolean> {
  if (!tool.scoop || !commandExists("scoop")) return false;
  print(`     scoop install ${tool.scoop}`);
  return run("scoop", ["install", tool.scoop]);
}

// ─── Orchestrator: try everything, stop on first success ─────────────────────

async function installSingleTool(tool: SecurityTool, os: OsType): Promise<boolean> {
  print(`\n  Installing ${tool.displayName}...`);

  const strategies: Array<() => Promise<boolean>> = [];

  if (os === "macos") {
    strategies.push(
      () => tryBrew(tool),
      () => tryPip(tool),
      () => tryGoInstall(tool),
      () => tryInstallScript(tool),
      () => installFromGitHub(tool, os)
    );
  } else if (os === "linux") {
    strategies.push(
      () => tryApt(tool),
      () => tryDnf(tool),
      () => tryPip(tool),
      () => tryGoInstall(tool),
      () => tryInstallScript(tool),
      () => installFromGitHub(tool, os)
    );
  } else {
    // Windows
    strategies.push(
      () => tryWinget(tool),
      () => tryChoco(tool),
      () => tryScoop(tool),
      () => tryPip(tool),
      () => tryGoInstall(tool)
    );
  }

  for (const strategy of strategies) {
    try {
      const ok = await strategy();
      if (ok && commandExists(tool.id)) {
        print(`  ✓ ${tool.displayName} installed successfully`);
        return true;
      }
    } catch {
      // try next method
    }
  }

  print(`  ✗ Could not install ${tool.displayName} automatically.`);
  print(`    Manual install: ${tool.manual_url}`);
  return false;
}

export async function installSecurityTools(tools: SecurityTool[]): Promise<void> {
  if (tools.length === 0) {
    print("  All tools are already installed.");
    return;
  }

  const os = getOsType();

  if (os === "windows" && !commandExists("winget") && !commandExists("choco") && !commandExists("scoop")) {
    print("\n  No package manager found (winget / choco / scoop).");
    print("  Please install the tools manually:\n");
    for (const tool of tools) {
      print(`  • ${tool.displayName.padEnd(16)} ${tool.manual_url}`);
    }
    return;
  }

  for (const tool of tools) {
    await installSingleTool(tool, os);
  }

  print("");
  // Final verification
  const stillMissing = tools.filter((t) => !commandExists(t.id));
  if (stillMissing.length > 0) {
    print("  Some tools could not be installed automatically:");
    for (const t of stillMissing) {
      print(`    • ${t.displayName.padEnd(14)} ${t.manual_url}`);
    }
    print("");
  }
}

// ─── Onboarding wizard ────────────────────────────────────────────────────────

export async function runOnboarding(): Promise<OnboardingResult | null> {
  if (!process.stdin.isTTY) {
    return null; // CI/piped environment — skip interactive questions
  }

  const rl = createInterface({ input, output });
  const ask = (q: string): Promise<string> => rl.question(q);

  try {
    print("");
    print("╔════════════════════════════════════════════════════════╗");
    print("║           Welcome to security-mcp Setup                ║");
    print("╚════════════════════════════════════════════════════════╝");
    print("");
    print("security-mcp adds AI-powered security scanning to your");
    print("coding workflow. It catches security issues right inside");
    print("your editor — before they ever reach production.");
    print("");
    print("Answer 3 quick questions to tailor the setup to your project.");
    print("(Press Ctrl+C at any time to skip and use defaults.)");
    print("");
    hr();
    print("");

    // ── Step 1: Project type ─────────────────────────────────────────────────

    print("QUESTION 1 of 3  —  What type of project are you building?");
    print("");
    for (const t of PROJECT_TYPES) {
      print(`   ${t.key}.  ${t.label}`);
      print(`         [e.g. ${t.examples}]`);
      print("");
    }
    const typeAnswer = await ask("Enter number(s) separated by spaces (e.g. 1 2): ");

    const selectedTypeKeys = typeAnswer.trim().split(/[\s,]+/).filter(Boolean);
    let projectTypes: string[];

    if (selectedTypeKeys.includes("6")) {
      projectTypes = ["web", "api", "mobile", "ai", "infra"];
    } else {
      projectTypes = selectedTypeKeys
        .map((k) => PROJECT_TYPES.find((t) => t.key === k)?.value as string | undefined)
        .filter((v): v is string => v !== undefined);
    }

    if (projectTypes.length === 0) projectTypes = ["web", "api"];

    print("");
    hr();
    print("");

    // ── Step 2: CI/CD ────────────────────────────────────────────────────────

    print("QUESTION 2 of 3  —  Does this project use a CI/CD pipeline?");
    print("");
    print("   CI/CD automatically builds, tests, and deploys your code.");
    print("   security-mcp can add a security gate that blocks risky releases.");
    print("");
    const ciAnswer = await ask("Do you use or plan to use CI/CD? (y/n): ");
    const hasCiCd = ciAnswer.trim().toLowerCase().startsWith("y");

    let ciPlatform: string | undefined;
    if (hasCiCd) {
      print("");
      print("   Which CI/CD platform?");
      print("");
      for (const p of CI_PLATFORMS) {
        print(`   ${p.key}.  ${p.label}`);
        print(`         [e.g. ${p.examples}]`);
        print("");
      }
      const platformAnswer = await ask("   Enter number: ");
      ciPlatform = CI_PLATFORMS.find((p) => p.key === platformAnswer.trim())?.value ?? "other";
    }

    print("");
    hr();
    print("");

    // ── Step 3: Sensitive data ───────────────────────────────────────────────

    print("QUESTION 3 of 3  —  Does your app handle sensitive information?");
    print("");
    print("   This applies the right compliance controls automatically,");
    print("   such as PCI DSS for payment cards or HIPAA for health data.");
    print("   You can select multiple options (e.g. 1 2 or 1,2).");
    print("");
    for (const d of SENSITIVE_DATA_OPTIONS) {
      print(`   ${d.key}.  ${d.label}`);
      print(`         [e.g. ${d.examples}]`);
      print("");
    }
    const dataAnswer = await ask("Enter number(s) (or 4 for none): ");

    const selectedDataKeys = dataAnswer.trim().split(/[\s,]+/).filter(Boolean);
    let sensitiveData: string[] = [];

    if (!selectedDataKeys.includes("4")) {
      sensitiveData = selectedDataKeys
        .map((k) => SENSITIVE_DATA_OPTIONS.find((d) => d.key === k)?.value as string | undefined)
        .filter((v): v is string => v !== undefined && v !== "none");
    }

    print("");
    hr();
    print("");

    // ── Summary ──────────────────────────────────────────────────────────────

    print("Here's what security-mcp will configure for your project:");
    print("");
    print(`   ✓  Security policy tailored to: ${projectTypes.join(", ")}`);
    if (sensitiveData.includes("payments")) print("   ✓  PCI DSS 4.0 controls and payment-specific checklists");
    if (sensitiveData.includes("hipaa"))    print("   ✓  HIPAA technical safeguard controls");
    if (sensitiveData.includes("gdpr"))     print("   ✓  GDPR / CCPA data privacy controls");
    if (hasCiCd)                            print(`   ✓  CI/CD security gate for ${ciPlatform ?? "your pipeline"}`);
    print("   ✓  200+ controls mapped to OWASP, NIST 800-53, SOC 2, MITRE ATT&CK");
    print("   ✓  Pre-release security checklists for your team");
    print("");

    // ── Tool installation prompt ─────────────────────────────────────────────

    const alreadyInstalled = SECURITY_TOOLS.filter((t) => commandExists(t.id));
    const toInstall = SECURITY_TOOLS.filter((t) => !commandExists(t.id));

    if (alreadyInstalled.length > 0) {
      print(`   Already installed: ${alreadyInstalled.map((t) => t.displayName).join(", ")}`);
      print("");
    }

    let installTools = false;

    if (toInstall.length > 0) {
      print("The following security scanning tools are not yet on your machine.");
      print("They run 100% locally — your code is never uploaded anywhere.");
      print("");
      for (const tool of toInstall) {
        print(`   ${tool.displayName.padEnd(14)}  ${tool.what_it_does}`);
      }
      print("");

      const os = getOsType();
      const osNote =
        os === "macos"
          ? "We'll use Homebrew (with multiple fallbacks if needed)."
          : os === "linux"
          ? "We'll try apt/dnf, then official install scripts, then GitHub releases."
          : "We'll try winget, chocolatey, and scoop.";
      print(`   ${osNote}`);
      print("");

      const toolAnswer = await ask("Install these tools now? (y/n): ");
      installTools = toolAnswer.trim().toLowerCase().startsWith("y");
    }

    print("");
    hr();
    print("");

    return { projectTypes, hasCiCd, ciPlatform, sensitiveData, installTools };
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ERR_USE_AFTER_CLOSE") {
      print("\n\nSetup skipped — installing with defaults.\n");
    }
    return null;
  } finally {
    rl.close();
  }
}
