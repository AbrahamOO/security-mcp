import { Finding, sanitizeErrorMessage } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import { checkActiveExploitation } from "../threat-intel.js";
import { join } from "node:path";

const THREAT_INTEL_CACHE_DIR = join(process.cwd(), ".mcp", "threat-intel");

const execFileAsync = promisify(execFile);

// 24-hour cache for OpenSSF Scorecard API responses
const scorecardCache = new Map<string, { score: number; fetchedAt: number }>();
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

async function fetchScorecardScore(dep: string): Promise<number | null> {
	try {
		const cached = scorecardCache.get(dep);
		if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
			return cached.score;
		}

		// dep may be scoped (e.g. @org/pkg) — map to github owner/repo is heuristic
		// We try the npm registry to find the repository
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 5000);
		try {
			const npmResp = await fetch(`https://registry.npmjs.org/${encodeURIComponent(dep)}/latest`, {
				signal: controller.signal
			});
			if (!npmResp.ok) return null;
			const npmData = await npmResp.json() as { repository?: { url?: string } };
			const repoUrl = npmData?.repository?.url ?? "";
			const ghMatch = /github\.com[/:]([^/]+\/[^/.]+)/.exec(repoUrl);
			if (!ghMatch) return null;
			const ghPath = ghMatch[1].replace(/\.git$/, "");

			const controller2 = new AbortController();
			const timeout2 = setTimeout(() => controller2.abort(), 5000);
			try {
				const scoreResp = await fetch(
					`https://api.securityscorecards.dev/projects/github.com/${ghPath}`,
					{ signal: controller2.signal }
				);
				if (!scoreResp.ok) return null;
				const scoreData = await scoreResp.json() as { score?: number };
				const score = scoreData?.score ?? null;
				if (score !== null) {
					scorecardCache.set(dep, { score, fetchedAt: Date.now() });
				}
				return score;
			} finally {
				clearTimeout(timeout2);
			}
		} finally {
			clearTimeout(timeout);
		}
	} catch {
		return null;
	}
}

async function checkNpmProvenance(): Promise<{ findings: Finding[] }> {
	const findings: Finding[] = [];

	try {
		// 1. npm audit signatures (npm 9+)
		try {
			const { stdout } = await execFileAsync("npm", ["audit", "signatures", "--json"], {
				timeout: 30000,
				// CWE-526: pass only PATH — do not propagate API keys or tokens from parent env.
				env: { PATH: process.env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin" }
			});
			if (stdout) {
				let auditResult: unknown;
				try {
					auditResult = JSON.parse(stdout);
				} catch {
					auditResult = null;
				}
				if (auditResult && typeof auditResult === "object") {
					const result = auditResult as Record<string, unknown>;
					const invalid = (result["invalid"] as unknown[]) ?? [];
					const missing = (result["missing"] as unknown[]) ?? [];
					const noProvenance = [...invalid, ...missing];
					if (noProvenance.length > 0) {
						findings.push({
							id: "DEP_NO_PROVENANCE",
							title: `${noProvenance.length} production dependencies lack npm provenance attestation`,
							severity: "MEDIUM",
							evidence: noProvenance.slice(0, 10).map((p) => typeof p === "object" && p !== null ? JSON.stringify(p).slice(0, 120) : String(p)),
							requiredActions: [
								"Require packages with npm provenance attestation (npm 9+).",
								"Pin dependencies to specific versions and verify signatures."
							]
						});
					}
				}
			}
		} catch {
			// npm not available or < v9 — skip gracefully
		}

		// 2. OpenSSF Scorecard for top 5 production deps
		try {
			const pkgRaw = await readFile("package.json", "utf8");
			const pkg = JSON.parse(pkgRaw) as { dependencies?: Record<string, string> };
			const prodDeps = Object.keys(pkg.dependencies ?? {}).slice(0, 5);

			for (const dep of prodDeps) {
				const score = await fetchScorecardScore(dep);
				if (score !== null && score < 5.0) {
					findings.push({
						id: "DEP_LOW_SCORECARD",
						title: `Dependency "${dep}" has a low OpenSSF Scorecard score (${score.toFixed(1)}/10)`,
						severity: "MEDIUM",
						evidence: [`${dep}: score ${score.toFixed(1)}/10 (threshold: 5.0)`],
						requiredActions: [
							`Review the OpenSSF Scorecard for ${dep} at https://scorecard.dev.`,
							"Consider replacing low-scored dependencies or accepting documented risk."
						]
					});
				}
			}
		} catch {
			// package.json unreadable or API unavailable — skip
		}
	} catch (err) {
		console.warn("[checkNpmProvenance] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return { findings };
}

export async function checkDependencies(_: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	const manifests = await fg(["package.json"], { dot: true });
	const lockfiles = await fg(["package-lock.json", "pnpm-lock.yaml", "yarn.lock"], { dot: true });
	if (manifests.length === 0 && lockfiles.length === 0) {
		return findings;
	}

	if (lockfiles.length === 0) {
		findings.push({
			id: "LOCKFILE_MISSING",
			title: "No JS lockfile found",
			severity: "HIGH",
			requiredActions: [
				"Add and commit a lockfile (package-lock.json, pnpm-lock.yaml, or yarn.lock).",
				"Pin versions and enable dependency scanning in CI."
			]
		});
		return findings;
	}

	// Basic check: ensure package.json exists and is valid JSON
	try {
		const pkg = JSON.parse(await readFileSafe("package.json"));
		if (!pkg.dependencies && !pkg.devDependencies) {
			findings.push({
				id: "PACKAGE_JSON_EMPTY",
				title: "package.json has no dependencies/devDependencies",
				severity: "LOW",
				requiredActions: ["Verify this is intentional. If not, add dependencies with pinned ranges."]
			});
		}
	} catch {
		findings.push({
			id: "PACKAGE_JSON_INVALID",
			title: "package.json is missing or invalid JSON",
			severity: "HIGH",
			requiredActions: ["Fix package.json JSON syntax."]
		});
	}

	const provenance = await checkNpmProvenance();
	findings.push(...provenance.findings);

	const transitive = await checkTransitiveDependencies();
	findings.push(...transitive);

	const typosquat = await checkTyposquatting();
	findings.push(...typosquat);

	const threatIntel = await checkCveExploitation();
	findings.push(...threatIntel);

	return findings;
}

// ─── CVE threat-intelligence enrichment ────────────────────────────────────

interface NpmAuditVulnVia {
	cve?: string[];
	id?: number;
	url?: string;
}

interface NpmAuditVuln {
	via?: Array<NpmAuditVulnVia | string>;
}

function extractCveIds(audit: { vulnerabilities?: Record<string, NpmAuditVuln> }): string[] {
	const cveSet = new Set<string>();
	for (const vuln of Object.values(audit.vulnerabilities ?? {})) {
		for (const via of vuln.via ?? []) {
			if (typeof via !== "object" || !Array.isArray(via.cve)) continue;
			for (const cve of via.cve) {
				if (typeof cve === "string" && cve.startsWith("CVE-")) cveSet.add(cve);
			}
		}
	}
	return [...cveSet];
}

function buildThreatIntelFindings(intel: Awaited<ReturnType<typeof checkActiveExploitation>>): Finding[] {
	const findings: Finding[] = [];
	if (intel.kevMatches.length > 0) {
		findings.push({
			id: "DEP_CVE_ACTIVELY_EXPLOITED",
			title: `${intel.kevMatches.length} dependency CVE(s) are actively exploited (CISA KEV)`,
			severity: "CRITICAL",
			evidence: intel.kevMatches.slice(0, 20),
			requiredActions: [
				"Upgrade or patch these dependencies immediately — these CVEs are in CISA's Known Exploited Vulnerabilities catalog.",
				"Run `npm audit fix` or manually update to a patched version.",
				"If no patch is available, apply mitigating controls and document accepted risk."
			]
		});
	}
	if (intel.highEpss.length > 0) {
		findings.push({
			id: "DEP_CVE_HIGH_EPSS",
			title: `${intel.highEpss.length} dependency CVE(s) have high exploitation probability (EPSS > 50%)`,
			severity: "HIGH",
			evidence: intel.highEpss.slice(0, 20).map((e) => `${e.cve}: ${(e.score * 100).toFixed(1)}% exploitation probability`),
			requiredActions: [
				"Prioritize patching these CVEs — high EPSS scores indicate active exploitation in the wild.",
				"Run `npm audit fix` or update affected packages.",
				"Monitor for exploit availability and treat as high urgency even without a current patch."
			]
		});
	}
	return findings;
}

async function checkCveExploitation(): Promise<Finding[]> {
	try {
		let stdout: string;
		try {
			const result = await execFileAsync("npm", ["audit", "--json"], {
				timeout: 30_000,
				env: { PATH: process.env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin" }
			});
			stdout = result.stdout;
		} catch (err: unknown) {
			// npm audit exits non-zero when vulnerabilities exist — output is still valid JSON.
			stdout = (err as { stdout?: string })?.stdout ?? "";
		}

		if (!stdout) return [];

		let audit: { vulnerabilities?: Record<string, NpmAuditVuln> };
		try {
			audit = JSON.parse(stdout) as { vulnerabilities?: Record<string, NpmAuditVuln> };
		} catch {
			return [];
		}

		const cveIds = extractCveIds(audit);
		if (cveIds.length === 0) return [];

		const intel = await checkActiveExploitation(cveIds, THREAT_INTEL_CACHE_DIR);
		if (intel.failed) return [];

		return buildThreatIntelFindings(intel);
	} catch (err) {
		console.warn("[checkCveExploitation] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
		return [];
	}
}

// ─── Transitive dependency analysis ────────────────────────────────────────

interface LockfilePackage {
	version?: string;
	integrity?: string;
	scripts?: Record<string, string>;
	dependencies?: Record<string, string>;
}

const LIFECYCLE_SCRIPTS = ["postinstall", "install", "preinstall"];

function hasLifecycleScript(pkg: LockfilePackage): boolean {
	return !!pkg.scripts && LIFECYCLE_SCRIPTS.some((s) => !!pkg.scripts![s]);
}

function scanLockfilePackages(packages: Record<string, LockfilePackage>): {
	scriptPkgs: string[];
	missingIntegrityPkgs: string[];
} {
	const scriptPkgs: string[] = [];
	const missingIntegrityPkgs: string[] = [];

	for (const [name, pkg] of Object.entries(packages)) {
		if (!name) continue; // skip root entry
		const pkgName = name.replace(/^node_modules\//, "");
		if (hasLifecycleScript(pkg)) scriptPkgs.push(pkgName);
		if (pkg.version && !pkg.integrity) missingIntegrityPkgs.push(pkgName);
	}

	return { scriptPkgs, missingIntegrityPkgs };
}

async function checkTransitiveDependencies(): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		let lockRaw: string;
		try {
			lockRaw = await readFile("package-lock.json", "utf8");
		} catch {
			return [];
		}

		let lock: { packages?: Record<string, LockfilePackage> };
		try {
			lock = JSON.parse(lockRaw) as { packages?: Record<string, LockfilePackage> };
		} catch {
			return [];
		}

		const { scriptPkgs, missingIntegrityPkgs } = scanLockfilePackages(lock.packages ?? {});

		if (scriptPkgs.length > 0) {
			findings.push({
				id: "DEP_LIFECYCLE_SCRIPTS",
				title: `${scriptPkgs.length} transitive dependencies contain lifecycle scripts (postinstall/install/preinstall)`,
				severity: "HIGH",
				evidence: scriptPkgs.slice(0, 15),
				requiredActions: [
					"Audit each package's lifecycle script for malicious behavior before trusting.",
					"Add `ignore-scripts=true` to `.npmrc` to prevent automatic execution of install scripts.",
					"For required scripts, explicitly allowlist them via `npm pkg set scripts.prepare=...`."
				]
			});

			findings.push(...await checkIgnoreScripts());
		}

		if (missingIntegrityPkgs.length > 0) {
			findings.push({
				id: "DEP_MISSING_INTEGRITY",
				title: `${missingIntegrityPkgs.length} lockfile entries are missing integrity hashes — possible tampering`,
				severity: "HIGH",
				evidence: missingIntegrityPkgs.slice(0, 15),
				requiredActions: [
					"Regenerate the lockfile with `npm install` and commit the result.",
					"Missing `integrity` fields prevent npm from verifying the downloaded package matches the expected content.",
					"Consider using `npm ci` in CI/CD — it fails if the lockfile has missing or mismatched integrity hashes."
				]
			});
		}
	} catch (err) {
		console.warn("[checkTransitiveDependencies] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}

async function checkIgnoreScripts(): Promise<Finding[]> {
	let npmrcContent = "";
	try {
		npmrcContent = await readFile(".npmrc", "utf8");
	} catch {
		// .npmrc absent — treat as missing
	}
	if (/ignore-scripts\s*=\s*true/.test(npmrcContent)) return [];
	return [{
		id: "DEP_IGNORE_SCRIPTS_MISSING",
		title: "`.npmrc` does not set `ignore-scripts=true` — lifecycle scripts run automatically on install",
		severity: "MEDIUM",
		requiredActions: [
			"Add `ignore-scripts=true` to your project's `.npmrc` file.",
			"This prevents malicious postinstall scripts from executing during `npm install`.",
			"Commit `.npmrc` to the repository so CI/CD enforces it consistently."
		]
	}];
}

// ─── Typosquatting / dependency confusion ──────────────────────────────────

// Known typosquat → legitimate package mappings (1-edit-distance variants of top npm packages)
const KNOWN_TYPOSQUATS: Record<string, string> = {
	"lodahs": "lodash",
	"loadsh": "lodash",
	"lodash-": "lodash",
	"expres": "express",
	"expresss": "express",
	"expres-session": "express-session",
	"requets": "request",
	"reqwest": "request",
	"reacts": "react",
	"reactt": "react",
	"react-doms": "react-dom",
	"axois": "axios",
	"axio": "axios",
	"momnet": "moment",
	"momment": "moment",
	"undersocre": "underscore",
	"underscoree": "underscore",
	"babbel": "babel",
	"webpakc": "webpack",
	"webapck": "webpack",
	"eslint-": "eslint",
	"typscript": "typescript",
	"typescrip": "typescript",
	"ts-nod": "ts-node",
	"nod-fetch": "node-fetch",
	"nodefetch": "node-fetch",
	"crossenv": "cross-env",
	"cross-envs": "cross-env",
	"dotenvs": "dotenv",
	"dot-env": "dotenv",
	"jest-": "jest",
	"jests": "jest",
	"chalkk": "chalk",
	"chak": "chalk",
	"commnder": "commander",
	"commanderjs": "commander",
	"yargss": "yargs",
	"uuid-": "uuid",
	"uuidd": "uuid",
	"semverr": "semver",
	"globb": "glob",
	"glo": "glob",
	"mimimatch": "minimatch",
	"minimach": "minimatch",
	"debugg": "debug",
	"debu": "debug",
	"async-": "async",
	"asyncs": "async"
};

// Suspicious version patterns used in dependency confusion / version injection attacks
const SUSPICIOUS_VERSION_RE = /^\^?999\.|^0\.0\.[01]$/;

async function checkTyposquatting(): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		let pkgRaw: string;
		try {
			pkgRaw = await readFile("package.json", "utf8");
		} catch {
			return [];
		}

		const pkg = JSON.parse(pkgRaw) as {
			dependencies?: Record<string, string>;
			devDependencies?: Record<string, string>;
		};

		const allDeps: Record<string, string> = {
			...pkg.dependencies,
			...pkg.devDependencies
		};

		const typosquatHits: string[] = [];
		const suspiciousVersionHits: string[] = [];

		for (const [name, version] of Object.entries(allDeps)) {
			const normalized = name.toLowerCase();

			// Check against known typosquat list
			if (KNOWN_TYPOSQUATS[normalized]) {
				typosquatHits.push(`"${name}" (possible typo of "${KNOWN_TYPOSQUATS[normalized]}")`);
			}

			// Check for suspicious version numbers used in dependency confusion attacks
			if (SUSPICIOUS_VERSION_RE.test(version) && name.length < 8) {
				suspiciousVersionHits.push(`"${name}@${version}"`);
			}
		}

		if (typosquatHits.length > 0) {
			findings.push({
				id: "DEP_TYPOSQUAT",
				title: `Possible typosquatted package name(s) detected in dependencies`,
				severity: "CRITICAL",
				evidence: typosquatHits.slice(0, 10),
				requiredActions: [
					"Verify each flagged package is the intended dependency — typosquatting replaces legitimate packages with malicious ones.",
					"Remove the package, run `npm install` with the correctly-spelled name, and audit `package-lock.json`.",
					"Use `npm audit` and review the package on npmjs.com before reinstalling."
				]
			});
		}

		if (suspiciousVersionHits.length > 0) {
			findings.push({
				id: "DEP_SUSPICIOUS_VERSION",
				title: "Dependencies with suspicious version numbers — possible dependency confusion attack",
				severity: "HIGH",
				evidence: suspiciousVersionHits.slice(0, 10),
				requiredActions: [
					"Packages with version `999.*` or `0.0.0`/`0.0.1` on short names are a common dependency confusion attack signal.",
					"Verify these packages are legitimate using `npm view <package>` and inspect the publish history.",
					"Use a private registry with an allowlist of approved packages (Artifactory, Verdaccio, GitHub Packages)."
				]
			});
		}
	} catch (err) {
		console.warn("[checkTyposquatting] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
