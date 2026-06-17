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

// Known public registry scopes — scoped packages under these are NOT private
const KNOWN_PUBLIC_SCOPES = new Set([
	"@types", "@babel", "@testing-library", "@jest", "@storybook", "@emotion",
	"@mui", "@angular", "@vue", "@svelte", "@nestjs", "@aws-sdk", "@google-cloud",
	"@azure", "@microsoft", "@graphql-codegen", "@typescript-eslint", "@eslint",
	"@rollup", "@vitejs", "@vitest", "@remix-run", "@next", "@vercel", "@sentry",
	"@opentelemetry", "@prisma", "@trpc", "@tanstack", "@radix-ui", "@headlessui",
	"@tailwindcss", "@postcss", "@node-red", "@npmcli"
]);

async function checkDependencyConfusion(): Promise<Finding[]> {
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

		// Read .npmrc for private registry scope routing
		let npmrcContent = "";
		try {
			npmrcContent = await readFile(".npmrc", "utf8");
		} catch {
			// .npmrc absent
		}

		const unprotectedScopes: string[] = [];
		for (const name of Object.keys(allDeps)) {
			if (!name.startsWith("@")) continue;
			const scope = name.split("/")[0]; // e.g. "@mycompany"
			if (!scope) continue;
			if (KNOWN_PUBLIC_SCOPES.has(scope)) continue;

			// Check if .npmrc has a registry entry for this scope
			// e.g. @mycompany:registry=https://npm.mycompany.com
			const escapedScope = scope.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
			const scopeRegistryRe = new RegExp(`${escapedScope}\\s*:.*registry\\s*=|registry\\s*=.*${escapedScope}`, "i");
			if (!scopeRegistryRe.test(npmrcContent)) {
				unprotectedScopes.push(`${name} (scope ${scope} has no private registry entry in .npmrc)`);
			}
		}

		// Also check for common typosquat vectors against critical ecosystem packages
		const EXTENDED_TYPOSQUATS: Record<string, string> = {
			"prism": "prisma",
			"prismaa": "prisma",
			"nextjs": "next",
			"nextt": "next",
			"nuxt3": "nuxt",
			"vue3": "vue",
			"sveltejs": "svelte",
			"mongoosejs": "mongoose",
			"sequelizejs": "sequelize",
			"passportjs": "passport",
			"jsonwebtoken-": "jsonwebtoken",
			"bcryptjs-": "bcrypt",
			"multerjs": "multer",
			"axiosjs": "axios",
			"socketio": "socket.io",
			"redisjs": "redis",
			"mysql-2": "mysql2",
			"pgg": "pg",
			"typeormjs": "typeorm",
			"expressjs": "express",
			"fastifyjs": "fastify",
			"helmetjs": "helmet",
			"corsjs": "cors"
		};

		const extendedHits: string[] = [];
		for (const [name] of Object.entries(allDeps)) {
			const normalized = name.toLowerCase();
			if (EXTENDED_TYPOSQUATS[normalized]) {
				extendedHits.push(`"${name}" (possible typo of "${EXTENDED_TYPOSQUATS[normalized]}")`);
			}
		}

		if (unprotectedScopes.length > 0) {
			findings.push({
				id: "DEPENDENCY_CONFUSION_RISK",
				title: `${unprotectedScopes.length} scoped package(s) lack a private registry entry in .npmrc — dependency confusion risk`,
				severity: "HIGH",
				evidence: unprotectedScopes.slice(0, 10),
				requiredActions: [
					"Scoped packages without a private registry mapping in .npmrc will resolve from the public npm registry, enabling dependency confusion attacks.",
					"ATT&CK T1195.002 — an attacker can publish a higher-versioned package to the public registry under your private scope name.",
					"Fix: add to .npmrc: @yourscope:registry=https://your-private-registry.example.com"
				]
			});
		}

		if (extendedHits.length > 0) {
			findings.push({
				id: "DEP_TYPOSQUAT_EXTENDED",
				title: "Possible typosquatted ecosystem package name(s) detected",
				severity: "CRITICAL",
				evidence: extendedHits.slice(0, 10),
				requiredActions: [
					"Verify each flagged package is the intended dependency — typosquatting replaces legitimate packages with malicious ones.",
					"Remove the package, run `npm install` with the correctly-spelled name, and audit `package-lock.json`.",
					"Use `npm audit` and review the package on npmjs.com before reinstalling."
				]
			});
		}
	} catch (err) {
		console.warn("[checkDependencyConfusion] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}

// Malicious lifecycle script patterns
const MALICIOUS_SCRIPT_RES = [
	/curl\s+[^\s]+\s*\|\s*(?:sh|bash)/,
	/wget\s+[^\s]+\s*\|\s*(?:sh|bash)/,
	/node\s+-e\s+['"`]\s*(?:eval|require|exec|spawn)/,
	/base64\s+--decode\s*\|\s*(?:sh|bash)/,
	/python\s+-c\s+['"`]\s*(?:import os|exec|eval)/,
];

function isScriptMalicious(scriptValue: string): boolean {
	return MALICIOUS_SCRIPT_RES.some((re) => re.test(scriptValue));
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

		// 2. OpenSSF Scorecard — check all prod deps and CI-executed dev deps, up to 20 total
		try {
			const pkgRaw = await readFile("package.json", "utf8");
			const pkg = JSON.parse(pkgRaw) as {
				dependencies?: Record<string, string>;
				devDependencies?: Record<string, string>;
				scripts?: Record<string, string>;
			};

			const prodDeps = Object.keys(pkg.dependencies ?? {});

			// Determine which devDependencies are executed in CI scripts
			const scriptText = Object.values(pkg.scripts ?? {}).join(" ");
			const devDepsUsedInScripts = Object.keys(pkg.devDependencies ?? {}).filter(
				(dep) => {
					// Check if the dep name (or its binary form) is referenced in any script
					const shortName = dep.replace(/^@[^/]+\//, "").replace(/-/g, "[-_]?");
					try {
						return new RegExp(shortName, "i").test(scriptText);
					} catch {
						return false;
					}
				}
			);

			// Merge: prod deps first, then CI-executed dev deps, up to 20.
			// CWE-200: never transmit private/internal package names to public
			// endpoints (registry.npmjs.org / securityscorecards.dev). Skip any
			// scoped package whose scope is not a known-public scope.
			const depsToCheck = [...new Set([...prodDeps, ...devDepsUsedInScripts])]
				.filter((dep) => {
					const scope = dep.startsWith("@") ? dep.split("/")[0] : null;
					return scope === null || KNOWN_PUBLIC_SCOPES.has(scope);
				})
				.slice(0, 20);
			const totalAllDeps = prodDeps.length + Object.keys(pkg.devDependencies ?? {}).length;

			// CWE-200: allow operators of private repos to disable all third-party
			// network egress (scorecard/EPSS/registry lookups) with SECURITY_OFFLINE.
			const offline = process.env["SECURITY_OFFLINE"] === "1" || process.env["SECURITY_OFFLINE"] === "true";

			for (const dep of (offline ? [] : depsToCheck)) {
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

			// Report partial coverage when total deps exceed the cap
			if (totalAllDeps > 20) {
				findings.push({
					id: "SUPPLY_CHAIN_SCORECARD_PARTIAL",
					title: `OpenSSF Scorecard checked ${depsToCheck.length} of ${totalAllDeps} total dependencies — coverage is partial`,
					severity: "LOW",
					evidence: [`Checked: ${depsToCheck.length} deps. Unchecked: ${totalAllDeps - depsToCheck.length} deps.`],
					requiredActions: [
						`${totalAllDeps - depsToCheck.length} dependencies were not checked against OpenSSF Scorecard due to the 20-dep cap.`,
						"Run `npx ossf-scorecard` or review https://scorecard.dev for full coverage.",
						"Consider using socket.dev or Snyk for continuous supply chain monitoring across all dependencies."
					]
				});
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

	const depConfusion = await checkDependencyConfusion();
	findings.push(...depConfusion);

	const threatIntel = await checkCveExploitation();
	findings.push(...threatIntel);

	const goSum = await checkGoSumMissing();
	findings.push(...goSum);

	const cargoLock = await checkCargoLockMissing();
	findings.push(...cargoLock);

	const lockfileSync = await checkLockfileSync();
	findings.push(...lockfileSync);

	const maintainerRisk = await checkMaintainerRisk();
	findings.push(...maintainerRisk);

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
	maliciousScriptPkgs: string[];
} {
	const scriptPkgs: string[] = [];
	const missingIntegrityPkgs: string[] = [];
	const maliciousScriptPkgs: string[] = [];

	for (const [name, pkg] of Object.entries(packages)) {
		if (!name) continue; // skip root entry
		const pkgName = name.replace(/^node_modules\//, "");
		if (hasLifecycleScript(pkg)) {
			scriptPkgs.push(pkgName);

			// Check each lifecycle script VALUE for malicious patterns
			for (const scriptKey of LIFECYCLE_SCRIPTS) {
				const scriptVal = pkg.scripts?.[scriptKey];
				if (scriptVal && isScriptMalicious(scriptVal)) {
					maliciousScriptPkgs.push(`${pkgName} [${scriptKey}]: ${scriptVal.slice(0, 120)}`);
				}
			}
		}
		if (pkg.version && !pkg.integrity) missingIntegrityPkgs.push(pkgName);
	}

	return { scriptPkgs, missingIntegrityPkgs, maliciousScriptPkgs };
}

/**
 * Scan yarn.lock content for lifecycle script values using a regex-based approach
 * (yarn.lock is a custom format, not JSON/YAML, so we use heuristic line scanning).
 * We look for `postinstall`, `preinstall`, or `install` key lines followed by a value
 * in the same stanza, and check the value for malicious patterns.
 */
function scanYarnLockForMaliciousScripts(content: string): { maliciousScriptPkgs: string[]; scriptPkgs: string[] } {
	const maliciousScriptPkgs: string[] = [];
	const scriptPkgs: string[] = [];
	const lines = content.split("\n");
	let currentPkg = "";
	for (const line of lines) {
		// New stanza starts with a non-space character that ends with a colon (package header)
		const pkgHeader = /^"?([^"#\s][^:]*)(?:@[^:]+)?":?\s*$/.exec(line);
		if (pkgHeader) {
			currentPkg = pkgHeader[1].trim();
			continue;
		}
		// Lifecycle script lines inside a stanza look like:  postinstall "cmd"
		const scriptLine = /^\s+(postinstall|preinstall|install)\s+"([^"]+)"/.exec(line);
		if (scriptLine && currentPkg) {
			const scriptKey = scriptLine[1];
			const scriptVal = scriptLine[2];
			scriptPkgs.push(`${currentPkg} [${scriptKey}]`);
			if (isScriptMalicious(scriptVal)) {
				maliciousScriptPkgs.push(`${currentPkg} [${scriptKey}]: ${scriptVal.slice(0, 120)}`);
			}
		}
	}
	return { maliciousScriptPkgs, scriptPkgs };
}

/**
 * Scan pnpm-lock.yaml content for lifecycle script values.
 * pnpm-lock.yaml stores scripts in `requiresBuild: true` stanzas; the actual
 * script content is in node_modules (not the lockfile itself). We flag any
 * package that sets `requiresBuild: true` as having a lifecycle script,
 * and also scan for inline `scripts:` blocks using a heuristic regex.
 */
function scanPnpmLockForMaliciousScripts(content: string): { maliciousScriptPkgs: string[]; scriptPkgs: string[] } {
	const maliciousScriptPkgs: string[] = [];
	const scriptPkgs: string[] = [];
	const lines = content.split("\n");
	let currentPkg = "";
	for (const line of lines) {
		// pnpm-lock.yaml package stanza: starts with exactly 2-space indent + "/" or name
		const pkgHeader = /^ {2}\/?([^\s:][^:]+):$/.exec(line);
		if (pkgHeader) {
			currentPkg = pkgHeader[1].trim();
			continue;
		}
		// requiresBuild: true means the package has a lifecycle script
		if (/^\s+requiresBuild:\s*true/.test(line) && currentPkg) {
			scriptPkgs.push(currentPkg);
		}
		// Inline script value (rare in pnpm-lock but possible in older format)
		const scriptLine = /^\s+(?:postinstall|preinstall|install):\s+"?([^"]+)"?/.exec(line);
		if (scriptLine && currentPkg) {
			const scriptVal = scriptLine[1];
			if (isScriptMalicious(scriptVal)) {
				maliciousScriptPkgs.push(`${currentPkg}: ${scriptVal.slice(0, 120)}`);
			}
		}
	}
	return { maliciousScriptPkgs, scriptPkgs };
}

async function checkTransitiveDependencies(): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		// Try package-lock.json first (npm), then yarn.lock, then pnpm-lock.yaml.
		// Each lockfile type has different structure; we use format-specific parsers.
		let scriptPkgs: string[] = [];
		let missingIntegrityPkgs: string[] = [];
		let maliciousScriptPkgs: string[] = [];
		let lockfileFound = false;

		// ── npm package-lock.json ──────────────────────────────────────────────
		try {
			const lockRaw = await readFile("package-lock.json", "utf8");
			let lock: { packages?: Record<string, LockfilePackage> };
			try {
				lock = JSON.parse(lockRaw) as { packages?: Record<string, LockfilePackage> };
				const result = scanLockfilePackages(lock.packages ?? {});
				scriptPkgs = result.scriptPkgs;
				missingIntegrityPkgs = result.missingIntegrityPkgs;
				maliciousScriptPkgs = result.maliciousScriptPkgs;
				lockfileFound = true;
			} catch {
				// JSON parse failure — skip
			}
		} catch {
			// package-lock.json not present — try alternatives
		}

		// ── yarn.lock ──────────────────────────────────────────────────────────
		if (!lockfileFound) {
			try {
				const yarnRaw = await readFile("yarn.lock", "utf8");
				const result = scanYarnLockForMaliciousScripts(yarnRaw);
				scriptPkgs = result.scriptPkgs;
				maliciousScriptPkgs = result.maliciousScriptPkgs;
				lockfileFound = true;
				// yarn.lock does not encode integrity per entry the same way; skip integrity check
			} catch {
				// yarn.lock not present
			}
		}

		// ── pnpm-lock.yaml ─────────────────────────────────────────────────────
		if (!lockfileFound) {
			try {
				const pnpmRaw = await readFile("pnpm-lock.yaml", "utf8");
				const result = scanPnpmLockForMaliciousScripts(pnpmRaw);
				scriptPkgs = result.scriptPkgs;
				maliciousScriptPkgs = result.maliciousScriptPkgs;
				lockfileFound = true;
			} catch {
				// pnpm-lock.yaml not present
			}
		}

		if (!lockfileFound) {
			return findings;
		}

		// Report malicious script patterns first — CRITICAL severity
		if (maliciousScriptPkgs.length > 0) {
			findings.push({
				id: "DEPENDENCY_MALICIOUS_SCRIPT",
				title: `${maliciousScriptPkgs.length} transitive dependency lifecycle script(s) contain malicious execution patterns`,
				severity: "CRITICAL",
				evidence: maliciousScriptPkgs.slice(0, 10),
				requiredActions: [
					"A transitive dependency has a lifecycle script matching known malicious patterns (download-and-execute, inline eval, base64 decode).",
					"CWE-494 / ATT&CK T1195.002 — malicious postinstall scripts run automatically on every npm install.",
					"Remove or replace these dependencies immediately. Treat the development environment as potentially compromised and rotate all secrets."
				]
			});
		}

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
	"asyncs": "async",
	// Extended ecosystem packages
	"prism": "prisma",
	"prismaa": "prisma",
	"nextjs": "next",
	"nextt": "next",
	"nuxt3": "nuxt",
	"vue3": "vue",
	"sveltejs": "svelte",
	"mongoosejs": "mongoose",
	"sequelizejs": "sequelize",
	"passportjs": "passport",
	"jsonwebtoken-": "jsonwebtoken",
	"bcryptjs-": "bcrypt",
	"multerjs": "multer",
	"axiosjs": "axios",
	"socketio": "socket.io",
	"redisjs": "redis",
	"mysql-2": "mysql2",
	"pgg": "pg",
	"typeormjs": "typeorm",
	"expressjs": "express",
	"fastifyjs": "fastify",
	"helmetjs": "helmet",
	"corsjs": "cors"
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

// ─── Go module integrity ────────────────────────────────────────────────────

async function checkGoSumMissing(): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const goModFiles = await fg(["**/go.mod"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/dist/**", "**/.git/**"]
		});

		const missing: string[] = [];

		for (const goModPath of goModFiles) {
			const dir = goModPath.replace(/\/go\.mod$/, "") || ".";
			const goSumPath = dir === "." ? "go.sum" : `${dir}/go.sum`;
			try {
				const content = await readFileSafe(goSumPath);
				if (!content) {
					missing.push(goModPath);
				}
			} catch {
				missing.push(goModPath);
			}
		}

		if (missing.length > 0) {
			findings.push({
				id: "GO_SUM_MISSING",
				title: `${missing.length} go.mod file(s) present without a corresponding go.sum — Go module integrity unverified`,
				severity: "HIGH",
				evidence: missing.slice(0, 10),
				requiredActions: [
					"go.mod present without go.sum — Go module integrity unverified, compromised proxy can serve any content (ATT&CK T1195.001)",
					"Run `go mod tidy` to generate go.sum, then commit it alongside go.mod.",
					"Without go.sum, the Go toolchain cannot verify cryptographic hashes of downloaded modules."
				]
			});
		}
	} catch (err) {
		console.warn("[checkGoSumMissing] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}

// ─── Cargo lock integrity ───────────────────────────────────────────────────

function isBinaryCrate(tomlContent: string): boolean {
	const hasBinSection = /^\[\[bin\]\]/m.test(tomlContent);
	const hasLibSection = /^\[lib\]/m.test(tomlContent);
	const hasPackageSection = /^\[package\]/m.test(tomlContent);
	return hasBinSection || (hasPackageSection && !hasLibSection);
}

async function cargoLockMissingForToml(cargoTomlPath: string): Promise<boolean> {
	let tomlContent = "";
	try {
		tomlContent = await readFileSafe(cargoTomlPath);
	} catch {
		return false;
	}
	if (!tomlContent || !isBinaryCrate(tomlContent)) return false;

	const dir = cargoTomlPath.replace(/\/Cargo\.toml$/, "") || ".";
	const cargoLockPath = dir === "." ? "Cargo.lock" : `${dir}/Cargo.lock`;
	try {
		const lockContent = await readFileSafe(cargoLockPath);
		return !lockContent;
	} catch {
		return true;
	}
}

async function checkCargoLockMissing(): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const cargoTomlFiles = await fg(["**/Cargo.toml"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/dist/**", "**/.git/**"]
		});

		const results = await Promise.all(cargoTomlFiles.map(async (p) => ({ path: p, missing: await cargoLockMissingForToml(p) })));
		const missing = results.filter((r) => r.missing).map((r) => r.path);

		if (missing.length > 0) {
			findings.push({
				id: "CARGO_LOCK_MISSING",
				title: `${missing.length} Cargo.toml binary crate(s) present without Cargo.lock — Rust dependency resolution unverified`,
				severity: "MEDIUM",
				evidence: missing.slice(0, 10),
				requiredActions: [
					"Cargo.toml without Cargo.lock — Rust binary crate dependency resolution unverified (ATT&CK T1195.001)",
					"Run `cargo generate-lockfile` to create Cargo.lock and commit it to version control.",
					"Cargo.lock ensures reproducible builds and prevents silent dependency upgrades."
				]
			});
		}
	} catch (err) {
		console.warn("[checkCargoLockMissing] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}

// ─── Lockfile sync check ────────────────────────────────────────────────────

function parsePkgDeps(content: string): Record<string, string> | null {
	try {
		const pkg = JSON.parse(content) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
		return { ...pkg.dependencies, ...pkg.devDependencies };
	} catch {
		return null;
	}
}

function parseLockPackages(content: string): Record<string, unknown> | null {
	try {
		const lock = JSON.parse(content) as { packages?: Record<string, unknown> };
		return lock.packages ?? {};
	} catch {
		return null;
	}
}

function findOutOfSyncDeps(allDeps: Record<string, string>, lockPackages: Record<string, unknown>): string[] {
	const outOfSync: string[] = [];
	for (const depName of Object.keys(allDeps)) {
		// package-lock.json v2/v3 stores entries as "node_modules/<name>"
		const key = `node_modules/${depName}`;
		if (!(key in lockPackages) && !(depName in lockPackages)) {
			outOfSync.push(depName);
		}
	}
	return outOfSync;
}

async function checkLockfileSyncForPkg(pkgPath: string): Promise<string[]> {
	const dir = pkgPath.replace(/\/package\.json$/, "") || ".";
	const lockPath = dir === "." ? "package-lock.json" : `${dir}/package-lock.json`;

	let pkgContent = "";
	try {
		pkgContent = await readFileSafe(pkgPath);
	} catch {
		return [];
	}
	if (!pkgContent) return [];

	const allDeps = parsePkgDeps(pkgContent);
	if (!allDeps || Object.keys(allDeps).length === 0) return [];

	let lockContent = "";
	try {
		lockContent = await readFileSafe(lockPath);
	} catch {
		return [];
	}
	if (!lockContent) return [];

	const lockPackages = parseLockPackages(lockContent);
	if (!lockPackages) return [];

	return findOutOfSyncDeps(allDeps, lockPackages);
}

async function checkLockfileSync(): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const pkgFiles = await fg(["**/package.json"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/dist/**", "**/.git/**"]
		});

		for (const pkgPath of pkgFiles) {
			const outOfSync = await checkLockfileSyncForPkg(pkgPath);
			if (outOfSync.length > 0) {
				findings.push({
					id: "LOCKFILE_OUT_OF_SYNC",
					title: `${pkgPath}: ${outOfSync.length} dependency(ies) in package.json not present in package-lock.json`,
					severity: "HIGH",
					evidence: outOfSync.slice(0, 15),
					requiredActions: [
						"package.json has dependencies not present in package-lock.json — lockfile out of sync (ATT&CK T1195.001)",
						"Run `npm install` to regenerate package-lock.json and commit the updated lockfile.",
						"Use `npm ci` in CI/CD pipelines — it fails if package-lock.json is out of sync with package.json."
					]
				});
			}
		}
	} catch (err) {
		console.warn("[checkLockfileSync] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}

// ─── Known supply-chain incident packages ──────────────────────────────────

const KNOWN_INCIDENT_PACKAGES = new Set([
	"node-ipc",
	"event-stream",
	"ua-parser-js",
	"faker",
	"colors",
	"left-pad"
]);

function flaggedIncidentDeps(allDeps: Record<string, string>): string[] {
	return Object.keys(allDeps).filter((name) => KNOWN_INCIDENT_PACKAGES.has(name));
}

async function maintainerRiskForPkg(pkgPath: string): Promise<string[]> {
	let pkgContent = "";
	try {
		pkgContent = await readFileSafe(pkgPath);
	} catch {
		return [];
	}
	if (!pkgContent) return [];

	const allDeps = parsePkgDeps(pkgContent);
	if (!allDeps) return [];

	return flaggedIncidentDeps(allDeps);
}

async function checkMaintainerRisk(): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const pkgFiles = await fg(["**/package.json"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/dist/**", "**/.git/**"]
		});

		for (const pkgPath of pkgFiles) {
			const flagged = await maintainerRiskForPkg(pkgPath);
			if (flagged.length > 0) {
				findings.push({
					id: "DEP_MAINTAINER_RISK",
					title: `${pkgPath}: ${flagged.length} dependency(ies) with known supply-chain incident history detected`,
					severity: "MEDIUM",
					evidence: flagged.slice(0, 10),
					requiredActions: [
						"Dependency with known supply-chain incident history detected — review and pin to safe version (ATT&CK T1195.001)",
						"Audit each flagged package: verify the current maintainer, review recent publish history on npmjs.com, and pin to a specific safe version.",
						"Consider replacing abandoned or historically-compromised packages with actively-maintained alternatives."
					]
				});
			}
		}
	} catch (err) {
		console.warn("[checkMaintainerRisk] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
