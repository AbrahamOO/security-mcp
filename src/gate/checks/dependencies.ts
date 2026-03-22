import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";

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
				env: process.env
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
		console.warn("[checkNpmProvenance] Internal error:", err instanceof Error ? err.message : String(err));
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

	return findings;
}
