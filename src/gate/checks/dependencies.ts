import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

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

	return findings;
}
