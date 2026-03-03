import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

export async function checkMobileIos(_: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];
	const plists = await fg(["**/Info.plist"], { dot: true, ignore: ["**/node_modules/**"] });

	for (const p of plists) {
		const text = await readFileSafe(p).catch(() => "");
		const lower = text.toLowerCase();

		if (lower.includes("nsallowsarbitraryloads") || lower.includes("allowsarbitraryloads")) {
			findings.push({
				id: "IOS_ATS_WEAK",
				title: "iOS ATS appears weakened (NSAllowsArbitraryLoads)",
				severity: "CRITICAL",
				files: [p],
				requiredActions: [
					"Remove NSAllowsArbitraryLoads. Enforce TLS 1.3. Restrict exceptions to specific domains with justification.",
					"Enable certificate pinning for high-risk APIs where appropriate."
				]
			});
		}
	}

	return findings;
}
