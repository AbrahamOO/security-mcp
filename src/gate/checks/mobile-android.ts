import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

export async function checkMobileAndroid(_: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	const manifests = await fg(["**/AndroidManifest.xml"], { dot: true, ignore: ["**/node_modules/**"] });
	for (const m of manifests) {
		const xml = await readFileSafe(m).catch(() => "");
		const lower = xml.toLowerCase();

		if (lower.includes('android:debuggable="true"')) {
			findings.push({
				id: "ANDROID_DEBUGGABLE",
				title: "Android app is debuggable in manifest",
				severity: "CRITICAL",
				files: [m],
				requiredActions: [
					"Remove android:debuggable=\"true\" for release builds.",
					"Ensure signing configs and build variants enforce non-debuggable release artifacts."
				]
			});
		}

		if (lower.includes('android:usescleartexttraffic="true"')) {
			findings.push({
				id: "ANDROID_CLEARTEXT",
				title: "Android cleartext traffic allowed",
				severity: "CRITICAL",
				files: [m],
				requiredActions: [
					"Disable cleartext traffic. Enforce TLS 1.3.",
					"Use Network Security Config with strict domain allowlists if exceptions are required."
				]
			});
		}
	}

	return findings;
}
