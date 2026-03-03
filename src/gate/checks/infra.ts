import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";

export async function checkInfra(_: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	const secretManagerRefs = await searchRepo({
		query: "secretmanager|Secret Manager|google_secret_manager",
		isRegex: true,
		maxMatches: 200
	});
	if (secretManagerRefs.length === 0) {
		findings.push({
			id: "SECRET_MANAGER_NOT_DETECTED",
			title: "GCP Secret Manager usage not detected in infra/app config",
			severity: "HIGH",
			requiredActions: [
				"Store secrets only in GCP Secret Manager.",
				"Configure workload identity / service accounts to access secrets, never plaintext env in repo."
			]
		});
	}

	const publicIngress = await searchRepo({
		query: String.raw`0\.0\.0\.0/0|::/0|public\s*=\s*true|allowAll|allUsers`,
		isRegex: true,
		maxMatches: 200
	});
	if (publicIngress.length > 0) {
		findings.push({
			id: "PUBLIC_EXPOSURE_RISK",
			title: "Potential public exposure patterns detected in IaC/config",
			severity: "HIGH",
			evidence: publicIngress.slice(0, 20).map((m) => `${m.file}:${m.line}:${m.preview}`),
			requiredActions: [
				"Remove or justify public ingress. Enforce Zero Trust. No implicit trust for any request or service call.",
				"Use private services, IAM-based auth, and least-privileged firewall rules."
			]
		});
	}

	return findings;
}
