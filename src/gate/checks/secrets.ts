import { execa } from "execa";
import { Finding } from "../result.js";

export async function checkSecrets(_: { changedFiles: string[] }): Promise<Finding[]> {
	// CI will also run gitleaks. This is a fast local heuristic backup.
	const findings: Finding[] = [];
	const patterns = [
		"-----BEGIN PRIVATE KEY-----",
		"AKIA", // AWS
		"AIza", // Google API key prefix
		"xoxb-", // Slack bot token
		"sk-", // common LLM key prefix
		"SECRET_KEY",
		"PRIVATE_KEY"
	];

	const { stdout } = await execa(
		"git",
		["grep", "-n", "--untracked", "--no-index", "-I", "-e", patterns.join("|"), "."],
		{
			reject: false
		}
	);

	if (stdout.trim()) {
		findings.push({
			id: "POSSIBLE_SECRET",
			title: "Potential secret material detected by heuristic scan",
			severity: "CRITICAL",
			evidence: stdout.split("\n").slice(0, 50),
			requiredActions: [
				"Remove secrets from repo immediately.",
				"Rotate any exposed credentials.",
				"Store secrets only in GCP Secret Manager. Do not log secrets."
			]
		});
	}

	return findings;
}
