import { execa } from "execa";
import { Finding } from "../result.js";

export async function checkSecrets(_: { changedFiles: string[] }): Promise<Finding[]> {
	// CI will also run gitleaks. This is a fast local heuristic backup.
	const findings: Finding[] = [];
	const patterns = [
		"-----BEGIN PRIVATE KEY-----",
		"AKIA",    // AWS access key prefix
		"AIza",    // Google API key prefix
		"xoxb-",   // Slack bot token
		"sk-",     // common LLM key prefix (OpenAI etc.)
		"SECRET_KEY",
		"PRIVATE_KEY"
	];

	// Each pattern must be passed as a separate -e flag.
	// Joining with | and using a single -e flag relies on ERE alternation, but
	// git grep defaults to BRE where | is a literal character, not alternation —
	// causing all patterns to be silently missed (false-negative). CWE-688.
	const eFlags = patterns.flatMap((p) => ["-e", p]);

	const { stdout } = await execa(
		"git",
		// --no-index: search working tree without git index (covers untracked files)
		// -l: list files with matches (reduce noise); -n: show line numbers
		// -I: skip binary files
		["grep", "-n", "--no-index", "-I", ...eFlags, "."],
		{ reject: false }
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
