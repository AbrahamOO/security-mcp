/**
 * GitHub Actions CI/CD pipeline hardening checks.
 * Covers supply chain attack vectors specific to GitHub Actions workflows.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

export async function runCiPipelineChecks(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const workflowFiles = await fg([".github/workflows/*.yml", ".github/workflows/*.yaml"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/.git/**"]
		});

		if (workflowFiles.length === 0) {
			return [];
		}

		const unpinnedFiles: string[] = [];
		const pwnTargetFiles: string[] = [];
		const secretEchoFiles: string[] = [];
		const noPermissionsFiles: string[] = [];
		const selfHostedFiles: string[] = [];

		for (const file of workflowFiles) {
			let content: string;
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}

			// Check 1: Third-party actions not pinned to a full 40-char SHA
			// Matches `uses: owner/repo@tag` but NOT `uses: owner/repo@<40hex chars>`
			// Also skip `uses: ./.github/actions/` (local actions are fine)
			const actionLines = content.split("\n").filter((line) => /uses:\s+[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+@/.test(line));
			const unpinnedActions = actionLines.filter((line) => {
				// Skip local actions
				if (/uses:\s+\.\//.test(line)) return false;
				// Flag anything not pinned to a 40-char hex SHA
				return !/uses:\s+[a-zA-Z0-9_.\-/]+@[0-9a-f]{40}/.test(line);
			});
			if (unpinnedActions.length > 0) {
				unpinnedFiles.push(file);
			}

			// Check 2: pull_request_target + dynamic ref usage (pwn-request vector)
			// Attacker controls the ref/sha when a PR from a fork triggers pull_request_target
			if (
				/pull_request_target/.test(content) &&
				/\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}/.test(content)
			) {
				pwnTargetFiles.push(file);
			}

			// Check 3: Secrets printed to logs via echo
			if (/echo\s+\$\{\{\s*secrets\./.test(content)) {
				secretEchoFiles.push(file);
			}

			// Check 4: No top-level permissions block
			// Without explicit permissions, the default is write access to all scopes
			if (!/^permissions:/m.test(content)) {
				noPermissionsFiles.push(file);
			}

			// Check 5: Self-hosted runners (broader attack surface — runner compromise = code execution)
			if (/runs-on:\s+self-hosted/.test(content)) {
				selfHostedFiles.push(file);
			}
		}

		if (unpinnedFiles.length > 0) {
			findings.push({
				id: "CI_UNPINNED_ACTION",
				title: "GitHub Actions using mutable tags instead of pinned SHA digests",
				severity: "HIGH",
				files: unpinnedFiles.slice(0, 10),
				requiredActions: [
					"Pin all third-party actions to a full 40-character commit SHA (e.g. `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`).",
					"Mutable tags like @v3 can be silently redirected to malicious commits — SHA pinning prevents supply chain substitution.",
					"Use a tool like `pin-github-action` or Dependabot to automate SHA pinning."
				]
			});
		}

		if (pwnTargetFiles.length > 0) {
			findings.push({
				id: "CI_PWNTARGET_SHA",
				title: "pull_request_target workflow uses attacker-controlled ref/SHA — pwn-request vector",
				severity: "CRITICAL",
				files: pwnTargetFiles.slice(0, 10),
				requiredActions: [
					"Never use `${{ github.event.pull_request.head.sha }}` or `head.ref` inside a `pull_request_target` workflow that checks out or runs code from the PR.",
					"`pull_request_target` runs with write permissions and secrets access; the PR head is attacker-controlled.",
					"Use `pull_request` (not `pull_request_target`) for code that executes untrusted contributions, or add explicit guard conditions."
				]
			});
		}

		if (secretEchoFiles.length > 0) {
			findings.push({
				id: "CI_SECRET_ECHO",
				title: "GitHub Actions workflow echoes secrets to logs",
				severity: "CRITICAL",
				files: secretEchoFiles.slice(0, 10),
				requiredActions: [
					"Remove any `echo ${{ secrets.* }}` statements — secrets printed to logs are visible to anyone with read access to the repository.",
					"GitHub masks known secret values in logs, but this is not reliable for all encodings.",
					"Pass secrets via environment variables (`env: MY_SECRET: ${{ secrets.MY_SECRET }}`) and read them in code, never echo them."
				]
			});
		}

		if (noPermissionsFiles.length > 0) {
			findings.push({
				id: "CI_NO_PERMISSIONS",
				title: "GitHub Actions workflows without explicit permissions block",
				severity: "MEDIUM",
				files: noPermissionsFiles.slice(0, 10),
				requiredActions: [
					"Add an explicit `permissions:` block at the top of each workflow (or at the job level) to grant only the minimum required scopes.",
					"Without explicit permissions, the default is determined by org/repo settings — often write-all.",
					"Example minimal read-only: `permissions: { contents: read }`."
				]
			});
		}

		if (selfHostedFiles.length > 0) {
			findings.push({
				id: "CI_SELF_HOSTED_RUNNER",
				title: "GitHub Actions using self-hosted runners",
				severity: "MEDIUM",
				files: selfHostedFiles.slice(0, 10),
				requiredActions: [
					"Self-hosted runners executing untrusted fork PRs can be compromised — restrict `pull_request` triggers on self-hosted runner workflows.",
					"Ensure self-hosted runners are ephemeral (destroyed after each job) and isolated from production networks.",
					"Use GitHub-hosted runners for public repositories or untrusted code paths."
				]
			});
		}
	} catch (err) {
		console.warn("[runCiPipelineChecks] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
