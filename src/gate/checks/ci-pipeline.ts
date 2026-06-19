/**
 * GitHub Actions CI/CD pipeline hardening checks.
 * Covers supply chain attack vectors specific to GitHub Actions workflows.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";

// Pattern that identifies an active (non-commented) security gate invocation line.
const GATE_INVOCATION_RE = /npm run ci:pr-gate|npx security-mcp|security-mcp.*gate|security_gate|run_pr_gate/;

async function checkGateStepPresent(changedFiles: string[]): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const workflowFiles = await fg([".github/workflows/*.yml", ".github/workflows/*.yaml"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/.git/**"]
		});

		if (workflowFiles.length === 0) {
			return findings;
		}

		let gateInvokedFile: string | null = null;
		let gateDisabledFile: string | null = null;

		for (const file of workflowFiles) {
			let content: string;
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}

			const lines = content.split("\n");

			// Check whether the file contains the gate invocation at all (commented or not)
			const hasGatePattern = lines.some((line) => GATE_INVOCATION_RE.test(line));
			if (!hasGatePattern) continue;

			// Distinguish active invocation from commented-out invocation
			const activeLines = lines.filter(
				(line) => GATE_INVOCATION_RE.test(line) && !/^\s*#/.test(line)
			);
			if (activeLines.length > 0) {
				gateInvokedFile = file;
			} else {
				// Pattern present but every matching line is commented out
				gateDisabledFile = file;
			}
		}

		if (!gateInvokedFile && !gateDisabledFile) {
			findings.push({
				id: "GATE_STEP_ABSENT",
				title: "No GitHub Actions workflow found that invokes the security gate",
				severity: "HIGH",
				files: [],
				requiredActions: [
					"No GitHub Actions workflow found that invokes the security gate (npm run ci:pr-gate). The gate may not be enforced on PRs.",
					"Add a step `run: npm run ci:pr-gate` to your PR workflow (e.g. .github/workflows/security-gate.yml).",
					"Without this step, HIGH/CRITICAL security findings will not block pull request merges."
				]
			});
		}

		if (gateDisabledFile) {
			findings.push({
				id: "GATE_STEP_DISABLED",
				title: "The security gate step is present in the workflow but appears to be commented out or disabled",
				severity: "CRITICAL",
				files: [gateDisabledFile],
				requiredActions: [
					"The security gate step is present in the workflow but appears to be commented out or disabled.",
					"Uncomment or re-enable the `npm run ci:pr-gate` step so it blocks PRs with HIGH/CRITICAL findings.",
					"A disabled gate provides no protection — attackers can merge vulnerable code without review."
				]
			});
		}

		// Check for self-modification: security-gate.yml is being modified AND the gate step would be removed
		const gateWorkflowChanged = changedFiles.some((f) => f.includes("security-gate.yml"));
		if (gateWorkflowChanged && gateDisabledFile && gateDisabledFile.includes("security-gate.yml")) {
			findings.push({
				id: "GATE_WORKFLOW_SELF_MODIFICATION",
				title: "security-gate.yml is being modified and the gate step is disabled",
				severity: "CRITICAL",
				files: ["security-gate.yml"],
				requiredActions: [
					"security-gate.yml is being modified in this PR and the gate invocation step appears to be commented out or removed.",
					"This self-modification could bypass the security gate for all future PRs.",
					"Restore the `npm run ci:pr-gate` step before merging this change."
				]
			});
		}
	} catch (err) {
		console.warn("[checkGateStepPresent] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}

async function checkWorkflowInjection(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const workflowFiles = await fg(["**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/.git/**"]
		});
		// Covers all attacker-controlled GitHub context tokens that can contain shell metacharacters:
		// - github.event.{issue,pull_request,comment,review,discussion,inputs,release}.*
		// - github.head_ref (attacker-controlled branch name on fork PRs)
		// - github.ref_name (mutable, attacker-influenced on PRs)
		// - github.actor (attacker-controlled username)
		// - github.event.workflow_run.head_branch / head_commit.*
		const injectionRe = /\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|discussion|inputs|release|workflow_run)\.[a-z_.]+|github\.(?:head_ref|ref_name|actor))\s*\}\}/;
		const flaggedFiles: string[] = [];
		for (const file of workflowFiles) {
			let content: string;
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}
			const lines = content.split("\n");
			for (let i = 0; i < lines.length; i++) {
				if (!injectionRe.test(lines[i])) continue;
				// Check if "run:" appears within the 5 lines before this match
				const windowStart = Math.max(0, i - 5);
				const contextLines = lines.slice(windowStart, i);
				if (contextLines.some((l) => /run:/.test(l))) {
					flaggedFiles.push(file);
					break;
				}
			}
		}
		if (flaggedFiles.length > 0) {
			findings.push({
				id: "CI_WORKFLOW_INJECTION",
				title: "GitHub Actions workflow uses github.event.* user input in run: step — workflow injection RCE",
				severity: "CRITICAL",
				files: flaggedFiles.slice(0, 10),
				requiredActions: [
					"GitHub Actions workflow uses github.event.* user input in run: step — workflow injection RCE (ATT&CK T1059, GHSL-2021-1167)",
					"Never interpolate ${{ github.event.* }} directly into shell run: steps — pass values via environment variables instead (`env: VAL: ${{ github.event.issue.title }}`) and reference $VAL in the shell.",
					"An attacker can craft a title/body/branch containing shell metacharacters to achieve arbitrary code execution with the runner's permissions."
				]
			});
		}
	} catch (err) {
		console.warn("[checkWorkflowInjection] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

async function checkCiCachePoisoning(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const workflowFiles = await fg(["**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/.git/**"]
		});
		const cacheActionRe = /uses:\s+actions\/cache/;
		const poisonKeyRe = /key:.*\$\{\{.*github\.(?:head_ref|event\.pull_request\.head)/;
		const flaggedFiles: string[] = [];
		for (const file of workflowFiles) {
			let content: string;
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}
			const lines = content.split("\n");
			for (let i = 0; i < lines.length; i++) {
				if (!cacheActionRe.test(lines[i])) continue;
				const windowEnd = Math.min(lines.length, i + 20);
				const contextLines = lines.slice(i, windowEnd);
				if (contextLines.some((l) => poisonKeyRe.test(l))) {
					flaggedFiles.push(file);
					break;
				}
			}
		}
		if (flaggedFiles.length > 0) {
			findings.push({
				id: "CI_CACHE_POISONING",
				title: "CI cache key includes attacker-controlled branch name — cache poisoning risk",
				severity: "HIGH",
				files: flaggedFiles.slice(0, 10),
				requiredActions: [
					"CI cache key includes attacker-controlled branch name — cache poisoning injects malicious build artifacts (ATT&CK T1195.002)",
					"Do not use `github.head_ref` or `github.event.pull_request.head.*` in cache keys — an attacker can craft a branch name to collide with another PR's cache.",
					"Use only trusted, non-user-controlled values in cache keys (e.g. `github.ref`, `hashFiles(...)`)."
				]
			});
		}
	} catch (err) {
		console.warn("[checkCiCachePoisoning] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

async function checkDownloadArtifactNoVerify(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const workflowFiles = await fg(["**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/.git/**"]
		});
		const downloadRe = /uses:\s+(?:actions\/download-artifact|dawidd6\/action-download-artifact)/;
		const verifyRe = /sha256|signature|cosign|sigstore|verify/i;
		const flaggedFiles: string[] = [];
		for (const file of workflowFiles) {
			let content: string;
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}
			const lines = content.split("\n");
			for (let i = 0; i < lines.length; i++) {
				if (!downloadRe.test(lines[i])) continue;
				const windowEnd = Math.min(lines.length, i + 10);
				const contextLines = lines.slice(i, windowEnd);
				if (!contextLines.some((l) => verifyRe.test(l))) {
					flaggedFiles.push(file);
					break;
				}
			}
		}
		if (flaggedFiles.length > 0) {
			findings.push({
				id: "CI_ARTIFACT_NO_VERIFY",
				title: "CI downloads build artifact without integrity verification",
				severity: "HIGH",
				files: flaggedFiles.slice(0, 10),
				requiredActions: [
					"CI downloads build artifact without integrity verification — artifact poisoning risk (ATT&CK T1195.002)",
					"After downloading an artifact, verify its SHA-256 checksum or use Sigstore/cosign attestations before executing it.",
					"An unverified artifact from a compromised or malicious workflow run can silently introduce backdoors into the build."
				]
			});
		}
	} catch (err) {
		console.warn("[checkDownloadArtifactNoVerify] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

async function checkGithubTokenWriteAll(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const workflowFiles = await fg(["**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/.git/**"]
		});
		const writePermRe = /permissions:\s*write-all|packages:\s*write|contents:\s*write|pull-requests:\s*write/;
		const prTriggerRe = /pull_request(?:_target)?:/;
		const flaggedFiles: string[] = [];
		for (const file of workflowFiles) {
			let content: string;
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}
			if (writePermRe.test(content) && prTriggerRe.test(content)) {
				flaggedFiles.push(file);
			}
		}
		if (flaggedFiles.length > 0) {
			findings.push({
				id: "CI_GITHUB_TOKEN_WRITE_ALL",
				title: "GITHUB_TOKEN granted write permissions in workflow triggered by external PRs",
				severity: "HIGH",
				files: flaggedFiles.slice(0, 10),
				requiredActions: [
					"GITHUB_TOKEN granted write permissions in workflow triggered by external PRs — token theft enables repo write (ATT&CK T1552.001)",
					"Restrict permissions to the minimum required scopes; avoid `write-all` on workflows that process untrusted pull requests.",
					"Use `permissions: read-all` as the default and elevate only the specific scopes needed (e.g. `issues: write`)."
				]
			});
		}
	} catch (err) {
		console.warn("[checkGithubTokenWriteAll] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

async function checkForkSecretExposure(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const workflowFiles = await fg(["**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/.git/**"]
		});
		const secretsRe = /secrets\./;
		const flaggedFiles: string[] = [];
		for (const file of workflowFiles) {
			let content: string;
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}
			// Match "pull_request:" but NOT "pull_request_target:"
			if (/^\s*pull_request:/m.test(content) && secretsRe.test(content)) {
				flaggedFiles.push(file);
			}
		}
		if (flaggedFiles.length > 0) {
			findings.push({
				id: "CI_FORK_SECRET_EXPOSURE",
				title: "Secrets referenced in pull_request-triggered workflow — exposed to fork PR contributors",
				severity: "CRITICAL",
				files: flaggedFiles.slice(0, 10),
				requiredActions: [
					"Secrets referenced in pull_request-triggered workflow — exposed to fork PR contributors (ATT&CK T1552.001)",
					"Workflows triggered by `pull_request` from forks do not have access to secrets by default, but referencing them signals intent and may expose them in other contexts.",
					"Move secret-dependent steps to a separate workflow triggered by `pull_request_target` with explicit trust checks, or use environment protection rules to gate secret access."
				]
			});
		}
	} catch (err) {
		console.warn("[checkForkSecretExposure] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

async function checkNpmIgnoreScriptsCi(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const workflowFiles = await fg(["**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/.git/**"]
		});

		// Check whether .npmrc already sets ignore-scripts=true
		let npmrcDisablesScripts = false;
		const npmrcFiles = await fg([".npmrc", "**/.npmrc"], {
			dot: true,
			ignore: ["**/node_modules/**", "**/.git/**"]
		});
		for (const rc of npmrcFiles) {
			let rcContent: string;
			try {
				rcContent = await readFileSafe(rc);
			} catch {
				continue;
			}
			if (/^\s*ignore-scripts\s*=\s*true/m.test(rcContent)) {
				npmrcDisablesScripts = true;
				break;
			}
		}

		if (npmrcDisablesScripts) {
			return findings;
		}

		// npm install/ci without --ignore-scripts (and not already covered by .npmrc)
		const npmBareRe = /npm\s+(?:install|ci)(?!.*--ignore-scripts)/;
		const flaggedFiles: string[] = [];
		for (const file of workflowFiles) {
			let content: string;
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}
			if (npmBareRe.test(content)) {
				flaggedFiles.push(file);
			}
		}
		if (flaggedFiles.length > 0) {
			findings.push({
				id: "CI_NPM_MISSING_IGNORE_SCRIPTS",
				title: "npm install/ci in CI without --ignore-scripts",
				severity: "MEDIUM",
				files: flaggedFiles.slice(0, 10),
				requiredActions: [
					"npm install/ci in CI without --ignore-scripts — postinstall scripts execute automatically (ATT&CK T1195.001)",
					"Add `--ignore-scripts` to all `npm install` / `npm ci` invocations in CI, or set `ignore-scripts=true` in .npmrc.",
					"Malicious or compromised dependencies can use postinstall/preinstall lifecycle scripts to exfiltrate secrets or modify build artifacts."
				]
			});
		}
	} catch (err) {
		console.warn("[checkNpmIgnoreScriptsCi] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

export async function runCiPipelineChecks(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [
		...await checkGateStepPresent(_opts.changedFiles)
	];

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
			// Matches `uses: owner/repo@tag` but NOT `uses: owner/repo@<exactly 40 hex chars>`
			// Also skip `uses: ./.github/actions/` (local actions are fine)
			const actionLines = content.split("\n").filter((line) => /uses:\s+[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+@/.test(line));
			const unpinnedActions = actionLines.filter((line) => {
				// Skip local actions
				if (/uses:\s+\.\//.test(line)) return false;
				// Flag anything not pinned to EXACTLY a 40-char hex SHA.
				// The negative lookahead (?![0-9a-f]) prevents 41+ char hex strings from
				// being mistakenly treated as valid SHA-1 digests.
				return !/uses:\s+[a-zA-Z0-9_.\-/]+@[0-9a-f]{40}(?![0-9a-f])/.test(line);
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

	const additional = await Promise.all([
		checkWorkflowInjection(),
		checkCiCachePoisoning(),
		checkDownloadArtifactNoVerify(),
		checkGithubTokenWriteAll(),
		checkForkSecretExposure(),
		checkNpmIgnoreScriptsCi()
	]);
	findings.push(...additional.flat());

	return findings;
}
