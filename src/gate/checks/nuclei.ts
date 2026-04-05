/**
 * DAST integration via Nuclei (https://github.com/projectdiscovery/nuclei).
 * Only runs when SECURITY_STAGING_URL is set — requires a live target.
 * Gracefully skips if the nuclei binary is not installed.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Finding, FindingSeverity, sanitizeErrorMessage } from "../result.js";

const execFileAsync = promisify(execFile);

// Template categories focused on high-signal findings with low false-positive rates
const NUCLEI_TEMPLATES = [
	"network",
	"http/misconfiguration",
	"http/exposed-panels",
	"http/default-logins",
	"http/exposed-tokens",
	"ssl"
];

interface NucleiResult {
	"template-id"?: string;
	info?: {
		name?: string;
		severity?: string;
	};
	host?: string;
	matched?: string;
	type?: string;
}

function mapSeverity(nucleiSev: string | undefined): FindingSeverity {
	switch ((nucleiSev ?? "").toLowerCase()) {
		case "critical": return "CRITICAL";
		case "high":     return "HIGH";
		case "medium":   return "MEDIUM";
		default:         return "LOW";
	}
}

async function isNucleiAvailable(): Promise<boolean> {
	try {
		await execFileAsync("nuclei", ["--version"], { timeout: 5000 });
		return true;
	} catch {
		return false;
	}
}

export async function runNucleiChecks(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	const targetUrl = process.env["SECURITY_STAGING_URL"];
	if (!targetUrl) return [];

	// Basic URL validation — block private/metadata ranges (CWE-918)
	try {
		const parsed = new URL(targetUrl);
		if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return [];
		const host = parsed.hostname;
		if (
			host === "localhost" ||
			host === "169.254.169.254" ||
			host === "metadata.google.internal" ||
			host.endsWith(".internal") ||
			/^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(host)
		) {
			console.warn("[runNucleiChecks] SECURITY_STAGING_URL resolves to private/metadata address — skipping DAST scan.");
			return [];
		}
	} catch {
		return [];
	}

	if (!(await isNucleiAvailable())) {
		// Silent skip — nuclei is optional. Scanner readiness check will flag missing tooling.
		return [];
	}

	const findings: Finding[] = [];

	try {
		const templateArgs = NUCLEI_TEMPLATES.flatMap((t) => ["-t", t]);

		let stdout = "";
		try {
			const result = await execFileAsync(
				"nuclei",
				[
					"-u", targetUrl,
					...templateArgs,
					"-json",
					"-silent",
					"-timeout", "30",
					"-max-host-error", "5",
					"-rate-limit", "50"
				],
				{
					timeout: 120_000, // 2 min hard cap
					// CWE-526: pass only PATH — do not propagate secrets/tokens from parent env.
					env: { PATH: process.env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin" },
					maxBuffer: 50 * 1024 * 1024 // 50 MB — nuclei output can be large in full-template scans
				}
			);
			stdout = result.stdout;
		} catch (execErr) {
			// nuclei exits non-zero when findings exist — that's expected
			const err = execErr as { stdout?: string; code?: number };
			stdout = err.stdout ?? "";
		}

		if (!stdout.trim()) return [];

		// nuclei -json outputs newline-delimited JSON (one object per line)
		const seen = new Set<string>();
		for (const line of stdout.split("\n")) {
			const trimmed = line.trim();
			if (!trimmed || !trimmed.startsWith("{")) continue;

			let result: NucleiResult;
			try {
				result = JSON.parse(trimmed) as NucleiResult;
			} catch {
				continue;
			}

			const templateId = result["template-id"] ?? "unknown";
			const host = result.host ?? targetUrl;
			const dedupeKey = `${templateId}:${host}`;
			if (seen.has(dedupeKey)) continue;
			seen.add(dedupeKey);

			const name = result.info?.name ?? templateId;
			const severity = mapSeverity(result.info?.severity);
			const matched = result.matched ?? host;

			findings.push({
				id: `NUCLEI_${templateId.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`,
				title: `[DAST] ${name}`,
				severity,
				evidence: [
					`Template: ${templateId}`,
					`Target: ${host}`,
					`Matched: ${matched}`
				],
				requiredActions: [
					`Review the Nuclei finding for template "${templateId}" against ${host}.`,
					"Reproduce with: `nuclei -u " + targetUrl + " -t " + templateId + " -debug`",
					"Remediate before deploying to production — this was detected against a live staging environment."
				]
			});
		}
	} catch (err) {
		console.warn("[runNucleiChecks] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
