import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

export async function checkWebNextjs(_: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	// 1) CSP and security headers should exist (Next middleware or edge config)
	const headerFiles = await fg(["middleware.ts", "middleware.tsx", "src/middleware.ts", "next.config.*"], {
		dot: true
	});

	if (headerFiles.length === 0) {
		findings.push({
			id: "WEB_HEADERS_MISSING",
			title: "Security headers not found (CSP/HSTS/etc.)",
			severity: "HIGH",
			requiredActions: [
				"Add strict security headers: CSP (no inline JS), HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy.",
				"Enforce secure cookies: HttpOnly, Secure, SameSite, short-lived tokens."
			]
		});
	} else {
		const combined = (await Promise.all(headerFiles.map((f) => readFileSafe(f).catch(() => "")))).join("\n");
		const mustContain = [
			"content-security-policy",
			"strict-transport-security",
			"referrer-policy",
			"permissions-policy"
		];
		const missing = mustContain.filter((k) => !combined.toLowerCase().includes(k));
		if (missing.length > 0) {
			findings.push({
				id: "WEB_HEADERS_INCOMPLETE",
				title: "Security headers exist but appear incomplete",
				severity: "HIGH",
				evidence: [`Missing: ${missing.join(", ")}`],
				requiredActions: [
					"Add missing headers and ensure CSP forbids inline scripts (no 'unsafe-inline').",
					"Add a CSP nonce strategy if you must load dynamic scripts."
				]
			});
		}
	}

	// 2) Flag dangerous React usage
	const dsi = await searchRepo({ query: "dangerouslySetInnerHTML", isRegex: false, maxMatches: 200 });
	if (dsi.length > 0) {
		findings.push({
			id: "DANGEROUSLY_SET_INNER_HTML",
			title: "dangerouslySetInnerHTML usage detected",
			severity: "HIGH",
			evidence: dsi.slice(0, 20).map((m) => `${m.file}:${m.line}:${m.preview}`),
			requiredActions: [
				"Remove dangerouslySetInnerHTML where possible.",
				"If unavoidable: sanitize with a proven HTML sanitizer and add unit tests with XSS payloads."
			]
		});
	}

	// 3) Basic SSRF risk pattern scan (server-side fetch)
	const fetchHits = await searchRepo({
		query: String.raw`\bfetch\(|axios\(|got\(|undici\b`,
		isRegex: true,
		maxMatches: 200
	});
	if (fetchHits.length > 0) {
		findings.push({
			id: "SSRF_GUARD_REQUIRED",
			title: "Server-side fetch patterns detected. SSRF protections must be enforced.",
			severity: "HIGH",
			evidence: fetchHits.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
			requiredActions: [
				"Implement SSRF guard for any server-side HTTP client: block localhost, private IP ranges, and cloud metadata endpoints.",
				"Require URL allowlists for outbound calls. Add tests for 127.0.0.1, 10/8, 172.16/12, 192.168/16, 169.254.169.254, metadata.google.internal."
			]
		});
	}

	return findings;
}
