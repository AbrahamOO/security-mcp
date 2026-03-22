/**
 * Data Loss Prevention checks.
 * Detects PII leaking into logs, APIs, and error responses.
 */
import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";

export async function checkDlp(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		// 1. SSN in logs
		const ssnHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+|log\.\w+)\s*\([^)]*\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`,
			isRegex: true,
			maxMatches: 200
		});
		if (ssnHits.length > 0) {
			findings.push({
				id: "DLP_SSN_IN_LOGS",
				title: "Social Security Number pattern detected in log statement",
				severity: "CRITICAL",
				evidence: ssnHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(ssnHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Remove SSN values from log statements immediately.",
					"HIPAA requires protection of SSNs as Protected Health Information (PHI).",
					"Use tokenization or masking before logging any government ID."
				]
			});
		}

		// 2. Credit card in logs (PAN)
		const panHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+)\s*\([^)]*\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`,
			isRegex: true,
			maxMatches: 200
		});
		if (panHits.length > 0) {
			findings.push({
				id: "DLP_PAN_IN_LOGS",
				title: "Credit card PAN pattern detected in log statement — PCI DSS violation",
				severity: "CRITICAL",
				evidence: panHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(panHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Remove all PAN values from log statements immediately.",
					"PCI DSS Requirement 3: Never log full card numbers.",
					"Use masked PANs (show only last 4 digits) if logging is required."
				]
			});
		}

		// 3. Full request body logged
		const reqBodyLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+)\s*\(\s*(?:req\.body|request\.body|ctx\.body|\{\.\.\.req)`,
			isRegex: true,
			maxMatches: 200
		});
		if (reqBodyLogHits.length > 0) {
			findings.push({
				id: "DLP_REQUEST_BODY_LOGGED",
				title: "Full request body logged — may expose PII/credentials",
				severity: "HIGH",
				evidence: reqBodyLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(reqBodyLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Never log full request bodies — use field allowlists to log only non-sensitive fields.",
					"GDPR Article 5: data minimization applies to logs. HIPAA prohibits logging PHI."
				]
			});
		}

		// 4. User object logged
		const userLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+)\s*\(\s*(?:user|currentUser|req\.user|session\.user)\s*[,)]`,
			isRegex: true,
			maxMatches: 200
		});
		if (userLogHits.length > 0) {
			findings.push({
				id: "DLP_USER_OBJECT_LOGGED",
				title: "User object logged — may expose PII, hashed passwords, or tokens",
				severity: "HIGH",
				evidence: userLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(userLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Log only specific non-sensitive user fields (e.g. userId, role).",
					"Never log the full user object — it likely contains PII and auth data (GDPR, HIPAA)."
				]
			});
		}

		// 5. Email in logs
		const emailLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+)\s*\([^)]*[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			isRegex: true,
			maxMatches: 200
		});
		if (emailLogHits.length > 0) {
			findings.push({
				id: "DLP_EMAIL_IN_LOGS",
				title: "Email address detected in log statement",
				severity: "MEDIUM",
				evidence: emailLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(emailLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Mask or hash email addresses before logging (GDPR Article 5 — data minimization).",
					"Use a user ID or anonymized identifier in logs instead of the email."
				]
			});
		}

		// 6. Stack traces in API responses
		const stackTraceHits = await searchRepo({
			query: String.raw`(?:res\.json|res\.send|response\.json)\s*\(\s*\{[^}]*(?:stack|stackTrace|error\.stack)`,
			isRegex: true,
			maxMatches: 200
		});
		if (stackTraceHits.length > 0) {
			findings.push({
				id: "DLP_STACK_TRACE_IN_RESPONSE",
				title: "Stack trace exposed in API response — CWE-209 information leakage",
				severity: "HIGH",
				evidence: stackTraceHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(stackTraceHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Never expose stack traces in API responses (CWE-209).",
					"Log errors internally with a correlation ID; return only a safe error message to clients."
				]
			});
		}

		// 7. Server version disclosure
		const poweredByHits = await searchRepo({
			query: String.raw`X-Powered-By|Server:\s*(?:Express|nginx|Apache)|app\.set\s*\(\s*['"]x-powered-by['"]`,
			isRegex: true,
			maxMatches: 200
		});
		if (poweredByHits.length > 0) {
			// Check if x-powered-by is disabled nearby
			const disableHits = await searchRepo({
				query: String.raw`app\.disable\s*\(\s*['"]x-powered-by['"]`,
				isRegex: true,
				maxMatches: 200
			});
			if (disableHits.length === 0) {
				findings.push({
					id: "DLP_SERVER_HEADER_DISCLOSURE",
					title: "Server technology disclosed via X-Powered-By or Server response header",
					severity: "MEDIUM",
					evidence: poweredByHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
					files: [...new Set(poweredByHits.slice(0, 10).map((m) => m.file))],
					requiredActions: [
						"Call app.disable('x-powered-by') in Express.",
						"Remove or obscure Server headers — version disclosure aids attacker reconnaissance."
					]
				});
			}
		}
	} catch (err) {
		console.warn("[checkDlp] Internal error:", err instanceof Error ? err.message : String(err));
	}

	return findings;
}
