import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";

export async function checkApi(_: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	const zodHits = await searchRepo({ query: "zod|valibot|yup|joi", isRegex: true, maxMatches: 200 });
	if (zodHits.length === 0) {
		findings.push({
			id: "API_VALIDATION_MISSING",
			title: "No server-side schema validation library detected in API surface",
			severity: "HIGH",
			requiredActions: [
				"Add mandatory server-side schema validation for all API boundaries (Zod/Valibot/Yup/Joi).",
				"Enforce allowlist validation and strict normalization at boundaries."
			]
		});
	}

	const csrfHits = await searchRepo({ query: "csrf|xsrf", isRegex: true, maxMatches: 200 });
	if (csrfHits.length === 0) {
		findings.push({
			id: "CSRF_MAY_BE_MISSING",
			title: "CSRF protections not detected",
			severity: "HIGH",
			requiredActions: [
				"Add CSRF protections for all state-changing endpoints.",
				"Use SameSite cookies + CSRF tokens, validate origin/referer for browser contexts."
			]
		});
	}

	const idorCues = await searchRepo({
		query: String.raw`req\.query\.|params\.|userId\s*=`,
		isRegex: true,
		maxMatches: 200
	});
	if (idorCues.length > 0) {
		findings.push({
			id: "IDOR_RISK_REVIEW",
			title: "Possible IDOR risk: parameterized resource access patterns detected",
			severity: "MEDIUM",
			evidence: idorCues.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
			requiredActions: [
				"Ensure every resource access enforces server-side authz checks (UI checks never count).",
				"Add tests for cross-tenant access attempts."
			]
		});
	}

	return findings;
}
