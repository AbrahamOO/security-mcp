import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";

export async function checkAi(_: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	const schemaEnforcement = await searchRepo({
		query: String.raw`zod\.object\(|outputSchema|json_schema|JSON schema`,
		isRegex: true,
		maxMatches: 200
	});
	const toolUse = await searchRepo({ query: "tool|function_call|tools:", isRegex: true, maxMatches: 200 });

	if (toolUse.length > 0 && schemaEnforcement.length === 0) {
		findings.push({
			id: "AI_OUTPUT_BOUNDS_MISSING",
			title: "AI/tooling present but bounded output (schema validation) not detected",
			severity: "HIGH",
			requiredActions: [
				"Enforce bounded outputs via JSON schema validation for every AI response used by code.",
				"Add prompt-injection defenses: input sanitization, tool allowlists, deny-by-default tool router, and sensitive data redaction."
			]
		});
	}

	const systemPromptLeaks = await searchRepo({
		query: "system prompt|developer message|ignore previous|prompt injection",
		isRegex: true,
		maxMatches: 200
	});
	if (systemPromptLeaks.length > 0) {
		findings.push({
			id: "AI_INJECTION_CUES",
			title: "Potential prompt injection cues detected. Requires explicit mitigations and tests.",
			severity: "MEDIUM",
			evidence: systemPromptLeaks.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			requiredActions: [
				"Add multi-layer prompt-injection protection: instruction hierarchy enforcement, content isolation, tool gating, and output validation.",
				"Add a red-team test harness with injection payloads and exfil attempts."
			]
		});
	}

	return findings;
}
