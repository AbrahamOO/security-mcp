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

	// Multi-tenancy isolation checks

	// 1. Tenant ID from user input
	const tenantIdInputHits = await searchRepo({
		query: String.raw`tenantId\s*[:=]\s*(?:req\.(?:query|params|body)|request\.(?:query|params|body))`,
		isRegex: true,
		maxMatches: 200
	});
	if (tenantIdInputHits.length > 0) {
		findings.push({
			id: "API_TENANT_ID_FROM_INPUT",
			title: "Tenant ID sourced from user-controlled input — insecure direct tenant access",
			severity: "CRITICAL",
			evidence: tenantIdInputHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(tenantIdInputHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Tenant ID must come from the authenticated session/JWT claims, never from user-controlled input.",
				"Validate that the tenant ID matches the authenticated user's tenant on every request."
			]
		});
	}

	// 2. Missing tenant filter in DB queries (heuristic)
	const ormQueryHits = await searchRepo({
		query: String.raw`findAll|findMany|find\(|query\(|select\(`,
		isRegex: true,
		maxMatches: 200
	});
	const tenantScopeHits = await searchRepo({
		query: String.raw`tenantId|tenant_id|organizationId|orgId`,
		isRegex: true,
		maxMatches: 200
	});
	if (ormQueryHits.length > 0 && tenantScopeHits.length === 0) {
		findings.push({
			id: "API_MISSING_TENANT_SCOPE",
			title: "ORM queries found without tenant scoping — possible multi-tenant data leakage",
			severity: "HIGH",
			evidence: ormQueryHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(ormQueryHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"All database queries in multi-tenant systems must include a tenantId/organizationId filter.",
				"Add tenant-scoped base repository or middleware to enforce tenant isolation automatically."
			]
		});
	}

	// 3. Shared Redis cache without tenant namespacing
	const cacheGetHits = await searchRepo({
		query: String.raw`cache\.get\s*\(["'][^'"]*["']`,
		isRegex: true,
		maxMatches: 200
	});
	const redisGetHits = await searchRepo({
		query: String.raw`redis\.get\s*\(`,
		isRegex: true,
		maxMatches: 200
	});
	const tenantKeyHits = await searchRepo({
		query: String.raw`tenantId|tenant:|orgId|userId:`,
		isRegex: true,
		maxMatches: 200
	});
	const allCacheHits = [...cacheGetHits, ...redisGetHits];
	if (allCacheHits.length > 0 && tenantKeyHits.length === 0) {
		findings.push({
			id: "API_CACHE_NOT_TENANT_SCOPED",
			title: "Cache operations found without tenant-namespaced keys",
			severity: "HIGH",
			evidence: allCacheHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(allCacheHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Prefix all cache keys with tenant ID (e.g. tenant:{id}:resource:{id}).",
				"Never use bare resource IDs as cache keys in multi-tenant systems."
			]
		});
	}

	// 4. Cross-tenant file access
	const fileInputHits = await searchRepo({
		query: String.raw`(?:readFile|writeFile|createReadStream)\s*\([^)]*(?:req\.|params\.|query\.|body\.)`,
		isRegex: true,
		maxMatches: 200
	});
	if (fileInputHits.length > 0) {
		findings.push({
			id: "API_FILE_PATH_FROM_INPUT",
			title: "File operation with user-supplied path — path traversal and cross-tenant access risk",
			severity: "CRITICAL",
			evidence: fileInputHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(fileInputHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Never use user-supplied paths for file operations.",
				"Validate paths against an allowlist of permitted paths; use a content-addressed storage key instead."
			]
		});
	}

	return findings;
}
