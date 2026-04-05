import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

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

	// 5. API schema drift (OpenAPI/Swagger spec vs code routes)
	findings.push(...await checkApiSchemaDrift());

	return findings;
}

function parseDeclaredPaths(specContent: string): Set<string> {
	const paths = new Set<string>();
	for (const match of specContent.matchAll(/^\s{0,4}(\/[a-zA-Z0-9/{}_-]+)\s*:/gm)) {
		paths.add(match[1]);
	}
	return paths;
}

function findShadowRoutes(
	codeRouteHits: { file: string; line: number; preview: string }[],
	declaredPaths: Set<string>
): string[] {
	const shadows: string[] = [];
	for (const hit of codeRouteHits) {
		const routeMatch = /['"](\/?[a-zA-Z0-9/{}_-]+)['"]/.exec(hit.preview);
		if (!routeMatch) continue;
		const route = routeMatch[1].startsWith("/") ? routeMatch[1] : `/${routeMatch[1]}`;
		const normalised = route.replaceAll(/:([a-zA-Z_]+)/g, "{$1}");
		if (!declaredPaths.has(normalised) && !declaredPaths.has(route)) {
			shadows.push(`${hit.file}:${hit.line} — ${route}`);
		}
	}
	return shadows;
}

async function checkApiSchemaDrift(): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const specFiles = await fg(
			[
				"openapi.{yaml,yml,json}",
				"swagger.{yaml,yml,json}",
				"**/openapi.{yaml,yml,json}",
				"**/swagger.{yaml,yml,json}",
				"**/api-spec.{yaml,yml,json}",
				"**/openapi/**/*.{yaml,yml,json}"
			],
			{ ignore: ["**/node_modules/**", "**/dist/**", "**/.git/**"], dot: true }
		);

		const codeRouteHits = await searchRepo({
			query: String.raw`(?:router|app|fastify|server)\.(?:get|post|put|delete|patch)\s*\(\s*['"](/[^'"]+)['"]`,
			isRegex: true,
			maxMatches: 300
		});

		if (specFiles.length === 0) {
			if (codeRouteHits.length > 0) {
				findings.push({
					id: "API_NO_OPENAPI_SPEC",
					title: "API routes detected but no OpenAPI/Swagger specification found",
					severity: "MEDIUM",
					evidence: codeRouteHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
					requiredActions: [
						"Create an OpenAPI 3.x specification (openapi.yaml) that documents all API routes.",
						"An API contract enables automated schema validation, client SDK generation, and drift detection.",
						"Use tools like `zod-to-openapi` or `tsoa` to generate the spec from existing TypeScript code."
					]
				});
			}
			return findings;
		}

		const specContent = await readFileSafe(specFiles[0]);
		const declaredPaths = parseDeclaredPaths(specContent);
		const shadowRoutes = findShadowRoutes(codeRouteHits, declaredPaths);

		if (shadowRoutes.length > 0) {
			findings.push({
				id: "API_SHADOW_ENDPOINT",
				title: `${shadowRoutes.length} API route(s) in code not declared in OpenAPI spec — shadow endpoints`,
				severity: "HIGH",
				evidence: [...new Set(shadowRoutes)].slice(0, 15),
				requiredActions: [
					"Add all undocumented routes to the OpenAPI specification.",
					"Shadow endpoints bypass API gateway policies, rate limiting, and schema validation.",
					"Automate spec generation (tsoa, zod-to-openapi) to prevent drift from recurring."
				]
			});
		}

		if (/type:\s+object/.test(specContent) && !/properties:/.test(specContent)) {
			findings.push({
				id: "API_PERMISSIVE_SCHEMA",
				title: "OpenAPI spec contains `type: object` without `properties` — accepts any payload shape",
				severity: "MEDIUM",
				files: [specFiles[0]],
				requiredActions: [
					"Define explicit `properties` for all object schemas in the OpenAPI spec.",
					"Permissive schemas allow attackers to inject unexpected fields (mass assignment, prototype pollution).",
					"Set `additionalProperties: false` on request body schemas to enforce strict validation."
				]
			});
		}
	} catch (err) {
		console.warn("[checkApiSchemaDrift] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
