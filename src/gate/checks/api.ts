import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import { scopedFg as fg } from "../scan-scope.js";
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

	// 6-12. Additional API surface detections
	findings.push(...await checkWebhookSignatureVerification());
	findings.push(...await checkBatchAmplification());
	findings.push(...await checkFilterOperatorInjection());
	findings.push(...await checkNestedIncludeExpansion());
	findings.push(...await checkSequentialIdEnumeration());
	findings.push(...await checkDeprecatedApiVersionRouted());
	findings.push(...await checkAuthTimingOracle());

	return findings;
}

// ---------------------------------------------------------------------------
// 6. Webhook receiver without signature verification
// ---------------------------------------------------------------------------
async function checkWebhookSignatureVerification(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Find webhook receiver route handlers (Stripe / GitHub / generic)
	const webhookRouteHits = await searchRepo({
		query: String.raw`(?:router|app|fastify|server)\.(?:post|put)\s*\(\s*['"][^'"]*(?:webhook|hook|callback|stripe|github)[^'"]*['"]|['"][^'"]*webhook[^'"]*['"]\s*,`,
		isRegex: true,
		maxMatches: 200
	});
	if (webhookRouteHits.length === 0) return findings;

	// Signature verification indicators near webhook handling.
	const verifyHits = await searchRepo({
		query: String.raw`constructEvent|verifyWebhook|verify_signature|X-Hub-Signature|x-hub-signature|Stripe-Signature|stripe-signature|createHmac|timingSafeEqual|webhookSignature|svix|verifyHeader`,
		isRegex: true,
		maxMatches: 200
	});

	// Raw body consumption is a strong indicator a webhook receiver exists.
	const rawBodyHits = await searchRepo({
		query: String.raw`rawBody|raw-body|express\.raw\s*\(|bodyParser\.raw|request\.text\(\)|req\.rawBody`,
		isRegex: true,
		maxMatches: 200
	});

	const receiverPresent = webhookRouteHits.length > 0 || rawBodyHits.length > 0;
	if (receiverPresent && verifyHits.length === 0) {
		const evidence = [...webhookRouteHits, ...rawBodyHits].slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`);
		findings.push({
			id: "API_WEBHOOK_NO_SIGNATURE_VERIFY",
			title: "Webhook receiver consumes request body without HMAC signature verification — forged webhook injection",
			severity: "CRITICAL",
			sla: "24h",
			evidence,
			files: [...new Set([...webhookRouteHits, ...rawBodyHits].slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Verify every inbound webhook's signature before processing the payload (Stripe: stripe.webhooks.constructEvent with the endpoint secret; GitHub: HMAC-SHA256 of the raw body against X-Hub-Signature-256).",
				"Compare signatures with a constant-time comparison (crypto.timingSafeEqual), never ==.",
				"Reject (HTTP 400) any request whose signature is missing or fails verification, before touching business logic."
			]
		});
	}

	return findings;
}

// ---------------------------------------------------------------------------
// 7. Batch / bulk request amplification (no cap on operations per request)
// ---------------------------------------------------------------------------
async function checkBatchAmplification(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Endpoints that iterate over a user-supplied array of operations/items/ids.
	const batchHits = await searchRepo({
		query: String.raw`(?:req|request)\.body\.(?:items|operations|ids|records|batch|users|entries)\b|for\s*\(\s*const\s+\w+\s+of\s+(?:req|request)\.body|(?:req|request)\.body\.(?:items|operations|ids|records|batch)\.(?:map|forEach|forOf|for)`,
		isRegex: true,
		maxMatches: 200
	});
	if (batchHits.length === 0) return findings;

	// A cap on batch size limits amplification.
	const capHits = await searchRepo({
		query: String.raw`\.length\s*(?:>|>=|<|<=)\s*\d+|MAX_BATCH|maxBatch|batchLimit|MAX_ITEMS|maxItems|slice\(0,\s*\d+\)`,
		isRegex: true,
		maxMatches: 200
	});

	if (capHits.length === 0) {
		findings.push({
			id: "API_BATCH_AMPLIFICATION",
			title: "Bulk/batch endpoint iterates over user-supplied array without a per-request operation cap — request amplification DoS",
			severity: "HIGH",
			sla: "7d",
			evidence: batchHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(batchHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Enforce a hard maximum on the number of operations/items per batch request (e.g. reject when body.items.length > 100).",
				"Return HTTP 413/400 when the cap is exceeded, before executing any operation.",
				"Account for batch size in rate limiting so N operations in one request consume N units of the quota."
			]
		});
	}

	return findings;
}

// ---------------------------------------------------------------------------
// 8. Search/filter operator injection (user-supplied operators reaching query)
// ---------------------------------------------------------------------------
async function checkFilterOperatorInjection(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// User-controlled filter/where object spread straight into a query, or user
	// input reaching LIKE / $gt / $regex operators.
	const mongoOperatorHits = await searchRepo({
		query: String.raw`(?:find|findOne|updateMany|deleteMany|aggregate)\s*\(\s*(?:req|request)\.(?:query|body|params)\b|\{\s*\.\.\.\s*(?:req|request)\.(?:query|body)\s*\}|where\s*:\s*(?:req|request)\.(?:query|body)`,
		isRegex: true,
		maxMatches: 200
	});
	const likeInjectionHits = await searchRepo({
		query: String.raw`(?:LIKE|ILIKE)\s+['"]?%?\$\{(?:req|request)\.(?:query|body|params)|\$regex\s*:\s*(?:req|request)\.(?:query|body)|new RegExp\s*\(\s*(?:req|request)\.(?:query|body)`,
		isRegex: true,
		maxMatches: 200
	});

	const allHits = [...mongoOperatorHits, ...likeInjectionHits];
	const uniqueHits = allHits.filter(
		(hit, idx, arr) => arr.findIndex((h) => h.file === hit.file && h.line === hit.line) === idx
	);

	if (uniqueHits.length > 0) {
		findings.push({
			id: "API_FILTER_OPERATOR_INJECTION",
			title: "User-supplied filter operators ($gt/$regex/LIKE) reach the query layer — operator injection (CWE-943/CWE-89)",
			severity: "HIGH",
			sla: "7d",
			evidence: uniqueHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(uniqueHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Never spread req.query/req.body directly into a query filter — build the filter from an allowlist of permitted field names and operators.",
				"For MongoDB, reject keys beginning with '$' in user input (or use a sanitizer like express-mongo-sanitize).",
				"For SQL LIKE, use parameterized queries and escape %/_ wildcards; never let the user control the operator itself."
			]
		});
	}

	return findings;
}

// ---------------------------------------------------------------------------
// 9. Field-level filtering bypass via nested include/expand
// ---------------------------------------------------------------------------
async function checkNestedIncludeExpansion(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// User-controlled include/expand/fields param driving a nested relation load.
	const includeHits = await searchRepo({
		query: String.raw`(?:req|request)\.query\.(?:include|expand|fields|populate|with)\b|include\s*:\s*(?:req|request)\.query|populate\s*\(\s*(?:req|request)\.query|\.split\(['"]\.['"]\)`,
		isRegex: true,
		maxMatches: 200
	});
	if (includeHits.length === 0) return findings;

	// An allowlist of includable relations mitigates the bypass.
	const allowlistHits = await searchRepo({
		query: String.raw`allowedInclude|ALLOWED_INCLUDES|includeAllowlist|allowedRelations|allowedFields|ALLOWED_FIELDS`,
		isRegex: true,
		maxMatches: 200
	});

	if (allowlistHits.length === 0) {
		findings.push({
			id: "API_NESTED_INCLUDE_FIELD_LEAK",
			title: "User-controlled include/expand parameter loads nested relations without an allowlist — field-level filtering bypass (e.g. ?include=profile.ssn)",
			severity: "MEDIUM",
			sla: "30d",
			evidence: includeHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(includeHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Restrict include/expand/populate parameters to an explicit allowlist of relations and fields the caller is authorised to see.",
				"Apply field-level authorization to nested/expanded objects, not just the top-level resource.",
				"Reject requests that reference relations or dotted paths outside the allowlist (HTTP 400)."
			]
		});
	}

	return findings;
}

// ---------------------------------------------------------------------------
// 10. Sequential numeric ID enumeration (auto-increment IDs exposed)
// ---------------------------------------------------------------------------
async function checkSequentialIdEnumeration(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Auto-increment / serial primary keys in schema or numeric-cast id route params.
	const autoIncrementHits = await searchRepo({
		query: String.raw`autoIncrement\s*:\s*true|@default\(autoincrement\(\)\)|AUTO_INCREMENT|SERIAL\s+PRIMARY|type\s*:\s*['"]?INTEGER['"]?[^\n]*primaryKey`,
		isRegex: true,
		maxMatches: 200
	});
	const numericRouteIdHits = await searchRepo({
		query: String.raw`parseInt\s*\(\s*(?:req\.params|params)\.(?:id|userId|user_id)\b|Number\s*\(\s*(?:req\.params|params)\.(?:id|userId)\b|:id\(\\\\d`,
		isRegex: true,
		maxMatches: 200
	});

	const allHits = [...autoIncrementHits, ...numericRouteIdHits];
	const uniqueHits = allHits.filter(
		(hit, idx, arr) => arr.findIndex((h) => h.file === hit.file && h.line === hit.line) === idx
	);

	if (autoIncrementHits.length > 0 && numericRouteIdHits.length > 0) {
		findings.push({
			id: "API_SEQUENTIAL_ID_ENUMERATION",
			title: "Auto-increment numeric IDs exposed in API routes/responses — resource enumeration risk",
			severity: "MEDIUM",
			sla: "30d",
			evidence: uniqueHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(uniqueHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Expose non-sequential, non-guessable identifiers (UUIDv4 or ULID) in API routes and responses instead of auto-increment primary keys.",
				"Enforce server-side ownership/authorization on every ID lookup so enumeration cannot reveal other users' resources.",
				"Add rate limiting and anomaly detection on endpoints that accept a resource ID."
			]
		});
	}

	return findings;
}

// ---------------------------------------------------------------------------
// 11. Deprecated API version with weaker auth still routed
// ---------------------------------------------------------------------------
async function checkDeprecatedApiVersionRouted(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// A versioned route path or router explicitly marked deprecated but still mounted.
	const deprecatedRouteHits = await searchRepo({
		query: String.raw`(?:@deprecated|deprecated\s*[:=]\s*true|//\s*deprecated)[^\n]*|(?:router|app)\.use\s*\(\s*['"]/(?:api/v[01]|v[01])\b|['"]/(?:api/v[01]|v[01])/`,
		isRegex: true,
		maxMatches: 200
	});
	if (deprecatedRouteHits.length === 0) return findings;

	// Restrict to versioned/deprecated paths that are actually mounted.
	const routedDeprecated = deprecatedRouteHits.filter((m) =>
		/v[01]\b|deprecated/i.test(m.preview)
	);
	if (routedDeprecated.length === 0) return findings;

	// Newer auth guard indicators present elsewhere but the old route lacks them.
	const legacyAuthHits = await searchRepo({
		query: String.raw`(?:api_key|apiKey|basic\s+auth|Basic\s|legacyAuth|x-api-key)[^\n]*v[01]|v[01][^\n]*(?:api_key|apiKey|x-api-key|basicAuth)`,
		isRegex: true,
		maxMatches: 200
	});

	findings.push({
		id: "API_DEPRECATED_VERSION_WEAK_AUTH",
		title: "Deprecated/legacy API version still routed — may bypass current authentication controls",
		severity: "MEDIUM",
		sla: "30d",
		evidence: [...routedDeprecated, ...legacyAuthHits].slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
		files: [...new Set([...routedDeprecated, ...legacyAuthHits].slice(0, 10).map((m) => m.file))],
		requiredActions: [
			"Retire deprecated API versions on a published schedule; return HTTP 410 Gone once sunset.",
			"Until retired, apply the same (current) authentication and authorization controls to legacy versions as to the current version.",
			"Never leave a v0/v1 route mounted with weaker auth (API keys, basic auth) than the current version."
		]
	});

	return findings;
}

// ---------------------------------------------------------------------------
// 12. Response-time oracle on auth (timing leak)
// ---------------------------------------------------------------------------
async function checkAuthTimingOracle(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Credential comparison using a non-constant-time operator.
	const naiveCompareHits = await searchRepo({
		query: String.raw`(?:password|token|apiKey|api_key|secret|hash|otp|code)\s*(?:===|==|!==|!=)\s*(?:req|request|user|stored|db|expected)\.[\w.]+|(?:req|request|user|stored|db|expected)\.[\w.]+\s*(?:===|==|!==|!=)\s*(?:password|token|apiKey|secret|hash|otp)\b`,
		isRegex: true,
		maxMatches: 200
	});
	if (naiveCompareHits.length === 0) return findings;

	// Constant-time comparison in use anywhere suppresses the finding for that area.
	const constantTimeHits = await searchRepo({
		query: String.raw`timingSafeEqual|crypto\.timingSafeEqual|safeCompare|constantTimeCompare|secure-compare|tsscmp`,
		isRegex: true,
		maxMatches: 200
	});

	if (constantTimeHits.length === 0) {
		findings.push({
			id: "API_AUTH_TIMING_ORACLE",
			title: "Secret/credential compared with a non-constant-time operator — response-time oracle (CWE-208)",
			severity: "MEDIUM",
			sla: "30d",
			evidence: naiveCompareHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(naiveCompareHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Compare secrets, tokens, password hashes, and OTPs with a constant-time function (crypto.timingSafeEqual), never == or ===.",
				"Ensure both branches (user found / not found) take comparable time to avoid a username-enumeration timing side channel.",
				"Where possible, verify passwords via a slow hash comparator (bcrypt.compare / argon2.verify) which is inherently constant-time-ish per candidate."
			]
		});
	}

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
