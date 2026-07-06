/**
 * GraphQL security checks.
 * Detects GraphQL schemas and validates security controls.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";

async function checkGraphqlIntrospection(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Find GraphQL server instantiation sites
	const serverHits = await searchRepo({
		query: String.raw`ApolloServer|createServer|buildSchema|makeExecutableSchema|new GraphQL`,
		isRegex: true,
		maxMatches: 200
	});

	if (serverHits.length === 0) return findings;

	// Check for explicit disabling of introspection near server setup
	const disableHits = await searchRepo({
		query: String.raw`introspection\s*:\s*false|disableIntrospection|NoIntrospection|validationRules.*introspection`,
		isRegex: true,
		maxMatches: 200
	});

	// Check for introspection: true explicitly set
	const alwaysOnHits = await searchRepo({
		query: String.raw`introspection\s*:\s*true`,
		isRegex: true,
		maxMatches: 200
	});

	// Filter always-on hits that have no NODE_ENV guard
	const unguardedAlwaysOn = alwaysOnHits.filter((m) => !/NODE_ENV|process\.env/i.test(m.preview));

	if (unguardedAlwaysOn.length > 0) {
		findings.push({
			id: "GRAPHQL_INTROSPECTION_ALWAYS_ON",
			title: "GraphQL introspection is explicitly enabled without a NODE_ENV guard",
			severity: "CRITICAL",
			evidence: unguardedAlwaysOn.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(unguardedAlwaysOn.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Disable introspection unconditionally in production.",
				"Use `introspection: process.env.NODE_ENV !== 'production'` at minimum."
			]
		});
	} else if (disableHits.length === 0) {
		// Server setup found but introspection is not explicitly disabled
		findings.push({
			id: "GRAPHQL_INTROSPECTION_ENABLED",
			title: "GraphQL introspection is enabled by default; ensure it is disabled in production with `introspection: process.env.NODE_ENV !== 'production'`",
			severity: "HIGH",
			evidence: serverHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(serverHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Disable introspection in non-dev environments.",
				"Use persisted queries instead of ad-hoc introspection in production."
			]
		});
	}

	return findings;
}

async function checkGraphqlAliasAmplification(graphqlInUse: boolean): Promise<Finding[]> {
	if (!graphqlInUse) return [];
	const findings: Finding[] = [];

	const complexityHits = await searchRepo({
		query: String.raw`complexityPlugin|costAnalysis|queryComplexity|createComplexityRule`,
		isRegex: true,
		maxMatches: 200
	});

	if (complexityHits.length === 0) {
		findings.push({
			id: "GRAPHQL_NO_COMPLEXITY_LIMIT",
			title: "No GraphQL query complexity limiter detected",
			severity: "HIGH",
			requiredActions: [
				"Add graphql-query-complexity or graphql-cost-analysis to limit query cost.",
				"Set a maximum complexity budget to prevent amplified alias abuse."
			]
		});
		return findings;
	}

	// Complexity limiter found — check if it accounts for aliases
	const aliasHits = await searchRepo({
		query: String.raw`aliasCost|aliasMultiplier|alias.*cost|fieldCost.*alias`,
		isRegex: true,
		maxMatches: 200
	});

	if (aliasHits.length === 0) {
		findings.push({
			id: "GRAPHQL_ALIAS_AMPLIFICATION",
			title: "GraphQL complexity limiter found but alias cost not configured — alias amplification attacks possible",
			severity: "HIGH",
			evidence: complexityHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(complexityHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Configure alias cost or alias multiplier in the complexity plugin.",
				"Without alias accounting, attackers can use field aliasing to bypass complexity limits."
			]
		});
	}

	return findings;
}

async function checkGraphqlResolverInjection(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const resolverInjectionHits = await searchRepo({
		query: String.raw`(?:resolve|resolver)\s*\([^)]*\)\s*\{[^}]*(?:SELECT|INSERT|UPDATE|DELETE|\$where|\$regex|aggregate)\s*['"].*\$\{args\.`,
		isRegex: true,
		maxMatches: 200
	});

	const resolverInjectionBroadHits = await searchRepo({
		query: String.raw`resolve.*\{[^}]*(?:SELECT|INSERT)[^}]*\$\{args`,
		isRegex: true,
		maxMatches: 200
	});

	const allHits = [...resolverInjectionHits, ...resolverInjectionBroadHits];
	const uniqueHits = allHits.filter(
		(hit, idx, arr) => arr.findIndex((h) => h.file === hit.file && h.line === hit.line) === idx
	);

	if (uniqueHits.length > 0) {
		findings.push({
			id: "GRAPHQL_RESOLVER_INJECTION",
			title: "GraphQL resolver argument concatenated into raw SQL/NoSQL query — injection via resolver args (CWE-89/CWE-943)",
			severity: "CRITICAL",
			evidence: uniqueHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(uniqueHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Never interpolate resolver args directly into SQL or NoSQL queries.",
				"Use parameterized queries or an ORM to pass resolver arguments safely.",
				"Validate and sanitize all args before use in any query expression."
			]
		});
	}

	return findings;
}

async function checkGraphqlAliasBatching(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const serverHits = await searchRepo({
		query: String.raw`(?:ApolloServer|makeExecutableSchema|buildSchema|graphqlHTTP)\s*\(`,
		isRegex: true,
		maxMatches: 200
	});

	if (serverHits.length === 0) return findings;

	const aliasLimitHits = await searchRepo({
		query: String.raw`(?:maxAliasCount|depthLimit|complexityLimit|queryComplexity|fieldExtensions.*complexity)`,
		isRegex: true,
		maxMatches: 200
	});

	if (aliasLimitHits.length === 0) {
		findings.push({
			id: "GRAPHQL_ALIAS_BATCHING",
			title: "GraphQL server without alias count limit — N+1 batching enables account enumeration and DoS (CWE-770)",
			severity: "HIGH",
			evidence: serverHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(serverHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Add a maxAliasCount or equivalent alias limit to the GraphQL server configuration.",
				"Use graphql-query-complexity or graphql-depth-limit to bound alias expansion.",
				"Without limits, attackers can batch aliased fields to enumerate data or exhaust backend resources."
			]
		});
	}

	return findings;
}

async function checkGraphqlCircularFragments(graphqlInUse: boolean): Promise<Finding[]> {
	if (!graphqlInUse) return [];
	const findings: Finding[] = [];

	const fragmentProtectionHits = await searchRepo({
		query: String.raw`NoSchemaIntrospectionCustomRule|maxFragmentDepth|FragmentDepthLimit`,
		isRegex: true,
		maxMatches: 200
	});

	const validationRulesHits = await searchRepo({
		query: String.raw`specifiedRules|validationRules`,
		isRegex: true,
		maxMatches: 200
	});

	const hasFragmentProtection =
		fragmentProtectionHits.length > 0 ||
		validationRulesHits.some((m) => /maxFragmentDepth|FragmentDepthLimit/i.test(m.preview));

	if (!hasFragmentProtection) {
		findings.push({
			id: "GRAPHQL_CIRCULAR_FRAGMENT_RISK",
			title: "No GraphQL fragment depth limiting detected — circular fragment DoS risk",
			severity: "MEDIUM",
			requiredActions: [
				"Add fragment depth limiting via a custom validation rule.",
				"Use graphql-depth-limit or implement NoSchemaIntrospectionCustomRule with fragment cycle detection.",
				"Circular fragments can be used to exhaust server resources."
			]
		});
	}

	return findings;
}

async function checkGraphqlAuthCacheKey(graphqlInUse: boolean): Promise<Finding[]> {
	if (!graphqlInUse) return [];
	const findings: Finding[] = [];

	// Response caching in front of authenticated GraphQL.
	const cacheHits = await searchRepo({
		query: String.raw`responseCachePlugin|@cacheControl|cacheControl\s*:|apollo-server-plugin-response-cache|InMemoryLRUCache|KeyvAdapter|cache\s*:\s*['"]?(?:public|private)`,
		isRegex: true,
		maxMatches: 200
	});
	if (cacheHits.length === 0) return findings;

	// Per-user session/context indicators in the cache key.
	const sessionScopedKeyHits = await searchRepo({
		query: String.raw`sessionId|session\.id|context\.user|context\.userId|user\.id|scope\s*:\s*['"]?PRIVATE|PRIVATE\b|sessionMode|generateCacheKey|cacheKeyFor`,
		isRegex: true,
		maxMatches: 200
	});

	const scoped = sessionScopedKeyHits.some((m) => /session|user|PRIVATE|cacheKey/i.test(m.preview));
	if (!scoped) {
		findings.push({
			id: "GRAPHQL_AUTH_CACHE_SHARED_KEY",
			title: "GraphQL response cache without per-user context in the cache key — authenticated data served across users (CWE-524/CWE-639)",
			severity: "CRITICAL",
			sla: "24h",
			evidence: cacheHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(cacheHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Include the authenticated user/session identity in every cache key for any field that returns user-specific data.",
				"Mark authenticated/user-scoped fields as @cacheControl(scope: PRIVATE) (or sessionId in responseCachePlugin) so responses are never shared across users.",
				"Default to no caching for resolvers that read from the request context (user, tenant, roles)."
			]
		});
	}

	return findings;
}

async function checkGraphqlMutationRateLimit(graphqlInUse: boolean): Promise<Finding[]> {
	if (!graphqlInUse) return [];
	const findings: Finding[] = [];

	// Mutations exist in the schema/resolvers.
	const mutationHits = await searchRepo({
		query: String.raw`type\s+Mutation\b|Mutation\s*:\s*\{|extend\s+type\s+Mutation`,
		isRegex: true,
		maxMatches: 200
	});
	if (mutationHits.length === 0) return findings;

	// Rate-limit / cost accounting that applies to mutations (not just query depth).
	const mutationLimitHits = await searchRepo({
		query: String.raw`graphql-rate-limit|@rateLimit|createRateLimitDirective|rateLimitDirective|mutationCost|costMap.*Mutation|shield\(.*Mutation`,
		isRegex: true,
		maxMatches: 200
	});

	if (mutationLimitHits.length === 0) {
		findings.push({
			id: "GRAPHQL_MUTATION_NOT_RATE_LIMITED",
			title: "GraphQL mutations not rate-limited or costed — only query depth/complexity is bounded (CWE-770)",
			severity: "HIGH",
			sla: "7d",
			evidence: mutationHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(mutationHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Apply per-user rate limiting to mutations (e.g. graphql-rate-limit @rateLimit directive), independent of query depth limits.",
				"Assign an explicit cost to each mutation and count mutations against the complexity/cost budget.",
				"Set tight limits on abuse-prone mutations (login, signup, password reset, payment) and return an error when exceeded."
			]
		});
	}

	return findings;
}

async function checkGraphqlNestedMutationBudget(graphqlInUse: boolean): Promise<Finding[]> {
	if (!graphqlInUse) return [];
	const findings: Finding[] = [];

	// Nested-write inputs (Prisma-style create/connect nesting) or nested input types.
	const nestedMutationHits = await searchRepo({
		query: String.raw`nestedCreate|createMany\s*:|connectOrCreate|input\s+\w*(?:Create|Update)\w*Input\b[^\n]*\{[^\n]*(?:Create|Update)Input|data\s*:\s*\{[^\n]*create\s*:`,
		isRegex: true,
		maxMatches: 200
	});
	if (nestedMutationHits.length === 0) return findings;

	// Complexity/cost accounting that covers mutation input depth.
	const nestedBudgetHits = await searchRepo({
		query: String.raw`mutationComplexity|inputComplexity|nestedCost|maxInputDepth|estimateComplexity.*Mutation|createComplexityRule`,
		isRegex: true,
		maxMatches: 200
	});

	if (nestedBudgetHits.length === 0) {
		findings.push({
			id: "GRAPHQL_NESTED_MUTATION_NO_BUDGET",
			title: "Nested-mutation inputs (nested create/connect) not budgeted in complexity accounting — write amplification (CWE-770)",
			severity: "HIGH",
			sla: "7d",
			evidence: nestedMutationHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(nestedMutationHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Include mutation input arguments and nested write structures in the complexity/cost calculation, not just output selection depth.",
				"Cap the number of nested records a single mutation may create/connect (e.g. reject inputs with > 50 nested items).",
				"Reject mutations whose input depth or fan-out exceeds the configured budget before executing any write."
			]
		});
	}

	return findings;
}

async function checkGraphqlSubscriptionLimits(graphqlInUse: boolean): Promise<Finding[]> {
	if (!graphqlInUse) return [];
	const findings: Finding[] = [];

	// Subscriptions / websocket server present.
	const subscriptionHits = await searchRepo({
		query: String.raw`type\s+Subscription\b|Subscription\s*:\s*\{|graphql-ws|subscriptions-transport-ws|useServer\s*\(|SubscriptionServer|WebSocketServer`,
		isRegex: true,
		maxMatches: 200
	});
	if (subscriptionHits.length === 0) return findings;

	// Connection timeout / max-connection / keepalive limits.
	const wsLimitHits = await searchRepo({
		query: String.raw`connectionInitWaitTimeout|maxConnections|keepAlive|connectionTimeout|socketTimeout|maxSubscriptions|closeCode|idleTimeout`,
		isRegex: true,
		maxMatches: 200
	});

	if (wsLimitHits.length === 0) {
		findings.push({
			id: "GRAPHQL_SUBSCRIPTION_NO_LIMITS",
			title: "GraphQL subscriptions/WebSocket server without connection timeout or connection cap — WebSocket DoS (CWE-770)",
			severity: "HIGH",
			sla: "7d",
			evidence: subscriptionHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(subscriptionHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Set connectionInitWaitTimeout so idle/unauthenticated sockets are closed promptly.",
				"Cap concurrent WebSocket connections per user/IP and cap the number of active subscriptions per connection.",
				"Authenticate on connection_init and enforce idle timeouts to prevent connection-exhaustion DoS."
			]
		});
	}

	return findings;
}

async function checkGraphqlAuthDirectiveInheritance(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const schemaFiles = await fg(["**/*.graphql", "**/*.gql"], {
		ignore: ["**/node_modules/**", "**/.git/**", "**/dist/**"]
	});
	if (schemaFiles.length === 0) return findings;

	const offenders: string[] = [];
	for (const file of schemaFiles) {
		try {
			const content = await readFileSafe(file);
			// Only relevant when auth directives are in use at all.
			if (!/@auth|@authenticated|@hasRole|@requiresAuth/i.test(content)) continue;
			// extend type / interface implementations that add fields without re-declaring auth.
			const hasExtend = /extend\s+type\s+\w+|implements\s+\w+/i.test(content);
			if (!hasExtend) continue;
			// Look for an extend/child type block whose fields carry no auth directive.
			const extendBlocks = content.match(/(?:extend\s+type|type\s+\w+\s+implements)[^{]*\{[^}]*\}/gi) || [];
			for (const block of extendBlocks) {
				if (!/@auth|@authenticated|@hasRole|@requiresAuth/i.test(block)) {
					offenders.push(file);
					break;
				}
			}
		} catch {
			// skip unreadable files
		}
	}

	if (offenders.length > 0) {
		findings.push({
			id: "GRAPHQL_AUTH_DIRECTIVE_NOT_INHERITED",
			title: "Extended/child GraphQL types add fields without re-applying auth directives — authorization not inherited (CWE-285)",
			severity: "HIGH",
			sla: "7d",
			files: [...new Set(offenders)].slice(0, 10),
			requiredActions: [
				"Re-apply @auth/@hasRole directives to fields added via `extend type` and to interface implementations — directives on a base type are not automatically inherited by extensions.",
				"Prefer centrally-enforced field authorization (e.g. graphql-shield rule tree) so extended types cannot silently expose unprotected fields.",
				"Add a schema test asserting every field returning sensitive data carries an auth directive."
			]
		});
	}

	return findings;
}

async function checkGraphqlDefaultResolverExposure(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Whole DB/model object returned from a resolver and relied on for default field resolution.
	const passthroughHits = await searchRepo({
		query: String.raw`return\s+(?:await\s)?(?:db|prisma|model|repository|ctx\.db)\.[\w.]+\.(?:find|findOne|findUnique|findFirst|get)\s*\(|return\s+user\s*;?\s*$|return\s+record\s*;?\s*$|return\s+row\s*;?\s*$`,
		isRegex: true,
		maxMatches: 200
	});
	if (passthroughHits.length === 0) return findings;

	// Explicit field selection / mapping suppresses the concern.
	const selectionHits = await searchRepo({
		query: String.raw`select\s*:\s*\{|pick\s*\(|_\.pick|toGraphQL|serialize\w*\s*\(|map\s*\(\s*\w+\s*=>\s*\(\{|omit\s*\(`,
		isRegex: true,
		maxMatches: 200
	});

	if (selectionHits.length === 0) {
		findings.push({
			id: "GRAPHQL_DEFAULT_RESOLVER_EXPOSURE",
			title: "Resolver returns whole DB/model objects relying on the default field resolver — may expose parent/prototype properties (CWE-200)",
			severity: "HIGH",
			sla: "7d",
			evidence: passthroughHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(passthroughHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Return an explicitly shaped object (or `select`/`pick` only the schema-declared fields) rather than the raw DB row, so the default resolver cannot surface hidden columns (passwordHash, internal flags) or inherited/prototype properties.",
				"Enforce field-level authorization even for scalar leaf fields.",
				"Add tests asserting sensitive columns are never resolvable through the GraphQL schema."
			]
		});
	}

	return findings;
}

async function checkGraphqlVerboseErrors(graphqlInUse: boolean): Promise<Finding[]> {
	if (!graphqlInUse) return [];
	const findings: Finding[] = [];

	// Error masking / formatting that strips internals.
	const maskingHits = await searchRepo({
		query: String.raw`maskErrors|formatError|ApolloServerErrorCode|includeStacktraceInErrorResponses\s*:\s*false|useMaskedErrors|rewriteError|GraphQLError\(`,
		isRegex: true,
		maxMatches: 200
	});
	// Explicit leaking of internals to the client.
	const leakHits = await searchRepo({
		query: String.raw`includeStacktraceInErrorResponses\s*:\s*true|debug\s*:\s*true|stacktrace|originalError\.stack|err\.stack.*response`,
		isRegex: true,
		maxMatches: 200
	});

	const masked = maskingHits.some((m) => /maskErrors|formatError|useMaskedErrors|rewriteError|includeStacktraceInErrorResponses\s*:\s*false/i.test(m.preview));
	const leaks = leakHits.some((m) => /:\s*true|stack/i.test(m.preview));

	if (!masked || leaks) {
		findings.push({
			id: "GRAPHQL_VERBOSE_ERRORS",
			title: "GraphQL errors returned without masking — resolver internals/stack traces leak to clients (CWE-209)",
			severity: "MEDIUM",
			sla: "30d",
			evidence: (leaks ? leakHits : maskingHits).slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set((leaks ? leakHits : maskingHits).slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Mask internal errors in production (e.g. Yoga `maskErrors`, or a `formatError` that returns a generic message + error code) so stack traces and DB errors never reach clients.",
				"Set includeStacktraceInErrorResponses: false / debug: false in production.",
				"Log the full error server-side with a correlation id; return only the id and a safe message to the client."
			]
		});
	}

	return findings;
}


export async function checkGraphQL(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		// 1. Detect if GraphQL is in use. Require an actual server/schema construct or a
		// graphql package import — not the bare word "graphql", which appears in prose,
		// READMEs, and feature lists without any GraphQL server being present.
		const graphqlHits = await searchRepo({
			query:
				String.raw`(?:ApolloServer|makeExecutableSchema|buildSchema|graphqlHTTP|GraphQLSchema|createYoga|mercurius)\s*\(|typeDefs\s*[:=]|from ['"](?:graphql|@apollo/server|apollo-server|graphql-yoga|type-graphql|@graphql-tools)|import\s+(?:graphene|strawberry)`,
			isRegex: true,
			maxMatches: 200
		});

		if (graphqlHits.length === 0) {
			return [];
		}

		const graphqlInUse = true;

		// 2. Introspection check (corrected: fire when NOT explicitly disabled)
		const introspectionFindings = await checkGraphqlIntrospection();
		findings.push(...introspectionFindings);

		// 3. No query depth/complexity limiting
		const depthLimitHits = await searchRepo({
			query: String.raw`depthLimit|complexityLimit|queryComplexity|createComplexityRule|maxDepth`,
			isRegex: true,
			maxMatches: 200
		});
		if (depthLimitHits.length === 0) {
			findings.push({
				id: "GRAPHQL_NO_DEPTH_LIMIT",
				title: "No GraphQL query depth or complexity limiting detected",
				severity: "HIGH",
				requiredActions: [
					"Add graphql-depth-limit or graphql-query-complexity library.",
					"Set max depth ≤ 10 to prevent deeply nested query DoS attacks."
				]
			});
		}

		// 4. No query batching limits
		const batchingHits = await searchRepo({
			query: String.raw`queryBatching|batchRequests|allowBatchedQueries`,
			isRegex: true,
			maxMatches: 200
		});
		if (batchingHits.length === 0) {
			findings.push({
				id: "GRAPHQL_NO_BATCH_LIMIT",
				title: "No GraphQL query batching limits detected",
				severity: "MEDIUM",
				requiredActions: [
					"Configure batching limits to prevent batch-based DoS attacks.",
					"Limit the number of operations per batch request."
				]
			});
		}

		// 5. Schema files found but no auth directives
		const schemaFiles = await fg(["**/*.graphql", "**/*.gql"], {
			ignore: ["**/node_modules/**", "**/.git/**", "**/dist/**"]
		});
		if (schemaFiles.length > 0) {
			let hasAuthDirectives = false;
			for (const file of schemaFiles) {
				try {
					const content = await readFileSafe(file);
					if (/@auth|@authenticated|@hasRole|@requiresAuth|directive.*auth/i.test(content)) {
						hasAuthDirectives = true;
						break;
					}
				} catch {
					// skip unreadable files
				}
			}
			if (!hasAuthDirectives) {
				findings.push({
					id: "GRAPHQL_NO_FIELD_AUTH",
					title: "GraphQL schema files found but no auth directives detected",
					severity: "HIGH",
					files: schemaFiles.slice(0, 10),
					requiredActions: [
						"Add @auth, @authenticated, or @hasRole directives to protect sensitive fields.",
						"Use a GraphQL auth plugin (e.g. graphql-shield) for field-level authorization."
					]
				});
			}
		}

		// 6. N+1 query protection
		const dataloaderHits = await searchRepo({
			query: String.raw`DataLoader|dataloader|BatchLoader`,
			isRegex: true,
			maxMatches: 200
		});
		if (dataloaderHits.length === 0) {
			findings.push({
				id: "GRAPHQL_NO_DATALOADER",
				title: "No DataLoader detected — GraphQL resolvers may be vulnerable to N+1 query attacks",
				severity: "MEDIUM",
				requiredActions: [
					"Add DataLoader (or equivalent batch loader) to batch and cache resolver requests.",
					"Prevent N+1 database queries which can be exploited as a DoS vector."
				]
			});
		}

		// 7. Alias amplification detection
		const aliasFindings = await checkGraphqlAliasAmplification(graphqlInUse);
		findings.push(...aliasFindings);

		// 8. Circular fragment protection
		const fragmentFindings = await checkGraphqlCircularFragments(graphqlInUse);
		findings.push(...fragmentFindings);

		// 9. Resolver injection
		const resolverInjectionFindings = await checkGraphqlResolverInjection();
		findings.push(...resolverInjectionFindings);

		// 10. Alias batching without limit
		const aliasBatchingFindings = await checkGraphqlAliasBatching();
		findings.push(...aliasBatchingFindings);

		// 11-17. Additional GraphQL detections
		findings.push(...await checkGraphqlAuthCacheKey(graphqlInUse));
		findings.push(...await checkGraphqlMutationRateLimit(graphqlInUse));
		findings.push(...await checkGraphqlNestedMutationBudget(graphqlInUse));
		findings.push(...await checkGraphqlSubscriptionLimits(graphqlInUse));
		findings.push(...await checkGraphqlAuthDirectiveInheritance());
		findings.push(...await checkGraphqlDefaultResolverExposure());
		findings.push(...await checkGraphqlVerboseErrors(graphqlInUse));
	} catch (err) {
		console.warn("[checkGraphQL] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
