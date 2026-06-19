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
	} catch (err) {
		console.warn("[checkGraphQL] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
