/**
 * GraphQL security checks.
 * Detects GraphQL schemas and validates security controls.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

export async function checkGraphQL(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		// 1. Detect if GraphQL is in use
		const graphqlHits = await searchRepo({
			query: "graphql|typeDefs|makeExecutableSchema|gql`|@graphql|graphene|strawberry",
			isRegex: true,
			maxMatches: 200
		});

		if (graphqlHits.length === 0) {
			return [];
		}

		// 2. Introspection enabled in prod
		const introspectionHits = await searchRepo({
			query: String.raw`introspection.*true|disableIntrospection.*false|GraphQLSchema.*introspection`,
			isRegex: true,
			maxMatches: 200
		});
		if (introspectionHits.length > 0) {
			findings.push({
				id: "GRAPHQL_INTROSPECTION_ENABLED",
				title: "GraphQL introspection is enabled — exposes full schema to attackers",
				severity: "HIGH",
				evidence: introspectionHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(introspectionHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Disable introspection in non-dev environments.",
					"Use persisted queries instead of ad-hoc introspection in production."
				]
			});
		}

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
	} catch (err) {
		console.warn("[checkGraphQL] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
