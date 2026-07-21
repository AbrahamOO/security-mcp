import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "GRAPHQL_INTROSPECTION_ALWAYS_ON",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: true,\n});\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: process.env.NODE_ENV !== "production",\n});\n`
    },
    note: "Positive's `introspection: true,` line has no NODE_ENV/process.env text, so it is an unguarded literal true. Negative uses the rule's own recommended `process.env.NODE_ENV !== 'production'` guard, which contains no literal `true` token, so the `introspection\\s*:\\s*true` scan never matches it."
  },
  {
    ruleId: "GRAPHQL_INTROSPECTION_ENABLED",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n});\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: false,\n});\n`
    },
    note: "Positive has an ApolloServer setup with no introspection setting at all, so both the always-on and disable searches come back empty and this fallback fires. Negative adds a literal `introspection: false`, which the disableHits regex matches directly, so the 'not explicitly disabled' branch never runs."
  },
  {
    ruleId: "GRAPHQL_NO_COMPLEXITY_LIMIT",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport { createComplexityRule } from "graphql-query-complexity";\n\nconst complexityRule = createComplexityRule({ maximumComplexity: 1000 });\nconst server = new ApolloServer({ typeDefs, resolvers, validationRules: [complexityRule] });\n`
    },
    note: "Negative literally contains `createComplexityRule`, one of the complexityHits alternatives, so the 'no complexity limiter' branch is skipped entirely."
  },
  {
    ruleId: "GRAPHQL_ALIAS_AMPLIFICATION",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport { createComplexityRule } from "graphql-query-complexity";\n\nconst complexityRule = createComplexityRule({ maximumComplexity: 1000 });\nconst server = new ApolloServer({ typeDefs, resolvers, validationRules: [complexityRule] });\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport { createComplexityRule, fieldExtensionsEstimator, simpleEstimator } from "graphql-query-complexity";\n\nconst complexityRule = createComplexityRule({\n  maximumComplexity: 1000,\n  estimators: [fieldExtensionsEstimator(), simpleEstimator({ defaultComplexity: 1 })],\n  aliasMultiplier: 2,\n});\nconst server = new ApolloServer({ typeDefs, resolvers, validationRules: [complexityRule] });\n`
    },
    note: "Positive has a complexity limiter (complexityHits > 0) but no alias-cost keyword, so aliasHits is empty and the rule fires. Negative adds a literal `aliasMultiplier: 2,`, one of the aliasHits alternatives, so the same complexity setup no longer counts as unprotected against alias amplification."
  },
  {
    ruleId: "GRAPHQL_RESOLVER_INJECTION",
    check: "graphql",
    positive: {
      file: "src/graphql/types/user.ts",
      content: `import { GraphQLObjectType, GraphQLSchema, GraphQLString } from "graphql";\n\nconst UserType = new GraphQLObjectType({\n  name: "User",\n  fields: {\n    email: {\n      type: GraphQLString,\n      resolve: (parent, args, context) => { return context.db.query(\`SELECT email FROM users WHERE id = \${args.id}\`); }\n    }\n  }\n});\n\nconst schema = new GraphQLSchema({ query: UserType });\n`
    },
    negative: {
      file: "src/graphql/types/user.ts",
      content: `import { GraphQLObjectType, GraphQLSchema, GraphQLString } from "graphql";\n\nconst UserType = new GraphQLObjectType({\n  name: "User",\n  fields: {\n    email: {\n      type: GraphQLString,\n      resolve: (parent, args, context) => { return context.db.query("SELECT email FROM users WHERE id = $1", [args.id]); }\n    }\n  }\n});\n\nconst schema = new GraphQLSchema({ query: UserType });\n`
    },
    note: "Search is line-based, so the whole resolver must sit on one line. Positive's line contains `resolve`, then a `{`, then `SELECT` before the next `}`, then a literal `${args` further along — matching the broad resolverInjectionBroadHits regex. Negative replaces the template-literal interpolation with a parameterized query (`$1` placeholder plus a separate args array), so the literal substring `${args` never appears and neither injection regex matches."
  },
  {
    ruleId: "GRAPHQL_ALIAS_BATCHING",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport depthLimit from "graphql-depth-limit";\n\nconst server = new ApolloServer({ typeDefs, resolvers, validationRules: [depthLimit(10)] });\n`
    },
    note: "Positive has an ApolloServer( call (serverHits) with no maxAliasCount/depthLimit/complexityLimit keyword anywhere (aliasLimitHits empty). Negative adds `depthLimit(10)`, a literal aliasLimitHits alternative, so the finding is suppressed."
  },
  {
    ruleId: "GRAPHQL_CIRCULAR_FRAGMENT_RISK",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport depthLimit from "graphql-depth-limit";\n\nfunction FragmentDepthLimit(context) {\n  return depthLimit(10)(context);\n}\n\nconst server = new ApolloServer({ typeDefs, resolvers, validationRules: [FragmentDepthLimit] });\n`
    },
    note: "Positive has neither `NoSchemaIntrospectionCustomRule`/`maxFragmentDepth`/`FragmentDepthLimit` nor a validationRules mention, so hasFragmentProtection is false. Negative defines and wires in a custom `FragmentDepthLimit` validation rule, whose literal name matches fragmentProtectionHits directly."
  },
  {
    ruleId: "GRAPHQL_AUTH_CACHE_SHARED_KEY",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport responseCachePlugin from "apollo-server-plugin-response-cache";\n\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  plugins: [responseCachePlugin()],\n});\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport responseCachePlugin from "apollo-server-plugin-response-cache";\n\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  plugins: [\n    responseCachePlugin({\n      sessionId: (requestContext) => requestContext.request.http?.headers.get("session-id") || null,\n    }),\n  ],\n});\n`
    },
    note: "Positive enables responseCachePlugin (cacheHits > 0) with no session/user/cacheKey token anywhere, so the cache key is effectively global. Negative passes a `sessionId:` resolver into responseCachePlugin, exactly the fix the rule's requiredActions describe, and the literal `sessionId` token satisfies the per-user scoping check."
  },
  {
    ruleId: "GRAPHQL_MUTATION_NOT_RATE_LIMITED",
    check: "graphql",
    positive: {
      file: "src/graphql/schema.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst typeDefs = "type Mutation { login(username: String!, password: String!): AuthPayload }";\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    negative: {
      file: "src/graphql/schema.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport { createRateLimitDirective } from "graphql-rate-limit-directive";\n\nconst rateLimitDirective = createRateLimitDirective({ identifyContext: (ctx) => ctx.user.id });\n\nconst typeDefs = "directive @rateLimit(max: Int, window: String) on FIELD_DEFINITION type Mutation { login(username: String!, password: String!): AuthPayload @rateLimit(max: 5, window: '1m') }";\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    note: "Positive declares a `type Mutation` block with no rate-limit/cost keyword anywhere. Negative imports and calls `createRateLimitDirective` and applies `@rateLimit` directly to the login mutation, matching mutationLimitHits and the rule's own recommended fix."
  },
  {
    ruleId: "GRAPHQL_NESTED_MUTATION_NO_BUDGET",
    check: "graphql",
    positive: {
      file: "src/graphql/schema.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst resolvers = {\n  Mutation: {\n    createPost: (parent, args, context) => {\n      return context.prisma.post.create({ data: { title: args.title, author: { connectOrCreate: { where: { id: args.authorId }, create: { name: args.authorName } } } } });\n    },\n  },\n};\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    negative: {
      file: "src/graphql/schema.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport { createComplexityRule } from "graphql-query-complexity";\n\nconst maxInputDepth = 5;\nconst complexityRule = createComplexityRule({ maximumComplexity: 500 });\n\nconst resolvers = {\n  Mutation: {\n    createPost: (parent, args, context) => {\n      if (countNestedInputs(args) > maxInputDepth) throw new Error("Nested input too deep");\n      return context.prisma.post.create({ data: { title: args.title, author: { connectOrCreate: { where: { id: args.authorId }, create: { name: args.authorName } } } } });\n    },\n  },\n};\n\nconst server = new ApolloServer({ typeDefs, resolvers, validationRules: [complexityRule] });\n`
    },
    note: "Positive's nested `connectOrCreate` write has no matching budget keyword anywhere (nestedBudgetHits empty). Negative enforces a literal `maxInputDepth` check before the same nested write executes, and also wires a complexity rule, both of which are nestedBudgetHits alternatives."
  },
  {
    ruleId: "GRAPHQL_SUBSCRIPTION_NO_LIMITS",
    check: "graphql",
    positive: {
      file: "src/graphql/subscriptions.ts",
      content: `import { WebSocketServer } from "ws";\nimport { useServer } from "graphql-ws/lib/use/ws";\n\nconst typeDefs = "type Subscription { messageAdded: Message }";\n\nconst wsServer = new WebSocketServer({ server: httpServer, path: "/graphql" });\nuseServer({ schema }, wsServer);\n`
    },
    negative: {
      file: "src/graphql/subscriptions.ts",
      content: `import { WebSocketServer } from "ws";\nimport { useServer } from "graphql-ws/lib/use/ws";\n\nconst typeDefs = "type Subscription { messageAdded: Message }";\n\nconst wsServer = new WebSocketServer({ server: httpServer, path: "/graphql", maxConnections: 1000 });\nuseServer({ schema, connectionInitWaitTimeout: 3000 }, wsServer);\n`
    },
    note: "Positive declares `type Subscription` and wires up graphql-ws with no timeout/cap keyword anywhere (wsLimitHits empty). Negative adds literal `maxConnections` and `connectionInitWaitTimeout`, both wsLimitHits alternatives and both named directly in the rule's requiredActions."
  },
  {
    ruleId: "GRAPHQL_AUTH_DIRECTIVE_NOT_INHERITED",
    check: "graphql",
    positive: {
      file: "src/graphql/schema.graphql",
      content: `# Schema served via: new ApolloServer({ typeDefs, resolvers })\n\ntype Query {\n  me: User @auth\n}\n\nextend type Query {\n  adminStats: AdminStats\n}\n`
    },
    negative: {
      file: "src/graphql/schema.graphql",
      content: `# Schema served via: new ApolloServer({ typeDefs, resolvers })\n\ntype Query {\n  me: User @auth\n}\n\nextend type Query {\n  adminStats: AdminStats @auth\n}\n`
    },
    note: "This check reads the .graphql file as one string (not line-based) and extracts every `extend type ... { ... }` block. Positive's base type uses @auth, but its `extend type Query { adminStats: AdminStats }` block carries no auth directive, so it is flagged as a non-inheriting extension. Negative re-applies `@auth` to the extended field, exactly the fix requiredActions calls for, so no offending block is found. The leading `#` comment supplies the ApolloServer( token the top-level GraphQL-in-use gate requires, without altering the schema being tested."
  },
  {
    ruleId: "GRAPHQL_DEFAULT_RESOLVER_EXPOSURE",
    check: "graphql",
    positive: {
      file: "src/graphql/resolvers/user.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst typeDefs = "type Query { user(id: ID!): User }";\n\nconst resolvers = {\n  Query: {\n    user: async (parent, args, ctx) => {\n      return await ctx.db.user.findUnique({ where: { id: args.id } });\n    },\n  },\n};\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    negative: {
      file: "src/graphql/resolvers/user.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst typeDefs = "type Query { user(id: ID!): User }";\n\nconst resolvers = {\n  Query: {\n    user: async (parent, args, ctx) => {\n      const record = await ctx.db.user.findUnique({ where: { id: args.id } });\n      return record ? { id: record.id, name: record.name, email: record.email } : null;\n    },\n  },\n};\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    note: "Positive's resolver line is `return await ctx.db.user.findUnique(...)`, matching the passthroughHits regex (return + optional await + ctx.db.<field>.findUnique() ) with no select/pick/map shaping anywhere. Negative assigns the DB result to `record` first (so no line starts with `return (await)? ctx.db...`) and returns an explicitly shaped object listing only id/name/email, so passthroughHits is empty and the check returns before ever looking at selectionHits."
  },
  {
    ruleId: "GRAPHQL_VERBOSE_ERRORS",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  debug: true,\n  includeStacktraceInErrorResponses: true,\n});\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  includeStacktraceInErrorResponses: false,\n  formatError: (formattedError, error) => {\n    return { message: "Internal server error", code: formattedError.extensions?.code };\n  },\n});\n`
    },
    note: "Positive sets `debug: true` and `includeStacktraceInErrorResponses: true`, both leakHits matches, with no maskErrors/formatError present, so `masked` is false and the finding fires. Negative sets `includeStacktraceInErrorResponses: false` and defines `formatError` returning a generic message, satisfying `masked` and leaving no `: true`/stack token for `leaks` to catch."
  },
  {
    ruleId: "GRAPHQL_NO_DEPTH_LIMIT",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst typeDefs = "type Query { hello: String }";\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport depthLimit from "graphql-depth-limit";\n\nconst typeDefs = "type Query { hello: String }";\n\nconst server = new ApolloServer({ typeDefs, resolvers, validationRules: [depthLimit(10)] });\n`
    },
    note: "Positive has no depthLimit/complexityLimit/queryComplexity/createComplexityRule/maxDepth keyword anywhere in the repo. Negative wires in `graphql-depth-limit` via `depthLimit(10)`, matching depthLimitHits directly."
  },
  {
    ruleId: "GRAPHQL_NO_BATCH_LIMIT",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst typeDefs = "type Query { hello: String }";\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst typeDefs = "type Query { hello: String }";\n\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  allowBatchedQueries: true,\n  maxBatchSize: 5,\n});\n`
    },
    note: "Positive has no queryBatching/batchRequests/allowBatchedQueries keyword anywhere. Negative sets `allowBatchedQueries: true` alongside an explicit `maxBatchSize: 5` cap, matching batchingHits and reflecting the rule's own remediation to limit operations per batch."
  },
  {
    ruleId: "GRAPHQL_NO_FIELD_AUTH",
    check: "graphql",
    positive: {
      file: "src/graphql/schema.graphql",
      content: `# Schema served via: new ApolloServer({ typeDefs, resolvers })\n\ntype Query {\n  me: User\n  users: [User]\n}\n\ntype User {\n  id: ID!\n  email: String\n  passwordHash: String\n}\n`
    },
    negative: {
      file: "src/graphql/schema.graphql",
      content: `# Schema served via: new ApolloServer({ typeDefs, resolvers })\n\ndirective @auth(requires: Role = USER) on FIELD_DEFINITION\n\nenum Role {\n  USER\n  ADMIN\n}\n\ntype Query {\n  me: User @auth\n  users: [User] @auth(requires: ADMIN)\n}\n\ntype User {\n  id: ID!\n  email: String @auth\n}\n`
    },
    note: "Positive's .graphql schema file has no @auth/@authenticated/@hasRole/@requiresAuth/directive-with-auth token anywhere. Negative declares an `@auth` directive and applies it to every sensitive field. The leading `#` comment supplies the ApolloServer( token the top-level GraphQL-in-use gate needs without changing the schema under test."
  },
  {
    ruleId: "GRAPHQL_NO_DATALOADER",
    check: "graphql",
    positive: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\n\nconst typeDefs = "type Query { user(id: ID!): User }";\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    negative: {
      file: "src/graphql/server.ts",
      content: `import { ApolloServer } from "@apollo/server";\nimport DataLoader from "dataloader";\n\nconst typeDefs = "type Query { user(id: ID!): User }";\n\nconst userLoader = new DataLoader(async (ids) => {\n  const users = await db.user.findMany({ where: { id: { in: ids } } });\n  return ids.map((id) => users.find((u) => u.id === id));\n});\n\nconst server = new ApolloServer({ typeDefs, resolvers });\n`
    },
    note: "Positive has no DataLoader/dataloader/BatchLoader token anywhere. Negative imports `dataloader` and constructs a `new DataLoader(...)` batch loader, matching dataloaderHits directly."
  }
];
