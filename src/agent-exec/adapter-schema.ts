/**
 * Declarative schema for local LLM CLI adapters.
 *
 * The whole point of this module is that an adapter is DATA. security-mcp drives
 * whatever agentic CLI the user already has (claude / codex / copilot / ...), and
 * those CLIs change their flags between releases. If the invocation lived in code,
 * every flag rename would be a patch release. Here it is one JSON edit.
 *
 * Two adapter classes:
 *   A = the CLI owns an agent loop and file tools. Hand it a persona and a task.
 *   B = completion-only (text in, text out). The server supplies the agent loop
 *       itself via the ReAct fallback in ./react/.
 *
 * `_unverified` is a first-class field, not a comment: it lists the config paths that
 * were never tested against a real binary, and executor_status surfaces it verbatim.
 * A reviewer must be able to tell a measured adapter from a plausible guess.
 */
import { z } from "zod";

/** Placeholders substituted into argv. Anything else is a hard config error. */
export const ARGV_TOKENS = [
  "{model}", "{fallbackModel}", "{systemPrompt}", "{systemPromptFile}", "{prompt}",
  "{promptFile}", "{workspaceRoot}", "{runDir}", "{allowedTools}", "{disallowedTools}",
  "{availableTools}", "{excludedTools}", "{jsonSchema}", "{jsonSchemaFile}",
  "{outputFile}", "{maxBudgetUsd}", "{maxCredits}", "{sessionId}", "{mcpConfig}",
  "{agentName}", "{agentRunId}", "{effort}", "{sandbox}", "{addDir}", "{denyUrls}",
  "{secretEnvVars}", "{transcriptFile}", "{logDir}"
] as const;

const TOKEN_RE = /\{[a-zA-Z][a-zA-Z0-9]*\}/g;

/** Every `{token}` present in a template string. */
export function tokensIn(value: string): string[] {
  return value.match(TOKEN_RE) ?? [];
}

const nonEmpty = z.string().min(1);

export const DetectSchema = z.object({
  /**
   * Empty is legal and meaningful: the `generic` fallback has no fixed binary name
   * and is bound at runtime from SECURITY_AGENT_CLI, so it is simply never
   * auto-detected. Any adapter with no binaries is skipped by detectProviders.
   */
  binaries: z.array(nonEmpty).default([]),
  versionArgs: z.array(z.string()).default(["--version"]),
  versionRegex: z.string().default("(\\d+\\.\\d+\\.\\d+)"),
  minVersion: z.string().optional(),
  /**
   * Extra glob roots to search beyond PATH. Both codex and copilot were invisible to
   * a PATH-only scan on the development machine: codex ships inside a VS Code
   * extension bundle, copilot as an npm global symlink created after first scan.
   */
  extraSearchGlobs: z.array(z.string()).default([])
});

export const AuthProbeSchema = z.object({
  mode: z.enum(["none", "probe", "env"]),
  /** True when the probe costs zero model tokens. Only zero-cost probes run per-run. */
  zeroCost: z.boolean().default(true),
  probeArgv: z.array(z.string()).default([]),
  probeParse: z.object({
    format: z.enum(["json", "text"]).default("text"),
    loggedInPath: z.string().optional(),
    /** Boolean for json format; regex source for text format. */
    expect: z.union([z.boolean(), z.string()]).optional(),
    detailPaths: z.record(z.string()).default({})
  }).optional(),
  /** Env vars consulted for auth, in precedence order. */
  envVars: z.array(nonEmpty).default([]),
  /**
   * Credential env vars a CHILD of this adapter may receive. Everything else is
   * stripped. A blanket strip of GITHUB_TOKEN would break Copilot, whose headless
   * precedence is COPILOT_GITHUB_TOKEN > GH_TOKEN > GITHUB_TOKEN — so passthrough is
   * per-adapter, and a Claude child never sees a GitHub token.
   */
  childCredentialEnv: z.array(nonEmpty).default([])
});

export const ModelsSchema = z.object({
  flag: z.string().nullable().default(null),
  flagStyle: z.enum(["separate", "equals", "positional"]).default("separate"),
  default: z.string().optional(),
  contextTokens: z.number().int().positive().default(128000),
  /** capabilityTier -> CLI model alias. Registry model IDs are never passed verbatim. */
  tiers: z.object({
    advanced: z.string().optional(),
    standard: z.string().optional(),
    light: z.string().optional()
  }).default({}),
  /** capabilityTier -> CLI effort level, when the CLI exposes one. */
  effortFlag: z.string().nullable().default(null),
  effortTiers: z.object({
    advanced: z.string().optional(),
    standard: z.string().optional(),
    light: z.string().optional()
  }).default({})
});

export const InvokeSchema = z.object({
  /** Base argv, always emitted. Tokens are substituted per element. */
  argv: z.array(z.string()).default([]),
  /**
   * Named flag groups appended ONLY when every token inside resolves non-empty.
   * That is what makes "this CLI has no budget flag" a config fact, not a branch.
   */
  optionalGroups: z.record(z.array(z.string())).default({}),
  cwd: z.string().default("{workspaceRoot}"),
  env: z.record(z.string()).default({})
});

export const AdapterSchema = z.object({
  label: nonEmpty,
  class: z.enum(["A", "B"]),
  notes: z.string().default(""),
  _unverified: z.array(z.string()).default([]),
  detect: DetectSchema,
  auth: AuthProbeSchema,
  models: ModelsSchema.default({}),
  prompt: z.object({
    delivery: z.enum(["stdin", "argv", "file"]).default("stdin"),
    fileExt: z.string().default(".md"),
    /** argv+env share ~1MB on macOS, and argv is visible in `ps`. */
    maxArgvBytes: z.number().int().positive().default(131072)
  }).default({}),
  systemPrompt: z.object({
    /**
     * "append" preserves the CLI's own system prompt, which is what teaches the model
     * to use its file tools well. Replacing it is the likeliest cause of an agent that
     * "runs" but reads nothing. Class B has no such flag, hence "prepend".
     */
    mode: z.enum(["flag", "flagFile", "append", "prepend", "none"]).default("prepend"),
    flag: z.string().nullable().default(null),
    appendFlag: z.string().nullable().default(null),
    prependTemplate: z.string().default("{systemPrompt}\n\n---\n\n{prompt}")
  }).default({}),
  invoke: InvokeSchema.default({}),
  structuredOutput: z.object({
    mode: z.enum(["jsonSchemaFlag", "none"]).default("none"),
    flag: z.string().nullable().default(null),
    schemaDelivery: z.enum(["argv", "file"]).default("argv"),
    /** Whether the parsed result field is a JSON-encoded string needing a second parse. */
    resultIsString: z.boolean().default(false),
    /** Path the CLI writes its final message to, when it supports one. */
    outputFileFlag: z.string().nullable().default(null),
    /**
     * Where the structured payload lands when a schema IS supplied — which is often a
     * DIFFERENT field from the free-text result. Claude Code, for example, leaves
     * `result` as an empty string and puts the object in `structured_output`; reading
     * `result` yields "" and looks exactly like an agent that produced nothing.
     */
    resultPath: z.string().nullable().default(null)
  }).default({}),
  outputParse: z.object({
    format: z.enum(["text", "json", "jsonl"]).default("text"),
    /** For jsonl: pick the event whose `path` equals `equals`. */
    jsonlSelector: z.object({ path: z.string(), equals: z.string() }).optional(),
    resultPath: z.string().nullable().default(null),
    isErrorPath: z.string().nullable().default(null),
    errorPath: z.string().nullable().default(null),
    stripPrefixes: z.array(z.string()).default([])
  }).default({}),
  usage: z.object({
    inputTokensPath: z.string().optional(),
    outputTokensPath: z.string().optional(),
    cacheReadPath: z.string().optional(),
    costUsdPath: z.string().optional(),
    sessionIdPath: z.string().optional(),
    durationMsPath: z.string().optional(),
    permissionDenialsPath: z.string().optional(),
    /**
     * Object keyed by the REAL model id the provider served (e.g. Claude Code's
     * `modelUsage`). The alias we requested ("opus") is not evidence of what actually
     * ran; this is, and a reviewer asking "which model produced this finding" needs it.
     */
    modelUsagePath: z.string().optional(),
    /** Direct path to a plain model-id string, when the CLI reports one that way. */
    modelPath: z.string().optional()
  }).default({}),
  tools: z.object({
    supportsFileTools: z.boolean().default(false),
    allowFlag: z.string().nullable().default(null),
    denyFlag: z.string().nullable().default(null),
    availableFlag: z.string().nullable().default(null),
    excludedFlag: z.string().nullable().default(null),
    separator: z.enum(["comma", "space", "repeat"]).default("space"),
    readOnly: z.array(z.string()).default([]),
    write: z.array(z.string()).default([]),
    network: z.array(z.string()).default([]),
    /** Never grantable: sub-agent spawning would defeat the recursion guard. */
    forbidden: z.array(z.string()).default([])
  }).default({}),
  permission: z.object({
    flag: z.string().nullable().default(null),
    auditValue: z.string().nullable().default(null),
    applyValue: z.string().nullable().default(null),
    addDirFlag: z.string().nullable().default(null),
    denyUrlFlag: z.string().nullable().default(null),
    secretEnvVarsFlag: z.string().nullable().default(null),
    /** Flags that are ALWAYS forbidden for this adapter, asserted in tests. */
    bannedArgs: z.array(z.string()).default([])
  }).default({}),
  recursionGuard: z.object({
    env: z.record(z.string()).default({}),
    denyTools: z.array(z.string()).default([]),
    isolationArgs: z.array(z.string()).default([])
  }).default({}),
  limits: z.object({
    timeoutMs: z.number().int().positive().default(1800000),
    maxConcurrent: z.number().int().min(1).max(16).default(2),
    budgetFlag: z.string().nullable().default(null),
    budgetPerAgentUsd: z.number().positive().optional(),
    maxOutputBytes: z.number().int().positive().default(33554432)
  }).default({}),
  rateLimit: z.object({
    exitCodes: z.array(z.number().int()).default([]),
    stderrPatterns: z.array(z.string()).default([]),
    jsonErrorPatterns: z.array(z.string()).default([]),
    backoff: z.object({
      baseMs: z.number().int().positive().default(30000),
      maxMs: z.number().int().positive().default(900000),
      factor: z.number().positive().default(2),
      jitter: z.number().min(0).max(1).default(0.25)
    }).default({})
  }).default({}),
  /** Class B only: server-driven ReAct loop bounds. */
  react: z.object({
    maxIterations: z.number().int().positive().default(24),
    contextTokens: z.number().int().positive().default(32768),
    reserveOutputTokens: z.number().int().positive().default(1024),
    observationBudgetChars: z.number().int().positive().default(12000),
    maxNudges: z.number().int().min(0).default(3),
    toolsEnabled: z.array(z.string()).default(["read_file", "search", "glob", "done"])
  }).optional()
});

export type AdapterConfig = z.infer<typeof AdapterSchema>;

export const AdapterRegistrySchema = z.object({
  version: z.string(),
  selection: z.object({
    overrideEnv: z.string().default("SECURITY_AGENT_CLI"),
    order: z.array(nonEmpty).default([]),
    fallback: z.string().default("generic")
  }),
  adapters: z.record(AdapterSchema)
});

export type AdapterRegistry = z.infer<typeof AdapterRegistrySchema>;

/**
 * Reject unknown `{tokens}` at LOAD time rather than emitting a literal "{foo}" into
 * argv at run time, where it would reach the CLI as a nonsense argument and produce a
 * confusing downstream failure hours into a run.
 */
export function assertKnownTokens(registry: AdapterRegistry): void {
  const known = new Set<string>(ARGV_TOKENS);
  const problems: string[] = [];
  for (const [id, adapter] of Object.entries(registry.adapters)) {
    const templates: [string, string[]][] = [
      ["invoke.argv", adapter.invoke.argv],
      ["invoke.cwd", [adapter.invoke.cwd]],
      ["invoke.env", Object.values(adapter.invoke.env)],
      ["systemPrompt.prependTemplate", [adapter.systemPrompt.prependTemplate]]
    ];
    for (const [group, args] of Object.entries(adapter.invoke.optionalGroups)) {
      templates.push([`invoke.optionalGroups.${group}`, args]);
    }
    for (const [where, values] of templates) {
      for (const value of values) {
        for (const token of tokensIn(value)) {
          if (!known.has(token)) problems.push(`${id}.${where}: unknown token ${token}`);
        }
      }
    }
  }
  if (problems.length > 0) {
    throw new Error(`Invalid agent CLI registry — unknown argv token(s):\n  ${problems.join("\n  ")}`);
  }
}
