import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";
import { searchRepo } from "../../repo/search.js";

const SOURCE_FILE_RE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|java|json)$/i;

// ─── Existing check regexes ────────────────────────────────────────────────
const SCHEMA_RE = /zod\.object\(|outputSchema|json_schema|JSON schema/i;
const TOOL_RE = /\bfunction_call\b|\btools?\b\s*[:=]/i;
const INJECTION_RE = /system prompt|developer message|ignore previous|prompt injection/i;

// ─── AI_PROMPT_CONCAT ────────────────────────────────────────────────────────
// System prompt built by direct concatenation with user input.
// Split into two patterns to keep each under the complexity threshold.
const PROMPT_CONCAT_A_RE = /systemPrompt\s*\+\s*\w+Input|`\$\{systemPrompt\}\$\{user/i;
const PROMPT_CONCAT_B_RE = /`\$\{system[^}]*\}\$\{[^}]*message|\[\s*\.{3}systemParts/i;

// ─── AI_OUTPUT_TO_EVAL ───────────────────────────────────────────────────────
// LLM response fed into eval / exec / spawn.
// Two regexes: one for eval/exec, one for spawn, to stay under complexity limit.
const OUTPUT_TO_EVAL_A_RE = /eval\s*\([^)]*(?:response|completion|output|result)/i;
const OUTPUT_TO_EVAL_B_RE = /exec\s*\([^)]*(?:response|completion|output)|spawn\s*\([^)]*(?:response|output)/i;

// ─── AI_PII_IN_PROMPT ────────────────────────────────────────────────────────
// PII field names embedded in prompt template literals.
// Split by direction (PII-then-prompt vs prompt-then-PII) to reduce per-regex complexity.
const PII_FIELDS_FRAG = "ssn|socialSecurity|cardNumber|cvv|password|secret";
const PROMPT_KEYS_FRAG = "messages|prompt|system";
const PII_IN_PROMPT_A_RE = new RegExp(
  "`[^`]*(?:" + PII_FIELDS_FRAG + ")[^`]*`[^`]*(?:" + PROMPT_KEYS_FRAG + ")",
  "i"
);
const PII_IN_PROMPT_B_RE = new RegExp(
  "(?:" + PROMPT_KEYS_FRAG + ")[^`]*`[^`]*(?:" + PII_FIELDS_FRAG + ")[^`]*`",
  "i"
);

// ─── AI_RATE_LIMIT_MISSING ───────────────────────────────────────────────────
const AI_ROUTE_HANDLER_RE = /(?:router|app)\s*\.\s*(?:get|post|put|patch|delete)\s*\(/i;
const RATE_LIMIT_PRESENT_RE = /rateLimit|rate_limit|rateLimiter|ThrottlerGuard|upstash\/ratelimit/i;
const AI_SDK_CALL_RE = /openai\.|anthropic\.|\.chat\.completions\.create|\.messages\.create/i;

// ─── AI_RAG_AUTHZ_MISSING ────────────────────────────────────────────────────
const VECTOR_SEARCH_RE = /similarity_search|vectorSearch|\.retrieve\s*\(|\.search\s*\([^)]*embed/i;
const AUTHZ_NEARBY_RE = /userId|tenantId|authorize|hasPermission|checkAccess/i;

// ─── AI_TOOL_ARGS_UNVALIDATED ────────────────────────────────────────────────
const TOOL_ARGS_HANDLER_RE = /(?:function_call|tool_call|toolCall)[^}]*(?:arguments|args)\s*[:=]/i;
const TOOL_ARGS_VALIDATED_RE = /\.parse\s*\(|z\.object|\.safeParse|ajv\.validate|joi\.validate/i;

// ─── AI_STREAMING_NO_TIMEOUT ─────────────────────────────────────────────────
const STREAMING_CALL_RE = /stream\s*:\s*true|\.stream\s*\(/i;
const STREAM_SAFEGUARD_RE = /AbortController|AbortSignal|setTimeout|signal\s*:|timeout\s*:/i;

// ─── AI_MULTI_TENANT_CONTEXT_LEAK ────────────────────────────────────────────
const CONTEXT_BUILD_RE = /(?:history|context|messages)\s*\.push\s*\(|\.concat\s*\([^)]*message/i;
const TENANT_FILTER_RE = /userId|tenantId|orgId|accountId/i;

// ─── AI_AGENT_UNBOUNDED_LOOP ──────────────────────────────────────────────────
const AGENT_LOOP_RE = /while\s*\([^)]*tool_calls|for\s*\([^)]*agent.*step|while\s*\([^)]*has_more/i;
const ITERATION_CAP_RE = /maxIterations|max_iterations|MAX_STEPS|iteration\s*[<>]=?\s*\d/i;

// ─── AI_SYSTEM_PROMPT_HARDCODED ───────────────────────────────────────────────
// Secrets embedded inside template-literal system prompts.
// Split across two regexes to stay under complexity threshold.
const HARDCODED_SECRET_A_RE = /`[^`]*(?:OPENAI_API_KEY|sk-[A-Z0-9]{20,})[^`]*`/i;
const HARDCODED_SECRET_B_RE = /`[^`]*(?:password|secret)\s*=\s*['"][^'"]+['"][^`]*`/i;

// ─── AI_MODEL_VERSION_UNPINNED ────────────────────────────────────────────────
const MODEL_UNPINNED_RE = /['"](?:gpt-4|gpt-3\.5-turbo|claude-3-(?:opus|sonnet|haiku)|claude-2)['"]/i;
const MODEL_PINNED_RE = /['"](?:gpt-4-\d{4}|gpt-3\.5-turbo-\d{4}|claude-(?:opus|sonnet|haiku)-\d|claude-sonnet-\d-\d)['"]/i;

// ─── AI_LANGCHAIN_DANGEROUS_TOOLS ─────────────────────────────────────────────
const LANGCHAIN_DANGEROUS_RE = /PythonREPLTool|BashTool|ShellTool|SystemCommandTool/i;

// ─── AI_HUGGINGFACE_UNPINNED ──────────────────────────────────────────────────
const HF_PRETRAINED_RE = /from_pretrained\s*\(/i;
const HF_REVISION_RE = /revision\s*=/i;

// ─── AI_EMBEDDING_UNAUTH ──────────────────────────────────────────────────────
const VECTOR_CLIENT_RE = /new\s+(?:PineconeClient|Pinecone|Chroma|QdrantClient|WeaviateClient|MilvusClient)\s*\(/i;
const VECTOR_AUTH_RE = /api_key|apiKey|auth_token|authToken|environment\s*=|username\s*=/i;

// ─── AI_FINE_TUNE_DATA_PII ────────────────────────────────────────────────────
const FINE_TUNE_RE = /fine.?tun(?:ing|e)|finetune|\.createFineTuningJob|openai\.fineTuning/i;
const PII_SCRUB_RE = /scrub|redact|anonymize|presidio|pii.?filter|removePii/i;

// ─── AI_FUNCTION_DESCRIPTION_USER_INPUT ───────────────────────────────────────
// Tool description field built from user-controlled data.
// Split into template-literal variant and string-concat variant.
const FUNC_DESC_TEMPLATE_RE = /description\s*:\s*`[^`]*\$\{(?:user|req\.|input\.|body\.)[^}]*\}/i;
const FUNC_DESC_CONCAT_RE = /description\s*:\s*['"][^'"]*['"]\s*\+\s*(?:user|req\.|input\.)/i;

// ─── AI_MISSING_CONTENT_FILTER ────────────────────────────────────────────────
const AI_OUTPUT_DIRECT_RE = /(?:completion|response|message)\.content.*res\.(?:json|send|write)/i;
const CONTENT_FILTER_RE = /moderate|moderation|content.?filter|openai\.moderations|guardrail|shield/i;

// ─── Glob ignore list ─────────────────────────────────────────────────────────
const GLOB_IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/fixtures/**",
  "**/.mcp/**",
  "**/.mcp/reviews/**",
  "**/.mcp/reports/**"
];

// ─── Evidence accumulator ─────────────────────────────────────────────────────
type FileEvidence = {
  toolFiles: string[];
  injectionFiles: string[];
  promptConcatFiles: string[];
  evalOutputFiles: string[];
  piiPromptFiles: string[];
  rateLimitMissingFiles: string[];
  ragNoAuthzFiles: string[];
  toolArgsUnvalidatedFiles: string[];
  streamNoTimeoutFiles: string[];
  multiTenantLeakFiles: string[];
  agentUnboundedFiles: string[];
  hardcodedSecretPromptFiles: string[];
  modelUnpinnedFiles: string[];
  langchainDangerousFiles: string[];
  hfUnpinnedFiles: string[];
  vectorUnauthFiles: string[];
  fineTunePiiFiles: string[];
  funcDescUserInputFiles: string[];
  contentFilterMissingFiles: string[];
  schemaDetected: boolean;
};

function makeEvidence(): FileEvidence {
  return {
    toolFiles: [],
    injectionFiles: [],
    promptConcatFiles: [],
    evalOutputFiles: [],
    piiPromptFiles: [],
    rateLimitMissingFiles: [],
    ragNoAuthzFiles: [],
    toolArgsUnvalidatedFiles: [],
    streamNoTimeoutFiles: [],
    multiTenantLeakFiles: [],
    agentUnboundedFiles: [],
    hardcodedSecretPromptFiles: [],
    modelUnpinnedFiles: [],
    langchainDangerousFiles: [],
    hfUnpinnedFiles: [],
    vectorUnauthFiles: [],
    fineTunePiiFiles: [],
    funcDescUserInputFiles: [],
    contentFilterMissingFiles: [],
    schemaDetected: false
  };
}

// ─── Window-based context check ───────────────────────────────────────────────
/**
 * Returns true if `targetRe` matches within `windowSize` lines around any line
 * matched by `anchorRe`. Used to detect paired patterns (e.g. search + authz).
 */
function windowMatch(
  lines: string[],
  anchorRe: RegExp,
  targetRe: RegExp,
  windowSize: number
): boolean {
  for (let i = 0; i < lines.length; i++) {
    if (!anchorRe.test(lines[i])) continue;
    const start = Math.max(0, i - windowSize);
    const end = Math.min(lines.length - 1, i + windowSize);
    for (let j = start; j <= end; j++) {
      if (targetRe.test(lines[j])) return true;
    }
  }
  return false;
}

// ─── Scan helpers (split to keep cognitive complexity under threshold) ─────────

function scanExisting(file: string, text: string, ev: FileEvidence): void {
  if (SCHEMA_RE.test(text)) ev.schemaDetected = true;
  if (TOOL_RE.test(text)) ev.toolFiles.push(file);
  if (INJECTION_RE.test(text)) ev.injectionFiles.push(file);
}

function scanPromptAndEval(file: string, text: string, ev: FileEvidence): void {
  if (PROMPT_CONCAT_A_RE.test(text) || PROMPT_CONCAT_B_RE.test(text)) {
    ev.promptConcatFiles.push(file);
  }
  if (OUTPUT_TO_EVAL_A_RE.test(text) || OUTPUT_TO_EVAL_B_RE.test(text)) {
    ev.evalOutputFiles.push(file);
  }
  if (PII_IN_PROMPT_A_RE.test(text) || PII_IN_PROMPT_B_RE.test(text)) {
    ev.piiPromptFiles.push(file);
  }
  if (FUNC_DESC_TEMPLATE_RE.test(text) || FUNC_DESC_CONCAT_RE.test(text)) {
    ev.funcDescUserInputFiles.push(file);
  }
}

function scanRateLimitAndContent(file: string, text: string, ev: FileEvidence): void {
  const hasAiCall = AI_SDK_CALL_RE.test(text);
  if (AI_ROUTE_HANDLER_RE.test(text) && hasAiCall && !RATE_LIMIT_PRESENT_RE.test(text)) {
    ev.rateLimitMissingFiles.push(file);
  }
  if (hasAiCall && AI_OUTPUT_DIRECT_RE.test(text) && !CONTENT_FILTER_RE.test(text)) {
    ev.contentFilterMissingFiles.push(file);
  }
}

function scanContextAndLoop(file: string, text: string, lines: string[], ev: FileEvidence): void {
  if (VECTOR_SEARCH_RE.test(text) && !windowMatch(lines, VECTOR_SEARCH_RE, AUTHZ_NEARBY_RE, 10)) {
    ev.ragNoAuthzFiles.push(file);
  }
  if (TOOL_ARGS_HANDLER_RE.test(text) && !TOOL_ARGS_VALIDATED_RE.test(text)) {
    ev.toolArgsUnvalidatedFiles.push(file);
  }
  if (STREAMING_CALL_RE.test(text) && !windowMatch(lines, STREAMING_CALL_RE, STREAM_SAFEGUARD_RE, 20)) {
    ev.streamNoTimeoutFiles.push(file);
  }
  if (CONTEXT_BUILD_RE.test(text) && !windowMatch(lines, CONTEXT_BUILD_RE, TENANT_FILTER_RE, 15)) {
    ev.multiTenantLeakFiles.push(file);
  }
  if (AGENT_LOOP_RE.test(text) && !windowMatch(lines, AGENT_LOOP_RE, ITERATION_CAP_RE, 10)) {
    ev.agentUnboundedFiles.push(file);
  }
}

function scanModelsAndSupply(file: string, text: string, lines: string[], ev: FileEvidence): void {
  if (HARDCODED_SECRET_A_RE.test(text) || HARDCODED_SECRET_B_RE.test(text)) {
    ev.hardcodedSecretPromptFiles.push(file);
  }
  if (MODEL_UNPINNED_RE.test(text) && !MODEL_PINNED_RE.test(text)) {
    ev.modelUnpinnedFiles.push(file);
  }
  if (LANGCHAIN_DANGEROUS_RE.test(text)) {
    ev.langchainDangerousFiles.push(file);
  }
  if (HF_PRETRAINED_RE.test(text) && !windowMatch(lines, HF_PRETRAINED_RE, HF_REVISION_RE, 5)) {
    ev.hfUnpinnedFiles.push(file);
  }
  if (VECTOR_CLIENT_RE.test(text) && !windowMatch(lines, VECTOR_CLIENT_RE, VECTOR_AUTH_RE, 10)) {
    ev.vectorUnauthFiles.push(file);
  }
  if (FINE_TUNE_RE.test(text) && !PII_SCRUB_RE.test(text)) {
    ev.fineTunePiiFiles.push(file);
  }
}

/** Single-pass per-file scanner — delegates to focused helpers. */
function scanFile(file: string, text: string, ev: FileEvidence): void {
  const lines = text.split("\n");
  scanExisting(file, text, ev);
  scanPromptAndEval(file, text, ev);
  scanRateLimitAndContent(file, text, ev);
  scanContextAndLoop(file, text, lines, ev);
  scanModelsAndSupply(file, text, lines, ev);
}

// ─── Finding builders (split to keep checkAi cognitive complexity low) ─────────

function buildBaseFindings(ev: FileEvidence, findings: Finding[]): void {
  if (ev.toolFiles.length > 0 && !ev.schemaDetected) {
    findings.push({
      id: "AI_OUTPUT_BOUNDS_MISSING",
      title: "AI/tooling present but bounded output (schema validation) not detected",
      severity: "HIGH",
      evidence: ev.toolFiles,
      requiredActions: [
        "Enforce bounded outputs via JSON schema validation for every AI response used by code.",
        "Add prompt-injection defenses: input sanitization, tool allowlists, deny-by-default tool router, and sensitive data redaction."
      ]
    });
  }
  if (ev.injectionFiles.length > 0) {
    findings.push({
      id: "AI_INJECTION_CUES",
      title: "Potential prompt injection cues detected. Requires explicit mitigations and tests.",
      severity: "MEDIUM",
      evidence: ev.injectionFiles,
      requiredActions: [
        "Add multi-layer prompt-injection protection: instruction hierarchy enforcement, content isolation, tool gating, and output validation.",
        "Add a red-team test harness with injection payloads and exfil attempts."
      ]
    });
  }
}

function buildPromptAndEvalFindings(ev: FileEvidence, findings: Finding[]): void {
  if (ev.promptConcatFiles.length > 0) {
    findings.push({
      id: "AI_PROMPT_CONCAT",
      title: "System prompt constructed by string concatenation with user-controlled input",
      severity: "CRITICAL",
      evidence: ev.promptConcatFiles,
      requiredActions: [
        "Never concatenate user input directly into the system prompt. Use a strict template with clearly delimited user sections.",
        "Sanitize and escape user-supplied content before embedding it anywhere in the prompt.",
        "Implement instruction-hierarchy enforcement so user content cannot override system instructions."
      ]
    });
  }
  if (ev.evalOutputFiles.length > 0) {
    findings.push({
      id: "AI_OUTPUT_TO_EVAL",
      title: "LLM output passed to eval(), exec(), or spawn() — arbitrary code execution risk",
      severity: "CRITICAL",
      evidence: ev.evalOutputFiles,
      requiredActions: [
        "Never pass AI-generated text to eval(), exec(), or spawn(). Parse structured output instead.",
        "If code execution from AI output is required, use a sandboxed execution environment (e2b, Firecracker, WASM) with strict allow-lists.",
        "Validate and parse AI output through a strict JSON schema before any programmatic use."
      ]
    });
  }
  if (ev.piiPromptFiles.length > 0) {
    findings.push({
      id: "AI_PII_IN_PROMPT",
      title: "PII field names detected inside AI prompt template literals",
      severity: "HIGH",
      evidence: ev.piiPromptFiles,
      requiredActions: [
        "Remove PII (SSN, card numbers, CVV, passwords) from prompt templates. Pass only anonymized or tokenized references.",
        "Implement a PII scrubber (e.g., Microsoft Presidio) at the prompt construction boundary.",
        "Audit all prompt templates for data minimization compliance (GDPR Art. 5, PCI DSS Req. 3)."
      ]
    });
  }
  if (ev.funcDescUserInputFiles.length > 0) {
    findings.push({
      id: "AI_FUNCTION_DESCRIPTION_USER_INPUT",
      title: "Tool/function schema 'description' field constructed from user-controlled input",
      severity: "HIGH",
      evidence: ev.funcDescUserInputFiles,
      requiredActions: [
        "Never embed user-supplied strings in tool or function description fields — this enables prompt injection via schema poisoning.",
        "Define tool descriptions as static compile-time constants only.",
        "Validate that tool schemas are constructed from trusted, server-controlled values before sending to the LLM."
      ]
    });
  }
}

function buildAccessFindings(ev: FileEvidence, findings: Finding[]): void {
  if (ev.rateLimitMissingFiles.length > 0) {
    findings.push({
      id: "AI_RATE_LIMIT_MISSING",
      title: "AI API route handlers detected without rate limiting middleware",
      severity: "HIGH",
      evidence: ev.rateLimitMissingFiles,
      requiredActions: [
        "Apply rate limiting (e.g., express-rate-limit, Upstash Ratelimit) to every route that triggers an LLM call.",
        "Set per-user and per-IP token budgets to prevent abuse and runaway inference costs.",
        "Add alerting when per-user token consumption exceeds defined thresholds."
      ]
    });
  }
  if (ev.ragNoAuthzFiles.length > 0) {
    findings.push({
      id: "AI_RAG_AUTHZ_MISSING",
      title: "Vector / similarity search results used without authorization check",
      severity: "HIGH",
      evidence: ev.ragNoAuthzFiles,
      requiredActions: [
        "Filter vector search results by userId/tenantId before passing them to the LLM context.",
        "Apply row-level security or namespace isolation in your vector database (Pinecone namespaces, Qdrant payload filters).",
        "Never inject retrieved documents into the prompt without confirming the requesting user has read access to those documents."
      ]
    });
  }
  if (ev.toolArgsUnvalidatedFiles.length > 0) {
    findings.push({
      id: "AI_TOOL_ARGS_UNVALIDATED",
      title: "Tool/function call arguments handled without schema validation",
      severity: "HIGH",
      evidence: ev.toolArgsUnvalidatedFiles,
      requiredActions: [
        "Validate every tool-call argument object through a Zod schema (z.parse) before executing the tool.",
        "Reject or throw on unexpected keys — use z.object().strict() to disallow additional properties.",
        "Log validation failures as security events; repeated failures may indicate adversarial tool-call injection."
      ]
    });
  }
  if (ev.multiTenantLeakFiles.length > 0) {
    findings.push({
      id: "AI_MULTI_TENANT_CONTEXT_LEAK",
      title: "LLM conversation context / history built without tenant isolation",
      severity: "CRITICAL",
      evidence: ev.multiTenantLeakFiles,
      requiredActions: [
        "Filter all history and context arrays by userId/tenantId/orgId before building the prompt.",
        "Store conversation history in tenant-scoped keys (e.g., Redis key prefix includes tenantId).",
        "Add an integration test that verifies cross-tenant context cannot bleed between requests."
      ]
    });
  }
}

function buildRuntimeFindings(ev: FileEvidence, findings: Finding[]): void {
  if (ev.streamNoTimeoutFiles.length > 0) {
    findings.push({
      id: "AI_STREAMING_NO_TIMEOUT",
      title: "Streaming LLM calls detected without AbortController or timeout",
      severity: "MEDIUM",
      evidence: ev.streamNoTimeoutFiles,
      requiredActions: [
        "Attach an AbortController signal to every streaming call: pass `signal: controller.signal` and call controller.abort() after a timeout.",
        "Set a maximum stream duration (e.g., 60 s) and enforce it server-side to prevent resource exhaustion.",
        "Ensure clients handle stream interruptions gracefully without leaking connections or memory."
      ]
    });
  }
  if (ev.agentUnboundedFiles.length > 0) {
    findings.push({
      id: "AI_AGENT_UNBOUNDED_LOOP",
      title: "Agentic loop detected without a maximum iteration / step limit",
      severity: "HIGH",
      evidence: ev.agentUnboundedFiles,
      requiredActions: [
        "Define a MAX_ITERATIONS constant and break or throw when the limit is exceeded.",
        "Track cumulative token consumption across iterations and enforce a hard budget.",
        "Log iteration counts and alert when agents consistently approach the limit (may indicate prompt logic errors)."
      ]
    });
  }
  if (ev.contentFilterMissingFiles.length > 0) {
    findings.push({
      id: "AI_MISSING_CONTENT_FILTER",
      title: "LLM output sent directly to client without content moderation or filtering",
      severity: "MEDIUM",
      evidence: ev.contentFilterMissingFiles,
      requiredActions: [
        "Pass all LLM outputs through a moderation layer (openai.moderations.create, Anthropic's safety guidelines, or a custom classifier) before returning to the client.",
        "Define and enforce an output policy: refuse, truncate, or warn on policy-violating content.",
        "Log moderation decisions (without PII) for audit and model safety feedback purposes."
      ]
    });
  }
}

function buildSupplyChainFindings(ev: FileEvidence, findings: Finding[]): void {
  if (ev.hardcodedSecretPromptFiles.length > 0) {
    findings.push({
      id: "AI_SYSTEM_PROMPT_HARDCODED",
      title: "Hardcoded secrets or credentials detected inside system prompt template literals",
      severity: "MEDIUM",
      evidence: ev.hardcodedSecretPromptFiles,
      requiredActions: [
        "Move all secrets to environment variables and inject them at runtime — never embed in source.",
        "Rotate any credentials that may have been exposed via the prompt (they may appear in LLM logs or responses).",
        "Run a secret-scanning pre-commit hook (e.g., gitleaks, truffleHog) to catch future occurrences."
      ]
    });
  }
  if (ev.modelUnpinnedFiles.length > 0) {
    findings.push({
      id: "AI_MODEL_VERSION_UNPINNED",
      title: "AI model identifier not pinned to a specific version/date suffix",
      severity: "MEDIUM",
      evidence: ev.modelUnpinnedFiles,
      requiredActions: [
        "Pin model versions with their date suffix (e.g., gpt-4-0125-preview, claude-sonnet-4-6) to ensure reproducible behavior.",
        "Treat model upgrades as a dependency change: test, review, and deploy deliberately — not automatically.",
        "Add a CI check that rejects unpinned model strings in AI SDK calls."
      ]
    });
  }
  if (ev.langchainDangerousFiles.length > 0) {
    findings.push({
      id: "AI_LANGCHAIN_DANGEROUS_TOOLS",
      title: "LangChain code-execution tool detected (PythonREPLTool / BashTool / ShellTool)",
      severity: "CRITICAL",
      evidence: ev.langchainDangerousFiles,
      requiredActions: [
        "Remove PythonREPLTool, BashTool, and ShellTool from all production agents — they allow arbitrary OS-level code execution.",
        "If code execution is required, use an isolated sandbox (e2b, Modal, AWS Lambda) with network egress restrictions and no filesystem write access.",
        "Implement a tool allow-list; any tool not explicitly listed should be denied by default."
      ]
    });
  }
  if (ev.hfUnpinnedFiles.length > 0) {
    findings.push({
      id: "AI_HUGGINGFACE_UNPINNED",
      title: "HuggingFace model loaded via from_pretrained() without a revision= pin",
      severity: "HIGH",
      evidence: ev.hfUnpinnedFiles,
      requiredActions: [
        "Always specify `revision='<commit-sha>'` in from_pretrained() to pin the exact model weights.",
        "Validate model checksums (SHA256) after download before loading into memory.",
        "Use private model registries or mirrored repositories for production workloads — never load directly from the public Hub without pinning."
      ]
    });
  }
  if (ev.vectorUnauthFiles.length > 0) {
    findings.push({
      id: "AI_EMBEDDING_UNAUTH",
      title: "Vector database client initialized without authentication credentials",
      severity: "HIGH",
      evidence: ev.vectorUnauthFiles,
      requiredActions: [
        "Pass api_key / auth_token when constructing the vector DB client — never use anonymous or open access in non-local environments.",
        "Store vector DB credentials in a secrets manager (AWS Secrets Manager, Vault) and inject at runtime.",
        "Enable network-level restrictions (VPC, IP allow-list) in addition to API key authentication."
      ]
    });
  }
  if (ev.fineTunePiiFiles.length > 0) {
    findings.push({
      id: "AI_FINE_TUNE_DATA_PII",
      title: "Fine-tuning data pipeline detected without PII scrubbing step",
      severity: "HIGH",
      evidence: ev.fineTunePiiFiles,
      requiredActions: [
        "Run all fine-tuning training data through a PII detection and redaction pipeline (e.g., Microsoft Presidio, AWS Comprehend) before submission.",
        "Maintain an audit log of what data was used to train each model version.",
        "Review the model provider's data retention policy — submitted fine-tune data may be stored by the provider."
      ]
    });
  }
}

// ─── Main export ───────────────────────────────────────────────────────────────
export async function checkAi(_: { changedFiles: string[] }): Promise<Finding[]> {
  const findings: Finding[] = [];

  const files = await fg(["**/*.*"], {
    dot: true,
    onlyFiles: true,
    ignore: GLOB_IGNORE
  });

  const ev = makeEvidence();

  for (const file of files) {
    if (!SOURCE_FILE_RE.test(file)) continue;
    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue;
    }
    scanFile(file, text, ev);
  }

  // Supplementary search: catch array-spread prompt-concat patterns not matched inline
  const extraMatches = await searchRepo({
    query: String.raw`\[\.{3}\w+Parts,\s*\w+[Mm]essage`,
    isRegex: true,
    maxMatches: 20
  });
  for (const m of extraMatches) {
    if (!ev.promptConcatFiles.includes(m.file)) {
      ev.promptConcatFiles.push(m.file);
    }
  }

  buildBaseFindings(ev, findings);
  buildPromptAndEvalFindings(ev, findings);
  buildAccessFindings(ev, findings);
  buildRuntimeFindings(ev, findings);
  buildSupplyChainFindings(ev, findings);

  return findings;
}
