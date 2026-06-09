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

// ─── AI_INDIRECT_PROMPT_INJECTION ────────────────────────────────────────────
const EXTERNAL_FETCH_RE = /(?:fetch|axios\.get|got\.get|request\.get|nodemailer|imapflow|cheerio\.load|parseHTML|pdf\.extract|mammoth\.extract)/i;
const PROMPT_BUILD_NEARBY_RE = /(?:messages|prompt|systemPrompt|userMessage|content)\s*(?:=|\+=|\.push)/i;

// ─── AI_MARKDOWN_EXFIL_RISK ───────────────────────────────────────────────────
const MARKDOWN_RENDER_RE = /(?:dangerouslySetInnerHTML|innerHTML\s*=|marked\.parse|showdown|remark|unified)\s*\(/i;

// ─── AI_MEMORY_POISONING ──────────────────────────────────────────────────────
const MEMORY_WRITE_RE = /(?:memory\.add|memory\.save|memory\.set|memoryStore\.write|redis\.set)\s*\([^)]*(?:summary|context|history|assistant)/i;

// ─── AI_RAG_CORPUS_POISONING ──────────────────────────────────────────────────
const VECTOR_UPSERT_RE = /(?:upsert|addDocuments|add_documents|indexDocuments|ingestDocument|vectorStore\.add|\.from_documents)\s*\([^)]*(?:userInput|req\.body|req\.file|formData|upload)/i;

// ─── AI_TOKEN_SMUGGLING ───────────────────────────────────────────────────────
const ZERO_WIDTH_RE = /[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u202e\u202f\u2028\u2029\u00ad]/;

// ─── AI_AGENTIC_PRIVILEGE_ESCALATION ─────────────────────────────────────────
const TOOL_REGISTER_RE = /(?:tools\.push|tools\.add|registerTool|addTool|extend_tools|capabilities\.push)\s*\([^)]*(?:response|output|completion|llm|agent)/i;

// ─── AI_LLM_JUDGE_MANIPULATION ───────────────────────────────────────────────
const LLM_JUDGE_RE = /(?:judge|evaluator|llm_eval|scoreWith|evaluate_with_llm|llmJudge|grader)\s*\(/i;
const JUDGE_USER_INPUT_RE = /(?:criteria|rubric|instruction)\s*[:=][^\n]*(?:userInput|req\.body|input\.|body\.)/i;

// ─── AI_IDOR_TOOL_CALLS ───────────────────────────────────────────────────────
const TOOL_IDOR_RE = /(?:toolCall|tool_call|toolHandler|function_call)\s*\([^)]*(?:args|arguments|params)\.[a-zA-Z]*[Ii][dD]/i;
const AUTHZ_CHECK_RE = /(?:authorize|checkPermission|hasAccess|enforceAuth|userId\s*===|ownedBy)/i;

// ─── AI_CONTEXT_STUFFING ──────────────────────────────────────────────────────
const INPUT_TOKEN_LIMIT_RE = /(?:maxTokens|max_tokens|tokenCount|countTokens|truncate.*tokens)/i;

// ─── AI_MULTIMODAL_INJECTION ──────────────────────────────────────────────────
const MULTIMODAL_RE = /(?:image_url|vision|file_content|image\/(?:jpeg|png|gif|webp)|application\/pdf|audio\/)/i;
const MESSAGES_ARRAY_RE = /messages\s*(?:=|\+=|\.push)\s*\[?/i;

// ─── AI_VECTOR_FILTER_BYPASS ──────────────────────────────────────────────────
const VECTOR_SOFT_FILTER_RE = /(?:similarity_search|vectorSearch|\.search\s*\()[^)]*(?:should|\$or|match_any)/i;

// ─── AI_STREAM_CHUNK_INJECTION ────────────────────────────────────────────────
const STREAM_FORWARD_RE = /(?:stream\.on\s*\(['"]data|for await.*chunk)[^\n]*(?:res\.write|socket\.send|push\(|emit\()/i;
const STREAM_VALIDATION_RE = /sanitize|validate|strip|encode|escape|DOMPurify/i;

// ─── AI_GENERATED_CODE_NO_AUDIT ───────────────────────────────────────────────
const AI_CODE_EXEC_RE = /(?:eval|exec|execSync|spawn|db\.query|prisma\.\$queryRaw|knex\.raw)\s*\([^)]*(?:response|completion|output|generated|llm|model)/i;
const AUDIT_LOG_RE = /audit(?:Log|log|\.log)|logger\.(?:info|warn|security)|logEvent|securityLog/i;

// ─── AI_EMBEDDING_INVERSION ───────────────────────────────────────────────────
const EMBEDDING_EXPOSE_RE = /(?:embedding|embeddings|vector)\.(?:data|values)\s*[,;)][^\n]*(?:res\.json|res\.send|JSON\.stringify|localStorage|log\s*\()/i;

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
  indirectPromptInjectionFiles: string[];
  markdownExfilFiles: string[];
  memoryPoisoningFiles: string[];
  ragCorpusPoisoningFiles: string[];
  tokenSmugglingFiles: string[];
  agenticPrivEscFiles: string[];
  llmJudgeManipFiles: string[];
  idorToolCallFiles: string[];
  contextStuffingFiles: string[];
  multimodalInjectionFiles: string[];
  vectorFilterBypassFiles: string[];
  streamChunkInjectionFiles: string[];
  aiGeneratedCodeNoAuditFiles: string[];
  embeddingInversionFiles: string[];
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
    indirectPromptInjectionFiles: [],
    markdownExfilFiles: [],
    memoryPoisoningFiles: [],
    ragCorpusPoisoningFiles: [],
    tokenSmugglingFiles: [],
    agenticPrivEscFiles: [],
    llmJudgeManipFiles: [],
    idorToolCallFiles: [],
    contextStuffingFiles: [],
    multimodalInjectionFiles: [],
    vectorFilterBypassFiles: [],
    streamChunkInjectionFiles: [],
    aiGeneratedCodeNoAuditFiles: [],
    embeddingInversionFiles: [],
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

function scanNewAiThreats(file: string, text: string, lines: string[], ev: FileEvidence): void {
  // AI_INDIRECT_PROMPT_INJECTION: external data fetch near prompt construction
  if (EXTERNAL_FETCH_RE.test(text) && windowMatch(lines, EXTERNAL_FETCH_RE, PROMPT_BUILD_NEARBY_RE, 20)) {
    ev.indirectPromptInjectionFiles.push(file);
  }
  // AI_MARKDOWN_EXFIL_RISK: markdown renderer called on LLM output variables
  if (MARKDOWN_RENDER_RE.test(text) && AI_SDK_CALL_RE.test(text)) {
    ev.markdownExfilFiles.push(file);
  }
  // AI_MEMORY_POISONING: unsanitized data written to memory/session store
  if (MEMORY_WRITE_RE.test(text)) {
    ev.memoryPoisoningFiles.push(file);
  }
  // AI_RAG_CORPUS_POISONING: user-supplied data upserted directly into vector store
  if (VECTOR_UPSERT_RE.test(text)) {
    ev.ragCorpusPoisoningFiles.push(file);
  }
  // AI_TOKEN_SMUGGLING: zero-width / invisible Unicode characters in source
  if (ZERO_WIDTH_RE.test(text)) {
    ev.tokenSmugglingFiles.push(file);
  }
  // AI_AGENTIC_PRIVILEGE_ESCALATION: tools registered from LLM output
  if (TOOL_REGISTER_RE.test(text)) {
    ev.agenticPrivEscFiles.push(file);
  }
  // AI_LLM_JUDGE_MANIPULATION: LLM judge with user-controlled criteria/rubric
  if (LLM_JUDGE_RE.test(text) && JUDGE_USER_INPUT_RE.test(text)) {
    ev.llmJudgeManipFiles.push(file);
  }
  // AI_IDOR_TOOL_CALLS: tool handler resolves an ID from args without authz check
  if (TOOL_IDOR_RE.test(text) && !windowMatch(lines, TOOL_IDOR_RE, AUTHZ_CHECK_RE, 15)) {
    ev.idorToolCallFiles.push(file);
  }
  // AI_CONTEXT_STUFFING: AI SDK call with no token limit / truncation nearby
  if (AI_SDK_CALL_RE.test(text) && !windowMatch(lines, AI_SDK_CALL_RE, INPUT_TOKEN_LIMIT_RE, 20)) {
    ev.contextStuffingFiles.push(file);
  }
  // AI_MULTIMODAL_INJECTION: multimodal content fed directly into messages array
  if (MULTIMODAL_RE.test(text) && windowMatch(lines, MULTIMODAL_RE, MESSAGES_ARRAY_RE, 10)) {
    ev.multimodalInjectionFiles.push(file);
  }
  // AI_VECTOR_FILTER_BYPASS: soft/optional vector filter without hard tenant guard
  if (VECTOR_SOFT_FILTER_RE.test(text)) {
    ev.vectorFilterBypassFiles.push(file);
  }
  // AI_STREAM_CHUNK_INJECTION: stream chunks forwarded to client without sanitization
  if (STREAM_FORWARD_RE.test(text) && !windowMatch(lines, STREAM_FORWARD_RE, STREAM_VALIDATION_RE, 10)) {
    ev.streamChunkInjectionFiles.push(file);
  }
  // AI_GENERATED_CODE_NO_AUDIT: AI-generated code executed without audit log
  if (AI_CODE_EXEC_RE.test(text) && !windowMatch(lines, AI_CODE_EXEC_RE, AUDIT_LOG_RE, 15)) {
    ev.aiGeneratedCodeNoAuditFiles.push(file);
  }
  // AI_EMBEDDING_INVERSION: raw embeddings/vectors serialised in API response or logs
  if (EMBEDDING_EXPOSE_RE.test(text)) {
    ev.embeddingInversionFiles.push(file);
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
  scanNewAiThreats(file, text, lines, ev);
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

function buildNewAiThreatFindings(ev: FileEvidence, findings: Finding[]): void {
  if (ev.indirectPromptInjectionFiles.length > 0) {
    findings.push({
      id: "AI_INDIRECT_PROMPT_INJECTION",
      title: "External data fetched and inserted into LLM prompt without sanitization — indirect prompt injection risk",
      severity: "CRITICAL",
      evidence: ev.indirectPromptInjectionFiles,
      requiredActions: [
        "Treat all externally fetched content (web pages, emails, PDFs, APIs) as untrusted — sanitize and delimit it before inserting into any prompt (CWE-77, MITRE ATLAS AML.T0051).",
        "Use clearly-marked content boundaries (e.g., XML tags or structured separators) so the model can distinguish instructions from data.",
        "Apply an LLM-input firewall or content-isolation layer that strips control-plane instructions from user-sourced text before prompt construction."
      ]
    });
  }
  if (ev.markdownExfilFiles.length > 0) {
    findings.push({
      id: "AI_MARKDOWN_EXFIL_RISK",
      title: "LLM output rendered as Markdown/HTML without sanitization — data exfiltration via link injection risk",
      severity: "CRITICAL",
      evidence: ev.markdownExfilFiles,
      requiredActions: [
        "Sanitize all LLM-generated Markdown/HTML with a strict allowlist renderer (e.g., DOMPurify) before rendering client-side (CWE-79, MITRE ATLAS AML.T0054).",
        "Disable auto-link and image rendering in the Markdown parser — these are the primary exfiltration vectors.",
        "Apply a Content-Security-Policy that blocks external image/script loads to prevent pixel-tracking and data exfiltration even if sanitization is bypassed."
      ]
    });
  }
  if (ev.memoryPoisoningFiles.length > 0) {
    findings.push({
      id: "AI_MEMORY_POISONING",
      title: "Data written to agent memory store without validation — memory poisoning risk",
      severity: "CRITICAL",
      evidence: ev.memoryPoisoningFiles,
      requiredActions: [
        "Validate and sanitize all content before persisting to memory/session stores — attacker-controlled summaries can shape future model behavior (MITRE ATLAS AML.T0051.000, CWE-20).",
        "Apply per-user memory namespacing and enforce write authorization so one user cannot poison another's context.",
        "Implement memory integrity checks: hash-and-verify stored entries on read; alert on unexpected modifications."
      ]
    });
  }
  if (ev.ragCorpusPoisoningFiles.length > 0) {
    findings.push({
      id: "AI_RAG_CORPUS_POISONING",
      title: "User-supplied content upserted directly into vector store — RAG corpus poisoning risk",
      severity: "HIGH",
      evidence: ev.ragCorpusPoisoningFiles,
      requiredActions: [
        "Never index user-uploaded content without human or automated review — poisoned documents retrieved at query time can hijack agent behavior (MITRE ATLAS AML.T0020, CWE-349).",
        "Quarantine and scan ingested documents through a moderation pipeline before they are made retrievable.",
        "Isolate tenant corpora using vector DB namespaces or collection-level ACLs to prevent cross-tenant retrieval poisoning."
      ]
    });
  }
  if (ev.tokenSmugglingFiles.length > 0) {
    findings.push({
      id: "AI_TOKEN_SMUGGLING",
      title: "Zero-width or invisible Unicode characters detected in source files — token smuggling risk",
      severity: "HIGH",
      evidence: ev.tokenSmugglingFiles,
      requiredActions: [
        "Audit all source files containing zero-width characters (U+200B–U+200F, U+2060, U+FEFF, U+202E–U+202F, U+2028–U+2029, U+00AD) — these can encode hidden instructions invisible to reviewers (CWE-116, MITRE ATLAS AML.T0051).",
        "Add a pre-commit hook (e.g., rg '[\\u200b-\\u200f\\u2060\\ufeff\\u202e\\u202f\\u2028\\u2029\\u00ad]') that rejects files containing homoglyph/zero-width characters.",
        "Normalize all user-supplied strings via Unicode NFC + strip non-printable characters before tokenization or storage."
      ]
    });
  }
  if (ev.agenticPrivEscFiles.length > 0) {
    findings.push({
      id: "AI_AGENTIC_PRIVILEGE_ESCALATION",
      title: "Agent tool registry modified from LLM output — privilege escalation via tool injection risk",
      severity: "CRITICAL",
      evidence: ev.agenticPrivEscFiles,
      requiredActions: [
        "Never register tools from LLM completions, API responses, or any runtime-generated data — tool definitions must be static and code-reviewed (MITRE ATLAS AML.T0054, CWE-284).",
        "Enforce a tool allowlist at startup; reject any attempt to add, modify, or extend tools at runtime.",
        "Apply principle of least privilege to all registered tools — each tool should have only the permissions required for its declared function."
      ]
    });
  }
  if (ev.llmJudgeManipFiles.length > 0) {
    findings.push({
      id: "AI_LLM_JUDGE_MANIPULATION",
      title: "LLM-as-judge evaluator accepts user-controlled criteria or rubric — judge manipulation risk",
      severity: "HIGH",
      evidence: ev.llmJudgeManipFiles,
      requiredActions: [
        "Define evaluation criteria and rubrics as static, server-controlled constants — never interpolate user input into judge instructions (MITRE ATLAS AML.T0051, CWE-77).",
        "Run LLM judges in a separate trust domain with no access to production tools or data stores.",
        "Log all judge inputs and outputs for audit; flag evaluations where the criteria field contains unusual formatting or injection-like patterns."
      ]
    });
  }
  if (ev.idorToolCallFiles.length > 0) {
    findings.push({
      id: "AI_IDOR_TOOL_CALLS",
      title: "Tool call handler resolves a resource ID from arguments without authorization check — IDOR risk",
      severity: "CRITICAL",
      evidence: ev.idorToolCallFiles,
      requiredActions: [
        "Enforce ownership/authorization checks on every ID extracted from tool call arguments before accessing the resource (CWE-639, MITRE ATLAS AML.T0054).",
        "Never rely on the LLM to supply or validate IDs for sensitive operations — resolve them from the authenticated session context instead.",
        "Apply object-level authorization (OLA) middleware that binds resource IDs to the requesting user's identity before tool execution."
      ]
    });
  }
  if (ev.contextStuffingFiles.length > 0) {
    findings.push({
      id: "AI_CONTEXT_STUFFING",
      title: "AI SDK call detected without input token limit or truncation — context stuffing / cost-exhaustion risk",
      severity: "HIGH",
      evidence: ev.contextStuffingFiles,
      requiredActions: [
        "Enforce a maxTokens / max_tokens cap on every LLM call and truncate inputs that exceed the budget before sending (CWE-400, MITRE ATLAS AML.T0057).",
        "Count tokens client-side before submission using tiktoken or the provider's token-counting API and reject oversized inputs early.",
        "Set per-user and per-session token budgets with alerting to detect context-stuffing abuse patterns."
      ]
    });
  }
  if (ev.multimodalInjectionFiles.length > 0) {
    findings.push({
      id: "AI_MULTIMODAL_INJECTION",
      title: "Multimodal content (image/PDF/audio) fed into messages array — multimodal prompt injection risk",
      severity: "CRITICAL",
      evidence: ev.multimodalInjectionFiles,
      requiredActions: [
        "Validate and sanitize all multimodal inputs before including them in the messages array — images and PDFs can encode hidden text instructions that override system prompts (MITRE ATLAS AML.T0051, CWE-20).",
        "Apply file-type verification (magic bytes, not extension) and size limits to all uploaded multimodal assets before forwarding to the LLM.",
        "Consider a two-stage pipeline: extract text from multimodal content first, sanitize the extracted text, then pass as clearly delimited user content."
      ]
    });
  }
  if (ev.vectorFilterBypassFiles.length > 0) {
    findings.push({
      id: "AI_VECTOR_FILTER_BYPASS",
      title: "Vector search uses soft/optional filter (should/$or/match_any) — filter bypass and cross-tenant data leak risk",
      severity: "HIGH",
      evidence: ev.vectorFilterBypassFiles,
      requiredActions: [
        "Replace soft/optional filters (should, $or, match_any) with hard mandatory filters (must, $and, match_all) for tenant and ownership constraints in all vector searches (CWE-285, MITRE ATLAS AML.T0025).",
        "Test that vector search results never return documents outside the authenticated user's namespace even under adversarial query conditions.",
        "Apply defense-in-depth: combine vector DB ACLs with application-layer result filtering before injecting retrieved documents into the prompt."
      ]
    });
  }
  if (ev.streamChunkInjectionFiles.length > 0) {
    findings.push({
      id: "AI_STREAM_CHUNK_INJECTION",
      title: "LLM stream chunks forwarded to client without validation — stream chunk injection risk",
      severity: "HIGH",
      evidence: ev.streamChunkInjectionFiles,
      requiredActions: [
        "Validate and sanitize each stream chunk before forwarding to the client — malicious chunks can contain XSS payloads, HTML injection, or embedded instructions (CWE-79, MITRE ATLAS AML.T0054).",
        "Apply an incremental sanitizer (e.g., streaming DOMPurify or a custom strip function) on the server-side stream pipeline.",
        "Add a maximum chunk-rate limit and total-response-size cap to prevent stream-based resource exhaustion."
      ]
    });
  }
  if (ev.aiGeneratedCodeNoAuditFiles.length > 0) {
    findings.push({
      id: "AI_GENERATED_CODE_NO_AUDIT",
      title: "AI-generated or LLM-completion output passed to code execution without audit logging",
      severity: "HIGH",
      evidence: ev.aiGeneratedCodeNoAuditFiles,
      requiredActions: [
        "Log every instance of AI-generated code execution with the full input prompt, generated output, execution context, and actor identity before running (CWE-778, MITRE ATLAS AML.T0054).",
        "Require a human-in-the-loop approval step or cryptographic signing before any AI-generated code is executed in production.",
        "Scope execution to a sandboxed environment (WASM, Firecracker, e2b) with strict capability restrictions and no access to production credentials."
      ]
    });
  }
  if (ev.embeddingInversionFiles.length > 0) {
    findings.push({
      id: "AI_EMBEDDING_INVERSION",
      title: "Raw embedding vectors serialised into API response, logs, or client storage — inversion / data reconstruction risk",
      severity: "MEDIUM",
      evidence: ev.embeddingInversionFiles,
      requiredActions: [
        "Never expose raw embedding vectors to clients or write them to accessible logs — embeddings can be partially inverted to reconstruct the original text (CWE-200, MITRE ATLAS AML.T0025).",
        "If embeddings must be stored client-side, apply dimensionality reduction (PCA, quantization) and add calibrated noise before transmission.",
        "Audit all API responses and log pipelines for accidental embedding leakage; add a data-type filter that strips float arrays from response payloads."
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
  buildNewAiThreatFindings(ev, findings);

  return findings;
}
