/**
 * Per-tool-call structured audit log.
 *
 * Every MCP tool invocation is recorded as one structured JSONL line — the
 * "one log per tool call, not per session" requirement for agentic systems.
 * Each record carries the eight mandatory fields:
 *
 *   1. timestamp          — ISO-8601 start time of the call
 *   2. agentId            — the calling agent (args.agentName) or the session id
 *   3. toolName           — the MCP tool that was invoked
 *   4. inputParameters    — tool arguments, with secret-bearing keys redacted
 *   5. outputResult       — outcome + byte size + a truncated, redacted preview
 *   6. credentialsUsed    — the session credential id (never the secret value)
 *   7. userContext        — requester/session context
 *   8. outcomeStatus      — success | error | unauthenticated
 *
 * Records are appended to `.mcp/audit/tool-calls.jsonl` (mode 0o600). For a
 * tamper-proof deployment, point SECURITY_TOOL_AUDIT_LOG at a path backed by an
 * append-only / write-once sink (e.g. an fs path on a volume with immutability,
 * or a fifo forwarded to S3 Object Lock). Logging never throws: an audit-sink
 * failure must not break tool execution.
 */

import { appendFileSync, mkdirSync, renameSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { getSessionId, isAuthRequired } from "./auth.js";

const AUDIT_LOG_PATH =
  process.env.SECURITY_TOOL_AUDIT_LOG ?? join(".mcp", "audit", "tool-calls.jsonl");
const MAX_STRING_LEN = 512;
const MAX_ARRAY_LEN = 100;
const MAX_DEPTH = 6;
const MAX_OUTPUT_PREVIEW = 512;
const MAX_AGENT_ID_LEN = 256;
const MAX_AUDIT_BYTES = 50 * 1024 * 1024; // rotate the log once it exceeds 50 MB

// Keys whose values are credentials/secrets. Substring match (not anchored) so
// decorated variants are caught: sharedSecret, hmacKey, refreshToken, apiKeyHeader,
// clientSecretValue, SECURITY_MCP_SHARED_SECRET, x-api-key, etc.
const SENSITIVE_KEY_RE =
  /(?:secret|token|passw|pwd|api[_-]?key|apikey|authorization|auth|signature|hmac|private[_-]?key|access[_-]?key|bearer|cookie|credential)/i;

// Secret-shaped patterns scrubbed from string VALUES (and the output preview),
// regardless of key name — catches secrets embedded in URLs, command strings, and
// file contents returned by repo.read_file / repo.search.
const SECRET_VALUE_PATTERNS: RegExp[] = [
  /AKIA[0-9A-Z]{16}/g,                                            // AWS access key id
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/g,                    // PEM private key header
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,  // JWT
  /gh[pousr]_[A-Za-z0-9]{20,}/g,                                  // GitHub token
  /xox[baprs]-[A-Za-z0-9-]{10,}/g,                                // Slack token
  /(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[:=]\s*["']?[^\s"'`]{6,}/gi, // key=value
  /\b[A-Fa-f0-9]{40,}\b/g,                                        // long hex (keys/digests)
  /\b[A-Za-z0-9+/]{40,}={0,2}\b/g                                 // long base64 blob
];

function scrubSecrets(s: string): string {
  let out = s;
  for (const re of SECRET_VALUE_PATTERNS) out = out.replace(re, "[REDACTED]");
  return out;
}

export type ToolCallOutcome = "success" | "error" | "unauthenticated";

export type ToolCallAuditEntry = {
  timestamp: string;
  durationMs: number;
  agentId: string;
  toolName: string;
  inputParameters: unknown;
  outputResult: { outcome: ToolCallOutcome; bytes: number; preview: string };
  credentialsUsed: string;
  userContext: string;
  outcomeStatus: ToolCallOutcome;
};

/** Deep-clone arguments while masking secret keys and capping size. */
function redact(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) return "[depth-capped]";
  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY_LEN).map((v) => redact(v, depth + 1));
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SENSITIVE_KEY_RE.test(k) ? "[REDACTED]" : redact(v, depth + 1);
    }
    return out;
  }
  if (typeof value === "string") {
    const scrubbed = scrubSecrets(value);
    return scrubbed.length > MAX_STRING_LEN ? scrubbed.slice(0, MAX_STRING_LEN) + "…[truncated]" : scrubbed;
  }
  return value;
}

/** Classify a tool result (the asTextResponse shape) into an outcome status. */
export function classifyOutcome(result: unknown): ToolCallOutcome {
  try {
    const text = (result as { content?: Array<{ text?: unknown }> })?.content?.[0]?.text;
    if (typeof text === "string") {
      if (text.startsWith("[security-mcp error]")) return "error";
      // Match the structured framings only — not the bare word, which could appear in
      // returned file content (repo.read_file) and poison the outcome field.
      if (/"error"\s*:\s*"UNAUTHENTICATED"/.test(text)) return "unauthenticated";
      if (/"authenticated"\s*:\s*false/.test(text)) return "unauthenticated"; // failed auth attempt
    }
  } catch {
    /* fall through to success */
  }
  return "success";
}

function summarizeOutput(result: unknown, outcome: ToolCallOutcome): ToolCallAuditEntry["outputResult"] {
  let preview = "";
  let bytes = 0;
  try {
    const text = (result as { content?: Array<{ text?: unknown }> })?.content?.[0]?.text;
    if (typeof text === "string") {
      bytes = Buffer.byteLength(text, "utf-8");
      // Scrub secrets/PII before previewing — tool outputs include repo file contents.
      const scrubbed = scrubSecrets(text);
      preview = scrubbed.length > MAX_OUTPUT_PREVIEW ? scrubbed.slice(0, MAX_OUTPUT_PREVIEW) + "…[truncated]" : scrubbed;
    }
  } catch {
    /* leave defaults */
  }
  return { outcome, bytes, preview };
}

function extractAgentId(args: unknown): string {
  if (args && typeof args === "object" && "agentName" in args) {
    const a = (args as { agentName?: unknown }).agentName;
    if (typeof a === "string" && a.length > 0) return a.slice(0, MAX_AGENT_ID_LEN);
  }
  return (getSessionId() ?? "mcp-session").slice(0, MAX_AGENT_ID_LEN);
}

function safeStringify(entry: ToolCallAuditEntry): string {
  // Coerce BigInt so JSON.stringify never throws — a throw would silently drop the
  // record, which an attacker could weaponize as an audit-evasion primitive.
  return JSON.stringify(entry, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
}

/** Append one audit record. Swallows all errors — never breaks tool execution. */
function recordToolCall(entry: ToolCallAuditEntry): void {
  try {
    mkdirSync(dirname(AUDIT_LOG_PATH), { recursive: true, mode: 0o700 });
    // CWE-400: single-rotation size guard so a tight tool-call loop cannot exhaust disk.
    try {
      if (statSync(AUDIT_LOG_PATH).size > MAX_AUDIT_BYTES) {
        renameSync(AUDIT_LOG_PATH, `${AUDIT_LOG_PATH}.1`);
      }
    } catch {
      /* file absent or not rotatable — ignore */
    }
    let line: string;
    try {
      line = safeStringify(entry);
    } catch {
      // Last-resort minimal record so a sensitive call is never invisible in the log.
      line = JSON.stringify({
        timestamp: entry.timestamp,
        toolName: entry.toolName,
        outcomeStatus: entry.outcomeStatus,
        note: "serialize-failed"
      });
    }
    appendFileSync(AUDIT_LOG_PATH, line + "\n", { encoding: "utf-8", mode: 0o600 });
  } catch {
    /* audit sink unavailable — do not interrupt the tool call */
  }
}

/**
 * Wrap an MCP tool handler so every invocation emits one structured audit
 * record. The handler's behaviour and return value are unchanged.
 */
export function withToolAudit<H extends (args: unknown, extra: unknown) => Promise<unknown>>(
  toolName: string,
  handler: H
): H {
  const wrapped = async (args: unknown, extra: unknown): Promise<unknown> => {
    const startedAt = new Date().toISOString();
    const start = Date.now();
    let result: unknown;
    let outcome: ToolCallOutcome = "success";
    try {
      result = await handler(args, extra);
      outcome = classifyOutcome(result);
      return result;
    } catch (err) {
      outcome = "error";
      throw err;
    } finally {
      const sessionId = getSessionId();
      recordToolCall({
        timestamp: startedAt,
        durationMs: Date.now() - start,
        agentId: extractAgentId(args),
        toolName,
        inputParameters: redact(args),
        outputResult: summarizeOutput(result, outcome),
        credentialsUsed: sessionId ?? (isAuthRequired() ? "unauthenticated" : "no-auth-configured"),
        userContext: `session:${sessionId ?? "anonymous"} pid:${process.pid}`,
        outcomeStatus: outcome
      });
    }
  };
  return wrapped as H;
}
