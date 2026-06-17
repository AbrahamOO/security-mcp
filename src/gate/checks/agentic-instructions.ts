import { Finding } from "../result.js";
import fg from "fast-glob";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { readFileSafe } from "../../repo/fs.js";

// ════════════════════════════════════════════════════════════════════════════
// Bad-actor "Skills" / agentic-instruction threat detection.
//
// Scans the agentic-instruction surface of an AUDITED repository — the files an
// AI coding agent ingests as authority the moment it opens the repo:
//   SKILL.md, AGENTS.md, CLAUDE.md, .claude/**, .cursorrules, .cursor/**,
//   .windsurfrules, .github/copilot-instructions.md, .mcp.json
// A poisoned instruction file can hijack the agent (prompt injection), exfiltrate
// secrets, register destructive tools, or persist itself — entirely outside the
// application's own code. This is distinct from the framework's self-download
// sanitizer (src/mcp/orchestration.ts), which only protects skills the framework
// installs for itself.
//
// Maps to OWASP LLM01 (Prompt Injection), MITRE ATLAS AML.T0051 / AML.T0054,
// CWE-77 / CWE-94 / CWE-116.
// ════════════════════════════════════════════════════════════════════════════

// File globs for the agentic-instruction surface. Deliberately does NOT ignore
// .claude/ (unlike repo/search.ts) — those files ARE the attack surface here.
const AGENTIC_GLOBS = [
  "**/SKILL.md",
  "**/AGENTS.md",
  "**/CLAUDE.md",
  "**/.claude/**/*.md",
  "**/.claude/**/*.json",
  "**/.cursorrules",
  "**/.cursor/**/*.md",
  "**/.cursor/**/*.mdc",
  "**/.windsurfrules",
  "**/.github/copilot-instructions.md",
  "**/.mcp.json"
];

const AGENTIC_IGNORE = ["**/node_modules/**", "**/.git/**", "**/dist/**"];

// ─── AGENT_INSTRUCTION_OVERRIDE ──────────────────────────────────────────────
const OVERRIDE_IGNORE_RE = /ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|preceding|earlier|foregoing)\s+(?:instructions|prompts?|context|rules|messages)/i;
const OVERRIDE_DISREGARD_RE = /disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|foregoing|system)/i;
const OVERRIDE_TAGS_RE = /<\s*\/?\s*system\s*>|\[\s*\/?\s*system\s*\]|\[\/?INST\]|<\|im_start\|>|###\s*system/i;
const OVERRIDE_FORGET_RE = /(?:forget|disregard)\s+(?:everything|all\s+(?:previous|prior))|you\s+are\s+now\s+|new\s+instructions?\s*:|system\s+prompt\s+override/i;
const OVERRIDE_SAFETY_RE = /override\s+(?:the\s+)?(?:system|safety|previous|default)\s+(?:prompt|instructions?|guardrails?|rules)|do\s+not\s+(?:tell|inform|warn|mention\s+to)\s+the\s+user/i;

// ─── AGENT_INSTRUCTION_EXFIL ─────────────────────────────────────────────────
// Outbound fetch/curl directive to a non-allowlisted external host.
const EXFIL_FETCH_RE = /(?:fetch|curl|wget|axios(?:\.(?:get|post))?|requests\.(?:get|post)|http\.(?:get|post)|XMLHttpRequest|sendBeacon)\s*\(?\s*["'`]?https?:\/\/(?!raw\.githubusercontent\.com|github\.com|localhost|127\.0\.0\.1)/i;
const EXFIL_SEND_RE = /(?:send|post|upload|exfiltrat\w*|leak|transmit|beacon|ship)\b[^.\n]{0,48}(?:env(?:ironment)?\b|secret|token|api[_-]?key|credential|password|\.ssh|\.env\b|private\s+key)/i;

// ─── AGENT_TOOL_POISONING ────────────────────────────────────────────────────
const TOOL_DESTRUCTIVE_RE = /\brm\s+-rf\b|\bchmod\s+777\b|:\s*\(\s*\)\s*\{|\bmkfs\b|\bdd\s+if=|\beval\s*\(|\bexec(?:Sync)?\s*\(|child_process|os\.system|subprocess\.(?:call|run|Popen)|\bnc\s+-e|\/dev\/tcp\//i;
// Data-destruction / sabotage directives beyond raw shell exec.
const TOOL_SABOTAGE_RE = /git\s+push\s+(?:-f\b|--force)|git\s+reset\s+--hard|git\s+clean\s+-[a-z]*f|\bdrop\s+table\b|\btruncate\s+table\b|\bdelete\s+from\b(?!\s+\w+\s+where)|\bshred\b|>\s*\/dev\/sd[a-z]|\bformat\s+[a-z]:|\brimraf\b/i;
const TOOL_IMPERATIVE_DESC_RE = /"description"\s*:\s*"[^"]*(?:always\s+(?:run|execute|call|invoke)|before\s+(?:answering|responding|you\s+reply)|ignore\s+(?:the\s+)?(?:user|previous)|do\s+not\s+(?:tell|inform|reveal|mention))/i;
const TOOL_DISABLE_AUTH_RE = /(?:disable|turn\s+off|remove)\s+(?:the\s+)?(?:auth\w*|security|safety|guardrails?|validation|sandbox)|skip\s+(?:auth\w*|verification|approval|the\s+review)|bypass\s+(?:auth\w*|security|the\s+sandbox|review)/i;

// ─── AGENT_PERSISTENCE_DIRECTIVE ─────────────────────────────────────────────
const PERSIST_EVERY_RE = /on\s+every\s+(?:invocation|run|start|session|message|turn|request)/i;
const PERSIST_START_RE = /at\s+the\s+(?:start|beginning)\s+of\s+(?:every|each)\b/i;
const PERSIST_AUTOUPDATE_RE = /auto.?(?:update|reinstall|re-?install|download|fetch)\s+(?:this\s+)?(?:skill|agent|tool|file)|\bensure_skill\s*\(/i;

// ─── AGENT_HIDDEN_INSTRUCTION ────────────────────────────────────────────────
// Zero-width, bidi-override, and isolate characters used to smuggle instructions
// past human reviewers. CWE-116 / MITRE ATLAS AML.T0051.
const HIDDEN_INVISIBLE_RE = new RegExp("[\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2069\\ufeff\\u00ad\\u2028\\u2029]");
const HIDDEN_HTML_COMMENT_RE = /<!--[\s\S]{0,200}?(?:ignore|system\s+prompt|instruction|execute|\bfetch\b|secret|password|do\s+not\s+(?:tell|mention))[\s\S]{0,200}?-->/i;
const HIDDEN_CSS_HIDE_RE = /(?:display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*#?(?:fff(?:fff)?|white))/i;
const IMPERATIVE_WORD_RE = /\b(?:ignore|execute|run|fetch|send|delete|disable|override|reveal|exfiltrat\w*)\b/i;
const BASE64_BLOB_RE = /[A-Za-z0-9+/]{40,}={0,2}/;
const BASE64_DECODED_BAD_RE = /ignore|system\b|instruction|fetch\s*\(|secret|exec\s*\(|https?:\/\/|password/i;

// ─── AGENT_CREDENTIAL_HARVEST ────────────────────────────────────────────────
const CRED_READ_RE = /(?:read|cat\s|open|load|collect|dump|grab|access)\s+[^.\n]{0,32}(?:\.env\b|\.aws\/credentials|\.ssh\/|id_rsa|\.netrc|keychain|process\.env\b|credentials\.json)/i;
const CRED_EXFIL_RE = /(?:print|output|reveal|show|display|return|echo)\s+[^.\n]{0,32}(?:env(?:ironment)?\s+(?:vars?|variables)|all\s+secrets|api\s+keys|credentials|tokens)/i;

// ─── AGENT_MEMORY_POISONING ──────────────────────────────────────────────────
const MEM_FALSEPOS_RE = /(?:write|add|insert|save|record)\s+[^.\n]{0,48}false.?positive/i;
const MEM_SUPPRESS_RE = /(?:mark|record|suppress|whitelist|silence)\s+[^.\n]{0,36}(?:finding|alert|vulnerabilit\w+)[^.\n]{0,20}as\s+(?:safe|resolved|false|benign)/i;
const MEM_API_RE = /write_agent_memory[^.\n]{0,60}(?:false|suppress|ignore|whitelist)/i;

// ─── AGENT_JAILBREAK_PERSONA (folds into override) ───────────────────────────
// Roleplay / unrestricted-mode jailbreaks and non-English override phrasings.
const JAILBREAK_RE = /\bDAN\b|do\s+anything\s+now|developer\s+mode|jailbreak|unrestricted\s+mode|without\s+(?:any\s+)?(?:restrictions?|limitations?|filters?|guardrails?|rules)|no\s+(?:restrictions?|filters?|guardrails?|ethical\s+guidelines?)|act\s+as\s+if\s+you\s+have\s+no\s+(?:rules|restrictions|limits)|ignore\s+your\s+(?:safety\s+)?(?:guidelines|training|programming|policies)|pretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:unrestricted|uncensored)/i;
const MULTILANG_OVERRIDE_RE = /忽略(?:以上|之前|前面|上述)|无视(?:以上|之前)|前の指示を無視|이전\s*지시\s*무시|ignora\s+(?:las\s+)?instrucciones\s+anteriores|ignorez\s+les\s+instructions\s+pr[eé]c[eé]dentes|ignoriere\s+(?:die\s+)?(?:vorherigen|vorigen)\s+anweisungen|игнорир\w*\s+предыдущие\s+инструкции|تجاهل\s+التعليمات\s+السابقة|ignore\s+as\s+instru[cç][õo]es\s+anteriores/i;

// ─── AGENT_REMOTE_INSTRUCTION_LOAD ───────────────────────────────────────────
// Pulling instructions/commands in from an external location (inbound payload).
const REMOTE_INSTR_RE = /(?:load|fetch|import|read|follow|execute|obey|retrieve)\s+[^.\n]{0,40}(?:instructions?|rules?|prompt|commands?|steps?|directives?|config\w*)[^.\n]{0,24}(?:from|at|located\s+at|hosted\s+at)\s+https?:\/\//i;
const CMD_SUBST_RE = /\$\(\s*(?:curl|wget|fetch)\b|`\s*(?:curl|wget)\b|<\(\s*curl|\beval\s+["'`]?\$\(/i;

// ─── AGENT_PERMISSION_ESCALATION ─────────────────────────────────────────────
const PERM_ESCALATION_RE = /--dangerously-skip-permissions|bypassPermissions|--yolo\b|auto[_-]?approve|allowed-tools[^.\n]{0,40}(?:Bash\s*\(\s*\*|\*\s*\)|:\s*\*|all\b)|add\s+[^.\n]{0,30}to\s+(?:the\s+)?allowed[_-]?tools|grant\s+(?:yourself|the\s+agent)\s+[^.\n]{0,20}(?:full|all|admin)\s+(?:access|permissions?)|run\s+[^.\n]{0,20}without\s+(?:asking|confirmation|approval|permission)/i;

// ─── AGENT_BACKDOOR_INSERT ───────────────────────────────────────────────────
const BACKDOOR_RE = /authorized_keys|add\s+(?:my\s+|this\s+|the\s+following\s+)?ssh\s+(?:public\s+)?key|create\s+(?:an?\s+)?(?:admin|root|superuser|backdoor)\s+(?:user|account)|reverse\s+shell|bind\s+shell|add\s+[^.\n]{0,30}(?:webhook|backdoor)|hardcode\s+[^.\n]{0,24}(?:token|password|api[_-]?key|secret)|insert\s+[^.\n]{0,24}backdoor|disable\s+[^.\n]{0,20}(?:2fa|mfa|signature\s+(?:check|verification))/i;

// ─── AGENT_PROMPT_LEAK (system-prompt / instruction extraction) ──────────────
const PROMPT_LEAK_RE = /(?:repeat|print|reveal|show|output|display|tell\s+me|reproduce|echo)\s+(?:back\s+)?(?:your|the|all\s+(?:your|the))\s+(?:system\s+|initial\s+|original\s+)?(?:prompt|instructions|rules|guidelines|configuration|directives)|what\s+(?:are|were)\s+your\s+(?:initial\s+|original\s+|exact\s+)?(?:instructions|rules|system\s+prompt)/i;

// ─── AGENT_INSTRUCTION_EXFIL — markdown image/link beacon ─────────────────────
const MD_BEACON_RE = /!?\[[^\]]*\]\(\s*https?:\/\/[^)]*[?&][^)=]*=\s*[^)]*\)/i;

// ─── AGENT_HIDDEN_INSTRUCTION — homoglyph / mixed-script confusables ──────────
// A token mixing Latin with Cyrillic/Greek letters (e.g. spoofed skill name).
const HOMOGLYPH_RE = /[A-Za-z][Ѐ-ӿͰ-Ͽ]|[Ѐ-ӿͰ-Ͽ][A-Za-z]/;

type Acc = {
  override: string[];
  exfil: string[];
  toolPoison: string[];
  persist: string[];
  hidden: string[];
  cred: string[];
  memory: string[];
  remoteLoad: string[];
  permEsc: string[];
  backdoor: string[];
  promptLeak: string[];
};

function makeAcc(): Acc {
  return {
    override: [], exfil: [], toolPoison: [], persist: [], hidden: [], cred: [], memory: [],
    remoteLoad: [], permEsc: [], backdoor: [], promptLeak: []
  };
}

function isPrintableInstruction(decoded: string): boolean {
  if (!decoded || decoded.length < 6) return false;
  const printable = decoded.replace(/[^\x20-\x7e]/g, "").length / Math.max(decoded.length, 1);
  return printable > 0.8 && BASE64_DECODED_BAD_RE.test(decoded);
}

function rot13(s: string): string {
  return s.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCodePoint(((c.codePointAt(0)! - base + 13) % 26) + base);
  });
}

function tryBase64(text: string): string {
  const m = BASE64_BLOB_RE.exec(text);
  if (!m) return "";
  try { return Buffer.from(m[0], "base64").toString("utf-8"); } catch { return ""; }
}

function tryHex(text: string): string {
  const m = /(?:0x|\\x)?[0-9a-fA-F]{32,}/.exec(text);
  if (!m) return "";
  const cleaned = m[0].replace(/0x|\\x/g, "");
  if (cleaned.length % 2 !== 0) return "";
  try { return Buffer.from(cleaned, "hex").toString("utf-8"); } catch { return ""; }
}

function tryUnicodeEsc(text: string): string {
  if (!/\\u[0-9a-fA-F]{4}/.test(text)) return "";
  return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCodePoint(Number.parseInt(h, 16)));
}

function tryPercent(text: string): string {
  if (!/%[0-9a-fA-F]{2}/.test(text)) return "";
  try { return decodeURIComponent(text); } catch { return ""; }
}

// Decoders tried against each line; flag if ANY decoded form reveals
// instruction/exfil keywords. Covers ROT13, reversed text, base64, hex,
// \u-escape, and %-encoding.
const DECODERS: Array<(t: string) => string> = [
  rot13,
  (t) => t.split("").reverse().join(""),
  tryBase64,
  tryHex,
  tryUnicodeEsc,
  tryPercent
];

function decodesToInstruction(text: string): boolean {
  return DECODERS.some((decode) => isPrintableInstruction(decode(text)));
}

function scanOverrideExfil(file: string, text: string, acc: Acc): void {
  if (
    OVERRIDE_IGNORE_RE.test(text) ||
    OVERRIDE_DISREGARD_RE.test(text) ||
    OVERRIDE_TAGS_RE.test(text) ||
    OVERRIDE_FORGET_RE.test(text) ||
    OVERRIDE_SAFETY_RE.test(text) ||
    JAILBREAK_RE.test(text) ||
    MULTILANG_OVERRIDE_RE.test(text)
  ) {
    acc.override.push(file);
  }
  if (EXFIL_FETCH_RE.test(text) || EXFIL_SEND_RE.test(text) || MD_BEACON_RE.test(text)) {
    acc.exfil.push(file);
  }
}

function scanToolPersist(file: string, text: string, acc: Acc): void {
  if (
    TOOL_DESTRUCTIVE_RE.test(text) ||
    TOOL_SABOTAGE_RE.test(text) ||
    TOOL_IMPERATIVE_DESC_RE.test(text) ||
    TOOL_DISABLE_AUTH_RE.test(text)
  ) {
    acc.toolPoison.push(file);
  }
  if (PERSIST_EVERY_RE.test(text) || PERSIST_START_RE.test(text) || PERSIST_AUTOUPDATE_RE.test(text)) {
    acc.persist.push(file);
  }
}

function scanAdvanced(file: string, text: string, acc: Acc): void {
  if (REMOTE_INSTR_RE.test(text) || CMD_SUBST_RE.test(text)) acc.remoteLoad.push(file);
  if (PERM_ESCALATION_RE.test(text)) acc.permEsc.push(file);
  if (BACKDOOR_RE.test(text)) acc.backdoor.push(file);
  if (PROMPT_LEAK_RE.test(text)) acc.promptLeak.push(file);
}

function scanHidden(file: string, text: string, lines: string[], acc: Acc): void {
  if (HIDDEN_INVISIBLE_RE.test(text) || HIDDEN_HTML_COMMENT_RE.test(text) || HOMOGLYPH_RE.test(text)) {
    acc.hidden.push(file);
    return;
  }
  // CSS-hidden text only counts when paired with an imperative on the same line.
  if (lines.some((l) => HIDDEN_CSS_HIDE_RE.test(l) && IMPERATIVE_WORD_RE.test(l))) {
    acc.hidden.push(file);
    return;
  }
  // Encoded blob (base64/hex/\u/%/rot13/reversed) that decodes to instruction keywords.
  if (lines.some((l) => decodesToInstruction(l))) {
    acc.hidden.push(file);
  }
}

function scanCredMem(file: string, text: string, acc: Acc): void {
  if (CRED_READ_RE.test(text) || CRED_EXFIL_RE.test(text)) {
    acc.cred.push(file);
  }
  if (MEM_FALSEPOS_RE.test(text) || MEM_SUPPRESS_RE.test(text) || MEM_API_RE.test(text)) {
    acc.memory.push(file);
  }
}

// ─── Opt-in remediation (quarantine / sanitize) ──────────────────────────────
// Disabled by default. Enable with SECURITY_AGENTIC_QUARANTINE:
//   "strip" | "sanitize" → write a cleaned copy to <file>.sanitized (original untouched)
//   "move"  | "quarantine" → move the file into .quarantine/<file>
// Any other truthy value falls back to the safest mode ("strip"). Unset / "0" /
// "false" → no remediation (detection only).
type QuarantineMode = "off" | "strip" | "move";

function resolveQuarantineMode(): QuarantineMode {
  const raw = (process.env["SECURITY_AGENTIC_QUARANTINE"] ?? "").trim().toLowerCase();
  if (!raw || raw === "0" || raw === "false" || raw === "off") return "off";
  if (raw === "move" || raw === "quarantine") return "move";
  return "strip";
}

// Line-level predicate used only when stripping. The multi-line HTML-comment
// pattern is intentionally excluded — strip operates per line.
const LINE_MALICIOUS_RES: RegExp[] = [
  OVERRIDE_IGNORE_RE, OVERRIDE_DISREGARD_RE, OVERRIDE_TAGS_RE, OVERRIDE_FORGET_RE, OVERRIDE_SAFETY_RE,
  JAILBREAK_RE, MULTILANG_OVERRIDE_RE,
  EXFIL_FETCH_RE, EXFIL_SEND_RE, MD_BEACON_RE,
  TOOL_DESTRUCTIVE_RE, TOOL_SABOTAGE_RE, TOOL_IMPERATIVE_DESC_RE, TOOL_DISABLE_AUTH_RE,
  PERSIST_EVERY_RE, PERSIST_START_RE, PERSIST_AUTOUPDATE_RE,
  HIDDEN_INVISIBLE_RE, HIDDEN_CSS_HIDE_RE, HOMOGLYPH_RE,
  REMOTE_INSTR_RE, CMD_SUBST_RE, PERM_ESCALATION_RE, BACKDOOR_RE, PROMPT_LEAK_RE,
  CRED_READ_RE, CRED_EXFIL_RE,
  MEM_FALSEPOS_RE, MEM_SUPPRESS_RE, MEM_API_RE
];

function isMaliciousLine(line: string): boolean {
  return LINE_MALICIOUS_RES.some((re) => re.test(line)) || decodesToInstruction(line);
}

// Resolve a workspace-relative path and reject anything that escapes cwd (CWE-22).
function safeResolve(relPath: string): string | null {
  const root = process.cwd();
  const rootPrefix = root.endsWith(path.sep) ? root : root + path.sep;
  const p = path.resolve(root, relPath);
  if (p !== root && !p.startsWith(rootPrefix)) return null;
  return p;
}

function stripFile(file: string): string {
  const abs = safeResolve(file);
  if (!abs || !existsSync(abs)) return `skipped (unresolved path)`;
  let text = "";
  try {
    text = readFileSync(abs, "utf-8");
  } catch {
    return `skipped (unreadable)`;
  }
  const lines = text.split("\n");
  const kept = lines.filter((l) => !isMaliciousLine(l));
  const removed = lines.length - kept.length;
  const outRel = `${file}.sanitized`;
  const outAbs = safeResolve(outRel);
  if (!outAbs) return `skipped (unresolved output path)`;
  try {
    writeFileSync(outAbs, kept.join("\n"), "utf-8");
  } catch {
    return `skipped (write failed)`;
  }
  return `stripped ${removed} line(s) → ${outRel} (original left for review)`;
}

function moveFile(file: string): string {
  if (file.startsWith(".quarantine/")) return `already quarantined`;
  const abs = safeResolve(file);
  if (!abs || !existsSync(abs)) return `skipped (unresolved path)`;
  const destRel = path.join(".quarantine", file);
  const destAbs = safeResolve(destRel);
  if (!destAbs) return `skipped (unresolved destination)`;
  try {
    mkdirSync(path.dirname(destAbs), { recursive: true });
    renameSync(abs, destAbs);
  } catch {
    return `skipped (move failed)`;
  }
  return `moved → ${destRel}`;
}

/** Apply the configured remediation to every unique flagged file. */
function applyQuarantine(files: string[], mode: QuarantineMode): Map<string, string> {
  const out = new Map<string, string>();
  if (mode === "off") return out;
  for (const file of files) {
    out.set(file, mode === "move" ? moveFile(file) : stripFile(file));
  }
  return out;
}

function uniqueFlaggedFiles(acc: Acc): string[] {
  const all = [
    ...acc.override, ...acc.exfil, ...acc.toolPoison, ...acc.persist,
    ...acc.hidden, ...acc.cred, ...acc.memory,
    ...acc.remoteLoad, ...acc.permEsc, ...acc.backdoor, ...acc.promptLeak
  ];
  return Array.from(new Set(all));
}

function remediationNote(files: string[], remediation: Map<string, string>): string | null {
  const outcomes = files
    .filter((f) => remediation.has(f))
    .map((f) => `${f}: ${remediation.get(f)}`);
  if (outcomes.length === 0) return null;
  return `AUTO-REMEDIATION applied (SECURITY_AGENTIC_QUARANTINE) — ${outcomes.join("; ")}. Verify before trusting the result.`;
}

function buildFindings(acc: Acc, remediation: Map<string, string>): Finding[] {
  const findings: Finding[] = [];
  const withNote = (files: string[], actions: string[]): string[] => {
    const note = remediationNote(files, remediation);
    return note ? [...actions, note] : actions;
  };

  if (acc.override.length > 0) {
    findings.push({
      id: "AGENT_INSTRUCTION_OVERRIDE",
      title: "Agentic instruction file contains prompt-override / instruction-hijack directives",
      severity: "CRITICAL",
      files: acc.override,
      evidence: acc.override,
      requiredActions: withNote(acc.override, [
        "Treat this instruction file as hostile: an AI agent reading it can be hijacked via embedded 'ignore previous instructions', <system> tags, or 'you are now' directives (OWASP LLM01, MITRE ATLAS AML.T0051, CWE-77).",
        "Quarantine the file and trace its origin (commit author, PR, supply-chain source) before any agent ingests the repository.",
        "Enforce instruction-hierarchy isolation in agent runtimes: render repo-sourced instruction files as untrusted DATA inside delimited boundaries, never as system authority."
      ])
    });
  }
  if (acc.exfil.length > 0) {
    findings.push({
      id: "AGENT_INSTRUCTION_EXFIL",
      title: "Agentic instruction file directs the agent to exfiltrate data to an external host",
      severity: "CRITICAL",
      files: acc.exfil,
      evidence: acc.exfil,
      requiredActions: withNote(acc.exfil, [
        "Remove directives that instruct the agent to fetch/curl/POST to non-allowlisted hosts or to send env/secrets/tokens off-box (MITRE ATLAS AML.T0024, CWE-200).",
        "Apply an egress allowlist to the agent's tool runtime so instruction-driven exfiltration calls are blocked at execution time.",
        "Rotate any credentials reachable by the agent if there is evidence the instruction file was active during a run."
      ])
    });
  }
  if (acc.toolPoison.length > 0) {
    findings.push({
      id: "AGENT_TOOL_POISONING",
      title: "Agentic instruction / tool definition encodes destructive or unscoped tool behavior",
      severity: "HIGH",
      files: acc.toolPoison,
      evidence: acc.toolPoison,
      requiredActions: withNote(acc.toolPoison, [
        "Inspect tool/MCP 'description' fields and instruction bodies for destructive commands (rm -rf, eval, shell exec) or hidden imperatives ('always run', 'do not tell the user') — these poison the model's tool-use plane (MITRE ATLAS AML.T0054, CWE-94).",
        "Define MCP tool descriptions as static, code-reviewed constants; reject any tool whose description carries instructions to the model rather than a neutral capability summary.",
        "Run agent tools under least privilege with an explicit allowlist; deny directives that disable auth, validation, or the sandbox."
      ])
    });
  }
  if (acc.persist.length > 0) {
    findings.push({
      id: "AGENT_PERSISTENCE_DIRECTIVE",
      title: "Agentic instruction file contains self-persistence / auto-reinstall directives",
      severity: "HIGH",
      files: acc.persist,
      evidence: acc.persist,
      requiredActions: withNote(acc.persist, [
        "Strip 'on every invocation', 'at the start of every run', and auto-update/ensure_skill directives — they let a malicious instruction set survive removal (persistence; MITRE ATLAS AML.T0051).",
        "Pin and integrity-check (SHA-256) any skill/agent definition the repo loads; forbid runtime self-modification or self-reinstallation.",
        "Audit version history of the file for a benign-then-weaponized edit pattern."
      ])
    });
  }
  if (acc.hidden.length > 0) {
    findings.push({
      id: "AGENT_HIDDEN_INSTRUCTION",
      title: "Agentic instruction file hides instructions via invisible characters, HTML comments, or encoded payloads",
      severity: "CRITICAL",
      files: acc.hidden,
      evidence: acc.hidden,
      requiredActions: withNote(acc.hidden, [
        "Inspect the file for zero-width/bidi Unicode (U+200B–U+200F, U+202A–U+202E, U+2060–U+2069, U+FEFF), HTML comments, CSS-hidden text, and base64 blobs that decode to instructions — all smuggle directives past human review (CWE-116, MITRE ATLAS AML.T0051).",
        "Normalize instruction files to NFC and strip non-printable characters before any agent ingests them; add a pre-commit hook that rejects invisible characters.",
        "Decode and review every embedded base64/hex blob; treat any that decodes to imperatives or URLs as a live injection payload."
      ])
    });
  }
  if (acc.cred.length > 0) {
    findings.push({
      id: "AGENT_CREDENTIAL_HARVEST",
      title: "Agentic instruction file directs the agent to read or reveal credentials",
      severity: "CRITICAL",
      files: acc.cred,
      evidence: acc.cred,
      requiredActions: withNote(acc.cred, [
        "Remove directives instructing the agent to read .env, ~/.aws/credentials, ~/.ssh, keychains, or to dump process.env / print secrets (credential access; MITRE ATLAS AML.T0024, CWE-522).",
        "Run agents with secrets injected out-of-band and scoped to least privilege so instruction-driven harvesting yields nothing useful.",
        "Rotate any credentials the agent could reach and review run logs for prior harvesting attempts."
      ])
    });
  }
  if (acc.memory.length > 0) {
    findings.push({
      id: "AGENT_MEMORY_POISONING",
      title: "Agentic instruction file directs the agent to poison memory or suppress findings",
      severity: "HIGH",
      files: acc.memory,
      evidence: acc.memory,
      requiredActions: withNote(acc.memory, [
        "Remove directives that tell the agent to write false-positive entries, whitelist findings, or mark vulnerabilities as safe/resolved — these blind future scans (data poisoning; MITRE ATLAS AML.T0051).",
        "Make agent memory/finding-suppression writes require validated, authenticated provenance; never accept suppression instructions sourced from a scanned repository.",
        "Audit existing agent memory for entries that may have been planted by this directive."
      ])
    });
  }
  if (acc.remoteLoad.length > 0) {
    findings.push({
      id: "AGENT_REMOTE_INSTRUCTION_LOAD",
      title: "Agentic instruction file pulls instructions or commands from an external location",
      severity: "CRITICAL",
      files: acc.remoteLoad,
      evidence: acc.remoteLoad,
      requiredActions: withNote(acc.remoteLoad, [
        "Remove directives that load/fetch/follow instructions from a URL or run command-substitution ($(curl …), `wget …`) — the visible file looks clean while the real payload arrives at runtime (indirect injection; OWASP LLM01, MITRE ATLAS AML.T0051).",
        "Forbid agents from following instructions sourced from any network location; all agent authority must come from reviewed, pinned local files.",
        "Apply an egress allowlist so runtime instruction-fetching is blocked even if the directive survives review."
      ])
    });
  }
  if (acc.permEsc.length > 0) {
    findings.push({
      id: "AGENT_PERMISSION_ESCALATION",
      title: "Agentic instruction file requests elevated permissions or tool access",
      severity: "HIGH",
      files: acc.permEsc,
      evidence: acc.permEsc,
      requiredActions: withNote(acc.permEsc, [
        "Remove requests to skip permissions (--dangerously-skip-permissions, bypassPermissions, auto-approve), broaden allowed-tools to wildcards (Bash(*)), or run without confirmation — repo-sourced files must never widen the agent's own privileges (excessive agency; OWASP LLM08, CWE-269).",
        "Pin the agent's permission mode and tool allowlist in trusted operator config, never in repo-readable instruction files.",
        "Require human approval for any change to allowed-tools or permission scope."
      ])
    });
  }
  if (acc.backdoor.length > 0) {
    findings.push({
      id: "AGENT_BACKDOOR_INSERT",
      title: "Agentic instruction file directs the agent to insert a backdoor or persistent access",
      severity: "CRITICAL",
      files: acc.backdoor,
      evidence: acc.backdoor,
      requiredActions: withNote(acc.backdoor, [
        "Remove directives to add SSH keys / authorized_keys, create admin accounts, plant reverse/bind shells, add webhooks, hardcode credentials, or disable MFA/signature checks (persistence + privilege escalation; MITRE ATT&CK T1098, CWE-912).",
        "Treat the repository as potentially compromised: diff for any backdoor the agent may already have written, and review authorized_keys / IAM / webhook config.",
        "Block agent write-access to auth-sensitive paths (authorized_keys, IAM policies, CI secrets) entirely."
      ])
    });
  }
  if (acc.promptLeak.length > 0) {
    findings.push({
      id: "AGENT_PROMPT_LEAK",
      title: "Agentic instruction file attempts to extract the agent's system prompt or instructions",
      severity: "MEDIUM",
      files: acc.promptLeak,
      evidence: acc.promptLeak,
      requiredActions: withNote(acc.promptLeak, [
        "Remove directives asking the agent to repeat/print/reveal its system prompt, rules, or configuration — prompt-leak is reconnaissance that enables a tailored jailbreak (MITRE ATLAS AML.T0056).",
        "Configure the agent runtime to refuse system-prompt disclosure and to treat such requests as adversarial probes.",
        "Log and alert on prompt-extraction attempts as a precursor to a targeted attack."
      ])
    });
  }

  return findings;
}

export async function checkAgenticInstructions(_: { changedFiles: string[] }): Promise<Finding[]> {
  const files = await fg(AGENTIC_GLOBS, {
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
    ignore: AGENTIC_IGNORE
  });

  const acc = makeAcc();

  for (const file of files) {
    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue;
    }
    const lines = text.split("\n");
    scanOverrideExfil(file, text, acc);
    scanToolPersist(file, text, acc);
    scanAdvanced(file, text, acc);
    scanHidden(file, text, lines, acc);
    scanCredMem(file, text, acc);
  }

  // Opt-in remediation: only runs when SECURITY_AGENTIC_QUARANTINE is set.
  // Detection-only by default — never mutates the repo unless explicitly enabled.
  const remediation = applyQuarantine(uniqueFlaggedFiles(acc), resolveQuarantineMode());

  return buildFindings(acc, remediation);
}
