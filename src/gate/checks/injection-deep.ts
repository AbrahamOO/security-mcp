/**
 * Deep injection class enforcement — covers attack vectors not detected by existing checks.
 * CWE references per MITRE CWE catalog; ATT&CK techniques per MITRE ATT&CK v14.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";

const NON_CODE_RE = /\.(?:md|json|yaml|yml|txt|rst|toml|lock)$/i;

type Hit = { file: string; line: number; preview: string };

function toEvidence(hits: Hit[]): string[] {
  return hits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`);
}
function toFiles(hits: Hit[]): string[] {
  return [...new Set(hits.slice(0, 10).map((m) => m.file))];
}

async function codeSearch(query: string): Promise<Hit[]> {
  return (await searchRepo({ query, isRegex: true, maxMatches: 200 })).filter(
    (h) => !NON_CODE_RE.test(h.file)
  );
}

async function checkXxe(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:new\s+(?:DOMParser|SAXParser|XMLParser|fxp\.XMLParser)|xml2js\.parseString|fast-xml-parser|libxmljs\.parseXml|parseXML)\s*\(`
  );
  const unsafe = hits.filter(
    (h) => !/entityExpansion\s*:\s*false|processEntities\s*:\s*false|resolveEntities\s*:\s*false|FEATURE_EXTERNAL_GENERAL_ENTITIES|XMLConstants\.FEATURE_SECURE_PROCESSING/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "XXE_ENTITY_PARSING",
    title: "XML parser may process external entities (XXE — CWE-611)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Disable external entity processing: set processEntities:false (fast-xml-parser) or resolveEntities:false (xml2js).",
      "CWE-611 / ATT&CK T1190 — XXE can leak files, SSRF, or RCE via server-side request.",
      "Example fix (fast-xml-parser): new XMLParser({ processEntities: false, ignoreAttributes: false })"
    ]
  };
}

async function checkSsti(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:Handlebars\.compile|ejs\.render|ejs\.compile|nunjucks\.renderString|pug\.compile|pug\.render|\.template\s*\(|Mustache\.render)\s*\(\s*(?:req\.|body\.|params\.|query\.|user\.|input|template|src)`
  );
  if (!hits.length) return null;
  return {
    id: "SSTI_TEMPLATE_COMPILE",
    title: "Server-side template compiled from user input (SSTI — CWE-94)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Never compile templates from user input — only render with user-controlled data as context variables.",
      "CWE-94 / ATT&CK T1059 — SSTI achieves RCE via template engine expression evaluation.",
      "Fix: precompile templates at build time; pass untrusted data only as template context, never as template source."
    ]
  };
}

async function checkPrototypePollution(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:_\.merge|Object\.assign|deepmerge|lodash\.merge|merge\s*\()\s*\(\s*(?:\{\}|obj|target|options|config|settings|result)\s*,\s*(?:req\.|body\.|params\.|query\.|user\.|payload\.|data\.)`
  );
  if (!hits.length) return null;
  return {
    id: "PROTOTYPE_POLLUTION",
    title: "Unsafe merge of user-controlled data into plain object — prototype pollution risk (CWE-1321)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Validate with Zod/Joi schema before merging; use Object.create(null) as the merge target.",
      "CWE-1321 / ATT&CK T1548 — payload {\"__proto__\":{\"isAdmin\":true}} can pollute all objects in the process.",
      "Fix: const safe = schema.parse(req.body); Object.assign(Object.create(null), defaults, safe);"
    ]
  };
}

async function checkOpenRedirect(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`res\.redirect\s*\(\s*(?:req\.|body\.|params\.|query\.|headers\.|url\b|redirect|returnUrl|next|target|destination)`
  );
  const unsafe = hits.filter(
    (h) => !/allowlist|allowedHosts|isAllowed|REDIRECT_WHITELIST|validateRedirect|isSafeUrl|startsWith\s*\(['"]\/\b/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "OPEN_REDIRECT",
    title: "Open redirect — user-controlled URL in res.redirect() without allowlist (CWE-601)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Validate redirect targets against an allowlist of trusted hosts or enforce relative-only redirects.",
      "CWE-601 / ATT&CK T1598 — open redirects are used in phishing chains and OAuth token theft.",
      "Fix: if (!url.startsWith('/') || url.startsWith('//')) throw new Error('Invalid redirect');"
    ]
  };
}

async function checkNosqlInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:\.find|\.findOne|\.findOneAndUpdate|\.updateOne|\.deleteOne|\.aggregate)\s*\(\s*(?:req\.body|body\.|params\.|query\.)\b`
  );
  if (!hits.length) return null;
  return {
    id: "NOSQL_OPERATOR_INJECTION",
    title: "NoSQL query built from user input without operator stripping (CWE-943)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Never pass req.body directly into MongoDB queries — extract and validate each field individually.",
      "CWE-943 — payload {\"$gt\":\"\"} bypasses equality checks; {\"$where\":\"sleep(5000)\"} achieves DoS.",
      "Fix: const { username } = z.object({ username: z.string() }).parse(req.body); User.findOne({ username });"
    ]
  };
}

async function checkCrlfInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`res\.setHeader\s*\(\s*[^,]+,\s*(?:req\.|body\.|params\.|query\.|user\.|headers\.)`
  );
  const unsafe = hits.filter(
    (h) => !/replace\s*\(.*\\r|replace\s*\(.*\\n|sanitize|encodeURIComponent/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "CRLF_INJECTION",
    title: "CRLF injection risk — user value written to HTTP response header (CWE-113)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      String.raw`Strip \r and \n from any user-controlled value before writing to response headers.`,
      "CWE-113 — CRLF injection enables HTTP response splitting, header injection, session fixation.",
      String.raw`Fix: const safe = value.replace(/[\r\n]/g, ''); res.setHeader('X-Header', safe);`
    ]
  };
}

async function checkYamlUnsafeLoad(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`yaml\.load\s*\((?!.*FAILSAFE_SCHEMA)(?!.*JSON_SCHEMA)(?!.*CORE_SCHEMA)|jsYaml\.load\s*\((?!.*schema)|require\s*\(['"]js-yaml['"]\)\.load\s*\(`
  );
  if (!hits.length) return null;
  return {
    id: "YAML_UNSAFE_LOAD",
    title: "js-yaml load() without safe schema — arbitrary code execution risk (CWE-502)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Use yaml.load(str, { schema: yaml.FAILSAFE_SCHEMA }) or yaml.safeLoad() (js-yaml v3).",
      "CWE-502 — js-yaml default schema executes JS functions embedded in YAML (!!js/function).",
      "For js-yaml v4+: safeLoad was removed; use load() which is safe by default — verify version."
    ]
  };
}

async function checkUnsafeDeserialize(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:node-serialize\.unserialize|serialize\.unserialize|unserialize\s*\(|new\s+Function\s*\(\s*(?:req\.|body\.|params\.|data\.|input)|eval\s*\(\s*(?:req\.|body\.|params\.|data\.|Buffer\.from|atob\())`
  );
  if (!hits.length) return null;
  return {
    id: "DESERIALIZE_UNSAFE",
    title: "Unsafe deserialization of user input (CWE-502)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Never deserialize untrusted data with node-serialize, eval(), or new Function().",
      "CWE-502 / ATT&CK T1059 — deserialization gadget chains achieve RCE without user interaction.",
      "Fix: use JSON.parse() with a Zod schema for structured data; for binary formats use a safe decoder with a strict schema."
    ]
  };
}

async function checkPathTraversal(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`path\.(?:join|resolve)\s*\([^)]*(?:req\.|body\.|params\.|query\.|filename|filepath|file_path|filePath|fileName)[^)]*\)`
  );
  const unsafe = hits.filter(
    (h) => !/normalize|startsWith|indexOf\s*\(base|resolve.*startsWith|\.includes\s*\(['"]\.\.['"]|path\.sep/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "PATH_TRAVERSAL_JOIN",
    title: "Path traversal — path.join() with user input without prefix verification (CWE-22)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "After path.join(), verify the resolved path starts with the intended base directory.",
      "CWE-22 / ATT&CK T1083 — ../../etc/passwd reads arbitrary files on the server.",
      "Fix: const full = path.resolve(BASE_DIR, userFilename); if (!full.startsWith(BASE_DIR + path.sep)) throw new Error('Invalid path');"
    ]
  };
}

async function checkLogInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:console\.(?:log|warn|error|info)|logger\.(?:log|warn|error|info|debug)|log\.(?:info|warn|error|debug))\s*\([^)]*(?:req\.|body\.|params\.|query\.|headers\.|user\.|username|email|ip\b)`
  );
  const unsafe = hits.filter(
    (h) => !/replace\s*\(.*\\n|replace\s*\(.*\\r|sanitize|JSON\.stringify|inspect\s*\(/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "LOG_INJECTION",
    title: "Log injection — user-controlled string written to logs without newline sanitization (CWE-117)",
    severity: "MEDIUM",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      String.raw`Strip or encode \n and \r from user-controlled values before logging.`,
      "CWE-117 — log injection forges log entries, erasing evidence of attacks or injecting false audit trails.",
      String.raw`Fix: logger.info('Login attempt', { username: username.replace(/[\r\n]/g, '_') });`
    ]
  };
}

async function checkSsrfUserUrl(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:fetch|axios\.(?:get|post|put|delete|request)|https?\.(?:get|request)|got\s*\(|needle\.(?:get|post)|superagent\.(?:get|post))\s*\(\s*(?:req\.|body\.|params\.|query\.|url\b|webhook|endpoint|target|callback|proxy)`
  );
  const unsafe = hits.filter(
    (h) => !/allowedHosts|SSRF_GUARD|validateUrl|isAllowedUrl|new URL.*hostname|URL_ALLOWLIST/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "SSRF_USER_URL",
    title: "SSRF — HTTP request to user-controlled URL without allowlist (CWE-918)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Validate the URL hostname against an explicit allowlist before making server-side HTTP requests.",
      "CWE-918 / ATT&CK T1090 — SSRF reaches 169.254.169.254 for cloud metadata, internal services, and localhost.",
      "Fix: const { hostname } = new URL(userUrl); if (!ALLOWED_HOSTS.includes(hostname)) throw new Error('Blocked');"
    ]
  };
}

async function checkCommandInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*(?:['"][^'"]*\$\{|req\.|body\.|params\.|query\.|input\b|cmd\b|command\b|shell\b)|shell\s*:\s*true`
  );
  const unsafe = hits.filter(
    (h) => !/allowedCommands|COMMAND_ALLOWLIST|execFile\s*\(\s*['"][^'"]+['"]\s*,\s*\[/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "COMMAND_INJECTION",
    title: "Command injection — child_process called with user-controlled input or shell:true (CWE-78)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Use execFile() with a static path and an array of validated arguments — never string concatenation.",
      String.raw`CWE-78 / ATT&CK T1059 — command injection achieves full OS compromise via shell metacharacters (;, |, $(), \n).`,
      "Fix: execFile('/usr/bin/convert', ['-resize', validatedSize, inputFile, outputFile], { shell: false });"
    ]
  };
}

async function checkRedos(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`new\s+RegExp\s*\(\s*(?:req\.|body\.|params\.|query\.|user\.|input\b|pattern\b|search\b|filter\b)`
  );
  if (!hits.length) return null;
  return {
    id: "REDOS_USER_REGEXP",
    title: "ReDoS — user-controlled input used to construct RegExp — catastrophic backtracking (CWE-1333)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Never construct RegExp from user input. Escape with escape-string-regexp, or use string.includes() / startsWith().",
      "CWE-1333 / ATT&CK T1499 — a crafted pattern like (a+)+ causes exponential backtracking that hangs the Node.js event loop.",
      "Fix: const safe = escapeStringRegexp(userInput); const re = new RegExp(safe);"
    ]
  };
}

async function checkJsonpCallbackInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`res\.(?:send|end|write)\s*\(\s*(?:req\.|query\.|params\.)(?:callback|jsonp|cb)\s*\+`
  );
  if (!hits.length) return null;
  return {
    id: "JSONP_CALLBACK_INJECTION",
    title: "JSONP callback parameter reflected without validation — XSS via function name (CWE-79)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Validate the callback parameter against /^[a-zA-Z_$][a-zA-Z0-9_$.]*$/ before reflecting it in a JSONP response.",
      "CWE-79 — an unvalidated callback like alert(document.cookie) is executed when the browser loads the JSONP response.",
      String.raw`Fix: Remove JSONP and use CORS instead. If JSONP is required: if (!/^[\w$.]+$/.test(cb)) return res.status(400).end();`,
    ]
  };
}

async function checkEvalEncodedPayload(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`eval\s*\(\s*(?:atob|Buffer\.from[^)]*base64|decode|decodeURIComponent)\s*\(`
  );
  if (!hits.length) return null;
  return {
    id: "EVAL_ENCODED_PAYLOAD",
    title: "eval() with decoded/deserialized payload — obfuscated code execution (CWE-95)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Remove eval() entirely. Use JSON.parse() for structured data; import() with a static specifier for modules.",
      "CWE-95 / ATT&CK T1027 — base64-encoding evades naive static analysis; eval executes arbitrary JavaScript.",
      "Fix: const data = JSON.parse(Buffer.from(encoded, 'base64').toString('utf-8')); // never eval()"
    ]
  };
}

export async function checkInjectionDeep(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  try {
    const results = await Promise.all([
      checkXxe(),
      checkSsti(),
      checkPrototypePollution(),
      checkOpenRedirect(),
      checkNosqlInjection(),
      checkCrlfInjection(),
      checkYamlUnsafeLoad(),
      checkUnsafeDeserialize(),
      checkPathTraversal(),
      checkLogInjection(),
      checkSsrfUserUrl(),
      checkCommandInjection(),
      checkRedos(),
      checkJsonpCallbackInjection(),
      checkEvalEncodedPayload(),
    ]);
    return results.filter((f): f is Finding => f !== null);
  } catch (err) {
    console.warn("[checkInjectionDeep] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    return [];
  }
}
