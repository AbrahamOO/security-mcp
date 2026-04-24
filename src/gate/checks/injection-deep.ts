/**
 * Deep injection class enforcement — covers attack vectors not detected by existing checks.
 * CWE references per MITRE CWE catalog; ATT&CK techniques per MITRE ATT&CK v14.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";

const NON_CODE_RE = /\.(?:md|json|yaml|yml|txt|rst|toml|lock)$/i;

export async function checkInjectionDeep(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  const findings: Finding[] = [];

  const codeSearch = async (query: string) =>
    (await searchRepo({ query, isRegex: true, maxMatches: 200 })).filter(h => !NON_CODE_RE.test(h.file));

  try {
    // 1. XXE — XML entity parsing without entity disabling
    const xxeHits = await codeSearch(
      String.raw`(?:new\s+(?:DOMParser|SAXParser|XMLParser|fxp\.XMLParser)|xml2js\.parseString|fast-xml-parser|libxmljs\.parseXml|parseXML)\s*\(`);
    const xxeSafeRe = /entityExpansion\s*:\s*false|processEntities\s*:\s*false|resolveEntities\s*:\s*false|FEATURE_EXTERNAL_GENERAL_ENTITIES|XMLConstants\.FEATURE_SECURE_PROCESSING/;
    const xxeUnsafe = xxeHits.filter((h) => !xxeSafeRe.test(h.preview));
    if (xxeUnsafe.length > 0) {
      findings.push({
        id: "XXE_ENTITY_PARSING",
        title: "XML parser may process external entities (XXE — CWE-611)",
        severity: "HIGH",
        evidence: xxeUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(xxeUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Disable external entity processing: set processEntities:false (fast-xml-parser) or resolveEntities:false (xml2js).",
          "CWE-611 / ATT&CK T1190 — XXE can leak files, SSRF, or RCE via server-side request.",
          "Example fix (fast-xml-parser): new XMLParser({ processEntities: false, ignoreAttributes: false })"
        ]
      });
    }

    // 2. SSTI — server-side template injection via user-controlled compile
    const sstiHits = await codeSearch(
      String.raw`(?:Handlebars\.compile|ejs\.render|ejs\.compile|nunjucks\.renderString|pug\.compile|pug\.render|\.template\s*\(|Mustache\.render)\s*\(\s*(?:req\.|body\.|params\.|query\.|user\.|input|template|src)`);
    if (sstiHits.length > 0) {
      findings.push({
        id: "SSTI_TEMPLATE_COMPILE",
        title: "Server-side template compiled from user input (SSTI — CWE-94)",
        severity: "CRITICAL",
        evidence: sstiHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(sstiHits.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Never compile templates from user input — only render with user-controlled data as context variables.",
          "CWE-94 / ATT&CK T1059 — SSTI achieves RCE via template engine expression evaluation.",
          "Fix: precompile templates at build time; pass untrusted data only as template context, never as template source."
        ]
      });
    }

    // 3. Prototype pollution — unsafe merge of user-controlled data into plain objects
    const ppHits = await codeSearch(
      String.raw`(?:_\.merge|Object\.assign|deepmerge|lodash\.merge|merge\s*\()\s*\(\s*(?:\{\}|obj|target|options|config|settings|result)\s*,\s*(?:req\.|body\.|params\.|query\.|user\.|payload\.|data\.)`);
    if (ppHits.length > 0) {
      findings.push({
        id: "PROTOTYPE_POLLUTION",
        title: "Unsafe merge of user-controlled data into plain object — prototype pollution risk (CWE-1321)",
        severity: "HIGH",
        evidence: ppHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(ppHits.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Validate with Zod/Joi schema before merging; use Object.create(null) as the merge target.",
          "CWE-1321 / ATT&CK T1548 — payload {\"__proto__\":{\"isAdmin\":true}} can pollute all objects in the process.",
          "Fix: const safe = schema.parse(req.body); Object.assign(Object.create(null), defaults, safe);"
        ]
      });
    }

    // 4. Open redirect — res.redirect with unvalidated user input
    const openRedirectHits = await codeSearch(
      String.raw`res\.redirect\s*\(\s*(?:req\.|body\.|params\.|query\.|headers\.|url\b|redirect|returnUrl|next|target|destination)`);
    const redirectAllowlistRe = /allowlist|allowedHosts|isAllowed|REDIRECT_WHITELIST|validateRedirect|isSafeUrl|startsWith\s*\(['"]\/\b/;
    const openRedirectUnsafe = openRedirectHits.filter((h) => !redirectAllowlistRe.test(h.preview));
    if (openRedirectUnsafe.length > 0) {
      findings.push({
        id: "OPEN_REDIRECT",
        title: "Open redirect — user-controlled URL in res.redirect() without allowlist (CWE-601)",
        severity: "HIGH",
        evidence: openRedirectUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(openRedirectUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Validate redirect targets against an allowlist of trusted hosts or enforce relative-only redirects.",
          "CWE-601 / ATT&CK T1598 — open redirects are used in phishing chains and OAuth token theft.",
          "Fix: if (!url.startsWith('/') || url.startsWith('//')) throw new Error('Invalid redirect');"
        ]
      });
    }

    // 5. NoSQL operator injection — MongoDB query built from req.body directly
    const nosqlHits = await codeSearch(
      String.raw`(?:\.find|\.findOne|\.findOneAndUpdate|\.updateOne|\.deleteOne|\.aggregate)\s*\(\s*(?:req\.body|body\.|params\.|query\.)\b`);
    if (nosqlHits.length > 0) {
      findings.push({
        id: "NOSQL_OPERATOR_INJECTION",
        title: "NoSQL query built from user input without operator stripping (CWE-943)",
        severity: "HIGH",
        evidence: nosqlHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(nosqlHits.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Never pass req.body directly into MongoDB queries — extract and validate each field individually.",
          "CWE-943 — payload {\"$gt\":\"\"} bypasses equality checks; {\"$where\":\"sleep(5000)\"} achieves DoS.",
          "Fix: const { username } = z.object({ username: z.string() }).parse(req.body); User.findOne({ username });"
        ]
      });
    }

    // 6. CRLF injection — user value in res.setHeader without sanitization
    const crlfHits = await codeSearch(
      String.raw`res\.setHeader\s*\(\s*[^,]+,\s*(?:req\.|body\.|params\.|query\.|user\.|headers\.)`);
    const crlfSafeRe = /replace\s*\(.*\\r|replace\s*\(.*\\n|sanitize|encodeURIComponent/;
    const crlfUnsafe = crlfHits.filter((h) => !crlfSafeRe.test(h.preview));
    if (crlfUnsafe.length > 0) {
      findings.push({
        id: "CRLF_INJECTION",
        title: "CRLF injection risk — user value written to HTTP response header (CWE-113)",
        severity: "HIGH",
        evidence: crlfUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(crlfUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          String.raw`Strip \r and \n from any user-controlled value before writing to response headers.`,
          "CWE-113 — CRLF injection enables HTTP response splitting, header injection, session fixation.",
          String.raw`Fix: const safe = value.replace(/[\r\n]/g, ''); res.setHeader('X-Header', safe);`
        ]
      });
    }

    // 7. YAML unsafe load (js-yaml v3 default)
    const yamlHits = await codeSearch(
      String.raw`yaml\.load\s*\((?!.*FAILSAFE_SCHEMA)(?!.*JSON_SCHEMA)(?!.*CORE_SCHEMA)|jsYaml\.load\s*\((?!.*schema)|require\s*\(['"]js-yaml['"]\)\.load\s*\(`);
    if (yamlHits.length > 0) {
      findings.push({
        id: "YAML_UNSAFE_LOAD",
        title: "js-yaml load() without safe schema — arbitrary code execution risk (CWE-502)",
        severity: "CRITICAL",
        evidence: yamlHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(yamlHits.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Use yaml.load(str, { schema: yaml.FAILSAFE_SCHEMA }) or yaml.safeLoad() (js-yaml v3).",
          "CWE-502 — js-yaml default schema executes JS functions embedded in YAML (!!js/function).",
          "For js-yaml v4+: safeLoad was removed; use load() which is safe by default — verify version."
        ]
      });
    }

    // 8. Unsafe deserialization
    const deserializeHits = await codeSearch(
      String.raw`(?:node-serialize\.unserialize|serialize\.unserialize|unserialize\s*\(|new\s+Function\s*\(\s*(?:req\.|body\.|params\.|data\.|input)|eval\s*\(\s*(?:req\.|body\.|params\.|data\.|Buffer\.from|atob\())`);
    if (deserializeHits.length > 0) {
      findings.push({
        id: "DESERIALIZE_UNSAFE",
        title: "Unsafe deserialization of user input (CWE-502)",
        severity: "CRITICAL",
        evidence: deserializeHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(deserializeHits.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Never deserialize untrusted data with node-serialize, eval(), or new Function().",
          "CWE-502 / ATT&CK T1059 — deserialization gadget chains achieve RCE without user interaction.",
          "Fix: use JSON.parse() with a Zod schema for structured data; for binary formats use a safe decoder with a strict schema."
        ]
      });
    }

    // 9. Path traversal — path.join with user-controlled segment without normalization check
    const pathTraversalHits = await codeSearch(
      String.raw`path\.(?:join|resolve)\s*\([^)]*(?:req\.|body\.|params\.|query\.|filename|filepath|file_path|filePath|fileName)[^)]*\)`);
    const pathSafeRe = /normalize|startsWith|indexOf\s*\(base|resolve.*startsWith|\.includes\s*\(['"]\.\.['"]|path\.sep/;
    const pathUnsafe = pathTraversalHits.filter((h) => !pathSafeRe.test(h.preview));
    if (pathUnsafe.length > 0) {
      findings.push({
        id: "PATH_TRAVERSAL_JOIN",
        title: "Path traversal — path.join() with user input without prefix verification (CWE-22)",
        severity: "HIGH",
        evidence: pathUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(pathUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "After path.join(), verify the resolved path starts with the intended base directory.",
          "CWE-22 / ATT&CK T1083 — ../../etc/passwd reads arbitrary files on the server.",
          "Fix: const full = path.resolve(BASE_DIR, userFilename); if (!full.startsWith(BASE_DIR + path.sep)) throw new Error('Invalid path');"
        ]
      });
    }

    // 10. Log injection — user-controlled strings logged without newline stripping
    const logInjectionHits = await codeSearch(
      String.raw`(?:console\.(?:log|warn|error|info)|logger\.(?:log|warn|error|info|debug)|log\.(?:info|warn|error|debug))\s*\([^)]*(?:req\.|body\.|params\.|query\.|headers\.|user\.|username|email|ip\b)`);
    const logSafeRe = /replace\s*\(.*\\n|replace\s*\(.*\\r|sanitize|JSON\.stringify|inspect\s*\(/;
    const logUnsafe = logInjectionHits.filter((h) => !logSafeRe.test(h.preview));
    if (logUnsafe.length > 0) {
      findings.push({
        id: "LOG_INJECTION",
        title: "Log injection — user-controlled string written to logs without newline sanitization (CWE-117)",
        severity: "MEDIUM",
        evidence: logUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(logUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          String.raw`Strip or encode \n and \r from user-controlled values before logging.`,
          "CWE-117 — log injection forges log entries, erasing evidence of attacks or injecting false audit trails.",
          String.raw`Fix: logger.info('Login attempt', { username: username.replace(/[\r\n]/g, '_') });`
        ]
      });
    }

    // 11. SSRF via user-controlled URL in HTTP request
    const ssrfHits = await codeSearch(
      String.raw`(?:fetch|axios\.(?:get|post|put|delete|request)|https?\.(?:get|request)|got\s*\(|needle\.(?:get|post)|superagent\.(?:get|post))\s*\(\s*(?:req\.|body\.|params\.|query\.|url\b|webhook|endpoint|target|callback|proxy)`);
    const ssrfSafeRe = /allowedHosts|SSRF_GUARD|validateUrl|isAllowedUrl|new URL.*hostname|URL_ALLOWLIST/;
    const ssrfUnsafe = ssrfHits.filter((h) => !ssrfSafeRe.test(h.preview));
    if (ssrfUnsafe.length > 0) {
      findings.push({
        id: "SSRF_USER_URL",
        title: "SSRF — HTTP request to user-controlled URL without allowlist (CWE-918)",
        severity: "CRITICAL",
        evidence: ssrfUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(ssrfUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Validate the URL hostname against an explicit allowlist before making server-side HTTP requests.",
          "CWE-918 / ATT&CK T1090 — SSRF reaches 169.254.169.254 for cloud metadata, internal services, and localhost.",
          "Fix: const { hostname } = new URL(userUrl); if (!ALLOWED_HOSTS.includes(hostname)) throw new Error('Blocked');"
        ]
      });
    }
  } catch (err) {
    console.warn("[checkInjectionDeep] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
  }

  return findings;
}
