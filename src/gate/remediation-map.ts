// Remediation templates for security.generate_remediations.
// Relocated out of src/mcp/server.ts: these entries embed intentional "before"
// vulnerable-code examples (md5, SQL concatenation, sslmode=disable, ...) used to
// teach fixes. This repo's own gate run excludes them through SECURITY_GATE_IGNORE
// (see .github/workflows/security-gate.yml), so the examples do not self-trigger
// checks. searchRepo no longer skips src/gate/** for everyone: that exclusion was
// this project's self-scan preference, and applying it to every reviewed repository
// left any project with a src/gate/ directory silently unscanned.

export type RemediationTemplate = {
  pattern: string;
  fix: string;
  explanation: string;
  references: string[];
};

// Domain remediation partials (1.6.1). Each file lives under src/gate/ so the gate
// self-scan ignores its intentional vulnerable "pattern" examples, and each is
// merged into REMEDIATION_MAP below so security.generate_remediations resolves a
// concrete fix for the overwhelming majority of finding IDs (the 90%-fix mandate).
import { CLOUD_REMEDIATIONS } from "./remediation-parts/cloud.js";
import { AI_REMEDIATIONS } from "./remediation-parts/ai.js";
import { DATA_REMEDIATIONS } from "./remediation-parts/data.js";
import { WEB_REMEDIATIONS } from "./remediation-parts/web.js";
import { WEB_HARDENING_REMEDIATIONS } from "./remediation-parts/web-hardening-remediations.js";
import { MISC_REMEDIATIONS } from "./remediation-parts/misc.js";

// Base templates (the original hand-authored set). Domain partials are spread in
// after this literal via Object.assign.
const BASE_REMEDIATION_MAP: Record<string, RemediationTemplate> = {
  "POSSIBLE_SECRET": {
    pattern: "const API_KEY = 'sk-...'  // hardcoded secret",
    fix: "const API_KEY = process.env['API_KEY']; // loaded from secret manager",
    explanation: "Hardcoded secrets are exposed in source control and logs. Load secrets from environment variables backed by a secret manager (AWS Secrets Manager, HashiCorp Vault, etc.).",
    references: ["CWE-798", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
  },
  "CRYPTO_WEAK_HASH": {
    pattern: "crypto.createHash('md5').update(data).digest('hex')",
    fix: "crypto.createHash('sha256').update(data).digest('hex')",
    explanation: "MD5 and SHA-1 are cryptographically broken. Use SHA-256 or higher.",
    references: ["NIST SP 800-131A Rev 2", "CWE-327"]
  },
  "CRYPTO_WEAK_CIPHER": {
    pattern: "crypto.createCipheriv('des', key, iv)",
    fix: "crypto.createCipheriv('aes-256-gcm', key, nonce)",
    explanation: "DES/RC4/3DES are prohibited by NIST. Use AES-256-GCM for authenticated encryption.",
    references: ["NIST SP 800-131A Rev 2", "CWE-327", "FIPS 140-3"]
  },
  "CRYPTO_INSECURE_RANDOM": {
    pattern: "const token = Math.random().toString(36).slice(2)",
    fix: "const token = crypto.randomBytes(32).toString('hex')",
    explanation: "Math.random() is not cryptographically secure. Use crypto.randomBytes() for tokens, keys, and nonces.",
    references: ["CWE-338", "OWASP ASVS 2.3.1"]
  },
  "CRYPTO_WEAK_JWT_ALGO": {
    pattern: "jwt.sign(payload, secret, { algorithm: 'HS256' })",
    fix: "jwt.sign(payload, privateKey, { algorithm: 'RS256' })",
    explanation: "HS256 requires sharing the signing secret with every verifier. RS256/ES256 use asymmetric keys so verifiers only need the public key.",
    references: ["RFC 7518", "OWASP JWT Security Cheat Sheet"]
  },
  "DB_TLS_DISABLED": {
    pattern: "postgresql://user:pass@host/db?sslmode=disable",
    fix: "postgresql://user:pass@host/db?sslmode=verify-full",
    explanation: "Disabling TLS exposes credentials and data in transit. Always require and verify TLS.",
    references: ["PCI DSS 4.0 Req 4.2", "NIST 800-53 SC-8", "CWE-319"]
  },
  "DB_SQL_INJECTION_RISK": {
    pattern: "db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
    fix: "db.query('SELECT * FROM users WHERE id = $1', [req.params.id])",
    explanation: "Never concatenate user input into SQL. Use parameterized queries or ORM query builders.",
    references: ["OWASP Top 10 A03:2021", "CWE-89", "NIST 800-53 SI-10"]
  },
  "GRAPHQL_INTROSPECTION_ENABLED": {
    pattern: "new ApolloServer({ introspection: true })",
    fix: "new ApolloServer({ introspection: process.env.NODE_ENV !== 'production' })",
    explanation: "GraphQL introspection exposes the full schema to attackers. Disable it in non-dev environments.",
    references: ["OWASP API Security Top 10 API8:2023", "CWE-200"]
  },
  "GRAPHQL_NO_DEPTH_LIMIT": {
    pattern: "new ApolloServer({ schema })",
    fix: "import depthLimit from 'graphql-depth-limit';\nnew ApolloServer({ schema, validationRules: [depthLimit(10)] })",
    explanation: "Without depth limiting, attackers can send deeply nested queries to exhaust server resources.",
    references: ["OWASP API Security Top 10 API4:2023"]
  },
  "K8S_PRIVILEGED_CONTAINER": {
    pattern: "securityContext:\n  privileged: true",
    fix: "securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false\n  runAsNonRoot: true\n  capabilities:\n    drop: [\"ALL\"]",
    explanation: "Privileged containers have unrestricted access to the host kernel. Remove privileged mode and drop all capabilities.",
    references: ["CIS Kubernetes Benchmark 5.2.1", "NIST 800-190"]
  },
  "K8S_NO_SECURITY_CONTEXT": {
    pattern: "containers:\n  - name: app\n    image: myapp:1.0",
    fix: "containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true\n      runAsUser: 1000\n      readOnlyRootFilesystem: true\n      allowPrivilegeEscalation: false\n      capabilities:\n        drop: [\"ALL\"]",
    explanation: "Always set a securityContext to enforce least-privilege container execution.",
    references: ["CIS Kubernetes Benchmark", "NIST 800-190", "OWASP Kubernetes Security Cheat Sheet"]
  },
  "DLP_REQUEST_BODY_LOGGED": {
    pattern: "console.log(req.body)",
    fix: "const { password, token, ...safeFields } = req.body;\nconsole.log({ requestId, safeFields })",
    explanation: "Full request bodies may contain PII, passwords, or tokens. Log only allowlisted non-sensitive fields.",
    references: ["GDPR Article 5", "HIPAA 45 CFR 164.312", "CWE-532"]
  },
  "DLP_STACK_TRACE_IN_RESPONSE": {
    pattern: "res.json({ error: err.message, stack: err.stack })",
    fix: "logger.error({ err, requestId }); // log internally\nres.json({ error: 'An internal error occurred', requestId })",
    explanation: "Stack traces in API responses disclose internal architecture to attackers (CWE-209). Log internally, return only a safe message.",
    references: ["CWE-209", "OWASP Top 10 A05:2021", "PCI DSS 4.0 Req 6.2.4"]
  },
  "API_TENANT_ID_FROM_INPUT": {
    pattern: "const tenantId = req.query.tenantId",
    fix: "const tenantId = req.auth.tenantId // from verified JWT claims",
    explanation: "Tenant ID must come from the authenticated session/JWT claims. User-supplied tenant IDs allow cross-tenant data access.",
    references: ["OWASP API Security Top 10 API1:2023", "CWE-639"]
  },
  "LOCKFILE_MISSING": {
    pattern: "# No package-lock.json in repository",
    fix: "npm install # generates package-lock.json\ngit add package-lock.json\ngit commit -m 'chore: add lockfile'",
    explanation: "Without a lockfile, npm install resolves the latest matching version on each run, opening the door to supply chain attacks.",
    references: ["SLSA L1", "NIST 800-218 PS-3", "CWE-829"]
  },

  // ---------------------------------------------------------------------------
  // Injection — command / SQL / SSRF (high-frequency, high-severity)
  // ---------------------------------------------------------------------------
  "COMMAND_INJECTION": {
    pattern: "child_process.exec(`ping ${req.query.host}`)",
    fix: "import { execFile } from 'node:child_process';\nexecFile('ping', ['-c', '1', '--', req.query.host]); // no shell, args passed as array",
    explanation: "Concatenating user input into a shell command lets an attacker chain arbitrary commands (e.g. `; rm -rf /`). Use execFile/spawn with an argument array so no shell interprets the input, and validate against an allowlist.",
    references: ["CWE-78", "OWASP Top 10 A03:2021", "NIST 800-53 SI-10"]
  },
  "SQL_INJECTION": {
    pattern: "db.query(`SELECT * FROM orders WHERE user = '${req.body.user}'`)",
    fix: "db.query('SELECT * FROM orders WHERE user = $1', [req.body.user]) // parameterized",
    explanation: "String-built SQL lets an attacker alter query logic (auth bypass, data exfiltration, `DROP TABLE`). Always use parameterized queries or an ORM query builder; never interpolate user input.",
    references: ["CWE-89", "OWASP Top 10 A03:2021", "OWASP ASVS 5.3.4"]
  },
  "SSRF_USER_URL": {
    pattern: "const data = await fetch(req.query.url) // user controls destination",
    fix: "const target = new URL(req.query.url);\nif (!ALLOWED_HOSTS.has(target.hostname) || isPrivateIp(target.hostname)) throw new Error('blocked');\nconst data = await fetch(target, { redirect: 'manual' });",
    explanation: "Fetching a user-supplied URL lets an attacker reach internal services and cloud metadata endpoints (169.254.169.254). Enforce a host allowlist, block private/link-local ranges, and disable auto-following redirects.",
    references: ["CWE-918", "OWASP Top 10 A10:2021", "OWASP API Security API7:2023"]
  },

  // ---------------------------------------------------------------------------
  // Object / prototype / parser abuse
  // ---------------------------------------------------------------------------
  "PROTOTYPE_POLLUTION": {
    pattern: "function merge(target, src) { for (const k in src) target[k] = src[k]; } // merges __proto__",
    fix: "for (const k in src) {\n  if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;\n  if (Object.hasOwn(src, k)) target[k] = src[k];\n}\n// or use structuredClone / a Map instead of a plain object",
    explanation: "Recursively merging attacker JSON that contains a `__proto__` key mutates Object.prototype, affecting every object in the process (auth bypass, RCE via gadget chains). Skip prototype keys and use own-property checks.",
    references: ["CWE-1321", "OWASP Top 10 A08:2021"]
  },
  "XXE_ENTITY_PARSING": {
    pattern: "const doc = new DOMParser().parseFromString(xml, 'text/xml') // external entities enabled",
    fix: "import { XMLParser } from 'fast-xml-parser';\nconst parser = new XMLParser({ processEntities: false }); // no DTD / external entities\nconst doc = parser.parse(xml);",
    explanation: "XML parsers that resolve external entities let an attacker read local files (`file:///etc/passwd`), perform SSRF, or trigger billion-laughs DoS. Disable DTD processing and external entity resolution.",
    references: ["CWE-611", "OWASP Top 10 A05:2021", "OWASP XXE Prevention Cheat Sheet"]
  },
  "YAML_UNSAFE_LOAD": {
    pattern: "const cfg = yaml.load(untrustedInput) // full type resolution",
    fix: "const cfg = yaml.load(untrustedInput, { schema: yaml.JSON_SCHEMA }); // no custom tags\n// python: yaml.safe_load(untrusted_input)",
    explanation: "Unsafe YAML loading resolves custom tags that can instantiate arbitrary types and, in some libraries, execute code. Restrict to a safe/JSON schema so only plain data types are produced.",
    references: ["CWE-502", "OWASP Top 10 A08:2021"]
  },
  "DESERIALIZE_UNSAFE": {
    pattern: "const obj = deserialize(Buffer.from(req.body.data, 'base64')) // native object deserialization",
    fix: "const obj = JSON.parse(req.body.data); // data-only\nconst parsed = MySchema.parse(obj); // validate shape before use",
    explanation: "Deserializing attacker-controlled binary into live objects enables gadget-chain RCE. Prefer data-only formats (JSON) and validate the parsed shape against a strict schema before use.",
    references: ["CWE-502", "OWASP Top 10 A08:2021", "OWASP Deserialization Cheat Sheet"]
  },
  "PICKLE_MARSHAL_DESERIALIZATION": {
    pattern: "import pickle; obj = pickle.loads(untrusted_bytes)  # arbitrary code on load",
    fix: "import json\nobj = json.loads(untrusted_str)  # data-only\n# for ML models use safetensors instead of pickle checkpoints",
    explanation: "Python pickle/marshal execute arbitrary code during deserialization via __reduce__, so loading untrusted bytes is RCE. Use JSON for data and safetensors for model weights.",
    references: ["CWE-502", "OWASP Top 10 A08:2021", "MITRE ATLAS AML.T0010"]
  },

  // ---------------------------------------------------------------------------
  // Auth / session / tokens
  // ---------------------------------------------------------------------------
  "JWT_ALG_NONE_ACCEPTED": {
    pattern: "jwt.verify(token, key, { algorithms: ['none', 'HS256'] })",
    fix: "jwt.verify(token, publicKey, { algorithms: ['RS256'] }); // pin exact asymmetric alg, never 'none'",
    explanation: "Accepting the `none` algorithm lets an attacker forge tokens with no signature. Pin a single expected asymmetric algorithm and reject `none` and algorithm-confusion (HS/RS) attempts.",
    references: ["CWE-347", "RFC 8725", "OWASP JWT Security Cheat Sheet"]
  },
  "JWT_KID_INJECTION": {
    pattern: "const key = fs.readFileSync(header.kid) // kid used as a file path",
    fix: "const key = KEY_REGISTRY[header.kid];\nif (!key) throw new Error('unknown kid'); // resolve from a fixed allowlist only",
    explanation: "Using the attacker-controlled `kid` header as a path or SQL lookup enables path traversal / injection to swap in a key the attacker controls. Resolve `kid` only against a fixed, server-side key registry.",
    references: ["CWE-347", "CWE-88", "RFC 8725"]
  },
  "SESSION_FIXATION": {
    pattern: "req.session.userId = user.id // no session regeneration after login",
    fix: "req.session.regenerate(() => {\n  req.session.userId = user.id; // fresh session id post-auth\n});",
    explanation: "Reusing the pre-login session id lets an attacker who planted a known id ride the authenticated session. Regenerate the session identifier immediately after any privilege change (login, step-up).",
    references: ["CWE-384", "OWASP Session Management Cheat Sheet", "OWASP ASVS 3.2.1"]
  },
  "PKCE_NOT_ENFORCED": {
    pattern: "authorize({ response_type: 'code', client_id }) // no code_challenge",
    fix: "authorize({ response_type: 'code', client_id, code_challenge, code_challenge_method: 'S256' });\n// server: require code_verifier at token exchange",
    explanation: "OAuth authorization-code flows without PKCE are vulnerable to code interception, especially for public/mobile clients. Require the S256 code_challenge and validate the code_verifier at token exchange.",
    references: ["RFC 7636", "OAuth 2.1", "CWE-347"]
  },

  // ---------------------------------------------------------------------------
  // Access control
  // ---------------------------------------------------------------------------
  "MASS_ASSIGNMENT": {
    pattern: "await User.update(req.params.id, req.body) // whole body bound to model",
    fix: "const { name, email } = req.body; // explicit allowlist\nawait User.update(req.params.id, { name, email }); // never bind role/isAdmin from input",
    explanation: "Binding the entire request body to a model lets an attacker set privileged fields like `role` or `isAdmin`. Bind only an explicit allowlist of user-editable fields.",
    references: ["CWE-915", "OWASP API Security API3:2023", "OWASP Top 10 A08:2021"]
  },
  "IDOR_DIRECT_ACCESS": {
    pattern: "const doc = await Document.findById(req.params.id) // no owner check",
    fix: "const doc = await Document.findOne({ _id: req.params.id, ownerId: req.auth.userId });\nif (!doc) return res.status(404).end(); // enforce ownership, avoid enumeration",
    explanation: "Looking up an object by user-supplied id without an authorization check lets an attacker read or modify other users' records. Scope every query to the authenticated principal and return 404 on miss.",
    references: ["CWE-639", "OWASP API Security API1:2023", "OWASP Top 10 A01:2021"]
  },

  // ---------------------------------------------------------------------------
  // Web headers / cookies / CORS
  // ---------------------------------------------------------------------------
  "WEB_CORS_WILDCARD": {
    pattern: "res.setHeader('Access-Control-Allow-Origin', '*');\nres.setHeader('Access-Control-Allow-Credentials', 'true')",
    fix: "const origin = req.headers.origin;\nif (ALLOWED_ORIGINS.has(origin)) {\n  res.setHeader('Access-Control-Allow-Origin', origin);\n  res.setHeader('Access-Control-Allow-Credentials', 'true');\n}",
    explanation: "A wildcard CORS origin combined with credentials exposes authenticated responses to any site. Reflect only origins from a server-side allowlist and never pair `*` with credentialed requests.",
    references: ["CWE-942", "OWASP Top 10 A05:2021", "MDN CORS"]
  },
  "WEB_COOKIE_SAMESITE_MISSING": {
    pattern: "res.cookie('session', id, { httpOnly: true }) // no SameSite / Secure",
    fix: "res.cookie('session', id, { httpOnly: true, secure: true, sameSite: 'lax' });",
    explanation: "Session cookies without SameSite are sent on cross-site requests, enabling CSRF. Set SameSite (lax/strict) and the Secure flag so cookies are scoped and only sent over HTTPS.",
    references: ["CWE-1275", "CWE-352", "OWASP CSRF Prevention Cheat Sheet"]
  },
  "WEB_NEXTJS_MIDDLEWARE_AUTH_BYPASS": {
    pattern: "export const config = { matcher: '/dashboard' } // middleware auth on a single path only",
    fix: "export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };\n// re-check authorization in the route handler / server action, not middleware alone",
    explanation: "Relying on Next.js middleware for authorization is bypassable (CVE-2025-29927 spoofed the internal `x-middleware-subrequest` header). Enforce authorization in the data layer / route handler, not solely in middleware.",
    references: ["CWE-285", "CVE-2025-29927", "OWASP Top 10 A01:2021"]
  },
  "WEB_DJANGO_ORM_CONNECTOR_SQLI": {
    pattern: "User.objects.raw('SELECT * FROM users WHERE name = %s' % name) // %-formatted",
    fix: "User.objects.raw('SELECT * FROM users WHERE name = %s', [name]) # params list\n# or User.objects.filter(name=name)",
    explanation: "Django `.raw()` / `.extra()` with Python string formatting reintroduces SQL injection the ORM otherwise prevents. Pass parameters as the second argument, or use the standard queryset API.",
    references: ["CWE-89", "OWASP Top 10 A03:2021", "Django SQL injection docs"]
  },

  // ---------------------------------------------------------------------------
  // Containers / Kubernetes / IaC
  // ---------------------------------------------------------------------------
  "K8S_HOSTPATH_MOUNT": {
    pattern: "volumes:\n  - name: host\n    hostPath:\n      path: /",
    fix: "volumes:\n  - name: data\n    emptyDir: {}\n# or a scoped PersistentVolumeClaim; never mount host root or the docker socket",
    explanation: "Mounting a host path (especially `/` or `/var/run/docker.sock`) gives a compromised pod a route to the node and container escape. Use emptyDir/PVCs and forbid hostPath via admission policy.",
    references: ["CWE-668", "CIS Kubernetes Benchmark 5.7.3", "NIST 800-190"]
  },
  "DOCKER_EXPLICIT_USER_ROOT": {
    pattern: "USER root\nCMD [\"node\", \"server.js\"]",
    fix: "RUN addgroup -S app && adduser -S app -G app\nUSER app\nCMD [\"node\", \"server.js\"]",
    explanation: "Running the container process as root widens the blast radius of any RCE and eases escape. Create and switch to a non-root user before the entrypoint.",
    references: ["CWE-250", "CIS Docker Benchmark 4.1", "NIST 800-190"]
  },
  "IAC_TF_MODULE_GIT_UNPINNED_REF": {
    pattern: "module \"vpc\" {\n  source = \"git::https://github.com/org/modules.git//vpc\"\n}",
    fix: "module \"vpc\" {\n  source = \"git::https://github.com/org/modules.git//vpc?ref=v1.4.2\" # pin to a tag/commit\n}",
    explanation: "A Terraform module sourced from a git ref without a pinned `?ref=` tracks the default branch, so an upstream change (or compromise) is pulled silently. Pin to an immutable tag or commit SHA.",
    references: ["CWE-829", "SLSA L2", "Terraform module source docs"]
  },
  "IAC_AWS_PASSROLE_PRIVESC_CHAIN": {
    pattern: "{ \"Effect\": \"Allow\", \"Action\": \"iam:PassRole\", \"Resource\": \"*\" }",
    fix: "{ \"Effect\": \"Allow\", \"Action\": \"iam:PassRole\", \"Resource\": \"arn:aws:iam::123:role/app-task-role\",\n  \"Condition\": { \"StringEquals\": { \"iam:PassedToService\": \"ecs-tasks.amazonaws.com\" } } }",
    explanation: "`iam:PassRole` on `*` lets a principal hand any role (including admin) to a service it controls, a classic privilege-escalation chain. Scope PassRole to specific role ARNs and constrain the target service.",
    references: ["CWE-269", "AWS IAM PassRole docs", "NIST 800-53 AC-6"]
  },
  "K8S_INGRESS_NGINX_SNIPPET_INJECTION": {
    pattern: "metadata:\n  annotations:\n    nginx.ingress.kubernetes.io/configuration-snippet: |\n      more_set_headers \"X: ${request_uri}\"",
    fix: "# disable snippet annotations cluster-wide:\n# controller flag: --enable-annotation-validation=true\n# helm: controller.allowSnippetAnnotations: false",
    explanation: "ingress-nginx configuration/server snippets let a namespace tenant inject raw NGINX config and read controller secrets (CVE-2025-1974 / IngressNightmare). Disable snippet annotations and enable annotation validation.",
    references: ["CWE-94", "CVE-2025-1974", "NIST 800-190"]
  },

  // ---------------------------------------------------------------------------
  // CI/CD and dependency supply chain
  // ---------------------------------------------------------------------------
  "CI_UNPINNED_ACTION": {
    pattern: "- uses: actions/checkout@v4 # mutable tag",
    fix: "- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1 pinned SHA",
    explanation: "GitHub Actions referenced by a mutable tag can be repointed by an upstream compromise (as in the tj-actions/changed-files incident). Pin third-party actions to a full commit SHA.",
    references: ["CWE-829", "SLSA L3", "GitHub Actions security hardening"]
  },
  "DEP_TYPOSQUAT": {
    pattern: "\"dependencies\": { \"reqiests\": \"^1.0.0\" } // typo of a popular package",
    fix: "\"dependencies\": { \"requests\": \"2.32.3\" } // correct name, exact pin\n// verify against the official registry before installing",
    explanation: "Typosquatted package names (a transposed or misspelled popular name) ship malware that runs on install. Verify the exact package name against the official registry and pin known-good versions.",
    references: ["CWE-427", "OWASP Top 10 A06:2021", "NIST 800-218 PW-4"]
  },
  "SUPPLY_MCP_REMOTE_COMMAND_INJECTION": {
    pattern: "{ \"mcpServers\": { \"tool\": { \"command\": \"sh\", \"args\": [\"-c\", userProvidedCmd] } } }",
    fix: "{ \"mcpServers\": { \"tool\": { \"command\": \"/usr/local/bin/tool\", \"args\": [\"--safe\"] } } }\n// pin the binary, never pass user input to a shell; review server config before trust",
    explanation: "An MCP server config that runs a shell with attacker-influenced arguments yields command execution on the host. Pin the exact binary and static args, and review any third-party MCP server before trusting it.",
    references: ["CWE-78", "OWASP Top 10 A03:2021", "MITRE ATLAS AML.T0051"]
  },

  // ---------------------------------------------------------------------------
  // AI / ML specific
  // ---------------------------------------------------------------------------
  "AI_INVISIBLE_UNICODE_INJECTION": {
    pattern: "const prompt = `Summarize: ${userText}` // userText may contain hidden tag chars",
    fix: "const clean = userText.replace(/[\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\uE0000-\\uE007F]/gu, '');\nconst prompt = `Summarize: ${clean}`;",
    explanation: "Zero-width and Unicode tag characters (U+E0000 block) are invisible to reviewers but tokenized by the model, letting an attacker smuggle hidden instructions. Strip invisible/bidi/tag code points before building the prompt.",
    references: ["CWE-116", "OWASP LLM01:2025", "MITRE ATLAS AML.T0051"]
  },
  "AI_MODEL_PICKLE_OPCODE_DANGEROUS": {
    pattern: "model = torch.load('downloaded.ckpt') # pickle-backed, runs REDUCE/GLOBAL opcodes",
    fix: "from safetensors.torch import load_file\nmodel = load_file('downloaded.safetensors') # no code execution on load",
    explanation: "Pickle-backed model checkpoints execute code via dangerous opcodes (GLOBAL/REDUCE) when loaded, so a downloaded model is untrusted code. Distribute and load weights as safetensors, or scan pickles before loading.",
    references: ["CWE-502", "MITRE ATLAS AML.T0010", "OWASP LLM05:2025"]
  },
  "AI_MCP_CONFIG_RUG_PULL": {
    pattern: "// tool description changes silently after approval (rug pull)\ntool.description = fetchRemote() // mutable, re-fetched each run",
    fix: "const pinned = TOOL_MANIFEST[tool.name];\nif (hash(tool.description) !== pinned.descriptionHash) throw new Error('tool definition changed — re-review required');",
    explanation: "An MCP tool whose description/behavior mutates after the user approves it can inject new instructions later (a rug pull). Pin and hash tool definitions and require re-approval when they change.",
    references: ["CWE-494", "OWASP LLM01:2025", "MITRE ATLAS AML.T0051"]
  },

  // ---------------------------------------------------------------------------
  // Coverage-gap signal: the CISA KEV/EPSS lookup itself could not run, so exploit
  // status is unknown rather than clean. Not a code-pattern fix like the rest of this
  // map — the "fix" is restoring evaluability, not editing source.
  "EVAL_UNAVAILABLE_THREAT_INTEL": {
    pattern: "# npm audit found CVEs, but the CISA KEV / EPSS lookup failed (network error, rate limit, unreachable endpoint) — exploit status unknown, not confirmed clean",
    fix: "# Re-run the gate with network access so CISA KEV and EPSS can be queried\n# Or, if intentionally offline: SECURITY_OFFLINE=1 (skips the check rather than reporting clean)",
    explanation: "A failed threat-intel lookup is not the same as \"no actively-exploited CVEs\" — treating a network failure as a clean result would silently hide known-exploited or high-EPSS dependencies. Re-run with connectivity, or explicitly opt out with SECURITY_OFFLINE=1 so the gap is recorded rather than hidden.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  // The remaining EVAL_UNAVAILABLE_* templates below follow the same convention:
  // none are code-pattern fixes, since the underlying "problem" is a check that
  // could not run, not a vulnerability in the target repo. The "fix" is restoring
  // whatever resource (network, binary, target reachability) the check depends on.
  "EVAL_UNAVAILABLE_NPM_AUDIT": {
    pattern: "# `npm audit --json` produced no output or unparseable output — dependency CVE/exploit status is unknown, not confirmed clean",
    fix: "# Ensure npm is installed and on PATH, then run `npm audit --json` manually to confirm it completes",
    explanation: "An audit that never ran is not the same as a clean audit. Restore npm availability (or network access, since npm audit queries the registry) and re-run before trusting a clean dependency-CVE result.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_CLOUD_CONTROLS": {
    pattern: "# defaults/cloud-controls/{aws,gcp,azure}.json could not be read — IaC misconfiguration status is unknown for the affected provider(s), not confirmed clean",
    fix: "# Reinstall the security-mcp package (npm install) and confirm the missing defaults/cloud-controls/*.json file(s) are present",
    explanation: "The FSBP/CIS cloud-control ruleset ships as bundled JSON files. If one is missing or unreadable (a stale or partial install), the entire provider's rule set is unavailable and must not be silently treated as \"zero violations.\"",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_NUCLEI_DAST": {
    pattern: "# SECURITY_STAGING_URL was set (DAST requested) but nuclei is missing, or the scan against the live target failed to return output",
    fix: "# Install nuclei (https://github.com/projectdiscovery/nuclei) and/or verify the target is reachable, then re-run",
    explanation: "DAST was explicitly requested via SECURITY_STAGING_URL. A missing binary or a failed live scan means the check the operator asked for did not run — that is not evidence the target is free of the misconfigurations DAST checks for.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_SCANNER_GITLEAKS": {
    pattern: "# gitleaks ran but produced no readable JSON report (timeout, crash, or permission error) — secret-scan result is unknown, not confirmed clean",
    fix: "# Re-run gitleaks manually against the same source to see its actual output and diagnose the failure",
    explanation: "A scanner that fails to produce a report is not the same as a scanner that found nothing. Diagnose and fix the underlying failure (timeout, permissions, disk space) before trusting a clean result.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_SCANNER_SEMGREP": {
    pattern: "# semgrep ran but produced no readable JSON report (timeout, crash, or permission error) — SAST result is unknown, not confirmed clean",
    fix: "# Re-run semgrep manually against the same source to see its actual output and diagnose the failure",
    explanation: "A scanner that fails to produce a report is not the same as a scanner that found nothing. Diagnose and fix the underlying failure (timeout, permissions, disk space) before trusting a clean result.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_SCANNER_TRIVY": {
    pattern: "# trivy ran but produced no readable JSON report (timeout, crash, or permission error) — container/dependency CVE result is unknown, not confirmed clean",
    fix: "# Re-run trivy manually against the same target to see its actual output and diagnose the failure",
    explanation: "A scanner that fails to produce a report is not the same as a scanner that found nothing. Diagnose and fix the underlying failure (timeout, permissions, disk space) before trusting a clean result.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_SCANNER_CHECKOV": {
    pattern: "# checkov ran but produced no readable JSON report (timeout, crash, or permission error) — IaC misconfiguration result is unknown, not confirmed clean",
    fix: "# Re-run checkov manually against the same source to see its actual output and diagnose the failure",
    explanation: "A scanner that fails to produce a report is not the same as a scanner that found nothing. Diagnose and fix the underlying failure (timeout, permissions, disk space) before trusting a clean result.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_SCANNER_OSV_SCANNER": {
    pattern: "# osv-scanner ran but produced no readable JSON report (timeout, crash, or permission error) — dependency vulnerability result is unknown, not confirmed clean",
    fix: "# Re-run osv-scanner manually against the same source to see its actual output and diagnose the failure",
    explanation: "A scanner that fails to produce a report is not the same as a scanner that found nothing. Diagnose and fix the underlying failure (timeout, permissions, disk space) before trusting a clean result.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_RUNTIME_HEADERS": {
    pattern: "# The configured runtime target did not answer the HTTP header probe (timeout or connection error) — header-hardening status is unknown, not confirmed clean",
    fix: "# Verify the target is reachable from the environment running the gate, then re-run",
    explanation: "A target that never answered is not the same as a target with no missing headers. Fix connectivity to the target before trusting a clean header-hardening result.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_RUNTIME_TLS": {
    pattern: "# The TLS handshake against the configured runtime target timed out or errored — TLS/certificate posture is unknown, not confirmed clean",
    fix: "# Verify the target is reachable and accepting TLS connections from the environment running the gate, then re-run",
    explanation: "A TLS probe that never completed is not the same as a target with no weak TLS version, weak cipher, or certificate problem. Fix connectivity before trusting a clean TLS result.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_AUTH_DEEP": {
    pattern: "# An internal error aborted the auth-deep check before any of its ~40 sub-checks (JWT, session, OAuth, SAML, timing) could report — status is unknown, not confirmed clean",
    fix: "# Check the gate logs for the underlying error; file a bug if it reproduces",
    explanation: "One failing sub-check currently discards every other sub-check's result in this module. A crash here is not the same as a clean auth-hardening pass.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "GATE_CHECK_CRASHED": {
    pattern: "# A check module, or a rule inside one, threw instead of returning findings — that module's coverage is unknown for this run, not clean",
    fix: "# Read the evidence for the module and error named in the finding, reproduce it locally, and file a bug; re-run the gate once fixed",
    explanation: "Findings the failed rule would have produced are missing from this report. Absence of a finding from a crashed rule is not evidence that the vulnerability is absent, so a PASS that includes this finding is a partial result. Rules now settle independently, so the rest of the module still reported.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  // ── Gate-level findings ────────────────────────────────────────────────────
  // Emitted by the gate itself (policy.ts, baseline.ts, exceptions.ts) rather than
  // by a check module. They had no templates because the rule/template parity claim
  // only ever compared src/gate/checks/**, so `security.generate_remediations`
  // returned nothing for a report containing a baseline regression or any
  // exceptions-integrity finding — the findings operators are most likely to need
  // guidance on, since each is a decision rather than a code change.
  "BASELINE_REGRESSION": {
    pattern: "# This run introduced findings that are not in the stored baseline",
    fix: "# Triage each new finding, then re-baseline only after it is fixed or covered by a signed exception",
    explanation: "A baseline records the findings that existed at a point in time so a change set is judged on what it adds. Regenerating the baseline to make a regression disappear accepts the risk silently and without an owner, expiry, or ticket.",
    references: ["NIST 800-218 RV-1", "SOC 2 CC7.2"]
  },
  "CI_EXCEPTIONS_IN_LOCAL_SCAN": {
    pattern: "# .github/security-exceptions-ci.json was loaded during a local (non-CI) run",
    fix: "# Keep local risk acceptance in .mcp/exceptions/security-exceptions.json; leave the CI file to CI",
    explanation: "The CI exceptions file records decisions taken for the CI self-scan. Loading it locally suppresses findings under justifications that were never reviewed for the local scope, and hides the difference between what CI enforces and what you just ran.",
    references: ["NIST 800-53 CM-3", "SOC 2 CC8.1"]
  },
  "CONTROL_EVIDENCE_MISSING": {
    pattern: "# A required control has no evidence artifact in this repository",
    fix: "# Add the artifact the control expects and map it in defaults/evidence-map.json, or record a signed exception stating why the control does not apply",
    explanation: "A control with no evidence is unverified, not satisfied. Either produce the artifact (threat model, pentest sign-off, IR playbook, SBOM) or state in an approved, expiring exception why this system does not implement it.",
    references: ["NIST 800-53 CA-2", "SOC 2 CC4.1", "ISO 27001 A.5.35"]
  },
  "EVIDENCE_MAPPING_MISSING": {
    pattern: "# A control in the catalog has no entry in the evidence map",
    fix: "# Add the control id to defaults/evidence-map.json with the file globs that prove it",
    explanation: "Without a mapping the gate cannot look for the control's evidence at all, so the control is neither satisfied nor reported as failing — it simply drops out of coverage.",
    references: ["NIST 800-53 CA-7", "SOC 2 CC4.1"]
  },
  "EXCEPTIONS_FILE_UNSIGNED": {
    pattern: "# The exceptions file carries no valid HMAC signature",
    fix: "SECURITY_POLICY_HMAC_KEY=<key> security-mcp sign-exceptions   # then commit the signed file",
    explanation: "The exceptions file lives inside the repository under scan, so its name and location prove nothing: any change to the repo can add or edit one. A signature made with a key the repository does not contain is what turns it from configuration into an authenticated act of risk acceptance. Unsigned, it may hide LOW/MEDIUM only.",
    references: ["CWE-345", "NIST 800-53 CM-5", "SOC 2 CC8.1"]
  },
  "EXCEPTIONS_UNSIGNED_SUPPRESSION": {
    pattern: "# An unsigned exceptions file suppressed findings in this run",
    fix: "# Sign the file (security-mcp sign-exceptions) so the suppression is attributable, or resolve the findings instead of hiding them",
    explanation: "This finding mirrors the highest severity that was hidden, so the report cannot look cleaner than the suppression it applied. Signing records who accepted the risk; without it the suppression has no accountable owner.",
    references: ["CWE-345", "NIST 800-53 CM-5"]
  },
  "EXCEPTION_MISSING_TICKET": {
    pattern: "# An exception entry has no tracking ticket, and the policy requires one",
    fix: "# Add ticket, owner, approver and expiry to the entry, then re-sign the file",
    explanation: "An exception without a ticket has no audit trail: no reviewer, no revisit date, and nothing linking the accepted risk to the decision that accepted it.",
    references: ["SOC 2 CC3.2", "ISO 27001 A.5.36"]
  },
  "EXCEPTION_UNSIGNED_HIGH_BLOCKED": {
    pattern: "# An unsigned exception tried to suppress a HIGH/CRITICAL finding and was refused",
    fix: "# Fix the underlying finding, or sign the exceptions file so the acceptance is authenticated and attributable",
    explanation: "Refusing the suppression is the intended behaviour, not an error: a fork or an untrusted change set cannot produce a valid signature, so it cannot silence blocking findings by editing a file it controls. The finding it tried to hide is still active.",
    references: ["CWE-345", "NIST 800-53 CM-5", "SOC 2 CC8.1"]
  },
  "SECURITY_EXCEPTION_EXPIRED": {
    pattern: "# An exception's expiry date has passed, so it no longer suppresses anything",
    fix: "# Re-review the risk, then either fix the finding or re-approve with a new expiry and re-sign the file",
    explanation: "Expiry is what stops a temporary acceptance becoming permanent. An expired entry is deliberately inert, which means the findings it used to hide are back in the report and blocking again.",
    references: ["SOC 2 CC3.2", "ISO 27001 A.5.36", "NIST 800-53 CA-5"]
  },
  "SEARCH_RESULTS_TRUNCATED": {
    pattern: "# One or more detection queries stopped at their match cap — the rules driven by them saw a prefix of the matching lines, not all of them",
    fix: "# Scan in smaller slices: SECURITY_GATE_TARGETS=src/api then src/web, and SECURITY_GATE_IGNORE for vendored or generated trees",
    explanation: "A capped search and an exhausted search return the same result, so a rule that filters its hits (keep the ones without a sanitizer on the line) or intersects two searches by filename can miss the match that mattered. Expected on large monorepos; treat it as reduced confidence in the absence of findings, not as a vulnerability and not as a clean result.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },
  "EVAL_UNAVAILABLE_BUSINESS_LOGIC": {
    pattern: "# An internal error aborted the business-logic check before any of its ~37 sub-checks (refund, inventory, race conditions, payments) could report — status is unknown, not confirmed clean",
    fix: "# Check the gate logs for the underlying error; file a bug if it reproduces",
    explanation: "One failing sub-check currently discards every other sub-check's result in this module. A crash here is not the same as a clean business-logic pass.",
    references: ["CWE-1188", "NIST 800-218 RV-1"]
  },

  // ---------------------------------------------------------------------------
  // 1.5.0 emerging-threat fixes — every new detection ships a concrete fix so the
  // gate stays 90% fixing / 10% advisory. (Templates for the remaining new IDs.)
  // ---------------------------------------------------------------------------
  "WEB_RSC_FLIGHT_DESERIALIZATION_RCE": {
    pattern: "\"react\": \"19.2.0\", \"next\": \"15.2.0\" // React2Shell RSC deserialization RCE",
    fix: "// Upgrade to a patched line, e.g.\n\"react\": \"19.2.1\", \"next\": \"15.3.6\"\n// then `npm ci` and redeploy; add a WAF rule blocking POST bodies with `$1:__proto__:then`",
    explanation: "Unpatched React Server Components deserialize a crafted Flight payload and execute attacker code pre-auth (CVE-2025-55182, CVSS 10). Upgrade react/next to a patched release; there is no safe config workaround on a vulnerable version.",
    references: ["CWE-502", "CVE-2025-55182", "OWASP Top 10 A08:2021"]
  },
  "WEB_PROXY_MIDDLEWARE_HEADER_UNSTRIPPED": {
    pattern: "location / { proxy_pass http://app; } # forwards client x-middleware-subrequest",
    fix: "location / {\n  proxy_set_header x-middleware-subrequest \"\"; # strip client-supplied value\n  proxy_pass http://app;\n}",
    explanation: "Next.js middleware auth is bypassed when a client supplies the internal `x-middleware-subrequest` header (CVE-2025-29927). At the edge, always strip this header from inbound requests so only the framework can set it.",
    references: ["CWE-285", "CVE-2025-29927"]
  },
  "WEB_KESTREL_CHUNKED_SMUGGLING": {
    pattern: "<PackageReference Include=\"Microsoft.AspNetCore\" Version=\"8.0.10\" /> // pre-patch",
    fix: "<PackageReference Include=\"Microsoft.AspNetCore\" Version=\"8.0.11\" />\n// never set AppContext InsecureChunkedParsing=true",
    explanation: "Kestrel accepted a lone \\n in chunk extensions, letting a front-end proxy desync and smuggle requests (CVE-2025-55315, CVSS 9.9). Upgrade ASP.NET Core and remove any InsecureChunkedParsing compatibility flag.",
    references: ["CWE-444", "CVE-2025-55315"]
  },
  "WEB_JWT_JKU_X5U_SSRF": {
    pattern: "const key = await fetch(jwt.header.jku).then(r => r.json()) // attacker-controlled URL",
    fix: "const ALLOWED_JKU = new Set(['https://auth.example.com/.well-known/jwks.json']);\nif (!ALLOWED_JKU.has(jwt.header.jku)) throw new Error('untrusted jku');",
    explanation: "Fetching JWT signing keys from a URL inside the token header (jku/x5u) lets an attacker point the verifier at their own key or an internal host (SSRF + signature bypass). Pin JWKS URLs to a strict allowlist.",
    references: ["CWE-918", "CWE-347", "RFC 7515"]
  },
  "WEB_PATH_TO_REGEXP_REDOS": {
    pattern: "\"path-to-regexp\": \"6.2.0\" // catastrophic backtracking on crafted routes",
    fix: "\"path-to-regexp\": \"8.0.0\" // patched\n// regenerate lockfile and `npm ci`",
    explanation: "Vulnerable path-to-regexp ranges compile route patterns that backtrack exponentially, so one crafted URL stalls the event loop (ReDoS DoS). Upgrade to a patched version.",
    references: ["CWE-1333", "OWASP A06:2021"]
  },
  "IAC_GCP_TOKEN_CREATOR_PROJECT_BINDING": {
    pattern: "resource \"google_project_iam_member\" \"x\" {\n  role = \"roles/iam.serviceAccountTokenCreator\"\n}",
    fix: "resource \"google_service_account_iam_member\" \"x\" {\n  service_account_id = google_service_account.target.name # scoped to ONE SA\n  role               = \"roles/iam.serviceAccountTokenCreator\"\n}",
    explanation: "Binding serviceAccountTokenCreator/User at project level lets the member impersonate every service account in the project — a privilege-escalation chain. Scope the binding to the single service account that actually needs it.",
    references: ["CWE-269", "CIS GCP 1.5", "MITRE ATT&CK T1078.004"]
  },
  "K8S_RUNC_ESCAPE_DELIVERY_SURFACE": {
    pattern: "securityContext:\n  privileged: true\nvolumeMounts:\n  - mountPath: /host\n    name: hostroot # hostPath bind",
    fix: "securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false\n  runAsNonRoot: true\nhostUsers: false   # user-namespace remap\n# remove hostPath mounts; pin runc >= 1.2.8/1.3.3",
    explanation: "Privileged pods and hostPath mounts are the delivery path for the 2025 runc container escapes (CVE-2025-31133/52565/52881). Drop privilege, enable user-namespace remapping, remove host mounts, and patch runc on the nodes.",
    references: ["CWE-59", "CVE-2025-31133", "MITRE ATT&CK T1611"]
  },
  "SUPPLY_LOCKFILE_OFFREGISTRY_RESOLVED": {
    pattern: "\"resolved\": \"https://evil.example.com/left-pad/-/left-pad-1.3.0.tgz\"",
    fix: "\"resolved\": \"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\"\n// regenerate lockfile from a trusted registry; verify integrity hashes",
    explanation: "A lockfile `resolved` URL pointing off the official registry can silently substitute a malicious tarball even when the name looks legitimate. Regenerate the lockfile against the trusted registry and review the integrity hash.",
    references: ["CWE-345", "SLSA L2", "OWASP A08:2021"]
  },
  "SUPPLY_SHAI_HULUD_IOC": {
    pattern: "// package ships router_init.js >1MB / known IoC hash / postinstall exfil",
    fix: "// 1) Remove the package + delete node_modules and the lockfile entry\n// 2) Rotate every exposed secret: NPM_TOKEN, GITHUB_TOKEN, AWS_* keys\n// 3) Audit for rogue self-hosted GitHub runners and pin all deps to safe versions\n// 4) `npm ci` from a clean, trusted lockfile",
    explanation: "The Shai-Hulud worm embeds self-replicating exfiltration in npm/PyPI packages and steals CI/cloud secrets. Remediation is containment, not a code edit: remove the package, rotate all credentials it could have read, hunt for attacker-installed runners, and reinstall from a trusted lockfile.",
    references: ["CWE-506", "CWE-829", "MITRE ATT&CK T1195.002"]
  },
  "AI_A2A_CREDENTIAL_FORWARDING": {
    pattern: "downstreamAgent.invoke({ token: req.headers.authorization }) // forwards caller creds",
    fix: "const scoped = await mintScopedToken({ audience: 'downstream', scopes: ['read:x'], ttl: 60 });\ndownstreamAgent.invoke({ token: scoped }); // least-privilege, short-lived",
    explanation: "Forwarding the caller's credentials to a downstream agent makes it a confused deputy with the caller's full authority. Mint a fresh, audience-scoped, short-lived token for each delegation instead.",
    references: ["CWE-441", "CWE-863", "OWASP LLM06:2025"]
  },

  // ---------------------------------------------------------------------------
  // "Vibe coding" — how attackers exploit AI-generated apps (Cursor / Lovable /
  // Bolt / v0 / Replit). Paired with src/gate/checks/vibe-coding.ts.
  // ---------------------------------------------------------------------------
  "VIBE_SUPABASE_SERVICE_ROLE_IN_CLIENT": {
    pattern: "// client component\nconst supabase = createClient(url, 'eyJ...service_role...') // sb_secret / service_role key in browser",
    fix: "// browser: anon/publishable key only, protected by RLS\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n// server route/Edge Function only:\nconst admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);",
    explanation: "The Supabase service_role / sb_secret_ key bypasses Row-Level Security and grants full read/write to every table. Shipped in browser code it is public to every visitor (the Moltbook breach). Rotate it, keep it server-only, and use the anon key + RLS in the client.",
    references: ["CWE-522", "CWE-269", "OWASP A07:2021"]
  },
  "VIBE_PUBLIC_ENV_HOLDS_SECRET": {
    pattern: "NEXT_PUBLIC_STRIPE_SECRET_KEY=<stripe-secret-key>  # inlined into the client bundle",
    fix: "STRIPE_SECRET_KEY=<stripe-secret-key>   # server-only, no public prefix\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=<stripe-publishable-key>  # safe to publish",
    explanation: "Any NEXT_PUBLIC_/VITE_/REACT_APP_/EXPO_PUBLIC_/PUBLIC_ variable is compiled into the browser bundle. Naming a real secret with that prefix ships it to every visitor. Drop the prefix, read it server-side, and reserve public prefixes for publishable/anon values.",
    references: ["CWE-798", "OWASP A02:2021", "NIST 800-53 IA-5"]
  },
  "VIBE_PROVIDER_KEY_IN_FRONTEND": {
    pattern: "// client-side fetch to a provider with a raw key\nfetch('https://api.openai.com/v1/chat/completions', { headers: { Authorization: 'Bearer sk-proj-XXXXplaceholderXXXX' } })",
    fix: "// browser calls YOUR server; the key stays server-side\nawait fetch('/api/chat', { method: 'POST', body: JSON.stringify({ prompt }) });\n// server route: const key = process.env.OPENAI_API_KEY;",
    explanation: "A provider API key (OpenAI/Anthropic/Stripe/AWS/Google/GitHub) hardcoded in browser code is visible to every visitor and is billed to you. Proxy the call through a server route that holds the key in a server-only env var, and rotate any key that shipped to the client.",
    references: ["CWE-798", "OWASP A02:2021", "OWASP LLM06:2025"]
  },
  "VIBE_SUPABASE_RLS_DISABLED": {
    pattern: "create table profiles (id uuid primary key, email text);\n-- no ENABLE ROW LEVEL SECURITY; anon key reads all rows\ncreate policy p on profiles using (true);",
    fix: "alter table public.profiles enable row level security;\ncreate policy owner_read on public.profiles\n  for select using (auth.uid() = id);",
    explanation: "A Supabase/Postgres table is only safe with Row-Level Security enabled AND a restrictive policy. Without it (or with USING (true)) the public anon key reads and writes every row — the Lovable CVE-2025-48757 pattern. Enable RLS and scope policies to the owning user.",
    references: ["CWE-862", "CVE-2025-48757", "OWASP A01:2021"]
  },
  "VIBE_FIREBASE_RULES_PUBLIC": {
    pattern: "// firestore.rules\nmatch /{document=**} { allow read, write: if true; }   // world-open",
    fix: "match /users/{uid} {\n  allow read, write: if request.auth != null && request.auth.uid == uid;\n}",
    explanation: "Firebase security rules are the only thing between the public web SDK and your data. A rule that evaluates to true makes the whole database/bucket world-readable and writable (the Tea app breach). Require request.auth and a per-document ownership check, then add App Check.",
    references: ["CWE-306", "OWASP A01:2021"]
  },
  "VIBE_API_ROUTE_NO_SERVER_AUTHZ": {
    pattern: "// app/api/orders/route.ts\nexport async function GET() { return Response.json(await db.order.findMany()) } // no auth",
    fix: "export async function GET() {\n  const session = await getServerSession(authOptions);\n  if (!session) return new Response('Unauthorized', { status: 401 });\n  return Response.json(await db.order.findMany({ where: { userId: session.user.id } }));\n}",
    explanation: "Hiding a button in the frontend is not authorization — an attacker calls the API directly and gets everyone's data (the Base44 breach). Verify the session at the top of every handler and scope every query to the authenticated user.",
    references: ["CWE-306", "CWE-862", "OWASP API1:2023"]
  },
  "VIBE_CLIENT_SIDE_AUTH_GUARD_ONLY": {
    pattern: "'use client';\nif (!user) router.push('/login'); // only protection — runs in the attacker's browser",
    fix: "// server component / middleware enforces access:\nconst session = await getServerSession(authOptions);\nif (!session) redirect('/login');\n// AND every API the page calls re-checks the session",
    explanation: "A client-side redirect guard only hides UI; it runs in the browser and is trivially bypassed (disable JS, call the API directly). Keep it for UX but enforce the real check on the server for both the page and its data endpoints.",
    references: ["CWE-602", "OWASP A01:2021"]
  },
  "VIBE_CORS_WILDCARD_CREDENTIALS": {
    pattern: "app.use(cors()); // reflects any origin\napp.use(cors({ origin: '*', credentials: true }));",
    fix: "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));",
    explanation: "A wildcard or reflected CORS origin combined with credentials lets any website make authenticated cross-origin requests with the victim's cookies and read the response. Use an explicit origin allowlist and never pair origin '*'/true with credentials:true.",
    references: ["CWE-942", "OWASP A05:2021"]
  },
  "VIBE_CLIENT_CONTROLLED_PRICE": {
    pattern: "const amount = req.body.amount; // user sets their own price\nstripe.paymentIntents.create({ amount, currency: 'usd' })",
    fix: "const product = await db.product.findUnique({ where: { id: req.body.productId } });\nstripe.paymentIntents.create({ amount: product.priceCents, currency: 'usd' })",
    explanation: "Trusting the amount/price/total from the request lets a user pay $0.01 for a $100 item by editing the request. Look up the authoritative price server-side by product ID and ignore any amount the client sends; reconcile in the webhook before fulfilling.",
    references: ["CWE-807", "OWASP A04:2021", "OWASP API6:2023"]
  },
  "VIBE_TOKEN_IN_LOCALSTORAGE": {
    pattern: "localStorage.setItem('access_token', token); // readable by any XSS",
    fix: "// server sets an httpOnly cookie JS cannot read:\nres.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });",
    explanation: "Tokens in localStorage are readable by any script on the page, so a single XSS exfiltrates every user's session. Store the session in an httpOnly, Secure, SameSite cookie set by the server, or hold a token only in memory for the tab's lifetime.",
    references: ["CWE-522", "OWASP A07:2021", "OWASP ASVS 3.2"]
  },
  "VIBE_UNRESTRICTED_FILE_UPLOAD": {
    pattern: "const upload = multer({ dest: 'uploads/' }); // no fileFilter, no limits",
    fix: "const upload = multer({\n  limits: { fileSize: 5 * 1024 * 1024 },\n  fileFilter: (_req, file, cb) => cb(null, ['image/png','image/jpeg'].includes(file.mimetype))\n});",
    explanation: "An upload with no MIME/extension allowlist and no size limit lets an attacker upload a web shell or an oversized file (DoS). Allowlist expected types (verified by content, not just the client header), cap the size, and store uploads outside the web root with a random name.",
    references: ["CWE-434", "OWASP A04:2021"]
  },
  "VIBE_ENV_FILE_COMMITTED": {
    pattern: "# .env and serviceAccount.json tracked in git, not in .gitignore",
    fix: "# .gitignore\n.env*\n!.env.example\n*.pem\nserviceAccount*.json\nid_rsa\n# then: git rm --cached .env serviceAccount.json && rotate every secret",
    explanation: "A committed .env / serviceAccount.json / *.pem / id_rsa leaks every secret it holds, and stays exposed in git history after deletion. Rotate the secrets, gitignore the files, git rm --cached them, and purge history with git-filter-repo/BFG.",
    references: ["CWE-540", "CWE-312", "OWASP A05:2021"]
  },
  "VIBE_SOURCEMAPS_IN_PROD": {
    pattern: "// next.config.js\nmodule.exports = { productionBrowserSourceMaps: true } // ships source to the browser",
    fix: "module.exports = { productionBrowserSourceMaps: false };\n// upload maps privately to your error tracker (e.g. Sentry) instead",
    explanation: "Production source maps publish your original unminified source — comments, internal endpoints, sometimes inlined secrets — to anyone with dev-tools. Disable browser-served maps in prod and upload them privately to your error monitor if needed.",
    references: ["CWE-540", "CWE-200", "OWASP A05:2021"]
  },
  "VIBE_DEBUG_MODE_ENABLED": {
    pattern: "app.run(debug=True)   # Flask Werkzeug debugger = RCE surface\nres.json({ error: err.stack })  # leaks internals",
    fix: "app.run(debug=os.environ.get('FLASK_DEBUG') == '1')  # default off\nres.status(500).json({ error: 'Internal error', requestId })  # log stack server-side",
    explanation: "Debug mode in production exposes an interactive console and stack traces (Flask/Django debug=True is a known RCE via the Werkzeug PIN). Drive debug from the environment defaulting off, drop Express errorhandler() in prod, and never return err.stack in a response.",
    references: ["CWE-489", "CWE-209", "OWASP A05:2021"]
  },
  "VIBE_HALLUCINATED_OR_UNVETTED_DEP": {
    pattern: "// package.json declares a package that is NOT in the lockfile\n\"dependencies\": { \"react-safe-fetcher\": \"^1.0.0\" }  // does it even exist?",
    fix: "// verify on the official registry (npmjs.com / pypi.org): publisher, age, downloads\n// then install so it is recorded and pinned in the lockfile:\nnpm install react-safe-fetcher && git add package-lock.json",
    explanation: "AI assistants sometimes invent plausible-but-nonexistent package names that attackers pre-register (slopsquatting). A dependency missing from the lockfile is a heuristic signal — verify the package really exists and is the intended one, check publisher/age/downloads, then pin it.",
    references: ["CWE-1357", "CWE-829", "OWASP A06:2021"]
  },
  "VIBE_PROMPT_INJECTION_UNSAFE_CHAIN": {
    pattern: "messages: [{ role: 'system', content: `You are a bot. ${req.body.userInput}` }]\neval(response.choices[0].message.content) // model output as code",
    fix: "messages: [\n  { role: 'system', content: 'You are a bot.' },\n  { role: 'user', content: req.body.userInput }  // user text stays in the user role\n]\n// treat model output as data: validate against an allowlist; sanitize HTML with DOMPurify; never eval it",
    explanation: "Concatenating user input into the system prompt lets the user override your instructions (prompt injection), and feeding model output into eval/exec/shell/dangerouslySetInnerHTML turns the LLM's text into code (RCE/XSS). Keep user text in the user role and treat model output as untrusted data.",
    references: ["CWE-77", "CWE-94", "OWASP LLM01:2025"]
  }
};

// The full lookup: base templates plus every domain partial. Object.assign merges
// in priority order (later sources win on the rare shared key). Domain partials
// only cover finding IDs the base map does not, so in practice there are no
// collisions — this raises deterministic fix coverage from ~8% to the vast
// majority of the engine's finding IDs (the 90%-fix mandate).
export const REMEDIATION_MAP: Record<string, RemediationTemplate> = {
  ...BASE_REMEDIATION_MAP,
  ...CLOUD_REMEDIATIONS,
  ...AI_REMEDIATIONS,
  ...DATA_REMEDIATIONS,
  ...WEB_REMEDIATIONS,
  ...WEB_HARDENING_REMEDIATIONS,
  ...MISC_REMEDIATIONS,
};
