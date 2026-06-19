// Remediation templates for security.generate_remediations.
// Relocated out of src/mcp/server.ts: these entries embed intentional "before"
// vulnerable-code examples (md5, SQL concatenation, sslmode=disable, ...) used to
// teach fixes. Living under src/gate/ means the gate self-scan excludes them
// (searchRepo ignores src/gate/**), so the examples no longer self-trigger checks.

export type RemediationTemplate = {
  pattern: string;
  fix: string;
  explanation: string;
  references: string[];
};

export const REMEDIATION_MAP: Record<string, RemediationTemplate> = {
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
  "DEP_FLOATING_VERSION": {
    pattern: "\"some-package\": \"^1.0.0\"",
    fix: "\"some-package\": \"1.2.3\" // exact pin\n// or use npm shrinkwrap / lockfile",
    explanation: "Floating version ranges allow unexpected major/minor updates that may introduce vulnerabilities or breaking changes.",
    references: ["SLSA L1", "OWASP Top 10 A06:2021"]
  }
};
