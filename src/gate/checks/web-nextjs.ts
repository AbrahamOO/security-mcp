import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

// ---------------------------------------------------------------------------
// Helper — run all checks in parallel and flatten results
// ---------------------------------------------------------------------------

type CheckFn = () => Promise<Finding[]>;

async function runAll(checks: CheckFn[]): Promise<Finding[]> {
  const results = await Promise.all(checks.map((fn) => fn()));
  return results.flat();
}

// ---------------------------------------------------------------------------
// 1. CSP and security headers (EXISTING)
// ---------------------------------------------------------------------------

async function checkSecurityHeaders(): Promise<Finding[]> {
  const headerFiles = await fg(
    ["middleware.ts", "middleware.tsx", "src/middleware.ts", "next.config.*"],
    { dot: true }
  );

  if (headerFiles.length === 0) {
    return [
      {
        id: "WEB_HEADERS_MISSING",
        title: "Security headers not found (CSP/HSTS/etc.)",
        severity: "HIGH",
        requiredActions: [
          "Add strict security headers: CSP (no inline JS), HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy.",
          "Enforce secure cookies: HttpOnly, Secure, SameSite, short-lived tokens."
        ]
      }
    ];
  }

  const combined = (
    await Promise.all(headerFiles.map((f) => readFileSafe(f).catch(() => "")))
  ).join("\n");

  const mustContain = [
    "content-security-policy",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy"
  ];
  const missing = mustContain.filter((k) => !combined.toLowerCase().includes(k));

  if (missing.length === 0) return [];
  return [
    {
      id: "WEB_HEADERS_INCOMPLETE",
      title: "Security headers exist but appear incomplete",
      severity: "HIGH",
      evidence: [`Missing: ${missing.join(", ")}`],
      requiredActions: [
        "Add missing headers and ensure CSP forbids inline scripts (no 'unsafe-inline').",
        "Add a CSP nonce strategy if you must load dynamic scripts."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 2. dangerouslySetInnerHTML (EXISTING)
// ---------------------------------------------------------------------------

async function checkDangerouslySetInnerHTML(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: "dangerouslySetInnerHTML",
    isRegex: false,
    maxMatches: 200
  });
  if (hits.length === 0) return [];
  return [
    {
      id: "DANGEROUSLY_SET_INNER_HTML",
      title: "dangerouslySetInnerHTML usage detected",
      severity: "HIGH",
      evidence: hits.slice(0, 20).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "Remove dangerouslySetInnerHTML where possible.",
        "If unavoidable: sanitize with a proven HTML sanitizer and add unit tests with XSS payloads."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 3. SSRF guard (EXISTING)
// ---------------------------------------------------------------------------

async function checkSsrf(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`\bfetch\(|axios\(|got\(|undici\b`,
    isRegex: true,
    maxMatches: 200
  });
  if (hits.length === 0) return [];
  return [
    {
      id: "SSRF_GUARD_REQUIRED",
      title: "Server-side fetch patterns detected. SSRF protections must be enforced.",
      severity: "HIGH",
      evidence: hits.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "Implement SSRF guard for any server-side HTTP client: block localhost, private IP ranges, and cloud metadata endpoints.",
        "Require URL allowlists for outbound calls. Add tests for 127.0.0.1, 10/8, 172.16/12, 192.168/16, 169.254.169.254, metadata.google.internal."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 4. WEB_OPEN_REDIRECT — unvalidated redirects with user-controlled input
// ---------------------------------------------------------------------------

async function checkOpenRedirect(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`redirect\(|res\.redirect\(`,
    isRegex: true,
    maxMatches: 200
  });

  // Filter to lines that also reference common user-input sources
  const suspicious = hits.filter((m) =>
    /req\.(query|body)|searchParams|\.get\(/.test(m.preview)
  );

  if (suspicious.length === 0) return [];
  return [
    {
      id: "WEB_OPEN_REDIRECT",
      title: "Unvalidated redirect with user-controlled input detected",
      severity: "HIGH",
      evidence: suspicious.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "Validate redirect destinations against a strict allowlist of trusted origins.",
        "Never pass raw req.query, req.body, or searchParams values directly to redirect().",
        "Return a 400 if the destination is not in the allowlist."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 5. WEB_IDOR_RISK — direct object reference from URL params without auth check
// ---------------------------------------------------------------------------

async function checkIdorRisk(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`params\.(id|userId|user_id|accountId|account_id)\b`,
    isRegex: true,
    maxMatches: 200
  });

  // Keep only hits that don't have an obvious auth guard on the same or adjacent line
  const suspicious = hits.filter(
    (m) => !/auth|session|getServerSession|currentUser|requireAuth|userId\s*===/.test(m.preview)
  );

  if (suspicious.length === 0) return [];
  return [
    {
      id: "WEB_IDOR_RISK",
      title: "Direct object reference from URL params without visible ownership check",
      severity: "HIGH",
      evidence: suspicious.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "After fetching a resource by URL param, verify the authenticated user owns or is authorised to access it.",
        "Never rely on obscurity of IDs — enforce ownership checks server-side.",
        "Use opaque, non-guessable IDs (UUIDs) and still enforce access control."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 6. WEB_SERVER_ACTION_UNVALIDATED — Server Actions without Zod validation
// ---------------------------------------------------------------------------

async function checkServerActionValidation(): Promise<Finding[]> {
  // Find all files that contain "use server"
  const useServerHits = await searchRepo({
    query: '"use server"',
    isRegex: false,
    maxMatches: 200
  });

  if (useServerHits.length === 0) return [];

  // For each unique file, check whether it also contains a Zod parse call
  const serverActionFiles = [...new Set(useServerHits.map((m) => m.file))];

  const unvalidated: string[] = [];
  for (const file of serverActionFiles) {
    const content = await readFileSafe(file).catch(() => "");
    if (!content.includes(".parse(") && !content.includes(".safeParse(")) {
      unvalidated.push(file);
    }
  }

  if (unvalidated.length === 0) return [];
  return [
    {
      id: "WEB_SERVER_ACTION_UNVALIDATED",
      title: 'Next.js Server Actions found without Zod input validation',
      severity: "HIGH",
      evidence: unvalidated.slice(0, 15).map((f) => `${f}: no .parse() or .safeParse() found`),
      requiredActions: [
        'Add a Zod schema and call schema.parse() or schema.safeParse() at the top of every Server Action.',
        "Never trust FormData or action arguments directly — validate shape, type, and constraints.",
        "Throw or return an error object when validation fails; never proceed with unvalidated data."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 7. WEB_API_NO_AUTH — route.ts files without auth middleware
// ---------------------------------------------------------------------------

async function checkApiRouteAuth(): Promise<Finding[]> {
  const routeFiles = await fg(["**/route.ts", "**/route.tsx"], { dot: true });
  if (routeFiles.length === 0) return [];

  const unprotected: string[] = [];
  for (const file of routeFiles) {
    const content = await readFileSafe(file).catch(() => "");
    if (!/auth\(|session\(|getServerSession|currentUser|requireAuth/.test(content)) {
      unprotected.push(file);
    }
  }

  if (unprotected.length === 0) return [];
  return [
    {
      id: "WEB_API_NO_AUTH",
      title: "API route handlers found without authentication middleware",
      severity: "HIGH",
      evidence: unprotected.slice(0, 15).map((f) => `${f}: no auth guard detected`),
      requiredActions: [
        "Add authentication to every route handler: call auth(), getServerSession(), or a custom requireAuth() wrapper.",
        "Return HTTP 401 for unauthenticated requests before touching any business logic.",
        "If the route is intentionally public, add a comment // PUBLIC ROUTE so this check can be tuned to ignore it."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 8. WEB_CORS_WILDCARD — Access-Control-Allow-Origin: * in API responses
// ---------------------------------------------------------------------------

async function checkCorsWildcard(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: "Access-Control-Allow-Origin",
    isRegex: false,
    maxMatches: 200
  });

  const wildcards = hits.filter((m) => /:\s*['"]\*['"]|,\s*['"]\*['"]/.test(m.preview));
  if (wildcards.length === 0) return [];
  return [
    {
      id: "WEB_CORS_WILDCARD",
      title: "CORS wildcard (Access-Control-Allow-Origin: *) found in API response",
      severity: "CRITICAL",
      evidence: wildcards.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "Replace the wildcard origin with an explicit allowlist of trusted origins.",
        "Never use * on endpoints that handle authenticated sessions or sensitive data.",
        "Use environment-specific origin lists (dev vs prod)."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 9. WEB_JWT_HARDCODED_SECRET — jwt.sign / jwt.verify with string literal secret
// ---------------------------------------------------------------------------

async function checkJwtHardcodedSecret(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`jwt\.(sign|verify)\(`,
    isRegex: true,
    maxMatches: 200
  });

  // Flag lines where the secret argument looks like a string literal rather than
  // a reference to process.env or a variable.
  const suspicious = hits.filter((m) =>
    /jwt\.(sign|verify)\([^)]*["'][A-Za-z0-9+/=_\-!@#$%^&*]{8,}["']/.test(m.preview)
  );

  if (suspicious.length === 0) return [];
  return [
    {
      id: "WEB_JWT_HARDCODED_SECRET",
      title: "JWT sign/verify called with what appears to be a hardcoded secret",
      severity: "CRITICAL",
      evidence: suspicious.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "Move the JWT secret to an environment variable (e.g. process.env.JWT_SECRET).",
        "Rotate any secret that was ever hardcoded in source — treat it as compromised.",
        "Use a minimum 256-bit secret for HMAC-SHA256 signed tokens."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 10. WEB_RATE_LIMIT_MISSING — auth/payment routes without rate limiting
// ---------------------------------------------------------------------------

async function checkRateLimitMissing(): Promise<Finding[]> {
  // Find route handlers for sensitive operations
  const sensitiveRoutes = await fg(
    [
      "**/auth**/route.ts",
      "**/login**/route.ts",
      "**/register**/route.ts",
      "**/payment**/route.ts",
      "**/checkout**/route.ts",
      "**/signin**/route.ts",
      "**/signup**/route.ts"
    ],
    { dot: true }
  );

  if (sensitiveRoutes.length === 0) return [];

  const unprotected: string[] = [];
  for (const file of sensitiveRoutes) {
    const content = await readFileSafe(file).catch(() => "");
    if (!/rateLimit|upstash|rate.limit|rateLimiter/.test(content)) {
      unprotected.push(file);
    }
  }

  if (unprotected.length === 0) return [];
  return [
    {
      id: "WEB_RATE_LIMIT_MISSING",
      title: "Auth/payment route handlers found without rate limiting",
      severity: "HIGH",
      evidence: unprotected.slice(0, 15).map((f) => `${f}: no rate-limit guard detected`),
      requiredActions: [
        "Apply rate limiting to all auth, login, register, and payment endpoints.",
        "Use Upstash Rate Limit or a similar sliding-window implementation.",
        "Return HTTP 429 with a Retry-After header when the limit is exceeded.",
        "Set tight limits: e.g. 5 attempts / 15 minutes for login, 3 / 60 min for registration."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 11. WEB_ENV_EXPOSED_CLIENT — server secrets in NEXT_PUBLIC_ vars
// ---------------------------------------------------------------------------

async function checkEnvExposedClient(): Promise<Finding[]> {
  const envFiles = await fg([".env*", "**/env.js", "**/env.ts", "**/env.mjs"], { dot: true });

  const hits = await searchRepo({
    query: "NEXT_PUBLIC_SECRET|NEXT_PUBLIC_API_KEY|NEXT_PUBLIC_TOKEN|NEXT_PUBLIC_PASSWORD",
    isRegex: false,
    maxMatches: 200
  });

  // Also scan env files directly for the patterns
  const envHits: string[] = [];
  for (const file of envFiles) {
    const content = await readFileSafe(file).catch(() => "");
    if (/NEXT_PUBLIC_(SECRET|API_KEY|TOKEN|PASSWORD)/.test(content)) {
      envHits.push(file);
    }
  }

  if (hits.length === 0 && envHits.length === 0) return [];

  const evidence: string[] = [
    ...hits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
    ...envHits.map((f) => `${f}: contains NEXT_PUBLIC_ secret variable`)
  ];

  return [
    {
      id: "WEB_ENV_EXPOSED_CLIENT",
      title: "Server-side secrets detected in NEXT_PUBLIC_ environment variables",
      severity: "CRITICAL",
      evidence: evidence.slice(0, 20),
      requiredActions: [
        "Remove NEXT_PUBLIC_ prefix from any variable containing a secret, API key, token, or password.",
        "NEXT_PUBLIC_ variables are bundled into the client JS and visible to all users.",
        "Use server-only env vars (no NEXT_PUBLIC_ prefix) and access them in Server Components or API routes.",
        "Rotate any secret that was ever exposed as NEXT_PUBLIC_ — treat it as compromised."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 12. WEB_GRAPHQL_INTROSPECTION — introspection enabled without NODE_ENV guard
// ---------------------------------------------------------------------------

async function checkGraphqlIntrospection(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: "introspection: true",
    isRegex: false,
    maxMatches: 100
  });

  const unguarded = hits.filter(
    (m) => !/NODE_ENV|process\.env/.test(m.preview)
  );

  if (unguarded.length === 0) return [];
  return [
    {
      id: "WEB_GRAPHQL_INTROSPECTION",
      title: "GraphQL introspection enabled without NODE_ENV guard",
      severity: "MEDIUM",
      evidence: unguarded.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "Disable GraphQL introspection in production: `introspection: process.env.NODE_ENV !== 'production'`.",
        "Introspection exposes the full API schema to attackers and aids targeted exploitation.",
        "Consider also disabling GraphQL Playground / Sandbox in production."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 13. WEB_PATH_TRAVERSAL — user-controlled input passed to fs / path.join
// ---------------------------------------------------------------------------

async function checkPathTraversal(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`fs\.readFile|fs\.readFileSync|path\.join`,
    isRegex: true,
    maxMatches: 200
  });

  const suspicious = hits.filter((m) =>
    /req\.(query|params|body)|searchParams|\.get\(/.test(m.preview)
  );

  if (suspicious.length === 0) return [];
  return [
    {
      id: "WEB_PATH_TRAVERSAL",
      title: "Potential path traversal — user input passed to fs or path.join",
      severity: "HIGH",
      evidence: suspicious.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "Never pass user-supplied path segments directly to fs.readFile / path.join.",
        "Resolve the full path and assert it starts with the expected base directory (path.resolve check).",
        "Use an allowlist of valid filenames instead of accepting arbitrary paths from user input."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 14. WEB_LOG_PII — PII fields near console.log / logger calls
// ---------------------------------------------------------------------------

async function checkLogPii(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`console\.(log|error|warn|info|debug)|logger\.(log|error|warn|info|debug)`,
    isRegex: true,
    maxMatches: 400
  });

  const piiFields = /email|password|token|ssn|cardNumber|card_number|cvv|dob|dateOfBirth/i;
  const suspicious = hits.filter((m) => piiFields.test(m.preview));

  if (suspicious.length === 0) return [];
  return [
    {
      id: "WEB_LOG_PII",
      title: "Potential PII or sensitive fields logged in server-side code",
      severity: "HIGH",
      evidence: suspicious.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "Never log PII (email, password, token, SSN, card number, CVV, date-of-birth) at any log level.",
        "Strip sensitive fields before logging: log only IDs, timestamps, and non-sensitive metadata.",
        "Replace logged secrets with [REDACTED] and add a lint rule (eslint-plugin-no-secrets) to enforce this."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 15. WEB_SESSION_WEAK_CONFIG — session config without secure/httpOnly/sameSite
// ---------------------------------------------------------------------------

async function checkSessionWeakConfig(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`express-session|iron-session|session\(\{`,
    isRegex: true,
    maxMatches: 200
  });

  if (hits.length === 0) return [];

  // Gather unique files and inspect their full content for secure config flags
  const sessionFiles = [...new Set(hits.map((m) => m.file))];
  const weakFiles: string[] = [];

  for (const file of sessionFiles) {
    const content = await readFileSafe(file).catch(() => "");
    const hasSecure = /secure\s*:\s*true/.test(content);
    const hasHttpOnly = /httpOnly\s*:\s*true/.test(content);
    const hasSameSite = /sameSite\s*:/.test(content);
    if (!hasSecure || !hasHttpOnly || !hasSameSite) {
      weakFiles.push(file);
    }
  }

  if (weakFiles.length === 0) return [];
  return [
    {
      id: "WEB_SESSION_WEAK_CONFIG",
      title: "Session configuration missing secure: true, httpOnly: true, or sameSite",
      severity: "HIGH",
      evidence: weakFiles.slice(0, 10).map((f) => `${f}: incomplete session cookie config`),
      requiredActions: [
        "Set secure: true so cookies are only sent over HTTPS.",
        "Set httpOnly: true to prevent JavaScript access to session cookies (mitigates XSS theft).",
        "Set sameSite: 'strict' or 'lax' to prevent CSRF attacks.",
        "Also set a short maxAge (e.g. 15–60 minutes for sensitive sessions) and regenerate the session ID after login."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function checkWebNextjs(_: { changedFiles: string[] }): Promise<Finding[]> {
  return runAll([
    checkSecurityHeaders,
    checkDangerouslySetInnerHTML,
    checkSsrf,
    checkOpenRedirect,
    checkIdorRisk,
    checkServerActionValidation,
    checkApiRouteAuth,
    checkCorsWildcard,
    checkJwtHardcodedSecret,
    checkRateLimitMissing,
    checkEnvExposedClient,
    checkGraphqlIntrospection,
    checkPathTraversal,
    checkLogPii,
    checkSessionWeakConfig
  ]);
}
