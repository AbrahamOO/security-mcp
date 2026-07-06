import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import { scopedFg as fg } from "../scan-scope.js";
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
// 16. WEB_DANGLING_MARKUP — user input reflected in HTML attribute values
// ---------------------------------------------------------------------------

async function checkDanglingMarkup(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`(?:res\.send\s*\(\s*['"][^'"]*<[a-z]+[^>]*(?:src|href|action)\s*=\s*['"][^'"]*\$\{|ejs\.render[^)]*\{[^}]*(?:req\.|body\.|params\.|query\.))`,
    isRegex: true,
    maxMatches: 200
  });

  if (hits.length === 0) return [];
  return [
    {
      id: "WEB_DANGLING_MARKUP",
      title: "User input reflected in HTML attribute value — dangling markup injection risk",
      severity: "HIGH",
      evidence: hits.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "User input reflected in HTML attribute value — dangling markup injection enables data exfiltration (CWE-79/CWE-116).",
        "Never interpolate user-controlled values directly into HTML attribute values.",
        "Use a proper HTML templating engine with context-aware escaping or a sanitizer.",
        "Apply output encoding appropriate to the context (HTML attribute, URL, JS, CSS)."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 17. WEB_POSTMESSAGE_WILDCARD — postMessage with wildcard targetOrigin
// ---------------------------------------------------------------------------

async function checkPostMessageWildcard(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`(?:postMessage|parent\.postMessage|window\.postMessage)\s*\([^,)]+,\s*['"]\*['"]`,
    isRegex: true,
    maxMatches: 200
  });

  if (hits.length === 0) return [];
  return [
    {
      id: "WEB_POSTMESSAGE_WILDCARD",
      title: "postMessage with wildcard targetOrigin '*' detected",
      severity: "MEDIUM",
      evidence: hits.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "postMessage with wildcard targetOrigin '*' — data sent to any listening origin (CWE-346).",
        "Replace '*' with an explicit trusted origin (e.g. 'https://example.com').",
        "Validate the sender's origin in the message receiver with event.origin checks."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 18. WEB_CACHE_POISONING — X-Forwarded-Host or unkeyed header reflected
// ---------------------------------------------------------------------------

async function checkCachePoisoningHeaders(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`req\.headers\s*\[\s*['"]x-forwarded-host['"]]|req\.headers\.(?:host|x-forwarded-host|x-original-url)`,
    isRegex: true,
    maxMatches: 200
  });

  const suspicious = hits.filter(
    (m) => !/allowlist|===.*TRUSTED_HOST|ALLOWED_HOSTS/.test(m.preview)
  );

  if (suspicious.length === 0) return [];
  return [
    {
      id: "WEB_CACHE_POISONING",
      title: "X-Forwarded-Host or unkeyed header reflected in response — cache poisoning risk",
      severity: "MEDIUM",
      evidence: suspicious.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "X-Forwarded-Host or unkeyed header reflected in response — web cache poisoning risk (CWE-444).",
        "Validate X-Forwarded-Host against a strict allowlist of trusted hostnames before use.",
        "Never reflect raw Host or X-Forwarded-Host headers into cached responses (e.g. URLs, redirects, links).",
        "Configure your reverse proxy / CDN to strip or normalise forwarding headers before they reach the app."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 19. WEB_MISSING_SRI — external scripts without Subresource Integrity
// ---------------------------------------------------------------------------

async function checkMissingSri(): Promise<Finding[]> {
  const hits = await searchRepo({
    query: String.raw`<script[^>]+src\s*=\s*['"]https?://(?!localhost|127\.)[^'"]+['"][^>]*>`,
    isRegex: true,
    maxMatches: 200
  });

  const suspicious = hits.filter((m) => !/integrity=/.test(m.preview));

  if (suspicious.length === 0) return [];
  return [
    {
      id: "WEB_MISSING_SRI",
      title: "External script loaded without Subresource Integrity (SRI)",
      severity: "MEDIUM",
      evidence: suspicious.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "External script loaded without Subresource Integrity (SRI) — CDN compromise risk (CWE-829).",
        "Add integrity and crossorigin attributes to all external <script> tags.",
        "Generate SRI hashes at build time (e.g. using the SRI Hash Generator or webpack-subresource-integrity).",
        "Consider self-hosting critical third-party scripts to eliminate CDN supply-chain risk."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 20. WEB_CLIENT_ENV_LEAK — non-NEXT_PUBLIC env var used in a client component
// ---------------------------------------------------------------------------

async function checkClientEnvLeak(): Promise<Finding[]> {
  // Files that declare "use client" and reference a non-NEXT_PUBLIC env var.
  const useClientHits = await searchRepo({
    query: '"use client"',
    isRegex: false,
    maxMatches: 200
  });
  if (useClientHits.length === 0) return [];

  const clientFiles = [...new Set(useClientHits.map((m) => m.file))];
  const offenders: string[] = [];

  for (const file of clientFiles) {
    const content = await readFileSafe(file).catch(() => "");
    // Match process.env.FOO where FOO does not start with NEXT_PUBLIC_ and is not NODE_ENV.
    const re = /process\.env\.([A-Z0-9_]+)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) {
      const name = m[1];
      if (name !== "NODE_ENV" && !name.startsWith("NEXT_PUBLIC_")) {
        offenders.push(`${file}: process.env.${name} referenced in a "use client" component`);
        break;
      }
    }
  }

  if (offenders.length === 0) return [];
  return [
    {
      id: "WEB_CLIENT_ENV_LEAK",
      title: "Non-NEXT_PUBLIC_ environment variable referenced inside a client component — bundled into browser JS or resolves to undefined",
      severity: "CRITICAL",
      sla: "24h",
      evidence: offenders.slice(0, 15),
      requiredActions: [
        "Never reference a server-only env var (no NEXT_PUBLIC_ prefix) in a \"use client\" component — at build time its value is either inlined into the client bundle or silently undefined.",
        "Read secrets only in Server Components, route handlers, or Server Actions and pass non-sensitive derived values to the client as props.",
        "Rotate any secret that was ever inlined into a client bundle — treat it as compromised."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 21. WEB_MIDDLEWARE_MATCHER_GAP — middleware auth not covering protected routes
// ---------------------------------------------------------------------------

async function checkMiddlewareMatcherGap(): Promise<Finding[]> {
  const middlewareFiles = await fg(
    ["middleware.ts", "middleware.tsx", "src/middleware.ts", "src/middleware.tsx"],
    { dot: true }
  );
  if (middlewareFiles.length === 0) return [];

  const combined = (
    await Promise.all(middlewareFiles.map((f) => readFileSafe(f).catch(() => "")))
  ).join("\n");

  // Only relevant if the middleware actually performs auth.
  const doesAuth = /auth|session|getToken|withAuth|getServerSession|jwt|clerk|next-auth/i.test(combined);
  if (!doesAuth) return [];

  // Extract the matcher config.
  const matcherMatch = combined.match(/matcher\s*:\s*(\[[^\]]*\]|['"][^'"]*['"])/);
  if (!matcherMatch) {
    // Auth middleware with no matcher runs on every request by default — acceptable; skip.
    return [];
  }
  const matcher = matcherMatch[1];

  // Discover protected-looking route folders.
  const protectedRoutes = await fg(
    [
      "**/app/**/(admin|dashboard|account|settings|billing)/**/page.tsx",
      "**/app/**/(admin|dashboard|account|settings|billing)/**/route.ts",
      "**/pages/**/(admin|dashboard|account|settings|billing)/**"
    ],
    { dot: true }
  );
  if (protectedRoutes.length === 0) return [];

  // Heuristic: matcher references none of the protected segment names.
  const segments = ["admin", "dashboard", "account", "settings", "billing", "api"];
  const covered = segments.some((seg) => matcher.includes(seg)) || matcher.includes("/(.*)") || matcher.includes(":path*");
  if (covered) return [];

  return [
    {
      id: "WEB_MIDDLEWARE_MATCHER_GAP",
      title: "Auth middleware matcher does not cover protected route segments — routes bypass authentication",
      severity: "HIGH",
      sla: "7d",
      evidence: [
        `matcher: ${matcher}`,
        ...protectedRoutes.slice(0, 10).map((f) => `${f}: protected route not matched by middleware`)
      ],
      requiredActions: [
        "Ensure the middleware `matcher` (or its route logic) covers every protected segment (admin, dashboard, account, settings, billing, and protected API routes).",
        "Prefer a deny-by-default matcher that runs on all routes and explicitly allowlists public paths, rather than an allowlist of protected paths that is easy to leave incomplete.",
        "Add an integration test that requests each protected route unauthenticated and asserts a redirect/401."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 22. WEB_IMAGE_REMOTE_WILDCARD — next/image remotePatterns/domains wildcard
// ---------------------------------------------------------------------------

async function checkImageRemoteWildcard(): Promise<Finding[]> {
  const configFiles = await fg(["next.config.js", "next.config.mjs", "next.config.ts"], { dot: true });
  if (configFiles.length === 0) return [];

  const offenders: string[] = [];
  for (const file of configFiles) {
    const content = await readFileSafe(file).catch(() => "");
    if (!/images\s*:/.test(content)) continue;
    // Wildcard hostname in remotePatterns or a "**" domain.
    if (
      /hostname\s*:\s*['"]\*\*?['"]/.test(content) ||
      /hostname\s*:\s*['"][^'"]*\*\*[^'"]*['"]/.test(content) ||
      /domains\s*:\s*\[[^\]]*['"]\*['"]/.test(content) ||
      /remotePatterns\s*:\s*\[\s*\{\s*protocol[^}]*hostname\s*:\s*['"]\*/.test(content)
    ) {
      offenders.push(`${file}: next/image remotePatterns/domains use a wildcard hostname`);
    }
  }

  if (offenders.length === 0) return [];
  return [
    {
      id: "WEB_IMAGE_REMOTE_WILDCARD",
      title: "next/image remotePatterns/domains use a wildcard hostname — image optimizer can be abused as an SSRF/proxy",
      severity: "HIGH",
      sla: "7d",
      evidence: offenders.slice(0, 15),
      requiredActions: [
        "Replace wildcard image hostnames with an explicit allowlist of exact hostnames you control or trust.",
        "A wildcard remotePattern lets an attacker make the Next.js image optimizer fetch arbitrary URLs (SSRF, internal-network probing, bandwidth abuse).",
        "Pin protocol to https and constrain pathname where possible."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 23. WEB_UNSAFE_URI_SCHEME — redirect/router to data:/javascript: or unvalidated URL
// ---------------------------------------------------------------------------

async function checkUnsafeUriScheme(): Promise<Finding[]> {
  // data:/javascript: URIs flowing into a redirect or client navigation.
  const schemeHits = await searchRepo({
    query: String.raw`(?:redirect|router\.(?:push|replace)|res\.redirect|location\.href\s*=)\s*\(?[^)\n]*(?:javascript:|data:)`,
    isRegex: true,
    maxMatches: 200
  });

  // User-controlled URL flowing into navigation without an allowlist check on the same line.
  const userUrlHits = await searchRepo({
    query: String.raw`(?:router\.(?:push|replace)|location\.href\s*=)\s*\(?\s*(?:req\.(?:query|body)|searchParams\.get\([^)]*\)|params\.\w+|props\.\w*url)`,
    isRegex: true,
    maxMatches: 200
  });
  const suspiciousUserUrl = userUrlHits.filter(
    (m) => !/allowlist|allowList|startsWith\(['"]\/|new URL|isSafeUrl|validateUrl/.test(m.preview)
  );

  const all = [...schemeHits, ...suspiciousUserUrl];
  const unique = all.filter(
    (hit, idx, arr) => arr.findIndex((h) => h.file === hit.file && h.line === hit.line) === idx
  );
  if (unique.length === 0) return [];

  return [
    {
      id: "WEB_UNSAFE_URI_SCHEME",
      title: "Navigation/redirect to a data:/javascript: URI or an unvalidated user-controlled URL — XSS / open redirect",
      severity: "HIGH",
      sla: "7d",
      evidence: unique.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "Reject javascript: and data: URIs before redirecting or navigating — allow only http(s) and same-origin relative paths.",
        "Validate user-supplied destinations against an allowlist, or require them to be relative paths beginning with a single '/' (and not '//').",
        "Parse candidate URLs with `new URL()` and check the protocol/host explicitly rather than string-matching."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 24. WEB_SSR_FETCH_USER_INPUT — SSR/route handler fetches a user-controlled URL
// ---------------------------------------------------------------------------

async function checkSsrFetchUserInput(): Promise<Finding[]> {
  // fetch()/axios() whose argument is built from user input, in an SSR context.
  const hits = await searchRepo({
    query: String.raw`(?:fetch|axios(?:\.(?:get|post))?|got|undici\.request)\s*\(\s*[^)]*(?:req\.(?:query|body|params)|searchParams\.get\(|params\.\w+|context\.query|ctx\.query)`,
    isRegex: true,
    maxMatches: 200
  });

  // Restrict to files that are server-rendered (getServerSideProps / route handler / server component).
  const suspicious: typeof hits = [];
  const cache: Record<string, string> = {};
  for (const h of hits) {
    let content = cache[h.file];
    if (content === undefined) {
      content = await readFileSafe(h.file).catch(() => "");
      cache[h.file] = content;
    }
    const ssrContext =
      /getServerSideProps|getStaticProps|route\.tsx?$/.test(h.file) ||
      /getServerSideProps|export\s+async\s+function\s+(?:GET|POST|PUT|DELETE|PATCH)\b/.test(content) ||
      !/["']use client["']/.test(content);
    const guarded = /allowlist|allowList|new URL\(|isSafeUrl|validateUrl|SSRF/i.test(content);
    if (ssrContext && !guarded) suspicious.push(h);
  }

  if (suspicious.length === 0) return [];
  return [
    {
      id: "WEB_SSR_FETCH_USER_INPUT",
      title: "Server-side fetch built from user input in getServerSideProps/route handler — SSRF and path traversal",
      severity: "HIGH",
      sla: "7d",
      evidence: suspicious.slice(0, 15).map((m) => `${m.file}:${m.line}:${m.preview}`),
      requiredActions: [
        "Never pass req.query/req.body/searchParams straight into a server-side fetch() URL.",
        "Resolve the target with `new URL()` and enforce an allowlist of permitted hosts; block localhost, private IP ranges, and 169.254.169.254 (cloud metadata).",
        "For path segments, validate against an allowlist and reject '..' / encoded traversal before composing the URL."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 25. WEB_ISR_REVALIDATE_WEAK_SECRET — on-demand ISR revalidate secret weak/hardcoded
// ---------------------------------------------------------------------------

async function checkIsrRevalidateSecret(): Promise<Finding[]> {
  // Revalidation endpoints compare a secret token from the request.
  const revalidateHits = await searchRepo({
    query: String.raw`res\.revalidate\s*\(|revalidatePath\s*\(|revalidateTag\s*\(|['"]x-revalidate|revalidate.*secret|REVALIDATE_(?:TOKEN|SECRET)`,
    isRegex: true,
    maxMatches: 200
  });
  if (revalidateHits.length === 0) return [];

  const files = [...new Set(revalidateHits.map((m) => m.file))];
  const offenders: string[] = [];
  for (const file of files) {
    const content = await readFileSafe(file).catch(() => "");
    if (!/revalidate/i.test(content)) continue;
    // A secret compared against a string literal (hardcoded) rather than process.env.
    const hardcoded =
      /(?:secret|token)\s*(?:===|==|!==|!=)\s*['"][^'"]{1,32}['"]/i.test(content) ||
      /(?:query|searchParams[^\n]*get\([^)]*)\.?secret\s*(?:===|==)\s*['"][^'"]+['"]/i.test(content);
    // Weak: short/guessable literal or no env reference around a revalidate secret check.
    const usesEnv = /process\.env\.[A-Z0-9_]*REVALIDAT|process\.env\.[A-Z0-9_]*SECRET/i.test(content);
    const checksSecret = /(?:secret|token)/i.test(content);
    if (hardcoded || (checksSecret && !usesEnv && /revalidate/i.test(content) && /['"][A-Za-z0-9]{1,16}['"]/.test(content))) {
      offenders.push(`${file}: on-demand revalidation secret appears hardcoded or weak`);
    }
  }

  if (offenders.length === 0) return [];
  return [
    {
      id: "WEB_ISR_REVALIDATE_WEAK_SECRET",
      title: "On-demand ISR revalidation endpoint protected by a weak or hardcoded secret",
      severity: "HIGH",
      sla: "7d",
      evidence: offenders.slice(0, 15),
      requiredActions: [
        "Load the revalidation secret from an environment variable (process.env.REVALIDATE_SECRET), never a string literal in source.",
        "Use a long, high-entropy random token and compare it in constant time (crypto.timingSafeEqual).",
        "Rotate any revalidation secret that was ever committed to source control.",
        "Return 401 for missing/invalid tokens before triggering any cache invalidation."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 26. WEB_COOKIE_SAMESITE_MISSING — sensitive cookie without SameSite Strict/Lax
// ---------------------------------------------------------------------------

async function checkCookieSameSite(): Promise<Finding[]> {
  // Explicit cookie writes for sensitive names.
  const hits = await searchRepo({
    query: String.raw`(?:cookies\(\)\.set|res\.cookie|response\.cookies\.set|setCookie|Set-Cookie)\s*\(?[^)]*(?:session|token|auth|jwt|sid|refresh)`,
    isRegex: true,
    maxMatches: 200
  });
  if (hits.length === 0) return [];

  const files = [...new Set(hits.map((m) => m.file))];
  const offenders: string[] = [];
  for (const file of files) {
    const content = await readFileSafe(file).catch(() => "");
    // Look at each sensitive cookie set; flag if no SameSite Strict/Lax nearby.
    const sensitiveSet = /(?:cookies\(\)\.set|res\.cookie|response\.cookies\.set|setCookie)\s*\(?[^)]*(?:session|token|auth|jwt|sid|refresh)/i.test(content);
    if (!sensitiveSet) continue;
    const hasSameSite = /sameSite\s*:\s*['"]?(?:strict|lax)['"]?/i.test(content) || /SameSite=(?:Strict|Lax)/i.test(content);
    if (!hasSameSite) {
      offenders.push(`${file}: sensitive cookie set without SameSite=Strict/Lax`);
    }
  }

  if (offenders.length === 0) return [];
  return [
    {
      id: "WEB_COOKIE_SAMESITE_MISSING",
      title: "Sensitive cookie (session/token/auth) set without SameSite=Strict or Lax",
      severity: "MEDIUM",
      sla: "30d",
      evidence: offenders.slice(0, 15),
      requiredActions: [
        "Set SameSite: 'strict' (or at minimum 'lax') on all session/auth/token cookies to mitigate CSRF and cross-site leakage.",
        "Also set httpOnly: true and secure: true on the same cookies.",
        "Use SameSite=None only for cookies that genuinely must be sent cross-site, and always pair it with Secure."
      ]
    }
  ];
}

// ---------------------------------------------------------------------------
// 27. WEB_CATCHALL_ROUTE_OVERRIDE — catch-all [...slug] shadowing protected routes
// ---------------------------------------------------------------------------

async function checkCatchAllRouteOverride(): Promise<Finding[]> {
  // Catch-all / optional catch-all route files.
  const catchAllFiles = await fg(
    [
      "**/app/**/[[...*]]/**/route.ts",
      "**/app/**/[[...*]]/**/page.tsx",
      "**/app/**/[...*]/**/route.ts",
      "**/app/**/[...*]/**/page.tsx",
      "**/pages/**/[[...*]].tsx",
      "**/pages/**/[[...*]].ts",
      "**/pages/**/[...*].tsx",
      "**/pages/**/[...*].ts"
    ],
    { dot: true }
  );
  if (catchAllFiles.length === 0) return [];

  // Protected route segments that could be shadowed by a broad catch-all.
  const protectedRoutes = await fg(
    [
      "**/app/**/(admin|dashboard|account|billing)/**/page.tsx",
      "**/app/**/(admin|dashboard|account|billing)/**/route.ts"
    ],
    { dot: true }
  );

  // Flag catch-all handlers that don't themselves enforce auth.
  const offenders: string[] = [];
  for (const file of catchAllFiles) {
    const content = await readFileSafe(file).catch(() => "");
    const enforcesAuth = /auth\(|getServerSession|currentUser|requireAuth|session\(/.test(content);
    if (!enforcesAuth) offenders.push(`${file}: catch-all route without an auth guard`);
  }

  if (offenders.length === 0 || protectedRoutes.length === 0) return [];
  return [
    {
      id: "WEB_CATCHALL_ROUTE_OVERRIDE",
      title: "Catch-all route ([...slug]) without auth may shadow or expose protected routes",
      severity: "MEDIUM",
      sla: "30d",
      evidence: [
        ...offenders.slice(0, 10),
        ...protectedRoutes.slice(0, 5).map((f) => `${f}: protected route in a tree also served by a catch-all`)
      ],
      requiredActions: [
        "Ensure catch-all routes ([...slug] / [[...slug]]) enforce the same authentication/authorization as the specific protected routes they can shadow.",
        "Validate the resolved slug against an allowlist and return 404 for anything that maps to a protected or non-public resource.",
        "Add tests confirming the catch-all cannot serve or leak protected paths to unauthenticated users."
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
    checkSessionWeakConfig,
    checkDanglingMarkup,
    checkPostMessageWildcard,
    checkCachePoisoningHeaders,
    checkMissingSri,
    checkClientEnvLeak,
    checkMiddlewareMatcherGap,
    checkImageRemoteWildcard,
    checkUnsafeUriScheme,
    checkSsrFetchUserInput,
    checkIsrRevalidateSecret,
    checkCookieSameSite,
    checkCatchAllRouteOverride
  ]);
}
