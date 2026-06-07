/**
 * Deep authentication and session enforcement — covers JWT, OAuth, session, and cookie
 * attack classes not detected by existing checks.
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

async function checkJwtAlgNone(): Promise<Finding | null> {
  const hits = await codeSearch(String.raw`jwt\.verify\s*\(`);
  const unsafe = hits.filter((h) => !/algorithms\s*:\s*\[/.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "JWT_ALG_NONE_ACCEPTED",
    title: "jwt.verify() called without explicit algorithms array — algorithm confusion attack possible (CWE-327)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Always pass algorithms: ['RS256'] (or your actual algorithm) to jwt.verify().",
      "CWE-327 — without algorithms pin, attacker can forge tokens using alg:none or switch RS256→HS256 using the public key as secret.",
      "Fix: jwt.verify(token, publicKey, { algorithms: ['RS256'] })"
    ]
  };
}

async function checkSessionFixation(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:req\.session\.user|req\.session\.userId|req\.session\.account|req\.session\.authenticated)\s*=`
  );
  const unsafe = hits.filter((h) => !/req\.session\.regenerate|session\.regenerate\s*\(/.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "SESSION_FIXATION",
    title: "Session identity set without session regeneration — session fixation risk (CWE-384)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Call req.session.regenerate() before setting session identity after authentication.",
      "CWE-384 — an attacker who fixes the session ID before login can hijack the authenticated session.",
      "Fix: req.session.regenerate((err) => { req.session.userId = user.id; res.json({ ok: true }); });"
    ]
  };
}

async function checkOauthMissingState(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:authorizationUrl|oauth\.authorize|passport\.authenticate\s*\(\s*['"]oauth|\.redirect\s*\(\s*['"]https:\/\/[^'"]*\/oauth\/authorize|\/oauth\/callback|\/auth\/callback)`
  );
  const unsafe = hits.filter(
    (h) => !/state\s*[:=]|generateState|crypto\.randomBytes|randomUUID|nonce/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "OAUTH_MISSING_STATE",
    title: "OAuth flow without state parameter — CSRF on authorization callback (CWE-352)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Generate a cryptographically random state parameter and verify it on the callback.",
      "CWE-352 — without state, an attacker can inject their own authorization code into the victim's session.",
      "Fix: const state = crypto.randomBytes(32).toString('hex'); session.oauthState = state; // verify on callback"
    ]
  };
}

async function checkOauthOpenRedirectUri(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`redirect_uri.*(?:\.includes\s*\(|\.startsWith\s*\(|\.match\s*\(|indexOf\s*\()|(?:\.includes\s*\(|\.startsWith\s*\().*redirect_uri`
  );
  if (!hits.length) return null;
  return {
    id: "OAUTH_OPEN_REDIRECT_URI",
    title: "OAuth redirect_uri validated with includes/startsWith — open redirect via subdomain (CWE-601)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Validate redirect_uri with exact string equality against a pre-registered allowlist.",
      "CWE-601 — startsWith('https://example.com') allows https://example.com.evil.com/.",
      "Fix: if (redirectUri !== REGISTERED_REDIRECT_URI) throw new Error('Invalid redirect_uri');"
    ]
  };
}

async function checkPkceNotEnforced(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:authorization_code|grant_type.*authorization_code|code.*exchange|token.*endpoint.*code\b)`
  );
  const unsafe = hits.filter((h) => !/code_challenge|code_verifier|pkce|PKCE/.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "PKCE_NOT_ENFORCED",
    title: "OAuth authorization code flow without PKCE — code interception attack (RFC 7636)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Require PKCE (code_challenge_method=S256) for all public clients and SPAs.",
      "RFC 7636 / ATT&CK T1528 — without PKCE, a stolen authorization code can be exchanged for tokens.",
      "Fix: enforce code_challenge in the /authorize handler and verify code_verifier in /token exchange."
    ]
  };
}

async function checkHardcodedJwtSecret(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`jwt\.sign\s*\([^,]+,\s*['"][a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{1,32}['"]|jwt\.verify\s*\([^,]+,\s*['"][a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{1,32}['"]`
  );
  if (!hits.length) return null;
  return {
    id: "HARDCODED_JWT_SECRET",
    title: "Hardcoded JWT secret literal — secret exposed in source code (CWE-798)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Move JWT secrets to environment variables or a secrets manager; never commit them to source.",
      "CWE-798 — hardcoded secrets are trivially extracted from git history and Docker images.",
      "Fix: jwt.sign(payload, process.env.JWT_SECRET!, { algorithms: ['RS256'] })"
    ]
  };
}

async function checkMissingRateLimitLogin(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:router|app)\.post\s*\(\s*['"][^'"]*(?:\/login|\/signin|\/auth|\/token|\/session)['"]\s*,`
  );
  const unsafe = hits.filter(
    (h) => !/rateLimit|rateLimiter|rate_limit|limiter|throttle|slowDown|expressRateLimit/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "MISSING_RATE_LIMIT_LOGIN",
    title: "Authentication endpoint without rate limiting — brute force attack surface (CWE-307)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Apply express-rate-limit or equivalent middleware to all authentication endpoints.",
      "CWE-307 — without rate limiting, brute force or credential stuffing attacks are unrestricted.",
      "Fix: app.post('/login', loginRateLimiter, authHandler); // max: 5 attempts per 15 minutes"
    ]
  };
}

async function checkPasswordPlainCompare(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`password\s*===\s*(?:req\.|user\.|stored|db\.|record\.)|(?:req\.|body\.)password\s*===\s*|password\s*==\s*(?:req\.|user\.|stored|db\.)|compareSync\s*\(\s*(?:req\.|body\.)`
  );
  const unsafe = hits.filter((h) => !/bcrypt|argon2|scrypt|pbkdf2|timingSafeEqual|compare\s*\(/i.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "PASSWORD_PLAIN_COMPARE",
    title: "Plaintext password comparison — no hashing or timing oracle (CWE-256)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Use bcrypt.compare() or argon2.verify() for password verification — never === comparison.",
      "CWE-256 — plaintext comparison leaks timing information and stores passwords without hashing.",
      "Fix: const valid = await bcrypt.compare(password, user.passwordHash); if (!valid) throw new Error('Unauthorized');"
    ]
  };
}

async function checkSamlSignatureDisabled(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:new\s+saml\.Strategy|passport-saml|samlify|node-saml|SAMLResponse|validateSignature\s*:\s*false|wantAssertionsSigned\s*:\s*false|signatureAlgorithm\s*:\s*['"]none['"])`
  );
  const unsafe = hits.filter(
    (h) => /validateSignature\s*:\s*false|wantAssertionsSigned\s*:\s*false|signatureAlgorithm\s*:\s*['"]none['"]/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "SAML_SIGNATURE_NOT_ENFORCED",
    title: "SAML signature validation disabled — SAML response forgery (CWE-347)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Set validateSignature:true and wantAssertionsSigned:true in all SAML strategy configurations.",
      "CWE-347 — unsigned SAML responses allow any user to craft an assertion claiming to be any other user.",
      "Fix: new SamlStrategy({ validateSignature: true, wantAssertionsSigned: true, cert: IDP_CERT }, ...)"
    ]
  };
}

async function checkCookieSecureFlags(): Promise<Finding | null> {
  const hits = await codeSearch(String.raw`res\.cookie\s*\(\s*['"][^'"]+['"]`);
  const unsafe = hits.filter(
    (h) => !/httpOnly\s*:\s*true/.test(h.preview) || !/secure\s*:\s*true/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "COOKIE_MISSING_SECURE_FLAGS",
    title: "Cookie set without httpOnly and/or secure flags (CWE-1004 / CWE-614)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Set httpOnly:true, secure:true, and sameSite:'Strict' on all authentication and session cookies.",
      "CWE-1004/CWE-614 — missing httpOnly enables XSS cookie theft; missing secure sends cookie over HTTP.",
      "Fix: res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 3600000 });"
    ]
  };
}

async function checkRefreshTokenNotRotated(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:refresh_token|refreshToken)\s*[:=](?:.*jwt\.sign|.*generateToken|.*createToken|.*sign\s*\()|(?:grantType|grant_type)\s*[:=]\s*['"]refresh_token['"]`
  );
  const unsafe = hits.filter(
    (h) => !/delete|revoke|invalidate|blacklist|rotateToken|revokeToken|tokenFamily|REFRESH_TOKEN_FAMILY/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "REFRESH_TOKEN_NOT_ROTATED",
    title: "Refresh token issued without revoking previous token — replay attack surface (CWE-613)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Implement refresh token rotation: invalidate the old token before issuing the new one.",
      "CWE-613 — without rotation, a stolen refresh token remains valid indefinitely.",
      "Fix: await db.refreshTokens.delete(oldToken); const newToken = issueRefreshToken(user);"
    ]
  };
}

async function checkJwtHsRsConfusion(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`jwt\.verify\s*\(\s*[^,]+,\s*(?:publicKey|PUBLIC_KEY|pub_key|process\.env\.[A-Z_]*PUBLIC|fs\.readFileSync[^)]*\.pem)`
  );
  const unsafe = hits.filter((h) => !/algorithms\s*:\s*\[\s*['"](?:RS|ES|PS)/.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "JWT_HS_RS_CONFUSION",
    title: "JWT verified with public key without algorithm pin — HS/RS confusion attack (CVE-2015-9235 pattern)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Pin the algorithm to RS256/ES256 explicitly: jwt.verify(token, publicKey, { algorithms: ['RS256'] }).",
      "Without algorithm pin: attacker signs token with HS256 using the RS256 public key as HMAC secret — library accepts it.",
      "This is CVE-2015-9235 — still exploitable in jsonwebtoken < 9.0 without the algorithms option."
    ]
  };
}

async function checkApiKeyInUrl(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:req\.query\.|query\.\b)(?:api_key|apikey|access_token|token|key|secret|auth|authorization)\b`
  );
  if (!hits.length) return null;
  return {
    id: "API_KEY_IN_URL",
    title: "API key or token transmitted in URL query parameter — logged in plaintext (CWE-598)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Transmit API keys and tokens exclusively in the Authorization header or a POST body, never in query parameters.",
      "CWE-598 — query parameters appear in server access logs, browser history, Referer headers, and CDN logs.",
      "Fix: const token = req.headers['authorization']?.replace('Bearer ', ''); // never req.query.token"
    ]
  };
}

async function checkPasswordResetNoExpiry(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:resetToken|reset_token|passwordResetToken|forgotToken|verificationToken)\s*(?:===|==)\s*(?:req\.|body\.|params\.|token\b)`
  );
  const unsafe = hits.filter(
    (h) => !/expir|ttl|expiresAt|Date\.now|createdAt.*<|isExpired|maxAge/i.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "PASSWORD_RESET_NO_EXPIRY",
    title: "Password reset token compared without expiry check — indefinitely valid tokens (CWE-640)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Enforce a maximum reset token lifetime (≤ 1 hour) and invalidate the token after first use.",
      "CWE-640 — an unexpired reset token from a breached database allows permanent account takeover.",
      "Fix: if (user.resetTokenExpiry < Date.now()) throw new Error('Token expired'); // then delete token on use"
    ]
  };
}

async function checkAdminRouteNoAuthz(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:router|app)\.(?:get|post|put|patch|delete)\s*\(\s*['"][^'"]*(?:\/admin|\/internal|\/debug|\/\_|\/__)/`
  );
  const unsafe = hits.filter(
    (h) => !/requireAdmin|isAdmin|adminAuth|checkAdmin|authorize.*admin|role.*admin|admin.*role|verifyAdmin|adminMiddleware/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "ADMIN_ROUTE_NO_AUTHZ",
    title: "Admin or internal route without authorization middleware — broken function-level authorization (CWE-862)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Apply an authorization middleware that verifies admin role before registering any /admin or /internal route.",
      "CWE-862 / ATT&CK T1078 — routes without function-level authz are reachable by any authenticated user.",
      "Fix: router.use('/admin', requireAdminRole); // placed BEFORE route handlers, not after"
    ]
  };
}

async function checkTimingOracle(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:otp|pin|code|token|secret|apiKey|api_key)\s*===\s*(?:req\.|body\.|params\.|query\.|provided|input)|(?:req\.|body\.|params\.)(?:otp|pin|code|mfa|totp|hotp)\s*===`
  );
  const unsafe = hits.filter(
    (h) => !/timingSafeEqual|safeCompare|crypto\.timingSafeEqual|subtle\.timingSafeEqual/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "TIMING_ORACLE_COMPARISON",
    title: "Security token compared with === — timing oracle leaks token length and prefix (CWE-208)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Use crypto.timingSafeEqual() for all security-critical equality comparisons.",
      "CWE-208 — string === short-circuits on the first differing byte, leaking token contents via response time.",
      "Fix: const a = Buffer.from(provided); const b = Buffer.from(stored); a.length === b.length && timingSafeEqual(a, b);"
    ]
  };
}

export async function checkAuthDeep(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  try {
    const results = await Promise.all([
      checkJwtAlgNone(),
      checkSessionFixation(),
      checkOauthMissingState(),
      checkOauthOpenRedirectUri(),
      checkPkceNotEnforced(),
      checkHardcodedJwtSecret(),
      checkMissingRateLimitLogin(),
      checkPasswordPlainCompare(),
      checkSamlSignatureDisabled(),
      checkCookieSecureFlags(),
      checkRefreshTokenNotRotated(),
      checkJwtHsRsConfusion(),
      checkApiKeyInUrl(),
      checkPasswordResetNoExpiry(),
      checkAdminRouteNoAuthz(),
      checkTimingOracle(),
    ]);
    return results.filter((f): f is Finding => f !== null);
  } catch (err) {
    console.warn("[checkAuthDeep] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    return [];
  }
}
