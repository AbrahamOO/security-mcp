/**
 * Deep authentication and session enforcement — covers JWT, OAuth, session, and cookie
 * attack classes not detected by existing checks.
 * CWE references per MITRE CWE catalog; ATT&CK techniques per MITRE ATT&CK v14.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";

const NON_CODE_RE = /\.(?:md|json|yaml|yml|txt|rst|toml|lock)$/i;

export async function checkAuthDeep(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  const findings: Finding[] = [];

  const codeSearch = async (query: string) =>
    (await searchRepo({ query, isRegex: true, maxMatches: 200 })).filter(h => !NON_CODE_RE.test(h.file));

  try {
    // 1. JWT verify without explicit algorithms array (algorithm confusion / none-attack)
    const jwtVerifyHits = await codeSearch(String.raw`jwt\.verify\s*\(`);
    const jwtAlgSafeRe = /algorithms\s*:\s*\[/;
    const jwtAlgUnsafe = jwtVerifyHits.filter((h) => !jwtAlgSafeRe.test(h.preview));
    if (jwtAlgUnsafe.length > 0) {
      findings.push({
        id: "JWT_ALG_NONE_ACCEPTED",
        title: "jwt.verify() called without explicit algorithms array — algorithm confusion attack possible (CWE-327)",
        severity: "CRITICAL",
        evidence: jwtAlgUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(jwtAlgUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Always pass algorithms: ['RS256'] (or your actual algorithm) to jwt.verify().",
          "CWE-327 — without algorithms pin, attacker can forge tokens using alg:none or switch RS256→HS256 using the public key as secret.",
          "Fix: jwt.verify(token, publicKey, { algorithms: ['RS256'] })"
        ]
      });
    }

    // 2. Session not regenerated after login (session fixation)
    const loginHandlerHits = await codeSearch(
      String.raw`(?:req\.session\.user|req\.session\.userId|req\.session\.account|req\.session\.authenticated)\s*=`);
    const sessionRegenerateRe = /req\.session\.regenerate|session\.regenerate\s*\(/;
    const sessionFixationRisk = loginHandlerHits.filter((h) => !sessionRegenerateRe.test(h.preview));
    if (sessionFixationRisk.length > 0) {
      findings.push({
        id: "SESSION_FIXATION",
        title: "Session identity set without session regeneration — session fixation risk (CWE-384)",
        severity: "HIGH",
        evidence: sessionFixationRisk.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(sessionFixationRisk.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Call req.session.regenerate() before setting session identity after authentication.",
          "CWE-384 — an attacker who fixes the session ID before login can hijack the authenticated session.",
          "Fix: req.session.regenerate((err) => { req.session.userId = user.id; res.json({ ok: true }); });"
        ]
      });
    }

    // 3. OAuth authorize endpoint without state parameter generation
    const oauthAuthHits = await codeSearch(
      String.raw`(?:authorizationUrl|oauth\.authorize|passport\.authenticate\s*\(\s*['"]oauth|\.redirect\s*\(\s*['"]https:\/\/[^'"]*\/oauth\/authorize|\/oauth\/callback|\/auth\/callback)`);
    const oauthStateSafeRe = /state\s*[:=]|generateState|crypto\.randomBytes|randomUUID|nonce/;
    const oauthStateUnsafe = oauthAuthHits.filter((h) => !oauthStateSafeRe.test(h.preview));
    if (oauthStateUnsafe.length > 0) {
      findings.push({
        id: "OAUTH_MISSING_STATE",
        title: "OAuth flow without state parameter — CSRF on authorization callback (CWE-352)",
        severity: "HIGH",
        evidence: oauthStateUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(oauthStateUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Generate a cryptographically random state parameter and verify it on the callback.",
          "CWE-352 — without state, an attacker can inject their own authorization code into the victim's session.",
          "Fix: const state = crypto.randomBytes(32).toString('hex'); session.oauthState = state; // verify on callback"
        ]
      });
    }

    // 4. OAuth redirect_uri validated with includes/startsWith (too broad)
    const redirectUriHits = await codeSearch(
      String.raw`redirect_uri.*(?:\.includes\s*\(|\.startsWith\s*\(|\.match\s*\(|indexOf\s*\()|(?:\.includes\s*\(|\.startsWith\s*\().*redirect_uri`);
    if (redirectUriHits.length > 0) {
      findings.push({
        id: "OAUTH_OPEN_REDIRECT_URI",
        title: "OAuth redirect_uri validated with includes/startsWith — open redirect via subdomain (CWE-601)",
        severity: "HIGH",
        evidence: redirectUriHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(redirectUriHits.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Validate redirect_uri with exact string equality against a pre-registered allowlist.",
          "CWE-601 — startsWith('https://example.com') allows https://example.com.evil.com/.",
          "Fix: if (redirectUri !== REGISTERED_REDIRECT_URI) throw new Error('Invalid redirect_uri');"
        ]
      });
    }

    // 5. PKCE not enforced — OAuth/OIDC flow without code_challenge
    const pkceHits = await codeSearch(
      String.raw`(?:authorization_code|grant_type.*authorization_code|code.*exchange|token.*endpoint.*code\b)`);
    const pkceSafeRe = /code_challenge|code_verifier|pkce|PKCE/;
    const pkceUnsafe = pkceHits.filter((h) => !pkceSafeRe.test(h.preview));
    if (pkceUnsafe.length > 0) {
      findings.push({
        id: "PKCE_NOT_ENFORCED",
        title: "OAuth authorization code flow without PKCE — code interception attack (RFC 7636)",
        severity: "HIGH",
        evidence: pkceUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(pkceUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Require PKCE (code_challenge_method=S256) for all public clients and SPAs.",
          "RFC 7636 / ATT&CK T1528 — without PKCE, a stolen authorization code can be exchanged for tokens.",
          "Fix: enforce code_challenge in the /authorize handler and verify code_verifier in /token exchange."
        ]
      });
    }

    // 6. Hardcoded JWT secret (short literal string)
    const hardcodedJwtHits = await codeSearch(
      String.raw`jwt\.sign\s*\([^,]+,\s*['"][a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{1,32}['"]|jwt\.verify\s*\([^,]+,\s*['"][a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{1,32}['"]`);
    if (hardcodedJwtHits.length > 0) {
      findings.push({
        id: "HARDCODED_JWT_SECRET",
        title: "Hardcoded JWT secret literal — secret exposed in source code (CWE-798)",
        severity: "CRITICAL",
        evidence: hardcodedJwtHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(hardcodedJwtHits.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Move JWT secrets to environment variables or a secrets manager; never commit them to source.",
          "CWE-798 — hardcoded secrets are trivially extracted from git history and Docker images.",
          "Fix: jwt.sign(payload, process.env.JWT_SECRET!, { algorithms: ['RS256'] })"
        ]
      });
    }

    // 7. Login/auth/token endpoints without rate limiting middleware
    const loginRouteHits = await codeSearch(
      String.raw`(?:router|app)\.post\s*\(\s*['"][^'"]*(?:\/login|\/signin|\/auth|\/token|\/session)['"]\s*,`);
    const rateLimitRe = /rateLimit|rateLimiter|rate_limit|limiter|throttle|slowDown|expressRateLimit/;
    const rateLimitMissing = loginRouteHits.filter((h) => !rateLimitRe.test(h.preview));
    if (rateLimitMissing.length > 0) {
      findings.push({
        id: "MISSING_RATE_LIMIT_LOGIN",
        title: "Authentication endpoint without rate limiting — brute force attack surface (CWE-307)",
        severity: "HIGH",
        evidence: rateLimitMissing.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(rateLimitMissing.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Apply express-rate-limit or equivalent middleware to all authentication endpoints.",
          "CWE-307 — without rate limiting, brute force or credential stuffing attacks are unrestricted.",
          "Fix: app.post('/login', loginRateLimiter, authHandler); // max: 5 attempts per 15 minutes"
        ]
      });
    }

    // 8. Plaintext password comparison (timing oracle / no hashing)
    const passwordCompareHits = await codeSearch(
      String.raw`password\s*===\s*(?:req\.|user\.|stored|db\.|record\.)|(?:req\.|body\.)password\s*===\s*|password\s*==\s*(?:req\.|user\.|stored|db\.)|compareSync\s*\(\s*(?:req\.|body\.)`);
    const passwordSafeRe = /bcrypt|argon2|scrypt|pbkdf2|timingSafeEqual|compare\s*\(/i;
    const passwordUnsafe = passwordCompareHits.filter((h) => !passwordSafeRe.test(h.preview));
    if (passwordUnsafe.length > 0) {
      findings.push({
        id: "PASSWORD_PLAIN_COMPARE",
        title: "Plaintext password comparison — no hashing or timing oracle (CWE-256)",
        severity: "CRITICAL",
        evidence: passwordUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(passwordUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Use bcrypt.compare() or argon2.verify() for password verification — never === comparison.",
          "CWE-256 — plaintext comparison leaks timing information and stores passwords without hashing.",
          "Fix: const valid = await bcrypt.compare(password, user.passwordHash); if (!valid) throw new Error('Unauthorized');"
        ]
      });
    }

    // 9. SAML signature validation disabled
    const samlHits = await codeSearch(
      String.raw`(?:new\s+saml\.Strategy|passport-saml|samlify|node-saml|SAMLResponse|validateSignature\s*:\s*false|wantAssertionsSigned\s*:\s*false|signatureAlgorithm\s*:\s*['"]none['"])`);
    const samlUnsafeRe = /validateSignature\s*:\s*false|wantAssertionsSigned\s*:\s*false|signatureAlgorithm\s*:\s*['"]none['"]/;
    const samlUnsafe = samlHits.filter((h) => samlUnsafeRe.test(h.preview));
    if (samlUnsafe.length > 0) {
      findings.push({
        id: "SAML_SIGNATURE_NOT_ENFORCED",
        title: "SAML signature validation disabled — SAML response forgery (CWE-347)",
        severity: "CRITICAL",
        evidence: samlUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(samlUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Set validateSignature:true and wantAssertionsSigned:true in all SAML strategy configurations.",
          "CWE-347 — unsigned SAML responses allow any user to craft an assertion claiming to be any other user.",
          "Fix: new SamlStrategy({ validateSignature: true, wantAssertionsSigned: true, cert: IDP_CERT }, ...)"
        ]
      });
    }

    // 10. Cookies without httpOnly/secure/sameSite flags
    const cookieHits = await codeSearch(String.raw`res\.cookie\s*\(\s*['"][^'"]+['"]`);
    const cookieHttpOnlyRe = /httpOnly\s*:\s*true/;
    const cookieSecureRe = /secure\s*:\s*true/;
    const cookieUnsafe = cookieHits.filter((h) => !cookieHttpOnlyRe.test(h.preview) || !cookieSecureRe.test(h.preview));
    if (cookieUnsafe.length > 0) {
      findings.push({
        id: "COOKIE_MISSING_SECURE_FLAGS",
        title: "Cookie set without httpOnly and/or secure flags (CWE-1004 / CWE-614)",
        severity: "HIGH",
        evidence: cookieUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(cookieUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Set httpOnly:true, secure:true, and sameSite:'Strict' on all authentication and session cookies.",
          "CWE-1004/CWE-614 — missing httpOnly enables XSS cookie theft; missing secure sends cookie over HTTP.",
          "Fix: res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 3600000 });"
        ]
      });
    }

    // 11. Refresh token issued but old token not invalidated (token rotation missing)
    const refreshTokenHits = await codeSearch(
      String.raw`(?:refresh_token|refreshToken)\s*[:=](?:.*jwt\.sign|.*generateToken|.*createToken|.*sign\s*\()|(?:grantType|grant_type)\s*[:=]\s*['"]refresh_token['"]`);
    const refreshRotateRe = /delete|revoke|invalidate|blacklist|rotateToken|revokeToken|tokenFamily|REFRESH_TOKEN_FAMILY/;
    const refreshUnsafe = refreshTokenHits.filter((h) => !refreshRotateRe.test(h.preview));
    if (refreshUnsafe.length > 0) {
      findings.push({
        id: "REFRESH_TOKEN_NOT_ROTATED",
        title: "Refresh token issued without revoking previous token — replay attack surface (CWE-613)",
        severity: "HIGH",
        evidence: refreshUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(refreshUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Implement refresh token rotation: invalidate the old token before issuing the new one.",
          "CWE-613 — without rotation, a stolen refresh token remains valid indefinitely.",
          "Fix: await db.refreshTokens.delete(oldToken); const newToken = issueRefreshToken(user); // token family detection for theft detection"
        ]
      });
    }

    // 12. JWT HS/RS confusion — jwt.verify called without algorithm pin on RS256 context
    const jwtHsRsHits = await codeSearch(
      String.raw`jwt\.verify\s*\(\s*[^,]+,\s*(?:publicKey|PUBLIC_KEY|pub_key|process\.env\.[A-Z_]*PUBLIC|fs\.readFileSync[^)]*\.pem)`);
    const jwtHsRsSafeRe = /algorithms\s*:\s*\[\s*['"](?:RS|ES|PS)/;
    const jwtHsRsUnsafe = jwtHsRsHits.filter((h) => !jwtHsRsSafeRe.test(h.preview));
    if (jwtHsRsUnsafe.length > 0) {
      findings.push({
        id: "JWT_HS_RS_CONFUSION",
        title: "JWT verified with public key without algorithm pin — HS/RS confusion attack (CVE-2015-9235 pattern)",
        severity: "CRITICAL",
        evidence: jwtHsRsUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
        files: [...new Set(jwtHsRsUnsafe.slice(0, 10).map((m) => m.file))],
        requiredActions: [
          "Pin the algorithm to RS256/ES256 explicitly: jwt.verify(token, publicKey, { algorithms: ['RS256'] }).",
          "Without algorithm pin: attacker takes RS256 public key, signs token with HS256 using that key as the HMAC secret — library accepts it.",
          "This is CVE-2015-9235 — still exploitable in jsonwebtoken < 9.0 without the algorithms option."
        ]
      });
    }
  } catch (err) {
    console.warn("[checkAuthDeep] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
  }

  return findings;
}
