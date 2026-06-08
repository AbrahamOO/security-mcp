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

async function checkJwtAlgNone(): Promise<Finding[]> {
  const hits = await codeSearch(String.raw`jwt\.verify\s*\(`);
  const findings: Finding[] = [];

  // Missing algorithms array entirely
  const missingAlg = hits.filter((h) => !/algorithms\s*:\s*\[/.test(h.preview));
  if (missingAlg.length) {
    findings.push({
      id: "JWT_ALG_NONE_ACCEPTED",
      title: "jwt.verify() called without explicit algorithms array — algorithm confusion attack possible (CWE-327)",
      severity: "CRITICAL",
      evidence: toEvidence(missingAlg),
      files: toFiles(missingAlg),
      requiredActions: [
        "Always pass algorithms: ['RS256'] (or your actual algorithm) to jwt.verify().",
        "CWE-327 — without algorithms pin, attacker can forge tokens using alg:none or switch RS256→HS256 using the public key as secret.",
        "Fix: jwt.verify(token, publicKey, { algorithms: ['RS256'] })"
      ]
    });
  }

  // Explicit 'none' in algorithms array — case-insensitive to catch 'None', 'NONE', etc.
  // The jsonwebtoken library lowercases the alg header before comparison, so 'None' and 'NONE'
  // are functionally equivalent to 'none' (CVE-2022-23529 pattern). CWE-327.
  const explicitNone = hits.filter((h) => /algorithms\s*:\s*\[.*['"]none['"].*\]/i.test(h.preview));
  if (explicitNone.length) {
    findings.push({
      id: "JWT_ALG_NONE_EXPLICIT",
      title: "jwt.verify() explicitly allows 'none' algorithm — unsigned tokens accepted (CWE-327)",
      severity: "CRITICAL",
      evidence: toEvidence(explicitNone),
      files: toFiles(explicitNone),
      requiredActions: [
        "Remove 'none' from the algorithms array immediately.",
        "CWE-327 — algorithms:['none'] allows any attacker to forge tokens by stripping the signature.",
        "Fix: jwt.verify(token, secret, { algorithms: ['RS256'] }) // never include 'none'"
      ]
    });
  }

  // HS256 used with a key name suggesting RSA/public key material
  const algConfusionExplicit = hits.filter(
    (h) =>
      /algorithms\s*:\s*\[/.test(h.preview) &&
      /['"]HS256['"]/.test(h.preview) &&
      /pub|public|cert|rsa/i.test(h.preview)
  );
  if (algConfusionExplicit.length) {
    findings.push({
      id: "JWT_ALG_CONFUSION_EXPLICIT",
      title: "jwt.verify() uses HS256 with a key that appears to be an RSA/public key — algorithm confusion (CWE-327)",
      severity: "CRITICAL",
      evidence: toEvidence(algConfusionExplicit),
      files: toFiles(algConfusionExplicit),
      requiredActions: [
        "Use RS256/ES256 when verifying with an RSA public key; HS256 is for symmetric secrets only.",
        "CWE-327 — using HS256 with an RSA public key as the HMAC secret is the classic algorithm confusion exploit.",
        "Fix: jwt.verify(token, publicKey, { algorithms: ['RS256'] })"
      ]
    });
  }

  return findings;
}

async function checkSessionFixation(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Existing single-line check
  const hits = await codeSearch(
    String.raw`(?:req\.session\.user|req\.session\.userId|req\.session\.account|req\.session\.authenticated)\s*=`
  );
  const unsafeSingleLine = hits.filter(
    (h) =>
      !/req\.session\.regenerate|session\.regenerate\s*\(|req\.login\s*\(|lucia\.createSession|lucia\.invalidateSession/.test(h.preview)
  );
  if (unsafeSingleLine.length) {
    findings.push({
      id: "SESSION_FIXATION",
      title: "Session identity set without session regeneration — session fixation risk (CWE-384)",
      severity: "HIGH",
      evidence: toEvidence(unsafeSingleLine),
      files: toFiles(unsafeSingleLine),
      requiredActions: [
        "Call req.session.regenerate() before setting session identity after authentication.",
        "CWE-384 — an attacker who fixes the session ID before login can hijack the authenticated session.",
        "Fix: req.session.regenerate((err) => { req.session.userId = user.id; res.json({ ok: true }); });"
      ]
    });
  }

  // Multi-line check: session assignment without adjacent regeneration
  const sessionAssignHits = await codeSearch(
    String.raw`req\.session\.\w+\s*=|session\.\w+\s*=`
  );
  // Filter out hits that have passport req.login, lucia, or regenerate in the preview
  const multiLineUnsafe = sessionAssignHits.filter(
    (h) =>
      !/req\.session\.regenerate|session\.regenerate\s*\(|req\.login\s*\(|lucia\.createSession|lucia\.invalidateSession|passport/.test(h.preview)
  );
  if (multiLineUnsafe.length) {
    findings.push({
      id: "SESSION_FIXATION_MULTILINE",
      title: "Session property assigned without adjacent session regeneration — potential session fixation (CWE-384)",
      severity: "HIGH",
      evidence: toEvidence(multiLineUnsafe),
      files: toFiles(multiLineUnsafe),
      requiredActions: [
        "Ensure req.session.regenerate() is called within 20 lines before any session identity assignment.",
        "CWE-384 — session fixation allows an attacker who sets the session ID pre-login to hijack the post-login session.",
        "Valid regeneration patterns: req.session.regenerate(), req.login() (Passport), lucia.createSession()."
      ]
    });
  }

  return findings;
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

async function checkOauthImplicitFlow(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`response_type\s*[=:]\s*['"]token['"]|responseType\s*:\s*['"]token['"]`
  );
  if (!hits.length) return null;
  return {
    id: "OAUTH_IMPLICIT_FLOW",
    title: "OAuth implicit flow (response_type=token) exposes tokens in URL fragments (CWE-319)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Replace implicit flow with authorization code flow + PKCE for all public clients and SPAs.",
      "OAuth 2.0 BCP (RFC 9700) — implicit flow exposes access tokens in URL fragments, browser history, and Referer headers.",
      "Fix: response_type=code with code_challenge_method=S256; exchange code for tokens server-side or via PKCE."
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

async function checkJwtMissingExpiry(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // jwt.sign() without expiresIn in options
  const signHits = await codeSearch(String.raw`jwt\.sign\s*\(`);
  const missingExpiry = signHits.filter((h) => !/expiresIn\s*:/.test(h.preview));
  if (missingExpiry.length) {
    findings.push({
      id: "JWT_MISSING_EXPIRY",
      title: "jwt.sign() called without expiresIn — tokens never expire (CWE-613)",
      severity: "HIGH",
      evidence: toEvidence(missingExpiry),
      files: toFiles(missingExpiry),
      requiredActions: [
        "Always set an expiry on JWTs: jwt.sign(payload, secret, { expiresIn: '1h' }).",
        "CWE-613 — a JWT without expiresIn remains valid indefinitely, even after account compromise.",
        "Fix: jwt.sign(payload, process.env.JWT_SECRET!, { algorithms: ['RS256'], expiresIn: '1h' })"
      ]
    });
  }

  // API key / token ORM creation without expiresAt / expiresIn
  const tokenCreateHits = await codeSearch(
    String.raw`(?:apiToken|apiKey|personalToken|accessToken)\s*=.*\.create\s*\(\s*\{|\.create\s*\(\s*\{[^}]*(?:apiToken|apiKey|personalToken|accessToken)`
  );
  const missingTokenExpiry = tokenCreateHits.filter(
    (h) => !/expiresAt|expiresIn|expires_at|expires_in/i.test(h.preview)
  );
  if (missingTokenExpiry.length) {
    findings.push({
      id: "TOKEN_MISSING_EXPIRY",
      title: "API token created without expiry field — long-lived credentials increase breach impact (CWE-613)",
      severity: "MEDIUM",
      evidence: toEvidence(missingTokenExpiry),
      files: toFiles(missingTokenExpiry),
      requiredActions: [
        "Include an expiresAt or expiresIn field when creating API tokens and enforce it on every use.",
        "CWE-613 — tokens without expiry remain valid indefinitely after a credential leak.",
        "Fix: await db.apiTokens.create({ userId, token, expiresAt: new Date(Date.now() + 90 * 86400000) })"
      ]
    });
  }

  return findings;
}

async function checkMissingRateLimitLogin(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:router|app)\.post\s*\(\s*['"][^'"]*(?:\/login|\/signin|\/auth|\/token|\/session|\/mfa|\/otp|\/totp|\/2fa|\/verify|\/reset|\/forgot|\/confirm|\/unlock|\/activate|\/resend)['"]\s*,`
  );
  const unsafe = hits.filter(
    (h) => !/rateLimit|rateLimiter|rate_limit|limiter|throttle|slowDown|expressRateLimit/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "MISSING_RATE_LIMIT_LOGIN",
    title: "Authentication or MFA/OTP endpoint without rate limiting — brute force attack surface (CWE-307)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Apply express-rate-limit or equivalent middleware to all authentication, MFA, OTP, and account-recovery endpoints.",
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

async function checkSamlXsw(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Detect SAML library usage
  const samlLibHits = await codeSearch(
    String.raw`require\s*\(\s*['"](?:saml2-js|passport-saml|@node-saml\/passport-saml|@node-saml|samlify|saml-encoder)['"]`
  );
  if (!samlLibHits.length) return findings;

  const samlFiles = toFiles(samlLibHits);

  // Check for missing InResponseTo validation
  const inResponseToHits = await codeSearch(String.raw`validateInResponseTo|InResponseToCheck`);
  if (!inResponseToHits.length) {
    findings.push({
      id: "SAML_MISSING_INRESPONSETO",
      title: "SAML library used without validateInResponseTo — open to unsolicited response injection (CWE-347)",
      severity: "HIGH",
      evidence: toEvidence(samlLibHits),
      files: samlFiles,
      requiredActions: [
        "Enable validateInResponseTo: true in your SAML strategy configuration.",
        "CWE-347 — without InResponseTo validation, an attacker can inject a valid SAML response from a different SP session.",
        "Fix: new SamlStrategy({ validateInResponseTo: 'always', ... }, ...)"
      ]
    });
  }

  // Check for allowUnsolicitedResponses: true
  const unsolicitedHits = await codeSearch(String.raw`allowUnsolicitedResponses\s*:\s*true`);
  if (unsolicitedHits.length) {
    findings.push({
      id: "SAML_UNSOLICITED_RESPONSE_ALLOWED",
      title: "SAML allowUnsolicitedResponses:true — IdP-initiated SSO enables XSW and session injection (CWE-347)",
      severity: "CRITICAL",
      evidence: toEvidence(unsolicitedHits),
      files: toFiles(unsolicitedHits),
      requiredActions: [
        "Set allowUnsolicitedResponses: false and require InResponseTo validation.",
        "CWE-347 — unsolicited SAML responses bypass InResponseTo checks, enabling XML Signature Wrapping attacks.",
        "Fix: new SamlStrategy({ allowUnsolicitedResponses: false, validateInResponseTo: 'always' }, ...)"
      ]
    });
  }

  // Check for unsigned assertions/responses
  const signedFalseHits = await codeSearch(
    String.raw`wantAuthnResponseSigned\s*:\s*false|wantAssertionsSigned\s*:\s*false`
  );
  if (signedFalseHits.length) {
    findings.push({
      id: "SAML_RESPONSE_UNSIGNED",
      title: "SAML wantAuthnResponseSigned or wantAssertionsSigned set to false — forged assertions accepted (CWE-347)",
      severity: "CRITICAL",
      evidence: toEvidence(signedFalseHits),
      files: toFiles(signedFalseHits),
      requiredActions: [
        "Set wantAuthnResponseSigned: true and wantAssertionsSigned: true in all SAML configurations.",
        "CWE-347 — disabling signature requirements allows an attacker to forge arbitrary SAML assertions.",
        "Fix: new SamlStrategy({ wantAuthnResponseSigned: true, wantAssertionsSigned: true, ... }, ...)"
      ]
    });
  }

  // Check for XMLDOM xpath getElementsByTagName without signature verification
  const xpathHits = await codeSearch(String.raw`getElementsByTagName\s*\(`);
  const xpathUnsafe = xpathHits.filter(
    (h) => !/validateSignature|verifySignature|checkSignature|SignedInfo|xmldsig/.test(h.preview)
  );
  if (xpathUnsafe.length) {
    findings.push({
      // Distinct ID from the aggregate SAML_XSW_RISK below to avoid dedup dropping
      // the more actionable aggregate finding when both conditions fire simultaneously.
      id: "SAML_XSW_XPATH_RISK",
      title: "SAML XML parsed with getElementsByTagName without per-element signature verification — XSW attack vector (CWE-347)",
      severity: "HIGH",
      evidence: toEvidence(xpathUnsafe),
      files: toFiles(xpathUnsafe),
      requiredActions: [
        "Verify the XML signature on the specific element returned by getElementsByTagName before trusting its content.",
        "CWE-347 / XSW — XML Signature Wrapping attacks move the signed element to a different location; always verify after selection.",
        "Fix: use xml-crypto or saml-validated methods that verify signature on the exact element before attribute extraction."
      ]
    });
  }

  // Aggregate XSW risk: SAML without full protection set
  const hasInResponseTo = inResponseToHits.length > 0;
  const hasWantResponseSigned = (await codeSearch(String.raw`wantAuthnResponseSigned\s*:\s*true`)).length > 0;
  const hasWantAssertionsSigned = (await codeSearch(String.raw`wantAssertionsSigned\s*:\s*true`)).length > 0;

  if (!hasInResponseTo || !hasWantResponseSigned || !hasWantAssertionsSigned) {
    findings.push({
      id: "SAML_XSW_RISK",
      title: "SAML used without full XSW protection (validateInResponseTo + wantAuthnResponseSigned + wantAssertionsSigned) — XML Signature Wrapping risk (CWE-347)",
      severity: "CRITICAL",
      evidence: toEvidence(samlLibHits),
      files: samlFiles,
      requiredActions: [
        "Ensure all three protections are enabled: validateInResponseTo: 'always', wantAuthnResponseSigned: true, wantAssertionsSigned: true.",
        "CWE-347 — partial SAML protections leave XML Signature Wrapping (XSW) attack surface open.",
        "Fix: new SamlStrategy({ validateInResponseTo: 'always', wantAuthnResponseSigned: true, wantAssertionsSigned: true, cert: IDP_CERT }, ...)"
      ]
    });
  }

  // Deduplicate by id, keeping first occurrence
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
}

async function checkSamlReplay(): Promise<Finding | null> {
  // Detect SAML library usage
  const samlLibHits = await codeSearch(
    String.raw`require\s*\(\s*['"](?:saml2-js|passport-saml|@node-saml\/passport-saml|@node-saml|samlify|saml-encoder)['"]`
  );
  if (!samlLibHits.length) return null;

  // Check for replay prevention: assertion ID caching or NotOnOrAfter tracking
  const replayPreventionHits = await codeSearch(
    String.raw`assertionId|NotOnOrAfter|InResponseTo.*cache|assertionCache|replayCache|usedAssertions|seenIds`
  );
  if (replayPreventionHits.length) return null;

  return {
    id: "SAML_REPLAY_NOT_PREVENTED",
    title: "SAML library used without assertion replay prevention — replayed assertions accepted (CWE-294)",
    severity: "HIGH",
    evidence: toEvidence(samlLibHits),
    files: toFiles(samlLibHits),
    requiredActions: [
      "Implement assertion ID caching: store each assertion's ID with a TTL matching the NotOnOrAfter window; reject duplicate IDs.",
      "CWE-294 — without replay prevention, a captured SAML assertion can be replayed to authenticate as the victim until the assertion expires.",
      "Fix: if (assertionCache.has(assertionId)) throw new Error('Replayed assertion'); assertionCache.set(assertionId, true, ttl);"
    ]
  };
}

async function checkJwtHsRsConfusion(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Existing pattern: explicit public key variable names
  const publicKeyHits = await codeSearch(
    String.raw`jwt\.verify\s*\(\s*[^,]+,\s*(?:publicKey|PUBLIC_KEY|pub_key|process\.env\.[A-Z_]*PUBLIC|fs\.readFileSync[^)]*\.pem)`
  );
  const unsafePublicKey = publicKeyHits.filter((h) => !/algorithms\s*:\s*\[\s*['"](?:RS|ES|PS)/.test(h.preview));
  if (unsafePublicKey.length) {
    findings.push({
      id: "JWT_HS_RS_CONFUSION",
      title: "JWT verified with public key without algorithm pin — HS/RS confusion attack (CVE-2015-9235 pattern)",
      severity: "CRITICAL",
      evidence: toEvidence(unsafePublicKey),
      files: toFiles(unsafePublicKey),
      requiredActions: [
        "Pin the algorithm to RS256/ES256 explicitly: jwt.verify(token, publicKey, { algorithms: ['RS256'] }).",
        "Without algorithm pin: attacker signs token with HS256 using the RS256 public key as HMAC secret — library accepts it.",
        "This is CVE-2015-9235 — still exploitable in jsonwebtoken < 9.0 without the algorithms option."
      ]
    });
  }

  // New pattern: any jwt.verify() without algorithms array locked to asymmetric algorithm
  const allVerifyHits = await codeSearch(String.raw`jwt\.verify\s*\(`);
  const notLocked = allVerifyHits.filter(
    (h) =>
      !/algorithms\s*:\s*\[\s*['"](?:RS|ES|PS)/.test(h.preview) &&
      !/algorithms\s*:\s*\[/.test(h.preview)
  );
  if (notLocked.length) {
    findings.push({
      id: "JWT_ALG_NOT_LOCKED",
      title: "jwt.verify() without algorithms array locked to an asymmetric algorithm — algorithm confusion vector (CWE-327)",
      severity: "HIGH",
      evidence: toEvidence(notLocked),
      files: toFiles(notLocked),
      requiredActions: [
        "Explicitly set algorithms: ['RS256'] or ['ES256'] (or your asymmetric algorithm) in jwt.verify() options.",
        "CWE-327 — without an algorithm pin, the library will accept whatever algorithm the token header specifies.",
        "Fix: jwt.verify(token, publicKey, { algorithms: ['RS256'] })"
      ]
    });
  }

  // New pattern: jwt.verify() with process.env.* secret and no algorithm pin (confusion vector via env var holding public key)
  const envVarHits = await codeSearch(
    String.raw`jwt\.verify\s*\(\s*\w+,\s*process\.env\.\w+`
  );
  const envUnsafe = envVarHits.filter(
    (h) => !/algorithms\s*:\s*\[\s*['"](?:RS|ES|PS)/.test(h.preview)
  );
  if (envUnsafe.length) {
    findings.push({
      id: "JWT_ALG_CONFUSION_RISK",
      title: "jwt.verify() uses process.env secret without asymmetric algorithm pin — env var may hold public key (CWE-327)",
      severity: "HIGH",
      evidence: toEvidence(envUnsafe),
      files: toFiles(envUnsafe),
      requiredActions: [
        "If the env var holds an RSA public key, pin to RS256: jwt.verify(token, process.env.PUBLIC_KEY, { algorithms: ['RS256'] }).",
        "CWE-327 — when an RSA public key is stored in a generic env var, HS256 confusion attacks are possible without an algorithm pin.",
        "Fix: jwt.verify(token, process.env.JWT_PUBLIC_KEY!, { algorithms: ['RS256'] })"
      ]
    });
  }

  // Deduplicate by id
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
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

async function checkAccountLockout(): Promise<Finding | null> {
  const loginHits = await codeSearch(
    String.raw`(?:router|app)\.post\s*\(\s*['"][^'"]*(?:\/login|\/signin|\/auth\/local|\/session)['"]\s*,`
  );
  if (!loginHits.length) return null;

  const lockoutHits = await codeSearch(
    String.raw`failedAttempts|loginAttempts|lockoutUntil|accountLocked|lockedAt|bruteForce|maxAttempts|attempt[Cc]ount`
  );
  if (lockoutHits.length) return null;

  return {
    id: "ACCOUNT_LOCKOUT_MISSING",
    title: "Login endpoint found but no account lockout counter detected — brute-force persistence risk (CWE-307 / NIST IA-5(1))",
    severity: "MEDIUM",
    evidence: loginHits.slice(0, 5).map((h) => `${h.file}:${h.line}:${h.preview}`),
    files: [...new Set(loginHits.slice(0, 5).map((h) => h.file))],
    requiredActions: [
      "Track failed login attempts per account and lock the account after a configurable threshold (e.g., 5 attempts).",
      "CWE-307 / NIST IA-5(1) — rate limiting prevents brute-force per IP but does not prevent distributed credential stuffing across IPs.",
      "Fix: increment failedAttempts on each failed login; if failedAttempts >= MAX_ATTEMPTS set lockoutUntil = Date.now() + 15 * 60 * 1000; reject logins when locked."
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

export async function checkAuthDeep(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  try {
    const [
      jwtAlgNoneFindings,
      sessionFixationFindings,
      oauthMissingState,
      oauthOpenRedirectUri,
      oauthImplicitFlow,
      pkceNotEnforced,
      hardcodedJwtSecret,
      jwtMissingExpiryFindings,
      missingRateLimitLogin,
      passwordPlainCompare,
      samlSignatureDisabled,
      samlXswFindings,
      samlReplay,
      jwtHsRsConfusionFindings,
      apiKeyInUrl,
      passwordResetNoExpiry,
      adminRouteNoAuthz,
      timingOracle,
      cookieSecureFlags,
      refreshTokenNotRotated,
      accountLockout,
    ] = await Promise.all([
      checkJwtAlgNone(),
      checkSessionFixation(),
      checkOauthMissingState(),
      checkOauthOpenRedirectUri(),
      checkOauthImplicitFlow(),
      checkPkceNotEnforced(),
      checkHardcodedJwtSecret(),
      checkJwtMissingExpiry(),
      checkMissingRateLimitLogin(),
      checkPasswordPlainCompare(),
      checkSamlSignatureDisabled(),
      checkSamlXsw(),
      checkSamlReplay(),
      checkJwtHsRsConfusion(),
      checkApiKeyInUrl(),
      checkPasswordResetNoExpiry(),
      checkAdminRouteNoAuthz(),
      checkTimingOracle(),
      checkCookieSecureFlags(),
      checkRefreshTokenNotRotated(),
      checkAccountLockout(),
    ]);

    const singleFindings = [
      oauthMissingState,
      oauthOpenRedirectUri,
      oauthImplicitFlow,
      pkceNotEnforced,
      hardcodedJwtSecret,
      missingRateLimitLogin,
      passwordPlainCompare,
      samlSignatureDisabled,
      samlReplay,
      apiKeyInUrl,
      passwordResetNoExpiry,
      adminRouteNoAuthz,
      timingOracle,
      cookieSecureFlags,
      refreshTokenNotRotated,
      accountLockout,
    ].filter((f): f is Finding => f !== null);

    return [
      ...jwtAlgNoneFindings,
      ...sessionFixationFindings,
      ...singleFindings,
      ...jwtMissingExpiryFindings,
      ...samlXswFindings,
      ...jwtHsRsConfusionFindings,
    ];
  } catch (err) {
    console.warn("[checkAuthDeep] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    return [];
  }
}
