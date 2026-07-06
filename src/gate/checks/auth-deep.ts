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

// ---------------------------------------------------------------------------
// OWASP A09 / NIST AU-11 / PCI Req 10 — Observability checks
// ---------------------------------------------------------------------------

async function checkMissingStructuredLogging(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Detect web framework usage
  const webFrameworkHits = await codeSearch(
    String.raw`require\s*\(\s*['"](?:express|fastify|koa)['"]\s*\)|from\s+['"](?:express|fastify|koa)['"]`
  );
  if (!webFrameworkHits.length) return findings;

  // Detect structured logger
  const loggerHits = await codeSearch(
    String.raw`require\s*\(\s*['"](?:pino|morgan|winston|bunyan)['"]\s*\)|from\s+['"](?:pino|winston|morgan|bunyan)['"]`
  );

  if (!loggerHits.length) {
    findings.push({
      id: "MISSING_STRUCTURED_LOGGING",
      title: "No structured logging library detected (pino, winston, morgan, bunyan). OWASP A09 requires logging security events.",
      severity: "HIGH",
      evidence: toEvidence(webFrameworkHits),
      files: toFiles(webFrameworkHits),
      requiredActions: [
        "Install a structured logging library (pino, winston, morgan, or bunyan) and integrate it with the web framework.",
        "OWASP A09 — without structured logs, authentication failures, authorization errors, and anomalies cannot be detected or alerted on.",
        "Fix: import pino from 'pino'; const logger = pino(); app.use(pinoHttp({ logger }));"
      ]
    });
    return findings;
  }

  // Logger found — check for .error( or .warn( near auth endpoints
  const authRouteHits = await codeSearch(
    String.raw`(?:router|app)\.(?:post|get|put|patch|delete)\s*\(\s*['"][^'"]*(?:\/login|\/auth|\/token)['"]\s*,`
  );
  if (!authRouteHits.length) return findings;

  const authLogHits = await codeSearch(
    String.raw`\.(?:error|warn)\s*\([^)]*(?:login|auth|token|unauthorized|forbidden|invalid|fail|deny|reject)`
  );
  if (!authLogHits.length) {
    findings.push({
      id: "AUTH_EVENTS_NOT_LOGGED",
      title: "Auth endpoints detected but no .error()/.warn() calls found near login/auth/token routes — security events may not be logged",
      severity: "MEDIUM",
      evidence: toEvidence(authRouteHits),
      files: toFiles(authRouteHits),
      requiredActions: [
        "Add structured log calls (logger.warn / logger.error) for authentication failures, authorization denials, and anomalous requests.",
        "OWASP A09 — unlogged auth failures prevent detection of credential stuffing and brute-force attacks.",
        "Fix: logger.warn({ userId, ip: req.ip }, 'Authentication failed — invalid credentials');"
      ]
    });
  }

  return findings;
}

async function checkLogRetentionConfig(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Only run if a logger is configured
  const loggerHits = await codeSearch(
    String.raw`require\s*\(\s*['"](?:pino|morgan|winston|bunyan)['"]\s*\)|from\s+['"](?:pino|winston|morgan|bunyan)['"]`
  );
  if (!loggerHits.length) return findings;

  // Check for retention settings
  const retentionHits = await codeSearch(
    String.raw`maxFiles|maxsize|tailable|retentionDays|retention|logRotation`
  );
  if (retentionHits.length) return findings; // retention configured — no finding needed

  findings.push({
    id: "LOG_RETENTION_NOT_CONFIGURED",
    title: "No log retention policy found. PCI DSS Req 10.3 requires audit logs retained for 12 months; NIST AU-11 requires risk-aligned retention.",
    severity: "MEDIUM",
    evidence: toEvidence(loggerHits),
    files: toFiles(loggerHits),
    requiredActions: [
      "Configure log rotation and retention: set maxFiles / maxsize / retentionDays in your logging configuration.",
      "PCI DSS Req 10.3 — audit logs must be retained for at least 12 months, with 3 months immediately available.",
      "NIST AU-11 — audit record retention must be aligned to organizational risk policy.",
      "Fix (winston): new winston.transports.File({ filename: 'app.log', maxFiles: 365, maxsize: 10485760, tailable: true })"
    ]
  });

  return findings;
}

async function checkJwtKidInjection(): Promise<Finding | null> {
  const headerKidHits = await codeSearch(
    String.raw`(?:header\.kid|token\.header\.kid|decoded\.header\.kid)`
  );
  const unsafe1 = headerKidHits.filter(
    (h) => !/allowlist|ALLOWED_KIDS|path\.join.*validateKid|parameterized|sanitize/.test(h.preview)
  );
  const rawQueryHits = await codeSearch(
    String.raw`SELECT[^;]*\$\{[^}]*kid|readFileSync[^)]*kid`
  );
  const combined = [...unsafe1, ...rawQueryHits];
  const seen = new Set<string>();
  const deduped = combined.filter((h) => {
    const key = `${h.file}:${h.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  if (!deduped.length) return null;
  return {
    id: "JWT_KID_INJECTION",
    title: "JWT kid header used for DB lookup or filesystem read without sanitization — SQL/path-traversal injection (CWE-89/CWE-22)",
    severity: "CRITICAL",
    evidence: toEvidence(deduped),
    files: toFiles(deduped),
    requiredActions: [
      "Validate the kid header against a strict allowlist before using it in any DB query or filesystem read.",
      "CWE-89 — unsanitized kid in SQL interpolation enables SQL injection; CWE-22 — unsanitized kid in readFileSync enables path traversal.",
      "Fix: const key = ALLOWED_KIDS[decoded.header.kid]; if (!key) throw new Error('Unknown kid');"
    ]
  };
}

async function checkJwksUriOverride(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:jwksUri|jwks_uri|JwksClient|createRemoteJWKSet|getSigningKey.*jwks)`
  );
  const unsafe = hits.filter(
    (h) => !/allowlist|JWKS_URI|staticKeys|hardcoded|process\.env\.JWKS/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "JWT_JWKS_URI_OVERRIDE",
    title: "JWKS endpoint fetched dynamically — attacker can override jwks_uri to serve their own keys (CWE-295)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Pin the JWKS URI to a hardcoded or environment-variable-controlled value; never derive it from the token or request.",
      "CWE-295 — a dynamic jwks_uri allows an attacker to point key resolution at their own server and sign arbitrary tokens.",
      "Fix: const client = new JwksClient({ jwksUri: process.env.JWKS_URI }); // JWKS_URI set at deploy time, never at runtime from user input"
    ]
  };
}

async function checkOauthClientSecretPublic(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:client_secret|clientSecret)\s*[:=]\s*['"][a-zA-Z0-9_\-]{8,}['"]`
  );
  if (!hits.length) return null;
  return {
    id: "OAUTH_CLIENT_SECRET_HARDCODED",
    title: "OAuth client_secret hardcoded in source — public client credentials extractable from bundle (CWE-798)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Move client_secret to a server-side environment variable or secrets manager; never embed it in frontend bundles.",
      "CWE-798 — hardcoded OAuth secrets are extractable from git history, Docker layers, and compiled bundles.",
      "Fix: clientSecret: process.env.OAUTH_CLIENT_SECRET"
    ]
  };
}

async function checkSessionTokenInUrl(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`req\.query\.(?:sessionid|session_id|sid|jsessionid|auth_token|session_token)`
  );
  if (!hits.length) return null;
  return {
    id: "SESSION_TOKEN_IN_URL",
    title: "Session token transmitted in URL query parameter — logged in server access logs and browser history (CWE-598)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Transmit session tokens exclusively in cookies or the Authorization header, never in query parameters.",
      "CWE-598 — query parameters appear in server access logs, browser history, Referer headers, and CDN logs in plaintext.",
      "Fix: const sessionId = req.cookies['session']; // never req.query.session_id"
    ]
  };
}

async function checkTokenEntropyTooLow(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`crypto\.randomBytes\s*\(\s*([1-9]|1[0-5])\s*\)`
  );
  if (!hits.length) return null;
  return {
    id: "TOKEN_ENTROPY_TOO_LOW",
    title: "crypto.randomBytes() called with fewer than 16 bytes (<128 bits entropy) — tokens brute-forceable (CWE-331)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Use crypto.randomBytes(32) or larger to generate tokens with at least 256 bits of entropy.",
      "CWE-331 — tokens generated with fewer than 128 bits of entropy are vulnerable to brute-force enumeration.",
      "Fix: const token = crypto.randomBytes(32).toString('hex'); // 256-bit entropy"
    ]
  };
}

async function checkRememberMeNoRotation(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:rememberMe|remember_me|persistent.*token|rememberToken|keepLoggedIn|staySignedIn)`
  );
  const unsafe = hits.filter(
    (h) => !/rotate|revoke|invalidate|delete.*token|tokenFamily/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "REMEMBER_ME_NO_ROTATION",
    title: "Persistent remember-me token without rotation — stolen token grants indefinite access (CWE-613)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Rotate remember-me tokens on each use: invalidate the presented token and issue a fresh one.",
      "CWE-613 — a static persistent token that is never rotated or revoked grants indefinite access if stolen.",
      "Fix: await db.rememberTokens.delete(oldToken); const newToken = crypto.randomBytes(32).toString('hex'); await db.rememberTokens.create({ userId, token: newToken, expiresAt });"
    ]
  };
}

async function checkPasswordResetSingleUse(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:resetToken|reset_token|passwordResetToken|forgotToken)\s*(?:===|==)\s*(?:req\.|body\.|params\.)`
  );
  const unsafe = hits.filter(
    (h) => !/delete|update.*null|set.*null|invalidate|revoke|markUsed|usedAt/.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "PASSWORD_RESET_NOT_SINGLE_USE",
    title: "Password reset token validated but not deleted/invalidated after use — token reuse attack possible (CWE-640)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Delete or null out the reset token immediately after successful verification.",
      "CWE-640 — a reset token that remains valid after use can be replayed to reset the password again.",
      "Fix: await db.users.update({ where: { id: user.id }, data: { resetToken: null, resetTokenExpiry: null } });"
    ]
  };
}

async function checkAccountEnumeration(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:user|account|email).*not.*found|no.*user.*(?:found|exists)|User.*does.*not.*exist|unknown.*(?:email|user|account)`
  );
  const safeRe = /\/\/|expect\s*\(|toBe|toEqual|console\.log|logger\.(debug|info|warn)|\.test\s*\(/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "ACCOUNT_ENUMERATION",
    title: "Distinct error message reveals whether username/email exists — enables account enumeration (CWE-203)",
    severity: "MEDIUM",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Return the same generic error message for both 'user not found' and 'wrong password' scenarios.",
      "CWE-203 — distinct error messages for unknown vs wrong-password allow attackers to enumerate valid accounts.",
      "Fix: throw new Error('Invalid credentials'); // same message regardless of whether user exists"
    ]
  };
}

async function checkBcryptCostFactor(): Promise<Finding | null> {
  const hashHits = await codeSearch(
    String.raw`bcrypt\.(?:hash|hashSync)\s*\([^,]+,\s*([1-9])\s*[,)]`
  );
  const saltHits = await codeSearch(
    String.raw`genSalt\s*\(\s*([1-9])\s*\)`
  );
  const combined = [...hashHits, ...saltHits];
  const seen = new Set<string>();
  const deduped = combined.filter((h) => {
    const key = `${h.file}:${h.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  if (!deduped.length) return null;
  return {
    id: "BCRYPT_COST_TOO_LOW",
    title: "bcrypt cost factor below 10 — password hashes crackable with GPU (OWASP PBKDF guidance)",
    severity: "HIGH",
    evidence: toEvidence(deduped),
    files: toFiles(deduped),
    requiredActions: [
      "Set the bcrypt cost factor to at least 10 (OWASP recommends 12 for new systems).",
      "OWASP PBKDF guidance — a cost factor below 10 allows GPU-accelerated brute-force cracking of password hashes.",
      "Fix: await bcrypt.hash(password, 12); // or bcrypt.genSalt(12)"
    ]
  };
}

async function checkJwtKidLoadWithoutAllowlist(): Promise<Finding | null> {
  // kid header value flowing into a key load from path / DB / URL, without an allowlist gate.
  const kidHits = await codeSearch(
    String.raw`(?:header\.kid|\.header\.kid|decoded\.kid|jwtHeader\.kid|token\.kid|payload\.kid)`
  );
  // Require a key-loading sink on the same line and a JWT/key-loading context.
  const sinkRe = /readFile|readFileSync|createReadStream|path\.join|path\.resolve|fetch\s*\(|axios|https?\.get|SELECT|findOne|findUnique|query\s*\(|getKey|loadKey|keyStore|\.get\s*\(/i;
  const allowlistRe = /allowlist|allowList|ALLOWED_KIDS?|allowedKids|KEY_MAP|keyMap\b|keysById|KEYS\[|whitelist/i;
  const unsafe = kidHits.filter((h) => sinkRe.test(h.preview) && !allowlistRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "JWT_KID_KEY_LOAD_NO_ALLOWLIST",
    title: "JWT kid header used to load signing key from path/DB/URL without an allowlist — key injection (CWE-347/CWE-290)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    sla: "24h",
    requiredActions: [
      "Resolve the kid only through a fixed allowlist map (kid -> known public key); reject any kid not present in it.",
      "CWE-347/CWE-290 — loading the key named by the attacker-controlled kid (from disk, DB, or a URL) lets an attacker supply their own key and forge valid signatures.",
      "Fix: const key = ALLOWED_KEYS[decoded.header.kid]; if (!key) throw new Error('Unknown kid'); jwt.verify(token, key, { algorithms: ['RS256'] });"
    ]
  };
}

async function checkJwtAlgListContainsNone(): Promise<Finding | null> {
  // algorithms array that mixes a real algorithm with 'none' (e.g. ['HS256','none']).
  const hits = await codeSearch(
    String.raw`algorithms\s*:\s*\[[^\]]*['"](?:HS|RS|ES|PS)(?:256|384|512)['"][^\]]*['"]none['"]|algorithms\s*:\s*\[[^\]]*['"]none['"][^\]]*['"](?:HS|RS|ES|PS)(?:256|384|512)['"]`
  );
  if (!hits.length) return null;
  return {
    id: "JWT_ALG_LIST_INCLUDES_NONE",
    title: "JWT algorithms array lists a real algorithm alongside 'none' — unsigned tokens accepted (CWE-327)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    sla: "24h",
    requiredActions: [
      "Remove 'none' from the algorithms array; it must contain only the real algorithm(s) you actually issue.",
      "CWE-327 — an attacker sets the token header alg to 'none', strips the signature, and the verifier still accepts it because 'none' is allowlisted.",
      "Fix: jwt.verify(token, key, { algorithms: ['HS256'] }) // never ['HS256','none']"
    ]
  };
}

async function checkOidcNonceNotValidated(): Promise<Finding | null> {
  // OIDC flow present (nonce sent in the authorize request) but nonce never compared/validated on the id_token.
  const oidcHits = await codeSearch(
    String.raw`(?:openid|id_token|idToken|oidc|OIDC)`
  );
  if (!oidcHits.length) return null;
  const nonceSentHits = await codeSearch(String.raw`nonce\s*[:=]`);
  if (!nonceSentHits.length) return null;
  // Look for evidence the nonce is actually validated against the stored value.
  const nonceValidatedHits = await codeSearch(
    String.raw`(?:claims|payload|idToken|decoded|id_token)\.nonce\s*(?:===|==|!==|!=)|nonce\s*(?:===|==|!==|!=)\s*(?:session|stored|expected|req\.session)|validateNonce|verifyNonce|checkNonce`
  );
  if (nonceValidatedHits.length) return null;
  const evidence = nonceSentHits.filter((h) => /openid|id_token|idToken|oidc/i.test(h.preview) || true).slice(0, 10);
  return {
    id: "OIDC_NONCE_NOT_VALIDATED",
    title: "OIDC nonce sent but never validated against the id_token — token replay / injection (CWE-287)",
    severity: "HIGH",
    evidence: toEvidence(evidence),
    files: toFiles(evidence),
    sla: "7d",
    requiredActions: [
      "Store the nonce in the user's session before redirecting to the IdP, then compare it to the id_token's nonce claim after exchange.",
      "CWE-287 / OIDC Core §3.1.2.7 — without nonce validation an attacker can replay or inject an id_token obtained in a different session.",
      "Fix: if (idToken.nonce !== req.session.oidcNonce) throw new Error('Invalid nonce');"
    ]
  };
}

async function checkOauthCodeReuse(): Promise<Finding | null> {
  // Authorization-code exchange present, but the code is not invalidated/consumed after the token exchange.
  const exchangeHits = await codeSearch(
    String.raw`grant_type\s*[:=]\s*['"]authorization_code['"]|getToken\s*\(|exchangeCode|\.exchange\s*\(|tokenEndpoint|\/token['"]`
  );
  if (!exchangeHits.length) return null;
  const unsafe = exchangeHits.filter(
    (h) =>
      !/delete|revoke|invalidate|consume|markUsed|usedAt|codeUsed|once\b|single.?use/i.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "OAUTH_CODE_REUSE",
    title: "OAuth authorization code exchanged without being invalidated — code replay / reuse (CWE-294)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    sla: "7d",
    requiredActions: [
      "Invalidate (delete/mark used) the authorization code atomically at exchange time and reject any subsequent presentation of it.",
      "CWE-294 / RFC 6749 §4.1.2 — authorization codes MUST be single-use; a replayed code lets an attacker mint a second set of tokens.",
      "Fix: const rec = await db.authCodes.findUnique({ where: { code } }); if (!rec || rec.usedAt) throw new Error('Invalid code'); await db.authCodes.update({ where: { code }, data: { usedAt: new Date() } });"
    ]
  };
}

async function checkSamlAssertionXxe(): Promise<Finding | null> {
  // XML parse of a SAML assertion/response without XXE hardening.
  const samlXmlHits = await codeSearch(
    String.raw`(?:DOMParser|libxmljs|xml2js|@xmldom\/xmldom|new\s+DOMParser|parseFromString|parseXml|xmldom)`
  );
  // Require SAML context in the same file to keep FPs low.
  const samlContextHits = await codeSearch(
    String.raw`SAMLResponse|saml2|passport-saml|@node-saml|samlify|Assertion|<saml`
  );
  const samlFiles = new Set(samlContextHits.map((h) => h.file));
  const inSaml = samlXmlHits.filter((h) => samlFiles.has(h.file));
  if (!inSaml.length) return null;
  // Suppress if XXE hardening is present anywhere (noent/entity disabling).
  const hardeningHits = await codeSearch(
    String.raw`noent\s*:\s*false|resolveExternalEntities\s*:\s*false|DOCTYPE.*false|disallowDoctype|noblanks|FEATURE_SECURE_PROCESSING|nonet\s*:\s*true|noExternalEntities`
  );
  const hardenedFiles = new Set(hardeningHits.map((h) => h.file));
  const unsafe = inSaml.filter((h) => !hardenedFiles.has(h.file));
  if (!unsafe.length) return null;
  return {
    id: "SAML_ASSERTION_XXE",
    title: "SAML assertion XML parsed without XXE hardening — XML External Entity injection (CWE-611)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    sla: "24h",
    requiredActions: [
      "Parse SAML XML with external entities and DOCTYPE processing disabled (noent:false / resolveExternalEntities:false / disallow DOCTYPE).",
      "CWE-611 — an attacker-supplied SAMLResponse containing an external entity can read local files (file:///etc/passwd) or perform SSRF during signature processing.",
      "Fix: use a hardened parser, e.g. libxmljs2 parseXml(xml, { noent: false, nonet: true, dtdload: false }) or a SAML library configured to reject DOCTYPE."
    ]
  };
}

async function checkPredictableSessionId(): Promise<Finding | null> {
  // Session/token id generated from a predictable source (Math.random / Date.now / sequential counter).
  const hits = await codeSearch(
    String.raw`(?:sessionId|session_id|sessionToken|session_token|sid|token|authToken|auth_token)\s*[:=][^;\n]*(?:Math\.random\s*\(|Date\.now\s*\(|new\s+Date\s*\(|performance\.now\s*\(|\+\+|counter\b|sequence\b|incrementId)`
  );
  const unsafe = hits.filter(
    (h) => !/crypto\.randomBytes|crypto\.randomUUID|randomUUID|uuidv4|nanoid|getRandomValues/i.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "PREDICTABLE_SESSION_ID",
    title: "Session/token identifier derived from Math.random / Date.now / sequential counter — predictable session ID (CWE-330/CWE-340)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    sla: "24h",
    requiredActions: [
      "Generate session and token identifiers with a CSPRNG: crypto.randomBytes(32).toString('hex') or crypto.randomUUID().",
      "CWE-330/CWE-340 — Math.random(), Date.now(), and incrementing counters are predictable, letting an attacker guess or enumerate valid session IDs and hijack sessions.",
      "Fix: const sessionId = crypto.randomBytes(32).toString('hex');"
    ]
  };
}

async function checkPostLoginOpenRedirect(): Promise<Finding | null> {
  // Post-login/post-auth redirect using a user-supplied param without allowlisting.
  const hits = await codeSearch(
    String.raw`res\.redirect\s*\(\s*(?:req\.query\.(?:returnTo|redirect|redirectUrl|redirect_uri|next|url|returnUrl|dest|continue|callback)|req\.body\.(?:returnTo|redirect|redirectUrl|next|url|returnUrl|dest|continue)|returnTo\b|redirectUrl\b|nextUrl\b)`
  );
  const unsafe = hits.filter(
    (h) =>
      !/allowlist|allowList|whitelist|isAllowed|startsWith\s*\(\s*['"]\/['"]|new\s+URL|validateRedirect|safeRedirect|ALLOWED_REDIRECTS?/i.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "POST_LOGIN_OPEN_REDIRECT",
    title: "Post-login redirect to a user-supplied URL without allowlisting — open redirect / credential phishing (CWE-601)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    sla: "7d",
    requiredActions: [
      "Validate the post-login redirect target against an allowlist of relative paths or registered hosts; default to a fixed internal URL otherwise.",
      "CWE-601 — an attacker crafts a login link with ?returnTo=https://evil.com so the victim is redirected off-site (with tokens/session) immediately after authenticating.",
      "Fix: const dest = ALLOWED_REDIRECTS.has(req.query.returnTo) ? req.query.returnTo : '/dashboard'; res.redirect(dest);"
    ]
  };
}

async function checkOidcDiscoveryUnpinned(): Promise<Finding | null> {
  // .well-known/openid-configuration fetched without pinning/trust anchoring.
  const hits = await codeSearch(
    String.raw`\.well-known\/openid-configuration|openid-configuration|discoveryEndpoint|issuer\.discover|Issuer\.discover`
  );
  const unsafe = hits.filter(
    (h) =>
      !/pin|allowlist|allowList|expectedIssuer|EXPECTED_ISSUER|ca\s*:|checkServerIdentity|trustedIssuers?|process\.env\.(?:OIDC|ISSUER)/i.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "OIDC_DISCOVERY_UNPINNED",
    title: "OIDC discovery document fetched without issuer pinning / trust anchoring — malicious IdP metadata (CWE-295/CWE-346)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    sla: "7d",
    requiredActions: [
      "Pin the expected issuer and validate the discovery document's issuer against it; fetch it only over TLS with certificate verification enabled.",
      "CWE-295/CWE-346 — if an attacker can influence the discovery URL or MITM the fetch, they control the jwks_uri and authorization/token endpoints, enabling full token forgery.",
      "Fix: const issuer = await Issuer.discover(process.env.OIDC_ISSUER!); if (issuer.issuer !== EXPECTED_ISSUER) throw new Error('Untrusted issuer');"
    ]
  };
}

async function checkGraphqlAliasAuthBypass(): Promise<Finding | null> {
  // Field-level @auth / authorization applied to resolvers that can be renamed via GraphQL aliases,
  // where the auth decision keys off the alias/field name rather than the resolver.
  const graphqlHits = await codeSearch(
    String.raw`(?:info\.fieldName|fieldNodes|info\.path\.key|\.alias\b|selectionSet)`
  );
  // Require an auth decision in the same file that references the field/alias name.
  const authNameHits = graphqlHits.filter((h) =>
    /auth|permission|requireAuth|@auth|isAuthorized|denyIf|allowIf|role/i.test(h.preview)
  );
  const unsafe = authNameHits.filter(
    (h) => !/directive|resolver.*wrap|middleware.*resolve|shield|rule\s*\(/i.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "GRAPHQL_ALIAS_AUTH_BYPASS",
    title: "GraphQL field authorization keyed on field/alias name — auth bypass via query aliases (CWE-863)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    sla: "24h",
    requiredActions: [
      "Enforce authorization on the resolver/type itself (schema directive, graphql-shield rule, or wrapped resolver), never by string-matching info.fieldName or the response alias.",
      "CWE-863 — a client can alias a protected field (e.g. `secret: sensitiveField`) so any name-based auth check misses it while the resolver still runs.",
      "Fix: apply auth in the resolver via a directive/shield rule tied to the field's resolver, so it fires regardless of the alias the client chooses."
    ]
  };
}

async function checkBasicAuthOverHttp(): Promise<Finding | null> {
  // Basic auth accepted/sent without requiring HTTPS.
  const basicHits = await codeSearch(
    String.raw`(?:Authorization['"]?\s*[:,]\s*['"]?Basic\s|['"]Basic\s+['"]\s*\+|basic-auth|basicAuth|auth\s*:\s*\{[^}]*user)`
  );
  const httpUrlHits = await codeSearch(String.raw`['"]http:\/\/[^'"]`);
  const httpFiles = new Set(httpUrlHits.map((h) => h.file));
  // Flag Basic auth where either an explicit http:// URL is in the same file, or the line itself
  // shows Basic auth without any https/TLS guard.
  const unsafe = basicHits.filter(
    (h) =>
      (httpFiles.has(h.file) || /http:\/\//i.test(h.preview)) &&
      !/req\.secure|x-forwarded-proto|forceHttps|requireHttps|https:\/\//i.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "BASIC_AUTH_OVER_HTTP",
    title: "HTTP Basic authentication used over a non-HTTPS channel — credentials sent in cleartext (CWE-319/CWE-522)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    sla: "7d",
    requiredActions: [
      "Only accept/transmit Basic auth over TLS; reject Basic credentials when req.secure is false (or X-Forwarded-Proto is not https).",
      "CWE-319/CWE-522 — Basic auth base64-encodes (does not encrypt) credentials, so over HTTP they are trivially recovered by any network observer.",
      "Fix: if (!req.secure) return res.status(400).send('HTTPS required'); // and change all http:// client base URLs to https://"
    ]
  };
}

async function checkImplicitFlowInProduction(): Promise<Finding | null> {
  // response_type=token (implicit) present in code that looks production-bound.
  const hits = await codeSearch(
    String.raw`response_type\s*[:=]\s*['"]token['"]|responseType\s*[:=]\s*['"]token['"]|response_type=token`
  );
  // Keep this distinct from the existing OAUTH_IMPLICIT_FLOW by requiring a production/non-test context.
  const testRe = /test|spec|mock|fixture|example|localhost|127\.0\.0\.1/i;
  const unsafe = hits.filter((h) => !testRe.test(h.file) && !testRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "OAUTH_IMPLICIT_FLOW_PRODUCTION",
    title: "OAuth implicit flow (response_type=token) configured in production code — access tokens exposed in URL (CWE-319)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    sla: "7d",
    requiredActions: [
      "Disable the implicit grant for production clients; use authorization code flow with PKCE (response_type=code, code_challenge_method=S256).",
      "OAuth 2.0 Security BCP (RFC 9700) — the implicit flow is deprecated; access tokens in the URL fragment leak via history, Referer, and logs.",
      "Fix: response_type=code with PKCE; exchange the code for tokens on the token endpoint."
    ]
  };
}

async function checkAccountLinkingNoReauth(): Promise<Finding | null> {
  // Account linking (adding a federated identity to an existing account) without a re-authentication step.
  const hits = await codeSearch(
    String.raw`(?:linkAccount|link_account|linkIdentity|linkProvider|connectAccount|mergeIdentity|addProvider|linkSocial)`
  );
  const unsafe = hits.filter(
    (h) =>
      !/reauth|re-auth|reauthenticate|requirePassword|verifyPassword|confirmPassword|recentLogin|stepUp|step-up|mfa|reAuthenticated/i.test(h.preview)
  );
  if (!unsafe.length) return null;
  return {
    id: "ACCOUNT_LINKING_NO_REAUTH",
    title: "Account/identity linking without re-authentication — account takeover via forced linking (CWE-306/CWE-287)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    sla: "7d",
    requiredActions: [
      "Require a fresh re-authentication (password re-entry, recent login, or MFA/step-up) before linking any new federated identity to an existing account.",
      "CWE-306/CWE-287 — without re-auth, a CSRF or a hijacked session can attach an attacker-controlled IdP identity, giving the attacker a permanent alternate login.",
      "Fix: if (!req.session.reauthenticatedAt || Date.now() - req.session.reauthenticatedAt > 5*60*1000) return res.status(403).send('Re-authentication required'); // then link"
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
      missingStructuredLoggingFindings,
      logRetentionFindings,
      jwtKidInjection,
      jwksUriOverride,
      oauthClientSecretPublic,
      sessionTokenInUrl,
      tokenEntropyTooLow,
      rememberMeNoRotation,
      passwordResetSingleUse,
      accountEnumeration,
      bcryptCostFactor,
      jwtKidLoadNoAllowlist,
      jwtAlgListContainsNone,
      oidcNonceNotValidated,
      oauthCodeReuse,
      samlAssertionXxe,
      predictableSessionId,
      postLoginOpenRedirect,
      oidcDiscoveryUnpinned,
      graphqlAliasAuthBypass,
      basicAuthOverHttp,
      implicitFlowInProduction,
      accountLinkingNoReauth,
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
      checkMissingStructuredLogging(),
      checkLogRetentionConfig(),
      checkJwtKidInjection(),
      checkJwksUriOverride(),
      checkOauthClientSecretPublic(),
      checkSessionTokenInUrl(),
      checkTokenEntropyTooLow(),
      checkRememberMeNoRotation(),
      checkPasswordResetSingleUse(),
      checkAccountEnumeration(),
      checkBcryptCostFactor(),
      checkJwtKidLoadWithoutAllowlist(),
      checkJwtAlgListContainsNone(),
      checkOidcNonceNotValidated(),
      checkOauthCodeReuse(),
      checkSamlAssertionXxe(),
      checkPredictableSessionId(),
      checkPostLoginOpenRedirect(),
      checkOidcDiscoveryUnpinned(),
      checkGraphqlAliasAuthBypass(),
      checkBasicAuthOverHttp(),
      checkImplicitFlowInProduction(),
      checkAccountLinkingNoReauth(),
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
      jwtKidInjection,
      jwksUriOverride,
      oauthClientSecretPublic,
      sessionTokenInUrl,
      tokenEntropyTooLow,
      rememberMeNoRotation,
      passwordResetSingleUse,
      accountEnumeration,
      bcryptCostFactor,
      jwtKidLoadNoAllowlist,
      jwtAlgListContainsNone,
      oidcNonceNotValidated,
      oauthCodeReuse,
      samlAssertionXxe,
      predictableSessionId,
      postLoginOpenRedirect,
      oidcDiscoveryUnpinned,
      graphqlAliasAuthBypass,
      basicAuthOverHttp,
      implicitFlowInProduction,
      accountLinkingNoReauth,
    ].filter((f): f is Finding => f !== null);

    return [
      ...jwtAlgNoneFindings,
      ...sessionFixationFindings,
      ...singleFindings,
      ...jwtMissingExpiryFindings,
      ...samlXswFindings,
      ...jwtHsRsConfusionFindings,
      ...missingStructuredLoggingFindings,
      ...logRetentionFindings,
    ];
  } catch (err) {
    console.warn("[checkAuthDeep] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    return [];
  }
}
