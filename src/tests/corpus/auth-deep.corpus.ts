import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "JWT_ALG_NONE_ACCEPTED",
    check: "auth-deep",
    positive: {
      file: "src/auth/verifyToken.ts",
      content: `export function verifySessionToken(token: string) {\n  return jwt.verify(token, process.env.JWT_SECRET);\n}\n`
    },
    negative: {
      file: "src/auth/verifyToken.ts",
      content: `export function verifySessionToken(token: string) {\n  return jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] });\n}\n`
    },
    note: "Positive line has no algorithms option so it lands in missingAlg. Negative puts algorithms:['RS256'] on the same physical line jwt.verify() is called on, which is what the same-line preview regex /algorithms\\s*:\\s*\\[/ actually inspects."
  },
  {
    ruleId: "JWT_ALG_CONFUSION_EXPLICIT",
    check: "auth-deep",
    positive: {
      file: "src/auth/verifyRsaToken.ts",
      content: `const publicKey = fs.readFileSync("rsa_public.pem");\n\nexport function verifyRsaToken(token: string) {\n  return jwt.verify(token, publicKey, { algorithms: ["HS256"] });\n}\n`
    },
    negative: {
      file: "src/auth/verifyRsaToken.ts",
      content: `const publicKey = fs.readFileSync("rsa_public.pem");\n\nexport function verifyRsaToken(token: string) {\n  return jwt.verify(token, publicKey, { algorithms: ["RS256"] });\n}\n`
    },
    note: "Positive line contains algorithms:[...], the literal 'HS256', and 'publicKey' (matches /pub|public|cert|rsa/i) all on one line, so it fires. Negative uses RS256 -- the algorithm that actually matches the key material -- so the required 'HS256' substring is absent and the rule cannot fire."
  },
  {
    ruleId: "HARDCODED_JWT_SECRET",
    check: "auth-deep",
    positive: {
      file: "src/auth/issueToken.ts",
      content: `export function issueToken(payload: object) {\n  return jwt.sign(payload, "super-secret-key-123");\n}\n`
    },
    negative: {
      file: "src/auth/issueToken.ts",
      content: `export function issueToken(payload: object) {\n  return jwt.sign(payload, process.env.JWT_SECRET, { algorithms: ["RS256"] });\n}\n`
    },
    note: "Positive's second jwt.sign() argument is a quoted literal 1-32 chars long, matching the hardcoded-secret regex exactly. Negative's second argument is process.env.JWT_SECRET (no surrounding quotes), so the ['\"]...['\"] capture never anchors -- an env-var lookup, not a literal, per the rule's own Fix line."
  },
  {
    ruleId: "JWT_MISSING_EXPIRY",
    check: "auth-deep",
    positive: {
      file: "src/auth/issueSession.ts",
      content: `export function issueSessionToken(payload: object) {\n  return jwt.sign(payload, process.env.JWT_SECRET);\n}\n`
    },
    negative: {
      file: "src/auth/issueSession.ts",
      content: `export function issueSessionToken(payload: object) {\n  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" });\n}\n`
    },
    note: "Positive's jwt.sign() line has no expiresIn: token, so it lands in missingExpiry. Negative adds expiresIn:'1h' on the same line, matching the rule's own Fix exactly, so the /expiresIn\\s*:/ same-line check excludes it."
  },
  {
    ruleId: "JWT_KID_KEY_LOAD_NO_ALLOWLIST",
    check: "auth-deep",
    positive: {
      file: "src/auth/jwks.ts",
      content: `export function loadSigningKey(decoded: { header: { kid: string } }) {\n  return fs.readFileSync(path.join(KEYS_DIR, decoded.header.kid));\n}\n`
    },
    negative: {
      file: "src/auth/jwks.ts",
      content: `const ALLOWED_KIDS: Record<string, Buffer> = { "key-1": RSA_PUBLIC_KEY_1, "key-2": RSA_PUBLIC_KEY_2 };\n\nexport function loadSigningKey(decoded: { header: { kid: string } }) {\n  const key = ALLOWED_KIDS[decoded.header.kid];\n  if (!key) throw new Error("Unknown kid");\n  return key;\n}\n`
    },
    note: "Positive's line has decoded.header.kid feeding directly into readFileSync/path.join (a sink) with no allowlist token present, so sinkRe matches and allowlistRe does not. Negative resolves the kid only through a fixed ALLOWED_KIDS map -- the exact remediation in requiredActions -- and the line that indexes it contains no filesystem/DB/network sink at all, so sinkRe never matches."
  },
  {
    ruleId: "SESSION_FIXATION",
    check: "auth-deep",
    positive: {
      file: "src/routes/login.ts",
      content: `export function handleLogin(req, res) {\n  req.session.userId = user.id;\n  res.redirect("/dashboard");\n}\n`
    },
    negative: {
      file: "src/routes/login.ts",
      content: `export function handleLogin(req, res) {\n  req.session.regenerate((err) => { req.session.userId = user.id; res.json({ ok: true }); });\n}\n`
    },
    note: "Positive's assignment line has no regenerate/login/lucia token on it, so it lands in unsafeSingleLine. Negative places the regenerate() call and the identity assignment on the SAME physical line (the rule's own Fix line, verbatim), which is what the same-line preview check actually inspects -- splitting them across a callback body on separate lines would not exclude the hit."
  },
  {
    ruleId: "PREDICTABLE_SESSION_ID",
    check: "auth-deep",
    positive: {
      file: "src/session/createSession.ts",
      content: `export function createSessionId() {\n  const sessionId = Math.random().toString(36).substring(2);\n  return sessionId;\n}\n`
    },
    negative: {
      file: "src/session/createSession.ts",
      content: `export function createSessionId() {\n  const sessionId = crypto.randomBytes(32).toString("hex");\n  return sessionId;\n}\n`
    },
    note: "The rule requires the literal token sessionId/session_id/etc. followed by ':' or '=' on the SAME line as the predictable source, so the assignment must read `const sessionId = Math.random()...` rather than a bare `return Math.random()...`. Negative keeps the same `sessionId =` shape but assigns from crypto.randomBytes(), which matches none of the Math.random/Date.now/counter alternatives."
  },
  {
    ruleId: "COOKIE_MISSING_SECURE_FLAGS",
    check: "auth-deep",
    positive: {
      file: "src/routes/session.ts",
      content: `export function setSessionCookie(res, token: string) {\n  res.cookie("session", token);\n}\n`
    },
    negative: {
      file: "src/routes/session.ts",
      content: `export function setSessionCookie(res, token: string) {\n  res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "Strict", maxAge: 3600000 });\n}\n`
    },
    note: "Positive's res.cookie() call has neither httpOnly:true nor secure:true on the line. Negative sets both flags plus sameSite on the same line as the call -- exactly the rule's own Fix -- so neither of the two OR'd absence checks trips."
  },
  {
    ruleId: "OAUTH_MISSING_STATE",
    check: "auth-deep",
    positive: {
      file: "src/routes/oauthCallback.ts",
      content: `export function handleOauthCallback(req, res) {\n  app.get("/oauth/callback", (r, s) => exchangeCodeForToken(r.query.code));\n}\n`
    },
    negative: {
      file: "src/routes/oauthCallback.ts",
      content: `export function startOauthLogin(req, res) {\n  const state = crypto.randomBytes(32).toString("hex");\n  req.session.oauthState = state;\n  res.redirect("https://idp.example.com/oauth/authorize?client_id=abc&state=" + state);\n}\n`
    },
    note: "Positive's route-registration line matches the /oauth/callback alternative with no state/nonce/crypto.randomBytes token on it. Negative generates the state with a CSPRNG, stores it in session, and appends it to the authorize redirect -- the literal 'state=' text lands on the same line as the matched .redirect(...oauth/authorize) call, satisfying the same-line state\\s*[:=] exclusion because a real state parameter is genuinely present."
  },
  {
    ruleId: "OAUTH_OPEN_REDIRECT_URI",
    check: "auth-deep",
    positive: {
      file: "src/oauth/validateRedirect.ts",
      content: `export function isValidRedirect(redirect_uri: string) {\n  if (redirect_uri.startsWith("https://app.example.com")) { approveRedirect(redirect_uri); }\n}\n`
    },
    negative: {
      file: "src/oauth/validateRedirect.ts",
      content: `const REGISTERED_REDIRECT_URI = "https://app.example.com/callback";\n\nexport function isValidRedirect(redirect_uri: string) {\n  if (redirect_uri !== REGISTERED_REDIRECT_URI) { throw new Error("Invalid redirect_uri"); }\n}\n`
    },
    note: "Positive's line pairs the redirect_uri identifier with .startsWith(, matching the rule's alternation, which allows the evil.com-suffixed-subdomain bypass it targets. Negative uses exact !== equality against a pre-registered constant -- the rule's own Fix -- with no .includes/.startsWith/.match/indexOf call anywhere near redirect_uri, so the base query never matches."
  },
  {
    ruleId: "PKCE_NOT_ENFORCED",
    check: "auth-deep",
    positive: {
      file: "src/oauth/tokenExchange.ts",
      content: `export async function exchangeToken(grant_type: string, code: string) {\n  if (grant_type === "authorization_code") { return exchangeCodeForTokens(code); }\n}\n`
    },
    negative: {
      file: "src/oauth/tokenExchange.ts",
      content: `export async function exchangeToken(grant_type: string, code: string, code_verifier: string) {\n  if (grant_type === "authorization_code" && code_verifier) { return exchangeCodeForTokens(code, code_verifier); }\n}\n`
    },
    note: "Positive's line matches grant_type.*authorization_code with no code_challenge/code_verifier/pkce token present. Negative requires code_verifier on that same line before exchanging the code -- enforcing PKCE as requiredActions instructs -- which satisfies the exclusion regex."
  },
  {
    ruleId: "OIDC_NONCE_NOT_VALIDATED",
    check: "auth-deep",
    positive: {
      file: "src/oidc/login.ts",
      content: `export function startOidcLogin(req, res) {\n  const nonce = generateNonce();\n  req.session.oidcNonce = nonce;\n  res.redirect("https://idp.example.com/authorize?response_type=id_token&scope=openid&nonce=" + nonce);\n}\n\nexport function handleOidcCallback(req, res) {\n  const idToken = req.body.id_token;\n  const claims = decodeJwt(idToken);\n  createSession(req, claims);\n}\n`
    },
    negative: {
      file: "src/oidc/login.ts",
      content: `export function startOidcLogin(req, res) {\n  const nonce = generateNonce();\n  req.session.oidcNonce = nonce;\n  res.redirect("https://idp.example.com/authorize?response_type=id_token&scope=openid&nonce=" + nonce);\n}\n\nexport function handleOidcCallback(req, res) {\n  const idToken = req.body.id_token;\n  const claims = decodeJwt(idToken);\n  if (claims.nonce !== req.session.oidcNonce) { throw new Error("Invalid nonce"); }\n  createSession(req, claims);\n}\n`
    },
    note: "Both files contain openid/id_token markers and send a nonce, so both pass the two prerequisite whole-file searches. Positive never compares the nonce anywhere in the file, so nonceValidatedHits is empty and the finding fires. Negative adds claims.nonce !== req.session.oidcNonce, matching the claims\\.nonce\\s*(?:===|==|!==|!=) alternative, which suppresses it."
  },
  {
    ruleId: "SAML_SIGNATURE_NOT_ENFORCED",
    check: "auth-deep",
    positive: {
      file: "src/saml/strategy.ts",
      content: `import { Strategy as SamlStrategy } from "passport-saml";\n\nexport const samlStrategy = new SamlStrategy({ entryPoint: "https://idp.example.com/sso", issuer: "app", cert: IDP_CERT, validateSignature: false }, verifyCallback);\n`
    },
    negative: {
      file: "src/saml/strategy.ts",
      content: `import { Strategy as SamlStrategy } from "passport-saml";\n\nexport const samlStrategy = new SamlStrategy({ entryPoint: "https://idp.example.com/sso", issuer: "app", cert: IDP_CERT, validateSignature: true, wantAssertionsSigned: true }, verifyCallback);\n`
    },
    note: "Positive's strategy-config line contains the literal validateSignature:false, matching both the base query and the explicit-false re-check. Negative's import line still matches the base query's 'passport-saml' library-detection alternative, but its config line reads validateSignature:true/wantAssertionsSigned:true, so the explicit-false re-check filters it out and no finding is produced."
  },
  {
    ruleId: "SAML_ASSERTION_XXE",
    check: "auth-deep",
    positive: {
      file: "src/saml/parseAssertion.ts",
      content: `const { DOMParser } = require("@xmldom/xmldom");\n\n// Parses the raw SAMLResponse XML payload from the IdP.\nexport function parseSamlAssertion(samlResponseXml: string) {\n  const doc = new DOMParser().parseFromString(samlResponseXml, "text/xml");\n  return doc.getElementsByTagName("saml:Assertion");\n}\n`
    },
    negative: {
      file: "src/saml/parseAssertion.ts",
      content: `const { parseXml } = require("libxmljs2");\n\n// Parses the raw SAMLResponse XML payload from the IdP with external entities disabled.\nexport function parseSamlAssertion(samlResponseXml: string) {\n  const doc = parseXml(samlResponseXml, { noent: false, nonet: true, dtdload: false });\n  return doc.get("//saml:Assertion");\n}\n`
    },
    note: "Both files contain an XML-parser call (DOMParser/parseXml) plus SAML context markers (SAMLResponse, Assertion) in the same file, satisfying the two prerequisite whole-file searches. Positive has no XXE-hardening token anywhere, so the file is not in hardenedFiles and the finding fires. Negative's parse call passes { noent: false, nonet: true, dtdload: false } -- the rule's own Fix -- which matches the hardening regex and removes the whole file from the unsafe set."
  },
  {
    ruleId: "PASSWORD_PLAIN_COMPARE",
    check: "auth-deep",
    positive: {
      file: "src/auth/localLogin.ts",
      content: `export function checkPassword(password: string, user) {\n  if (password === user.password) { return login(user); }\n}\n`
    },
    negative: {
      file: "src/auth/localLogin.ts",
      content: `export async function checkPassword(password: string, user) {\n  const valid = await bcrypt.compare(password, user.passwordHash);\n  if (!valid) { throw new Error("Unauthorized"); }\n}\n`
    },
    note: "Positive's line matches password\\s*===\\s*user\\. with no bcrypt/argon2/timingSafeEqual token present. Negative uses bcrypt.compare() -- an async hashed comparison, not a === on plaintext -- which does not contain '===' at all, so the base query never matches."
  },
  {
    ruleId: "BCRYPT_COST_TOO_LOW",
    check: "auth-deep",
    positive: {
      file: "src/auth/hashPassword.ts",
      content: `export async function hashPassword(password: string) {\n  return bcrypt.hash(password, 8);\n}\n`
    },
    negative: {
      file: "src/auth/hashPassword.ts",
      content: `export async function hashPassword(password: string) {\n  return bcrypt.hash(password, 12);\n}\n`
    },
    note: "Positive's cost factor '8' is a single digit 1-9, matching bcrypt\\.hash\\s*\\([^,]+,\\s*([1-9])\\s*[,)] exactly. Negative's cost factor '12' is two digits: after the single-char group ([1-9]) consumes '1', the regex requires \\s*[,)] immediately next, but the following character is '2', so the match fails entirely -- OWASP's recommended cost of 12 is structurally outside what this single-digit regex can match."
  },
  {
    ruleId: "TOKEN_ENTROPY_TOO_LOW",
    check: "auth-deep",
    positive: {
      file: "src/utils/generateToken.ts",
      content: `export function generateApiToken() {\n  return crypto.randomBytes(8).toString("hex");\n}\n`
    },
    negative: {
      file: "src/utils/generateToken.ts",
      content: `export function generateApiToken() {\n  return crypto.randomBytes(32).toString("hex");\n}\n`
    },
    note: "Positive's byte count '8' matches the ([1-9]|1[0-5]) alternation directly. Negative's byte count '32' matches neither alternative (not a single digit, and not '1' followed by 0-5), so crypto.randomBytes(32) -- 256 bits of entropy -- produces no hit."
  },
  {
    ruleId: "TIMING_ORACLE_COMPARISON",
    check: "auth-deep",
    positive: {
      file: "src/mfa/verifyOtp.ts",
      content: `export function verifyOtp(otp: string, req) {\n  if (otp === req.body.otp) { return grantAccess(); }\n}\n`
    },
    negative: {
      file: "src/mfa/verifyOtp.ts",
      content: `export function verifyOtp(req) {\n  const provided = Buffer.from(req.body.otp);\n  const stored = Buffer.from(getStoredOtp(req.session.userId));\n  return provided.length === stored.length && crypto.timingSafeEqual(provided, stored);\n}\n`
    },
    note: "Positive's line matches otp\\s*===\\s*req\\. with no timingSafeEqual token present -- a classic short-circuiting equality timing oracle. Negative replaces the direct otp/req. comparison entirely with a Buffer.from + crypto.timingSafeEqual() comparison keyed on .length, matching neither of the rule's two keyword-adjacent-to-=== alternatives, so no hit is produced."
  },
  {
    ruleId: "MISSING_RATE_LIMIT_LOGIN",
    check: "auth-deep",
    positive: {
      file: "src/routes/authRoutes.ts",
      content: `export function registerAuthRoutes(app) {\n  app.post("/login", loginHandler);\n}\n`
    },
    negative: {
      file: "src/routes/authRoutes.ts",
      content: `export function registerAuthRoutes(app) {\n  const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });\n  app.post("/login", limiter, loginHandler);\n}\n`
    },
    note: "Positive's route-registration line matches the /login alternative with no rate-limit token on it. The exclusion check /rateLimit|rateLimiter|...|limiter|.../.test(h.preview) has NO 'i' flag, so it is case-sensitive: a camelCase 'loginRateLimiter' argument would NOT match (its relevant substring is 'RateLimiter' with a capital R from the camelCase boundary, not lowercase 'rateLimiter'). Negative instead names the middleware instance 'limiter' (all lowercase, the idiomatic express-rate-limit convention) on the same app.post() line, which matches the 'limiter' alternative literally."
  },
  {
    ruleId: "ADMIN_ROUTE_NO_AUTHZ",
    check: "auth-deep",
    positive: {
      file: "src/routes/adminRoutes.ts",
      content: `export function registerAdminRoutes(router) {\n  router.get("/admin/users", listUsers);\n}\n`
    },
    negative: {
      file: "src/routes/adminRoutes.ts",
      content: `export function registerAdminRoutes(router) {\n  router.get("/admin/users", requireAdminRole, listUsers);\n}\n`
    },
    note: "Positive's route path '/admin/users' matches the /admin alternative (admin followed immediately by another slash) with no requireAdmin/isAdmin/adminAuth/role-based token on the line. Negative inserts requireAdminRole as middleware on the same line: it contains 'Admin' immediately followed by 'Role', matching the admin.*role alternative, so the finding is suppressed."
  },
  {
    ruleId: "API_KEY_IN_URL",
    check: "auth-deep",
    positive: {
      file: "src/clients/inventory.ts",
      content: `export async function fetchItems() {\n  const res = await fetch(\`https://api.example.com/v1/items?api_key=\${process.env.API_KEY}\`);\n  return res.json();\n}\n`
    },
    negative: {
      file: "src/clients/inventory.ts",
      content: `export async function fetchItems() {\n  const res = await fetch("https://api.example.com/v1/items", {\n    headers: { Authorization: \`Bearer \${process.env.API_KEY}\` },\n  });\n  return res.json();\n}\n`
    },
    note: "Only the receiving side (req.query.api_key) was covered. A key placed in a URL this service CALLS leaks identically — into the upstream's access logs and every proxy in between — and is the more common form in application code. Negative moves the same key to the Authorization header."
  },
  {
    ruleId: "SESSION_TOKEN_IN_URL",
    check: "auth-deep",
    positive: {
      file: "src/routes/post-login.ts",
      content: `export function afterLogin(req, res) {\n  res.redirect(\`/dashboard?session_token=\${req.session.id}\`);\n}\n`
    },
    negative: {
      file: "src/routes/post-login.ts",
      content: `export function afterLogin(req, res) {\n  res.cookie("session", req.session.id, { httpOnly: true, secure: true, sameSite: "lax" });\n  res.redirect("/dashboard");\n}\n`
    },
    note: "Reading a session id from the query string was covered; writing one into a URL was not. A token in a redirect target lands in browser history and in the Referer header of every subsequent outbound link. Negative carries the session in an httpOnly cookie instead."
  },
  {
    ruleId: "PASSWORD_RESET_NO_EXPIRY",
    check: "auth-deep",
    positive: {
      file: "src/routes/reset.ts",
      content: `app.post("/password-reset", async (req, res) => {\n  const token = crypto.randomBytes(32).toString("hex");\n  await db.resetToken.create({ data: { token, userId: user.id } });\n  await sendResetEmail(user.email, token);\n});\n`
    },
    negative: {
      file: "src/routes/reset.ts",
      content: `app.post("/password-reset", async (req, res) => {\n  const token = crypto.randomBytes(32).toString("hex");\n  await db.resetToken.create({\n    data: { token, userId: user.id, expiresAt: new Date(Date.now() + 3600_000) },\n  });\n  await sendResetEmail(user.email, token);\n});\n`
    },
    note: "Only the verify side was covered, so a token PERSISTED with no expiry column — where the bug is usually written — produced nothing. The negative sets expiresAt on a different line from the matched one, which is why this rule judges a window around the hit rather than the matched line alone."
  },
  {
    ruleId: "REFRESH_TOKEN_NOT_ROTATED",
    check: "auth-deep",
    positive: {
      file: "src/routes/refresh.ts",
      content: `app.post("/refresh", async (req, res) => {\n  const rt = await db.refreshToken.findUnique({ where: { token: req.body.refresh_token } });\n  if (!rt) return res.status(401).end();\n  const access_token = jwt.sign({ sub: rt.userId }, SECRET, { expiresIn: "15m" });\n  res.json({ access_token, refresh_token: rt.token });\n});\n`
    },
    negative: {
      file: "src/routes/refresh.ts",
      content: `app.post("/refresh", async (req, res) => {\n  const rt = await db.refreshToken.findUnique({ where: { token: req.body.refresh_token } });\n  if (!rt) return res.status(401).end();\n  await db.refreshToken.delete({ where: { id: rt.id } });\n  const next = await issueRefreshToken(rt.userId);\n  const access_token = jwt.sign({ sub: rt.userId }, SECRET, { expiresIn: "15m" });\n  res.json({ access_token, refresh_token: next.token });\n});\n`
    },
    note: "The most literal form of 'not rotated' — handing the same stored token back in the response — matched nothing, because the old pattern required a token-minting call on the line and only the access token is minted here. Negative deletes the presented token and issues a new one before responding."
  }
];
