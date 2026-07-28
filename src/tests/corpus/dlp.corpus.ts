import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "DLP_SSN_IN_LOGS",
    check: "dlp",
    positive: {
      file: "src/services/user-service.ts",
      content: `export function logUserVerification(user) {\n  console.log("Verifying user SSN:", "123-45-6789");\n}\n`
    },
    negative: {
      file: "src/services/user-service.ts",
      content: `export function logUserVerification(user, ssn) {\n  console.log("SSN on file (masked): ***-**-" + ssn.slice(-4));\n}\n`
    },
    note: "Negative masks all but the last 4 digits before logging, so no literal 3-2-4 digit run appears on the log line; only a single digit (\"4\" in slice(-4)) is present in source."
  },
  {
    ruleId: "DLP_PAN_IN_LOGS",
    check: "dlp",
    positive: {
      file: "src/services/payment-service.ts",
      content: `export function chargeCard(cardNumber) {\n  console.log("Charging card:", "4111111111111111");\n  return processCharge(cardNumber);\n}\n`
    },
    negative: {
      file: "src/services/payment-service.ts",
      content: `export function chargeCard(cardNumber) {\n  console.log("Charging card ending in:", cardNumber.slice(-4));\n  return processCharge(cardNumber);\n}\n`
    },
    note: "Negative logs only the last 4 digits via .slice(-4), the exact remediation the rule recommends; no full 13/16-digit PAN literal appears in source."
  },
  {
    ruleId: "DLP_REQUEST_BODY_LOGGED",
    check: "dlp",
    positive: {
      file: "src/routes/signup.ts",
      content: `export function handleSignup(req, res) {\n  console.log(req.body);\n  res.status(201).send();\n}\n`
    },
    negative: {
      file: "src/routes/signup.ts",
      content: `export function handleSignup(req, res) {\n  console.log("Signup payload:", { email: req.body.email, plan: req.body.plan });\n  res.status(201).send();\n}\n`
    },
    note: "Rule requires req.body/request.body/ctx.body/{...req to appear immediately after the opening paren. Negative's console.log( is followed by a literal object allowlisting two fields, not req.body itself, so the anchored alternation never matches even though req.body appears later in the line."
  },
  {
    ruleId: "DLP_USER_OBJECT_LOGGED",
    check: "dlp",
    positive: {
      file: "src/routes/profile.ts",
      content: `export function getProfile(req, res) {\n  const user = req.session.user;\n  console.log(user);\n  res.json(user);\n}\n`
    },
    negative: {
      file: "src/routes/profile.ts",
      content: `export function getProfile(req, res) {\n  const user = req.session.user;\n  console.log(user.id, user.role);\n  res.json(user);\n}\n`
    },
    note: "Rule requires user|currentUser|req.user|session.user to be followed immediately by whitespace then , or ). Negative's console.log(user.id, ...) has \".\" right after \"user\", which is not in the [,)] class, so it does not match, even though \"user\" is the first token logged."
  },
  {
    ruleId: "DLP_EMAIL_IN_LOGS",
    check: "dlp",
    positive: {
      file: "src/services/notification-service.ts",
      content: `export function notifySignup(email) {\n  console.log("New signup:", "jane.doe@example.com");\n}\n`
    },
    negative: {
      file: "src/services/notification-service.ts",
      content: `export function notifySignup(email) {\n  console.log("New signup:", hashEmail(email));\n}\n`
    },
    note: "Negative logs the return value of hashEmail(email) instead of a literal address; no local-part@domain.tld pattern appears in source."
  },
  {
    ruleId: "DLP_STACK_TRACE_IN_RESPONSE",
    check: "dlp",
    positive: {
      file: "src/routes/error-handler.ts",
      content: `export function errorHandler(err, req, res, next) {\n  res.json({ error: err.message, stack: err.stack });\n}\n`
    },
    negative: {
      file: "src/routes/error-handler.ts",
      content: `export function errorHandler(err, req, res, next) {\n  const errorId = logInternalError(err);\n  res.json({ error: "Internal server error", correlationId: errorId });\n}\n`
    },
    note: "Negative's res.json({...}) object contains neither \"stack\" nor \"stackTrace\" nor \"error.stack\"; the error is logged internally with a correlation ID instead, matching the rule's own requiredActions."
  },
  {
    ruleId: "DLP_PHI_IN_LOGS",
    check: "dlp",
    positive: {
      file: "src/services/patient-service.ts",
      content: `export function recordVisit(patient, diagnosis) {\n  logger.info("Patient diagnosis:", diagnosis);\n}\n`
    },
    negative: {
      file: "src/services/patient-service.ts",
      content: `export function recordVisit(patientRef, encounterId) {\n  logger.info("Patient encounter processed", { patientRef, encounterId });\n}\n`
    },
    note: "Rule matches bare \"diagnosis\" or patient followed by Name/Id/_id/Record. Negative logs \"patientRef\"/\"encounterId\" (Ref is not one of the required suffixes) and \"Patient encounter\" (space+\"encounter\" fails the Name|Id|_id|Record alternation) — an opaque reference, not PHI."
  },
  {
    ruleId: "DLP_BIOMETRIC_IN_LOGS",
    check: "dlp",
    positive: {
      file: "src/services/biometric-auth.ts",
      content: `export function verifyUser(fingerprintHash) {\n  console.log("Verifying user", "fingerprintHash:", fingerprintHash);\n}\n`
    },
    negative: {
      file: "src/services/biometric-auth.ts",
      content: `export function verifyUser(matchResult) {\n  console.log("Identity verification outcome:", matchResult ? "match" : "no-match");\n}\n`
    },
    note: "Negative logs only the boolean match outcome and avoids every keyword in the alternation (fingerprint, faceId, iris, retina, voiceprint, biometric, palmPrint) — \"Identity\" does not contain \"iris\" as a substring, so nothing fires."
  },
  {
    ruleId: "DLP_OAUTH_TOKEN_IN_LOGS",
    check: "dlp",
    positive: {
      file: "src/auth/oauth-callback.ts",
      content: `export function handleOAuthCallback(accessToken) {\n  console.log("Issued token for user:", accessToken);\n}\n`
    },
    negative: {
      file: "src/auth/oauth-callback.ts",
      content: `export function handleOAuthCallback(session) {\n  const tokenRef = hashToken(session.accessToken);\n  console.log("Session established, token ref:", tokenRef);\n}\n`
    },
    note: "The raw accessToken is only referenced on a line with no console/logger call (hashToken assignment). The console.log line logs \"tokenRef\" — bare \"token\" without an access_/refresh_/id_ prefix, which the rule does not match — so the actual token value never appears next to a log call."
  },
  {
    ruleId: "DLP_PASSPORT_IN_LOGS",
    check: "dlp",
    positive: {
      file: "src/services/kyc-service.ts",
      content: `export function verifyIdentity(passportNumber) {\n  console.log("Passport:", passportNumber);\n}\n`
    },
    negative: {
      file: "src/services/kyc-service.ts",
      content: `export function verifyIdentity(passportNumber) {\n  const maskedId = maskPassport(passportNumber);\n  console.log("Passport on file (masked):", maskedId);\n}\n`
    },
    note: "The raw passportNumber is only passed to maskPassport() on a non-log line. The console.log line contains \"Passport on file\" — \"Passport\" is followed by \" on\" (space+letter), which fails the required trailing \\s*[:=,)], so it does not match, matching the rule's masking remediation."
  },
  {
    ruleId: "DLP_DRIVERS_LICENSE_IN_LOGS",
    check: "dlp",
    positive: {
      file: "src/services/dmv-verification.ts",
      content: `export function verifyLicense(licenseNumber) {\n  console.log("License:", licenseNumber);\n}\n`
    },
    negative: {
      file: "src/services/dmv-verification.ts",
      content: `export function verifyLicense(licenseNumber) {\n  const maskedId = maskLicense(licenseNumber);\n  console.log("Driver license on file (masked):", maskedId);\n}\n`
    },
    note: "Same anchoring logic as the passport case: \"Driver license\" matches the driver's-license phrase alternative, but is followed by \" on\" rather than one of :=,) so the trailing requirement fails; the raw number itself is masked before logging."
  },
  {
    ruleId: "DLP_DB_BACKUP_WEB_EXPOSED",
    check: "dlp",
    positive: {
      file: "src/server.ts",
      content: `import express from "express";\nconst app = express();\napp.use(express.static("public"));\nconst backupFile = "public/backups/production-2024.sql";\napp.get("/download-backup", (req, res) => {\n  res.download(backupFile);\n});\n`
    },
    negative: {
      file: "src/server.ts",
      content: `import express from "express";\nconst app = express();\napp.use(express.static("public"));\nconst backupFile = path.join(process.env.BACKUP_DIR, "production-2024.sql");\napp.get("/download-backup", requireAdmin, (req, res) => {\n  res.download(backupFile);\n});\n`
    },
    note: "Negative resolves the backup path from an env-configured directory outside the web root; the literal string is just \"production-2024.sql\" with no public/www/static/... prefix on the same line, so the path-based alternative never matches."
  },
  {
    ruleId: "DLP_UNENCRYPTED_DATA_EXPORT",
    check: "dlp",
    positive: {
      file: "src/routes/export.ts",
      content: `app.get("/export/csv", requireAuth, (req, res) => {\n  res.download("/tmp/exports/customer-data.csv");\n});\n`
    },
    negative: {
      file: "src/routes/export.ts",
      content: `app.get("/export", requireAuth, async (req, res) => {\n  const signedUrl = await generateSignedExportUrl(req.user.id);\n  res.redirect(signedUrl);\n});\n`
    },
    note: "Negative never calls res.download/res.sendFile with a .csv/.json path, never writes an export file directly, and never fetches a plaintext http:// export URL — it redirects to a short-lived signed URL instead, per the rule's own requiredActions."
  },
  {
    ruleId: "DLP_URL_WITH_TOKEN_LOGGED",
    check: "dlp",
    positive: {
      file: "src/middleware/error-logger.ts",
      content: `export function logError(err, req) {\n  console.error("Request failed:", req.originalUrl);\n}\n`
    },
    negative: {
      file: "src/middleware/error-logger.ts",
      content: `export function logError(err, req) {\n  console.error("Request failed for route:", req.route.path);\n}\n`
    },
    note: "Negative logs req.route.path (the route template) instead of req.originalUrl/req.url/req.query, so no query string or token-bearing URL is ever logged."
  },
  {
    ruleId: "DLP_PII_IN_CACHE_KEY",
    check: "dlp",
    positive: {
      file: "src/cache/session-cache.ts",
      content: `export function cacheSession(userEmail, sessionData) {\n  cache.set("email:" + userEmail, sessionData);\n}\n`
    },
    negative: {
      file: "src/cache/session-cache.ts",
      content: `export function cacheSession(userEmail, sessionData) {\n  const cacheKey = "user:" + sha256(userEmail);\n  cache.set(cacheKey, sessionData);\n}\n`
    },
    note: "Rule requires a quote/backtick to appear immediately after cache.set(. Negative passes a pre-built variable (cacheKey) into cache.set(cacheKey, ...) — the character right after the opening paren is \"c\", not a quote — so the rule never fires, even though the literal string containing \"email\" exists earlier on a non-cache.set line."
  },
  {
    ruleId: "DLP_SERVER_HEADER_DISCLOSURE",
    check: "dlp",
    positive: {
      file: "src/server.ts",
      content: `import express from "express";\nconst app = express();\napp.use((req, res, next) => {\n  res.setHeader("X-Powered-By", "Express");\n  next();\n});\n`
    },
    negative: {
      file: "src/server.ts",
      content: `import express from "express";\nconst app = express();\napp.disable("x-powered-by");\napp.listen(3000);\n`
    },
    note: "The rule only fires when an X-Powered-By/Server-header reference is found AND no app.disable('x-powered-by') call exists anywhere in the repo. Negative's app.disable(\"x-powered-by\") line matches both the disable-check query and the disclosure query itself, so disableHits is non-empty and the finding is suppressed."
  },
  {
    ruleId: "DLP_SERVER_HEADER_DISCLOSURE",
    check: "dlp",
    positive: {
      file: "src/server.ts",
      content: `import express from "express";\n\nconst app = express();\napp.get("/", (req, res) => res.send("ok"));\napp.listen(3000);\n`
    },
    negative: {
      file: "src/server.ts",
      content: `import express from "express";\nimport helmet from "helmet";\n\nconst app = express();\napp.use(helmet());\napp.get("/", (req, res) => res.send("ok"));\napp.listen(3000);\n`
    },
    note: "Express sets X-Powered-By itself unless told not to, so the positive discloses it without any line saying so. The negative uses helmet, which removes the header — previously only app.disable('x-powered-by') counted as a mitigation, so every helmet-using Express app was flagged."
  },
  {
    ruleId: "DLP_SERVER_HEADER_DISCLOSURE",
    check: "dlp",
    positive: {
      file: "src/http/headers.ts",
      content: `export function applyHeaders(res) {\n  res.setHeader("X-Powered-By", "Express 4.18.2");\n}\n`
    },
    negative: {
      file: "src/http/headers.ts",
      content: `export function applyHeaders(res) {\n  res.removeHeader("X-Powered-By");\n}\n`
    },
    note: "Both lines name the header in a header call; only the positive sets it. The rule used to match the bare string anywhere, so any mention — including a checklist line saying the header should be suppressed — counted as disclosure."
  }
];
