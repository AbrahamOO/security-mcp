/**
 * Business logic security checks — catches IDOR, mass assignment, race conditions,
 * and other logic-layer vulnerabilities that injection and auth scanners miss.
 * CWE references per MITRE CWE catalog; ATT&CK techniques per MITRE ATT&CK v15.
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

async function checkMassAssignment(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:Object\.assign|spread)\s*\(\s*(?:user|account|profile|model|record|entity|document)\s*,\s*(?:req\.body|body\b)|(?:new\s+\w+\s*\(|create\s*\(|update\s*\()\s*(?:req\.body|body\b|\.\.\.\s*body\b)`
  );
  const safeRe = /pick\s*\(|omit\s*\(|z\.|schema\.parse|validate\s*\(|allowedFields|whitelist/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "MASS_ASSIGNMENT",
    title: "Mass assignment — req.body spread directly into database model without field allowlist (CWE-915)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Explicitly pick allowed fields from req.body before passing to the model.",
      "CWE-915 — mass assignment allows attackers to set internal fields like isAdmin, role, or balance by including them in the request body.",
      "Fix: const { name, email } = req.body; await User.update({ name, email }, { where: { id: userId } });"
    ]
  };
}

async function checkIdorDirect(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:findById|findOne|findByPk|findUnique|getById|where\s*:\s*\{\s*id)\s*\(\s*(?:req\.|params\.|query\.|body\.)(?:id|userId|accountId|recordId|documentId|resourceId)\b`
  );
  const safeRe = /userId\s*===|\.userId\s*==|currentUser|req\.user\.|session\.userId|ownership|authorized|canAccess|hasPermission/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "IDOR_DIRECT_ACCESS",
    title: "Direct object lookup from user-supplied ID without ownership check — IDOR (CWE-639 / OWASP API1)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Always verify that the authenticated user owns or has permission to access the requested resource.",
      "CWE-639 — IDOR allows any authenticated user to access any other user's data by changing the ID in the request.",
      "Fix: const record = await Model.findById(req.params.id); if (record.userId !== req.user.id) return res.status(403).end();"
    ]
  };
}

async function checkNegativeAmountBypass(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:amount|price|quantity|balance|credit|debit|total|cost)\s*[+\-]=\s*(?:req\.|body\.|params\.|query\.)\w+|(?:req\.|body\.|params\.)(?:amount|price|quantity|total)\b[^;]*(?:balance|transfer|charge|debit|credit)`
  );
  const safeReA = />\s*0|>=\s*0\b|Math\.abs|isPositive|validate/;
  const safeReB = /minimum\s*:\s*0|positive\(\)|min\s*\(\s*0/;
  const unsafe = hits.filter((h) => !safeReA.test(h.preview) && !safeReB.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "NEGATIVE_AMOUNT_BYPASS",
    title: "Financial amount from user input not validated as positive — business logic bypass (CWE-20)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Validate that financial amounts are strictly positive before processing any transaction.",
      "CWE-20 — negative amounts can credit accounts, refund without a purchase, or subtract from balances in reverse.",
      "Fix: const amount = z.number().positive().parse(req.body.amount); // reject <= 0"
    ]
  };
}

async function checkRaceConditionBalance(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:findOne|findById|findUnique)[^;]*(?:balance|quota|inventory|stock|seats|credits)[^;]*(?:update|save|increment|decrement)`
  );
  const safeRe = /transaction|atomic|$inc|increment.*atomic|select.*for\s+update|WITH\s+LOCK|optimisticLock|version/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "RACE_CONDITION_BALANCE",
    title: "Read-then-write on balance/quota without atomic operation — TOCTOU race condition (CWE-362)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Use atomic database operations (SQL FOR UPDATE, MongoDB $inc, Prisma transactions) to prevent race conditions.",
      "CWE-362 — concurrent requests reading the same balance and both decrementing can overdraft accounts or oversell inventory.",
      "Fix: await db.$transaction([db.account.update({ where: { id }, data: { balance: { decrement: amount } } })]);"
    ]
  };
}

async function checkHardcodedCredentials(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:password|passwd|secret|apiKey|api_key|token|credential|auth)\s*[:=]\s*['"][^'"]{8,}['"](?!\s*\+|\s*process\.env)`
  );
  const safeRe = /process\.env|config\.|getSecret|secretsManager|vault|PLACEHOLDER|CHANGE_ME|YOUR_SECRET|example|test/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "HARDCODED_CREDENTIALS",
    title: "Hardcoded credential literal in source code — secret exposed in git history (CWE-798)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Move all secrets to environment variables or a secrets manager. Rotate any exposed credentials immediately.",
      "CWE-798 / ATT&CK T1552.001 — hardcoded credentials are extractable from git history even after removal.",
      "Fix: const secret = process.env.MY_SECRET; // never: const secret = 'hardcoded-value';"
    ]
  };
}

async function checkMissingInputValidation(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:router|app)\.(?:post|put|patch)\s*\([^,]+,\s*\([^)]*req[^)]*\)\s*=>\s*\{[^}]*(?:req\.body|body\.)\w+[^}]*(?:await|db\.|model\.|\.create|\.update|\.save)`
  );
  const safeRe = /parse\s*\(|validate\s*\(|schema\.|Joi\.|Zod|yup\.|valibot|ajv|body\s*\(|check\s*\(/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "MISSING_INPUT_VALIDATION",
    title: "POST/PUT/PATCH handler writes req.body to database without schema validation (CWE-20)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Validate all request bodies with a schema library (Zod, Joi, Valibot) before writing to the database.",
      "CWE-20 — missing validation allows type confusion, unexpected field types, and business logic bypasses.",
      "Fix: const data = CreateUserSchema.parse(req.body); await db.user.create({ data });"
    ]
  };
}

async function checkInsecureDirectUrlAccess(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:router|app)\.(?:get|post|put|patch|delete)\s*\(\s*['"][^'"]*(?:\/export|\/download|\/report|\/backup|\/dump|\/list-all|\/all-users|\/admin-data)['"]\s*,(?![^)]*(?:requireAuth|isAuthenticated|passport|authenticate|verifyToken|checkAuth|session\.user))`
  );
  if (!hits.length) return null;
  return {
    id: "UNRESTRICTED_SENSITIVE_ENDPOINT",
    title: "Sensitive data endpoint (export/download/backup) registered without authentication middleware (CWE-284)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Apply authentication and authorization middleware to all data export, download, and backup endpoints.",
      "CWE-284 — unauthenticated export endpoints allow any internet user to download entire user databases.",
      "Fix: router.get('/export', requireAuth, requireRole('admin'), exportHandler);"
    ]
  };
}

async function checkIntegerOverflow(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:parseInt|parseFloat|Number\s*\()\s*\(\s*(?:req\.|body\.|params\.|query\.)\w+\s*\)[^;]*(?:\*|\+\+|\+=|\*=|Math\.pow|<<)`
  );
  const safeRe = /isNaN|isFinite|Number\.isInteger|Number\.isSafeInteger|MAX_SAFE_INTEGER|clamp|Math\.min.*Math\.max/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "INTEGER_OVERFLOW_RISK",
    title: "Parsed integer from user input used in arithmetic without bounds check — overflow risk (CWE-190)",
    severity: "MEDIUM",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Validate that parsed integers are within safe bounds before using them in arithmetic.",
      "CWE-190 — extremely large values can cause incorrect calculations, memory allocation failures, or logic bypasses.",
      "Fix: const qty = z.number().int().min(1).max(10000).parse(Number(req.body.quantity));"
    ]
  };
}

async function checkMissingAdminAuth(): Promise<Finding | null> {
  // Matches route definitions whose path contains /admin, /internal, /debug, or /_/
  // and whose immediate handler argument does not include an auth middleware reference.
  const hits = await codeSearch(
    String.raw`(?:router|app)\.(?:get|post|put|patch|delete|use)\s*\(\s*['"][^'"]*(?:\/admin|\/internal|\/debug|\/_\/)[^'"]*['"]`
  );
  const authRe = /requireAuth|isAuthenticated|authenticate|verifyToken|checkAuth|passport\.authenticate|session\.user|authMiddleware|ensureAuth|protect|authGuard|bearerAuth|jwtVerify/;
  const unsafe = hits.filter((h) => !authRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "MISSING_ADMIN_ROUTE_AUTH",
    title: "Admin/internal/debug route registered without authentication middleware — missing authorization (CWE-862)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Apply authentication and role-enforcement middleware to every /admin, /internal, /debug, and /_/ route.",
      "CWE-862 / ATT&CK T1078 — unauthenticated admin endpoints expose privileged operations to any internet user.",
      "Fix: router.use('/admin', requireAuth, requireRole('admin')); // applied before any sub-routes"
    ]
  };
}

async function checkTimingOracle(): Promise<Finding | null> {
  // Detects equality comparisons (=== or ==) applied directly to OTP, PIN, token,
  // or API-key values without a constant-time comparison helper.
  const hits = await codeSearch(
    String.raw`(?:otp|pin|token|apiKey|api_key|secret|code|passcode|verificationCode|resetToken|authCode)\s*(?:===|==)\s*(?:req\.|body\.|params\.|query\.|user\.|stored|expected|db\.)|(?:req\.|body\.|params\.)(?:otp|pin|token|code|passcode)\s*(?:===|==)`
  );
  const safeRe = /timingSafeEqual|crypto\.timingSafeEqual|constantTimeCompare|safeCompare|timingAttack|tsscmp|slow-equal/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "TIMING_ORACLE_COMPARISON",
    title: "Security code (OTP/PIN/API key) compared with === — timing oracle leaks secret length/value (CWE-208)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Use crypto.timingSafeEqual() for all equality checks involving OTPs, PINs, API keys, and session tokens.",
      "CWE-208 / ATT&CK T1110 — string equality short-circuits on the first mismatch; timing differences allow offline brute-force recovery.",
      "Fix: const a = Buffer.from(storedToken); const b = Buffer.from(userToken); if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('Invalid token');"
    ]
  };
}

async function checkHardcodedDbUrlPassword(): Promise<Finding | null> {
  // Catches database connection URLs with embedded credentials and API key literals inside config objects.
  const hitsA = await codeSearch(
    String.raw`(?:mongodb|mongodb\+srv|postgresql|postgres|mysql|redis|amqp|jdbc):\/\/[^:'"]+:[^@'"]{4,}@`
  );
  const hitsB = await codeSearch(
    String.raw`(?:DATABASE_URL|MONGO_URI|DB_PASSWORD|REDIS_URL|RABBITMQ_URL)\s*[:=]\s*['"][^'"]{8,}['"](?!\s*\+|\s*process\.env)`
  );
  const hitsC = await codeSearch(
    String.raw`(?:api_key|access_key|secret_key|client_secret|apiKey)\s*[:=]\s*['"][A-Za-z0-9\-_]{16,}['"]`
  );
  const hits = [...hitsA, ...hitsB, ...hitsC];
  const safeRe = /process\.env|config\.|getSecret|secretsManager|vault|PLACEHOLDER|CHANGE_ME|example|test|localhost|127\.0\.0\.1/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "HARDCODED_DB_URL_OR_API_KEY",
    title: "Database URL with embedded password or API key literal in config object — credential exposure (CWE-798)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Remove all database URLs with embedded passwords and API key literals from source code. Rotate any exposed credentials immediately.",
      "CWE-798 / ATT&CK T1552.001 — credentials in config files are captured in git history even after deletion and are frequently scraped by automated tools.",
      "Fix: const dbUrl = process.env.DATABASE_URL; // store in .env, inject via secrets manager at runtime"
    ]
  };
}

export async function checkBusinessLogic(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  try {
    const results = await Promise.all([
      checkMassAssignment(),
      checkIdorDirect(),
      checkNegativeAmountBypass(),
      checkRaceConditionBalance(),
      checkHardcodedCredentials(),
      checkHardcodedDbUrlPassword(),
      checkMissingInputValidation(),
      checkInsecureDirectUrlAccess(),
      checkIntegerOverflow(),
      checkMissingAdminAuth(),
      checkTimingOracle(),
    ]);
    return results.filter((f): f is Finding => f !== null);
  } catch (err) {
    console.warn("[checkBusinessLogic] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    return [];
  }
}
