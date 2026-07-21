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

async function checkIdorDirect(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Original single-line IDOR check
  const hits = await codeSearch(
    String.raw`(?:findById|findOne|findByPk|findUnique|getById|where\s*:\s*\{\s*id)\s*\(\s*(?:req\.|params\.|query\.|body\.)(?:id|userId|accountId|recordId|documentId|resourceId)\b`
  );
  // req\.user\?? covers both req.user.id and req.user?.id (optional chaining ownership pattern)
  const safeRe = /userId\s*===|\.userId\s*==|currentUser|req\.user\??\.id|session\.userId|ownership|authorized|canAccess|hasPermission/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (unsafe.length > 0) {
    findings.push({
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
    });
  }

  // Two-pass multi-line IDOR: find user-supplied ID, then check if DB lookup uses it without ownership
  const idSourceHits = await codeSearch(
    String.raw`(?:req\.params\.\w+|req\.query\.\w+|args\.\w+)`
  );
  const dbLookupHits = await codeSearch(
    String.raw`(?:findById|findOne|findByPk|findUnique|findFirst|getById)\s*\(`
  );

  const idsByFile = new Map<string, Array<{ line: number; varName: string; preview: string }>>();
  for (const h of idSourceHits) {
    const varMatch = /(?:const|let|var)\s+(\w+)\s*=/.exec(h.preview);
    const varName = varMatch?.[1] ?? "";
    if (!idsByFile.has(h.file)) idsByFile.set(h.file, []);
    idsByFile.get(h.file)!.push({ line: h.line, varName, preview: h.preview });
  }

  const toctouIdorHits: Array<{ file: string; line: number; preview: string }> = [];
  for (const db of dbLookupHits) {
    if (safeRe.test(db.preview)) continue;
    const idSources = idsByFile.get(db.file) ?? [];
    for (const src of idSources) {
      const lineDiff = db.line - src.line;
      if (lineDiff >= 0 && lineDiff <= 15 && src.varName && db.preview.includes(src.varName)) {
        toctouIdorHits.push({ file: db.file, line: db.line, preview: `id@${src.line}→lookup@${db.line}: ${db.preview.trim()}` });
        break;
      }
    }
  }

  // GraphQL resolver IDOR: resolve functions using args.id without context.user.id check
  const resolverHits = await codeSearch(
    String.raw`resolve\s*:\s*(?:async\s)?\([^)]*\)\s*=>\s*\{`
  );
  const resolverIdorHits = resolverHits.filter((h) => {
    return /args\.\w+/.test(h.preview) && !safeRe.test(h.preview) && !/context\.user\.id/.test(h.preview);
  });

  // Prisma findFirst without userId in where clause
  const prismaHits = await codeSearch(
    String.raw`\.findFirst\s*\(\s*\{[^}]*where\s*:\s*\{[^}]*id\s*:`
  );
  const prismaIdorHits = prismaHits.filter((h) => !/userId\s*:/.test(h.preview));

  const multiLineIdorHits = [...toctouIdorHits, ...resolverIdorHits, ...prismaIdorHits];
  if (multiLineIdorHits.length > 0) {
    findings.push({
      id: "IDOR_MULTI_LINE",
      title: "User-supplied ID reaches DB lookup without ownership check across multiple lines — IDOR (CWE-639)",
      severity: "HIGH",
      evidence: multiLineIdorHits.slice(0, 10).map((h) => `${h.file}:${h.line}:${h.preview}`),
      files: [...new Set(multiLineIdorHits.slice(0, 10).map((h) => h.file))],
      requiredActions: [
        "Verify ownership before returning any record fetched by a user-supplied ID.",
        "CWE-639 — multi-line IDOR occurs when the ID is extracted early, then used in a DB call several lines later without an intermediate ownership check.",
        "Fix: add userId to the where clause (Prisma: { where: { id: args.id, userId: ctx.user.id } }) or check after fetch."
      ]
    });
  }

  return findings;
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

async function checkRaceConditionBalance(): Promise<Finding[]> {
  const findings: Finding[] = [];
  const safeRe = /transaction|atomic|\$inc|increment.*atomic|select.*for\s+update|WITH\s+LOCK|optimisticLock|version/i;

  // Single-line check (original)
  const singleLineHits = await codeSearch(
    String.raw`(?:findOne|findById|findUnique)[^;]*(?:balance|quota|inventory|stock|seats|credits)[^;]*(?:update|save|increment|decrement)`
  );
  const unsafeSingle = singleLineHits.filter((h) => !safeRe.test(h.preview));
  if (unsafeSingle.length > 0) {
    findings.push({
      id: "RACE_CONDITION_BALANCE",
      title: "Read-then-write on balance/quota without atomic operation — TOCTOU race condition (CWE-362)",
      severity: "HIGH",
      evidence: toEvidence(unsafeSingle),
      files: toFiles(unsafeSingle),
      requiredActions: [
        "Use atomic database operations (SQL FOR UPDATE, MongoDB $inc, Prisma transactions) to prevent race conditions.",
        "CWE-362 — concurrent requests reading the same balance and both decrementing can overdraft accounts or oversell inventory.",
        "Fix: await db.$transaction([db.account.update({ where: { id }, data: { balance: { decrement: amount } } })]);"
      ]
    });
  }

  // Two-pass multi-line TOCTOU: find read operations, capture variable, find writes near them
  const readHits = await codeSearch(
    String.raw`(?:findOne|findById|findUnique|getBalance|getAccount|fs\.access|fs\.stat|fs\.exists)\s*\(`
  );
  const writeHits = await codeSearch(
    String.raw`(?:\.update\s*\(|\.save\s*\(|\.increment\s*\(|\.decrement\s*\(|fs\.unlink\s*\(|fs\.write\s*\(|fs\.rename\s*\()`
  );

  const readByFile = new Map<string, Array<{ line: number; varName: string; preview: string }>>();
  for (const rh of readHits) {
    if (safeRe.test(rh.preview)) continue;
    const varMatch = /(?:const|let|var)\s+(\w+)\s*=/.exec(rh.preview);
    const varName = varMatch?.[1] ?? "";
    if (!readByFile.has(rh.file)) readByFile.set(rh.file, []);
    readByFile.get(rh.file)!.push({ line: rh.line, varName, preview: rh.preview });
  }

  const toctouHits: Array<{ file: string; line: number; preview: string }> = [];
  for (const wh of writeHits) {
    if (safeRe.test(wh.preview)) continue;
    const reads = readByFile.get(wh.file) ?? [];
    for (const r of reads) {
      const lineDiff = wh.line - r.line;
      if (lineDiff > 0 && lineDiff <= 15 && r.varName && wh.preview.includes(r.varName)) {
        toctouHits.push({ file: wh.file, line: wh.line, preview: `read@${r.line}→write@${wh.line}: ${wh.preview.trim()}` });
        break;
      }
    }
  }

  if (toctouHits.length > 0) {
    findings.push({
      id: "RACE_CONDITION_TOCTOU",
      title: "Multi-line read-then-write without SELECT FOR UPDATE, transaction, or mutex — TOCTOU race condition (CWE-362)",
      severity: "HIGH",
      evidence: toctouHits.slice(0, 10).map((h) => `${h.file}:${h.line}:${h.preview}`),
      files: [...new Set(toctouHits.slice(0, 10).map((h) => h.file))],
      requiredActions: [
        "Wrap read-then-write sequences in a database transaction with SELECT FOR UPDATE to prevent concurrent modification.",
        "CWE-362 — TOCTOU allows two concurrent requests to read the same state and both apply writes based on stale data.",
        "Fix: await db.$transaction(async (tx) => { const r = await tx.account.findUnique(...); await tx.account.update(...); });"
      ]
    });
  }

  // File system TOCTOU: fs.access/stat followed by fs.unlink/open/write within 10 lines without locking
  const fsReadHits = await codeSearch(
    String.raw`fs\.(?:access|stat|exists)\s*\(`
  );
  const fsWriteHits = await codeSearch(
    String.raw`fs\.(?:unlink|open|rename|writeFile|writeFileSync)\s*\(`
  );

  const fsReadByFile = new Map<string, Array<{ line: number; preview: string }>>();
  for (const rh of fsReadHits) {
    if (!fsReadByFile.has(rh.file)) fsReadByFile.set(rh.file, []);
    fsReadByFile.get(rh.file)!.push({ line: rh.line, preview: rh.preview });
  }

  const fsLockRe = /flock|lockFile|lock\s*\(|exclusive/i;
  const fsToctouHits: Array<{ file: string; line: number; preview: string }> = [];
  for (const wh of fsWriteHits) {
    if (fsLockRe.test(wh.preview)) continue;
    const reads = fsReadByFile.get(wh.file) ?? [];
    for (const r of reads) {
      const lineDiff = wh.line - r.line;
      if (lineDiff > 0 && lineDiff <= 10) {
        fsToctouHits.push({ file: wh.file, line: wh.line, preview: `fs.check@${r.line}→fs.write@${wh.line}: ${wh.preview.trim()}` });
        break;
      }
    }
  }

  if (fsToctouHits.length > 0) {
    findings.push({
      id: "FILESYSTEM_TOCTOU",
      title: "fs.access/fs.stat followed by fs.write/fs.unlink without file locking — filesystem TOCTOU (CWE-362)",
      severity: "HIGH",
      evidence: fsToctouHits.slice(0, 10).map((h) => `${h.file}:${h.line}:${h.preview}`),
      files: [...new Set(fsToctouHits.slice(0, 10).map((h) => h.file))],
      requiredActions: [
        "Use atomic file operations (open with O_EXCL flag, or a file-locking library) instead of check-then-act patterns.",
        "CWE-362 — between fs.access() and fs.unlink/fs.write, another process can modify or replace the file.",
        "Fix: use fs.open(path, 'wx') which atomically creates-or-fails, or proper advisory locking via proper-lockfile."
      ]
    });
  }

  return findings;
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

async function checkFloatMonetaryArithmetic(): Promise<Finding | null> {
  const hitsA = await codeSearch(
    String.raw`(?:price|amount|total|balance|cost|fee|charge)\s*\*\s*(?:\d+\.\d+|[^;]*(?:rate|percent|factor))`
  );
  const hitsB = await codeSearch(
    String.raw`parseFloat\s*\([^)]*(?:price|amount|total|balance|cost|fee)`
  );
  // Unary + coercion: +req.body.price, +req.query.amount — same float risk as parseFloat()
  const hitsD = await codeSearch(
    String.raw`(?<![+\w])\+\s*req\.(?:body|query|params)\.\w*(?:price|amount|total|balance|cost|fee)\w*`
  );
  const hitsC = await codeSearch(
    String.raw`\.toFixed\s*\(\s*[02]\s*\)`
  );
  const hits = [...hitsA, ...hitsB, ...hitsC, ...hitsD];
  const safeRe = /BigInt|bigint|Decimal|decimal\.js|dinero|bignumber|integer.*cent|cent.*integer|\*\s*100|Math\.round.*100/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "MONETARY_FLOAT_ARITHMETIC",
    title: "Floating-point arithmetic on monetary values — rounding errors in financial calculations (CWE-681)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Floating-point arithmetic on monetary values can cause rounding errors. Use integer-cent representation (multiply by 100, work in integers, divide at display time) or a decimal library.",
      "CWE-681 — float imprecision can cause under- or over-charging by fractional amounts that accumulate at scale.",
      "Fix: const amountCents = Math.round(price * 100); // work in integers, or use: import Decimal from 'decimal.js'; new Decimal(price).times(rate)"
    ]
  };
}

async function checkHttpParamPollution(): Promise<Finding | null> {
  const hitsA = await codeSearch(
    String.raw`(?:parseInt|parseFloat|Number)\s*\(\s*req\.(?:query|body)\.\w+`
  );
  const hitsB = await codeSearch(
    String.raw`if\s*\(\s*req\.(?:query|body)\.\w+\s*(?:===|!==|>|<|>=|<=)`
  );
  const hits = [...hitsA, ...hitsB];
  const safeRe = /Array\.isArray|isArray\s*\(|typeof.*string|schema\.parse|validate\s*\(/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "HTTP_PARAM_POLLUTION_RISK",
    title: "Request parameter used in arithmetic/comparison without Array.isArray guard — HTTP parameter pollution (CWE-20)",
    severity: "MEDIUM",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Request parameters may be arrays when sent as duplicate query params (e.g., ?amount=10&amount=-500). Validate scalar vs array type before use in business logic.",
      "CWE-20 — HTTP parameter pollution allows sending duplicate params that become arrays, bypassing single-value validations.",
      "Fix: const raw = req.query.amount; if (Array.isArray(raw)) return res.status(400).end(); const amount = Number(raw);"
    ]
  };
}

async function checkVoucherReplay(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:coupon|voucher|promo|gift.*card|redeem|discount.*code)`
  );
  // Require the idempotency signal to be a READ/CHECK, not just an assignment.
  // "voucher.usedAt = new Date()" set in-memory before persistence does NOT prevent replay —
  // two concurrent requests both read usedAt=null, both pass the check, then both write.
  // Safe patterns: conditional checks (if/throw/return on usedAt), DB-level unique constraints,
  // or idempotency key lookups. Pure assignment lines are excluded via negative lookahead.
  const idempotencyRe = /(?:if|throw|return|where|find|unique|create).*(?:usedAt|redeemed|usageCount|redemptionCount|idempotencyKey)|(?:usedAt|redeemed).*(?:===|!==|==|!=|throw|return)|unique.*code|code.*unique/i;
  const unsafe = hits.filter((h) => !idempotencyRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "VOUCHER_REPLAY_RISK",
    title: "Voucher/coupon redemption without idempotency check — replay attack enables unlimited reuse (CWE-384)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Voucher/coupon redemption without idempotency check enables replay. Track redemptions with a unique constraint on code+userId.",
      "CWE-384 — a replayable redemption endpoint allows a single coupon to be used unlimited times.",
      "Fix: await db.redemption.create({ data: { code, userId } }); // with UNIQUE(code, userId) constraint to reject duplicates"
    ]
  };
}

async function checkStateMachineBypass(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:\/checkout\/confirm|\/checkout\/payment|\/verify\/complete|\/onboarding\/step\d|\/wizard\/step)`
  );
  const prerequisiteRe = /req\.session\.\w+|req\.user\.\w+|await.*[Ss]tep.*[Cc]omplete|await.*verified|session\[|user\.step|completed/;
  const unsafe = hits.filter((h) => !prerequisiteRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "STATE_MACHINE_BYPASS_RISK",
    title: "Multi-step flow endpoint does not verify prior-step completion — state machine bypass (CWE-841)",
    severity: "MEDIUM",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Each step in a multi-step flow (checkout, onboarding, wizard) must verify that preceding steps were completed.",
      "CWE-841 — skipping steps can bypass payment, identity verification, or terms acceptance.",
      "Fix: if (!req.session.step1Complete) return res.status(400).json({ error: 'Complete step 1 first' });"
    ]
  };
}

async function checkCurrencyConfusion(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:currency|currencyCode|currency_code)\s*[:=]\s*(?:req\.|body\.|params\.|query\.)`
  );
  const safeRe = /allowedCurrencies|CURRENCY_ALLOWLIST|===.*'USD'/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_CURRENCY_CONFUSION",
    title: "Payment currency sourced from client request — currency confusion enables 100 JPY instead of 100 USD payment (CWE-20)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Never accept currency codes from client requests. Hard-code or allowlist acceptable currencies server-side.",
      "CWE-20 — currency confusion allows an attacker to specify a low-value currency (JPY, CLP) to pay a fraction of the intended amount.",
      "Fix: const currency = CURRENCY_ALLOWLIST.includes(req.body.currency) ? req.body.currency : 'USD';"
    ]
  };
}

async function checkDiscountStacking(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:discount|coupon|promo)(?:s|List|Stack|Array|\[)`
  );
  const safeRe = /maxDiscounts|MAX_COUPONS|singleDiscount|onlyOne/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_DISCOUNT_STACKING",
    title: "Discount/coupon list without stacking limit — attacker applies N codes to reduce price to zero (CWE-20)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Enforce a maximum number of stackable discounts/coupons per order server-side.",
      "CWE-20 — unlimited coupon stacking allows an attacker to chain enough codes to reduce any order total to zero.",
      "Fix: if (coupons.length > MAX_COUPONS) throw new Error('Too many coupons applied');"
    ]
  };
}

async function checkOrderFulfillmentBypass(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:status|paymentStatus|orderStatus|fulfillmentStatus)\s*[:=]\s*(?:req\.|body\.|params\.|query\.)`
  );
  const safeRe = /processor|stripe|braintree|paypal|PAYMENT_PROCESSOR/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_ORDER_FULFILLMENT_BYPASS",
    title: "Order status sourced from client — attacker sets status=paid to bypass payment processor confirmation (CWE-602)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Order and payment status must be set exclusively by your payment processor webhook or server-side logic, never from client input.",
      "CWE-602 — accepting status from the client allows any user to set their order to 'paid' without completing payment.",
      "Fix: const status = await stripe.paymentIntents.retrieve(paymentIntentId); // derive status from processor, not client"
    ]
  };
}

async function checkWebhookTimestamp(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:stripe|webhook|payment).*(?:Signature|signature|sig)\s*[:=]`
  );
  const safeRe = /tolerance|timestamp|maxAge|t=|Date\.now|\d+\s*\*\s*1000/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_WEBHOOK_NO_TIMESTAMP",
    title: "Webhook signature verified but timestamp tolerance not enforced — unlimited replay window (CWE-294)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Enforce a timestamp tolerance (e.g., 5 minutes) when verifying webhook signatures to prevent replay attacks.",
      "CWE-294 — without a replay window check, a captured webhook payload can be replayed indefinitely to re-trigger payment events.",
      "Fix: stripe.webhooks.constructEvent(body, sig, secret, 300); // 300s = 5 minute tolerance"
    ]
  };
}

async function checkTaxShippingParamTamper(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:taxAmount|tax_amount|shippingCost|shipping_cost|shippingFee)\s*[:=]\s*(?:req\.|body\.|params\.|query\.)`
  );
  if (!hits.length) return null;
  return {
    id: "BIZ_TAX_SHIPPING_TAMPER",
    title: "Tax or shipping amount sourced from client — tamper to zero bypasses fees server-side (CWE-602)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Calculate tax and shipping amounts server-side using cart contents and customer location. Never trust client-supplied fee values.",
      "CWE-602 — accepting tax/shipping from the client allows any user to set these to zero, bypassing all fees.",
      "Fix: const tax = calculateTax(cart, shippingAddress); // server-computed, not req.body.taxAmount"
    ]
  };
}

async function checkClientTotalAmount(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:charge|createPaymentIntent|capturePayment|processPayment)\s*\([^)]*(?:req\.|body\.|params\.)(?:total|amount|chargeAmount|finalAmount)`
  );
  if (!hits.length) return null;
  return {
    id: "BIZ_CLIENT_SUPPLIED_TOTAL",
    title: "Final charge amount sourced from client request — attacker sets amount=1 to pay $0.01 for any cart (CWE-602)",
    severity: "CRITICAL",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Always compute the final charge amount server-side from authoritative cart/order data. Never use a client-supplied total for payment.",
      "CWE-602 — passing a client-supplied amount directly to your payment processor allows purchasing any item for any price.",
      "Fix: const amount = await computeCartTotal(userId); await stripe.paymentIntents.create({ amount, currency: 'usd' });"
    ]
  };
}

async function checkReferralAbuse(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:referral|referrer|referralBonus|inviteCode|referral_code)\s*[:=]\s*(?:req\.|body\.|params\.|query\.)`
  );
  const safeRe = /deduplication|uniqueIP|deviceFingerprint|normalizeEmail/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_REFERRAL_ABUSE",
    title: "Referral/signup bonus without multi-account deduplication — self-referral farming possible (CWE-20)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Implement multi-account deduplication for referral bonuses using email normalization, IP velocity, and/or device fingerprinting.",
      "CWE-20 — without deduplication, a single user can create unlimited accounts and self-refer to farm referral bonuses indefinitely.",
      "Fix: const canonical = normalizeEmail(email); if (await db.user.findUnique({ where: { canonicalEmail: canonical } })) throw new Error('Duplicate account');"
    ]
  };
}

async function checkEmailNormalization(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:email|emailAddress)\s*(?:===|==|LIKE)\s*(?:req\.|body\.|params\.|query\.)`
  );
  const safeRe = /toLowerCase|normalize|replace.*@|canonicalize/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_EMAIL_NORMALIZATION",
    title: "Email uniqueness compared without normalization — u.s.e.r@gmail.com creates duplicate account (CWE-20)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Normalize email addresses (lowercase, strip dots from Gmail local-part, handle + aliases) before uniqueness checks.",
      "CWE-20 — unnormalized email comparison allows creating duplicate accounts with minor variations of the same address.",
      String.raw`Fix: const canonical = email.toLowerCase().replace(/\.(?=[^@]*@)/g, ''); // then check uniqueness on canonical form`
    ]
  };
}

async function checkFeatureFlagBypass(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:isPremium|isEnterprise|planTier|featureFlag|tier|subscription)\s*[:=]\s*(?:req\.|body\.|params\.|query\.)`
  );
  if (!hits.length) return null;
  return {
    id: "BIZ_FEATURE_FLAG_CLIENT",
    title: "Feature entitlement sourced from client — attacker sets isPremium=true to unlock paid features (CWE-602)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Derive feature entitlements exclusively from your database/subscription records, never from client-supplied request parameters.",
      "CWE-602 — accepting tier or entitlement flags from the client allows any user to self-elevate to premium/enterprise tier.",
      "Fix: const { plan } = await db.subscription.findUnique({ where: { userId: req.user.id } }); // never: req.body.isPremium"
    ]
  };
}

async function checkApiVersionBypass(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:router|app)\.[a-z]+\(['"]\/?(api\/)?v[0-9]+\/`
  );
  if (!hits.length) return null;
  const versions = new Set<string>();
  for (const h of hits) {
    const m = /v(\d+)\//.exec(h.preview);
    if (m) versions.add(m[1]);
  }
  if (versions.size < 2) return null;
  return {
    id: "BIZ_API_VERSION_BYPASS",
    title: "Multiple API versions detected — older versions may lack security controls added to current version (CWE-284)",
    severity: "HIGH",
    evidence: toEvidence(hits),
    files: toFiles(hits),
    requiredActions: [
      "Audit all active API versions to ensure security controls (auth, rate limiting, validation) are consistently applied across every version.",
      "CWE-284 — deprecated API versions that remain accessible may lack authentication or authorization controls added in newer versions.",
      "Fix: retire old API versions or apply the same security middleware stack (auth, validation, rate-limiting) to all /vN routes."
    ]
  };
}

async function checkPaginationAbuse(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:limit|offset|pageSize|perPage)\s*[:=]\s*(?:parseInt|Number)?\+?\s*(?:req\.|body\.|params\.|query\.)`
  );
  const safeRe = /Math\.min|MAX_PAGE_SIZE|maxLimit|\|\|\s*\d{2,3}/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_PAGINATION_UNBOUNDED",
    title: "Pagination limit/offset sourced from client without upper bound — DoS via limit=1000000 or data leak (CWE-400)",
    severity: "MEDIUM",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Cap pagination parameters to a maximum page size server-side to prevent DoS and bulk data exfiltration.",
      "CWE-400 — an unbounded limit parameter allows fetching millions of records in a single request, enabling DoS or mass data extraction.",
      "Fix: const limit = Math.min(parseInt(req.query.limit) || 20, MAX_PAGE_SIZE);"
    ]
  };
}

async function checkFreeTrialAbuse(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:trial|freeTrial|trialPeriod|trialActive)\s*[:=]`
  );
  const safeRe = /velocity|fingerprint|BIN|paymentMethod|deduplication/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_FREE_TRIAL_ABUSE",
    title: "Free trial creation without velocity/fingerprint check — unlimited trial acquisition with synthetic identities (CWE-20)",
    severity: "HIGH",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Gate free trial creation with velocity limits, email normalization, and optionally payment method BIN checks or device fingerprinting.",
      "CWE-20 — without controls, attackers use synthetic email addresses to acquire unlimited free trials at scale.",
      "Fix: enforce max one trial per normalized email, per IP (velocity window), and optionally require a payment method for trial activation."
    ]
  };
}

async function checkDoubleSpendPayment(): Promise<Finding | null> {
  const hits = await codeSearch(
    String.raw`(?:confirmPayment|capturePayment|chargeCard|processCharge|paymentIntent\.confirm)\s*\(`
  );
  const safeRe = /mutex|lock|transaction|serializable|FOR UPDATE|idempotency/;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_DOUBLE_SPEND_CONCURRENT",
    title: "Payment capture without distributed lock — concurrent requests double-charge or double-decrement gift cards (CWE-362)",
    severity: "CRITICAL",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Use idempotency keys, database transactions with serializable isolation, or a distributed mutex around payment capture operations.",
      "CWE-362 — concurrent payment capture requests can double-charge customers or double-decrement gift card balances.",
      "Fix: await stripe.paymentIntents.confirm(id, {}, { idempotencyKey: orderId }); // or wrap in a serializable DB transaction"
    ]
  };
}

async function checkPaymentIdempotency(): Promise<Finding | null> {
  // Charge/payment-intent creation without an idempotency key: a network retry
  // (or attacker replay) produces a duplicate charge.
  const hits = await codeSearch(
    String.raw`(?:stripe\.(?:charges|paymentIntents)\.(?:create|confirm|capture)|\.createCharge|\.chargeCard|\.createPaymentIntent|createCharge)\s*\(`
  );
  const safeRe = /idempotency|idempotencyKey|Idempotency-Key|requestId\s*,|{\s*idempotency/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_PAYMENT_NO_IDEMPOTENCY",
    title: "Payment/charge created without idempotency key — retry or replay double-charges the customer (CWE-799)",
    severity: "CRITICAL",
    sla: "24h",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Pass a per-operation idempotency key (e.g. the order ID) to every charge/payment-intent create/capture call so retries collapse to a single charge.",
      "CWE-799 — without idempotency, a client or network retry re-executes the charge and bills the customer multiple times.",
      "Fix: await stripe.paymentIntents.create({ amount, currency }, { idempotencyKey: orderId });"
    ]
  };
}

async function checkWalletNonAtomicDecrement(): Promise<Finding | null> {
  // Gift-card / wallet / store-credit balance mutated via read-modify-write on a
  // JS value rather than an atomic DB decrement — concurrent spends over-draw.
  const hits = await codeSearch(
    String.raw`(?:giftCard|gift_card|wallet|storeCredit|store_credit|balance)\b[^;\n]{0,60}(?:balance|amount)\s*(?:-=|=\s*[\w.]+\s*-)`
  );
  const safeRe = /decrement\s*:|{\s*decrement|FOR\s+UPDATE|\$transaction|serializable|\.increment\(|atomic|WHERE[^;]*balance\s*>=/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_WALLET_NONATOMIC_DECREMENT",
    title: "Gift-card/wallet balance decremented via read-modify-write, not an atomic operation — concurrent spend double-spends (CWE-362)",
    severity: "CRITICAL",
    sla: "24h",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Decrement wallet/gift-card balances with an atomic, conditional DB update, not a JS subtraction of a previously read value.",
      "CWE-362 — two concurrent spend requests both read the same balance and both subtract, letting a user spend more than they have.",
      "Fix: UPDATE wallet SET balance = balance - :amt WHERE id = :id AND balance >= :amt (0 rows affected => reject); or Prisma { balance: { decrement: amt } } inside a serializable transaction."
    ]
  };
}

async function checkRefundWithoutPurchase(): Promise<Finding | null> {
  // Refund issued without first verifying the original order was paid/captured.
  // The (?<!function\s) lookbehind excludes function declarations named "refund"
  // (e.g. `async function refund(orderId, order)`) — without it, the declaration
  // line itself false-fires as an unguarded call site, even when the real call
  // inside the function body is correctly guarded on a different line.
  const hits = await codeSearch(
    String.raw`(?<!function\s)(?:refund|createRefund|issueRefund|processRefund|stripe\.refunds\.create)\s*\(`
  );
  const safeRe = /status\s*===?\s*['"](?:paid|captured|succeeded|completed)['"]|isPaid|paidAt|verifyPayment|paymentStatus|charge(?:Id)?\s*[,)]|original.*paid|hasPaid/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_REFUND_WITHOUT_PAID_PURCHASE",
    title: "Refund issued without verifying the original purchase was paid — refund fraud / negative-balance abuse (CWE-840)",
    severity: "CRITICAL",
    sla: "24h",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Before issuing any refund, load the original order and confirm it was actually paid/captured and not already refunded.",
      "CWE-840 — refunding without checking the original payment lets an attacker extract money for orders that were never paid or were already refunded.",
      "Fix: const order = await db.order.findUnique({ where: { id } }); if (order.status !== 'paid' || order.refundedAt) throw new Error('Not refundable'); then refund at most order.amountPaid."
    ]
  };
}

async function checkBulkOpNotTenantScoped(): Promise<Finding | null> {
  // updateMany/deleteMany (or bulk UPDATE/DELETE) whose where-clause is not scoped
  // to the caller's tenant/user — mass update or delete across all tenants.
  const hits = await codeSearch(
    String.raw`\.(?:updateMany|deleteMany|removeAll|bulkWrite|destroy)\s*\(|(?:UPDATE|DELETE\s+FROM)\s+\w+\b[^;]{0,80}\bWHERE\b`
  );
  const safeRe = /(?:tenantId|tenant_id|orgId|org_id|organizationId|userId|user_id|accountId|account_id|workspaceId)\s*[:=]|where[^;]*(?:tenantId|orgId|userId|accountId)/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_BULK_OP_NOT_TENANT_SCOPED",
    title: "Bulk update/delete not scoped to tenant or user — mass modification across all tenants (CWE-639 / CWE-284)",
    severity: "CRITICAL",
    sla: "24h",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Every bulk updateMany/deleteMany must include the caller's tenantId/userId in the where clause so it cannot touch other tenants' rows.",
      "CWE-639 / CWE-284 — an unscoped bulk operation lets one tenant mass-update or delete every tenant's data.",
      "Fix: await db.record.deleteMany({ where: { id: { in: ids }, tenantId: req.user.tenantId } });"
    ]
  };
}

async function checkCouponSingleUseReplay(): Promise<Finding | null> {
  // Coupon/promo redemption that does not enforce single-use via a unique
  // constraint or a persisted redeemed check — the code can be replayed.
  const hits = await codeSearch(
    String.raw`(?:coupon|promo(?:Code)?|discount(?:Code)?|voucher)\b[^;\n]{0,60}(?:redeem|apply|validate|use)`
  );
  const safeRe = /unique|usedAt|redeemedAt|redemptionCount|usageLimit|timesUsed|already.*redeem|redeemed\s*(?:===|!==|==|!=)|@@unique|createMany.*skipDuplicates|UNIQUE/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_COUPON_SINGLE_USE_NOT_ENFORCED",
    title: "Single-use coupon/promo redemption not enforced by unique constraint — replay reuses the code (CWE-384)",
    severity: "HIGH",
    sla: "7d",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Enforce single-use redemption with a database UNIQUE(code) or UNIQUE(code, userId) constraint written inside the same transaction that grants the discount.",
      "CWE-384 — checking a boolean in application code is racy; two concurrent redemptions both pass and the code is used twice.",
      "Fix: insert a redemption row with a unique constraint and treat the duplicate-key error as 'already redeemed' rather than reading-then-writing a flag."
    ]
  };
}

async function checkWithdrawalLimitRace(): Promise<Finding | null> {
  // Daily/periodic withdrawal or transfer limit checked then applied without an
  // atomic guard — concurrent requests each pass the limit check.
  const hits = await codeSearch(
    String.raw`(?:daily|withdrawal|transfer|payout|spending)\w*[Ll]imit\b|(?:withdraw|transfer|payout)\b[^;\n]{0,60}limit`
  );
  const safeRe = /FOR\s+UPDATE|\$transaction|serializable|atomic|mutex|lock\b|WHERE[^;]*(?:sum|total)[^;]*<=|redis.*incr|SELECT.*SUM.*FOR\s+UPDATE/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_WITHDRAWAL_LIMIT_RACE",
    title: "Withdrawal/transfer daily-limit check not atomic — concurrent requests bypass the limit (CWE-362)",
    severity: "HIGH",
    sla: "7d",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Compute the running total and enforce the limit inside a single serializable transaction with SELECT ... FOR UPDATE (or an atomic counter), not a read-check-then-write.",
      "CWE-362 — two withdrawals fired simultaneously both read the same prior total, both pass the limit check, and together exceed it.",
      "Fix: BEGIN; SELECT COALESCE(SUM(amount),0) FROM withdrawals WHERE user_id=:u AND day=:today FOR UPDATE; if total+amount>limit reject; INSERT; COMMIT;"
    ]
  };
}

async function checkRoleNotRevalidated(): Promise<Finding | null> {
  // Authorization decisions read the role from the session/JWT rather than
  // re-loading it per request — a role revoked after login stays effective.
  const hits = await codeSearch(
    String.raw`(?:if|return|&&|\|\|)\s*[^;\n]{0,40}(?:req\.(?:session|user)\.role|session\.role|token\.role|jwt\.role|decoded\.role|req\.user\.isAdmin)\s*(?:===|==|!==|!=)\s*['"]`
  );
  const safeRe = /await\s+[^;]*(?:findUnique|findById|getRole|db\.|prisma|repository|loadUser|refetch)|fetchRole|reloadUser|await.*role/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_ROLE_NOT_REVALIDATED",
    title: "Authorization uses role from session/JWT without per-request re-validation — stale role after revocation (CWE-613)",
    severity: "HIGH",
    sla: "7d",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Re-load the user's current role/permissions from the source of truth on each privileged request rather than trusting the role baked into the session or JWT at login.",
      "CWE-613 — a role or permission revoked after the token was issued remains effective until the token expires, letting a demoted user keep admin access.",
      "Fix: const { role } = await db.user.findUnique({ where: { id: req.user.id }, select: { role: true } }); if (role !== 'admin') return res.status(403).end();"
    ]
  };
}

async function checkPermissionCacheNoTtl(): Promise<Finding | null> {
  // A permissions/roles/ACL cache populated without a TTL or an invalidation
  // hook — permission changes never take effect until process restart.
  const hits = await codeSearch(
    String.raw`(?:permission|permissions|roles?|acl|entitlement|authz)\w*[Cc]ache\b|cache(?:\.set)?\s*\([^)]*(?:permission|role|acl|entitlement)`
  );
  const safeRe = /ttl|expires?|maxAge|EX\b|setex|invalidate|\.del\(|\.delete\(|evict|revalidate|staleWhileRevalidate|expireAt/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_PERMISSION_CACHE_NO_TTL",
    title: "Permission/role cache without TTL or invalidation — revoked permissions stay effective (CWE-613)",
    severity: "MEDIUM",
    sla: "30d",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Give the permission/role cache a short TTL and invalidate it explicitly whenever a user's role or permissions change.",
      "CWE-613 — a permission cache with no expiry serves stale authorization data, so a revoked grant keeps working indefinitely.",
      "Fix: cache.set(key, perms, { ttl: 60 }); and call cache.del(userPermKey) inside the role-change handler."
    ]
  };
}

async function checkInventoryUnderflow(): Promise<Finding | null> {
  // Inventory/stock decrement without a guard preventing it from going negative.
  const hits = await codeSearch(
    String.raw`(?:inventory|stock|quantity|qty|available|units)\b[^;\n]{0,50}(?:-=|decrement|\.dec\b|=\s*[\w.]+\s*-\s*)`
  );
  const safeRe = /(?:stock|inventory|quantity|qty|available)\s*>=?\s*|WHERE[^;]*(?:stock|quantity|inventory)\s*>=|Math\.max\s*\(\s*0|if\s*\([^)]*<\s*0|GREATEST\s*\(\s*0|CHECK\s*\([^)]*>=\s*0/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_INVENTORY_UNDERFLOW",
    title: "Inventory/stock decremented without a non-negative guard — oversell / negative stock (CWE-191 / CWE-362)",
    severity: "HIGH",
    sla: "7d",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Decrement stock with a conditional atomic update that refuses to go below zero, and reject the order when no row is affected.",
      "CWE-191 / CWE-362 — an unguarded decrement lets concurrent orders drive stock negative, overselling inventory you cannot fulfill.",
      "Fix: UPDATE product SET stock = stock - :qty WHERE id = :id AND stock >= :qty; if rowCount === 0 -> out of stock; or add a CHECK (stock >= 0) constraint."
    ]
  };
}

async function checkClientShippingPriceAmount(): Promise<Finding | null> {
  // Shipping cost / line-item price / unit price taken from the client request
  // and used to build the order without server-side recomputation.
  const hits = await codeSearch(
    String.raw`(?:shippingCost|shipping_cost|shippingPrice|unitPrice|unit_price|itemPrice|item_price|lineTotal|price)\s*[:=]\s*(?:req\.|body\.|params\.|query\.)\w+`
  );
  const safeRe = /lookup|catalog|priceList|db\.|prisma|await\s+get(?:Price|Product)|calculateShipping|computePrice|server|PRICE_TABLE|fromDatabase/i;
  const unsafe = hits.filter((h) => !safeRe.test(h.preview));
  if (!unsafe.length) return null;
  return {
    id: "BIZ_CLIENT_SHIPPING_PRICE",
    title: "Shipping cost or item price taken from client without server-side validation — price tampering (CWE-602)",
    severity: "HIGH",
    sla: "7d",
    evidence: toEvidence(unsafe),
    files: toFiles(unsafe),
    requiredActions: [
      "Look up unit prices and compute shipping cost server-side from the product catalog and destination; never trust a price or shipping amount sent by the client.",
      "CWE-602 — accepting client-supplied prices/shipping lets an attacker set them to arbitrary low values and underpay for the order.",
      "Fix: const product = await db.product.findUnique({ where: { id } }); const lineTotal = product.price * qty; // ignore req.body.price"
    ]
  };
}

export async function checkBusinessLogic(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  try {
    const [
      massAssignment,
      idorResults,
      negativeAmount,
      raceResults,
      hardcodedCreds,
      hardcodedDb,
      missingValidation,
      insecureUrl,
      intOverflow,
      missingAdminAuth,
      timingOracle,
      floatMonetary,
      httpParamPollution,
      voucherReplay,
      stateMachineBypass,
      currencyConfusion,
      discountStacking,
      orderFulfillmentBypass,
      webhookTimestamp,
      taxShippingParamTamper,
      clientTotalAmount,
      referralAbuse,
      emailNormalization,
      featureFlagBypass,
      apiVersionBypass,
      paginationAbuse,
      freeTrialAbuse,
      doubleSpendPayment,
      paymentIdempotency,
      walletNonAtomic,
      refundWithoutPurchase,
      bulkOpNotScoped,
      couponSingleUse,
      withdrawalLimitRace,
      roleNotRevalidated,
      permissionCacheNoTtl,
      inventoryUnderflow,
      clientShippingPrice,
    ] = await Promise.all([
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
      checkFloatMonetaryArithmetic(),
      checkHttpParamPollution(),
      checkVoucherReplay(),
      checkStateMachineBypass(),
      checkCurrencyConfusion(),
      checkDiscountStacking(),
      checkOrderFulfillmentBypass(),
      checkWebhookTimestamp(),
      checkTaxShippingParamTamper(),
      checkClientTotalAmount(),
      checkReferralAbuse(),
      checkEmailNormalization(),
      checkFeatureFlagBypass(),
      checkApiVersionBypass(),
      checkPaginationAbuse(),
      checkFreeTrialAbuse(),
      checkDoubleSpendPayment(),
      checkPaymentIdempotency(),
      checkWalletNonAtomicDecrement(),
      checkRefundWithoutPurchase(),
      checkBulkOpNotTenantScoped(),
      checkCouponSingleUseReplay(),
      checkWithdrawalLimitRace(),
      checkRoleNotRevalidated(),
      checkPermissionCacheNoTtl(),
      checkInventoryUnderflow(),
      checkClientShippingPriceAmount(),
    ]);

    const singles = [
      massAssignment, negativeAmount, hardcodedCreds, hardcodedDb, missingValidation,
      insecureUrl, intOverflow, missingAdminAuth, timingOracle, floatMonetary,
      httpParamPollution, voucherReplay, stateMachineBypass,
      currencyConfusion, discountStacking, orderFulfillmentBypass, webhookTimestamp,
      taxShippingParamTamper, clientTotalAmount, referralAbuse, emailNormalization,
      featureFlagBypass, apiVersionBypass, paginationAbuse,
      freeTrialAbuse, doubleSpendPayment,
      paymentIdempotency, walletNonAtomic, refundWithoutPurchase, bulkOpNotScoped,
      couponSingleUse, withdrawalLimitRace, roleNotRevalidated, permissionCacheNoTtl,
      inventoryUnderflow, clientShippingPrice,
    ];
    return [
      ...singles.filter((f): f is Finding => f !== null),
      ...idorResults,
      ...raceResults,
    ];
  } catch (err) {
    // EVALUABILITY: an internal error here (a bug in any one of ~37 sub-checks)
    // currently discards every other sub-check's result too — returning [] would
    // report a full business-logic pass when the truth is this check never ran.
    console.warn("[checkBusinessLogic] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    return [{
      id: "EVAL_UNAVAILABLE_BUSINESS_LOGIC",
      title: "Business-logic checks could not complete — refund/inventory/race-condition status is UNKNOWN, not clean",
      severity: "HIGH",
      evidence: [sanitizeErrorMessage(err instanceof Error ? err.message : String(err))],
      requiredActions: [
        "Check the gate logs for the underlying error and file a bug if it reproduces.",
        "Do not treat this run as evidence that refund, inventory, payment, or race-condition logic is free of the issues this module checks for."
      ]
    }];
  }
}
