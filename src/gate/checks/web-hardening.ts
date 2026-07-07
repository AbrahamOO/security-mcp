/**
 * Web-hardening threat detection — confirmed blindspots in real-world web apps.
 *
 * THREAT MODEL (for a non-security reader):
 *   These are six mistakes that keep shipping to production in Express/Next/
 *   Fastify/Node web apps because "it works in the browser" and nothing visibly
 *   breaks. An attacker never sees your UI code the way you do — they see the raw
 *   HTTP surface, and they grep for exactly these shapes:
 *     • No security headers  — your page can be silently framed (clickjacking),
 *       served over plain HTTP, or allowed to load attacker script (no CSP).
 *     • Open redirect        — your own /redirect?url=… bounces a victim to a
 *       phishing site under YOUR domain's trust.
 *     • Hard-coded session/JWT secret — anyone who reads the source (or guesses
 *       the well-known default "keyboard cat") can forge any user's session.
 *     • Email header injection — a user types a newline into a "name"/"email"
 *       field and appends their own Bcc:/To: headers to the mail you send.
 *     • Server Action with no authz — Next.js Server Actions are publicly-callable
 *       POST endpoints; hiding the button does NOT stop a direct POST (the 2025
 *       Server-Actions authorization gap).
 *     • Sensitive field in response — you `res.json(user)` and the row still
 *       carries passwordHash/mfaSecret/apiKey, handing it to every client.
 *
 * WHY THIS MODULE IS ALWAYS-ON:
 *   None of these hide behind a single "web" flag. A hard-coded JWT secret or a
 *   password field returned from an API is dangerous whether or not the scan
 *   classified the repo as "web" — and the repos most likely to contain them are
 *   exactly the ones a surface-gate would misclassify. So this check runs
 *   unconditionally, mirroring vibe-coding.ts.
 *
 * DESIGN NOTES (shared with the other always-on modules):
 *   • Every rule is wrapped so malformed input can never throw the gate down.
 *   • Detection uses searchRepo({isRegex:true,maxMatches:200}) for content and
 *     scopedFg + readFileSafe for file-shape / per-file inspection.
 *   • Regexes are kept tight (no nested quantifiers) to stay under the repo's
 *     ReDoS guard (src/repo/search.ts::isCatastrophicRegex); a rejected query
 *     degrades to [] rather than crashing.
 *   • Secrets are NEVER echoed in full — hard-coded-secret evidence is truncated.
 *   • requiredActions are prescriptive fixes with concrete code, never "review".
 */
import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";

type Hit = { file: string; line: number; preview: string };

// ─── Shared helpers (mirror vibe-coding.ts style) ────────────────────────────

async function allSearch(query: string): Promise<Hit[]> {
  try {
    return await searchRepo({ query, isRegex: true, maxMatches: 200 });
  } catch {
    // A malformed/over-complex query or a scan error must never crash the gate.
    return [];
  }
}

/** Show only enough of a secret to identify it; never echo a usable value. */
function truncateSecret(raw: string): string {
  const s = raw.trim();
  if (s.length <= 8) return s.slice(0, 2) + "…";
  return `${s.slice(0, 4)}…${s.slice(-2)} (${s.length} chars)`;
}

// Server handler file globs (used by the Server-Action authz rule to enumerate
// candidate files that could carry a `use server` directive).
const SERVER_ACTION_GLOBS = [
  "**/app/**/*.ts",
  "**/app/**/*.tsx",
  "**/app/**/*.js",
  "**/app/**/*.jsx",
  "**/app/**/*.mjs",
  "**/src/app/**/*.ts",
  "**/src/app/**/*.tsx",
  "**/src/**/actions/**/*.ts",
  "**/src/**/actions/**/*.tsx",
  "**/actions/**/*.ts",
  "**/actions/**/*.tsx",
  "**/lib/**/*.ts",
  "**/lib/**/*.tsx",
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. WEB_MISSING_SECURITY_HEADERS (CWE-1021 Improper Restriction of Rendered UI
//    Layers / Frames — Clickjacking; CWE-693 Protection Mechanism Failure)
//
// A web app is only as safe as its response headers. Three headers matter most:
//   • X-Frame-Options / CSP frame-ancestors — stops your page being framed by an
//     attacker's site to trick a logged-in user into clicking (clickjacking).
//   • Strict-Transport-Security (HSTS) — forces HTTPS so a network attacker can't
//     downgrade the connection and read/modify traffic.
//   • Content-Security-Policy — limits which scripts can run, shrinking the blast
//     radius of any XSS.
// AI-scaffolded and hand-written apps routinely ship NONE of these. `helmet`
// sets all three sensibly by default, so its total absence — in a repo that DOES
// have a web-server surface — is a strong signal the app is unprotected.
//
// This rule fires ONCE at repo level, and ONLY when there is a real server
// surface AND zero evidence of any header protection anywhere — so pure static
// sites and libraries (no server) do not trip it.
// ─────────────────────────────────────────────────────────────────────────────

async function checkMissingSecurityHeaders(): Promise<Finding | null> {
  try {
    // (1) Is there a web-server surface at all? Any one of these signals suffices.
    const serverSignals: string[] = [
      String.raw`\bexpress\s*\(\s*\)`,            // const app = express()
      String.raw`\bapp\.use\s*\(`,                // app.use(...)
      String.raw`\bapp\.(?:get|post|put|patch|delete)\s*\(`, // route handlers
      String.raw`\bfastify\s*\(`,                 // fastify()
      String.raw`next\.config\.(?:js|ts|mjs)`,    // a Next.js app
      String.raw`from\s+['"]next/server['"]`,     // Next route handlers/middleware
      String.raw`createServer\s*\(`,              // node:http/https createServer
    ];
    let hasServerSurface = false;
    for (const sig of serverSignals) {
      if ((await allSearch(sig)).length > 0) {
        hasServerSurface = true;
        break;
      }
    }
    if (!hasServerSurface) return null; // static/library repo — nothing to harden

    // (2) Is there ANY evidence of header protection anywhere in the repo?
    const protections: Array<{ label: string; query: string }> = [
      { label: "helmet", query: String.raw`\bhelmet\s*\(` },
      {
        label: "X-Frame-Options / frame-ancestors / frameguard",
        query: String.raw`X-Frame-Options|frame-ancestors|frameguard`,
      },
      {
        label: "Strict-Transport-Security / HSTS",
        query: String.raw`Strict-Transport-Security|\bhsts\b`,
      },
      {
        label: "Content-Security-Policy",
        query: String.raw`Content-Security-Policy|contentSecurityPolicy`,
      },
    ];

    const present: string[] = [];
    const absent: string[] = [];
    for (const p of protections) {
      const found = (await allSearch(p.query)).length > 0;
      if (found) present.push(p.label);
      else absent.push(p.label);
    }

    // Be conservative: only fire when there is a server surface AND NOT A SINGLE
    // protection is present. If any header protection exists, assume the author
    // is aware and stay quiet (avoids noisy partial-coverage findings).
    if (present.length > 0) return null;

    return {
      id: "WEB_MISSING_SECURITY_HEADERS",
      title:
        "Web server ships no clickjacking / transport / CSP protection — no helmet, X-Frame-Options, HSTS, or Content-Security-Policy anywhere (CWE-1021/CWE-693)",
      severity: "MEDIUM",
      sla: "30d",
      evidence: [
        "A web-server surface was detected but no response-header hardening was found anywhere in the repo.",
        `Absent protections: ${absent.join("; ")}.`,
      ],
      requiredActions: [
        "Express/Fastify: add helmet at the top of the middleware chain: `import helmet from 'helmet'; app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"], frameAncestors: [\"'none'\"] } }, hsts: { maxAge: 31536000, includeSubDomains: true, preload: true } }));` — this sets X-Frame-Options DENY, HSTS, and a CSP in one place.",
        "Next.js (no helmet): add a `headers()` block to next.config.js returning, for every route, `{ key: 'Content-Security-Policy', value: \"default-src 'self'; frame-ancestors 'none'\" }`, `{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }`, and `{ key: 'X-Frame-Options', value: 'DENY' }`.",
        "If a page must NOT be framed at all, prefer CSP `frame-ancestors 'none'` (modern, granular) plus `X-Frame-Options: DENY` (legacy fallback); add a CI assertion that a HEAD request to a route returns all three headers.",
      ],
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. WEB_OPEN_REDIRECT (CWE-601 URL Redirection to Untrusted Site)
//
// When a redirect target is taken straight from user input, an attacker crafts a
// link to YOUR site that silently bounces the victim to a phishing/malware page:
// `https://yourapp.com/go?url=https://evil.example`. Because the link is on your
// trusted domain, users (and email filters) trust it. The fix is always an
// allowlist / relative-path-only check before redirecting.
//
// We match a redirect call whose argument is (or contains) a request-derived
// value: req.query/req.body/req.params, a Next `searchParams.get(...)`, a Java
// `request.getParameter(...)`, or `NextResponse.redirect(new URL(<user>...))`.
// Regexes are bounded (`{0,80}`) so there are no nested quantifiers.
// ─────────────────────────────────────────────────────────────────────────────

async function checkOpenRedirect(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();
    const seen = new Set<string>();

    const push = (h: Hit, note: string) => {
      const key = `${h.file}:${h.line}`;
      if (seen.has(key)) return;
      seen.add(key);
      evidence.push(`${h.file}:${h.line}: ${note} — ${h.preview.trim().slice(0, 140)}`);
      files.add(h.file);
    };

    // (a) res.redirect(...) / sendRedirect(...) / redirect(...) whose argument
    //     carries a request-derived value within a short window.
    const redirectFromReq = await allSearch(
      String.raw`(?:res\.redirect|sendRedirect|\.redirect)\s*\([^)]{0,80}(?:req\.(?:query|body|params)|request\.getParameter|searchParams\.get|req\.get\s*\(\s*['"]referer)`
    );
    for (const h of redirectFromReq) push(h, "redirect target taken from user input");

    // (b) Next.js: NextResponse.redirect(new URL(<user>...)) — user value inside
    //     the URL constructor fed to a redirect.
    const nextRedirect = await allSearch(
      String.raw`redirect\s*\(\s*new\s+URL\s*\([^)]{0,80}(?:searchParams|req\.|request\.|params\.|query\.|body\.)`
    );
    for (const h of nextRedirect) push(h, "NextResponse.redirect(new URL(<user input>))");

    // (c) bare `redirect(searchParams.get('...'))` (Next server action / RSC).
    const bareRedirect = await allSearch(
      String.raw`\bredirect\s*\(\s*searchParams\.get\s*\(`
    );
    for (const h of bareRedirect) push(h, "redirect(searchParams.get(...)) with no validation");

    if (evidence.length === 0) return null;
    return {
      id: "WEB_OPEN_REDIRECT",
      title:
        "Redirect target taken from user input without validation — attacker can bounce victims from your trusted domain to a phishing site (CWE-601)",
      severity: "HIGH",
      sla: "7d",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "Never redirect to a raw user-supplied URL. Allow only relative, same-app paths: `const dest = req.query.url; if (typeof dest !== 'string' || !dest.startsWith('/') || dest.startsWith('//')) return res.redirect('/'); res.redirect(dest);` (reject `//host` and `http(s)://` targets).",
        "If cross-origin redirects are required, validate the parsed host against an explicit allowlist: `const u = new URL(dest, base); if (!ALLOWED_HOSTS.has(u.host)) return res.redirect('/'); res.redirect(u.toString());`.",
        "For OAuth/login `returnTo` params, map an opaque key to a server-side table of permitted destinations instead of accepting a full URL from the client.",
      ],
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. WEB_HARDCODED_SESSION_SECRET (CWE-798 Use of Hard-coded Credentials;
//    CWE-330 Use of Insufficiently Random Values)
//
// A session/cookie/JWT signing secret is the key that proves a session is
// genuine. If it is a string literal in the source (or the well-known Express
// default "keyboard cat"), anyone who can read the code — or who simply guesses
// the default — can forge a valid session or token for ANY user. It must come
// from a secret manager / env var and be high-entropy.
//
// We match: session()/cookieSession() with a literal `secret`, the notorious
// "keyboard cat" default, a NEXTAUTH_SECRET assigned a literal in code (not
// process.env), and jwt.sign(..., '<short literal>', ...). We exclude
// process.env references, .env.example templates, and empty strings.
// ─────────────────────────────────────────────────────────────────────────────

async function checkHardcodedSessionSecret(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();
    const seen = new Set<string>();

    const isTemplate = (file: string) =>
      /\.env\.(?:example|sample|template|dist)$/i.test(file) ||
      /(?:example|sample|template)\.env$/i.test(file);

    const push = (h: Hit, note: string, secret?: string) => {
      if (isTemplate(h.file)) return; // placeholders in *.env.example are fine
      if (/process\.env/i.test(h.preview)) return; // env-driven — not hardcoded
      const key = `${h.file}:${h.line}`;
      if (seen.has(key)) return;
      seen.add(key);
      const shown = secret ? ` (${truncateSecret(secret)})` : "";
      evidence.push(`${h.file}:${h.line}: ${note}${shown}`);
      files.add(h.file);
    };

    // (a) session({...secret:'literal'...}) / cookieSession({ secret: '...' }).
    const sessionSecret = await allSearch(
      String.raw`(?:session|cookieSession)\s*\([^)]{0,120}secret\s*:\s*['"][^'"]{1,}['"]`
    );
    for (const h of sessionSecret) {
      const m = /secret\s*:\s*['"]([^'"]{1,})['"]/.exec(h.preview);
      push(h, "session/cookie secret hardcoded as a string literal", m?.[1]);
    }

    // (b) the well-known Express default "keyboard cat" — always weak.
    const keyboardCat = await allSearch(String.raw`secret\s*:\s*['"]keyboard cat['"]`);
    for (const h of keyboardCat) push(h, 'well-known default session secret "keyboard cat"', "keyboard cat");

    // (c) NEXTAUTH_SECRET / AUTH_SECRET assigned a literal in code (not env).
    const nextAuthSecret = await allSearch(
      String.raw`(?:NEXTAUTH_SECRET|AUTH_SECRET)\s*[:=]\s*['"][^'"]{4,}['"]`
    );
    for (const h of nextAuthSecret) {
      const m = /['"]([^'"]{4,})['"]/.exec(h.preview);
      push(h, "NextAuth secret hardcoded as a literal instead of process.env", m?.[1]);
    }

    // (d) jwt.sign(payload, '<short quoted literal secret>', ...) — HMAC key inline.
    const jwtSign = await allSearch(
      String.raw`jwt\.sign\s*\([^,]{1,60},\s*['"][A-Za-z0-9_\-]{4,}['"]`
    );
    for (const h of jwtSign) {
      const m = /,\s*['"]([A-Za-z0-9_-]{4,})['"]/.exec(h.preview);
      push(h, "jwt.sign() uses a hardcoded literal signing secret", m?.[1]);
    }

    if (evidence.length === 0) return null;
    return {
      id: "WEB_HARDCODED_SESSION_SECRET",
      title:
        "Session / cookie / JWT signing secret hardcoded (or the well-known default) — anyone who reads the source can forge any user's session (CWE-798/CWE-330)",
      severity: "HIGH",
      sla: "7d",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "Treat the committed secret as compromised and ROTATE it now — a hardcoded signing key lets an attacker mint valid sessions/tokens for every user. Rotating invalidates all existing sessions (expected).",
        "Load the secret from the environment / a secret manager, never a literal: `secret: process.env.SESSION_SECRET` (Express) / `secret: process.env.NEXTAUTH_SECRET` (NextAuth). Fail fast at boot if the var is unset.",
        "Generate a high-entropy value: `node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"` and store it only in the deployment secret store; keep just a placeholder in .env.example.",
      ],
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. WEB_EMAIL_HEADER_INJECTION (CWE-93 Improper Neutralization of CRLF
//    Sequences; CWE-88 Argument Injection)
//
// Email envelope fields (To, From, Subject, Reply-To, Cc, Bcc) are separated by
// CRLF (`\r\n`). If user input flows unsanitized into one of these fields, an
// attacker embeds a newline plus their own header — e.g. a "name" of
// `Bob\r\nBcc: victim@corp.com` silently adds a Bcc, turning your app into a
// spam/phishing relay or leaking mail to third parties.
//
// We match nodemailer `sendMail({ to|subject|from|replyTo|cc|bcc: req... })`,
// SendGrid `msg.to = req...`, and raw header strings built with an explicit
// `\r\n` next to request input. Bounded windows keep the regex ReDoS-safe.
// ─────────────────────────────────────────────────────────────────────────────

async function checkEmailHeaderInjection(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();
    const seen = new Set<string>();

    const push = (h: Hit, note: string) => {
      const key = `${h.file}:${h.line}`;
      if (seen.has(key)) return;
      seen.add(key);
      evidence.push(`${h.file}:${h.line}: ${note} — ${h.preview.trim().slice(0, 140)}`);
      files.add(h.file);
    };

    // (a) an envelope field (to/subject/from/replyTo/cc/bcc) set from request input
    //     inside a mail-options object literal.
    const envelopeFromReq = await allSearch(
      String.raw`(?:to|subject|from|replyTo|reply_to|cc|bcc)\s*:\s*[^,}\n]{0,40}(?:req\.(?:body|query|params)|request\.(?:body|query)|searchParams\.get)`
    );
    for (const h of envelopeFromReq) push(h, "email envelope field built from unsanitized user input");

    // (b) SendGrid-style `msg.to = req...` / `message.subject = req...`.
    const sendgridAssign = await allSearch(
      String.raw`\b(?:msg|message|mail|email)\.(?:to|from|subject|replyTo|cc|bcc)\s*=\s*[^;\n]{0,40}(?:req\.|request\.|searchParams)`
    );
    for (const h of sendgridAssign) push(h, "mail header assigned directly from a request value");

    // (c) a raw header string concatenating CRLF with user input (classic form).
    const crlfConcat = await allSearch(
      String.raw`(?:To|From|Subject|Cc|Bcc|Reply-To)\s*:\s*[^\n]{0,40}(?:req\.|request\.|\$\{)[^\n]{0,40}\\r\\n`
    );
    for (const h of crlfConcat) push(h, "raw mail header concatenated with \\r\\n and user input");

    if (evidence.length === 0) return null;
    return {
      id: "WEB_EMAIL_HEADER_INJECTION",
      title:
        "User input flows unsanitized into email envelope fields — CRLF header injection lets attackers add Bcc/To headers and relay mail (CWE-93/CWE-88)",
      severity: "HIGH",
      sla: "7d",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "Strip CR/LF from every user-supplied header value before it reaches the mailer: `const clean = String(value).replace(/[\\r\\n]+/g, ' ').trim();` — a newline is what lets an attacker inject a second header.",
        "Validate recipient addresses against a strict format (e.g. a single RFC-5322 address, or a server-side allowlist) and reject anything with multiple addresses/commas unless you explicitly support them.",
        "Never let users set arbitrary To/Cc/Bcc/From/Reply-To or raw headers. Fix From/Reply-To server-side, put user text only in the body (or a length-capped, newline-free Subject), and prefer the mailer's structured address fields over hand-built header strings.",
      ],
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. WEB_SERVER_ACTION_NO_AUTHZ (CWE-306 Missing Authentication for a Critical
//    Function; CWE-862 Missing Authorization)
//
// A Next.js Server Action (a function/file marked `'use server'`) compiles to a
// publicly-invocable POST endpoint. The button that calls it may be hidden behind
// a login screen, but an attacker can POST to the action's endpoint directly —
// hiding the UI is NOT authorization (the 2025 Server-Actions authz gap). If an
// action performs a DB mutation/read but never verifies the caller's session, it
// leaks or mutates data for anyone on the internet.
//
// We enumerate candidate files, keep only those containing a `use server`
// directive (file-top or inside an async function), and flag any that do DB work
// but contain no recognised server-side auth verifier. The does-work and
// has-auth heuristics mirror vibe-coding.ts::checkApiRouteNoServerAuthz.
// ─────────────────────────────────────────────────────────────────────────────

// The `'use server'` / "use server" directive (either quote style).
const USE_SERVER_RE = /['"]use server['"]/;
// A DB mutation/read — i.e. the action actually touches data.
const ACTION_DOES_WORK_RE =
  /prisma\.|supabase\.|\bdb\.|drizzle|\.(?:insert|update|delete|findMany|findUnique|findFirst|create|createMany|updateMany|deleteMany)\s*\(/;
// Any recognised server-side auth/identity verifier (same set as the API rule).
const ACTION_HAS_AUTH_RE =
  /getServerSession|auth\s*\(|currentUser|getUser\s*\(|clerkClient|verifyToken|getToken|requireAuth|getAuth\s*\(|next-auth|supabase[\s\S]{0,60}auth\.getUser/i;
// An action explicitly marked public/webhook is intentional — don't flag it.
const ACTION_PUBLIC_MARK_RE = /\/\/\s*PUBLIC(?:\s+ACTION)?|allowUnauthenticated|webhook/i;

async function checkServerActionNoAuthz(): Promise<Finding | null> {
  try {
    let candidates: string[] = [];
    try {
      candidates = await fg(SERVER_ACTION_GLOBS, { dot: true, onlyFiles: true, followSymbolicLinks: false });
    } catch {
      return null;
    }
    if (candidates.length === 0) return null;

    const offenders: string[] = [];
    for (const file of [...new Set(candidates)]) {
      let content = "";
      try {
        content = await readFileSafe(file);
      } catch {
        continue;
      }
      if (!USE_SERVER_RE.test(content)) continue; // not a Server Action file
      if (!ACTION_DOES_WORK_RE.test(content)) continue; // no DB work — skip
      if (ACTION_HAS_AUTH_RE.test(content)) continue; // has an auth verifier — ok
      if (ACTION_PUBLIC_MARK_RE.test(content)) continue; // intentionally public
      offenders.push(`${file}: 'use server' action performs a DB mutation/read with no server-side auth check`);
      if (offenders.length >= 15) break;
    }

    if (offenders.length === 0) return null;
    return {
      id: "WEB_SERVER_ACTION_NO_AUTHZ",
      title:
        "Next.js Server Action mutates/reads the DB with no server-side authorization — the action is a public POST endpoint anyone can invoke (CWE-306/CWE-862)",
      severity: "HIGH",
      sla: "7d",
      evidence: offenders.slice(0, 10),
      files: [...new Set(offenders.map((o) => o.split(":")[0]))].slice(0, 10),
      requiredActions: [
        "A Server Action is a publicly-callable POST endpoint — hiding its button does nothing. Verify the session at the TOP of every action: `'use server'; const session = await getServerSession(authOptions); if (!session) throw new Error('Unauthorized');` (or `auth()` / `currentUser()` with your provider).",
        "After authenticating, authorize the specific object and scope every query to the authed user: `await prisma.doc.update({ where: { id, userId: session.user.id }, data })` — never trust an id from the form alone (prevents IDOR).",
        "If an action is genuinely public, mark it `// PUBLIC ACTION` and validate/rate-limit it explicitly; for webhook-style handlers verify the provider signature instead of a user session.",
      ],
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. WEB_SENSITIVE_FIELD_IN_RESPONSE (CWE-213 Exposure of Sensitive Information
//    Due to Incompatible Policies; CWE-200 Exposure of Sensitive Information)
//
// A very common leak: you fetch a DB row and serialize the WHOLE object to the
// client — but the row still carries password/passwordHash/salt/mfaSecret/apiKey/
// refreshToken/ssn. The browser (and anyone proxying it) now has those secrets.
// Two tight shapes catch most of it without noise:
//   (a) a response object literal that literally includes a secret field name, and
//   (b) a `SELECT *` (or a Prisma find* with no `select`/`omit`) whose result is
//       then handed to res.json/Response.json/res.send.
// ─────────────────────────────────────────────────────────────────────────────

const SECRET_FIELD_ALT =
  "password|passwordHash|hashedPassword|password_hash|salt|mfaSecret|mfa_secret|totpSecret|totp_secret|apiKey|api_key|refreshToken|refresh_token|ssn|socialSecurityNumber|privateKey|private_key";

async function checkSensitiveFieldInResponse(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();
    const seen = new Set<string>();

    const push = (h: Hit, note: string) => {
      const key = `${h.file}:${h.line}`;
      if (seen.has(key)) return;
      seen.add(key);
      evidence.push(`${h.file}:${h.line}: ${note} — ${h.preview.trim().slice(0, 140)}`);
      files.add(h.file);
    };

    // (a) a response serializer whose object literal includes a secret field name,
    //     e.g. res.json({ id, email, password }) / Response.json({ ..., apiKey }).
    const secretInResponse = await allSearch(
      String.raw`(?:res\.json|res\.send|Response\.json|NextResponse\.json)\s*\([^)]{0,120}(?:${SECRET_FIELD_ALT})\b`
    );
    for (const h of secretInResponse) push(h, "response body includes a secret field name");

    // (b) a `SELECT *` query in a file that also serializes rows to the client.
    //     We flag the SELECT * site; the response sink presence is verified below.
    const selectStarHits = await allSearch(String.raw`select\s+\*\s+from\s+[A-Za-z0-9_."\` ]{1,60}`);
    const selectStarFiles = [...new Set(selectStarHits.map((h) => h.file))];
    for (const file of selectStarFiles) {
      let content = "";
      try {
        content = await readFileSafe(file);
      } catch {
        continue;
      }
      // Only flag when the same file also hands data to a response serializer.
      if (!/(?:res\.json|res\.send|Response\.json|NextResponse\.json)\s*\(/.test(content)) continue;
      const first = selectStarHits.find((h) => h.file === file);
      if (first) push(first, "`SELECT *` result serialized to the client without a field allowlist");
    }

    // (c) a Prisma find* with no `select`/`omit` whose result is returned in the
    //     same statement to a response serializer — returns every column, incl.
    //     secret fields. Bounded window keeps it ReDoS-safe.
    const prismaFindToResponse = await allSearch(
      String.raw`(?:res\.json|res\.send|Response\.json|NextResponse\.json)\s*\(\s*await\s+[A-Za-z0-9_.]{1,40}\.(?:findUnique|findFirst|findMany)\s*\(\s*\{[^}]{0,120}\}\s*\)\s*\)`
    );
    for (const h of prismaFindToResponse) {
      if (/select\s*:|omit\s*:/.test(h.preview)) continue; // already scoped — ok
      push(h, "Prisma find* result returned directly with no select/omit — every column exposed");
    }

    if (evidence.length === 0) return null;
    return {
      id: "WEB_SENSITIVE_FIELD_IN_RESPONSE",
      title:
        "Sensitive fields (password/mfaSecret/apiKey/refreshToken/ssn) serialized to the client — raw DB rows returned without a field allowlist (CWE-213/CWE-200)",
      severity: "MEDIUM",
      sla: "30d",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "Never return a raw DB row. Map to an explicit DTO that lists only safe fields: `return res.json({ id: user.id, email: user.email, name: user.name });` — an allowlist means new secret columns are never leaked by accident.",
        "With Prisma, use `select` to fetch only what the client needs, or `omit` the secrets: `prisma.user.findUnique({ where: { id }, select: { id: true, email: true, name: true } })` (never `SELECT *` / a bare find into the response).",
        "Add a serializer/interceptor (or a Zod response schema) that strips password/passwordHash/salt/mfaSecret/totpSecret/apiKey/refreshToken/ssn from every outbound payload, and a test asserting those keys never appear in a response.",
      ],
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point — ALWAYS-ON. Runs every rule, tolerates individual failures, never
// throws (a single rule must never take the whole gate down).
// ─────────────────────────────────────────────────────────────────────────────

export async function checkWebHardening(_: { changedFiles: string[] }): Promise<Finding[]> {
  try {
    const results = await Promise.all([
      checkMissingSecurityHeaders(),
      checkOpenRedirect(),
      checkHardcodedSessionSecret(),
      checkEmailHeaderInjection(),
      checkServerActionNoAuthz(),
      checkSensitiveFieldInResponse(),
    ]);
    return results.filter((f): f is Finding => f !== null);
  } catch {
    return [];
  }
}
