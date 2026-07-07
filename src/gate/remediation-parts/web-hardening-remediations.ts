// Remediation templates for the web-hardening detection module
// (src/gate/checks/web-hardening.ts). One entry per detection ID. These teach the
// concrete fix — a realistic vulnerable pattern, the secure replacement, a
// plain-language explanation, and standards references. Living under src/gate/
// means the gate self-scan excludes the intentional vulnerable strings.
import type { RemediationTemplate } from "../remediation-map.js";

export const WEB_HARDENING_REMEDIATIONS: Record<string, RemediationTemplate> = {
  WEB_MISSING_SECURITY_HEADERS: {
    pattern: "const app = express();\napp.get('/', handler); // no helmet, no CSP/HSTS/X-Frame-Options",
    fix: "import helmet from 'helmet';\napp.use(helmet({\n  contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"], frameAncestors: [\"'none'\"] } },\n  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },\n}));\n// Next.js equivalent (next.config.js):\n// async headers() { return [{ source: '/(.*)', headers: [\n//   { key: 'Content-Security-Policy', value: \"default-src 'self'; frame-ancestors 'none'\" },\n//   { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },\n//   { key: 'X-Frame-Options', value: 'DENY' } ] }]; }",
    explanation: "Without response-header hardening the page can be framed (clickjacking), served over plain HTTP (downgrade), and run any script (no CSP). helmet sets X-Frame-Options, HSTS, and a Content-Security-Policy in one place; Next.js apps set the equivalent via the headers() config.",
    references: ["CWE-1021", "CWE-693", "OWASP Secure Headers Project", "OWASP Top 10 A05:2021"],
  },

  WEB_OPEN_REDIRECT: {
    pattern: "res.redirect(req.query.url); // attacker: /go?url=https://evil.example",
    fix: "const dest = req.query.url;\nif (typeof dest !== 'string' || !dest.startsWith('/') || dest.startsWith('//')) {\n  return res.redirect('/');\n}\nres.redirect(dest); // relative same-app paths only; validate host against an allowlist for cross-origin",
    explanation: "A redirect target taken from user input lets an attacker craft a link on your trusted domain that bounces the victim to a phishing site. Allow only relative same-app paths, or validate the parsed host against an explicit allowlist before redirecting.",
    references: ["CWE-601", "OWASP Top 10 A01:2021", "OWASP Unvalidated Redirects and Forwards Cheat Sheet"],
  },

  WEB_HARDCODED_SESSION_SECRET: {
    pattern: "app.use(session({ secret: 'keyboard cat' }));\njwt.sign(payload, 'my-hardcoded-secret');",
    fix: "if (!process.env.SESSION_SECRET) throw new Error('SESSION_SECRET is not set');\napp.use(session({ secret: process.env.SESSION_SECRET }));\njwt.sign(payload, process.env.JWT_SECRET);\n// generate once, store only in the secret manager:\n// node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"",
    explanation: "A hardcoded or default (\"keyboard cat\") signing secret lets anyone who reads the source — or guesses the well-known default — forge a valid session or JWT for any user. Load a high-entropy secret from the environment / a secret manager and rotate any value that was committed.",
    references: ["CWE-798", "CWE-330", "OWASP Top 10 A02:2021", "NIST 800-53 IA-5"],
  },

  WEB_EMAIL_HEADER_INJECTION: {
    pattern: "transporter.sendMail({ to: req.body.email, subject: req.body.subject, from: 'no-reply@app.com' });",
    fix: "const stripCRLF = (v) => String(v).replace(/[\\r\\n]+/g, ' ').trim();\nconst to = stripCRLF(req.body.email);\nif (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(to)) return res.status(400).send('invalid recipient');\ntransporter.sendMail({ to, subject: stripCRLF(req.body.subject), from: 'no-reply@app.com' });",
    explanation: "Email envelope fields are separated by CRLF, so an unsanitized newline in user input lets an attacker append their own To/Cc/Bcc headers and relay mail. Strip CR/LF from every user-supplied header value, validate recipient addresses, and never let users set arbitrary From/Reply-To or raw headers.",
    references: ["CWE-93", "CWE-88", "OWASP Top 10 A03:2021"],
  },

  WEB_SERVER_ACTION_NO_AUTHZ: {
    pattern: "'use server';\nexport async function deletePost(id: string) {\n  await prisma.post.delete({ where: { id } }); // no auth check — public POST endpoint\n}",
    fix: "'use server';\nimport { getServerSession } from 'next-auth';\nexport async function deletePost(id: string) {\n  const session = await getServerSession(authOptions);\n  if (!session) throw new Error('Unauthorized');\n  await prisma.post.delete({ where: { id, userId: session.user.id } }); // authz + ownership scope\n}",
    explanation: "A Next.js Server Action compiles to a publicly-invocable POST endpoint; hiding its button in the UI does not stop a direct POST. Verify the session at the top of every action and scope each query to the authenticated user to prevent unauthorized access and IDOR.",
    references: ["CWE-306", "CWE-862", "OWASP Top 10 A01:2021", "OWASP API Security Top 10 API5:2023"],
  },

  WEB_SENSITIVE_FIELD_IN_RESPONSE: {
    pattern: "const user = await prisma.user.findUnique({ where: { id } });\nres.json(user); // leaks passwordHash, mfaSecret, apiKey, ...",
    fix: "const user = await prisma.user.findUnique({\n  where: { id },\n  select: { id: true, email: true, name: true }, // explicit allowlist\n});\nres.json(user);",
    explanation: "Serializing a raw DB row hands secret columns (passwordHash, salt, mfaSecret, apiKey, refreshToken, ssn) to the client. Never return raw rows: use an explicit field allowlist (Prisma select / a DTO mapper) so newly-added secret columns can never leak by accident.",
    references: ["CWE-213", "CWE-200", "OWASP API Security Top 10 API3:2023", "OWASP Top 10 A01:2021"],
  },
};
