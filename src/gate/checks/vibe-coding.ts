/**
 * "Vibe coding" threat detection — how attackers exploit AI-generated apps.
 *
 * THREAT MODEL (for a non-security reader):
 *   "Vibe coding" is shipping an app that an AI tool (Cursor, Lovable, Bolt, v0,
 *   Replit, Claude, etc.) wrote for you from a natural-language prompt. These
 *   tools optimise for "it works and it looks done", not for a threat model, so
 *   they reliably produce a small, repeatable set of security holes: the database
 *   admin key ends up in the browser bundle, the database has Row-Level-Security
 *   turned off, the API route never checks who is calling it, the price is trusted
 *   from the client, and so on. Because the code *runs*, the author assumes it is
 *   safe — and attackers know exactly what to grep for. Several of these patterns
 *   have already produced real breaches:
 *     • Moltbook / Supabase — the `service_role` (god-mode) key shipped to the
 *       browser, letting anyone read/write every row (bypasses RLS entirely).
 *     • Lovable "VibeScamming" / CVE-2025-48757 — generated apps with Supabase
 *       Row-Level-Security disabled or a `USING (true)` policy: the frontend anon
 *       key could read every table.
 *     • Tea app — Firebase Storage/Firestore rules left world-readable/writable,
 *       exposing users' IDs and DMs.
 *     • Base44 — an API backend with no server-side authorization: the frontend
 *       "checked" auth but the endpoints did not, so requests straight to the API
 *       returned everyone's data.
 *
 * WHY THIS MODULE IS ALWAYS-ON:
 *   These bugs do not live behind a single "surface" flag — a leaked provider key
 *   or a public Firebase rule is dangerous whether or not the scan classified the
 *   repo as "web" or "api". Surface-gating any of these would leave a blindspot on
 *   exactly the class of project (an AI-scaffolded prototype pushed to prod) that
 *   is most likely to contain them. So this check runs unconditionally.
 *
 * DESIGN NOTES (shared with the other always-on modules):
 *   • Every rule is wrapped so malformed input can never throw the gate down.
 *   • Detection uses searchRepo({isRegex:true,maxMatches:200}) for content and
 *     scopedFg + readFileSafe for file-shape / per-file inspection.
 *   • Regexes are kept tight (no nested quantifiers) to stay under the repo's
 *     ReDoS guard (src/repo/search.ts::isCatastrophicRegex).
 *   • Secrets/keys are NEVER echoed in full — provider-key evidence is truncated.
 *   • requiredActions are prescriptive fixes ("move X server-side and rotate",
 *     "enable RLS + add a policy"), never a vague "review this".
 *
 * CLIENT-vs-SERVER heuristic (used by several rules):
 *   A file is treated as part of the browser-shipped "client tree" when it lives
 *   under src/, app/, pages/, components/, or public/, or is a *.tsx/*.jsx/Vue/
 *   Svelte/vite/react file — UNLESS its path marks it as a server handler
 *   (app/api/**, pages/api/**, functions/**, server/**, or a *.server.* file, an
 *   Express/Fastify route, or a Next.js route handler). Anything a leaked secret
 *   in the client tree = shipped to every visitor's browser.
 */
import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";

type Hit = { file: string; line: number; preview: string };

// ─── Shared helpers (mirror emerging-supply-ai.ts style) ─────────────────────

async function allSearch(query: string): Promise<Hit[]> {
  try {
    return await searchRepo({ query, isRegex: true, maxMatches: 200 });
  } catch {
    // A malformed/over-complex query or a scan error must never crash the gate.
    return [];
  }
}

function toEvidence(hits: Hit[]): string[] {
  return hits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`);
}
function toFiles(hits: Hit[]): string[] {
  return [...new Set(hits.slice(0, 10).map((m) => m.file))];
}

// A path that is a SERVER handler / server-only module. A secret here is bad but
// not automatically browser-exposed, so the client-tree rules exclude it.
const SERVER_PATH_RE =
  /(?:^|\/)(?:app\/api|pages\/api|src\/app\/api|src\/pages\/api|functions|netlify\/functions|supabase\/functions|api|server|backend|routes?|middleware)\//i;
const SERVER_FILE_RE = /\.server\.(?:ts|tsx|js|jsx|mjs|cjs)$/i;
const NEXT_ROUTE_HANDLER_RE = /(?:^|\/)route\.(?:ts|tsx|js|jsx|mjs)$/i;

/** True when the file is browser-shipped client code (not a server handler). */
function isClientTree(file: string): boolean {
  if (SERVER_PATH_RE.test(file)) return false;
  if (SERVER_FILE_RE.test(file)) return false;
  if (NEXT_ROUTE_HANDLER_RE.test(file)) return false;
  // Browser-shipped surfaces: framework component/page files, or a *.tsx/*.jsx/
  // Vue/Svelte file, or anything under a conventional client source directory.
  if (/\.(?:tsx|jsx|vue|svelte)$/i.test(file)) return true;
  if (/(?:^|\/)(?:src|app|pages|components|public|client|frontend|ui|views)\//i.test(file)) return true;
  return false;
}

// Server handler file globs (used by the API-authz rule to enumerate handlers).
const SERVER_HANDLER_GLOBS = [
  "**/app/**/route.ts",
  "**/app/**/route.tsx",
  "**/app/**/route.js",
  "**/app/**/route.mjs",
  "**/src/app/**/route.ts",
  "**/src/app/**/route.js",
  "**/pages/api/**/*.ts",
  "**/pages/api/**/*.js",
  "**/src/pages/api/**/*.ts",
  "**/functions/**/*.ts",
  "**/functions/**/*.js",
  "**/netlify/functions/**/*.ts",
  "**/netlify/functions/**/*.js",
  "**/supabase/functions/**/*.ts",
  "**/server/**/*.ts",
  "**/server/**/*.js",
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. VIBE_SUPABASE_SERVICE_ROLE_IN_CLIENT (CWE-522 / CWE-269 — Insufficiently
//    Protected Credentials / Improper Privilege Management)
//
// Supabase's `service_role` key (and the newer `sb_secret_...` secret key) bypass
// Row-Level Security entirely — it is a full-database god-mode credential meant
// to live ONLY on a server. AI tools frequently paste it into a browser-shipped
// client (the Moltbook breach). Any of these in the client tree is CRITICAL:
//   • the literal string "service_role"
//   • an `sb_secret_...` secret key literal
//   • a JWT-looking constant sitting next to the words "service_role" (decode-free
//     heuristic — a service-role JWT carries `"role":"service_role"` in its body).
// ─────────────────────────────────────────────────────────────────────────────

async function checkSupabaseServiceRoleInClient(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();

    // (a) literal "service_role" appearing in browser-shipped code.
    const roleHits = (await allSearch(String.raw`service_role`)).filter((h) => isClientTree(h.file));
    for (const h of roleHits) {
      evidence.push(`${h.file}:${h.line}: "service_role" referenced in client-shipped code`);
      files.add(h.file);
    }

    // (b) an sb_secret_... secret key literal in the client tree.
    const secretKeyHits = (await allSearch(String.raw`sb_secret_[A-Za-z0-9]{10,}`)).filter((h) =>
      isClientTree(h.file)
    );
    for (const h of secretKeyHits) {
      evidence.push(`${h.file}:${h.line}: Supabase secret key (sb_secret_…) literal in client-shipped code`);
      files.add(h.file);
    }

    // (c) decode-free heuristic: a JWT-looking literal near the string
    //     "service_role" on the same line (e.g. a hardcoded service-role JWT).
    const jwtNearRole = (await allSearch(
      String.raw`service_role[\s\S]{0,80}eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}`
    )).filter((h) => isClientTree(h.file));
    for (const h of jwtNearRole) {
      evidence.push(`${h.file}:${h.line}: JWT literal adjacent to "service_role" — likely a hardcoded service-role token`);
      files.add(h.file);
    }

    if (evidence.length === 0) return null;
    return {
      id: "VIBE_SUPABASE_SERVICE_ROLE_IN_CLIENT",
      title: "Supabase service_role / sb_secret_ god-mode key shipped in client-side code — full database bypass of Row-Level Security (CWE-522/CWE-269)",
      severity: "CRITICAL",
      sla: "24h",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "The service_role / sb_secret_ key bypasses Row-Level Security and grants full read/write to every table. Shipped to the browser it is public to every visitor (the Moltbook breach). Rotate it NOW in the Supabase dashboard (Settings → API → generate new service_role / secret key).",
        "Delete the key from all client-tree files. Move any code that legitimately needs it (admin tasks, webhooks) into a server route / Edge Function that reads it from a server-only env var, and have the browser call THAT endpoint.",
        "In the browser use ONLY the anon/publishable key, and enforce access with Row-Level Security policies — never the service_role key."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. VIBE_PUBLIC_ENV_HOLDS_SECRET (CWE-798 — Use of Hard-coded Credentials)
//
// Framework "public" env prefixes (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_,
// PUBLIC_) are INLINED into the browser bundle at build time. Naming a real secret
// with one of these prefixes ships it to every visitor. AI tools do this constantly
// because "it made the value reach the frontend". We flag a public-prefixed var
// whose name says SECRET/SERVICE_ROLE/PRIVATE/PASSWORD/_KEY/API_KEY/TOKEN — while
// excluding names that are legitimately public (PUBLISHABLE/ANON, and a Stripe
// PUBLIC_KEY publishable key).
// ─────────────────────────────────────────────────────────────────────────────

// Tight regex: one public prefix, then an uppercase name ending in a secret-y word.
const PUBLIC_SECRET_ENV_RE =
  /(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|_KEY|API_KEY|TOKEN)/;
// Names that are legitimately public even though they contain _KEY etc.
const PUBLISHABLE_ALLOW_RE = /PUBLISHABLE|ANON|PUBLIC_KEY|CLIENT_KEY|MAPS?_KEY|MAPBOX|RECAPTCHA|SENTRY_DSN|POSTHOG|CLERK_PUBLISHABLE/i;

async function checkPublicEnvHoldsSecret(): Promise<Finding | null> {
  try {
    const hits = await allSearch(
      String.raw`(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|_KEY|API_KEY|TOKEN)`
    );
    const offending = hits.filter((h) => {
      const m = PUBLIC_SECRET_ENV_RE.exec(h.preview);
      if (!m) return false;
      // Suppress obvious publishable/anon names.
      return !PUBLISHABLE_ALLOW_RE.test(m[0]);
    });
    if (offending.length === 0) return null;

    return {
      id: "VIBE_PUBLIC_ENV_HOLDS_SECRET",
      title: "A build-time PUBLIC_ env var (NEXT_PUBLIC_/VITE_/REACT_APP_/EXPO_PUBLIC_/PUBLIC_) holds a secret — inlined into the browser bundle (CWE-798)",
      severity: "CRITICAL",
      sla: "24h",
      evidence: toEvidence(offending),
      files: toFiles(offending),
      requiredActions: [
        "A *_PUBLIC_ / VITE_ / REACT_APP_ / EXPO_PUBLIC_ variable is compiled into the client JavaScript — its value is visible to every visitor. Rotate this credential immediately; treat it as already leaked.",
        "Rename the variable to drop the public prefix (e.g. NEXT_PUBLIC_STRIPE_SECRET_KEY → STRIPE_SECRET_KEY) and read it only in a server route / Server Action / Edge Function; expose to the browser only via a server endpoint that uses it.",
        "Reserve public-prefixed vars for values that are genuinely safe to publish (publishable/anon keys, DSNs). Add a build check that fails if a *_PUBLIC_ var name contains SECRET/PRIVATE/PASSWORD/SERVICE_ROLE."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. VIBE_PROVIDER_KEY_IN_FRONTEND (CWE-798 — Use of Hard-coded Credentials)
//
// A raw AI/cloud/payment provider key literal committed into browser-shipped code.
// AI scaffolds often hardcode the key "so it works" instead of proxying through a
// server. We identify the provider and TRUNCATE the key in evidence (never echo a
// usable secret). Client-tree only, so pure server config is not flagged here.
// ─────────────────────────────────────────────────────────────────────────────

const PROVIDER_KEY_PATTERNS: Array<{ provider: string; re: RegExp }> = [
  { provider: "Anthropic API key",  re: /sk-ant-[A-Za-z0-9_-]{80,}/ },
  { provider: "OpenAI API key",     re: /sk-(?:proj-)?[A-Za-z0-9]{40,}/ },
  { provider: "Stripe live secret", re: /sk_live_[0-9a-zA-Z]{24,}/ },
  { provider: "AWS access key ID",  re: /AKIA[0-9A-Z]{16}/ },
  { provider: "Google API key",     re: /AIza[0-9A-Za-z_-]{35}/ },
  { provider: "GitHub PAT",         re: /ghp_[A-Za-z0-9]{36}/ },
];

/** Show only enough of a key to identify it; never echo a usable secret. */
function truncateKey(raw: string): string {
  const s = raw.trim();
  if (s.length <= 12) return s.slice(0, 4) + "…";
  return `${s.slice(0, 8)}…${s.slice(-4)} (${s.length} chars)`;
}

async function checkProviderKeyInFrontend(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();
    const providers = new Set<string>();

    for (const { provider, re } of PROVIDER_KEY_PATTERNS) {
      // Build the search from the pattern source (case-insensitive search engine
      // is fine; we anchor provider identity via the source string).
      const hits = (await allSearch(re.source)).filter((h) => isClientTree(h.file));
      for (const h of hits) {
        const m = re.exec(h.preview);
        // The search preview may already be [REDACTED] by the engine; if we can't
        // re-extract a raw key we still report the location + provider only.
        const shown = m ? truncateKey(m[0]) : "[redacted by scanner]";
        evidence.push(`${h.file}:${h.line}: ${provider} literal in client-shipped code — ${shown}`);
        files.add(h.file);
        providers.add(provider);
        if (evidence.length >= 10) break;
      }
      if (evidence.length >= 10) break;
    }

    if (evidence.length === 0) return null;
    return {
      id: "VIBE_PROVIDER_KEY_IN_FRONTEND",
      title: `Provider API key (${[...providers].slice(0, 3).join(", ")}) hardcoded in client-side code — public to every visitor (CWE-798)`,
      severity: "CRITICAL",
      sla: "24h",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        `Rotate the exposed key(s) immediately in the provider dashboard — anything shipped in a browser bundle is compromised. Providers found: ${[...providers].join(", ")}.`,
        "Never call a paid AI/cloud/payment API directly from the browser with a real secret key. Move the call behind a server route / Edge Function that holds the key in a server-only env var, and have the frontend call your endpoint.",
        "Add a secret-scanning pre-commit hook (gitleaks) so raw provider keys cannot be committed again."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. VIBE_SUPABASE_RLS_DISABLED (CWE-862 — Missing Authorization)
//
// In Postgres/Supabase, a table with data is only safe if Row-Level Security is
// enabled AND has a restrictive policy. AI-generated migrations routinely:
//   • CREATE TABLE but never `ENABLE ROW LEVEL SECURITY` (anon key reads all rows), or
//   • add `CREATE POLICY ... USING (true)` — a policy that allows everyone.
// Lovable's generated apps shipped exactly this (CVE-2025-48757). We scan *.sql
// and supabase/migrations/**. CRITICAL.
// ─────────────────────────────────────────────────────────────────────────────

const SQL_GLOBS = ["**/*.sql", "**/supabase/migrations/**", "**/migrations/**/*.sql"];

async function checkSupabaseRlsDisabled(): Promise<Finding | null> {
  try {
    let sqlFiles: string[] = [];
    try {
      sqlFiles = await fg(SQL_GLOBS, { dot: true, onlyFiles: true, followSymbolicLinks: false });
    } catch {
      return null;
    }
    if (sqlFiles.length === 0) return null;

    const evidence: string[] = [];
    const files = new Set<string>();

    const CREATE_TABLE_RE = /create\s+table\s+(?:if\s+not\s+exists\s+)?["'`]?([A-Za-z0-9_."]+)/gi;
    const ENABLE_RLS_RE = /enable\s+row\s+level\s+security/i;
    // Permissive policy: USING (true) with optional whitespace/parens.
    const PERMISSIVE_POLICY_RE = /create\s+policy[\s\S]{0,200}?using\s*\(\s*true\s*\)/i;

    for (const file of sqlFiles) {
      let sql = "";
      try {
        sql = await readFileSafe(file);
      } catch {
        continue;
      }

      // (a) any CREATE TABLE with no ENABLE ROW LEVEL SECURITY anywhere in the file.
      const enablesRls = ENABLE_RLS_RE.test(sql);
      CREATE_TABLE_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      const tables: string[] = [];
      while ((m = CREATE_TABLE_RE.exec(sql)) !== null) {
        // Skip system/temp tables that are not user data surfaces.
        const name = (m[1] || "").replace(/["'`]/g, "");
        if (/^pg_|^information_schema|temp|temporary/i.test(name)) continue;
        tables.push(name);
      }
      if (tables.length > 0 && !enablesRls) {
        evidence.push(
          `${file}: CREATE TABLE (${tables.slice(0, 3).join(", ")}${tables.length > 3 ? ", …" : ""}) with no ENABLE ROW LEVEL SECURITY in the file`
        );
        files.add(file);
      }

      // (b) a permissive USING (true) policy anywhere in the file.
      if (PERMISSIVE_POLICY_RE.test(sql)) {
        evidence.push(`${file}: CREATE POLICY ... USING (true) — policy grants access to everyone`);
        files.add(file);
      }

      if (evidence.length >= 10) break;
    }

    if (evidence.length === 0) return null;
    return {
      id: "VIBE_SUPABASE_RLS_DISABLED",
      title: "Supabase/Postgres table without Row-Level Security, or a permissive USING (true) policy — anyone with the anon key reads/writes all rows (CWE-862, CVE-2025-48757)",
      severity: "CRITICAL",
      sla: "24h",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "For every table holding user or private data, enable RLS: `ALTER TABLE public.<table> ENABLE ROW LEVEL SECURITY;` — without it, the public anon key can read and write every row (Lovable CVE-2025-48757).",
        "Replace any `USING (true)` policy with a real ownership check, e.g. `CREATE POLICY owner_can_read ON public.<table> FOR SELECT USING (auth.uid() = user_id);` and add matching INSERT/UPDATE/DELETE policies.",
        "Add a migration test / CI assertion that fails if any table in a public schema has RLS disabled or a policy whose qualifier is literally `true`."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. VIBE_FIREBASE_RULES_PUBLIC (CWE-306 — Missing Authentication for a Critical
//    Function)
//
// Firebase security rules are the ONLY thing standing between the public web SDK
// and your data. A rule that allows read/write to `true` makes the whole database
// or bucket world-accessible. This is the Tea app breach. We scan firestore.rules,
// database.rules.json, and storage.rules for:
//   • JSON RTDB rules: `".read"/".write": true`
//   • Firestore/Storage rules: `allow read/write/…: if true`
// ─────────────────────────────────────────────────────────────────────────────

const FIREBASE_RULES_GLOBS = [
  "**/firestore.rules",
  "**/storage.rules",
  "**/database.rules.json",
  "**/*.rules",
];

// RTDB JSON form: ".read": true  (quotes optional around the boolean).
const RTDB_PUBLIC_RE = /"\.(?:read|write)"\s*:\s*"?true"?/i;
// Firestore/Storage form: allow read: if true;  (verb list, then `if true`).
const FIRESTORE_PUBLIC_RE = /allow\s+(?:read|write|create|update|delete|list|get)[^:]*:\s*if\s+true/i;

async function checkFirebaseRulesPublic(): Promise<Finding | null> {
  try {
    let ruleFiles: string[] = [];
    try {
      ruleFiles = await fg(FIREBASE_RULES_GLOBS, { dot: true, onlyFiles: true, followSymbolicLinks: false });
    } catch {
      return null;
    }
    if (ruleFiles.length === 0) return null;

    const evidence: string[] = [];
    const files = new Set<string>();

    for (const file of ruleFiles) {
      let text = "";
      try {
        text = await readFileSafe(file);
      } catch {
        continue;
      }
      const lines = text.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (RTDB_PUBLIC_RE.test(line) || FIRESTORE_PUBLIC_RE.test(line)) {
          evidence.push(`${file}:${i + 1}: ${line.trim().slice(0, 160)}`);
          files.add(file);
          if (evidence.length >= 10) break;
        }
      }
      if (evidence.length >= 10) break;
    }

    if (evidence.length === 0) return null;
    return {
      id: "VIBE_FIREBASE_RULES_PUBLIC",
      title: "Firebase security rules allow public read/write (`.read/.write: true` or `allow …: if true`) — database/bucket is world-accessible (CWE-306)",
      severity: "CRITICAL",
      sla: "24h",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "A rule that evaluates to `true` makes the whole database/bucket readable and writable by anyone on the internet (the Tea app breach). Replace it with an auth + ownership check, e.g. Firestore `allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;`.",
        "For Realtime Database, remove `\".read\": true` / `\".write\": true` and scope with `\"auth != null\"` plus per-node ownership rules; for Storage require `request.auth != null` and validate the path prefix.",
        "Deploy the tightened rules (`firebase deploy --only firestore:rules,storage`), then add App Check and a rules unit test (firebase emulators) asserting that an unauthenticated client is denied."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. VIBE_API_ROUTE_NO_SERVER_AUTHZ (CWE-306 / CWE-862 — Missing Authentication /
//    Authorization)
//
// The Base44 pattern: the frontend "checks auth" but the API endpoints do not, so
// a request sent straight to the API returns everyone's data. We enumerate server
// handler files, and flag any that read request input (req.body/req.query/params/
// searchParams) or do a DB call but contain NO recognisable server-side auth
// verifier. HIGH.
// ─────────────────────────────────────────────────────────────────────────────

// Reads user input or does a DB call — i.e. the handler actually does something.
const HANDLER_DOES_WORK_RE =
  /req\.(?:body|query|params)|request\.(?:json|formData)\s*\(|searchParams|params\.[A-Za-z]|\.(?:from|select|insert|update|delete|findMany|findUnique|findFirst|create|query|aggregate)\s*\(|prisma\.|supabase\.|db\./;
// Any recognised server-side auth/identity verifier.
const HANDLER_HAS_AUTH_RE =
  /getServerSession|auth\s*\(|verifyToken|requireAuth|getUser\s*\(|jwt\.verify|clerk|withApiAuth|getToken|authenticate|getAuth\s*\(|currentUser|createServerClient[\s\S]{0,200}auth|supabase[\s\S]{0,60}auth\.getUser|next-auth/i;
// A handler explicitly marked public is intentional — don't flag it.
const HANDLER_PUBLIC_MARK_RE = /\/\/\s*PUBLIC(?:\s+ROUTE)?|public\s*:\s*true|allowUnauthenticated|webhook/i;

async function checkApiRouteNoServerAuthz(): Promise<Finding | null> {
  try {
    let handlers: string[] = [];
    try {
      handlers = await fg(SERVER_HANDLER_GLOBS, { dot: true, onlyFiles: true, followSymbolicLinks: false });
    } catch {
      return null;
    }
    if (handlers.length === 0) return null;

    const offenders: string[] = [];
    for (const file of handlers) {
      let content = "";
      try {
        content = await readFileSafe(file);
      } catch {
        continue;
      }
      if (!HANDLER_DOES_WORK_RE.test(content)) continue; // trivial handler — skip
      if (HANDLER_HAS_AUTH_RE.test(content)) continue; // has an auth verifier — ok
      if (HANDLER_PUBLIC_MARK_RE.test(content)) continue; // intentionally public
      offenders.push(`${file}: reads request input / hits the DB but has no server-side auth check`);
      if (offenders.length >= 15) break;
    }

    if (offenders.length === 0) return null;
    return {
      id: "VIBE_API_ROUTE_NO_SERVER_AUTHZ",
      title: "API route handler reads user input / queries the DB without any server-side authorization — data returned to anyone who calls the endpoint (CWE-306/CWE-862)",
      severity: "HIGH",
      sla: "7d",
      evidence: offenders.slice(0, 10),
      files: [...new Set(offenders.map((o) => o.split(":")[0]))].slice(0, 10),
      requiredActions: [
        "The frontend hiding a button is NOT authorization — an attacker calls the API directly (the Base44 breach). Verify the caller at the top of every handler: `const session = await getServerSession(...); if (!session) return new Response('Unauthorized', { status: 401 });`.",
        "After authenticating, authorize the specific object: confirm the session user owns or may access the requested record before returning it (prevents IDOR), e.g. `where: { id, userId: session.user.id }`.",
        "If an endpoint is genuinely public (health check, webhook), mark it with a `// PUBLIC ROUTE` comment and, for webhooks, verify the provider signature instead of a session."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. VIBE_CLIENT_SIDE_AUTH_GUARD_ONLY (CWE-602 — Client-Side Enforcement of
//    Server-Side Security)
//
// A guard like `if (!user) router.push('/login')` in a client component only hides
// UI — it runs in the attacker's browser and can be bypassed (disable JS, call the
// API directly, edit the redirect). It is a UX nicety, never a security control.
// We flag client-tree files where the ONLY thing protecting a view is this pattern.
// HIGH (insufficient alone).
// ─────────────────────────────────────────────────────────────────────────────

async function checkClientSideAuthGuardOnly(): Promise<Finding | null> {
  try {
    // `if (!user/session/isAuthenticated/isAdmin) <redirect|router.push|Navigate|return null>`.
    const hits = await allSearch(
      String.raw`if\s*\(\s*!\s*(?:user|session|isAuthenticated|isLoggedIn|isAdmin|currentUser)\b[^)]{0,40}\)[\s\S]{0,80}(?:redirect\s*\(|router\.(?:push|replace)\s*\(|<Navigate\b|return\s+null)`
    );
    const clientHits = hits.filter((h) => isClientTree(h.file));
    if (clientHits.length === 0) return null;

    return {
      id: "VIBE_CLIENT_SIDE_AUTH_GUARD_ONLY",
      title: "Access control enforced only by a client-side guard (redirect / return null) — trivially bypassable, not a security control (CWE-602)",
      severity: "HIGH",
      sla: "7d",
      evidence: toEvidence(clientHits),
      files: toFiles(clientHits),
      requiredActions: [
        "A client-side `if (!user) redirect(...)` runs in the attacker's browser and can be skipped (disable JS, hit the API directly). Keep it for UX, but enforce the real check on the server: gate the page in a Server Component / middleware and gate the data in the API route.",
        "Every endpoint the protected page calls must independently verify the session and the user's authorization for the specific resource — never assume the client already checked.",
        "Add a test that requests the protected route/API unauthenticated and asserts a 401/redirect rather than data."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. VIBE_CORS_WILDCARD_CREDENTIALS (CWE-942 — Permissive Cross-domain Policy)
//
// `cors()` with no options, or `origin: '*'`/`origin: true` combined with
// `credentials: true`, lets any website make authenticated cross-origin requests
// with the victim's cookies — reading their data. AI scaffolds add `app.use(cors())`
// "to fix a CORS error" without understanding the consequence. HIGH.
// ─────────────────────────────────────────────────────────────────────────────

async function checkCorsWildcardCredentials(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();

    // (a) bare app.use(cors()) — reflects the request origin AND allows credentials.
    const bareHits = await allSearch(String.raw`\.use\s*\(\s*cors\s*\(\s*\)\s*\)`);
    for (const h of bareHits) {
      evidence.push(`${h.file}:${h.line}: app.use(cors()) with no options — reflects any origin`);
      files.add(h.file);
    }

    // (b) origin:'*' or origin:true together with credentials:true (same config).
    const credHits = await allSearch(
      String.raw`(?:origin\s*:\s*(?:['"]\*['"]|true)[\s\S]{0,120}credentials\s*:\s*true|credentials\s*:\s*true[\s\S]{0,120}origin\s*:\s*(?:['"]\*['"]|true))`
    );
    for (const h of credHits) {
      evidence.push(`${h.file}:${h.line}: wildcard/reflected origin combined with credentials:true`);
      files.add(h.file);
    }

    if (evidence.length === 0) return null;
    return {
      id: "VIBE_CORS_WILDCARD_CREDENTIALS",
      title: "Permissive CORS — bare cors(), or origin '*'/true with credentials:true — any site can make authenticated cross-origin requests (CWE-942)",
      severity: "HIGH",
      sla: "7d",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "Replace the wildcard/reflected origin with an explicit allowlist: `cors({ origin: ['https://app.example.com'], credentials: true })`. A reflected origin plus credentials lets any malicious site read your users' authenticated responses.",
        "Never combine `origin: '*'` (or `origin: true`, which reflects the caller) with `credentials: true`; if you don't need cookies cross-origin, drop credentials instead of widening origin.",
        "Drive the allowlist from an env var per environment and reject unknown origins with no CORS headers (the browser then blocks the response)."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. VIBE_CLIENT_CONTROLLED_PRICE (CWE-807 — Reliance on Untrusted Inputs in a
//    Security Decision)
//
// Trusting the price/amount/total from the request body means a user can pay $0.01
// for a $100 item by editing the request. AI-built checkout flows pass the client's
// amount straight to the payment API. We flag an amount/price/total assigned from
// req.body/req.query (and Stripe amounts built from request input). HIGH.
// ─────────────────────────────────────────────────────────────────────────────

async function checkClientControlledPrice(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();

    // (a) amount/price/total/cost/unit_amount taken directly from request input.
    const assignHits = await allSearch(
      String.raw`(?:amount|price|total|cost|unit_amount|unitAmount)\s*[:=]\s*req\.(?:body|query)\.`
    );
    for (const h of assignHits) {
      evidence.push(`${h.file}:${h.line}:${h.preview}`);
      files.add(h.file);
    }

    // (b) a Stripe amount field fed from request input (line_items / paymentIntent).
    const stripeHits = await allSearch(
      String.raw`(?:unit_amount|amount)\s*:\s*[^,}\n]{0,40}req\.(?:body|query)\.`
    );
    for (const h of stripeHits) {
      const key = `${h.file}:${h.line}`;
      if (evidence.some((e) => e.startsWith(key))) continue;
      evidence.push(`${h.file}:${h.line}:${h.preview}`);
      files.add(h.file);
    }

    if (evidence.length === 0) return null;
    return {
      id: "VIBE_CLIENT_CONTROLLED_PRICE",
      title: "Payment amount/price taken from the request body/query — user can set their own price (CWE-807)",
      severity: "HIGH",
      sla: "7d",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "Never trust a price/amount/total sent by the client. Look up the authoritative price server-side by product ID: `const price = await db.product.findUnique({ where: { id } }).price;` and charge THAT, ignoring any amount in the request.",
        "For Stripe, build `line_items` / `PaymentIntent.amount` from server-side prices (or use Stripe Price IDs / Checkout with fixed prices), not from `req.body.amount`.",
        "Validate quantity and currency server-side too, and reconcile the final charged amount in the webhook before fulfilling the order."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. VIBE_TOKEN_IN_LOCALSTORAGE (CWE-522 — Insufficiently Protected Credentials)
//
// Storing a JWT / session / API key in localStorage exposes it to any XSS on the
// page: JavaScript can read localStorage, so one injected script exfiltrates every
// user's token. httpOnly cookies are the safe alternative. HIGH.
// ─────────────────────────────────────────────────────────────────────────────

async function checkTokenInLocalStorage(): Promise<Finding | null> {
  try {
    const hits = await allSearch(
      String.raw`localStorage\.setItem\s*\(\s*['"](?:token|jwt|access_token|accessToken|auth|authToken|session|apiKey|api_key|refresh|refreshToken)`
    );
    if (hits.length === 0) return null;
    return {
      id: "VIBE_TOKEN_IN_LOCALSTORAGE",
      title: "Auth token / API key stored in localStorage — readable by any XSS on the page (CWE-522)",
      severity: "HIGH",
      sla: "7d",
      evidence: toEvidence(hits),
      files: toFiles(hits),
      requiredActions: [
        "Stop storing tokens in localStorage — any injected script can read them. Store the session in an httpOnly, Secure, SameSite cookie set by the server so JavaScript (and therefore XSS) cannot read it.",
        "If you must keep a token in the SPA, hold it only in memory (a variable / React state) for the tab's lifetime and re-fetch via a refresh cookie on reload — never persist it to localStorage/sessionStorage.",
        "Add a strict Content-Security-Policy to reduce XSS reach, and rotate any long-lived token that has been stored client-side."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. VIBE_UNRESTRICTED_FILE_UPLOAD (CWE-434 — Unrestricted Upload of File with
//     Dangerous Type)
//
// A `multer(...)` upload with no `fileFilter` and no `limits`, or an upload handler
// with no extension/MIME allowlist, lets an attacker upload a web shell or an
// oversized file (DoS). AI scaffolds add the happy-path upload and stop there. HIGH.
// ─────────────────────────────────────────────────────────────────────────────

async function checkUnrestrictedFileUpload(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();

    // Files that use multer — inspect the whole file for fileFilter/limits.
    const multerHits = await allSearch(String.raw`\bmulter\s*\(`);
    const multerFiles = [...new Set(multerHits.map((h) => h.file))];
    for (const file of multerFiles) {
      let content = "";
      try {
        content = await readFileSafe(file);
      } catch {
        continue;
      }
      const hasFilter = /fileFilter\s*:/.test(content);
      const hasLimits = /limits\s*:/.test(content);
      const hasAllowlist = /(?:allowed(?:Mime)?Types|mimetype\s*(?:===|==|\.match|\.includes)|\bextname\b|\.(?:png|jpe?g|pdf|gif|webp)\b['"]?\s*[,\])])/i.test(content);
      if (!hasFilter && !hasLimits && !hasAllowlist) {
        evidence.push(`${file}: multer() upload with no fileFilter, no limits, and no MIME/extension allowlist`);
        files.add(file);
      }
    }

    // Generic upload handlers with no allowlist in the same file.
    const uploadHits = await allSearch(
      String.raw`\.(?:single|array|fields|any)\s*\(\s*['"][A-Za-z0-9_]+['"]\s*\)|upload\.(?:single|array|any)\b|formidable\s*\(`
    );
    for (const h of uploadHits) {
      if (files.has(h.file)) continue;
      let content = "";
      try {
        content = await readFileSafe(h.file);
      } catch {
        continue;
      }
      const hasAllowlist =
        /(?:allowed(?:Mime)?Types|mimetype\s*(?:===|==|\.match|\.includes)|\bextname\b|fileFilter\s*:|limits\s*:)/i.test(content);
      if (!hasAllowlist) {
        evidence.push(`${h.file}:${h.line}: file upload handler with no extension/MIME allowlist or size limit`);
        files.add(h.file);
      }
      if (evidence.length >= 10) break;
    }

    if (evidence.length === 0) return null;
    return {
      id: "VIBE_UNRESTRICTED_FILE_UPLOAD",
      title: "File upload with no type/size restriction — web-shell upload and DoS risk (CWE-434)",
      severity: "HIGH",
      sla: "7d",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "Add a `fileFilter` that allowlists expected MIME types (and verify by content/magic bytes, not just the client-sent Content-Type), and reject everything else: `multer({ fileFilter, limits: { fileSize: 5 * 1024 * 1024 } })`.",
        "Set `limits.fileSize` (and `limits.files`) to bound uploads so a large file cannot exhaust disk/memory.",
        "Store uploads outside the web root (or in object storage) with a generated random filename, never serve them from a path the user controls, and never execute uploaded files."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. VIBE_ENV_FILE_COMMITTED (CWE-540 — Inclusion of Sensitive Information in
//     Source Code)
//
// A tracked .env / serviceAccount*.json / *.pem / id_rsa that is present on disk
// and NOT covered by .gitignore is (almost certainly) committed — leaking every
// secret in it. We read .gitignore, and for each sensitive file present on disk we
// flag it unless a .gitignore rule ignores it. HIGH.
// ─────────────────────────────────────────────────────────────────────────────

const SENSITIVE_FILE_GLOBS = [
  "**/.env",
  "**/.env.local",
  "**/.env.production",
  "**/.env.production.local",
  "**/.env.development.local",
  "**/serviceAccount*.json",
  "**/service-account*.json",
  "**/*.pem",
  "**/id_rsa",
  "**/id_dsa",
  "**/id_ecdsa",
  "**/id_ed25519",
];

/** Very small .gitignore matcher: does any non-negated pattern cover this path? */
function gitignoreCovers(patterns: string[], relPath: string): boolean {
  const base = relPath.split("/").pop() ?? relPath;
  let covered = false;
  for (const raw of patterns) {
    const p = raw.trim();
    if (!p || p.startsWith("#")) continue;
    const negated = p.startsWith("!");
    const pat = negated ? p.slice(1) : p;
    const clean = pat.replace(/^\/+/, "").replace(/\/+$/, "");
    if (!clean) continue;
    // Match on basename equality, a *.ext glob, or a substring path segment match.
    let matches = false;
    if (clean === base || clean === relPath) matches = true;
    else if (clean.startsWith("*.") && base.endsWith(clean.slice(1))) matches = true;
    else if (clean.includes("*")) {
      // Turn a simple glob into a regex against the basename.
      const re = new RegExp("^" + clean.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*") + "$");
      if (re.test(base)) matches = true;
    } else if (relPath === clean || relPath.startsWith(clean + "/") || relPath.endsWith("/" + clean)) {
      matches = true;
    }
    if (matches) covered = !negated; // a later negation can re-include the file
  }
  return covered;
}

async function checkEnvFileCommitted(): Promise<Finding | null> {
  try {
    let sensitive: string[] = [];
    try {
      sensitive = await fg(SENSITIVE_FILE_GLOBS, { dot: true, onlyFiles: true, followSymbolicLinks: false });
    } catch {
      return null;
    }
    // Do not flag env EXAMPLE/template files — those are meant to be committed.
    sensitive = sensitive.filter((f) => !/\.(?:example|sample|template|dist)$/i.test(f) && !/\.env\.(?:example|sample|template)$/i.test(f));
    if (sensitive.length === 0) return null;

    // Read the root .gitignore (best effort). If there is none, everything on disk
    // is presumed tracked.
    let gitignore: string[] = [];
    try {
      const raw = await readFileSafe(".gitignore");
      gitignore = raw.split("\n");
    } catch {
      gitignore = [];
    }

    const offenders = sensitive.filter((f) => !gitignoreCovers(gitignore, f));
    if (offenders.length === 0) return null;

    return {
      id: "VIBE_ENV_FILE_COMMITTED",
      title: "Sensitive file (.env / serviceAccount.json / *.pem / id_rsa) present and not gitignored — secrets likely committed to source control (CWE-540)",
      severity: "HIGH",
      sla: "7d",
      evidence: offenders.slice(0, 10).map((f) => `${f}: sensitive file present on disk and not matched by .gitignore`),
      files: offenders.slice(0, 10),
      requiredActions: [
        "Assume every secret in these files is compromised and rotate them now (DB passwords, API keys, private keys, service-account credentials).",
        "Add the file(s) to .gitignore (e.g. `.env*`, `*.pem`, `serviceAccount*.json`, `id_rsa`), remove them from the index (`git rm --cached <file>`), and commit — .gitignore does not untrack an already-tracked file.",
        "Purge them from git history (git-filter-repo or BFG), force-push, and have collaborators re-clone; keep only a committed `.env.example` with placeholder values."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. VIBE_SOURCEMAPS_IN_PROD (CWE-540 — Inclusion of Sensitive Information in
//     Source Code)
//
// Shipping source maps to production publishes your original (unminified) source,
// including comments and sometimes inlined secrets, to anyone with dev-tools.
// `productionBrowserSourceMaps: true` (Next) or `sourcemap: true` in a vite build.
// MEDIUM.
// ─────────────────────────────────────────────────────────────────────────────

async function checkSourceMapsInProd(): Promise<Finding | null> {
  try {
    const nextHits = await allSearch(String.raw`productionBrowserSourceMaps\s*:\s*true`);
    // vite build.sourcemap: true — restrict to config-looking files to avoid noise.
    const viteHits = (await allSearch(String.raw`sourcemap\s*:\s*true`)).filter((h) =>
      /(?:vite|rollup|build|webpack|next)\.config\.|vite\.config|\.config\.(?:ts|js|mjs|cjs)$/i.test(h.file)
    );
    const hits = [...nextHits, ...viteHits];
    if (hits.length === 0) return null;

    return {
      id: "VIBE_SOURCEMAPS_IN_PROD",
      title: "Production source maps enabled — original source (and any inlined secrets) published to the browser (CWE-540)",
      severity: "MEDIUM",
      sla: "30d",
      evidence: toEvidence(hits),
      files: toFiles(hits),
      requiredActions: [
        "Disable browser-served source maps in production: set `productionBrowserSourceMaps: false` (Next.js) or `build.sourcemap: false` (Vite) for prod builds.",
        "If you need source maps for error monitoring, generate them and upload privately to your error tracker (e.g. Sentry) instead of shipping them to the public bundle.",
        "Audit anything the exposed source revealed (internal endpoints, comments, keys) and rotate any secret that was visible."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. VIBE_DEBUG_MODE_ENABLED (CWE-489 — Active Debug Code)
//
// Debug mode in production exposes an interactive console / stack traces / config
// to attackers (Flask/Django debug=True is the classic RCE via the Werkzeug
// console PIN, and returning err.stack leaks internals). We flag debug=True,
// app.run(debug=True), DEBUG=True, Express errorhandler(), and err.stack in a
// response. HIGH.
// ─────────────────────────────────────────────────────────────────────────────

async function checkDebugModeEnabled(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();

    // Python/Flask/Django debug flags.
    const debugHits = await allSearch(String.raw`app\.run\s*\([^)]*debug\s*=\s*True|\bdebug\s*=\s*True|\bDEBUG\s*=\s*True`);
    for (const h of debugHits) {
      // Skip an obviously env-driven value like DEBUG = os.environ.get(...) == "True".
      if (/os\.environ|getenv|env\.|process\.env/i.test(h.preview)) continue;
      evidence.push(`${h.file}:${h.line}:${h.preview}`);
      files.add(h.file);
    }

    // Express errorhandler middleware (dev-only; leaks stack traces in prod).
    const errHandlerHits = await allSearch(String.raw`\berrorhandler\s*\(\s*\)|require\s*\(\s*['"]errorhandler['"]\s*\)`);
    for (const h of errHandlerHits) {
      evidence.push(`${h.file}:${h.line}: Express errorhandler() — returns stack traces to clients if used in production`);
      files.add(h.file);
    }

    // Returning err.stack in a response body.
    const stackHits = await allSearch(String.raw`res\.(?:send|json)\s*\([^)]{0,80}err(?:or)?\.stack`);
    for (const h of stackHits) {
      evidence.push(`${h.file}:${h.line}: error stack trace returned in the HTTP response`);
      files.add(h.file);
    }

    if (evidence.length === 0) return null;
    return {
      id: "VIBE_DEBUG_MODE_ENABLED",
      title: "Debug mode / stack-trace leakage enabled — interactive debugger or internal details exposed to attackers (CWE-489)",
      severity: "HIGH",
      sla: "7d",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "Never run with debug enabled in production. For Flask/Django drive it from the environment and default OFF: `app.run(debug=os.environ.get('FLASK_DEBUG') == '1')` / `DEBUG = os.environ.get('DJANGO_DEBUG') == 'True'`; Flask's Werkzeug debugger is a known remote-code-execution surface.",
        "Remove Express `errorhandler()` from the production pipeline; use a custom error handler that logs the stack server-side and returns a generic message + request ID to the client.",
        "Never put `err.stack` (or `err.message`) in a response body — return `{ error: 'Internal error', requestId }` and log the details internally (CWE-209)."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. VIBE_HALLUCINATED_OR_UNVETTED_DEP (CWE-1357 — Reliance on Insufficiently
//     Trustworthy Component)
//
// AI assistants sometimes "hallucinate" a package name that does not exist (or is
// a typo of a real one). Attackers pre-register those names ("slopsquatting").
// OFFLINE heuristic: a dependency declared in package.json / requirements.txt that
// does NOT appear anywhere in the lockfile is a candidate unvetted/hallucinated
// package — either never installed, or added by hand without resolution. This is a
// HEURISTIC signal, not proof. MEDIUM.
// ─────────────────────────────────────────────────────────────────────────────

async function checkHallucinatedOrUnvettedDep(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();

    // ── npm side ──────────────────────────────────────────────────────────────
    const pkgFiles = await fg(["**/package.json"], { dot: true, onlyFiles: true, followSymbolicLinks: false });
    for (const pkgFile of pkgFiles) {
      let raw = "";
      try {
        raw = await readFileSafe(pkgFile);
      } catch {
        continue;
      }
      let pkg: any;
      try {
        pkg = JSON.parse(raw);
      } catch {
        continue;
      }
      const deps = {
        ...(pkg.dependencies ?? {}),
        ...(pkg.devDependencies ?? {}),
        ...(pkg.optionalDependencies ?? {}),
      };
      const names = Object.keys(deps).filter((n) => typeof n === "string");
      if (names.length === 0) continue;

      // Read the sibling lockfile(s) as text and check for each name's presence.
      const dir = pkgFile.replace(/package\.json$/i, "");
      let lockText = "";
      for (const lf of ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]) {
        try {
          lockText += "\n" + (await readFileSafe(dir + lf));
        } catch {
          /* missing lockfile variant — ignore */
        }
      }
      if (!lockText.trim()) {
        // No lockfile at all: cannot verify — surface once, not per-dependency.
        evidence.push(`${pkgFile}: declares ${names.length} dependencies but has no lockfile to resolve them against`);
        files.add(pkgFile);
        continue;
      }
      const missing = names.filter((n) => !lockText.includes(`"${n}"`) && !lockText.includes(`\n${n}@`) && !lockText.includes(`/${n}/`) && !lockText.includes(` ${n}:`));
      for (const n of missing.slice(0, 8)) {
        // Skip workspace-local names that resolve via file:/workspace:.
        const spec = String(deps[n] ?? "");
        if (/^(?:file:|link:|workspace:|portal:)/i.test(spec)) continue;
        evidence.push(`${pkgFile}: dependency "${n}" (${spec}) is not present in the lockfile — unresolved / possibly nonexistent`);
        files.add(pkgFile);
      }
    }

    // ── python side ───────────────────────────────────────────────────────────
    const reqFiles = await fg(["**/requirements*.txt"], { dot: true, onlyFiles: true, followSymbolicLinks: false });
    if (reqFiles.length > 0) {
      // A pinned lock: poetry.lock or a fully-pinned requirements.lock if present.
      let pyLock = "";
      for (const lf of ["poetry.lock", "requirements.lock", "Pipfile.lock"]) {
        const found = await fg([`**/${lf}`], { dot: true, onlyFiles: true, followSymbolicLinks: false }).catch(() => []);
        for (const p of found) {
          try {
            pyLock += "\n" + (await readFileSafe(p));
          } catch {
            /* ignore */
          }
        }
      }
      if (pyLock.trim()) {
        for (const reqFile of reqFiles) {
          let raw = "";
          try {
            raw = await readFileSafe(reqFile);
          } catch {
            continue;
          }
          const names = raw
            .split("\n")
            .map((l) => l.trim())
            .filter((l) => l && !l.startsWith("#") && !l.startsWith("-"))
            .map((l) => (l.split(/[=<>!~[; ]/)[0] || "").trim().toLowerCase())
            .filter(Boolean);
          const lockLower = pyLock.toLowerCase();
          const missing = [...new Set(names)].filter((n) => !lockLower.includes(n));
          for (const n of missing.slice(0, 8)) {
            evidence.push(`${reqFile}: package "${n}" is not present in the resolved lock (poetry.lock/Pipfile.lock) — unvetted / possibly nonexistent`);
            files.add(reqFile);
          }
        }
      }
    }

    if (evidence.length === 0) return null;
    return {
      id: "VIBE_HALLUCINATED_OR_UNVETTED_DEP",
      title: "Declared dependency missing from the lockfile — possible AI-hallucinated / unvetted package (slopsquatting risk) (CWE-1357)",
      severity: "MEDIUM",
      sla: "30d",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "This is a HEURISTIC, not proof. For each flagged package, verify it actually exists on the official registry (npmjs.com / pypi.org) and is the one you intended — AI tools sometimes invent plausible-but-nonexistent names that attackers then register (slopsquatting).",
        "Before installing, check the package's publisher, first-publish date, weekly downloads, and repository; be suspicious of a brand-new, low-download package with a name close to a popular one (typosquat).",
        "Once verified, install it so it is recorded in the lockfile and commit the lockfile; install with `npm ci` / `pip install -r ... --require-hashes` in CI so only lockfile-resolved packages are used."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. VIBE_PROMPT_INJECTION_UNSAFE_CHAIN (CWE-77 — Improper Neutralization of
//     Special Elements used in a Command)
//
// Two AI-app anti-patterns:
//   (a) untrusted user input concatenated into a system/instruction prompt (a
//       template literal with ${...user...} inside a role:'system' message context),
//       letting the user override the system instructions (prompt injection).
//   (b) model OUTPUT passed straight into eval/exec/a shell/dangerouslySetInnerHTML
//       — the LLM's text becomes code (indirect prompt injection → RCE/XSS).
// HIGH.
// ─────────────────────────────────────────────────────────────────────────────

async function checkPromptInjectionUnsafeChain(): Promise<Finding | null> {
  try {
    const evidence: string[] = [];
    const files = new Set<string>();

    // (a) user input interpolated into a system/instruction prompt string.
    const sysPromptHits = await allSearch(
      String.raw`(?:role\s*:\s*['"]system['"]|systemPrompt|system_prompt|instructions?)\s*[:=][\s\S]{0,120}\$\{[^}]{0,60}(?:user|input|message|query|prompt|req\.|body\.|params\.|searchParams)`
    );
    for (const h of sysPromptHits) {
      evidence.push(`${h.file}:${h.line}: user-controlled value interpolated into a system/instruction prompt`);
      files.add(h.file);
    }
    // Also the reverse order: a ${user...} template that then flows into system content.
    const sysPromptHits2 = await allSearch(
      String.raw`\$\{[^}]{0,60}(?:userInput|userMessage|userPrompt|user_input|req\.body|req\.query)[^}]{0,20}\}[\s\S]{0,80}(?:role\s*:\s*['"]system['"]|system(?:_|)prompt)`
    );
    for (const h of sysPromptHits2) {
      const key = `${h.file}:${h.line}`;
      if (evidence.some((e) => e.startsWith(key))) continue;
      evidence.push(`${h.file}:${h.line}: user-controlled value flows into a system prompt`);
      files.add(h.file);
    }

    // (b) model output passed into a dangerous sink.
    const sinkHits = await allSearch(
      String.raw`(?:eval|exec|execSync|spawn|spawnSync|Function|dangerouslySetInnerHTML)\s*[:(]\s*[^)]{0,80}(?:completion|response\.(?:choices|content|text|output)|message\.content|llmOutput|modelOutput|aiResponse|result\.(?:content|text)|choices\[0\])`
    );
    for (const h of sinkHits) {
      evidence.push(`${h.file}:${h.line}: model output passed into a code/HTML execution sink`);
      files.add(h.file);
    }

    if (evidence.length === 0) return null;
    return {
      id: "VIBE_PROMPT_INJECTION_UNSAFE_CHAIN",
      title: "User input concatenated into a system prompt, or model output fed into eval/exec/shell/dangerouslySetInnerHTML — prompt-injection to RCE/XSS (CWE-77)",
      severity: "HIGH",
      sla: "7d",
      evidence: evidence.slice(0, 10),
      files: [...files].slice(0, 10),
      requiredActions: [
        "Keep untrusted user text OUT of the system/instruction role. Put the fixed instructions in the system message and pass user text only as a separate user-role message; never string-concatenate user input into the system prompt (that is how the user overrides your rules).",
        "Treat model output as untrusted data, never as code: do not pass it to eval/Function/exec/spawn or a shell, and do not render it via dangerouslySetInnerHTML. If the model must trigger actions, constrain it to a fixed allowlist of tools/parameters and validate every argument server-side.",
        "For any HTML from a model, sanitize with a proven sanitizer (DOMPurify) before rendering; for any command, map the model's intent to a predefined, parameterized operation rather than executing its text."
      ]
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point — ALWAYS-ON. Runs every rule, tolerates individual failures, never
// throws (a single rule must never take the whole gate down).
// ─────────────────────────────────────────────────────────────────────────────

export async function checkVibeCoding(_: { changedFiles: string[] }): Promise<Finding[]> {
  try {
    const results = await Promise.all([
      checkSupabaseServiceRoleInClient(),
      checkPublicEnvHoldsSecret(),
      checkProviderKeyInFrontend(),
      checkSupabaseRlsDisabled(),
      checkFirebaseRulesPublic(),
      checkApiRouteNoServerAuthz(),
      checkClientSideAuthGuardOnly(),
      checkCorsWildcardCredentials(),
      checkClientControlledPrice(),
      checkTokenInLocalStorage(),
      checkUnrestrictedFileUpload(),
      checkEnvFileCommitted(),
      checkSourceMapsInProd(),
      checkDebugModeEnabled(),
      checkHallucinatedOrUnvettedDep(),
      checkPromptInjectionUnsafeChain(),
    ]);
    return results.filter((f): f is Finding => f !== null);
  } catch {
    return [];
  }
}
