import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "WEB_HEADERS_MISSING",
    check: "web-nextjs",
    positive: {
      file: "app/page.tsx",
      content: `export default function HomePage() {
  return <main><h1>Welcome</h1></main>;
}
`
    },
    negative: {
      file: "middleware.ts",
      content: `import { NextResponse } from "next/server";

export function middleware() {
  const response = NextResponse.next();
  response.headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self'");
  response.headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  return response;
}
`
    },
    note: "checkSecurityHeaders looks for the literal filenames middleware.ts/middleware.tsx/src/middleware.ts/next.config.* at the workspace root; the positive sample is any ordinary page so none of those exist and headerFiles.length === 0. The negative is a real middleware.ts containing all four required header strings, so the rule finds the file and is satisfied."
  },
  {
    ruleId: "DANGEROUSLY_SET_INNER_HTML",
    check: "web-nextjs",
    positive: {
      file: "src/components/Comment.tsx",
      content: `export function Comment({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
`
    },
    negative: {
      file: "src/components/Comment.tsx",
      content: `import DOMPurify from "isomorphic-dompurify";

export function Comment({ html }: { html: string }) {
  const clean = DOMPurify.sanitize(html);
  return <div>{clean}</div>;
}
`
    },
    note: "The check is a bare substring search for 'dangerouslySetInnerHTML'. The negative removes the API entirely and renders sanitized text as a normal child, which is exactly what the rule's own requiredActions recommend ('Remove dangerouslySetInnerHTML where possible'), rather than sanitizing while still calling the risky API."
  },
  {
    ruleId: "WEB_OPEN_REDIRECT",
    check: "web-nextjs",
    positive: {
      file: "app/api/auth/callback/route.ts",
      content: `export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  return Response.redirect(searchParams.get("returnTo"));
}
`
    },
    negative: {
      file: "app/api/auth/callback/route.ts",
      content: `const ALLOWED_REDIRECTS = new Set(["/dashboard", "/settings", "/"]);

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const dest = searchParams.get("returnTo");
  const target = dest && ALLOWED_REDIRECTS.has(dest) ? dest : "/";
  return Response.redirect(new URL(target, req.url));
}
`
    },
    note: "checkOpenRedirect only flags a redirect(...) line that ALSO contains searchParams/.get(/req.query on the SAME line. The vulnerable line calls Response.redirect(searchParams.get(...)) directly. The safe line calls Response.redirect(new URL(target, req.url)) where target was already validated against an allowlist on a separate line, so the redirect line itself contains none of the trigger tokens."
  },
  {
    ruleId: "WEB_IDOR_RISK",
    check: "web-nextjs",
    positive: {
      file: "app/api/orders/[id]/route.ts",
      content: `export async function GET(req: Request, { params }: { params: { id: string } }) {
  const order = await db.order.findUnique({ where: { id: params.id } });
  return Response.json(order);
}
`
    },
    negative: {
      file: "app/api/orders/[id]/route.ts",
      content: `export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  const order = await db.order.findUnique({ where: { id: params.id, userId: session.user.id } });
  return Response.json(order);
}
`
    },
    note: "checkIdorRisk matches params.id and then excludes any hit line that also contains auth/session/getServerSession/etc. The negative keeps params.id but scopes the query with session.user.id on the same line (an ownership-check query, not just a renamed field), which is what the rule's requiredActions call for."
  },
  {
    ruleId: "WEB_SERVER_ACTION_UNVALIDATED",
    check: "web-nextjs",
    positive: {
      file: "app/actions/updateProfile.ts",
      content: `"use server";

export async function updateProfile(formData: FormData) {
  const name = formData.get("name");
  const email = formData.get("email");
  await db.user.update({ where: { id: formData.get("userId") }, data: { name, email } });
}
`
    },
    negative: {
      file: "app/actions/updateProfile.ts",
      content: `"use server";

import { z } from "zod";

const ProfileSchema = z.object({
  userId: z.string().uuid(),
  name: z.string().min(1).max(100),
  email: z.string().email()
});

export async function updateProfile(formData: FormData) {
  const parsed = ProfileSchema.safeParse({
    userId: formData.get("userId"),
    name: formData.get("name"),
    email: formData.get("email")
  });
  if (!parsed.success) {
    throw new Error("Invalid input");
  }
  await db.user.update({
    where: { id: parsed.data.userId },
    data: { name: parsed.data.name, email: parsed.data.email }
  });
}
`
    },
    note: "checkServerActionValidation finds every file containing the literal 'use server' directive, then checks the SAME file's full text for '.parse(' or '.safeParse('. The negative adds a Zod schema and calls .safeParse(), which is the exact fix its requiredActions describe."
  },
  {
    ruleId: "WEB_API_NO_AUTH",
    check: "web-nextjs",
    positive: {
      file: "app/api/admin/users/route.ts",
      content: `export async function GET() {
  const users = await db.user.findMany();
  return Response.json(users);
}
`
    },
    negative: {
      file: "app/api/admin/users/route.ts",
      content: `import { auth } from "@/lib/auth";

export async function GET() {
  const session = await auth();
  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }
  const users = await db.user.findMany();
  return Response.json(users);
}
`
    },
    note: "checkApiRouteAuth globs every route.ts/route.tsx and tests the full file content against /auth\\(|session\\(|getServerSession|currentUser|requireAuth/. The negative calls auth() and returns 401 before touching data, satisfying the guard the rule looks for."
  },
  {
    ruleId: "WEB_CORS_WILDCARD",
    check: "web-nextjs",
    positive: {
      file: "app/api/public-data/route.ts",
      content: `export async function GET() {
  return new Response(JSON.stringify({ ok: true }), {
    headers: { "Access-Control-Allow-Origin": "*" }
  });
}
`
    },
    negative: {
      file: "app/api/public-data/route.ts",
      content: `const ALLOWED_ORIGINS = new Set(["https://app.example.com"]);

export async function GET(req: Request) {
  const origin = req.headers.get("origin") ?? "";
  const allowOrigin = ALLOWED_ORIGINS.has(origin) ? origin : "";
  return new Response(JSON.stringify({ ok: true }), {
    headers: { "Access-Control-Allow-Origin": allowOrigin }
  });
}
`
    },
    note: "checkCorsWildcard requires a line with 'Access-Control-Allow-Origin' whose value is a literal '*' (colon-or-comma then quote-star-quote). The negative computes the header value from an origin allowlist instead of a literal asterisk."
  },
  {
    ruleId: "WEB_JWT_HARDCODED_SECRET",
    check: "web-nextjs",
    positive: {
      file: "src/lib/jwt.ts",
      content: `import jwt from "jsonwebtoken";

export function signToken(payload: object) {
  return jwt.sign(payload, "my-super-secret-key-2024");
}
`
    },
    negative: {
      file: "src/lib/jwt.ts",
      content: `import jwt from "jsonwebtoken";

const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  throw new Error("JWT_SECRET is not set");
}

export function signToken(payload: object) {
  return jwt.sign(payload, SECRET);
}
`
    },
    note: "checkJwtHardcodedSecret requires a quoted string literal (8+ chars) as an argument inside jwt.sign(/jwt.verify(. The negative passes the SECRET identifier (sourced from process.env.JWT_SECRET) instead of any quoted literal, so the regex's quote-delimited literal requirement never matches."
  },
  {
    ruleId: "WEB_RATE_LIMIT_MISSING",
    check: "web-nextjs",
    positive: {
      file: "app/api/login/route.ts",
      content: `export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = await db.user.findUnique({ where: { email } });
  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    return new Response("Invalid credentials", { status: 401 });
  }
  const token = await createSession(user.id);
  return Response.json({ token });
}
`
    },
    negative: {
      file: "app/api/login/route.ts",
      content: `import { Ratelimit } from "@upstash/ratelimit";
import { redis } from "@/lib/redis";

const rateLimiter = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(5, "15 m") });

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for") ?? "unknown";
  const { success } = await rateLimiter.limit(ip);
  if (!success) {
    return new Response("Too many requests", { status: 429 });
  }
  const { email, password } = await req.json();
  const user = await db.user.findUnique({ where: { email } });
  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    return new Response("Invalid credentials", { status: 401 });
  }
  const token = await createSession(user.id);
  return Response.json({ token });
}
`
    },
    note: "The file path matches the fg pattern **/login**/route.ts, so checkRateLimitMissing inspects its content for /rateLimit|upstash|rate.limit|rateLimiter/. The negative imports @upstash/ratelimit and calls a variable literally named rateLimiter before doing any auth work, matching the rule's own remediation."
  },
  {
    ruleId: "WEB_ENV_EXPOSED_CLIENT",
    check: "web-nextjs",
    positive: {
      file: ".env.local",
      content: `DATABASE_URL=postgres://user:pass@localhost:5432/app
NEXT_PUBLIC_API_KEY=sk_live_abc123456789
`
    },
    negative: {
      file: ".env.local",
      content: `DATABASE_URL=postgres://user:pass@localhost:5432/app
API_KEY=sk_live_abc123456789
NEXT_PUBLIC_API_URL=https://api.example.com
`
    },
    note: "checkEnvExposedClient globs .env* files and tests their content against /NEXT_PUBLIC_(SECRET|API_KEY|TOKEN|PASSWORD)/. The negative keeps the real secret server-only (API_KEY, no NEXT_PUBLIC_ prefix) and only exposes a genuinely public URL under NEXT_PUBLIC_API_URL, which does not match the SECRET|API_KEY|TOKEN|PASSWORD suffix set."
  },
  {
    ruleId: "WEB_PATH_TRAVERSAL",
    check: "web-nextjs",
    positive: {
      file: "app/api/files/route.ts",
      content: `import fs from "fs";
import path from "path";

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const data = fs.readFileSync(path.join(process.cwd(), "uploads", searchParams.get("file")));
  return new Response(data);
}
`
    },
    negative: {
      file: "app/api/files/route.ts",
      content: `import fs from "fs";
import path from "path";

const UPLOADS_DIR = path.join(process.cwd(), "uploads");

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const requested = searchParams.get("file") ?? "";
  const safeName = path.basename(requested);
  const fullPath = path.join(UPLOADS_DIR, safeName);
  if (!fullPath.startsWith(UPLOADS_DIR)) {
    return new Response("Invalid file", { status: 400 });
  }
  const data = fs.readFileSync(fullPath);
  return new Response(data);
}
`
    },
    note: "checkPathTraversal only flags an fs.readFile/path.join hit LINE that also contains searchParams/.get(/req.query. In the negative, the actual fs.readFileSync/path.join calls operate on safeName/fullPath/UPLOADS_DIR — none of those lines mention searchParams or .get( directly, because the raw value was resolved with path.basename and prefix-checked on earlier, separate lines."
  },
  {
    ruleId: "WEB_LOG_PII",
    check: "web-nextjs",
    positive: {
      file: "app/api/signup/route.ts",
      content: `export async function POST(req: Request) {
  const { email, password } = await req.json();
  console.log("New signup attempt", email, password);
  const user = await createUser(email, password);
  return Response.json({ id: user.id });
}
`
    },
    negative: {
      file: "app/api/signup/route.ts",
      content: `export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = await createUser(email, password);
  console.log("New signup completed", { userId: user.id, createdAt: user.createdAt });
  return Response.json({ id: user.id });
}
`
    },
    note: "checkLogPii flags console.log lines whose text matches /email|password|token|.../. The negative's console.log line only mentions userId and createdAt, not any PII field name, so the same log call is safe."
  },
  {
    ruleId: "WEB_SESSION_WEAK_CONFIG",
    check: "web-nextjs",
    positive: {
      file: "src/lib/session.ts",
      content: `import session from "express-session";

export const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
});
`
    },
    negative: {
      file: "src/lib/session.ts",
      content: `import session from "express-session";

export const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "strict",
    maxAge: 15 * 60 * 1000
  }
});
`
    },
    note: "checkSessionWeakConfig requires secure: true, httpOnly: true and sameSite: somewhere in the same file as an express-session/iron-session/session({ hit. The negative adds all three inside the cookie config object."
  },
  {
    ruleId: "WEB_POSTMESSAGE_WILDCARD",
    check: "web-nextjs",
    positive: {
      file: "src/components/EmbedFrame.tsx",
      content: `export function sendToChild(iframeRef: React.RefObject<HTMLIFrameElement>, data: unknown) {
  iframeRef.current?.contentWindow?.postMessage(data, "*");
}
`
    },
    negative: {
      file: "src/components/EmbedFrame.tsx",
      content: `const TRUSTED_ORIGIN = "https://trusted-partner.example.com";

export function sendToChild(iframeRef: React.RefObject<HTMLIFrameElement>, data: unknown) {
  iframeRef.current?.contentWindow?.postMessage(data, TRUSTED_ORIGIN);
}
`
    },
    note: "checkPostMessageWildcard requires the postMessage(...) call's second argument to be a literal quote-star-quote. The negative passes the TRUSTED_ORIGIN identifier instead of '*'."
  },
  {
    ruleId: "WEB_MISSING_SRI",
    check: "web-nextjs",
    positive: {
      file: "pages/_document.tsx",
      content: `import { Html, Head, Main, NextScript } from "next/document";

export default function Document() {
  return (
    <Html>
      <Head>
        <script src="https://cdn.jsdelivr.net/npm/some-lib@1.2.3/dist/lib.min.js"></script>
      </Head>
      <body>
        <Main />
        <NextScript />
      </body>
    </Html>
  );
}
`
    },
    negative: {
      file: "pages/_document.tsx",
      content: `import { Html, Head, Main, NextScript } from "next/document";

export default function Document() {
  return (
    <Html>
      <Head>
        <script src="https://cdn.jsdelivr.net/npm/some-lib@1.2.3/dist/lib.min.js" integrity="sha384-Qw2yEXJ58WXWyc0nSuOtJnnUyWEAOsFxDvjc/8QeGnkxKryeaWKtx7VUdvQfhrQI" crossOrigin="anonymous"></script>
      </Head>
      <body>
        <Main />
        <NextScript />
      </body>
    </Html>
  );
}
`
    },
    note: "checkMissingSri matches a full <script src=\"https?://...\"...> tag on ONE line and then excludes any hit line containing 'integrity='. The negative keeps the identical tag and single-line layout but adds integrity and crossOrigin attributes, so the same line now contains 'integrity='."
  },
  {
    ruleId: "WEB_CLIENT_ENV_LEAK",
    check: "web-nextjs",
    positive: {
      file: "src/components/Analytics.tsx",
      content: `"use client";

export function Analytics() {
  const apiSecret = process.env.ANALYTICS_API_SECRET;
  fetch("https://analytics.example.com/collect?key=" + apiSecret);
  return null;
}
`
    },
    negative: {
      file: "src/components/Analytics.tsx",
      content: `"use client";

export function Analytics() {
  const publicKey = process.env.NEXT_PUBLIC_ANALYTICS_KEY;
  fetch("https://analytics.example.com/collect?key=" + publicKey);
  return null;
}
`
    },
    note: "checkClientEnvLeak scans files with a 'use client' directive for process.env.FOO where FOO is not NODE_ENV and does not start with NEXT_PUBLIC_. The negative reads the same style of env var but under the NEXT_PUBLIC_ prefix, which the rule explicitly allows for client components."
  },
  {
    ruleId: "WEB_IMAGE_REMOTE_WILDCARD",
    check: "web-nextjs",
    positive: {
      file: "next.config.js",
      content: `module.exports = {
  images: {
    remotePatterns: [
      { protocol: "https", hostname: "**" }
    ]
  }
};
`
    },
    negative: {
      file: "next.config.js",
      content: `module.exports = {
  images: {
    remotePatterns: [
      { protocol: "https", hostname: "cdn.example.com" }
    ]
  }
};
`
    },
    note: "checkImageRemoteWildcard flags next.config.* files whose images config has a hostname of '*' or '**' (or a '*' domains entry). The negative pins the remotePattern to an exact hostname it controls."
  },
  {
    ruleId: "WEB_UNSAFE_URI_SCHEME",
    check: "web-nextjs",
    positive: {
      file: "app/redirect/page.tsx",
      content: `"use client";

import { useSearchParams } from "next/navigation";

export default function RedirectPage() {
  const params = useSearchParams();
  window.location.href = params.get("next");
  return null;
}
`
    },
    negative: {
      file: "app/redirect/page.tsx",
      content: `"use client";

import { useSearchParams } from "next/navigation";

const ALLOWED_PATHS = new Set(["/dashboard", "/settings"]);

export default function RedirectPage() {
  const params = useSearchParams();
  const next = params.get("next");
  if (next && ALLOWED_PATHS.has(next) && next.startsWith("/")) {
    window.location.href = next;
  }
  return null;
}
`
    },
    note: "checkUnsafeUriScheme's second sub-pattern flags a 'location.href =' line whose right-hand side is directly params.<word>, req.query/body, or searchParams.get(...). The positive assigns params.get(\"next\") inline. The negative resolves 'next' on an earlier line, validates it against an allowlist and a leading-slash check, and only then assigns the plain identifier 'next' to location.href — that assignment line no longer matches any of the trigger tokens."
  },
  {
    ruleId: "WEB_SSR_FETCH_USER_INPUT",
    check: "web-nextjs",
    positive: {
      file: "pages/api/proxy.ts",
      content: `export default async function handler(req, res) {
  const upstream = await fetch(req.query.url);
  const body = await upstream.text();
  res.status(200).send(body);
}
`
    },
    negative: {
      file: "pages/api/proxy.ts",
      content: `const ALLOWED_HOSTS = new Set(["api.trusted-partner.com"]);

export default async function handler(req, res) {
  const target = new URL(String(req.query.url));
  if (!ALLOWED_HOSTS.has(target.hostname) || target.protocol !== "https:") {
    res.status(400).send("Invalid target");
    return;
  }
  const upstream = await fetch(target.toString());
  const body = await upstream.text();
  res.status(200).send(body);
}
`
    },
    note: "checkSsrFetchUserInput's initial search requires the fetch(...) call ITSELF to contain req.query/req.body/searchParams.get(/params.x on the same line. The positive calls fetch(req.query.url) directly. The negative resolves and validates the URL into 'target' on earlier lines and calls fetch(target.toString()) — that line contains no user-input token at all, so the rule's own searchRepo query never even matches it (a stronger guarantee than merely being filtered out)."
  },
  {
    ruleId: "WEB_ISR_REVALIDATE_WEAK_SECRET",
    check: "web-nextjs",
    positive: {
      file: "pages/api/revalidate.ts",
      content: `export default async function handler(req, res) {
  if (req.query.secret === "letmein123") {
    await res.revalidate("/blog/post-1");
    return res.json({ revalidated: true });
  }
  return res.status(401).json({ message: "Invalid token" });
}
`
    },
    negative: {
      file: "pages/api/revalidate.ts",
      content: `const REVALIDATE_SECRET = process.env.REVALIDATE_SECRET;

export default async function handler(req, res) {
  if (req.query.secret !== REVALIDATE_SECRET) {
    return res.status(401).json({ message: "Invalid token" });
  }
  await res.revalidate("/blog/post-1");
  return res.json({ revalidated: true });
}
`
    },
    note: "checkIsrRevalidateSecret flags a file that compares 'secret' against a quoted string literal (or otherwise checks a secret without any process.env.*REVALIDAT*/*SECRET* reference). The negative compares req.query.secret against REVALIDATE_SECRET, an identifier sourced from process.env.REVALIDATE_SECRET, which satisfies the rule's usesEnv check and contains no quoted literal to match the hardcoded pattern."
  }
];
