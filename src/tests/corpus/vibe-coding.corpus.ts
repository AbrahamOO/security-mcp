import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "VIBE_SUPABASE_SERVICE_ROLE_IN_CLIENT",
    check: "vibe-coding",
    positive: {
      file: "src/lib/supabaseClient.ts",
      content: `import { createClient } from "@supabase/supabase-js";\n\n// service_role key - full DB access, bypasses Row Level Security\nconst SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.abcdefghij1234567890";\n\nexport const supabaseAdmin = createClient(\n  "https://xyzcompany.supabase.co",\n  SUPABASE_SERVICE_ROLE_KEY\n);\n`
    },
    negative: {
      file: "src/lib/supabaseClient.ts",
      content: `import { createClient } from "@supabase/supabase-js";\n\nconst supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;\nconst supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;\n\nexport const supabase = createClient(supabaseUrl, supabaseAnonKey);\n`
    },
    note: "Negative uses only the anon key (from a NEXT_PUBLIC_ env var, as intended) and never mentions \"service_role\" anywhere in the file, so none of the three sub-patterns (literal string, sb_secret_ literal, JWT-near-role) can match."
  },
  {
    ruleId: "VIBE_PUBLIC_ENV_HOLDS_SECRET",
    check: "vibe-coding",
    positive: {
      file: "src/lib/stripe.ts",
      content: `export const stripeSecretKey = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n`
    },
    negative: {
      file: "src/lib/stripe.ts",
      content: `// Server-only: never inlined into the client bundle.\nexport const stripeSecretKey = process.env.STRIPE_SECRET_KEY;\n\n// Publishable keys are safe to expose to the browser.\nexport const stripePublishableKey = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;\n`
    },
    note: "Negative renames the public var to end in PUBLISHABLE_KEY, which PUBLISHABLE_ALLOW_RE explicitly excludes, and reads the real secret from a non-prefixed var that never reaches the bundle."
  },
  {
    ruleId: "VIBE_PROVIDER_KEY_IN_FRONTEND",
    check: "vibe-coding",
    positive: {
      file: "src/components/CheckoutForm.tsx",
      content: `import { loadStripe } from "@stripe/stripe-js";\n\n// TODO: move this behind the API before launch\nconst stripe = loadStripe("${"sk_live_" + "FAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"}");\n\nexport function CheckoutForm() {\n  return null;\n}\n`
    },
    negative: {
      file: "src/components/CheckoutForm.tsx",
      content: `import { loadStripe } from "@stripe/stripe-js";\n\n// Publishable key only - the secret key lives in the server API route.\nconst stripe = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);\n\nexport function CheckoutForm() {\n  return null;\n}\n`
    },
    note: "Negative uses Stripe's publishable key (pk_live_...) sourced from env, which matches none of the PROVIDER_KEY_PATTERNS regexes (all target secret-key formats: sk_live_, sk-ant-, AKIA, AIza, ghp_)."
  },
  {
    ruleId: "VIBE_SUPABASE_RLS_DISABLED",
    check: "vibe-coding",
    positive: {
      file: "supabase/migrations/0001_create_profiles.sql",
      content: `create table public.profiles (\n  id uuid primary key references auth.users(id),\n  username text,\n  bio text\n);\n`
    },
    negative: {
      file: "supabase/migrations/0001_create_profiles.sql",
      content: `create table public.profiles (\n  id uuid primary key references auth.users(id),\n  username text,\n  bio text\n);\n\nalter table public.profiles enable row level security;\n\ncreate policy "Users can view own profile"\n  on public.profiles for select\n  using (auth.uid() = id);\n\ncreate policy "Users can update own profile"\n  on public.profiles for update\n  using (auth.uid() = id);\n`
    },
    note: "Negative adds ENABLE ROW LEVEL SECURITY (satisfies ENABLE_RLS_RE) plus real ownership-check policies keyed on auth.uid(), never USING (true), so neither sub-check fires."
  },
  {
    ruleId: "VIBE_FIREBASE_RULES_PUBLIC",
    check: "vibe-coding",
    positive: {
      file: "firestore.rules",
      content: `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n`
    },
    negative: {
      file: "firestore.rules",
      content: `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /users/{userId} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n  }\n}\n`
    },
    note: "FIRESTORE_PUBLIC_RE requires the literal sequence \"if true\" right after the verb list; the negative's condition is \"if request.auth != null && ...\", which never matches that literal."
  },
  {
    ruleId: "VIBE_API_ROUTE_NO_SERVER_AUTHZ",
    check: "vibe-coding",
    positive: {
      file: "src/app/api/orders/route.ts",
      content: `export async function GET(req: Request) {\n  const { searchParams } = new URL(req.url);\n  const userId = searchParams.get("userId");\n  const orders = await prisma.order.findMany({ where: { userId } });\n  return Response.json(orders);\n}\n`
    },
    negative: {
      file: "src/app/api/orders/route.ts",
      content: `import { getServerSession } from "next-auth";\nimport { authOptions } from "@/lib/auth";\n\nexport async function GET(req: Request) {\n  const session = await getServerSession(authOptions);\n  if (!session?.user?.id) {\n    return new Response("Unauthorized", { status: 401 });\n  }\n  const orders = await prisma.order.findMany({ where: { userId: session.user.id } });\n  return Response.json(orders);\n}\n`
    },
    note: "Negative still reads request input and hits the DB (so it is not skipped as trivial) but calls getServerSession, which HANDLER_HAS_AUTH_RE recognizes as a server-side auth verifier."
  },
  {
    ruleId: "VIBE_CLIENT_SIDE_AUTH_GUARD_ONLY",
    check: "vibe-coding",
    positive: {
      file: "src/components/Dashboard.tsx",
      content: `export function Dashboard({ user }) {\n  if (!user) { router.push("/login"); return null; }\n  return <AdminPanel data={user.secretData} />;\n}\n`
    },
    negative: {
      file: "src/components/Dashboard.tsx",
      content: `// Auth is enforced server-side in middleware.ts and the layout Server Component;\n// by the time this client component renders, "user" is guaranteed to be present\n// and every API this page calls independently verifies the session too.\nexport function Dashboard({ user }) {\n  return <AdminPanel data={user.secretData} />;\n}\n`
    },
    note: "Negative removes the client-side if(!user) redirect entirely and relies on server-side (middleware/API) enforcement instead, so the guard-only pattern never appears in the file for the regex to match."
  },
  {
    ruleId: "VIBE_CORS_WILDCARD_CREDENTIALS",
    check: "vibe-coding",
    positive: {
      file: "server/index.ts",
      content: `import express from "express";\nimport cors from "cors";\n\nconst app = express();\napp.use(cors());\n`
    },
    negative: {
      file: "server/index.ts",
      content: `import express from "express";\nimport cors from "cors";\n\nconst app = express();\nconst allowedOrigins = ["https://app.example.com"];\napp.use(\n  cors({\n    origin: allowedOrigins,\n    credentials: true,\n  })\n);\n`
    },
    note: "Negative passes an explicit allowlist array as origin (never the string '*' or boolean true), so neither the bare cors() pattern nor the wildcard+credentials pattern matches."
  },
  {
    ruleId: "VIBE_CLIENT_CONTROLLED_PRICE",
    check: "vibe-coding",
    positive: {
      file: "pages/api/checkout.ts",
      content: `export default async function handler(req, res) {\n  const amount = req.body.amount;\n  const paymentIntent = await stripe.paymentIntents.create({\n    amount,\n    currency: "usd",\n  });\n  res.json(paymentIntent);\n}\n`
    },
    negative: {
      file: "pages/api/checkout.ts",
      content: `export default async function handler(req, res) {\n  const { productId } = req.body;\n  const product = await db.product.findUnique({ where: { id: productId } });\n  const paymentIntent = await stripe.paymentIntents.create({\n    amount: product.priceInCents,\n    currency: "usd",\n  });\n  res.json(paymentIntent);\n}\n`
    },
    note: "Negative looks up the authoritative price server-side by product id and charges product.priceInCents, never assigning amount/price/total directly from req.body/req.query."
  },
  {
    ruleId: "VIBE_TOKEN_IN_LOCALSTORAGE",
    check: "vibe-coding",
    positive: {
      file: "src/lib/auth.ts",
      content: `export function saveSession(token: string) {\n  localStorage.setItem("token", token);\n}\n`
    },
    negative: {
      file: "src/lib/auth.ts",
      content: `export async function login(credentials: { email: string; password: string }) {\n  // Server sets an httpOnly, Secure, SameSite cookie; the client never touches the token.\n  const res = await fetch("/api/login", {\n    method: "POST",\n    credentials: "include",\n    body: JSON.stringify(credentials),\n  });\n  return res.json();\n}\n`
    },
    note: "Negative never calls localStorage.setItem with a token-shaped key; the session is an httpOnly cookie set by the server, unreadable from JavaScript."
  },
  {
    ruleId: "VIBE_UNRESTRICTED_FILE_UPLOAD",
    check: "vibe-coding",
    positive: {
      file: "server/routes/upload.ts",
      content: `import multer from "multer";\n\nconst upload = multer({ dest: "uploads/" });\n\nrouter.post("/upload", upload.single("file"), (req, res) => {\n  res.json({ path: req.file.path });\n});\n`
    },
    negative: {
      file: "server/routes/upload.ts",
      content: `import multer from "multer";\nimport path from "node:path";\n\nconst ALLOWED_TYPES = new Set(["image/png", "image/jpeg", "application/pdf"]);\n\nconst upload = multer({\n  dest: "uploads/",\n  limits: { fileSize: 5 * 1024 * 1024 },\n  fileFilter: (req, file, cb) => {\n    const ext = path.extname(file.originalname).toLowerCase();\n    if (!ALLOWED_TYPES.has(file.mimetype) || ![".png", ".jpg", ".jpeg", ".pdf"].includes(ext)) {\n      return cb(new Error("Unsupported file type"));\n    }\n    cb(null, true);\n  },\n});\n\nrouter.post("/upload", upload.single("file"), (req, res) => {\n  res.json({ path: req.file.path });\n});\n`
    },
    note: "Negative's multer() call has both a fileFilter (MIME+extension allowlist) and limits.fileSize, so hasFilter and hasLimits are both true and the missing-restriction condition never triggers."
  },
  {
    ruleId: "VIBE_ENV_FILE_COMMITTED",
    check: "vibe-coding",
    positive: {
      file: ".env",
      content: `DATABASE_URL=postgres://user:CHANGEME_PASSWORD@localhost:5432/mydb\nSTRIPE_SECRET_KEY=${"sk_live_" + "FAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"}\n`
    },
    negative: {
      file: ".env.example",
      content: `DATABASE_URL=postgres://user:password@localhost:5432/mydb\nSTRIPE_SECRET_KEY=sk_live_replace_with_your_key\n`
    },
    note: "Negative uses the .env.example naming the module explicitly exempts (checkEnvFileCommitted filters out *.example/*.sample/*.template files and *.env.example specifically), matching the rule's own remediation of keeping only a committed template with placeholder values."
  },
  {
    ruleId: "VIBE_SOURCEMAPS_IN_PROD",
    check: "vibe-coding",
    positive: {
      file: "next.config.js",
      content: `module.exports = {\n  productionBrowserSourceMaps: true,\n};\n`
    },
    negative: {
      file: "next.config.js",
      content: `module.exports = {\n  productionBrowserSourceMaps: false,\n};\n`
    },
    note: "Negative sets the flag to false, which does not match the literal `productionBrowserSourceMaps: true` the rule searches for."
  },
  {
    ruleId: "VIBE_DEBUG_MODE_ENABLED",
    check: "vibe-coding",
    positive: {
      file: "app.py",
      content: `from flask import Flask\n\napp = Flask(__name__)\n\nif __name__ == "__main__":\n    app.run(debug=True, host="0.0.0.0")\n`
    },
    negative: {
      file: "app.py",
      content: `import os\nfrom flask import Flask\n\napp = Flask(__name__)\n\nif __name__ == "__main__":\n    debug_mode = os.environ.get("FLASK_DEBUG") == "1"\n    app.run(debug=debug_mode, host="0.0.0.0")\n`
    },
    note: "Negative assigns debug from an environment-derived boolean (debug=debug_mode), never the literal token True/true, so app\\.run\\(...debug\\s*=\\s*True and the bare debug=True/DEBUG=True patterns cannot match."
  },
  {
    ruleId: "VIBE_HALLUCINATED_OR_UNVETTED_DEP",
    check: "vibe-coding",
    positive: {
      file: "package.json",
      content: `{\n  "name": "vibe-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "react-fast-toastify": "^1.2.0",\n    "express": "^4.19.2"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "vibe-app",\n  "version": "1.0.0",\n  "private": true,\n  "scripts": {\n    "start": "node server.js"\n  }\n}\n`
    },
    note: "Harness limitation: the corpus runner writes exactly one file per sample, so the true 'lockfile resolves every dependency' fix cannot be represented (there is no way to also supply a package-lock.json). The negative instead declares zero dependencies/devDependencies (names.length === 0), the one single-file state that legitimately has nothing to hallucinate and so is skipped before the lockfile check ever runs."
  },
  {
    ruleId: "VIBE_PROMPT_INJECTION_UNSAFE_CHAIN",
    check: "vibe-coding",
    positive: {
      file: "server/chat.ts",
      content: `export async function runAssistantAction(userInput: string) {\n  const completion = await openai.chat.completions.create({\n    model: "gpt-4",\n    messages: [{ role: "user", content: userInput }],\n  });\n  eval(completion.choices[0].message.content);\n}\n`
    },
    negative: {
      file: "server/chat.ts",
      content: `export async function runAssistantAction(userInput: string) {\n  const completion = await openai.chat.completions.create({\n    model: "gpt-4",\n    messages: [{ role: "user", content: userInput }],\n  });\n  const reply = completion.choices[0].message.content;\n  const allowedActions = new Set(["summarize", "translate", "search"]);\n  const intent = JSON.parse(reply).action;\n  if (!allowedActions.has(intent)) {\n    throw new Error("Unrecognized action");\n  }\n  await runAllowlistedAction(intent);\n}\n`
    },
    note: "Positive passes model output (completion.choices[0].message.content) straight into eval(), matching the dangerous-sink pattern. Negative parses the reply and checks the requested action against a fixed allowlist before running anything, and never calls eval/exec/spawn/Function/dangerouslySetInnerHTML at all."
  },
  {
    ruleId: "VIBE_API_ROUTE_NO_SERVER_AUTHZ",
    check: "vibe-coding",
    positive: {
      file: "app/api/admin/route.ts",
      content: `import { prisma } from "@/lib/prisma";\n\n// the webhook receiver lives in another file\nexport async function DELETE(req: Request) {\n  const { id } = await req.json();\n  await prisma.user.delete({ where: { id } });\n  return Response.json({ ok: true });\n}\n`
    },
    negative: {
      file: "app/api/admin/route.ts",
      content: `import Stripe from "stripe";\nimport { prisma } from "@/lib/prisma";\n\nconst stripe = new Stripe(process.env.STRIPE_KEY!);\n\nexport async function POST(req: Request) {\n  const signature = req.headers.get("stripe-signature")!;\n  const event = stripe.webhooks.constructEvent(await req.text(), signature, process.env.STRIPE_WEBHOOK_SECRET!);\n  await prisma.order.update({ where: { id: event.data.object.id }, data: { paid: true } });\n  return Response.json({ ok: true });\n}\n`
    },
    note: "The word 'webhook' appears in both. The positive only mentions it in a comment and authorizes nothing; the negative is a real webhook receiver that verifies the provider signature over the raw body, which is the correct authorization for an endpoint with no user session. Naming a handler after a webhook is a claim; verifying the signature is the control."
  }
];
