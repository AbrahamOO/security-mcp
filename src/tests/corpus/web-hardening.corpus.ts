import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "WEB_OPEN_REDIRECT",
    check: "web-hardening",
    positive: {
      file: "src/routes/login.ts",
      content: `export function handleLogin(req, res) {\n  res.redirect(req.query.returnTo);\n}\n`
    },
    negative: {
      file: "src/routes/login.ts",
      content: `const ALLOWED = new Set(["/dashboard", "/settings"]);\nexport function handleLogin(req, res) {\n  const dest = req.query.returnTo;\n  if (typeof dest === "string" && ALLOWED.has(dest)) {\n    res.redirect(dest);\n  } else {\n    res.redirect("/");\n  }\n}\n`
    },
    note: "Negative validates the destination against an explicit allowlist before redirecting, the exact fix the rule's requiredActions recommend — not just a renamed variable."
  },
  {
    ruleId: "WEB_HARDCODED_SESSION_SECRET",
    check: "web-hardening",
    positive: {
      file: "src/auth/config.ts",
      content: `export const authConfig = {\n  secret: "keyboard cat",\n};\n`
    },
    negative: {
      file: "src/auth/config.ts",
      content: `export const authConfig = {\n  secret: process.env.SESSION_SECRET,\n};\n`
    },
    note: "Negative reads the secret from process.env, which the rule explicitly excludes, instead of any literal string."
  },
  {
    ruleId: "WEB_SERVER_ACTION_NO_AUTHZ",
    check: "web-hardening",
    positive: {
      file: "app/actions/docs.ts",
      content: `'use server';\nimport { prisma } from "@/lib/prisma";\n\n// move this to the webhook handler later\nexport async function deleteDoc(id: string) {\n  await prisma.doc.delete({ where: { id } });\n}\n`
    },
    negative: {
      file: "app/actions/docs.ts",
      content: `'use server';\nimport { prisma } from "@/lib/prisma";\nimport { getServerSession } from "next-auth";\n\n// move this to the webhook handler later\nexport async function deleteDoc(id: string) {\n  const session = await getServerSession();\n  if (!session) throw new Error("Unauthorized");\n  await prisma.doc.delete({ where: { id, userId: session.user.id } });\n}\n`
    },
    note: "Both files contain the word 'webhook' in a comment. The whole-file public-mark regex used to accept that word as an 'intentionally public' declaration, so the positive was suppressed. Only the negative actually verifies the session, and it does so inside the action body."
  },
  {
    ruleId: "WEB_SERVER_ACTION_NO_AUTHZ",
    check: "web-hardening",
    positive: {
      file: "app/actions/publish.ts",
      content: `'use server';\nimport { prisma } from "@/lib/prisma";\n\nconst getToken = () => null;\n\nexport async function publishPost(id: string) {\n  await prisma.post.update({ where: { id }, data: { published: true } });\n}\n`
    },
    negative: {
      file: "app/actions/publish.ts",
      content: `'use server';\nimport { cookies } from "next/headers";\nimport { prisma } from "@/lib/prisma";\n\nconst getToken = () => cookies().get("session")?.value ?? null;\n\nexport async function publishPost(id: string) {\n  const token = getToken();\n  if (!token) throw new Error("Unauthorized");\n  await prisma.post.update({ where: { id }, data: { published: true } });\n}\n`
    },
    note: "Both files declare getToken. In the positive it is a stub that returns null and is never called; in the negative it is called inside the action and its result gates the mutation. The rule used to accept the mere presence of the identifier anywhere in the file, so the positive passed the gate."
  }
];
