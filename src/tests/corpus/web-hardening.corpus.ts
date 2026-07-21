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
  }
];
