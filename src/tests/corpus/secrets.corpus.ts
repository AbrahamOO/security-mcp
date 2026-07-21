import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "POSSIBLE_SECRET",
    check: "secrets",
    positive: {
      file: "src/config/aws.ts",
      content: `export const s3Client = new AWS.S3({\n  accessKeyId: "AKIAIOSFODNN7EXAMPLE",\n  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n});\n`
    },
    negative: {
      file: "src/config/aws.ts",
      content: `export const s3Client = new AWS.S3({\n  accessKeyId: process.env.AWS_ACCESS_KEY_ID,\n  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY\n});\n`
    },
    note: "Positive's accessKeyId literal matches \\bAKIA[0-9A-Z]{16}\\b (aws_access_key_id, one of the ~50 SECRET_PATTERNS that all funnel into the single POSSIBLE_SECRET id). Negative reads both fields from process.env — no quoted literal follows either key, so none of the 50 patterns can match."
  },
  {
    ruleId: "ENCODED_SECRET",
    check: "secrets",
    positive: {
      file: "src/config/legacy.ts",
      content: `export const legacyConfig = {\n  legacyToken: "${"QUtJQUlPU0ZP" + "RE5ON0VYQU1QTEU="}"\n};\n`
    },
    negative: {
      file: "src/config/legacy.ts",
      content: `export const legacyConfig = {\n  legacyFlag: "d2VsY29tZS1iYW5uZXItZmxhZy0yMDI0LWVuYWJsZWQ="\n};\n`
    },
    note: "Positive's base64 literal (20+ chars, matches the b64Regex candidate scan) decodes via Buffer.from(...,'base64') to the literal string 'AKIAIOSFODNN7EXAMPLE', which matchSecretPatterns() then matches against aws_access_key_id, emitting ENCODED_SECRET. Negative's base64 literal is equally long and equally valid base64, but decodes to the plain string 'welcome-banner-flag-2024-enabled', which matches none of the SECRET_PATTERNS regexes, so matchSecretPatterns() returns null and no hit is recorded — proving the rule inspects decoded content, not just 'looks like base64'."
  },
  {
    ruleId: "SECRET_CONCATENATION_SUSPICIOUS",
    check: "secrets",
    positive: {
      file: "src/utils/credentials.js",
      content: `const apiKey = "AKIA" + "IOSFODNN7EXAMPLE";\nconsole.log(apiKey);\n`
    },
    negative: {
      file: "src/utils/credentials.js",
      content: `const apiKey = process.env.API_KEY_PREFIX + process.env.API_KEY_SUFFIX;\nconsole.log(apiKey);\n`
    },
    note: "Positive matches /(?:apiKey|secret|token|password|key)\\s*=\\s*['\"][^'\"]{4,}['\"]\\s*\\+/gi — 'apiKey = \"AKIA\" +' has the keyword, a >=4-char quoted literal, then a '+' concatenation operator. Negative keeps the same 'apiKey = ... + ...' concatenation shape but both operands are process.env reads with no quoted literal immediately after '=', so the required ['\"][^'\"]{4,}['\"] segment never appears."
  },
  {
    ruleId: "SECRET_OPENSSH_PRIVATE_KEY",
    check: "secrets",
    positive: {
      file: "keys/deploy_key.pem",
      content: `-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx\nOQAAACBGQUtFS0VZTUFURVJJQUxOT1RSRUFMRVhBTVBMRU9OTFlYWFhYWFhYWFhYWFhYWFhYWA==\n-----END OPENSSH PRIVATE KEY-----\n`
    },
    negative: {
      file: "keys/deploy_key.pem",
      content: `export function loadDeployKey() {\n  // Key material lives in the platform secret manager, not in source.\n  return readFileSync(process.env.SSH_KEY_PATH, "utf8");\n}\n`
    },
    note: "Positive contains the literal '-----BEGIN OPENSSH PRIVATE KEY-----' header the regex alternation matches directly. Negative keeps the same 'deploy key' file/purpose but only reads the key path from an env var at runtime — no PEM header or openssh-key-v1 base64 magic ('b3BlbnNzaC1rZXktdjEA...') appears anywhere in the file."
  },
  {
    ruleId: "SECRET_WEBHOOK_SIGNING_SECRET",
    check: "secrets",
    positive: {
      file: "src/config/webhooks.ts",
      content: `export const webhookConfig = {\n  webhook_secret: "whsec_9k2Lm8Qp3Rt6Vw1Xz4Bc7Nd0"\n};\n`
    },
    negative: {
      file: "src/config/webhooks.ts",
      content: `export const webhookConfig = {\n  webhook_secret: process.env.STRIPE_WEBHOOK_SECRET\n};\n`
    },
    note: "Positive's value matches \\bwhsec_[A-Za-z0-9]{20,}\\b directly (24 chars after the whsec_ prefix). Negative keeps the identical 'webhook_secret: ...' key but the value is an unquoted process.env reference, so neither the whsec_ prefix alternative nor the webhook_secret\\s*[:=]\\s*[\"'] literal-value alternative can match."
  },
  {
    ruleId: "SECRET_CONTAINER_REGISTRY_PASSWORD",
    check: "secrets",
    positive: {
      file: "scripts/push-image.sh",
      content: `#!/bin/sh\ndocker login registry.internal.corp -p S9r2Tq7Lm4Xp8Vw1\ndocker push registry.internal.corp/app:latest\n`
    },
    negative: {
      file: "scripts/push-image.sh",
      content: `#!/bin/sh\necho "$DOCKER_REGISTRY_PASSWORD" | docker login registry.internal.corp -u deploybot --password-stdin\ndocker push registry.internal.corp/app:latest\n`
    },
    note: "Positive matches the docker\\s+login\\b[^\\n]*\\s-p\\s+[\"']?[^\\s\"']{6,} alternative (an inline '-p <password>' flag). The registry host deliberately avoids the word 'example' since PLACEHOLDER_RE (the ignore guard) scans the whole matched line, not just the captured value. Negative uses '--password-stdin' with nothing following it on the line, so the --password(?:-stdin)?\\s+[^\\s\"']{6,} alternative has no trailing value to match, and '-p' never appears as its own whitespace-delimited token — this is exactly the fix the rule's requiredActions recommend."
  },
  {
    ruleId: "SECRET_CLIENT_EXPOSED_API_KEY",
    check: "secrets",
    positive: {
      file: "src/client/analytics.js",
      content: `window.SECRET_API_KEY = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c";\n`
    },
    negative: {
      file: "src/client/analytics.js",
      content: `window.NEXT_PUBLIC_SECRET_API_KEY = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c";\n`
    },
    note: "Both lines satisfy the context guard (window\\.) and the primary regex, which has no left-anchor so 'SECRET_API_KEY' matches even inside 'NEXT_PUBLIC_SECRET_API_KEY'. The negative is only safe because of the explicit ignore guard /NEXT_PUBLIC_|VITE_PUBLIC_|REACT_APP_|PUBLIC_/ — the NEXT_PUBLIC_ prefix on the same line suppresses the hit, which is the documented, intentional way to ship a value to the client."
  },
  {
    ruleId: "SECRET_CLOUDFLARE_API_TOKEN",
    check: "secrets",
    positive: {
      file: "src/config/cloudflare.ts",
      content: `export const CLOUDFLARE_API_TOKEN = "${"aB3dE7fG9hJ2kL4mN6pQ8" + "rS0tU1vW3xY5zA7bC9d"}";\n`
    },
    negative: {
      file: "src/config/cloudflare.ts",
      content: `export const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;\n`
    },
    note: "Positive's 40-char literal satisfies \\bCLOUDFLARE_API_TOKEN\\s*[:=]\\s*[\"'][A-Za-z0-9_-]{30,}[\"']. Negative keeps the identical variable name but assigns an unquoted process.env reference, so the required quoted-literal segment never appears."
  },
  {
    ruleId: "SECRET_ATLASSIAN_API_TOKEN",
    check: "secrets",
    positive: {
      file: "src/integrations/jira.ts",
      content: `export const jiraToken = "${"ATATT3xFfGF0abcdEFGH" + "1234ijklMNOPqrstuvwx"}";\n`
    },
    negative: {
      file: "src/integrations/jira.ts",
      content: `export const jiraToken = process.env.JIRA_API_TOKEN;\n`
    },
    note: "Positive's literal starts with the ATATT3 magic prefix and has 34 trailing alnum chars, matching \\bATATT3[A-Za-z0-9_\\-=]{20,}\\b. Negative's value is an unquoted process.env.JIRA_API_TOKEN reference immediately followed by ';' rather than '=' or ':', so the second alternative's \\s*[:=]\\s*[\"'] requirement is never satisfied either."
  },
  {
    ruleId: "SECRET_KEY_IN_COMMENT",
    check: "secrets",
    positive: {
      file: "src/crypto/encrypt.ts",
      content: `// TODO: remove before merging - encryption_key = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"\nfunction encrypt(data: Buffer): Buffer {\n  return data;\n}\n`
    },
    negative: {
      file: "src/crypto/encrypt.ts",
      content: `// encryption_key is loaded from AWS KMS at startup; see src/config/kms.ts\nfunction encrypt(data: Buffer): Buffer {\n  return data;\n}\n`
    },
    note: "Positive comment line has '//' followed eventually by 'encryption_key = \"<32-char literal>\"', matching the comment-marker + keyword + [:=] + quoted-value regex. Negative keeps 'encryption_key' in the same comment but followed by prose ('is loaded from...') instead of '=' or ':', so \\s*[:=]\\s*[\"'] never matches — the key concept is documented, no value is embedded."
  },
  {
    ruleId: "SECRET_DB_URL_PASSWORD_IN_TEMPLATE",
    check: "secrets",
    positive: {
      file: ".env.example",
      content: `# Example environment configuration for local development\nDATABASE_URL=postgres://appuser:S9kQ2mLp7Vt4Xz1B@db-primary.internal.corp:5432/appdb\n`
    },
    negative: {
      file: ".env.example",
      content: `# Example environment configuration for local development\nDATABASE_URL=postgres://appuser:CHANGEME@db-primary.internal.corp:5432/appdb\n`
    },
    note: "File matches TEMPLATE_FILE_RE (.env.example), so the rule is in-scope. Positive's credentialed URL matches the postgres://user:pass@host pattern and the password 'S9kQ2mLp7Vt4Xz1B' does not match any of the ignore guard's placeholder words. Negative has the identical URL shape but the password segment is literally 'CHANGEME', which the ignore regex's :(?:...|changeme|...)@ alternative matches case-insensitively, suppressing the hit — the exact placeholder convention the rule's requiredActions recommend."
  },
  {
    ruleId: "SECRET_FIREBASE_WEB_CONFIG",
    check: "secrets",
    positive: {
      file: "src/config/firebase.ts",
      content: `export const firebaseConfig = {\n  apiKey: "AIzaSyD1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P",\n  authDomain: "myapp-12345.firebaseapp.com",\n  projectId: "myapp-12345"\n};\n`
    },
    negative: {
      file: "src/config/firebase.ts",
      content: `export const firebaseConfig = {\n  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,\n  authDomain: \`\${import.meta.env.VITE_FIREBASE_PROJECT_ID}.firebaseapp.com\`,\n  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID\n};\n`
    },
    note: "Positive's apiKey value is exactly 'AIza' + 35 alnum chars, and within 200 chars an authDomain ending in .firebaseapp.com follows, matching the full regex (which has no ignore guard for this id). Negative keeps the identical firebaseConfig object shape but every field is a build-time import.meta.env reference — no literal 'AIza...' string exists anywhere in the file for the regex to find."
  }
];
