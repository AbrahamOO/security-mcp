import { Finding } from "../result.js";
import { scopedFg as fg, scanIgnoreGlobs } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";
import { getWorkspaceRoot } from "../../repo/workspace.js";
import picomatch from "picomatch";
import { execFile } from "child_process";
import { promisify } from "util";
import { existsSync, readFileSync } from "fs";
import { unlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";

const execFileAsync = promisify(execFile);

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp; description: string }> = [
  // Private keys
  { name: "private_key_pem",        regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, description: "PEM private key" },
  { name: "private_key_pkcs8",      regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----/, description: "Encrypted PKCS8 private key" },

  // AWS
  { name: "aws_access_key_id",      regex: /\bAKIA[0-9A-Z]{16}\b/, description: "AWS access key ID" },
  { name: "aws_secret_access_key",  regex: /\bAWS_SECRET(?:_ACCESS)?_KEY\s*[:=]\s*["']?[A-Za-z0-9/+]{40}["']?/, description: "AWS secret access key" },
  { name: "aws_session_token",      regex: /\bAWS_SESSION_TOKEN\s*[:=]\s*["'][A-Za-z0-9/+]{100,}["']/, description: "AWS session token" },
  { name: "aws_mws_key",            regex: /\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/, description: "AWS MWS key" },

  // GCP
  { name: "google_api_key",         regex: /\bAIza[0-9A-Za-z\-_]{35}\b/, description: "Google API key" },
  { name: "gcp_service_account",    regex: /"type"\s*:\s*"service_account"/, description: "GCP service account JSON" },
  { name: "gcp_oauth_client",       regex: /\d+-\w{32}\.apps\.googleusercontent\.com/, description: "GCP OAuth client ID" },

  // Azure
  { name: "azure_connection_string", regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==/, description: "Azure storage connection string" },
  { name: "azure_sas_token",         regex: /\bsig=[A-Za-z0-9%+/]{43,}%3D/, description: "Azure SAS token" },
  { name: "azure_client_secret",     regex: /\bAZURE_CLIENT_SECRET\s*[:=]\s*["'][^"'\n]{20,}["']/, description: "Azure client secret" },
  { name: "azure_subscription_key",  regex: /\bOcp-Apim-Subscription-Key\s*[:=]\s*["'][0-9a-f]{32}["']/, description: "Azure APIM subscription key" },
  { name: "arm_client_secret",       regex: /\bARM_CLIENT_SECRET\s*[:=]\s*['"][^'"]{20,}['"]/, description: "Terraform Azure ARM client secret" },

  // GitHub / GitLab / Bitbucket
  { name: "github_personal_token",   regex: /\bghp_[A-Za-z0-9]{36}\b/, description: "GitHub personal access token" },
  { name: "github_oauth_token",      regex: /\bgho_[A-Za-z0-9]{36}\b/, description: "GitHub OAuth token" },
  { name: "github_actions_token",    regex: /\bghs_[A-Za-z0-9]{36}\b/, description: "GitHub Actions token" },
  { name: "github_refresh_token",    regex: /\bghr_[A-Za-z0-9]{76}\b/, description: "GitHub refresh token" },
  { name: "gitlab_token",            regex: /\bglpat-[A-Za-z0-9\-_]{20}\b/, description: "GitLab personal access token" },
  { name: "bitbucket_token",         regex: /\bATBB[A-Za-z0-9]{28}\b/, description: "Bitbucket access token" },

  // Slack
  { name: "slack_bot_token",         regex: /\bxoxb-[0-9A-Za-z-]{20,}\b/, description: "Slack bot token" },
  { name: "slack_user_token",        regex: /\bxoxp-[0-9A-Za-z-]{20,}\b/, description: "Slack user token" },
  { name: "slack_workspace_token",   regex: /\bxoxa-[0-9A-Za-z-]{20,}\b/, description: "Slack workspace token" },
  { name: "slack_webhook",           regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, description: "Slack webhook URL" },

  // Stripe / Payment
  { name: "stripe_secret_key",       regex: /\bsk_live_[A-Za-z0-9]{24,}\b/, description: "Stripe live secret key" },
  { name: "stripe_restricted_key",   regex: /\brk_live_[A-Za-z0-9]{24,}\b/, description: "Stripe restricted key" },
  { name: "stripe_webhook_secret",   regex: /\bwhsec_[A-Za-z0-9]{32,}\b/, description: "Stripe webhook secret" },
  { name: "paypal_braintree_key",    regex: /\baccess_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}\b/, description: "PayPal/Braintree access token" },
  { name: "square_access_token",     regex: /\bEAAAE[A-Za-z0-9\-_]{60,}\b/, description: "Square access token" },

  // Communication
  { name: "twilio_account_sid",      regex: /\bAC[a-fA-F0-9]{32}\b/, description: "Twilio account SID" },
  { name: "twilio_auth_token",       regex: /\bTWILIO_AUTH_TOKEN\s*[:=]\s*["'][a-fA-F0-9]{32}["']/, description: "Twilio auth token" },
  { name: "twilio_token_positional", regex: /new\s+(?:Twilio|twilio)\s*\([^,]+,\s*['"]([A-Fa-f0-9]{32})['"]/, description: "Twilio auth token (positional constructor)" },
  { name: "sendgrid_api_key",        regex: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/, description: "SendGrid API key" },
  { name: "mailgun_api_key",         regex: /\bkey-[A-Za-z0-9]{32}\b/, description: "Mailgun API key" },

  // LLM / AI providers
  { name: "openai_api_key",          regex: /\bsk-[A-Za-z0-9]{20,}\b/, description: "OpenAI API key" },
  { name: "anthropic_api_key",       regex: /\bsk-ant-[A-Za-z0-9\-_]{40,}\b/, description: "Anthropic API key" },
  { name: "huggingface_token",       regex: /\bhf_[A-Za-z0-9]{34,}\b/, description: "HuggingFace token" },
  { name: "cohere_api_key",          regex: /\bCOHERE_API_KEY\s*[:=]\s*["'][A-Za-z0-9]{40}["']/, description: "Cohere API key" },

  // Database connection strings with embedded credentials
  { name: "db_connection_string",    regex: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^:]+:[^@\s]{6,}@/, description: "Database connection string with embedded credentials" },
  { name: "jdbc_credentials",        regex: /jdbc:[a-z]+:\/\/[^;]+;?[Pp]assword=[^;\s"']{6,}/, description: "JDBC connection string with password" },

  // Infrastructure tokens
  { name: "hashicorp_vault_token",   regex: /\bhvs\.[A-Za-z0-9]{24,}\b/, description: "HashiCorp Vault service token" },
  { name: "npm_token",               regex: /\bnpm_[A-Za-z0-9]{36}\b/, description: "npm access token" },
  { name: "npmrc_auth_token",        regex: /_authToken\s*=\s*[A-Za-z0-9_\-.]{10,}/, description: "npm _authToken in .npmrc" },
  { name: "docker_hub_pat",          regex: /\bdckr_pat_[A-Za-z0-9\-_]{27}\b/, description: "Docker Hub personal access token" },
  { name: "terraform_cloud_token",   regex: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{60,}\b/, description: "Terraform Cloud token" },
  { name: "datadog_api_key",         regex: /\bDD_API_KEY\s*[:=]\s*["'][a-fA-F0-9]{32}["']/, description: "Datadog API key" },
  { name: "new_relic_key",           regex: /\bNEW_RELIC_LICENSE_KEY\s*[:=]\s*["'][A-Za-z0-9]{40}["']/, description: "New Relic license key" },

  // SaaS / Cloud platform tokens
  { name: "vercel_token",            regex: /\bvercel_[A-Za-z0-9]{20,}\b/, description: "Vercel token" },
  { name: "planetscale_token",       regex: /\bpscale_tkn_[A-Za-z0-9_]{20,}\b/, description: "PlanetScale token" },
  { name: "databricks_token",        regex: /\bdapi[a-fA-F0-9]{32}\b/, description: "Databricks API token" },
  { name: "linear_api_key",          regex: /\blin_api_[A-Za-z0-9]{20,}\b/, description: "Linear API key" },
  { name: "doppler_token",           regex: /\bdp\.st\.[a-zA-Z0-9.]+\b/, description: "Doppler service token" },
  { name: "railway_token",           regex: /\bRW_[A-Za-z0-9]{20,}\b/, description: "Railway token" },

  // process.env fallback with hardcoded secret
  { name: "env_fallback_hardcoded",  regex: /process\.env\.\w+\s*(?:\?\?|\|\|)\s*['"][^'"]{16,}['"]/, description: "process.env fallback with hardcoded secret value" },

  // Generic high-confidence patterns
  { name: "secret_key_assignment",   regex: /\b(?:SECRET|API)_KEY\s*[:=]\s*["'][^"'\n]{16,}["']/, description: "Generic secret/API key assignment" },
  { name: "password_assignment",     regex: /\b(?:PASSWORD|PASSWD|PWD)\s*[:=]\s*["'][^"'\n]{8,}["']/, description: "Hardcoded password assignment" },
  { name: "private_key_assignment",  regex: /\bPRIVATE_KEY\s*[:=]\s*["'][^"'\n]{16,}["']/, description: "Private key value assignment" },
  { name: "bearer_token_literal",    regex: /Authorization['"]?\s*[:=]\s*['"]Bearer [A-Za-z0-9\-_=.]{20,}['"]/, description: "Hardcoded Bearer token" },
];

// Lower-confidence generic patterns whose captured literal is frequently a file
// path or config default (e.g. `process.env.X || ".mcp/policies/policy.json"`)
// rather than a real secret. For these, a literal that is an obvious source/config
// path is treated as a non-secret to suppress the false positive.
const PATH_PRONE_PATTERNS = new Set([
  "env_fallback_hardcoded",
  "secret_key_assignment",
  "password_assignment",
  "private_key_assignment"
]);

const NON_SECRET_LITERAL_RE =
  /\.(?:json|jsonc|js|mjs|cjs|ts|tsx|jsx|yaml|yml|md|markdown|txt|html|xml|toml|ini|cfg|conf|lock|sh|py|go|rb|java|csv|svg|png)$/i;

/** True when the trailing quoted literal of a match looks like a file path, not a secret. */
function literalLooksLikeNonSecret(matchText: string): boolean {
  const q = /["']([^"']+)["']\s*$/.exec(matchText);
  if (!q) return false;
  const value = q[1];
  return NON_SECRET_LITERAL_RE.test(value) || value.startsWith("./") || value.startsWith("../");
}

function previewLine(text: string, index: number): string {
  const lineStart = text.lastIndexOf("\n", index);
  const lineEnd = text.indexOf("\n", index);
  return text.slice(lineStart === -1 ? 0 : lineStart + 1, lineEnd === -1 ? undefined : lineEnd).trim();
}

/** Scan decoded text against all SECRET_PATTERNS; returns first match name or null */
function matchSecretPatterns(decoded: string): { name: string; match: string } | null {
  for (const pattern of SECRET_PATTERNS) {
    const m = pattern.regex.exec(decoded);
    if (!m) continue;
    if (PATH_PRONE_PATTERNS.has(pattern.name) && literalLooksLikeNonSecret(m[0])) continue;
    return { name: pattern.name, match: m[0] };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Extended, specifically-classified secret detections.
//
// Unlike SECRET_PATTERNS (which all funnel into a single CRITICAL
// POSSIBLE_SECRET finding), these produce their own finding id, severity, SLA,
// and remediation guidance. Each entry carries a `context` guard so a bare
// keyword match without the sensitive surrounding context is ignored — this
// keeps false positives low per the scanner's design.
// ---------------------------------------------------------------------------
type ClassifiedSecret = {
  id: string;
  title: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  sla: "24h" | "7d" | "30d" | "90d";
  regex: RegExp;
  /** Optional secondary guard the match text must satisfy to count. */
  context?: RegExp;
  /** Optional guard that, if matched, suppresses the hit (placeholder/example). */
  ignore?: RegExp;
  requiredActions: string[];
};

const PLACEHOLDER_RE =
  /example|placeholder|your[-_]?(?:key|secret|token|password)|xxxx|<[^>]+>|change[-_]?me|dummy|sample|redacted|\*{4,}/i;

const CLASSIFIED_SECRETS: ClassifiedSecret[] = [
  {
    id: "SECRET_OPENSSH_PRIVATE_KEY",
    title: "OpenSSH private key material committed to source",
    severity: "CRITICAL",
    sla: "24h",
    // OPENSSH-format private key block, incl. raw ed25519/ecdsa key bodies that
    // begin with the base64 magic "b3BlbnNzaC1rZXktdjE" ("openssh-key-v1").
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----|\bb3BlbnNzaC1rZXktdjEA[A-Za-z0-9+/]{20,}/,
    requiredActions: [
      "Remove the OpenSSH private key from source immediately and rotate the corresponding key pair (regenerate with ssh-keygen and re-deploy the public key).",
      "Revoke the old public key from every authorized_keys file, deploy host, and CI system it was trusted by.",
      "Store SSH keys in a secret manager or dedicated key store; never commit private key material to the repository."
    ]
  },
  {
    id: "SECRET_WEBHOOK_SIGNING_SECRET",
    title: "Webhook signing secret hardcoded in source",
    severity: "CRITICAL",
    sla: "24h",
    regex:
      /\bwhsec_[A-Za-z0-9]{20,}\b|\b(?:github|gh)_?webhook_?secret\s*[:=]\s*["'][^"'\n]{12,}["']|\bwebhook_secret\s*[:=]\s*["'][^"'\n]{12,}["']/i,
    ignore: PLACEHOLDER_RE,
    requiredActions: [
      "Remove the webhook signing secret from source and rotate it in the provider dashboard (Stripe, GitHub, etc.) — a leaked signing secret lets an attacker forge signed webhook payloads.",
      "Load the signing secret from an environment variable or secret manager at runtime.",
      "Re-verify inbound webhooks with the rotated secret and enforce a timestamp tolerance to block replay."
    ]
  },
  {
    id: "SECRET_CONTAINER_REGISTRY_PASSWORD",
    title: "Container registry password / docker login credential exposed",
    severity: "CRITICAL",
    sla: "24h",
    // .docker/config.json "auth" base64 blob, or `docker login -p <pw>`.
    // The --password(-stdin) alternative bounds its separator to [ \t]+ (not \s+)
    // so it can't span a newline and pick up the next line's leading token as a
    // fake password value — a real cross-line false positive on `--password-stdin`
    // (the safe, recommended form) followed by an unrelated command on the next line.
    regex:
      /"auths"\s*:\s*\{[\s\S]{0,200}?"auth"\s*:\s*"[A-Za-z0-9+/]{16,}={0,2}"|docker\s+login\b[^\n]*\s-p\s+["']?[^\s"']{6,}|--password(?:-stdin)?[ \t]+["']?[^\s"']{6,}/,
    ignore: PLACEHOLDER_RE,
    requiredActions: [
      "Remove the registry credential from source (and from any committed .docker/config.json) and rotate the registry password / access token immediately.",
      "Use `docker login --password-stdin` fed from a secret manager, or short-lived registry tokens (e.g. OIDC), instead of an inline `-p` password.",
      "Ensure ~/.docker/config.json is gitignored and CI injects registry auth from encrypted secrets."
    ]
  },
  {
    id: "SECRET_CLIENT_EXPOSED_API_KEY",
    title: "Server/private API key embedded in client-exposed frontend code",
    severity: "CRITICAL",
    sla: "24h",
    // A secret/private/service API key assigned in frontend/build-time inline
    // config. The context guard requires a client-shipped surface (window,
    // import.meta.env without a public prefix, a *.client./*.jsx/tsx file marker,
    // or an inline <script> define) so pure server config does not match.
    regex:
      /(?:SERVICE|SECRET|PRIVATE|ADMIN)_?API_?KEY\s*[:=]\s*["'][A-Za-z0-9\-_]{16,}["']|(?:apiKey|secretKey)\s*:\s*["'][A-Za-z0-9\-_]{20,}["']/,
    context:
      /window\.|globalThis\.|import\.meta\.env\.(?!(?:VITE_PUBLIC|NEXT_PUBLIC|PUBLIC_))|__NEXT_DATA__|dangerouslySetInnerHTML|<script[\s>]|export\s+const|process\.env\.(?!NEXT_PUBLIC_)/i,
    ignore: /NEXT_PUBLIC_|VITE_PUBLIC_|REACT_APP_|PUBLIC_/,
    requiredActions: [
      "Any key shipped in a client bundle is public — rotate it immediately and treat it as compromised.",
      "Move the secret behind a server-side proxy/BFF endpoint; the browser should call your backend, which holds the key from a secret manager.",
      "Only expose keys explicitly designed to be public (and prefixed NEXT_PUBLIC_/VITE_/PUBLIC_) to the frontend."
    ]
  },
  {
    id: "SECRET_CLOUDFLARE_API_TOKEN",
    title: "Cloudflare API token exposed",
    severity: "HIGH",
    sla: "24h",
    regex:
      /\bCLOUDFLARE_API_TOKEN\s*[:=]\s*["'][A-Za-z0-9_-]{30,}["']|\bCF_API_(?:TOKEN|KEY)\s*[:=]\s*["'][A-Za-z0-9_-]{30,}["']|\bcf-[A-Za-z0-9]{8,}-[A-Za-z0-9_-]{30,}\b/,
    ignore: PLACEHOLDER_RE,
    requiredActions: [
      "Roll (rotate) the Cloudflare API token in the Cloudflare dashboard immediately and remove it from source.",
      "Scope the replacement token to the minimum zones/permissions required rather than a global API key.",
      "Load the token from an environment variable or secret manager at runtime."
    ]
  },
  {
    id: "SECRET_ATLASSIAN_API_TOKEN",
    title: "Jira / Atlassian API token exposed",
    severity: "HIGH",
    sla: "24h",
    regex:
      /\bATATT3[A-Za-z0-9_\-=]{20,}\b|\b(?:JIRA|ATLASSIAN|CONFLUENCE)_API_TOKEN\s*[:=]\s*["'][A-Za-z0-9_\-=]{20,}["']/,
    ignore: PLACEHOLDER_RE,
    requiredActions: [
      "Revoke the Atlassian API token at id.atlassian.com/manage-profile/security/api-tokens and remove it from source.",
      "Generate a replacement token and store it in a secret manager; reference it via environment variable.",
      "Audit Jira/Confluence audit logs for unauthorized access made with the leaked token."
    ]
  },
  {
    id: "SECRET_KEY_IN_COMMENT",
    title: "Encryption/secret key left in commented-out code or comment",
    severity: "HIGH",
    sla: "7d",
    // A comment line (// ... or * ... or # ...) that assigns an encryption/secret
    // key to a substantial literal. The comment marker is the required context.
    regex:
      /(?:\/\/|\*|#)[^\n]*\b(?:encryption_?key|encryptionKey|aes_?key|secret_?key|signing_?key|master_?key)\s*[:=]\s*["'][A-Za-z0-9+/=\-_]{16,}["']/i,
    ignore: PLACEHOLDER_RE,
    requiredActions: [
      "Commenting out a key does not protect it — it is still in git history. Remove the comment and rotate the key immediately.",
      "Treat any key that has ever appeared in the repository (even commented) as compromised and re-key affected data.",
      "Store keys in a KMS / secret manager and reference them at runtime, never inline in code or comments."
    ]
  },
  {
    id: "SECRET_DB_URL_PASSWORD_IN_TEMPLATE",
    title: "Database URL with embedded password in .env.example / docs / template",
    severity: "HIGH",
    sla: "7d",
    // Real-looking credentialed DB URL. The scan-block below restricts this to
    // example/template/docs files, which is where committed real passwords in a
    // "template" are especially dangerous (developers copy them verbatim).
    regex:
      /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql|amqp):\/\/[^:\s'"]+:[^@\s'"]{6,}@[^\s'"/]+/,
    ignore:
      /:(?:password|pass|pwd|secret|user|username|host|dbname|xxxx|\*+|<[^>]+>|changeme|example|yourpassword)@/i,
    requiredActions: [
      "Replace the embedded password in the template/example/docs with a placeholder (e.g. postgres://user:PASSWORD@host/db).",
      "If the credential is real, rotate it immediately — templates are frequently the first thing an attacker greps for.",
      "Document the required environment variable name instead of a working connection string."
    ]
  },
  {
    id: "SECRET_FIREBASE_WEB_CONFIG",
    title: "Firebase Web API config key present (verify it is not used for privileged auth)",
    severity: "MEDIUM",
    sla: "30d",
    // Firebase web config object: apiKey alongside an *.firebaseapp.com authDomain
    // or a firebase projectId. Web apiKeys are not secret by design, but they are
    // routinely misused (e.g. treated as an auth secret, or paired with permissive
    // rules), so this is a MEDIUM advisory rather than CRITICAL.
    regex:
      /apiKey\s*:\s*["']AIza[0-9A-Za-z\-_]{35}["'][\s\S]{0,200}?(?:authDomain\s*:\s*["'][^"']+\.firebaseapp\.com["']|projectId\s*:\s*["'][^"']+["'])/,
    requiredActions: [
      "A Firebase Web API key is not a secret, but it must be protected by Firebase Security Rules and App Check — do not rely on the key itself for authorization.",
      "Restrict the key in Google Cloud Console (HTTP referrer / API restrictions) so it can only call the intended Firebase services.",
      "Ensure Firestore/Storage/Realtime Database rules enforce per-user access; never use the web config key as a server-side admin credential."
    ]
  }
];

/** Files that count as env-example / docs / template surfaces. */
const TEMPLATE_FILE_RE =
  /(?:\.env\.(?:example|sample|template|dist)|\.env-example|\.env\.local\.example|(?:^|\/)(?:docs?|examples?|templates?)\/|readme|\.mdx?$|\.dist$|\.sample$|\.template$)/i;

export async function checkSecrets(_: { changedFiles: string[] }): Promise<Finding[]> {
  const findings: Finding[] = [];

  const IGNORE_LIST = [
    "**/node_modules/**",
    "**/.git/**",
    "**/dist/**",
    "**/fixtures/**",
    "**/.mcp/reviews/**",
    "**/.mcp/reports/**",
    "**/.claude/**",
    // Exclude detection source — contains regex patterns that match their own rules
    "src/gate/checks/secrets.ts"
  ];

  // "**/*" (not "**/*.*") — the dotted form silently excludes every extensionless
  // file. SSH private keys (id_rsa, id_ed25519), Dockerfile, Makefile, Jenkinsfile,
  // Procfile and bare "credentials" all have no dot, so this module could not see them
  // at all. src/repo/search.ts:91 already carries this fix; it was never propagated.
  const files = await fg(["**/*"], {
    dot: true,
    onlyFiles: true,
    ignore: IGNORE_LIST
  });

  // ------------------------------------------------------------------
  // Fix 8: Warn when dist/ exists but is excluded from scanning
  // ------------------------------------------------------------------
  const distExists = existsSync(path.join(getWorkspaceRoot(), "dist"));
  if (distExists) {
    findings.push({
      id: "SECRET_DIST_NOT_SCANNED",
      title: "Compiled dist/ directory excluded from secret scan",
      severity: "LOW",
      files: ["dist/"],
      evidence: ["dist/ directory exists but is excluded from secret scanning"],
      requiredActions: [
        "Manually inspect dist/ for secrets injected by build tools such as webpack DefinePlugin or Vite define.",
        "Ensure secrets are not inlined into compiled bundles via build-time substitution.",
        "Consider adding a targeted scan of dist/ for high-confidence patterns (API key prefixes, PEM headers) in CI."
      ]
    });
  }

  // Track hits per pattern so each type gets its own finding with specific guidance
  const hitsByPattern = new Map<string, string[]>();

  // Track encoding evasion hits separately
  const encodingHits: string[] = [];

  // Track concatenation hits separately
  const concatHits: string[] = [];

  // Track classified-secret hits (id -> evidence lines)
  const classifiedHits = new Map<string, string[]>();

  for (const file of files) {
    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue;
    }

    // ------------------------------------------------------------------
    // Primary scan: run all SECRET_PATTERNS against raw file content
    // ------------------------------------------------------------------
    for (const pattern of SECRET_PATTERNS) {
      const match = pattern.regex.exec(text);
      if (!match || match.index === undefined) continue;
      if (PATH_PRONE_PATTERNS.has(pattern.name) && literalLooksLikeNonSecret(match[0])) continue;

      const preview = previewLine(text, match.index);
      // Redact the matched value itself — only expose location and pattern name
      const redacted = preview.replace(pattern.regex, "[REDACTED]");
      const hit = `${file}: ${redacted}`;

      const existing = hitsByPattern.get(pattern.name) ?? [];
      if (existing.length < 5) {
        existing.push(hit);
        hitsByPattern.set(pattern.name, existing);
      }
    }

    // ------------------------------------------------------------------
    // Classified secret scan (specific id / severity / SLA per pattern)
    // ------------------------------------------------------------------
    for (const cs of CLASSIFIED_SECRETS) {
      const m = cs.regex.exec(text);
      if (!m || m.index === undefined) continue;
      // The DB-URL-in-template rule only fires inside example/docs/template files.
      if (cs.id === "SECRET_DB_URL_PASSWORD_IN_TEMPLATE" && !TEMPLATE_FILE_RE.test(file)) continue;
      const preview = previewLine(text, m.index);
      if (cs.context && !cs.context.test(preview)) continue;
      if (cs.ignore && cs.ignore.test(preview)) continue;
      const redacted = preview.replace(cs.regex, "[REDACTED]");
      const existing = classifiedHits.get(cs.id) ?? [];
      if (existing.length < 5) {
        existing.push(`${file}: ${redacted}`);
        classifiedHits.set(cs.id, existing);
      }
    }

    // ------------------------------------------------------------------
    // Fix 6: Split-string / concatenation detection
    // ------------------------------------------------------------------
    const concatPatterns = [
      /(?:apiKey|secret|token|password|key)\s*=\s*['"][^'"]{4,}['"]\s*\+/gi,
      /(?:AKIA|sk_live_|sk-|ghp_|xoxb-)[\w+/]{4,}['"]\s*,[\s\S]{0,40}\.join\s*\(\s*['"]{2}\s*\)/gi,
    ];
    for (const cp of concatPatterns) {
      const m = cp.exec(text);
      if (m) {
        const preview = previewLine(text, m.index);
        concatHits.push(`${file}: ${preview.slice(0, 120)}`);
        break; // one hit per file per pass is enough
      }
    }

    // ------------------------------------------------------------------
    // Fix 2: Encoding evasion — base64 and hex secondary pass
    // ------------------------------------------------------------------
    // SECURITY (CWE-400): a single multi-MB contiguous base64/hex run makes V8's
    // regex engine throw RangeError ("Maximum call stack size exceeded"). The
    // readFileSafe size cap bounds file size, but contain any residual throw here
    // so one crafted repo file cannot crash the gate (docs tier) or silently drop
    // all secret findings (full tier swallows the rejection via Promise.allSettled).
    try {
    // Base64 candidates: length >= 20, valid base64 chars
    const b64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
    let b64Match: RegExpExecArray | null;
    while ((b64Match = b64Regex.exec(text)) !== null) {
      const candidate = b64Match[0];
      try {
        const decoded = Buffer.from(candidate, "base64").toString("utf8");
        // Only proceed if decoded output looks like printable ASCII (avoid false positives on binary)
        if (!/^[\x20-\x7E\t\r\n]{8,}$/.test(decoded)) continue;
        const hit = matchSecretPatterns(decoded);
        if (hit) {
          const preview = previewLine(text, b64Match.index);
          encodingHits.push(
            `${file}: base64-encoded ${hit.name} detected — encoded="${candidate.slice(0, 40)}…" decoded_match="[REDACTED]" context="${preview.slice(0, 80)}"`
          );
        }
      } catch {
        // decode failed — skip
      }
    }

    // Hex candidates: length >= 32, even number of hex chars
    const hexRegex = /\b[0-9a-fA-F]{32,}\b/g;
    let hexMatch: RegExpExecArray | null;
    while ((hexMatch = hexRegex.exec(text)) !== null) {
      const candidate = hexMatch[0];
      if (candidate.length % 2 !== 0) continue;
      try {
        const decoded = Buffer.from(candidate, "hex").toString("utf8");
        if (!/^[\x20-\x7E\t\r\n]{8,}$/.test(decoded)) continue;
        const hit = matchSecretPatterns(decoded);
        if (hit) {
          const preview = previewLine(text, hexMatch.index);
          encodingHits.push(
            `${file}: hex-encoded ${hit.name} detected — encoded="${candidate.slice(0, 40)}…" decoded_match="[REDACTED]" context="${preview.slice(0, 80)}"`
          );
        }
      } catch {
        // decode failed — skip
      }
    }
    } catch {
      // CWE-400: regex engine RangeError or similar on a pathological file —
      // skip this file's encoding pass rather than aborting the whole scan.
      continue;
    }
  }

  // ------------------------------------------------------------------
  // Emit findings for primary pattern hits
  // ------------------------------------------------------------------
  for (const [patternName, hits] of hitsByPattern) {
    const pattern = SECRET_PATTERNS.find((p) => p.name === patternName);
    const description = pattern?.description ?? patternName;

    findings.push({
      id: "POSSIBLE_SECRET",
      title: `Hardcoded secret detected: ${description}`,
      severity: "CRITICAL",
      files: hits.map((h) => h.split(":")[0]).filter(Boolean),
      evidence: hits,
      requiredActions: [
        `Remove the ${description} from source code immediately.`,
        "Rotate the exposed credential — treat it as compromised.",
        "Store the secret in your cloud secret manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, Doppler, or 1Password Secrets Automation).",
        "Add a pre-commit hook or CI check with gitleaks to prevent future secret commits."
      ]
    });
  }

  // ------------------------------------------------------------------
  // Emit findings for classified secret hits
  // ------------------------------------------------------------------
  for (const cs of CLASSIFIED_SECRETS) {
    const hits = classifiedHits.get(cs.id);
    if (!hits || hits.length === 0) continue;
    findings.push({
      id: cs.id,
      title: cs.title,
      severity: cs.severity,
      sla: cs.sla,
      files: [...new Set(hits.map((h) => h.split(":")[0]).filter(Boolean))],
      evidence: hits,
      requiredActions: cs.requiredActions
    });
  }

  // ------------------------------------------------------------------
  // Emit findings for encoding evasion hits
  // ------------------------------------------------------------------
  if (encodingHits.length > 0) {
    findings.push({
      id: "ENCODED_SECRET",
      title: "Encoded secret detected (base64 or hex evasion)",
      severity: "CRITICAL",
      files: [...new Set(encodingHits.map((h) => h.split(":")[0]).filter(Boolean))],
      evidence: encodingHits.slice(0, 10),
      requiredActions: [
        "Encoded secrets are still secrets — encoding is not encryption.",
        "Decode and rotate any exposed credentials immediately.",
        "Remove the encoded value from source code and use a secret manager instead."
      ]
    });
  }

  // ------------------------------------------------------------------
  // Emit findings for concatenation heuristic hits
  // ------------------------------------------------------------------
  if (concatHits.length > 0) {
    findings.push({
      id: "SECRET_CONCATENATION_SUSPICIOUS",
      title: "Suspicious secret concatenation or split-string obfuscation detected",
      severity: "MEDIUM",
      files: [...new Set(concatHits.map((h) => h.split(":")[0]).filter(Boolean))],
      evidence: concatHits.slice(0, 10),
      requiredActions: [
        "Review concatenated string assignments near secret-keyword variable names.",
        "Split-string obfuscation does not prevent extraction — treat as a hardcoded secret.",
        "Move the value to a secret manager and reference it via environment variable."
      ]
    });
  }

  // ------------------------------------------------------------------
  // Fix 7: Git history scan via gitleaks
  // ------------------------------------------------------------------
  let gitleaksAvailable = false;
  try {
    await execFileAsync("gitleaks", ["version"]);
    gitleaksAvailable = true;
  } catch {
    gitleaksAvailable = false;
  }

  if (!gitleaksAvailable) {
    findings.push({
      id: "GITLEAKS_NOT_IN_PATH",
      title: "git history not scanned — gitleaks binary not found",
      severity: "MEDIUM",
      files: [],
      evidence: ["gitleaks was not found in PATH; git history secrets scan was skipped"],
      requiredActions: [
        "Install gitleaks (https://github.com/gitleaks/gitleaks) to enable git history scanning.",
        "Run: gitleaks detect --source . --log-opts='--all' to scan full commit history.",
        "Secrets committed in the past and later removed are still exposed in git history."
      ]
    });
  } else {
    const tmpReport = path.join(os.tmpdir(), `gitleaks-${randomBytes(8).toString("hex")}.json`);
    try {
      await execFileAsync("gitleaks", [
        "detect",
        "--source", ".",
        "--log-opts=--all",
        "--no-git=false",
        "--exit-code", "1",
        "--report-format", "json",
        "--report-path", tmpReport
      ]);
      // exit code 0 — no findings
    } catch {
      // exit code 1 means findings were found; report file should exist
    }

    try {
      if (existsSync(tmpReport)) {
        const raw = readFileSync(tmpReport, "utf8");
        const rawLeaks = JSON.parse(raw) as Array<{
          RuleID?: string;
          File?: string;
          Commit?: string;
          Secret?: string;
          Description?: string;
        }>;

        // Apply the same scan-scope ignores to git-history results that file scans
        // use. gitleaks walks every commit and cannot honor the file globs directly,
        // so a leak in an ignored path (e.g. an intentional fixtures/ test secret, or
        // SECURITY_GATE_IGNORE project paths) is filtered out here for consistency.
        const ignoreMatchers = scanIgnoreGlobs().map((g) => picomatch(g));
        const leaksData = (Array.isArray(rawLeaks) ? rawLeaks : []).filter((leak) => {
          const file = leak.File ?? "";
          return !file || !ignoreMatchers.some((m) => m(file));
        });

        if (leaksData.length > 0) {
          const evidence = leaksData.slice(0, 20).map((leak) => {
            const commit = leak.Commit ? leak.Commit.slice(0, 8) : "unknown";
            const file = leak.File ?? "unknown";
            const rule = leak.RuleID ?? leak.Description ?? "unknown";
            return `commit=${commit} file=${file} rule=${rule}`;
          });

          const uniqueFiles = [...new Set(leaksData.map((l) => l.File ?? "unknown").filter(Boolean))];

          findings.push({
            id: "GIT_HISTORY_SECRET",
            title: `Secret detected in git history (${leaksData.length} finding${leaksData.length === 1 ? "" : "s"})`,
            severity: "HIGH",
            files: uniqueFiles,
            evidence,
            requiredActions: [
              "Secrets in git history remain exposed even after removal from the working tree.",
              "Rotate all exposed credentials immediately.",
              "Use git-filter-repo or BFG Repo-Cleaner to purge the secrets from history, then force-push and notify all collaborators to re-clone.",
              "Enable branch protection and secret scanning alerts on the remote host."
            ]
          });
        }
      }
    } catch {
      // report parse failure — non-fatal
    } finally {
      try { await unlink(tmpReport); } catch { /* ignore cleanup failure */ }
    }
  }

  return findings;
}
