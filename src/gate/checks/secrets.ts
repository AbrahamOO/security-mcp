import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";
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
  { name: "npmrc_auth_token",        regex: /_authToken\s*=\s*[A-Za-z0-9_\-\.]{10,}/, description: "npm _authToken in .npmrc" },
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

function previewLine(text: string, index: number): string {
  const lineStart = text.lastIndexOf("\n", index);
  const lineEnd = text.indexOf("\n", index);
  return text.slice(lineStart === -1 ? 0 : lineStart + 1, lineEnd === -1 ? undefined : lineEnd).trim();
}

/** Scan decoded text against all SECRET_PATTERNS; returns first match name or null */
function matchSecretPatterns(decoded: string): { name: string; match: string } | null {
  for (const pattern of SECRET_PATTERNS) {
    const m = pattern.regex.exec(decoded);
    if (m) return { name: pattern.name, match: m[0] };
  }
  return null;
}

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

  const files = await fg(["**/*.*", "**/.*"], {
    dot: true,
    onlyFiles: true,
    ignore: IGNORE_LIST
  });

  // ------------------------------------------------------------------
  // Fix 8: Warn when dist/ exists but is excluded from scanning
  // ------------------------------------------------------------------
  const distExists = existsSync("dist") || existsSync("./dist");
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
        const leaksData = JSON.parse(raw) as Array<{
          RuleID?: string;
          File?: string;
          Commit?: string;
          Secret?: string;
          Description?: string;
        }>;

        if (Array.isArray(leaksData) && leaksData.length > 0) {
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
      try { await unlink(tmpReport); } catch {}
    }
  }

  return findings;
}
