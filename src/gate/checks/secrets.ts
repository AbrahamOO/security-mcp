import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

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
  { name: "sendgrid_api_key",        regex: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/, description: "SendGrid API key" },
  { name: "mailgun_api_key",         regex: /\bkey-[A-Za-z0-9]{32}\b/, description: "Mailgun API key" },

  // LLM / AI providers
  { name: "openai_api_key",          regex: /\bsk-[A-Za-z0-9]{20,}\b/, description: "OpenAI API key" },
  { name: "anthropic_api_key",       regex: /\bsk-ant-[A-Za-z0-9\-_]{40,}\b/, description: "Anthropic API key" },
  { name: "huggingface_token",       regex: /\bhf_[A-Za-z0-9]{34}\b/, description: "HuggingFace token" },
  { name: "cohere_api_key",          regex: /\bCOHERE_API_KEY\s*[:=]\s*["'][A-Za-z0-9]{40}["']/, description: "Cohere API key" },

  // Database connection strings with embedded credentials
  { name: "db_connection_string",    regex: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^:]+:[^@\s]{6,}@/, description: "Database connection string with embedded credentials" },
  { name: "jdbc_credentials",        regex: /jdbc:[a-z]+:\/\/[^;]+;?[Pp]assword=[^;\s"']{6,}/, description: "JDBC connection string with password" },

  // Infrastructure tokens
  { name: "hashicorp_vault_token",   regex: /\bhvs\.[A-Za-z0-9]{24,}\b/, description: "HashiCorp Vault service token" },
  { name: "npm_token",               regex: /\bnpm_[A-Za-z0-9]{36}\b/, description: "npm access token" },
  { name: "docker_hub_pat",          regex: /\bdckr_pat_[A-Za-z0-9\-_]{27}\b/, description: "Docker Hub personal access token" },
  { name: "terraform_cloud_token",   regex: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{60,}\b/, description: "Terraform Cloud token" },
  { name: "datadog_api_key",         regex: /\bDD_API_KEY\s*[:=]\s*["'][a-fA-F0-9]{32}["']/, description: "Datadog API key" },
  { name: "new_relic_key",           regex: /\bNEW_RELIC_LICENSE_KEY\s*[:=]\s*["'][A-Za-z0-9]{40}["']/, description: "New Relic license key" },

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

export async function checkSecrets(_: { changedFiles: string[] }): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await fg(["**/*.*"], {
    dot: true,
    onlyFiles: true,
    ignore: [
      "**/node_modules/**",
      "**/.git/**",
      "**/dist/**",
      "**/fixtures/**",
      "**/.mcp/reviews/**",
      "**/.mcp/reports/**"
    ]
  });

  // Track hits per pattern so each type gets its own finding with specific guidance
  const hitsByPattern = new Map<string, string[]>();

  for (const file of files) {
    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue;
    }

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
  }

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

  return findings;
}
