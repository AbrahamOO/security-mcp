import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";

// Patterns that indicate a supported secret manager is in use — cloud-agnostic.
// Covers: AWS Secrets Manager, AWS SSM Parameter Store, GCP Secret Manager,
// Azure Key Vault, HashiCorp Vault, Doppler, 1Password Secrets Automation.
const SECRET_MANAGER_PATTERN = [
  "secretsmanager",                            // AWS Secrets Manager (SDK + SDK v3)
  "ssm:GetParameter|GetSecretValue",           // AWS SSM Parameter Store
  String.raw`secretmanager\.googleapis`,       // GCP Secret Manager REST/gRPC
  "google_secret_manager",                     // GCP Terraform resource
  "SecretManagerServiceClient",                // GCP Secret Manager client lib
  "@azure/keyvault",                           // Azure Key Vault SDK (JS/TS)
  String.raw`azure\.keyvault`,                 // Azure Key Vault (Python)
  "KeyVaultSecret|SecretClient",               // Azure Key Vault client classes
  String.raw`vault\.read|vault\.write`,        // HashiCorp Vault API calls
  "hvault:|vault_generic_secret",              // HashiCorp Vault Terraform
  "doppler run|DOPPLER_TOKEN",                 // Doppler
  "op run|op read|onepassword",                // 1Password Secrets Automation
].join("|");

// IAM wildcard patterns — any cloud provider
const IAM_WILDCARD_PATTERN =
  String.raw`"Action"\s*:\s*"\*"|` +           // AWS IAM wildcard action
  String.raw`"Resource"\s*:\s*"\*"|` +          // AWS IAM wildcard resource
  String.raw`roles/owner|roles/editor|` +       // GCP over-privileged built-in roles
  String.raw`allUsers|allAuthenticatedUsers|` + // GCP public IAM
  String.raw`"role"\s*:\s*"roles/owner"|` +     // GCP Terraform owner binding
  String.raw`contributor|Owner\b.*roleDefinitionId`; // Azure Contributor/Owner

// Public network exposure — Terraform, K8s, CloudFormation, ARM, CDK
const PUBLIC_INGRESS_PATTERN =
  String.raw`0\.0\.0\.0/0|::/0|` +
  String.raw`public\s*=\s*true|` +
  String.raw`PubliclyAccessible\s*:\s*true|` +  // AWS RDS
  String.raw`allow_stopping_for_update.*true|` +
  String.raw`internet-facing|` +               // AWS ALB scheme
  String.raw`"Scheme"\s*:\s*"internet-facing"|` +
  String.raw`block_public_acls\s*=\s*false|` + // AWS S3 block public access disabled
  String.raw`restrict_public_buckets\s*=\s*false`;

// Logging / audit disabled
const LOGGING_DISABLED_PATTERN =
  String.raw`enable_logging\s*=\s*false|` +
  String.raw`log_config\s*\{\s*\}|` +          // GCP empty log config
  String.raw`"CloudWatchLogs"\s*:\s*\{\s*\}|` + // AWS empty CloudWatch config
  String.raw`disable_api_termination\s*=\s*true|` +
  String.raw`deletion_protection\s*=\s*false`;

// Encryption disabled
const ENCRYPTION_DISABLED_PATTERN =
  String.raw`encrypted\s*=\s*false|` +         // AWS EBS, RDS
  String.raw`enable_encryption\s*=\s*false|` +
  String.raw`kms_key_id\s*=\s*""|` +
  String.raw`storage_encrypted\s*=\s*false|` +
  String.raw`"EnableEncryption"\s*:\s*false`;

export async function checkInfra(_: { changedFiles: string[] }): Promise<Finding[]> {
  const findings: Finding[] = [];

  // 1. Secret manager usage — cloud-agnostic check
  const secretManagerRefs = await searchRepo({
    query: SECRET_MANAGER_PATTERN,
    isRegex: true,
    maxMatches: 5
  });
  if (secretManagerRefs.length === 0) {
    findings.push({
      id: "SECRET_MANAGER_NOT_DETECTED",
      title: "No secret manager usage detected — secrets may be hardcoded or in env files",
      severity: "HIGH",
      requiredActions: [
        "Integrate a cloud secret manager appropriate for your platform:",
        "  • AWS: AWS Secrets Manager or SSM Parameter Store (SecureString)",
        "  • GCP: Secret Manager with Workload Identity",
        "  • Azure: Azure Key Vault with Managed Identity",
        "  • Multi-cloud / self-hosted: HashiCorp Vault, Doppler, or 1Password Secrets Automation",
        "Never store secrets in environment files committed to the repo, CI log output, or container images."
      ]
    });
  }

  // 2. IAM wildcards / over-privileged roles
  const iamWildcards = await searchRepo({
    query: IAM_WILDCARD_PATTERN,
    isRegex: true,
    maxMatches: 200
  });
  if (iamWildcards.length > 0) {
    findings.push({
      id: "IAM_OVERPRIVILEGED",
      title: "Overprivileged IAM role or wildcard permission detected",
      severity: "HIGH",
      evidence: iamWildcards.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Apply least-privilege to every IAM role — enumerate only the specific actions and resources required.",
        "Replace wildcard actions ('*') with explicit action lists.",
        "Replace Owner/Contributor/Editor bindings with purpose-scoped custom roles.",
        "Run IAM Access Analyzer (AWS) or Policy Analyzer (GCP) to detect unused permissions."
      ]
    });
  }

  // 3. Public network exposure
  const publicIngress = await searchRepo({
    query: PUBLIC_INGRESS_PATTERN,
    isRegex: true,
    maxMatches: 200
  });
  if (publicIngress.length > 0) {
    findings.push({
      id: "PUBLIC_EXPOSURE_RISK",
      title: "Public network exposure detected in IaC or cloud config",
      severity: "HIGH",
      evidence: publicIngress.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Restrict ingress to known CIDR ranges or private VPC subnets only.",
        "Place public load balancers in a DMZ; never expose internal services directly.",
        "Enable S3 Block Public Access at the account level.",
        "Use Zero Trust network access (BeyondCorp / Zscaler / Cloudflare Access) instead of IP allowlisting."
      ]
    });
  }

  // 4. Encryption disabled
  const encryptionDisabled = await searchRepo({
    query: ENCRYPTION_DISABLED_PATTERN,
    isRegex: true,
    maxMatches: 200
  });
  if (encryptionDisabled.length > 0) {
    findings.push({
      id: "ENCRYPTION_DISABLED",
      title: "Encryption at rest explicitly disabled in IaC config",
      severity: "HIGH",
      evidence: encryptionDisabled.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Enable encryption at rest on all storage resources (RDS, EBS, S3, GCS, Azure Blob, etc.).",
        "Use customer-managed keys (CMK/CMEK) for regulated data (PCI, HIPAA, SOC 2).",
        "Never set encrypted=false or storage_encrypted=false in Terraform."
      ]
    });
  }

  // 5. Audit logging disabled
  const loggingDisabled = await searchRepo({
    query: LOGGING_DISABLED_PATTERN,
    isRegex: true,
    maxMatches: 200
  });
  if (loggingDisabled.length > 0) {
    findings.push({
      id: "AUDIT_LOGGING_DISABLED",
      title: "Audit logging or deletion protection explicitly disabled in IaC config",
      severity: "MEDIUM",
      evidence: loggingDisabled.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Enable audit logging on all cloud resources and ship logs to a centralised, tamper-evident store.",
        "Enable deletion protection on databases and stateful resources.",
        "Retain audit logs for at least 1 year (SOC 2 / PCI DSS requirement)."
      ]
    });
  }

  return findings;
}
