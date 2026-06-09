import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";

// Split into two patterns to stay under the 256-char ReDoS guard in searchRepo.
// AWS + GCP secret managers
const SECRET_MANAGER_PATTERN_A = [
  "secretsmanager",                            // AWS Secrets Manager
  "ssm:GetParameter|GetSecretValue",           // AWS SSM Parameter Store
  String.raw`secretmanager\.googleapis`,       // GCP Secret Manager REST/gRPC
  "google_secret_manager",                     // GCP Terraform resource
  "SecretManagerServiceClient",                // GCP Secret Manager client lib
].join("|");

// Azure + HashiCorp Vault + Doppler + 1Password
const SECRET_MANAGER_PATTERN_B = [
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
  String.raw`\bContributor\b.*roleDefinitionId|\bOwner\b.*roleDefinitionId`; // Azure Contributor/Owner (word-bounded to avoid matching variable names)

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

  // 1. Secret manager usage — cloud-agnostic check (split across two searches
  //    to stay under the 256-char ReDoS guard in searchRepo)
  const [smRefsA, smRefsB] = await Promise.all([
    searchRepo({ query: SECRET_MANAGER_PATTERN_A, isRegex: true, maxMatches: 5 }),
    searchRepo({ query: SECRET_MANAGER_PATTERN_B, isRegex: true, maxMatches: 5 })
  ]);
  const secretManagerRefs = [...smRefsA, ...smRefsB];
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

  // 6–16. Additional cloud-specific checks (all searches run in parallel)
  const [
    imdsv1Results,
    lambdaUrlNoAuthResults,
    ecrNoScanResults,
    ecsHostNetworkResults,
    cloudtrailNotMultiregionResults,
    s3NoAccessLoggingResults,
    vpcNoFlowLogsResults,
    assumeRoleResults,
    externalIdResults,
    gcpDefaultSaResults,
    gcpProjectSshResults,
    gcpExternalIpResults,
    azurePublicNetworkResults,
    dbNoDeletionProtectionResults,
    vpcEndpointResults,
    awsInfraResults,
    guarddutyResults,
    securityHubResults,
  ] = await Promise.all([
    // hop_limit [2-9] misses values >= 10; use \d{2,}|[2-9] to catch all insecure values
    searchRepo({ query: String.raw`http_tokens\s*=\s*"optional"|http_put_response_hop_limit\s*=\s*(?:[2-9]|\d{2,})`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`(?:FunctionUrlAuthType|authorization_type)\s*[=:]\s*"NONE"`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`scan_on_push\s*=\s*false`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`(?:network_mode|networkMode)\s*[=:]\s*"host"`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`is_multi_region_trail\s*=\s*false|"IsMultiRegionTrail"\s*:\s*false`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`"LoggingEnabled"\s*:\s*\{\s*\}|target_bucket\s*=\s*""`, isRegex: true, maxMatches: 200 }),
    // aws_vpc has no enable_flow_log attr; use aws_flow_log resource absence as the signal instead
    searchRepo({ query: String.raw`aws_flow_log`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`"Action"\s*:\s*"sts:AssumeRole"`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`sts:ExternalId`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`-compute@developer\.gserviceaccount\.com`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`"ssh-keys"\s*:`, isRegex: true, maxMatches: 200 }),
    // access_config {} catches only ephemeral IPs; access_config { nat_ip = ... } (static) also exposes external IP
    searchRepo({ query: String.raw`access_config\s*\{`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`public_network_access_enabled\s*=\s*true`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`(?:deletion_protection|enable_deletion_protection)\s*=\s*false`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`aws_vpc_endpoint`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`aws_(?:instance|ecs_service|lambda_function)`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`aws_guardduty_detector`, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: String.raw`aws_securityhub_account`, isRegex: true, maxMatches: 200 }),
  ]);

  // 6. IMDSv1 accessible
  if (imdsv1Results.length > 0) {
    findings.push({
      id: "INFRA_IMDSV1_ACCESSIBLE",
      title: "IMDSv1 still accessible on EC2 — SSRF attackers can reach 169.254.169.254 for IAM credentials",
      severity: "CRITICAL",
      evidence: imdsv1Results.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Set http_tokens = \"required\" on all aws_instance and launch template resources.",
        "Set http_put_response_hop_limit = 1 to prevent hop-based SSRF escalation.",
        "Enforce IMDSv2-only at the AWS account level via EC2 default metadata options."
      ]
    });
  }

  // 7. Lambda URL no auth
  if (lambdaUrlNoAuthResults.length > 0) {
    findings.push({
      id: "INFRA_LAMBDA_URL_NO_AUTH",
      title: "Lambda function URL with no authentication — publicly invocable by anyone",
      severity: "CRITICAL",
      evidence: lambdaUrlNoAuthResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Set authorization_type = \"AWS_IAM\" on all aws_lambda_function_url resources.",
        "Use a CloudFront distribution with signed URLs or an API Gateway with IAM/Cognito auth as an alternative.",
        "If public invocation is intentional, add CORS restrictions and rate limiting."
      ]
    });
  }

  // 8. ECR scan on push disabled
  if (ecrNoScanResults.length > 0) {
    findings.push({
      id: "INFRA_ECR_NO_SCAN",
      title: "ECR scan-on-push disabled — container images deployed without CVE scanning",
      severity: "HIGH",
      evidence: ecrNoScanResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Set scan_on_push = true on all aws_ecr_repository resources.",
        "Enable ECR Enhanced Scanning (Inspector-based) for continuous vulnerability monitoring.",
        "Gate deployments on zero critical/high CVEs using CI checks against ECR scan results."
      ]
    });
  }

  // 9. ECS host network
  if (ecsHostNetworkResults.length > 0) {
    findings.push({
      id: "INFRA_ECS_HOST_NETWORK",
      title: "ECS task using host network mode — bypasses container network isolation",
      severity: "HIGH",
      evidence: ecsHostNetworkResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Use network_mode = \"awsvpc\" for Fargate or bridge mode for EC2 ECS tasks.",
        "Host networking exposes all host ports to the container — remove unless strictly required.",
        "Apply security groups at the task level when using awsvpc mode."
      ]
    });
  }

  // 10. CloudTrail not multi-region
  if (cloudtrailNotMultiregionResults.length > 0) {
    findings.push({
      id: "INFRA_CLOUDTRAIL_NOT_MULTIREGION",
      title: "CloudTrail is not multi-region — attacker actions in secondary regions go unlogged",
      severity: "HIGH",
      evidence: cloudtrailNotMultiregionResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Set is_multi_region_trail = true on all aws_cloudtrail resources.",
        "Enable CloudTrail in all opted-in regions including global service events.",
        "Send CloudTrail logs to a dedicated, cross-account S3 bucket with MFA delete enabled."
      ]
    });
  }

  // 11. S3 server access logging disabled
  if (s3NoAccessLoggingResults.length > 0) {
    findings.push({
      id: "INFRA_S3_NO_ACCESS_LOGGING",
      title: "S3 server access logging not enabled — exfiltration events undetectable post-incident",
      severity: "MEDIUM",
      evidence: s3NoAccessLoggingResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Configure server access logging on all S3 buckets by specifying a target_bucket.",
        "Use AWS CloudTrail data events as a supplementary audit trail for S3 object-level operations.",
        "Retain access logs for at least 90 days and ship to a SIEM for alerting."
      ]
    });
  }

  // 12. VPC flow logs missing (absence check: AWS infra present but no aws_flow_log resource found)
  if (awsInfraResults.length > 0 && vpcNoFlowLogsResults.length === 0) {
    findings.push({
      id: "INFRA_VPC_NO_FLOW_LOGS",
      title: "No aws_flow_log resource found — VPC network traffic is unlogged, lateral movement and exfiltration undetectable",
      severity: "MEDIUM",
      requiredActions: [
        "Add an aws_flow_log resource for each VPC and ship logs to CloudWatch Logs or S3.",
        "Set flow log aggregation interval to 1 minute for near-real-time detection.",
        "Create CloudWatch metric filters and alarms for rejected traffic spikes."
      ]
    });
  }

  // 13. Cross-account trust without ExternalId
  if (assumeRoleResults.length > 0 && externalIdResults.length === 0) {
    findings.push({
      id: "INFRA_CROSS_ACCOUNT_NO_EXTERNAL_ID",
      title: "Cross-account IAM trust without sts:ExternalId condition — confused deputy attack possible",
      severity: "HIGH",
      evidence: assumeRoleResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Add a Condition block with sts:ExternalId to all cross-account AssumeRole trust policies.",
        "Use a unique, unguessable ExternalId per third-party relationship and rotate periodically.",
        "Audit all cross-account role trusts with AWS IAM Access Analyzer."
      ]
    });
  }

  // 14. GCP default service account
  if (gcpDefaultSaResults.length > 0) {
    findings.push({
      id: "INFRA_GCP_DEFAULT_SERVICE_ACCOUNT",
      title: "GCP instance uses default Compute Engine service account — broad project-level API permissions",
      severity: "HIGH",
      evidence: gcpDefaultSaResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Create a dedicated, least-privilege service account for each GCP compute resource.",
        "Disable the default Compute Engine service account or remove the Editor role binding.",
        "Use Workload Identity Federation instead of service account keys where possible."
      ]
    });
  }

  // 15. GCP project-level SSH keys
  if (gcpProjectSshResults.length > 0) {
    findings.push({
      id: "INFRA_GCP_PROJECT_SSH_KEYS",
      title: "GCP project-level SSH keys set — single key compromise grants access to all instances",
      severity: "MEDIUM",
      evidence: gcpProjectSshResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Remove project-level SSH keys from project metadata and use instance-level keys only.",
        "Prefer OS Login over metadata-based SSH keys for centralized IAM-controlled access.",
        "Rotate any existing project-level SSH keys immediately and audit which instances they reached."
      ]
    });
  }

  // 16. GCP compute external IP
  if (gcpExternalIpResults.length > 0) {
    findings.push({
      id: "INFRA_GCP_EXTERNAL_IP",
      title: "GCP compute instance has external IP — directly internet-reachable without load balancer",
      severity: "MEDIUM",
      evidence: gcpExternalIpResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Remove access_config blocks from google_compute_instance resources to disable external IPs.",
        "Route traffic through a GCP Cloud Load Balancer or Cloud NAT instead of direct external IPs.",
        "Use Identity-Aware Proxy (IAP) for admin access rather than exposing SSH/RDP externally."
      ]
    });
  }

  // 17. Azure public network access
  if (azurePublicNetworkResults.length > 0) {
    findings.push({
      id: "INFRA_AZURE_PUBLIC_NETWORK_ACCESS",
      title: "Azure managed service with public_network_access_enabled=true — reachable from internet",
      severity: "HIGH",
      evidence: azurePublicNetworkResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Set public_network_access_enabled = false on all Azure managed services.",
        "Use Private Endpoints and Private DNS Zones for internal connectivity.",
        "Apply Azure Firewall or NSG rules to restrict any legitimately public-facing services."
      ]
    });
  }

  // 18. Database deletion protection disabled
  if (dbNoDeletionProtectionResults.length > 0) {
    findings.push({
      id: "INFRA_DB_NO_DELETION_PROTECTION",
      title: "Database resource missing deletion protection — single terraform apply can permanently destroy prod DB",
      severity: "HIGH",
      evidence: dbNoDeletionProtectionResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Set deletion_protection = true on all aws_db_instance, aws_rds_cluster, and equivalent resources.",
        "Enable automated backups with a retention window of at least 7 days.",
        "Use Terraform prevent_destroy lifecycle rules as an additional safeguard."
      ]
    });
  }

  // 19. Missing VPC endpoint for S3/ECR
  if (awsInfraResults.length > 0 && vpcEndpointResults.length === 0) {
    findings.push({
      id: "INFRA_NO_VPC_ENDPOINT",
      title: "No VPC endpoint found for AWS services — traffic routes over public internet",
      severity: "MEDIUM",
      evidence: awsInfraResults.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`),
      requiredActions: [
        "Create aws_vpc_endpoint resources for S3, ECR (api + dkr), and other frequently used AWS services.",
        "Use Gateway endpoints for S3/DynamoDB (free) and Interface endpoints for other services.",
        "Set the VPC endpoint policy to restrict access to specific S3 buckets or ECR repositories."
      ]
    });
  }

  // 20. GuardDuty not enabled
  if (awsInfraResults.length > 0 && guarddutyResults.length === 0) {
    findings.push({
      id: "INFRA_GUARDDUTY_MISSING",
      title: "No GuardDuty detector resource found — threat detection (credential misuse, crypto-mining) disabled",
      severity: "HIGH",
      requiredActions: [
        "Add an aws_guardduty_detector resource with enable = true to your Terraform.",
        "Enable GuardDuty in all AWS regions and aggregate findings into a delegated admin account.",
        "Subscribe to GuardDuty findings via EventBridge and route high-severity alerts to your on-call channel."
      ]
    });
  }

  // 21. Security Hub not enabled
  if (awsInfraResults.length > 0 && securityHubResults.length === 0) {
    findings.push({
      id: "INFRA_SECURITY_HUB_MISSING",
      title: "AWS Security Hub not enabled — findings from GuardDuty/Inspector/Macie not centrally aggregated",
      severity: "MEDIUM",
      requiredActions: [
        "Add an aws_securityhub_account resource to your Terraform.",
        "Enable the AWS Foundational Security Best Practices and CIS AWS Foundations standards.",
        "Aggregate Security Hub findings across regions and accounts into a central delegated admin."
      ]
    });
  }

  return findings;
}
