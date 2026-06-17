import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";

// ---------------------------------------------------------------------------
// Pattern definitions. Each string is kept well under 256 chars and contains
// no nested quantifiers (the searchRepo ReDoS guard rejects (x+)+, (a|b)+, etc.).
// Patterns are alternations of literal-ish tokens. String.raw is used so that
// backslashes survive into the regex source.
// ---------------------------------------------------------------------------

// 1. Terraform state secrets / unencrypted or unlocked remote backend.
const TF_STATE_PATTERN =
  String.raw`encrypt\s*=\s*false|` +              // s3 backend encryption off
  String.raw`backend\s+"local"|` +                // local backend for shared infra
  String.raw`skip_credentials_validation\s*=\s*true|` +
  String.raw`skip_metadata_api_check\s*=\s*true`;

// Heuristic: an s3 backend block present but no dynamodb_table lock key.
const TF_BACKEND_S3_PATTERN = String.raw`backend\s+"s3"`;
const TF_BACKEND_LOCK_PATTERN = String.raw`dynamodb_table\s*=`;

// 2. Unpinned / mutable module & provider sources.
const TF_UNPINNED_PATTERN =
  String.raw`source\s*=\s*"git::|` +              // git module source (ref checked below)
  String.raw`source\s*=\s*"github\.com|` +
  String.raw`\?ref=master"|\?ref=main"|\?ref=HEAD"`; // branch refs (mutable)
const TF_PROVIDER_PATTERN = String.raw`provider\s+"aws"|provider\s+"google"|provider\s+"azurerm"`;
const TF_VERSION_PATTERN = String.raw`version\s*=`;

// 3. local-exec / remote-exec provisioner RCE surface.
const TF_PROVISIONER_PATTERN =
  String.raw`provisioner\s+"local-exec"|` +
  String.raw`provisioner\s+"remote-exec"|` +
  String.raw`"local-exec"|"remote-exec"`;

// 4. Hardcoded secrets/credentials. Tight: token must be assigned a literal.
const SECRET_PATTERN_A =
  String.raw`access_key\s*=\s*"[A-Za-z0-9/+]{8}|` +
  String.raw`secret_key\s*=\s*"[A-Za-z0-9/+]{8}|` +
  String.raw`password\s*=\s*"[^"$\s]{4}|` +
  String.raw`password\s*:\s*"[^"$\s]{4}`;
const SECRET_PATTERN_B =
  String.raw`private_key\s*=\s*"-----BEGIN|` +
  String.raw`token\s*=\s*"[A-Za-z0-9_-]{12}|` +
  String.raw`api_key\s*=\s*"[A-Za-z0-9_-]{12}|` +
  String.raw`client_secret\s*=\s*"[A-Za-z0-9_-]{8}`;

// 5. Terraform outputs missing sensitive = true (heuristic markers).
const TF_OUTPUT_SECRET_PATTERN =
  String.raw`output\s+"[a-z_]*password|` +
  String.raw`output\s+"[a-z_]*secret|` +
  String.raw`output\s+"[a-z_]*token|` +
  String.raw`output\s+"[a-z_]*private_key`;
const TF_SENSITIVE_PATTERN = String.raw`sensitive\s*=\s*true`;

// 6. Disabled validation / destructive safety toggles.
const TF_UNSAFE_PATTERN =
  String.raw`skip_final_snapshot\s*=\s*true|` +
  String.raw`force_destroy\s*=\s*true|` +
  String.raw`skip_provider_registration\s*=\s*true|` +
  String.raw`disable_rollback\s*=\s*true`;

// 7. Wildcard / over-broad CloudFormation & inline IAM JSON.
const CFN_IAM_WILDCARD_PATTERN =
  String.raw`"Action"\s*:\s*"\*"|` +
  String.raw`"Resource"\s*:\s*"\*"|` +
  String.raw`"Action"\s*:\s*\[\s*"\*"`;

// 8. Pulumi plaintext secrets / hardcoded creds.
const PULUMI_PLAINTEXT_PATTERN =
  String.raw`config:[a-zA-Z0-9_-]*password|` +    // Pulumi.<stack>.yaml plaintext value
  String.raw`config:[a-zA-Z0-9_-]*secret|` +
  String.raw`new\s+aws\.Provider\(|` +            // inline provider with creds
  String.raw`accessKey:\s*"[A-Za-z0-9/+]{8}|` +
  String.raw`secretKey:\s*"[A-Za-z0-9/+]{8}`;

// 9. Ansible insecure task patterns.
const ANSIBLE_PATTERN_A =
  String.raw`no_log:\s*false|` +
  String.raw`validate_certs:\s*no|` +
  String.raw`validate_certs:\s*false|` +
  String.raw`validate_certs:\s*"no"`;
const ANSIBLE_PATTERN_B =
  String.raw`ansible_become_pass:\s*[^{\s]|` +    // hardcoded sudo password
  String.raw`ansible_ssh_pass:\s*[^{\s]|` +
  String.raw`ansible_password:\s*[^{\s]`;

// 10. Public exposure introduced by IaC (S3 ACL, RDS public).
const IAC_PUBLIC_PATTERN =
  String.raw`acl\s*=\s*"public-read"|` +
  String.raw`acl\s*=\s*"public-read-write"|` +
  String.raw`publicly_accessible\s*=\s*true|` +
  String.raw`"PubliclyAccessible"\s*:\s*true`;

// ===========================================================================
// Round 2 — CloudFormation DEEP, CDK/SAM/Bicep/ARM breadth, Terraform DEPTH.
// ===========================================================================

// --- CloudFormation: public S3 (PublicAccessBlock off / policy Principal *) ---
const CFN_S3_PUBLIC_PATTERN =
  String.raw`"BlockPublicAcls"\s*:\s*false|` +
  String.raw`"BlockPublicPolicy"\s*:\s*false|` +
  String.raw`"IgnorePublicAcls"\s*:\s*false|` +
  String.raw`"RestrictPublicBuckets"\s*:\s*false|` +
  String.raw`"AccessControl"\s*:\s*"PublicRead`;

// --- CloudFormation: security group ingress open to the world ---
const CFN_SG_OPEN_PATTERN =
  String.raw`"CidrIp"\s*:\s*"0\.0\.0\.0/0"|` +
  String.raw`"CidrIpv6"\s*:\s*"::/0"`;

// --- CloudFormation: RDS/Redshift publicly accessible ---
const CFN_DB_PUBLIC_PATTERN =
  String.raw`"PubliclyAccessible"\s*:\s*true|` +
  String.raw`"PubliclyAccessible"\s*:\s*"true"`;

// --- CloudFormation: encryption disabled / missing ---
const CFN_ENCRYPTION_PATTERN =
  String.raw`"StorageEncrypted"\s*:\s*false|` +
  String.raw`"Encrypted"\s*:\s*false|` +
  String.raw`"SSEEnabled"\s*:\s*false|` +
  String.raw`"BucketEncryption"\s*:\s*\{\s*\}`;

// --- CloudFormation: secret Parameter without NoEcho (heuristic per-line) ---
const CFN_PARAM_SECRET_PATTERN =
  String.raw`"[A-Za-z]*Password"\s*:\s*\{|` +
  String.raw`"[A-Za-z]*Secret"\s*:\s*\{|` +
  String.raw`"[A-Za-z]*Token"\s*:\s*\{|` +
  String.raw`"[A-Za-z]*ApiKey"\s*:\s*\{`;
const CFN_NOECHO_PATTERN = String.raw`"NoEcho"\s*:\s*true`;

// --- CloudFormation: secret literal inline in template ---
const CFN_INLINE_SECRET_PATTERN =
  String.raw`"MasterUserPassword"\s*:\s*"[^"$\s{]|` +
  String.raw`"Password"\s*:\s*"[^"$\s{]|` +
  String.raw`"Token"\s*:\s*"[A-Za-z0-9_-]{8}|` +
  String.raw`"SecretString"\s*:\s*"[^"$\s{]`;

// --- CloudFormation: IAM PassRole wildcard ---
const CFN_PASSROLE_PATTERN =
  String.raw`"iam:PassRole"|` +
  String.raw`"Action"\s*:\s*"iam:\*"`;

// --- CloudFormation: IAM::User with inline access key ---
const CFN_IAM_USER_KEY_PATTERN =
  String.raw`AWS::IAM::AccessKey|` +
  String.raw`"AccessKeyId"\s*:\s*"AKIA`;

// --- CloudFormation: Lambda public function URL (AuthType NONE) ---
const CFN_LAMBDA_URL_PATTERN =
  String.raw`"AuthType"\s*:\s*"NONE"`;

// --- CloudFormation: SNS/SQS/Lambda resource policy Principal "*" ---
const CFN_RESOURCE_PRINCIPAL_PATTERN =
  String.raw`"Principal"\s*:\s*"\*"|` +
  String.raw`"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"`;

// --- CloudFormation: CloudTrail not multi-region / no log validation ---
const CFN_CLOUDTRAIL_PATTERN =
  String.raw`"IsMultiRegionTrail"\s*:\s*false|` +
  String.raw`"EnableLogFileValidation"\s*:\s*false`;

// --- CloudFormation: !Sub / TemplateURL untrusted, cfn-init external URL ---
const CFN_UNTRUSTED_URL_PATTERN =
  String.raw`"TemplateURL"\s*:\s*"http://|` +
  String.raw`"TemplateURL"\s*:\s*".*\.s3-website|` +
  String.raw`source\s*=\s*"http://|` +
  String.raw`"source"\s*:\s*"http://`;

// --- CloudFormation: stateful resource without DeletionPolicy: Retain ---
const CFN_STATEFUL_PATTERN =
  String.raw`AWS::RDS::DBInstance|` +
  String.raw`AWS::DynamoDB::Table|` +
  String.raw`AWS::S3::Bucket"`;
const CFN_DELETION_RETAIN_PATTERN = String.raw`"DeletionPolicy"\s*:\s*"Retain"`;

// --- CloudFormation: EC2 IMDSv1 (no token required) ---
const CFN_IMDS_PATTERN =
  String.raw`"HttpTokens"\s*:\s*"optional"`;

// --- CDK: escape-hatch wildcard / removalPolicy DESTROY ---
const CDK_PATTERN =
  String.raw`addToRolePolicy|` +
  String.raw`actions:\s*\[\s*['"]\*['"]|` +
  String.raw`resources:\s*\[\s*['"]\*['"]|` +
  String.raw`RemovalPolicy\.DESTROY|` +
  String.raw`removalPolicy:\s*cdk\.RemovalPolicy\.DESTROY`;

// --- SAM: Globals open CORS "*" ---
const SAM_CORS_PATTERN =
  String.raw`AllowOrigin\s*:\s*"'\*'"|` +
  String.raw`AllowOrigin:\s*'\*'|` +
  String.raw`"AllowOrigins"\s*:\s*\[\s*"\*"`;

// --- Bicep/ARM: insecure network / TLS / public blob / privileged role ---
const BICEP_PATTERN_A =
  String.raw`publicNetworkAccess:\s*'Enabled'|` +
  String.raw`"publicNetworkAccess"\s*:\s*"Enabled"|` +
  String.raw`supportsHttpsTrafficOnly:\s*false|` +
  String.raw`allowBlobPublicAccess:\s*true`;
const BICEP_PATTERN_B =
  String.raw`minimumTlsVersion:\s*'TLS1_0'|` +
  String.raw`minimumTlsVersion:\s*'TLS1_1'|` +
  String.raw`defaultAction:\s*'Allow'|` +
  String.raw`"defaultAction"\s*:\s*"Allow"`;
// Azure built-in Owner / Contributor role definition GUIDs.
const BICEP_ROLE_PATTERN =
  String.raw`8e3af657-a8ff-443c-a75c-2fe8c4bcb635|` +   // Owner
  String.raw`b24988ac-6180-42a0-ab88-20f7382dd24c`;     // Contributor

// --- Terraform DEPTH ---
const TF_TFVARS_SECRET_PATTERN =
  String.raw`password\s*=\s*"[^"$\s]{4}|` +
  String.raw`secret\s*=\s*"[^"$\s]{4}|` +
  String.raw`token\s*=\s*"[A-Za-z0-9_-]{8}|` +
  String.raw`api_key\s*=\s*"[A-Za-z0-9_-]{8}`;
const TF_SENSITIVE_FALSE_PATTERN = String.raw`sensitive\s*=\s*false`;
const TF_HTTP_DATA_PATTERN =
  String.raw`data\s+"http"|` +
  String.raw`data\s+"terraform_remote_state".*http://|` +
  String.raw`address\s*=\s*"http://`;
const TF_NULL_RESOURCE_PATTERN = String.raw`resource\s+"null_resource"`;
const TF_VAULT_TOKEN_PATTERN =
  String.raw`provider\s+"vault"|token\s*=\s*"s\.[A-Za-z0-9]{8}|token\s*=\s*"hvs\.[A-Za-z0-9]{8}`;
const TF_DEFAULT_VPC_PATTERN =
  String.raw`resource\s+"aws_default_vpc"|` +
  String.raw`resource\s+"aws_default_security_group"|` +
  String.raw`resource\s+"aws_default_subnet"`;
const TF_INSECURE_TLS_PATTERN =
  String.raw`allow_unverified_ssl\s*=\s*true|` +
  String.raw`insecure\s*=\s*true|` +
  String.raw`skip_tls_verify\s*=\s*true`;

// ===========================================================================
// Round 3 — EXTRA-DEEP Terraform-specific detection (prefix IAC_TF_).
// ===========================================================================

// Provider auth: hardcoded creds / committed credential files / inline JSON key.
const TF_PROVIDER_CREDS_PATTERN =
  String.raw`shared_credentials_file\s*=|` +
  String.raw`credentials\s*=\s*file\(|` +
  String.raw`credentials\s*=\s*"\{|` +                 // inline GCP JSON key
  String.raw`client_secret\s*=\s*"[^"$\s{]|` +         // azurerm inline secret
  String.raw`"private_key_id"\s*:\s*"`;                // committed GCP SA key json

// Backend: S3 without KMS key / no lock / http backend.
const TF_BACKEND_KMS_PATTERN = String.raw`kms_key_id\s*=`;
const TF_BACKEND_HTTP_PATTERN =
  String.raw`backend\s+"http"|` +
  String.raw`backend\s+"http"\s*\{`;

// Module supply chain: git over http / registry without version / branch ref.
const TF_MODULE_GIT_HTTP_PATTERN =
  String.raw`source\s*=\s*"git::http://|` +
  String.raw`source\s*=\s*"http://`;
const TF_REQUIRED_VERSION_OPEN_PATTERN =
  String.raw`required_version\s*=\s*">=|` +
  String.raw`required_version\s*=\s*">\s`;

// S3 hardening: bucket present but SSE/public-access-block resources absent.
const TF_S3_BUCKET_PATTERN = String.raw`resource\s+"aws_s3_bucket"`;
const TF_S3_SSE_PATTERN = String.raw`aws_s3_bucket_server_side_encryption_configuration`;
const TF_S3_PAB_PATTERN = String.raw`aws_s3_bucket_public_access_block`;

// RDS hardening (storage_encrypted false / IAM auth disabled).
const TF_RDS_HARDENING_PATTERN =
  String.raw`storage_encrypted\s*=\s*false|` +
  String.raw`iam_database_authentication_enabled\s*=\s*false`;

// Security group 0.0.0.0/0 on admin ports.
const TF_SG_OPEN_CIDR_PATTERN =
  String.raw`cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"|` +
  String.raw`cidr_blocks\s*=\s*\["0\.0\.0\.0/0"|` +
  String.raw`ipv6_cidr_blocks\s*=\s*\[\s*"::/0"`;

// IAM HCL policy wildcards / AssumeRole Principal "*".
const TF_IAM_WILDCARD_HCL_PATTERN =
  String.raw`"Action"\s*:\s*"\*"|` +
  String.raw`actions\s*=\s*\[\s*"\*"|` +
  String.raw`resources\s*=\s*\[\s*"\*"|` +
  String.raw`identifiers\s*=\s*\[\s*"\*"`;

// EC2 IMDSv1 via metadata_options http_tokens optional.
const TF_IMDS_HCL_PATTERN = String.raw`http_tokens\s*=\s*"optional"`;

// EKS / ECR public.
const TF_EKS_ECR_PUBLIC_PATTERN =
  String.raw`endpoint_public_access\s*=\s*true|` +
  String.raw`resource\s+"aws_ecrpublic_repository"|` +
  String.raw`image_tag_mutability\s*=\s*"MUTABLE"`;

// KMS key rotation disabled.
const TF_KMS_ROTATION_PATTERN = String.raw`enable_key_rotation\s*=\s*false`;

// Long-lived IAM access key resource.
const TF_IAM_ACCESS_KEY_PATTERN = String.raw`resource\s+"aws_iam_access_key"`;

// CloudTrail log file validation disabled.
const TF_CLOUDTRAIL_VALIDATION_PATTERN =
  String.raw`enable_log_file_validation\s*=\s*false`;

// Root/EBS volume encrypted = false.
const TF_VOLUME_UNENCRYPTED_PATTERN =
  String.raw`root_block_device\s*\{|` +
  String.raw`ebs_block_device\s*\{`;
const TF_VOLUME_ENC_FALSE_PATTERN = String.raw`encrypted\s*=\s*false`;

// Variable default that looks like a real secret.
const TF_VAR_DEFAULT_SECRET_PATTERN =
  String.raw`default\s*=\s*"AKIA[A-Z0-9]{6}|` +
  String.raw`default\s*=\s*"ghp_[A-Za-z0-9]{8}|` +
  String.raw`default\s*=\s*"sk-[A-Za-z0-9]{8}|` +
  String.raw`default\s*=\s*"-----BEGIN`;

// user_data / templatefile embedding credentials.
const TF_USERDATA_SECRET_PATTERN =
  String.raw`user_data\s*=.*password|` +
  String.raw`user_data\s*=.*secret|` +
  String.raw`templatefile\(.*password|` +
  String.raw`export\s+[A-Z_]*PASSWORD=|` +
  String.raw`export\s+[A-Z_]*SECRET=`;

// lifecycle ignore_changes = all (masks drift/tampering).
const TF_IGNORE_ALL_PATTERN =
  String.raw`ignore_changes\s*=\s*all|` +
  String.raw`ignore_changes\s*=\s*\[\s*all`;

// prevent_destroy = false on a lifecycle block.
const TF_PREVENT_DESTROY_FALSE_PATTERN = String.raw`prevent_destroy\s*=\s*false`;

// create_before_destroy on a security group (widens exposure window).
const TF_CBD_PATTERN = String.raw`create_before_destroy\s*=\s*true`;

// Committed wrapper scripts using -auto-approve / -target.
const TF_AUTO_APPROVE_PATTERN =
  String.raw`terraform\s+apply\s+.*-auto-approve|` +
  String.raw`terraform\s+destroy\s+.*-auto-approve|` +
  String.raw`-auto-approve`;

export async function checkIac(opts: { changedFiles: string[] }): Promise<Finding[]> {
  void opts; // signature consistency; matching scans the whole repo via searchRepo
  const findings: Finding[] = [];

  const [
    tfState,
    backendS3,
    backendLock,
    unpinned,
    providers,
    versions,
    provisioners,
    secretsA,
    secretsB,
    outputSecrets,
    sensitiveMarkers,
    unsafe,
    cfnWildcard,
    pulumiPlaintext,
    ansibleA,
    ansibleB,
    iacPublic,
  ] = await Promise.all([
    searchRepo({ query: TF_STATE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_BACKEND_S3_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_BACKEND_LOCK_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_UNPINNED_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_PROVIDER_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_VERSION_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_PROVISIONER_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SECRET_PATTERN_A, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SECRET_PATTERN_B, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_OUTPUT_SECRET_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_SENSITIVE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_UNSAFE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_IAM_WILDCARD_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: PULUMI_PLAINTEXT_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: ANSIBLE_PATTERN_A, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: ANSIBLE_PATTERN_B, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: IAC_PUBLIC_PATTERN, isRegex: true, maxMatches: 200 }),
  ]);

  const ev = (m: { file: string; line: number; preview: string }[]) =>
    m.slice(0, 20).map((x) => `${x.file}:${x.line}: ${x.preview}`);

  // 1. Unencrypted / unlocked / local Terraform state backend.
  const stateEvidence = [...tfState];
  if (backendS3.length > 0 && backendLock.length === 0) {
    stateEvidence.push(...backendS3);
  }
  if (stateEvidence.length > 0) {
    findings.push({
      id: "IAC_TF_STATE_INSECURE",
      title: "Terraform remote state is unencrypted, unlocked, or stored on a local backend — state contains plaintext secrets",
      severity: "HIGH",
      evidence: ev(stateEvidence),
      requiredActions: [
        "Set encrypt = true on the S3 backend so state (which holds plaintext secrets) is encrypted at rest.",
        "Add dynamodb_table to the S3 backend to enable state locking and prevent concurrent corrupting applies.",
        "Never use a local backend for shared infrastructure — use S3+DynamoDB, Terraform Cloud, or GCS with versioning.",
        "Restrict the state bucket with a bucket policy, block public access, and enable a customer-managed KMS key.",
      ],
    });
  }

  // 2. Unpinned / mutable module & provider sources.
  const providerNoVersion = providers.length > 0 && versions.length === 0;
  if (unpinned.length > 0 || providerNoVersion) {
    findings.push({
      id: "IAC_TF_UNPINNED_SOURCE",
      title: "Terraform module or provider source is unpinned/mutable — supply-chain tampering via moving ref",
      severity: "HIGH",
      evidence: ev(unpinned.length > 0 ? unpinned : providers),
      requiredActions: [
        "Pin every git module source to an immutable commit SHA: source = \"git::https://...//mod?ref=<40-char-sha>\".",
        "Pin registry modules with an exact version = \"x.y.z\" (not a range).",
        "Add a required_providers block with a pinned version constraint (= or ~> with a lockfile) for every provider.",
        "Commit .terraform.lock.hcl so provider checksums are verified on every init.",
      ],
    });
  }

  // 3. Provisioner RCE surface.
  if (provisioners.length > 0) {
    findings.push({
      id: "IAC_TF_PROVISIONER_EXEC",
      title: "local-exec / remote-exec provisioner detected — command-injection and RCE surface during apply",
      severity: "HIGH",
      evidence: ev(provisioners),
      requiredActions: [
        "Remove local-exec/remote-exec provisioners; use a proper config-management tool or cloud-init instead.",
        "If unavoidable, never interpolate untrusted variables into the command string — use environment/null_resource with fixed args.",
        "Run terraform apply only from a hardened CI runner with no standing cloud credentials.",
        "Audit who can submit plans, since provisioners execute arbitrary commands on the operator's host.",
      ],
    });
  }

  // 4. Hardcoded secrets.
  const secretHits = [...secretsA, ...secretsB];
  if (secretHits.length > 0) {
    findings.push({
      id: "IAC_HARDCODED_SECRET",
      title: "Hardcoded credential or private key found in IaC source",
      severity: "CRITICAL",
      evidence: ev(secretHits),
      requiredActions: [
        "Remove the secret from source immediately and rotate it — assume it is already compromised.",
        "Reference secrets via a secret manager data source (aws_secretsmanager_secret_version, vault_generic_secret, etc.).",
        "Pass sensitive values as TF_VAR_ environment variables injected at runtime, never committed.",
        "Add a pre-commit secret scanner (gitleaks/trufflehog) and purge the secret from git history.",
      ],
    });
  }

  // 5. Outputs exposing secrets without sensitive = true. Count-based so prose
  //    or remediation docs that merely mention "sensitive = true" cannot suppress
  //    a genuine unguarded secret output: fire when secret-named outputs outnumber
  //    the sensitive markers present.
  if (outputSecrets.length > sensitiveMarkers.length) {
    findings.push({
      id: "IAC_TF_OUTPUT_NOT_SENSITIVE",
      title: "Terraform output exposing a secret without sensitive = true — value leaks to plan/CI logs and state",
      severity: "MEDIUM",
      evidence: ev(outputSecrets),
      requiredActions: [
        "Mark each secret output sensitive, e.g.:",
        "  output \"db_password\" {",
        "    value     = aws_db_instance.db.password",
        "    sensitive = true",
        "  }",
        "Better: do not export secrets at all — read them on demand from the secret manager:",
        "  data \"aws_secretsmanager_secret_version\" \"db\" { secret_id = \"prod/db\" }",
        "Scrub CI logs that may already contain the plaintext value, then verify with: terraform plan -no-color | grep -i password",
        "Detect regressions in CI with: checkov -d . --check CKV_SECRET_6 ; trivy config .",
      ],
    });
  }

  // 6. Disabled validation / destructive toggles.
  if (unsafe.length > 0) {
    findings.push({
      id: "IAC_TF_UNSAFE_DESTROY",
      title: "Destructive or validation-skipping toggle enabled (force_destroy / skip_final_snapshot / disable_rollback)",
      severity: "HIGH",
      evidence: ev(unsafe),
      requiredActions: [
        "Set skip_final_snapshot = false on RDS so a snapshot is taken before deletion.",
        "Remove force_destroy = true from buckets holding real data; require manual emptying instead.",
        "Add a lifecycle { prevent_destroy = true } block to critical stateful resources.",
        "Keep skip_provider_registration / disable_rollback at their safe defaults.",
      ],
    });
  }

  // 7. CloudFormation / inline IAM wildcards.
  if (cfnWildcard.length > 0) {
    findings.push({
      id: "IAC_CFN_IAM_WILDCARD",
      title: "CloudFormation/inline IAM policy grants wildcard Action or Resource — least-privilege violated",
      severity: "HIGH",
      evidence: ev(cfnWildcard),
      requiredActions: [
        "Replace \"Action\": \"*\" with the explicit minimal action list the resource needs.",
        "Replace \"Resource\": \"*\" with specific ARNs scoped to this stack.",
        "Add NoEcho: true to any CloudFormation parameter that carries a secret.",
        "Validate templates with cfn-lint and cfn_nag / Checkov in CI before deploy.",
      ],
    });
  }

  // 8. Pulumi plaintext secrets.
  if (pulumiPlaintext.length > 0) {
    findings.push({
      id: "IAC_PULUMI_PLAINTEXT_SECRET",
      title: "Pulumi config secret stored in plaintext or provider credentials hardcoded",
      severity: "HIGH",
      evidence: ev(pulumiPlaintext),
      requiredActions: [
        "Set secret config with `pulumi config set --secret` so values are encrypted in Pulumi.<stack>.yaml.",
        "Wrap sensitive program values with pulumi.secret() so they never appear in state or logs in cleartext.",
        "Source provider credentials from environment / OIDC, never `new aws.Provider({ accessKey, secretKey })` literals.",
        "Use a Pulumi secrets provider backed by AWS KMS / Azure Key Vault / GCP KMS.",
      ],
    });
  }

  // 9. Ansible insecure tasks.
  const ansibleHits = [...ansibleA, ...ansibleB];
  if (ansibleHits.length > 0) {
    findings.push({
      id: "IAC_ANSIBLE_INSECURE_TASK",
      title: "Ansible task disables TLS verification, logging of secrets, or hardcodes a privileged password",
      severity: "HIGH",
      evidence: ev(ansibleHits),
      requiredActions: [
        "Remove validate_certs: no/false — always verify TLS certificates against a trusted CA.",
        "Set no_log: true on any task that handles secrets so values are not printed to the play log.",
        "Never hardcode ansible_become_pass / ansible_ssh_pass — store them in ansible-vault or a secret manager.",
        "Avoid passing unsanitized variables to the shell/command modules; prefer purpose-built modules.",
      ],
    });
  }

  // 10. Public exposure via IaC.
  if (iacPublic.length > 0) {
    findings.push({
      id: "IAC_PUBLIC_RESOURCE",
      title: "IaC creates a publicly exposed resource (public-read ACL or publicly_accessible database)",
      severity: "HIGH",
      evidence: ev(iacPublic),
      requiredActions: [
        "Remove acl = \"public-read\"/\"public-read-write\"; use bucket policies with explicit principals instead.",
        "Set publicly_accessible = false on all database instances and place them in private subnets.",
        "Enable S3 Block Public Access at the account and bucket level to override accidental public ACLs.",
        "Front any legitimately public asset bucket with CloudFront + Origin Access Control, not a public ACL.",
      ],
    });
  }

  // -------------------------------------------------------------------------
  // Round 2: deep CloudFormation, CDK/SAM/Bicep, Terraform depth.
  // -------------------------------------------------------------------------
  const [
    cfnS3Public,
    cfnSgOpen,
    cfnDbPublic,
    cfnEncryption,
    cfnParamSecret,
    cfnNoEcho,
    cfnInlineSecret,
    cfnPassRole,
    cfnIamUserKey,
    cfnLambdaUrl,
    cfnResourcePrincipal,
    cfnCloudtrail,
    cfnUntrustedUrl,
    cfnStateful,
    cfnDeletionRetain,
    cfnImds,
    cdkHits,
    samCors,
    bicepA,
    bicepB,
    bicepRole,
    tfvarsSecret,
    tfSensitiveFalse,
    tfHttpData,
    tfNullResource,
    tfVaultToken,
    tfDefaultVpc,
    tfInsecureTls,
  ] = await Promise.all([
    searchRepo({ query: CFN_S3_PUBLIC_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_SG_OPEN_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_DB_PUBLIC_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_ENCRYPTION_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_PARAM_SECRET_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_NOECHO_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_INLINE_SECRET_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_PASSROLE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_IAM_USER_KEY_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_LAMBDA_URL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_RESOURCE_PRINCIPAL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_CLOUDTRAIL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_UNTRUSTED_URL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_STATEFUL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_DELETION_RETAIN_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CFN_IMDS_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: CDK_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SAM_CORS_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: BICEP_PATTERN_A, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: BICEP_PATTERN_B, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: BICEP_ROLE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_TFVARS_SECRET_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_SENSITIVE_FALSE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_HTTP_DATA_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_NULL_RESOURCE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_VAULT_TOKEN_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_DEFAULT_VPC_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_INSECURE_TLS_PATTERN, isRegex: true, maxMatches: 200 }),
  ]);

  // 11. CFN public S3 bucket.
  if (cfnS3Public.length > 0) {
    findings.push({
      id: "IAC_CFN_S3_PUBLIC",
      title: "CloudFormation S3 bucket disables Public Access Block or sets a public AccessControl/policy",
      severity: "HIGH",
      evidence: ev(cfnS3Public),
      requiredActions: [
        "Set every PublicAccessBlockConfiguration field (BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets) to true.",
        "Remove AccessControl: PublicRead/PublicReadWrite and any bucket policy with Principal \"*\".",
        "Front public assets with CloudFront + Origin Access Control instead of a public bucket.",
      ],
    });
  }

  // 12. CFN security group open to the internet.
  if (cfnSgOpen.length > 0) {
    findings.push({
      id: "IAC_CFN_SG_OPEN_INGRESS",
      title: "CloudFormation SecurityGroup ingress allows 0.0.0.0/0 or ::/0 — open to the entire internet",
      severity: "HIGH",
      evidence: ev(cfnSgOpen),
      requiredActions: [
        "Restrict CidrIp/CidrIpv6 to specific known CIDR ranges, never 0.0.0.0/0 or ::/0.",
        "Use a bastion host or SSM Session Manager for admin access instead of open SSH/RDP ingress.",
        "Reference security-group IDs as source instead of CIDRs for intra-VPC traffic.",
      ],
    });
  }

  // 13. CFN RDS/Redshift publicly accessible.
  if (cfnDbPublic.length > 0) {
    findings.push({
      id: "IAC_CFN_DB_PUBLIC",
      title: "CloudFormation RDS/Redshift instance set PubliclyAccessible: true — database reachable from the internet",
      severity: "HIGH",
      evidence: ev(cfnDbPublic),
      requiredActions: [
        "Set PubliclyAccessible: false on all DB and cluster resources.",
        "Place databases in private subnets with no route to an internet gateway.",
        "Restrict the DB security group to application subnets only.",
      ],
    });
  }

  // 14. CFN encryption disabled / missing.
  if (cfnEncryption.length > 0) {
    findings.push({
      id: "IAC_CFN_ENCRYPTION_DISABLED",
      title: "CloudFormation resource has encryption explicitly disabled or missing (StorageEncrypted/Encrypted/SSE false)",
      severity: "HIGH",
      evidence: ev(cfnEncryption),
      requiredActions: [
        "Set StorageEncrypted: true (RDS), Encrypted: true (EBS), and a BucketEncryption SSE rule (S3).",
        "Specify a customer-managed KmsKeyId for regulated data instead of relying on defaults.",
        "Enforce encryption org-wide with AWS Config rules / SCPs.",
      ],
    });
  }

  // 15. CFN secret Parameter without NoEcho.
  if (cfnParamSecret.length > 0 && cfnNoEcho.length === 0) {
    findings.push({
      id: "IAC_CFN_PARAM_NO_NOECHO",
      title: "CloudFormation Parameter carries a secret but no NoEcho: true — value leaks in console and describe-stacks",
      severity: "MEDIUM",
      evidence: ev(cfnParamSecret),
      requiredActions: [
        "Add NoEcho: true to every parameter that holds a password, secret, token, or API key.",
        "Prefer resolving secrets at deploy time via dynamic references to Secrets Manager / SSM ('{{resolve:secretsmanager:...}}').",
        "Never pass secrets as plaintext CLI parameter values that land in CloudTrail.",
      ],
    });
  }

  // 16. CFN inline secret literal.
  if (cfnInlineSecret.length > 0) {
    findings.push({
      id: "IAC_CFN_INLINE_SECRET",
      title: "CloudFormation template contains a hardcoded secret literal (MasterUserPassword / SecretString / Token)",
      severity: "CRITICAL",
      evidence: ev(cfnInlineSecret),
      requiredActions: [
        "Remove the literal and rotate the secret — assume compromise.",
        "Use a dynamic reference '{{resolve:secretsmanager:MySecret}}' or a Secrets Manager generated secret.",
        "Add a template secret scanner (cfn-lint + git secret scanning) to CI.",
      ],
    });
  }

  // 17. CFN IAM PassRole / iam:* wildcard.
  if (cfnPassRole.length > 0) {
    findings.push({
      id: "IAC_CFN_IAM_PASSROLE_WILDCARD",
      title: "CloudFormation IAM policy grants iam:PassRole or iam:* — privilege escalation to any role",
      severity: "HIGH",
      evidence: ev(cfnPassRole),
      requiredActions: [
        "Scope iam:PassRole to specific role ARNs with an iam:PassedToService condition.",
        "Never grant iam:* — enumerate only the precise IAM actions needed.",
        "Audit PassRole grants with IAM Access Analyzer for escalation paths.",
      ],
    });
  }

  // 18. CFN IAM::User with inline access key.
  if (cfnIamUserKey.length > 0) {
    findings.push({
      id: "IAC_CFN_IAM_USER_ACCESS_KEY",
      title: "CloudFormation provisions an AWS::IAM::AccessKey / long-lived IAM user key — static credentials in templates",
      severity: "HIGH",
      evidence: ev(cfnIamUserKey),
      requiredActions: [
        "Replace IAM users + access keys with IAM roles and STS short-lived credentials.",
        "For workloads, use instance profiles / IRSA / Workload Identity instead of static keys.",
        "If a key is unavoidable, store it in Secrets Manager and rotate automatically.",
      ],
    });
  }

  // 19. CFN Lambda public function URL.
  if (cfnLambdaUrl.length > 0) {
    findings.push({
      id: "IAC_CFN_LAMBDA_URL_PUBLIC",
      title: "CloudFormation Lambda FunctionUrlConfig AuthType: NONE — function publicly invocable by anyone",
      severity: "HIGH",
      evidence: ev(cfnLambdaUrl),
      requiredActions: [
        "Set AuthType: AWS_IAM on FunctionUrlConfig.",
        "Front the function with API Gateway (IAM/Cognito) or CloudFront with signed URLs.",
        "Add throttling and WAF if a public endpoint is genuinely required.",
      ],
    });
  }

  // 20. CFN SNS/SQS/Lambda resource policy Principal "*".
  if (cfnResourcePrincipal.length > 0) {
    findings.push({
      id: "IAC_CFN_RESOURCE_POLICY_PUBLIC",
      title: "CloudFormation resource policy uses Principal \"*\" — SNS/SQS/Lambda open to all AWS accounts",
      severity: "HIGH",
      evidence: ev(cfnResourcePrincipal),
      requiredActions: [
        "Replace Principal \"*\" with specific account IDs, service principals, or org-id conditions.",
        "Add aws:SourceArn / aws:SourceAccount conditions to confused-deputy-prone policies.",
        "Review topic/queue/function policies with IAM Access Analyzer for external exposure.",
      ],
    });
  }

  // 21. CFN CloudTrail not multi-region / no log validation.
  if (cfnCloudtrail.length > 0) {
    findings.push({
      id: "IAC_CFN_CLOUDTRAIL_WEAK",
      title: "CloudFormation CloudTrail is not multi-region or has log file validation disabled — audit gaps and tampering risk",
      severity: "MEDIUM",
      evidence: ev(cfnCloudtrail),
      requiredActions: [
        "Set IsMultiRegionTrail: true so actions in every region are captured.",
        "Set EnableLogFileValidation: true to detect tampering of delivered logs.",
        "Send logs to a dedicated cross-account bucket with MFA delete and Object Lock.",
      ],
    });
  }

  // 22. CFN untrusted nested-stack / cfn-init URL.
  if (cfnUntrustedUrl.length > 0) {
    findings.push({
      id: "IAC_CFN_UNTRUSTED_TEMPLATE_URL",
      title: "CloudFormation references a nested stack or cfn-init source over plaintext HTTP / untrusted URL — MITM and template tampering",
      severity: "HIGH",
      evidence: ev(cfnUntrustedUrl),
      requiredActions: [
        "Use HTTPS S3 URLs (https://...s3.amazonaws.com) for all TemplateURL and cfn-init sources.",
        "Host nested templates in a controlled, access-restricted S3 bucket with bucket policy.",
        "Verify artifact integrity (checksums / signed objects) before cfn-init fetches them.",
      ],
    });
  }

  // 23. CFN stateful resource without DeletionPolicy: Retain.
  if (cfnStateful.length > 0 && cfnDeletionRetain.length === 0) {
    findings.push({
      id: "IAC_CFN_NO_DELETION_POLICY",
      title: "CloudFormation stateful resource (RDS/DynamoDB/S3) has no DeletionPolicy: Retain — stack delete destroys data",
      severity: "HIGH",
      evidence: ev(cfnStateful),
      requiredActions: [
        "Add DeletionPolicy: Retain (and UpdateReplacePolicy: Retain) to RDS, DynamoDB, and S3 resources.",
        "Enable termination protection on production stacks.",
        "Take final snapshots / backups before any stack deletion.",
      ],
    });
  }

  // 24. CFN EC2 IMDSv1 still allowed.
  if (cfnImds.length > 0) {
    findings.push({
      id: "IAC_CFN_IMDSV1_ALLOWED",
      title: "CloudFormation EC2 MetadataOptions HttpTokens: optional — IMDSv1 reachable, SSRF can steal IAM credentials",
      severity: "CRITICAL",
      evidence: ev(cfnImds),
      requiredActions: [
        "Set HttpTokens: required in MetadataOptions to enforce IMDSv2.",
        "Set HttpPutResponseHopLimit: 1 to block container-relayed metadata access.",
        "Enforce IMDSv2 account-wide via EC2 default metadata options.",
      ],
    });
  }

  // 25. CDK escape hatch wildcard / removalPolicy DESTROY.
  if (cdkHits.length > 0) {
    findings.push({
      id: "IAC_CDK_INSECURE_CONSTRUCT",
      title: "AWS CDK grants wildcard IAM via escape hatch or sets RemovalPolicy.DESTROY on a data store",
      severity: "HIGH",
      evidence: ev(cdkHits),
      requiredActions: [
        "Replace actions/resources ['*'] in addToRolePolicy with explicit, scoped values.",
        "Use RemovalPolicy.RETAIN (and removal protection) on stateful constructs (RDS, DynamoDB, S3).",
        "Run cdk-nag in the pipeline to catch over-broad grants and destructive removal policies.",
      ],
    });
  }

  // 26. SAM Globals open CORS.
  if (samCors.length > 0) {
    findings.push({
      id: "IAC_CDK_SAM_OPEN_CORS",
      title: "SAM/CDK API exposes AllowOrigin \"*\" — wildcard CORS permits any site to call the API with credentials",
      severity: "MEDIUM",
      evidence: ev(samCors),
      requiredActions: [
        "Replace AllowOrigin '*' with an explicit allowlist of trusted origins.",
        "Never combine wildcard AllowOrigin with AllowCredentials: true.",
        "Define CORS per route and restrict allowed methods/headers.",
      ],
    });
  }

  // 27. Bicep/ARM public network + TLS + public blob.
  const bicepNet = [...bicepA, ...bicepB];
  if (bicepNet.length > 0) {
    findings.push({
      id: "IAC_BICEP_INSECURE_NETWORK",
      title: "Bicep/ARM resource enables public network access, weak TLS, public blob access, or Allow-all network ACLs",
      severity: "HIGH",
      evidence: ev(bicepNet),
      requiredActions: [
        "Set publicNetworkAccess to 'Disabled' and use Private Endpoints + Private DNS.",
        "Set supportsHttpsTrafficOnly: true and minimumTlsVersion: 'TLS1_2'.",
        "Set allowBlobPublicAccess: false and networkAcls.defaultAction: 'Deny' with explicit allow rules.",
      ],
    });
  }

  // 28. Bicep/ARM Owner/Contributor role assignment.
  if (bicepRole.length > 0) {
    findings.push({
      id: "IAC_BICEP_PRIVILEGED_ROLE",
      title: "Bicep/ARM role assignment grants built-in Owner or Contributor — broad subscription/resource-group control",
      severity: "HIGH",
      evidence: ev(bicepRole),
      requiredActions: [
        "Replace Owner/Contributor with a least-privilege built-in or custom role scoped to the resource.",
        "Scope role assignments to the narrowest resource scope, never the whole subscription.",
        "Use PIM (Privileged Identity Management) for just-in-time elevation instead of standing Owner.",
      ],
    });
  }

  // 29. Terraform tfvars / auto.tfvars secrets.
  if (tfvarsSecret.length > 0) {
    findings.push({
      id: "IAC_TF_TFVARS_SECRET",
      title: "Hardcoded secret found in a Terraform variables file (.tfvars / .auto.tfvars)",
      severity: "CRITICAL",
      evidence: ev(tfvarsSecret),
      requiredActions: [
        "Remove the secret and rotate it; never commit .tfvars containing credentials.",
        "Inject secret variables via TF_VAR_ environment variables or a secret manager data source.",
        "Add *.tfvars (except example files) to .gitignore and scan history with gitleaks.",
      ],
    });
  }

  // 30. Terraform sensitive = false on secret variable.
  if (tfSensitiveFalse.length > 0) {
    findings.push({
      id: "IAC_TF_SENSITIVE_FALSE",
      title: "Terraform variable/output explicitly sets sensitive = false — value rendered in plan output and logs",
      severity: "MEDIUM",
      evidence: ev(tfSensitiveFalse),
      requiredActions: [
        "Set sensitive = true on any variable or output that holds a credential or PII.",
        "Avoid sensitive = false on secret-bearing values — it overrides Terraform's redaction.",
        "Scrub CI logs that may already contain the rendered value.",
      ],
    });
  }

  // 31. Terraform http data source / remote state over http (plaintext).
  if (tfHttpData.length > 0) {
    findings.push({
      id: "IAC_TF_HTTP_PLAINTEXT",
      title: "Terraform uses an http data source or remote state over plaintext HTTP — MITM and data tampering",
      severity: "HIGH",
      evidence: ev(tfHttpData),
      requiredActions: [
        "Use HTTPS endpoints for the http data source and terraform_remote_state backends.",
        "Validate fetched content (checksums) before consuming it in resource arguments.",
        "Prefer a native data source over fetching arbitrary URLs at plan time.",
      ],
    });
  }

  // 32. Terraform null_resource + local-exec.
  if (tfNullResource.length > 0) {
    findings.push({
      id: "IAC_TF_NULL_RESOURCE_EXEC",
      title: "Terraform null_resource detected — typically wraps local-exec, an arbitrary-command RCE surface during apply",
      severity: "MEDIUM",
      evidence: ev(tfNullResource),
      requiredActions: [
        "Avoid null_resource + local-exec for provisioning; use a proper provider or config-management tool.",
        "If retained, never interpolate untrusted variables into the executed command.",
        "Run apply only from a hardened CI runner with scoped, short-lived credentials.",
      ],
    });
  }

  // 33. Terraform vault provider with inline token.
  if (tfVaultToken.length > 0) {
    findings.push({
      id: "IAC_TF_VAULT_TOKEN_INLINE",
      title: "Terraform Vault provider configured with an inline token — long-lived root/admin token in source",
      severity: "HIGH",
      evidence: ev(tfVaultToken),
      requiredActions: [
        "Never set the Vault token inline; source it from VAULT_TOKEN env or an auth method (AppRole, OIDC, AWS).",
        "Use short-lived, least-privilege Vault tokens issued per run, not a static root token.",
        "Rotate any committed Vault token immediately and revoke it.",
      ],
    });
  }

  // 34. Terraform default VPC / default security group usage.
  if (tfDefaultVpc.length > 0) {
    findings.push({
      id: "IAC_TF_DEFAULT_VPC",
      title: "Terraform manages the AWS default VPC / default security group / default subnet — insecure permissive defaults",
      severity: "MEDIUM",
      evidence: ev(tfDefaultVpc),
      requiredActions: [
        "Provision purpose-built VPCs, subnets, and security groups instead of adopting AWS defaults.",
        "The default security group allows all intra-group traffic — define explicit, scoped rules.",
        "Restrict or delete the default VPC to prevent accidental public deployments.",
      ],
    });
  }

  // 35. Terraform allow_unverified_ssl / insecure / skip_tls_verify.
  if (tfInsecureTls.length > 0) {
    findings.push({
      id: "IAC_TF_INSECURE_TLS",
      title: "Terraform provider disables TLS verification (insecure / allow_unverified_ssl / skip_tls_verify = true)",
      severity: "HIGH",
      evidence: ev(tfInsecureTls),
      requiredActions: [
        "Remove insecure = true / allow_unverified_ssl = true / skip_tls_verify = true from provider configs.",
        "Trust the proper CA bundle instead of disabling certificate verification.",
        "If using a private CA, distribute its root cert rather than turning off verification.",
      ],
    });
  }

  // -------------------------------------------------------------------------
  // Round 3: extra-deep Terraform checks. Each requiredActions entry is a
  // copy-pasteable corrected HCL block plus a verify command.
  // -------------------------------------------------------------------------
  const [
    tfProviderCreds,
    tfBackendKms,
    tfBackendHttp,
    tfModuleGitHttp,
    tfReqVersionOpen,
    tfS3Bucket,
    tfS3Sse,
    tfS3Pab,
    tfRdsHardening,
    tfSgOpenCidr,
    tfIamWildcardHcl,
    tfImdsHcl,
    tfEksEcrPublic,
    tfKmsRotation,
    tfIamAccessKey,
    tfCloudtrailValidation,
    tfVolumeBlocks,
    tfVolumeEncFalse,
    tfVarDefaultSecret,
    tfUserdataSecret,
    tfIgnoreAll,
    tfPreventDestroyFalse,
    tfCbd,
    tfAutoApprove,
  ] = await Promise.all([
    searchRepo({ query: TF_PROVIDER_CREDS_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_BACKEND_KMS_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_BACKEND_HTTP_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_MODULE_GIT_HTTP_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_REQUIRED_VERSION_OPEN_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_S3_BUCKET_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_S3_SSE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_S3_PAB_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_RDS_HARDENING_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_SG_OPEN_CIDR_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_IAM_WILDCARD_HCL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_IMDS_HCL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_EKS_ECR_PUBLIC_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_KMS_ROTATION_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_IAM_ACCESS_KEY_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_CLOUDTRAIL_VALIDATION_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_VOLUME_UNENCRYPTED_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_VOLUME_ENC_FALSE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_VAR_DEFAULT_SECRET_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_USERDATA_SECRET_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_IGNORE_ALL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_PREVENT_DESTROY_FALSE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_CBD_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: TF_AUTO_APPROVE_PATTERN, isRegex: true, maxMatches: 200 }),
  ]);

  // 36. Provider auth: hardcoded creds / committed credential file / inline key.
  if (tfProviderCreds.length > 0) {
    findings.push({
      id: "IAC_TF_PROVIDER_HARDCODED_CREDS",
      title: "Terraform provider authenticates with hardcoded credentials, a committed credentials file, or an inline key",
      severity: "CRITICAL",
      evidence: ev(tfProviderCreds),
      requiredActions: [
        "Remove the inline credential and rotate it immediately — treat it as compromised.",
        "AWS: authenticate via the default chain / OIDC, never inline keys:",
        "  provider \"aws\" { region = var.region }   # creds via env, SSO, or IRSA/OIDC",
        "GCP: use Workload Identity Federation instead of a committed JSON key:",
        "  provider \"google\" { project = var.project }   # GOOGLE_APPLICATION_CREDENTIALS via WIF",
        "azurerm: source client_secret from a Key Vault data source or OIDC, never a literal:",
        "  provider \"azurerm\" { features {}; use_oidc = true }",
        "Add the key path to .gitignore, purge it from history (git filter-repo), then verify: trivy config . ; checkov -d . --check CKV_SECRET_6",
      ],
    });
  }

  // 37. S3 backend without KMS key.
  if (backendS3.length > 0 && tfBackendKms.length === 0) {
    findings.push({
      id: "IAC_TF_BACKEND_NO_KMS",
      title: "Terraform S3 backend has no kms_key_id — state (plaintext secrets) is not encrypted with a customer-managed key",
      severity: "MEDIUM",
      evidence: ev(backendS3),
      requiredActions: [
        "Encrypt remote state with a customer-managed KMS key:",
        "  terraform {",
        "    backend \"s3\" {",
        "      bucket         = \"my-tfstate\"",
        "      key            = \"prod/terraform.tfstate\"",
        "      region         = \"us-east-1\"",
        "      encrypt        = true",
        "      kms_key_id     = \"arn:aws:kms:us-east-1:111122223333:key/abcd-...\"",
        "      dynamodb_table = \"tf-locks\"",
        "    }",
        "  }",
        "Verify: terraform init -reconfigure && aws s3api get-bucket-encryption --bucket my-tfstate",
      ],
    });
  }

  // 38. http backend over plaintext.
  if (tfBackendHttp.length > 0) {
    findings.push({
      id: "IAC_TF_BACKEND_HTTP",
      title: "Terraform uses the http backend — state transferred over an unauthenticated/plaintext channel risks MITM",
      severity: "HIGH",
      evidence: ev(tfBackendHttp),
      requiredActions: [
        "Replace the http backend with S3+DynamoDB, GCS, or Terraform Cloud:",
        "  terraform {",
        "    backend \"s3\" {",
        "      bucket = \"my-tfstate\"; key = \"prod.tfstate\"; region = \"us-east-1\"",
        "      encrypt = true; dynamodb_table = \"tf-locks\"",
        "    }",
        "  }",
        "If the http backend is mandatory, require HTTPS and lock/unlock addresses with auth, never plain http://.",
        "Verify: terraform init -reconfigure",
      ],
    });
  }

  // 39. Module supply chain: git over http / branch ref.
  if (tfModuleGitHttp.length > 0) {
    findings.push({
      id: "IAC_TF_MODULE_GIT_HTTP",
      title: "Terraform module source uses plaintext git::http:// (or http://) — module code can be tampered with in transit",
      severity: "HIGH",
      evidence: ev(tfModuleGitHttp),
      requiredActions: [
        "Use https or ssh and pin to an immutable tag or commit SHA:",
        "  module \"vpc\" {",
        "    source = \"git::https://github.com/org/tf-vpc.git//modules/vpc?ref=v3.2.1\"",
        "  }",
        "For registry modules add an exact version:  version = \"5.1.0\"",
        "Verify the pin took effect: terraform init && terraform get && terraform providers lock",
      ],
    });
  }

  // 40. required_version unbounded (LOW).
  if (tfReqVersionOpen.length > 0) {
    findings.push({
      id: "IAC_TF_REQUIRED_VERSION_UNPINNED",
      title: "Terraform required_version uses an open >= constraint with no upper bound — unexpected CLI upgrades can break or alter behavior",
      severity: "LOW",
      evidence: ev(tfReqVersionOpen),
      requiredActions: [
        "Pin the Terraform CLI to a bounded range:",
        "  terraform { required_version = \"~> 1.7.0\" }   # or \">= 1.7.0, < 1.8.0\"",
        "Pin providers too, e.g.:",
        "  required_providers { aws = { source = \"hashicorp/aws\", version = \"~> 5.40\" } }",
        "Commit .terraform.lock.hcl and verify: terraform version && terraform providers lock",
      ],
    });
  }

  // 41. S3 bucket without SSE / public access block.
  if (tfS3Bucket.length > 0 && (tfS3Sse.length === 0 || tfS3Pab.length === 0)) {
    findings.push({
      id: "IAC_TF_S3_MISSING_HARDENING",
      title: "aws_s3_bucket has no server-side encryption and/or no public access block resource — data may be unencrypted or publicly exposable",
      severity: "HIGH",
      evidence: ev(tfS3Bucket),
      requiredActions: [
        "Add a server-side encryption configuration:",
        "  resource \"aws_s3_bucket_server_side_encryption_configuration\" \"this\" {",
        "    bucket = aws_s3_bucket.this.id",
        "    rule { apply_server_side_encryption_by_default { sse_algorithm = \"aws:kms\" } }",
        "  }",
        "Add a public access block:",
        "  resource \"aws_s3_bucket_public_access_block\" \"this\" {",
        "    bucket                  = aws_s3_bucket.this.id",
        "    block_public_acls       = true",
        "    block_public_policy     = true",
        "    ignore_public_acls      = true",
        "    restrict_public_buckets = true",
        "  }",
        "Verify: checkov -d . --check CKV2_AWS_6,CKV_AWS_19 ; trivy config .",
      ],
    });
  }

  // 42. RDS hardening: storage_encrypted false / IAM auth disabled.
  if (tfRdsHardening.length > 0) {
    findings.push({
      id: "IAC_TF_RDS_WEAK_HARDENING",
      title: "aws_db_instance has storage_encrypted = false or iam_database_authentication_enabled = false",
      severity: "HIGH",
      evidence: ev(tfRdsHardening),
      requiredActions: [
        "Harden the DB instance:",
        "  resource \"aws_db_instance\" \"db\" {",
        "    storage_encrypted                   = true",
        "    kms_key_id                          = aws_kms_key.rds.arn",
        "    iam_database_authentication_enabled = true",
        "    publicly_accessible                 = false",
        "    deletion_protection                 = true",
        "  }",
        "Verify: checkov -d . --check CKV_AWS_16,CKV_AWS_161 ; terraform plan",
      ],
    });
  }

  // 43. Security group open to 0.0.0.0/0.
  if (tfSgOpenCidr.length > 0) {
    findings.push({
      id: "IAC_TF_SG_OPEN_WORLD",
      title: "Security group rule allows 0.0.0.0/0 (or ::/0) — open to the entire internet, typically on SSH/RDP/all ports",
      severity: "HIGH",
      evidence: ev(tfSgOpenCidr),
      requiredActions: [
        "Restrict ingress to known CIDRs (or reference a source SG):",
        "  resource \"aws_security_group_rule\" \"ssh\" {",
        "    type        = \"ingress\"",
        "    from_port   = 22",
        "    to_port     = 22",
        "    protocol    = \"tcp\"",
        "    cidr_blocks = [var.admin_cidr]   # never [\"0.0.0.0/0\"]",
        "    security_group_id = aws_security_group.app.id",
        "  }",
        "Prefer SSM Session Manager over open SSH. Verify: checkov -d . --check CKV_AWS_24,CKV_AWS_260",
      ],
    });
  }

  // 44. IAM HCL wildcard / AssumeRole Principal "*".
  if (tfIamWildcardHcl.length > 0) {
    findings.push({
      id: "IAC_TF_IAM_WILDCARD_HCL",
      title: "Terraform IAM policy/document uses a wildcard action, resource, or Principal \"*\" — least-privilege violated",
      severity: "HIGH",
      evidence: ev(tfIamWildcardHcl),
      requiredActions: [
        "Enumerate explicit actions/resources in the policy document:",
        "  data \"aws_iam_policy_document\" \"app\" {",
        "    statement {",
        "      actions   = [\"s3:GetObject\", \"s3:PutObject\"]",
        "      resources = [\"${aws_s3_bucket.app.arn}/*\"]",
        "    }",
        "  }",
        "For trust policies, scope the principal to a specific ARN — never identifiers = [\"*\"].",
        "Verify with IAM Access Analyzer and: checkov -d . --check CKV_AWS_1,CKV_AWS_111",
      ],
    });
  }

  // 45. EC2 IMDSv1 (http_tokens optional).
  if (tfImdsHcl.length > 0) {
    findings.push({
      id: "IAC_TF_IMDSV1_OPTIONAL",
      title: "aws_instance metadata_options sets http_tokens = \"optional\" — IMDSv1 reachable, SSRF can steal IAM credentials",
      severity: "CRITICAL",
      evidence: ev(tfImdsHcl),
      requiredActions: [
        "Enforce IMDSv2 on the instance / launch template:",
        "  metadata_options {",
        "    http_endpoint               = \"enabled\"",
        "    http_tokens                 = \"required\"",
        "    http_put_response_hop_limit = 1",
        "  }",
        "Verify: checkov -d . --check CKV_AWS_79 ; aws ec2 describe-instances --query 'Reservations[].Instances[].MetadataOptions'",
      ],
    });
  }

  // 46. EKS/ECR public.
  if (tfEksEcrPublic.length > 0) {
    findings.push({
      id: "IAC_TF_EKS_ECR_PUBLIC",
      title: "EKS public endpoint enabled, public ECR repository, or mutable image tags — control-plane/registry exposed or tamperable",
      severity: "HIGH",
      evidence: ev(tfEksEcrPublic),
      requiredActions: [
        "Lock down the EKS API endpoint:",
        "  vpc_config {",
        "    endpoint_public_access  = false",
        "    endpoint_private_access = true",
        "  }",
        "Make ECR tags immutable and scan on push:",
        "  resource \"aws_ecr_repository\" \"app\" {",
        "    image_tag_mutability = \"IMMUTABLE\"",
        "    image_scanning_configuration { scan_on_push = true }",
        "  }",
        "Verify: checkov -d . --check CKV_AWS_39,CKV_AWS_51",
      ],
    });
  }

  // 47. KMS key rotation disabled.
  if (tfKmsRotation.length > 0) {
    findings.push({
      id: "IAC_TF_KMS_NO_ROTATION",
      title: "aws_kms_key sets enable_key_rotation = false — keys are never rotated, increasing blast radius of a key compromise",
      severity: "MEDIUM",
      evidence: ev(tfKmsRotation),
      requiredActions: [
        "Enable automatic annual key rotation:",
        "  resource \"aws_kms_key\" \"this\" {",
        "    description         = \"app data key\"",
        "    enable_key_rotation = true",
        "  }",
        "Verify: checkov -d . --check CKV_AWS_7 ; aws kms get-key-rotation-status --key-id <id>",
      ],
    });
  }

  // 48. Long-lived IAM access key resource.
  if (tfIamAccessKey.length > 0) {
    findings.push({
      id: "IAC_TF_IAM_ACCESS_KEY_RESOURCE",
      title: "aws_iam_access_key resource provisions long-lived static credentials — prefer short-lived STS/role-based auth",
      severity: "HIGH",
      evidence: ev(tfIamAccessKey),
      requiredActions: [
        "Replace static user keys with an assumable role:",
        "  resource \"aws_iam_role\" \"app\" {",
        "    assume_role_policy = data.aws_iam_policy_document.trust.json",
        "  }",
        "For workloads use IRSA / instance profiles / OIDC instead of aws_iam_access_key.",
        "If a key is unavoidable, store it in Secrets Manager and rotate on a schedule.",
        "Verify: checkov -d . --check CKV_AWS_273 ; aws iam list-access-keys --user-name <user>",
      ],
    });
  }

  // 49. CloudTrail log file validation disabled.
  if (tfCloudtrailValidation.length > 0) {
    findings.push({
      id: "IAC_TF_CLOUDTRAIL_NO_VALIDATION",
      title: "aws_cloudtrail sets enable_log_file_validation = false — delivered logs can be tampered without detection",
      severity: "MEDIUM",
      evidence: ev(tfCloudtrailValidation),
      requiredActions: [
        "Enable log file validation:",
        "  resource \"aws_cloudtrail\" \"main\" {",
        "    enable_log_file_validation = true",
        "    is_multi_region_trail      = true",
        "    kms_key_id                 = aws_kms_key.trail.arn",
        "  }",
        "Verify: checkov -d . --check CKV_AWS_36 ; aws cloudtrail validate-logs --trail-arn <arn> --start-time <t>",
      ],
    });
  }

  // 50. Root/EBS volume encrypted = false (only when a volume block is present).
  if (tfVolumeBlocks.length > 0 && tfVolumeEncFalse.length > 0) {
    findings.push({
      id: "IAC_TF_VOLUME_UNENCRYPTED",
      title: "Root or EBS block device sets encrypted = false — instance storage holds data at rest unencrypted",
      severity: "HIGH",
      evidence: ev(tfVolumeEncFalse),
      requiredActions: [
        "Encrypt every block device:",
        "  root_block_device {",
        "    encrypted  = true",
        "    kms_key_id = aws_kms_key.ebs.arn",
        "  }",
        "Enable account-wide EBS encryption by default: aws ec2 enable-ebs-encryption-by-default",
        "Verify: checkov -d . --check CKV_AWS_8 ; trivy config .",
      ],
    });
  }

  // 51. Variable default that is a real-looking secret.
  if (tfVarDefaultSecret.length > 0) {
    findings.push({
      id: "IAC_TF_VAR_DEFAULT_SECRET",
      title: "Terraform variable default contains a real-looking secret (AWS key / GitHub PAT / OpenAI key / PEM)",
      severity: "CRITICAL",
      evidence: ev(tfVarDefaultSecret),
      requiredActions: [
        "Remove the default and rotate the secret immediately.",
        "Declare the variable without a default and inject it at runtime:",
        "  variable \"db_password\" { type = string; sensitive = true }   # no default",
        "  # supplied via TF_VAR_db_password or a secret manager data source",
        "Or read it from the secret manager:",
        "  data \"aws_secretsmanager_secret_version\" \"db\" { secret_id = \"prod/db\" }",
        "Purge from history (git filter-repo) and verify: gitleaks detect ; checkov -d . --check CKV_SECRET_6",
      ],
    });
  }

  // 52. user_data / templatefile embedding credentials.
  if (tfUserdataSecret.length > 0) {
    findings.push({
      id: "IAC_TF_USERDATA_SECRET",
      title: "Credentials embedded in user_data / templatefile / cloud-init — secrets land in EC2 metadata and the state file",
      severity: "HIGH",
      evidence: ev(tfUserdataSecret),
      requiredActions: [
        "Never bake secrets into user_data — fetch them at boot from a secret manager:",
        "  # in cloud-init:",
        "  aws secretsmanager get-secret-value --secret-id prod/app --query SecretString --output text",
        "Grant the instance role only secretsmanager:GetSecretValue on that one secret ARN.",
        "Mark any user_data variables sensitive = true so they are redacted in plan output.",
        "Verify: checkov -d . --check CKV_AWS_46 ; terraform plan -no-color | grep -i password",
      ],
    });
  }

  // 53. lifecycle ignore_changes = all.
  if (tfIgnoreAll.length > 0) {
    findings.push({
      id: "IAC_TF_IGNORE_CHANGES_ALL",
      title: "lifecycle { ignore_changes = all } masks configuration drift — tampering with the live resource goes undetected by Terraform",
      severity: "MEDIUM",
      evidence: ev(tfIgnoreAll),
      requiredActions: [
        "Scope ignore_changes to the specific attributes that legitimately drift, never `all`:",
        "  lifecycle {",
        "    ignore_changes = [tags[\"LastScanned\"]]   # explicit, minimal list",
        "  }",
        "Run drift detection on a schedule: terraform plan -detailed-exitcode (exit 2 = drift).",
      ],
    });
  }

  // 54. prevent_destroy = false on a lifecycle block.
  if (tfPreventDestroyFalse.length > 0) {
    findings.push({
      id: "IAC_TF_PREVENT_DESTROY_FALSE",
      title: "lifecycle { prevent_destroy = false } explicitly allows destruction of a (likely stateful) resource",
      severity: "MEDIUM",
      evidence: ev(tfPreventDestroyFalse),
      requiredActions: [
        "Protect stateful resources from accidental destroy:",
        "  lifecycle { prevent_destroy = true }",
        "Pair with provider-level guards (deletion_protection = true, skip_final_snapshot = false).",
        "Verify a destroy is blocked: terraform plan -destroy (should error on the protected resource).",
      ],
    });
  }

  // 55. create_before_destroy on a security group.
  if (tfCbd.length > 0) {
    findings.push({
      id: "IAC_TF_CBD_SECURITY_GROUP",
      title: "create_before_destroy on a security group can transiently widen exposure during replacement",
      severity: "LOW",
      evidence: ev(tfCbd),
      requiredActions: [
        "Audit create_before_destroy on aws_security_group — during replacement both the old and new SG exist briefly.",
        "Manage rules as separate aws_security_group_rule / aws_vpc_security_group_ingress_rule resources so the group itself is not replaced:",
        "  resource \"aws_vpc_security_group_ingress_rule\" \"https\" { ... }",
        "Verify no unintended replacement: terraform plan (look for -/+ on the security group).",
      ],
    });
  }

  // 56. Committed wrapper scripts using -auto-approve / -target.
  if (tfAutoApprove.length > 0) {
    findings.push({
      id: "IAC_TF_AUTO_APPROVE_SCRIPT",
      title: "Committed script runs terraform apply/destroy with -auto-approve — unreviewed, non-interactive changes to infrastructure",
      severity: "MEDIUM",
      evidence: ev(tfAutoApprove),
      requiredActions: [
        "Require a reviewed plan artifact before applying, instead of blind -auto-approve:",
        "  terraform plan -out=tfplan",
        "  # human/PR review of tfplan, then:",
        "  terraform apply tfplan",
        "Gate apply behind CI approval (environments/required reviewers); restrict who can run destroy.",
        "Avoid broad -target in committed scripts — it produces partial, drift-prone applies.",
      ],
    });
  }

  return findings;
}
