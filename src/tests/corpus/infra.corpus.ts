import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "SECRET_MANAGER_NOT_DETECTED",
    check: "infra",
    positive: {
      file: "infra/secrets.tf",
      content: `locals {\n  db_password = "SuperSecretPassword123!"\n  api_key     = "prod_api_key_abcdef1234567890"\n}\n`
    },
    negative: {
      file: "infra/secrets.tf",
      content: `data "aws_secretsmanager_secret_version" "db_password" {\n  secret_id = aws_secretsmanager_secret.db.id\n}\n`
    },
    note: "Negative references AWS Secrets Manager (matches the 'secretsmanager' substring in SECRET_MANAGER_PATTERN_A), so secretManagerRefs is non-empty and the absence finding does not fire; positive has literal hardcoded secrets and no secret-manager reference anywhere."
  },
  {
    ruleId: "IAM_OVERPRIVILEGED",
    check: "infra",
    positive: {
      file: "iam/policy.json",
      content: `{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}\n`
    },
    negative: {
      file: "iam/policy.json",
      content: `{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": ["s3:GetObject", "s3:PutObject"],\n      "Resource": "arn:aws:s3:::my-app-bucket/*"\n    }\n  ]\n}\n`
    },
    note: "Positive line '\"Action\": \"*\"' matches the exact quoted-wildcard alternatives in IAM_WILDCARD_PATTERN; negative enumerates specific actions and scopes Resource to an ARN prefix, so the value never equals the literal string \"*\"."
  },
  {
    ruleId: "PUBLIC_EXPOSURE_RISK",
    check: "infra",
    positive: {
      file: "terraform/security-group.tf",
      content: `resource "aws_security_group_rule" "open_ingress" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["0.0.0.0/0"]\n  security_group_id = "sg-0123456789abcdef0"\n}\n`
    },
    negative: {
      file: "terraform/security-group.tf",
      content: `resource "aws_security_group_rule" "office_ingress" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["203.0.113.0/24"]\n  security_group_id = "sg-0123456789abcdef0"\n}\n`
    },
    note: "Positive's cidr_blocks contains the literal '0.0.0.0/0' matched by PUBLIC_INGRESS_PATTERN; negative restricts ingress to a specific known CIDR block, exactly the remediation the rule recommends, with no wildcard CIDR, public flag, or internet-facing scheme anywhere."
  },
  {
    ruleId: "ENCRYPTION_DISABLED",
    check: "infra",
    positive: {
      file: "terraform/rds.tf",
      content: `resource "aws_db_instance" "app" {\n  identifier        = "app-db"\n  engine            = "postgres"\n  storage_encrypted = false\n}\n`
    },
    negative: {
      file: "terraform/rds.tf",
      content: `resource "aws_db_instance" "app" {\n  identifier        = "app-db"\n  engine            = "postgres"\n  storage_encrypted = true\n  kms_key_id        = "arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"\n}\n`
    },
    note: "Positive line 'storage_encrypted = false' matches ENCRYPTION_DISABLED_PATTERN directly; negative sets storage_encrypted = true and supplies a customer-managed KMS key ARN (not an empty string), so neither 'storage_encrypted=false' nor 'kms_key_id=\"\"' appears."
  },
  {
    ruleId: "AUDIT_LOGGING_DISABLED",
    check: "infra",
    positive: {
      file: "terraform/firewall.tf",
      content: `resource "google_compute_firewall" "allow_all_egress" {\n  name    = "allow-all-egress"\n  network = "default"\n  log_config {}\n}\n`
    },
    negative: {
      file: "terraform/firewall.tf",
      content: `resource "google_compute_firewall" "allow_all_egress" {\n  name    = "allow-all-egress"\n  network = "default"\n  log_config {\n    metadata = "INCLUDE_ALL_METADATA"\n  }\n}\n`
    },
    note: "searchRepo matches line-by-line, and positive's single line 'log_config {}' matches the empty-braces alternative in LOGGING_DISABLED_PATTERN exactly; negative's 'log_config {' line has no closing brace on the same line (the block spans three lines with a real metadata attribute inside), so \\{\\s*\\} cannot match on any single line."
  },
  {
    ruleId: "INFRA_IMDSV1_ACCESSIBLE",
    check: "infra",
    positive: {
      file: "terraform/ec2.tf",
      content: `resource "aws_instance" "web" {\n  ami           = "ami-0123456789abcdef0"\n  instance_type = "t3.micro"\n\n  metadata_options {\n    http_tokens                 = "optional"\n    http_put_response_hop_limit = 2\n  }\n}\n`
    },
    negative: {
      file: "terraform/ec2.tf",
      content: `resource "aws_instance" "web" {\n  ami           = "ami-0123456789abcdef0"\n  instance_type = "t3.micro"\n\n  metadata_options {\n    http_tokens                 = "required"\n    http_put_response_hop_limit = 1\n  }\n}\n`
    },
    note: "Positive's 'http_tokens = \"optional\"' matches directly; negative sets http_tokens = \"required\" and hop_limit = 1 (a single digit outside both the [2-9] and \\d{2,} alternatives), so IMDSv2 is enforced and no alternative in the pattern matches."
  },
  {
    ruleId: "INFRA_LAMBDA_URL_NO_AUTH",
    check: "infra",
    positive: {
      file: "terraform/lambda-url.tf",
      content: `resource "aws_lambda_function_url" "public" {\n  function_name      = aws_lambda_function.api.function_name\n  authorization_type = "NONE"\n}\n`
    },
    negative: {
      file: "terraform/lambda-url.tf",
      content: `resource "aws_lambda_function_url" "internal" {\n  function_name      = aws_lambda_function.api.function_name\n  authorization_type = "AWS_IAM"\n}\n`
    },
    note: "Positive's 'authorization_type = \"NONE\"' matches the (?:FunctionUrlAuthType|authorization_type)...\"NONE\" pattern; negative sets authorization_type = \"AWS_IAM\", the exact fix in requiredActions, so the value is never \"NONE\"."
  },
  {
    ruleId: "INFRA_ECR_NO_SCAN",
    check: "infra",
    positive: {
      file: "terraform/ecr.tf",
      content: `resource "aws_ecr_repository" "app" {\n  name = "app-repo"\n\n  image_scanning_configuration {\n    scan_on_push = false\n  }\n}\n`
    },
    negative: {
      file: "terraform/ecr.tf",
      content: `resource "aws_ecr_repository" "app" {\n  name = "app-repo"\n\n  image_scanning_configuration {\n    scan_on_push = true\n  }\n}\n`
    },
    note: "Positive's 'scan_on_push = false' matches the rule's only pattern directly; negative flips it to true, enabling on-push CVE scanning as requiredActions instructs."
  },
  {
    ruleId: "INFRA_ECS_HOST_NETWORK",
    check: "infra",
    positive: {
      file: "terraform/ecs.tf",
      content: `resource "aws_ecs_task_definition" "app" {\n  family       = "app"\n  network_mode = "host"\n}\n`
    },
    negative: {
      file: "terraform/ecs.tf",
      content: `resource "aws_ecs_task_definition" "app" {\n  family       = "app"\n  network_mode = "awsvpc"\n}\n`
    },
    note: "Positive's 'network_mode = \"host\"' matches (?:network_mode|networkMode)...\"host\"; negative uses \"awsvpc\", the isolated networking mode the rule recommends, so the literal \"host\" value never appears."
  },
  {
    ruleId: "INFRA_CLOUDTRAIL_NOT_MULTIREGION",
    check: "infra",
    positive: {
      file: "terraform/cloudtrail.tf",
      content: `resource "aws_cloudtrail" "org" {\n  name                   = "org-trail"\n  s3_bucket_name         = aws_s3_bucket.trail.id\n  is_multi_region_trail  = false\n}\n`
    },
    negative: {
      file: "terraform/cloudtrail.tf",
      content: `resource "aws_cloudtrail" "org" {\n  name                   = "org-trail"\n  s3_bucket_name         = aws_s3_bucket.trail.id\n  is_multi_region_trail  = true\n}\n`
    },
    note: "Positive's 'is_multi_region_trail = false' matches the rule's Terraform alternative; negative sets it to true so trail coverage spans all opted-in regions, matching requiredActions."
  },
  {
    ruleId: "INFRA_S3_NO_ACCESS_LOGGING",
    check: "infra",
    positive: {
      file: "terraform/s3-logging.tf",
      content: `resource "aws_s3_bucket_logging" "app" {\n  bucket        = aws_s3_bucket.app.id\n  target_bucket = ""\n  target_prefix = "log/"\n}\n`
    },
    negative: {
      file: "terraform/s3-logging.tf",
      content: `resource "aws_s3_bucket_logging" "app" {\n  bucket        = aws_s3_bucket.app.id\n  target_bucket = aws_s3_bucket.access_logs.id\n  target_prefix = "log/"\n}\n`
    },
    note: "Positive's 'target_bucket = \"\"' matches the empty-string alternative in the rule's pattern; negative points target_bucket at a real logging bucket resource reference, never an empty string literal."
  },
  {
    ruleId: "INFRA_VPC_NO_FLOW_LOGS",
    check: "infra",
    positive: {
      file: "terraform/instance.tf",
      content: `resource "aws_instance" "app" {\n  ami           = "ami-0123456789abcdef0"\n  instance_type = "t3.micro"\n  subnet_id     = aws_subnet.app.id\n}\n`
    },
    negative: {
      file: "terraform/instance.tf",
      content: `resource "aws_instance" "app" {\n  ami           = "ami-0123456789abcdef0"\n  instance_type = "t3.micro"\n  subnet_id     = aws_subnet.app.id\n}\n\nresource "aws_flow_log" "app_vpc" {\n  vpc_id               = aws_vpc.app.id\n  traffic_type         = "ALL"\n  log_destination      = aws_cloudwatch_log_group.vpc_flow_logs.arn\n  log_destination_type = "cloud-watch-logs"\n}\n`
    },
    note: "This is an absence check: it fires when an aws_instance/ecs_service/lambda_function resource exists but no aws_flow_log resource is found anywhere. Positive has only the instance; negative adds an aws_flow_log resource whose declaration line contains the literal 'aws_flow_log' text, flipping vpcNoFlowLogsResults.length to non-zero and suppressing the finding."
  },
  {
    ruleId: "INFRA_CROSS_ACCOUNT_NO_EXTERNAL_ID",
    check: "infra",
    positive: {
      file: "iam/trust-policy.json",
      content: `{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": { "AWS": "arn:aws:iam::999999999999:root" },\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}\n`
    },
    negative: {
      file: "iam/trust-policy.json",
      content: `{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": { "AWS": "arn:aws:iam::999999999999:root" },\n      "Action": "sts:AssumeRole",\n      "Condition": {\n        "StringEquals": {\n          "sts:ExternalId": "a1b2c3d4-partner-unique-id"\n        }\n      }\n    }\n  ]\n}\n`
    },
    note: "Positive's '\"Action\": \"sts:AssumeRole\"' line satisfies assumeRoleResults with no 'sts:ExternalId' anywhere in the file; negative adds a Condition block whose 'sts:ExternalId' line makes externalIdResults non-empty, which suppresses the confused-deputy finding per the check's own absence logic."
  },
  {
    ruleId: "INFRA_GCP_DEFAULT_SERVICE_ACCOUNT",
    check: "infra",
    positive: {
      file: "terraform/gce-instance.tf",
      content: `resource "google_compute_instance" "app" {\n  name         = "app-vm"\n  machine_type = "e2-medium"\n  zone         = "us-central1-a"\n\n  service_account {\n    email  = "123456789012-compute@developer.gserviceaccount.com"\n    scopes = ["cloud-platform"]\n  }\n}\n`
    },
    negative: {
      file: "terraform/gce-instance.tf",
      content: `resource "google_compute_instance" "app" {\n  name         = "app-vm"\n  machine_type = "e2-medium"\n  zone         = "us-central1-a"\n\n  service_account {\n    email  = google_service_account.app_sa.email\n    scopes = ["cloud-platform"]\n  }\n}\n`
    },
    note: "Positive's email literal ends in '-compute@developer.gserviceaccount.com', the exact default-SA suffix the rule matches; negative references a dedicated google_service_account resource instead of any literal default-SA email string."
  },
  {
    ruleId: "INFRA_GCP_PROJECT_SSH_KEYS",
    check: "infra",
    positive: {
      file: "terraform/gce-metadata.tf",
      content: `resource "google_compute_project_metadata" "default" {\n  metadata = {\n    "ssh-keys": "admin:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7examplekeydata admin@example.com"\n  }\n}\n`
    },
    negative: {
      file: "terraform/gce-metadata.tf",
      content: `resource "google_compute_project_metadata" "default" {\n  metadata = {\n    "enable-oslogin": "TRUE"\n  }\n}\n`
    },
    note: "Positive's '\"ssh-keys\":' key matches the rule's pattern exactly; negative uses '\"enable-oslogin\": \"TRUE\"' instead, which the rule's own requiredActions recommends in place of metadata-based SSH keys, and contains no 'ssh-keys' substring."
  },
  {
    ruleId: "INFRA_GCP_EXTERNAL_IP",
    check: "infra",
    positive: {
      file: "terraform/gce-network.tf",
      content: `resource "google_compute_instance" "app" {\n  name         = "app-vm"\n  machine_type = "e2-medium"\n  zone         = "us-central1-a"\n\n  network_interface {\n    network = "default"\n\n    access_config {}\n  }\n}\n`
    },
    negative: {
      file: "terraform/gce-network.tf",
      content: `resource "google_compute_instance" "app" {\n  name         = "app-vm"\n  machine_type = "e2-medium"\n  zone         = "us-central1-a"\n\n  network_interface {\n    network    = "default"\n    subnetwork = google_compute_subnetwork.app.id\n  }\n}\n`
    },
    note: "Positive's 'access_config {}' line matches access_config\\s*\\{ (the pattern needs no closing brace to match); negative's network_interface block omits access_config entirely, the exact remediation (no external IP, private-only via subnetwork), so the literal string 'access_config' never appears."
  },
  {
    ruleId: "INFRA_AZURE_PUBLIC_NETWORK_ACCESS",
    check: "infra",
    positive: {
      file: "terraform/azure-storage.tf",
      content: `resource "azurerm_storage_account" "app" {\n  name                     = "appstorageacct"\n  resource_group_name      = azurerm_resource_group.app.name\n  location                 = azurerm_resource_group.app.location\n  account_tier             = "Standard"\n  account_replication_type = "LRS"\n\n  public_network_access_enabled = true\n}\n`
    },
    negative: {
      file: "terraform/azure-storage.tf",
      content: `resource "azurerm_storage_account" "app" {\n  name                     = "appstorageacct"\n  resource_group_name      = azurerm_resource_group.app.name\n  location                 = azurerm_resource_group.app.location\n  account_tier             = "Standard"\n  account_replication_type = "LRS"\n\n  public_network_access_enabled = false\n}\n`
    },
    note: "Positive's 'public_network_access_enabled = true' matches the rule's only pattern; negative sets it to false, forcing access through Private Endpoints as requiredActions recommends."
  },
  {
    ruleId: "INFRA_DB_NO_DELETION_PROTECTION",
    check: "infra",
    positive: {
      file: "terraform/rds-lifecycle.tf",
      content: `resource "aws_db_instance" "app" {\n  identifier          = "app-db"\n  engine              = "postgres"\n  deletion_protection = false\n}\n`
    },
    negative: {
      file: "terraform/rds-lifecycle.tf",
      content: `resource "aws_db_instance" "app" {\n  identifier          = "app-db"\n  engine              = "postgres"\n  deletion_protection = true\n\n  lifecycle {\n    prevent_destroy = true\n  }\n}\n`
    },
    note: "Positive's 'deletion_protection = false' matches (?:deletion_protection|enable_deletion_protection)\\s*=\\s*false directly; negative sets it to true and adds a lifecycle prevent_destroy block, the additional safeguard requiredActions calls for, so the false literal never appears."
  },
  {
    ruleId: "INFRA_NO_VPC_ENDPOINT",
    check: "infra",
    positive: {
      file: "terraform/ecs-service.tf",
      content: `resource "aws_ecs_service" "app" {\n  name            = "app-service"\n  cluster         = aws_ecs_cluster.app.id\n  task_definition = aws_ecs_task_definition.app.arn\n  desired_count   = 2\n  launch_type     = "FARGATE"\n\n  network_configuration {\n    subnets = [aws_subnet.private.id]\n  }\n}\n`
    },
    negative: {
      file: "terraform/ecs-service.tf",
      content: `resource "aws_ecs_service" "app" {\n  name            = "app-service"\n  cluster         = aws_ecs_cluster.app.id\n  task_definition = aws_ecs_task_definition.app.arn\n  desired_count   = 2\n  launch_type     = "FARGATE"\n\n  network_configuration {\n    subnets = [aws_subnet.private.id]\n  }\n}\n\nresource "aws_vpc_endpoint" "ecr_api" {\n  vpc_id            = aws_vpc.app.id\n  service_name      = "com.amazonaws.us-east-1.ecr.api"\n  vpc_endpoint_type = "Interface"\n}\n`
    },
    note: "Absence check: fires when an aws_ecs_service (matches awsInfraResults) exists but no aws_vpc_endpoint resource is found. Positive has only the service; negative adds an aws_vpc_endpoint resource declaration, whose literal text suppresses the finding via vpcEndpointResults.length > 0."
  },
  {
    ruleId: "INFRA_GUARDDUTY_MISSING",
    check: "infra",
    positive: {
      file: "terraform/lambda-function.tf",
      content: `resource "aws_lambda_function" "api" {\n  function_name = "api-handler"\n  runtime       = "nodejs20.x"\n  handler       = "index.handler"\n  role          = aws_iam_role.lambda.arn\n  filename      = "function.zip"\n}\n`
    },
    negative: {
      file: "terraform/lambda-function.tf",
      content: `resource "aws_lambda_function" "api" {\n  function_name = "api-handler"\n  runtime       = "nodejs20.x"\n  handler       = "index.handler"\n  role          = aws_iam_role.lambda.arn\n  filename      = "function.zip"\n}\n\nresource "aws_guardduty_detector" "main" {\n  enable = true\n}\n`
    },
    note: "Absence check: fires when an aws_lambda_function (matches awsInfraResults) exists but no aws_guardduty_detector is found. Positive has only the function; negative adds an aws_guardduty_detector resource, whose literal text makes guarddutyResults non-empty and suppresses the finding."
  },
  {
    ruleId: "INFRA_SECURITY_HUB_MISSING",
    check: "infra",
    positive: {
      file: "terraform/ec2-worker.tf",
      content: `resource "aws_instance" "worker" {\n  ami           = "ami-0abcdef1234567890"\n  instance_type = "m5.large"\n}\n`
    },
    negative: {
      file: "terraform/ec2-worker.tf",
      content: `resource "aws_instance" "worker" {\n  ami           = "ami-0abcdef1234567890"\n  instance_type = "m5.large"\n}\n\nresource "aws_securityhub_account" "main" {\n  enable_default_standards = true\n}\n`
    },
    note: "Absence check: fires when an aws_instance (matches awsInfraResults) exists but no aws_securityhub_account is found. Positive has only the instance; negative adds an aws_securityhub_account resource, whose literal text makes securityHubResults non-empty and suppresses the finding."
  }
];
