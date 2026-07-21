import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "IAC_TF_STATE_INSECURE",
    check: "iac",
    positive: {
      file: "infra/backend.tf",
      content: `terraform {
  backend "s3" {
    bucket  = "my-terraform-state"
    key     = "prod/terraform.tfstate"
    region  = "us-east-1"
    encrypt = false
  }
}
`
    },
    negative: {
      file: "infra/backend.tf",
      content: `terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
    dynamodb_table = "terraform-locks"
  }
}
`
    },
    note: "Positive hits encrypt = false directly. Negative sets encrypt = true and adds dynamodb_table (lock), so neither TF_STATE_PATTERN nor the backendS3-without-lock heuristic fires — a genuine encrypted, locked backend, not a cosmetic edit."
  },
  {
    ruleId: "IAC_TF_PROVISIONER_EXEC",
    check: "iac",
    positive: {
      file: "infra/web.tf",
      content: `resource "aws_instance" "web" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

  provisioner "local-exec" {
    command = "curl -s http://tools.example/install.sh | bash"
  }
}
`
    },
    negative: {
      file: "infra/web.tf",
      content: `resource "aws_instance" "web" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  user_data     = filebase64("\${path.module}/init.sh")
}
`
    },
    note: "Negative removes the provisioner entirely and moves bootstrap logic to a static user_data file, the exact remediation this rule recommends, instead of merely renaming the provisioner block."
  },
  {
    ruleId: "IAC_HARDCODED_SECRET",
    check: "iac",
    positive: {
      file: "infra/provider.tf",
      content: `provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region     = "us-east-1"
}
`
    },
    negative: {
      file: "infra/provider.tf",
      content: `provider "aws" {
  region = "us-east-1"
  # credentials resolved via the default provider chain (env vars, SSO, or
  # IRSA/OIDC role assumption) — never a literal access_key/secret_key here.
}
`
    },
    note: "Negative authenticates via the default credential chain instead of literal quoted key values, so SECRET_PATTERN_A never finds a quoted access_key/secret_key literal to match."
  },
  {
    ruleId: "IAC_TF_UNSAFE_DESTROY",
    check: "iac",
    positive: {
      file: "infra/db.tf",
      content: `resource "aws_db_instance" "prod" {
  identifier          = "prod-db"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  skip_final_snapshot = true
}
`
    },
    negative: {
      file: "infra/db.tf",
      content: `resource "aws_db_instance" "prod" {
  identifier           = "prod-db"
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  skip_final_snapshot  = false
  deletion_protection  = true
}
`
    },
    note: "Negative flips skip_final_snapshot to false and adds deletion_protection, so no destructive/validation-skipping toggle is set to true anywhere in the file."
  },
  {
    ruleId: "IAC_TF_SG_OPEN_WORLD",
    check: "iac",
    positive: {
      file: "infra/sg.tf",
      content: `resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}
`
    },
    negative: {
      file: "infra/sg.tf",
      content: `variable "admin_cidr" {
  type    = string
  default = "203.0.113.4/32"
}

resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.admin_cidr]
  security_group_id = aws_security_group.app.id
}
`
    },
    note: "Negative restricts ingress to a specific admin CIDR variable instead of 0.0.0.0/0, so the literal wildcard CIDR the regex looks for is not present."
  },
  {
    ruleId: "IAC_TF_IMDSV1_OPTIONAL",
    check: "iac",
    positive: {
      file: "infra/instance.tf",
      content: `resource "aws_instance" "web" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
}
`
    },
    negative: {
      file: "infra/instance.tf",
      content: `resource "aws_instance" "web" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
`
    },
    note: "Negative sets http_tokens = \"required\" (IMDSv2 enforced), the exact fix recommended, so the \"optional\" literal the regex targets is gone."
  },
  {
    ruleId: "IAC_TF_S3_MISSING_HARDENING",
    check: "iac",
    positive: {
      file: "infra/s3.tf",
      content: `resource "aws_s3_bucket" "data" {
  bucket = "my-app-data-bucket"
}
`
    },
    negative: {
      file: "infra/s3.tf",
      content: `resource "aws_s3_bucket" "data" {
  bucket = "my-app-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`
    },
    note: "The rule fires when a bucket resource exists but neither an SSE-configuration nor a public-access-block resource is present anywhere in the file. Negative adds both companion resources, exactly the remediation shown, so both presence checks are satisfied."
  },
  {
    ruleId: "IAC_TF_KMS_NO_ROTATION",
    check: "iac",
    positive: {
      file: "infra/kms.tf",
      content: `resource "aws_kms_key" "app" {
  description         = "app data key"
  enable_key_rotation = false
}
`
    },
    negative: {
      file: "infra/kms.tf",
      content: `resource "aws_kms_key" "app" {
  description         = "app data key"
  enable_key_rotation = true
}
`
    },
    note: "Negative flips enable_key_rotation to true, the one attribute the regex checks, with no other change."
  },
  {
    ruleId: "IAC_TF_VAR_DEFAULT_SECRET",
    check: "iac",
    positive: {
      file: "infra/variables.tf",
      content: `variable "aws_access_key" {
  type    = string
  default = "AKIAIOSFODNN7EXAMPLE"
}
`
    },
    negative: {
      file: "infra/variables.tf",
      content: `variable "aws_access_key" {
  type      = string
  sensitive = true
  # No default: value is injected at apply time via the TF_VAR_aws_access_key
  # environment variable, never committed to source.
}
`
    },
    note: "Negative declares the variable with no default at all (the rule's own recommended fix), so there is no quoted AKIA... literal for the regex to match."
  },
  {
    ruleId: "IAC_TF_IAM_PRIVILEGE_ESCALATION",
    check: "iac",
    positive: {
      file: "infra/iam.tf",
      content: `data "aws_iam_policy_document" "escalate" {
  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole", "iam:CreateAccessKey"]
    resources = ["*"]
  }
}
`
    },
    negative: {
      file: "infra/iam.tf",
      content: `data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = ["111122223333"]
    }
  }
}

resource "aws_iam_role" "task" {
  name               = "ecs-task-role"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}
`
    },
    note: "This detector matches literal privileged-action/wildcard-trust strings (iam:PassRole, iam:Create/SetDefaultPolicyVersion, iam:PutUserPolicy, iam:AttachUserPolicy, iam:CreateAccessKey, AWS/Principal/identifiers \"*\") and cannot evaluate IAM conditions, so a genuinely safe negative must omit those grants/trust entirely rather than merely add a condition on the same PassRole grant (which would still match the literal string). This negative grants only a scoped AssumeRole trust to a specific service principal with a SourceAccount condition and requests no PassRole/escalation actions at all — the real-world fix the rule's own requiredActions describe."
  },
  {
    ruleId: "IAC_TF_VPC_NO_FLOW_LOGS",
    check: "iac",
    positive: {
      file: "infra/vpc.tf",
      content: `resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
`
    },
    negative: {
      file: "infra/vpc.tf",
      content: `resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow.arn
  iam_role_arn    = aws_iam_role.flow.arn
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/vpc/flow-logs"
  retention_in_days = 365
}

resource "aws_iam_role" "flow" {
  name               = "vpc-flow-logs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_trust.json
}
`
    },
    note: "Negative adds an aws_flow_log resource capturing traffic_type = \"ALL\" for the same VPC, satisfying both the presence and the ALL-traffic condition the rule checks."
  },
  {
    ruleId: "IAC_TF_SQS_SNS_UNENCRYPTED",
    check: "iac",
    positive: {
      file: "infra/queue.tf",
      content: `resource "aws_sqs_queue" "orders" {
  name = "orders-queue"
}
`
    },
    negative: {
      file: "infra/queue.tf",
      content: `resource "aws_sqs_queue" "orders" {
  name                              = "orders-queue"
  kms_master_key_id                 = aws_kms_key.sqs.id
  kms_data_key_reuse_period_seconds = 300
}
`
    },
    note: "Negative adds kms_master_key_id to the same queue resource, the exact server-side encryption attribute the rule looks for before considering the queue hardened."
  },
  {
    ruleId: "IAC_TF_DEFAULT_VPC",
    check: "iac",
    positive: {
      file: "infra/network.tf",
      content: `resource "aws_default_vpc" "default" {
  tags = {
    Name = "default vpc"
  }
}
`
    },
    negative: {
      file: "infra/network.tf",
      content: `resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "app" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
`
    },
    note: "Negative provisions a purpose-built aws_vpc/aws_subnet instead of adopting the AWS default VPC, so no aws_default_vpc/aws_default_security_group/aws_default_subnet resource type appears."
  },
  {
    ruleId: "IAC_CFN_IAM_WILDCARD",
    check: "iac",
    positive: {
      file: "cloudformation/template.json",
      content: `{
  "Resources": {
    "AppRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "Policies": [
          {
            "PolicyName": "AppPolicy",
            "PolicyDocument": {
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": "*",
                  "Resource": "*"
                }
              ]
            }
          }
        ]
      }
    }
  }
}
`
    },
    negative: {
      file: "cloudformation/template.json",
      content: `{
  "Resources": {
    "AppRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "Policies": [
          {
            "PolicyName": "AppPolicy",
            "PolicyDocument": {
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": ["s3:GetObject", "s3:PutObject"],
                  "Resource": "arn:aws:s3:::app-bucket/*"
                }
              ]
            }
          }
        ]
      }
    }
  }
}
`
    },
    note: "Negative enumerates explicit S3 actions and a scoped ARN instead of \"*\"/\"*\", removing the wildcard literal entirely rather than just reformatting it."
  },
  {
    ruleId: "IAC_CFN_S3_PUBLIC",
    check: "iac",
    positive: {
      file: "cloudformation/bucket.json",
      content: `{
  "Resources": {
    "AppBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": false,
          "BlockPublicPolicy": false,
          "IgnorePublicAcls": false,
          "RestrictPublicBuckets": false
        }
      }
    }
  }
}
`
    },
    negative: {
      file: "cloudformation/bucket.json",
      content: `{
  "Resources": {
    "AppBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": true,
          "BlockPublicPolicy": true,
          "IgnorePublicAcls": true,
          "RestrictPublicBuckets": true
        }
      }
    }
  }
}
`
    },
    note: "Negative sets every PublicAccessBlockConfiguration field to true, so none of the \"...\": false / AccessControl PublicRead literals the regex looks for are present."
  },
  {
    ruleId: "IAC_CFN_IMDSV1_ALLOWED",
    check: "iac",
    positive: {
      file: "cloudformation/instance.json",
      content: `{
  "Resources": {
    "WebInstance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "MetadataOptions": {
          "HttpEndpoint": "enabled",
          "HttpTokens": "optional"
        }
      }
    }
  }
}
`
    },
    negative: {
      file: "cloudformation/instance.json",
      content: `{
  "Resources": {
    "WebInstance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "MetadataOptions": {
          "HttpEndpoint": "enabled",
          "HttpTokens": "required",
          "HttpPutResponseHopLimit": 1
        }
      }
    }
  }
}
`
    },
    note: "Negative sets HttpTokens to \"required\" (IMDSv2 enforced) instead of \"optional\", the literal string the regex requires."
  },
  {
    ruleId: "IAC_CFN_NO_DELETION_POLICY",
    check: "iac",
    positive: {
      file: "cloudformation/table.json",
      content: `{
  "Resources": {
    "OrdersTable": {
      "Type": "AWS::DynamoDB::Table",
      "Properties": {
        "TableName": "orders",
        "BillingMode": "PAY_PER_REQUEST"
      }
    }
  }
}
`
    },
    negative: {
      file: "cloudformation/table.json",
      content: `{
  "Resources": {
    "OrdersTable": {
      "Type": "AWS::DynamoDB::Table",
      "DeletionPolicy": "Retain",
      "UpdateReplacePolicy": "Retain",
      "Properties": {
        "TableName": "orders",
        "BillingMode": "PAY_PER_REQUEST"
      }
    }
  }
}
`
    },
    note: "Rule fires when a stateful resource type (RDS/DynamoDB/S3) exists without a \"DeletionPolicy\": \"Retain\" anywhere in the file. Negative adds it (plus UpdateReplacePolicy), satisfying the presence check."
  },
  {
    ruleId: "IAC_BICEP_INSECURE_NETWORK",
    check: "iac",
    positive: {
      file: "bicep/storage.bicep",
      content: `resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'appstorage001'
  location: resourceGroup().location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: false
    allowBlobPublicAccess: true
  }
}
`
    },
    negative: {
      file: "bicep/storage.bicep",
      content: `resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'appstorage001'
  location: resourceGroup().location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    publicNetworkAccess: 'Disabled'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    networkAcls: {
      defaultAction: 'Deny'
    }
  }
}
`
    },
    note: "Negative flips all three flags (publicNetworkAccess Disabled, HTTPS-only true, blob public access false) and adds TLS1_2 + a Deny-by-default network ACL — none of the insecure literals (Enabled/false/true in those specific slots, TLS1_0/1_1, defaultAction Allow) remain."
  },
  {
    ruleId: "IAC_CDK_INSECURE_CONSTRUCT",
    check: "iac",
    positive: {
      file: "cdk/lib/app-stack.ts",
      content: `import * as cdk from 'aws-cdk-lib';
import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

export class AppStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    new dynamodb.Table(this, 'OrdersTable', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
  }
}
`
    },
    negative: {
      file: "cdk/lib/app-stack.ts",
      content: `import * as cdk from 'aws-cdk-lib';
import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

export class AppStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    new dynamodb.Table(this, 'OrdersTable', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      pointInTimeRecovery: true,
    });
  }
}
`
    },
    note: "Negative sets removalPolicy to RETAIN instead of DESTROY on the same stateful DynamoDB construct and adds point-in-time recovery, the exact fix requiredActions recommends, with no addToRolePolicy or wildcard actions/resources present either."
  },
  {
    ruleId: "IAC_ANSIBLE_INSECURE_TASK",
    check: "iac",
    positive: {
      file: "ansible/playbook.yml",
      content: `- name: Configure app server
  hosts: appservers
  become: yes
  vars:
    ansible_become_pass: SuperSecretRootPass123
  tasks:
    - name: Fetch internal config over TLS
      uri:
        url: "https://internal.example.com/config"
        validate_certs: no
      no_log: false
`
    },
    negative: {
      file: "ansible/playbook.yml",
      content: `- name: Configure app server
  hosts: appservers
  become: yes
  tasks:
    - name: Fetch internal config over TLS
      uri:
        url: "https://internal.example.com/config"
        validate_certs: yes
      no_log: true
`
    },
    note: "Negative never inlines ansible_become_pass at all (the become password is supplied out-of-band via --ask-become-pass or an ansible-vault-encrypted group_vars file, not shown in this playbook), keeps validate_certs: yes, and sets no_log: true — removing every one of the three anti-patterns instead of just quoting the password behind a Jinja reference (which the regex would still match on the leading quote character)."
  }
];
