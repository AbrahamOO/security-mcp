import type { RuleCase } from "./types.js";

// Terraform corpus for the registry-driven "cloud-controls" check
// (src/gate/checks/cloud-controls.ts -> src/gate/cloud-controls/detect.ts).
//
// detectTerraform() matches each rule's `detect.resourceType` against parsed
// `resource "type" "name" { ... }` blocks, then applies exactly one of:
//   - forbid:               regex present anywhere in the block body => insecure
//   - require:               regex ABSENT from the block body => insecure-by-omission
//   - requireCompanionType:  no sibling resource of that type references this
//                            resource's `type.name` in the same file => insecure
// Positives are built to hit the forbid regex / omit the require regex / omit
// the companion resource; negatives apply the exact hardened attribute (or add
// the companion) the rule's `remediate.ensure` / `remediate.companion` prescribes.

export const cases: RuleCase[] = [
  // ---------------------------------------------------------------------
  // AWS
  // ---------------------------------------------------------------------
  {
    ruleId: "AWS_EC2_IMDSV2_REQUIRED",
    check: "cloud-controls",
    positive: {
      file: "terraform/aws/ec2.tf",
      content: `resource "aws_instance" "api" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
}
`
    },
    negative: {
      file: "terraform/aws/ec2.tf",
      content: `resource "aws_instance" "api" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
`
    },
    note: "require: \"http_tokens\\s*=\\s*\\\"required\\\"\" on aws_instance; the positive has no metadata_options block at all (insecure-by-omission), the negative adds one with http_tokens = \"required\", the exact remediate.ensure value."
  },
  {
    ruleId: "AWS_RDS_NOT_PUBLIC",
    check: "cloud-controls",
    positive: {
      file: "terraform/aws/rds.tf",
      content: `resource "aws_db_instance" "primary" {
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  publicly_accessible  = true
  skip_final_snapshot  = true
}
`
    },
    negative: {
      file: "terraform/aws/rds.tf",
      content: `resource "aws_db_instance" "primary" {
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  publicly_accessible  = false
  skip_final_snapshot  = true
}
`
    },
    note: "forbid: \"publicly_accessible\\s*=\\s*true\" on aws_db_instance; negative flips the same attribute to false rather than deleting it."
  },
  {
    ruleId: "AWS_S3_BUCKET_NO_PUBLIC_ACL",
    check: "cloud-controls",
    positive: {
      file: "terraform/aws/s3.tf",
      content: `resource "aws_s3_bucket" "assets" {
  bucket = "prod-assets-bucket"
  acl    = "public-read"
}
`
    },
    negative: {
      file: "terraform/aws/s3.tf",
      content: `resource "aws_s3_bucket" "assets" {
  bucket = "prod-assets-bucket"
  acl    = "private"
}
`
    },
    note: "forbid: \"acl\\s*=\\s*\\\"public-read\" on aws_s3_bucket; negative sets acl = \"private\", the remediate.ensure value, instead of removing the acl attribute."
  },
  {
    ruleId: "AWS_S3_BLOCK_PUBLIC_ACCESS",
    check: "cloud-controls",
    positive: {
      file: "terraform/aws/s3-block.tf",
      content: `resource "aws_s3_bucket" "assets" {
  bucket = "prod-assets-bucket"
  acl    = "private"
}
`
    },
    negative: {
      file: "terraform/aws/s3-block.tf",
      content: `resource "aws_s3_bucket" "assets" {
  bucket = "prod-assets-bucket"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`
    },
    note: "requireCompanionType: \"aws_s3_bucket_public_access_block\"; companionExists() scans sibling blocks in the same file for one whose body contains \"aws_s3_bucket.assets\". Positive has the bucket alone (no companion at all); negative adds the companion block referencing it by local name, exactly as remediate.companion prescribes."
  },
  {
    ruleId: "AWS_KMS_KEY_ROTATION",
    check: "cloud-controls",
    positive: {
      file: "terraform/aws/kms.tf",
      content: `resource "aws_kms_key" "data" {
  description = "CMK for application data"
}
`
    },
    negative: {
      file: "terraform/aws/kms.tf",
      content: `resource "aws_kms_key" "data" {
  description         = "CMK for application data"
  enable_key_rotation  = true
}
`
    },
    note: "require: \"enable_key_rotation\\s*=\\s*true\" on aws_kms_key; positive omits the attribute entirely, negative sets it exactly as remediate.ensure prescribes."
  },
  {
    ruleId: "AWS_VPC_SG_INGRESS_RULE_NO_OPEN_IPV4",
    check: "cloud-controls",
    positive: {
      file: "terraform/aws/sg-rule.tf",
      content: `resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.app.id
  from_port          = 22
  to_port            = 22
  ip_protocol        = "tcp"
  cidr_ipv4          = "0.0.0.0/0"
}
`
    },
    negative: {
      file: "terraform/aws/sg-rule.tf",
      content: `resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.app.id
  from_port          = 22
  to_port            = 22
  ip_protocol        = "tcp"
  cidr_ipv4          = "10.0.4.0/24"
}
`
    },
    note: "forbid: \"cidr_ipv4\\s*=\\s*\\\"0\\.0\\.0\\.0/0\\\"\" on aws_vpc_security_group_ingress_rule; negative scopes the same attribute to a specific VPC CIDR instead of deleting the rule."
  },
  {
    ruleId: "AWS_LAMBDA_URL_AUTH_REQUIRED",
    check: "cloud-controls",
    positive: {
      file: "terraform/aws/lambda-url.tf",
      content: `resource "aws_lambda_function_url" "public" {
  function_name      = "checkout-handler"
  authorization_type = "NONE"
}
`
    },
    negative: {
      file: "terraform/aws/lambda-url.tf",
      content: `resource "aws_lambda_function_url" "public" {
  function_name      = "checkout-handler"
  authorization_type = "AWS_IAM"
}
`
    },
    note: "forbid: \"authorization_type\\s*=\\s*\\\"NONE\\\"\" on aws_lambda_function_url; negative sets authorization_type = \"AWS_IAM\", the remediate.ensure value."
  },

  // ---------------------------------------------------------------------
  // GCP
  // ---------------------------------------------------------------------
  {
    ruleId: "GCP_SQL_NO_PUBLIC_IP",
    check: "cloud-controls",
    positive: {
      file: "terraform/gcp/sql.tf",
      content: `resource "google_sql_database_instance" "db" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-custom-2-8192"
    ip_configuration {
      ipv4_enabled = true
    }
  }
}
`
    },
    negative: {
      file: "terraform/gcp/sql.tf",
      content: `resource "google_sql_database_instance" "db" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-custom-2-8192"
    ip_configuration {
      ipv4_enabled = false
    }
  }
}
`
    },
    note: "forbid: \"ipv4_enabled\\s*=\\s*true\"; the regex applies to the whole resource body (brace-matched across nested settings/ip_configuration blocks), so negative flips the nested attribute to false rather than deleting the block."
  },
  {
    ruleId: "GCP_SQL_REQUIRE_SSL",
    check: "cloud-controls",
    positive: {
      file: "terraform/gcp/sql-ssl.tf",
      content: `resource "google_sql_database_instance" "db" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-custom-2-8192"
    ip_configuration {
      ipv4_enabled = false
    }
  }
}
`
    },
    negative: {
      file: "terraform/gcp/sql-ssl.tf",
      content: `resource "google_sql_database_instance" "db" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-custom-2-8192"
    ip_configuration {
      ipv4_enabled = false
      require_ssl  = true
    }
  }
}
`
    },
    note: "require: \"require_ssl\\s*=\\s*true\"; positive is otherwise hardened (no public IP) but forgets require_ssl, negative adds it inside the nested ip_configuration block, the remediate.ensure path."
  },
  {
    ruleId: "GCP_STORAGE_UNIFORM_ACCESS",
    check: "cloud-controls",
    positive: {
      file: "terraform/gcp/storage.tf",
      content: `resource "google_storage_bucket" "data" {
  name     = "app-data-bucket"
  location = "US"
}
`
    },
    negative: {
      file: "terraform/gcp/storage.tf",
      content: `resource "google_storage_bucket" "data" {
  name                        = "app-data-bucket"
  location                    = "US"
  uniform_bucket_level_access = true
}
`
    },
    note: "require: \"uniform_bucket_level_access\\s*=\\s*true\" on google_storage_bucket; positive omits it entirely (legacy ACLs still apply), negative sets it exactly as remediate.ensure prescribes."
  },
  {
    ruleId: "GCP_KMS_KEY_ROTATION",
    check: "cloud-controls",
    positive: {
      file: "terraform/gcp/kms.tf",
      content: `resource "google_kms_crypto_key" "data" {
  name     = "app-data-key"
  key_ring = "projects/my-project/locations/us/keyRings/app-ring"
}
`
    },
    negative: {
      file: "terraform/gcp/kms.tf",
      content: `resource "google_kms_crypto_key" "data" {
  name            = "app-data-key"
  key_ring        = "projects/my-project/locations/us/keyRings/app-ring"
  rotation_period = "7776000s"
}
`
    },
    note: "require: \"rotation_period\" on google_kms_crypto_key; positive has no rotation_period at all, negative adds the 90-day value from remediate.ensure."
  },
  {
    ruleId: "GCP_FIREWALL_NO_OPEN_ADMIN",
    check: "cloud-controls",
    positive: {
      file: "terraform/gcp/firewall.tf",
      content: `resource "google_compute_firewall" "allow-ssh" {
  name    = "allow-ssh"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}
`
    },
    negative: {
      file: "terraform/gcp/firewall.tf",
      content: `resource "google_compute_firewall" "allow-ssh" {
  name    = "allow-ssh"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["10.10.0.0/16"]
}
`
    },
    note: "forbid: \"0\\.0\\.0\\.0/0\" anywhere in the google_compute_firewall body; negative scopes source_ranges to a specific internal CIDR instead of the whole internet."
  },
  {
    ruleId: "GCP_COMPUTE_SHIELDED_VM",
    check: "cloud-controls",
    positive: {
      file: "terraform/gcp/compute.tf",
      content: `resource "google_compute_instance" "app" {
  name         = "app-vm"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }
  network_interface {
    network = "default"
  }
}
`
    },
    negative: {
      file: "terraform/gcp/compute.tf",
      content: `resource "google_compute_instance" "app" {
  name         = "app-vm"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }
  network_interface {
    network = "default"
  }
  shielded_instance_config {
    enable_secure_boot = true
  }
}
`
    },
    note: "require: \"enable_secure_boot\\s*=\\s*true\" on google_compute_instance; positive has no shielded_instance_config block, negative adds it with secure boot enabled, matching remediate.ensure's nested path."
  },
  {
    ruleId: "GCP_IAM_NO_PRIMITIVE_ROLES",
    check: "cloud-controls",
    positive: {
      file: "terraform/gcp/iam.tf",
      content: `resource "google_project_iam_member" "admin" {
  project = "my-project"
  role    = "roles/owner"
  member  = "user:alice@example.com"
}
`
    },
    negative: {
      file: "terraform/gcp/iam.tf",
      content: `resource "google_project_iam_member" "admin" {
  project = "my-project"
  role    = "roles/cloudsql.admin"
  member  = "user:alice@example.com"
}
`
    },
    note: "forbid: \"\\\"roles/owner\\\"|\\\"roles/editor\\\"\" on google_project_iam_member; negative swaps the primitive role for a scoped predefined role instead of deleting the binding."
  },

  // ---------------------------------------------------------------------
  // Azure
  // ---------------------------------------------------------------------
  {
    ruleId: "AZURE_STORAGE_HTTPS_ONLY",
    check: "cloud-controls",
    positive: {
      file: "terraform/azure/storage.tf",
      content: `resource "azurerm_storage_account" "sa" {
  name                      = "appstorageacct"
  resource_group_name       = "app-rg"
  location                  = "eastus"
  enable_https_traffic_only = false
}
`
    },
    negative: {
      file: "terraform/azure/storage.tf",
      content: `resource "azurerm_storage_account" "sa" {
  name                      = "appstorageacct"
  resource_group_name       = "app-rg"
  location                  = "eastus"
  enable_https_traffic_only = true
}
`
    },
    note: "forbid: \"enable_https_traffic_only\\s*=\\s*false\" on azurerm_storage_account; negative flips the same attribute to true rather than removing it."
  },
  {
    ruleId: "AZURE_STORAGE_NO_PUBLIC_BLOB",
    check: "cloud-controls",
    positive: {
      file: "terraform/azure/storage-blob.tf",
      content: `resource "azurerm_storage_account" "sa" {
  name                            = "appstorageacct"
  resource_group_name             = "app-rg"
  location                        = "eastus"
  allow_nested_items_to_be_public = true
}
`
    },
    negative: {
      file: "terraform/azure/storage-blob.tf",
      content: `resource "azurerm_storage_account" "sa" {
  name                            = "appstorageacct"
  resource_group_name             = "app-rg"
  location                        = "eastus"
  allow_nested_items_to_be_public = false
}
`
    },
    note: "forbid: \"allow_nested_items_to_be_public\\s*=\\s*true\" on azurerm_storage_account; negative sets it to false, the remediate.ensure value, instead of deleting the attribute."
  },
  {
    ruleId: "AZURE_KV_PURGE_PROTECTION",
    check: "cloud-controls",
    positive: {
      file: "terraform/azure/keyvault.tf",
      content: `resource "azurerm_key_vault" "kv" {
  name                = "app-kv"
  resource_group_name = "app-rg"
  location            = "eastus"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
}
`
    },
    negative: {
      file: "terraform/azure/keyvault.tf",
      content: `resource "azurerm_key_vault" "kv" {
  name                     = "app-kv"
  resource_group_name      = "app-rg"
  location                 = "eastus"
  tenant_id                = "00000000-0000-0000-0000-000000000000"
  sku_name                 = "standard"
  purge_protection_enabled = true
}
`
    },
    note: "require: \"purge_protection_enabled\\s*=\\s*true\" on azurerm_key_vault; positive omits the attribute entirely, negative adds it per remediate.ensure."
  },
  {
    ruleId: "AZURE_SQL_NO_PUBLIC_ACCESS",
    check: "cloud-controls",
    positive: {
      file: "terraform/azure/sql-server.tf",
      content: `resource "azurerm_mssql_server" "sql" {
  name                         = "app-sql-server"
  resource_group_name          = "app-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "REPLACE_ME"
  public_network_access_enabled = true
}
`
    },
    negative: {
      file: "terraform/azure/sql-server.tf",
      content: `resource "azurerm_mssql_server" "sql" {
  name                         = "app-sql-server"
  resource_group_name          = "app-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "REPLACE_ME"
  public_network_access_enabled = false
}
`
    },
    note: "forbid: \"public_network_access_enabled\\s*=\\s*true\" on azurerm_mssql_server; negative flips the same attribute to false and would sit behind a private endpoint in practice."
  },
  {
    ruleId: "AZURE_MSSQL_MIN_TLS",
    check: "cloud-controls",
    positive: {
      file: "terraform/azure/sql-tls.tf",
      content: `resource "azurerm_mssql_server" "sql" {
  name                          = "app-sql-server"
  resource_group_name           = "app-rg"
  location                      = "eastus"
  version                       = "12.0"
  administrator_login           = "sqladmin"
  administrator_login_password  = "REPLACE_ME"
  minimum_tls_version           = "1.0"
}
`
    },
    negative: {
      file: "terraform/azure/sql-tls.tf",
      content: `resource "azurerm_mssql_server" "sql" {
  name                          = "app-sql-server"
  resource_group_name           = "app-rg"
  location                      = "eastus"
  version                       = "12.0"
  administrator_login           = "sqladmin"
  administrator_login_password  = "REPLACE_ME"
  minimum_tls_version           = "1.2"
}
`
    },
    note: "require: \"minimum_tls_version\\s*=\\s*\\\"1.2\\\"\" on azurerm_mssql_server; positive sets the old 1.0 value (a real vulnerable config, not just an omission), negative sets 1.2 per remediate.ensure."
  },
  {
    ruleId: "AZURE_NSG_NO_OPEN_ADMIN",
    check: "cloud-controls",
    positive: {
      file: "terraform/azure/nsg-rule.tf",
      content: `resource "azurerm_network_security_rule" "ssh" {
  name                        = "allow-ssh"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "app-rg"
  network_security_group_name = "app-nsg"
}
`
    },
    negative: {
      file: "terraform/azure/nsg-rule.tf",
      content: `resource "azurerm_network_security_rule" "ssh" {
  name                        = "allow-ssh"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  destination_port_range      = "22"
  source_address_prefix       = "10.20.0.0/24"
  destination_address_prefix  = "*"
  resource_group_name         = "app-rg"
  network_security_group_name = "app-nsg"
}
`
    },
    note: "forbid: \"source_address_prefix\\s*=\\s*\\\"\\*\\\"\" on azurerm_network_security_rule; negative scopes the admin-port rule to a specific corporate CIDR instead of any source."
  },
  {
    ruleId: "AZURE_VM_NO_PASSWORD_AUTH",
    check: "cloud-controls",
    positive: {
      file: "terraform/azure/vm.tf",
      content: `resource "azurerm_linux_virtual_machine" "app" {
  name                            = "app-vm"
  resource_group_name             = "app-rg"
  location                        = "eastus"
  size                            = "Standard_B2s"
  admin_username                  = "azureuser"
  disable_password_authentication = false
  admin_password                  = "REPLACE_ME_123!"
}
`
    },
    negative: {
      file: "terraform/azure/vm.tf",
      content: `resource "azurerm_linux_virtual_machine" "app" {
  name                            = "app-vm"
  resource_group_name             = "app-rg"
  location                        = "eastus"
  size                            = "Standard_B2s"
  admin_username                  = "azureuser"
  disable_password_authentication = true

  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }
}
`
    },
    note: "forbid: \"disable_password_authentication\\s*=\\s*false\" on azurerm_linux_virtual_machine; negative flips the attribute to true and switches to an SSH key, the realistic paired fix rather than a cosmetic edit."
  }
];
