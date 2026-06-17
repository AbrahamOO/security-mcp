# INSECURE FIXTURE — Databricks workspace / job / git / mount anti-patterns.

# 20. Cluster spark_conf exposing storage keys inline
resource "databricks_cluster" "keyed" {
  cluster_name = "keyed-cluster"
  spark_conf = {
    "fs.azure.account.key.acct.dfs.core.windows.net" = "abcDEF1234567890abcDEFkeymaterial=="
    "fs.s3a.access.key"                              = "AKIAIOSFODNN7EXAMPLE"
    "spark.hadoop.fs.gs.auth.service.account.key"    = "privatekeymaterial12345"
  }
}

# 21. single_user_name / data_security_mode mismatch
resource "databricks_cluster" "mismatch" {
  cluster_name       = "single-user-bad"
  data_security_mode = "SINGLE_USER"
  single_user_name   = ""
}

# 24. Repos git credential with inline PAT
resource "databricks_git_credential" "gh" {
  git_provider          = "gitHub"
  git_username          = "ci-bot"
  personal_access_token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
}

# 25. Job run_as elevated service principal
resource "databricks_job" "etl_job" {
  name = "nightly-etl"
  run_as {
    service_principal_name = "ci-admin-sp"
  }
}

# 28. Workspace conf weakening controls
resource "databricks_workspace_conf" "this" {
  custom_config = {
    "enableTokensConfig"    = "true"
    "enableDbfsFileBrowser" = "true"
    "enforceUserIsolation"  = "false"
    "enableExportNotebook"  = "true"
  }
}

# 29. Audit / verbose logging disabled
resource "databricks_mws_log_delivery" "audit" {
  status = "DISABLED"
}
# spark.databricks.audit.enabled false
