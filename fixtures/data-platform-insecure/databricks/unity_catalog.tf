# INSECURE FIXTURE — Databricks Unity Catalog / governance anti-patterns.

# 17. Broad UC grant to all account users
resource "databricks_grants" "cat" {
  catalog = "main"
  grant {
    principal  = "account users"
    privileges = ["ALL_PRIVILEGES"]
  }
}
# GRANT ALL PRIVILEGES ON CATALOG main TO `account users`;
# GRANT MANAGE ON SCHEMA main.sales TO `users`;

# 18. External location / storage credential public / over-broad
resource "databricks_external_location" "raw" {
  name            = "raw"
  url             = "s3a://data-lake/*"
  credential_name = "lake_cred"
  skip_validation = true
}
# GRANT READ FILES ON EXTERNAL LOCATION raw TO `account users`;

# 19. Serverless SQL warehouse with no IP access list
resource "databricks_sql_endpoint" "wh" {
  name                      = "serverless-wh"
  enable_serverless_compute = true
  warehouse_type            = "PRO"
}

# 22. Model serving endpoint public / no auth
resource "databricks_model_serving" "infer" {
  name = "fraud-model"
  auth = "none"
}
resource "databricks_serving_endpoint" "ep" {
  name   = "public-ep"
  public = true
}

# 23. databricks_permissions granting CAN_MANAGE to users group
resource "databricks_permissions" "job_perms" {
  job_id = "123"
  access_control {
    group_name       = "users"
    permission_level = "CAN_MANAGE"
  }
  # condensed single-line form also seen in generated HCL / JSON job specs:
  # group_name = "users", permission_level = "CAN_MANAGE"
}

# 22. Model serving: auth disabled, endpoint public (per-line signals)
resource "databricks_model_serving" "infer2" {
  name = "m2"
  auth = "none"
}
resource "databricks_serving_endpoint" "ep2" {
  name              = "ep2"
  serving_endpoint_public = true
}

# 27. Overprivileged instance profile
resource "databricks_cluster" "ip_cluster" {
  cluster_name        = "etl"
  instance_profile_arn = "arn:aws:iam::123456789012:instance-profile/DatabricksAdminRole"
}
