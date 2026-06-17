# INSECURE FIXTURE — Snowflake Terraform with hardcoded connection creds.

provider "snowflake" {
  snowflake_account = "xy12345.us-east-1"
  account  = "xy12345.snowflakecomputing.com"
  username = "TF_ADMIN"
  password = "PlaintextPass123"
  role     = "ACCOUNTADMIN"
}

resource "snowflake_user" "ci" {
  name     = "ci_user"
  password = "AnotherHardcoded!1"
}

# snowflake service password embedded in code
# snowflake password = "rotateme99"
