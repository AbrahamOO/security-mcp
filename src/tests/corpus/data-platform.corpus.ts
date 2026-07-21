import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "DATABRICKS_HARDCODED_TOKEN",
    check: "data-platform",
    positive: {
      file: "databricks/config.py",
      content: `DATABRICKS_HOST = "https://my-workspace.cloud.databricks.com"\nDATABRICKS_TOKEN = "dapi1234567890abcdef1234567890ab"\n`
    },
    negative: {
      file: "databricks/config.py",
      content: `import os\n\nDATABRICKS_HOST = os.environ["DATABRICKS_HOST"]\nDATABRICKS_TOKEN = os.environ["DATABRICKS_TOKEN"]\n`
    },
    note: "Negative sources the token from the environment at runtime, exactly what requiredActions recommends, instead of a literal dapi… value."
  },
  {
    ruleId: "DATABRICKS_WEAK_CLUSTER_ISOLATION",
    check: "data-platform",
    positive: {
      file: "databricks/clusters.tf",
      content: `resource "databricks_cluster" "adhoc" {\n  cluster_name       = "adhoc-cluster"\n  spark_version      = "13.3.x-scala2.12"\n  node_type_id       = "i3.xlarge"\n  data_security_mode = "NONE"\n}\n`
    },
    negative: {
      file: "databricks/clusters.tf",
      content: `resource "databricks_cluster" "adhoc" {\n  cluster_name       = "adhoc-cluster"\n  spark_version      = "13.3.x-scala2.12"\n  node_type_id       = "i3.xlarge"\n  data_security_mode = "USER_ISOLATION"\n}\n`
    },
    note: "Negative uses USER_ISOLATION, the exact mode requiredActions calls for, instead of NONE/LEGACY_*."
  },
  {
    ruleId: "DATABRICKS_PUBLIC_NETWORK",
    check: "data-platform",
    positive: {
      file: "databricks/workspace.tf",
      content: `resource "databricks_mws_workspaces" "this" {\n  workspace_name      = "prod"\n  enable_no_public_ip = false\n}\n`
    },
    negative: {
      file: "databricks/workspace.tf",
      content: `resource "databricks_mws_workspaces" "this" {\n  workspace_name      = "prod"\n  enable_no_public_ip = true\n}\n\nresource "databricks_ip_access_list" "corp" {\n  label        = "corp-cidrs"\n  list_type    = "ALLOW"\n  ip_addresses = ["10.0.0.0/8"]\n  enabled      = true\n}\n`
    },
    note: "Negative sets enable_no_public_ip = true AND attaches an enabled IP access list, matching both requiredActions bullets, not just a bare flag flip."
  },
  {
    ruleId: "DATABRICKS_TOKEN_NO_EXPIRY",
    check: "data-platform",
    positive: {
      file: "databricks/tokens.tf",
      content: `resource "databricks_token" "ci_pipeline" {\n  comment           = "ci pipeline token"\n  lifetime_seconds  = -1\n}\n`
    },
    negative: {
      file: "databricks/tokens.tf",
      content: `resource "databricks_token" "ci_pipeline" {\n  comment           = "ci pipeline token"\n  lifetime_seconds  = 3600\n}\n`
    },
    note: "Negative sets lifetime_seconds = 3600 (<= the 1h ceiling requiredActions asks for) instead of -1/0/unset; the resource+braces are split across lines so the no-lifetime-at-all alternative (which needs both on one line) can't accidentally fire either."
  },
  {
    ruleId: "DATABRICKS_UC_BROAD_GRANT",
    check: "data-platform",
    positive: {
      file: "databricks/grants.sql",
      content: `GRANT ALL PRIVILEGES ON CATALOG main TO account users;\n`
    },
    negative: {
      file: "databricks/grants.sql",
      content: `GRANT USE CATALOG, USE SCHEMA, SELECT ON CATALOG main TO \`data-analysts\`;\n`
    },
    note: "Negative grants least-privilege verbs (USE CATALOG/USE SCHEMA/SELECT) to a named functional group instead of ALL PRIVILEGES/MANAGE/MODIFY to account users — the precise fix requiredActions describes."
  },
  {
    ruleId: "DATABRICKS_EXTERNAL_LOCATION_BROAD",
    check: "data-platform",
    positive: {
      file: "databricks/external_location.tf",
      content: `resource "databricks_external_location" "raw_data" {\n  name            = "raw-data"\n  url             = "s3://data-lake-bucket/*"\n  credential_name = "raw_data_cred"\n  skip_validation = true\n}\n`
    },
    negative: {
      file: "databricks/external_location.tf",
      content: `resource "databricks_external_location" "raw_data" {\n  name            = "raw-data"\n  url             = "s3://data-lake-bucket/raw/"\n  credential_name = "raw_data_prod_cred"\n  skip_validation = false\n}\n`
    },
    note: "Negative scopes the URL to an exact prefix (no wildcard) and validates the credential (skip_validation = false), removing both triggering conditions."
  },
  {
    ruleId: "DATABRICKS_MODEL_SERVING_PUBLIC",
    check: "data-platform",
    positive: {
      file: "databricks/model_serving.tf",
      content: `resource "databricks_model_serving" "fraud_model" {\n  name = "fraud-model"\n  config {\n    served_models {\n      model_name    = "fraud_model"\n      workload_size = "Small"\n    }\n  }\n  access_control = "none"\n}\n`
    },
    negative: {
      file: "databricks/model_serving.tf",
      content: `resource "databricks_model_serving" "fraud_model" {\n  name = "fraud-model"\n  config {\n    served_models {\n      model_name    = "fraud_model"\n      workload_size = "Small"\n    }\n  }\n}\n\nresource "databricks_permissions" "fraud_model_perms" {\n  serving_endpoint_id = databricks_model_serving.fraud_model.serving_endpoint_id\n  access_control {\n    group_name       = "ml-fraud-team"\n    permission_level = "CAN_QUERY"\n  }\n}\n`
    },
    note: "Negative removes access_control = \"none\" and instead grants CAN_QUERY to a named group via a separate databricks_permissions resource, matching requiredActions."
  },
  {
    ruleId: "DATABRICKS_INSTANCE_PROFILE_OVERPRIVILEGED",
    check: "data-platform",
    positive: {
      file: "databricks/instance_profile.tf",
      content: `resource "databricks_cluster" "etl" {\n  cluster_name = "etl-cluster"\n  aws_attributes {\n    instance_profile_arn = "arn:aws:iam::123456789012:instance-profile/data-admin-profile"\n  }\n}\n`
    },
    negative: {
      file: "databricks/instance_profile.tf",
      content: `resource "databricks_cluster" "etl" {\n  cluster_name = "etl-cluster"\n  aws_attributes {\n    instance_profile_arn = "arn:aws:iam::123456789012:instance-profile/etl-readonly-s3-profile"\n  }\n}\n`
    },
    note: "Negative uses a scoped, purpose-named instance profile (no admin/PowerUser/FullAccess/wildcard substring) as requiredActions asks."
  },
  {
    ruleId: "DATABRICKS_GIT_CREDENTIAL_INLINE_PAT",
    check: "data-platform",
    positive: {
      file: "databricks/git_credential.tf",
      content: `resource "databricks_git_credential" "ci" {\n  git_provider           = "gitHub"\n  personal_access_token  = "ghp_1234567890abcdef1234567890abcdef1234"\n}\n`
    },
    negative: {
      file: "databricks/git_credential.tf",
      content: `resource "databricks_git_credential" "ci" {\n  git_provider           = "gitHub"\n  personal_access_token  = var.github_pat\n}\n`
    },
    note: "Negative sources the PAT from a Terraform variable (var.github_pat) instead of an inline ghp_/glpat-/dapi literal, per requiredActions."
  },
  {
    ruleId: "DATABRICKS_AUDIT_LOGGING_DISABLED",
    check: "data-platform",
    positive: {
      file: "databricks/audit_logging.tf",
      content: `resource "databricks_mws_log_delivery" "audit" {\n  log_type = "AUDIT_LOGS"\n  status   = "DISABLED"\n}\n`
    },
    negative: {
      file: "databricks/audit_logging.tf",
      content: `resource "databricks_mws_log_delivery" "audit" {\n  log_type = "AUDIT_LOGS"\n  status   = "ENABLED"\n}\n`
    },
    note: "Negative sets status = \"ENABLED\", the direct fix requiredActions describes (enable databricks_mws_log_delivery)."
  },
  {
    ruleId: "DATABRICKS_NO_CLUSTER_POLICY",
    check: "data-platform",
    positive: {
      file: "databricks/clusters_no_policy.tf",
      content: `resource "databricks_cluster" "adhoc" {\n  cluster_name            = "adhoc-cluster"\n  spark_version           = "13.3.x-scala2.12"\n  node_type_id            = "i3.xlarge"\n  autotermination_minutes = 20\n}\n`
    },
    negative: {
      file: "databricks/clusters_no_policy.tf",
      content: `resource "databricks_cluster_policy" "standard" {\n  name       = "standard-cluster-policy"\n  definition = jsonencode({\n    "spark_conf.spark.databricks.cluster.profile" = { type = "fixed", value = "singleNode" }\n  })\n}\n\nresource "databricks_cluster" "adhoc" {\n  cluster_name  = "adhoc-cluster"\n  spark_version = "13.3.x-scala2.12"\n  node_type_id  = "i3.xlarge"\n  policy_id     = databricks_cluster_policy.standard.id\n}\n`
    },
    note: "Negative defines a databricks_cluster_policy and references it via policy_id on the cluster, exactly as requiredActions prescribes; the rule only fires when a cluster/job exists with no policy anywhere in scope."
  },
  {
    ruleId: "DATABRICKS_LEGACY_HIVE_METASTORE",
    check: "data-platform",
    positive: {
      file: "databricks/legacy_metastore_notebook.py",
      content: `# Databricks notebook source\ndf.write.saveAsTable("hive_metastore.sales.transactions")\nspark.sql("SELECT * FROM hive_metastore.sales.transactions").show()\n`
    },
    negative: {
      file: "databricks/legacy_metastore_notebook.py",
      content: `# Databricks notebook source\ndf.write.saveAsTable("main.sales.transactions")\nspark.sql("SELECT * FROM main.sales.transactions").show()\n`
    },
    note: "Negative addresses tables via the Unity Catalog three-level namespace (main.sales.transactions) with no hive_metastore reference at all, matching the migrate-off-hive_metastore remediation."
  },
  {
    ruleId: "SNOWFLAKE_OVERPRIVILEGED_GRANT",
    check: "data-platform",
    positive: {
      file: "snowflake/grants.sql",
      content: `GRANT ROLE ACCOUNTADMIN TO USER svc_etl;\n`
    },
    negative: {
      file: "snowflake/grants.sql",
      content: `GRANT ROLE ETL_LOAD_ROLE TO USER svc_etl;\n`
    },
    note: "Negative grants a custom least-privilege functional role instead of ACCOUNTADMIN/SECURITYADMIN/SYSADMIN, and never targets PUBLIC, matching requiredActions."
  },
  {
    ruleId: "SNOWFLAKE_HARDCODED_USER_PASSWORD",
    check: "data-platform",
    positive: {
      file: "snowflake/users.sql",
      content: `CREATE USER svc_reporting\n  PASSWORD = 'SuperSecret123!'\n  MUST_CHANGE_PASSWORD = FALSE;\n`
    },
    negative: {
      file: "snowflake/users.sql",
      content: `CREATE USER svc_reporting\n  RSA_PUBLIC_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...'\n  MUST_CHANGE_PASSWORD = TRUE;\n`
    },
    note: "Negative uses RSA key-pair auth (no PASSWORD literal at all) and MUST_CHANGE_PASSWORD = TRUE, precisely what requiredActions recommends."
  },
  {
    ruleId: "SNOWFLAKE_NETWORK_POLICY_OPEN",
    check: "data-platform",
    positive: {
      file: "snowflake/network_policy.sql",
      content: `CREATE NETWORK POLICY corp_policy ALLOWED_IP_LIST = ('0.0.0.0/0');\n`
    },
    negative: {
      file: "snowflake/network_policy.sql",
      content: `CREATE NETWORK POLICY corp_policy ALLOWED_IP_LIST = ('203.0.113.0/24', '198.51.100.10');\n`
    },
    note: "Negative restricts ALLOWED_IP_LIST to explicit corporate CIDRs instead of 0.0.0.0/0, '*', or 0.0.0.0, per requiredActions."
  },
  {
    ruleId: "SNOWFLAKE_PII_NO_MASKING_POLICY",
    check: "data-platform",
    positive: {
      file: "snowflake/customers_pii.sql",
      content: `CREATE TABLE customers (\n  customer_id NUMBER,\n  ssn VARCHAR(11),\n  email VARCHAR(255),\n  created_at TIMESTAMP\n);\n`
    },
    negative: {
      file: "snowflake/customers_pii.sql",
      content: `CREATE MASKING POLICY ssn_mask AS (val STRING) RETURNS STRING ->\n  CASE WHEN CURRENT_ROLE() IN ('PII_VIEWER') THEN val ELSE '***-**-****' END;\n\nCREATE TABLE customers (\n  customer_id NUMBER,\n  ssn VARCHAR(11) MASKING POLICY ssn_mask,\n  email VARCHAR(255) MASKING POLICY ssn_mask,\n  created_at TIMESTAMP\n);\n`
    },
    note: "Negative defines and attaches an actual MASKING POLICY to the PII columns, which suppresses the heuristic (it only fires when PII-shaped columns exist with zero masking/row-access policy anywhere in scope)."
  },
  {
    ruleId: "SNOWFLAKE_DYNAMIC_SQL_CONCAT",
    check: "data-platform",
    positive: {
      file: "snowflake/dynamic_sql_proc.sql",
      content: `CREATE OR REPLACE PROCEDURE update_status(TABLE_NAME STRING, USER_INPUT STRING)\nRETURNS STRING\nLANGUAGE JAVASCRIPT\nEXECUTE AS OWNER\nAS\n$$\n  var stmt = snowflake.createStatement({sqlText: "UPDATE accounts SET status = 1 WHERE user_id = " + USER_INPUT});\n  stmt.execute();\n  return "OK";\n$$;\n`
    },
    negative: {
      file: "snowflake/dynamic_sql_proc.sql",
      content: `CREATE OR REPLACE PROCEDURE update_status(TABLE_NAME STRING, USER_INPUT STRING)\nRETURNS STRING\nLANGUAGE JAVASCRIPT\nEXECUTE AS CALLER\nAS\n$$\n  var stmt = snowflake.createStatement({sqlText: "UPDATE accounts SET status = 1 WHERE user_id = ?", binds: [USER_INPUT]});\n  stmt.execute();\n  return "OK";\n$$;\n`
    },
    note: "Negative uses a bind placeholder (?) with a binds: [...] array instead of string concatenation with '+', and runs EXECUTE AS CALLER — both explicitly recommended by requiredActions."
  },
  {
    ruleId: "DATAPLATFORM_NOTEBOOK_SQL_INJECTION",
    check: "data-platform",
    positive: {
      file: "databricks/notebook_sql_injection.py",
      content: `# Databricks notebook source\nresult = spark.sql(f"SELECT * FROM {dbutils.widgets.get('table_name')}")\ndisplay(result)\n`
    },
    negative: {
      file: "databricks/notebook_sql_injection.py",
      content: `# Databricks notebook source\nALLOWED_TABLES = {"sales", "orders", "customers"}\ntable_name = dbutils.widgets.get("table_name")\nif table_name not in ALLOWED_TABLES:\n    raise ValueError("Unknown table")\nresult = spark.sql(f"SELECT * FROM {table_name}")\ndisplay(result)\n`
    },
    note: "Negative validates the widget value against an explicit allowlist before using it as a table identifier, instead of interpolating dbutils.widgets.get(...) directly into the SQL f-string — the identifier-allowlisting fix requiredActions calls for."
  },
  {
    ruleId: "SNOWFLAKE_SHARE_PARAMETERIZED_ACCOUNT",
    check: "data-platform",
    positive: {
      file: "snowflake/share_accounts.sql",
      content: `ALTER SHARE sales_share ADD ACCOUNTS = \${partner_account_locator};\n`
    },
    negative: {
      file: "snowflake/share_accounts.sql",
      content: `ALTER SHARE sales_share ADD ACCOUNTS = ('ORGABC.PARTNER_PROD_ACCT');\n`
    },
    note: "Negative pins an explicit, named account locator instead of a template variable (${...}), matching requiredActions."
  },
  {
    ruleId: "SNOWFLAKE_INTEGRATION_NO_NETWORK_POLICY",
    check: "data-platform",
    positive: {
      file: "snowflake/integrations.sql",
      content: `CREATE SECURITY INTEGRATION ext_saml TYPE = SAML2 ENABLED = TRUE SAML2_ISSUER = 'https://idp.example.com';\n`
    },
    negative: {
      file: "snowflake/integrations.sql",
      content: `CREATE SECURITY INTEGRATION ext_saml TYPE = SAML2 ENABLED = TRUE NETWORK_POLICY = corp_ip_policy SAML2_ISSUER = 'https://idp.example.com';\n`
    },
    note: "Negative attaches NETWORK_POLICY = corp_ip_policy to the same integration statement, exactly what requiredActions asks for."
  }
];
