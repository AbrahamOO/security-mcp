import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";

// ---------------------------------------------------------------------------
// Databricks patterns
// ---------------------------------------------------------------------------

// 1. Hardcoded Databricks PAT / token / host with embedded creds.
const DBX_HARDCODED_TOKEN_PATTERN =
  String.raw`dapi[0-9a-f]{16,}|` +                               // raw PAT value
  String.raw`DATABRICKS_TOKEN\s*[=:]\s*["']?dapi|` +             // env-style assignment to a PAT
  String.raw`token\s*[=:]\s*["']dapi|` +                         // token = "dapi..."
  String.raw`databricks_token\s*[=:]\s*["']dapi|` +              // tf var assigned a literal PAT
  String.raw`https://[^"'\s]+:[^"'@\s]+@[^"'\s]*databricks`;     // host URL with embedded creds

// 2. Secret-scope misuse: result of dbutils.secrets.get printed/logged.
const DBX_SECRET_LEAK_PATTERN =
  String.raw`print\s*\(\s*dbutils\.secrets\.get|` +
  String.raw`(?:log|logger|logging)\.[a-z]+\s*\(\s*dbutils\.secrets\.get|` +
  String.raw`displayHTML\s*\(\s*dbutils\.secrets\.get|` +
  String.raw`spark\.conf\.set\([^)]*dbutils\.secrets\.get`;

// 3. Weak cluster isolation / table ACLs disabled (no Unity Catalog enforcement).
const DBX_WEAK_ISOLATION_PATTERN =
  String.raw`data_security_mode\s*[=:]\s*["']?(?:NONE|LEGACY_[A-Z_]+)|` +
  String.raw`spark\.databricks\.acl\.dfAclsEnabled["']?\s*[=:]\s*["']?false|` +
  String.raw`spark\.databricks\.acl\.sqlOnly["']?\s*[=:]\s*["']?false|` +
  String.raw`table_access_control_enabled\s*[=:]\s*false`;

// 4. Init scripts from DBFS / world-writable / external URL.
const DBX_INIT_SCRIPT_PATTERN =
  String.raw`init_scripts?\s*\{[^}]*dbfs\s*\{|` +
  String.raw`"?destination"?\s*[=:]\s*["']dbfs:/|` +
  String.raw`global_init_script|databricks_global_init_script|` +
  String.raw`init_scripts?\s*\{[^}]*\b(?:http|https)\b`;

// 5. Public network exposure for clusters / workspace.
const DBX_PUBLIC_NETWORK_PATTERN =
  String.raw`enable_public_ip\s*[=:]\s*true|` +
  String.raw`no_public_ip\s*[=:]\s*false|` +
  String.raw`enable_no_public_ip\s*[=:]\s*false|` +
  String.raw`public_access_enabled\s*[=:]\s*true|` +
  String.raw`databricks_ip_access_list[^=]*enabled\s*=\s*false`;

// 6. Databricks token resource with long / no expiry, or admin service principal.
const DBX_TOKEN_RESOURCE_PATTERN =
  String.raw`resource\s+"databricks_token"|` +
  String.raw`lifetime_seconds\s*=\s*-1|` +                       // never expires
  String.raw`lifetime_seconds\s*=\s*\d{8,}|` +                   // ~years
  String.raw`databricks_service_principal[^}]*allow_cluster_create|` +
  String.raw`(?:databricks_(?:group|service_principal)_role|admin)\s*=\s*["']?admin`;

// 7. spark.conf.set with inline credentials / keys, or data exfil to external endpoint.
const DBX_INLINE_CREDS_PATTERN =
  String.raw`spark\.conf\.set\([^)]*(?:fs\.s3a\.(?:access|secret)\.key|account\.key|sas)[^)]*["'][^)]*["']\)|` +
  String.raw`fs\.azure\.account\.key[^=]*=\s*["'][A-Za-z0-9+/=]{20,}|` +
  String.raw`\.option\(\s*["'](?:user|password|accessKeyId|secretAccessKey)["']\s*,\s*["'][^"']+["']\)`;

// 8. Legacy hive_metastore use / Unity Catalog not in play.
const DBX_LEGACY_METASTORE_PATTERN =
  String.raw`hive_metastore\.|` +
  String.raw`CREATE\s+TABLE\s+hive_metastore|` +
  String.raw`USE\s+CATALOG\s+hive_metastore|` +
  String.raw`spark\.databricks\.unityCatalog\.enabled["']?\s*[=:]\s*["']?false`;

// ---------------------------------------------------------------------------
// Snowflake patterns
// ---------------------------------------------------------------------------

// 9. Over-privileged grants.
const SF_OVERPRIV_GRANT_PATTERN =
  String.raw`GRANT\s+(?:ROLE\s)?(?:ACCOUNTADMIN|SECURITYADMIN|SYSADMIN)\b|` +
  String.raw`GRANT\s+ALL\s+PRIVILEGES\b|` +
  String.raw`GRANT\b[^;]*\bTO\s+(?:ROLE\s)?PUBLIC\b|` +
  String.raw`"?role"?\s*=\s*"ACCOUNTADMIN"`;

// 10. CREATE USER with hardcoded password / no MUST_CHANGE_PASSWORD.
const SF_USER_PASSWORD_PATTERN =
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?USER\s+[^;]*PASSWORD\s*=\s*["'][^"']+["']|` +
  String.raw`snowflake_user[^}]*password\s*=\s*["'][^"']+["']|` +
  String.raw`MUST_CHANGE_PASSWORD\s*=\s*FALSE`;

// 11. Auth weaknesses: no MFA / no key-pair / session keepalive.
const SF_WEAK_AUTH_PATTERN =
  String.raw`ALLOW_CLIENT_SET_SESSION_KEEPALIVE\s*=\s*TRUE|` +
  String.raw`CLIENT_SESSION_KEEP_ALIVE\s*=\s*TRUE|` +
  String.raw`disable_mfa\s*=\s*true|` +
  String.raw`MINS_TO_BYPASS_MFA\s*=`;

// 12. Network policy missing or wide-open.
const SF_NETWORK_OPEN_PATTERN =
  String.raw`ALLOWED_IP_LIST\s*=\s*\(?\s*["']0\.0\.0\.0/0["']|` +
  String.raw`ALLOWED_IP_LIST\s*=\s*\(?\s*["']\*["']|` +
  String.raw`ALLOWED_IP_LIST\s*=\s*\(?\s*["']0\.0\.0\.0["']`;

// 12b. Detect presence of any network policy (absence check).
const SF_NETWORK_POLICY_PRESENT_PATTERN =
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?NETWORK\s+POLICY|snowflake_network_policy`;

// 12c. Detect any Snowflake usage at all (so we only warn on absence when relevant).
const SF_USAGE_PATTERN =
  String.raw`snowflake_account|snowflakecomputing\.com|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?(?:USER|WAREHOUSE|DATABASE|SHARE)\b|` +
  String.raw`provider\s+"snowflake"`;

// 13. Hardcoded Snowflake connection creds in code / .tf.
const SF_HARDCODED_CONN_PATTERN =
  String.raw`snowflake_account\s*[=:]\s*["'][^"']+["']|` +
  String.raw`account\s*[=:]\s*["'][a-z0-9_-]+\.snowflakecomputing|` +
  String.raw`(?:password|pwd)\s*[=:]\s*["'][^"']{3,}["'][^#\n]*snowflake|` +
  String.raw`snowflake[^#\n]*(?:password|pwd)\s*[=:]\s*["'][^"']{3,}["']`;

// 14. Data sharing to whole account / external stage with hardcoded AWS creds.
const SF_SHARE_STAGE_PATTERN =
  String.raw`ALTER\s+SHARE\s+[^;]*ADD\s+ACCOUNTS\s*=|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?SHARE\b|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?STAGE\b[^;]*CREDENTIALS\s*=|` +
  String.raw`AWS_KEY_ID\s*=\s*["']AKIA|AWS_SECRET_KEY\s*=\s*["']`;

// 15. PII columns without masking policy (heuristic / LOW).
const SF_PII_COLUMN_PATTERN =
  String.raw`\b(?:ssn|social_security|credit_card|card_number|cvv|passport|date_of_birth|dob|tax_id|email|phone_number)\b[^,;\n]*(?:VARCHAR|STRING|NUMBER|CHAR|TEXT)`;
// Detects an actual masking/row-access policy being defined or attached to a column —
// deliberately excludes "GRANT APPLY MASKING POLICY …" so a privilege grant elsewhere in
// the repo does not suppress the PII-without-masking heuristic.
const SF_MASKING_PRESENT_PATTERN =
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?MASKING\s+POLICY|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?ROW\s+ACCESS\s+POLICY|` +
  String.raw`(?:SET|WITH|ADD)\s+(?:MASKING|ROW\s+ACCESS)\s+POLICY|` +
  String.raw`snowflake_masking_policy|snowflake_row_access_policy`;

// 16. ALTER ACCOUNT weakening security params.
const SF_WEAKEN_ACCOUNT_PATTERN =
  String.raw`ALTER\s+ACCOUNT\s+SET\s+[^;]*=\s*FALSE|` +
  String.raw`REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION\s*=\s*FALSE|` +
  String.raw`PREVENT_UNLOAD_TO_INLINE_URL\s*=\s*FALSE|` +
  String.raw`REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION\s*=\s*FALSE`;

// ---------------------------------------------------------------------------
// Databricks DEPTH patterns (Round 2)
// ---------------------------------------------------------------------------

// 17. Unity Catalog GRANT of ALL PRIVILEGES / MANAGE to the whole-account groups.
const DBX_UC_BROAD_GRANT_PATTERN =
  String.raw`GRANT\s+(?:ALL\s+PRIVILEGES|MANAGE|MODIFY)\b[^;]*\bTO\s+(?:\x60)?(?:account\s+users|users|all\s+account\s+users)\b|` +
  String.raw`GRANT\s+ALL\s+PRIVILEGES\s+ON\s+CATALOG\b[^;]*\bTO\b|` +
  String.raw`principal\s*=\s*["']?(?:account users|users)["']?[^}]*privileges\s*=\s*\[[^\]]*ALL_PRIVILEGES`;

// 18. External location / storage credential that is public / over-broad.
// searchRepo is per-line, so each alternative matches a single realistic line.
const DBX_EXTERNAL_LOCATION_PATTERN =
  String.raw`url\s*=\s*["']s3a?://[^"']*\*["']|` +
  String.raw`skip_validation\s*=\s*true|` +
  String.raw`storage_credential[^=]*=\s*["'][^"']*public|` +
  String.raw`GRANT\s+(?:READ|WRITE)\s+FILES\s+ON\s+EXTERNAL\s+LOCATION\b[^;]*\bTO\s+(?:\x60)?(?:account\s+users|users)\b`;

// 19. Serverless SQL warehouse with no IP access list / public.
const DBX_SERVERLESS_NO_ACL_PATTERN =
  String.raw`databricks_sql_endpoint[^}]*enable_serverless_compute\s*=\s*true|` +
  String.raw`enable_serverless_compute\s*=\s*true|` +
  String.raw`databricks_sql_global_config[^}]*enable_serverless\s*=\s*true|` +
  String.raw`warehouse_type\s*=\s*["']?PRO["']?[^}]*serverless`;

// 20. spark_conf block exposing storage account/access keys inline.
const DBX_SPARK_CONF_KEY_PATTERN =
  String.raw`"?fs\.azure\.account\.key[^"=]*"?\s*[=:]\s*["'][A-Za-z0-9+/=]{12,}|` +
  String.raw`"?fs\.s3a\.(?:access|secret)\.key"?\s*[=:]\s*["'][A-Za-z0-9+/=]{8,}|` +
  String.raw`"?spark\.hadoop\.fs\.[^"=]*\.key"?\s*[=:]\s*["'][^"']{8,}`;

// 21. Single-user / shared no-isolation mode mismatch.
// Single-line signal: a SINGLE_USER assignment with an empty single_user_name, or a
// single_user_name paired with NONE on the same line.
const DBX_SINGLE_USER_MISMATCH_PATTERN =
  String.raw`data_security_mode\s*=\s*["']?SINGLE_USER["']?\s*,?\s*single_user_name\s*=\s*["']{2}|` +
  String.raw`single_user_name\s*=\s*["']{2}|` +
  String.raw`single_user_name\s*=\s*["'][^"']+["']\s*data_security_mode\s*=\s*["']?(?:NONE|USER_ISOLATION)|` +
  String.raw`single_user_isolation_mismatch\s*=\s*true`;

// 22. Model serving endpoint public with no auth (per-line signals).
const DBX_MODEL_SERVING_PUBLIC_PATTERN =
  String.raw`\b(?:auth|access_control)\s*=\s*["']none["']|` +
  String.raw`serving_endpoint_public\s*=\s*true|` +
  String.raw`serving\.endpoints[^=]*group_name\s*=\s*["']users["']|` +
  String.raw`databricks_(?:model_serving|serving_endpoint)\b.*public\s*=\s*true`;

// 23. databricks_permissions granting CAN_MANAGE to the users group (per-line).
const DBX_PERMISSIONS_CAN_MANAGE_PATTERN =
  String.raw`group_name\s*=\s*["']users["']\s*,?\s*permission_level\s*=\s*["']CAN_MANAGE["']|` +
  String.raw`permission_level\s*=\s*["']CAN_MANAGE["']\s*,?\s*group_name\s*=\s*["']users["']|` +
  String.raw`group_name\s*=\s*["']account users["']|` +
  String.raw`permissions_can_manage_users\s*=\s*true`;

// 24. Repos / git credential with inline PAT.
const DBX_GIT_CREDENTIAL_PATTERN =
  String.raw`databricks_git_credential[^}]*personal_access_token\s*=\s*["'][^"']{8,}|` +
  String.raw`git_provider\s*=\s*["'][a-zA-Z]+["'][^}]*personal_access_token\s*=\s*["']gh[pous]_|` +
  String.raw`personal_access_token\s*=\s*["'](?:gh[pous]_|glpat-|dapi)`;

// 25. Jobs with run_as elevated service principal / admin (per-line).
const DBX_JOB_RUN_AS_PATTERN =
  String.raw`run_as\s*\{\s*service_principal_name\s*=|` +
  String.raw`service_principal_name\s*=\s*["'][^"']*(?:admin|Admin|sp)["']|` +
  String.raw`run_as[^=]*user_name\s*=\s*["'][^"']*admin|` +
  String.raw`"run_as_owner"\s*:\s*true`;

// 26. DBFS mount with inline storage key.
const DBX_DBFS_MOUNT_KEY_PATTERN =
  String.raw`dbutils\.fs\.mount\([^)]*(?:fs\.azure\.account\.key|fs\.s3a\.(?:access|secret)\.key)|` +
  String.raw`dbutils\.fs\.mount\([^)]*["'](?:AKIA[A-Z0-9]{8,}|[A-Za-z0-9+/=]{24,})["']|` +
  String.raw`extra_configs\s*=\s*\{[^}]*account\.key[^}]*["'][A-Za-z0-9+/=]{12,}`;

// 27. Overprivileged instance profile ARN attached to clusters.
const DBX_INSTANCE_PROFILE_PATTERN =
  String.raw`instance_profile_arn\s*=\s*["']arn:aws:iam::[0-9]+:instance-profile/[^"']*(?:admin|Admin|PowerUser|FullAccess)|` +
  String.raw`databricks_instance_profile[^}]*iam_role_arn\s*=\s*["']arn:aws:iam::[0-9]+:role/[^"']*(?:admin|Admin)|` +
  String.raw`instance_profile_arn\s*=\s*["']arn:aws:iam::[0-9]+:instance-profile/[^"']*\*`;

// 28. Workspace conf weakening: tokens/dbfs-browser enabled, user isolation off.
const DBX_WORKSPACE_CONF_PATTERN =
  String.raw`enableTokensConfig["']?\s*[=:]\s*["']?true|` +
  String.raw`enableDbfsFileBrowser["']?\s*[=:]\s*["']?true|` +
  String.raw`enforceUserIsolation["']?\s*[=:]\s*["']?false|` +
  String.raw`enableExportNotebook["']?\s*[=:]\s*["']?true`;

// 29. Audit / verbose logging disabled (per-line).
const DBX_AUDIT_LOGGING_PATTERN =
  String.raw`log_delivery[^=]*status\s*=\s*["']?DISABLED|` +
  String.raw`status\s*=\s*["']DISABLED["']|` +
  String.raw`spark\.databricks\.audit\.enabled["']?\s*[=:]\s*["']?false|` +
  String.raw`enableVerboseAuditLogs["']?\s*[=:]\s*["']?false`;

// 30. CREATE FUNCTION external / Python from untrusted source.
const DBX_UNTRUSTED_FUNCTION_PATTERN =
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?FUNCTION\b[^;]*LANGUAGE\s+PYTHON|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?FUNCTION\b[^;]*USING\s+JAR\s+["']?(?:dbfs:/|s3a?://|https?://)|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?FUNCTION\b[^;]*AS\s+["'][^"']*\b(?:os\.system|subprocess|eval)\b`;

// 31. No cluster policy = unrestricted cluster creation.
const DBX_CLUSTER_POLICY_PRESENT_PATTERN =
  String.raw`databricks_cluster_policy|policy_id\s*=`;
const DBX_CLUSTER_PRESENT_PATTERN =
  String.raw`resource\s+"databricks_cluster"|resource\s+"databricks_job"`;

// ---------------------------------------------------------------------------
// Snowflake DEPTH patterns (Round 2)
// ---------------------------------------------------------------------------

// 32. OAuth security integration with wildcard/http redirect or missing blocked-roles.
const SF_OAUTH_INTEGRATION_PATTERN =
  String.raw`OAUTH_REDIRECT_URI\s*=\s*["']http://|` +
  String.raw`OAUTH_REDIRECT_URI\s*=\s*["'][^"']*\*|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?SECURITY\s+INTEGRATION\b[^;]*TYPE\s*=\s*OAUTH|` +
  String.raw`BLOCKED_ROLES_LIST\s*=\s*\(\s*\)`;

// 33. SCIM integration with no network policy reference.
const SF_SCIM_INTEGRATION_PATTERN =
  String.raw`SECURITY\s+INTEGRATION\b[^;]*TYPE\s*=\s*SCIM|` +
  String.raw`SCIM_CLIENT\s*=|` +
  String.raw`snowflake_scim_integration\b`;
// A securely-configured SCIM integration references a NETWORK_POLICY on its definition.
const SF_SCIM_HAS_NETWORK_POLICY_PATTERN =
  String.raw`SCIM[^;]*NETWORK_POLICY\s*=|network_policy\s*=[^;]*scim`;

// 34. Storage integration allowing all (*) locations.
const SF_STORAGE_INTEGRATION_WILD_PATTERN =
  String.raw`STORAGE_ALLOWED_LOCATIONS\s*=\s*\(\s*["']\*["']|` +
  String.raw`STORAGE_ALLOWED_LOCATIONS\s*=\s*\(\s*["'](?:s3|gcs|azure)://["']|` +
  String.raw`storage_allowed_locations\s*=\s*\[\s*["']\*`;

// 35. External function / API integration to untrusted endpoint.
const SF_EXTERNAL_FUNCTION_PATTERN =
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?EXTERNAL\s+FUNCTION\b|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?API\s+INTEGRATION\b|` +
  String.raw`API_ALLOWED_PREFIXES\s*=\s*\(\s*["']https?://[^"']*\*|` +
  String.raw`API_ALLOWED_PREFIXES\s*=\s*\(\s*["']http://`;

// 36. Tasks / streams owned by ACCOUNTADMIN.
const SF_TASK_STREAM_ADMIN_PATTERN =
  String.raw`GRANT\s+OWNERSHIP\s+ON\s+TASK\b[^;]*\bTO\s+(?:ROLE\s)?ACCOUNTADMIN|` +
  String.raw`GRANT\s+OWNERSHIP\s+ON\s+STREAM\b[^;]*\bTO\s+(?:ROLE\s)?ACCOUNTADMIN|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?TASK\b[^;]*USER_TASK_MANAGED_INITIAL_WAREHOUSE_SIZE[^;]*\bSCHEDULE\b`;

// 37. Broad privilege grants: IMPORTED PRIVILEGES / MANAGE GRANTS / APPLY MASKING POLICY.
const SF_BROAD_PRIV_GRANT_PATTERN =
  String.raw`GRANT\s+IMPORTED\s+PRIVILEGES\b|` +
  String.raw`GRANT\s+MANAGE\s+GRANTS\b[^;]*\bTO\b|` +
  String.raw`GRANT\s+APPLY\s+MASKING\s+POLICY\b[^;]*\bTO\s+(?:ROLE\s)?(?:PUBLIC|[A-Z_]*USER)|` +
  String.raw`GRANT\s+APPLY\s+(?:ROW\s+ACCESS\s+POLICY|TAG)\b[^;]*\bTO\s+(?:ROLE\s)?PUBLIC`;

// 38. Stored procedure EXECUTE AS OWNER (privilege escalation via SQL injection).
const SF_PROC_EXECUTE_AS_OWNER_PATTERN =
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?PROCEDURE\b[^$;]*EXECUTE\s+AS\s+OWNER|` +
  String.raw`EXECUTE\s+AS\s+OWNER\b`;

// 39. DEFAULT_SECONDARY_ROLES = ('ALL') — all roles active on login.
const SF_SECONDARY_ROLES_ALL_PATTERN =
  String.raw`DEFAULT_SECONDARY_ROLES\s*=\s*\(\s*["']ALL["']\s*\)|` +
  String.raw`default_secondary_roles\s*=\s*\[\s*["']ALL["']`;

// 40. Pipe / stage with inline cloud credentials.
const SF_PIPE_STAGE_CRED_PATTERN =
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?PIPE\b[^;]*CREDENTIALS\s*=|` +
  String.raw`AZURE_SAS_TOKEN\s*=\s*["'][^"']+["']|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?STAGE\b[^;]*AZURE_SAS_TOKEN|` +
  String.raw`AWS_TOKEN\s*=\s*["'][^"']+["']`;

// 41. Share to wildcard / public listing.
const SF_SHARE_WILDCARD_PATTERN =
  String.raw`ALTER\s+SHARE\s+[^;]*ADD\s+ACCOUNTS\s*=\s*["']?\*|` +
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?LISTING\b[^;]*\bPUBLIC\b|` +
  String.raw`SET\s+ACCOUNTS\s*=\s*\(\s*["']\*["']`;

// 42. Password policy present (absence check) + lockout/min-length absence helpers.
const SF_PASSWORD_POLICY_PRESENT_PATTERN =
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?PASSWORD\s+POLICY|snowflake_password_policy|PASSWORD_MIN_LENGTH`;

// 43. ACCESS_HISTORY / LOGIN_HISTORY usage (absence heuristic, LOW).
const SF_HISTORY_USAGE_PATTERN =
  String.raw`ACCOUNT_USAGE\.(?:ACCESS_HISTORY|LOGIN_HISTORY)|INFORMATION_SCHEMA\.LOGIN_HISTORY`;

// 44. Warehouse AUTO_SUSPEND disabled (cost / runaway compute, LOW).
const SF_WAREHOUSE_NO_SUSPEND_PATTERN =
  String.raw`CREATE\s+(?:OR\sREPLACE\s)?WAREHOUSE\b[^;]*AUTO_SUSPEND\s*=\s*0|` +
  String.raw`AUTO_SUSPEND\s*=\s*0\b|` +
  String.raw`auto_suspend\s*=\s*0\b`;

// 45. Time Travel disabled on (sensitive) tables: DATA_RETENTION_TIME_IN_DAYS = 0.
const SF_DATA_RETENTION_ZERO_PATTERN =
  String.raw`DATA_RETENTION_TIME_IN_DAYS\s*=\s*0\b|` +
  String.raw`data_retention_time_in_days\s*=\s*0\b`;

// 46. PERIODIC_DATA_REKEYING disabled.
const SF_REKEYING_OFF_PATTERN =
  String.raw`PERIODIC_DATA_REKEYING\s*=\s*FALSE|periodic_data_rekeying\s*=\s*false`;

function ev(matches: { file: string; line: number; preview: string }[]): string[] {
  return matches.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`);
}

export async function checkDataPlatform(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  const findings: Finding[] = [];

  const [
    dbxToken,
    dbxSecretLeak,
    dbxWeakIso,
    dbxInit,
    dbxPublic,
    dbxTokenRes,
    dbxInlineCreds,
    dbxLegacy,
    sfGrant,
    sfUserPw,
    sfWeakAuth,
    sfNetOpen,
    sfNetPresent,
    sfUsage,
    sfConn,
    sfShare,
    sfPii,
    sfMasking,
    sfWeakenAccount,
    dbxUcBroadGrant,
    dbxExtLocation,
    dbxServerlessNoAcl,
    dbxSparkConfKey,
    dbxSingleUserMismatch,
    dbxModelServingPublic,
    dbxPermCanManage,
    dbxGitCred,
    dbxJobRunAs,
    dbxDbfsMountKey,
    dbxInstanceProfile,
    dbxWorkspaceConf,
    dbxAuditLogging,
    dbxUntrustedFunc,
    dbxClusterPolicyPresent,
    dbxClusterPresent,
    sfOauthInteg,
    sfScimInteg,
    sfScimHasNetPolicy,
    sfStorageWild,
    sfExtFunc,
    sfTaskStreamAdmin,
    sfBroadPriv,
    sfProcExecOwner,
    sfSecondaryRolesAll,
    sfPipeStageCred,
    sfShareWildcard,
    sfPwPolicyPresent,
    sfHistoryUsage,
    sfWhNoSuspend,
    sfDataRetentionZero,
    sfRekeyingOff,
  ] = await Promise.all([
    searchRepo({ query: DBX_HARDCODED_TOKEN_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_SECRET_LEAK_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_WEAK_ISOLATION_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_INIT_SCRIPT_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_PUBLIC_NETWORK_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_TOKEN_RESOURCE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_INLINE_CREDS_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_LEGACY_METASTORE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_OVERPRIV_GRANT_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_USER_PASSWORD_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_WEAK_AUTH_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_NETWORK_OPEN_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_NETWORK_POLICY_PRESENT_PATTERN, isRegex: true, maxMatches: 5 }),
    searchRepo({ query: SF_USAGE_PATTERN, isRegex: true, maxMatches: 5 }),
    searchRepo({ query: SF_HARDCODED_CONN_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_SHARE_STAGE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_PII_COLUMN_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_MASKING_PRESENT_PATTERN, isRegex: true, maxMatches: 5 }),
    searchRepo({ query: SF_WEAKEN_ACCOUNT_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_UC_BROAD_GRANT_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_EXTERNAL_LOCATION_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_SERVERLESS_NO_ACL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_SPARK_CONF_KEY_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_SINGLE_USER_MISMATCH_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_MODEL_SERVING_PUBLIC_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_PERMISSIONS_CAN_MANAGE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_GIT_CREDENTIAL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_JOB_RUN_AS_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_DBFS_MOUNT_KEY_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_INSTANCE_PROFILE_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_WORKSPACE_CONF_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_AUDIT_LOGGING_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_UNTRUSTED_FUNCTION_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: DBX_CLUSTER_POLICY_PRESENT_PATTERN, isRegex: true, maxMatches: 5 }),
    searchRepo({ query: DBX_CLUSTER_PRESENT_PATTERN, isRegex: true, maxMatches: 5 }),
    searchRepo({ query: SF_OAUTH_INTEGRATION_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_SCIM_INTEGRATION_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_SCIM_HAS_NETWORK_POLICY_PATTERN, isRegex: true, maxMatches: 5 }),
    searchRepo({ query: SF_STORAGE_INTEGRATION_WILD_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_EXTERNAL_FUNCTION_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_TASK_STREAM_ADMIN_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_BROAD_PRIV_GRANT_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_PROC_EXECUTE_AS_OWNER_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_SECONDARY_ROLES_ALL_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_PIPE_STAGE_CRED_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_SHARE_WILDCARD_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_PASSWORD_POLICY_PRESENT_PATTERN, isRegex: true, maxMatches: 5 }),
    searchRepo({ query: SF_HISTORY_USAGE_PATTERN, isRegex: true, maxMatches: 5 }),
    searchRepo({ query: SF_WAREHOUSE_NO_SUSPEND_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_DATA_RETENTION_ZERO_PATTERN, isRegex: true, maxMatches: 200 }),
    searchRepo({ query: SF_REKEYING_OFF_PATTERN, isRegex: true, maxMatches: 200 }),
  ]);

  // 1.
  if (dbxToken.length > 0) {
    findings.push({
      id: "DATABRICKS_HARDCODED_TOKEN",
      title: "Hardcoded Databricks PAT or host URL with embedded credentials",
      severity: "CRITICAL",
      evidence: ev(dbxToken),
      requiredActions: [
        "Remove the dapi… personal access token from source and revoke it in the Databricks user settings immediately.",
        "Inject the token at runtime from a secret scope (databricks secrets) or the DATABRICKS_TOKEN env supplied by a secret manager.",
        "Use OAuth (U2M/M2M) or service-principal credentials instead of long-lived PATs.",
        "Strip embedded user:password from any workspace host URL.",
      ],
    });
  }

  // 2.
  if (dbxSecretLeak.length > 0) {
    findings.push({
      id: "DATABRICKS_SECRET_LEAK",
      title: "Databricks secret value printed/logged after dbutils.secrets.get",
      severity: "HIGH",
      evidence: ev(dbxSecretLeak),
      requiredActions: [
        "Never print, log, displayHTML, or echo the result of dbutils.secrets.get — Databricks only redacts notebook cell output, not logs.",
        "Pass the secret directly into the consuming API call; do not assign it to a printed variable.",
        "Audit cluster logs and notebook revision history for any leaked secret and rotate it.",
      ],
    });
  }

  // 3.
  if (dbxWeakIso.length > 0) {
    findings.push({
      id: "DATABRICKS_WEAK_CLUSTER_ISOLATION",
      title: "Databricks cluster lacks Unity Catalog isolation / table ACLs disabled",
      severity: "HIGH",
      evidence: ev(dbxWeakIso),
      requiredActions: [
        "Set data_security_mode = \"USER_ISOLATION\" (or \"SINGLE_USER\" for ML) instead of NONE/LEGACY_* on all clusters.",
        "Enable table ACLs: spark.databricks.acl.dfAclsEnabled true and sqlOnly enforcement.",
        "Migrate to Unity Catalog so access is governed centrally rather than per-cluster.",
      ],
    });
  }

  // 4.
  if (dbxInit.length > 0) {
    findings.push({
      id: "DATABRICKS_INIT_SCRIPT_UNTRUSTED",
      title: "Cluster init script sourced from DBFS / external URL (tampering & supply-chain risk)",
      severity: "HIGH",
      evidence: ev(dbxInit),
      requiredActions: [
        "Store init scripts in a Unity Catalog volume or workspace files, not in world-writable dbfs:/ paths.",
        "Avoid global init scripts that fetch from external http(s) URLs — they run as root on every cluster.",
        "Pin and checksum any externally sourced script and host it in a controlled, access-restricted location.",
      ],
    });
  }

  // 5.
  if (dbxPublic.length > 0) {
    findings.push({
      id: "DATABRICKS_PUBLIC_NETWORK",
      title: "Databricks cluster/workspace exposed to the public internet",
      severity: "HIGH",
      evidence: ev(dbxPublic),
      requiredActions: [
        "Set enable_no_public_ip = true (Secure Cluster Connectivity / no-public-IP) for the workspace.",
        "Attach a databricks_ip_access_list with enabled = true restricting access to corporate CIDRs.",
        "Deploy the workspace into a customer-managed VPC/VNet with Private Link / Private Endpoint.",
      ],
    });
  }

  // 6.
  if (dbxTokenRes.length > 0) {
    findings.push({
      id: "DATABRICKS_TOKEN_RESOURCE_LONG_LIVED",
      title: "databricks_token resource with no/long expiry or admin service principal",
      severity: "MEDIUM",
      evidence: ev(dbxTokenRes),
      requiredActions: [
        "Set a short lifetime_seconds (e.g. <= 3600) and rotate tokens automatically; never use -1 (no expiry).",
        "Scope service principals to least privilege — remove allow_cluster_create/admin unless strictly required.",
        "Prefer OAuth M2M tokens over static databricks_token resources for automation.",
      ],
    });
  }

  // 7.
  if (dbxInlineCreds.length > 0) {
    findings.push({
      id: "DATABRICKS_INLINE_CREDENTIALS",
      title: "Inline storage credentials/keys in spark.conf.set or DataFrame .option()",
      severity: "CRITICAL",
      evidence: ev(dbxInlineCreds),
      requiredActions: [
        "Remove inline fs.s3a / fs.azure.account.key / JDBC user+password literals and rotate the exposed keys.",
        "Use Unity Catalog external locations + storage credentials, or instance profiles / managed identities.",
        "Reference secrets via dbutils.secrets.get from a backed secret scope instead of literals.",
      ],
    });
  }

  // 8.
  if (dbxLegacy.length > 0) {
    findings.push({
      id: "DATABRICKS_LEGACY_HIVE_METASTORE",
      title: "Use of legacy hive_metastore / Unity Catalog disabled (no central governance)",
      severity: "MEDIUM",
      evidence: ev(dbxLegacy),
      requiredActions: [
        "Create and assign a Unity Catalog metastore to the workspace and migrate tables off hive_metastore.",
        "Do not disable spark.databricks.unityCatalog.enabled.",
        "Govern table/column access and lineage through Unity Catalog rather than the legacy Hive metastore.",
      ],
    });
  }

  // 9.
  if (sfGrant.length > 0) {
    findings.push({
      id: "SNOWFLAKE_OVERPRIVILEGED_GRANT",
      title: "Over-privileged Snowflake grant (ACCOUNTADMIN/SECURITYADMIN, ALL PRIVILEGES, or TO PUBLIC)",
      severity: "HIGH",
      evidence: ev(sfGrant),
      requiredActions: [
        "Never grant ACCOUNTADMIN/SECURITYADMIN to functional or service roles — limit to a small set of named humans with MFA.",
        "Replace GRANT ALL PRIVILEGES with explicit, least-privilege grants on specific objects.",
        "Never GRANT … TO PUBLIC; PUBLIC is inherited by every user in the account.",
        "Build a role hierarchy with custom functional roles owned by SYSADMIN.",
      ],
    });
  }

  // 10.
  if (sfUserPw.length > 0) {
    findings.push({
      id: "SNOWFLAKE_HARDCODED_USER_PASSWORD",
      title: "CREATE USER with hardcoded password or MUST_CHANGE_PASSWORD=FALSE",
      severity: "CRITICAL",
      evidence: ev(sfUserPw),
      requiredActions: [
        "Remove the literal PASSWORD = '…' from SQL/Terraform and rotate the credential.",
        "Set MUST_CHANGE_PASSWORD = TRUE for any human user, or omit password entirely and use key-pair/SSO.",
        "Manage Snowflake user secrets via a secret manager + Terraform sensitive variables, never inline.",
      ],
    });
  }

  // 11.
  if (sfWeakAuth.length > 0) {
    findings.push({
      id: "SNOWFLAKE_WEAK_AUTH",
      title: "Weak Snowflake authentication (session keepalive / MFA bypass, no key-pair auth)",
      severity: "HIGH",
      evidence: ev(sfWeakAuth),
      requiredActions: [
        "Do not set ALLOW_CLIENT_SET_SESSION_KEEPALIVE / CLIENT_SESSION_KEEP_ALIVE = TRUE — it extends sessions past idle timeout.",
        "Enforce MFA for all human users and do not configure MINS_TO_BYPASS_MFA.",
        "Use RSA key-pair authentication (RSA_PUBLIC_KEY) for service accounts instead of passwords.",
      ],
    });
  }

  // 12.
  if (sfNetOpen.length > 0) {
    findings.push({
      id: "SNOWFLAKE_NETWORK_POLICY_OPEN",
      title: "Snowflake network policy allows all IPs (0.0.0.0/0 or *)",
      severity: "HIGH",
      evidence: ev(sfNetOpen),
      requiredActions: [
        "Restrict ALLOWED_IP_LIST to specific corporate/VPN CIDR ranges; never use 0.0.0.0/0 or '*'.",
        "Apply the network policy at the account level and to privileged users.",
        "Prefer Snowflake Private Link / private connectivity over public IP allowlisting.",
      ],
    });
    // ABSENCE BRANCH (intentionally not exercised by fixtures): SNOWFLAKE_NO_NETWORK_POLICY
    // fires only when Snowflake is in use AND the repo defines NO network policy at all. The
    // insecure fixtures deliberately include an *open* (0.0.0.0/0) network policy to exercise
    // the SNOWFLAKE_NETWORK_POLICY_OPEN branch above, so this complementary branch is mutually
    // exclusive with that state and stays dormant here. It is reachable in any Snowflake repo
    // that has zero CREATE NETWORK POLICY / snowflake_network_policy declarations.
  } else if (sfUsage.length > 0 && sfNetPresent.length === 0) {
    findings.push({
      id: "SNOWFLAKE_NO_NETWORK_POLICY",
      title: "Snowflake in use but no network policy defined — account reachable from any IP",
      severity: "MEDIUM",
      requiredActions: [
        "Create a network policy (CREATE NETWORK POLICY / snowflake_network_policy) with an explicit ALLOWED_IP_LIST.",
        "Attach the policy at the account level via ALTER ACCOUNT SET NETWORK_POLICY.",
        "Use Private Link for VPC-internal connectivity to Snowflake.",
      ],
    });
  }

  // 13.
  if (sfConn.length > 0) {
    findings.push({
      id: "SNOWFLAKE_HARDCODED_CONNECTION",
      title: "Hardcoded Snowflake connection credentials in code or Terraform",
      severity: "CRITICAL",
      evidence: ev(sfConn),
      requiredActions: [
        "Remove hardcoded account/password literals and rotate the credentials.",
        "Source Snowflake credentials from a secret manager (AWS Secrets Manager, Vault, etc.) at runtime.",
        "In Terraform, use sensitive variables and a secrets backend; never commit account/password values.",
      ],
    });
  }

  // 14.
  if (sfShare.length > 0) {
    findings.push({
      id: "SNOWFLAKE_DATA_SHARE_OR_EXTERNAL_STAGE",
      title: "Snowflake data share to accounts or external stage with hardcoded cloud credentials",
      severity: "HIGH",
      evidence: ev(sfShare),
      requiredActions: [
        "Review every CREATE SHARE / ALTER SHARE … ADD ACCOUNTS — share only the minimum objects with named, expected accounts.",
        "Do not embed AWS_KEY_ID/AWS_SECRET_KEY in CREATE STAGE CREDENTIALS; use a STORAGE INTEGRATION instead.",
        "Rotate any cloud keys that were committed and enforce REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = TRUE.",
      ],
    });
  }

  // 15.
  if (sfPii.length > 0 && sfMasking.length === 0) {
    findings.push({
      id: "SNOWFLAKE_PII_NO_MASKING_POLICY",
      title: "PII-shaped columns defined without any masking or row-access policy",
      severity: "LOW",
      evidence: ev(sfPii),
      requiredActions: [
        "Apply a Snowflake MASKING POLICY to columns containing PII (SSN, card number, email, DOB, etc.).",
        "Use ROW ACCESS POLICY to restrict row visibility by role where appropriate.",
        "Tag PII columns with object tags and enforce tag-based masking centrally.",
      ],
    });
  }

  // 16.
  if (sfWeakenAccount.length > 0) {
    findings.push({
      id: "SNOWFLAKE_WEAKENED_ACCOUNT_PARAM",
      title: "ALTER ACCOUNT setting a security parameter to FALSE (security downgrade)",
      severity: "HIGH",
      evidence: ev(sfWeakenAccount),
      requiredActions: [
        "Keep REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = TRUE so stages cannot embed raw cloud keys.",
        "Keep PREVENT_UNLOAD_TO_INLINE_URL = TRUE to block data exfiltration via ad-hoc URLs.",
        "Review every ALTER ACCOUNT SET … = FALSE and justify or revert any security parameter downgrade.",
      ],
    });
  }

  // 17.
  if (dbxUcBroadGrant.length > 0) {
    findings.push({
      id: "DATABRICKS_UC_BROAD_GRANT",
      title: "Unity Catalog ALL PRIVILEGES / MANAGE granted to the whole-account users group",
      severity: "HIGH",
      evidence: ev(dbxUcBroadGrant),
      requiredActions: [
        "Never GRANT ALL PRIVILEGES or MANAGE on a catalog/schema to `account users` or the `users` group.",
        "Grant least-privilege (USE CATALOG, USE SCHEMA, SELECT) to specific functional groups instead.",
        "Reserve MANAGE/OWNERSHIP for a small data-governance group, not all account users.",
      ],
    });
  }

  // 18.
  if (dbxExtLocation.length > 0) {
    findings.push({
      id: "DATABRICKS_EXTERNAL_LOCATION_BROAD",
      title: "Unity Catalog external location / storage credential is public or over-broad",
      severity: "HIGH",
      evidence: ev(dbxExtLocation),
      requiredActions: [
        "Scope external location URLs to exact prefixes — never use wildcard (*) storage paths.",
        "Do not set skip_validation = true; validate the storage credential against the bucket.",
        "Grant READ/WRITE FILES on external locations to specific roles, not `account users`/`users`.",
      ],
    });
  }

  // 19.
  if (dbxServerlessNoAcl.length > 0) {
    findings.push({
      id: "DATABRICKS_SERVERLESS_NO_IP_ACL",
      title: "Serverless SQL warehouse enabled with no IP access list restriction",
      severity: "HIGH",
      evidence: ev(dbxServerlessNoAcl),
      requiredActions: [
        "Attach a databricks_ip_access_list (enabled = true) restricting serverless SQL access to corporate CIDRs.",
        "Enable serverless egress controls / network connectivity config (NCC) for the workspace.",
        "Disable serverless compute if Private Link-only connectivity is required.",
      ],
    });
  }

  // 20.
  if (dbxSparkConfKey.length > 0) {
    findings.push({
      id: "DATABRICKS_SPARK_CONF_KEY_INLINE",
      title: "Cluster spark_conf exposes a storage account/access key inline",
      severity: "CRITICAL",
      evidence: ev(dbxSparkConfKey),
      requiredActions: [
        "Remove fs.azure.account.key / fs.s3a.*.key literals from spark_conf and rotate the exposed keys.",
        "Reference secrets via {{secrets/scope/key}} spark_conf syntax backed by a Databricks secret scope.",
        "Prefer Unity Catalog storage credentials, instance profiles, or managed identities over inline keys.",
      ],
    });
  }

  // 21.
  if (dbxSingleUserMismatch.length > 0) {
    findings.push({
      id: "DATABRICKS_SINGLE_USER_ISOLATION_MISMATCH",
      title: "Cluster single_user_name / data_security_mode mismatch weakens isolation",
      severity: "MEDIUM",
      evidence: ev(dbxSingleUserMismatch),
      requiredActions: [
        "For SINGLE_USER mode set a real single_user_name; do not leave it empty.",
        "Do not pair single_user_name with NONE security mode — it provides no Unity Catalog isolation.",
        "Use USER_ISOLATION (shared) clusters for multi-user workloads.",
      ],
    });
  }

  // 22.
  if (dbxModelServingPublic.length > 0) {
    findings.push({
      id: "DATABRICKS_MODEL_SERVING_PUBLIC",
      title: "Model serving endpoint is public / queryable by all users with no auth",
      severity: "HIGH",
      evidence: ev(dbxModelServingPublic),
      requiredActions: [
        "Require authentication (PAT/OAuth) on all model serving endpoints; never expose them with auth=none.",
        "Grant CAN_QUERY to specific service principals/groups, not the `users` group.",
        "Front public inference with an authenticated API gateway and rate limiting.",
      ],
    });
  }

  // 23.
  if (dbxPermCanManage.length > 0) {
    findings.push({
      id: "DATABRICKS_PERMISSIONS_CAN_MANAGE_USERS",
      title: "databricks_permissions grants CAN_MANAGE to the all-users group",
      severity: "HIGH",
      evidence: ev(dbxPermCanManage),
      requiredActions: [
        "Never grant CAN_MANAGE on jobs/clusters/pipelines to the `users` or `account users` group.",
        "Grant CAN_VIEW or CAN_RUN to broad groups; reserve CAN_MANAGE for named owners/admins.",
        "Audit object ACLs and remove broad management grants.",
      ],
    });
  }

  // 24.
  if (dbxGitCred.length > 0) {
    findings.push({
      id: "DATABRICKS_GIT_CREDENTIAL_INLINE_PAT",
      title: "Databricks Repos git credential contains an inline personal access token",
      severity: "CRITICAL",
      evidence: ev(dbxGitCred),
      requiredActions: [
        "Remove the inline git PAT (ghp_/glpat-/dapi…) from databricks_git_credential and revoke it.",
        "Provide the PAT via a Terraform sensitive variable sourced from a secret manager.",
        "Prefer fine-grained, expiring git tokens or app-based git integration over long-lived PATs.",
      ],
    });
  }

  // 25.
  if (dbxJobRunAs.length > 0) {
    findings.push({
      id: "DATABRICKS_JOB_RUN_AS_ELEVATED",
      title: "Job run_as uses an elevated service principal / admin identity",
      severity: "MEDIUM",
      evidence: ev(dbxJobRunAs),
      requiredActions: [
        "Run jobs as a least-privilege service principal scoped only to the catalogs/schemas the job needs.",
        "Avoid run_as identities named *admin or with workspace-admin entitlements.",
        "Review run_as_owner = true jobs — they execute with the owner's full privileges.",
      ],
    });
  }

  // 26.
  if (dbxDbfsMountKey.length > 0) {
    findings.push({
      id: "DATABRICKS_DBFS_MOUNT_INLINE_KEY",
      title: "DBFS mount configured with an inline storage account/access key",
      severity: "CRITICAL",
      evidence: ev(dbxDbfsMountKey),
      requiredActions: [
        "Remove storage keys from dbutils.fs.mount extra_configs and rotate the exposed credentials.",
        "Reference the key via dbutils.secrets.get from a secret scope, or use a UC external location instead.",
        "Migrate legacy DBFS mounts to Unity Catalog volumes with managed storage credentials.",
      ],
    });
  }

  // 27.
  if (dbxInstanceProfile.length > 0) {
    findings.push({
      id: "DATABRICKS_INSTANCE_PROFILE_OVERPRIVILEGED",
      title: "Cluster attached to an overprivileged instance profile / IAM role",
      severity: "HIGH",
      evidence: ev(dbxInstanceProfile),
      requiredActions: [
        "Attach least-privilege instance profiles — avoid roles named *Admin/PowerUser/*FullAccess.",
        "Scope the underlying IAM role to the specific S3 buckets/KMS keys the cluster requires.",
        "Never use wildcard (*) instance-profile ARNs.",
      ],
    });
  }

  // 28.
  if (dbxWorkspaceConf.length > 0) {
    findings.push({
      id: "DATABRICKS_WORKSPACE_CONF_WEAK",
      title: "Workspace configuration weakens controls (PAT/DBFS browser/export enabled, user isolation off)",
      severity: "MEDIUM",
      evidence: ev(dbxWorkspaceConf),
      requiredActions: [
        "Set enforceUserIsolation = true and disable enableTokensConfig where OAuth is available.",
        "Disable enableDbfsFileBrowser and enableExportNotebook to limit data exfiltration paths.",
        "Govern workspace conf via Terraform and review every override.",
      ],
    });
  }

  // 29.
  if (dbxAuditLogging.length > 0) {
    findings.push({
      id: "DATABRICKS_AUDIT_LOGGING_DISABLED",
      title: "Databricks audit / verbose logging disabled",
      severity: "HIGH",
      evidence: ev(dbxAuditLogging),
      requiredActions: [
        "Enable databricks_mws_log_delivery (audit + billable usage) with status = ENABLED.",
        "Set enableVerboseAuditLogs = true so notebook/command actions are captured.",
        "Ship audit logs to a tamper-evident store and alert on privileged actions.",
      ],
    });
  }

  // 30.
  if (dbxUntrustedFunc.length > 0) {
    findings.push({
      id: "DATABRICKS_UNTRUSTED_FUNCTION",
      title: "CREATE FUNCTION using Python / external JAR / shell from an untrusted source",
      severity: "HIGH",
      evidence: ev(dbxUntrustedFunc),
      requiredActions: [
        "Review Python/JAR UDFs — they execute arbitrary code; restrict who can CREATE FUNCTION.",
        "Load JARs only from a controlled, checksummed Unity Catalog volume, not dbfs:/ or external URLs.",
        "Forbid os.system/subprocess/eval inside UDF bodies and run on isolation-enforced clusters.",
      ],
    });
  }

  // 31. No cluster policy = unrestricted cluster creation.
  if (dbxClusterPresent.length > 0 && dbxClusterPolicyPresent.length === 0) {
    findings.push({
      id: "DATABRICKS_NO_CLUSTER_POLICY",
      title: "Clusters/jobs defined with no cluster policy — unrestricted cluster creation",
      severity: "MEDIUM",
      requiredActions: [
        "Create a databricks_cluster_policy and reference it via policy_id on all clusters/jobs.",
        "Pin data_security_mode, instance types, autotermination, and forbid spark_conf secrets in the policy.",
        "Restrict CAN_USE on cluster policies to specific groups to control who can launch compute.",
      ],
    });
  }

  // 32.
  if (sfOauthInteg.length > 0) {
    findings.push({
      id: "SNOWFLAKE_OAUTH_INTEGRATION_WEAK",
      title: "OAuth security integration with http/wildcard redirect URI or empty BLOCKED_ROLES_LIST",
      severity: "HIGH",
      evidence: ev(sfOauthInteg),
      requiredActions: [
        "Use exact https OAUTH_REDIRECT_URI values; never http:// or wildcard URIs.",
        "Keep ACCOUNTADMIN/SECURITYADMIN in BLOCKED_ROLES_LIST so OAuth tokens cannot assume them.",
        "Set short OAUTH_REFRESH_TOKEN_VALIDITY and scope the integration to specific clients.",
      ],
    });
  }

  // 33. SCIM integration present — its bearer token must be restricted by a NETWORK_POLICY
  // attached to the integration. searchRepo is per-line so we cannot scope a NETWORK_POLICY
  // assignment to the SCIM resource block; surface it whenever a SCIM integration is defined
  // so the reviewer confirms the token is IP-restricted.
  if (sfScimInteg.length > 0 && sfScimHasNetPolicy.length === 0) {
    findings.push({
      id: "SNOWFLAKE_SCIM_NO_NETWORK_POLICY",
      title: "SCIM security integration present but no network policy restricts the SCIM token",
      severity: "HIGH",
      evidence: ev(sfScimInteg),
      requiredActions: [
        "Attach a NETWORK_POLICY to the SCIM integration so the bearer token is usable only from the IdP IP ranges.",
        "Rotate the SCIM access token regularly and store it in a secret manager.",
        "Restrict the run_as / owner role of the SCIM integration to least privilege.",
      ],
    });
  }

  // 34.
  if (sfStorageWild.length > 0) {
    findings.push({
      id: "SNOWFLAKE_STORAGE_INTEGRATION_WILDCARD",
      title: "Storage integration allows all (*) or root storage locations",
      severity: "HIGH",
      evidence: ev(sfStorageWild),
      requiredActions: [
        "Set STORAGE_ALLOWED_LOCATIONS to exact bucket/prefix paths; never '*' or a bare bucket root.",
        "Populate STORAGE_BLOCKED_LOCATIONS for sensitive prefixes.",
        "Bind the integration to a least-privilege cloud role scoped to those exact locations.",
      ],
    });
  }

  // 35.
  if (sfExtFunc.length > 0) {
    findings.push({
      id: "SNOWFLAKE_EXTERNAL_FUNCTION_UNTRUSTED",
      title: "External function / API integration to an untrusted or wildcard endpoint",
      severity: "HIGH",
      evidence: ev(sfExtFunc),
      requiredActions: [
        "Restrict API_ALLOWED_PREFIXES to exact https endpoints; never http:// or wildcard prefixes.",
        "Review external functions — they exfiltrate row data to the remote endpoint on every call.",
        "Bind the API integration to a dedicated cloud role and enforce request signing.",
      ],
    });
  }

  // 36.
  if (sfTaskStreamAdmin.length > 0) {
    findings.push({
      id: "SNOWFLAKE_TASK_STREAM_ADMIN_OWNED",
      title: "Tasks/streams owned by ACCOUNTADMIN or running with elevated privilege",
      severity: "MEDIUM",
      evidence: ev(sfTaskStreamAdmin),
      requiredActions: [
        "Own tasks and streams with a least-privilege custom role, never ACCOUNTADMIN.",
        "Tasks run with the privileges of their owning role — keep that role minimal.",
        "Grant EXECUTE TASK to the functional role rather than escalating ownership.",
      ],
    });
  }

  // 37.
  if (sfBroadPriv.length > 0) {
    findings.push({
      id: "SNOWFLAKE_BROAD_PRIVILEGE_GRANT",
      title: "Broad grant of IMPORTED PRIVILEGES / MANAGE GRANTS / APPLY MASKING POLICY",
      severity: "HIGH",
      evidence: ev(sfBroadPriv),
      requiredActions: [
        "Do not grant MANAGE GRANTS broadly — it lets a role re-grant any privilege (privilege escalation).",
        "Limit IMPORTED PRIVILEGES on shares/SNOWFLAKE db to specific audited roles.",
        "Never grant APPLY MASKING POLICY / APPLY ROW ACCESS POLICY to PUBLIC or generic user roles.",
      ],
    });
  }

  // 38.
  if (sfProcExecOwner.length > 0) {
    findings.push({
      id: "SNOWFLAKE_PROCEDURE_EXECUTE_AS_OWNER",
      title: "Stored procedure EXECUTE AS OWNER — SQL injection enables privilege escalation",
      severity: "HIGH",
      evidence: ev(sfProcExecOwner),
      requiredActions: [
        "Prefer EXECUTE AS CALLER unless owner's rights are strictly required.",
        "For EXECUTE AS OWNER procedures, parameterize all SQL and never concatenate caller input.",
        "Own such procedures with a least-privilege role and restrict who can CALL them.",
      ],
    });
  }

  // 39.
  if (sfSecondaryRolesAll.length > 0) {
    findings.push({
      id: "SNOWFLAKE_DEFAULT_SECONDARY_ROLES_ALL",
      title: "User DEFAULT_SECONDARY_ROLES = ('ALL') — every granted role active at login",
      severity: "MEDIUM",
      evidence: ev(sfSecondaryRolesAll),
      requiredActions: [
        "Avoid DEFAULT_SECONDARY_ROLES = ('ALL') for privileged or service users — it activates all roles simultaneously.",
        "Require explicit USE ROLE / USE SECONDARY ROLES so privileged actions are intentional.",
        "Audit which users have ALL secondary roles and tighten the role hierarchy.",
      ],
    });
  }

  // 40.
  if (sfPipeStageCred.length > 0) {
    findings.push({
      id: "SNOWFLAKE_PIPE_STAGE_INLINE_CRED",
      title: "Pipe/stage configured with inline cloud credentials (AWS/Azure SAS token)",
      severity: "CRITICAL",
      evidence: ev(sfPipeStageCred),
      requiredActions: [
        "Remove AWS_KEY_ID/AWS_SECRET_KEY/AWS_TOKEN/AZURE_SAS_TOKEN from CREATE PIPE/STAGE and rotate them.",
        "Use a STORAGE INTEGRATION (and NOTIFICATION INTEGRATION for pipes) instead of inline credentials.",
        "Enforce REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = TRUE at the account level.",
      ],
    });
  }

  // 41.
  if (sfShareWildcard.length > 0) {
    findings.push({
      id: "SNOWFLAKE_SHARE_WILDCARD_PUBLIC",
      title: "Data share added to wildcard accounts or published as a public listing",
      severity: "HIGH",
      evidence: ev(sfShareWildcard),
      requiredActions: [
        "Never ALTER SHARE … ADD ACCOUNTS = '*' — share only with explicitly named, expected accounts.",
        "Review any public Marketplace LISTING for unintended exposure of sensitive data.",
        "Apply secure views / row-access policies to shared objects before sharing.",
      ],
    });
  }

  // 42. Password policy absent.
  if (sfUsage.length > 0 && sfPwPolicyPresent.length === 0) {
    findings.push({
      id: "SNOWFLAKE_NO_PASSWORD_POLICY",
      title: "Snowflake in use but no password policy (min length / lockout) defined",
      severity: "MEDIUM",
      requiredActions: [
        "Create a PASSWORD POLICY with PASSWORD_MIN_LENGTH >= 14 and complexity requirements.",
        "Set PASSWORD_MAX_RETRIES / lockout and PASSWORD_MAX_AGE_DAYS, then ALTER ACCOUNT SET PASSWORD POLICY.",
        "Prefer SSO/key-pair auth and reserve passwords for break-glass accounts only.",
      ],
    });
  }

  // 43. Access/login history not used (LOW heuristic).
  if (sfUsage.length > 0 && sfHistoryUsage.length === 0) {
    findings.push({
      id: "SNOWFLAKE_NO_ACCESS_HISTORY_MONITORING",
      title: "No use of ACCESS_HISTORY / LOGIN_HISTORY — privileged access goes unmonitored",
      severity: "LOW",
      requiredActions: [
        "Query SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY to track column-level data access on sensitive tables.",
        "Monitor LOGIN_HISTORY for failed logins, new IPs, and client types; alert via a SIEM.",
        "Retain and export these views beyond the default 365-day window for audit.",
      ],
    });
  }

  // 44. Warehouse AUTO_SUSPEND disabled (cost, LOW).
  if (sfWhNoSuspend.length > 0) {
    findings.push({
      id: "SNOWFLAKE_WAREHOUSE_NO_AUTO_SUSPEND",
      title: "Warehouse AUTO_SUSPEND = 0 — runaway compute / cost amplification",
      severity: "LOW",
      evidence: ev(sfWhNoSuspend),
      requiredActions: [
        "Set AUTO_SUSPEND to a small idle timeout (e.g. 60 seconds) on all warehouses.",
        "Enable AUTO_RESUME and set resource monitors with credit quotas to cap spend.",
        "Alert on warehouses that never suspend — they can mask abusive query activity.",
      ],
    });
  }

  // 45. Time Travel disabled on sensitive tables.
  if (sfDataRetentionZero.length > 0) {
    findings.push({
      id: "SNOWFLAKE_DATA_RETENTION_ZERO",
      title: "DATA_RETENTION_TIME_IN_DAYS = 0 — Time Travel disabled, no recovery from malicious deletes",
      severity: "MEDIUM",
      evidence: ev(sfDataRetentionZero),
      requiredActions: [
        "Set DATA_RETENTION_TIME_IN_DAYS >= 7 (Enterprise: up to 90) on sensitive tables/databases.",
        "Time Travel enables recovery from accidental or malicious DROP/TRUNCATE/UPDATE.",
        "Combine with fail-safe and external backups for regulated data.",
      ],
    });
  }

  // 46. Periodic data rekeying disabled.
  if (sfRekeyingOff.length > 0) {
    findings.push({
      id: "SNOWFLAKE_PERIODIC_REKEYING_OFF",
      title: "PERIODIC_DATA_REKEYING = FALSE — encryption keys not rotated annually",
      severity: "LOW",
      evidence: ev(sfRekeyingOff),
      requiredActions: [
        "Set PERIODIC_DATA_REKEYING = TRUE so Snowflake re-encrypts data with new keys yearly.",
        "Document key rotation for SOC 2 / PCI DSS evidence.",
        "Use Tri-Secret Secure with a customer-managed key for regulated workloads.",
      ],
    });
  }

  return findings;
}
