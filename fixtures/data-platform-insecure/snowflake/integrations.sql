-- INSECURE FIXTURE — Snowflake integrations / functions / sharing anti-patterns.

-- 32. OAuth security integration with http/wildcard redirect, empty blocked-roles
CREATE OR REPLACE SECURITY INTEGRATION ext_oauth
  TYPE = OAUTH
  OAUTH_CLIENT = CUSTOM
  OAUTH_REDIRECT_URI = 'http://localhost/callback'
  BLOCKED_ROLES_LIST = ();
ALTER SECURITY INTEGRATION ext_oauth SET OAUTH_REDIRECT_URI = 'https://app.example.com/*';

-- 33. SCIM integration (no network policy attached in this repo)
CREATE OR REPLACE SECURITY INTEGRATION okta_scim
  TYPE = SCIM
  SCIM_CLIENT = 'okta'
  RUN_AS_ROLE = 'ACCOUNTADMIN';

-- 34. Storage integration allowing all (*) locations
CREATE OR REPLACE STORAGE INTEGRATION s3_int
  TYPE = EXTERNAL_STAGE
  STORAGE_PROVIDER = 'S3'
  STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::123:role/sf'
  STORAGE_ALLOWED_LOCATIONS = ('*');

-- 35. External function / API integration to untrusted endpoint
CREATE OR REPLACE API INTEGRATION ext_api
  API_PROVIDER = aws_api_gateway
  API_ALLOWED_PREFIXES = ('http://api.partner.example/')
  ENABLED = TRUE;
CREATE EXTERNAL FUNCTION enrich(x VARCHAR) RETURNS VARCHAR API_INTEGRATION = ext_api AS 'https://api.partner.example/enrich';

-- 36. Tasks / streams owned by ACCOUNTADMIN
GRANT OWNERSHIP ON TASK etl_task TO ROLE ACCOUNTADMIN;
GRANT OWNERSHIP ON STREAM cdc_stream TO ROLE ACCOUNTADMIN;

-- 37. Broad privilege grants
GRANT IMPORTED PRIVILEGES ON DATABASE shared_db TO ROLE analyst;
GRANT MANAGE GRANTS ON ACCOUNT TO ROLE etl_role;
GRANT APPLY MASKING POLICY ON ACCOUNT TO ROLE PUBLIC;

-- 38. Stored procedure EXECUTE AS OWNER
CREATE OR REPLACE PROCEDURE run_dynamic(stmt STRING)
  RETURNS STRING
  LANGUAGE SQL
  EXECUTE AS OWNER
  AS $$ BEGIN RETURN 'ok'; END; $$;

-- 39. DEFAULT_SECONDARY_ROLES = ('ALL')
ALTER USER svc_etl SET DEFAULT_SECONDARY_ROLES = ('ALL');

-- 40. Pipe / stage with inline cloud credentials
CREATE PIPE load_pipe AS COPY INTO t FROM @stg CREDENTIALS = (AWS_KEY_ID = 'AKIAEXAMPLE12345678' AWS_SECRET_KEY = 'secretkeymaterialxyz');
CREATE STAGE az_stage URL = 'azure://acct.blob.core.windows.net/c' AZURE_SAS_TOKEN = '?sv=2021-08-06&ss=b&srt=co&sig=abc';

-- 41. Share to wildcard accounts / public listing
ALTER SHARE prod_share ADD ACCOUNTS = '*';
CREATE LISTING marketplace_listing IN DATA EXCHANGE snowflake_data_marketplace PUBLIC AS '...';
