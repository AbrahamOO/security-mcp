-- INSECURE FIXTURE — Snowflake warehouse / retention / rekeying anti-patterns.

-- 44. Warehouse AUTO_SUSPEND disabled (never suspends)
CREATE WAREHOUSE etl_wh WITH WAREHOUSE_SIZE = 'XLARGE' AUTO_SUSPEND = 0 AUTO_RESUME = TRUE;

-- 45. Time Travel disabled on sensitive table
CREATE TABLE sensitive_pii (id NUMBER, ssn VARCHAR) DATA_RETENTION_TIME_IN_DAYS = 0;
ALTER DATABASE prod SET DATA_RETENTION_TIME_IN_DAYS = 0;

-- 46. Periodic data rekeying disabled
ALTER ACCOUNT SET PERIODIC_DATA_REKEYING = FALSE;
