# Databricks notebook source
# INSECURE FIXTURE — DBFS mount + untrusted SQL UDF anti-patterns.

# 26. DBFS mount with inline storage key
dbutils.fs.mount(
    source="wasbs://container@acct.blob.core.windows.net",
    mount_point="/mnt/data",
    extra_configs={"fs.azure.account.key.acct.blob.core.windows.net": "abcDEF1234567890keymaterialXYZ=="},
)

# 30. CREATE FUNCTION with LANGUAGE PYTHON / external jar / shell from untrusted source
spark.sql("CREATE OR REPLACE FUNCTION main.util.run_cmd() RETURNS STRING LANGUAGE PYTHON AS 'return 1'")
spark.sql("CREATE FUNCTION main.util.loader() RETURNS STRING USING JAR 'dbfs:/tmp/unverified.jar'")
spark.sql("CREATE FUNCTION main.util.pwn() RETURNS STRING AS 'import os; os.system(\"id\")'")
