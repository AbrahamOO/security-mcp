# Databricks notebook source
# INSECURE FIXTURE — do not use. Demonstrates Databricks anti-patterns.

# 1. Hardcoded Databricks PAT and host URL with embedded creds
DATABRICKS_TOKEN = "dapideadbeef0123456789abcdef0123"
token = "dapi0011223344556677889900aabbccdd"
WORKSPACE = "https://admin:hunter2@dbc-abc123.cloud.databricks.com"

# 2. Secret printed/logged after dbutils.secrets.get (secret leakage)
db_pw = dbutils.secrets.get(scope="kv", key="db-password")
print(dbutils.secrets.get(scope="kv", key="api-key"))
logger.info(dbutils.secrets.get(scope="kv", key="token"))
displayHTML(dbutils.secrets.get(scope="kv", key="html-secret"))

# 7. Inline storage credentials in spark.conf.set and DataFrame .option()
spark.conf.set("fs.s3a.access.key", "AKIAIOSFODNN7EXAMPLE")
spark.conf.set("fs.s3a.secret.key", "wJalrXUtnFEMI0987654321EXAMPLEKEY+abc")
fs.azure.account.key.myacct.dfs.core.windows.net = "abcDEF1234567890abcDEF1234567890abcDEF=="
df = spark.read.format("jdbc").option("user", "admin").option("password", "Sup3rSecret!").load()

# 8. Legacy hive_metastore use (no Unity Catalog governance)
USE CATALOG hive_metastore
spark.sql("CREATE TABLE hive_metastore.default.events AS SELECT * FROM src")
spark.conf.set("spark.databricks.unityCatalog.enabled", "false")
data = spark.table("hive_metastore.analytics.users")
