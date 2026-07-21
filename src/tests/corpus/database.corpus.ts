import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "DB_TLS_DISABLED",
    check: "database",
    positive: {
      file: "src/db/connection.ts",
      content: `export const dbConfig = {\n  host: process.env.DB_HOST,\n  connectionString: \`postgres://app_user:\${process.env.DB_PASSWORD}@prod-db.internal:5432/orders?sslmode=disable\`\n};\n`
    },
    negative: {
      file: "src/db/connection.ts",
      content: `export const dbConfig = {\n  host: process.env.DB_HOST,\n  connectionString: \`postgres://app_user:\${process.env.DB_PASSWORD}@prod-db.internal:5432/orders?sslmode=verify-full\`\n};\n`
    },
    note: "Negative pins sslmode=verify-full (the rule's own remediation) instead of any sslmode=disable/ssl=false/TrustServerCertificate=true variant the regex looks for."
  },
  {
    ruleId: "DB_ADMIN_CREDENTIALS",
    check: "database",
    positive: {
      file: "src/db/mongoClient.ts",
      content: `export const MONGO_URI = "mongodb://admin:SuperSecret123@cluster0.example.mongodb.net/mydb";\n`
    },
    negative: {
      file: "src/db/mongoClient.ts",
      content: `export const MONGO_URI = \`mongodb://app_readwrite:\${process.env.MONGO_PASSWORD}@cluster0.example.mongodb.net/mydb\`;\n`
    },
    note: "Negative uses a scoped least-privilege user (app_readwrite) instead of admin/root/sa, so it never matches the mongodb://admin:|mongodb://root:|//sa: alternatives."
  },
  {
    ruleId: "DB_HARDCODED_PASSWORD",
    check: "database",
    positive: {
      file: "src/db/knexConfig.ts",
      content: `const password = "Sup3rSecretP@ss1"; // knex database password, should live in a secrets manager\nexport const knexConnection = { host: "prod-db.internal", user: "app_user", password, database: "orders" };\n`
    },
    negative: {
      file: "src/db/knexConfig.ts",
      content: `const password = process.env.DB_PASSWORD; // knex database password read from environment\nexport const knexConnection = { host: process.env.DB_HOST, user: process.env.DB_USER, password, database: process.env.DB_NAME };\n`
    },
    note: "The rule matches password: /= followed by a quoted literal on the same line as an ORM/db keyword. The negative's password line has no quoted literal at all (process.env.DB_PASSWORD), so the hardcoded-password regex never matches, exactly the fix in requiredActions."
  },
  {
    ruleId: "DB_NO_POOL_LIMITS",
    check: "database",
    positive: {
      file: "src/db/pool.ts",
      content: `import { Pool } from "pg";\n\nexport const pool = new Pool({\n  host: process.env.DB_HOST,\n  user: process.env.DB_USER,\n  password: process.env.DB_PASSWORD,\n  database: process.env.DB_NAME\n});\n`
    },
    negative: {
      file: "src/db/pool.ts",
      content: `import { Pool } from "pg";\n\nexport const pool = new Pool({\n  host: process.env.DB_HOST,\n  user: process.env.DB_USER,\n  password: process.env.DB_PASSWORD,\n  database: process.env.DB_NAME,\n  max: 20,\n  min: 2,\n  idleTimeoutMillis: 30000\n});\n`
    },
    note: "Rule fires only when a pool-creation call (new Pool) exists AND no pool-limit keyword (max:/poolSize/connectionLimit) appears anywhere in the file. The negative adds explicit max/min limits, which the requiredActions call out directly."
  },
  {
    ruleId: "DB_BACKUP_NOT_ENCRYPTED",
    check: "database",
    positive: {
      file: "infra/rds.tf",
      content: `resource "aws_db_instance" "main" {\n  identifier              = "prod-orders-db"\n  engine                  = "postgres"\n  backup_retention_period = 7\n  backup_window           = "03:00-04:00"\n  publicly_accessible     = false\n}\n`
    },
    negative: {
      file: "infra/rds.tf",
      content: `resource "aws_db_instance" "main" {\n  identifier              = "prod-orders-db"\n  engine                  = "postgres"\n  backup_retention_period = 7\n  backup_window           = "03:00-04:00"\n  storage_encrypted       = true\n  kms_key_id              = aws_kms_key.db.arn\n  publicly_accessible     = false\n}\n`
    },
    note: "Rule fires when backup config keywords (backup_retention_period/backup_window) exist AND no encryption keyword (encrypted/kms_key) appears anywhere in the file. The negative adds storage_encrypted and kms_key_id, matching the rule's own requiredActions."
  },
  {
    ruleId: "DB_SQL_INJECTION_RISK",
    check: "database",
    positive: {
      file: "src/api/users.ts",
      content: `import type { Request, Response } from "express";\nimport { db } from "./connection.js";\n\nexport function getUserById(req: Request, res: Response) {\n  const sql = "SELECT * FROM users WHERE id = " + req.query.id;\n  db.query(sql, (err: unknown, results: unknown) => {\n    res.json(results);\n  });\n}\n`
    },
    negative: {
      file: "src/api/users.ts",
      content: `import type { Request, Response } from "express";\nimport { db } from "./connection.js";\n\nexport function getUserById(req: Request, res: Response) {\n  const sql = "SELECT * FROM users WHERE id = $1";\n  db.query(sql, [req.query.id], (err: unknown, results: unknown) => {\n    res.json(results);\n  });\n}\n`
    },
    note: "Positive concatenates req.query.id directly after a closing quote (\"...\" + req.query.id), matching the [\"']\\s*\\+\\s*req\\. pattern. The negative binds the same value as a $1 parameter passed separately to db.query, so no quote-plus-req./template-with-req. pattern appears anywhere."
  },
  {
    ruleId: "DB_MONGO_OPERATOR_KEY_INJECTION",
    check: "database",
    positive: {
      file: "src/api/search.ts",
      content: `import type { Request, Response } from "express";\nimport { User } from "../models/User.js";\n\nexport async function searchUsers(req: Request, res: Response) {\n  const results = await User.find({ ...req.body });\n  res.json(results);\n}\n`
    },
    negative: {
      file: "src/api/search.ts",
      content: `import type { Request, Response } from "express";\nimport { z } from "zod";\nimport { User } from "../models/User.js";\n\nconst searchSchema = z.object({ username: z.string() });\n\nexport async function searchUsers(req: Request, res: Response) {\n  const { username } = searchSchema.parse(req.body);\n  const results = await User.find({ username });\n  res.json(results);\n}\n`
    },
    note: "Positive spreads req.body straight into a Mongo filter (User.find({ ...req.body })), matching the mongoSpreadHits pattern. The negative extracts and validates one named field with zod before building the filter — the exact fix in requiredActions — so no spread or computed-key pattern remains."
  },
  {
    ruleId: "DB_PREPARED_STATEMENT_MISUSE",
    check: "database",
    positive: {
      file: "src/db/userRepo.ts",
      content: `import Database from "better-sqlite3";\nimport type { Request, Response } from "express";\n\nconst db = new Database("app.db");\n\nexport function getUser(req: Request, res: Response) {\n  const stmt = db.prepare("SELECT * FROM users WHERE id = " + req.params.id);\n  const user = stmt.get();\n  res.json(user);\n}\n`
    },
    negative: {
      file: "src/db/userRepo.ts",
      content: `import Database from "better-sqlite3";\nimport type { Request, Response } from "express";\n\nconst db = new Database("app.db");\n\nexport function getUser(req: Request, res: Response) {\n  const stmt = db.prepare("SELECT * FROM users WHERE id = ?");\n  const user = stmt.get(req.params.id);\n  res.json(user);\n}\n`
    },
    note: "Positive concatenates req.params.id into the .prepare() string itself. The negative uses a ? placeholder in .prepare() and passes req.params.id as a bound argument to .get() instead — no quote-plus-req./template-with-req. appears next to any prepare/run/get/all/execute call."
  },
  {
    ruleId: "DB_DYNAMIC_SQL_CONCAT",
    check: "database",
    positive: {
      file: "db/procedures/search_users.sql",
      content: `CREATE OR REPLACE PROCEDURE search_users(p_input IN VARCHAR2) AS\nBEGIN\n  EXECUTE IMMEDIATE 'SELECT * FROM users WHERE name = ''' || p_input || '''';\nEND;\n/\n`
    },
    negative: {
      file: "db/procedures/search_users.sql",
      content: `CREATE OR REPLACE PROCEDURE search_users(p_input IN VARCHAR2) AS\nBEGIN\n  EXECUTE IMMEDIATE 'SELECT * FROM users WHERE name = :1' USING p_input;\nEND;\n/\n`
    },
    note: "Positive's EXECUTE IMMEDIATE clause contains || string concatenation with p_input on the same statement. The negative uses a :1 bind variable with USING p_input — no ||, CONCAT(, '+ , or +@ token appears near EXECUTE IMMEDIATE, matching the rule's own Oracle fix example."
  },
  {
    ruleId: "DB_RLS_POLICY_BYPASS",
    check: "database",
    positive: {
      file: "db/migrations/0007_rls_tenants.sql",
      content: `-- Temporary maintenance window: disable RLS for bulk import\nALTER TABLE tenants DISABLE ROW LEVEL SECURITY;\n`
    },
    negative: {
      file: "db/migrations/0007_rls_tenants.sql",
      content: `ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;\nALTER TABLE tenants FORCE ROW LEVEL SECURITY;\n\nCREATE POLICY tenant_isolation ON tenants\n  USING (tenant_id = current_setting('app.tenant_id')::uuid);\n`
    },
    note: "Positive directly disables RLS (DISABLE ROW LEVEL SECURITY), an unconditional match. The negative keeps RLS enabled and forced and contains no BYPASSRLS or SECURITY DEFINER text at all, so neither trigger branch of the rule fires."
  },
  {
    ruleId: "DB_READ_UNCOMMITTED_ISOLATION",
    check: "database",
    positive: {
      file: "db/queries/orders_report.sql",
      content: `SELECT * FROM orders WITH (NOLOCK) WHERE customer_id = @customerId;\n`
    },
    negative: {
      file: "db/queries/orders_report.sql",
      content: `SET TRANSACTION ISOLATION LEVEL READ COMMITTED;\nSELECT * FROM orders WHERE customer_id = @customerId;\n`
    },
    note: "Positive uses the WITH (NOLOCK) hint, an unconditional dirty-read match. The negative explicitly sets READ COMMITTED isolation and drops the hint — 'READ COMMITTED' does not contain the literal 'UNCOMMITTED' substring the rule requires, so it does not match."
  },
  {
    ruleId: "DB_GRANT_PRIVILEGE_ESCALATION",
    check: "database",
    positive: {
      file: "db/grants/orders_grant.sql",
      content: `GRANT ALL ON orders TO app_role;\n`
    },
    negative: {
      file: "db/grants/orders_grant.sql",
      content: `GRANT SELECT, INSERT ON app.orders TO app_role;\n`
    },
    note: "Positive uses GRANT ALL, matching GRANT\\s+ALL\\b directly. The negative grants only SELECT and INSERT with no WITH GRANT OPTION, so neither alternative in the grantHits regex matches — the least-privilege fix the requiredActions describe."
  }
];
