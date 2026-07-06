/**
 * Database security checks.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";

export async function checkDatabase(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		// 1. SSL/TLS disabled in connection strings
		const tlsDisabledHits = await searchRepo({
			query: String.raw`sslmode=disable|ssl=false|ssl:\s*false|useSSL=false|TrustServerCertificate=true`,
			isRegex: true,
			maxMatches: 200
		});
		if (tlsDisabledHits.length > 0) {
			findings.push({
				id: "DB_TLS_DISABLED",
				title: "Database connection with TLS/SSL disabled detected",
				severity: "CRITICAL",
				evidence: tlsDisabledHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(tlsDisabledHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Always use sslmode=require or sslmode=verify-full for PostgreSQL.",
					"Never disable TLS for database connections — transmits credentials and data in plaintext."
				]
			});
		}

		// 2. Root/admin credentials in connection strings
		const adminCredHits = await searchRepo({
			query: String.raw`postgresql://root:|mysql://root:|mongodb://admin:|mongodb://root:|postgres://postgres:|//sa:`,
			isRegex: true,
			maxMatches: 200
		});
		if (adminCredHits.length > 0) {
			findings.push({
				id: "DB_ADMIN_CREDENTIALS",
				title: "Root/admin database credentials detected in connection strings",
				severity: "CRITICAL",
				evidence: adminCredHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(adminCredHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Create a least-privilege DB user scoped to only required tables and operations.",
					"Never use root/admin/sa/postgres superuser credentials in application code."
				]
			});
		}

		// 3. Plaintext credentials in ORM config
		const hardcodedPwdHits = await searchRepo({
			query: String.raw`password\s*[:=]\s*["'][^"'\n]{6,}["']`,
			isRegex: true,
			maxMatches: 200
		});
		// Filter for hits near ORM/DB keywords
		const ormKeywordRe = /database|db|sequelize|typeorm|prisma|mongoose|knex/i;
		const ormPwdHits = hardcodedPwdHits.filter((m) => ormKeywordRe.test(m.preview));
		if (ormPwdHits.length > 0) {
			findings.push({
				id: "DB_HARDCODED_PASSWORD",
				title: "Hardcoded database password detected in ORM/DB configuration",
				severity: "CRITICAL",
				evidence: ormPwdHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(ormPwdHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Move database credentials to environment variables or a secrets manager.",
					"Never hardcode passwords in source code."
				]
			});
		}

		// 4. No connection pool limits
		const poolInitHits = await searchRepo({
			query: String.raw`new Pool|createPool|new Sequelize|DataSource\(|createConnection`,
			isRegex: true,
			maxMatches: 200
		});
		const poolLimitHits = await searchRepo({
			query: String.raw`max:|pool_size|poolSize|connectionLimit`,
			isRegex: true,
			maxMatches: 200
		});
		if (poolInitHits.length > 0 && poolLimitHits.length === 0) {
			findings.push({
				id: "DB_NO_POOL_LIMITS",
				title: "Database connection pool initialized without explicit limits",
				severity: "MEDIUM",
				evidence: poolInitHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(poolInitHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Set connection pool limits (max, min) to prevent resource exhaustion.",
					"Unbounded pools can crash the database under load or be exploited for DoS."
				]
			});
		}

		// 5. Backup encryption not configured
		const backupHits = await searchRepo({
			query: String.raw`backup_retention|automated_backups|backup_window`,
			isRegex: true,
			maxMatches: 200
		});
		const encryptionHits = await searchRepo({
			query: String.raw`encrypted|kms_key`,
			isRegex: true,
			maxMatches: 200
		});
		if (backupHits.length > 0 && encryptionHits.length === 0) {
			findings.push({
				id: "DB_BACKUP_NOT_ENCRYPTED",
				title: "Database backup configured without encryption",
				severity: "HIGH",
				evidence: backupHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(backupHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Enable backup encryption with a KMS key.",
					"Unencrypted backups expose all data if storage is compromised."
				]
			});
		}

		// 6. SQL string concatenation (SQLi risk)
		const sqliHits = await searchRepo({
			query: String.raw`["']\s*\+\s*(?:req\.|params\.|query\.|body\.|user\.|input\.)`,
			isRegex: true,
			maxMatches: 200
		});
		// Also check for template literal injection
		const sqliTemplateHits = await searchRepo({
			query: String.raw`\$\{.*(?:req\.|params\.|query\.|body\.)[^}]*\}`,
			isRegex: true,
			maxMatches: 200
		});
		const allSqliHits = [...sqliHits, ...sqliTemplateHits];
		if (allSqliHits.length > 0) {
			findings.push({
				id: "DB_SQL_INJECTION_RISK",
				title: "Possible SQL injection: user input concatenated into query string",
				severity: "CRITICAL",
				evidence: allSqliHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(allSqliHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Use parameterized queries or ORM query builders — never concatenate user input into SQL.",
					"CWE-89: SQL injection can lead to full database compromise."
				]
			});
		}

		// 7. MongoDB operator-key injection: user-controlled object KEYS reaching a query
		const mongoKeyInjectionHits = await searchRepo({
			query: String.raw`\{\s*\[\s*(?:req\.|body\.|params\.|query\.|userKey|key)\b[^\]]*\]\s*:`,
			isRegex: true,
			maxMatches: 200
		});
		const mongoSpreadHits = await searchRepo({
			query: String.raw`(?:\.find|\.findOne|\.findOneAndUpdate|\.updateOne|\.updateMany|\.deleteOne|\.deleteMany|\.aggregate|\.count)\s*\(\s*\{\s*\.\.\.\s*(?:req\.body|req\.query|req\.params|body|query|params)\b`,
			isRegex: true,
			maxMatches: 200
		});
		const mongoOpKeyHits = [...mongoKeyInjectionHits, ...mongoSpreadHits];
		if (mongoOpKeyHits.length > 0) {
			findings.push({
				id: "DB_MONGO_OPERATOR_KEY_INJECTION",
				title: "MongoDB operator-key injection: user-controlled object keys or spread reach a query (CWE-943)",
				severity: "CRITICAL",
				evidence: mongoOpKeyHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(mongoOpKeyHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Never use user input as object keys or spread req.body into a filter — attacker keys like $where/$gt/$ne change query semantics.",
					"CWE-943: {[req.body.key]: v} or {...req.body} enables operator injection ({\"$gt\":\"\"} bypasses equality, {\"$where\":...} runs JS).",
					"Fix: extract and validate each field explicitly — const { username } = z.object({ username: z.string() }).parse(req.body); Model.findOne({ username })."
				]
			});
		}

		// 8. Prepared-statement misuse: statement created but params concatenated instead of bound
		const preparedStmtHits = await searchRepo({
			query: String.raw`(?:\.prepare\s*\(|PREPARE\s+\w+|prepareStatement\s*\()`,
			isRegex: true,
			maxMatches: 200
		});
		const preparedStmtFiles = new Set(preparedStmtHits.map((m) => m.file));
		const preparedConcatCandidates = await searchRepo({
			query: String.raw`(?:\.prepare\s*\(|prepareStatement\s*\(|\.run\s*\(|\.get\s*\(|\.all\s*\(|\.execute\s*\()[^;\n]*(?:['"]\s*\+\s*(?:req\.|params\.|query\.|body\.|user\.)|\$\{(?:req|params|query|body|user)\.)`,
			isRegex: true,
			maxMatches: 200
		});
		const preparedMisuseHits = preparedConcatCandidates.filter((m) => preparedStmtFiles.has(m.file));
		if (preparedMisuseHits.length > 0) {
			findings.push({
				id: "DB_PREPARED_STATEMENT_MISUSE",
				title: "Prepared statement misuse: parameters concatenated into SQL instead of bound (CWE-89)",
				severity: "CRITICAL",
				evidence: preparedMisuseHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(preparedMisuseHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Bind every user value as a positional/named parameter — concatenating into a prepared statement defeats the entire protection.",
					"CWE-89: db.prepare('... WHERE id = ' + req.params.id) is still injectable; the placeholder must carry the value.",
					"Fix: const stmt = db.prepare('SELECT * FROM users WHERE id = ?'); stmt.get(req.params.id);"
				]
			});
		}

		// 9. Dynamic SQL in stored procedures / EXECUTE IMMEDIATE / EXEC(@sql) with concatenation
		const dynamicSqlHits = await searchRepo({
			query: String.raw`(?:EXECUTE\s+IMMEDIATE|EXEC\s*\(\s*@\w+|EXECUTE\s*\(\s*@\w+|sp_executesql|PREPARE\s+\w+\s+FROM)\b`,
			isRegex: true,
			maxMatches: 200
		});
		const dynamicSqlConcatHits = await searchRepo({
			query: String.raw`(?:EXECUTE\s+IMMEDIATE|sp_executesql|@sql\b)[^;\n]{0,200}(?:\|\||CONCAT\s*\(|'\s*\+\s*|\+\s*@\w+)`,
			isRegex: true,
			maxMatches: 200
		});
		const dynSqlFiles = new Set(dynamicSqlHits.map((m) => m.file));
		const dynSqlUnsafe = dynamicSqlConcatHits.filter((m) => dynSqlFiles.has(m.file) || /EXECUTE\s+IMMEDIATE|sp_executesql|EXEC\s*\(\s*@/i.test(m.preview));
		if (dynSqlUnsafe.length > 0) {
			findings.push({
				id: "DB_DYNAMIC_SQL_CONCAT",
				title: "Dynamic SQL in stored procedure (EXECUTE IMMEDIATE / EXEC(@sql) / sp_executesql) built by concatenation (CWE-89)",
				severity: "CRITICAL",
				evidence: dynSqlUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(dynSqlUnsafe.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Never build dynamic SQL strings by concatenation inside stored procedures — use parameterized dynamic SQL.",
					"CWE-89: EXECUTE IMMEDIATE 'SELECT ... ' || p_input runs injected SQL with the procedure's (often elevated) privileges.",
					"Fix: EXECUTE IMMEDIATE 'SELECT ... WHERE id = :1' USING p_input; (Oracle) or sp_executesql @sql, N'@id int', @id = @id; (SQL Server)."
				]
			});
		}

		// 10. Row-Level-Security bypass / SECURITY DEFINER view missing security_barrier
		const rlsDisableHits = await searchRepo({
			query: String.raw`(?:DISABLE\s+ROW\s+LEVEL\s+SECURITY|NO\s+FORCE\s+ROW\s+LEVEL\s+SECURITY|BYPASSRLS|ALTER\s+USER\s+\w+\s+BYPASSRLS)`,
			isRegex: true,
			maxMatches: 200
		});
		const securityDefinerHits = await searchRepo({
			query: String.raw`SECURITY\s+DEFINER`,
			isRegex: true,
			maxMatches: 200
		});
		const searchPathPinned = await searchRepo({
			query: String.raw`SET\s+search_path|security_barrier\s*=\s*true`,
			isRegex: true,
			maxMatches: 200
		});
		const definerUnsafe = securityDefinerHits.length > 0 && searchPathPinned.length === 0
			? securityDefinerHits
			: [];
		const rlsHits = [...rlsDisableHits, ...definerUnsafe];
		if (rlsHits.length > 0) {
			findings.push({
				id: "DB_RLS_POLICY_BYPASS",
				title: "Row-Level-Security bypass or SECURITY DEFINER routine without pinned search_path (CWE-863)",
				severity: "HIGH",
				evidence: rlsHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(rlsHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Do not DISABLE ROW LEVEL SECURITY or grant BYPASSRLS to application roles; keep FORCE ROW LEVEL SECURITY on tenant tables.",
					"CWE-863: a SECURITY DEFINER function/view without a pinned search_path lets a caller shadow objects and run code as the definer (privilege escalation).",
					"Fix: keep RLS enabled/forced; on every SECURITY DEFINER routine add `SET search_path = pg_catalog, public` and mark views with security_barrier=true."
				]
			});
		}

		// 11. READ UNCOMMITTED isolation (dirty reads)
		const readUncommittedHits = await searchRepo({
			query: String.raw`(?:ISOLATION\s+LEVEL\s+READ\s+UNCOMMITTED|WITH\s*\(\s*NOLOCK\s*\)|READ[\s_]?UNCOMMITTED|IsolationLevel\.ReadUncommitted|isolationLevel\s*:\s*['"]?READ[\s_]?UNCOMMITTED)`,
			isRegex: true,
			maxMatches: 200
		});
		if (readUncommittedHits.length > 0) {
			findings.push({
				id: "DB_READ_UNCOMMITTED_ISOLATION",
				title: "READ UNCOMMITTED / NOLOCK isolation enables dirty reads (CWE-362)",
				severity: "MEDIUM",
				evidence: readUncommittedHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(readUncommittedHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Avoid READ UNCOMMITTED / WITH (NOLOCK) — it reads uncommitted, possibly rolled-back data and can produce inconsistent or duplicated rows.",
					"CWE-362: dirty reads on financial/authorization data lead to incorrect decisions and race-condition bugs.",
					"Fix: use READ COMMITTED (default) or REPEATABLE READ / SERIALIZABLE for consistency-critical transactions; remove NOLOCK hints."
				]
			});
		}

		// 12. GRANT chain / privilege escalation (WITH GRANT OPTION, GRANT ALL)
		const grantHits = await searchRepo({
			query: String.raw`GRANT\s+ALL\b|WITH\s+GRANT\s+OPTION`,
			isRegex: true,
			maxMatches: 200
		});
		const grantUnsafe = grantHits.filter((m) => !/GRANT\s+SELECT\s+ON[^;]*TO\s+\w+\s*;?\s*$/i.test(m.preview) || /WITH\s+GRANT\s+OPTION|GRANT\s+ALL/i.test(m.preview));
		if (grantUnsafe.length > 0) {
			findings.push({
				id: "DB_GRANT_PRIVILEGE_ESCALATION",
				title: "Over-broad GRANT (GRANT ALL / WITH GRANT OPTION) enables privilege escalation (CWE-269)",
				severity: "HIGH",
				evidence: grantUnsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(grantUnsafe.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Grant only the specific privileges required (SELECT/INSERT/UPDATE on named tables); never GRANT ALL to application roles.",
					"CWE-269: WITH GRANT OPTION lets the grantee re-delegate privileges, creating an uncontrolled grant chain and privilege escalation.",
					"Fix: GRANT SELECT, INSERT ON app.orders TO app_role; — omit WITH GRANT OPTION and revoke existing over-broad grants."
				]
			});
		}
	} catch (err) {
		console.warn("[checkDatabase] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
