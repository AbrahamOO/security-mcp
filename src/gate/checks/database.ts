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
	} catch (err) {
		console.warn("[checkDatabase] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
