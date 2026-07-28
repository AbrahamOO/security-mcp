/**
 * Data Loss Prevention checks.
 * Detects PII leaking into logs, APIs, and error responses.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";

export async function checkDlp(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		// 1. SSN in logs
		const ssnHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+|log\.\w+)\s*\([^)]*\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`,
			isRegex: true,
			maxMatches: 200
		});
		if (ssnHits.length > 0) {
			findings.push({
				id: "DLP_SSN_IN_LOGS",
				title: "Social Security Number pattern detected in log statement",
				severity: "CRITICAL",
				evidence: ssnHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(ssnHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Remove SSN values from log statements immediately.",
					"HIPAA requires protection of SSNs as Protected Health Information (PHI).",
					"Use tokenization or masking before logging any government ID."
				]
			});
		}

		// 2. Credit card in logs (PAN)
		const panHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+)\s*\([^)]*\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`,
			isRegex: true,
			maxMatches: 200
		});
		if (panHits.length > 0) {
			findings.push({
				id: "DLP_PAN_IN_LOGS",
				title: "Credit card PAN pattern detected in log statement — PCI DSS violation",
				severity: "CRITICAL",
				evidence: panHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(panHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Remove all PAN values from log statements immediately.",
					"PCI DSS Requirement 3: Never log full card numbers.",
					"Use masked PANs (show only last 4 digits) if logging is required."
				]
			});
		}

		// 3. Full request body logged
		const reqBodyLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+)\s*\(\s*(?:req\.body|request\.body|ctx\.body|\{\.\.\.req)`,
			isRegex: true,
			maxMatches: 200
		});
		if (reqBodyLogHits.length > 0) {
			findings.push({
				id: "DLP_REQUEST_BODY_LOGGED",
				title: "Full request body logged — may expose PII/credentials",
				severity: "HIGH",
				evidence: reqBodyLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(reqBodyLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Never log full request bodies — use field allowlists to log only non-sensitive fields.",
					"GDPR Article 5: data minimization applies to logs. HIPAA prohibits logging PHI."
				]
			});
		}

		// 4. User object logged
		const userLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+)\s*\(\s*(?:user|currentUser|req\.user|session\.user)\s*[,)]`,
			isRegex: true,
			maxMatches: 200
		});
		if (userLogHits.length > 0) {
			findings.push({
				id: "DLP_USER_OBJECT_LOGGED",
				title: "User object logged — may expose PII, hashed passwords, or tokens",
				severity: "HIGH",
				evidence: userLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(userLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Log only specific non-sensitive user fields (e.g. userId, role).",
					"Never log the full user object — it likely contains PII and auth data (GDPR, HIPAA)."
				]
			});
		}

		// 5. Email in logs
		const emailLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+)\s*\([^)]*[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			isRegex: true,
			maxMatches: 200
		});
		if (emailLogHits.length > 0) {
			findings.push({
				id: "DLP_EMAIL_IN_LOGS",
				title: "Email address detected in log statement",
				severity: "MEDIUM",
				evidence: emailLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(emailLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Mask or hash email addresses before logging (GDPR Article 5 — data minimization).",
					"Use a user ID or anonymized identifier in logs instead of the email."
				]
			});
		}

		// 6. Stack traces in API responses
		const stackTraceHits = await searchRepo({
			query: String.raw`(?:res\.json|res\.send|response\.json)\s*\(\s*\{[^}]*(?:stack|stackTrace|error\.stack)`,
			isRegex: true,
			maxMatches: 200
		});
		if (stackTraceHits.length > 0) {
			findings.push({
				id: "DLP_STACK_TRACE_IN_RESPONSE",
				title: "Stack trace exposed in API response — CWE-209 information leakage",
				severity: "HIGH",
				evidence: stackTraceHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(stackTraceHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Never expose stack traces in API responses (CWE-209).",
					"Log errors internally with a correlation ID; return only a safe error message to clients."
				]
			});
		}

		// 7a. Health / medical record (PHI) in logs — HIPAA
		const phiLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+|log\.\w+)\s*\([^)]*(?:diagnosis|icd[-_ ]?(?:9|10)|medicalRecord|medical_record|patient(?:Name|Id|_id|Record)|prescription|medication|bloodType|blood_type|healthRecord|labResult|lab_result|mrn\b)`,
			isRegex: true,
			maxMatches: 200
		});
		if (phiLogHits.length > 0) {
			findings.push({
				id: "DLP_PHI_IN_LOGS",
				title: "Protected Health Information (PHI) detected in log statement — HIPAA violation",
				severity: "CRITICAL",
				sla: "24h",
				evidence: phiLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(phiLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Remove all medical/health record fields (diagnosis, medication, MRN, lab results) from log statements immediately.",
					"HIPAA Security Rule prohibits logging PHI in plaintext; logs are not a permitted disclosure.",
					"Log a non-reversible patient reference (opaque ID) instead, and route any required PHI to an access-controlled, encrypted audit store."
				]
			});
		}

		// 7b. Biometric data in logs
		const biometricLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+|log\.\w+)\s*\([^)]*(?:fingerprint(?:Data|Template|Hash)?|faceId|face_id|faceprint|faceEmbedding|iris(?:Scan|Code)|retina(?:Scan)?|voiceprint|biometric|palmPrint)`,
			isRegex: true,
			maxMatches: 200
		});
		if (biometricLogHits.length > 0) {
			findings.push({
				id: "DLP_BIOMETRIC_IN_LOGS",
				title: "Biometric identifier detected in log statement",
				severity: "CRITICAL",
				sla: "24h",
				evidence: biometricLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(biometricLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Never log biometric templates or identifiers (fingerprint, faceprint, iris, voiceprint) — they are immutable and cannot be rotated if leaked.",
					"BIPA / GDPR Article 9 classify biometrics as special-category data requiring the highest protection.",
					"Store biometric data only in an encrypted vault; log a derived non-reversible token if an audit trail is required."
				]
			});
		}

		// 7c. OAuth access / refresh token in logs
		const oauthTokenLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+|log\.\w+)\s*\([^)]*(?:access_?[Tt]oken|refresh_?[Tt]oken|id_?[Tt]oken|bearer[^)]*[A-Za-z0-9._\-]{16,}|ya29\.[A-Za-z0-9._\-]+|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.)`,
			isRegex: true,
			maxMatches: 200
		});
		if (oauthTokenLogHits.length > 0) {
			findings.push({
				id: "DLP_OAUTH_TOKEN_IN_LOGS",
				title: "OAuth access/refresh token detected in log statement",
				severity: "CRITICAL",
				sla: "24h",
				evidence: oauthTokenLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(oauthTokenLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Remove access/refresh/ID tokens from log statements — a logged token grants an attacker with log access the user's session.",
					"Rotate/revoke any tokens that may have been written to logs and invalidate affected sessions.",
					"If a token must be referenced, log only a short prefix or an opaque correlation ID, never the full value."
				]
			});
		}

		// 7d. Passport number in logs
		const passportLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+|log\.\w+)\s*\([^)]*(?:passport(?:No|Number|_number|Num)?)\s*[:=,)]`,
			isRegex: true,
			maxMatches: 200
		});
		if (passportLogHits.length > 0) {
			findings.push({
				id: "DLP_PASSPORT_IN_LOGS",
				title: "Passport number detected in log statement",
				severity: "HIGH",
				sla: "7d",
				evidence: passportLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(passportLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Remove passport numbers from log statements — they are government identity documents and high-value PII.",
					"GDPR / national ID-protection laws require minimization; passport numbers must not appear in application logs.",
					"Mask to the last 2-3 characters if any reference is required for support."
				]
			});
		}

		// 7e. Driver's license number in logs
		const licenseLogHits = await searchRepo({
			query: String.raw`(?:console\.log|logger\.\w+|log\.\w+)\s*\([^)]*(?:driver'?s?[_ ]?licen[sc]e|driversLicense|dlNumber|dl_number|licenseNumber|license_number)\s*[:=,)]`,
			isRegex: true,
			maxMatches: 200
		});
		if (licenseLogHits.length > 0) {
			findings.push({
				id: "DLP_DRIVERS_LICENSE_IN_LOGS",
				title: "Driver's license number detected in log statement",
				severity: "HIGH",
				sla: "7d",
				evidence: licenseLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(licenseLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Remove driver's license numbers from log statements — they are government-issued PII used for identity theft.",
					"Apply data minimization (GDPR Art. 5, state privacy laws); do not persist license numbers in plaintext logs.",
					"Log a masked or tokenized reference instead of the full license number."
				]
			});
		}

		// 7f. Database backup exposed under web root / public bucket
		const backupExposureHits = await searchRepo({
			query: String.raw`(?:public|www|static|dist|htdocs|wwwroot|assets)\/[^'"\s]*\.(?:sql|dump|bak|sqlite|db|mdb|bacpac)\b|(?:s3[^'"\s]*|bucket[^'"\s]*)\/[^'"\s]*\.(?:sql|dump|bak|sqlite)\b|(?:app\.use|express\.static|serveStatic)\s*\([^)]*(?:backup|dump|dumps|db_backup)`,
			isRegex: true,
			maxMatches: 200
		});
		if (backupExposureHits.length > 0) {
			findings.push({
				id: "DLP_DB_BACKUP_WEB_EXPOSED",
				title: "Database backup/dump file exposed under web root or public bucket",
				severity: "CRITICAL",
				sla: "24h",
				evidence: backupExposureHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(backupExposureHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Move all database backups/dumps out of the web root and out of any public bucket immediately — a single request can exfiltrate the entire database.",
					"Set the bucket/object to private (block public access) and store backups in encrypted, access-controlled storage.",
					"Rotate any credentials contained in the exposed dump and audit access logs for downloads."
				]
			});
		}

		// 7g. Data export sent unencrypted (CSV/JSON over http)
		const unencryptedExportHits = await searchRepo({
			query: String.raw`(?:fetch|axios|http\.request|got|request)\s*\(\s*['"]http:\/\/[^'"]*(?:export|report|download)[^'"]*['"]|(?:createWriteStream|writeFile|fs\.write)\s*\([^)]*\.(?:csv|json)['"][^)]*(?:export|report|dump)|(?:res\.(?:download|sendFile))\s*\([^)]*\.(?:csv|json)`,
			isRegex: true,
			maxMatches: 200
		});
		if (unencryptedExportHits.length > 0) {
			findings.push({
				id: "DLP_UNENCRYPTED_DATA_EXPORT",
				title: "Data export transmitted or written without encryption (CSV/JSON over http / plaintext file)",
				severity: "HIGH",
				sla: "7d",
				evidence: unencryptedExportHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(unencryptedExportHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Transmit data exports over HTTPS/TLS only; never POST or GET an export endpoint over plaintext http://.",
					"Encrypt export files at rest (e.g. server-side encryption or GPG) before writing them to disk or a bucket.",
					"Require authentication and short-lived signed URLs for export download links."
				]
			});
		}

		// 7h. Full URL / query params with token logged in error context
		const urlTokenLogHits = await searchRepo({
			query: String.raw`(?:console\.(?:error|warn|log)|logger\.\w+)\s*\([^)]*(?:req\.(?:originalUrl|url|fullUrl)|req\.query\b|error[^)]*\breq\.url)`,
			isRegex: true,
			maxMatches: 200
		});
		if (urlTokenLogHits.length > 0) {
			findings.push({
				id: "DLP_URL_WITH_TOKEN_LOGGED",
				title: "Full request URL / query string logged — may leak tokens or PII in query params",
				severity: "MEDIUM",
				sla: "30d",
				evidence: urlTokenLogHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(urlTokenLogHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Do not log full request URLs or query strings — tokens, session IDs, and PII are frequently passed as query parameters.",
					"Log only the route path (e.g. req.route.path) with query parameters stripped or an allowlist of safe keys.",
					"Scrub sensitive query keys (token, code, access_token, email) before logging error context."
				]
			});
		}

		// 7i. PII used in cache key
		const piiCacheKeyHits = await searchRepo({
			// Note: [\x60'"] matches a backtick (\x60), single, or double quote — a
			// literal backtick cannot appear inside this String.raw template literal.
			query: String.raw`(?:cache|redis|memcached|client)\.(?:set|setex|put|mset)\s*\(\s*[\x60'"][^\x60'"]*(?:email|ssn|phoneNumber|phone_number|passport|creditCard|card_number)[^\x60'"]*[\x60'"]`,
			isRegex: true,
			maxMatches: 200
		});
		if (piiCacheKeyHits.length > 0) {
			findings.push({
				id: "DLP_PII_IN_CACHE_KEY",
				title: "PII embedded in cache key — plaintext identifiers exposed in cache store / keyspace",
				severity: "MEDIUM",
				sla: "30d",
				evidence: piiCacheKeyHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(piiCacheKeyHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Do not put raw PII (email, SSN, phone, passport) into cache keys — keys are visible via KEYS/SCAN and monitoring tools and are rarely encrypted.",
					"Hash the identifier (e.g. SHA-256) to derive a stable, non-reversible cache key.",
					"Apply the same minimization to cache values; store only what is needed and set a TTL."
				]
			});
		}

		// 7. Server version disclosure
		//
		// The old query matched the bare string "X-Powered-By" anywhere in the repo, so a
		// security checklist saying the header should be SUPPRESSED reported the header as
		// exposed — this repository flagged its own checklist text. And the only accepted
		// mitigation was `app.disable('x-powered-by')`, so every Express app using helmet
		// (which removes the header by default) was flagged too.
		//
		// Two signals now, both context-bound: a header actually being set, and an Express
		// app that never disables the header it sets by default.
		const SUPPRESSION_CONTEXT_RE =
			/remove|delete|disable|suppress|unset|strip|hide|omit|\bno\b|helmet|false|should not|must not/i;

		const explicitSetHits = (
			await searchRepo({
				query: String.raw`(?:res|response|reply)\.(?:set|setHeader|header|writeHead)\s*\([^)]{0,60}['"](?:X-Powered-By|Server)['"]|['"]X-Powered-By['"]\s*:\s*['"]|add_header\s+(?:X-Powered-By|Server)\s|app\.set\s*\(\s*['"]x-powered-by['"]\s*,\s*true|Server:\s*(?:Express|nginx|Apache)[/ ][\d.]`,
				isRegex: true,
				maxMatches: 200
			})
		).filter((m) => !SUPPRESSION_CONTEXT_RE.test(m.preview));

		// Express sets X-Powered-By itself unless told not to, so an Express app with no
		// suppression anywhere is disclosing it even though nothing in the source says so.
		const [expressAppHits, suppressionHits] = await Promise.all([
			searchRepo({
				query: String.raw`require\s*\(\s*['"]express['"]\s*\)|from\s+['"]express['"]|express\s*\(\s*\)`,
				isRegex: true,
				maxMatches: 5
			}),
			searchRepo({
				query: String.raw`app\.disable\s*\(\s*['"]x-powered-by['"]|hidePoweredBy|helmet\s*\(|removeHeader\s*\(\s*['"](?:X-Powered-By|Server)['"]|app\.set\s*\(\s*['"]x-powered-by['"]\s*,\s*false`,
				isRegex: true,
				maxMatches: 5
			})
		]);
		const expressDefaultExposure = expressAppHits.length > 0 && suppressionHits.length === 0;

		if (explicitSetHits.length > 0 || expressDefaultExposure) {
			const evidence =
				explicitSetHits.length > 0
					? explicitSetHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`)
					: expressAppHits
							.slice(0, 3)
							.map((m) => `${m.file}:${m.line}: Express app with no x-powered-by suppression anywhere in the repo`);
			findings.push({
				id: "DLP_SERVER_HEADER_DISCLOSURE",
				title: "Server technology disclosed via X-Powered-By or Server response header",
				severity: "MEDIUM",
				evidence,
				files: [
					...new Set(
						(explicitSetHits.length > 0 ? explicitSetHits : expressAppHits).slice(0, 10).map((m) => m.file)
					)
				],
				requiredActions: [
					"Call app.disable('x-powered-by') in Express, or use helmet(), which removes the header for you.",
					"Remove or obscure Server headers — version disclosure aids attacker reconnaissance."
				]
			});
		}
	} catch (err) {
		console.warn("[checkDlp] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
