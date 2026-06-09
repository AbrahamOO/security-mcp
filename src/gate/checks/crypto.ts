/**
 * Weak cryptography detection.
 * Mapped to NIST SP 800-131A Rev 2.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";

function checkPbkdf2Iterations(hits: { file: string; line: number; preview: string }[]): import("../result.js").Finding | null {
	for (const hit of hits) {
		const iterMatch = /pbkdf2(?:Sync)?\s*\([^)]*?,\s*[^,]+,\s*(\d+)/.exec(hit.preview);
		if (!iterMatch) continue;
		const iters = Number.parseInt(iterMatch[1], 10);
		if (iters < 600000) {
			return {
				id: "CRYPTO_LOW_PBKDF2_ITERATIONS",
				title: `PBKDF2 iteration count too low (${iters} < 600,000)`,
				severity: "HIGH",
				evidence: [`${hit.file}:${hit.line}:${hit.preview}`],
				files: [hit.file],
				requiredActions: [
					"Use ≥ 600,000 iterations for PBKDF2-SHA256 (OWASP 2023 recommendation).",
					"Prefer bcrypt (cost ≥ 12) or Argon2id instead."
				]
			};
		}
	}
	return null;
}

async function checkAesCbcUnauthenticated(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Primary: string literal match
	const cbcLiteralHits = await searchRepo({
		query: String.raw`createCipheriv\s*\(\s*['"]aes-(?:128|192|256)-cbc['"]`,
		isRegex: true,
		maxMatches: 200
	});

	// Secondary: detect concatenated or dynamic AES-CBC strings that evade the
	// string-literal regex (e.g. 'aes-' + '256-cbc', `aes-${bits}-cbc`).
	// CWE-327 evasion via string concatenation is a documented bypass technique.
	const cbcConcatHits = await searchRepo({
		query: String.raw`createCipheriv\s*\([^)]*['"\x60][^)]*-cbc['"\x60]|['"]aes-['"].*cbc|['"\x60].*-cbc['"\x60].*createCipheriv`,
		isRegex: true,
		maxMatches: 200
	});

	const cbcHits = [
		...cbcLiteralHits,
		...cbcConcatHits.filter((h) => !cbcLiteralHits.some((l) => l.file === h.file && l.line === h.line))
	];

	if (cbcHits.length === 0) return findings;

	// Check for HMAC authentication near AES-CBC usage
	const hmacHits = await searchRepo({
		query: String.raw`createHmac|hmac\.digest|crypto\.sign|authenticate`,
		isRegex: true,
		maxMatches: 200
	});

	// If AES-CBC is used and no HMAC found anywhere nearby, flag it
	const hmacFiles = new Set(hmacHits.map((m) => m.file));
	const unauthenticated = cbcHits.filter((m) => !hmacFiles.has(m.file));

	if (unauthenticated.length > 0) {
		findings.push({
			id: "CRYPTO_AES_CBC_NO_AUTH",
			title: "AES-CBC without HMAC authentication is vulnerable to padding oracle attacks. Use AES-256-GCM instead.",
			severity: "CRITICAL",
			evidence: unauthenticated.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(unauthenticated.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Replace createCipheriv('aes-256-cbc') with createCipheriv('aes-256-gcm') and use the GCM authentication tag"
			]
		});
	}

	return findings;
}

async function checkGcmNonceReuse(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const gcmHits = await searchRepo({
		query: String.raw`createCipheriv\s*\(\s*['"]aes-(?:128|192|256)-gcm['"]`,
		isRegex: true,
		maxMatches: 200
	});

	if (gcmHits.length === 0) return findings;

	// Check for nonce reuse patterns
	const nonceReuseHits = await searchRepo({
		query: String.raw`(?:let|var)\s+(?:iv|nonce|counter)\s*=|iv\+\+|nonce\+\+|counter\+\+|iv\s*\+=|nonce\s*\+=|Date\.now\(\)|new Date\(\)|performance\.now`,
		isRegex: true,
		maxMatches: 200
	});

	const gcmFiles = new Set(gcmHits.map((m) => m.file));
	const reuseInGcmFiles = nonceReuseHits.filter((m) => gcmFiles.has(m.file));

	if (reuseInGcmFiles.length > 0) {
		findings.push({
			id: "CRYPTO_GCM_NONCE_REUSE_RISK",
			title: "GCM nonce reuse risk detected — mutable or time-based IV/nonce near AES-GCM cipher",
			severity: "CRITICAL",
			evidence: reuseInGcmFiles.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(reuseInGcmFiles.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Generate a fresh random 12-byte nonce for every encryption with crypto.randomBytes(12).",
				"GCM nonce reuse completely breaks confidentiality and authentication."
			]
		});
	}

	// Check for missing crypto.randomBytes near GCM usage
	const randomBytesHits = await searchRepo({
		query: String.raw`crypto\.randomBytes`,
		isRegex: true,
		maxMatches: 200
	});

	const randomBytesFiles = new Set(randomBytesHits.map((m) => m.file));
	const gcmWithoutRandom = gcmHits.filter((m) => !randomBytesFiles.has(m.file));

	if (gcmWithoutRandom.length > 0) {
		findings.push({
			id: "CRYPTO_GCM_NO_RANDOM_NONCE",
			title: "AES-GCM used without crypto.randomBytes for nonce generation",
			severity: "HIGH",
			evidence: gcmWithoutRandom.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(gcmWithoutRandom.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Use crypto.randomBytes(12) to generate a random 12-byte nonce for each AES-GCM encryption.",
				"Never use a fixed, sequential, or time-based nonce with GCM."
			]
		});
	}

	// Check for module-level (top-scope) nonce/iv assigned from randomBytes — reused across calls.
	// Pattern: const/let iv = (crypto.)randomBytes(...) appearing at module scope (not inside a function).
	// Heuristic: the assignment is not indented (or indented only by whitespace without a function keyword
	// on the same line), combined with GCM usage in the same file.
	const moduleLevelNonceHits = await searchRepo({
		query: String.raw`^(?:const|let|var)\s+(?:iv|nonce|counter)\s*=\s*(?:crypto\.)?randomBytes\s*\(`,
		isRegex: true,
		maxMatches: 200
	});
	const moduleLevelInGcmFiles = moduleLevelNonceHits.filter((m) => gcmFiles.has(m.file));
	if (moduleLevelInGcmFiles.length > 0) {
		findings.push({
			id: "CRYPTO_GCM_MODULE_LEVEL_NONCE",
			title: "AES-GCM nonce generated at module scope — nonce is reused across all encrypt calls",
			severity: "CRITICAL",
			evidence: moduleLevelInGcmFiles.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(moduleLevelInGcmFiles.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Move crypto.randomBytes(12) inside the encryption function so a fresh nonce is generated per call.",
				"A module-level nonce is initialised once and reused — GCM nonce reuse completely breaks confidentiality and authentication (CWE-329)."
			]
		});
	}

	return findings;
}

async function checkRsaPaddingScheme(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const rsaHits = await searchRepo({
		query: String.raw`crypto\.publicEncrypt|crypto\.privateDecrypt`,
		isRegex: true,
		maxMatches: 200
	});

	if (rsaHits.length === 0) return findings;

	// Check for explicit OAEP padding
	const oaepHits = await searchRepo({
		query: String.raw`RSA_PKCS1_OAEP_PADDING|oaepHash`,
		isRegex: true,
		maxMatches: 200
	});

	// Check for explicit PKCS1 v1.5 padding
	const pkcs1Hits = await searchRepo({
		query: String.raw`RSA_PKCS1_PADDING|'pkcs1'|padding.*PKCS1`,
		isRegex: true,
		maxMatches: 200
	});

	const oaepFiles = new Set(oaepHits.map((m) => m.file));
	const rsaWithoutOaep = rsaHits.filter((m) => !oaepFiles.has(m.file));

	if (rsaWithoutOaep.length > 0 || pkcs1Hits.length > 0) {
		const allEvidence = [...rsaWithoutOaep, ...pkcs1Hits].slice(0, 10);
		findings.push({
			id: "CRYPTO_RSA_PKCS1_PADDING",
			title: "RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks. Use RSA-OAEP padding: { key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }",
			severity: "HIGH",
			evidence: allEvidence.map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(allEvidence.map((m) => m.file))],
			requiredActions: [
				"Pass an options object with padding: crypto.constants.RSA_PKCS1_OAEP_PADDING to publicEncrypt/privateDecrypt.",
				"The default RSA padding (PKCS#1 v1.5) is vulnerable to adaptive chosen-ciphertext attacks."
			]
		});
	}

	return findings;
}

async function checkShaUsedForPassword(weakHashHits: { file: string; line: number; preview: string }[]): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Detect SHA-256/384/512 used in password context
	const shaPasswordHits = await searchRepo({
		query: String.raw`createHash\s*\(\s*['"]sha(?:256|384|512|2)['"]`,
		isRegex: true,
		maxMatches: 200
	});

	if (shaPasswordHits.length === 0) return findings;

	const passwordContextRe = /password|passwd|pwd|credential/i;
	const shaPasswordContext = shaPasswordHits.filter((m) => passwordContextRe.test(m.preview));

	// Also search for direct pattern: createHash('sha256').update(password
	const directPatternHits = await searchRepo({
		query: String.raw`createHash\s*\(\s*['"]sha(?:256|384|512)['"]\s*\)\.update\s*\(\s*(?:password|passwd|pwd)`,
		isRegex: true,
		maxMatches: 200
	});

	const combined = [...shaPasswordContext, ...directPatternHits];
	const unique = combined.filter((m, i, arr) => arr.findIndex((x) => x.file === m.file && x.line === m.line) === i);

	if (unique.length > 0) {
		findings.push({
			id: "CRYPTO_SHA_USED_FOR_PASSWORD",
			title: "SHA-256/SHA-512 are fast hash functions unsuitable for password storage. Use bcrypt, argon2, or scrypt.",
			severity: "HIGH",
			evidence: unique.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(unique.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Replace SHA-based password hashing with bcrypt (cost ≥ 12), argon2id, or scrypt.",
				"Fast hash functions allow billions of guesses per second with GPU hardware."
			]
		});
	}

	return findings;
}

async function checkHardcodedSalt(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const hardcodedSaltHits = await searchRepo({
		query: String.raw`pbkdf2(?:Sync)?\s*\([^,]+,\s*(?:['"][^'"]{1,}['"]|Buffer\.from\s*\(\s*['"][^'"]+['"]\s*\))`,
		isRegex: true,
		maxMatches: 200
	});

	if (hardcodedSaltHits.length > 0) {
		findings.push({
			id: "CRYPTO_PBKDF2_HARDCODED_SALT",
			title: "Hardcoded salt makes PBKDF2 equivalent to an unsalted hash. Generate a unique random salt per user with crypto.randomBytes(32).",
			severity: "HIGH",
			evidence: hardcodedSaltHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(hardcodedSaltHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Replace the hardcoded salt with crypto.randomBytes(32) generated uniquely per user.",
				"Store the random salt alongside the hash in the database."
			]
		});
	}

	return findings;
}

async function checkTlsConfig(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Check for weak TLS minimum version
	const weakTlsHits = await searchRepo({
		query: String.raw`minVersion\s*:\s*['"]TLSv1(?:\.[01])?['"]|secureProtocol\s*:\s*['"](?:SSLv3|TLSv1)_method['"]`,
		isRegex: true,
		maxMatches: 200
	});

	if (weakTlsHits.length > 0) {
		findings.push({
			id: "TLS_WEAK_MIN_VERSION",
			title: "TLS 1.0/1.1 or SSL configured as minimum version — insecure protocol",
			severity: "HIGH",
			evidence: weakTlsHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(weakTlsHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Set minVersion: 'TLSv1.2' or 'TLSv1.3' in TLS/HTTPS server configuration.",
				"TLS 1.0 and 1.1 are deprecated by RFC 8996 and prohibited by PCI DSS 4.0."
			]
		});
	}

	// Check for disabled certificate verification
	const rejectUnauthorizedHits = await searchRepo({
		query: String.raw`rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]`,
		isRegex: true,
		maxMatches: 200
	});

	if (rejectUnauthorizedHits.length > 0) {
		findings.push({
			id: "TLS_REJECT_UNAUTHORIZED_DISABLED",
			title: "rejectUnauthorized: false disables TLS certificate verification, enabling MITM attacks.",
			severity: "HIGH",
			evidence: rejectUnauthorizedHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(rejectUnauthorizedHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Remove rejectUnauthorized: false and fix the underlying certificate issue.",
				"If using a self-signed cert, add it via the ca option rather than disabling verification."
			]
		});
	}

	return findings;
}

async function checkZeroFilledIv(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const zeroIvHits = await searchRepo({
		query: String.raw`(?:Buffer\.alloc\s*\(\s*(?:8|12|16|24|32)\s*\)|new\s+Uint8Array\s*\(\s*(?:8|12|16|24|32)\s*\))[^\n]*(?:iv|IV|nonce|Nonce)`,
		isRegex: true,
		maxMatches: 200
	});

	const zeroIvAssignHits = await searchRepo({
		query: String.raw`(?:iv|nonce)\s*=\s*Buffer\.alloc\s*\(`,
		isRegex: true,
		maxMatches: 200
	});

	const combined = [
		...zeroIvHits,
		...zeroIvAssignHits.filter((h) => !zeroIvHits.some((l) => l.file === h.file && l.line === h.line))
	];

	if (combined.length > 0) {
		findings.push({
			id: "CRYPTO_ZERO_IV",
			title: "Zero-filled IV or nonce (Buffer.alloc creates all-zeros) — deterministic IV breaks cipher security (CWE-330)",
			severity: "CRITICAL",
			evidence: combined.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(combined.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Replace Buffer.alloc(n) with crypto.randomBytes(n) for IV/nonce generation.",
				"A zero-filled IV is equivalent to a hardcoded IV — every encryption with the same key produces the same ciphertext."
			]
		});
	}

	return findings;
}

async function checkWeakRsaKeySize(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const weakRsaHits = await searchRepo({
		query: String.raw`modulusLength\s*:\s*(?:512|768|1536)`,
		isRegex: true,
		maxMatches: 200
	});

	if (weakRsaHits.length > 0) {
		findings.push({
			id: "CRYPTO_RSA_WEAK_KEY",
			title: "RSA key size 512/768/1536 bits — sub-2048 keys factorable with commodity hardware (CWE-326)",
			severity: "CRITICAL",
			evidence: weakRsaHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(weakRsaHits.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Use a minimum modulusLength of 2048; prefer 4096 for long-lived keys.",
				"Keys below 2048 bits can be factored with commodity hardware and are prohibited by NIST SP 800-131A Rev 2."
			]
		});
	}

	return findings;
}

async function checkWeakDhParams(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const weakDhSizeHits = await searchRepo({
		query: String.raw`createDiffieHellman\s*\(\s*(?:[0-9]{1,3}|1[0-9]{3}|[5-9][0-9]{2})\s*[,)]`,
		isRegex: true,
		maxMatches: 200
	});

	const weakDhGroupHits = await searchRepo({
		query: String.raw`createDiffieHellmanGroup\s*\(\s*['"]modp(?:1|2|5)['"]`,
		isRegex: true,
		maxMatches: 200
	});

	const combined = [
		...weakDhSizeHits,
		...weakDhGroupHits.filter((h) => !weakDhSizeHits.some((l) => l.file === h.file && l.line === h.line))
	];

	if (combined.length > 0) {
		findings.push({
			id: "CRYPTO_WEAK_DH_PARAMS",
			title: "DH parameters below 2048 bits or weak group (modp1/2/5) — vulnerable to Logjam precomputation (CWE-326)",
			severity: "HIGH",
			evidence: combined.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(combined.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Use createDiffieHellmanGroup('modp14') or higher (modp14 = 2048-bit), or prefer ECDH with P-256 or P-384.",
				"modp1/2/5 and DH groups below 2048 bits are broken by Logjam-style precomputation attacks."
			]
		});
	}

	return findings;
}

async function checkMissingForwardSecrecy(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const weakCipherSuiteHits = await searchRepo({
		query: String.raw`ciphers\s*:\s*['"][^'"]*(?:TLS_RSA_WITH|RC4|NULL|EXPORT|!ECDHE|!DHE)[^'"]*['"]`,
		isRegex: true,
		maxMatches: 200
	});

	const honorCipherOrderHits = await searchRepo({
		query: String.raw`honorCipherOrder\s*:\s*false`,
		isRegex: true,
		maxMatches: 200
	});

	const combined = [
		...weakCipherSuiteHits,
		...honorCipherOrderHits.filter((h) => !weakCipherSuiteHits.some((l) => l.file === h.file && l.line === h.line))
	];

	if (combined.length > 0) {
		findings.push({
			id: "CRYPTO_NO_FORWARD_SECRECY",
			title: "TLS cipher suite config without forward secrecy (no ECDHE/DHE) — retroactive decryption possible (PCI DSS 4.0)",
			severity: "HIGH",
			evidence: combined.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(combined.slice(0, 10).map((m) => m.file))],
			requiredActions: [
				"Configure ciphers to prefer ECDHE or DHE key exchange (e.g. 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256').",
				"Set honorCipherOrder: true so the server's cipher preference (which should list ECDHE first) takes effect.",
				"Without forward secrecy, a compromised private key retroactively decrypts all recorded sessions (PCI DSS 4.0 requirement 4.2.1)."
			]
		});
	}

	return findings;
}

export async function checkCrypto(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		// 1. Weak hash algorithms
		const weakHashHits = await searchRepo({
			query: String.raw`createHash\s*\(\s*['"](?:md5|sha1|sha-1)['"]\s*\)|hashlib\.md5|hashlib\.sha1|DigestUtils\.md5`,
			isRegex: true,
			maxMatches: 200
		});
		if (weakHashHits.length > 0) {
			findings.push({
				id: "CRYPTO_WEAK_HASH",
				title: "Weak hash algorithm (MD5/SHA-1) detected",
				severity: "HIGH",
				evidence: weakHashHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(weakHashHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Use SHA-256 minimum (SHA-3 recommended for new code).",
					"MD5/SHA-1 are broken for security purposes (NIST SP 800-131A Rev 2)."
				]
			});
		}

		// SHA-256/512 used for password hashing (extends weak hash check)
		const shaPasswordFindings = await checkShaUsedForPassword(weakHashHits);
		findings.push(...shaPasswordFindings);

		// 2. Weak symmetric ciphers
		const weakCipherHits = await searchRepo({
			query: String.raw`createCipheriv\s*\(\s*['"](?:des|rc4|rc2|blowfish|3des|des-ede)['"]\)|Cipher\.getInstance\(['"](?:DES|RC4|RC2|Blowfish)['"]`,
			isRegex: true,
			maxMatches: 200
		});
		if (weakCipherHits.length > 0) {
			findings.push({
				id: "CRYPTO_WEAK_CIPHER",
				title: "Weak symmetric cipher (DES/RC4/3DES) detected",
				severity: "CRITICAL",
				evidence: weakCipherHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(weakCipherHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Use AES-256-GCM for symmetric encryption.",
					"DES/RC4/3DES are prohibited by NIST SP 800-131A Rev 2."
				]
			});
		}

		// 3. Insecure random — security-specific contexts (CRITICAL)
		const insecureRandomHits = await searchRepo({
			query: String.raw`Math\.random\(\)|random\.random\(\)|rand\(\)|srand\(`,
			isRegex: true,
			maxMatches: 200
		});
		const securityContextRe = /token|key|secret|password|nonce|salt|csrf|session/i;
		const identifierContextRe = /id|path|url|upload|order|invoice|coupon|code|ref|link|hash/i;

		const insecureSecRandom = insecureRandomHits.filter((m) => securityContextRe.test(m.preview));
		if (insecureSecRandom.length > 0) {
			findings.push({
				id: "CRYPTO_INSECURE_RANDOM",
				title: "Non-cryptographic random used in security-sensitive context",
				severity: "CRITICAL",
				evidence: insecureSecRandom.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(insecureSecRandom.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Use crypto.randomBytes() (Node.js) for security-sensitive randomness.",
					"Math.random() is not cryptographically secure and must never be used for tokens, keys, or nonces."
				]
			});
		}

		// Insecure random — identifier/path contexts (HIGH)
		const insecureIdentifierRandom = insecureRandomHits.filter(
			(m) => !securityContextRe.test(m.preview) && identifierContextRe.test(m.preview)
		);
		if (insecureIdentifierRandom.length > 0) {
			findings.push({
				id: "CRYPTO_INSECURE_RANDOM_IDENTIFIER",
				title: "Non-cryptographic random used to generate identifiers or paths — predictable IDs enable enumeration attacks",
				severity: "HIGH",
				evidence: insecureIdentifierRandom.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(insecureIdentifierRandom.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Use crypto.randomBytes() or crypto.randomUUID() for generating IDs, paths, and codes.",
					"Predictable identifiers enable IDOR and enumeration attacks."
				]
			});
		}

		// 4. Weak JWT algorithm
		const weakJwtHits = await searchRepo({
			query: String.raw`algorithm\s*[:=]\s*['"]HS(?:256|384|512)['"]|sign\(.*['"]HS256['"]`,
			isRegex: true,
			maxMatches: 200
		});
		if (weakJwtHits.length > 0) {
			findings.push({
				id: "CRYPTO_WEAK_JWT_ALGO",
				title: "HS256/HS384/HS512 JWT algorithm detected — symmetric key shared with all verifiers",
				severity: "HIGH",
				evidence: weakJwtHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(weakJwtHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Use RS256 or ES256 for stateless JWTs.",
					"HS256 requires sharing the secret with every verifier — use asymmetric algorithms instead."
				]
			});
		}

		// 5. Low PBKDF2 iterations
		const pbkdf2Hits = await searchRepo({
			query: String.raw`pbkdf2(?:Sync)?\s*\(`,
			isRegex: true,
			maxMatches: 200
		});
		const pbkdf2Finding = checkPbkdf2Iterations(pbkdf2Hits);
		if (pbkdf2Finding) findings.push(pbkdf2Finding);

		// Hardcoded PBKDF2 salt
		const hardcodedSaltFindings = await checkHardcodedSalt();
		findings.push(...hardcodedSaltFindings);

		// 6. Hardcoded IV/nonce
		const hardcodedIvHits = await searchRepo({
			query: String.raw`iv\s*[:=]\s*(?:Buffer\.from\(['"][0-9a-fA-F]+['"]\)|['"][0-9a-fA-F]{16,}['"])`,
			isRegex: true,
			maxMatches: 200
		});
		if (hardcodedIvHits.length > 0) {
			findings.push({
				id: "CRYPTO_HARDCODED_IV",
				title: "Hardcoded IV/nonce detected in cryptographic operation",
				severity: "CRITICAL",
				evidence: hardcodedIvHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(hardcodedIvHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Always generate a random IV/nonce using crypto.randomBytes(16) for AES-CBC.",
					"Use a 12-byte nonce for AES-GCM; never reuse IVs."
				]
			});
		}

		// 7. ECB mode
		const ecbModeHits = await searchRepo({
			query: String.raw`createCipheriv\s*\(\s*['"][^'"]*-ecb['"]|AES\/ECB|Cipher\.getInstance\(['"][^'"]*ECB['"]`,
			isRegex: true,
			maxMatches: 200
		});
		if (ecbModeHits.length > 0) {
			findings.push({
				id: "CRYPTO_ECB_MODE",
				title: "ECB cipher mode detected — leaks plaintext patterns",
				severity: "CRITICAL",
				evidence: ecbModeHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(ecbModeHits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Replace ECB mode with AES-256-GCM (authenticated encryption).",
					"ECB mode leaks plaintext patterns because identical blocks produce identical ciphertext."
				]
			});
		}

		// 8. Post-quantum readiness: RSA-1024
		const rsa1024Hits = await searchRepo({
			query: String.raw`modulusLength\s*:\s*1024|generateKeyPair\s*\(\s*['"]rsa['"][^)]*1024`,
			isRegex: true,
			maxMatches: 200
		});
		if (rsa1024Hits.length > 0) {
			findings.push({
				id: "CRYPTO_RSA_1024",
				title: "RSA-1024 key detected — cryptographically broken",
				severity: "CRITICAL",
				evidence: rsa1024Hits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(rsa1024Hits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Upgrade to RSA-4096 minimum, or migrate to ML-DSA (FIPS 204) / SLH-DSA (FIPS 205) for new key material.",
					"RSA-1024 is fully broken — NIST deprecated it in 2013 (SP 800-131A).",
					"For TLS certificates, reissue with RSA-4096 or ECDSA P-384 immediately."
				]
			});
		}

		// 9. Post-quantum readiness: RSA-2048 warning
		const rsa2048Hits = await searchRepo({
			query: String.raw`modulusLength\s*:\s*2048|generateKeyPair\s*\(\s*['"]rsa['"][^)]*2048`,
			isRegex: true,
			maxMatches: 200
		});
		if (rsa2048Hits.length > 0) {
			findings.push({
				id: "CRYPTO_RSA_2048_PQC",
				title: "RSA-2048 detected — quantum-vulnerable; plan migration to post-quantum algorithms",
				severity: "MEDIUM",
				evidence: rsa2048Hits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(rsa2048Hits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"RSA-2048 is currently secure against classical computers but will be broken by sufficiently large quantum computers.",
					"NIST finalized post-quantum standards in 2024: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).",
					"For long-lived keys or data requiring 10+ year secrecy: migrate to ML-DSA or use a hybrid classical+PQC scheme."
				]
			});
		}

		// 10. Post-quantum readiness: ECDSA P-256 (informational)
		const p256Hits = await searchRepo({
			query: String.raw`prime256v1|secp256r1|namedCurve\s*:\s*['"]P-256['"]|namedCurve\s*:\s*['"]p256['"]`,
			isRegex: true,
			maxMatches: 200
		});
		if (p256Hits.length > 0) {
			findings.push({
				id: "CRYPTO_ECDSA_P256_PQC",
				title: "ECDSA P-256 detected — quantum-vulnerable in the long term",
				severity: "LOW",
				evidence: p256Hits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(p256Hits.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"P-256 (secp256r1) is secure today but vulnerable to Shor's algorithm on a sufficiently large quantum computer.",
					"NIST post-quantum signature standards: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) are the recommended replacements.",
					"For new systems handling sensitive long-lived data, evaluate hybrid ECDSA+ML-DSA or pure ML-DSA."
				]
			});
		}

		// 11. AES-CBC without authentication (padding oracle)
		const aesCbcFindings = await checkAesCbcUnauthenticated();
		findings.push(...aesCbcFindings);

		// 12. GCM nonce reuse
		const gcmNonceFindings = await checkGcmNonceReuse();
		findings.push(...gcmNonceFindings);

		// 13. RSA PKCS#1 v1.5 padding
		const rsaPaddingFindings = await checkRsaPaddingScheme();
		findings.push(...rsaPaddingFindings);

		// 14. TLS configuration weaknesses
		const tlsFindings = await checkTlsConfig();
		findings.push(...tlsFindings);

		// 15. Zero-filled IV/nonce
		const zeroIvFindings = await checkZeroFilledIv();
		findings.push(...zeroIvFindings);

		// 16. Weak RSA key sizes (512/768/1536)
		const weakRsaKeyFindings = await checkWeakRsaKeySize();
		findings.push(...weakRsaKeyFindings);

		// 17. Weak DH parameters or named groups
		const weakDhFindings = await checkWeakDhParams();
		findings.push(...weakDhFindings);

		// 18. Missing forward secrecy in TLS cipher config
		const forwardSecrecyFindings = await checkMissingForwardSecrecy();
		findings.push(...forwardSecrecyFindings);
	} catch (err) {
		console.warn("[checkCrypto] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
