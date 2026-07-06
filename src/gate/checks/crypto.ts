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

async function checkShaUsedForPassword(_weakHashHits: { file: string; line: number; preview: string }[]): Promise<Finding[]> {
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

async function checkStaticIvReused(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Cipher usage that consumes an IV/nonce.
	const cipherHits = await searchRepo({
		query: String.raw`createCipheriv\s*\(|createDecipheriv\s*\(`,
		isRegex: true,
		maxMatches: 200
	});
	if (cipherHits.length === 0) return findings;
	const cipherFiles = new Set(cipherHits.map((m) => m.file));

	// Module-scope (unindented) const/let IV/nonce assigned once and reused across calls.
	const moduleScopeIvHits = await searchRepo({
		query: String.raw`^(?:const|let|var)\s+(?:iv|nonce|IV|NONCE)\b\s*=`,
		isRegex: true,
		maxMatches: 200
	});
	const staticInCipherFiles = moduleScopeIvHits.filter(
		(m) => cipherFiles.has(m.file) && !/crypto\.randomBytes|randomFillSync|getRandomValues/i.test(m.preview)
	);

	if (staticInCipherFiles.length > 0) {
		findings.push({
			id: "CRYPTO_STATIC_IV_REUSED",
			title: "IV/nonce defined at module scope and reused across every encryption — deterministic IV breaks confidentiality (CWE-329/CWE-323)",
			severity: "CRITICAL",
			evidence: staticInCipherFiles.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(staticInCipherFiles.slice(0, 10).map((m) => m.file))],
			sla: "24h",
			requiredActions: [
				"Generate a fresh IV/nonce per message inside the encryption function with crypto.randomBytes() and prepend it to the ciphertext.",
				"CWE-329/CWE-323 — a constant IV means identical plaintexts encrypt to identical ciphertexts, and for CTR/GCM/stream modes IV+key reuse leaks the keystream entirely.",
				"Fix: function encrypt(pt){ const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', key, iv); /* store iv with output */ }"
			]
		});
	}

	return findings;
}

async function checkStreamCipherNonceReuse(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// ChaCha20 / stream cipher usage.
	const streamHits = await searchRepo({
		query: String.raw`createCipheriv\s*\(\s*['"](?:chacha20-poly1305|chacha20|rc4|aes-128-ctr|aes-192-ctr|aes-256-ctr)['"]`,
		isRegex: true,
		maxMatches: 200
	});
	if (streamHits.length === 0) return findings;
	const streamFiles = new Set(streamHits.map((m) => m.file));

	// Static / non-random nonce in the same file: module-scope const, hardcoded buffer, or Buffer.alloc.
	const staticNonceHits = await searchRepo({
		query: String.raw`^(?:const|let|var)\s+(?:nonce|iv|counter)\b\s*=|(?:nonce|iv)\s*=\s*Buffer\.(?:from|alloc)\s*\(|(?:nonce|iv)\s*=\s*['"][0-9a-fA-F]{8,}['"]`,
		isRegex: true,
		maxMatches: 200
	});
	const reused = staticNonceHits.filter(
		(m) => streamFiles.has(m.file) && !/crypto\.randomBytes|randomFillSync|getRandomValues/i.test(m.preview)
	);

	if (reused.length > 0) {
		findings.push({
			id: "CRYPTO_STREAM_NONCE_REUSE",
			title: "ChaCha20/stream-cipher nonce appears static or reused with the same key — keystream reuse breaks the cipher (CWE-323)",
			severity: "CRITICAL",
			evidence: reused.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(reused.slice(0, 10).map((m) => m.file))],
			sla: "24h",
			requiredActions: [
				"Use a unique random nonce per message for ChaCha20/CTR/RC4-class ciphers with crypto.randomBytes(); never reuse a (key, nonce) pair.",
				"CWE-323 — reusing a nonce with the same key produces the same keystream; XORing two ciphertexts then recovers both plaintexts and, for Poly1305, forges tags.",
				"Fix: const nonce = crypto.randomBytes(12); const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });"
			]
		});
	}

	return findings;
}

async function checkAeadTagNotVerified(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// GCM/ChaCha-Poly decryption usage.
	const decHits = await searchRepo({
		query: String.raw`createDecipheriv\s*\(\s*['"](?:aes-(?:128|192|256)-gcm|chacha20-poly1305)['"]`,
		isRegex: true,
		maxMatches: 200
	});
	if (decHits.length === 0) return findings;

	// setAuthTag must be present for the tag to be checked at all.
	const setAuthTagHits = await searchRepo({
		query: String.raw`setAuthTag\s*\(`,
		isRegex: true,
		maxMatches: 200
	});
	const tagVerifiedFiles = new Set(setAuthTagHits.map((m) => m.file));

	const noTag = decHits.filter((m) => !tagVerifiedFiles.has(m.file));
	if (noTag.length > 0) {
		findings.push({
			id: "CRYPTO_AEAD_TAG_NOT_VERIFIED",
			title: "AEAD (GCM/ChaCha-Poly) decryption without setAuthTag — authentication tag never verified before using plaintext (CWE-347/CWE-354)",
			severity: "CRITICAL",
			evidence: noTag.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(noTag.slice(0, 10).map((m) => m.file))],
			sla: "24h",
			requiredActions: [
				"Call decipher.setAuthTag(tag) before final(), and treat the error thrown by final() as an authentication failure — never use plaintext that failed the tag check.",
				"CWE-347/CWE-354 — without setAuthTag the GCM/Poly1305 tag is not checked, so an attacker can tamper with ciphertext and the app will act on forged plaintext (defeating AEAD entirely).",
				"Fix: decipher.setAuthTag(tag); let pt; try { pt = Buffer.concat([decipher.update(ct), decipher.final()]); } catch { throw new Error('Auth failed'); }"
			]
		});
	}

	return findings;
}

async function checkInsecureRngForCryptoMaterial(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const mathRandomHits = await searchRepo({
		query: String.raw`Math\.random\s*\(\s*\)`,
		isRegex: true,
		maxMatches: 200
	});
	if (mathRandomHits.length === 0) return findings;

	// Require crypto-material context on the same line to keep FPs low.
	const materialRe = /\biv\b|nonce|salt|\bkey\b|secret|token|seed|password/i;
	const unsafe = mathRandomHits.filter((m) => materialRe.test(m.preview));
	if (unsafe.length > 0) {
		findings.push({
			id: "CRYPTO_INSECURE_RNG_MATERIAL",
			title: "Math.random() used to derive IV/nonce/salt/key/token — non-cryptographic RNG for keying material (CWE-338)",
			severity: "CRITICAL",
			evidence: unsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(unsafe.slice(0, 10).map((m) => m.file))],
			sla: "24h",
			requiredActions: [
				"Replace Math.random() with crypto.randomBytes() (or crypto.getRandomValues in the browser) for all IVs, nonces, salts, keys, and tokens.",
				"CWE-338 — Math.random() is a predictable PRNG whose internal state can be recovered from a few outputs, letting an attacker reconstruct the keying material.",
				"Fix: const iv = crypto.randomBytes(12); const salt = crypto.randomBytes(16);"
			]
		});
	}

	return findings;
}

async function checkHardcodedSymmetricKey(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// AES/symmetric key assigned from a hex or base64 literal of key-plausible length.
	const hexKeyHits = await searchRepo({
		query: String.raw`(?:key|secretKey|encryptionKey|aesKey|symmetricKey)\s*[:=][^'"\n]{0,24}['"][0-9a-fA-F]{32,}['"]`,
		isRegex: true,
		maxMatches: 200
	});
	const b64KeyHits = await searchRepo({
		query: String.raw`(?:key|secretKey|encryptionKey|aesKey|symmetricKey)\s*[:=][^'"\n]{0,24}['"][A-Za-z0-9+/]{40,}={0,2}['"]`,
		isRegex: true,
		maxMatches: 200
	});
	const combined = [
		...hexKeyHits,
		...b64KeyHits.filter((h) => !hexKeyHits.some((l) => l.file === h.file && l.line === h.line))
	];
	// Require symmetric-crypto context somewhere in the repo to reduce FPs on unrelated hex blobs.
	const symCtxHits = await searchRepo({
		query: String.raw`createCipheriv|createDecipheriv|createHmac|aes-(?:128|192|256)`,
		isRegex: true,
		maxMatches: 200
	});
	const symFiles = new Set(symCtxHits.map((m) => m.file));
	const unsafe = combined.filter((m) => symFiles.has(m.file));

	if (unsafe.length > 0) {
		findings.push({
			id: "CRYPTO_HARDCODED_SYMMETRIC_KEY",
			title: "Symmetric encryption key hardcoded as a hex/base64 literal — key exposed in source (CWE-798/CWE-321)",
			severity: "CRITICAL",
			evidence: unsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(unsafe.slice(0, 10).map((m) => m.file))],
			sla: "24h",
			requiredActions: [
				"Load symmetric keys from a KMS/secrets manager or an environment variable at runtime; never embed key bytes in source.",
				"CWE-798/CWE-321 — a hardcoded key is recoverable from source, git history, and compiled bundles, so anyone with the code can decrypt all data protected by it.",
				"Fix: const key = Buffer.from(process.env.AES_KEY_HEX!, 'hex'); // rotate the leaked key immediately"
			]
		});
	}

	return findings;
}

async function checkTruncatedHmac(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// HMAC digest sliced/substr'd to fewer than 16 bytes.
	// Hex slice < 32 chars, or byte slice < 16 on an hmac digest.
	const hmacHits = await searchRepo({
		query: String.raw`createHmac\s*\(`,
		isRegex: true,
		maxMatches: 200
	});
	if (hmacHits.length === 0) return findings;
	const hmacFiles = new Set(hmacHits.map((m) => m.file));

	const sliceHits = await searchRepo({
		query: String.raw`\.digest\s*\([^)]*\)\s*\.(?:slice|substring|substr)\s*\(\s*0\s*,\s*([0-9]|1[0-5]|2[0-9]|3[01])\s*\)|\.(?:slice|substring|substr)\s*\(\s*0\s*,\s*([0-9]|1[0-5])\s*\)[^\n]*hmac`,
		isRegex: true,
		maxMatches: 200
	});
	// Truncation is only weak when the resulting length is < 16 bytes. For hex output that is < 32 chars.
	const unsafe = sliceHits.filter((m) => {
		if (!hmacFiles.has(m.file) && !/hmac|digest/i.test(m.preview)) return false;
		const nums = [...m.preview.matchAll(/\.(?:slice|substring|substr)\s*\(\s*0\s*,\s*(\d+)\s*\)/g)].map((x) => Number(x[1]));
		if (!nums.length) return false;
		const n = Math.min(...nums);
		const isHex = /hex/i.test(m.preview);
		// hex: < 32 chars = < 16 bytes; raw/byte: < 16
		return isHex ? n < 32 : n < 16;
	});

	if (unsafe.length > 0) {
		findings.push({
			id: "CRYPTO_TRUNCATED_HMAC",
			title: "HMAC output truncated to fewer than 16 bytes — reduced forgery resistance (CWE-328)",
			severity: "MEDIUM",
			evidence: unsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(unsafe.slice(0, 10).map((m) => m.file))],
			sla: "30d",
			requiredActions: [
				"Keep at least 128 bits (16 bytes) of the HMAC output; use the full digest for authentication tags unless a standard specifies otherwise.",
				"CWE-328 — truncating an HMAC below 128 bits lowers the effort to forge a valid tag and weakens the authentication guarantee.",
				"Fix: const tag = crypto.createHmac('sha256', key).update(msg).digest(); // compare the full tag with timingSafeEqual"
			]
		});
	}

	return findings;
}

async function checkWeakEcdsaCurve(): Promise<Finding[]> {
	const findings: Finding[] = [];

	const weakCurveHits = await searchRepo({
		query: String.raw`secp192r1|prime192v1|namedCurve\s*[:=]\s*['"]P-192['"]|namedCurve\s*[:=]\s*['"]p192['"]|secp192k1|secp160r1`,
		isRegex: true,
		maxMatches: 200
	});

	if (weakCurveHits.length > 0) {
		findings.push({
			id: "CRYPTO_WEAK_ECDSA_CURVE",
			title: "Weak elliptic curve (P-192/secp192r1 or smaller) — below the 128-bit security floor (CWE-326)",
			severity: "HIGH",
			evidence: weakCurveHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(weakCurveHits.slice(0, 10).map((m) => m.file))],
			sla: "7d",
			requiredActions: [
				"Use P-256 (prime256v1) at minimum, or P-384 for higher assurance; retire P-192 and smaller curves.",
				"CWE-326 — a 192-bit curve provides only ~96 bits of security, below the 128-bit minimum required by NIST SP 800-131A Rev 2.",
				"Fix: crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });"
			]
		});
	}

	return findings;
}

async function checkSignatureWithSha1(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// SHA-1 named explicitly in a signing/verification context (ECDSA/RSA).
	const sha1SignHits = await searchRepo({
		query: String.raw`createSign\s*\(\s*['"](?:sha1|RSA-SHA1|ecdsa-with-SHA1|SHA1)['"]|createVerify\s*\(\s*['"](?:sha1|RSA-SHA1|ecdsa-with-SHA1|SHA1)['"]|(?:signature|sign|hash)?[Aa]lgorithm\s*[:=]\s*['"](?:RSA-SHA1|ecdsa-with-SHA1|SHA1withRSA|SHA1withECDSA|sha1)['"]`,
		isRegex: true,
		maxMatches: 200
	});

	if (sha1SignHits.length > 0) {
		findings.push({
			id: "CRYPTO_SIGNATURE_SHA1",
			title: "Digital signature (RSA/ECDSA) computed over SHA-1 — collision-based forgery (CWE-327/CWE-328)",
			severity: "HIGH",
			evidence: sha1SignHits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(sha1SignHits.slice(0, 10).map((m) => m.file))],
			sla: "7d",
			requiredActions: [
				"Sign and verify with SHA-256 or stronger (e.g. 'sha256', 'RSA-SHA256', 'SHA256withECDSA').",
				"CWE-327/CWE-328 — SHA-1 is broken for collision resistance (SHAttered), enabling forged signatures over crafted colliding messages.",
				"Fix: crypto.createSign('sha256').update(data).sign(privateKey);"
			]
		});
	}

	return findings;
}

async function checkWeakKdfParameters(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// scrypt N (cost) <= 2^14 (16384).
	const scryptHits = await searchRepo({
		query: String.raw`scrypt(?:Sync)?\s*\([^)]*\bN\s*[:=]\s*(\d+)|scrypt(?:Sync)?\s*\([^,]+,[^,]+,[^,]+,\s*\{[^}]*\bN\s*:\s*(\d+)|scrypt(?:Sync)?\s*\([^,]+,[^,]+,[^,]+,\s*(\d+)`,
		isRegex: true,
		maxMatches: 200
	});
	const weakScrypt = scryptHits.filter((m) => {
		const nums = [...m.preview.matchAll(/\bN\s*[:=]\s*(\d+)|,\s*(\d+)\s*[,)]/g)]
			.map((x) => Number(x[1] ?? x[2]))
			.filter((n) => Number.isFinite(n) && n > 1);
		if (!nums.length) return false;
		// Any explicit N at or below 2^14 is too low.
		return nums.some((n) => n <= 16384);
	});

	// bcrypt rounds < 10 (cost factor in genSalt / hash).
	const bcryptHits = await searchRepo({
		query: String.raw`bcrypt\.(?:hash|hashSync)\s*\([^,]+,\s*([1-9])\s*[,)]|genSalt(?:Sync)?\s*\(\s*([1-9])\s*\)`,
		isRegex: true,
		maxMatches: 200
	});

	// argon2 with low memoryCost / timeCost.
	const argonHits = await searchRepo({
		query: String.raw`argon2|memoryCost\s*[:=]\s*(\d+)|timeCost\s*[:=]\s*([1-2])\b`,
		isRegex: true,
		maxMatches: 200
	});
	const weakArgon = argonHits.filter((m) => {
		const mem = /memoryCost\s*[:=]\s*(\d+)/.exec(m.preview);
		const time = /timeCost\s*[:=]\s*(\d+)/.exec(m.preview);
		// OWASP argon2id: memory >= 19456 KiB (19 MiB), time >= 2. Flag memoryCost < 19456 or timeCost < 2.
		if (mem && Number(mem[1]) < 19456) return true;
		if (time && Number(time[1]) < 2) return true;
		return false;
	});

	const combined = [
		...weakScrypt,
		...bcryptHits,
		...weakArgon
	];
	const unique = combined.filter((m, i, arr) => arr.findIndex((x) => x.file === m.file && x.line === m.line) === i);

	if (unique.length > 0) {
		findings.push({
			id: "CRYPTO_WEAK_KDF_PARAMETERS",
			title: "Password KDF parameters below recommended minimums (argon2 memory/time, scrypt N ≤ 2^14, bcrypt rounds < 10) — cheap offline cracking (CWE-916)",
			severity: "MEDIUM",
			evidence: unique.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(unique.slice(0, 10).map((m) => m.file))],
			sla: "30d",
			requiredActions: [
				"Raise KDF work factors to OWASP 2023 minimums: argon2id memoryCost ≥ 19456 KiB and timeCost ≥ 2, scrypt N ≥ 2^17 (131072), bcrypt cost ≥ 10 (prefer 12).",
				"CWE-916 — low work factors let an attacker with the hash database test billions of candidate passwords per second on commodity GPUs.",
				"Fix: await argon2.hash(pw, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 }); // or bcrypt.hash(pw, 12)"
			]
		});
	}

	return findings;
}

async function checkTokenWithoutTtl(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Fernet / symmetric token generation without a TTL/expiry.
	const fernetHits = await searchRepo({
		query: String.raw`[Ff]ernet\s*\(|\.encrypt\s*\(|generateToken|issueToken|createToken`,
		isRegex: true,
		maxMatches: 200
	});
	// Only consider Fernet/token context.
	const tokenCtx = fernetHits.filter((m) => /fernet|token/i.test(m.preview));
	if (tokenCtx.length === 0) return findings;

	// Presence of any TTL/expiry handling anywhere in those files suppresses the finding.
	const ttlHits = await searchRepo({
		query: String.raw`ttl\b|TTL|max_age|maxAge|expires?(?:In|At|_at|_in)|decrypt\s*\([^)]*,\s*\d+|exp\b`,
		isRegex: true,
		maxMatches: 200
	});
	const ttlFiles = new Set(ttlHits.map((m) => m.file));
	const unsafe = tokenCtx.filter((m) => !ttlFiles.has(m.file));

	if (unsafe.length > 0) {
		findings.push({
			id: "CRYPTO_TOKEN_NO_TTL",
			title: "Fernet/encrypted token issued or verified without a TTL/expiry — indefinitely valid tokens (CWE-613)",
			severity: "HIGH",
			evidence: unsafe.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(unsafe.slice(0, 10).map((m) => m.file))],
			sla: "7d",
			requiredActions: [
				"Enforce a TTL when decrypting/verifying tokens (e.g. Fernet.decrypt(token, ttl=SECONDS)) and embed an expiry claim you check on every use.",
				"CWE-613 — a token with no expiry stays valid forever, so a single leaked token grants permanent access even after rotation or logout.",
				"Fix (python): f.decrypt(token, ttl=3600) — raises on expiry; (node) verify an 'exp' field and reject expired tokens."
			]
		});
	}

	return findings;
}

async function checkMissingCertPinning(): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Outbound HTTPS client usage.
	const clientHits = await searchRepo({
		query: String.raw`https\.request\s*\(|https\.get\s*\(|new\s+https\.Agent\s*\(|axios\.create\s*\(|got\s*\(|node-fetch`,
		isRegex: true,
		maxMatches: 200
	});
	if (clientHits.length === 0) return findings;
	const clientFiles = new Set(clientHits.map((m) => m.file));

	// Pinning indicators anywhere in the repo/those files.
	const pinningHits = await searchRepo({
		query: String.raw`checkServerIdentity|pinnedPublicKey|pin-sha256|sslPinning|certificatePinning|fingerprint256|publicKeyPin|expectedFingerprint`,
		isRegex: true,
		maxMatches: 200
	});
	const pinnedFiles = new Set(pinningHits.map((m) => m.file));

	// Only flag when no pinning appears at all in the codebase (keep it a single low-noise finding).
	if (pinnedFiles.size === 0 && clientFiles.size > 0) {
		const evidence = clientHits.slice(0, 10);
		findings.push({
			id: "CRYPTO_MISSING_CERT_PINNING",
			title: "HTTPS client without certificate/public-key pinning — MITM via rogue or compromised CA (CWE-295)",
			severity: "HIGH",
			evidence: evidence.map((m) => `${m.file}:${m.line}:${m.preview}`),
			files: [...new Set(evidence.map((m) => m.file))],
			sla: "7d",
			requiredActions: [
				"Pin the server's certificate or public key (SPKI SHA-256) for high-value API endpoints via checkServerIdentity/fingerprint256, and fail closed on mismatch.",
				"CWE-295 — relying only on the CA trust store means any mis-issued or compromised CA certificate lets an attacker transparently MITM the connection.",
				"Fix: https.request({ ..., checkServerIdentity: (host, cert) => { if (cert.fingerprint256 !== PINNED_FP) throw new Error('Pin mismatch'); } });"
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

		// 19. Static IV reused across encryption calls
		findings.push(...(await checkStaticIvReused()));

		// 20. ChaCha20 / stream cipher nonce reuse with same key
		findings.push(...(await checkStreamCipherNonceReuse()));

		// 21. AEAD/GCM tag not verified before using decrypted data
		findings.push(...(await checkAeadTagNotVerified()));

		// 22. Insecure RNG (Math.random) for IV/nonce/salt/key/token
		findings.push(...(await checkInsecureRngForCryptoMaterial()));

		// 23. Hardcoded symmetric key literal
		findings.push(...(await checkHardcodedSymmetricKey()));

		// 24. Truncated HMAC (<16 bytes)
		findings.push(...(await checkTruncatedHmac()));

		// 25. Weak ECDSA curve (P-192/secp192r1)
		findings.push(...(await checkWeakEcdsaCurve()));

		// 26. ECDSA/RSA signature with SHA-1
		findings.push(...(await checkSignatureWithSha1()));

		// 27. Weak Argon2/scrypt/bcrypt KDF parameters
		findings.push(...(await checkWeakKdfParameters()));

		// 28. Fernet/token without TTL/expiry
		findings.push(...(await checkTokenWithoutTtl()));

		// 29. Missing certificate pinning in HTTPS clients
		findings.push(...(await checkMissingCertPinning()));
	} catch (err) {
		console.warn("[checkCrypto] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
