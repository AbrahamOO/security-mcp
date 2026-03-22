/**
 * Weak cryptography detection.
 * Mapped to NIST SP 800-131A Rev 2.
 */
import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";

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

		// 3. Insecure random for security use
		const insecureRandomHits = await searchRepo({
			query: String.raw`Math\.random\(\)|random\.random\(\)|rand\(\)|srand\(`,
			isRegex: true,
			maxMatches: 200
		});
		const securityContextRe = /token|key|secret|password|nonce|salt|csrf|session/i;
		const insecureSecRandom = insecureRandomHits.filter((m) => securityContextRe.test(m.preview));
		if (insecureSecRandom.length > 0) {
			findings.push({
				id: "CRYPTO_INSECURE_RANDOM",
				title: "Non-cryptographic random used in security-sensitive context",
				severity: "HIGH",
				evidence: insecureSecRandom.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`),
				files: [...new Set(insecureSecRandom.slice(0, 10).map((m) => m.file))],
				requiredActions: [
					"Use crypto.randomBytes() (Node.js) for security-sensitive randomness.",
					"Math.random() is not cryptographically secure and must never be used for tokens, keys, or nonces."
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
		// Check for numeric iteration counts in the context
		for (const hit of pbkdf2Hits) {
			const iterMatch = /pbkdf2(?:Sync)?\s*\([^)]*?,\s*[^,]+,\s*(\d+)/.exec(hit.preview);
			if (iterMatch) {
				const iters = parseInt(iterMatch[1], 10);
				if (iters < 600000) {
					findings.push({
						id: "CRYPTO_LOW_PBKDF2_ITERATIONS",
						title: `PBKDF2 iteration count too low (${iters} < 600,000)`,
						severity: "HIGH",
						evidence: [`${hit.file}:${hit.line}:${hit.preview}`],
						files: [hit.file],
						requiredActions: [
							"Use ≥ 600,000 iterations for PBKDF2-SHA256 (OWASP 2023 recommendation).",
							"Prefer bcrypt (cost ≥ 12) or Argon2id instead."
						]
					});
					break;
				}
			}
		}

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
	} catch (err) {
		console.warn("[checkCrypto] Internal error:", err instanceof Error ? err.message : String(err));
	}

	return findings;
}
