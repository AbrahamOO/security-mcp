import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "CRYPTO_WEAK_HASH",
    check: "crypto",
    positive: {
      file: "src/utils/fingerprint.ts",
      content: `import { createHash } from "crypto";\n\nexport function fingerprint(data: string): string {\n  return createHash('md5').update(data).digest('hex');\n}\n`
    },
    negative: {
      file: "src/utils/fingerprint.ts",
      content: `import { createHash } from "crypto";\n\nexport function fingerprint(data: string): string {\n  return createHash('sha256').update(data).digest('hex');\n}\n`
    },
    note: "The weak-hash regex only matches md5/sha1/sha-1 literals; sha256 falls outside it entirely, and this non-password context also avoids CRYPTO_SHA_USED_FOR_PASSWORD."
  },
  {
    ruleId: "CRYPTO_SHA_USED_FOR_PASSWORD",
    check: "crypto",
    positive: {
      file: "src/auth/hash-password.ts",
      content: `import { createHash } from "crypto";\n\nexport function hashPassword(password: string): string {\n  return createHash('sha256').update(password).digest('hex');\n}\n`
    },
    negative: {
      file: "src/auth/hash-password.ts",
      content: `import bcrypt from "bcrypt";\n\nexport async function hashPassword(password: string): Promise<string> {\n  return bcrypt.hash(password, 12);\n}\n`
    },
    note: "Positive matches both the password-context filter (line contains 'password') and the direct createHash('sha256').update(password pattern. Negative has no createHash call at all, so shaPasswordHits is empty before any context filtering runs."
  },
  {
    ruleId: "CRYPTO_WEAK_CIPHER",
    check: "crypto",
    positive: {
      file: "src/main/java/com/example/CryptoUtil.java",
      content: `import javax.crypto.Cipher;\n\npublic class CryptoUtil {\n    public byte[] encrypt(byte[] data, java.security.Key key) throws Exception {\n        Cipher cipher = Cipher.getInstance("DES");\n        cipher.init(Cipher.ENCRYPT_MODE, key);\n        return cipher.doFinal(data);\n    }\n}\n`
    },
    negative: {
      file: "src/main/java/com/example/CryptoUtil.java",
      content: `import javax.crypto.Cipher;\nimport javax.crypto.spec.GCMParameterSpec;\n\npublic class CryptoUtil {\n    public byte[] encrypt(byte[] data, java.security.Key key, byte[] iv) throws Exception {\n        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n        GCMParameterSpec spec = new GCMParameterSpec(128, iv);\n        cipher.init(Cipher.ENCRYPT_MODE, key, spec);\n        return cipher.doFinal(data);\n    }\n}\n`
    },
    note: "Positive matches Cipher.getInstance([\"'])(?:DES|RC4|RC2|Blowfish)['\"] exactly ('DES' immediately followed by the closing quote). Negative's 'AES/GCM/NoPadding' string never matches that alternation."
  },
  {
    ruleId: "CRYPTO_ECB_MODE",
    check: "crypto",
    positive: {
      file: "src/crypto/legacy-encrypt.ts",
      content: `import { createCipheriv } from "crypto";\n\nexport function encryptRecord(data: Buffer, key: Buffer): Buffer {\n  const cipher = createCipheriv('aes-256-ecb', key, null);\n  return Buffer.concat([cipher.update(data), cipher.final()]);\n}\n`
    },
    negative: {
      file: "src/crypto/legacy-encrypt.ts",
      content: `import { createCipheriv, randomBytes } from "crypto";\n\nexport function encryptRecord(data: Buffer, key: Buffer): { ciphertext: Buffer; iv: Buffer; tag: Buffer } {\n  const iv = randomBytes(12);\n  const cipher = createCipheriv('aes-256-gcm', key, iv);\n  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);\n  return { ciphertext, iv, tag: cipher.getAuthTag() };\n}\n`
    },
    note: "Positive's 'aes-256-ecb' literal ends in '-ecb', matching the ECB regex directly. Negative uses 'aes-256-gcm' with a random IV per call; no '-ecb' substring exists anywhere in the file."
  },
  {
    ruleId: "CRYPTO_HARDCODED_IV",
    check: "crypto",
    positive: {
      file: "src/crypto/cbc-encrypt.ts",
      content: `import { createCipheriv } from "crypto";\n\nconst iv = Buffer.from('000102030405060708090a0b0c0d0e0f');\n\nexport function encrypt(data: Buffer, key: Buffer): Buffer {\n  const cipher = createCipheriv('aes-256-cbc', key, iv);\n  return Buffer.concat([cipher.update(data), cipher.final()]);\n}\n`
    },
    negative: {
      file: "src/crypto/cbc-encrypt.ts",
      content: `import { createCipheriv, randomBytes } from "crypto";\n\nexport function encrypt(data: Buffer, key: Buffer): { ciphertext: Buffer; iv: Buffer } {\n  const iv = randomBytes(16);\n  const cipher = createCipheriv('aes-256-cbc', key, iv);\n  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);\n  return { ciphertext, iv };\n}\n`
    },
    note: "Positive's 'iv = Buffer.from(<32 hex chars>)' matches the hardcoded-IV literal regex exactly. Negative derives iv from randomBytes(16) per call, which is not a Buffer.from(hex-literal) or bare hex-string assignment."
  },
  {
    ruleId: "CRYPTO_ZERO_IV",
    check: "crypto",
    positive: {
      file: "src/crypto/zero-iv-encrypt.ts",
      content: `import { createCipheriv } from "crypto";\n\nexport function encrypt(data: Buffer, key: Buffer): Buffer {\n  const iv = Buffer.alloc(16);\n  const cipher = createCipheriv('aes-256-cbc', key, iv);\n  return Buffer.concat([cipher.update(data), cipher.final()]);\n}\n`
    },
    negative: {
      file: "src/crypto/zero-iv-encrypt.ts",
      content: `import { createCipheriv, randomBytes } from "crypto";\n\nexport function encrypt(data: Buffer, key: Buffer): { ciphertext: Buffer; iv: Buffer } {\n  const iv = randomBytes(16);\n  const cipher = createCipheriv('aes-256-cbc', key, iv);\n  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);\n  return { ciphertext, iv };\n}\n`
    },
    note: "Positive's 'iv = Buffer.alloc(' matches the zeroIvAssignHits pattern (Buffer.alloc produces an all-zero buffer). Negative assigns iv from randomBytes(16); no Buffer.alloc call exists anywhere in the file."
  },
  {
    ruleId: "CRYPTO_STATIC_IV_REUSED",
    check: "crypto",
    positive: {
      file: "src/crypto/static-iv-encrypt.ts",
      content: `import { createCipheriv } from "crypto";\n\nconst iv = Buffer.from('a1b2c3d4e5f60718293a4b5c6d7e8f90', 'hex');\n\nexport function encryptMessage(data: Buffer, key: Buffer): Buffer {\n  const cipher = createCipheriv('aes-256-cbc', key, iv);\n  return Buffer.concat([cipher.update(data), cipher.final()]);\n}\n`
    },
    negative: {
      file: "src/crypto/static-iv-encrypt.ts",
      content: `import { createCipheriv, randomBytes } from "crypto";\n\nexport function encryptMessage(data: Buffer, key: Buffer): { ciphertext: Buffer; iv: Buffer } {\n  const iv = randomBytes(12);\n  const cipher = createCipheriv('aes-256-gcm', key, iv);\n  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);\n  return { ciphertext, iv };\n}\n`
    },
    note: "Positive's 'const iv = Buffer.from(...)' sits at module scope (column 0), matching the ^(?:const|let|var)\\s+(?:iv|nonce)... anchor, and is reused by every call. Negative's 'const iv = randomBytes(12)' is indented inside the function body, so the ^-anchored module-scope regex never matches it — a fresh iv is generated per call."
  },
  {
    ruleId: "CRYPTO_GCM_NONCE_REUSE_RISK",
    check: "crypto",
    positive: {
      file: "src/crypto/gcm-counter-nonce.ts",
      content: `import { createCipheriv } from "crypto";\n\nlet counter = 0;\n\nexport function encrypt(data: Buffer, key: Buffer): Buffer {\n  counter++;\n  const nonceBuf = Buffer.alloc(12);\n  nonceBuf.writeUInt32BE(counter, 8);\n  const cipher = createCipheriv('aes-256-gcm', key, nonceBuf);\n  return Buffer.concat([cipher.update(data), cipher.final()]);\n}\n`
    },
    negative: {
      file: "src/crypto/gcm-counter-nonce.ts",
      content: `import { createCipheriv, randomBytes } from "crypto";\n\nexport function encrypt(data: Buffer, key: Buffer): { ciphertext: Buffer; nonce: Buffer; tag: Buffer } {\n  const nonce = randomBytes(12);\n  const cipher = createCipheriv('aes-256-gcm', key, nonce);\n  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);\n  return { ciphertext, nonce, tag: cipher.getAuthTag() };\n}\n`
    },
    note: "Positive has 'let counter = 0' and 'counter++' in the same file as the GCM cipher call, matching the nonce-reuse pattern (let/var counter= or counter++). Negative uses only 'const nonce = randomBytes(12)' with no let/var/++/Date.now anywhere, so nonceReuseHits is empty."
  },
  {
    ruleId: "CRYPTO_GCM_NO_RANDOM_NONCE",
    check: "crypto",
    positive: {
      file: "src/crypto/gcm-encrypt.ts",
      content: `import { createCipheriv } from "crypto";\n\nexport function encrypt(data: Buffer, key: Buffer, nonce: Buffer): Buffer {\n  const cipher = createCipheriv('aes-256-gcm', key, nonce);\n  return Buffer.concat([cipher.update(data), cipher.final()]);\n}\n`
    },
    negative: {
      file: "src/crypto/gcm-encrypt.ts",
      content: `import crypto from "crypto";\n\nexport function encrypt(data: Buffer, key: Buffer): { ciphertext: Buffer; nonce: Buffer; tag: Buffer } {\n  const nonce = crypto.randomBytes(12);\n  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);\n  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);\n  return { ciphertext, nonce, tag: cipher.getAuthTag() };\n}\n`
    },
    note: "Positive uses aes-256-gcm but the nonce is an opaque caller-supplied parameter; the literal string 'crypto.randomBytes' never appears in the file, so gcmWithoutRandom is non-empty. Negative calls crypto.randomBytes(12) explicitly, which the regex requires verbatim."
  },
  {
    ruleId: "CRYPTO_AES_CBC_NO_AUTH",
    check: "crypto",
    positive: {
      file: "src/crypto/cbc-auth.ts",
      content: `import { createCipheriv } from "crypto";\n\nexport function encrypt(data: Buffer, key: Buffer, iv: Buffer): Buffer {\n  const cipher = createCipheriv('aes-256-cbc', key, iv);\n  return Buffer.concat([cipher.update(data), cipher.final()]);\n}\n`
    },
    negative: {
      file: "src/crypto/cbc-auth.ts",
      content: `import { createCipheriv, createDecipheriv, createHmac, timingSafeEqual } from "crypto";\n\nexport function encrypt(data: Buffer, key: Buffer, macKey: Buffer, iv: Buffer): { ciphertext: Buffer; tag: Buffer } {\n  const cipher = createCipheriv('aes-256-cbc', key, iv);\n  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);\n  const tag = createHmac('sha256', macKey).update(Buffer.concat([iv, ciphertext])).digest();\n  return { ciphertext, tag };\n}\n\nexport function verifyAndDecrypt(ciphertext: Buffer, tag: Buffer, key: Buffer, macKey: Buffer, iv: Buffer): Buffer {\n  const expected = createHmac('sha256', macKey).update(Buffer.concat([iv, ciphertext])).digest();\n  if (!timingSafeEqual(expected, tag)) {\n    throw new Error('Authentication failed');\n  }\n  const decipher = createDecipheriv('aes-256-cbc', key, iv);\n  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);\n}\n`
    },
    note: "Positive uses AES-CBC with no HMAC/sign/authenticate keyword anywhere in the file. Negative implements real encrypt-then-MAC: HMAC-SHA256 computed over iv+ciphertext and checked with timingSafeEqual before decrypting — the exact 'createHmac' presence the rule's own hmacFiles check treats as authentication, not a cosmetic edit."
  },
  {
    ruleId: "CRYPTO_AEAD_TAG_NOT_VERIFIED",
    check: "crypto",
    positive: {
      file: "src/crypto/gcm-decrypt.ts",
      content: `import { createDecipheriv } from "crypto";\n\nexport function decrypt(ciphertext: Buffer, key: Buffer, iv: Buffer): Buffer {\n  const decipher = createDecipheriv('aes-256-gcm', key, iv);\n  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);\n}\n`
    },
    negative: {
      file: "src/crypto/gcm-decrypt.ts",
      content: `import { createDecipheriv } from "crypto";\n\nexport function decrypt(ciphertext: Buffer, key: Buffer, iv: Buffer, tag: Buffer): Buffer {\n  const decipher = createDecipheriv('aes-256-gcm', key, iv);\n  decipher.setAuthTag(tag);\n  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);\n}\n`
    },
    note: "Positive decrypts with createDecipheriv('aes-256-gcm', ...) and never calls setAuthTag, so the tag is never checked. Negative calls decipher.setAuthTag(tag) before final(), exactly the fix in the rule's requiredActions."
  },
  {
    ruleId: "CRYPTO_STREAM_NONCE_REUSE",
    check: "crypto",
    positive: {
      file: "src/crypto/chacha20-encrypt.ts",
      content: `import { createCipheriv } from "crypto";\n\nconst nonce = Buffer.from('4e6f6e63653132627974', 'hex');\n\nexport function encrypt(data: Buffer, key: Buffer): Buffer {\n  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });\n  return Buffer.concat([cipher.update(data), cipher.final()]);\n}\n`
    },
    negative: {
      file: "src/crypto/chacha20-encrypt.ts",
      content: `import { createCipheriv, randomBytes } from "crypto";\n\nexport function encrypt(data: Buffer, key: Buffer): { ciphertext: Buffer; nonce: Buffer; tag: Buffer } {\n  const nonce = randomBytes(12);\n  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });\n  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);\n  return { ciphertext, nonce, tag: cipher.getAuthTag() };\n}\n`
    },
    note: "Positive's 'const nonce = Buffer.from(...)' sits at module scope, matching the static-nonce anchor, and is reused across every chacha20-poly1305 call. Negative generates 'const nonce = randomBytes(12)' inside the function body (indented, so the ^-anchored regex doesn't match it), a fresh nonce per call."
  },
  {
    ruleId: "CRYPTO_RSA_PKCS1_PADDING",
    check: "crypto",
    positive: {
      file: "src/crypto/rsa-encrypt.ts",
      content: `import crypto from "crypto";\n\nexport function encryptForRecipient(data: Buffer, publicKey: string): Buffer {\n  return crypto.publicEncrypt(publicKey, data);\n}\n`
    },
    negative: {
      file: "src/crypto/rsa-encrypt.ts",
      content: `import crypto from "crypto";\n\nconst OAEP = crypto.constants.RSA_PKCS1_OAEP_PADDING;\n\nexport function encryptForRecipient(data: Buffer, publicKey: string): Buffer {\n  return crypto.publicEncrypt({ key: publicKey, padding: OAEP, oaepHash: 'sha256' }, data);\n}\n`
    },
    note: "Positive calls crypto.publicEncrypt with only (publicKey, data) — Node's default RSA padding is PKCS#1 v1.5, and no OAEP marker appears anywhere in the file, so rsaWithoutOaep fires. Negative passes crypto.constants.RSA_PKCS1_OAEP_PADDING explicitly, which the oaepHits check recognizes, removing this file from rsaWithoutOaep."
  },
  {
    ruleId: "CRYPTO_RSA_WEAK_KEY",
    check: "crypto",
    positive: {
      file: "src/crypto/rsa-keygen-weak.ts",
      content: `import crypto from "crypto";\n\nexport function generateLegacyKeyPair() {\n  return crypto.generateKeyPairSync('rsa', {\n    modulusLength: 768,\n    publicKeyEncoding: { type: 'spki', format: 'pem' },\n    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }\n  });\n}\n`
    },
    negative: {
      file: "src/crypto/rsa-keygen-weak.ts",
      content: `import crypto from "crypto";\n\nexport function generateKeyPair() {\n  return crypto.generateKeyPairSync('rsa', {\n    modulusLength: 4096,\n    publicKeyEncoding: { type: 'spki', format: 'pem' },\n    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }\n  });\n}\n`
    },
    note: "Positive's 'modulusLength: 768' matches the weak-key alternation (512|768|1536) directly. Negative uses 'modulusLength: 4096', which is outside that set."
  },
  {
    ruleId: "CRYPTO_LOW_PBKDF2_ITERATIONS",
    check: "crypto",
    positive: {
      file: "src/auth/derive-key.ts",
      content: `import { pbkdf2Sync, randomBytes } from "crypto";\n\nexport function deriveKey(password: string): Buffer {\n  const salt = randomBytes(16);\n  return pbkdf2Sync(password, salt, 10000, 32, 'sha256');\n}\n`
    },
    negative: {
      file: "src/auth/derive-key.ts",
      content: `import { pbkdf2Sync, randomBytes } from "crypto";\n\nexport function deriveKey(password: string): Buffer {\n  const salt = randomBytes(16);\n  return pbkdf2Sync(password, salt, 600000, 32, 'sha256');\n}\n`
    },
    note: "checkPbkdf2Iterations extracts the 3rd positional argument as the iteration count. Positive's 10000 is < 600,000 and fires; negative's 600000 fails the strict '< 600000' comparison, matching the OWASP 2023 minimum the rule itself recommends."
  },
  {
    ruleId: "CRYPTO_INSECURE_RNG_MATERIAL",
    check: "crypto",
    positive: {
      file: "src/crypto/generate-salt.ts",
      content: `export function generateSalt(): string {\n  const salt = Math.random().toString(36).substring(2, 18);\n  return salt;\n}\n`
    },
    negative: {
      file: "src/crypto/generate-salt.ts",
      content: `import { randomBytes } from "crypto";\n\nexport function generateSalt(): Buffer {\n  const salt = randomBytes(16);\n  return salt;\n}\n`
    },
    note: "Positive's line contains both 'Math.random()' and the word 'salt', matching the materialRe context filter. Negative has no Math.random() call anywhere in the file, so mathRandomHits is empty and the check returns immediately."
  },
  {
    ruleId: "CRYPTO_WEAK_ECDSA_CURVE",
    check: "crypto",
    positive: {
      file: "src/crypto/ec-keygen.ts",
      content: `import crypto from "crypto";\n\nexport function generateSigningKey() {\n  return crypto.generateKeyPairSync('ec', {\n    namedCurve: 'secp192r1'\n  });\n}\n`
    },
    negative: {
      file: "src/crypto/ec-keygen.ts",
      content: `import crypto from "crypto";\n\nexport function generateSigningKey() {\n  return crypto.generateKeyPairSync('ec', {\n    namedCurve: 'prime256v1'\n  });\n}\n`
    },
    note: "Positive's 'secp192r1' literal matches the weak-curve alternation directly. Negative uses 'prime256v1' (P-256), which is not in the (secp192r1|prime192v1|P-192|p192|secp192k1|secp160r1) set."
  },
  {
    ruleId: "CRYPTO_INSECURE_RANDOM",
    check: "crypto",
    positive: {
      file: "src/auth/session-token.ts",
      content: `export function generateSessionToken(): string {\n  const token = 'sess_' + Math.random().toString(36).slice(2);\n  return token;\n}\n`
    },
    negative: {
      file: "src/auth/session-token.ts",
      content: `import { randomBytes } from "crypto";\n\nexport function generateSessionToken(): string {\n  const token = randomBytes(32).toString('hex');\n  return token;\n}\n`
    },
    note: "Positive's line contains both 'Math.random()' and the word 'token', matching the securityContextRe filter for the CRITICAL identifier path. Negative has no Math.random()/rand()/srand() call anywhere, so insecureRandomHits is empty."
  },
  {
    ruleId: "CRYPTO_RSA_1024",
    check: "crypto",
    positive: {
      file: "src/crypto/rsa-keygen-1024.ts",
      content: `import crypto from "crypto";\n\nexport function generateLegacyKeyPair() {\n  return crypto.generateKeyPairSync('rsa', {\n    modulusLength: 1024,\n    publicKeyEncoding: { type: 'spki', format: 'pem' },\n    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }\n  });\n}\n`
    },
    negative: {
      file: "src/crypto/rsa-keygen-1024.ts",
      content: `import crypto from "crypto";\n\nexport function generateKeyPair() {\n  return crypto.generateKeyPairSync('rsa', {\n    modulusLength: 4096,\n    publicKeyEncoding: { type: 'spki', format: 'pem' },\n    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }\n  });\n}\n`
    },
    note: "Positive's 'modulusLength: 1024' matches the RSA-1024 regex literally. Negative's 'modulusLength: 4096' contains no '1024' substring anywhere in the file, following the rule's own requiredActions to upgrade to RSA-4096 minimum."
  },
  {
    ruleId: "CRYPTO_RSA_2048_PQC",
    check: "crypto",
    positive: {
      file: "src/crypto/rsa-keygen-2048.ts",
      content: `import crypto from "crypto";\n\nexport function generateKeyPair() {\n  return crypto.generateKeyPairSync('rsa', {\n    modulusLength: 2048,\n    publicKeyEncoding: { type: 'spki', format: 'pem' },\n    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }\n  });\n}\n`
    },
    negative: {
      file: "src/crypto/rsa-keygen-2048.ts",
      content: `import crypto from "crypto";\n\nexport function generateKeyPair() {\n  return crypto.generateKeyPairSync('rsa', {\n    modulusLength: 4096,\n    publicKeyEncoding: { type: 'spki', format: 'pem' },\n    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }\n  });\n}\n`
    },
    note: "Positive's 'modulusLength: 2048' matches the PQC-readiness warning regex exactly. Negative moves to 'modulusLength: 4096', which contains no '2048' substring, per the rule's own note that RSA-2048 warrants migration planning for long-lived keys."
  }
];
