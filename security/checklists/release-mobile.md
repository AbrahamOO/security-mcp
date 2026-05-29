# Mobile Release Security Checklist

Use before every iOS and Android production release. All items must be checked or explicitly risk-accepted with a ticket and owner.

---

## All Surfaces (Required for Every Release)

- [ ] Threat model completed and reviewed by security-designated reviewer
- [ ] SAST scan results reviewed — all CRITICAL/HIGH findings resolved or risk-accepted
- [ ] SCA scan clean — no CRITICAL CVEs in dependencies; HIGH CVEs triaged
- [ ] Secrets scan clean — no credentials, tokens, or API keys in source or binary
- [ ] SBOM generated for this release artifact
- [ ] Error messages reviewed — no stack traces or internal paths exposed
- [ ] Logging reviewed — no PII, secrets, or tokens in crash reports or analytics
- [ ] Rollback / force-update strategy documented and tested
- [ ] IR playbook updated if a new attack surface was introduced

---

## Network Security

- [ ] iOS: NSAllowsArbitraryLoads is false — ATS strictly enforced
- [ ] iOS: NSExceptionDomains documented and justified for any exceptions
- [ ] Android: android:usesCleartextTraffic=false in manifest
- [ ] Android: Network Security Config restricts cleartext and pins certificates
- [ ] Certificate pinning implemented for high-value API calls
- [ ] Certificate pins include at least one backup pin
- [ ] TLS 1.2+ enforced on all connections — no SSLv3 or TLS 1.0/1.1

---

## Data Storage

- [ ] Sensitive data stored in iOS Keychain / Android Keystore — not plaintext files
- [ ] No sensitive data in SharedPreferences (Android) or NSUserDefaults (iOS) in plaintext
- [ ] No sensitive data written to external storage or SD card
- [ ] Database files encrypted at rest (SQLCipher or platform encryption APIs)
- [ ] Sensitive data excluded from iCloud and Android auto-backup
- [ ] Android: android:allowBackup=false or backup rules exclude sensitive files
- [ ] iOS: Data Protection class set to NSFileProtectionComplete for sensitive files

---

## Build Configuration

- [ ] Release build: android:debuggable=false in AndroidManifest.xml
- [ ] Release build: iOS debug symbols stripped from distribution binary
- [ ] ProGuard / R8 obfuscation enabled for Android release builds
- [ ] No developer/debug API keys bundled in release binary
- [ ] No test accounts or backdoor credentials in production build
- [ ] Build signing configuration uses release keystore — not debug keystore

---

## Authentication and Authorization

- [ ] Biometric authentication properly tied to Keychain/Keystore — not bypassable via bypass
- [ ] Jailbreak/root detection implemented for high-risk operations (payments, admin)
- [ ] Session expiry enforced — tokens invalidated on logout and app background
- [ ] No hardcoded credentials, tokens, or API keys in source code or resources
- [ ] Authentication state not stored in non-secure locations

---

## UI and Data Handling

- [ ] Screenshot prevention enabled for sensitive screens (payment, credentials, PII)
- [ ] Clipboard protection on sensitive fields (passwords, card numbers)
- [ ] No sensitive data in activity/fragment intent extras passed to untrusted components
- [ ] Deep links validated — no open redirect or intent injection possible
- [ ] Exported Android components (activities, services, receivers) restricted with permissions
- [ ] iOS URL scheme handlers validate all input before processing

---

## Third-Party SDKs and Dependencies

- [ ] All third-party SDKs reviewed for data collection and privacy
- [ ] Analytics SDKs configured to exclude PII and credentials
- [ ] Crash reporting SDK configured to scrub sensitive data before upload
- [ ] No abandoned or unmaintained SDKs in production build
- [ ] SDK versions pinned — no floating version ranges

---

## OWASP Mobile Top 10

- [ ] M1 Improper Credential Usage: No hardcoded creds, secure storage confirmed
- [ ] M2 Inadequate Supply Chain Security: SDK review completed
- [ ] M3 Insecure Authentication: Biometric and session security confirmed
- [ ] M4 Insufficient Input/Output Validation: Input validation on all API calls
- [ ] M5 Insecure Communication: TLS and pinning confirmed
- [ ] M6 Inadequate Privacy Controls: PII handling reviewed, consent flows verified
- [ ] M7 Insufficient Binary Protections: Obfuscation and anti-debugging confirmed
- [ ] M8 Security Misconfiguration: All debug flags disabled
- [ ] M9 Insecure Data Storage: Encryption at rest confirmed
- [ ] M10 Insufficient Cryptography: Only approved algorithms used (AES-256, RSA-2048+)

---

## Monitoring and Incident Response

- [ ] Crash reporting configured with PII scrubbing
- [ ] Anomalous usage alerting (geographic anomalies, high API error rates)
- [ ] Mobile credential theft IR playbook current and tested
- [ ] Force-update mechanism available and tested for critical security fixes

---

## Advanced Binary and Runtime Protection

- [ ] Code obfuscation verified on release binary — class/method names not recoverable
- [ ] Anti-debugging controls active for high-risk flows (biometric auth, payment)
- [ ] Anti-instrumentation detection: Frida, Magisk, Cydia, Xposed signatures checked at runtime
- [ ] Binary integrity verified at runtime — detects tampering or repackaging
- [ ] Certificate Transparency (CT) monitoring configured — alerts on unauthorized certs for app domains
- [ ] OCSP stapling or Must-Staple configured for TLS certificates used by backend
- [ ] Universal Links (iOS) / App Links (Android) used for auth callbacks — custom URL scheme NOT used for auth
- [ ] Intent extras reviewed: no sensitive data passed via implicit intents to external components
- [ ] Custom URL scheme hijacking prevention: scheme registered and validated before processing
- [ ] SSL pinning bypass test executed against release build — pinning holds under instrumentation

---

## Post-Quantum Readiness Gate

- [ ] Certificate pinning uses EC keys (P-256 minimum) — RSA 2048 pins flagged for timeline migration
- [ ] Any token stored in Keychain / Keystore with validity > 1 year reviewed for harvest-now-decrypt-later risk
- [ ] App-to-backend mTLS certificates: key algorithms inventoried and migration plan documented
- [ ] On-device ML models (ONNX, CoreML, TFLite): model provenance verified; no RSA-signed model manifest with long-lived signature

## Learning Loop Review

- [ ] `security.pattern_report` reviewed — most common mobile findings (MASVS-STORAGE, MASVS-AUTH) addressed
- [ ] All CRITICAL/HIGH findings from this run recorded via `security.record_outcome`
- [ ] Platform-specific bypass techniques found in prior runs confirmed still blocked in release build

## Cross-Checklist Dependencies

- [ ] Mobile app calls backend APIs? → `release-api.md` authentication and rate-limit controls also verified
- [ ] Mobile app handles payments? → `release-payments.md` PCI mobile scope verification also completed
- [ ] Mobile app uses AI/LLM features? → `release-ai.md` on-device model security also verified
