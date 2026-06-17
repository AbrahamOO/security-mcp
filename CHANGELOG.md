# Changelog

All notable changes to `security-mcp` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### ⚠️ BREAKING CHANGES

- **Unsigned security-exception files can no longer suppress `HIGH`/`CRITICAL` findings by default.**
  Previously, when `SECURITY_POLICY_HMAC_KEY` was unset, the gate trusted any exceptions file and
  would silently move matched findings — including `HIGH`/`CRITICAL` — into the suppressed list,
  letting anyone who could edit an unsigned exceptions file silently bypass the gate. The gate now
  refuses to suppress `HIGH`/`CRITICAL` findings from an unsigned/unverified exceptions file
  (`LOW`/`MEDIUM` may still be suppressed); blocked findings stay active and emit
  `EXCEPTION_UNSIGNED_HIGH_BLOCKED`.

  **Migration — choose one:**
  - **Recommended:** set `SECURITY_POLICY_HMAC_KEY` (≥32 bytes), run `security-mcp sign-policy`,
    and sign your exceptions file (store its `hmacSha256`). Signed exceptions suppress all
    severities as before.
  - Set `SECURITY_ALLOW_UNSIGNED_HIGH_SUPPRESSION=1` to restore the legacy behavior on all paths
    (intended only for scanning intentionally-vulnerable fixtures).
  - The named CI self-scan file `.github/security-exceptions-ci.json` is exempt from this floor
    (it represents a project suppressing its own test fixtures) and continues to work unsigned.

### Added — security controls / new env vars

- `SECURITY_OFFLINE=1` — disables all third-party network egress from the dependency/threat-intel
  checks (OpenSSF Scorecard, npm registry, EPSS/CISA KEV). Private dependency names and your CVE
  IDs no longer leave the machine. Public-scope filtering also prevents private/internal scoped
  package names from being sent to public endpoints even when online.
- `SECURITY_REQUIRE_SIGNED_EXCEPTIONS=1` — full fail-closed: rejects any unsigned/unverifiable
  exceptions file (all severities).
- `SECURITY_ALLOW_UNSIGNED_HIGH_SUPPRESSION=1` — break-glass for the new default above.
- `SECURITY_ATTEST_ALLOW_INCOMPLETE=1` — break-glass for the stricter `security.attest_review`.

### Security — hardening (no config change required)

- **Gate-verdict integrity:** when the policy file is not HMAC-verified, `severity_block` is now
  floored to include `HIGH`/`CRITICAL` — an unsigned policy edit can no longer relax the gate to PASS.
- **DoS / availability:** the secret scanner's base64/hex passes are wrapped against `RangeError`,
  and `readFileSafe` enforces a 10 MB per-file cap — a crafted repo file can no longer crash the
  gate, silently disable secret detection, or exhaust memory.
- **Attestation:** `security.attest_review` refuses to attest unless the latest gate is `PASS` with
  all required steps complete (no more zero-coverage/forged green attestations), and unsigned
  attestations are now explicitly labelled (`signed: false`).
- **Exceptions visibility:** any suppression by an unsigned exceptions file now emits an
  unsuppressible `EXCEPTIONS_UNSIGNED_SUPPRESSION` finding — the bypass is never silent.
- **Supply chain:** removed the unpinned `curl | sudo sh` tool-install path (root-RCE) and made the
  GitHub-release installer fail closed when a binary has no checksum; `ensure_skill` now resolves
  the bundled, package-local skill (the installed package is the trust root) before any network
  download, closing the trust-on-first-use gap; deleted the dead, integrity-free `downloadSkill`.
- **Data at rest:** findings, agent memory, and usage files are now written `0o600` (dirs `0o700`),
  not world-readable `644`.
- **Prompt injection:** `run_pr_gate` output now strips control bytes, collapses newlines, and caps
  the length of repo-derived `evidence`/`changedFiles`/`requiredActions` before they reach an LLM.

### Notes for maintainers enabling HMAC integrity in CI

`.github/workflows/security-gate.yml` now reads `SECURITY_POLICY_HMAC_KEY` from
`${{ secrets.SECURITY_POLICY_HMAC_KEY }}`. The secret is optional and a no-op until set. To enable
tamper-evident integrity: (1) add a ≥32-byte `SECURITY_POLICY_HMAC_KEY` repository secret, then
(2) sign the committed policy and exceptions with that key (`security-mcp sign-policy`, and store the
exceptions `hmacSha256`) and commit the signatures. With a key set, the gate **requires** a valid
signature on the policy file (a missing `.hmac` sidecar is rejected by design), so steps (1) and (2)
must land together.
