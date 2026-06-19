# Changelog

All notable changes to `security-mcp` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project adheres to [Semantic Versioning](https://semver.org/).

## [1.3.3] - 2026-06-18

### Added — agentic threat-model hardening

Closes two gaps from an agentic-AI threat model of security-mcp's own multi-agent
system (article surfaces: inter-agent interactions and per-tool-call observability).

- **Inter-agent payload integrity in `orchestration.merge_agent_findings`.** The merge
  step is the single trust sink for an entire agent run. It now (a) validates every
  agent's findings file against a strict zod schema before trusting it, and (b) verifies
  each file's findings hash against that agent's signed attestation
  (`security.attest_agent` / `audit-chain`) before the findings reach the gate.
  - Attestation chain present → **enforced** mode: unattested or hash-mismatched agent
    files are rejected from the merge; a hash mismatch (tampering) or a chain that fails
    `verify_chain` forces the gate to **FAIL** even with zero findings.
  - No attestation chain → **unattested** mode: findings are schema-validated only, with
    a warning recorded in `merged-findings.json` under `signatureVerification`.
  - Backward compatible: runs that never attested behave as before, plus the new
    schema validation.
- **Per-tool-call structured audit log.** Every MCP tool invocation now emits one
  structured JSONL record (`src/mcp/tool-audit.ts`) with the eight mandatory fields:
  timestamp, agent id, tool name, input parameters (secrets redacted), output result
  (outcome + size + truncated preview), credentials used (session id, never the secret),
  user context, and outcome status. Written to `.mcp/audit/tool-calls.jsonl` (`0o600`).
  Point `SECURITY_TOOL_AUDIT_LOG` at an append-only / write-once sink for tamper-proof
  retention. Logging never interrupts tool execution.

### Hardened — from a three-agent adversarial review of the above

- **`SECURITY_REQUIRE_AGENT_ATTESTATION`** (new, opt-in, default off): when set,
  `merge_agent_findings` fails the gate closed unless the run is HMAC-signed,
  `enforced`, chain-valid, and has zero rejected agents. Closes the "delete the
  attestation chain to downgrade to unattested mode and skip hash checks" bypass.
- **Honest unsigned-chain reporting:** an unsigned attestation chain is forgeable by
  anyone who can write the run directory, so `merge_agent_findings` now surfaces
  `verifyChain`'s unsigned-chain caveat in `signatureVerification.warning` even on the
  success path instead of implying cryptographic enforcement.
- **Dedupe keeps highest severity per finding id** (was first-occurrence-wins), so a
  malicious or mislabeled same-id LOW can no longer shadow a real CRITICAL.
- **Audit-log secret/PII scrubbing:** redaction now matches decorated key names
  (`sharedSecret`, `hmacKey`, `refreshToken`, …) and scrubs secret-shaped *values*
  (AWS keys, PEM private keys, JWTs, GitHub/Slack tokens, long hex/base64) in both
  inputs and the output preview — the preview previously logged tool output (e.g.
  `repo.read_file` file contents) unredacted.
- **Failed authentication is recorded as such**, not as a successful tool call;
  `UNAUTHENTICATED` is matched only in its structured framing to avoid outcome-field
  poisoning by returned file content.
- **Audit-log robustness:** BigInt-safe serialization with a minimal fallback record
  (no silent audit-evasion), 50 MB single-rotation size guard, and capped `agentId`.

**Residual risk (accepted — local single-process trust model):** an *unsigned*
attestation chain is tamper-evident, not tamper-proof, against an attacker with write
access to `.mcp/agent-runs/{id}/`; the `SECURITY_AUDIT_HMAC_KEY` is the real boundary.
Findings-hash canonicalization, per-agent id namespacing, and an immutable audit sink
are not implemented in-code (the sink is a deployment option via `SECURITY_TOOL_AUDIT_LOG`).
These controls assume distributed agent fleets holding cloud credentials; this is a
single-tenant local stdio MCP whose trust root is the installed package.

### Fixed — self-scan exceptions

- Refreshed `.github/security-exceptions-ci.json` for the v1.3.2 998-rule cloud-controls
  expansion: the insecure-by-design IaC test fixtures emit renamed detection IDs
  (`CFN_S3_BLOCK_PUBLIC_ACCESS`, `CFN_CLOUDTRAIL_MULTIREGION`, `CFN_EC2_IMDSV2`,
  `AWS_S3_ACL_NOT_PUBLIC`, `GCP_SQL_SSL_MODE_ENCRYPTED_ONLY`, `BICEP_STORAGE_NO_PUBLIC_BLOB`,
  `AZURE_BICEP_STORAGE_NETWORK_DENY_DEFAULT`) that the stale exception list missed.
- Excepted `CI_FORK_SECRET_EXPOSURE` on the repo's own `pull_request` workflow: GitHub does
  not expose secrets to fork PRs, so the referenced `SECURITY_POLICY_HMAC_KEY` is not
  reachable by fork contributors (conservative true-positive, not exploitable here).
- Both are repo-local self-scan suppressions only; `.github/` is not in the published npm
  package, so downstream detection is unaffected.

## [1.3.2] - 2026-06-18

### Added — cloud security controls engine

- **Registry-driven cloud controls engine** (`security.run_pr_gate` check + `security-mcp autoharden`).
  Detects misconfigurations in infrastructure-as-code against **998 rules** mapped to AWS
  Foundational Security Best Practices (FSBP), CIS Benchmarks (AWS / GCP / Azure), and the Microsoft
  Cloud Security Benchmark.
  - Coverage: **AWS 483 · Azure 320 · GCP 195** rules across **Terraform/HCL (774)**,
    **CloudFormation (128)**, and **Bicep (96)**.
  - **Auto-remediation** for Terraform via `security-mcp autoharden` (`--dry-run` to preview): applies
    `set-attr` and `companion-resource` fixes, then re-detects to verify each fix cleared the
    violation before keeping it. Rules it cannot safely auto-fix are emitted as manual actions.

### Added — CLI

- `security-mcp ci:pr-gate` — run the policy gate directly from the CLI / `npx` (previously only
  available as the `npm run ci:pr-gate` script). Honors the `SECURITY_GATE_*` environment variables
  and exits non-zero on `HIGH`/`CRITICAL` findings.
- `security-mcp sign-policy` — sign the active policy file with `SECURITY_POLICY_HMAC_KEY`, writing a
  `0o600` `.hmac` sidecar so policy tampering is detected at gate startup.

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
