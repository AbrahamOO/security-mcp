# Changelog

All notable changes to `security-mcp` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project adheres to [Semantic Versioning](https://semver.org/).

## [1.3.5] - 2026-07-07

First version published to npm since 1.3.4. The versions documented below as 1.4.0,
1.5.0, 1.6.0, and 1.6.1 were internal milestones that never reached the registry (their
publishes failed on a registry credential issue); everything they describe ships publicly
in this release. The npm version sequence therefore continues 1.3.4 → 1.3.5, while the
internal milestone numbers are retained below for historical accuracy.

### Added: pre-release checklist synced with the detection engine (8 new sections)

`security.checklist` (the `CHECKLIST_ALL` constant in `src/mcp/server.ts`) previously
documented only a subset of the surfaces the gate's check modules actually detect. The
checklist now carries a section for every detection domain, growing from roughly 180 to
246 items. New sections, each derived from the real finding IDs in `src/gate/checks/`:

- **Containers / Docker** — digest-pinned base images, non-root users, build-arg secret
  hygiene, host bind mounts, daemon exposure (from `docker-deep.ts`).
- **Database** — connection TLS, hardcoded credentials, dynamic SQL, MongoDB operator-key
  injection, RLS bypass, GRANT escalation (from `database.ts`).
- **Data Platform (Databricks / Snowflake)** — token expiry, network policies, Unity
  Catalog grants, masking policies, notebook SQL injection (from `data-platform.ts`).
- **GitOps (ArgoCD / Flux / Helm)** — plaintext secrets, project/RBAC scoping,
  ApplicationSet injection, source verification, chart pinning (from `gitops.ts`).
- **Cryptography / PKI** — weak hashes, nonce/IV reuse, AEAD tag verification, RSA and
  curve strength, CSPRNG use, post-quantum readiness (from `crypto.ts`).
- **AI-Assisted Development (Vibe Coding)** — hallucinated dependencies, Supabase
  RLS/service-role, client-side-only auth, provider keys in frontend bundles (from
  `vibe-coding.ts`).
- **Data Leakage Prevention (DLP)** — PII/tokens in logs, stack traces in responses,
  PII in cache keys, exposed backups (from `dlp.ts`).
- **Emerging Threats** — Next.js middleware auth bypass, RSC flight deserialization,
  JWT `jku`/`x5u` SSRF, IngressNightmare, IAM privilege-escalation chains (from the
  `emerging-*.ts` modules).

Existing sections were extended with supply-chain IoC/lockfile/MCP-config items and
AI/LLM items for invisible-Unicode injection, pickle opcode scanning, and
agent-to-agent credential forwarding.

### Changed — version

- `1.3.4` (npm) → `1.3.5`. Internal milestones 1.4.0–1.6.1 consolidated into this
  release; see the note at the top of this entry.

## [1.6.1] - 2026-07-06 (internal milestone — unpublished, consolidated into 1.3.5)

### Added: always-on "web-hardening" threat detection (6 new rules)

A new check module, `src/gate/checks/web-hardening.ts` (`checkWebHardening`), wired into
`runAllChecks` and `CHECK_NAMES` as `web-hardening`. Like `vibe-coding` and
`emerging-supply-ai`, it runs unconditionally on every scan, because the flaws it targets
are dangerous regardless of detected surface. First-party static rule coverage grows from
roughly 883 to roughly 887 finding IDs.

- **`WEB_MISSING_SECURITY_HEADERS`** (MEDIUM, CWE-1021/693): a web-server surface exists
  but there is no response-header hardening anywhere in the repo (no `helmet`, no
  `X-Frame-Options`, no HSTS, no Content-Security-Policy), leaving the app open to
  clickjacking and protocol downgrade with no CSP backstop. Conservative by design: fires
  once at repo level and skips static/library repos with no server surface to harden.
- **`WEB_OPEN_REDIRECT`** (HIGH, CWE-601): a redirect target taken directly from user
  input, e.g. `res.redirect(req.query.url)` or an unvalidated `NextResponse.redirect`.
- **`WEB_HARDCODED_SESSION_SECRET`** (HIGH, CWE-798/330): a session/cookie/JWT signing
  secret hardcoded as a literal or a well-known weak default (e.g. `"keyboard cat"`).
  Excludes `process.env` reads and `.env.example`; truncates the secret in evidence.
- **`WEB_EMAIL_HEADER_INJECTION`** (HIGH, CWE-93/88): user input flowing unsanitized into
  email envelope fields (nodemailer/SendGrid `to`, `subject`, headers), enabling CRLF
  header injection and mail-relay abuse.
- **`WEB_SERVER_ACTION_NO_AUTHZ`** (HIGH, CWE-306/862): a Next.js Server Action
  (`'use server'`) that performs a DB mutation/read with no server-side auth verifier;
  Server Actions are publicly-invocable POST endpoints, so hiding the triggering button
  does not protect them.
- **`WEB_SENSITIVE_FIELD_IN_RESPONSE`** (MEDIUM, CWE-213/200): a serialized DB row/object
  that includes a secret field (`passwordHash`, `salt`, `mfaSecret`, `apiKey`,
  `refreshToken`, `ssn`), or a `SELECT *`-to-response shape.

All six rules were verified firing on planted vulnerabilities. Detection follows the same
regex/heuristic convention as the rest of the gate: no AST or data-flow analysis.

### Changed: remediation map reaches 888 templates, 100% (887/887) detection-ID coverage

- Before 1.6.1, only 71 of roughly 882 finding IDs (about 8%) had a concrete remediation
  template. `src/gate/remediation-map.ts` now composes `REMEDIATION_MAP` from six domain
  partials under `src/gate/remediation-parts/`: `cloud.ts` (256 templates: Kubernetes,
  IaC, Docker, ArgoCD, Flux, Helm, GitOps, infrastructure, runtime), `ai.ts` (69:
  AI/agentic), `data.ts` (172: crypto, JWT, SAML, OAuth, passwords, database, Snowflake,
  Databricks, supply-chain hygiene), `web.ts` (203: web, API, business logic, GraphQL,
  Android, iOS, DLP, CI), `misc.ts` (112: injection, deserialization, SSRF, TLS, tokens,
  mobile storage, XSS), and `web-hardening-remediations.ts` (6, one per new `WEB_` rule
  above).
- Result: 888 fix templates covering 100% (887/887) of detection IDs, up from roughly 8%.
  Each template ships a realistic vulnerable pattern, a concrete secure fix in the correct
  language, a plain-language explanation, and standards references (CWE plus OWASP Top 10
  / API Top 10 / LLM Top 10 / MASVS, and NIST / CIS / PCI DSS / FIPS or the relevant
  provider's docs). This makes the product's "90% fixing, 10% advisory" operating mandate
  a deterministic, verifiable property of the engine, rather than something carried only
  by the live agent's judgment.

### Changed — version bump

- `1.6.0` → `1.6.1` (odometer rule: all version segments stay below 10).

## [1.6.0] - 2026-07-06 (internal milestone — unpublished, consolidated into 1.3.5)

### Added: always-on "vibe coding" threat detection (16 new rules)

A new check module, `src/gate/checks/vibe-coding.ts` (`checkVibeCoding`), wired into
`runAllChecks` and `CHECK_NAMES` as `vibe-coding`. Unlike the surface-gated 1.5.0 modules,
it runs unconditionally on every scan, the same way `emerging-supply-ai` does, because a
leaked admin key or an open database rule is dangerous regardless of what surface the
changed files suggest. It targets the recurring failure modes of apps scaffolded by
Cursor, Lovable, Bolt, v0, and Replit, grounded in the Moltbook Supabase `service_role` key
leak, Lovable's "VibeScamming" Row-Level-Security gap (CVE-2025-48757), the Tea app's
world-writable Firebase rules, Base44's frontend-only auth check, Replit Agent incidents,
and slopsquatting research. First-party static rule coverage grows from roughly 867 to
roughly 883 finding IDs.

- **Client-side secret exposure (CRITICAL).** `VIBE_SUPABASE_SERVICE_ROLE_IN_CLIENT`
  (the Moltbook breach): a `service_role`/`sb_secret_` Supabase key, or a service-role JWT
  literal, referenced in browser-shipped code. `VIBE_PUBLIC_ENV_HOLDS_SECRET`: a
  `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`/`EXPO_PUBLIC_` variable whose name indicates a real
  secret rather than a publishable value. `VIBE_PROVIDER_KEY_IN_FRONTEND`: an
  Anthropic/OpenAI/Stripe/AWS/Google/GitHub key literal hardcoded in the client tree.
- **Datastore access control (CRITICAL).** `VIBE_SUPABASE_RLS_DISABLED` (CVE-2025-48757):
  a `CREATE TABLE` with no `ENABLE ROW LEVEL SECURITY` in the same file, or a
  `CREATE POLICY ... USING (true)`. `VIBE_FIREBASE_RULES_PUBLIC` (the Tea app breach):
  Firestore/Storage/RTDB rules that allow read or write when `true`.
- **Missing server-side authorization (HIGH).** `VIBE_API_ROUTE_NO_SERVER_AUTHZ` (the
  Base44 breach): a server handler that reads request input or hits the database with no
  recognizable auth verifier. `VIBE_CLIENT_SIDE_AUTH_GUARD_ONLY`: access enforced only by
  a client-component redirect guard, which runs in the attacker's browser and is
  bypassable. `VIBE_CORS_WILDCARD_CREDENTIALS`: a bare `cors()` or a wildcard/reflected
  origin combined with `credentials: true`.
- **Trust-boundary and storage issues (HIGH).** `VIBE_CLIENT_CONTROLLED_PRICE`: a
  payment amount/price/total read directly from the request body or query.
  `VIBE_TOKEN_IN_LOCALSTORAGE`: a session token or API key stored in `localStorage`,
  readable by any XSS on the page. `VIBE_UNRESTRICTED_FILE_UPLOAD`: an upload handler with
  no MIME/extension allowlist or size limit. `VIBE_ENV_FILE_COMMITTED`: a `.env`,
  `serviceAccount*.json`, `*.pem`, or SSH private key present on disk and not covered by
  `.gitignore`. `VIBE_DEBUG_MODE_ENABLED`: Flask/Django debug mode, Express
  `errorhandler()`, or `err.stack` returned in an HTTP response.
- **Hardening and supply chain (MEDIUM).** `VIBE_SOURCEMAPS_IN_PROD`: production source
  maps enabled (`productionBrowserSourceMaps: true` / Vite `sourcemap: true`).
  `VIBE_HALLUCINATED_OR_UNVETTED_DEP`: a dependency declared in `package.json` /
  `requirements.txt` but absent from the lockfile, an offline slopsquatting heuristic. A
  missing lockfile entry is a candidate for manual verification against the official
  registry, not proof of a hallucinated or malicious package.
- **AI-specific chain (HIGH).** `VIBE_PROMPT_INJECTION_UNSAFE_CHAIN`: user input
  concatenated into a system/instruction prompt, or model output passed into
  `eval`/`exec`/a shell/`dangerouslySetInnerHTML`.

Detection follows the same regex/heuristic convention as the rest of the gate: no AST or
data-flow analysis. The client-vs-server split used by several rules is a path/extension
heuristic (files under `src/`, `app/`, `pages/`, `components/`, `public/`, or with a
`.tsx`/`.jsx`/Vue/Svelte extension count as client-shipped, unless the path marks a server
handler), not a bundler or build-graph analysis, so it can misclassify unconventional
project layouts. Every rule is wrapped so a malformed input or an internal error degrades
to no finding rather than crashing the gate, and secret evidence is truncated, never echoed
in full.

### Changed: remediation map expanded to 70+ templates

- Added a concrete fix template for every new `VIBE_` finding ID in
  `src/gate/remediation-map.ts`: rotate-and-move-server-side guidance for leaked keys, an
  `ENABLE ROW LEVEL SECURITY` + ownership-policy snippet, a `getServerSession` check for
  API routes, an httpOnly-cookie pattern for token storage, a `multer` `fileFilter` +
  `limits` example, and more. This keeps the roughly 90%-fixing, 10%-advisory posture
  intact as detection coverage grows.

## [1.5.0] - 2026-07-06 (internal milestone — unpublished, consolidated into 1.3.5)

### Added — 20 new detection rules for 2025-2026 CVEs and agentic-AI threats

Three new check modules, wired into `runAllChecks` alongside the existing surface-gated
checks. First-party static rule coverage grows from roughly 847 to roughly 867 finding IDs.

- **`emerging-web` (runs on web/API surfaces).** `WEB_NEXTJS_MIDDLEWARE_AUTH_BYPASS`
  (CVE-2025-29927): CRITICAL when a vulnerable `next` version is paired with
  auth-in-middleware, MEDIUM when the version cannot be resolved to a concrete value.
  `WEB_PROXY_MIDDLEWARE_HEADER_UNSTRIPPED`: LOW hardening gap for reverse proxies that do
  not strip `x-middleware-subrequest`. `WEB_RSC_FLIGHT_DESERIALIZATION_RCE` ("React2Shell",
  CVE-2025-55182): version-gated on React 19.0.0-19.2.0. `WEB_DJANGO_ORM_CONNECTOR_SQLI`
  (CVE-2025-64459): CRITICAL when unsafe ORM lookup patterns correlate with request input,
  or when the Django version alone is vulnerable. `WEB_KESTREL_CHUNKED_SMUGGLING`
  (CVE-2025-55315): HIGH on the `InsecureChunkedParsing` compatibility switch or a
  vulnerable ASP.NET Core version. `WEB_JWT_JKU_X5U_SSRF`: HIGH when a JWT header's `jku`
  or `x5u` claim flows into an HTTP client call with no allowlist. `WEB_PATH_TO_REGEXP_REDOS`:
  MEDIUM, read from the resolved lockfile version rather than the manifest range.
- **`emerging-cloud` (runs on infrastructure surfaces).**
  `K8S_INGRESS_NGINX_SNIPPET_INJECTION` ("IngressNightmare", CVE-2025-1974): CRITICAL on
  injectable snippet annotations or a controller image below the fixed tag.
  `IAC_AWS_PASSROLE_PRIVESC_CHAIN`: HIGH, escalating to CRITICAL on a wildcard-resource
  `iam:PassRole` with no `iam:PassedToService` condition; now also covers the Bedrock
  AgentCore code-interpreter delivery vector. `IAC_TF_MODULE_GIT_UNPINNED_REF`: HIGH for
  git-sourced Terraform modules without a 40-character commit SHA pin.
  `IAC_GCP_TOKEN_CREATOR_PROJECT_BINDING`: HIGH when a token-creator or service-account-user
  role is bound at the project scope. `K8S_RUNC_ESCAPE_DELIVERY_SURFACE`
  (CVE-2025-31133/52565/52881): HIGH for privileged or arbitrary-`hostPath` containers with
  no user-namespace remap.
- **`emerging-supply-ai` (always runs).** `SUPPLY_SHAI_HULUD_IOC`: CRITICAL, matches
  oversized worm payload filenames, a known IOC hash in a lockfile, or a lifecycle script
  that exfiltrates tokens. `SUPPLY_LOCKFILE_OFFREGISTRY_RESOLVED`: HIGH for lockfile
  entries resolved from a host outside the recognized public and private registry list.
  `SUPPLY_MCP_REMOTE_COMMAND_INJECTION` (CVE-2025-6514): CRITICAL on a vulnerable
  `mcp-remote` version, HIGH on the code-pattern signal alone.
  `AI_INVISIBLE_UNICODE_INJECTION`: HIGH, detects Unicode tag, zero-width, bidi-override,
  and variation-selector characters; emits only the codepoint and location, never the raw
  invisible bytes. `AI_MCP_CONFIG_RUG_PULL` (CVE-2025-54136/54135): HIGH for MCP server
  configs that shell out or invoke an unpinned package. `AI_MODEL_PICKLE_OPCODE_DANGEROUS`:
  CRITICAL, a best-effort binary heuristic that scans model files for dangerous pickle
  opcodes combined with dangerous module names; it can miss obfuscated payloads and flag
  benign files, and a clean result is not proof of safety. `AI_A2A_CREDENTIAL_FORWARDING`:
  HIGH for a caller's raw bearer token or environment secret forwarded into a downstream
  agent call with no scoping.

All three modules follow the existing check-engine contract: regex- and manifest-based
heuristics, no AST or data-flow analysis, wrapped so a single rule failure degrades to an
empty result instead of crashing the gate.

### Added — capability-floor enforcement for spawned agents

- **`enforceCapabilityFloor`.** A new check in `src/mcp/capability-enforcer.ts`, invoked
  from `orchestration.merge_agent_findings` as an additional thoroughness check. For every
  agent in the run it evaluates four floors: the model tier required by the task under
  `model-router`'s task-capability map, the SKILL.md `allowed-tools` floor, non-empty
  evidence for high-risk leads, and SKILL.md section coverage (delegated to the existing
  `verifySkillCoverage`).
- **New findings.** A degraded agent raises a HIGH `CAPABILITY_DEGRADED` finding. Any
  degraded agent in the run raises one run-level CRITICAL `CAPABILITY_FLOOR_NOT_MET`
  finding, which forces the gate to FAIL. Floors that cannot be evaluated raise a MEDIUM
  `CAPABILITY_UNVERIFIED` advisory instead of a silent pass or a hard failure.
- **Known gap, documented honestly.** Orchestration does not yet record which model, task
  type, and tools a spawned agent actually used. Until it does, the model-tier and
  tool-floor checks surface as MEDIUM advisories rather than HIGH violations. The forward-
  compatible schema for this metadata (`modelUsed`, `taskType`, `toolsUsed`) already exists
  in `capability-enforcer.ts`; wiring orchestration to populate it is tracked as a
  follow-up.
- Enforcement never crashes the merge: any internal error in the enforcer degrades to a
  non-fatal warning rather than blocking the run.

### Changed — remediation map expanded from 15 to 55 templates

- Added a concrete fix template for every new 1.5.0 finding ID, and for the largest
  previously-uncovered gaps from earlier releases, keeping the roughly 90%-fixing,
  10%-advisory posture as detection coverage grows.
- Removed the orphaned `DEP_FLOATING_VERSION` template, which had no matching finding ID,
  and replaced it with `DEP_UNPINNED_VERSION`.

## [1.4.0] - 2026-07-05 (internal milestone — unpublished, consolidated into 1.3.5)

### Changed — full-power model routing by default

Security agents now run at maximum capability by default instead of cheapest-first.

- **Capability-first advanced tier.** Security-critical reasoning tasks (`code_review`,
  `remediation`, `threat_model`, `compliance_analysis`, `exploit_chain`, `ai_redteam`,
  `pentest`, `crypto_analysis`, `auth_analysis`, `incident_response`, `risk_scoring`)
  default to the `advanced` capability tier. Within that tier the router now selects the
  most capable model (Claude Opus 4.8) first and uses cost only as a tiebreak, so flagship
  security reasoning is never silently downgraded to a cheaper, weaker advanced model.
- **Budget safety valve with a protected set.** When spend utilization reaches
  `model_budget.downgrade_threshold_pct` (default 80), only NON-protected advanced tasks
  drop to standard, emitting a `MODEL_BUDGET_DOWNGRADE` audit event. The protected set —
  `exploit_chain`, `pentest`, `ai_redteam`, `crypto_analysis`, `auth_analysis`,
  `threat_model`, `remediation` — never downgrades, regardless of spend.
- **Opt-out, not opt-in.** New `model_budget.force_standard_tier_for` list forces named
  tasks down to standard; protected tasks ignore it. Legacy `advanced_task_preference` is
  still honored (unioned in, never reduces power). Light mechanical tasks (`secret_scan`,
  `dlp_scan`, `pattern_match`, manifest/lockfile parsing, `config_read`, `dependency_scan`)
  stay on the cheap tier; `report_generation` stays standard.
- **Refreshed model IDs and honest logging.** `SONNET_MODEL` is now `claude-sonnet-5`,
  the advanced tier is `claude-opus-4-8`, Haiku is `claude-haiku-4-5`. Routing decisions
  log reason `max_power_advanced` for advanced selections, and degrade gracefully with a
  `MODEL_ADVANCED_UNAVAILABLE` event if no advanced model is healthy.

### Added — orchestration thoroughness enforcement

A green gate now requires proof that agents did thorough work, not just that they
reported success.

- **Coverage gate.** `orchestration.merge_agent_findings` auto-runs SKILL.md section
  coverage verification and forces the gate to FAIL when coverage falls below a threshold
  (default 90%, `SECURITY_MIN_SKILL_COVERAGE_PCT`), listing uncovered sections.
- **Ghost / missing-agent detection.** Required Phase-1 lead agents must report
  `completed` / `completed_partial`; a missing lead forces the gate to FAIL.
- **Semantic finding validation.** Findings marked remediated must carry a remediation
  summary; a completed high-risk lead with zero findings and no explicit "no issues found"
  note raises `WEAK_AGENT_OUTPUT`.
- **Agent failure escalation.** Failed agents are retried up to twice
  (`AGENT_RETRY_TRIGGERED`) then escalated (`AGENT_ESCALATION_REQUIRED`), forcing the gate
  to FAIL. New optional manifest fields `failureCount` / `escalationRequired`
  (`defaults/agent-run-schema.json`) are backward compatible.
- **Prompt-injection hardening.** Nested `stackContext` string arrays are sanitized before
  they reach spawned-agent prompts.

### Added — 155 new detection rules

Net 155 new unique detection rules across the check engine, plus new AWS cloud-control
rules (controls engine total: 1,002). Highlights by domain:

- **Injection / database:** HTTP request smuggling, .NET / XSLT / Groovy / Perl template
  and code injection, MongoDB server-side JS and operator-key injection, prepared-statement
  misuse, dynamic SQL, RLS-bypass and GRANT privilege escalation.
- **Auth / crypto:** JWT `kid` injection and `none`-in-alg-list, OIDC nonce, OAuth code
  reuse, SAML assertion XXE, predictable session IDs, post-login open redirect; static-IV
  and stream-cipher nonce reuse, AEAD tag not verified, insecure RNG for key material,
  hardcoded symmetric keys, weak ECDSA curve, SHA-1 signatures, weak KDF parameters.
- **Secrets / DLP:** OpenSSH keys, webhook signing secrets, container-registry passwords,
  client-exposed API keys; PHI / biometric / OAuth-token / passport / license in logs,
  web-exposed database backups.
- **Business logic / API / GraphQL / web:** payment idempotency, wallet and gift-card
  non-atomic decrement, refund-without-purchase, bulk operations not tenant-scoped,
  inventory underflow; webhook signature verification, batch amplification; GraphQL
  auth-cache leakage, mutation rate limiting, subscription DoS; Next.js client env leakage,
  image-loader SSRF, middleware matcher gaps, SSR fetch of user input.
- **Cloud / Kubernetes / CI / supply chain:** VPC flow logs, CloudTrail, IAM privilege
  escalation (`PassRole` / `CreatePolicyVersion`), Lambda plaintext env secrets, K8s
  default-SA token automount and admission-webhook external URLs, PodSecurity exemptions;
  `COPY .git`, plaintext build fetch, CI job-level secret env, secret-in-step-output,
  secrets passed to third-party actions, self-hosted runners on PR triggers, ArgoCD
  default-project auto-prune, Flux validation disabled, git-protocol / local-path
  dependency overrides, install-integrity bypass.
- **AI / LLM / agentic / data platform:** unsafe model deserialization
  (pickle / joblib / torch), insecure LLM output handling, tool-call substitution,
  confused-deputy tool chains, missing RAG tenant filter, cross-user prompt caching; MCP
  tool-description poisoning, recursive base64, instruction chain-loading, homoglyph / bidi
  obfuscation, script-in-markdown, symlink escape; notebook SQL injection, Snowflake
  dynamic SQL, non-expiring Databricks tokens.
- **Mobile:** Android WebView user-controlled load, wildcard-MIME intent filters,
  world-readable file modes, cleartext traffic; iOS WKWebView custom-scheme handlers,
  synchronizable keychain, pasteboard access without a user gesture, method swizzling,
  keychain accessible-when-locked.

## [1.3.4] - 2026-06-19

### Changed

- **README architecture diagrams render on npm.** The five Mermaid diagrams were
  pre-rendered to static SVGs under `assets/diagrams/` and embedded via absolute
  `raw.githubusercontent.com` image URLs. npm does not render Mermaid code fences,
  so they previously showed as raw code blocks on the package page; they now
  display as images on both npm and GitHub.
- **Security gate runs on push to `main`.** `security-gate.yml` previously triggered
  only on `pull_request`, so the CI status badge never reflected the default branch
  and could stay red after a fix merged. It now also runs on push to `main`.

### Added

- **Odometer versioning tooling.** `npm run version:bump` / `version:check` and the
  shared `scripts/version-rule.mjs`. The publish workflow runs `version:check` on
  every release tag and refuses to publish a version whose `minor`/`patch` segment
  is `>= 10` or whose `vX.Y.Z` tag does not match `package.json`. Documented in
  `CONTRIBUTING.md`.

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
