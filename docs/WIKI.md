# Wiki

Last updated: 2026-07-17

A practical reference for running security-mcp, understanding how the gate decides
PASS/FAIL, the full list of rule IDs added in 1.5.0, 1.6.0, and 1.6.1, how capability
enforcement works, how to add a new check module, and the environment variables relevant
to the new features. For a description of how the pieces fit together, see
[ARCHITECTURE.md](ARCHITECTURE.md).

> **Version note:** 1.4.0, 1.5.0, 1.6.0, and 1.6.1 referenced throughout this document
> are internal milestones that were never published to npm. All of them ship publicly in
> **1.3.5** (the first npm release after 1.3.4). The milestone labels are kept because the
> CHANGELOG documents features under them.

## The pre-release checklist (`security.checklist`)

The `security.checklist` MCP tool returns the human pre-release attestation checklist,
optionally filtered by surface (`web`, `api`, `mobile`, `ai`, `infra`, `payments`, `all`).
As of 1.3.5 the checklist is synced with the detection engine: it carries a section for
every detection domain the gate's check modules cover — 246 items across 21 sections,
including Containers / Docker, Database, Data Platform (Databricks / Snowflake), GitOps
(ArgoCD / Flux / Helm), Cryptography / PKI, AI-Assisted Development (Vibe Coding), Data
Leakage Prevention, and Emerging Threats, each derived from the finding IDs in
`src/gate/checks/`. The checklist is deliberately an *attestation* layer for what static
analysis cannot verify (runtime behavior, red-team exercises, rollback drills); the
automated PASS/FAIL enforcement described below never depends on it.

## Is security-mcp safe to use? (the MCP's own security & governance)

A security tool that reads your repository and calls out to an AI model is itself part
of your trust boundary, so this section documents security-mcp's own trust model: what
data leaves your machine, how the gate resists being silently weakened, and what happens
when a component inside it fails or is tampered with. Every mechanism below is implemented
in the code cited, not aspirational.

### Local, single-process, stdio trust model

security-mcp runs as an MCP server over stdio (`src/mcp/server.ts` connects with
`new StdioServerTransport(); await server.connect(transport);`) or as a plain CLI. There is
no `.listen()`, no `createServer`, no HTTP framework, and no inbound network listener
anywhere in `src/mcp/`. Because it has no server surface of its own, there is nothing on
the network for an outside attacker to connect to. The only outbound network calls are
ones you opt into: live threat intel (CISA KEV, EPSS, OpenSSF Scorecard, npm registry),
scanner-binary and skill downloads, and any Slack/Jira/PagerDuty/webhook integration you
configure. There is no telemetry or analytics call anywhere in the server or CLI code. Set
`SECURITY_OFFLINE=1` for a fully air-gapped run that disables all third-party egress.

The stdio channel itself can be gated with caller authentication: `src/mcp/auth.ts`
implements an opt-in shared secret (`SECURITY_MCP_SHARED_SECRET`), a constant-time HMAC
comparison (`timingSafeEqual`) so timing side-channels can't leak the secret, a 3-strike
lockout, and a session TTL (8 hours by default, capped at 24). When the shared secret is
unset, the channel stays open for frictionless local use — a deliberate default for a
single-user local tool, not an oversight.

### How does security-mcp protect my code and secrets?

Finding evidence never echoes the thing it detects. Secret-scan matches are replaced with
`[REDACTED]` (`src/gate/checks/secrets.ts`); a hardcoded session, cookie, or JWT secret is
shown truncated as `prefix…suffix` via a `truncateSecret` helper
(`src/gate/checks/web-hardening.ts`); and the invisible-Unicode prompt-injection rule
(`AI_INVISIBLE_UNICODE_INJECTION`) reports only the codepoint and location — `U+200B` at
`file:line` — never the raw invisible bytes (`src/gate/checks/emerging-supply-ai.ts`).

Regex-based scanning is hardened against hostile input in the same spirit: `searchRepo`
(`src/repo/search.ts`) runs every pattern through `isCatastrophicRegex`, which rejects
nested quantifiers, ambiguous alternation, and other catastrophic-backtracking shapes, and
caps any user-supplied pattern at `MAX_REGEX_LEN` (500 characters) before compiling it.
This is a heuristic signature-and-length guard, not a formal proof of ReDoS-safety, but it
means a crafted string planted in a malicious repository can't hang the scanner.

### Can the gate be silently disabled?

Not without leaving evidence. Policy, exceptions, and baseline files are HMAC-signed
(`SECURITY_POLICY_HMAC_KEY`, generated via `security-mcp sign-policy`), enforced in
`src/gate/policy.ts`, `src/gate/exceptions.ts`, and `src/gate/baseline.ts`. If a key is
set, a missing `.hmac` sidecar or a bad signature throws outright. If no key is set at
all, the gate does not silently trust the file: `policyIntegrityVerified` evaluates to
false, and the gate force-adds `HIGH` and `CRITICAL` back into `blockedSeverities`
regardless of what the policy file's `severity_block` says. In practice this means an
attacker who edits an unsigned policy file to clear `severity_block: []` still cannot get
a HIGH or CRITICAL finding to pass — the floor is enforced in code, not by trusting the
file's own content.

Crash containment works the same way: all check modules run in parallel via
`Promise.allSettled`, and a module that throws produces a `severity: "HIGH"` finding with
`id: "GATE_CHECK_CRASHED"` naming the failed module, rather than disappearing from the
result set. The error text that reaches that finding is passed through
`sanitizeErrorMessage` (`src/gate/result.ts`), which strips absolute Unix and Windows
filesystem paths (CWE-200/CWE-209) before the message is ever surfaced.

### Can a multi-agent run fake a clean result?

Every `/ciso-orchestrator` run writes a hash-linked attestation chain
(`src/mcp/audit-chain.ts`: `initChain`, `attestAgent`, `verifyChain`, `getChain`,
`computeFindingsHash`), optionally HMAC-signed with `SECURITY_AUDIT_HMAC_KEY`. The merge
step (`orchestration.merge_agent_findings` in `src/mcp/orchestration.ts`) calls
`verifyChain`, then checks each agent's raw findings hash against the hash recorded in
that agent's signed attestation before trusting the file; a hash mismatch or a tampered
chain forces the gate to FAIL. Set `SECURITY_REQUIRE_AGENT_ATTESTATION=1` to fail closed
unless the run is signed, enforced, and clean. The corresponding MCP tools —
`security.attest_review`, `security.attest_agent`, `security.verify_chain` — are how you
inspect or drive this chain directly.

Spawned agents are also held to a capability floor so a run can't quietly under-deliver.
`enforceCapabilityFloor` (`src/mcp/capability-enforcer.ts`) checks, per agent, whether it
ran at the model tier its task type requires (per `model-router.ts`'s
`TASK_CAPABILITY_MAP`), whether it had and used its declared tool floor, and whether a
high-risk lead produced real evidence rather than a silent empty result. A shortfall
raises a HIGH `CAPABILITY_DEGRADED::<agentName>` finding, and any degraded agent in the
run raises one run-level CRITICAL `CAPABILITY_FLOOR_NOT_MET` that forces the gate to FAIL.
Honestly disclosed limitation: the model-tier and tool floors depend on per-agent metadata
(`modelUsed`, `taskType`, `toolsUsed`) that orchestration does not yet record for every
agent, so those two floors currently surface as a MEDIUM `CAPABILITY_UNVERIFIED` advisory
rather than a hard pass or fail until that metadata is wired up — see "Capability
enforcement" above for the full detail.

### Does it execute anything unsafely?

Child processes the tool spawns itself — resolving an installed CLI, running `git`,
running `npm audit`, downloading a scanner binary — are invoked with `spawnSync`/
`execFile` and fixed argument arrays, never a shell string built from repo or user input
(`src/cli/onboarding.ts`, `src/gate/baseline.ts`). There is no code path in the tool that
interpolates untrusted input into a shell command. Network fetches are similarly
restricted: scanner-binary downloads are checked against an explicit host allowlist
(`ALLOWED_BINARY_HOSTS` in `src/cli/onboarding.ts`, limited to GitHub release hosts) and
downloaded binaries are verified by SHA-256 before use; skill downloads are checked
against a `raw.githubusercontent.com`-only URL prefix (`src/mcp/orchestration.ts`). There
is no `curl | sh` install path.

### Does security-mcp trust itself?

It scans its own source on every change. `.github/workflows/security-gate.yml` runs the
same gate (`ci:pr-gate`) against security-mcp's own repository in CI, alongside gitleaks,
trivy, semgrep, and checkov, with a narrowly-scoped
`.github/security-exceptions-ci.json` covering only the handful of intentional
insecure-by-design test fixtures and controls that are genuinely not applicable to this
repo — that file never ships in the published npm package, so it has no effect on
downstream detection.

Its own supply chain stays deliberately small and pinned: `package.json` declares five
runtime dependencies (`@modelcontextprotocol/sdk`, `execa`, `fast-glob`, `picomatch`,
`zod`), `package-lock.json` is committed, and third-party GitHub Actions in
`.github/workflows/` are pinned to full 40-character commit SHAs (with the version as a
trailing comment) rather than floating tags like `@v4`.

### Summary

| Mechanism | What it protects | Where in code |
| --- | --- | --- |
| Local stdio process, no listener, no telemetry | Your code never leaves your machine to a third party by default | `src/mcp/server.ts` |
| Optional shared-secret + HMAC caller auth on the stdio channel | Prevents an unauthorized local caller from driving the tool | `src/mcp/auth.ts` |
| HMAC-signed policy / exceptions / baseline | An unsigned edit can't silently weaken the gate; HIGH/CRITICAL stay blocked | `src/gate/policy.ts`, `src/gate/exceptions.ts`, `src/gate/baseline.ts` |
| Hash-linked, optionally signed audit chain + attestations | A verified record of what actually ran, not a self-reported one | `src/mcp/audit-chain.ts`, `src/mcp/orchestration.ts` |
| Capability-floor enforcement for spawned agents | Agents can't silently run under-powered or unsupervised | `src/mcp/capability-enforcer.ts`, `src/mcp/model-router.ts` |
| Fail-safe crash containment | A crashing check becomes a HIGH finding, not a silent blind spot | `src/gate/policy.ts`, `src/gate/result.ts` |
| ReDoS-hardened pattern matching | A hostile repo or string can't hang the scanner | `src/repo/search.ts` |
| Secret/PII redaction in findings | Findings never echo a full secret or raw invisible bytes | `src/gate/checks/secrets.ts`, `src/gate/checks/web-hardening.ts`, `src/gate/checks/emerging-supply-ai.ts` |
| Host-allowlisted downloads + SHA-256 verified binaries | Skill/scanner fetches can't be redirected to an attacker host | `src/cli/onboarding.ts`, `src/mcp/orchestration.ts` |
| No-shell child processes | Can't be turned into a command-injection vector | `src/cli/onboarding.ts`, `src/gate/baseline.ts` |
| Self-scan in CI | The gate is held to its own bar on every change | `.github/workflows/security-gate.yml` |
| Minimal, pinned dependencies | Small, auditable attack surface | `package.json`, `.github/workflows/` |

### Honest residual risk

security-mcp does not overclaim its own trust model. As the CHANGELOG documents: an
*unsigned* attestation chain is tamper-evident, not tamper-proof, against an attacker who
already has write access to `.mcp/agent-runs/{id}/` — `SECURITY_AUDIT_HMAC_KEY` is the
real boundary, not the chain's hash-linking alone. This is a single-tenant, local, stdio
MCP whose trust root is the installed package, not a distributed system defending against
a remote adversary with its own credentials. See the "Residual risk (accepted — local
single-process trust model)" note in [CHANGELOG.md](../CHANGELOG.md) for the full
disclosure.

## Running the two entry points

security-mcp exposes two ways to use the gate interactively, plus a non-interactive CI
path.

**`/senior-security-engineer`** is the daily-driver skill. Invoke it from an MCP-connected
editor (Claude Code, Cursor, VS Code with GitHub Copilot, Windsurf, Codex, Replit, or any
MCP-compatible editor). It calls `security.start_review` to open a stateful run, works
through findings by writing fixes directly into your working tree, calls
`security.run_pr_gate` to re-check that a fix actually cleared, and calls
`security.attest_review` to write a signed attestation once the run is clean. This is the
right entry point for day-to-day changes: it is scoped to the current diff and is meant to
be fast.

**`/ciso-orchestrator`** is the full security program. It spawns a multi-agent run: Phase 1
discovery leads and their sub-agents in parallel, Phase 2 adversarial (pentest) and
compliance/GRC agents that consume Phase 1's threat model, Phase 3 synthesis via
`orchestration.merge_agent_findings`. Cloud, AI/LLM, and mobile sub-agents only activate
when the relevant stack is detected; otherwise they report N/A. Use this when the stakes
are high: a new feature area, a compliance audit, a pre-release review. It is slower and
more thorough than the daily skill by design.

**CI** runs the same gate without any AI session or MCP call. Install the
`security-gate.yml` workflow (or run `security-mcp ci:pr-gate` directly in any CI system).
It exits non-zero on any un-excepted HIGH or CRITICAL finding, which is what actually
blocks a merge; the interactive skills and CI enforce identically because they call the
same `runAllChecks` logic underneath.

## Client support matrix

security-mcp runs in any MCP-capable editor. The server is stdio; the agent roster is
delivered over the MCP protocol (prompts + resources), so the guided experience is not
Claude-only.

| Client | MCP config | Key / format |
| --- | --- | --- |
| Claude Code | `~/.claude/settings.json` | `mcpServers` (JSON) |
| Cursor | `~/.cursor/mcp.json` or `.cursor/mcp.json` | `mcpServers` (JSON) |
| VS Code / GitHub Copilot | `.vscode/mcp.json` | `servers` (JSON) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` (JSON) |
| Codex | `~/.codex/config.toml` or `.codex/config.toml` | `[mcp_servers.security-mcp]` (TOML) |
| Replit | Integrations UI (remote MCP) | hosted endpoint — no local stdio config |

`npx -y security-mcp@latest install` writes the correct config for every detected local
client; `doctor` verifies it. The installer also drops a per-client instruction file
(`.cursor/rules`, `.github/copilot-instructions.md`, `.windsurf/rules`, `AGENTS.md`) that
tells each host how to drive the agents.

### Portable agent delivery

The two entry prompts (`senior-security-engineer`, `ciso-orchestrator`) are MCP prompts,
so they appear as slash commands / prompt pickers in every client. Every specialist
persona is reachable two ways: the `skill://<name>` MCP resource (browse `skill://catalog`
for the roster) and the `orchestration.ensure_skill` tool, which returns the full SKILL.md
on demand. A host with parallel subagents runs the roster concurrently; a host without one
runs the agents sequentially, each to full completion — `orchestration.verify_skill_coverage`
gates run completion either way, so no agent is skipped and no persona is abbreviated.

## How the gate decides PASS/FAIL

1. The policy file (default `.mcp/policies/security-policy.json`) sets
   `severity_block`, which defaults to `["HIGH", "CRITICAL"]`. If the policy is not
   HMAC-signed (`SECURITY_POLICY_HMAC_KEY` unset), `HIGH` and `CRITICAL` are forced into
   the blocking set regardless of what the policy file says, so an unsigned edit can never
   relax the gate.
2. Surfaces are detected from the changed files (web, API, infra, iOS, Android, AI/LLM,
   agentic), and every check module relevant to those surfaces runs, alongside the checks
   that always run regardless of surface.
3. All checks run in parallel via `Promise.allSettled`. A crashing check becomes a HIGH
   `GATE_CHECK_CRASHED` finding rather than disappearing silently.
4. Findings are deduplicated, assigned an SLA by severity (CRITICAL 24h, HIGH 7d, MEDIUM
   30d, LOW 90d), and checked against the exceptions file; an approved, unexpired exception
   suppresses its listed finding IDs, and an expired one becomes a blocking finding again.
5. A regression check compares against the last saved baseline: a control that was
   previously satisfied and is now missing becomes a HIGH finding even if no check module
   directly re-detected the underlying issue.
6. **Verdict:** if any finding that survives the steps above has a severity in the blocked
   set, the gate is FAIL. Otherwise it is PASS. There is no partial-credit scoring.

In a `/ciso-orchestrator` run, the gate can also fail for reasons unrelated to any single
finding's severity: SKILL.md section coverage below the required threshold, a missing or
ghost required lead agent, an escalated agent that exhausted its retries, or (new in 1.5.0)
a capability-floor violation. See "Capability enforcement" below.

## 1.5.0 rule IDs

All 1.5.0 rules are regex/manifest-based heuristics, consistent with the rest of the check
engine: there is no AST or data-flow analysis anywhere in the gate. Version-gated rules
read a package's manifest or lockfile; when the exact version cannot be resolved (a range
specifier, a dist-tag, or a missing file), the rule downgrades to a MEDIUM advisory rather
than asserting a hard finding.

### `emerging-web` (`src/gate/checks/emerging-web.ts`, runs on web/API surfaces)

| Rule ID | Reference | Severity | What it detects |
| --- | --- | --- | --- |
| `WEB_NEXTJS_MIDDLEWARE_AUTH_BYPASS` | CVE-2025-29927 | CRITICAL (MEDIUM if version unresolvable) | A vulnerable `next` version paired with an auth check inside `middleware.ts`/`.js` |
| `WEB_PROXY_MIDDLEWARE_HEADER_UNSTRIPPED` | companion hardening gap | LOW | A reverse-proxy config that forwards requests without stripping `x-middleware-subrequest` |
| `WEB_RSC_FLIGHT_DESERIALIZATION_RCE` | "React2Shell", CVE-2025-55182 | CRITICAL (MEDIUM if version unresolvable) | React declared in the vulnerable 19.0.0-19.2.0 window |
| `WEB_DJANGO_ORM_CONNECTOR_SQLI` | CVE-2025-64459 | CRITICAL (MEDIUM if version unresolvable) | Unsafe `.filter`/`.exclude`/`.get(**...)` or `Q(**...)` patterns correlated with request input, or a vulnerable Django version alone |
| `WEB_KESTREL_CHUNKED_SMUGGLING` | CVE-2025-55315 | HIGH (MEDIUM if version unresolvable) | The `InsecureChunkedParsing` compatibility switch, or a vulnerable Microsoft.AspNetCore package version |
| `WEB_JWT_JKU_X5U_SSRF` | CWE-918 | HIGH (MEDIUM if an allowlist-like symbol is present) | A JWT header's `jku`/`x5u` claim flowing into an HTTP client call with no allowlist |
| `WEB_PATH_TO_REGEXP_REDOS` | CWE-1333 | MEDIUM | A vulnerable `path-to-regexp` version, read from the resolved lockfile rather than the manifest range |

### `emerging-cloud` (`src/gate/checks/emerging-cloud.ts`, runs on infrastructure surfaces)

| Rule ID | Reference | Severity | What it detects |
| --- | --- | --- | --- |
| `K8S_INGRESS_NGINX_SNIPPET_INJECTION` | "IngressNightmare", CVE-2025-1974 | CRITICAL | Injectable ingress-nginx snippet annotations, or a controller image tag below the fixed version |
| `IAC_AWS_PASSROLE_PRIVESC_CHAIN` | CWE-269 | HIGH (CRITICAL on wildcard resource with no `iam:PassedToService` condition) | `iam:PassRole` combined with a launch/compute action (EC2, Lambda, ECS, Glue, or Bedrock AgentCore code interpreter) |
| `IAC_TF_MODULE_GIT_UNPINNED_REF` | CWE-829 | HIGH | A git-sourced Terraform module without a 40-character commit SHA pin |
| `IAC_GCP_TOKEN_CREATOR_PROJECT_BINDING` | CWE-269 | HIGH | A token-creator or service-account-user IAM role bound at the project scope |
| `K8S_RUNC_ESCAPE_DELIVERY_SURFACE` | CVE-2025-31133/52565/52881 | HIGH | A privileged container or arbitrary `hostPath` mount with no user-namespace remap |

### `emerging-supply-ai` (`src/gate/checks/emerging-supply-ai.ts`, always runs)

| Rule ID | Reference | Severity | What it detects |
| --- | --- | --- | --- |
| `SUPPLY_SHAI_HULUD_IOC` | Shai-Hulud npm worm | CRITICAL | Oversized worm-payload filenames, a known IOC hash in a lockfile, or an exfiltrating lifecycle script |
| `SUPPLY_LOCKFILE_OFFREGISTRY_RESOLVED` | CWE-345 | HIGH | A lockfile entry resolved from a host outside the recognized public/private registry list |
| `SUPPLY_MCP_REMOTE_COMMAND_INJECTION` | CVE-2025-6514 | CRITICAL (version match) or HIGH (code-pattern signal only) | A vulnerable `mcp-remote` version, or first-party code piping a server-supplied URL into a shell |
| `AI_INVISIBLE_UNICODE_INJECTION` | CWE-1427 | HIGH | Unicode tag block, zero-width, bidi-override, or variation-selector characters used for prompt injection; the finding reports only the codepoint and location, never the raw invisible bytes |
| `AI_MCP_CONFIG_RUG_PULL` | CVE-2025-54136/54135 ("MCPoison"/"CurXecute") | HIGH | An MCP server config whose `command` shells out, or invokes an unpinned package/binary |
| `AI_MODEL_PICKLE_OPCODE_DANGEROUS` | CWE-502 | CRITICAL | Dangerous pickle opcodes combined with dangerous module names in a model file. **This is a best-effort binary heuristic**: it can miss obfuscated payloads and can flag benign files. A clean scan is not proof that a model file is safe. |
| `AI_A2A_CREDENTIAL_FORWARDING` | CWE-441 | HIGH | A caller's raw bearer token or environment secret forwarded into a downstream agent call with no scoping |

## 1.6.0 rule IDs: "vibe coding" threat detection

`src/gate/checks/vibe-coding.ts` (`checkVibeCoding`) is **always on**: unlike the
surface-gated 1.5.0 modules above, it runs on every gate invocation regardless of the
detected surface, because the failure modes it targets (a leaked admin key, an
access-control gap in a datastore) are not confined to any one surface and are common in
apps generated end to end by an AI tool (Cursor, Lovable, Bolt, v0, Replit). Detection is
the same regex/heuristic approach as the rest of the gate, not AST or data-flow analysis.
Several rules rely on a client-vs-server heuristic (a file under `src/`, `app/`, `pages/`,
`components/`, `public/`, or with a `.tsx`/`.jsx`/Vue/Svelte extension counts as
browser-shipped, unless its path also matches a server-handler pattern like `app/api/**`
or `*.server.ts`), which is a path/extension check, not a bundler analysis, and can
misclassify an unconventional layout.

| Rule ID | Severity | Breach it maps to | What it detects |
| --- | --- | --- | --- |
| `VIBE_SUPABASE_SERVICE_ROLE_IN_CLIENT` | CRITICAL | Moltbook | A Supabase `service_role`/`sb_secret_` key, or a service-role-shaped JWT literal, referenced in browser-shipped code |
| `VIBE_PUBLIC_ENV_HOLDS_SECRET` | CRITICAL | n/a | A `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`/`EXPO_PUBLIC_`/`PUBLIC_` variable whose name indicates a real secret (not a publishable/anon value) |
| `VIBE_PROVIDER_KEY_IN_FRONTEND` | CRITICAL | n/a | An Anthropic/OpenAI/Stripe/AWS/Google/GitHub API key literal hardcoded in client-shipped code |
| `VIBE_SUPABASE_RLS_DISABLED` | CRITICAL | Lovable, CVE-2025-48757 | A `CREATE TABLE` with no `ENABLE ROW LEVEL SECURITY` in the same SQL file, or a `CREATE POLICY ... USING (true)` |
| `VIBE_FIREBASE_RULES_PUBLIC` | CRITICAL | Tea app | Firestore/Storage/RTDB rules that allow read or write when `true` |
| `VIBE_API_ROUTE_NO_SERVER_AUTHZ` | HIGH | Base44 | A server handler (API route / serverless function) that reads request input or queries the database with no recognizable server-side auth verifier |
| `VIBE_CLIENT_SIDE_AUTH_GUARD_ONLY` | HIGH | n/a | Access enforced only by a client-component redirect guard (`if (!user) router.push(...)`), which runs in the attacker's browser and is bypassable |
| `VIBE_CORS_WILDCARD_CREDENTIALS` | HIGH | n/a | A bare `cors()` with no options, or a wildcard/reflected origin combined with `credentials: true` |
| `VIBE_CLIENT_CONTROLLED_PRICE` | HIGH | n/a | A payment amount/price/total read directly from the request body or query instead of looked up server-side |
| `VIBE_TOKEN_IN_LOCALSTORAGE` | HIGH | n/a | A session token, JWT, or API key stored via `localStorage.setItem`, readable by any XSS on the page |
| `VIBE_UNRESTRICTED_FILE_UPLOAD` | HIGH | n/a | An upload handler (`multer`, `formidable`, etc.) with no MIME/extension allowlist and no size limit |
| `VIBE_ENV_FILE_COMMITTED` | HIGH | n/a | A `.env`, `serviceAccount*.json`, `*.pem`, or SSH private key present on disk and not covered by `.gitignore` |
| `VIBE_SOURCEMAPS_IN_PROD` | MEDIUM | n/a | Production source maps enabled (`productionBrowserSourceMaps: true`, or `sourcemap: true` in a build config) |
| `VIBE_DEBUG_MODE_ENABLED` | HIGH | n/a | Flask/Django `debug=True`, Express `errorhandler()`, or `err.stack` returned in an HTTP response |
| `VIBE_HALLUCINATED_OR_UNVETTED_DEP` | MEDIUM | slopsquatting research | A dependency declared in `package.json`/`requirements.txt` but absent from the lockfile. **This is an offline heuristic, not proof**: a missing lockfile entry is a candidate for manual verification against the official registry, not a confirmed hallucinated or malicious package |
| `VIBE_PROMPT_INJECTION_UNSAFE_CHAIN` | HIGH | n/a | User input concatenated into a system/instruction prompt, or model output passed into `eval`/`exec`/a shell/`dangerouslySetInnerHTML` |

Every `VIBE_` finding ID has a matching fix template in `src/gate/remediation-map.ts`, so
the fixing agent applies a concrete change (rotate-and-move-server-side, an RLS-enabling
migration, a `getServerSession` check, an httpOnly-cookie pattern, and so on) rather than
just filing an advisory.

## 1.6.1 rule IDs: web-hardening blindspots

`src/gate/checks/web-hardening.ts` (`checkWebHardening`) is **always on**, the same as
`vibe-coding` and `emerging-supply-ai`: it runs on every gate invocation regardless of
detected surface, because a missing security header, a hardcoded session secret, or an
unauthenticated Next.js Server Action is exactly as exploitable in a repo the surface
detector misclassifies as it is in one it classifies correctly. Detection is the same
regex/heuristic approach as the rest of the gate.

| Rule ID | Severity | CWE | What it detects |
| --- | --- | --- | --- |
| `WEB_MISSING_SECURITY_HEADERS` | MEDIUM | CWE-1021/693 | A web-server surface with no response-header hardening anywhere (no `helmet`, no `X-Frame-Options`, no HSTS, no Content-Security-Policy), leaving the app open to clickjacking and protocol downgrade. Conservative by design: fires once at repo level and skips static/library repos with no server surface to harden |
| `WEB_OPEN_REDIRECT` | HIGH | CWE-601 | A redirect target taken from user input, e.g. `res.redirect(req.query.url)` or an unvalidated `NextResponse.redirect` |
| `WEB_HARDCODED_SESSION_SECRET` | HIGH | CWE-798/330 | A session/cookie/JWT signing secret hardcoded as a literal or a weak default (e.g. `"keyboard cat"`). Excludes `process.env` reads and `.env.example`; truncates the secret in evidence |
| `WEB_EMAIL_HEADER_INJECTION` | HIGH | CWE-93/88 | User input flowing unsanitized into email envelope fields (nodemailer/SendGrid `to`, `subject`, headers), enabling CRLF header injection and mail-relay abuse |
| `WEB_SERVER_ACTION_NO_AUTHZ` | HIGH | CWE-306/862 | A Next.js Server Action (`'use server'`) that performs a DB mutation/read with no server-side auth verifier; Server Actions are publicly-invocable POST endpoints, so hiding the triggering button does not protect them |
| `WEB_SENSITIVE_FIELD_IN_RESPONSE` | MEDIUM | CWE-213/200 | A serialized DB row/object that includes a secret field (`passwordHash`, `salt`, `mfaSecret`, `apiKey`, `refreshToken`, `ssn`), or a `SELECT *`-to-response shape |

These six rules lift first-party static rule coverage from roughly 883 to roughly 887
finding IDs. Every `WEB_` finding ID from this module has a matching remediation template
in `src/gate/remediation-parts/web-hardening-remediations.ts`.

### How does security-mcp fix vulnerabilities automatically?

By resolving the finding ID against `REMEDIATION_MAP` (`src/gate/remediation-map.ts`) and
writing the returned template's fix directly into the working tree, then re-running the
check to confirm the finding cleared. As of 1.6.1, `REMEDIATION_MAP` is composed from six
domain partials under `src/gate/remediation-parts/` — `cloud.ts` (256 templates), `ai.ts`
(69), `data.ts` (172), `web.ts` (203), `misc.ts` (112), and `web-hardening-remediations.ts`
(6), plus the evaluability-gap templates in the base map — for **900 fix templates covering 100% (900/900) of detection IDs**, up from just 71
templates (roughly 8% of finding IDs) before this release. Each template pairs a realistic
vulnerable pattern with a concrete secure fix in the correct language, a plain-language
explanation, and standards references (CWE plus OWASP Top 10 / API Security Top 10 / LLM
Top 10 / MASVS, and NIST / CIS / PCI DSS / FIPS or the relevant provider's docs). This is
what makes the "90% fixing, 10% advisory" operating mandate achievable in practice: every
detection ID has a concrete template to work from via `security.generate_remediations`,
rather than the agent having to invent a fix from scratch. Applying the template and
verifying the fix is still the calling agent's job — the re-verification step re-runs the
same detection rule that originally fired, which confirms the flagged pattern no longer
matches but cannot independently prove the underlying vulnerability is resolved rather than
merely evaded. The one path where this is fully deterministic end-to-end is Terraform:
`security-mcp autoharden` applies the fix, re-detects, and reverts automatically if the
finding doesn't clear, with no agent judgment call in the loop.

## Capability enforcement

New in 1.5.0: `enforceCapabilityFloor` (`src/mcp/capability-enforcer.ts`) runs as
thoroughness check "(e)" inside `orchestration.merge_agent_findings`, alongside SKILL.md
coverage, ghost-agent detection, and escalation checks. It exists to turn "agents always
operate at full capability" from a stated policy into something the gate actually
verifies.

For every agent in a run it checks four floors:

- **Model tier.** Whether the agent ran at or above the tier its task type requires,
  per `model-router.ts`'s `TASK_CAPABILITY_MAP`. Seven task types
  (`exploit_chain`, `pentest`, `ai_redteam`, `crypto_analysis`, `auth_analysis`,
  `threat_model`, `remediation`) are protected from ever being downgraded by the router's
  own budget circuit-breaker.
- **Tool floor.** Whether the agent had and used the security-critical tools (`Read`,
  `Grep`, `Glob`, `Bash`) declared in its SKILL.md `allowed-tools` frontmatter.
- **Evidence depth.** Whether a high-risk lead agent (appsec code auditor, crypto/PKI
  specialist, supply-chain DevSecOps, cloud infra specialist, AI/LLM red-team, pentest
  team, threat modeler) produced findings/evidence, or an explicit justified "clean"
  attestation; a silent empty result from one of these leads is a violation.
- **Section coverage.** Reuses the existing `verifySkillCoverage` result.

**Findings emitted:**

- `CAPABILITY_DEGRADED::<agentName>`, HIGH: a specific agent failed one or more floors it
  could be evaluated against.
- `CAPABILITY_FLOOR_NOT_MET`, CRITICAL, run-level: emitted once if any agent was degraded.
  Because the gate fails on any un-excepted CRITICAL, this is what actually forces FAIL.
- `CAPABILITY_UNVERIFIED::<agentName>`, MEDIUM: a floor could not be evaluated because the
  needed metadata was not recorded, so it is reported as unknown rather than failed or
  passed.
- `CAPABILITY_COVERAGE_INCOMPLETE` (HIGH) / `CAPABILITY_COVERAGE_UNVERIFIED` (MEDIUM):
  coverage-specific variants of the same pattern.
- `CAPABILITY_MANIFEST_UNREADABLE` (MEDIUM, non-blocking): the run manifest itself could
  not be read, so there is nothing to affirmatively check.

**Honest current limitation:** the agent-run manifest and per-agent findings files do not
yet record which model, task type, or tools an agent actually used. Until orchestration is
updated to populate that metadata (`modelUsed`, `taskType`, `toolsUsed`, the schema for
which already exists in `capability-enforcer.ts` as `AgentCapabilityMetadataSchema`), the
model-tier and tool-floor checks surface as MEDIUM `CAPABILITY_UNVERIFIED` advisories for
most agents rather than as HIGH violations. This is called out here deliberately: those two
floors are not fully enforced yet, only the evidence-depth and coverage floors are backed
by data that is actually recorded today. Wiring orchestration to record that metadata is
tracked as a follow-up.

Enforcement is defensive end to end: any internal error inside the enforcer degrades to a
non-fatal warning rather than blocking an otherwise-passing run.

## How to add a new check module

Every check module, including the three added in 1.5.0, follows the same contract so
`runAllChecks` can treat them uniformly:

1. **Location.** Add the file under `src/gate/checks/`. This directory is deliberately
   excluded from `searchRepo`'s own scan scope, which matters if your module's code
   contains any vulnerable-looking example strings (it usually will not, but
   `remediation-map.ts` relies on this exclusion and lives in the parent `src/gate/`
   directory for the same reason).
2. **Signature.** Export a single async function matching:
   ```ts
   export async function checkYourModule(_: { changedFiles: string[] }): Promise<Finding[]>
   ```
   Accept `changedFiles` even if you do not use it, for contract consistency with the rest
   of the check array. Most existing checks, including all three 1.5.0 modules, scan the
   whole repository rather than just the diff, because most of what they detect (a
   vulnerable dependency version, a misconfigured resource) is a risk regardless of
   whether it was touched in the current change. Scope to `changedFiles` only if your
   check is inherently about the diff itself.
3. **Detection method.** Use `searchRepo` (`src/repo/search.ts`) for text/regex scanning
   and `readFileSafe` (`src/repo/fs.ts`) for individual file reads. Keep regex patterns
   short and free of nested quantifiers; `searchRepo` enforces a ReDoS guard, and you
   should not need to work around it. There is no AST layer available or expected. For
   version-gated rules, read the manifest or lockfile directly and use a small
   dependency-free semver comparison, falling back to a MEDIUM "review" finding rather
   than a hard assertion whenever the version cannot be resolved to a concrete value.
4. **Finding shape.** Every `Finding` needs at minimum an `id` (the rule ID string, upper
   snake case, prefixed by domain: `WEB_`, `IAC_`, `K8S_`, `SUPPLY_`, `AI_`, and so on), a
   `title`, a `severity`, `evidence`/`files`, and `requiredActions`. Follow the severity
   conventions already in use: CRITICAL for a confirmed, exploitable condition; HIGH for
   a serious but conditional or unresolved-version case; MEDIUM for advisory or
   unresolvable-version cases; LOW for hardening gaps that are not exploitable alone.
5. **Fail safe — but distinguish "one file" from "the whole check."** Wrap your
   detection logic in try/catch and log failures with `sanitizeErrorMessage`. The
   right response to a caught error depends on its scope:
   - **One input among many** (a single file that's malformed, binary, or too large;
     a glob that matches zero files because the pattern genuinely doesn't apply):
     return an empty array or `continue` past that one file. This is the common
     case, and README:191's "the absence of a result is itself a result" and this
     guide's older wording ("a check that cannot run should produce no finding for
     its rule, not a crashed gate") both apply correctly — a check that legitimately
     has nothing to check should report nothing, silently.
   - **The check's entire evidence source** (a network/API call the whole check
     depends on fails, a required external binary is missing, an external service
     is unreachable): do **not** return `[]`. That silently converts "I could not
     determine this" into "clean," which is worse than a crash, because a crash at
     least produces a visible `GATE_CHECK_CRASHED` finding. Emit an explicit
     `EVAL_UNAVAILABLE_<NAME>` finding instead (HIGH severity, mirroring
     `GATE_CHECK_CRASHED`'s intent) — see `checkCveExploitation` in
     `src/gate/checks/dependencies.ts` for the canonical example, and give it a
     remediation template in `src/gate/remediation-map.ts` like every other
     finding id (the "fix" describes restoring the resource, not a code diff).
     If the failure is an intentional, operator-chosen skip (`SECURITY_OFFLINE=1`),
     that is not this case either — check for it explicitly and return `[]` with no
     finding, the same as "not applicable."
   The dividing line: if this specific failure happens, does the user lose ALL of
   this check's signal for the entire run with no indication anything went wrong?
   If yes, it needs an `EVAL_UNAVAILABLE_<NAME>` finding, not silence.
6. **Wire it in.** This is done in `src/gate/policy.ts`, not inside your module:
   - Add your function call to the check-promise array inside `runAllChecks`, gated on
     whichever `surfaces.*` flag (or `isApiOrWeb`) matches where your check should run, or
     left ungated if it should always run.
   - Add a matching entry to the `CHECK_NAMES` array, in the same position, so the check's
     name and its result line up positionally.
7. **Add a remediation template.** Add an entry to `REMEDIATION_MAP` in
   `src/gate/remediation-map.ts` for every new finding ID, with a `pattern`, `fix`,
   `explanation`, and `references`. A finding with no remediation template is still valid,
   but it erodes the product's fixing-vs-advisory ratio, so treat this as a required step,
   not an optional one.
8. **Verify.** Run `npm run build` (tsc) and `npm test` (`src/tests/run.ts`) before
   considering the module complete.

## Environment variables relevant to 1.5.0

The 1.5.0 features do not introduce new environment variables of their own; they reuse
the existing gate and orchestration configuration. The ones most relevant to the new
detection modules and capability enforcement are:

| Variable | Default | Relevance to 1.5.0 |
| --- | --- | --- |
| `SECURITY_GATE_TARGETS` | (changed files) | Scopes which files the gate (including the three new emerging-* modules) considers part of the current change; note that `emerging-cloud`, `emerging-web`, and `emerging-supply-ai` still scan the whole repo internally regardless of this scope |
| `SECURITY_GATE_BASE_REF` / `SECURITY_GATE_HEAD_REF` | `origin/main` / `HEAD` | Determines whether `surfaces.web`/`surfaces.api`/`surfaces.infra` are detected as true, which is what gates `emerging-web` and `emerging-cloud` |
| `SECURITY_POLICY_HMAC_KEY` | (none) | Unset means HIGH/CRITICAL, including the new CRITICAL `CAPABILITY_FLOOR_NOT_MET` and the new emerging-* CRITICAL findings, are force-blocked regardless of policy content |
| `SECURITY_MIN_SKILL_COVERAGE_PCT` | 90 | The coverage floor reused by both thoroughness check (a) and by capability enforcement's coverage floor |
| `SECURITY_REQUIRE_AGENT_ATTESTATION` | (unset) | Fail-closed attestation requirement; capability enforcement runs after attestation verification in `mergeAgentFindings`, so a rejected agent file never reaches the capability floor check |
| `SECURITY_OFFLINE` | (unset) | Disables third-party egress; does not affect the emerging-* modules, which are local, static checks with no network calls |

No new variable currently exists to relax or tune the capability-floor thresholds
themselves; they are evaluated against `model-router.ts`'s `TASK_CAPABILITY_MAP` and
`PROTECTED_MAX_POWER_TASKS`, which are code-level constants, not policy-file or
environment-variable configuration, as of 1.5.0.

## Change History

- 2026-07-17 — Rewrote the "Fail safe" check-authoring rule (item 5) to distinguish
  a per-file skip (legitimately silent) from the whole check's evidence source
  being unavailable (must emit `EVAL_UNAVAILABLE_<NAME>`, not `[]`) — the old
  unconditional "return an empty array on any internal error" wording was itself
  the reason this bug class kept getting introduced by new check authors following
  the guide as written. Reconciles with README's "the absence of a result is
  itself a result" (which was about crashes and remains accurate).
- 2026-07-17 — Remediation-template count updated from 888 to 900: added 12
  `EVAL_UNAVAILABLE_*` findings (Track E, the fail-open/evaluability sweep across all
  check modules) and a matching template for each, keeping "100% detection-ID
  coverage" exact.
- 2026-07-17 — Corrected the "90% fixing" claim: applying and verifying a remediation
  template is still the calling agent's job, not something the engine enforces
  deterministically (Terraform via `autoharden` is the one exception). Updated the
  remediation-template coverage ratio from 887/887 to 888/888 to match the live rule
  count, and fixed a real 1-rule coverage gap it surfaced (`EVAL_UNAVAILABLE_THREAT_INTEL`
  had no template) as part of adding the claims registry (Track A).
- 2026-07-14 — Added the "Client support matrix" and "Portable agent delivery" sections: per-client MCP config paths/keys (VS Code `servers`, Windsurf `~/.codeium/windsurf/mcp_config.json`, Codex TOML, Replit remote-only) and how agents are delivered over MCP prompts/resources so every client runs the full roster.
- 2026-07-07 — Added the version note (internal milestones 1.4.0–1.6.1 ship publicly in
  1.3.5) and the "pre-release checklist" section documenting the checklist's sync with
  the detection engine (246 items across 21 sections).
- 2026-07-06 — Added the "Is security-mcp safe to use? (the MCP's own security &
  governance)" section (self trust model, tamper-evident policy, fail-safe, egress
  control, no-shell exec, self-scan).
- 2026-07-06 — Added the "1.6.1 rule IDs: web-hardening blindspots" section (six new
  `WEB_` rules) and a "How does security-mcp fix vulnerabilities automatically?" section
  documenting the remediation map's expansion to 888 templates / 100% (887/887)
  detection-ID coverage.
