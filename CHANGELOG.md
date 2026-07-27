# Changelog

All notable changes to `security-mcp` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Trust hardening (2026-07-26)

Six defects, one shape: something unknown or untrusted was treated as good. Each fix was
verified by reproducing the original attack against the patched build.

- **The CI exceptions file was trusted by its filename.** `.github/security-exceptions-ci.json`
  lives inside the repository being scanned, so any pull request could add one and suppress
  every blocking finding (measured: 51 findings, 48 blocking, down to 0). The lone warning was
  fixed at MEDIUM so it never blocked, and the HIGH warning was suppressed *in CI*, the only
  place the gate gates. Trust now requires either a valid HMAC signature, or an out-of-band
  `SECURITY_TRUST_CI_EXCEPTIONS=1` set by the workflow **and** the file being unmodified by the
  change set under review. A missing change set is refused rather than assumed safe.
  `EXCEPTIONS_UNSIGNED_SUPPRESSION` now mirrors the highest severity it hid, and
  `CI_EXCEPTIONS_IN_LOCAL_SCAN` fires in CI too. New `security-mcp sign-exceptions` command,
  because "sign it" was previously advice with no way to act on it.
- **The attested hash covered only `findings[]`.** Section coverage, summary, and the
  capability record sat outside the signature, so a file could be rewritten after attestation
  to claim full coverage and a clean summary with the chain still verifying (measured: 4% to
  100%, gate FAIL to PASS, no secret required). New `payloadHash` covers the whole attestable
  envelope and is itself inside the chain payload. Hashing is now canonical (recursively
  sorted keys), which also fixes honest attestations being rejected as `hash-mismatch`
  because zod reorders keys — that bug was silently discarding real CRITICAL findings.
  Re-attesting the same agent is now recorded as tampering rather than last-write-wins.
- **`run_pr_gate` erased the multi-agent completion evidence.** It wrote the same review step
  key as the merge, and the step was replaced wholesale, so `attest_review` signed runs whose
  agents never executed. This was the documented order of operations. Verdicts are now
  monotonic: a recorded FAIL cannot be silently replaced by a PASS, failure evidence is
  carried forward rather than dropped by omission, and a refused downgrade is recorded.
- **Self-verification could not fail.** Delegated GUARANTEE claims passed on the suite's exit
  code without ever reading `testFunction`, so deleting every test the claims named still
  produced 35/35. QUANTITY claims used substring matching, so zero cloud rules on disk still
  verified "1,002 rules" (because the sentence contains "0"); 400-vs-40, 910-vs-91 and
  9000-vs-900 also passed. Delegation now parses TAP and requires the named test to be present
  and passing, failing closed when it cannot be found. QUANTITY now requires exact numeric
  equality against a token in the verbatim. `guarantee-agent-executor-attestation-roundtrip`
  delegated to a test with zero assertions about attestation; it now has a real one.
- **Auto-remediation corrupted valid Terraform.** A CRLF file's block body starts with `\r`,
  so the newline check failed and attributes were glued to the opening brace, turning a valid
  file into a parse error. Both insertion paths now match the document's own line ending.
  Writes are atomic (sibling temp plus rename) with a one-shot `.orig` backup, replacing an
  in-place truncate on user infrastructure code. Every rewrite is checked by a structural
  guard that is independent of the regex rules that produced it, covering glued attributes,
  brace balance, duplicate resource addresses, and truncation; a rewrite that fails is
  reported and not written. A single unwritable file no longer aborts the sweep.
- **The installer destroyed any config it could not parse.** `readJsonSafe` returned `{}` for
  both "absent" and "unparseable", and the writer serialized that empty object over the file,
  so a trailing comma in `~/.claude/settings.json` silently deleted the user's model,
  permissions, and hooks while reporting "updated". Absent and unparseable are now distinct:
  JSONC (comments, trailing commas) parses correctly, and a genuinely unreadable file aborts
  that writer with its contents untouched. Writes are atomic with a `.bak`. The Codex TOML
  header regex now tolerates a trailing comment, which previously caused a duplicate table
  that made the entire config unloadable; `doctor`'s matching regex was aligned.

### Full-repo adversarial QA pass (2026-07-25)

Nine specialists audited the whole codebase, not just the recent diff. Every finding below was
reproduced before it was fixed, and each fix has a regression assertion in the new
`runQaRegressionTests` suite. The persona and method are in `.claude/agents/mcp-qa-adversary.md`.

Fixed:

- **`security.logout` cleared the authentication lockout for an unauthenticated caller.** It is
  reachable without authenticating and is in `CHILD_SAFE_TOOLS`, so interleaving logout with
  guesses defeated the exponential backoff entirely (CWE-307). Measured at 60 guesses in 26 ms with
  no backoff ever applied. The lockout counters now clear only for a session that actually
  authenticated (`src/mcp/auth.ts`).
- **`writeReport` reported `signed: true` from a zero-byte HMAC key.** `Buffer.from(key, "hex")`
  silently returns an empty buffer for any non-hex value, so a natural non-hex `SECURITY_ATTEST_KEY`
  produced a MAC that anyone could forge without knowing the key. Now uses the key string directly,
  as all four other HMAC sites in the repo already did (`src/mcp/reports.ts`).
- **`model-router.ts` and `learning.ts` resolved state against `process.cwd()`, not the workspace
  root.** Same defect class that made `audit-chain.ts` report correctly-attested agents as
  unattested. The workspace budget policy was never read, so the circuit breaker ran on the 5 USD
  default, and spend and pattern state were written to the wrong tree.
- **Concurrent `saveStore` calls discarded 23 of 24 outcomes.** The temp filenames were fixed rather
  than random, so every caller after the first failed with `ENOENT` (`src/mcp/learning.ts`).
- **`readFileSafe` hung forever on a FIFO.** `stat()` reports size 0 for a FIFO, so the size guard
  passed and `readFile` then blocked with no timeout. Now refuses anything that is not a regular
  file (`src/repo/fs.ts`).
- **`createReviewAttestation` and `verifyAttestationHmac` did not validate `runId`.** Every other
  export in the module does. A traversing `runId` wrote attacker-named JSON outside the workspace
  root (CWE-22, `src/review/store.ts`).
- **README claimed 41 MCP tools; the server registers 46.** The README contradicted itself 36 lines
  later, and the unregistered-number scan could not catch it because `tools` is not in its unit list.
- **A source file in any directory named `docs`, or with `readme` anywhere in its path, skipped 40 of
  41 check modules.** The change-type classifier matched `/docs/` and `README` as path substrings
  rather than matching a documentation extension, and the docs tier runs only the secrets check.
  Identical code containing `eval(req.query.q)` produced 47 findings at `src/api/handler.ts` and zero
  at `src/docs/handler.ts` (`src/gate/policy.ts`).
- **The adapter registry accepted execution-affecting fields from the repo under review.** A
  committed `.mcp/agent-clis/agent-clis.json` could point `detect.extraSearchGlobs` at a script in
  that repo, which adapter detection then executed, reachable from `orchestration.executor_status` or
  `security.fortify` with no agent run and no LLM in the loop. The same file could grant `Task` and
  `Bash`, select `bypassPermissions`, empty the banned-argument list, and widen
  `auth.childCredentialEnv` so one child received every provider's credentials. In-workspace
  overrides are now restricted to tuning that cannot change what is executed, with what privileges,
  or with whose secrets; rejected fields are logged as `ADAPTER_OVERRIDE_FIELDS_REJECTED`
  (`src/agent-exec/adapter.ts`).
- **The injection detector missed the exact directive in this repo's own malicious fixture.**
  "Ignore all previous instructions" defeated `IGNORE\s+PREVIOUS` because of the quantifier between
  the verb and the adjective. `orchestration.ts` uses this same list to strip lines from a downloaded
  SKILL.md before it becomes an agent persona, so a miss was a persona backdoor rather than a missing
  warning banner. Replaced the fixed phrases with one bounded combinatorial pattern
  (`src/mcp/injection-patterns.ts`).
- **`skills-manifest.json` is read at runtime but was absent from the published tarball.**
  `buildQueue` resolves it from the package root, so `orchestration.start_agent_run` would have
  thrown `ENOENT` on any global install. Not yet live, because the executor is unpublished; it would
  have broken on the next publish (`package.json` `files`).

### Documentation, diagrams, and drift detection

- **New `docs/DATA_FLOW.md`.** A trust-boundary data-flow diagram, which did not previously exist,
  enumerating every outbound call site in `src/` with what crosses each edge.
- **Corrected the README trust-boundary claims.** "Your code never leaves your machine to a third
  party by default" was false for the normal case: running the server inside an AI client sends file
  contents to that client's model provider on the first `repo.read_file`. The section now separates
  what security-mcp uploads (nothing) from what reaches a model provider through the host client and
  through an explicit agent run.
- **`docs/ARCHITECTURE.md` gained the `src/agent-exec/` subsystem and a fourth mermaid diagram.** The
  executor had shipped while the architecture doc did not mention it at all. Also corrected the
  capability-enforcement section, which claimed orchestration records no model or tool metadata.
- **`docs/WIKI.md` gained an operator reference for the five executor tools** and their environment
  variables.
- **New doc-drift gate.** `npm run docs:check` (`scripts/check-doc-drift.mjs`) enforces the bindings
  in `docs/doc-map.json`: every anchor must appear in every bound doc, and a change set touching
  bound source must also touch its bound docs. Wired into `security-gate.yml` and available as a
  blocking pre-commit hook (`scripts/doc-drift-hook.sh`). It failed on its first run with nine real
  issues.

### Agents that actually execute

The orchestrator previously wrote a manifest of pending agents and returned prose asking
the calling assistant to spawn them. It now runs them itself, on the LLM CLIs already
installed on the machine, with no API key. Across the 13 pre-existing runs on disk, 266 of
280 agent slots had never left `pending` and every run was stuck at `phase: 0`.

- **A local-CLI executor.** `orchestration.start_agent_run` spawns a detached supervisor
  that drives every agent in the roster to a terminal state and survives the end of the
  MCP session. Adapters are declarative data (`defaults/agent-clis.json`), mirroring the
  existing scanner-config pattern, so a CLI flag change is a JSON edit rather than a code
  change. `claude` 2.1.92, `codex` 0.146.0-alpha.3.1, and `copilot` 1.0.75 are verified
  end to end; other adapters ship with a populated `_unverified[]` surfaced at runtime.
- **All detected providers run concurrently**, each with its own AIMD rate limiter and
  circuit breaker, so throttling on one does not stall the others and the quota cost is
  split across plans rather than falling on one.
- **Detection searches beyond `PATH`** — well-known paths, npm and pnpm global roots
  across every installed Node version, and editor extension bundles. Codex ships inside
  the ChatGPT VS Code extension and is invisible to a `PATH`-only scan.
- **A deterministic pre-pass** runs the scanners once and builds a repository map shared
  by the whole roster. Unavailable scanners are named, so "not run" never reads as "clean".
- **Scheduling derives from `skills-manifest.json`**, which already carries `phase` for all
  91 skills and `subAgents` for the 11 leads. Sub-agents wait for their lead; Phase 2 waits
  for all of Phase 1, per `pentest-team`'s stated contract.
- **`completed_na` is a new terminal status**: an evidenced verdict that an agent's domain
  is absent, recording which signals were searched. Distinct from `pending` everywhere.
- **Cross-provider corroboration.** Every CRITICAL and HIGH finding is independently
  re-checked by the other providers, labelled `corroborated` / `disputed` / `unconfirmed`.
- **A ReAct fallback** lets a completion-only CLI still work, with the resulting quality
  ceiling recorded as degradation rather than hidden.

### The completion gate: a run cannot be reported done while agents are pending

- `orchestration.assert_run_complete` **throws** rather than returning, so a caller cannot
  read past it.
- `mergeAgentFindings` forces the gate to FAIL and records every non-terminal agent by name.
- `security.attest_review` refuses to sign when that list is non-empty.
- The only bypass is `SECURITY_ATTEST_ALLOW_INCOMPLETE=1`, which stamps the artifact.

### Fixed

- **`update_agent_status` crashed on any scoped roster.** The phase gate read
  `manifest.agents["pentest-team"].status` unguarded, and `.every()` invokes its callback
  on the first element immediately, so every status update on a 9-agent `CORE_TARGETED_TEAM`
  run threw a `TypeError` before `writeManifest` and was silently discarded. This is why
  scoped runs showed zero completed agents and contained nothing but a manifest.
- **`manifest.phase` could never leave 0.** Nothing anywhere assigned `phase = 1`, so the
  1→2 transition could never fire. The first agent reporting `running` now starts phase 1.
- **`findingsPath` rejected its own paths.** The validation regex required an alphanumeric
  first character, so `.mcp/agent-runs/<id>/x.json` was unstorable; manifests on disk show
  the leading dot stripped to satisfy it. Traversal and absolute paths are now rejected
  explicitly instead.
- **Merge and attest disagreed on a key.** `mergeAgentFindings` wrote `gateStatus` while
  `attest_review` read `status`, so a multi-agent FAIL was invisible to attestation if a
  standalone gate run had already recorded a PASS. Both are now written.
- **Bookkeeping artifacts were parsed as agent findings.** The run-directory glob excluded
  only two filenames, so `attestation-chain.json` was schema-rejected on every merge and
  reported as a phantom partial agent, and `merged-findings.json` fed its own coverage back
  on a second merge.
- **Roughly 50 of ~84 agents were unreachable.** Explicit rosters were intersected against
  the stack-gated default list, so micro-specialists such as `incident-responder` and
  `capec-code-mapper` could never enter a manifest. Validation is now against the agents
  that actually have a bundled persona to execute.
- **The attestation chain resolved against `process.cwd()`**, unlike every other writer,
  so it could land outside the workspace the merge step reads. Its atomic write also used
  `os.tmpdir()`, which throws `EXDEV` when the workspace is on another filesystem.
- **`security.generate_compliance_report` wrote no file.** It returned markdown and
  persisted nothing, which is why every report on disk had been hand-authored by an LLM
  with incompatible schemas and invented midnight timestamps. Reports now persist to
  `.mcp/reports/` as schema-versioned artifacts with a real clock and a SHA-256 digest.
- **Prompt-injection patterns were duplicated byte-for-byte** between `server.ts` and
  `orchestration.ts`; hardening one while the other drifted would leave a live bypass.

### Security

- Four-layer recursion guard: an env depth marker set by the parent, per-adapter isolation
  flags, sub-agent tools never grantable in any mode, and a server-side child tool profile
  under which orchestration tools are not registered at all.
- Per-adapter child credential passthrough. A blanket strip would break Copilot, whose
  headless auth precedence is `COPILOT_GITHUB_TOKEN` > `GH_TOKEN` > `GITHUB_TOKEN`, so each
  adapter declares exactly what its children may receive. A Claude child never sees a
  GitHub token; no child sees the parent's HMAC or attestation keys.
- Execution provenance on every findings file, plus per-agent transcripts, so a reviewer
  can open the session behind any finding.
- New `docs/LIMITATIONS.md` states what the tool does not do, cannot do, or does less well
  than it appears.

## [1.3.6] - 2026-07-14

### Hardening: truth-and-integrity pass (enterprise-grade foundation, phase 1)

A ground-truth audit of the product's own claims found several places where the engine
overstated what it verifies. This pass makes the code match the claims, or narrows the
claims to match the code — nothing is left asserted-but-unproven.

- **Compliance reports no longer default to "satisfied".** `security.generate_compliance_report`
  previously marked every control satisfied whenever no adverse finding matched — so a call
  with *no gate run at all* returned a fully "compliant" report (SOC 2: 9/9 satisfied from
  zero evidence). A control is now `satisfied` only when a gate run completed the control's
  required workflow steps with no adverse finding; absent a run every control is `unverified`.
  Reports carry an explicit "partial mapping, not an audit" caveat. GDPR and HIPAA are
  retracted from the offered frameworks (1–2 mapped controls could not represent them
  honestly); SOC 2, PCI DSS 4.0, NIST 800-53, and ISO 27001 remain as partial control
  mappings. Regression-tested.
- **Threat-intel unavailability is no longer reported as "clean".** When the dependency
  audit found CVEs but the live CISA KEV / EPSS lookup failed (network error, rate limit,
  unreachable endpoint), the check silently returned no findings — turning "exploit status
  unknown" into "no actively-exploited CVEs". It now emits a HIGH `EVAL_UNAVAILABLE_THREAT_INTEL`
  coverage-gap finding. `SECURITY_OFFLINE=1` is unaffected (intentional skip, not a failure).
- **`safeTool` error responses no longer leak filesystem paths (CWE-209).** The MCP error
  wrapper returned the raw `err.message` — which for IO failures contains absolute paths —
  despite a comment claiming it was sanitized. It now runs `sanitizeErrorMessage` for real.
- **Attestation-chain downgrade hardened.** `verifyChain` classified a chain as signed via
  `.some(hasHmac)`; it now requires `.every(hasHmac)` and fails closed when a key is
  configured but any link is unsigned, so signatures cannot be stripped to reach the
  hash-only pass path.
- **Audit-log rotation retains history.** The single-rotation guard overwrote `.1` on every
  rotation, silently destroying older audit segments; it now keeps `.1`–`.5`. The log path
  is also resolved per-call against the workspace root instead of once at module load.
- **Failed auth no longer kills the process.** Three failed attempts triggered
  `process.exit(1)`, a self-inflicted DoS on the stdio session; it is now an
  exponential-backoff lockout (1s→30s) that a legitimate operator recovers from.
- **Internals:** workspace root is resolved through an `AsyncLocalStorage` seam
  (`src/repo/workspace.ts`) instead of `process.cwd()` across 40+ sites, so the gate can
  scan a target directory without `process.chdir` — which also fixes tests polluting the
  repo's own `.mcp/baselines/latest.json` on every run. The parallel `CHECK_NAMES` array was
  replaced by a single `CHECKS` registry co-locating each check's name, gate, and runner, so
  a crash can no longer be misattributed to the wrong module. `GateResult.scope.surfaces`
  now declares the `agentic` surface it already carried.
- **First-ever measured false-positive rate.** A new per-rule test corpus
  (`src/tests/corpus/`, one file per check module, 507 true-positive/true-negative cases
  across all 35 modules) is now part of the test suite and reports `tpRate`/`fpRate` to
  `.mcp/reports/rule-quality.json` on every run. Triaging the first real run (which started
  at 40 failures) found and fixed real detection-engine defects, not just corpus mistakes:
  - `searchRepo`'s file-discovery glob was `**/*.*`, which silently excludes every
    extensionless file — `Dockerfile`, `Makefile`, `Jenkinsfile`, etc. Every Docker-deep rule
    gated on `isDockerfile()` was unreachable on a conventionally-named `Dockerfile`. Fixed to
    `**/*`.
  - `checkDependencies` emitted `LOCKFILE_MISSING` and returned immediately, skipping
    typosquat, dependency-confusion, suspicious-version, CVE, maintainer-risk,
    git-protocol-pinning, local-path-override, and scorecard checks entirely whenever a
    lockfile was absent — a realistic, common state, not an edge case. It now keeps running
    the rest of the checks.
  - `ai-redteam.ts`'s `isBinaryFile()` read files via a bare relative path instead of one
    resolved against the workspace root — a second, independent instance of the Wave 0
    `process.chdir()` regression that the original sweep missed. Every file was silently
    treated as binary and skipped.
  - `supply-chain-deep.ts`'s postinstall-network-request regex required the network keyword
    to be the literal last token before the closing quote, so it missed the single most
    common attack shape (`"curl ... | bash"`) entirely.
  - `graphql.ts`'s GraphQL-error-leak check matched the bare substring `stacktrace` inside
    the property name `includeStacktraceInErrorResponses`, so it fired even when that flag
    was correctly set to `false` — the recommended remediation triggered its own violation.
  - `secrets.ts`'s container-registry-password rule used an unbounded `\s+` after
    `--password-stdin` (the safe form), letting the match span a newline and swallow the
    next line's leading token as a fake password value.
  - `business-logic.ts`'s refund-without-purchase-check rule matched `refund(` with no
    guard against function *declarations* — `async function refund(orderId, order)` itself
    false-fired as an unguarded call site, independent of how the real call inside the
    function body was written.
  - `ai.ts`'s PII-in-prompt rule had no bound between the template-literal match and the
    nearby prompt-key reference, so it could span the entire rest of a file — matching a
    `messages` variable near the top against an unrelated PII substring inside a completely
    different, later function (e.g. a masking helper) with no real data flow between them.
  All 507 cases pass after these fixes: `tpRate=1.00`, `fpRate=0.00`. A follow-up adversarial
  review of the negative samples across a 15-module, ~210-case sample found no gamed or
  cosmetic negatives — each implements the rule's own documented remediation.
- **CI self-scan exceptions file shrunk from 16 entries / 452 ids to 13 entries / 282 ids.**
  A full non-diff-scoped self-scan (every git-tracked, non-ignored file, matching CI's own
  invocation exactly) found that two entries — `self-scan-fixtures-and-cloud-controls` (208
  ids) and `self-scan-agentic-instruction-and-ai-governance` (14 ids) — were entirely
  redundant: their stated justification (`fixtures/`, `skills/*/SKILL.md`) is now handled
  outright by CI's `SECURITY_GATE_IGNORE`, which excludes those paths from scanning
  regardless of the exceptions file. Both were deleted. A third, `self-scan-v15-v16-fixtures-
  and-teaching-skills`, was likewise deleted after confirming its 11 still-live ids no longer
  reproduce for the reason stated (the same ignore-list) but do reproduce via the new Wave 2
  corpus fixtures — moved to `self-scan-rule-corpus` with corrected justification rather than
  left under an inaccurate one. Five smaller entries had their genuinely stale ids (confirmed
  gone from a raw, unsuppressed full scan) removed in place. Net result: same self-scan
  outcome (`PASS`, 7 non-blocking MEDIUM findings, identical before and after), with no
  finding_id kept for a reason that no longer holds.
- **Claims registry (`claims/registry.json` + `node scripts/verify-claims.mjs --strict`,
  wired into CI).** Every quantitative or guarantee-style claim security-mcp's own docs make
  about itself now has a probe or test that proves or disproves it, run on every push. 25
  claims registered: 15 QUANTITY (headline numbers — 1,002 cloud rules, 888 remediation
  templates, 91 skills, 40 check modules, 39 named agents, etc. — each checked against a live
  probe that reads the actual built artifact, never a cached value), 2 COVERAGE (set-equality
  checks, not just count-equality), 2 GUARANTEE (one adversarial: an unsigned policy with
  `severity_block:[]` plus a known CRITICAL finding must still FAIL; one delegated to the
  existing e2e compliance-truth test), and 3 SCOPED (claims rewritten to what's actually true,
  with the walk-back recorded in the registry). A `--strict` unregistered-number scan also
  checks README/WIKI/ARCHITECTURE for any `<N> (rules|skills|templates|...)` mention that
  isn't backed by a registered claim, so a new number can't enter those docs unchecked.
  Building this surfaced and fixed four real bugs, not just doc drift: (1) the "888
  templates / 100% coverage" claim was true by count but not by set — `EVAL_UNAVAILABLE_
  THREAT_INTEL` (a live rule) had no template, and `DEP_UNPINNED_VERSION` (a template) had
  no live rule; both fixed in `remediation-map.ts`. (2) 3 of 91 skill manifest entries
  (`aws/gcp/azure-penetration-tester`) had a stale `sha256` that no longer matched their
  SKILL.md content — a real integrity-check failure waiting to happen on the remote-fetch
  skill-loading path; regenerated. (3) `orchestration.verify_skill_coverage`'s tool
  description and README both said "24" or "§0-§24" sections; the enforced set is actually
  28 (24 numbered + 4 universal) — `SKILL_MD_SECTIONS` is now exported so this can never
  silently drift again. (4) A README diagram's alt text said "38 checks"; the live `CHECKS`
  registry has 40. The "90% fixing is a deterministic property of the engine" claim in
  WIKI.md and ARCHITECTURE.md, and README's unconditional "audit trail cannot be silently
  rewritten," were rewritten to what's true (SCOPED) rather than left overstated — see the
  registry's `rewrite.reason` on each for the full explanation.
- **Fail-open sweep (Track E): 12 more evaluability gaps found and fixed.** A full audit
  of all 34 check modules for the "catch → return `[]`" pattern (three parallel reviews,
  ~300 catch sites examined) found 12 additional sites — beyond the
  `EVAL_UNAVAILABLE_THREAT_INTEL` fix already shipped — where a whole check's evidence
  source becoming unavailable silently produced a "clean" result instead of surfacing the
  gap: `checkCveExploitation`'s `npm audit` call (dependencies.ts, also newly threaded
  through `SECURITY_OFFLINE`), the bundled cloud-controls ruleset failing to load
  (cloud-controls.ts, now partial-degrades per-provider instead of losing everything),
  all 5 external scanners' unreadable-output paths (scanners.ts: gitleaks, semgrep,
  trivy, checkov, osv-scanner), nuclei DAST's missing-binary and failed-scan paths
  (nuclei.ts — the module's own "scanner readiness will flag this" comment was false,
  since nuclei was never in the default scanner config), a configured live target's
  header/TLS probes failing (runtime.ts), and the two sites the original audit had
  already named (`auth-deep.ts`, `business-logic.ts` — an internal error in any one of
  ~40 or ~37 sub-checks was discarding every other sub-check's result too). Each gets a
  new `EVAL_UNAVAILABLE_<NAME>` finding (HIGH) and a matching remediation template — the
  remediation-template count moves from 888 to 900, keeping "100% detection-ID coverage"
  exactly true rather than approximately true. Also rewrote the check-authoring "fail
  safe" guidance in WIKI.md and ARCHITECTURE.md, which previously told new check authors
  to unconditionally "return an empty array on any internal error" with no carve-out —
  that wording is itself why this bug class kept getting introduced. Added a new
  adversarial GUARANTEE test (`node scripts/verify-claims.mjs --strict`): forcing `npm
  audit` to fail (empty PATH) must produce `EVAL_UNAVAILABLE_NPM_AUDIT`, not a silently
  clean gate PASS.
- **New `SECURITY_STRICT=1` mode (Track C).** Every permissive default
  (no MCP auth secret required, unsigned policy/audit chains allowed, live
  third-party network egress permitted) is intentional for frictionless local use
  — but there was previously no single switch to lock all of them down at once, and
  no guarantee that a "strict" run wasn't quietly falling back to a weaker default
  when a key was missing. `src/config.ts` computes a frozen `CONFIG` once at import
  time: `SECURITY_STRICT=1` requires `SECURITY_POLICY_HMAC_KEY` and
  `SECURITY_AUDIT_HMAC_KEY` for both the CLI gate and the MCP server, additionally
  requires `SECURITY_MCP_SHARED_SECRET` for the MCP server (a CI gate run has no
  session to authenticate a caller against, so that requirement is server-specific),
  and forces `SECURITY_OFFLINE` on regardless of its own setting. If a required key
  is absent, the process throws at startup and refuses to run rather than silently
  proceeding with a weaker default. The three `SECURITY_OFFLINE` call sites
  (threat-intel KEV/EPSS, dependency scorecard, npm audit) now read `CONFIG.offline`
  instead of the raw environment variable directly, so the strict-mode override
  actually reaches them. Verified with a new adversarial GUARANTEE test that spawns
  a real child process with `SECURITY_STRICT=1` and no keys set and asserts it fails
  at import time with the expected error — plus manual verification of the MCP
  server's additional shared-secret requirement.
- **Migrated the test suite to `node:test` (Track B).** `src/tests/run.ts`'s
  hand-rolled `main()` — 13 async test functions each manually `await`-chained,
  with `process.exit(1)` on the first thrown assertion — is now
  `src/tests/legacy.test.ts`: the same 13 functions, unchanged, each registered
  via `await test(name, fn)` in the identical order the old `main()` called them
  in (several share fixture state through `cleanupFixtureReviewArtifacts()`
  before/after, so the explicit sequential `await` preserves that ordering
  guarantee rather than assuming `node:test`'s default scheduling would happen to
  match). `npm test` is now `node --test --experimental-test-coverage
  dist/tests` — zero new dependencies, and `--experimental-test-coverage` adds a
  per-file coverage report the hand-rolled runner never had. All 13 tests
  (507-case rule corpus included) verified passing after the migration, in the
  same 13/13 shape as before. `scripts/verify-claims.mjs`'s delegated-GUARANTEE
  path and every doc/exception-file reference to the old `src/tests/run.ts` /
  `dist/tests/run.js` path updated to match.

### Added: one-shot `security.fortify` — natural-language "lock down X" dispatch

Plain requests like "fortify my codebase" or "lock down the forms on my website for
highest security" previously had no single tool to call — the calling model had to already
know to chain `start_review(auto_apply)` → `generate_remediations` → apply → re-verify,
with no way to narrow either the file scope or the specialist team to a named surface.

- New MCP tool `security.fortify` (`src/mcp/server.ts`) and matching `fortify` MCP prompt:
  a single call that always auto-applies (no `remediationMode` question, no confirmation
  gate), resolves a free-text `target` to concrete files via the existing repo-search
  engine, and pre-selects the specialist agent team.
- New module `src/mcp/fortify.ts`: agent selection is not a fixed feature-name table (users
  name arbitrary surfaces — forms, a payment flow, an admin panel). Instead it's two axes —
  a generic core app-security team (`threat-modeler`, `attack-navigator`,
  `appsec-code-auditor`, `injection-specialist`, `auth-session-hacker`,
  `business-logic-attacker`, `logic-race-fuzzer`, `serialization-memory-attacker`,
  `privacy-flow-analyst`) dispatched for any named surface, plus domain-specific additions
  gated on genuine technology signals (cloud, crypto, supply-chain, AI/LLM, mobile) rather
  than on the feature's name.
- `src/mcp/orchestration.ts`: `buildInitialAgents` split into an exported
  `buildInitialAgentNames(stackContext)` plus a thin wrapper, so `orchestration.create_agent_run`
  can accept an optional pre-filtered `agentNames` list (intersected against the real agent
  universe before use) without changing behavior for existing callers that omit it.
- Trigger wording added across `skills/senior-security-engineer/SKILL.md`,
  `skills/ciso-orchestrator/SKILL.md`, `skills-manifest.json`, `README.md`, and
  `client-templates/*` so plain "fortify"/"lock down X"/"harden to production grade"
  requests reliably route to `security.fortify` on every MCP host, not just Claude Code.

### Changed: `security.start_review` defaults to `auto_apply`

Omitting `remediationMode` on `security.start_review` previously returned a
`required_user_decision` question and did nothing until answered. It now defaults to
`auto_apply` — fixes are written immediately as findings are discovered, matching the
"90% fixing, 10% advisory" operating mandate this project already states elsewhere.
`detection_only` remains fully supported as an explicit opt-out for a report-only run;
`security.run_pr_gate`'s "should specialist agents apply the fixes?" prompt is unchanged
and now only fires for callers who explicitly chose `detection_only`.

**Migration:** pass `remediationMode: "detection_only"` explicitly if you relied on the old
ask-first default to get a report without any file changes.

### Fixed: stale/unpinned security-mcp installs silently degrading the CISO orchestrator

`npx security-mcp` without a pinned version can resolve to a stale global install or npx
cache entry, launching an old server missing the `orchestration.*` control plane tools.
The ciso-orchestrator skill previously degraded silently to a deterministic-only run
instead of surfacing this.

- `security-mcp doctor` now detects a global install older than the running version
  (flags `npm rm -g security-mcp`) and unpinned `npx security-mcp` launch entries across
  Claude Code, Cursor, VS Code, and Windsurf configs (flags re-running the installer).
- `ciso-orchestrator` SKILL.md adds a mandatory Step 0 control-plane preflight: it checks
  for the `orchestration.*` tools under any host-namespaced form before starting, and
  halts with exact remediation instead of silently falling back if they are genuinely
  absent.

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
