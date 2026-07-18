# security-mcp

Last updated: 2026-07-17

[![npm version](https://img.shields.io/npm/v/security-mcp.svg)](https://www.npmjs.com/package/security-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![CI](https://github.com/AbrahamOO/security-mcp/actions/workflows/security-gate.yml/badge.svg)](https://github.com/AbrahamOO/security-mcp/actions)

An autonomous application-security engineering layer for AI-assisted development.

security-mcp is a [Model Context Protocol](https://modelcontextprotocol.io) server that turns your AI coding assistant into a security engineer that does the work, not a linter that files tickets. It reads code the way an attacker does, writes the secure fix inline, and enforces a gate in CI so insecure code cannot merge. The operating mandate across the product is the same one a strong security hire would hold: roughly 90% fixing, 10% advisory.

Platform and security teams can standardize their entire AppSec program on it. A solo founder can install it in a minute and ship safer code on day one. No security background is required to benefit, but nothing is dumbed down for the people who have one.

Works with Claude Code, Cursor, VS Code / GitHub Copilot, Windsurf, Codex, Replit, and any MCP-compatible editor.

```bash
npx -y security-mcp@latest install
```

---

## Table of Contents

- [Why this exists](#why-this-exists)
- [Is security-mcp safe to use?](#is-security-mcp-safe-to-use-the-mcps-own-security--governance)
- [What's new in 1.3.6](#whats-new-in-136)
- [System overview](#system-overview)
- [The two entry points](#the-two-entry-points)
  - [/senior-security-engineer](#senior-security-engineer)
  - [/ciso-orchestrator](#ciso-orchestrator)
- [The gate engine](#the-gate-engine)
- [Cloud security controls engine](#cloud-security-controls-engine)
- [Install](#install)
- [CI/CD gate](#cicd-gate)
- [Built for teams](#built-for-teams)
- [Self-protection and supply-chain posture](#self-protection-and-supply-chain-posture)
- [MCP tools](#mcp-tools)
- [Frameworks](#frameworks)
- [Policy and exceptions](#policy-and-exceptions)
- [Environment variables](#environment-variables)
- [The 10 non-negotiable rules](#the-10-non-negotiable-rules)
- [CLI reference](#cli-reference)
- [Documentation and disclosure](#documentation-and-disclosure)
- [License](#license)

---

## Why this exists

Most security tooling stops at detection. It produces a list, hands it to a human, and waits. That model breaks down when AI assistants are writing the majority of the code, because the volume of change outpaces anyone's ability to triage a backlog by hand.

security-mcp inverts the default. When it finds a vulnerability it writes the production-ready fix into your working tree, re-runs the check to confirm the issue cleared, and only then moves on. The same engine runs as a deterministic gate in CI, so the contract is simple: HIGH and CRITICAL findings do not merge.

You get three things from one install:

- An interactive security engineer that fixes code inside your editor.
- A multi-agent security program that runs a full audit on demand.
- A standalone CI gate that needs no AI session to enforce the line.

---

## Is security-mcp safe to use? (the MCP's own security & governance)

A security tool that reads your repository and calls out to an AI model is itself part of your trust boundary. Short answer: security-mcp runs locally, sends your code to a third party only for steps you explicitly opt into, and is built so it cannot be silently disabled or made to lie about what it did.

### Does it send my code anywhere?

No, not by default. security-mcp runs as a local MCP server over stdio (`src/mcp/server.ts` connects via `StdioServerTransport`, never an HTTP listener) or as a plain CLI, and there is no telemetry call anywhere in the server or CLI code. The network calls that do exist are ones you opt into: live threat intel (CISA KEV, EPSS, OpenSSF Scorecard, npm registry), scanner-binary and skill downloads, and any Slack/Jira/PagerDuty/webhook integration you configure. Set `SECURITY_OFFLINE=1` for a fully air-gapped run.

### How does security-mcp protect my code and secrets?

Findings never echo the thing they detect. Secret-scan matches are replaced with `[REDACTED]` (`src/gate/checks/secrets.ts`), a hardcoded session secret is shown truncated as `prefix…suffix` (`src/gate/checks/web-hardening.ts`), and an invisible-Unicode prompt-injection finding reports only the codepoint and location, never the raw bytes (`src/gate/checks/emerging-supply-ai.ts`). Regex scanning is hardened against hostile input too: `isCatastrophicRegex` rejects catastrophic-backtracking patterns and user-supplied patterns are length-capped, so a crafted string in a malicious repo can't hang the scanner (`src/repo/search.ts`).

### Can the gate be silently disabled?

Not without leaving evidence. Policy, exceptions, and baseline files are HMAC-signed (`SECURITY_POLICY_HMAC_KEY`, `security-mcp sign-policy`). If the signature is missing or invalid, the gate does not just warn — it forces `HIGH` and `CRITICAL` back into the blocking severity set regardless of what the policy file says (`src/gate/policy.ts`), so editing an unsigned policy to clear `severity_block` still can't let HIGH/CRITICAL findings merge. A check module that throws never disappears quietly either: it becomes a HIGH `GATE_CHECK_CRASHED` finding, with the error text sanitized to strip local filesystem paths before it's shown (`sanitizeErrorMessage`, `src/gate/result.ts`).

### Can a multi-agent run fake a clean result?

Every `/ciso-orchestrator` run writes a hash-linked, optionally HMAC-signed attestation chain (`initChain`, `attestAgent`, `verifyChain`, `getChain` in `src/mcp/audit-chain.ts`), and the merge step verifies each agent's findings hash against its signed attestation before trusting it (`src/mcp/orchestration.ts`) — a tampered chain or a hash mismatch forces the gate to FAIL. Spawned agents are also held to a capability floor: `enforceCapabilityFloor` (`src/mcp/capability-enforcer.ts`) checks that each agent ran at the model tier its task required (per `src/mcp/model-router.ts`'s task-capability map) and produced real evidence, raising a HIGH finding for a degraded agent and a run-level CRITICAL that fails the gate if any agent falls short.

### Does it execute anything unsafely?

Child processes (git, npm audit, binary downloads) are invoked with `execFile`/`spawnSync` and fixed argument arrays, never a shell string built from repo or user input (`src/cli/onboarding.ts`, `src/gate/baseline.ts`), so the tool itself can't be turned into a command-injection vector. The network fetches it does make are restricted to explicit host allowlists — scanner binaries to `ALLOWED_BINARY_HOSTS` (`src/cli/onboarding.ts`), skills to a `raw.githubusercontent.com`-only prefix check (`src/mcp/orchestration.ts`) — and downloaded binaries are verified by SHA-256 before use.

### Does security-mcp trust itself?

It scans its own source on every change: `.github/workflows/security-gate.yml` runs the same gate against security-mcp's own code in CI, with a narrowly-scoped exceptions file (`.github/security-exceptions-ci.json`) for the handful of intentional test fixtures and non-applicable controls. Its own supply chain stays small and pinned: five runtime dependencies (`package.json`), a committed lockfile, and CI actions pinned to full commit SHAs rather than floating tags.

| Mechanism | What it protects | Where in code |
| --- | --- | --- |
| Local stdio process, no listener, no telemetry | Your code never leaves your machine to a third party by default | `src/mcp/server.ts` |
| HMAC-signed policy / exceptions / baseline | An unsigned edit can't silently weaken the gate; HIGH/CRITICAL stay blocked | `src/gate/policy.ts`, `src/gate/exceptions.ts`, `src/gate/baseline.ts` |
| Hash-linked, optionally signed audit chain + attestations | A verified record of what actually ran, not a self-reported one | `src/mcp/audit-chain.ts`, `src/mcp/orchestration.ts` |
| Fail-safe crash containment | A crashing check becomes a HIGH finding, not a silent blind spot | `src/gate/policy.ts`, `src/gate/result.ts` |
| ReDoS-hardened pattern matching | A hostile repo or string can't hang the scanner | `src/repo/search.ts` |
| Secret/PII redaction in findings | Findings never echo a full secret or raw invisible bytes | `src/gate/checks/secrets.ts`, `src/gate/checks/web-hardening.ts`, `src/gate/checks/emerging-supply-ai.ts` |
| Host-allowlisted downloads + SHA-256 verified binaries | Skill/scanner fetches can't be redirected to an attacker host | `src/cli/onboarding.ts`, `src/mcp/orchestration.ts` |
| No-shell child processes | Can't be turned into a command-injection vector | `src/cli/onboarding.ts`, `src/gate/baseline.ts` |
| Capability-floor enforcement for spawned agents | Agents can't silently run under-powered or unsupervised | `src/mcp/capability-enforcer.ts`, `src/mcp/model-router.ts` |
| Self-scan in CI | The gate is held to its own bar on every change | `.github/workflows/security-gate.yml` |
| Minimal, pinned dependencies | Small, auditable attack surface | `package.json`, `.github/workflows/` |

security-mcp is honest about where its trust model stops: this is a single-tenant, local, stdio MCP whose trust root is the installed package, and an unsigned attestation chain is tamper-evident rather than cryptographically tamper-proof unless you set `SECURITY_AUDIT_HMAC_KEY`. See the [CHANGELOG](CHANGELOG.md) for the full residual-risk disclosure, and [self-protection and supply-chain posture](#self-protection-and-supply-chain-posture) below for more detail on the CI/gate hardening.

---

## What's new in 1.3.6

**One-shot fortify.** Say "fortify my codebase", "lock down my forms", "secure our payment flow", or "harden the AWS account to enterprise grade", and the assistant calls the new `security.fortify` tool (or the `fortify` MCP prompt) with your own words as the target. It always auto-applies: no "detection only or auto-apply?" question, no pause to ask whether to fix what it found. It resolves your target to concrete files via repo search, then dispatches the right specialist team immediately — a generic core app-security team (injection, auth/session, business logic, race conditions, serialization, privacy) for any named surface, plus cloud, crypto, AI/LLM, mobile, or supply-chain specialists layered on when those technical domains are detected. The target is free text, not a fixed category list: any surface you can name resolves the same way.

**Auto-apply is now the default everywhere.** `security.start_review` previously required you to choose `auto_apply` or `detection_only` before it would do anything. Omitting `remediationMode` now means `auto_apply` — findings get fixed as they are discovered, matching the 90%-fixing mandate the rest of the product already states. Pass `remediationMode: "detection_only"` explicitly for a report-only run; that path, including the gate's "should specialist agents apply the fixes?" checkpoint, is unchanged.

**Stale-install detection.** `security-mcp doctor` now detects a global install older than the running version and unpinned `npx security-mcp` launch entries across Claude Code, Cursor, VS Code, and Windsurf, and `ciso-orchestrator` halts with exact remediation instead of silently degrading to a deterministic-only run when the `orchestration.*` control plane is genuinely missing.

For every prior release — the cloud controls engine, the vibe-coding and web-hardening modules, 900 remediation templates at 100% detection-ID coverage, capability-floor enforcement, and inter-agent payload integrity — see the [CHANGELOG](CHANGELOG.md).

---

## System overview

<p align="center">
  <img src="https://raw.githubusercontent.com/AbrahamOO/security-mcp/main/assets/diagrams/system-overview.svg" alt="System overview: editor skills and CI both call the same MCP server, which drives the gate engine, orchestration, cloud controls, and platform subsystems into a shared attestation." width="820">
</p>

The MCP server is the trust root. Both entry-point skills, the standalone CI gate, and every supporting subsystem call into the same engine, so an interactive fix and a CI verdict are produced by identical logic.

---

## The two entry points

You drive security-mcp through two skills. One is your daily security engineer. The other is a full security program you run when the stakes are high.

| | `/senior-security-engineer` | `/ciso-orchestrator` |
| --- | --- | --- |
| Shape | One elite engineer agent | 39 named agents, 40+ at runtime |
| Best for | Every PR, targeted hardening | Pre-release audits, compliance prep |
| Scope | You pick: diff, full codebase, or specific paths | Full: every surface, every framework |
| Speed | Seconds to minutes | Minutes to hours |
| Output | Inline fixes + SHA-256 attested report | Merged findings, compliance mapping, signed attestation |
| Network | Not required | Optional live threat intel |

Rule of thumb: run `/senior-security-engineer` on every PR, and `/ciso-orchestrator` before a release or an audit.

### One-shot fortify

Both entry points respond to plain language, not just slash commands. Say "fortify my codebase," "lock down my forms," "secure our payment flow," or "harden the AWS account for enterprise grade," and the assistant calls the `security.fortify` MCP tool (or the `fortify` prompt) with your own words as the `target` — free text, not a fixed category list, so any named surface resolves the same way.

`security.fortify` always auto-applies: no "detection only or auto-apply?" question, no pause to ask whether to fix what it finds. It resolves your target to concrete files via repo search (or scans the whole codebase if you didn't name a specific surface), and dispatches the right specialist team immediately — a generic core app-security team (injection, auth/session, business logic, race conditions, serialization, privacy) for any named surface, plus cloud, crypto, AI/LLM, mobile, or supply-chain specialists layered on top when those technical domains are detected. For "lock down the forms on my website for highest security," that means the auth/injection/business-logic specialists go straight to your form and login files and write the fixes, then the gate re-runs to a PASS attestation.

`security.start_review` itself defaults to auto-apply too — omit `remediationMode` and it fixes findings as it finds them rather than asking first. Pass `remediationMode: "detection_only"` explicitly if you want a report without any file changes.

### /senior-security-engineer

A single elite security-engineer agent. It operates 90% fixing, 10% advisory: it writes the secure code rather than handing you a report to act on. You pick the scope at the start (recent changes via git diff, the full codebase, or specific files and folders), and it runs a strategy pass, then the gate, then inline fixes, and finishes with a SHA-256 attested report you can keep as an audit artifact.

This is the daily driver. Use it on every PR.

<p align="center">
  <img src="https://raw.githubusercontent.com/AbrahamOO/security-mcp/main/assets/diagrams/senior-security-engineer.svg" alt="senior-security-engineer flow: pick scope, build strategy, run gate, write inline fixes, re-run until clean, then emit a SHA-256 attested report." width="720">
</p>

### /ciso-orchestrator

A full security program in one command, held to the same 90% fixing, 10% advisory mandate as the single agent: every specialist writes the fix rather than filing a finding. Nine specialist lead agents command 30 sub-agents, for 39 named agents in the static spawn tree. At runtime the orchestrator dynamically spawns additional ghost and coverage agents based on cross-domain findings, so a real run typically fields 40 or more. It draws on a registry of 91 specialist skills (registry version 1.6.1), loaded on demand based on your detected stack. `security.generate_compliance_report` provides partial control mappings for SOC 2, PCI DSS 4.0, NIST 800-53, and ISO 27001 — a control is marked satisfied only when a gate run completed its required steps with no adverse finding, never by default, and the report is an evidence-gathering aid, not an audit.

It runs in three phases:

1. **Discovery (parallel).** Seven leads run at once: threat modeling, AppSec code audit, cloud and infrastructure, supply chain, AI/LLM red team, mobile, and crypto/PKI.
2. **Adversarial and compliance (parallel).** A penetration-test team reads Phase 1's threat model as its attack brief, while a compliance/GRC synthesizer maps findings to controls.
3. **Synthesis.** Each agent's findings file is schema-validated and verified against that agent's signed attestation before it is trusted, then findings are merged and deduplicated, SKILL.md section coverage (§0 through §24) is verified, and a signed attestation is written. A tampered attestation chain or a findings-hash mismatch forces the gate to FAIL.

<p align="center">
  <img src="https://raw.githubusercontent.com/AbrahamOO/security-mcp/main/assets/diagrams/ciso-orchestrator.svg" alt="ciso-orchestrator spawn tree: Phase 1 discovery leads and sub-agents in parallel, Phase 2 pentest and compliance teams, Phase 3 attestation verification, merge, coverage check, and signed attestation." width="940">
</p>

Cloud, AI/LLM, and mobile sub-agents are conditional: they activate only when the relevant stack is detected, and report N/A otherwise.

---

## The gate engine

The gate is the deterministic core. On every run it executes 38 security checks in parallel (36 distinct check modules plus 2 precomputed coverage feeds). It is surface-aware: it first detects which surfaces a change touches (web, API, infrastructure, iOS, Android, AI/LLM, agentic) and runs the relevant checks against them.

<p align="center">
  <img src="https://raw.githubusercontent.com/AbrahamOO/security-mcp/main/assets/diagrams/gate-engine.svg" alt="Gate engine pipeline: load HMAC-verified policy, resolve scope, classify change, detect surfaces, run 40 checks in parallel, assign SLAs, build coverage manifest, apply exceptions, score confidence, diff against baseline, and produce a verdict." width="760">
</p>

A crashed check module never disappears quietly. It becomes a HIGH coverage-gap finding, so the absence of a result is itself a result. A control that regresses from satisfied to missing against the saved baseline also becomes a HIGH finding.

### Deep-analysis modules

| Module | Patterns | What it targets |
| --- | --- | --- |
| Deep injection | 56 | SQL/NoSQL, SSTI, SpEL/OGNL, deserialization, CRLF, SSRF, HTTP request smuggling, and more |
| Deep authentication | 55 | JWT confusion (including `kid` injection), session and OAuth flaws, SAML XXE, weak hashing, token entropy |
| Deep supply chain | 33 | Obfuscated payloads, malicious scripts, exfiltration channels |
| Business logic | 41 | IDOR, race conditions, payment and e-commerce abuse |
| Data platform | 52 | Databricks and Snowflake misconfiguration |
| Deep Docker | 52 | Container build and runtime hardening |
| GitOps | 45 | ArgoCD and Flux pipeline integrity |
| Agentic-instruction integrity | 16 | Poisoned AI agent instruction files |
| AI governance | 3 | Shadow-AI and data-to-LLM exfiltration |

Alongside these, the gate runs Kubernetes (74 checks), IaC (63), and dedicated modules for secrets, dependencies, crypto, web/Next.js, API, mobile (iOS and Android), GraphQL, database, DLP, SBOM, an incident-response playbook, runtime/DAST, CI pipeline hardening, and a Nuclei DAST integration.

Three additional modules, added in 1.5.0, target current CVEs and agentic-AI threats rather than a broad pattern class: `emerging-web` (Next.js middleware auth bypass, React2Shell RSC deserialization, Django ORM SQLi, Kestrel smuggling, JWT `jku`/`x5u` SSRF, `path-to-regexp` ReDoS; runs on web/API surfaces), `emerging-cloud` (IngressNightmare, AWS `PassRole` privilege escalation, unpinned Terraform module refs, GCP token-creator bindings, runc escape delivery surfaces; runs on infrastructure surfaces), and `emerging-supply-ai` (Shai-Hulud worm IOCs, off-registry lockfile resolution, `mcp-remote` command injection, invisible-Unicode injection, MCP config rug-pulls, dangerous pickle opcodes, A2A credential forwarding; always runs). See [docs/WIKI.md](docs/WIKI.md) for the full rule list.

### Scanner orchestration and threat intel

When they are present on the host, the gate orchestrates industry scanners: gitleaks, semgrep, trivy, osv-scanner, checkov, conftest, and zaproxy. Their results fold into the same findings model.

Live threat intelligence (cached for 24 hours) enriches the verdict: CISA KEV, EPSS (a score above 0.5 escalates severity), OpenSSF Scorecard, and the npm registry. Set `SECURITY_OFFLINE=1` to disable all third-party egress. Private and internal scoped package names are never sent to public endpoints, online or off.

---

## Cloud security controls engine

A registry-driven engine scans infrastructure-as-code against 1,002 rules mapped to AWS Foundational Security Best Practices (FSBP), CIS Benchmarks for AWS, GCP, and Azure, and the Microsoft Cloud Security Benchmark.

| Coverage | Rules |
| --- | --- |
| AWS | 487 |
| Azure | 320 |
| GCP | 195 |
| Terraform / HCL | 778 |
| CloudFormation | 128 |
| Bicep | 96 |

<p align="center">
  <img src="https://raw.githubusercontent.com/AbrahamOO/security-mcp/main/assets/diagrams/cloud-controls.svg" alt="Cloud controls flow: detect IaC against the 1,002-rule registry, surface violations, auto-fix safe Terraform cases then re-detect to confirm, revert if not cleared, and report anything unsafe as a manual action with a snippet." width="720">
</p>

Terraform supports auto-remediation through `security-mcp autoharden` (use `--dry-run` to preview). The engine applies a fix, re-detects to confirm the violation actually cleared, and only then keeps the change. Anything it cannot safely auto-fix is reported as a manual action with a code snippet.

---

## Install

Prerequisite: Node.js 20 or higher (`node --version`).

```bash
npx -y security-mcp@latest install
```

The installer auto-detects Claude Code, Cursor, VS Code / GitHub Copilot, Windsurf, and Codex, and writes the config to the right place. (Replit is remote-MCP only — see below.) Restart your editor, then run a review:

```text
/senior-security-engineer
```

For a full audit:

```text
/ciso-orchestrator
```

Confirm the install is healthy at any time:

```bash
npx -y security-mcp@latest doctor
```

### Manual config

Add the server to your editor's MCP config and restart.

Claude Code (`~/.claude/settings.json`), Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`) — all use the `mcpServers` key:

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "npx",
      "args": ["-y", "security-mcp@latest", "serve"]
    }
  }
}
```

VS Code / GitHub Copilot (`.vscode/mcp.json`) — top-level key is `servers` (in user `settings.json` it nests under `"mcp": { "servers": { … } }`):

```json
{
  "servers": {
    "security-mcp": {
      "command": "npx",
      "args": ["-y", "security-mcp@latest", "serve"]
    }
  }
}
```

Codex (`~/.codex/config.toml`, or project-scoped `.codex/config.toml`) — TOML:

```toml
[mcp_servers.security-mcp]
command = "npx"
args = ["-y", "security-mcp@latest", "serve"]
```

Replit consumes MCP as a remote server only. Add security-mcp through Replit's
Integrations UI (Add custom MCP server) pointing at a hosted MCP endpoint; the local
`npx … serve` stdio command above does not apply there.

### Runs on every client, at full capability

The agent roster is delivered over the MCP protocol itself, not a Claude-only skills
directory. Every client can load and run every agent: the `senior-security-engineer` and
`ciso-orchestrator` MCP prompts are the entry points, `skill://catalog` and
`skill://<name>` resources expose each agent's full persona, and the
`orchestration.ensure_skill` tool returns any agent's complete instructions on demand.
Hosts with parallel subagents run the roster concurrently; others run it sequentially —
each agent to full completion, nothing skipped.

---

## CI/CD gate

The gate runs as plain Node.js with no AI session involved, so it belongs in your pipeline as a required check.

```bash
npx -y security-mcp@latest ci:pr-gate
```

It exits non-zero on HIGH or CRITICAL findings.

### GitHub Actions

Create `.github/workflows/security-gate.yml`:

```yaml
name: Security Gate

on:
  pull_request:
    branches: [main]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # required for git diff

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Block insecure code from merging
        run: npx -y security-mcp@latest ci:pr-gate
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Optional HMAC integrity

To make the policy tamper-evident, add a repository secret named `SECURITY_POLICY_HMAC_KEY` that is at least 32 bytes, then sign and commit:

```bash
security-mcp sign-policy
```

Commit the policy file together with its generated `.hmac` sidecar. Once a key is set, the gate requires a valid signature on the policy, and a missing sidecar is rejected by design, so the key and the signature must land in the same change.

---

## Built for teams

Four platform subsystems let a security team operate security-mcp at scale, not just run it ad hoc.

**Multi-provider model router.** Cost-aware routing across model providers, with circuit breakers and a spend budget so a single provider outage or a runaway run cannot stall or overspend the program.

**Learning engine.** Remembers confirmed patterns and false positives per project, with rate-limited false-positive suppression so noise drops over time. Routing decisions are written to an ISO 42001 audit log.

**Tamper-evident attestation hash chain.** Each agent attestation is chained (`init_chain`, `attest_agent`, `verify_chain`, `get_chain`). With `SECURITY_AUDIT_HMAC_KEY` set, every link is signed and a rewrite requires the key, not just filesystem access — that configuration is what actually makes the audit trail resistant to silent rewriting. Without a key, the chain is hash-only: still detects an accidental edit, but anyone with write access to the attestation files can recompute the chain over edited content, since no secret is required to forge it.

**MCP caller authentication.** An optional shared-secret gate on the MCP channel uses constant-time HMAC comparison, a 3-strike lockout, and a session TTL (8 hours by default, capped at 24). When unset, the channel stays open for frictionless local use.

---

## Self-protection and supply-chain posture

A security tool is part of your supply chain, so security-mcp is built to resist the same attacks it looks for. This matters most when the threat is a malicious repository or a compromised dependency trying to neutralize the gate.

- **Signed policy, exceptions, and baseline.** These files are HMAC-signed. When the policy is not signed, the gate floors `severity_block` to HIGH/CRITICAL, so an unsigned edit cannot relax the gate to PASS.
- **Exceptions cannot quietly suppress.** By default an unsigned exceptions file may not suppress HIGH/CRITICAL findings. A break-glass env var exists for scanning intentionally-vulnerable fixtures.
- **Honest attestation.** Attestation refuses to sign unless the latest gate result is PASS with all required steps complete. There are no forged green attestations.
- **Verified inter-agent payloads.** The merge step that aggregates every agent's findings is the trust sink for a whole run, so it schema-validates each agent's findings file and checks its hash against that agent's signed attestation before trusting it. Findings dedupe keeps the highest severity per id, so a same-id low-severity entry cannot shadow a real CRITICAL. A tampered chain or a findings-hash mismatch forces FAIL. Set `SECURITY_REQUIRE_AGENT_ATTESTATION=1` to fail closed unless the run is HMAC-signed, fully attested, and clean — note that an *unsigned* attestation chain is only tamper-evident, not tamper-proof, against an attacker who can write the run directory, so the HMAC key is the real boundary.
- **Per-tool-call audit trail.** Every MCP tool call is logged as one structured JSONL record (timestamp, agent id, tool, inputs, output summary, session credential, outcome) to `.mcp/audit/tool-calls.jsonl`. Secret-bearing keys and secret-shaped values (in inputs and in the output preview) are scrubbed; failed auth attempts are recorded as such, not as successes; the log rotates at 50 MB and writing never interrupts a tool call. Set `SECURITY_TOOL_AUDIT_LOG` to forward to an append-only sink.
- **Locked-down data at rest.** Findings, agent memory, and signatures are written with `0o600` file permissions.
- **Prompt-injection defense.** Tool outputs that originate from the repo are sanitized before they reach an LLM.
- **Verified installer.** Downloaded scanner binaries are verified by SHA-256, unchecksummed binaries are refused, and there is no `curl | sh` install path.
- **Air-gap mode.** `SECURITY_OFFLINE=1` produces a fully offline run with no third-party egress.

---

## MCP tools

Your AI calls these automatically; you rarely invoke them by hand. There are 41, grouped into three namespaces plus 6 MCP prompts.

### Most useful tools

| Tool | Purpose |
| --- | --- |
| `security.fortify` | One-shot: auto-apply review + scoped specialist team for a named surface |
| `security.start_review` | Open a stateful review run and get a `runId` (defaults to auto-apply) |
| `security.run_pr_gate` | Run the gate, return PASS/FAIL with findings |
| `security.attest_review` | Write a SHA-256 attestation (PASS-gated) |
| `security.threat_model` | STRIDE + PASTA + ATT&CK model for a surface |
| `security.scan_strategy` | Map every check to OWASP/NIST/ATT&CK controls |
| `security.generate_policy` | Generate a policy tailored to your stack |
| `security.terraform_hardening_blueprint` | Terraform hardening baseline + mappings |
| `security.generate_opa_rego` | OPA/Rego for plans, pipelines, admission |
| `security.generate_compliance_report` | Partial control mapping for SOC 2, PCI DSS 4.0, NIST 800-53, ISO 27001 (evidence aid, not an audit) |
| `security.generate_remediations` | Concrete fix template per finding |
| `repo.read_file` / `repo.search` | Read or search the codebase (guarded) |
| `orchestration.create_agent_run` | Stand up the multi-agent run + manifest |
| `orchestration.merge_agent_findings` | Dedupe and sort findings across agents |
| `orchestration.verify_skill_coverage` | Check §1-§24 plus the 4 universal SKILL.md sections (28 total) |

### Operational families

Beyond the tools above, the rest of the surface clusters into four families:

- **Model routing and budget.** `get_routing`, `get_model_for_task`, `track_usage`, `model_budget_status`, `get_provider_health`, `record_provider_failure`, `reset_provider_circuit`.
- **Learning and pattern memory.** `record_outcome`, `pattern_report`, `self_heal_loop`, plus `orchestration.read_agent_memory` / `write_agent_memory`.
- **Attestation hash chain.** `init_chain`, `attest_agent`, `verify_chain`, `get_chain`.
- **Caller auth and lifecycle.** `authenticate`, `logout`, plus update tools `orchestration.check_updates` / `apply_updates` and skill loading `orchestration.ensure_skill`.

Namespace counts: `security.*` (30 tools), `repo.*` (2), `orchestration.*` (9), and 6 MCP prompts (`security-engineer`, `threat-model-template`, `ciso-orchestrator`, `senior-security-engineer`, `agentic-instruction-auditor`, `fortify`).

---

## Frameworks

Every finding and fix maps to recognized standards. You do not need to know them to benefit; they are there so your evidence stands up to an auditor.

| Domain | Standards |
| --- | --- |
| OWASP | Top 10 (Web + API), ASVS L2/L3, MASVS, Top 10 for LLMs, Testing Guide |
| MITRE | ATT&CK (Enterprise + Cloud + Mobile), D3FEND, ATLAS, CAPEC |
| NIST | 800-53 Rev 5, CSF 2.0, 800-207 Zero Trust, 800-218 SSDF, AI RMF, 800-131A |
| Compliance | PCI DSS 4.0, SOC 2 Type II, ISO 27001:2022 + 27002, ISO 42001:2023, GDPR / CCPA / HIPAA |
| Supply chain and cloud | SLSA Level 3, CIS Benchmarks L2, AWS FSBP, Microsoft Cloud Security Benchmark |
| Scoring | CVSS v4.0 + EPSS |

---

## Policy and exceptions

The policy lives at `.mcp/policies/security-policy.json`. Copy the default to start:

```bash
mkdir -p .mcp/policies
cp node_modules/security-mcp/defaults/security-policy.json .mcp/policies/security-policy.json
```

Exceptions live at `.mcp/exceptions/security-exceptions.json`. Each entry needs `id`, `finding_ids`, `justification`, `ticket`, `owner`, `approver` (the owner cannot be the approver), `approval_role`, and `expires_on` (within 365 days):

```json
{
  "version": "1.0.0",
  "exceptions": [
    {
      "id": "EX-001",
      "finding_ids": ["DEP_CVE_CVE-2024-12345"],
      "justification": "Library being replaced next sprint; no public exploit",
      "ticket": "JIRA-9999",
      "owner": "alice@example.com",
      "approver": "bob@example.com",
      "approval_role": "SecurityLead",
      "expires_on": "2026-12-31"
    }
  ]
}
```

Expired exceptions automatically become blocking findings until they are renewed or resolved.

---

## Environment variables

### Strict mode

| Variable | Purpose |
| --- | --- |
| `SECURITY_STRICT` | Set to `1` to require every integrity/auth key below and force offline mode, refusing to start if any required key is missing |

Every permissive default below (no MCP auth secret required, unsigned policy/audit
chains allowed, live third-party network egress permitted) exists for frictionless
local use. `SECURITY_STRICT=1` flips all of them to their locked-down setting in one
step: `SECURITY_POLICY_HMAC_KEY` and `SECURITY_AUDIT_HMAC_KEY` become mandatory for
both the CLI gate and the MCP server, `SECURITY_MCP_SHARED_SECRET` additionally
becomes mandatory for the MCP server, and `SECURITY_OFFLINE` is forced on regardless
of its own setting. If a required key is missing, the process throws and refuses to
start rather than silently falling back to a weaker default — see `src/config.ts`.

### Gate and scope

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECURITY_GATE_POLICY` | `.mcp/policies/security-policy.json` | Policy file path |
| `SECURITY_GATE_MODE` | `recent_changes` | Scan mode |
| `SECURITY_GATE_TARGETS` | (changed files) | Comma-separated paths to restrict the scan |
| `SECURITY_GATE_BASE_REF` | `origin/main` | Branch to diff against |
| `SECURITY_GATE_HEAD_REF` | `HEAD` | Branch being scanned |
| `SECURITY_GATE_EXCEPTIONS` | (default path) | Exceptions file path |
| `SECURITY_GATE_SCANNERS` | built-in | Custom scanner config path |
| `SECURITY_GATE_EVIDENCE_MAP` | (none) | Evidence-coverage map path |
| `SECURITY_GATE_CONTROL_CATALOG` | (none) | Control-catalog path |

### Integrity and signing

| Variable | Purpose |
| --- | --- |
| `SECURITY_POLICY_HMAC_KEY` | Signs policy / exceptions / baseline (>=32 bytes) |
| `SECURITY_REQUIRE_SIGNED_EXCEPTIONS` | Fail closed on any unsigned exceptions file |
| `SECURITY_REQUIRE_AGENT_ATTESTATION` | Fail closed unless the agent run is signed + enforced + clean (see below) |
| `SECURITY_ALLOW_UNSIGNED_HIGH_SUPPRESSION` | Break-glass: allow unsigned HIGH/CRITICAL suppression |
| `SECURITY_ATTEST_ALLOW_INCOMPLETE` | Break-glass: attest without a complete PASS |
| `SECURITY_ATTEST_KEY` | Signs attestation files |
| `SECURITY_AUDIT_HMAC_KEY` | Signs the routing audit log and the per-agent attestation chain |

### Observability

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECURITY_TOOL_AUDIT_LOG` | `.mcp/audit/tool-calls.jsonl` | Path for the per-tool-call structured audit log; point at an append-only / write-once sink for tamper-proof retention |

### Privacy and air-gap

| Variable | Purpose |
| --- | --- |
| `SECURITY_OFFLINE` | Disable all third-party network egress |

### MCP channel

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECURITY_MCP_SHARED_SECRET` | (none) | Require caller auth on the MCP channel |
| `SECURITY_SESSION_TTL_MS` | 8h | Session lifetime, capped at 24h |

### Remediation

| Variable | Purpose |
| --- | --- |
| `SECURITY_AGENTIC_QUARANTINE` | Handling for poisoned agent files: `strip`, `sanitize`, `quarantine`, or `off` |

### Integrations

| Variable | Purpose |
| --- | --- |
| `SECURITY_SLACK_WEBHOOK` | Post gate results to Slack |
| `SECURITY_JIRA_URL` | Create Jira tickets for failures |
| `SECURITY_JIRA_TOKEN` | Jira API token (never logged) |
| `SECURITY_JIRA_PROJECT` | Jira project key (default `SECURITY`) |
| `SECURITY_PAGERDUTY_KEY` | Page on-call for CRITICAL findings |
| `SECURITY_WEBHOOK_URL` | POST gate results as JSON to any URL |

### Live scanning

| Variable | Purpose |
| --- | --- |
| `SECURITY_STAGING_URL` | Enable runtime + Nuclei DAST against staging |
| `SECURITY_AI_ENDPOINT` | Enable live AI red-team probes |
| `SECURITY_AUTO_SBOM` | Auto-generate a CycloneDX SBOM each run |

---

## The 10 non-negotiable rules

No matter what the AI is asked to build, these hold:

1. No `0.0.0.0/0` firewall rules. Ingress and egress are source-restricted.
2. Internal services live on a private VPC only, never on public IPs.
3. Secrets live in a secret manager only, never in code, `.env`, CI logs, or images.
4. TLS 1.3 for everything in transit. TLS 1.0 and 1.1 are blocked.
5. Passwords hashed with Argon2id, or bcrypt at cost 14 or higher.
6. Every API input validated server-side with a schema.
7. No inline JavaScript. Content Security Policy is nonce-based only.
8. Admin interfaces require FIDO2/WebAuthn.
9. Threat-model before any auth, payment, or AI feature.
10. Zero Trust: every request authenticated and authorized regardless of origin.

---

## CLI reference

The `security-mcp` binary exposes:

| Command | Purpose |
| --- | --- |
| `serve` | Run the MCP server |
| `install` | Install for auto-detected editors |
| `install-global` | Install globally |
| `config` | Manage configuration |
| `doctor` (alias `verify`) | Health check |
| `autoharden` | Auto-remediate Terraform (`--dry-run` to preview) |
| `ci:pr-gate` | Run the gate in CI (non-zero exit on HIGH/CRITICAL) |
| `sign-policy` | HMAC-sign the active policy |

---

## Documentation and disclosure

- **Deep-dive docs:** the [GitHub Wiki](https://github.com/AbrahamOO/security-mcp/wiki).
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md).
- **Reporting a vulnerability in security-mcp itself:** see [SECURITY.md](SECURITY.md), which uses GitHub private security advisories for responsible disclosure.

---

## License

[MIT](LICENSE)

---

## Change History

- 2026-07-17 — Added the "Strict mode" environment-variable section documenting
  `SECURITY_STRICT=1` (Track C): a single switch that requires both HMAC keys plus
  the MCP shared secret and forces offline mode, refusing to start if any
  required key is missing rather than silently falling back to a weaker default.
- 2026-07-17 — Remediation-template count updated from 888 to 900: added 12
  `EVAL_UNAVAILABLE_*` findings (Track E, the fail-open/evaluability sweep) and a
  matching template for each, keeping the "100% detection-ID coverage" claim exact.
- 2026-07-17 — Corrected the SKILL.md-coverage tool description (was "§0-§24", a
  nonexistent range; now "§1-§24 plus the 4 universal sections, 28 total") and the
  audit-chain integrity claim (was an unconditional "cannot be silently rewritten"; now
  scoped to when `SECURITY_AUDIT_HMAC_KEY` is set, since the unsigned hash-only chain
  detects accidental edits but not a deliberate rewrite by anyone with file access).
  Added as part of building the claims registry (Track A).
- 2026-07-16 — Added `security.fortify` (one-shot, auto-apply, natural-language-scoped hardening) and the `fortify` MCP prompt; documented in a new "One-shot fortify" section. `security.start_review` now defaults to `remediationMode: "auto_apply"` instead of asking first (`detection_only` is an explicit opt-out). Updated the tools table and namespace counts. Collapsed the six stacked "What's new" sections into a single one for the current release; release history now lives only in the CHANGELOG.
- 2026-07-14 — Multi-client parity: corrected manual-config paths/keys (VS Code `.vscode/mcp.json` with `servers`, Windsurf `~/.codeium/windsurf/mcp_config.json`, added Codex TOML and the Replit remote-only note); added the "Runs on every client, at full capability" section describing MCP-native agent delivery (prompts, `skill://` resources, `ensure_skill`).
- 2026-07-07 — Added the "What's new in 1.3.5" section: pre-release checklist synced with the detection engine (8 new sections, 246 items) and the note that internal milestones 1.4.0–1.6.1 ship publicly in 1.3.5.
- 2026-07-07 — Tightened the 1.4.0 self-hardening note to an outcome statement (removed internal review-process mechanics), keeping the residual-risk disclosure pointer.
- 2026-07-06 — Added the "MCP security & governance / safe to use" section (self trust model, tamper-evident policy, fail-safe, egress control, no-shell exec, self-scan).
- 2026-07-06 — Added the "What's new in 1.6.1" section: the always-on `web-hardening` module (six new `WEB_` rules) and the remediation map reaching 888 templates / 100% (887/887) detection-ID coverage.
