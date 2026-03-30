# security-mcp — Your AI's Built-In Security Expert

[![npm version](https://img.shields.io/npm/v/security-mcp.svg)](https://www.npmjs.com/package/security-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![CI](https://github.com/AbrahamOO/security-mcp/actions/workflows/security-gate.yml/badge.svg)](https://github.com/AbrahamOO/security-mcp/actions)

**Stop shipping vulnerable code.** security-mcp gives your AI assistant the knowledge and tools of an elite security team — actively finding and fixing vulnerabilities, not just listing them.

Works with Claude Code, GitHub Copilot, Cursor, Codex, Replit, and any MCP-compatible editor.

---

## Who Is This For?

You don't need a security background to use this. It's built for:

- **Vibe coders** building fast and shipping faster — who need security to just work
- **Indie hackers and solo founders** who can't afford a dedicated security team
- **Full-stack developers** who know their code works but aren't sure if it's safe
- **Startups and small teams** shipping web apps, mobile apps, APIs, and SaaS products
- **AI-assisted developers** using Claude Code, Copilot, Cursor, or Codex to write code
- **Anyone who's ever shipped code and wondered "wait, is this secure?"**

---

## Two Modes — Pick Your Depth

| | `/senior-security-engineer` | `/ciso-orchestrator` |
| --- | --- | --- |
| **What it is** | Single expert agent | 40-agent parallel security program |
| **Best for** | Daily development, PR reviews, targeted hardening | Pre-launch audit, compliance prep, incident response |
| **Time** | Seconds to minutes | Minutes to hours |
| **Scope** | You choose: recent changes, full codebase, specific files | Always full — every surface, every framework |
| **Agents** | 1 | 40 (9 leads + 30 specialists) |
| **Output** | Inline code fixes + attestation | Full findings reports per domain + merged report + attestation |
| **API cost** | Low | High |
| **Internet** | Not required | Optional (enriches findings with live CVEs, CISA KEV, MITRE ATT&CK) |

**Use `/senior-security-engineer` daily.** Use `/ciso-orchestrator` for major milestones.

---

## Quick Start

```bash
npx -y security-mcp@latest install
```

Restart your editor. Then in Claude Code:

```text
/senior-security-engineer
```

The engineer will ask you how to scope the review, then find and fix security issues.

For a full 40-agent security audit:

```text
/ciso-orchestrator
```

---

## Architecture

### System Overview

```text
┌─────────────────────────────────────────────────────────────────────┐
│                        Your Editor (Claude Code)                    │
│                                                                     │
│   /senior-security-engineer          /ciso-orchestrator             │
│   (single expert agent)              (40-agent security program)    │
│           │                                    │                    │
└───────────┼────────────────────────────────────┼────────────────────┘
            │                                    │
            └──────────────┬─────────────────────┘
                           │  calls tools
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    MCP Server  (stdio process)                       │
│                    src/mcp/server.ts                                 │
│                                                                      │
│  security.*  tools          orchestration.*  tools                  │
│  ─────────────────          ───────────────────────                 │
│  start_review               create_agent_run                        │
│  run_pr_gate                update_agent_status                     │
│  threat_model               merge_agent_findings                    │
│  checklist                  ensure_skill                            │
│  attest_review              read/write_agent_memory                 │
│  get_system_prompt          check_updates                           │
│  scan_strategy              apply_updates                           │
│  generate_policy            verify_skill_coverage                   │
│  terraform_blueprint                                                │
│  generate_opa_rego          repo.*  tools                          │
│                             ──────────────                          │
│                             read_file / search                      │
└──────────────────────────────────────────────────────────────────────┘
            │
            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Policy Gate Engine                                │
│                    src/gate/policy.ts                                │
│                                                                      │
│  18 checks run in parallel:                                          │
│  checkSecrets    checkDependencies   checkApi      checkInfra        │
│  checkCrypto     checkMobileIos      checkMobileAndroid              │
│  checkAi         checkGraphQL        checkKubernetes                 │
│  checkDatabase   checkDlp            checkWebNextjs                  │
│  runSbomChecks   runAiRedteamChecks  runRuntimeChecks  ...          │
│                                                                      │
│  Surface detection → Control catalog → Exception handling →          │
│  Confidence scoring → PASS / FAIL                                    │
└──────────────────────────────────────────────────────────────────────┘
```

---

### `/senior-security-engineer` Flow

```text
User: /senior-security-engineer
         │
         ▼
  Claude reads SKILL.md
  Presents scope choice to user:
    A) Recent changes
    B) Full codebase
    C) Specific files/folders
         │
         ▼  (user picks A/B/C)
  security.start_review(mode)
    └── creates .mcp/reviews/{runId}.json
         │
         ▼
  security.scan_strategy(runId, mode)
    └── builds exhaustive scan plan
         │
         ▼
  security.run_pr_gate(runId, mode, targets)
    └── git diff / glob targets
    └── detectSurfaces()  →  web? api? infra? mobile? ai?
    └── 18 checks in parallel
    └── apply exceptions
    └── compute confidence score
    └── returns PASS/FAIL + findings[]
         │
         ▼
  Claude fixes every finding inline
  (writes production-ready secure code)
         │
         ▼
  security.attest_review(runId)
    └── .mcp/reports/{runId}.attestation.json
    └── SHA-256 integrity hash
```

---

### `/ciso-orchestrator` Flow (40 Agents)

```text
User: /ciso-orchestrator
         │
         ▼
  CISO Orchestrator reads SKILL.md
  ├── check_updates()          →  notify user if new version available
  ├── ask internet permission  →  stored for all child agents
  ├── scan project stack       →  stackContext object
  │     (package.json, go.mod, terraform, docker, .github/workflows)
  ├── security.start_review()  →  runId
  ├── orchestration.create_agent_run()  →  agentRunId + manifest.json
  └── orchestration.ensure_skill(×39)  →  download from GitHub if missing
         │
         ▼
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 1 — 7 LEAD AGENTS + 30 SUB-AGENTS  (all parallel)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Agent 1: threat-modeler
  ├── 1a stride-pasta-analyst       →  STRIDE matrix, PASTA stages, LINDDUN
  ├── 1b attack-navigator           →  ATT&CK Navigator layer, D3FEND countermeasures
  ├── 1c business-logic-attacker    →  attack trees per business flow
  └── 1d privacy-flow-analyst       →  GDPR/HIPAA data flows, DPIA triggers
  Output: threat-model.json

Agent 2: appsec-code-auditor
  ├── 2a injection-specialist       →  SQL, NoSQL, SSTI, OS cmd, path traversal
  ├── 2b auth-session-hacker        →  JWT, OAuth, SAML, session fixation
  ├── 2c logic-race-fuzzer          →  race conditions, double-spend, mass assignment
  └── 2d serialization-memory-attacker → prototype pollution, ReDoS, zip slip
  Output: appsec-findings.json

Agent 3: cloud-infra-specialist
  ├── 3a aws-penetration-tester     →  IAM escalation, S3, Lambda, EKS  (if AWS)
  ├── 3b gcp-penetration-tester     →  SA abuse, GCS, Cloud Run, GKE    (if GCP)
  ├── 3c azure-penetration-tester   →  Managed Identity, Key Vault, AKS (if Azure)
  └── 3d k8s-container-escaper      →  privileged pods, RBAC, hostPath   (if K8s)
  Output: infra-findings.json

Agent 4: supply-chain-devsecops
  ├── 4a dependency-confusion-attacker → CVEs, CISA KEV, typosquatting, SBOM
  ├── 4b cicd-pipeline-hijacker     →  PR_TARGET misuse, mutable Actions, injection
  └── 4c artifact-integrity-analyst →  SLSA L3, Cosign, provenance, SBOM
  Output: supply-chain-findings.json + sbom.cyclonedx.json

Agent 5: ai-llm-redteam            (skipped if no AI detected)
  ├── 5a prompt-injection-specialist →  direct + indirect injection, PoC payloads
  ├── 5b model-extraction-attacker  →  API abuse, cost amplification, rate limiting
  ├── 5c rag-poisoning-specialist   →  vector store isolation, metadata filter injection
  └── 5d agentic-loop-exploiter     →  tool blast radius, loop hijacking
  Output: ai-findings.json

Agent 6: mobile-security-specialist (skipped if no mobile detected)
  ├── 6a ios-security-auditor       →  Keychain, ATS, Secure Enclave, Universal Links
  ├── 6b android-penetration-tester →  manifest, NSC, exported components, StrongBox
  └── 6c mobile-api-network-attacker → cert pinning, hardcoded keys, GraphQL exposure
  Output: mobile-findings.json

Agent 7: crypto-pki-specialist
  ├── 9a tls-certificate-auditor    →  TLS 1.3, AEAD ciphers, HSTS, OCSP, mTLS
  ├── 9b algorithm-implementation-reviewer → banned algos, Argon2id params, nonce reuse
  └── 9c key-management-lifecycle-analyst  → hardcoded keys, rotation, CMEK, post-quantum
  Output: crypto-findings.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                Wait for all Phase 1 agents
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PHASE 2 — ADVERSARIAL + COMPLIANCE  (both parallel)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Agent 8: pentest-team
  (reads threat-model.json as attack brief)
  ├── 7a pentest-web-api            →  OWASP Testing Guide on every endpoint
  ├── 7b pentest-infra              →  privilege escalation graph, Terraform state
  └── 7c pentest-social             →  OSINT, spear-phishing scenarios, insider threat
  Output: pentest-report.json

Agent 9: compliance-grc
  (reads all Phase 1 findings)
  ├── 8a evidence-collector         →  logging schema, SIEM rules, audit trail
  └── 8b compliance-gap-analyst     →  PCI DSS 4.0, SOC 2, ISO 27001, NIST, HIPAA, GDPR
  Output: compliance-report.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                Wait for Phase 2 agents
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PHASE 3 — SYNTHESIS  (sequential)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  merge_agent_findings()     →  deduplicate, sort CRITICAL→LOW
  verify_skill_coverage()    →  check §1–§24 SKILL.md coverage
  security.attest_review()   →  SHA-256 attestation

  Present final report:
  ├── 9 agents ran, all completed
  ├── Findings: X CRITICAL / X HIGH / X MEDIUM / X LOW
  ├── Remediated: X  Open: X
  ├── SKILL.md coverage: XX%
  ├── Release blocked: yes/no
  └── Attestation: .mcp/reports/{runId}.attestation.json
```

---

### Agent Memory System

Every agent learns from each run and improves over time:

```
~/.security-mcp/agent-memory/{agentName}/
  ├── patterns.json        ← confirmed attack patterns for this tech stack
  ├── false-positives.json ← findings to deprioritize next run
  ├── remediations.json    ← what fixes worked for this project
  └── intel.json           ← cached threat intel (24h TTL)
```

---

### Data Persistence

```
Project directory:
.mcp/
├── reviews/{runId}.json              ← review run state + step tracking
├── reports/{runId}.attestation.json  ← SHA-256 auditable attestation
├── agent-runs/{agentRunId}/
│   ├── manifest.json                 ← all 39 agent statuses + phase
│   ├── threat-model.json
│   ├── appsec-findings.json
│   ├── infra-findings.json
│   ├── supply-chain-findings.json
│   ├── ai-findings.json
│   ├── mobile-findings.json
│   ├── crypto-findings.json
│   ├── pentest-report.json
│   ├── compliance-report.json
│   ├── sbom.cyclonedx.json
│   └── merged-findings.json          ← Phase 3 deduplicated output
├── policies/security-policy.json
└── exceptions/security-exceptions.json
```

---

## Installation

```bash
npx -y security-mcp@latest install
```

Auto-detects your editor and writes the MCP config. Restart your editor — done.

Target a specific editor:

```bash
npx -y security-mcp@latest install --claude-code
npx -y security-mcp@latest install --cursor
npx -y security-mcp@latest install --vscode
```

Preview without writing anything:

```bash
npx -y security-mcp@latest install --dry-run
```

### Global Install

```bash
npm install -g security-mcp@latest
security-mcp install-global
```

---

## CI/CD Security Gate

Blocks insecure code from merging on every PR — no Claude, no agents, pure code execution:

```bash
npx -y security-mcp ci:pr-gate
```

Add to GitHub Actions:

```yaml
name: Security Gate

on:
  pull_request:
    branches: [main, master]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Block insecure code from merging
        run: npx -y security-mcp ci:pr-gate
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**What it blocks:**

- Hardcoded secrets or credentials
- Known vulnerable dependencies (CRITICAL/HIGH CVEs)
- Dangerous IaC (open firewall rules, world-readable storage, wildcard IAM)
- Auth gaps, SSRF, CSRF exposure
- AI/LLM output without validation bounds

**Note:** The CI gate runs independently of any Claude session. No agents are spawned. It calls the gate engine directly as a Node.js process.

---

## What Gets Fixed Automatically

When your AI has security-mcp active, it **writes the fix** — not a suggestion, not a comment:

### Secrets and Authentication

- Moves hardcoded secrets to environment variables / secret managers
- Implements proper JWT validation (signature, expiry, issuer, audience)
- Adds rate limiting and account lockout to auth endpoints
- Enforces MFA requirements and session timeout policies
- Implements Argon2id password hashing (not MD5, not SHA-1)

### Input Validation and Injection

- Adds server-side schema validation (Zod / Yup) to every API route
- Blocks SQL injection, XSS, command injection, path traversal, SSRF
- Sanitizes file uploads (validates magic bytes, strips filenames, scans for malware)
- Normalizes and validates all user inputs with allowlist rules

### Network and Cloud

- Removes `0.0.0.0/0` ingress rules and replaces with source-restricted rules
- Locks down world-readable S3/GCS/Azure Blob buckets
- Removes wildcard IAM permissions and replaces with least-privilege policies
- Enforces TLS 1.3 and rejects weak cipher suites

### Web Security

- Sets mandatory security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy)
- Removes inline JavaScript; enforces nonce-based CSP
- Fixes CORS configurations that allow `*` on authenticated endpoints
- Adds CSRF protection to all state-mutating endpoints

### AI / LLM Security

- Separates user content from system prompts (prevents prompt injection)
- Adds output schema validation so models can't return arbitrary dangerous content
- Enforces access control on RAG document retrieval
- Adds rate limiting specific to AI endpoints

---

## MCP Tools Reference

Your AI uses these automatically — you don't call them directly.

### Core Security Tools

| Tool | What It Does |
| --- | --- |
| `security.start_review` | Starts a stateful review run, returns `runId` for ordered execution and attestation |
| `security.run_pr_gate` | Runs 18 security checks in parallel; blocks on CRITICAL/HIGH findings |
| `security.threat_model` | Generates STRIDE + PASTA + ATT&CK threat model for any feature |
| `security.checklist` | Pre-release security checklist filtered by surface (web/api/mobile/ai/infra) |
| `security.scan_strategy` | Builds an exhaustive scan plan with framework coverage mapping |
| `security.get_system_prompt` | Returns the full security engineering directive |
| `security.generate_policy` | Generates `security-policy.json` tailored to your project |
| `security.terraform_hardening_blueprint` | Terraform hardening baseline (network, IAM, data, logging) |
| `security.generate_opa_rego` | OPA/Rego policy packs for Terraform, CI, Kubernetes admission |
| `security.self_heal_loop` | Proposes self-healing improvements (requires explicit human approval) |
| `security.attest_review` | Writes auditable attestation with SHA-256 integrity hash |
| `repo.read_file` | Reads project files for analysis |
| `repo.search` | Searches the codebase for vulnerable patterns |

### Orchestration Tools (used by `/ciso-orchestrator`)

| Tool | What It Does |
| --- | --- |
| `orchestration.create_agent_run` | Initialises the 39-agent manifest + run directory |
| `orchestration.update_agent_status` | Agents report start/completion; auto-advances phase |
| `orchestration.merge_agent_findings` | Deduplicates + sorts findings from all agents |
| `orchestration.ensure_skill` | Downloads a skill from GitHub if not cached locally |
| `orchestration.read_agent_memory` | Loads agent's prior patterns and false-positives |
| `orchestration.write_agent_memory` | Persists learned patterns and remediations |
| `orchestration.check_updates` | Checks npm + skills manifest for new versions |
| `orchestration.apply_updates` | Runs auto-update or prints manual update commands |
| `orchestration.verify_skill_coverage` | Reports which SKILL.md §1–§24 sections had no coverage |

---

## Supported Editors

| Editor | Install Command | Config Location |
| --- | --- | --- |
| Claude Code | `npx -y security-mcp@latest install --claude-code` | `~/.claude/settings.json` |
| Claude Code (global binary) | `security-mcp install-global --claude-code` | `~/.claude/settings.json` |
| Cursor | `npx -y security-mcp@latest install --cursor` | `~/.cursor/mcp.json` |
| Cursor (global binary) | `security-mcp install-global --cursor` | `~/.cursor/mcp.json` |
| VS Code | `npx -y security-mcp@latest install --vscode` | User `settings.json` |
| VS Code (global binary) | `security-mcp install-global --vscode` | User `settings.json` |
| GitHub Copilot | Manual config (see below) | `.vscode/settings.json` |
| Codex | Manual config (see below) | Editor config |
| Replit | Manual config (see below) | `.replit` config |
| Any MCP-compatible | `npx -y security-mcp@latest config` | Paste into editor config |

### Manual Configuration

**Claude Code** (`~/.claude/settings.json`):

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

**Cursor** (`~/.cursor/mcp.json`):

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

**VS Code / GitHub Copilot** (`settings.json`):

```json
{
  "mcp.servers": {
    "security-mcp": {
      "command": "npx",
      "args": ["-y", "security-mcp@latest", "serve"]
    }
  }
}
```

---

## Security Policy and Exceptions

Copy the default policy into your project:

```bash
cp node_modules/security-mcp/defaults/security-policy.json .mcp/policies/security-policy.json
cp node_modules/security-mcp/defaults/control-catalog.json .mcp/catalog/control-catalog.json
cp node_modules/security-mcp/defaults/security-exceptions.json .mcp/exceptions/security-exceptions.json
```

Or generate one tailored to your project:

```text
Ask your AI: "Run security.generate_policy with surfaces=[web, api, ai] and cloud=aws"
```

---

## Security Frameworks Applied

You don't need to know what these are. They're the standards that the world's top security teams use. security-mcp applies all of them automatically:

- **OWASP Top 10** (Web + API) — most common attack patterns
- **OWASP ASVS Level 2/3** — application security verification
- **OWASP MASVS** — mobile app security
- **OWASP Top 10 for LLMs** — AI-specific vulnerabilities
- **MITRE ATT&CK** (Enterprise, Cloud, Mobile) — real attacker playbooks
- **MITRE D3FEND** — defensive countermeasures mapped to every attack
- **MITRE ATLAS** — adversarial ML/AI attack techniques
- **NIST 800-53 Rev 5** — US government security control catalog
- **NIST 800-207** — Zero Trust Architecture
- **NIST AI RMF** — AI risk management
- **PCI DSS 4.0** — payment card security
- **SOC 2 Type II** — cloud service security
- **ISO 27001:2022** — international security management
- **GDPR / CCPA / HIPAA** — data privacy compliance
- **SLSA Level 3** — software supply chain security
- **CIS Benchmarks Level 2** — hardened cloud and container configurations
- **CVSS v4.0 + EPSS** — vulnerability scoring and exploit probability

---

## Environment Variables

### CI / Gate

| Variable | Default | What it does |
| --- | --- | --- |
| `GITHUB_TOKEN` | set by GitHub Actions | Authenticates git operations in CI |
| `SECURITY_GATE_BASE_REF` | `origin/main` | Branch to compare against |
| `SECURITY_GATE_HEAD_REF` | `HEAD` | Branch being scanned |
| `SECURITY_GATE_POLICY` | `.mcp/policies/security-policy.json` | Custom policy file path |

### Integrations (all optional)

| Variable | What it does |
| --- | --- |
| `SECURITY_SLACK_WEBHOOK` | Sends findings to a Slack channel |
| `SECURITY_JIRA_URL` | Creates Jira tickets for findings |
| `SECURITY_JIRA_TOKEN` | Jira API token |
| `SECURITY_JIRA_PROJECT` | Jira project key (default: `SECURITY`) |
| `SECURITY_PAGERDUTY_KEY` | Pages on-call for CRITICAL findings |
| `SECURITY_WEBHOOK_URL` | Sends findings as JSON POST to any URL |

### Scanning

| Variable | What it does |
| --- | --- |
| `SECURITY_STAGING_URL` | URL of staging environment — enables live runtime checks |
| `SECURITY_AUTO_SBOM` | Set `true` to auto-generate SBOM on each gate run |
| `SECURITY_AI_ENDPOINT` | URL of AI endpoint — enables live red-team probing |

---

## The 10 Rules That Are Never Broken

No matter what your AI is asked to do, these are enforced without exception:

1. No `0.0.0.0/0` firewall rules — ever
2. All internal services talk over private VPC only
3. Secrets live in a secret manager only — never in code, env files, or logs
4. TLS 1.3 for everything in transit — 1.0 and 1.1 are blocked
5. Passwords hashed with Argon2id or bcrypt (cost 14+) — no MD5, no SHA-1
6. Every API input validated server-side with a schema — no exceptions
7. No inline JavaScript — CSP nonce-based only
8. Admin interfaces require FIDO2/WebAuthn passkey
9. Threat model written before building any auth, payment, or AI feature
10. Zero Trust: every request authenticated and authorized regardless of origin

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible Disclosure

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) — security-mcp contributors
