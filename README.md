# security-mcp - AI Security Engineer for Claude Code, Cursor, Copilot & Codex

[![npm version](https://img.shields.io/npm/v/security-mcp.svg)](https://www.npmjs.com/package/security-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![CI](https://github.com/AbrahamOO/security-mcp/actions/workflows/security-gate.yml/badge.svg)](https://github.com/AbrahamOO/security-mcp/actions)

**Stop shipping vulnerable code.**

**security-mcp** is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that gives your AI coding assistant the knowledge and tooling of a senior security engineer. Instead of just warning you about vulnerabilities, it **writes the secure code** - inline, immediately, every time.

Works with **Claude Code, GitHub Copilot, Cursor, Codex, Replit**, and any MCP-compatible editor.

> **One command to install. Zero security background required.**

---

## Table of Contents

- [What Problem Does This Solve?](#what-problem-does-this-solve)
- [Who Is This For?](#who-is-this-for)
- [Two Modes - Pick Your Depth](#two-modes--pick-your-depth)
- [Quick Start - Install in 60 Seconds](#quick-start--install-in-60-seconds)
- [Step-by-Step Installation Guide](#step-by-step-installation-guide)
  - [Claude Code](#step-by-step-claude-code)
  - [Cursor](#step-by-step-cursor)
  - [VS Code / GitHub Copilot](#step-by-step-vs-code--github-copilot)
  - [Manual Configuration](#manual-configuration-any-mcp-editor)
- [How to Run Your First Security Review](#how-to-run-your-first-security-review)
- [CI/CD Security Gate](#cicd-security-gate)
- [What Gets Fixed Automatically](#what-gets-fixed-automatically)
- [Architecture](#architecture)
- [MCP Tools Reference](#mcp-tools-reference)
- [Security Frameworks Applied](#security-frameworks-applied)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [The 10 Rules That Are Never Broken](#the-10-rules-that-are-never-broken)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## What Problem Does This Solve?

When you use an AI coding assistant to build features fast, security is easy to skip - not because you don't care, but because:

- Security is deep expertise that takes years to develop
- Most AI assistants write working code but don't enforce secure code
- Static analysis tools flag problems but don't fix them
- Hiring a security team or running a pentest is expensive and slow

**security-mcp closes that gap.** It integrates a security enforcement layer directly into your AI assistant. Every code change, every PR, every new feature gets reviewed against OWASP, MITRE ATT&CK, NIST, PCI DSS, and 16 other frameworks - and the AI writes the fix immediately.

**The result:** You ship faster AND more securely. No security background required.

---

## Who Is This For?

- **Vibe coders and solo founders** building fast who need security to just work without slowing them down
- **Full-stack developers** who know their code works but aren't sure if it's safe
- **Startups and small teams** shipping web apps, mobile apps, APIs, and SaaS products
- **AI-assisted developers** using Claude Code, Copilot, Cursor, or Codex to write most of their code
- **Teams preparing for SOC 2, PCI DSS, or ISO 27001 audits** who need evidence and gap analysis
- **Security-conscious engineers** who want systematic coverage, not ad-hoc reviews
- **Anyone who's shipped code and thought "wait, is this actually secure?"**

---

## Two Modes - Pick Your Depth

### `/senior-security-engineer` - Your Daily Security Expert

A single elite security engineer agent that reviews your code, finds vulnerabilities, and writes the fix immediately. You choose the scope: just your recent changes, your whole codebase, or specific files and folders. It covers secrets, dependencies, cryptography, injection, authentication, web headers, cloud config, AI/LLM safety, mobile, and more - all in parallel. Every finding gets an inline code fix, not a suggestion. Finishes with a SHA-256 attested report you can keep as an audit trail.

**Use this on every PR. Use it before you push. Use it when something feels off.**

### `/ciso-orchestrator` - A Full Security Program in One Command

40 specialist agents running in parallel across 3 phases: threat modeling, deep code and infrastructure attack simulation, then compliance synthesis. Every domain gets its own specialist - a dedicated injection attacker, a JWT/OAuth hacker, a cloud privilege escalation analyst, a prompt injection specialist, a TLS auditor, a pentest team that reads the threat model as its attack brief, and a compliance analyst that maps every finding to PCI DSS 4.0, SOC 2, ISO 27001, NIST 800-53, HIPAA, and GDPR. Agents learn from each run and improve over time. Optionally fetches live CVE, CISA KEV, and ATT&CK data. Produces a merged findings report with full compliance mapping and a signed attestation.

**Use this before major releases, compliance audits, or security reviews. -> [See the full 40-agent architecture](#ciso-orchestrator-flow-40-agents)**

---

| | `/senior-security-engineer` | `/ciso-orchestrator` |
| --- | --- | --- |
| **What it is** | Single expert agent | 40-agent parallel security program |
| **Best for** | Daily development, PR reviews, targeted hardening | Pre-launch audits, compliance prep, incident response |
| **Speed** | Seconds to minutes | Minutes to hours |
| **Scope** | You choose: recent changes, full codebase, or specific files | Always full - every surface, every framework |
| **Agents** | 1 | 40 (9 leads + 30 specialists) |
| **Output** | Inline code fixes + SHA-256 attestation | Full domain reports + merged findings + attestation |
| **API cost** | Low | High |
| **Internet** | Not required | Optional (enriches findings with live CVEs, CISA KEV, MITRE ATT&CK) |

**Rule of thumb:** Use `/senior-security-engineer` on every PR. Use `/ciso-orchestrator` before major releases or compliance deadlines.

---

## Quick Start - Install in 60 Seconds

```bash
npx -y security-mcp@latest install
```

Restart your editor. Then in Claude Code:

```text
/senior-security-engineer
```

That's it. The engineer will ask how you want to scope the review, then find and fix security issues in your code.

For a full 40-agent deep audit:

```text
/ciso-orchestrator
```

---

## Step-by-Step Installation Guide

### Step-by-Step: Claude Code

**Prerequisite:** Node.js 20+ installed. Check with `node --version`.

**Step 1 - Run the installer:**

```bash
npx -y security-mcp@latest install --claude-code
```

This writes the MCP server config to `~/.claude/settings.json`.

**Step 2 - Verify the config was written:**

```bash
cat ~/.claude/settings.json
```

You should see:

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

**Step 3 - Restart Claude Code** to pick up the new MCP server.

**Step 4 - Verify the tools loaded.** In Claude Code, run:

```text
/mcp
```

You should see `security-mcp` listed as a connected server with `security.*`, `orchestration.*`, and `repo.*` tools available.

**Step 5 - Run your first security review:**

```text
/senior-security-engineer
```

The agent will ask:

- **A) Recent changes** - scans only what changed since your last commit (fastest, use daily)
- **B) Full codebase** - scans everything (use for new projects or after major changes)
- **C) Specific files or folders** - scans exactly what you specify

Pick one and let it run.

---

### Step-by-Step: Cursor

**Step 1 - Run the installer:**

```bash
npx -y security-mcp@latest install --cursor
```

This writes to `~/.cursor/mcp.json`.

**Step 2 - Verify:**

```bash
cat ~/.cursor/mcp.json
```

Expected output:

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

**Step 3 - Restart Cursor.**

**Step 4 - Open Cursor's MCP panel** (Settings -> MCP) and confirm `security-mcp` shows as connected.

**Step 5 - In the Cursor AI chat, type:**

```text
Use /senior-security-engineer to review my recent changes
```

---

### Step-by-Step: VS Code / GitHub Copilot

**Step 1 - Run the installer:**

```bash
npx -y security-mcp@latest install --vscode
```

This writes to your VS Code user `settings.json`.

**Step 2 - Verify in VS Code:**

Open Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`) -> `Preferences: Open User Settings (JSON)`.

You should see:

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

**Step 3 - Restart VS Code.**

**Step 4 - In GitHub Copilot Chat, type:**

```text
@security-mcp run /senior-security-engineer on recent changes
```

---

### Manual Configuration (Any MCP Editor)

If the installer doesn't detect your editor, or you prefer to configure manually:

**Step 1 - Print the config snippet:**

```bash
npx -y security-mcp@latest config
```

**Step 2 - Copy the output** and paste it into your editor's MCP configuration file.

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

**Windsurf / Codex / Replit** - use the same `command`/`args` format your editor supports for MCP servers.

**Step 3 - Restart your editor** after saving the config.

---

### Global Install (Optional)

If you want the `security-mcp` binary available system-wide without `npx`:

```bash
npm install -g security-mcp@latest
security-mcp install-global
```

Then you can use:

```bash
security-mcp install-global --claude-code
security-mcp install-global --cursor
security-mcp install-global --vscode
```

---

### Preview Without Writing Anything

To see what the installer would do without making any changes:

```bash
npx -y security-mcp@latest install --dry-run
```

---

## How to Run Your First Security Review

### Daily Workflow: `/senior-security-engineer`

**Step 1 - Open your project in your editor.**

**Step 2 - Invoke the skill:**

```text
/senior-security-engineer
```

**Step 3 - Choose your scan scope when prompted:**

- **Recent changes** - scans only files modified since your last commit. Use this on every PR.
- **Full codebase** - scans all source files. Use when onboarding a new project.
- **Specific folders** - you name the folders. Use when you know the blast radius.

**Step 4 - Watch it work.** The agent will:

1. Call `security.start_review` to create a tracked run
2. Build a scan plan covering all relevant OWASP/NIST/ATT&CK controls
3. Run 18 security checks in parallel across secrets, dependencies, crypto, auth, injection, cloud config, AI/LLM, mobile, and more
4. Write fixes directly into your code for every finding it can remediate
5. Generate a SHA-256 attested report at `.mcp/reports/{runId}.attestation.json`

**Step 5 - Review the output.** Each finding shows:

- What the vulnerability is and why it matters
- Which attack it enables (mapped to MITRE ATT&CK and CWE)
- The exact fix that was applied to your code

**Step 6 - Commit with confidence.** The attestation file is your audit trail.

---

### Deep Audit: `/ciso-orchestrator`

Use this before a major release, compliance deadline, or security review.

**Step 1 - Invoke:**

```text
/ciso-orchestrator
```

**Step 2 - Answer the internet permission prompt.**

The orchestrator will ask:

> "I can fetch live CVE data, CISA KEV, and MITRE ATT&CK updates to improve this analysis. Allow internet access for this run? (yes/no)"

- **Yes** - agents enrich findings with live threat intelligence. More accurate, more current.
- **No** - agents use cached intel. Still comprehensive, no external calls made.

**Step 3 - Wait for Phase 1 (7 lead agents + 30 sub-agents, all parallel).**

Each agent writes findings to `.mcp/agent-runs/{agentRunId}/`.

**Step 4 - Wait for Phase 2 (pentest team + compliance synthesizer).**

The pentest team reads Phase 1's threat model as its attack brief. The compliance agent maps every finding to PCI DSS 4.0, SOC 2, ISO 27001, NIST 800-53, HIPAA, and GDPR controls.

**Step 5 - Review the merged report.**

The orchestrator presents:

```text
Agents: 9 leads completed (+ sub-agents)
Findings: X CRITICAL / X HIGH / X MEDIUM / X LOW
Remediated inline: X
Open (need your decision): X
SKILL.md coverage: XX% (§1-§24)
Release blocked: yes / no
Attestation: .mcp/reports/{runId}.attestation.json
```

**Step 6 - For any open findings**, follow the required actions in the report. The agent will help you implement each fix.

---

## CI/CD Security Gate

Block insecure code from merging on every pull request - no Claude session required, pure Node.js execution:

```bash
npx -y security-mcp ci:pr-gate
```

### Add to GitHub Actions

Create `.github/workflows/security-gate.yml`:

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
          fetch-depth: 0        # required for git diff to work

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Block insecure code from merging
        run: npx -y security-mcp ci:pr-gate
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### What the CI Gate Checks

The gate runs **18 checks in parallel** against your diff:

| Category | What It Catches |
| --- | --- |
| **Secrets** | Hardcoded API keys, tokens, passwords, private keys (via Gitleaks patterns) |
| **Dependencies** | CRITICAL/HIGH CVEs in npm/pip/go/maven packages; CISA KEV cross-check and EPSS >50% auto-escalation via live threat-intel (24h cached) |
| **Cryptography** | MD5, SHA-1, DES, RC4, ECB mode, `Math.random()` for tokens, short JWT secrets |
| **Authentication** | Missing rate limiting, no account lockout, JWT `alg:none`, weak session config |
| **Injection** | SQL, NoSQL, command injection, path traversal, SSRF, prototype pollution |
| **Web headers** | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **IaC** | `0.0.0.0/0` firewall rules, public storage buckets, wildcard IAM permissions |
| **AI/LLM** | `eval()` on model output, unvalidated model responses, prompt injection patterns |
| **Database** | TLS disabled on connections, raw query concatenation, missing connection encryption |
| **Mobile** | `android:debuggable=true`, cleartext traffic, insecure ATS config |
| **GraphQL** | Introspection in production, no depth/complexity limits, batching abuse |
| **Kubernetes** | Privileged containers, missing security context, hostPath mounts |
| **DLP** | PII in logs, stack traces in API responses, sensitive data in error messages |
| **Supply chain** | Missing lockfiles, floating version ranges (`^`, `~`), abandoned packages |
| **SBOM** | Generates CycloneDX SBOM for the scanned surface |
| **Runtime** | HTTP security headers and TLS config on live staging URL (if configured) |
| **AI red-team** | Static + optional dynamic probes against AI endpoints |
| **Exceptions** | Validates any active security exceptions are non-expired and properly approved |
| **Baseline regression** | Detects when previously-satisfied controls go missing (BASELINE_REGRESSION HIGH finding injected on regression) |

### Customize the Gate Policy

Copy the default policy into your project and edit:

```bash
mkdir -p .mcp/policies
cp node_modules/security-mcp/defaults/security-policy.json .mcp/policies/security-policy.json
```

Or generate one tailored to your stack:

```text
Ask your AI: "Run security.generate_policy with surfaces=[web, api, ai] and cloud=aws"
```

### Add Exceptions for Known Accepted Risks

Copy and edit the exceptions file:

```bash
mkdir -p .mcp/exceptions
cp node_modules/security-mcp/defaults/security-exceptions.json .mcp/exceptions/security-exceptions.json
```

Format:

```json
{
  "version": "1.0.0",
  "exceptions": [
    {
      "id": "EX-001",
      "finding_ids": ["CRYPTO_WEAK_HASH"],
      "justification": "Legacy hash used only for non-security cache keys",
      "ticket": "JIRA-1234",
      "owner": "alice@example.com",
      "approver": "bob@example.com",
      "approval_role": "SecurityLead",
      "expires_on": "2025-12-31"
    }
  ]
}
```

Expired exceptions automatically become CRITICAL findings that block the gate.

---

## What Gets Fixed Automatically

When your AI has security-mcp active, it **writes the production-ready fix** - not a suggestion, not a warning comment:

### Secrets and Credentials

| Insecure | Fixed to |
| --- | --- |
| `const KEY = "sk-abc123"` | `const KEY = process.env["API_KEY"]` + vault reference |
| `password: "hardcoded"` in config | Environment variable + secret manager setup |
| JWT signed with `"secret"` | RS256 with generated key pair, proper validation |
| Bcrypt with cost factor 4 | Argon2id with `memory: 65536, iterations: 3, parallelism: 4` |

### Authentication and Authorization

- Rate limiting middleware added to all auth endpoints (configurable thresholds)
- Account lockout after N failed attempts with progressive delays
- Session absolute timeout (8h) and idle timeout (30 min)
- FIDO2/WebAuthn requirement flagged for admin interfaces
- IDOR protection: tenant/user IDs read from JWT claims, never from request params

### Injection and Input Validation

- Zod/Yup schema validation added to every API route handler
- SQL: string concatenation -> parameterized queries or tagged template literals
- Command execution: `exec(userInput)` -> `spawnSync` with arg array, no shell
- Path traversal: user-controlled paths validated against project boundary
- SSRF: server-side HTTP clients get RFC-1918 CIDR block lists + DNS validation

### Web Security Headers

Before:

```javascript
app.get("/", (req, res) => res.send(html));
```

After:

```javascript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
    }
  },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  frameguard: { action: "deny" },
  noSniff: true,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));
```

### Cloud Infrastructure

- `cidr_blocks = ["0.0.0.0/0"]` -> source-restricted CIDR with comment explaining rationale
- `acl = "public-read"` S3 -> Block Public Access enabled at bucket and account level
- Wildcard IAM `"Action": "*"` -> least-privilege policy with specific actions
- Long-lived static credentials -> IAM roles / Workload Identity / OIDC federation

### Cryptography

- `crypto.createHash('md5')` -> `crypto.createHash('sha256')`
- `Math.random()` for tokens -> `crypto.randomBytes(32).toString('hex')`
- AES-CBC -> AES-256-GCM with per-message nonce
- RSA PKCS#1 v1.5 -> RSA-OAEP or ECDH P-256

### AI / LLM Security

- String-concatenated system prompts -> structured `messages` array with role separation
- `eval(modelOutput)` -> `JSON.parse()` + Zod schema validation
- RAG retrieval without auth check -> authorization check before and after retrieval
- Unvalidated tool calls -> allowlist router that blocks unlisted tool names

---

## Architecture

### System Overview

```text
┌───────────────────────────────────────────────────────────────┐
│                   Your Editor (Claude Code)                   │
│                                                               │
│  /senior-security-engineer      /ciso-orchestrator           │
│  (single expert agent)          (40-agent security program)  │
│          │                                │                   │
└──────────┼────────────────────────────────┼───────────────────┘
           │                                │
           └──────────────┬─────────────────┘
                          │  MCP protocol (stdio)
                          ▼
┌──────────────────────────────────────────────────────────────┐
│                  MCP Server  (src/mcp/server.ts)             │
│                                                              │
│  security.*  tools         orchestration.*  tools           │
│  ─────────────────         ──────────────────────           │
│  start_review              create_agent_run                 │
│  run_pr_gate               update_agent_status              │
│  threat_model              merge_agent_findings             │
│  checklist                 ensure_skill                     │
│  attest_review             read/write_agent_memory          │
│  get_system_prompt         check_updates / apply_updates    │
│  scan_strategy             verify_skill_coverage            │
│  generate_policy                                            │
│  terraform_blueprint       repo.*  tools                    │
│  generate_opa_rego         ─────────────                    │
│  generate_compliance_report  read_file / search             │
│  notify_webhooks                                            │
│  generate_remediations                                      │
└──────────────────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────┐
│               Policy Gate Engine  (src/gate/policy.ts)       │
│                                                              │
│  18 checks run in parallel:                                  │
│  checkSecrets    checkDependencies   checkApi    checkInfra  │
│  checkCrypto     checkMobileIos      checkMobileAndroid      │
│  checkAi         checkGraphQL        checkKubernetes         │
│  checkDatabase   checkDlp            checkWebNextjs          │
│  runSbomChecks   runAiRedteamChecks  runRuntimeChecks  ...  │
│                                                              │
│  Surface detection -> Control catalog -> Exception handling ->  │
│  Confidence scoring -> PASS / FAIL                           │
└──────────────────────────────────────────────────────────────┘
```

### `/senior-security-engineer` Flow

```text
User: /senior-security-engineer
        │
        ▼
  Claude reads SKILL.md + asks scope choice:
    A) Recent changes (git diff)
    B) Full codebase
    C) Specific files/folders
        │
        ▼  user picks scope
  security.start_review(mode)
    └── creates .mcp/reviews/{runId}.json
        │
        ▼
  security.threat_model(runId, feature)
    └── STRIDE + PASTA + ATT&CK template for changed surface
        │
        ▼
  security.run_pr_gate(runId, mode, targets)
    ├── git diff / glob targets -> changed files list
    ├── detectSurfaces()  ->  web? api? infra? mobile? ai?
    ├── 18 checks in parallel
    ├── apply exceptions from .mcp/exceptions/
    ├── compute confidence score
    └── returns PASS/FAIL + findings[]
        │
        ▼
  Claude writes inline fixes for every finding
  (production-ready secure code, not suggestions)
        │
        ▼
  security.attest_review(runId)
    └── .mcp/reports/{runId}.attestation.json
    └── SHA-256 integrity hash
```

### `/ciso-orchestrator` Flow (40 Agents)

```text
User: /ciso-orchestrator
        │
        ▼
  CISO Orchestrator
  ├── orchestration.check_updates()   -> prompt if new version available
  ├── ask internet permission          -> stored for all child agents
  ├── scan project for stack context
  │   (package.json, go.mod, terraform/, .github/workflows/, Dockerfile)
  │   -> stackContext: { languages, frameworks, cloudProvider, hasAI, hasMobile, ... }
  ├── security.start_review()          -> runId
  ├── orchestration.create_agent_run() -> agentRunId + manifest.json
  └── orchestration.ensure_skill(×39) -> download skills if not cached
        │
        ▼
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 1 - 7 leads + sub-agents  (all parallel)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Agent 1: threat-modeler
  ├── stride-pasta-analyst        -> STRIDE matrix, PASTA 7 stages, LINDDUN, DREAD
  ├── attack-navigator            -> ATT&CK Navigator layer + D3FEND countermeasures
  ├── business-logic-attacker     -> attack trees per route/flow found in codebase
  └── privacy-flow-analyst        -> GDPR/HIPAA data flows, DPIA trigger check
  Output: .mcp/agent-runs/{id}/threat-model.json

Agent 2: appsec-code-auditor
  ├── injection-specialist        -> SQL/NoSQL/SSTI/OS cmd/CRLF/log injection
  ├── auth-session-hacker         -> JWT algo confusion, SAML wrap, OAuth confusion
  ├── logic-race-fuzzer           -> race conditions, integer overflow, mass assignment
  └── serialization-memory-attacker -> prototype pollution, ReDoS, zip slip, sandbox escape
  Output: .mcp/agent-runs/{id}/appsec-findings.json

Agent 3: cloud-infra-specialist
  ├── aws-penetration-tester      -> IAM escalation, S3, Lambda, EKS    (if AWS)
  ├── gcp-penetration-tester      -> SA abuse, GCS, Cloud Run, GKE       (if GCP)
  ├── azure-penetration-tester    -> Managed Identity, AKS, Key Vault    (if Azure)
  └── k8s-container-escaper       -> privileged pods, RBAC escape, hostPath (if K8s)
  Output: .mcp/agent-runs/{id}/infra-findings.json

Agent 4: supply-chain-devsecops
  ├── dependency-confusion-attacker -> CVEs, CISA KEV, typosquatting, SBOM
  ├── cicd-pipeline-hijacker       -> pull_request_target, mutable Actions, injection
  └── artifact-integrity-analyst   -> SLSA L3, Cosign signatures, provenance
  Output: .mcp/agent-runs/{id}/supply-chain-findings.json

Agent 5: ai-llm-redteam            (skipped if no AI stack detected)
  ├── prompt-injection-specialist  -> direct + indirect injection, PoC payloads
  ├── model-extraction-attacker    -> API abuse, cost amplification, rate limiting
  ├── rag-poisoning-specialist     -> vector store isolation, metadata filter injection
  └── agentic-loop-exploiter       -> tool blast radius, loop hijacking, allowlist gaps
  Output: .mcp/agent-runs/{id}/ai-findings.json

Agent 6: mobile-security-specialist (skipped if no mobile detected)
  ├── ios-security-auditor         -> Keychain, ATS, Secure Enclave, Universal Links
  ├── android-penetration-tester   -> manifest hardening, NSC, exported components
  └── mobile-api-network-attacker  -> cert pinning, API key extraction, token storage
  Output: .mcp/agent-runs/{id}/mobile-findings.json

Agent 7: crypto-pki-specialist
  ├── tls-certificate-auditor      -> TLS 1.3, AEAD ciphers, HSTS preload, OCSP, mTLS
  ├── algorithm-implementation-reviewer -> banned algos, Argon2id params, nonce reuse
  └── key-management-lifecycle-analyst  -> hardcoded keys, rotation, CMEK, post-quantum
  Output: .mcp/agent-runs/{id}/crypto-findings.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     Wait for all Phase 1 agents to complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PHASE 2 - adversarial + compliance  (both parallel)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Agent 8: pentest-team  (reads threat-model.json as attack brief)
  ├── pentest-web-api   -> OWASP Testing Guide on every route found in codebase
  ├── pentest-infra     -> privilege escalation graph, Terraform state, cloud posture
  └── pentest-social    -> OSINT on org, spear-phishing scenarios, insider threat model
  Output: .mcp/agent-runs/{id}/pentest-report.json

Agent 9: compliance-grc  (reads all Phase 1 findings)
  ├── evidence-collector    -> logging schema verification, SIEM rules, audit trail
  └── compliance-gap-analyst -> PCI DSS 4.0, SOC 2, ISO 27001, NIST 800-53, HIPAA, GDPR
  Output: .mcp/agent-runs/{id}/compliance-report.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     Wait for Phase 2 agents to complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PHASE 3 - synthesis  (sequential)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  orchestration.merge_agent_findings()  -> deduplicate + sort CRITICAL->LOW
  orchestration.verify_skill_coverage() -> check §1-§24 SKILL.md section coverage
  security.attest_review()              -> SHA-256 attestation written

  Final report:
  ├── X CRITICAL / X HIGH / X MEDIUM / X LOW
  ├── Remediated inline: X    Open: X
  ├── SKILL.md section coverage: XX%
  ├── Release blocked: yes / no
  └── .mcp/reports/{runId}.attestation.json
```

### Agent Memory System

Every agent persists what it learns so each subsequent run is smarter:

```text
~/.security-mcp/agent-memory/{agentName}/
  ├── patterns.json         ← confirmed attack patterns for this tech stack
  ├── false-positives.json  ← findings to deprioritize on next run
  ├── remediations.json     ← what fixes worked for this project
  ├── intel.json            ← cached threat intel (refreshed every 24h)
  └── errors.json           ← tool failure log (used for self-healing)
```

### Data Written to Your Project

```text
.mcp/
├── reviews/{runId}.json                ← review run state + step tracking
├── reports/{runId}.attestation.json    ← SHA-256 auditable attestation
├── agent-runs/{agentRunId}/
│   ├── manifest.json                   ← all agent statuses + current phase
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
│   └── merged-findings.json            ← Phase 3 deduplicated, sorted output
├── policies/security-policy.json
└── exceptions/security-exceptions.json
```

---

## MCP Tools Reference

Your AI uses these automatically. You don't call them directly, but understanding what they do helps you know what's happening during a review.

### Core Security Tools

| Tool | What It Does |
| --- | --- |
| `security.start_review` | Starts a stateful review run; returns `runId` used to track all subsequent steps and produce the final attestation |
| `security.run_pr_gate` | Runs 18 security checks in parallel; returns PASS/FAIL, findings with severity, and required actions |
| `security.threat_model` | Generates a STRIDE + PASTA + ATT&CK threat model template for a specific feature or surface |
| `security.checklist` | Returns the pre-release security checklist, optionally filtered by surface (web / api / mobile / ai / infra / payments) |
| `security.scan_strategy` | Builds an exhaustive scan plan mapping every check to OWASP, NIST, ATT&CK, and compliance controls |
| `security.get_system_prompt` | Returns the full security engineering directive, optionally scoped to your stack and cloud provider |
| `security.generate_policy` | Generates a `security-policy.json` tailored to your active surfaces and cloud provider |
| `security.terraform_hardening_blueprint` | Terraform hardening baseline with module layout, guardrails, and control mappings |
| `security.generate_opa_rego` | OPA/Rego policy code for Terraform plans, CI pipelines, and Kubernetes admission |
| `security.generate_compliance_report` | Maps gate findings to SOC 2, PCI-DSS, ISO 27001, NIST 800-53, HIPAA, or GDPR controls |
| `security.generate_remediations` | Maps each finding ID to a concrete code-level fix template |
| `security.notify_webhooks` | Sends findings to Slack, Jira, PagerDuty, or any webhook URL |
| `security.self_heal_loop` | Proposes adaptive policy improvements based on recurring findings (requires explicit human approval) |
| `security.attest_review` | Writes a SHA-256 integrity-hashed attestation file at `.mcp/reports/{runId}.attestation.json` |
| `repo.read_file` | Reads a project file for analysis (path-traversal guarded) |
| `repo.search` | Searches the codebase for patterns or regex (ReDoS guarded, max 500 matches) |

### Orchestration Tools (`/ciso-orchestrator` only)

| Tool | What It Does |
| --- | --- |
| `orchestration.create_agent_run` | Initialises the 39-agent manifest and `.mcp/agent-runs/{id}/` directory |
| `orchestration.update_agent_status` | Agents report start/completion; automatically advances phase when all phase agents finish |
| `orchestration.merge_agent_findings` | Deduplicates findings from all agents, sorts by severity, writes `merged-findings.json` |
| `orchestration.ensure_skill` | Downloads a skill from the GitHub registry if not cached locally (`~/.claude/skills/`) |
| `orchestration.read_agent_memory` | Loads an agent's prior patterns, false-positives, remediations, and cached intel |
| `orchestration.write_agent_memory` | Persists newly learned patterns and remediations after a run |
| `orchestration.check_updates` | Checks npm and the skills manifest for newer versions of security-mcp or installed skills |
| `orchestration.apply_updates` | Returns update commands (manual) or instructions for the agent to run them (auto) |
| `orchestration.verify_skill_coverage` | Reports which SKILL.md sections §1-§24 had zero coverage findings in this run |

---

## Security Frameworks Applied

All of the following frameworks are applied automatically. You don't need to know them - they're the standards used by the world's top security teams, and security-mcp maps every finding and fix to them:

| Framework | What It Covers |
| --- | --- |
| **OWASP Top 10** (Web + API) | The 10 most critical web and API vulnerability classes |
| **OWASP ASVS Level 2/3** | Application security verification standard - L3 for auth, payments, PII |
| **OWASP MASVS** | Mobile application security verification standard |
| **OWASP Top 10 for LLMs** | AI-specific vulnerabilities: prompt injection, training data poisoning, etc. |
| **OWASP Testing Guide** | Methodology used by pentest sub-agents for endpoint-level testing |
| **MITRE ATT&CK Enterprise + Cloud + Mobile** | Real attacker playbooks - every finding maps to a technique ID |
| **MITRE D3FEND** | Defensive countermeasure mapped to every ATT&CK technique in scope |
| **MITRE ATLAS** | Adversarial ML/AI attack techniques |
| **MITRE CAPEC** | Attack patterns used at design-time threat modeling |
| **NIST 800-53 Rev 5** | Full US government security control catalog |
| **NIST CSF 2.0** | Govern / Identify / Protect / Detect / Respond / Recover |
| **NIST 800-207** | Zero Trust Architecture - every request authenticated and authorized |
| **NIST 800-218 (SSDF)** | Secure Software Development Framework |
| **NIST AI RMF** | AI risk management: Map, Measure, Manage, Govern |
| **PCI DSS 4.0** | Payment card industry data security standard |
| **SOC 2 Type II** | Trust Services Criteria (Security, Availability, Confidentiality, PI) |
| **ISO 27001:2022 + 27002** | International information security management system |
| **ISO 42001:2023** | AI management system - applied to all LLM/AI components |
| **GDPR / CCPA / HIPAA** | Data privacy: consent, retention, breach notification, minimum necessary |
| **SLSA Level 3** | Software supply chain security - hermetic builds, signed provenance |
| **CIS Benchmarks Level 2** | Hardened cloud, OS, and container configurations |
| **CVSS v4.0 + EPSS** | Vulnerability scoring and exploit probability - EPSS > 0.5 fixed within 48h |

---

## Configuration

### Customize the Security Policy

The policy file controls what the gate blocks, what evidence it requires, and how exceptions are handled. Copy the default and edit:

```bash
mkdir -p .mcp/policies
cp node_modules/security-mcp/defaults/security-policy.json .mcp/policies/security-policy.json
```

Key sections:

```json
{
  "required_checks": {
    "secrets_scan": { "severity_block": ["HIGH", "CRITICAL"] },
    "dependency_scan": { "severity_block": ["CRITICAL"] },
    "sast": { "severity_block": ["CRITICAL"] },
    "iac_scan": { "severity_block": ["HIGH", "CRITICAL"] }
  },
  "vulnerability_slas": {
    "CRITICAL": "24h",
    "HIGH": "7d",
    "MEDIUM": "30d",
    "CISA_KEV": "24h"
  },
  "exceptions": {
    "require_ticket": true,
    "approval_roles": ["SecurityLead", "GRC", "CTO"]
  }
}
```

### Add a Security Exception

When you have a finding you've consciously accepted (e.g., a CVE in a library you're actively replacing):

```bash
mkdir -p .mcp/exceptions
cp node_modules/security-mcp/defaults/security-exceptions.json .mcp/exceptions/security-exceptions.json
```

Edit `.mcp/exceptions/security-exceptions.json`:

```json
{
  "version": "1.0.0",
  "exceptions": [
    {
      "id": "EX-001",
      "finding_ids": ["DEP_CVE_CVE-2024-12345"],
      "justification": "Library being replaced in sprint 42; no public exploit yet",
      "ticket": "JIRA-9999",
      "owner": "your-email@company.com",
      "approver": "security-lead@company.com",
      "approval_role": "SecurityLead",
      "expires_on": "2025-06-30"
    }
  ]
}
```

**Expired exceptions automatically become `SECURITY_EXCEPTION_EXPIRED` CRITICAL findings** that block the gate until renewed or resolved.

---

## Environment Variables

### CI / Gate

| Variable | Default | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` | set by Actions | Authenticates git operations in CI |
| `SECURITY_GATE_BASE_REF` | `origin/main` | Branch to diff against |
| `SECURITY_GATE_HEAD_REF` | `HEAD` | Branch being scanned |
| `SECURITY_GATE_POLICY` | `.mcp/policies/security-policy.json` | Path to policy file |
| `SECURITY_GATE_SCANNERS` | built-in | Path to custom scanner config (must be within project directory) |
| `SECURITY_GATE_EXCEPTIONS` | `.mcp/exceptions/security-exceptions.json` | Path to exceptions file (must be within project directory) |
| `SECURITY_GATE_MODE` | `full` | Set to `file_by_file` for scoped per-file scanning |
| `SECURITY_GATE_TARGETS` | (all changed files) | Comma-separated file paths to restrict the scan surface |

### Integrations (all optional)

| Variable | Purpose |
| --- | --- |
| `SECURITY_SLACK_WEBHOOK` | Sends gate results to a Slack channel |
| `SECURITY_JIRA_URL` | Creates Jira tickets for gate failures |
| `SECURITY_JIRA_TOKEN` | Jira API token (never logged) |
| `SECURITY_JIRA_PROJECT` | Jira project key (default: `SECURITY`) |
| `SECURITY_PAGERDUTY_KEY` | Pages on-call when CRITICAL findings are found |
| `SECURITY_WEBHOOK_URL` | POST gate results as JSON to any URL |

### Live Scanning (optional)

| Variable | Purpose |
| --- | --- |
| `SECURITY_STAGING_URL` | Enables live HTTP header and TLS checks against your staging environment |
| `SECURITY_AI_ENDPOINT` | Enables live jailbreak, injection, PII, and rate-limit probes against your AI endpoint |
| `SECURITY_AUTO_SBOM` | Set `true` to auto-generate a CycloneDX SBOM on each gate run |

---

## The 10 Rules That Are Never Broken

No matter what your AI is asked to build, these are enforced without exception:

1. **No `0.0.0.0/0` firewall rules** - ingress and egress must be source-restricted
2. **All internal services over private VPC only** - no public IPs for databases, queues, or internal APIs
3. **Secrets in a secret manager only** - never in code, `.env` files, CI logs, or container images
4. **TLS 1.3 for everything in transit** - TLS 1.0 and 1.1 are explicitly blocked
5. **Passwords hashed with Argon2id or bcrypt (cost ≥ 14)** - MD5 and SHA-1 are forbidden
6. **Every API input validated server-side with a schema** - no passing raw request data to business logic
7. **No inline JavaScript** - Content Security Policy is nonce-based only; no `unsafe-inline` or `unsafe-eval`
8. **Admin interfaces require FIDO2/WebAuthn passkey** - TOTP is not acceptable for admin access
9. **Threat model before any auth, payment, or AI feature** - no design-free implementation
10. **Zero Trust: every request authenticated and authorized regardless of origin** - no implicit network trust

---

## Troubleshooting

### The `/senior-security-engineer` command isn't available in my editor

**Cause:** The skill was not installed to `~/.claude/skills/`.

**Fix:** Re-run the installer:

```bash
npx -y security-mcp@latest install
```

Then verify the skill exists:

```bash
ls ~/.claude/skills/senior-security-engineer/SKILL.md
```

### The MCP server doesn't appear as connected

**Cause:** Config file was not written, or the editor wasn't restarted after config was written.

**Fix:**

1. Check the config file was written (see editor-specific paths in [Manual Configuration](#manual-configuration-any-mcp-editor))
2. Fully restart the editor (quit and reopen, not just reload window)
3. Check Node.js version: `node --version` - must be 20 or higher

### The CI gate fails with "cannot find module"

**Cause:** The dist files weren't included in the npm package, or you're referencing a path that doesn't exist.

**Fix:** Use `npx -y security-mcp@latest ci:pr-gate` which always pulls the latest published version, rather than referencing a local path.

### A finding is a false positive

**Fix:** Add it to `.mcp/exceptions/security-exceptions.json` with a justification, ticket, owner, and expiry date. See [Add a Security Exception](#add-a-security-exception).

### The gate is too strict for my current project stage

**Fix:** Edit `.mcp/policies/security-policy.json` to lower severity thresholds for your current environment. For example, set `dev` environment to only block on `CRITICAL`:

```json
"environments": {
  "dev": {
    "severity_block": ["CRITICAL"],
    "required_checks": ["secrets_scan"]
  }
}
```

### I want to update to the latest version

```bash
npx -y security-mcp@latest install
```

This always pulls the latest published version. If you have it globally installed:

```bash
npm install -g security-mcp@latest
```

---

## FAQ

**Q: Does this send my code to any external service?**

No. The MCP server runs locally as a Node.js process. Your code never leaves your machine. The only external calls made are to the npm registry (to check for updates) and optionally to GitHub (to download skill files) - both only if explicitly permitted. Live CVE/CISA KEV fetches during `/ciso-orchestrator` require your explicit internet permission at runtime.

**Q: Do I need to know security to use this?**

No. The tool is designed so that you don't need to understand what OWASP or ATT&CK mean. You describe what you're building, and the security engineer handles the rest.

**Q: Will it slow down my development?**

For daily use with `/senior-security-engineer` on recent changes, a typical review takes seconds to a few minutes. The fix is inline - you don't need to context-switch to a separate tool.

**Q: What if it fixes something I don't want changed?**

Everything is in your git working tree. Review the diff with `git diff`, revert anything you disagree with (`git checkout -- <file>`), and add a security exception if the finding is a false positive or accepted risk.

**Q: Can I use this on an existing codebase with lots of issues?**

Yes. Use `security.generate_policy` to set appropriate thresholds for your current state, add exceptions for known-accepted technical debt, and use the gate's MEDIUM/LOW findings as a backlog rather than blockers.

**Q: Is this a replacement for a real pentest?**

No - but it covers the same ground and more, continuously, on every change. Use `/ciso-orchestrator` before major releases to get the depth of a structured security review. For compliance purposes (SOC 2, PCI DSS), the attestation files and compliance reports generated are audit-trail artifacts.

**Q: What AI models does this work with?**

security-mcp is model-agnostic - it's an MCP server, not a model. It works with any AI assistant that supports the MCP protocol: Claude (all models), GitHub Copilot, Cursor, Codex, and others.

**Q: How do I report a vulnerability in security-mcp itself?**

See [SECURITY.md](SECURITY.md) for the responsible disclosure policy.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) - security-mcp contributors
