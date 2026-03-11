# security-mcp -- Your AI's Built-In Security Expert

[![npm version](https://img.shields.io/npm/v/security-mcp.svg)](https://www.npmjs.com/package/security-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![CI](https://github.com/AbrahamOO/security-mcp/actions/workflows/security-gate.yml/badge.svg)](https://github.com/AbrahamOO/security-mcp/actions)

**Stop shipping vulnerable code.** security-mcp gives your AI assistant the knowledge of a Senior Security Engineer who actively **finds and fixes** security issues in your code -- not just lists them.

Works with Claude Code, GitHub Copilot, Cursor, Codex, Replit, and any MCP-compatible editor.

---

## Who Is This For?

You don't need a security background to use this. It's built for:

- **Vibe coders** building fast and shipping faster -- who need security to just work
- **Indie hackers and solo founders** who can't afford a dedicated security team
- **Full-stack developers** who know their code works but aren't sure if it's safe
- **Startups and small teams** shipping web apps, mobile apps, APIs, and SaaS products
- **AI-assisted developers** using Claude Code, Copilot, Cursor, or Codex to write code
- **Anyone who's ever shipped code and wondered "wait, is this secure?"**

You write the code. Your AI + security-mcp enforces the security.

---

## What It Fortifies

security-mcp actively hardens every surface of your software:

| Surface | What Gets Fortified |
| --- | --- |
| **Web Apps** | XSS, CSRF, injection attacks, insecure headers, authentication flaws, session bugs |
| **APIs (REST, GraphQL, gRPC)** | Auth gaps, IDOR, rate limiting, input validation, CORS misconfigs, SSRF |
| **Mobile Apps (iOS + Android)** | Insecure storage, certificate pinning, network security, reverse engineering exposure |
| **Cloud Infrastructure (AWS, GCP, Azure)** | Open firewall rules, public buckets, wildcard IAM, missing encryption, exposed metadata |
| **AI / LLMs** | Prompt injection, jailbreaks, RAG access control, output validation, data leakage |
| **Code and Dependencies** | Hardcoded secrets, vulnerable packages, supply chain risks, insecure crypto |
| **CI/CD Pipelines** | Secrets in logs, overprivileged deploy credentials, unvalidated artifacts |

---

## Quick Start

```bash
npx -y security-mcp@latest install
```

That's it. The tool auto-detects your editor and writes the MCP config. Restart your editor -- done.

To target a specific editor:

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

Install the package globally, then configure editors to call the global binary directly:

```bash
npm install -g security-mcp@latest
security-mcp install-global
```

Preview the global install flow without writing:

```bash
security-mcp install-global --dry-run
```

### Update Behavior

- `npx -y security-mcp@latest ...` always runs the latest published npm version.
- Global installs (`npm install -g security-mcp`) do not auto-upgrade by themselves.
- The CLI now checks npm for new releases and prints an update prompt when a newer version is available.

Global update command:

```bash
npm install -g security-mcp@latest
security-mcp install-global
```

In **Claude Code**, activate the security engineer:

```text
/senior-security-engineer
```

Your AI will now **find and fix** security issues instead of just mentioning them.

---

## How It Works

When you invoke `/senior-security-engineer` or call any security-mcp MCP tool, your AI shifts into the role of a Senior Security Engineer. It will:

1. **Ask scan scope first** -- folder-by-folder, file-by-file, or recent changes
2. **Start a review run** -- carry a `runId` for ordered execution and attestation
3. **Scan your code** for vulnerabilities, misconfigurations, and security anti-patterns
4. **Fix what it finds** -- not just flag it; it rewrites the insecure code with the secure version
5. **Enforce policies** -- set up input validation, auth middleware, security headers, and rate limiting
6. **Block dangerous patterns** -- refuse to implement code that introduces known vulnerabilities
7. **Produce an attestation** -- emit a confidence summary and integrity hash for the completed review

### MCP Tools (Your AI Uses These Automatically)

| Tool | What It Does |
| --- | --- |
| `security.start_review` | Starts a stateful review run and returns the `runId` used for ordered execution and attestation |
| `security.get_system_prompt` | Loads the full security directive into your AI session -- activates the Senior Security Engineer mode |
| `security.threat_model` | Generates a complete threat model for any feature before a single line of code is written |
| `security.checklist` | Returns a hardened pre-ship checklist specific to your surface (web, API, mobile, AI, cloud) |
| `security.scan_strategy` | Forces scan mode selection (`folder_by_folder`, `file_by_file`, `recent_changes`) and builds an exhaustive review plan |
| `security.generate_policy` | Writes a `security-policy.json` for your project that the gate enforces on every PR |
| `security.terraform_hardening_blueprint` | Produces an advanced Terraform hardening baseline (network, IAM, data, logging, CI controls) |
| `security.generate_opa_rego` | Generates preventive OPA/Rego policies for Terraform plans, CI pipelines, and Kubernetes admission (requires explicit consent) |
| `security.self_heal_loop` | Proposes self-healing improvements, but requires explicit human approval before any change |
| `security.attest_review` | Writes an auditable review attestation with integrity hash and confidence summary |
| `security.run_pr_gate` | Scans recent changes, selected folders, or selected files and **blocks merge** on CRITICAL/HIGH vulnerabilities; requires `runId` in MCP usage |
| `repo.read_file` | Reads files from your workspace for analysis |
| `repo.search` | Searches your codebase for vulnerable patterns |

### Security Gate (Blocks Bad Code from Shipping)

```bash
npx -y security-mcp@latest ci:pr-gate
```

Add this to your CI pipeline. It scans every PR and **blocks the merge** if it finds:

- Hardcoded secrets or credentials
- Known vulnerable dependencies (CRITICAL/HIGH CVEs)
- Dangerous IaC patterns (open firewall rules, world-readable storage, wildcard IAM)
- Auth gaps, SSRF, CSRF exposure
- AI/LLM output that isn't properly bounded or validated

---

## What Gets Fixed Automatically

When your AI has security-mcp active, it will **fix these automatically** -- not just warn about them:

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
- Locks down S3/GCS/Azure Blob buckets that are world-readable
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

## Supported Editors

| Editor | Install Command | Config Location |
| --- | --- | --- |
| Claude Code | `npx -y security-mcp@latest install --claude-code` | `~/.claude/settings.json` |
| Claude Code (global binary) | `security-mcp install-global --claude-code` | `~/.claude/settings.json` |
| Cursor (global) | `npx -y security-mcp@latest install --cursor` | `~/.cursor/mcp.json` |
| Cursor (global binary) | `security-mcp install-global --cursor` | `~/.cursor/mcp.json` |
| Cursor (workspace) | `npx -y security-mcp@latest install --cursor` | `.cursor/mcp.json` |
| VS Code | `npx -y security-mcp@latest install --vscode` | User `settings.json` |
| VS Code (global binary) | `security-mcp install-global --vscode` | User `settings.json` |
| GitHub Copilot | Manual config (see below) | `.vscode/settings.json` |
| Codex | Manual config (see below) | Editor config |
| Replit | Manual config (see below) | `.replit` config |
| Any MCP-compatible | `npx -y security-mcp@latest config` or `security-mcp config --use-global-binary` | Paste into editor config |

---

## Security Frameworks Applied (Automatically)

You don't need to know what these are. They're the standards that the world's top security teams use.
security-mcp applies all of them on your behalf:

- OWASP Top 10 (Web + API) -- the most common attack patterns
- OWASP ASVS Level 2/3 -- application security verification
- OWASP MASVS -- mobile app security
- OWASP Top 10 for LLMs -- AI-specific vulnerabilities
- MITRE ATT&CK Enterprise, Cloud, and Mobile -- real attacker playbooks
- MITRE D3FEND -- defensive countermeasures mapped to every attack
- MITRE ATLAS -- adversarial ML/AI attack techniques
- NIST 800-53 Rev 5 -- the US government's security control catalog
- NIST 800-207 -- Zero Trust Architecture
- NIST AI RMF -- AI risk management
- PCI DSS 4.0 -- payment card security (if you handle payments)
- SOC 2 Type II -- cloud service security (if you serve enterprise customers)
- ISO 27001:2022 -- international security management standard
- GDPR / CCPA / HIPAA -- data privacy compliance
- SLSA Level 3 -- supply chain security
- CIS Benchmarks Level 2 -- hardened configurations for cloud and containers
- CVSS v4.0 + EPSS -- vulnerability scoring and exploit probability

---

## Manual Editor Configuration

### Claude Code (`~/.claude/settings.json`)

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

### Claude Code With Global Binary (`~/.claude/settings.json`)

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "security-mcp",
      "args": ["serve"]
    }
  }
}
```

### Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)

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

### VS Code / GitHub Copilot (`settings.json`)

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

Print the config snippet for any editor:

```bash
npx -y security-mcp@latest config
security-mcp config --use-global-binary
```

---

## Security Policy (CI/CD Gate)

Copy the default policy into your project:

```bash
cp node_modules/security-mcp/defaults/security-policy.json .mcp/policies/security-policy.json
cp node_modules/security-mcp/defaults/evidence-map.json .mcp/mappings/evidence-map.json
cp node_modules/security-mcp/defaults/control-catalog.json .mcp/catalog/control-catalog.json
cp node_modules/security-mcp/defaults/security-tools.json .mcp/scanners/security-tools.json
cp node_modules/security-mcp/defaults/security-exceptions.json .mcp/exceptions/security-exceptions.json
```

Or generate one tailored to your project:

```text
Ask your AI: "Run security.generate_policy with surfaces=[web, api, ai] and cloud=aws"
```

Add the gate to GitHub Actions:

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

---

## The 10 Rules That Are Never Broken

No matter what your AI is asked to do, these rules are enforced without exception:

1. No `0.0.0.0/0` firewall rules -- ever
2. All internal services talk over private VPC only (no public internet)
3. Secrets live in a secret manager only -- never in code, env files, or logs
4. TLS 1.3 for everything in transit -- 1.0 and 1.1 are blocked
5. Passwords hashed with Argon2id or bcrypt (cost 14+) -- no MD5, no SHA-1
6. Every API input validated server-side with a schema -- no exceptions
7. No inline JavaScript -- CSP nonce-based only
8. Admin interfaces require FIDO2/WebAuthn passkey -- not just a password
9. Threat model written before building any auth, payment, or AI feature
10. Zero Trust: every request authenticated and authorized regardless of origin

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible Disclosure

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) - security-mcp contributors
