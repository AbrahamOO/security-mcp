# security-mcp

[![npm version](https://img.shields.io/npm/v/security-mcp.svg)](https://www.npmjs.com/package/security-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![CI](https://github.com/AbrahamOO/security-mcp/actions/workflows/security-gate.yml/badge.svg)](https://github.com/AbrahamOO/security-mcp/actions)

**AI security MCP server and automated gate for Claude Code, GitHub Copilot, Cursor, Codex, Replit, and any MCP-compatible editor** -- enforcing OWASP, MITRE ATT&CK, NIST 800-53, Zero Trust, PCI DSS 4.0, and 20+ security frameworks on every code change before it ships.

---

## Quick Start

Install the MCP security server into all detected editors with one command:

```bash
npx security-mcp install
```

Target a specific editor:

```bash
npx security-mcp install --claude-code
npx security-mcp install --cursor
npx security-mcp install --vscode
```

Preview what would be installed without writing anything:

```bash
npx security-mcp install --dry-run
```

After installation, restart your editor. The `security-mcp` MCP server starts automatically.

In **Claude Code**, invoke the skill directly:

```text
/security-review
```

---

## What It Does

`security-mcp` gives your AI coding assistant the knowledge and tools of a **Principal Security Engineer** who has internalized every major security framework. It operates at four levels:

### 1. MCP Server (Real-Time Tools)

The MCP server exposes tools that your AI can call during any coding session:

| Tool | What It Does |
| --- | --- |
| `security.get_system_prompt` | Returns the full elite security prompt (optionally filtered by stack, cloud provider, or payment processor) |
| `security.threat_model` | Generates a complete STRIDE + PASTA + ATT&CK + D3FEND threat model template for any described feature |
| `security.checklist` | Returns the pre-release security checklist, filterable by surface (web, api, mobile, ai, infra, payments) |
| `security.generate_policy` | Generates a `security-policy.json` tailored to your project surfaces and cloud provider |
| `security.run_pr_gate` | Runs the security policy gate against the current Git diff and reports findings |
| `repo.read_file` | Reads a file from the workspace |
| `repo.search` | Searches the codebase for patterns |

### 2. MCP Prompts

Two reusable prompts are registered in the MCP server:

- **`security-engineer`** - Loads the full security system prompt, turning your AI into a Principal Security Engineer persona for the session.
- **`threat-model-template`** - Accepts a `feature` argument and returns a ready-to-fill threat model template.

### 3. Claude Code Skill

The `/security-review` skill is a 24-section, 900-line security directive that embeds the complete security framework directly into Claude Code's context. It covers:

- STRIDE + PASTA + LINDDUN + DREAD threat modeling
- MITRE ATT&CK (Enterprise, Cloud, Mobile) coverage table
- MITRE D3FEND countermeasure mapping
- MITRE ATLAS adversarial ML threat coverage
- Zero Trust architecture enforcement (NIST 800-207)
- Cloud security rules (GCP, AWS, Azure) with absolute prohibitions
- Container and Kubernetes hardening (CIS Benchmark Level 2)
- Supply chain security (SLSA L3, SBOM, Sigstore)
- DevSecOps pipeline gates (SAST, SCA, IaC, DAST)
- Input validation - three-layer defense for every field type
- AI/LLM security (prompt injection defense, RAG access control, output validation)
- PCI DSS 4.0 payment flow controls
- GDPR/CCPA/HIPAA data flow compliance
- Vulnerability SLAs (CRITICAL: 24h, HIGH: 7d, MEDIUM: 30d)
- Pre-release security checklist (Section 22E)

### 4. Security Gate (CI/CD)

The policy gate runs in CI and blocks PRs that violate security policy:

```bash
npx security-mcp ci:pr-gate
```

Gate checks cover hardcoded secrets, dependency vulnerabilities, IaC misconfigurations,
auth and authorization gaps, SSRF and CSRF exposure, and AI/LLM output bounding.

---

## Supported Editors

| Editor | Installation Method | Config Location |
| --- | --- | --- |
| Claude Code | `npx security-mcp install --claude-code` | `~/.claude/settings.json` |
| Cursor (global) | `npx security-mcp install --cursor` | `~/.cursor/mcp.json` |
| Cursor (workspace) | `npx security-mcp install --cursor` | `.cursor/mcp.json` |
| VS Code | `npx security-mcp install --vscode` | User `settings.json` |
| GitHub Copilot | Manual config (see below) | `.vscode/settings.json` |
| Codex | Manual config (see below) | Editor config |
| Replit | Manual config (see below) | `.replit` config |
| Any MCP-compatible | `npx security-mcp config` for snippet | Paste into editor config |

---

## Security Frameworks Covered

- OWASP Top 10 (Web + API)
- OWASP ASVS Level 2/3
- OWASP MASVS (Mobile)
- OWASP SAMM
- OWASP Top 10 for LLMs
- MITRE ATT&CK Enterprise v14+
- MITRE ATT&CK Cloud
- MITRE ATT&CK Mobile
- MITRE CAPEC
- MITRE D3FEND
- MITRE ATLAS (adversarial ML)
- NIST 800-53 Rev 5
- NIST CSF 2.0
- NIST 800-207 (Zero Trust Architecture)
- NIST 800-218 (SSDF)
- NIST AI RMF
- NIST 800-190 (Container Security)
- PCI DSS 4.0
- SOC 2 Type II
- ISO/IEC 27001:2022
- ISO/IEC 42001:2023 (AI Management)
- GDPR / CCPA / HIPAA
- CIS Benchmarks Level 2
- CSA CCM v4
- SLSA Level 3
- FedRAMP Moderate
- CVSS v4.0 + EPSS
- CWE/SANS Top 25

---

## Manual Configuration

### Claude Code (`~/.claude/settings.json`)

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "npx",
      "args": ["-y", "security-mcp", "serve"]
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
      "args": ["-y", "security-mcp", "serve"]
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
      "args": ["-y", "security-mcp", "serve"]
    }
  }
}
```

Print the recommended config snippet for any editor:

```bash
npx security-mcp config
```

---

## Security Policy

Copy the default security policy to your project and customize it:

```bash
cp node_modules/security-mcp/defaults/security-policy.json .mcp/policies/security-policy.json
cp node_modules/security-mcp/defaults/evidence-map.json .mcp/mappings/evidence-map.json
```

Or generate a policy tailored to your project via the MCP tool:

```text
Ask your AI: "Run security.generate_policy with surfaces=[web, api, ai] and cloud=aws"
```

---

## CI/CD Integration

Add the security gate to your GitHub Actions workflow:

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

      - name: Run security gate
        run: npx -y security-mcp ci:pr-gate
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The gate exits non-zero on CRITICAL or HIGH findings, blocking the PR merge.

---

## Threat Modeling

Ask your AI to generate a threat model for any feature:

```text
Run security.threat_model with feature="user authentication with OAuth 2.0" and surfaces=["web", "api"]
```

The tool returns a complete STRIDE + PASTA + ATT&CK + D3FEND template covering:

- Asset inventory and trust boundaries
- STRIDE analysis per component and trust boundary
- ATT&CK technique mapping with D3FEND countermeasures
- NIST 800-53 Rev 5 control IDs
- Residual risk register with owner and review date
- Pre-release security checklist

---

## Non-Negotiable Rules (Always Enforced)

The security persona enforces these rules without exception:

- No `0.0.0.0/0` ingress or egress rules anywhere
- All internal services communicate via private VPC paths only (VPC endpoints, PrivateLink)
- Secrets stored only in a dedicated secret manager - never in code, env files, or logs
- TLS 1.3 for all in-transit data; TLS 1.0/1.1 strictly prohibited
- Argon2id (or bcrypt cost 14+) for password hashing - no MD5, SHA-1, or unsalted hashes
- Server-side schema validation (Zod, Yup, Valibot) on every API input
- No inline JavaScript; CSP nonce-based only
- FIDO2/WebAuthn passkey for admin and privileged operations
- Threat model required before implementing auth, payment, or AI features
- Zero Trust: never trust, always verify - every request, every token, every service call

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security Disclosure

See [SECURITY.md](SECURITY.md) for responsible disclosure policy.

## License

[MIT](LICENSE) - security-mcp contributors
