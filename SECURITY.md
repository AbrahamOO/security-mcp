# Security Policy

## Reporting a Vulnerability

Please do NOT report security vulnerabilities via public GitHub issues.

Use **GitHub private vulnerability reporting** instead:
[https://github.com/AbrahamOO/security-mcp/security/advisories/new](https://github.com/AbrahamOO/security-mcp/security/advisories/new)

## What to Include

- Description of the vulnerability and its potential impact
- Steps to reproduce
- Affected versions
- Any proof-of-concept code (do not include active exploit code)

## Response Timeline

- **Acknowledgement**: within 2 business days
- **Initial assessment**: within 5 business days
- **Resolution target**: within 90 days for confirmed vulnerabilities
- **Public disclosure**: coordinated with reporter after fix is released

We follow responsible disclosure. We will not pursue legal action against researchers
who report vulnerabilities in good faith and do not exploit them.

## Scope

In scope:
- The MCP server and all tools it exposes
- The security gate engine
- The CLI install command
- The prompts and skill files

Out of scope:
- Findings in third-party dependencies (report to the upstream project)
- Denial-of-service attacks against the local dev server
- Social engineering

## Supported Versions

We support the latest published version on npm. Apply updates promptly.
