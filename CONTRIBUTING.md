# Contributing to security-mcp

Thank you for helping make AI-assisted development more secure.

## Getting Started

```bash
git clone https://github.com/AbrahamOO/security-mcp.git
cd security-mcp
npm install
npm run build
```

## Testing the MCP Server

Start the server directly:

```bash
node dist/cli/index.js serve
```

Test with MCP Inspector (recommended):

```bash
npx @modelcontextprotocol/inspector node dist/cli/index.js serve
```

Test the install command in dry-run mode:

```bash
node dist/cli/index.js install --dry-run
```

## Running the Security Gate

The project runs its own security gate on every PR:

```bash
node dist/ci/pr-gate.js
```

All PRs must pass the security gate before merging.

## Pull Request Requirements

1. All existing tests must pass.
2. The security gate (`node dist/ci/pr-gate.js`) must pass with no CRITICAL or HIGH findings.
3. New features that touch authentication, payment flows, or AI/LLM handling require a threat model in `security/threat-models/`.
4. No em dashes (`--`) in documentation files.
5. No personal information, employer names, or project-specific stack references in prompt files or the skill.

## Versioning (odometer rule)

Versions follow a strict odometer scheme, not standard semver overflow:

- A bump increases the version by `0.0.1` (patch + 1).
- The `minor` and `patch` segments are single digits `0-9`. Reaching `10`
  carries into the next-higher segment and resets to `0`. `major` is the top of
  the odometer and is never capped.

```text
1.0.9  -> bump -> 1.1.0
1.9.9  -> bump -> 2.0.0
```

Bump the version with the tool, never by hand:

```bash
npm run version:bump            # applies +0.0.1 with carry, writes package.json
npm run version:bump -- --dry-run   # preview only
npm run version:check           # fails if any version segment is >= 10
```

The publish workflow runs `version:check` on every release tag and refuses to
publish a version that violates the rule or whose `vX.Y.Z` tag does not match
`package.json`.

## Updating the Security Prompt

The generalized security prompt lives at `prompts/SECURITY_PROMPT.md`. When updating it:

- Keep all 24 sections.
- Do not remove existing controls - only strengthen them.
- Map new controls to MITRE ATT&CK techniques and NIST 800-53 control IDs.
- Test that the MCP server still loads it cleanly: `node dist/cli/index.js serve`

## Code of Conduct

Be respectful and constructive. Security research and responsible disclosure are welcome.
Report vulnerabilities via [GitHub private vulnerability reporting](https://github.com/AbrahamOO/security-mcp/security/advisories/new)
rather than public issues.
