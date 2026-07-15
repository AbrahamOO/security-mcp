# Windsurf rules — security-mcp

Last updated: 2026-07-14
Created: 2026-07-14

This project has the **security-mcp** server configured
(`~/.codeium/windsurf/mcp_config.json`). It exposes a full roster of security agents and
a deterministic policy gate over MCP.

## Security reviews

- Single-session review: invoke the `senior-security-engineer` MCP prompt. It picks a
  scan scope, runs the gate, writes the fixes (90% fixing), and attests.
- Full audit: invoke the `ciso-orchestrator` MCP prompt.

## Running any specialist agent

Agents are delivered over MCP — no Claude Code skills required.

- Read the `skill://catalog` MCP resource for the full roster.
- Read `skill://<name>` (e.g. `skill://cloud-infra-specialist`) or call
  `orchestration.ensure_skill` with `{ "skillName": "<name>" }` to load an agent's full
  persona, then execute every section.
- Coordinate multi-agent runs with the `orchestration.*` tools.

## Rules

Adopt each agent's FULL persona. Never skip an agent, never summarize a persona, never
lower the coverage bar. Where Cascade cannot spawn parallel subagents, run the agents
sequentially, each to completion. `orchestration.verify_skill_coverage` gates completion.

## CI gate

`npx -y security-mcp@latest ci:pr-gate` runs the gate in CI; it exits non-zero on
HIGH/CRITICAL findings.

## Change History

- 2026-07-14 - Added: initial Windsurf rules template for MCP-native security-mcp usage.
