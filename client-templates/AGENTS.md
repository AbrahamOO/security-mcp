# AGENTS.md — security-mcp

Last updated: 2026-07-14
Created: 2026-07-14

This project has the **security-mcp** server available over MCP. It provides a full
roster of security agents (threat modeling, appsec, cloud, supply chain, AI/LLM red
team, pentest, crypto, compliance) plus a deterministic policy gate. Every agent is
delivered over MCP, so this works in any MCP-capable host (Codex, Cursor, VS Code /
Copilot, Windsurf, Claude Code).

## How to run a security review

- **Single-session review:** invoke the `senior-security-engineer` MCP prompt. It picks
  a scan scope, runs the gate, writes the fixes (90% fixing, 10% advisory), and attests.
- **Full audit:** invoke the `ciso-orchestrator` MCP prompt. It coordinates the complete
  specialist roster across discovery and adversarial phases.

## Running any specialist agent

The full agent roster is served over MCP — you do not need Claude Code skills.

- List the roster: read the `skill://catalog` MCP resource.
- Load one agent's complete persona: read `skill://<name>` (e.g. `skill://threat-modeler`)
  or call the `orchestration.ensure_skill` tool with `{ "skillName": "<name>" }`. Both
  return the full SKILL.md.
- Coordinate a multi-agent run with the `orchestration.*` tools
  (`create_agent_run`, `update_agent_status`, `write_agent_memory`, `read_agent_memory`,
  `merge_agent_findings`, `verify_skill_coverage`).

## Rules that never relax

Adopt each agent's FULL persona. Never skip an agent, never summarize a persona, never
lower the coverage bar. If your host cannot spawn parallel subagents, run the agents
sequentially — each to completion — rather than dropping any. `verify_skill_coverage`
gates run completion.

## CI gate

`npx -y security-mcp@latest ci:pr-gate` runs the deterministic gate with no AI session.
It exits non-zero on HIGH/CRITICAL findings.

## Change History

- 2026-07-14 - Added: initial AGENTS.md template describing MCP-native agent delivery and the review/audit entry points.
