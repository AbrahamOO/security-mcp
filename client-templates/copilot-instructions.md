# GitHub Copilot instructions — security-mcp

Last updated: 2026-07-16
Created: 2026-07-14

This repository has the **security-mcp** server configured (`.vscode/mcp.json`). It
exposes a full roster of security agents and a deterministic policy gate over MCP.

## Security reviews

- For a single-session review, run the `senior-security-engineer` MCP prompt (Chat >
  prompt picker, or `/` in agent mode). It picks a scan scope, runs the gate, writes the
  fixes, and attests.
- For a full audit, run the `ciso-orchestrator` MCP prompt.
- For a plain "fortify"/"lock down X"/"harden to production grade" request, call the
  `security.fortify` tool (or the `fortify` MCP prompt) with the named target (e.g.
  "forms", "our API", "the whole codebase"). It always auto-applies, resolves scope via
  repo search, and pre-selects the specialist team — no confirmation gate.

`security.start_review` now defaults to auto-apply when `remediationMode` is omitted;
pass `remediationMode: "detection_only"` explicitly for a report-only run.

## Running any specialist agent

Agents are delivered over MCP — no Claude Code skills required.

- Read the `skill://catalog` MCP resource for the full roster.
- Read `skill://<name>` (e.g. `skill://appsec-code-auditor`) or call the
  `orchestration.ensure_skill` tool with `{ "skillName": "<name>" }` to load an agent's
  complete persona, then execute every section.
- Use the `orchestration.*` tools to coordinate a multi-agent run.

## Rules

Adopt each agent's FULL persona. Never skip an agent, never summarize a persona, never
lower the coverage bar. Where parallel subagents are unavailable, run agents sequentially,
each to completion. `orchestration.verify_skill_coverage` gates run completion.

## CI gate

`npx -y security-mcp@latest ci:pr-gate` runs the gate in CI (no AI session); it exits
non-zero on HIGH/CRITICAL findings.

## Change History

- 2026-07-16 - Added: one-shot fortify guidance (`security.fortify` tool / `fortify` prompt) and noted `security.start_review` now defaults to auto-apply.
- 2026-07-14 - Added: initial Copilot instructions template for MCP-native security-mcp usage.
