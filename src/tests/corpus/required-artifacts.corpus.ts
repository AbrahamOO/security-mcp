import type { RuleCase } from "./types.js";

// ---------------------------------------------------------------------------
// required-artifacts (src/gate/checks/required-artifacts.ts)
//
// Unlike most checks, presence/absence here is NOT about the shape of the
// changed file's own content — it is about whether a SEPARATE artifact file
// exists anywhere in the workspace (`anyExists()`, a workspace-root-scoped
// `fg` glob) and, for four of the six rules, whether the changed files also
// match a trigger glob (`anyChanged()`, matched with picomatch against the
// `changedFiles` list itself, no disk access).
//
// The corpus runner (src/tests/corpus/runner.ts) gives each sample its own
// throwaway workspace containing exactly ONE file — the sample's `file` —
// and passes `changedFiles: [file]`. That single-file constraint shapes every
// case below:
//   - For the two unconditional rules (NO_THREAT_MODEL, NO_SBOM) the negative
//     IS the artifact itself: writing e.g. docs/threat-model.md means
//     anyExists() finds it and the rule never fires, regardless of content.
//   - For the three trigger-gated rules (PENTEST_SIGNOFF, REDTEAM_RESULTS,
//     COMPLIANCE_GAP) the trigger-glob namespace and the artifact-glob
//     namespace both key off substrings of the SAME path segment (e.g.
//     "auth", "llm", "hipaa"), so a single realistic report filename can be
//     constructed that satisfies both anyChanged() (it changed, and its name
//     contains the trigger keyword) and anyExists() (its name also matches
//     the report glob) at once. This exercises the real suppression branch
//     (trigger fires, artifact already present) rather than the trivial
//     short-circuit (trigger never fires).
//   - ARTIFACTS_MISSING (the policy-driven `artifacts_required` loop) is the
//     one exception: its trigger namespace (on_changes: src/**, app/**,
//     api/**, server/**, infra/**, terraform/**, k8s/**, helm/**, mobile/**,
//     ios/**, android/**, ai/**, ml/**) and its required-artifact namespace
//     (security/threat-models/*.md) are disjoint directory prefixes, so no
//     single file path can satisfy both "touched" and "artifact present" at
//     once. The negative for that rule instead demonstrates the other real
//     suppression path: a change confined to security/threat-models/ never
//     matches any on_changes glob, so the loop `continue`s before ever
//     checking artifact presence.
// ---------------------------------------------------------------------------

export const cases: RuleCase[] = [
  {
    ruleId: "ARTIFACTS_MISSING",
    check: "required-artifacts",
    positive: {
      file: "src/payments/service.ts",
      content: `export function chargeCard(cardToken: string, amountCents: number) {\n  return fetch("https://api.processor.example/charge", {\n    method: "POST",\n    body: JSON.stringify({ cardToken, amountCents })\n  });\n}\n`
    },
    negative: {
      file: "security/threat-models/checkout-flow.md",
      content: `# Threat Model: Checkout Flow\n\n## STRIDE\n- Spoofing: card token replay mitigated by single-use processor tokens.\n- Tampering: amountCents validated server-side against cart total.\n- Repudiation: all charge attempts logged with request id.\n- Information Disclosure: card token never logged, PAN never touches our servers.\n- Denial of Service: charge endpoint rate-limited per account.\n- Elevation of Privilege: charge endpoint requires authenticated session + CSRF token.\n\n## OWASP / MITRE\n- Maps to OWASP API Top-10 API4:2023 (Unrestricted Resource Consumption).\n- Maps to MITRE ATT&CK T1499 (mitigated via rate limiting).\n`
    },
    note: "policy.artifacts_required has one entry: on_changes = src/**, app/**, api/**, server/**, infra/**, terraform/**, k8s/**, helm/**, mobile/**, ios/**, android/**, ai/**, ml/** ; required pattern = security/threat-models/*.md. These two path namespaces never overlap, so a single-file harness cannot construct a case where the changed file is both 'touched' and 'the artifact'. The negative here changes only security/threat-models/checkout-flow.md, which matches none of the on_changes globs, so `touched` is false and the loop `continue`s before ever globbing for the artifact — the genuine 'not applicable to this change' suppression path, not a content variant of the positive."
  },
  {
    ruleId: "ARTIFACTS_NO_THREAT_MODEL",
    check: "required-artifacts",
    positive: {
      file: "src/index.ts",
      content: `export function main() {\n  console.log("hello");\n}\n`
    },
    negative: {
      file: "docs/threat-model.md",
      content: `# Threat Model\n\n## Trust Boundaries\n- Public internet -> API gateway -> internal services -> database.\n\n## STRIDE\n- Spoofing: mTLS between internal services, OAuth2 for external clients.\n- Tampering: request signing on all internal RPC calls.\n- Repudiation: structured audit log shipped to SIEM.\n- Information Disclosure: field-level encryption for PII columns.\n- Denial of Service: WAF + rate limiting at the edge.\n- Elevation of Privilege: least-privilege IAM roles per service.\n\n## Mappings\n- OWASP Top-10: A01 Broken Access Control, A02 Cryptographic Failures.\n- MITRE ATT&CK: T1078 (Valid Accounts), T1190 (Exploit Public-Facing Application).\n\n## Data Flow Diagram\nSee docs/dfd.png.\n`
    },
    note: "checkThreatModel() is unconditional (no anyChanged() gate) and calls anyExists() over [.mcp|docs|security]/threat-model.{json,md} plus the **/threat-model.{json,md} fallback. The corpus runner's tmp workspace holds only the one sample file, so writing docs/threat-model.md as the sample IS the artifact anyExists() finds — no separate trigger file is needed or possible in this harness."
  },
  {
    ruleId: "ARTIFACTS_NO_SBOM",
    check: "required-artifacts",
    positive: {
      file: "src/index.ts",
      content: `export function main() {\n  console.log("hello");\n}\n`
    },
    negative: {
      file: "reports/sbom.json",
      content: `{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.5",\n  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",\n  "version": 1,\n  "components": [\n    { "type": "library", "name": "express", "version": "4.19.2", "purl": "pkg:npm/express@4.19.2" }\n  ]\n}\n`
    },
    note: "checkSbom() is unconditional and calls anyExists() over **/*.cdx.json, **/*.spdx(.json), **/sbom.{json,xml}, **/bom.{json,xml}. reports/sbom.json matches **/sbom.json (globstar matches the 'reports' directory segment), so writing it as the sample file is itself the suppressing artifact — same single-file mechanism as the threat-model case, without relying on a zero-segment globstar edge case."
  },
  {
    ruleId: "ARTIFACTS_NO_PENTEST_SIGNOFF",
    check: "required-artifacts",
    positive: {
      file: "src/routes/payment.ts",
      content: `export function handlePayment(req, res) {\n  const { cardToken, amountCents } = req.body;\n  return chargeCard(cardToken, amountCents);\n}\n`
    },
    negative: {
      file: ".mcp/pentest-report-auth-2026.md",
      content: `# Pentest Report: Auth & Payment Flows (2026)\n\n## Scope\nAuthentication, session management, and payment checkout endpoints.\n\n## Findings\n- No critical or high findings outstanding. One MEDIUM (missing rate limit on /login) remediated 2026-03-01.\n\n## Coverage\n- OWASP Top-10 auth/session flaws: reviewed, none exploitable.\n- IDOR checks on payment endpoints: reviewed, none exploitable.\n- PCI DSS 6.3-6.5: control walkthrough completed, evidence attached.\n\nSigned off by: Security Engineering, 2026-03-05.\n`
    },
    note: "checkPentestSignoff() gates on anyChanged(changedFiles, ['**/*payment*','**/*auth*','**/*checkout*','**/*stripe*']) before calling anyExists(['.mcp/pentest-report*', ..., '.mcp/*pentest*', ...]). The negative filename '.mcp/pentest-report-auth-2026.md' contains 'auth', so it satisfies the trigger glob itself (anyChanged = true, the real code path — not the trivial 'nothing changed that matters' short-circuit) AND its 'pentest-report' prefix satisfies the artifact glob (anyExists = true), so found=true and the check returns [] before ever reaching the finding-construction branch."
  },
  {
    ruleId: "ARTIFACTS_NO_REDTEAM_RESULTS",
    check: "required-artifacts",
    positive: {
      file: "src/services/llm-client.ts",
      content: `export async function askModel(prompt: string) {\n  return fetch("https://api.openai.com/v1/chat/completions", {\n    method: "POST",\n    body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: prompt }] })\n  });\n}\n`
    },
    negative: {
      file: ".mcp/redteam-llm-findings-2026.md",
      content: `# AI Red Team Results: LLM Client Integration (2026)\n\n## Scope\nPrompt injection, indirect prompt injection via tool outputs, jailbreak resistance, data exfiltration via model output.\n\n## Findings\nNo unmitigated HIGH/CRITICAL findings. Two MEDIUM findings (tool-output sanitization gaps) remediated.\n\n## Mappings\n- OWASP LLM Top 10: LLM01 (Prompt Injection) tested and mitigated via input/output filtering.\n- MITRE ATLAS: AML.T0051 tested.\n\nSigned off by: AI Security, 2026-02-20.\n`
    },
    note: "checkRedteamResults() gates on anyChanged(changedFiles, ['**/*llm*','**/*openai*','**/*anthropic*','**/*langchain*','**/*rag*']) before calling anyExists(['.mcp/agent-runs/ai-findings*', '.mcp/agent-runs/redteam*', ..., '.mcp/redteam*', ...]). The negative filename '.mcp/redteam-llm-findings-2026.md' contains 'llm' (trigger glob matches, real gated path) and starts with 'redteam' under .mcp/ (artifact glob '.mcp/redteam*' matches), so anyExists = true and the check suppresses before constructing a finding."
  },
  {
    ruleId: "ARTIFACTS_COMPLIANCE_GAP",
    check: "required-artifacts",
    positive: {
      file: "src/services/hipaa-export.ts",
      content: `export function exportPatientRecords(patientId: string) {\n  return db.query("SELECT * FROM patient_records WHERE patient_id = ?", [patientId]);\n}\n`
    },
    negative: {
      file: ".mcp/compliance-gap-hipaa-2026.md",
      content: `# Compliance Gap Analysis: HIPAA Patient Record Export (2026)\n\n## Scope\nPatient record export endpoint.\n\n## Control Mapping\n- HIPAA Security Rule 164.312(a)(1) (Access Control): role-based access enforced, gap closed.\n- HIPAA Security Rule 164.312(b) (Audit Controls): export events logged to immutable audit trail.\n\n## Residual Risk\nNone outstanding. Signed off by Compliance Owner, 2026-01-15.\n`
    },
    note: "checkComplianceGap() gates on anyChanged(changedFiles, ['**/*hipaa*','**/*pci*','**/*gdpr*','**/*compliance*','**/*policy*']) before calling anyExists(['.mcp/compliance-gap*', '.mcp/compliance-findings*', ..., 'docs/compliance-findings*']). The negative filename '.mcp/compliance-gap-hipaa-2026.md' contains both 'hipaa' and 'compliance' (trigger glob matches on either) and its 'compliance-gap' prefix satisfies the artifact glob '.mcp/compliance-gap*' directly, so anyExists = true and the check suppresses before constructing a finding."
  }
];
