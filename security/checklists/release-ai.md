# AI / LLM Release Security Checklist

Use before every AI or LLM feature production release. All items must be checked or explicitly risk-accepted with a ticket and owner.

---

## All Surfaces (Required for Every Release)

- [ ] Threat model completed covering MITRE ATLAS and OWASP LLM Top 10
- [ ] SAST scan results reviewed — all CRITICAL/HIGH findings resolved
- [ ] Secrets scan clean — no API keys or model credentials in source
- [ ] SCA scan clean — no CRITICAL CVEs in AI SDK dependencies
- [ ] SBOM generated for this release artifact
- [ ] Error messages reviewed — no model internals or system prompt content exposed
- [ ] Logging reviewed — no PII, user inputs, or sensitive context in logs
- [ ] Rollback plan documented — can disable AI feature via feature flag within 5 minutes
- [ ] LLM prompt injection IR playbook updated

---

## Prompt Security

- [ ] System prompt structurally separated from user content — no string concatenation
- [ ] User input sanitized and validated before injection into any prompt
- [ ] System prompt does not contain secrets, credentials, or sensitive configuration
- [ ] Instruction hierarchy enforced — user content cannot override system-level rules
- [ ] Prompt templates reviewed for PII patterns — SSN, card numbers, passwords absent
- [ ] Direct prompt injection: input filtering and content isolation implemented
- [ ] Indirect prompt injection: RAG-retrieved context treated as untrusted — isolated from instructions

---

## Output Validation and Safety

- [ ] Model outputs validated against JSON schema before acting on them
- [ ] Structured output mode enabled where available (response_format, tool_use)
- [ ] Outputs that fail schema validation are rejected — not retried with relaxed rules
- [ ] PII scan on all model outputs before returning to users — SSN, card, token patterns blocked
- [ ] Model output never passed to eval(), exec(), or shell commands
- [ ] Model output never used as a URL without allowlist validation
- [ ] Output length limits enforced — no unbounded streaming without timeout

---

## RAG and Retrieval Security

- [ ] Authorization enforced before and after document retrieval — tenant isolation confirmed
- [ ] Retrieved documents filtered by user permissions — no cross-tenant data leakage
- [ ] Retrieved content treated as untrusted input — applied content isolation
- [ ] Metadata injection prevention — retrieved chunk boundaries clearly delimited
- [ ] Vector database access restricted to minimum required scope

---

## Agentic Controls

- [ ] Tool definitions use allowlist — only permitted tools exposed to the model
- [ ] High-impact tools (delete, execute, send, write) require human-in-the-loop approval
- [ ] Tool call arguments validated before execution — not passed through raw
- [ ] Agent execution has a maximum step limit — no unbounded loops
- [ ] Agent actions are fully logged with user, timestamp, tool, and arguments

---

## Rate Limiting and Abuse Prevention

- [ ] AI endpoints rate-limited independently from regular API rate limits
- [ ] Per-user token budgets enforced — daily and hourly limits defined
- [ ] Request size limits enforced — max prompt token count validated before forwarding
- [ ] Cost anomaly alerting configured — spike in token usage triggers alert within 5 minutes
- [ ] Abuse pattern detection: repeated jailbreak attempts flagged and blocked

---

## Data Privacy

- [ ] Minimum necessary data included in prompts — no bulk data injection
- [ ] User data not used to train or fine-tune models without explicit consent
- [ ] Model provider's data retention policy reviewed and documented
- [ ] PII in conversation history handled per data retention policy — purged on schedule
- [ ] GDPR / CCPA data subject rights process applies to AI-processed data

---

## Red Team and Testing

- [ ] Jailbreak probe suite executed and results reviewed
- [ ] Prompt injection test suite executed against RAG and tool-calling flows
- [ ] PII exfiltration probe executed — model did not repeat back injected sensitive data
- [ ] Token flooding / DoS probe executed — rate limiting verified active
- [ ] Adversarial input fuzzing completed on prompt templates
- [ ] Red team results documented with findings and mitigations

---

## OWASP LLM Top 10 Review

- [ ] LLM01 Prompt Injection: mitigations implemented and tested
- [ ] LLM02 Insecure Output Handling: schema validation and output sanitization in place
- [ ] LLM03 Training Data Poisoning: model source and training provenance reviewed
- [ ] LLM04 Model Denial of Service: token and cost limits enforced
- [ ] LLM05 Supply Chain Vulnerabilities: AI SDK dependencies scanned
- [ ] LLM06 Sensitive Information Disclosure: PII scanning on outputs, context minimization
- [ ] LLM07 Insecure Plugin Design: tool allowlist and argument validation confirmed
- [ ] LLM08 Excessive Agency: human-in-the-loop controls on high-impact actions
- [ ] LLM09 Overreliance: user-facing disclaimers and fallback logic in place
- [ ] LLM10 Model Theft: model endpoints authenticated, access logs reviewed

---

## Monitoring and Incident Response

- [ ] Model access logging enabled: user, timestamp, token counts, model version
- [ ] Abuse monitoring: anomaly detection on token usage and response patterns
- [ ] LLM prompt injection IR playbook current and on-call contacts verified
- [ ] Model data poisoning IR playbook current
- [ ] Incident response drill completed for AI-specific attack scenarios in last 6 months

---

## Advanced AI Attack Surface

- [ ] System prompt extraction: model cannot be tricked into revealing full system prompt (OWASP LLM01)
- [ ] Multi-turn attack chains: tested across 5+ conversation turns — instruction hierarchy holds
- [ ] Context window overflow: very long inputs do not cause instruction truncation or bypass
- [ ] Multimodal injection: image/audio/document inputs treated as untrusted — no instruction execution
- [ ] Agent memory / scratchpad treated as untrusted — not elevated to trusted instruction context
- [ ] Model inversion / training data extraction: probed for PII recitation or memorized secrets
- [ ] Shadow alignment attacks: tested with gradual instruction-normalization attempts across sessions
- [ ] Cross-session data leakage: confirmed no user data bleeds across sessions or tenants
- [ ] Indirect injection via RAG: malicious content in retrieved documents cannot override system prompt
- [ ] Agent memory poisoning: external data stored in agent memory validated before future use
- [ ] AML.T0054 (LLM Prompt Injection) mitigations documented and verified in testing
- [ ] AML.T0057 (Craft Adversarial Data) rate limits and content filtering active and tested

---

## Post-Quantum Readiness Gate

- [ ] All RSA/ECDSA keys used for model authentication or token signing inventoried
- [ ] Any token with validity > 1 year assessed for harvest-now-decrypt-later risk
- [ ] Migration plan documented for ML-KEM (FIPS 203) / ML-DSA (FIPS 204) when CRQC timeline clarified
- [ ] Long-term user data encrypted at rest with AES-256-GCM (quantum-resistant symmetric) — NOT RSA-encrypted

## Security-MCP Specific Gates

- [ ] Skill integrity: every skill listed in `skills-manifest.json` has a `sha256` hash and `size` field populated — no entry is missing or null
- [ ] Skill integrity verified: downloaded skill content is checked against the manifest sha256 before use — tampered or substituted skills are rejected
- [ ] Policy file integrity: the active `security-policy.json` is verified via HMAC before evaluation — unsigned or tampered policy files are rejected, not silently accepted
- [ ] `apply_updates` output reviewed: any npm install commands generated by the self-heal loop are signed or pinned to exact versions, not floating ranges

---

## Learning Loop Review

- [ ] `security.pattern_report` consulted — top recurring AI finding types reviewed before release
- [ ] Findings from this run fed to `security.record_outcome` for routing improvement
- [ ] Any finding the AI red team has seen 3+ times across runs has a permanent automated gate check

## Cross-Checklist Dependencies

- [ ] AI output passed to API endpoints? → `release-api.md` authentication + rate-limit controls also verified
- [ ] AI features use cloud infrastructure? → `release-infra.md` IAM and network controls also verified
- [ ] AI processes payment or health data? → `release-payments.md` or `release-web.md` also completed
