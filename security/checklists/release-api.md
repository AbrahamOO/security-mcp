# API Release Security Checklist

Use before every API production release. All items must be checked or explicitly risk-accepted with a ticket and owner.

---

## All Surfaces (Required for Every Release)

- [ ] Threat model completed and reviewed by security-designated reviewer
- [ ] SAST scan results reviewed — all CRITICAL/HIGH findings resolved or risk-accepted with ticket
- [ ] SCA scan clean — no CRITICAL CVEs in dependencies; HIGH CVEs triaged and scheduled
- [ ] Secrets scan clean — no credentials, tokens, or API keys in source
- [ ] IaC scan — no HIGH/CRITICAL misconfigurations
- [ ] SBOM generated for this release artifact
- [ ] Error messages reviewed — no stack traces, schema details, or internal paths
- [ ] Logging reviewed — all required events logged; no PII, secrets, or tokens in logs
- [ ] Rollback plan documented and tested
- [ ] IR playbook updated if a new attack surface was introduced

---

## Authentication and Authorization

- [ ] All new endpoints require authentication — no unauthenticated access to sensitive data
- [ ] JWT validation: algorithm is RS256 or ES256 — HS256 with shared secret prohibited
- [ ] JWT expiry enforced — access tokens max 15 minutes, refresh tokens rotated on use
- [ ] Authorization checked server-side for every resource operation — IDOR prevention confirmed
- [ ] Row-level security enforced — cross-tenant access not possible
- [ ] Privilege escalation paths reviewed — no client-supplied role claims accepted
- [ ] Service-to-service auth uses short-lived tokens or mTLS — no static API keys
- [ ] API keys have minimum required scope — no wildcard permissions

---

## Input Validation

- [ ] Server-side schema validation on all new inputs (Zod / Valibot / Yup / Joi)
- [ ] Allowlist validation (not blocklist) for all user-controlled data
- [ ] Request size limits enforced — no unbounded body parsing
- [ ] Query parameter validation — types, ranges, and formats enforced
- [ ] File upload restrictions: type, size, name validated — stored outside web root
- [ ] SQL injection prevention — parameterized queries or ORM throughout (no raw string concat)
- [ ] Mass assignment prevention — explicit field allowlists, not object spread from request body
- [ ] Path traversal prevention — no user input used in file path construction

---

## Rate Limiting and Abuse Prevention

- [ ] Rate limiting on all new endpoints — per-user and per-IP limits defined
- [ ] Aggressive rate limiting on auth endpoints (login, token refresh, password reset)
- [ ] Request throttling documented: burst limit, sustained limit, and backoff behavior
- [ ] Bot detection on sensitive endpoints (registration, checkout, scraping-prone routes)

---

## Sensitive Data Handling

- [ ] PII not included in API responses unless explicitly required — minimization applied
- [ ] Sensitive fields (passwords, tokens, secrets) never returned in any response
- [ ] Response bodies reviewed for data leakage — no internal IDs or system details
- [ ] Pagination cursors are opaque — do not reveal internal DB row ordering
- [ ] Cache-Control headers set correctly — no sensitive data cached by CDN or proxy

---

## CSRF and Cross-Origin

- [ ] CSRF protection on all state-mutating browser-accessible endpoints
- [ ] SameSite=Strict cookies used for session management
- [ ] CORS origin allowlist reviewed — no wildcard on authenticated endpoints
- [ ] Access-Control-Allow-Credentials: true only where explicitly required

---

## Webhook and Third-Party Integration

- [ ] Incoming webhook signatures verified (HMAC-SHA256 with replay protection)
- [ ] Outgoing webhooks use mTLS or HMAC signing
- [ ] Third-party API keys stored in secret manager — not in code or env files
- [ ] Outbound HTTP calls have SSRF guard — private IPs and metadata endpoints blocked

---

## API Design and Documentation

- [ ] OpenAPI spec updated for all new endpoints — schema matches implementation
- [ ] Deprecated endpoints have defined removal timeline
- [ ] Health and readiness endpoints do not expose version, config, or dependency details
- [ ] Error responses use consistent structure without internal detail leakage

---

## Monitoring and Incident Response

- [ ] Security events logged: auth decisions, privilege changes, schema validation failures
- [ ] Alerting on anomalous patterns: high error rates, auth failures, unusual IP patterns
- [ ] API compromise IR playbook current and on-call contacts verified
- [ ] Distributed tracing enabled — request IDs propagated for incident investigation
