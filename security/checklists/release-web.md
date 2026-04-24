# Web Release Security Checklist

Use before every web production release. All items must be checked or explicitly risk-accepted with a ticket and owner.

---

## All Surfaces (Required for Every Release)

- [ ] Threat model completed and reviewed by security-designated reviewer
- [ ] SAST scan results reviewed — all CRITICAL/HIGH findings resolved or risk-accepted with ticket
- [ ] SCA scan clean — no CRITICAL CVEs in dependencies; HIGH CVEs triaged and scheduled
- [ ] Secrets scan clean (Gitleaks / Trufflehog) — no credentials, tokens, or keys in source
- [ ] IaC scan — no HIGH/CRITICAL misconfigurations (Checkov / tfsec)
- [ ] Container scan — no CRITICAL CVEs with available fix (Trivy / Grype)
- [ ] SBOM generated for this release artifact
- [ ] Error messages reviewed — no stack traces, schema details, or internal paths
- [ ] Logging reviewed — all required events logged; no PII, secrets, or tokens in logs
- [ ] Dependencies reviewed for new CVEs introduced by this change
- [ ] Rollback plan documented and tested (can revert within 15 minutes)
- [ ] IR playbook updated if a new attack surface was introduced

---

## Security Headers

- [ ] Content-Security-Policy: nonce-based script control — unsafe-inline and unsafe-eval absent
- [ ] Content-Security-Policy: default-src 'self' with explicit allowlists for external resources
- [ ] Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
- [ ] X-Frame-Options: DENY (or SAMEORIGIN with documented justification)
- [ ] X-Content-Type-Options: nosniff on all responses including error pages
- [ ] Referrer-Policy: strict-origin-when-cross-origin
- [ ] Permissions-Policy: camera, microphone, geolocation restricted to self or none
- [ ] Headers verified in staging with automated check (not just local dev)

---

## Cross-Site Scripting (XSS) Prevention

- [ ] dangerouslySetInnerHTML absent OR sanitized with proven HTML sanitizer (DOMPurify)
- [ ] No inline JavaScript or inline event handlers (onclick, onload, onerror, etc.)
- [ ] All user-supplied data escaped before rendering — confirmed in server-side templates
- [ ] CSP nonce strategy implemented for dynamic scripts
- [ ] Subresource Integrity (SRI) on all third-party scripts and stylesheets
- [ ] eval(), Function(), setTimeout(string) patterns absent from codebase

---

## Authentication and Session Management

- [ ] Session tokens are HttpOnly, Secure, SameSite=Strict cookies — not localStorage
- [ ] Session expiry: access tokens max 15 minutes, refresh tokens rotated on use
- [ ] Login rate limiting (max 5 failures per IP per minute with progressive lockout)
- [ ] Account lockout policy in place — alerts on brute-force patterns
- [ ] Password reset flow does not leak account existence (same response for valid/invalid email)
- [ ] Multi-factor authentication enforced for privileged users

---

## CSRF Protection

- [ ] CSRF protection on all state-changing endpoints (SameSite cookies + CSRF tokens)
- [ ] Origin and Referer headers validated for browser contexts
- [ ] CSRF tests added for all new state-changing routes
- [ ] Webhook endpoints validate HMAC-SHA256 signatures with replay protection

---

## CORS Configuration

- [ ] CORS origin allowlist reviewed — no wildcard on authenticated endpoints
- [ ] Access-Control-Allow-Credentials: true only where explicitly required
- [ ] CORS preflight responses do not expose sensitive headers

---

## Input Validation and Output Encoding

- [ ] Server-side schema validation on all new inputs (Zod / Valibot / Yup)
- [ ] Allowlist validation (not blocklist) for all user-controlled data
- [ ] File upload restrictions: type, size, name validation — stored outside web root
- [ ] Redirect targets validated against allowlist — no open redirects
- [ ] Request size limits enforced — no unbounded body parsing

---

## SSRF Prevention

- [ ] SSRF guard on all server-side HTTP clients — blocks private IPs and metadata endpoints
- [ ] URL allowlist enforced for all outbound calls
- [ ] Tests cover: 127.0.0.1, 10/8, 172.16/12, 192.168/16, 169.254.169.254

---

## Dependency and Supply Chain

- [ ] All dependencies pinned to exact versions or hash-locked
- [ ] No new dependencies added without security review
- [ ] No abandoned packages (no releases in 2+ years)
- [ ] CISA KEV cross-check completed for all dependency CVEs
- [ ] npm audit run and results reviewed

---

## Infrastructure and Deployment

- [ ] Staging environment mirrors production configuration
- [ ] No debug mode or verbose logging in production build
- [ ] Environment variables not embedded in client-side bundle
- [ ] Source maps not exposed in production
- [ ] Feature flags for new sensitive features default to OFF

---

## Monitoring and Incident Response

- [ ] Security events logged: auth failures, privilege changes, admin actions
- [ ] Alerting configured for anomalous patterns (more than 10 auth failures per minute)
- [ ] Web compromise IR playbook updated if new attack surface introduced
- [ ] On-call rotation confirmed with contact details current

---

## Advanced Browser Security

- [ ] Cross-Origin-Opener-Policy (COOP): same-origin set — prevents cross-origin window access
- [ ] Cross-Origin-Embedder-Policy (COEP): require-corp set where SharedArrayBuffer is used
- [ ] Cross-Origin-Resource-Policy (CORP): same-origin or same-site on all API responses
- [ ] Trusted Types policy enforced via CSP (require-trusted-types-for 'script') — DOM XSS sinks covered
- [ ] All `document.write()`, `innerHTML`, `insertAdjacentHTML`, `eval()` DOM sinks audited
- [ ] `postMessage` handlers validate `event.origin` against an explicit allowlist
- [ ] Subdomain takeover DNS audit completed — no dangling CNAME records pointing to unprovisioned services

---

## HTTP Request Smuggling Prevention

- [ ] Proxy and origin server normalize conflicting Content-Length / Transfer-Encoding headers
- [ ] H2C (HTTP/2 cleartext) upgrade disabled at the reverse proxy layer
- [ ] Backend rejects requests with both CL and TE headers simultaneously
- [ ] Load balancer / CDN keeps-alive behavior reviewed against origin HTTP version

---

## Regression and Coverage

- [ ] Regression gate: all CRITICAL/HIGH findings from previous security reviews verified still fixed
- [ ] Coverage-gap disclosure: documented what this scan CANNOT catch (runtime behavior, business logic, third-party libraries)
