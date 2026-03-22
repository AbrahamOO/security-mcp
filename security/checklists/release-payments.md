# Payments Release Security Checklist (PCI DSS 4.0)

Use before every payment-related production release. All items must be checked or explicitly risk-accepted with a ticket and approved by SecurityLead.

---

## All Surfaces (Required for Every Release)

- [ ] Threat model completed covering payment fraud and PCI breach scenarios
- [ ] SAST scan results reviewed — all CRITICAL/HIGH findings resolved
- [ ] SCA scan clean — no CRITICAL CVEs in payment-related dependencies
- [ ] Secrets scan clean — no payment credentials, API keys, or private keys in source
- [ ] IaC scan — no HIGH/CRITICAL misconfigurations in payment infrastructure
- [ ] SBOM generated for this release artifact
- [ ] Rollback plan documented and tested — can revert within 15 minutes
- [ ] Payment fraud IR playbook updated
- [ ] PCI breach IR playbook updated

---

## Cardholder Data Protection (PCI DSS Req 3)

- [ ] No card numbers, CVV, or full PAN stored anywhere — tokenization confirmed
- [ ] No card data in any log, database, cache, error message, or analytics system
- [ ] No card data in URL parameters, query strings, or browser history
- [ ] Primary Account Number (PAN) masked when displayed — show only last 4 digits
- [ ] Cryptographic key management documented — keys rotated per policy
- [ ] Data retention policy enforced — cardholder data purged per schedule

---

## Network Security (PCI DSS Req 1 and 4)

- [ ] Payment-adjacent systems network-segmented from non-payment systems
- [ ] CDE (Cardholder Data Environment) boundaries clearly defined and documented
- [ ] TLS 1.2+ required on all payment data flows — no fallback to older protocols
- [ ] No cardholder data transmitted over unencrypted channels
- [ ] Firewall rules reviewed — payment systems accessible only by authorized systems
- [ ] Network diagram updated to reflect changes to CDE

---

## Authentication and Access Control (PCI DSS Req 7 and 8)

- [ ] Access to payment data restricted to minimum necessary roles — least privilege
- [ ] MFA enforced for all access to CDE and payment management consoles
- [ ] Shared or generic accounts prohibited in payment systems
- [ ] Service accounts use minimum required permissions — no admin accounts
- [ ] Access logs reviewed — no unauthorized access to cardholder data

---

## Payment Processor Integration

- [ ] Payment processing handled by PCI-compliant vendor (Stripe / Braintree / Adyen) — not custom card capture
- [ ] Vendor PCI DSS certificate of compliance reviewed and current
- [ ] Payment form hosted by processor (iFrame or redirect) — card data never touches application servers
- [ ] Stripe / payment processor webhook signatures verified (HMAC-SHA256 with replay protection)
- [ ] Webhook endpoint validates timestamp — rejects events older than 5 minutes
- [ ] Payment processor API keys stored in secret manager — not in code or environment files
- [ ] Webhook secret rotated in the last 90 days

---

## Vulnerability Management (PCI DSS Req 6)

- [ ] All payment system components scanned for vulnerabilities — results reviewed
- [ ] CRITICAL vulnerabilities remediated within 24 hours
- [ ] HIGH vulnerabilities remediated within 7 days
- [ ] Penetration test conducted within the last 12 months covering CDE scope
- [ ] Web application firewall (WAF) rules updated for new payment endpoints
- [ ] WAF in detection mode for at least 2 weeks before blocking mode for new rules

---

## Monitoring and Logging (PCI DSS Req 10)

- [ ] Complete audit trail maintained for all payment operations — tamper-evident
- [ ] Payment events logged: initiation, authorization, capture, refund, dispute
- [ ] Log entries include: timestamp, user ID, action, affected record, source IP
- [ ] Logs retained for minimum 12 months with 3 months immediately accessible
- [ ] Log integrity monitoring configured — alerts on tampering or deletion
- [ ] Security event alerting on anomalous payment patterns (velocity, geographic, amount)

---

## Anti-Fraud Controls

- [ ] Velocity checks in place — limits on transactions per card, per IP, per account
- [ ] Geographic anomaly detection configured with defined alert thresholds
- [ ] 3DS (3D Secure) enforced for high-risk transactions
- [ ] Chargeback monitoring configured with defined response process
- [ ] Fraud scoring integrated — high-risk transactions require additional verification
- [ ] Bot detection on payment endpoints — CAPTCHA or behavioral analysis active

---

## PCI DSS Requirement Coverage

- [ ] Req 1 Network Security Controls: firewall rules reviewed and segmentation confirmed
- [ ] Req 2 Secure Configurations: default credentials changed, unnecessary services disabled
- [ ] Req 3 Protect Stored Account Data: no PANs stored, tokenization confirmed
- [ ] Req 4 Protect Cardholder Data in Transit: TLS enforced on all payment flows
- [ ] Req 5 Protect Against Malicious Software: anti-malware deployed on all CDE systems
- [ ] Req 6 Develop and Maintain Secure Systems: vulnerability management up to date
- [ ] Req 7 Restrict Access by Business Need: least privilege access confirmed
- [ ] Req 8 Identify and Authenticate Access: MFA and unique IDs enforced
- [ ] Req 9 Restrict Physical Access: physical controls documented (N/A for cloud-only)
- [ ] Req 10 Log and Monitor: audit logging confirmed with required retention
- [ ] Req 11 Test Security: scans and pen tests current
- [ ] Req 12 Support Information Security with Policies: security policies reviewed

---

## Incident Response

- [ ] Payment fraud IR playbook current — tested in last 6 months
- [ ] PCI breach IR playbook current — includes QSA notification procedure
- [ ] PCI DSS breach notification timeline understood: 72 hours to card brands
- [ ] Key contacts documented: payment processor security team, acquiring bank, legal
- [ ] Tabletop exercise completed for payment breach scenario in last 12 months
