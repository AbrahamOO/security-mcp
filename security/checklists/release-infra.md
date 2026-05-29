# Infrastructure Release Security Checklist

Use before every infrastructure or IaC production release. All items must be checked or explicitly risk-accepted with a ticket and owner.

---

## All Surfaces (Required for Every Release)

- [ ] Threat model completed and reviewed by security-designated reviewer
- [ ] IaC scan passed (Checkov / tfsec / Terrascan) — no HIGH/CRITICAL findings unresolved
- [ ] Container scan passed — no CRITICAL CVEs with available fix (Trivy / Grype)
- [ ] Secrets scan clean — no credentials, tokens, or keys in IaC source
- [ ] SBOM generated for all container images in this release
- [ ] SLSA provenance attestation generated for all release artifacts
- [ ] Rollback plan documented — Terraform state backup confirmed, revert tested
- [ ] Cloud misconfiguration IR playbook updated if new attack surface introduced
- [ ] Ransomware IR playbook current if backup or storage configuration changed

---

## Network Security

- [ ] No 0.0.0.0/0 ingress rules in any firewall, security group, or network ACL
- [ ] No 0.0.0.0/0 egress rules — outbound allowlists defined
- [ ] All managed services accessed via VPC endpoints or private connectivity — no public endpoints
- [ ] Network segmentation confirmed: web tier, app tier, and data tier isolated
- [ ] WAF rules updated for any new public endpoints — OWASP rule sets active
- [ ] DDoS protection enabled on all public-facing load balancers

---

## Identity and Access Management

- [ ] IAM roles follow least privilege — no wildcard (.*) permissions granted
- [ ] No long-lived static credentials — use workload identity or short-lived tokens
- [ ] Service accounts have minimum required scope — reviewed against usage
- [ ] Admin roles require MFA and are time-limited — no standing admin access
- [ ] New IAM roles reviewed for privilege escalation paths
- [ ] IAM policy changes require two-person review in production

---

## Data Security

- [ ] Encryption at rest with CMEK/KMS for all new data stores
- [ ] No world-readable storage buckets, blobs, or object stores
- [ ] Backup configured and tested — restore tested in non-production environment
- [ ] Point-in-time recovery (PITR) enabled for critical databases
- [ ] Data classification applied to all new storage resources
- [ ] Data residency requirements met — storage region confirmed compliant

---

## Secrets Management

- [ ] All secrets stored in secret manager — not in environment variables, CI logs, or container images
- [ ] Secret rotation configured for all new credentials
- [ ] No plaintext secrets in Terraform variables or state files
- [ ] Secret access audit logging enabled
- [ ] Emergency secret rotation procedure documented and tested

---

## Infrastructure as Code Quality

- [ ] Provider and module versions pinned to exact versions — no floating ranges
- [ ] Remote Terraform state with encryption, locking, and restricted access
- [ ] OPA / Conftest policy checks integrated into CI pipeline
- [ ] Terraform plan output reviewed before apply — no unexpected resource deletions
- [ ] Drift detection configured — unauthorized changes trigger alerts within 15 minutes
- [ ] All resources tagged with owner, environment, and data classification

---

## Container and Supply Chain Security

- [ ] Base images use minimal distroless or scratch images where possible
- [ ] Container images run as non-root user
- [ ] Read-only root filesystem where possible
- [ ] Capabilities dropped — only required capabilities retained
- [ ] Image signing with cosign — signatures verified at deployment
- [ ] Admission controller enforces image policy in Kubernetes (OPA Gatekeeper / Kyverno)

---

## Observability and Audit

- [ ] Cloud audit logging enabled on all new resources — immutable retention configured
- [ ] VPC flow logs enabled for all new subnets
- [ ] SIEM forwarding configured for new log sources
- [ ] Alerting on critical events: root login, IAM changes, security group changes, public exposure
- [ ] Security event retention meets compliance requirements (12 months minimum)

---

## Compliance and Hardening

- [ ] CIS Benchmark Level 2 controls applied for affected services
- [ ] Vulnerability scanning scheduled for all new compute resources
- [ ] Patch management policy applied — OS patches within 30 days, critical within 7 days
- [ ] Intrusion detection (IDS/IPS) configured for new network paths
- [ ] Security baseline enforced via organization policy / SCP — no exceptions without approval

---

## Change Management

- [ ] Change record created with security impact assessment
- [ ] Production apply requires two-person review and approval
- [ ] Maintenance window confirmed with on-call team
- [ ] Post-deployment verification checklist completed
- [ ] Monitoring dashboards updated to include new resources

---

## Cloud-Native Hardening

- [ ] EC2/GCE instances: IMDSv2 enforced (HttpTokens=required) — IMDSv1 disabled
- [ ] S3/GCS: Block Public Access enabled at the account level — no per-bucket overrides
- [ ] S3 Object Lock (WORM) enabled on backup buckets — prevents ransomware deletion
- [ ] GCP: Workload Identity Federation used for GKE service accounts — no key files
- [ ] Azure: Managed Identity used for all compute — no client secrets in environment
- [ ] Threat detection enabled: AWS GuardDuty / GCP SCC / Azure Defender for Cloud
- [ ] Service Control Policies (SCP) or Organization Policy blocking: public S3, disabled CloudTrail, IAM * wildcards
- [ ] Cross-account IAM trust relationships reviewed — no unexpected external principals
- [ ] CloudTrail / Cloud Audit log file integrity validation enabled
- [ ] Container runtime: seccomp profile applied (RuntimeDefault or stricter)
- [ ] Container runtime: AppArmor or SELinux profile enforced — not unconfined
- [ ] Kubernetes resource limits (CPU and memory) set on all workloads — no unbounded pods

---

## Post-Quantum Readiness Gate

- [ ] All KMS keys used for SIGN_VERIFY with RSA algorithm inventoried
- [ ] CloudFront signed URLs using RSA keys with validity > 1 year flagged for migration timeline
- [ ] TLS termination points inventoried — hybrid post-quantum key exchange readiness assessed
- [ ] IAM certificate-based authentication (mTLS) using RSA 2048+ documented for migration
- [ ] NIST FIPS 203/204/205 migration plan exists for any long-lived infrastructure secrets

## Security-MCP Specific Gates

- [ ] CI security gate base/head refs confirmed — `SECURITY_GATE_BASE_REF` and `SECURITY_GATE_HEAD_REF` are NOT both set to `HEAD` (a HEAD..HEAD diff is always empty and makes the gate a no-op)
- [ ] Branch protection confirmed active on `main` — direct pushes blocked, PR reviews required, status checks (security-gate workflow) must pass before merge
- [ ] Publish workflow environment protection enabled — `environment: npm-publish` with required-reviewers configured in GitHub Settings so any maintainer cannot unilaterally trigger npm publish by pushing a `v*` tag

---

## Learning Loop Review

- [ ] `security.pattern_report` reviewed — most-frequently-recurring infrastructure findings addressed
- [ ] All CRITICAL/HIGH findings from this run recorded via `security.record_outcome`
- [ ] IAM privilege escalation paths found in previous runs confirmed still blocked

## Cross-Checklist Dependencies

- [ ] Infrastructure runs containerized workloads? → Kubernetes/Docker security section required
- [ ] Infrastructure serves AI/LLM workloads? → `release-ai.md` access controls and model endpoints also verified
- [ ] Infrastructure handles payment processing? → `release-payments.md` network segmentation also completed
