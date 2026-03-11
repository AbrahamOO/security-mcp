import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { runPrGate } from "../gate/policy.js";
import { readFileSafe } from "../repo/fs.js";
import { searchRepo } from "../repo/search.js";
import { createReviewAttestation, createReviewRun, readReviewRun, updateReviewStep } from "../review/store.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "../..");
const PROMPTS_DIR = join(PKG_ROOT, "prompts");

// Load the generalized security prompt at startup.
// Falls back to a short notice if the file has not been built yet.
function loadPromptFile(name: string): string {
  const path = join(PROMPTS_DIR, name);
  if (existsSync(path)) {
    return readFileSync(path, "utf-8");
  }
  return `[security-mcp] Prompt file not found: ${name}. Run "npm run build" from the package root.`;
}

const SECURITY_PROMPT = loadPromptFile("SECURITY_PROMPT.md");

const server = new McpServer({
  name: "security-mcp",
  version: "1.0.0"
});
const tool = server.tool.bind(server) as (...args: unknown[]) => void;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function asTextResponse(data: unknown) {
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  return { content: [{ type: "text" as const, text }] };
}

/**
 * Wraps a tool handler so that unhandled exceptions never leak internal paths,
 * stack traces, or system details back to the MCP caller. CWE-209.
 */
function safeTool(
  handler: (args: unknown, extra: unknown) => Promise<ReturnType<typeof asTextResponse>>
): (args: unknown, extra: unknown) => Promise<ReturnType<typeof asTextResponse>> {
  return async (args, extra) => {
    try {
      return await handler(args, extra);
    } catch (err) {
      // Return only the sanitized message — never the stack or internal path.
      const msg = err instanceof Error ? err.message : "An internal error occurred";
      return asTextResponse(`[security-mcp error] ${msg}`);
    }
  };
}

// ---------------------------------------------------------------------------
// Review workflow
// ---------------------------------------------------------------------------

const ReviewRunIdParam = {
  runId: z.string().uuid().optional().describe("Optional security review run ID created by security.start_review.")
};

const StartReviewParams = {
  mode: z.enum(["recent_changes", "folder_by_folder", "file_by_file"]).describe(
    "Required scan scope mode for this review."
  ),
  targets: z.array(z.string()).optional().describe(
    "Required for folder_by_folder and file_by_file modes. Relative folders/files to evaluate."
  ),
  baseRef: z.string().optional().describe("Only for recent_changes mode. Base git ref, default origin/main."),
  headRef: z.string().optional().describe("Only for recent_changes mode. Head git ref, default HEAD.")
};
const StartReviewSchema = z.object(StartReviewParams);

tool(
  "security.start_review",
  "Start a stateful security review run, lock the scan mode, and return a run ID for ordered execution and attestation.",
  StartReviewParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { mode, targets, baseRef, headRef } = StartReviewSchema.parse(args);
    const cleanTargets = (targets ?? []).map((target) => target.trim()).filter(Boolean);
    if ((mode === "folder_by_folder" || mode === "file_by_file") && cleanTargets.length === 0) {
      throw new Error(`Mode "${mode}" requires one or more relative targets.`);
    }
    const run = await createReviewRun({ mode, targets, baseRef, headRef });
    await updateReviewStep(run.id, "scan_strategy", "completed", {
      mode,
      targets: cleanTargets,
      baseRef: baseRef ?? "origin/main",
      headRef: headRef ?? "HEAD"
    });

    return asTextResponse({
      runId: run.id,
      mode,
      targets: cleanTargets,
      baseRef: baseRef ?? "origin/main",
      headRef: headRef ?? "HEAD",
      requiredSteps: run.requiredSteps,
      nextSteps: [
        "Run security.threat_model with this runId.",
        "Run security.checklist with this runId.",
        "Run security.run_pr_gate with this runId.",
        "Run security.attest_review after remediation is complete."
      ]
    });
  })
);

const AttestReviewParams = {
  runId: z.string().uuid().describe("Security review run ID."),
  signatureEnvVar: z.string().optional().describe(
    "Optional environment variable containing an HMAC key for attestation signing."
  )
};
const AttestReviewSchema = z.object(AttestReviewParams);

tool(
  "security.attest_review",
  "Generate a security review attestation with integrity hash and optional HMAC signature.",
  AttestReviewParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { runId, signatureEnvVar } = AttestReviewSchema.parse(args);
    const run = await readReviewRun(runId);
    const required = new Set(run.requiredSteps);
    const completed = Array.from(required).filter((step) => {
      const status = run.steps[step]?.status;
      return status === "completed" || status === "approved";
    });
    const missing = Array.from(required).filter((step) => !completed.includes(step));
    const latestGate = run.steps["run_pr_gate"]?.details ?? {};
    const payload = {
      runId: run.id,
      createdAt: run.createdAt,
      updatedAt: run.updatedAt,
      mode: run.mode,
      targets: run.targets,
      steps: run.steps,
      coverage: {
        required: Array.from(required),
        completed,
        missing
      },
      latestGate
    };
    const signatureKey = signatureEnvVar ? process.env[signatureEnvVar] : undefined;
    const attestation = await createReviewAttestation(runId, payload, signatureKey);

    return asTextResponse({
      attestationPath: attestation.path,
      sha256: attestation.sha256,
      ...(attestation.hmacSha256 ? { hmacSha256: attestation.hmacSha256 } : {}),
      completedSteps: completed,
      missingSteps: missing,
      confidence: (latestGate as Record<string, unknown>)["confidence"] ?? null
    });
  })
);

// ---------------------------------------------------------------------------
// Existing tools
// ---------------------------------------------------------------------------

const RunPrGateParams = {
  ...ReviewRunIdParam,
  mode: z.enum(["recent_changes", "folder_by_folder", "file_by_file"]).optional().describe(
    "Scan scope mode. recent_changes (default) uses git diff; folder_by_folder scans one or more folders; file_by_file scans explicit files."
  ),
  targets: z.array(z.string()).optional().describe(
    "Required for folder_by_folder and file_by_file modes. Relative folders/files to evaluate."
  ),
  baseRef: z.string().optional().describe("Base git ref for diff (e.g. origin/main). Optional."),
  headRef: z.string().optional().describe("Head git ref for diff (e.g. HEAD). Optional."),
  policyPath: z.string().optional().describe("Override policy path. Default: .mcp/policies/security-policy.json")
};
const RunPrGateSchema = z.object(RunPrGateParams);

tool(
  "security.run_pr_gate",
  "Run the security policy gate for recent changes, selected folders, or selected files. Returns PASS/FAIL plus findings and required actions.",
  RunPrGateParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { runId, mode, targets, baseRef, headRef, policyPath } = RunPrGateSchema.parse(args);
    if (!runId) {
      return asTextResponse({
        requires_run_id: true,
        question: "Start the review with security.start_review before running the gate.",
        next_step: "Call security.start_review, then re-run security.run_pr_gate with the returned runId."
      });
    }
    const result = await runPrGate({
      mode,
      targets,
      baseRef,
      headRef,
      policyPath: policyPath ?? ".mcp/policies/security-policy.json"
    });
    await updateReviewStep(runId, "run_pr_gate", "completed", {
      status: result.status,
      confidence: result.confidence,
      findings: result.findings.map((finding) => ({ id: finding.id, severity: finding.severity })),
      suppressedFindings: result.suppressedFindings?.map((entry) => ({
        id: entry.finding.id,
        exceptionId: entry.exceptionId
      })) ?? []
    });
    return asTextResponse(result);
  })
);

const ReadFileParams = {
  path: z.string().describe("Relative path in the repo.")
};
const ReadFileSchema = z.object(ReadFileParams);

tool(
  "repo.read_file",
  "Read a file from the repo workspace.",
  ReadFileParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { path } = ReadFileSchema.parse(args);
    const data = await readFileSafe(path);
    return asTextResponse(data);
  })
);

const SearchParams = {
  query: z.string().describe("Plain string or regex pattern."),
  isRegex: z.boolean().optional().describe("Treat query as regex. Default false."),
  maxMatches: z.number().int().min(1).max(500).optional().describe("Default 200.")
};
const SearchSchema = z.object(SearchParams);

tool(
  "repo.search",
  "Search the repo for a regex or string. Returns matches with file + line numbers.",
  SearchParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { query, isRegex, maxMatches } = SearchSchema.parse(args);
    const matches = await searchRepo({ query, isRegex: !!isRegex, maxMatches: maxMatches ?? 200 });
    return asTextResponse(matches);
  })
);

// ---------------------------------------------------------------------------
// New tool: security.get_system_prompt
// ---------------------------------------------------------------------------

const GetSystemPromptParams = {
  stack: z.string().optional().describe(
    "Your tech stack, e.g. 'Next.js, TypeScript, PostgreSQL, AWS Lambda'. " +
    "Appended as a Scope section to the prompt."
  ),
  cloud: z.string().optional().describe(
    "Primary cloud provider(s), e.g. 'AWS', 'GCP', 'Azure', 'multi-cloud'."
  ),
  payment_processor: z.string().optional().describe(
    "Payment processor in use, e.g. 'Stripe', 'Braintree', 'Adyen', or 'none'."
  )
};
const GetSystemPromptSchema = z.object(GetSystemPromptParams);

tool(
  "security.get_system_prompt",
  "Return the full security engineering system prompt. Optionally customized with your stack, cloud provider, and payment processor. Use this as the system prompt to configure Claude as an elite security engineer for your project.",
  GetSystemPromptParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { stack, cloud, payment_processor } = GetSystemPromptSchema.parse(args);

    let prompt = SECURITY_PROMPT;

    // Append a project-specific scope section if any context was provided
    if (stack ?? cloud ?? payment_processor) {
      const scopeLines: string[] = [
        "",
        "---",
        "",
        "## PROJECT SCOPE (user-defined)",
        ""
      ];
      if (stack) scopeLines.push(`- **Stack**: ${stack}`);
      if (cloud) scopeLines.push(`- **Primary cloud**: ${cloud}`);
      if (payment_processor) scopeLines.push(`- **Payment processor**: ${payment_processor}`);
      scopeLines.push("");
      prompt = prompt + scopeLines.join("\n");
    }

    return asTextResponse(prompt);
  })
);

// ---------------------------------------------------------------------------
// New tool: security.threat_model
// ---------------------------------------------------------------------------

const ThreatModelParams = {
  ...ReviewRunIdParam,
  feature: z.string().describe(
    "One or two sentences describing the feature or component to threat-model. " +
    "Example: 'OAuth 2.0 login flow with PKCE and session cookies'."
  ),
  surfaces: z.array(
    z.enum(["web", "api", "mobile", "ai", "infra", "data"])
  ).optional().describe("Attack surfaces involved. Defaults to all.")
};
const ThreatModelSchema = z.object(ThreatModelParams);

tool(
  "security.threat_model",
  "Generate a STRIDE + PASTA + ATT&CK threat model template for a described feature or component. Returns a structured Markdown document ready to fill in.",
  ThreatModelParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { runId, feature, surfaces } = ThreatModelSchema.parse(args);
    const surfaceList = surfaces ?? ["web", "api", "mobile", "ai", "infra", "data"];

    const template = `# Threat Model: ${feature}

**Date**: ${new Date().toISOString().slice(0, 10)}
**Status**: DRAFT
**Surfaces**: ${surfaceList.join(", ")}

---

## 1. Asset Inventory

| Asset | Sensitivity | Owner |
|---|---|---|
| _e.g. User session tokens_ | HIGH | |
| _e.g. PII records_ | CRITICAL | |

## 2. Trust Boundaries

List every point where the trust level changes (e.g. browser -> API server, API -> DB, service A -> service B).

- [ ] Boundary 1:
- [ ] Boundary 2:

## 3. Data Flow Diagram (DFD)

Describe Level 0 (context) and Level 1 (process) flows in prose or embed a diagram link.

## 4. STRIDE Analysis

| Component | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation of Privilege |
|---|---|---|---|---|---|---|
| _component_ | | | | | | |

## 5. PASTA Risk Assessment

**Stage 1 - Business objectives at risk**:

**Stage 2 - Technical scope**:

**Stage 3 - Application decomposition** (key entry points, APIs, data stores):

**Stage 4 - Threat analysis** (attacker profile, motivation):

**Stage 5 - Vulnerability analysis**:

**Stage 6 - Attack modeling** (attack trees for top 3 risks):

**Stage 7 - Risk and impact analysis**:

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Applicable? | D3FEND Countermeasure |
|---|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | | |
| Credential Access | T1110 | Brute Force | | |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | | |
| Collection | T1530 | Data from Cloud Storage | | |

## 7. Controls

### Preventive
- [ ]

### Detective
- [ ]

### Corrective / Recovery
- [ ]

### Compensating (if primary control is not feasible)
- [ ]

## 8. NIST 800-53 Control Mapping

| Control ID | Control Name | Implemented? | Evidence |
|---|---|---|---|
| AC-3 | Access Enforcement | | |
| AU-2 | Event Logging | | |
| SC-8 | Transmission Confidentiality and Integrity | | |
| SI-10 | Information Input Validation | | |

## 9. Residual Risks

| Risk | Likelihood | Impact | Owner | Review Date | Acceptance Rationale |
|---|---|---|---|---|---|
| | | | | | |

## 10. Security Test Cases (from threat model)

| Test ID | Threat | Test Scenario | Expected Result | Status |
|---|---|---|---|---|
| TM-001 | | | | PENDING |

## 11. Pre-Release Checklist (Section 22E)

- [ ] Threat model reviewed by security-designated reviewer
- [ ] All SAST/SCA/IaC/container scan gates pass
- [ ] Auth and authorization logic reviewed
- [ ] Secrets handling reviewed - no hardcoded secrets
- [ ] Input validation present on all new inputs (server-side confirmed)
- [ ] Error messages reviewed - no information leakage
- [ ] Logging confirmed - required events logged, no PII in logs
- [ ] Security headers verified in staging
- [ ] Rate limiting confirmed on all new endpoints
- [ ] CORS configuration reviewed
- [ ] Dependencies reviewed for new CVEs
- [ ] Network rules reviewed - no 0.0.0.0/0, all traffic via private paths
- [ ] IR playbook updated if new attack surface introduced
- [ ] Compliance requirements addressed and documented
`;

    if (runId) {
      await updateReviewStep(runId, "threat_model", "completed", {
        feature,
        surfaces: surfaceList
      });
    }

    return asTextResponse(template);
  })
);

// ---------------------------------------------------------------------------
// New tool: security.checklist
// ---------------------------------------------------------------------------

const ChecklistParams = {
  ...ReviewRunIdParam,
  surface: z.enum(["web", "api", "mobile", "ai", "infra", "payments", "all"]).optional()
    .describe("Filter checklist by attack surface. Default: all.")
};
const ChecklistSchema = z.object(ChecklistParams);

const CHECKLIST_ALL = `# Pre-Release Security Checklist

Use before every production release. All items must be checked or explicitly risk-accepted.

## All Surfaces

- [ ] Threat model completed and reviewed by security-designated reviewer
- [ ] SAST scan results reviewed - all CRITICAL/HIGH findings resolved
- [ ] SCA scan - no CRITICAL CVEs in dependencies; HIGH CVEs triaged
- [ ] Secrets scan clean (Trufflehog / Gitleaks)
- [ ] IaC scan - no HIGH/CRITICAL misconfigurations (Checkov / tfsec)
- [ ] Container scan - no CRITICAL CVEs with available fix (Trivy / Grype)
- [ ] Error messages reviewed - no stack traces, schema details, or enum leakage
- [ ] Logging reviewed - all required events logged; no PII, secrets, or tokens in logs
- [ ] Dependencies reviewed for new CVEs introduced by this change
- [ ] SBOM generated for this release artifact
- [ ] Rollback plan documented and tested
- [ ] IR playbook updated if a new attack surface was introduced

## Web / Frontend

- [ ] Content-Security-Policy header present with nonce-based script control (no unsafe-inline)
- [ ] HSTS header with includeSubDomains and preload
- [ ] X-Frame-Options: DENY
- [ ] X-Content-Type-Options: nosniff
- [ ] Referrer-Policy: strict-origin-when-cross-origin
- [ ] Permissions-Policy set
- [ ] No inline JavaScript or inline event handlers
- [ ] Subresource Integrity (SRI) on any third-party scripts
- [ ] CSRF protection on all state-changing endpoints
- [ ] XSS: no dangerouslySetInnerHTML without sanitization

## API

- [ ] All new endpoints require authentication (JWT RS256/ES256 validated)
- [ ] Authorization checked server-side for every resource operation (IDOR prevention)
- [ ] Input validation present on all new inputs - server-side schema validation confirmed
- [ ] Rate limiting configured on all new endpoints
- [ ] CORS origin allowlist reviewed (no wildcard on authenticated endpoints)
- [ ] Request size limits enforced
- [ ] SSRF protection on any server-side HTTP client (block private IPs, metadata endpoints)
- [ ] Webhook signatures verified (HMAC-SHA256 + replay protection)
- [ ] OpenAPI spec updated

## Infrastructure / Cloud

- [ ] No 0.0.0.0/0 ingress or egress rules in any firewall / security group
- [ ] All managed services accessed via VPC endpoints / private connectivity
- [ ] No world-readable storage buckets
- [ ] Secrets stored in secret manager - not in env files, CI logs, or container images
- [ ] IAM roles follow least privilege - no wildcard permissions
- [ ] Network segmentation reviewed (web tier, app tier, data tier isolated)
- [ ] WAF rules updated if new public endpoints added
- [ ] Cloud audit logging confirmed for new resources

## Mobile

- [ ] iOS: NSAllowsArbitraryLoads is false (ATS enforced)
- [ ] Android: android:debuggable="false" in release build
- [ ] Android: cleartext traffic disabled (usesCleartextTraffic="false")
- [ ] Certificate pinning verified for high-value API calls
- [ ] Sensitive data not stored in shared preferences or external storage

## AI / LLM

- [ ] All AI inputs sanitized and validated
- [ ] System prompt structurally separated from user content (no string concatenation)
- [ ] Indirect prompt injection: retrieved context (RAG, external data) treated as untrusted
- [ ] Model outputs validated against JSON schema before acting on them
- [ ] Output PII scan: no SSN, card numbers, tokens in model responses
- [ ] AI endpoints rate-limited independently from regular API
- [ ] Model access logging enabled (user, timestamp, token counts)
- [ ] Red-team test cases executed and results reviewed

## Payments (PCI DSS 4.0)

- [ ] No card numbers, CVV, or PAN in any log, database, cache, or error message
- [ ] Stripe / payment processor webhook verified (HMAC-SHA256)
- [ ] PCI scope clearly defined and documented
- [ ] Payment-adjacent systems network-segmented from non-payment systems
- [ ] Audit trail maintained for all payment operations
`;

tool(
  "security.checklist",
  "Return the pre-release security checklist, optionally filtered by attack surface (web, api, mobile, ai, infra, payments, all).",
  ChecklistParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { runId, surface } = ChecklistSchema.parse(args);

    if (!surface || surface === "all") {
      if (runId) {
        await updateReviewStep(runId, "checklist", "completed", { surface: "all" });
      }
      return asTextResponse(CHECKLIST_ALL);
    }

    // Extract the relevant section
    const sectionMap: Record<string, string> = {
      web: "## Web / Frontend",
      api: "## API",
      infra: "## Infrastructure / Cloud",
      mobile: "## Mobile",
      ai: "## AI / LLM",
      payments: "## Payments (PCI DSS 4.0)"
    };

    const header = sectionMap[surface];
    const lines = CHECKLIST_ALL.split("\n");
    const start = lines.findIndex((l) => l === header);

    if (start === -1) {
      return asTextResponse(CHECKLIST_ALL);
    }

    // Include "All Surfaces" section + the requested section
    const allSurfacesEnd = lines.findIndex((l, i) => i > 0 && l.startsWith("## ") && l !== "## All Surfaces");
    const allSurfaces = lines.slice(0, allSurfacesEnd).join("\n");
    const sectionEnd = lines.findIndex((l, i) => i > start + 1 && l.startsWith("## "));
    const section = lines.slice(start, sectionEnd === -1 ? undefined : sectionEnd).join("\n");

    if (runId) {
      await updateReviewStep(runId, "checklist", "completed", { surface });
    }

    return asTextResponse(`# Pre-Release Security Checklist (${surface})\n\n${allSurfaces}\n\n${section}`);
  })
);

// ---------------------------------------------------------------------------
// New tool: security.generate_policy
// ---------------------------------------------------------------------------

const GeneratePolicyParams = {
  surfaces: z.array(
    z.enum(["web", "api", "mobile", "ai", "infra"])
  ).optional().describe("Active surfaces in your project. Determines which gate requirements are included."),
  cloud: z.enum(["gcp", "aws", "azure", "multi", "none"]).optional()
    .describe("Primary cloud provider. Adjusts cloud-specific evidence expectations.")
};
const GeneratePolicySchema = z.object(GeneratePolicyParams);

tool(
  "security.generate_policy",
  "Generate a security-policy.json for your project based on your active surfaces and cloud provider. Save the output to .mcp/policies/security-policy.json.",
  GeneratePolicyParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { surfaces, cloud } = GeneratePolicySchema.parse(args);
    const activeSurfaces = surfaces ?? ["web", "api", "infra"];

    const requirements: Array<{ id: string; type: string; evidence: string[] }> = [
      { id: "ZERO_TRUST", type: "gate", evidence: ["deny_by_default_authz", "service_to_service_auth"] },
      { id: "SECRET_MANAGER_ONLY", type: "gate", evidence: ["no_hardcoded_secrets", "secret_manager_refs"] },
      { id: "TLS_13", type: "gate", evidence: ["tls_config_verified"] }
    ];

    if (activeSurfaces.includes("web") || activeSurfaces.includes("api")) {
      requirements.push({ id: "CSP_NO_INLINE", type: "gate", evidence: ["security_headers_present"] });
      requirements.push({ id: "CSRF", type: "gate", evidence: ["csrf_protection_present", "csrf_tests_present"] });
      requirements.push({ id: "SSRF", type: "gate", evidence: ["ssrf_guard_present", "ssrf_tests_present"] });
    }

    if (activeSurfaces.includes("mobile")) {
      requirements.push({
        id: "MOBILE_MASVS",
        type: "gate",
        evidence: ["ios_ats_strict", "android_nsc_strict", "release_not_debuggable"]
      });
    }

    if (activeSurfaces.includes("ai")) {
      requirements.push({
        id: "AI_BOUNDED_OUTPUTS",
        type: "gate",
        evidence: ["json_schema_validation", "tool_allowlist_router"]
      });
    }

    const onChanges = ["src/**", "api/**"];
    if (activeSurfaces.includes("infra")) onChanges.push("infra/**", "terraform/**", "k8s/**");
    if (activeSurfaces.includes("mobile")) onChanges.push("ios/**", "android/**");
    if (activeSurfaces.includes("ai")) onChanges.push("ai/**");

    const policy = {
      name: "security-policy",
      version: "1.0.0",
      required_checks: {
        secrets_scan: { severity_block: ["HIGH", "CRITICAL"] },
        dependency_scan: { severity_block: ["CRITICAL"] },
        sast: { severity_block: ["CRITICAL"] },
        ...(activeSurfaces.includes("infra") ? { iac_scan: { severity_block: ["HIGH", "CRITICAL"] } } : {})
      },
      requirements,
      artifacts_required: [
        {
          pattern: "security/threat-models/*.md",
          on_changes: onChanges
        }
      ],
      exceptions: {
        require_ticket: true,
        approval_roles: ["SecurityLead", "GRC", "CTO"]
      },
      _meta: {
        generated_by: "security-mcp",
        surfaces: activeSurfaces,
        cloud: cloud ?? "unspecified"
      }
    };

    const comment =
      "// Save this to .mcp/policies/security-policy.json and customize as needed.\n" +
      "// See https://github.com/AbrahamOO/security-mcp for full documentation.\n\n";

    return asTextResponse(comment + JSON.stringify(policy, null, 2));
  })
);

// ---------------------------------------------------------------------------
// New tool: security.scan_strategy
// ---------------------------------------------------------------------------

const ScanStrategyParams = {
  ...ReviewRunIdParam,
  mode: z.enum(["folder_by_folder", "file_by_file", "recent_changes"]).optional().describe(
    "Required scan mode. Ask the user to choose before starting review."
  ),
  targets: z.array(z.string()).optional().describe(
    "Required for folder_by_folder and file_by_file. Relative folders/files to evaluate."
  ),
  baseRef: z.string().optional().describe("Only for recent_changes mode. Base git ref, default origin/main."),
  headRef: z.string().optional().describe("Only for recent_changes mode. Head git ref, default HEAD.")
};
const ScanStrategySchema = z.object(ScanStrategyParams);

tool(
  "security.scan_strategy",
  "Create an exhaustive security scan plan and enforce a required user choice: folder_by_folder, file_by_file, or recent_changes.",
  ScanStrategyParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { runId, mode, targets, baseRef, headRef } = ScanStrategySchema.parse(args);

    if (!mode) {
      return asTextResponse({
        required_user_decision: true,
        question: "Choose scan mode before running security checks.",
        options: ["folder_by_folder", "file_by_file", "recent_changes"],
        next_step: "Call security.scan_strategy again with the selected mode."
      });
    }

    const cleanTargets = (targets ?? []).map((t) => t.trim()).filter(Boolean);
    if ((mode === "folder_by_folder" || mode === "file_by_file") && cleanTargets.length === 0) {
      return asTextResponse({
        required_user_decision: true,
        question: `Mode "${mode}" requires explicit targets. Provide relative ${mode === "folder_by_folder" ? "folders" : "files"}.`,
        next_step: "Call security.scan_strategy with mode + targets."
      });
    }

    const frameworkCoverage = {
      threat_modeling: ["STRIDE", "PASTA", "LINDDUN", "DREAD", "ATT&CK Navigator", "Attack Trees", "TRIKE"],
      appsec_and_adversary: [
        "OWASP Top 10 (Web/API)",
        "OWASP ASVS L2/L3",
        "OWASP MASVS",
        "MITRE ATT&CK",
        "MITRE D3FEND",
        "MITRE CAPEC",
        "MITRE ATLAS"
      ],
      governance_and_compliance: [
        "NIST 800-53 Rev5",
        "NIST CSF 2.0",
        "NIST 800-207 (Zero Trust)",
        "NIST 800-218 (SSDF)",
        "PCI DSS 4.0",
        "SOC 2 Type II",
        "ISO 27001/27002/42001",
        "GDPR/CCPA"
      ],
      pipeline_controls: [
        "SAST",
        "SCA",
        "Secrets Scanning",
        "IaC Scanning",
        "Container Scanning",
        "DAST",
        "SBOM + Provenance"
      ]
    };

    const runGateTemplate =
      mode === "recent_changes"
        ? {
            tool: "security.run_pr_gate",
            args: {
              mode: "recent_changes",
              baseRef: baseRef ?? "origin/main",
              headRef: headRef ?? "HEAD"
            }
          }
        : {
            tool: "security.run_pr_gate",
            args: {
              mode,
              targets: cleanTargets
            }
          };

    if (runId) {
      await updateReviewStep(runId, "scan_strategy", "completed", {
        mode,
        targets: cleanTargets,
        baseRef: baseRef ?? "origin/main",
        headRef: headRef ?? "HEAD"
      });
    }

    return asTextResponse({
      decision_confirmed: true,
      mode,
      targets: cleanTargets,
      git_range: mode === "recent_changes" ? { baseRef: baseRef ?? "origin/main", headRef: headRef ?? "HEAD" } : null,
      execution_plan: [
        "1) Inventory scope and adjacent blast radius components.",
        "2) Run threat model coverage (STRIDE + PASTA + ATT&CK + D3FEND).",
        "3) Run policy gate + static/dynamic/IaC/container/security checks.",
        "4) Map findings to OWASP/NIST/PCI/SOC2/ISO controls.",
        "5) Apply code/config fixes immediately and re-run gate until PASS.",
        "6) Produce residual-risk register with owner, date, and review cadence."
      ],
      framework_coverage: frameworkCoverage,
      run_gate_template: runGateTemplate,
      completion_rule: "No section is complete until all required controls are either implemented or formally risk-accepted."
    });
  })
);

// ---------------------------------------------------------------------------
// New tool: security.terraform_hardening_blueprint
// ---------------------------------------------------------------------------

const TerraformHardeningParams = {
  cloud: z.enum(["aws", "gcp", "azure", "multi"]).optional().describe("Target cloud platform. Default: multi."),
  criticality: z.enum(["standard", "high", "regulated"]).optional().describe("Security strictness profile."),
  environment: z.string().optional().describe("Environment name (e.g., prod, staging).")
};
const TerraformHardeningSchema = z.object(TerraformHardeningParams);

tool(
  "security.terraform_hardening_blueprint",
  "Generate an advanced Terraform hardening blueprint with secure module design, guardrails, and control mappings.",
  TerraformHardeningParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { cloud, criticality, environment } = TerraformHardeningSchema.parse(args);
    const selectedCloud = cloud ?? "multi";
    const selectedCriticality = criticality ?? "high";

    const blueprint = {
      target: { cloud: selectedCloud, criticality: selectedCriticality, environment: environment ?? "unspecified" },
      module_layout: [
        "modules/network: private subnets, no default public ingress, egress allowlists",
        "modules/identity: least-privilege IAM roles, short-lived credentials, no wildcard actions",
        "modules/data: encryption at rest with CMEK/KMS, backup + PITR, private endpoints",
        "modules/observability: audit logs + flow logs + SIEM forwarding + immutable retention",
        "modules/security: WAF, DDoS controls, threat detection, guardrail SCP/org-policies"
      ],
      mandatory_terraform_controls: [
        "Pin providers and modules to exact versions; no floating ranges.",
        "Use remote state with encryption + locking + restricted access.",
        "Enforce policy checks: Checkov/tfsec/Terrascan + OPA Conftest in CI.",
        "Block 0.0.0.0/0 ingress/egress unless explicit risk acceptance.",
        "Disable public object storage by default.",
        "Require tags/labels for owner, data classification, and environment.",
        "Enable cloud audit logging on every managed resource."
      ],
      secure_cicd_flow: [
        "terraform fmt/validate -> terraform plan -> policy checks (OPA/Checkov/tfsec) -> manual approval -> terraform apply",
        "Store plan output artifact and sign provenance before apply.",
        "Run drift detection nightly and alert on unauthorized changes."
      ],
      control_mapping: {
        nist_800_53: ["AC-3", "AC-6", "AU-2", "AU-12", "SC-7", "SC-8", "SC-12", "SI-4"],
        cis: ["CIS cloud benchmark level 2", "CIS IaC policy enforcement"],
        zero_trust: ["explicit authn/authz for service paths", "micro-segmentation", "continuous verification"]
      }
    };

    return asTextResponse(blueprint);
  })
);

// ---------------------------------------------------------------------------
// New tool: security.generate_opa_rego
// ---------------------------------------------------------------------------

const GenerateOpaRegoParams = {
  ...ReviewRunIdParam,
  policyPack: z.enum(["terraform_plan", "ci_pipeline", "kubernetes"]).optional().describe(
    "Policy pack to generate. Default: terraform_plan."
  ),
  cloud: z.enum(["aws", "gcp", "azure", "multi"]).optional().describe("Cloud context for policy wording."),
  applySuggestion: z.boolean().optional().describe(
    "Must be true before generating policy code. This forces explicit user consent."
  )
};
const GenerateOpaRegoSchema = z.object(GenerateOpaRegoParams);

tool(
  "security.generate_opa_rego",
  "Generate preventive OPA/Rego policy code for Terraform plans or CI pipelines. Requires explicit user consent first.",
  GenerateOpaRegoParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { runId, policyPack, cloud, applySuggestion } = GenerateOpaRegoSchema.parse(args);
    const selectedPack = policyPack ?? "terraform_plan";

    if (!applySuggestion) {
      return asTextResponse({
        requires_user_confirmation: true,
        question:
          "Do you want security-mcp to generate preventive OPA/Rego policies for your pipeline and Terraform plan checks?",
        next_step: "Re-run security.generate_opa_rego with applySuggestion=true."
      });
    }

    const terraformPolicy = `package security.terraform

import rego.v1

deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_security_group_rule"
  lower(rc.change.after.type) == "ingress"
  rc.change.after.cidr_blocks[_] == "0.0.0.0/0"
  msg := "deny: public ingress 0.0.0.0/0 is not allowed"
}

deny contains msg if {
  some rc in input.resource_changes
  rc.type in {"aws_s3_bucket", "google_storage_bucket", "azurerm_storage_account"}
  not is_private_storage(rc.change.after)
  msg := sprintf("deny: storage resource %s must not be public", [rc.address])
}

deny contains msg if {
  some rc in input.resource_changes
  is_data_resource(rc.type)
  not encryption_enabled(rc.change.after)
  msg := sprintf("deny: encryption at rest is required for %s", [rc.address])
}

is_private_storage(after) if {
  not after.public
}

encryption_enabled(after) if {
  after.encryption == true
}

is_data_resource(kind) if {
  kind in {"aws_db_instance", "google_sql_database_instance", "azurerm_postgresql_flexible_server"}
}`;

    const ciPolicy = `package security.cicd

import rego.v1

required_jobs := {"sast", "sca", "secrets", "iac", "container", "dast"}

deny contains msg if {
  some job in required_jobs
  not input.pipeline.jobs[job]
  msg := sprintf("deny: missing required security job '%s'", [job])
}

deny contains msg if {
  input.pipeline.context.allow_high_findings == true
  msg := "deny: pipeline cannot allow HIGH/CRITICAL findings by default"
}

deny contains msg if {
  not input.pipeline.provenance.signed
  msg := "deny: release artifacts must include signed provenance/SBOM attestations"
}`;

    const k8sPolicy = `package security.kubernetes

import rego.v1

deny contains msg if {
  input.kind == "Deployment"
  some c in input.spec.template.spec.containers
  not c.securityContext.runAsNonRoot
  msg := sprintf("deny: container '%s' must run as non-root", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some c in input.spec.template.spec.containers
  c.securityContext.privileged == true
  msg := sprintf("deny: privileged container '%s' is not allowed", [c.name])
}`;

    const policyByPack: Record<string, { path: string; policy: string; conftest_command: string }> = {
      terraform_plan: {
        path: "policy/terraform/security.rego",
        policy: terraformPolicy,
        conftest_command: "terraform show -json tfplan.binary > tfplan.json && conftest test tfplan.json -p policy/terraform"
      },
      ci_pipeline: {
        path: "policy/ci/security.rego",
        policy: ciPolicy,
        conftest_command: "conftest test pipeline-input.json -p policy/ci"
      },
      kubernetes: {
        path: "policy/kubernetes/security.rego",
        policy: k8sPolicy,
        conftest_command: "conftest test k8s-manifest.yaml -p policy/kubernetes"
      }
    };

    const selected = policyByPack[selectedPack];
    if (runId) {
      await updateReviewStep(runId, "generate_opa_rego", "approved", {
        policyPack: selectedPack,
        cloud: cloud ?? "multi"
      });
    }
    return asTextResponse({
      generated_for: { policyPack: selectedPack, cloud: cloud ?? "multi" },
      files: [selected],
      install_notes: [
        "Run this in CI before deployment apply/admission.",
        "Fail the pipeline when any deny rules are returned.",
        "Version-control the policy and require security-owner approval for policy exceptions."
      ]
    });
  })
);

// ---------------------------------------------------------------------------
// New tool: security.self_heal_loop
// ---------------------------------------------------------------------------

const SelfHealLoopParams = {
  ...ReviewRunIdParam,
  useCase: z.string().optional().describe("Short description of recurring security issues in this codebase."),
  findings: z.array(z.string()).optional().describe("Recent recurring findings or control gaps."),
  approveAdaptiveUpdates: z.boolean().optional().describe(
    "Must be true before suggesting any adaptive improvement. Human approval is mandatory."
  )
};
const SelfHealLoopSchema = z.object(SelfHealLoopParams);

tool(
  "security.self_heal_loop",
  "Propose a human-approved self-healing improvement loop for this security setup. No adaptive change may be applied without explicit human approval.",
  SelfHealLoopParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { runId, useCase, findings, approveAdaptiveUpdates } = SelfHealLoopSchema.parse(args);

    if (!approveAdaptiveUpdates) {
      return asTextResponse({
        requires_human_approval: true,
        question:
          "Do you want security-mcp to propose adaptive updates to policies/checklists based on recurring findings in your use case?",
        next_step: "Re-run security.self_heal_loop with approveAdaptiveUpdates=true."
      });
    }

    if (runId) {
      await updateReviewStep(runId, "self_heal_loop", "approved", {
        useCase: useCase ?? "unspecified"
      });
    }

    return asTextResponse({
      adaptive_security_loop: [
        "1) Capture repeated findings from gate outputs and incident reports.",
        "2) Cluster by root cause (authz gaps, IaC misconfig, secrets, AI injection, dependency risk).",
        "3) Propose updates to .mcp/policies/security-policy.json and .mcp/mappings/evidence-map.json.",
        "4) Require explicit human approval before applying any policy, prompt, or checklist mutation.",
        "5) Re-run security.run_pr_gate in the selected scan mode and compare residual risk trend."
      ],
      guardrails: [
        "No autonomous code or policy mutation without explicit human approval.",
        "No weakening of controls without signed risk acceptance metadata.",
        "Every approved adaptive update must be logged with owner, date, rationale, and rollback path."
      ],
      input_summary: {
        useCase: useCase ?? "unspecified",
        findings: findings ?? []
      }
    });
  })
);

// ---------------------------------------------------------------------------
// MCP Prompts capability
// ---------------------------------------------------------------------------

server.prompt(
  "security-engineer",
  "Activate the security-mcp system prompt. Sets up the model as an elite, threat-informed security engineer applying OWASP, MITRE ATT&CK, NIST 800-53, Zero Trust, PCI DSS, SOC 2, and ISO 27001 to every code and architecture decision.",
  async () => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: SECURITY_PROMPT
        }
      }
    ]
  })
);

server.prompt(
  "threat-model-template",
  "Generate a blank STRIDE + PASTA + MITRE ATT&CK threat model template for a feature.",
  { feature: z.string().describe("Name or brief description of the feature to threat-model.") },
  async ({ feature }: { feature: string }) => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text:
            `You are a principal security engineer. Produce a complete, filled-out STRIDE + PASTA + ` +
            `MITRE ATT&CK threat model for the following feature:\n\n**${feature}**\n\n` +
            `Use the Section 22 output format from the security-mcp system prompt: ` +
            `Threat Model, Controls (preventive/detective/corrective), Compliance Mapping, ` +
            `Residual Risks, and a Security Checklist. Be specific and actionable.`
        }
      }
    ]
  })
);

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

export async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Only auto-start when this file is the direct entry point (not imported by CLI)
const isMain = process.argv[1]?.endsWith("server.js") || process.argv[1]?.endsWith("server.ts");
if (isMain) {
  main().catch((err) => {
    console.error("MCP server crashed:", err);
    process.exit(1);
  });
}
