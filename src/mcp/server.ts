import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { runPrGate } from "../gate/policy.js";
import { readFileSafe } from "../repo/fs.js";
import { searchRepo } from "../repo/search.js";

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

/* eslint-disable deprecation/deprecation */
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
// Existing tools (unchanged)
// ---------------------------------------------------------------------------

const RunPrGateParams = {
  baseRef: z.string().optional().describe("Base git ref for diff (e.g. origin/main). Optional."),
  headRef: z.string().optional().describe("Head git ref for diff (e.g. HEAD). Optional."),
  policyPath: z.string().optional().describe("Override policy path. Default: .mcp/policies/security-policy.json")
};
const RunPrGateSchema = z.object(RunPrGateParams);

tool(
  "security.run_pr_gate",
  "Run the security policy gate against the current workspace. Returns PASS/FAIL plus findings and required actions.",
  RunPrGateParams as unknown as Record<string, z.ZodTypeAny>,
  safeTool(async (args: unknown, _extra: unknown) => {
    const { baseRef, headRef, policyPath } = RunPrGateSchema.parse(args);
    const result = await runPrGate({
      baseRef,
      headRef,
      policyPath: policyPath ?? ".mcp/policies/security-policy.json"
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
    const { feature, surfaces } = ThreatModelSchema.parse(args);
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

    return asTextResponse(template);
  })
);

// ---------------------------------------------------------------------------
// New tool: security.checklist
// ---------------------------------------------------------------------------

const ChecklistParams = {
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
    const { surface } = ChecklistSchema.parse(args);

    if (!surface || surface === "all") {
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
