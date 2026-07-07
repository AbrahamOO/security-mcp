/**
 * emerging-cloud.ts — 2025-era cloud / Kubernetes / IaC detections.
 *
 * This module complements the broad rule sets in iac.ts, k8s.ts and infra.ts with
 * a handful of *specific*, recently-weaponized attack surfaces. Each rule is tied
 * to a named CVE or technique and a CWE so that a non-security reader can follow
 * WHY the pattern is dangerous. The rules are deliberately narrow (tight regexes /
 * cross-signal presence checks) to keep false positives low.
 *
 * Detections implemented here:
 *   1. K8S_INGRESS_NGINX_SNIPPET_INJECTION — IngressNightmare (CVE-2025-1974, CWE-94)
 *   2. IAC_AWS_PASSROLE_PRIVESC_CHAIN      — PassRole privilege escalation (CWE-269)
 *   3. IAC_TF_MODULE_GIT_UNPINNED_REF      — unpinned git module ref (CWE-829)
 *   4. IAC_GCP_TOKEN_CREATOR_PROJECT_BINDING — project-wide token creator (CWE-269)
 *   5. K8S_RUNC_ESCAPE_DELIVERY_SURFACE    — runc escape delivery (CVE-2025-31133/
 *                                            52565/52881, CWE-59)
 *
 * Style mirrors iac.ts (searchRepo regex rules) and k8s.ts (fg + readFileSafe
 * YAML heuristics). Every code path is wrapped so malformed input never throws.
 */
import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";

// ---------------------------------------------------------------------------
// Pattern definitions. Kept well under the 500-char / no-nested-quantifier
// ReDoS guard that searchRepo enforces (see compileUserRegex in repo/search.ts).
// String.raw preserves backslashes into the regex source.
// ---------------------------------------------------------------------------

// 1. IngressNightmare — CVE-2025-1974 (CWE-94, code injection).
//    The ingress-nginx admission controller renders certain Ingress annotations
//    directly into the NGINX config template. An attacker who can create/update
//    an Ingress object can smuggle raw NGINX `configuration-snippet` /
//    `server-snippet` directives, which are executed by the controller — leading
//    to remote code execution inside the controller pod (which typically holds a
//    cluster-wide ServiceAccount able to read every Secret). Presence of these
//    annotation keys at all is the dangerous surface.
const K8S_NGINX_SNIPPET_ANNOTATION_PATTERN =
  String.raw`nginx\.ingress\.kubernetes\.io/configuration-snippet|` +
  String.raw`nginx\.ingress\.kubernetes\.io/server-snippet|` +
  String.raw`nginx\.ingress\.kubernetes\.io/stream-snippet|` +
  String.raw`nginx\.ingress\.kubernetes\.io/auth-snippet`;

// The controller image itself. We only match ingress-nginx controller images so
// we can then decide, by parsing the tag, whether the version is below the fixed
// releases (v1.11.5 / v1.12.1). Matching just the image reference is broad; the
// vulnerable-version decision is made in code from the captured tag.
const K8S_INGRESS_NGINX_IMAGE_PATTERN =
  String.raw`ingress-nginx/controller:v?\d|` +
  String.raw`registry\.k8s\.io/ingress-nginx/controller`;

// 2. PassRole privilege-escalation chain — CWE-269 (improper privilege management).
//    iam:PassRole by itself is benign, but combined with a compute/launch action
//    it lets a low-privileged principal hand a *more privileged* role to a service
//    it controls (an EC2 instance, a Lambda, an ECS task, a Glue dev endpoint, or
//    — the newer AI vector — a Bedrock AgentCore code interpreter) and then run
//    arbitrary code AS that role. This is a classic AWS privilege-escalation
//    primitive. We detect PassRole and each launch action separately and correlate.
const AWS_PASSROLE_PATTERN =
  String.raw`"iam:PassRole"|` +
  String.raw`'iam:PassRole'|` +
  String.raw`\biam:PassRole\b`;

// Launch/compute actions that turn PassRole into code execution as the passed role.
const AWS_PASSROLE_LAUNCH_PATTERN =
  String.raw`ec2:RunInstances|` +
  String.raw`lambda:CreateFunction|` +
  String.raw`ecs:RunTask|` +
  String.raw`glue:CreateDevEndpoint|` +
  String.raw`bedrock-agentcore:[A-Za-z]*CodeInterpreter`;

// Lambda escalation needs BOTH create and invoke; track InvokeFunction separately.
const AWS_LAMBDA_INVOKE_PATTERN =
  String.raw`lambda:InvokeFunction`;

// Escalation to CRITICAL: PassRole granted on Resource "*" (any role) with no
// iam:PassedToService guard. We match a wildcard PassRole resource; the absence
// of an iam:PassedToService condition anywhere is checked as a companion signal.
const AWS_PASSROLE_WILDCARD_RESOURCE_PATTERN =
  String.raw`"iam:PassRole"[\s\S]{0,200}"Resource"\s*:\s*"\*"|` +
  String.raw`"Resource"\s*:\s*"\*"[\s\S]{0,200}"iam:PassRole"|` +
  String.raw`actions\s*=\s*\[[^\]]*"iam:PassRole"[\s\S]{0,200}resources\s*=\s*\[\s*"\*"`;
const AWS_PASSED_TO_SERVICE_PATTERN =
  String.raw`iam:PassedToService`;

// 3. Unpinned git module ref — CWE-829 (inclusion of functionality from untrusted
//    control sphere). A Terraform module sourced from git without a pin to an
//    immutable 40-hex commit SHA (a branch/tag can be force-moved) means whoever
//    controls that repo can swap the module code out from under you on the next
//    `terraform init` — a remote-module supply-chain attack. We first find git
//    module sources, then in code check whether a full 40-hex ?ref= is present.
const TF_GIT_MODULE_SOURCE_PATTERN =
  String.raw`source\s*=\s*"git::https://|` +
  String.raw`source\s*=\s*"git::ssh://|` +
  String.raw`source\s*=\s*"github\.com/|` +
  String.raw`source\s*=\s*"git@github\.com`;

// 4. GCP project-level token-creator / SA-user binding — CWE-269.
//    roles/iam.serviceAccountTokenCreator lets a member mint access tokens / sign
//    JWTs for a service account; roles/iam.serviceAccountUser lets a member run
//    workloads AS a service account. Granted in a google_project_iam_* binding
//    (project scope) these apply to EVERY service account in the project, so any
//    holder can impersonate the most privileged SA in the project. The safe form
//    binds them on a single SA via google_service_account_iam_*. We match the role
//    string and correlate with the project-level binding resource.
const GCP_TOKEN_CREATOR_ROLE_PATTERN =
  String.raw`roles/iam\.serviceAccountTokenCreator|` +
  String.raw`roles/iam\.serviceAccountUser`;
const GCP_PROJECT_IAM_BINDING_PATTERN =
  String.raw`resource\s+"google_project_iam_member"|` +
  String.raw`resource\s+"google_project_iam_binding"|` +
  String.raw`resource\s+"google_project_iam_policy"`;
const GCP_SA_IAM_BINDING_PATTERN =
  String.raw`resource\s+"google_service_account_iam_member"|` +
  String.raw`resource\s+"google_service_account_iam_binding"|` +
  String.raw`resource\s+"google_service_account_iam_policy"`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Format RepoMatch-like hits into the evidence-string shape the rest of the gate
// uses. Capped so a noisy repo cannot produce an enormous finding.
function ev(m: { file: string; line: number; preview: string }[]): string[] {
  return m.slice(0, 20).map((x) => `${x.file}:${x.line}: ${x.preview}`);
}

// ingress-nginx controller is fixed in v1.11.5 (1.11.x line) and v1.12.1 (1.12.x
// line). Any 1.11.x below .5, any 1.12.x below .1, and anything below 1.11 is
// vulnerable. Parse tags like "v1.11.2", "1.12.0", "v1.10.1@sha256:...".
// Returns true only when we can confidently read a below-fix version — unknown /
// unparseable tags return false so we never fire on a version we cannot read.
function isVulnerableIngressNginxTag(line: string): boolean {
  try {
    const m = line.match(/controller:v?(\d+)\.(\d+)\.(\d+)/);
    if (!m) return false;
    const major = Number(m[1]);
    const minor = Number(m[2]);
    const patch = Number(m[3]);
    if (!Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) {
      return false;
    }
    if (major > 1) return false; // future major — assume patched
    if (major < 1) return true; // 0.x — long unsupported
    // major === 1
    if (minor < 11) return true; // 1.0–1.10 all predate the fix
    if (minor === 11) return patch < 5; // fixed in 1.11.5
    if (minor === 12) return patch < 1; // fixed in 1.12.1
    return false; // 1.13+ — assume patched
  } catch {
    return false; // never throw on odd input
  }
}

// A 40-char lowercase-hex commit SHA in a ?ref=. This is the ONLY form that pins
// a git module immutably; a branch or tag ref (?ref=main, ?ref=v1.2.3) can move.
const PINNED_SHA_REF_RE = /\?ref=[0-9a-fA-F]{40}\b/;

// ---------------------------------------------------------------------------
// Main check
// ---------------------------------------------------------------------------

export async function checkEmergingCloud(_: { changedFiles: string[] }): Promise<Finding[]> {
  void _; // signature consistency; detection scans the whole repo, not just the diff
  const findings: Finding[] = [];

  // Run all repo-wide regex searches concurrently. searchRepo itself never throws
  // on unreadable files (it skips them); a bad pattern would throw at compile
  // time, but every pattern here is a static, guard-safe constant.
  let nginxSnippet: Awaited<ReturnType<typeof searchRepo>> = [];
  let ingressImage: typeof nginxSnippet = [];
  let passRole: typeof nginxSnippet = [];
  let passRoleLaunch: typeof nginxSnippet = [];
  let lambdaInvoke: typeof nginxSnippet = [];
  let passRoleWildcard: typeof nginxSnippet = [];
  let passedToService: typeof nginxSnippet = [];
  let gitModuleSource: typeof nginxSnippet = [];
  let gcpTokenRole: typeof nginxSnippet = [];
  let gcpProjectBinding: typeof nginxSnippet = [];
  let gcpSaBinding: typeof nginxSnippet = [];

  try {
    [
      nginxSnippet,
      ingressImage,
      passRole,
      passRoleLaunch,
      lambdaInvoke,
      passRoleWildcard,
      passedToService,
      gitModuleSource,
      gcpTokenRole,
      gcpProjectBinding,
      gcpSaBinding,
    ] = await Promise.all([
      searchRepo({ query: K8S_NGINX_SNIPPET_ANNOTATION_PATTERN, isRegex: true, maxMatches: 200 }),
      searchRepo({ query: K8S_INGRESS_NGINX_IMAGE_PATTERN, isRegex: true, maxMatches: 200 }),
      searchRepo({ query: AWS_PASSROLE_PATTERN, isRegex: true, maxMatches: 200 }),
      searchRepo({ query: AWS_PASSROLE_LAUNCH_PATTERN, isRegex: true, maxMatches: 200 }),
      searchRepo({ query: AWS_LAMBDA_INVOKE_PATTERN, isRegex: true, maxMatches: 200 }),
      searchRepo({ query: AWS_PASSROLE_WILDCARD_RESOURCE_PATTERN, isRegex: true, maxMatches: 200 }),
      searchRepo({ query: AWS_PASSED_TO_SERVICE_PATTERN, isRegex: true, maxMatches: 200 }),
      searchRepo({ query: TF_GIT_MODULE_SOURCE_PATTERN, isRegex: true, maxMatches: 200 }),
      searchRepo({ query: GCP_TOKEN_CREATOR_ROLE_PATTERN, isRegex: true, maxMatches: 200 }),
      searchRepo({ query: GCP_PROJECT_IAM_BINDING_PATTERN, isRegex: true, maxMatches: 200 }),
      searchRepo({ query: GCP_SA_IAM_BINDING_PATTERN, isRegex: true, maxMatches: 200 }),
    ]);
  } catch {
    // A failure in the shared search layer must not crash the gate — degrade to
    // "no regex-based findings" rather than throw. The YAML-based runc check below
    // runs independently and can still contribute findings.
    nginxSnippet = ingressImage = passRole = passRoleLaunch = lambdaInvoke = [];
    passRoleWildcard = passedToService = gitModuleSource = [];
    gcpTokenRole = gcpProjectBinding = gcpSaBinding = [];
  }

  // 1. K8S_INGRESS_NGINX_SNIPPET_INJECTION (IngressNightmare, CVE-2025-1974).
  //    Fire when the injectable snippet annotations are present OR the controller
  //    image is a version below the fixed v1.11.5 / v1.12.1 releases.
  const vulnImageHits = ingressImage.filter((h) => isVulnerableIngressNginxTag(h.preview));
  if (nginxSnippet.length > 0 || vulnImageHits.length > 0) {
    findings.push({
      id: "K8S_INGRESS_NGINX_SNIPPET_INJECTION",
      title:
        "ingress-nginx exposes snippet-annotation config injection or runs a pre-fix controller (IngressNightmare, CVE-2025-1974)",
      severity: "CRITICAL",
      evidence: ev([...nginxSnippet, ...vulnImageHits]),
      requiredActions: [
        "IngressNightmare (CVE-2025-1974) lets anyone who can create/update an Ingress inject raw NGINX directives via configuration-snippet / server-snippet / auth-snippet annotations, achieving RCE in the controller pod — which usually holds a cluster-wide ServiceAccount that can read every Secret in the cluster.",
        "Upgrade ingress-nginx controller to v1.11.5 (1.11.x) or v1.12.1 (1.12.x) or later, which contains the fix.",
        "Disable snippet annotations cluster-wide: set `allow-snippet-annotations: \"false\"` in the ingress-nginx ConfigMap (default since the patched releases).",
        "If snippets are truly required, restrict them with `annotation-value-word-blocklist` and lock down who can create Ingress objects via RBAC.",
        "Restrict network access to the admission webhook (port 8443) so it is only reachable from the API server, not arbitrary pods.",
      ],
    });
  }

  // 2. IAC_AWS_PASSROLE_PRIVESC_CHAIN (CWE-269).
  //    PassRole + a launch/compute action = code execution as the passed role.
  //    Lambda specifically needs both CreateFunction and InvokeFunction, but any
  //    of the other launch actions alone is sufficient, so we treat the launch
  //    pattern (which already includes lambda:CreateFunction) as the trigger and
  //    surface lambda:InvokeFunction as reinforcing evidence when present.
  const hasPassRole = passRole.length > 0;
  const hasLaunch = passRoleLaunch.length > 0;
  if (hasPassRole && hasLaunch) {
    // Escalate to CRITICAL when PassRole is on Resource "*" and there is no
    // iam:PassedToService condition anywhere to constrain which service the role
    // may be handed to.
    const wildcardUnconstrained =
      passRoleWildcard.length > 0 && passedToService.length === 0;
    findings.push({
      id: "IAC_AWS_PASSROLE_PRIVESC_CHAIN",
      title:
        "IAM policy grants iam:PassRole together with a launch action (RunInstances / Lambda / ECS / Glue / Bedrock AgentCore) — privilege-escalation chain",
      severity: wildcardUnconstrained ? "CRITICAL" : "HIGH",
      evidence: ev([...passRole, ...passRoleLaunch, ...lambdaInvoke, ...passRoleWildcard]),
      requiredActions: [
        "iam:PassRole combined with a launch/compute action lets a low-privileged principal hand a more-privileged role to a resource it controls (an EC2 instance, Lambda, ECS task, Glue dev endpoint, or Bedrock AgentCore code interpreter) and then execute code AS that role — a well-known AWS privilege-escalation primitive.",
        "Scope iam:PassRole to the exact role ARN(s) the workload needs, never Resource \"*\".",
        "Add an iam:PassedToService condition so a role can only be passed to the intended service, e.g.:",
        "  \"Condition\": { \"StringEquals\": { \"iam:PassedToService\": \"ec2.amazonaws.com\" } }",
        "Grant the launch action (ec2:RunInstances / lambda:CreateFunction+InvokeFunction / ecs:RunTask / glue:CreateDevEndpoint / bedrock-agentcore:*CodeInterpreter) only where genuinely required, and never to the same principal that can pass arbitrary roles.",
        "Review escalation paths with IAM Access Analyzer and least-privilege tooling (e.g. cloudsplaining, pmapper).",
      ],
    });
  }

  // 3. IAC_TF_MODULE_GIT_UNPINNED_REF (CWE-829).
  //    A git module source is unpinned unless it carries a full 40-hex ?ref= SHA.
  //    Branch/tag refs (?ref=main, ?ref=v1.2.3) still count as unpinned because
  //    they can be force-moved by whoever controls the source repo.
  const unpinnedModuleHits = gitModuleSource.filter((h) => !PINNED_SHA_REF_RE.test(h.preview));
  if (unpinnedModuleHits.length > 0) {
    findings.push({
      id: "IAC_TF_MODULE_GIT_UNPINNED_REF",
      title:
        "Terraform git module source is not pinned to an immutable 40-char commit SHA — remote-module supply-chain risk",
      severity: "HIGH",
      evidence: ev(unpinnedModuleHits),
      requiredActions: [
        "A git module without a full 40-hex ?ref=<sha> is mutable: a branch or tag can be force-moved, so whoever controls the source repo can swap the module code out from under you on the next `terraform init` (a remote-module supply-chain attack).",
        "Pin every git module to an immutable commit SHA:",
        "  module \"vpc\" {",
        "    source = \"git::https://github.com/org/tf-vpc.git//modules/vpc?ref=<40-char-commit-sha>\"",
        "  }",
        "A tag (?ref=v1.2.3) or branch (?ref=main) is NOT sufficient — only a full 40-character commit SHA is immutable.",
        "Prefer publishing internal modules to a private Terraform registry with exact `version = \"x.y.z\"` pins, and commit .terraform.lock.hcl.",
        "Verify the pin took effect: terraform init && terraform get",
      ],
    });
  }

  // 4. IAC_GCP_TOKEN_CREATOR_PROJECT_BINDING (CWE-269).
  //    Fire only when the token-creator / SA-user role appears AND at least one
  //    project-level IAM binding resource is present. Binding these roles at the
  //    project scope lets the member impersonate EVERY service account in the
  //    project. The SA-scoped resources are the safe alternative.
  if (gcpTokenRole.length > 0 && gcpProjectBinding.length > 0) {
    findings.push({
      id: "IAC_GCP_TOKEN_CREATOR_PROJECT_BINDING",
      title:
        "GCP serviceAccountTokenCreator / serviceAccountUser granted at project scope — lets a member impersonate every service account in the project",
      severity: "HIGH",
      evidence: ev([...gcpTokenRole, ...gcpProjectBinding]),
      requiredActions: [
        "roles/iam.serviceAccountTokenCreator lets a member mint access tokens / sign JWTs for a service account, and roles/iam.serviceAccountUser lets a member run workloads AS a service account. Granted in a google_project_iam_* binding (project scope), these apply to EVERY service account in the project, so any holder can impersonate the most privileged SA — a direct privilege-escalation path.",
        "Bind these roles on a SINGLE service account via google_service_account_iam_member instead of at the project level:",
        "  resource \"google_service_account_iam_member\" \"tokens\" {",
        "    service_account_id = google_service_account.target.name",
        "    role               = \"roles/iam.serviceAccountTokenCreator\"",
        "    member             = \"serviceAccount:${google_service_account.caller.email}\"",
        "  }",
        "Grant to the narrowest possible member (a specific SA or group), never allUsers / allAuthenticatedUsers / a broad domain.",
        "Audit existing impersonation reach: gcloud asset analyze-iam-policy --project=<id> --permissions=iam.serviceAccounts.getAccessToken",
      ],
    });
  }
  // (gcpSaBinding is read to document the safe alternative; referenced here so the
  // presence of SA-scoped bindings does not by itself suppress the finding — the
  // project-level binding above is what makes the grant dangerous.)
  void gcpSaBinding;

  // 5. K8S_RUNC_ESCAPE_DELIVERY_SURFACE (runc CVE-2025-31133/52565/52881, CWE-59).
  //    These runc container-escape bugs abuse symlink/bind-mount handling of
  //    /dev/console and masked paths. A pod is a *delivery surface* for them when
  //    it runs privileged (or with custom hostPath bind mounts) AND does not remap
  //    the user namespace (hostUsers:false / userns), so an escaped container's
  //    UID 0 maps straight to host root. This reinforces the existing
  //    privileged-container rules with the specific runc-escape context.
  const runcFiles: string[] = [];
  const runcEvidence: string[] = [];
  try {
    const yamlFiles = await fg(["**/*.yaml", "**/*.yml"]);
    for (const file of yamlFiles) {
      let content = "";
      try {
        content = await readFileSafe(file);
      } catch {
        continue; // unreadable / oversized / traversal-blocked — skip safely
      }
      // Only consider workload manifests.
      if (!/kind\s*:/.test(content)) continue;
      if (!/containers\s*:/.test(content)) continue;

      const isPrivileged = /privileged\s*:\s*true/.test(content);
      // A *custom* hostPath bind mount (not the SA token projection) is the other
      // delivery vector: it lets a runc escape write to an attacker-chosen host path.
      const hasHostPath = /hostPath\s*:/.test(content);
      // User-namespace remap present? hostUsers:false enables the userns that would
      // contain an escape. hostUsers:true (or absence with privileged) does not.
      const hasUserNsRemap = /hostUsers\s*:\s*false/.test(content);

      if ((isPrivileged || hasHostPath) && !hasUserNsRemap) {
        runcFiles.push(file);
        if (isPrivileged) runcEvidence.push(`${file}: privileged: true (no user-namespace remap)`);
        else if (hasHostPath) runcEvidence.push(`${file}: custom hostPath bind mount (no user-namespace remap)`);
      }
    }
  } catch {
    // Globbing/IO failure must not crash the gate — just yield no runc findings.
  }

  if (runcFiles.length > 0) {
    findings.push({
      id: "K8S_RUNC_ESCAPE_DELIVERY_SURFACE",
      title:
        "Pod is a delivery surface for the 2025 runc container escapes (CVE-2025-31133/52565/52881) — privileged / hostPath with no user-namespace isolation",
      severity: "HIGH",
      files: runcFiles.slice(0, 10),
      evidence: runcEvidence.slice(0, 20),
      requiredActions: [
        "The 2025 runc bugs CVE-2025-31133, CVE-2025-52565 and CVE-2025-52881 are container-escape vulnerabilities that abuse runc's handling of /dev/console and masked-path bind mounts via attacker-controlled symlinks (CWE-59, link following). A pod that runs `privileged: true` or mounts custom hostPath volumes AND does not remap the user namespace is the delivery surface: a successful escape maps the container's UID 0 directly to host root.",
        "Patch the container runtime: upgrade runc to a fixed release (>= 1.2.8 / 1.3.3, or the 1.4.0-rc.3+ line) on every node, and update containerd/CRI-O accordingly.",
        "Remove `privileged: true`; grant only the specific Linux capabilities the workload needs (drop ALL, then add back the minimum).",
        "Remove custom hostPath bind mounts; use emptyDir, PersistentVolumeClaims, or ConfigMaps instead so a runtime escape cannot reach the node filesystem.",
        "Enable user-namespace isolation by setting `hostUsers: false` on the pod spec (UserNamespacesSupport) so an escaped root is remapped to an unprivileged host UID.",
        "Enforce these constraints at admission time with PodSecurityAdmission (restricted) and a policy engine (Kyverno / OPA Gatekeeper).",
      ],
    });
  }

  return findings;
}
