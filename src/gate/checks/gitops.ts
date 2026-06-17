/**
 * GitOps continuous-delivery security checks (ArgoCD + Flux).
 *
 * Threat model: an attacker who controls a Git repository, an OCI registry, or
 * who can land a pull request can push malicious manifests that a GitOps
 * controller auto-applies to the cluster — frequently with cluster-admin. The
 * checks below hunt for the misconfigurations that turn "GitOps" into
 * "RCE-on-cluster as a service": mutable/unpinned sources, unrestricted
 * AppProjects, plaintext secrets, unverified Git/OCI sources, and auto-pull of
 * floating tags.
 */
import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";

const MAX = 200;

function evidence(matches: { file: string; line: number; preview: string }[]): string[] {
  return matches.slice(0, 20).map((m) => `${m.file}:${m.line}: ${m.preview}`);
}

export async function checkGitOps(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  const findings: Finding[] = [];

  const [
    argoAutomatedSync, // automated sync stanza
    argoSelfHeal, // selfHeal: true
    argoPrune, // prune: true
    argoTargetHead, // targetRevision: HEAD / branch
    argoProjectDefault, // project: default
    appProjectKind, // kind: AppProject present
    appProjectWildcardSource, // sourceRepos: ['*']
    appProjectWildcardDest, // destinations namespace/server '*'
    appProjectWildcardClusterRes, // clusterResourceWhitelist '*' '*'
    plaintextSecret, // kind: Secret + stringData/data
    secretMgmtOperator, // sealed-secrets / sops / external-secrets present
    argoPlugin, // config-management-plugin / plugin exec
    helmDangerousFlags, // --include-crds / arbitrary value files
    syncValidateFalse, // syncOptions Validate=false / ServerSideApply
    argoRbacAdmin, // role:admin broad grant / g, *, role:admin
    argoServerInsecure, // server.insecure / disable.auth / anonymous
    argoResourceIgnoreHealth, // resource.customizations ignore health / --insecure repo-server
  ] = await Promise.all([
    searchRepo({ query: String.raw`automated\s*:|syncPolicy\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`selfHeal\s*:\s*true`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`prune\s*:\s*true`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`targetRevision\s*:\s*['"]?(?:HEAD|main|master|develop|latest)['"]?`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`project\s*:\s*['"]?default['"]?`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`kind\s*:\s*AppProject`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`sourceRepos\s*:\s*\[?\s*['"]?\*['"]?`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`(?:namespace|server)\s*:\s*['"]?\*['"]?`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`(?:group|kind)\s*:\s*['"]?\*['"]?`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`kind\s*:\s*Secret`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`SealedSecret|kind\s*:\s*ExternalSecret|sops\s*:|encryptedRegex|kind\s*:\s*SecretStore`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`configManagementPlugin|config-management-plugin|kind\s*:\s*ConfigManagementPlugin|plugin\s*:\s*name`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`--include-crds|skipCrds\s*:\s*false|valueFiles\s*:|fileParameters\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`Validate=false|ServerSideApply=true|SkipDryRunOnMissingResource=true|RespectIgnoreDifferences=true`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`role\s*:\s*admin|g,\s*\*,\s*role:admin|p,\s*role:admin|,\s*role:admin`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`server\.insecure\s*:\s*['"]?true|disable\.auth\s*:\s*['"]?true|users\.anonymous\.enabled\s*:\s*['"]?true|--insecure`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`resource\.customizations|ignoreDifferences\s*:|health\.lua|--disable-tls`, isRegex: true, maxMatches: MAX }),
  ]);

  const [
    fluxGitRepo, // kind: GitRepository / OCIRepository
    fluxVerify, // verify: (cosign/signature)
    fluxInsecure, // insecure: true
    fluxKustomization, // kind: Kustomization (flux)
    fluxHelmRelease, // kind: HelmRelease
    fluxDecryption, // decryption: (SOPS)
    fluxImagePolicy, // ImagePolicy / ImageUpdateAutomation
    fluxImageRangeTag, // semver range / latest in imagePolicy
    helmRepoHttp, // HelmRepository url: http://
  ] = await Promise.all([
    searchRepo({ query: String.raw`kind\s*:\s*(?:GitRepository|OCIRepository)`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`verify\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`insecure\s*:\s*true`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`kind\s*:\s*Kustomization`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`kind\s*:\s*HelmRelease`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`decryption\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`kind\s*:\s*(?:ImagePolicy|ImageUpdateAutomation)`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`semver\s*:|range\s*:\s*['"]?[\^~>]|tag\s*:\s*['"]?latest`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`kind\s*:\s*HelmRepository|url\s*:\s*http://`, isRegex: true, maxMatches: MAX }),
  ]);

  // ---- ArgoCD ----

  // 1. Auto-deploy of a mutable upstream = RCE-on-cluster.
  if (
    argoAutomatedSync.length > 0 &&
    argoSelfHeal.length > 0 &&
    argoPrune.length > 0 &&
    argoTargetHead.length > 0
  ) {
    findings.push({
      id: "ARGOCD_AUTOSYNC_MUTABLE_SOURCE",
      title: "ArgoCD Application auto-syncs (selfHeal+prune) from a mutable/unpinned source (targetRevision: HEAD/branch) — anyone who pushes to the tracked ref gets RCE on the cluster",
      severity: "CRITICAL",
      evidence: evidence([...argoTargetHead, ...argoSelfHeal]),
      requiredActions: [
        "Pin targetRevision to an immutable Git tag or commit SHA, not HEAD or a branch name.",
        "Require signed commits/tags and enable ArgoCD GnuPG/cosign source verification (project signatureKeys).",
        "Gate auto-sync behind a protected branch with mandatory PR review and CODEOWNERS on manifests.",
        "Consider disabling automated.selfHeal in production so a human approves drift reconciliation."
      ]
    });
  }

  // 2. Application bound to the default AppProject (no restrictions).
  if (argoProjectDefault.length > 0) {
    findings.push({
      id: "ARGOCD_DEFAULT_PROJECT",
      title: "ArgoCD Application uses the 'default' AppProject — no source/destination/cluster-resource restrictions, unrestricted blast radius",
      severity: "HIGH",
      evidence: evidence(argoProjectDefault),
      requiredActions: [
        "Create a dedicated AppProject per team/app and set spec.project to it; never use 'default'.",
        "Restrict the AppProject sourceRepos, destinations, and clusterResourceWhitelist to explicit allowlists.",
        "Lock down the built-in default AppProject so it cannot deploy anywhere."
      ]
    });
  }

  // 3. AppProject with wildcard sources/destinations/cluster resources.
  if (
    appProjectKind.length > 0 &&
    (appProjectWildcardSource.length > 0 ||
      appProjectWildcardDest.length > 0 ||
      appProjectWildcardClusterRes.length > 0)
  ) {
    findings.push({
      id: "ARGOCD_APPPROJECT_WILDCARD",
      title: "ArgoCD AppProject grants wildcards in sourceRepos / destinations / clusterResourceWhitelist — any repo can deploy any cluster-scoped resource to any namespace",
      severity: "CRITICAL",
      evidence: evidence([
        ...appProjectWildcardSource,
        ...appProjectWildcardDest,
        ...appProjectWildcardClusterRes
      ]),
      requiredActions: [
        "Restrict AppProject sourceRepos/destinations/clusterResourceWhitelist to explicit allowlists.",
        "Remove '*'/'*' from clusterResourceWhitelist; whitelist only the specific cluster-scoped groups/kinds needed.",
        "Pin destinations to explicit namespace + server (no '*'), and pin sourceRepos to exact repo URLs.",
        "Set a clusterResourceBlacklist for high-risk kinds (ClusterRoleBinding, ValidatingWebhookConfiguration)."
      ]
    });
  }

  // 4. Plaintext Secret committed without a secret-management operator.
  if (plaintextSecret.length > 0 && secretMgmtOperator.length === 0) {
    findings.push({
      id: "GITOPS_PLAINTEXT_SECRET",
      title: "Plaintext kind: Secret committed to a GitOps repo with no Sealed Secrets / SOPS / External Secrets in use — credentials exposed to anyone with repo read access",
      severity: "CRITICAL",
      evidence: evidence(plaintextSecret),
      requiredActions: [
        "Move Secrets to Sealed Secrets, SOPS, or External Secrets Operator — never commit kind: Secret with stringData/data.",
        "Rotate every credential that was ever committed in plaintext; Git history is forever.",
        "Add a pre-commit/CI guard that blocks raw kind: Secret manifests from being committed."
      ]
    });
  }

  // 5. ArgoCD config-management-plugin / Helm privilege escalation.
  if (argoPlugin.length > 0 || helmDangerousFlags.length > 0) {
    findings.push({
      id: "ARGOCD_PLUGIN_EXEC",
      title: "ArgoCD config-management-plugin / Helm with --include-crds or arbitrary value files — manifest generation runs attacker-controllable code in the repo-server",
      severity: "HIGH",
      evidence: evidence([...argoPlugin, ...helmDangerousFlags]),
      requiredActions: [
        "Run config-management plugins as a sidecar with a read-only, non-root securityContext and no cluster credentials.",
        "Avoid --include-crds and arbitrary valueFiles/fileParameters sourced from the application repo; pin them in a trusted repo.",
        "Disable plugins entirely if not required; never let plugins shell out to repo-controlled scripts."
      ]
    });
  }

  // 6. syncOptions disabling validation / forcing server-side apply.
  if (syncValidateFalse.length > 0) {
    findings.push({
      id: "ARGOCD_SYNC_VALIDATE_DISABLED",
      title: "ArgoCD syncOptions disable schema validation (Validate=false) or force ServerSideApply — malformed/malicious manifests applied without admission checks",
      severity: "MEDIUM",
      evidence: evidence(syncValidateFalse),
      requiredActions: [
        "Remove Validate=false from syncOptions so kubectl/server schema validation runs on every apply.",
        "Only use ServerSideApply with field-manager conflict handling reviewed; do not use it to bypass validating webhooks.",
        "Keep admission controllers (OPA Gatekeeper / Kyverno) in the apply path for all GitOps-managed namespaces."
      ]
    });
  }

  // 7. ArgoCD RBAC granting broad admin.
  if (argoRbacAdmin.length > 0) {
    findings.push({
      id: "ARGOCD_RBAC_ADMIN_BROAD",
      title: "ArgoCD RBAC grants role:admin to a broad group (or g, *, role:admin) — broad principals gain full control of all Applications and clusters",
      severity: "HIGH",
      evidence: evidence(argoRbacAdmin),
      requiredActions: [
        "Replace role:admin grants with project-scoped custom roles in policy.csv (p, proj:team:role, applications, ...).",
        "Never grant 'g, *, role:admin'; bind admin only to a named, minimal SSO group.",
        "Set policy.default to role:'' (deny) and enumerate every allowed action explicitly."
      ]
    });
  }

  // 8. ArgoCD server exposed insecurely / auth disabled.
  if (argoServerInsecure.length > 0) {
    findings.push({
      id: "ARGOCD_SERVER_INSECURE",
      title: "ArgoCD server runs with insecure/anonymous access (server.insecure, disable.auth, users.anonymous.enabled, or --insecure) — unauthenticated control of the cluster delivery plane",
      severity: "CRITICAL",
      evidence: evidence(argoServerInsecure),
      requiredActions: [
        "Set server.insecure: false and terminate TLS at the ArgoCD server or ingress.",
        "Never set users.anonymous.enabled: true or disable.auth: true; require SSO/OIDC for every login.",
        "Remove --insecure flags from argocd-server and argocd-repo-server deployments."
      ]
    });
  }

  // 9. Resource health/diff ignored or insecure repo-server flags.
  if (argoResourceIgnoreHealth.length > 0) {
    findings.push({
      id: "ARGOCD_HEALTH_IGNORED",
      title: "ArgoCD resource.customizations / ignoreDifferences suppress health and drift detection (or --disable-tls on repo-server) — malicious drift goes unreported",
      severity: "MEDIUM",
      evidence: evidence(argoResourceIgnoreHealth),
      requiredActions: [
        "Scope ignoreDifferences narrowly to specific jsonPointers; never blanket-ignore whole resource health.",
        "Do not use health.lua overrides that always report Healthy; keep real health assessment.",
        "Remove --disable-tls and enforce TLS between repo-server, application-controller, and Git/Helm sources."
      ]
    });
  }

  // ---- Flux ----

  // 10. Git/OCI source with no signature verification or insecure transport.
  if (fluxGitRepo.length > 0 && (fluxVerify.length === 0 || fluxInsecure.length > 0)) {
    findings.push({
      id: "FLUX_SOURCE_UNVERIFIED",
      title: "Flux GitRepository/OCIRepository has no verify: (no cosign/PGP signature check) or sets insecure: true — Flux pulls and applies unauthenticated, tamperable source",
      severity: "HIGH",
      evidence: evidence([...fluxGitRepo, ...fluxInsecure]),
      requiredActions: [
        "Add a spec.verify block (provider: cosign or pgp) to every GitRepository/OCIRepository so Flux rejects unsigned revisions.",
        "Remove insecure: true; require TLS for all Git/OCI/Helm source fetches.",
        "Pin the source to an immutable tag/digest and sign artifacts in CI with cosign keyless (OIDC)."
      ]
    });
  }

  // 11. Kustomization/HelmRelease auto-prune from a source with no decryption (secrets) configured.
  if (
    (fluxKustomization.length > 0 || fluxHelmRelease.length > 0) &&
    argoPrune.length > 0 &&
    fluxDecryption.length === 0
  ) {
    findings.push({
      id: "FLUX_AUTOPRUNE_NO_DECRYPTION",
      title: "Flux Kustomization/HelmRelease auto-prunes on an interval but has no decryption: (SOPS) block — secrets are unmanaged and reconciliation auto-applies upstream changes",
      severity: "HIGH",
      evidence: evidence([...fluxKustomization, ...fluxHelmRelease]),
      requiredActions: [
        "Add a spec.decryption block (provider: sops) so Secrets are decrypted in-cluster, never stored in plaintext.",
        "Pin the Kustomization/HelmRelease sourceRef to a verified, immutable revision before enabling prune: true.",
        "Increase the reconcile interval / require manual approval for production so unreviewed upstream changes do not auto-apply."
      ]
    });
  }

  // 12. ImagePolicy / ImageUpdateAutomation auto-pulling floating tags.
  if (fluxImagePolicy.length > 0 && fluxImageRangeTag.length > 0) {
    findings.push({
      id: "FLUX_IMAGE_AUTOUPDATE_FLOATING_TAG",
      title: "Flux ImagePolicy/ImageUpdateAutomation auto-deploys a semver range or :latest tag — a poisoned upstream image is auto-pulled and rolled out (supply-chain auto-pull)",
      severity: "HIGH",
      evidence: evidence([...fluxImagePolicy, ...fluxImageRangeTag]),
      requiredActions: [
        "Pin images to an immutable digest (image@sha256:...) instead of a semver range or :latest.",
        "Require cosign signature verification (Kyverno/policy-controller) before any auto-updated image is admitted.",
        "Gate ImageUpdateAutomation commits behind a protected branch + PR review rather than direct push to the deploy branch."
      ]
    });
  }

  // 13. HelmRepository over plaintext HTTP.
  if (helmRepoHttp.length > 0) {
    findings.push({
      id: "FLUX_HELM_REPO_HTTP",
      title: "Flux HelmRepository / chart source uses plaintext HTTP (url: http://) — chart payloads are MITM-tamperable in transit",
      severity: "HIGH",
      evidence: evidence(helmRepoHttp),
      requiredActions: [
        "Use https:// (or oci://) for all HelmRepository/chart URLs; never http://.",
        "Provide a certSecretRef / CA bundle for private registries instead of disabling TLS.",
        "Enable chart provenance verification (Helm --verify / cosign) so tampered charts are rejected."
      ]
    });
  }

  // ---- Round 2: deeper ArgoCD / Flux / Helm supply-chain checks ----

  const [
    argoAppSetGenerator, // ApplicationSet SCM/PR/Git generator
    argoAppSetGoTemplate, // goTemplate + unsanitized params
    argoIgnoreDiffSensitive, // ignoreDifferences on RBAC/Secret kinds
    argoRolloutAnalysis, // AnalysisTemplate running jobs
    argoCompareIgnoreStatus, // resource.compareoptions ignoreResourceStatusField: all
    argoAccountApiKey, // accounts.* apiKey capability
    argoDexInlineSecret, // dex.config clientSecret inline
    argoNotifWebhook, // notifications-cm webhook / template injection
    argoRepoInlineCreds, // repositories/repo-creds inline password/sshPrivateKey
    argoKustomizeLoadRestrictor, // --load-restrictor LoadRestrictionsNone
    argoHelmPostRenderer, // helm --post-renderer exec
    argoExecExtensions, // exec / extensions enabled
    argoResourceTrackingLabel, // resourceTrackingMethod: label
  ] = await Promise.all([
    searchRepo({ query: String.raw`kind\s*:\s*ApplicationSet|generators\s*:|scmProvider\s*:|pullRequest\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`goTemplate\s*:\s*true|goTemplateOptions\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`kind\s*:\s*(?:Secret|Role|RoleBinding|ClusterRole|ClusterRoleBinding|ServiceAccount)`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`kind\s*:\s*AnalysisTemplate|provider\s*:\s*job|kind\s*:\s*ClusterAnalysisTemplate`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`ignoreResourceStatusField\s*:\s*all|resource\.compareoptions`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`accounts\..+\s*:\s*apiKey|accounts\..+\s*:\s*['"]?apiKey,\s*login|capabilities\s*:\s*\[?\s*apiKey`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`dex\.config|clientSecret\s*:\s*['"]?[A-Za-z0-9._-]{6,}`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`notifications-cm|service\.webhook|trigger\.on-|template\.app-`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`sshPrivateKey\s*:|password\s*:\s*['"]?\S|kind\s*:\s*repo-creds|argocd\.argoproj\.io/secret-type\s*:\s*repo`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`--load-restrictor[=\s]+LoadRestrictionsNone|Load_RestrictionsNone|buildOptions\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`--post-renderer|postRenderer\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`exec\.enabled\s*:\s*['"]?true|extension\.config|kind\s*:\s*ArgoCDExtension`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`application\.resourceTrackingMethod\s*:\s*['"]?label|resourceTrackingMethod\s*:\s*['"]?label`, isRegex: true, maxMatches: MAX }),
  ]);

  const [
    fluxReceiverWeakToken, // Receiver/webhook weak/no token
    fluxBucketInsecure, // Bucket source http / public
    fluxPostBuildSubstitute, // postBuild.substituteFrom unverified
    fluxHelmInlineSecret, // HelmRelease values inline secrets
    fluxPathTraversal, // Kustomization path ../
    fluxSaImpersonation, // serviceAccountName impersonation / cluster-admin
    fluxOciFloatingNoVerify, // OCIRepository floating tag (verify checked earlier)
    fluxDependsOn, // dependsOn present (absence => ordering bypass)
    fluxEnableHelm, // KustomizeConfig --enable-helm
    fluxImageGitPushBranch, // image automation push branch
  ] = await Promise.all([
    searchRepo({ query: String.raw`kind\s*:\s*Receiver|secretRef\s*:\s*$|type\s*:\s*generic-hmac|type\s*:\s*github`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`kind\s*:\s*Bucket`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`substituteFrom\s*:|postBuild\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`values\s*:\s*$|password\s*:|apiKey\s*:|token\s*:\s*['"]?[A-Za-z0-9]`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`path\s*:\s*['"]?\.\./|path\s*:\s*['"]?\.\.`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`serviceAccountName\s*:\s*['"]?(?:default|cluster-admin|kustomize-controller|flux)`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`tag\s*:\s*['"]?(?:latest|main|stable|edge)|semverFilter\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`dependsOn\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`--enable-helm|enableHelm\s*:\s*true|helmGlobals\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`push\s*:\s*$|branch\s*:\s*['"]?(?:main|master|production|release)`, isRegex: true, maxMatches: MAX }),
  ]);

  const [
    helmDepHttp, // chart dependencies from http repo
    helmChartLock, // Chart.lock present (absence => no digest pin)
    helmChartYaml, // Chart.yaml present (scope for lock check)
    helmUnpinnedVersion, // unpinned chart version range
    helmFilesGetSecret, // .Files.Get on secrets
    helmSetPrivileged, // --set privileged securityContext
  ] = await Promise.all([
    searchRepo({ query: String.raw`repository\s*:\s*['"]?http://|repository\s*:\s*['"]?@`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`digest\s*:\s*sha256:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`^\s*apiVersion\s*:\s*v[12]\s*$|^\s*name\s*:.+|dependencies\s*:`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`version\s*:\s*['"]?[\^~><]|version\s*:\s*['"]?\*|version\s*:\s*['"]?x`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`\.Files\.Get\s+['"]?[^'"\s]*secret|\.Files\.Get\s+['"]?[^'"\s]*\.key|\.Files\.Get\s+['"]?[^'"\s]*password`, isRegex: true, maxMatches: MAX }),
    searchRepo({ query: String.raw`--set\s+[^\s]*privileged=true|--set\s+[^\s]*runAsUser=0|--set\s+[^\s]*allowPrivilegeEscalation=true`, isRegex: true, maxMatches: MAX }),
  ]);

  // 14. ApplicationSet generator pulling from any org/repo.
  if (argoAppSetGenerator.length > 0) {
    findings.push({
      id: "ARGOCD_APPLICATIONSET_GENERATOR_INJECTION",
      title: "ArgoCD ApplicationSet uses an SCM/PR/Git generator that discovers repos/branches dynamically — an attacker who opens a PR or pushes a branch causes arbitrary Application creation (generator injection)",
      severity: "CRITICAL",
      evidence: evidence(argoAppSetGenerator),
      requiredActions: [
        "Scope SCM/PR generators to an explicit allowlist of repos and a trusted org; never match all repositories.",
        "Set a requiresReview / label filter on pullRequest generators so untrusted PRs cannot spawn Applications.",
        "Run applicationset-controller with the SCM provider token scoped read-only to the specific org.",
        "Template the destination namespace/cluster from a trusted field — never directly from branch/PR-controlled values."
      ]
    });
  }

  // 15. ApplicationSet goTemplate with unsanitized params.
  if (argoAppSetGoTemplate.length > 0) {
    findings.push({
      id: "ARGOCD_APPLICATIONSET_GOTEMPLATE_INJECTION",
      title: "ArgoCD ApplicationSet enables goTemplate — generator parameters (branch names, PR titles, repo metadata) flow unsanitized into Application specs, enabling template/field injection",
      severity: "HIGH",
      evidence: evidence(argoAppSetGoTemplate),
      requiredActions: [
        "Treat all generator params as untrusted; never interpolate them into project, destination.namespace, or destination.server.",
        "Pin project and destination to static values, not goTemplate expressions derived from SCM metadata.",
        "Enable goTemplateOptions: [missingkey=error] so undefined/injected keys fail closed instead of rendering empty."
      ]
    });
  }

  // 16. ignoreDifferences hiding drift on RBAC/Secret resources.
  if (argoIgnoreDiffSensitive.length > 0 && argoResourceIgnoreHealth.length > 0) {
    findings.push({
      id: "ARGOCD_IGNOREDIFF_SENSITIVE_DRIFT",
      title: "ArgoCD ignoreDifferences is configured alongside Secret/RBAC resources — drift on Secrets, Roles, or RoleBindings can be silently ignored, hiding privilege escalation",
      severity: "HIGH",
      evidence: evidence(argoIgnoreDiffSensitive),
      requiredActions: [
        "Never apply ignoreDifferences to Secret, Role, RoleBinding, ClusterRole, ClusterRoleBinding, or ServiceAccount resources.",
        "Scope ignoreDifferences to specific jsonPointers on non-security fields only (e.g. replica counts).",
        "Alert on any OutOfSync RBAC/Secret resource so injected privilege grants are surfaced, not suppressed."
      ]
    });
  }

  // 17. Argo Rollouts AnalysisTemplate running arbitrary jobs.
  if (argoRolloutAnalysis.length > 0) {
    findings.push({
      id: "ARGOCD_ROLLOUT_ANALYSIS_JOB",
      title: "Argo Rollouts AnalysisTemplate runs a Job/metric provider during promotion — a repo-controlled analysis template executes arbitrary pods with the rollouts controller's RBAC",
      severity: "HIGH",
      evidence: evidence(argoRolloutAnalysis),
      requiredActions: [
        "Store AnalysisTemplates in a trusted, review-gated repo — never let the application repo define the job spec.",
        "Run analysis Jobs under a dedicated, least-privilege ServiceAccount with no cluster-admin.",
        "Pin job container images to digests and forbid privileged/hostPath in analysis job pod specs."
      ]
    });
  }

  // 18. compareoptions ignoreResourceStatusField: all.
  if (argoCompareIgnoreStatus.length > 0) {
    findings.push({
      id: "ARGOCD_COMPARE_IGNORE_STATUS_ALL",
      title: "ArgoCD resource.compareoptions sets ignoreResourceStatusField: all — status-field drift is globally ignored, weakening drift/health detection across every Application",
      severity: "MEDIUM",
      evidence: evidence(argoCompareIgnoreStatus),
      requiredActions: [
        "Set ignoreResourceStatusField to 'crd' (the safe default) rather than 'all'.",
        "Do not globally suppress status comparison; handle noisy status fields per-resource with scoped ignoreDifferences.",
        "Keep health assessment enabled so degraded/compromised workloads are reported."
      ]
    });
  }

  // 19. accounts.* with apiKey capability (long-lived tokens).
  if (argoAccountApiKey.length > 0) {
    findings.push({
      id: "ARGOCD_ACCOUNT_APIKEY_CAPABILITY",
      title: "ArgoCD argocd-cm grants an account the apiKey capability — enables long-lived, non-expiring bearer tokens that bypass SSO and survive offboarding",
      severity: "HIGH",
      evidence: evidence(argoAccountApiKey),
      requiredActions: [
        "Remove the apiKey capability from human accounts; rely on SSO/OIDC login only.",
        "Where automation needs tokens, scope them via project-level roles and set short expiry; rotate frequently.",
        "Audit existing API tokens (argocd account get) and revoke any unattended long-lived tokens."
      ]
    });
  }

  // 20. dex.config connector with inline clientSecret.
  if (argoDexInlineSecret.length > 0) {
    findings.push({
      id: "ARGOCD_DEX_INLINE_CLIENT_SECRET",
      title: "ArgoCD dex.config embeds an OIDC connector clientSecret inline in argocd-cm — the IdP client secret is committed to Git in plaintext",
      severity: "HIGH",
      evidence: evidence(argoDexInlineSecret),
      requiredActions: [
        "Reference the connector clientSecret via $<secret-name>:<key> indirection into argocd-secret, never inline.",
        "Rotate any clientSecret that was committed inline; it is exposed to everyone with repo read access.",
        "Restrict the OIDC client redirect URIs and allowed groups to least privilege."
      ]
    });
  }

  // 21. notifications-cm webhook to untrusted URL / template injection.
  if (argoNotifWebhook.length > 0) {
    findings.push({
      id: "ARGOCD_NOTIFICATIONS_WEBHOOK_INJECTION",
      title: "ArgoCD argocd-notifications-cm defines webhook services / templates — outbound webhooks to untrusted URLs and unsanitized template variables enable SSRF and notification template injection",
      severity: "MEDIUM",
      evidence: evidence(argoNotifWebhook),
      requiredActions: [
        "Pin webhook service URLs to known, internal endpoints; do not template the URL from Application-controlled fields.",
        "Sanitize/escape app metadata used in notification templates to prevent injection into downstream systems.",
        "Store webhook tokens/headers in argocd-notifications-secret, not inline in the ConfigMap."
      ]
    });
  }

  // 22. Repo creds with inline password / sshPrivateKey.
  if (argoRepoInlineCreds.length > 0) {
    findings.push({
      id: "ARGOCD_REPO_INLINE_CREDENTIALS",
      title: "ArgoCD repository / repo-creds Secret embeds an inline password or sshPrivateKey — Git credentials committed in plaintext grant write access to source repos",
      severity: "CRITICAL",
      evidence: evidence(argoRepoInlineCreds),
      requiredActions: [
        "Never commit password / sshPrivateKey inline; manage repo credentials via Sealed Secrets, SOPS, or External Secrets.",
        "Rotate any Git credential / deploy key that was committed; Git history retains it forever.",
        "Use short-lived, scoped tokens (GitHub App installation tokens) instead of long-lived passwords/keys."
      ]
    });
  }

  // 23. kustomize buildOptions --load-restrictor LoadRestrictionsNone (path traversal).
  if (argoKustomizeLoadRestrictor.length > 0) {
    findings.push({
      id: "ARGOCD_KUSTOMIZE_LOAD_RESTRICTOR_NONE",
      title: "Kustomize buildOptions disable the load restrictor (--load-restrictor LoadRestrictionsNone) — kustomizations can reference files outside their root, reading host/repo-server secrets via path traversal",
      severity: "HIGH",
      evidence: evidence(argoKustomizeLoadRestrictor),
      requiredActions: [
        "Remove --load-restrictor LoadRestrictionsNone; keep the default LoadRestrictionsRootOnly.",
        "Vendor any genuinely external files into the kustomization root instead of disabling restrictions.",
        "Run the repo-server with a read-only root filesystem and no host secret mounts."
      ]
    });
  }

  // 24. Helm --post-renderer exec.
  if (argoHelmPostRenderer.length > 0) {
    findings.push({
      id: "ARGOCD_HELM_POST_RENDERER_EXEC",
      title: "Helm source uses a --post-renderer — manifest rendering shells out to a repo-controlled binary/script inside the repo-server, an arbitrary-code-execution sink",
      severity: "HIGH",
      evidence: evidence(argoHelmPostRenderer),
      requiredActions: [
        "Avoid --post-renderer / postRenderer sourced from the application repo; render deterministically.",
        "If post-rendering is required, run it in a locked-down CMP sidecar with no cluster credentials and a read-only FS.",
        "Pin and review the post-renderer binary; never execute scripts fetched at sync time."
      ]
    });
  }

  // 25. exec / extensions enabled.
  if (argoExecExtensions.length > 0) {
    findings.push({
      id: "ARGOCD_EXEC_EXTENSIONS_ENABLED",
      title: "ArgoCD exec feature (exec.enabled: true) or UI extensions are enabled — operators can open shells into pods via the API, and extensions load remote JS into the console",
      severity: "MEDIUM",
      evidence: evidence(argoExecExtensions),
      requiredActions: [
        "Set exec.enabled: false unless interactive pod shells are strictly required; gate it behind a dedicated RBAC role.",
        "Pin and review any UI extension sources; never load extension assets from untrusted URLs.",
        "Audit exec usage via the ArgoCD audit log and alert on shell sessions in production namespaces."
      ]
    });
  }

  // 26. resourceTrackingMethod: label (tracking confusion).
  if (argoResourceTrackingLabel.length > 0) {
    findings.push({
      id: "ARGOCD_RESOURCE_TRACKING_LABEL",
      title: "ArgoCD resourceTrackingMethod is set to 'label' — the app.kubernetes.io/instance label is spoofable, letting a malicious manifest claim or hijack resources owned by another Application",
      severity: "MEDIUM",
      evidence: evidence(argoResourceTrackingLabel),
      requiredActions: [
        "Use resourceTrackingMethod: annotation (or annotation+label) instead of label — annotations carry the app name and group, resisting spoofing.",
        "Avoid sharing the app.kubernetes.io/instance label across Applications.",
        "Audit for resources whose tracking label does not match their owning Application."
      ]
    });
  }

  // ---- Flux depth ----

  // 27. Receiver/webhook with weak or missing token.
  if (fluxReceiverWeakToken.length > 0) {
    findings.push({
      id: "FLUX_RECEIVER_WEAK_TOKEN",
      title: "Flux Receiver exposes a webhook — without a strong HMAC secretRef (or with a generic/empty token), anyone who can reach the receiver URL can force-reconcile and trigger deploys",
      severity: "HIGH",
      evidence: evidence(fluxReceiverWeakToken),
      requiredActions: [
        "Set a secretRef pointing to a high-entropy token and use type: generic-hmac (or a provider type that verifies signatures).",
        "Restrict the receiver Ingress to the source provider's IP ranges; do not expose it broadly.",
        "Rotate the receiver token periodically and store it via SOPS/Sealed Secrets, not inline."
      ]
    });
  }

  // 28. Bucket source insecure / public.
  if (fluxBucketInsecure.length > 0 && (fluxInsecure.length > 0 || helmRepoHttp.length > 0)) {
    findings.push({
      id: "FLUX_BUCKET_INSECURE",
      title: "Flux Bucket source is reachable over plaintext/insecure transport or a public endpoint — manifests fetched from object storage are tamperable and unauthenticated",
      severity: "HIGH",
      evidence: evidence(fluxBucketInsecure),
      requiredActions: [
        "Set the Bucket endpoint to an HTTPS/TLS endpoint and remove insecure: true.",
        "Authenticate to the bucket via a secretRef (or workload identity); do not rely on public/anonymous read.",
        "Pin and verify object integrity; restrict the bucket policy to the Flux controller identity only."
      ]
    });
  }

  // 29. postBuild.substituteFrom from unverified ConfigMap/Secret.
  if (fluxPostBuildSubstitute.length > 0) {
    findings.push({
      id: "FLUX_POSTBUILD_SUBSTITUTE_INJECTION",
      title: "Flux Kustomization uses postBuild.substituteFrom — variables pulled from a ConfigMap/Secret are substituted into rendered manifests, enabling var injection if that source is attacker-writable",
      severity: "MEDIUM",
      evidence: evidence(fluxPostBuildSubstitute),
      requiredActions: [
        "Source substituteFrom only from ConfigMaps/Secrets in a controller-only namespace with locked-down RBAC.",
        "Never substitute into security-relevant fields (image, securityContext, serviceAccountName) from mutable sources.",
        "Mark substituteFrom entries optional: false so a missing/tampered source fails closed."
      ]
    });
  }

  // 30. HelmRelease values with inline secrets.
  if (fluxHelmRelease.length > 0 && fluxHelmInlineSecret.length > 0 && fluxDecryption.length === 0) {
    findings.push({
      id: "FLUX_HELMRELEASE_INLINE_SECRET",
      title: "Flux HelmRelease embeds secret-like values (password/apiKey/token) inline under spec.values with no decryption configured — credentials are committed in plaintext",
      severity: "HIGH",
      evidence: evidence(fluxHelmInlineSecret),
      requiredActions: [
        "Move secret values out of spec.values; reference them via valuesFrom a SOPS-decrypted Secret.",
        "Configure spec.decryption (provider: sops) so secrets are decrypted in-cluster, never stored plaintext.",
        "Rotate any credential that was committed inline in a HelmRelease."
      ]
    });
  }

  // 31. Kustomization path traversal.
  if (fluxPathTraversal.length > 0) {
    findings.push({
      id: "FLUX_KUSTOMIZATION_PATH_TRAVERSAL",
      title: "Flux Kustomization spec.path uses '../' traversal — the reconciler can be pointed outside the intended directory to apply unintended/sibling manifests",
      severity: "MEDIUM",
      evidence: evidence(fluxPathTraversal),
      requiredActions: [
        "Set spec.path to a fixed subdirectory of the source; never use '../' to escape the configured root.",
        "Use separate GitRepository sources scoped to each app rather than traversing across directories.",
        "Review the source so the reconciled path cannot reach secrets or other teams' manifests."
      ]
    });
  }

  // 32. serviceAccountName impersonation / cluster-admin.
  if (
    (fluxKustomization.length > 0 || fluxHelmRelease.length > 0) &&
    fluxSaImpersonation.length > 0
  ) {
    findings.push({
      id: "FLUX_SERVICEACCOUNT_IMPERSONATION",
      title: "Flux Kustomization/HelmRelease sets a privileged serviceAccountName (default / cluster-admin / controller SA) — manifests are applied with broad RBAC, so a malicious manifest inherits cluster-admin",
      severity: "HIGH",
      evidence: evidence(fluxSaImpersonation),
      requiredActions: [
        "Set spec.serviceAccountName to a dedicated, least-privilege ServiceAccount scoped to the target namespace.",
        "Never reconcile with the default SA or a cluster-admin-bound SA; bind only the exact Roles needed.",
        "Enable Flux multi-tenancy lockdown (--default-service-account, --no-cross-namespace-refs)."
      ]
    });
  }

  // 33. OCIRepository floating tag with no cosign verify.
  if (fluxGitRepo.length > 0 && fluxOciFloatingNoVerify.length > 0 && fluxVerify.length === 0) {
    findings.push({
      id: "FLUX_OCI_FLOATING_TAG_NO_VERIFY",
      title: "Flux OCIRepository tracks a floating tag (latest/main/stable) with no verify.provider (cosign) — a re-pushed tag is auto-pulled and applied with no signature check",
      severity: "HIGH",
      evidence: evidence(fluxOciFloatingNoVerify),
      requiredActions: [
        "Pin OCIRepository ref to an immutable digest (ref.digest: sha256:...), not a floating tag.",
        "Add spec.verify.provider: cosign with the publisher's identity/key so unsigned artifacts are rejected.",
        "Sign artifacts in CI with cosign keyless (OIDC) and enforce verification before reconcile."
      ]
    });
  }

  // 34. dependsOn missing — apply ordering bypass (Kustomizations present but no dependsOn anywhere).
  if (fluxKustomization.length > 1 && fluxDependsOn.length === 0) {
    findings.push({
      id: "FLUX_NO_DEPENDS_ON_ORDERING",
      title: "Multiple Flux Kustomizations exist but none declare dependsOn — apply ordering is unenforced, so security-critical resources (NetworkPolicies, RBAC, PSA) may be applied after the workloads they protect",
      severity: "MEDIUM",
      requiredActions: [
        "Declare spec.dependsOn so policy/RBAC/namespace Kustomizations reconcile before application workloads.",
        "Gate workload reconciliation on the readiness of its security prerequisites (e.g. NetworkPolicy, Gatekeeper).",
        "Use health checks (spec.healthChecks) so dependents wait for prerequisites to become Ready."
      ]
    });
  }

  // 35. KustomizeConfig --enable-helm (arbitrary chart hooks).
  if (fluxEnableHelm.length > 0) {
    findings.push({
      id: "FLUX_KUSTOMIZE_ENABLE_HELM",
      title: "Flux Kustomization enables the Helm chart inflator (--enable-helm / helmGlobals) — kustomize templates and renders arbitrary remote charts, running chart hooks/templating as a code-execution sink",
      severity: "HIGH",
      evidence: evidence(fluxEnableHelm),
      requiredActions: [
        "Prefer a HelmRelease (with verify + decryption) over kustomize --enable-helm for chart rendering.",
        "If --enable-helm is required, pin chart name + version + repo and verify provenance before rendering.",
        "Restrict helmGlobals.chartHome to a vendored, reviewed chart directory; do not pull charts at build time."
      ]
    });
  }

  // 36. Image automation pushing to a protected branch.
  if (fluxImagePolicy.length > 0 && fluxImageGitPushBranch.length > 0) {
    findings.push({
      id: "FLUX_IMAGE_AUTOMATION_PUSH_PROTECTED_BRANCH",
      title: "Flux ImageUpdateAutomation pushes commits directly to a protected/deploy branch (main/master/production/release) — automated image bumps bypass PR review and protected-branch controls",
      severity: "MEDIUM",
      evidence: evidence(fluxImageGitPushBranch),
      requiredActions: [
        "Configure git.push.branch to a dedicated automation branch and require a reviewed PR to merge into the deploy branch.",
        "Require cosign signature verification on any image before it can be auto-promoted.",
        "Restrict the automation deploy key to the automation branch only, not the protected branch."
      ]
    });
  }

  // ---- Helm / Kustomize supply-chain breadth ----

  // 37. Chart dependencies from an http repo.
  if (helmDepHttp.length > 0) {
    findings.push({
      id: "HELM_DEPENDENCY_HTTP_REPO",
      title: "Helm Chart.yaml declares a dependency from a plaintext http:// (or alias '@') repository — subchart payloads are MITM-tamperable and unverified",
      severity: "HIGH",
      evidence: evidence(helmDepHttp),
      requiredActions: [
        "Use https:// or oci:// repositories for all chart dependencies; never http://.",
        "Pin each dependency to an exact version and commit Chart.lock with digests.",
        "Vendor critical subcharts into charts/ and verify provenance (helm verify / cosign)."
      ]
    });
  }

  // 38. Chart.lock digest missing (Chart with dependencies but no sha256 digest pin).
  if (helmDepHttp.length > 0 || (helmChartYaml.length > 0 && helmUnpinnedVersion.length > 0)) {
    if (helmChartLock.length === 0) {
      findings.push({
        id: "HELM_CHART_LOCK_DIGEST_MISSING",
        title: "Helm chart declares dependencies but no Chart.lock with sha256 digests is present — dependency resolution is not reproducible and a mutated upstream chart can be silently pulled",
        severity: "MEDIUM",
        requiredActions: [
          "Run `helm dependency update` and commit the generated Chart.lock with sha256 digests.",
          "Pin every dependency to an exact version (no ranges) so the lock is stable.",
          "Verify the lock digest in CI before packaging/deploying the chart."
        ]
      });
    }
  }

  // 39. Unpinned chart version range.
  if (helmUnpinnedVersion.length > 0) {
    findings.push({
      id: "HELM_UNPINNED_CHART_VERSION",
      title: "Helm chart/dependency version uses a range or wildcard (^, ~, >, *, x) — a new upstream release is pulled automatically, enabling supply-chain auto-update of subcharts",
      severity: "MEDIUM",
      evidence: evidence(helmUnpinnedVersion),
      requiredActions: [
        "Pin chart and dependency versions to an exact semver (e.g. 1.4.2), never a range or wildcard.",
        "Commit Chart.lock so the resolved versions/digests are reproducible.",
        "Review and bump versions deliberately via PR rather than allowing range-based auto-resolution."
      ]
    });
  }

  // 40. Template using .Files.Get on secrets.
  if (helmFilesGetSecret.length > 0) {
    findings.push({
      id: "HELM_FILES_GET_SECRET",
      title: "Helm template uses .Files.Get to read a secret/key/password file into rendered output — secret material is baked into manifests and may land in ConfigMaps or chart packages",
      severity: "HIGH",
      evidence: evidence(helmFilesGetSecret),
      requiredActions: [
        "Do not read secret files via .Files.Get; provide secrets through valuesFrom a managed Secret at deploy time.",
        "Ensure secret files are excluded via .helmignore so they are never packaged into the chart .tgz.",
        "Use SOPS/Sealed Secrets/External Secrets for secret delivery instead of embedding files in the chart."
      ]
    });
  }

  // 41. --set injecting privileged securityContext.
  if (helmSetPrivileged.length > 0) {
    findings.push({
      id: "HELM_SET_PRIVILEGED_OVERRIDE",
      title: "Helm install/upgrade uses --set to inject a privileged securityContext (privileged=true / runAsUser=0 / allowPrivilegeEscalation=true) — overrides chart hardening at deploy time, granting container escape primitives",
      severity: "HIGH",
      evidence: evidence(helmSetPrivileged),
      requiredActions: [
        "Remove --set overrides that set privileged=true, runAsUser=0, or allowPrivilegeEscalation=true.",
        "Enforce a restricted PodSecurity standard / Gatekeeper policy so privileged overrides are rejected at admission.",
        "Keep securityContext hardening in version-controlled values files reviewed via PR, not ad-hoc --set flags."
      ]
    });
  }

  return findings;
}
