import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "ARGOCD_AUTOSYNC_MUTABLE_SOURCE",
    check: "gitops",
    positive: {
      file: "argocd/application.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: payments-prod\n  namespace: argocd\nspec:\n  project: payments-team\n  source:\n    repoURL: https://github.com/example-org/payments-manifests\n    targetRevision: main\n    path: deploy/prod\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: payments\n  syncPolicy:\n    automated:\n      selfHeal: true\n      prune: true\n`
    },
    negative: {
      file: "argocd/application.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: payments-prod\n  namespace: argocd\nspec:\n  project: payments-team\n  source:\n    repoURL: https://github.com/example-org/payments-manifests\n    targetRevision: v2.4.1\n    path: deploy/prod\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: payments\n  syncPolicy:\n    automated:\n      selfHeal: true\n      prune: true\n`
    },
    note: "Both keep automated.selfHeal/prune (still matched by the automated/selfHeal/prune regexes); the negative pins targetRevision to an immutable tag (v2.4.1) instead of HEAD/main/master/develop/latest, which is the only variable the rule's own remediation calls out."
  },
  {
    ruleId: "ARGOCD_DEFAULT_PROJECT",
    check: "gitops",
    positive: {
      file: "argocd/application.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: payments-prod\n  namespace: argocd\nspec:\n  project: default\n  source:\n    repoURL: https://github.com/example-org/payments-manifests\n    targetRevision: v2.4.1\n    path: deploy/prod\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: payments\n`
    },
    negative: {
      file: "argocd/application.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: payments-prod\n  namespace: argocd\nspec:\n  project: payments-team\n  source:\n    repoURL: https://github.com/example-org/payments-manifests\n    targetRevision: v2.4.1\n    path: deploy/prod\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: payments\n`
    },
    note: "Negative binds the Application to a dedicated AppProject (payments-team) instead of 'default', the exact fix requiredActions recommends."
  },
  {
    ruleId: "ARGOCD_APPPROJECT_WILDCARD",
    check: "gitops",
    positive: {
      file: "argocd/appproject.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: AppProject\nmetadata:\n  name: wide-open\n  namespace: argocd\nspec:\n  sourceRepos:\n    - https://github.com/example-org/payments-manifests\n  destinations:\n    - namespace: '*'\n      server: '*'\n  clusterResourceWhitelist:\n    - group: '*'\n      kind: '*'\n`
    },
    negative: {
      file: "argocd/appproject.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: AppProject\nmetadata:\n  name: payments-team\n  namespace: argocd\nspec:\n  sourceRepos:\n    - https://github.com/example-org/payments-manifests\n  destinations:\n    - namespace: payments\n      server: https://kubernetes.default.svc\n  clusterResourceWhitelist:\n    - group: ""\n      kind: Namespace\n  clusterResourceBlacklist:\n    - group: rbac.authorization.k8s.io\n      kind: ClusterRoleBinding\n`
    },
    note: "Negative keeps kind: AppProject but replaces every '*' destination/cluster-resource entry with an explicit namespace/server and a named group+kind, plus adds a clusterResourceBlacklist, matching requiredActions."
  },
  {
    ruleId: "GITOPS_PLAINTEXT_SECRET",
    check: "gitops",
    positive: {
      file: "argocd/apps/payments/secret.yaml",
      content: `apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-credentials\n  namespace: payments\ntype: Opaque\nstringData:\n  DATABASE_URL: postgres://admin:hunter2@db.internal:5432/payments\n  API_KEY: plaintext-committed-key-do-not-do-this\n`
    },
    negative: {
      file: "argocd/apps/payments/secret.yaml",
      content: `apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: db-credentials\n  namespace: payments\nspec:\n  encryptedData:\n    DATABASE_URL: AgBy3i4OJSWK+PiTySYZZA9rO43cGDEqSAMPLEONLYNOTREALCIPHERTEXT\n    API_KEY: AgCtr9Y9pOAImKwK92qSAMPLEONLYNOTREALCIPHERTEXTVALUE\n  template:\n    metadata:\n      name: db-credentials\n      namespace: payments\n    type: Opaque\n`
    },
    note: "Negative uses kind: SealedSecret (not Secret) with encryptedData ciphertext instead of stringData, the Sealed Secrets fix the rule's requiredActions demand; 'kind: SealedSecret' does not match the kind: Secret regex since 'Sealed' sits between the colon and the literal 'Secret'."
  },
  {
    ruleId: "ARGOCD_PLUGIN_EXEC",
    check: "gitops",
    positive: {
      file: "argocd/apps/plugin-app.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: ConfigManagementPlugin\nmetadata:\n  name: render-with-script\nspec:\n  generate:\n    command: ["sh", "-c"]\n    args:\n      - "helm template . --include-crds | kubectl apply -f -"\n---\napiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: plugin-app\n  namespace: argocd\nspec:\n  source:\n    plugin:\n      name: render-with-script\n`
    },
    negative: {
      file: "argocd/apps/plugin-app.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: web-app\n  namespace: argocd\nspec:\n  project: web-team\n  source:\n    repoURL: https://github.com/example-org/web-charts\n    chart: web\n    targetRevision: 3.2.1\n    helm:\n      releaseName: web\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: web\n`
    },
    note: "Negative renders a plain, pinned Helm chart with no ConfigManagementPlugin kind, no --include-crds, and no valueFiles/fileParameters overrides — nothing shells out during manifest generation."
  },
  {
    ruleId: "ARGOCD_SYNC_VALIDATE_DISABLED",
    check: "gitops",
    positive: {
      file: "argocd/application.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: payments-prod\n  namespace: argocd\nspec:\n  project: payments-team\n  source:\n    repoURL: https://github.com/example-org/payments-manifests\n    targetRevision: v2.4.1\n    path: deploy/prod\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: payments\n  syncPolicy:\n    syncOptions:\n      - Validate=false\n      - ServerSideApply=true\n`
    },
    negative: {
      file: "argocd/application.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: payments-prod\n  namespace: argocd\nspec:\n  project: payments-team\n  source:\n    repoURL: https://github.com/example-org/payments-manifests\n    targetRevision: v2.4.1\n    path: deploy/prod\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: payments\n  syncPolicy:\n    automated:\n      selfHeal: false\n    syncOptions:\n      - CreateNamespace=true\n      - PrunePropagationPolicy=foreground\n`
    },
    note: "Negative still uses syncOptions (proving the feature itself isn't the problem) but only with benign entries; none of Validate=false/ServerSideApply=true/SkipDryRunOnMissingResource=true/RespectIgnoreDifferences=true appear."
  },
  {
    ruleId: "ARGOCD_RBAC_ADMIN_BROAD",
    check: "gitops",
    positive: {
      file: "argocd/argocd-rbac-cm.yaml",
      content: `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-rbac-cm\n  namespace: argocd\ndata:\n  policy.default: role:readonly\n  policy.csv: |\n    p, role:admin, applications, *, */*, allow\n    g, everyone@example.com, role:admin\n    g, *, role:admin\n`
    },
    negative: {
      file: "argocd/argocd-rbac-cm.yaml",
      content: `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-rbac-cm\n  namespace: argocd\ndata:\n  policy.default: role:''\n  policy.csv: |\n    p, proj:payments:deployer, applications, sync, payments/*, allow\n    p, proj:payments:deployer, applications, get, payments/*, allow\n    g, payments-sre@example.com, proj:payments:deployer\n`
    },
    note: "The rule fires on the literal substring 'role:admin' appearing anywhere (even scoped grants), so the only genuine fix is removing that literal entirely — the negative defines a project-scoped custom role (proj:payments:deployer) and sets policy.default to deny, exactly as requiredActions prescribes."
  },
  {
    ruleId: "ARGOCD_SERVER_INSECURE",
    check: "gitops",
    positive: {
      file: "argocd/argocd-cm.yaml",
      content: `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\n  namespace: argocd\ndata:\n  server.insecure: "true"\n  users.anonymous.enabled: "true"\n`
    },
    negative: {
      file: "argocd/argocd-cm.yaml",
      content: `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\n  namespace: argocd\ndata:\n  server.insecure: "false"\n  users.anonymous.enabled: "false"\n  oidc.config: |\n    name: SSO\n    issuer: https://sso.example.com\n    clientID: argocd\n`
    },
    note: "Negative sets both flags to \"false\" (TLS terminated, anonymous access off) and configures OIDC/SSO login instead."
  },
  {
    ruleId: "FLUX_SOURCE_UNVERIFIED",
    check: "gitops",
    positive: {
      file: "flux/gitrepository.yaml",
      content: `apiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\nmetadata:\n  name: app-repo\n  namespace: flux-system\nspec:\n  interval: 1m\n  url: https://github.com/example-org/app\n  ref:\n    branch: main\n`
    },
    negative: {
      file: "flux/gitrepository.yaml",
      content: `apiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\nmetadata:\n  name: app-repo\n  namespace: flux-system\nspec:\n  interval: 1m\n  url: https://github.com/example-org/app\n  ref:\n    tag: v2.4.1\n  verify:\n    provider: cosign\n    secretRef:\n      name: cosign-pub\n`
    },
    note: "Negative adds spec.verify (cosign) and pins ref.tag instead of tracking a branch; no insecure: true anywhere either, so both disjuncts (no-verify OR insecure) are false."
  },
  {
    ruleId: "FLUX_AUTOPRUNE_NO_DECRYPTION",
    check: "gitops",
    positive: {
      file: "flux/kustomization.yaml",
      content: `apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: apps\n  namespace: flux-system\nspec:\n  interval: 1m\n  prune: true\n  sourceRef:\n    kind: GitRepository\n    name: app-repo\n  path: ./deploy\n`
    },
    negative: {
      file: "flux/kustomization.yaml",
      content: `apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: apps\n  namespace: flux-system\nspec:\n  interval: 1m\n  prune: true\n  sourceRef:\n    kind: GitRepository\n    name: app-repo\n  path: ./deploy\n  decryption:\n    provider: sops\n    secretRef:\n      name: sops-age\n`
    },
    note: "Negative adds spec.decryption (provider: sops); the rule requires kind + prune:true + NO 'decryption:' anywhere, and this is the only line that changes."
  },
  {
    ruleId: "FLUX_IMAGE_AUTOUPDATE_FLOATING_TAG",
    check: "gitops",
    positive: {
      file: "flux/imagepolicy.yaml",
      content: `apiVersion: image.toolkit.fluxcd.io/v1beta2\nkind: ImagePolicy\nmetadata:\n  name: web-policy\n  namespace: flux-system\nspec:\n  imageRepositoryRef:\n    name: web\n  policy:\n    semver:\n      range: '>=1.0.0'\n  filterTags:\n    pattern: latest\n`
    },
    negative: {
      file: "flux/imagepolicy.yaml",
      content: `apiVersion: image.toolkit.fluxcd.io/v1beta2\nkind: ImagePolicy\nmetadata:\n  name: web-policy\n  namespace: flux-system\nspec:\n  imageRepositoryRef:\n    name: web\n  policy:\n    numerical:\n      order: asc\n  digestReflectionPolicy: Always\n`
    },
    note: "Negative uses policy.numerical (deterministic ascending build-number selection) instead of policy.semver with an open range, and drops the 'latest' filterTags pattern — no 'semver:'/'range: [^~>]'/'tag: latest' text remains."
  },
  {
    ruleId: "FLUX_HELM_REPO_HTTP",
    check: "gitops",
    positive: {
      file: "flux/helmrepository.yaml",
      content: `apiVersion: source.toolkit.fluxcd.io/v1\nkind: HelmRepository\nmetadata:\n  name: charts\n  namespace: flux-system\nspec:\n  interval: 10m\n  url: http://charts.example.com/stable\n`
    },
    negative: {
      file: "flux/helmrepository.yaml",
      content: `apiVersion: source.toolkit.fluxcd.io/v1\nkind: OCIRepository\nmetadata:\n  name: charts\n  namespace: flux-system\nspec:\n  interval: 10m\n  url: oci://registry.example.com/charts/web\n  ref:\n    tag: 3.2.1\n  verify:\n    provider: cosign\n---\napiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata:\n  name: web\n  namespace: flux-system\nspec:\n  chartRef:\n    kind: OCIRepository\n    name: charts\n`
    },
    note: "The rule's regex (kind: HelmRepository | url: http://) fires on the mere existence of any kind: HelmRepository object regardless of its URL scheme, so no 'kind: HelmRepository' block can ever be a true negative. The negative instead sources the chart via an OCIRepository over oci:// with cosign verification and a HelmRelease chartRef — the real Flux-supported alternative to a legacy HelmRepository, per the rule's own requiredActions ('Use https:// (or oci://)')."
  },
  {
    ruleId: "ARGOCD_APPLICATIONSET_GENERATOR_INJECTION",
    check: "gitops",
    positive: {
      file: "argocd/applicationset.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: ApplicationSet\nmetadata:\n  name: pr-previews\n  namespace: argocd\nspec:\n  generators:\n    - scmProvider:\n        github:\n          organization: "*"\n          allBranches: true\n    - pullRequest:\n        github:\n          owner: any-org\n          repo: any-repo\n  template:\n    metadata:\n      name: '{{.branch}}-preview'\n    spec:\n      project: default\n      destination:\n        namespace: '{{.branch}}'\n        server: https://kubernetes.default.svc\n`
    },
    negative: {
      file: "argocd/applicationset.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: payments-staging\n  namespace: argocd\nspec:\n  project: payments-team\n  source:\n    repoURL: https://github.com/example-org/payments-manifests\n    targetRevision: v2.4.1\n    path: deploy/staging\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: payments-staging\n---\napiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: payments-prod\n  namespace: argocd\nspec:\n  project: payments-team\n  source:\n    repoURL: https://github.com/example-org/payments-manifests\n    targetRevision: v2.4.1\n    path: deploy/prod\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: payments-prod\n`
    },
    note: "The rule's regex (kind: ApplicationSet | generators: | scmProvider: | pullRequest:) fires on ANY ApplicationSet, even one using a safe static 'list' generator, because 'kind: ApplicationSet' and 'generators:' are themselves matched alternatives. A true negative therefore cannot use ApplicationSet at all; the negative instead defines static, explicit per-environment Applications with fixed destinations, the safe architecture the rule implicitly pushes teams toward when dynamic SCM/PR discovery isn't tightly scoped."
  },
  {
    ruleId: "ARGOCD_REPO_INLINE_CREDENTIALS",
    check: "gitops",
    positive: {
      file: "argocd/repo-creds.yaml",
      content: `apiVersion: v1\nkind: Secret\nmetadata:\n  name: private-repo\n  namespace: argocd\n  labels:\n    argocd.argoproj.io/secret-type: repository\nstringData:\n  url: https://github.com/example-org/private-manifests\n  password: ghp_inlineplaintexttokencommittedtogit0000\n  sshPrivateKey: |\n    -----BEGIN OPENSSH PRIVATE KEY-----\n    inline-key-material-do-not-commit\n    -----END OPENSSH PRIVATE KEY-----\n`
    },
    negative: {
      file: "argocd/repo-creds.yaml",
      content: `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\n  namespace: argocd\ndata:\n  repositories: |\n    - url: https://github.com/example-org/private-manifests\n      passwordSecret:\n        name: private-repo-github-token\n        key: token\n      usernameSecret:\n        name: private-repo-github-token\n        key: username\n`
    },
    note: "Negative uses ArgoCD's argocd-cm 'repositories' indirection (passwordSecret/usernameSecret name+key references) instead of a Secret carrying the argocd.argoproj.io/secret-type: repository label with inline password/sshPrivateKey values — no literal password/sshPrivateKey value or repo-creds label appears, only pointers to a separately-managed Secret."
  },
  {
    ruleId: "ARGOCD_HELM_POST_RENDERER_EXEC",
    check: "gitops",
    positive: {
      file: "argocd/apps/postrender-app.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: postrender-app\n  namespace: argocd\nspec:\n  source:\n    repoURL: https://github.com/example-org/charts\n    chart: web\n    helm:\n      postRenderer:\n        exec:\n          command: ["sh", "-c", "./hack/post-render.sh"]\n`
    },
    negative: {
      file: "argocd/apps/postrender-app.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: web-app\n  namespace: argocd\nspec:\n  project: web-team\n  source:\n    repoURL: https://github.com/example-org/charts\n    chart: web\n    targetRevision: 3.2.1\n    helm:\n      releaseName: web\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: web\n`
    },
    note: "Negative renders the chart deterministically with no postRenderer / --post-renderer step at all."
  },
  {
    ruleId: "FLUX_HELMRELEASE_INLINE_SECRET",
    check: "gitops",
    positive: {
      file: "flux/helmrelease-api.yaml",
      content: `apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata:\n  name: api\n  namespace: flux-system\nspec:\n  interval: 1m\n  chart:\n    spec:\n      chart: api\n      version: '2.4.1'\n      sourceRef:\n        kind: HelmRepository\n        name: charts\n  values:\n    database:\n      password: inline-plaintext-password\n      apiKey: AKIAINLINEKEYNOTSECRET\n    auth:\n      token: abc123def456\n`
    },
    negative: {
      file: "flux/helmrelease-api.yaml",
      content: `apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata:\n  name: api\n  namespace: flux-system\nspec:\n  interval: 1m\n  chart:\n    spec:\n      chart: api\n      version: '2.4.1'\n      sourceRef:\n        kind: HelmRepository\n        name: charts\n  valuesFrom:\n    - kind: Secret\n      name: api-secret-values\n      valuesKey: values.yaml\n  decryption:\n    provider: sops\n    secretRef:\n      name: sops-age\n`
    },
    note: "Negative moves credentials out of spec.values into valuesFrom (a separate managed Secret) and adds spec.decryption (sops) — no password:/apiKey:/token: keys remain inline, and 'valuesFrom:' does not match the 'values:$' end-of-line regex."
  },
  {
    ruleId: "FLUX_SERVICEACCOUNT_IMPERSONATION",
    check: "gitops",
    positive: {
      file: "flux/kustomization-tenant.yaml",
      content: `apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: tenant-apps\n  namespace: flux-system\nspec:\n  interval: 1m\n  prune: true\n  serviceAccountName: cluster-admin\n  path: ./deploy\n  sourceRef:\n    kind: GitRepository\n    name: app-repo\n`
    },
    negative: {
      file: "flux/kustomization-tenant.yaml",
      content: `apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: tenant-apps\n  namespace: flux-system\nspec:\n  interval: 1m\n  prune: true\n  serviceAccountName: tenant-apps-deployer\n  path: ./deploy\n  sourceRef:\n    kind: GitRepository\n    name: app-repo\n`
    },
    note: "Negative sets serviceAccountName to a dedicated, least-privilege SA (tenant-apps-deployer) instead of default/cluster-admin/kustomize-controller/flux — the only line that differs from the positive."
  },
  {
    ruleId: "HELM_UNPINNED_CHART_VERSION",
    check: "gitops",
    positive: {
      file: "charts/insecure-app/Chart.yaml",
      content: `apiVersion: v2\nname: insecure-app\ndescription: A chart with insecure supply-chain dependencies\nversion: 1.0.0\nappVersion: "1.0"\ndependencies:\n  - name: redis\n    version: "^17.0.0"\n    repository: https://charts.example.com/stable\n  - name: postgresql\n    version: "*"\n    repository: https://charts.example.com/stable\n`
    },
    negative: {
      file: "charts/insecure-app/Chart.yaml",
      content: `apiVersion: v2\nname: insecure-app\ndescription: A chart with pinned, reproducible dependencies\nversion: 1.0.0\nappVersion: "1.0"\ndependencies:\n  - name: redis\n    version: 17.11.3\n    repository: https://charts.example.com/stable\n  - name: postgresql\n    version: 13.2.24\n    repository: https://charts.example.com/stable\n`
    },
    note: "Negative pins each dependency to an exact semver (17.11.3 / 13.2.24) instead of a caret range or wildcard '*'."
  },
  {
    ruleId: "HELM_SET_PRIVILEGED_OVERRIDE",
    check: "gitops",
    positive: {
      file: "charts/insecure-app/helm-install.sh",
      content: `#!/usr/bin/env bash\nset -euo pipefail\n\nhelm upgrade --install app ./insecure-app \\\n  --set securityContext.privileged=true \\\n  --set podSecurityContext.runAsUser=0 \\\n  --set securityContext.allowPrivilegeEscalation=true \\\n  --namespace payments\n`
    },
    negative: {
      file: "charts/insecure-app/helm-install.sh",
      content: `#!/usr/bin/env bash\nset -euo pipefail\n\nhelm upgrade --install app ./secure-app \\\n  -f values/production.yaml \\\n  --namespace payments\n`
    },
    note: "Negative moves securityContext hardening into a version-controlled values file (-f values/production.yaml) reviewed via PR, with no --set overrides of privileged/runAsUser/allowPrivilegeEscalation at deploy time."
  },
  {
    ruleId: "ARGOCD_DEFAULT_PROJECT_AUTOPRUNE",
    check: "gitops",
    positive: {
      file: "argocd/application.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: payments-prod\n  namespace: argocd\nspec:\n  project: default\n  source:\n    repoURL: https://github.com/example-org/payments-manifests\n    targetRevision: v2.4.1\n    path: deploy/prod\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: payments\n  syncPolicy:\n    automated:\n      prune: true\n`
    },
    negative: {
      file: "argocd/application.yaml",
      content: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: payments-prod\n  namespace: argocd\nspec:\n  project: payments-team\n  source:\n    repoURL: https://github.com/example-org/payments-manifests\n    targetRevision: v2.4.1\n    path: deploy/prod\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: payments\n  syncPolicy:\n    automated:\n      selfHeal: true\n`
    },
    note: "Negative binds to a dedicated AppProject (payments-team, not default) and drops automated.prune entirely — breaking both halves of the AND, not just one."
  }
];
