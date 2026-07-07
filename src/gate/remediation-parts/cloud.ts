import type { RemediationTemplate } from "../remediation-map.js";
// Fix templates for cloud/K8s/Docker/IaC/GitOps finding IDs. Lives under src/gate/
// so the gate self-scan ignores the intentional vulnerable "pattern" examples.
export const CLOUD_REMEDIATIONS: Record<string, RemediationTemplate> = {
	"ARGOCD_ACCOUNT_APIKEY_CAPABILITY": {
		pattern: "apiVersion: v1\nkind: ConfigMap\nmetadata: { name: argocd-cm }\ndata:\n  accounts.alice: apiKey, login",
		fix: "data:\n  # human accounts: SSO login only, no apiKey\n  accounts.alice: login\n  # automation only, with a project-scoped, short-lived token\n  accounts.ci-bot: apiKey",
		explanation: "The apiKey capability lets an account mint long-lived bearer tokens that bypass SSO and keep working after the person leaves. Give humans login-only and reserve apiKey for scoped automation accounts.",
		references: ["CWE-798", "CWE-522", "CIS Kubernetes Benchmark", "NIST 800-53 IA-5"]
	},
	"ARGOCD_APPLICATIONSET_GENERATOR_INJECTION": {
		pattern: "kind: ApplicationSet\nspec:\n  generators:\n    - scmProvider:\n        github: { organization: acme }  # matches ALL repos\n  template:\n    spec:\n      destination: { namespace: '{{branch}}' }",
		fix: "spec:\n  generators:\n    - scmProvider:\n        github:\n          organization: acme\n          allBranches: false\n        filters:\n          - repositoryMatch: ^(app-a|app-b)$   # explicit allowlist\n  template:\n    spec:\n      destination: { namespace: fixed-ns }   # not from SCM metadata",
		explanation: "SCM/PR/Git generators create an Application for every repo or branch they discover, so an attacker who pushes a branch or opens a PR can spawn deployments. Restrict generators to an explicit repo allowlist and never template the destination from branch/PR-controlled values.",
		references: ["CWE-1329", "CWE-94", "MITRE ATT&CK T1195", "NIST 800-53 CM-3"]
	},
	"ARGOCD_APPLICATIONSET_GOTEMPLATE_INJECTION": {
		pattern: "kind: ApplicationSet\nspec:\n  goTemplate: true\n  template:\n    spec:\n      project: '{{.branch}}'\n      destination: { namespace: '{{.head_short_sha}}' }",
		fix: "spec:\n  goTemplate: true\n  template:\n    spec:\n      project: team-a          # static, trusted value\n      destination:\n        namespace: team-a-prod   # not derived from SCM metadata\n        server: https://kubernetes.default.svc",
		explanation: "With goTemplate enabled, untrusted generator parameters (branch names, PR titles, repo metadata) flow into the Application spec and can inject into project or destination fields. Pin project and destination to static values instead of templating them from SCM data.",
		references: ["CWE-94", "CWE-20", "MITRE ATT&CK T1195", "NIST 800-53 SI-10"]
	},
	"ARGOCD_APPPROJECT_WILDCARD": {
		pattern: "kind: AppProject\nspec:\n  sourceRepos: ['*']\n  destinations: [{ namespace: '*', server: '*' }]\n  clusterResourceWhitelist: [{ group: '*', kind: '*' }]",
		fix: "kind: AppProject\nspec:\n  sourceRepos:\n    - https://github.com/acme/manifests.git\n  destinations:\n    - namespace: team-a-*\n      server: https://kubernetes.default.svc\n  clusterResourceWhitelist:\n    - { group: 'networking.k8s.io', kind: 'Ingress' }\n  clusterResourceBlacklist:\n    - { group: 'rbac.authorization.k8s.io', kind: 'ClusterRoleBinding' }",
		explanation: "Wildcards in an AppProject let any repo deploy any cluster-scoped resource to any namespace, giving a compromised source unlimited blast radius. Restrict sourceRepos, destinations, and clusterResourceWhitelist to explicit allowlists and blacklist high-risk kinds.",
		references: ["CWE-732", "CWE-284", "CIS Kubernetes Benchmark 5.1.3", "NIST 800-53 AC-6"]
	},
	"ARGOCD_AUTOSYNC_MUTABLE_SOURCE": {
		pattern: "kind: Application\nspec:\n  source: { targetRevision: HEAD }\n  syncPolicy:\n    automated: { selfHeal: true, prune: true }",
		fix: "kind: Application\nspec:\n  source:\n    targetRevision: v1.4.2          # immutable tag or commit SHA\n  syncPolicy:\n    automated: { selfHeal: true, prune: true }\n  # AppProject enforces signed commits:\n  # spec.signatureKeys: [{ keyID: ABCDEF0123456789 }]",
		explanation: "Auto-sync from HEAD or a branch means anyone who pushes to the tracked ref gets code execution on the cluster. Pin targetRevision to an immutable tag or commit SHA and require signed commits verified by the project's signatureKeys.",
		references: ["CWE-494", "CWE-829", "MITRE ATT&CK T1195.002", "NIST 800-53 CM-5"]
	},
	"ARGOCD_COMPARE_IGNORE_STATUS_ALL": {
		pattern: "kind: ConfigMap\nmetadata: { name: argocd-cm }\ndata:\n  resource.compareoptions: |\n    ignoreResourceStatusField: all",
		fix: "data:\n  resource.compareoptions: |\n    ignoreResourceStatusField: crd   # safe default, not 'all'",
		explanation: "Setting ignoreResourceStatusField to all globally suppresses status-field comparison, weakening drift and health detection for every Application. Use the default 'crd' scope and handle noisy fields per-resource with narrow ignoreDifferences.",
		references: ["CWE-778", "CIS Kubernetes Benchmark", "NIST 800-53 SI-4"]
	},
	"ARGOCD_DEFAULT_PROJECT": {
		pattern: "kind: Application\nspec:\n  project: default",
		fix: "kind: Application\nspec:\n  project: team-a   # dedicated, restricted AppProject",
		explanation: "The built-in 'default' AppProject applies no source, destination, or cluster-resource restrictions, so an Application bound to it has unlimited blast radius. Create a dedicated, restricted AppProject per team/app and lock the default project down.",
		references: ["CWE-732", "CWE-284", "CIS Kubernetes Benchmark 5.1.3", "NIST 800-53 AC-6"]
	},
	"ARGOCD_DEFAULT_PROJECT_AUTOPRUNE": {
		pattern: "kind: Application\nspec:\n  project: default\n  syncPolicy:\n    automated: { prune: true }",
		fix: "kind: Application\nspec:\n  project: team-a   # restricted AppProject with destination allowlist\n  syncPolicy:\n    automated: { prune: true }\n  # AppProject sets clusterResourceBlacklist + explicit destinations",
		explanation: "An unrestricted 'default' project combined with automated prune can auto-delete any resource in the cluster from a single bad manifest. Bind the Application to a dedicated restricted project with destination allowlists and a clusterResourceBlacklist before enabling prune.",
		references: ["CWE-732", "CWE-284", "MITRE ATT&CK T1485", "NIST 800-53 AC-6"]
	},
	"ARGOCD_DEX_INLINE_CLIENT_SECRET": {
		pattern: "kind: ConfigMap\nmetadata: { name: argocd-cm }\ndata:\n  dex.config: |\n    connectors:\n      - config: { clientSecret: abc123realsecret }",
		fix: "data:\n  dex.config: |\n    connectors:\n      - config:\n          clientSecret: $oidc.okta.clientSecret   # ref into argocd-secret\n---\nkind: Secret\nmetadata: { name: argocd-secret }\nstringData: { oidc.okta.clientSecret: <managed-by-sops> }",
		explanation: "An inline OIDC clientSecret in argocd-cm commits the IdP client secret to Git in plaintext, readable by anyone with repo access. Reference it via $<secret>:<key> indirection into argocd-secret and rotate any secret that was committed inline.",
		references: ["CWE-798", "CWE-522", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"ARGOCD_EXEC_EXTENSIONS_ENABLED": {
		pattern: "kind: ConfigMap\nmetadata: { name: argocd-cm }\ndata:\n  exec.enabled: 'true'",
		fix: "data:\n  exec.enabled: 'false'   # gate pod shells behind dedicated RBAC only\n# RBAC (argocd-rbac-cm): grant exec only to a break-glass role\n#   p, role:breakglass, exec, create, */*, allow",
		explanation: "exec.enabled lets operators open shells into pods through the ArgoCD API, and UI extensions load remote JavaScript into the console. Disable exec unless strictly required, gate it behind a dedicated RBAC role, and pin any extension sources.",
		references: ["CWE-284", "CWE-749", "CIS Kubernetes Benchmark", "NIST 800-53 AC-6"]
	},
	"ARGOCD_HEALTH_IGNORED": {
		pattern: "kind: Application\nspec:\n  ignoreDifferences:\n    - group: apps\n      kind: Deployment\n      jsonPointers: ['/spec']   # ignores whole spec/health",
		fix: "spec:\n  ignoreDifferences:\n    - group: apps\n      kind: Deployment\n      jsonPointers: ['/spec/replicas']   # narrow, non-security field only",
		explanation: "Blanket ignoreDifferences (or health.lua overrides that always report Healthy, or --disable-tls on repo-server) hide malicious drift from detection. Scope ignoreDifferences to specific non-security jsonPointers and keep real health assessment and TLS enabled.",
		references: ["CWE-778", "CWE-319", "CIS Kubernetes Benchmark", "NIST 800-53 SI-4"]
	},
	"ARGOCD_HELM_POST_RENDERER_EXEC": {
		pattern: "kind: Application\nspec:\n  source:\n    helm:\n      # renders via a repo-controlled binary\n      postRenderer: ./scripts/post-render.sh",
		fix: "spec:\n  source:\n    helm: {}   # deterministic render, no post-renderer\n# If post-rendering is unavoidable, run it in a locked-down CMP sidecar\n# with a read-only FS and no cluster credentials, using a pinned binary.",
		explanation: "A Helm --post-renderer shells out to a repo-controlled binary inside the repo-server, an arbitrary-code-execution sink at sync time. Render deterministically without a post-renderer, or confine it to a hardened CMP sidecar with no cluster access.",
		references: ["CWE-94", "CWE-829", "MITRE ATT&CK T1195", "NIST 800-53 SI-7"]
	},
	"ARGOCD_IGNOREDIFF_SENSITIVE_DRIFT": {
		pattern: "kind: Application\nspec:\n  ignoreDifferences:\n    - group: ''\n      kind: Secret\n      jsonPointers: ['/data']\n    - kind: RoleBinding\n      group: rbac.authorization.k8s.io\n      jsonPointers: ['/subjects']",
		fix: "spec:\n  ignoreDifferences:\n    - group: apps\n      kind: Deployment\n      jsonPointers: ['/spec/replicas']   # never Secret/Role/RoleBinding\n# Alert on any OutOfSync Secret/RBAC resource instead of ignoring it.",
		explanation: "Applying ignoreDifferences to Secret, Role, or RoleBinding resources means injected credentials or privilege grants drift silently and go unreported. Never ignore differences on security resources; scope ignoreDifferences to non-security fields and alert on RBAC/Secret drift.",
		references: ["CWE-778", "CWE-266", "CIS Kubernetes Benchmark", "NIST 800-53 AC-6"]
	},
	"ARGOCD_KUSTOMIZE_LOAD_RESTRICTOR_NONE": {
		pattern: "kind: ConfigMap\nmetadata: { name: argocd-cm }\ndata:\n  kustomize.buildOptions: '--load-restrictor LoadRestrictionsNone'",
		fix: "data:\n  kustomize.buildOptions: ''   # keep default LoadRestrictionsRootOnly\n# Vendor any external files into the kustomization root instead.",
		explanation: "Disabling the Kustomize load restrictor lets a kustomization reference files outside its root and read repo-server or host secrets via path traversal. Keep the default LoadRestrictionsRootOnly and vendor genuinely external files into the root.",
		references: ["CWE-22", "CWE-829", "CIS Kubernetes Benchmark", "NIST 800-53 SI-10"]
	},
	"ARGOCD_NOTIFICATIONS_WEBHOOK_INJECTION": {
		pattern: "kind: ConfigMap\nmetadata: { name: argocd-notifications-cm }\ndata:\n  service.webhook.ext: |\n    url: '{{.app.spec.source.repoURL}}'   # templated URL = SSRF",
		fix: "data:\n  service.webhook.slack: |\n    url: https://hooks.internal.example.com/argocd   # pinned, internal\n---\nkind: Secret\nmetadata: { name: argocd-notifications-secret }\nstringData: { webhook-token: <managed> }",
		explanation: "Templating a webhook URL from Application-controlled fields enables SSRF, and unsanitized app metadata in templates injects into downstream systems. Pin webhook URLs to known internal endpoints, escape templated metadata, and store tokens in argocd-notifications-secret.",
		references: ["CWE-918", "CWE-94", "OWASP Top 10 A10:2021", "NIST 800-53 SC-7"]
	},
	"ARGOCD_PLUGIN_EXEC": {
		pattern: "kind: ConfigMap\nmetadata: { name: argocd-cm }\ndata:\n  configManagementPlugins: |\n    - name: my-plugin\n      generate: { command: [sh, -c], args: ['./repo-script.sh'] }",
		fix: "# Run the plugin as a hardened CMP sidecar, no cluster creds:\nkind: Deployment   # argocd-repo-server\nspec:\n  template:\n    spec:\n      containers:\n        - name: cmp\n          securityContext:\n            runAsNonRoot: true\n            readOnlyRootFilesystem: true\n            allowPrivilegeEscalation: false\n            capabilities: { drop: ['ALL'] }",
		explanation: "Config-management plugins (and Helm --include-crds / arbitrary value files) run attacker-controllable code inside the repo-server. Run plugins as a read-only, non-root sidecar with no cluster credentials, and never let them shell out to repo-controlled scripts.",
		references: ["CWE-94", "CWE-829", "MITRE ATT&CK T1195", "NIST 800-53 SI-7"]
	},
	"ARGOCD_RBAC_ADMIN_BROAD": {
		pattern: "kind: ConfigMap\nmetadata: { name: argocd-rbac-cm }\ndata:\n  policy.csv: |\n    g, *, role:admin",
		fix: "data:\n  policy.default: role:''   # deny by default\n  policy.csv: |\n    p, proj:team-a:developer, applications, sync, team-a/*, allow\n    g, acme:platform-admins, role:admin   # named SSO group only",
		explanation: "Granting role:admin to a broad group (or g, *, role:admin) hands full control of every Application and cluster to any matching principal. Replace broad admin grants with project-scoped roles, bind admin only to a named SSO group, and default-deny.",
		references: ["CWE-269", "CWE-284", "CIS Kubernetes Benchmark 5.1.3", "NIST 800-53 AC-6"]
	},
	"ARGOCD_REPO_INLINE_CREDENTIALS": {
		pattern: "kind: Secret\nmetadata: { name: repo-acme, labels: { argocd.argoproj.io/secret-type: repository } }\nstringData:\n  url: https://github.com/acme/manifests.git\n  password: YOUR_GIT_TOKEN",
		fix: "kind: Secret\nmetadata: { name: repo-acme, labels: { argocd.argoproj.io/secret-type: repository } }\nstringData:\n  url: https://github.com/acme/manifests.git\n  # password/sshPrivateKey injected by External Secrets / SOPS, never inline",
		explanation: "An inline password or sshPrivateKey in a repository Secret commits Git write credentials to source in plaintext. Manage repo credentials via Sealed Secrets, SOPS, or External Secrets, use short-lived scoped tokens, and rotate anything ever committed.",
		references: ["CWE-798", "CWE-522", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"ARGOCD_REPO_SSH_NO_HOSTKEY": {
		pattern: "kind: Secret\nmetadata: { labels: { argocd.argoproj.io/secret-type: repository } }\nstringData:\n  url: git@github.com:acme/manifests.git\n  sshPrivateKey: <key>   # no pinned host key",
		fix: "kind: ConfigMap\nmetadata: { name: argocd-ssh-known-hosts-cm }\ndata:\n  ssh_known_hosts: |\n    github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		explanation: "An SSH repository with no pinned host key lets the controller trust any host key on connect, so a MITM can impersonate the Git server and inject manifests. Populate argocd-ssh-known-hosts-cm with the exact verified host key and disable any auto-accept behavior.",
		references: ["CWE-322", "CWE-295", "OWASP Top 10 A02:2021", "NIST 800-53 SC-8"]
	},
	"ARGOCD_RESOURCE_TRACKING_LABEL": {
		pattern: "kind: ConfigMap\nmetadata: { name: argocd-cm }\ndata:\n  application.resourceTrackingMethod: label",
		fix: "data:\n  application.resourceTrackingMethod: annotation   # spoof-resistant",
		explanation: "The label tracking method uses the spoofable app.kubernetes.io/instance label, letting a malicious manifest claim or hijack resources owned by another Application. Use resourceTrackingMethod: annotation so ownership carries the app name and group and resists spoofing.",
		references: ["CWE-290", "CWE-345", "CIS Kubernetes Benchmark", "NIST 800-53 SI-7"]
	},
	"ARGOCD_ROLLOUT_ANALYSIS_JOB": {
		pattern: "kind: AnalysisTemplate\nspec:\n  metrics:\n    - name: smoke\n      provider:\n        job:\n          spec:\n            template:\n              spec:\n                containers: [{ image: repo/attacker:latest, command: [sh,-c,'...'] }]",
		fix: "kind: AnalysisTemplate   # stored in a trusted, review-gated repo\nspec:\n  metrics:\n    - name: smoke\n      provider:\n        job:\n          spec:\n            template:\n              spec:\n                serviceAccountName: rollout-analysis   # least-privilege\n                containers:\n                  - image: repo/smoke@sha256:...   # digest-pinned\n                    securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ['ALL'] } }",
		explanation: "An Argo Rollouts AnalysisTemplate runs a Job with the rollouts controller's RBAC during promotion, so a repo-controlled analysis spec executes arbitrary pods. Keep AnalysisTemplates in a trusted review-gated repo, run analysis Jobs under a least-privilege SA, and digest-pin images.",
		references: ["CWE-94", "CWE-269", "MITRE ATT&CK T1610", "NIST 800-53 SI-7"]
	},
	"ARGOCD_SERVER_INSECURE": {
		pattern: "kind: ConfigMap\nmetadata: { name: argocd-cmd-params-cm }\ndata:\n  server.insecure: 'true'\n  users.anonymous.enabled: 'true'",
		fix: "data:\n  server.insecure: 'false'\n  users.anonymous.enabled: 'false'\n# terminate TLS at argocd-server or the ingress; require SSO/OIDC login",
		explanation: "Running ArgoCD server with server.insecure, disable.auth, anonymous access, or --insecure exposes unauthenticated control of the cluster delivery plane. Set server.insecure and anonymous to false, terminate TLS, and require SSO/OIDC for every login.",
		references: ["CWE-306", "CWE-319", "OWASP Top 10 A07:2021", "NIST 800-53 AC-3"]
	},
	"ARGOCD_SKIP_DRY_RUN": {
		pattern: "kind: Application\nspec:\n  syncPolicy:\n    syncOptions:\n      - SkipDryRunOnMissingResource=true",
		fix: "spec:\n  syncPolicy:\n    syncOptions: []   # keep server-side dry-run enabled\n# Install required CRDs first rather than skipping the dry-run.",
		explanation: "SkipDryRunOnMissingResource=true applies resources without a server-side dry-run, bypassing admission and validation feedback. Remove it so ArgoCD dry-runs before applying, and keep validating admission webhooks enforcing regardless.",
		references: ["CWE-20", "CIS Kubernetes Benchmark", "NIST 800-53 SI-10"]
	},
	"ARGOCD_SYNC_VALIDATE_DISABLED": {
		pattern: "kind: Application\nspec:\n  syncPolicy:\n    syncOptions:\n      - Validate=false",
		fix: "spec:\n  syncPolicy:\n    syncOptions: []   # schema validation runs on every apply\n# Keep OPA Gatekeeper / Kyverno admission enforcing on managed namespaces.",
		explanation: "Validate=false disables kubectl/server schema validation, so malformed or malicious manifests are applied without checks. Remove it, and keep admission controllers (Gatekeeper/Kyverno) in the apply path for all GitOps-managed namespaces.",
		references: ["CWE-20", "CIS Kubernetes Benchmark", "NIST 800-53 SI-10"]
	},
	"DOCKER_ADD_LOCAL_ARCHIVE": {
		pattern: "ADD app.tar.gz /opt/app/",
		fix: "COPY app.tar.gz /tmp/\nRUN echo \"<sha256>  /tmp/app.tar.gz\" | sha256sum -c - \\\n && tar -xzf /tmp/app.tar.gz -C /opt/app --no-same-owner && rm /tmp/app.tar.gz",
		explanation: "ADD auto-extracts local archives with no integrity check, which can enable path traversal / zip-slip. Use COPY and, if extraction is needed, verify a checksum then extract with an explicit, audited tar command.",
		references: ["CWE-22", "NIST 800-190", "Docker Best Practices"]
	},
	"DOCKER_ADD_REMOTE_URL": {
		pattern: "ADD https://example.com/tool.tar.gz /opt/",
		fix: "RUN curl --fail -sSL https://example.com/tool.tar.gz -o /tmp/tool.tar.gz \\\n && echo \"<sha256>  /tmp/tool.tar.gz\" | sha256sum -c - \\\n && tar -xzf /tmp/tool.tar.gz -C /opt && rm /tmp/tool.tar.gz",
		explanation: "ADD with a remote URL performs no integrity check, so a CDN compromise or DNS hijack injects malicious content into the image. Fetch with curl --fail over HTTPS and verify a published sha256 before using the artifact.",
		references: ["CWE-494", "CWE-829", "NIST 800-190"]
	},
	"DOCKER_APK_NO_CACHE": {
		pattern: "RUN apk add curl",
		fix: "RUN apk add --no-cache curl=8.5.0-r0",
		explanation: "apk add without --no-cache persists the package index in the layer, enlarging the image and retaining stale metadata. Add --no-cache and pin exact package versions for reproducible builds.",
		references: ["CWE-1104", "NIST 800-190", "CIS Docker Benchmark 4.9"]
	},
	"DOCKER_APT_RECOMMENDS": {
		pattern: "RUN apt-get update && apt-get install -y curl",
		fix: "RUN apt-get update \\\n && apt-get install -y --no-install-recommends curl=7.88.1-10 \\\n && rm -rf /var/lib/apt/lists/*",
		explanation: "apt-get install without --no-install-recommends pulls extra packages, enlarging the image and its attack surface. Add --no-install-recommends, pin versions, and clean apt lists in the same layer.",
		references: ["CWE-1104", "NIST 800-190", "CIS Docker Benchmark 4.9"]
	},
	"DOCKER_BASE_IMAGE_NO_DIGEST": {
		pattern: "FROM node:20-alpine",
		fix: "FROM node:20-alpine@sha256:6d0f18a1c67dc218c4af50c21256616286a53c09e500fd3a6a1c9c6c7b0c0a2b",
		explanation: "A base image pinned by tag alone is mutable and can be repointed upstream to a different image. Append the content digest (image:tag@sha256:...) so every build uses the exact reviewed image.",
		references: ["CWE-1357", "MITRE ATT&CK T1195.002", "NIST 800-190"]
	},
	"DOCKER_BASE_IMAGE_UNPINNED": {
		pattern: "FROM ubuntu:latest",
		fix: "FROM ubuntu:22.04@sha256:0e0402cd13f68137edc0dc04c0d4e5b1e0ca55e21ed19eb32e4e4d5f36cccce3",
		explanation: "A :latest or untagged base image is not pinned to a digest, allowing a supply-chain image swap. Pin the base image to an immutable digest and update it deliberately in CI.",
		references: ["CWE-1357", "MITRE ATT&CK T1195.002", "NIST 800-190"]
	},
	"DOCKER_BROAD_CHOWN": {
		pattern: "RUN chown -R root:root /",
		fix: "COPY --chown=appuser:appuser . /app",
		explanation: "A recursive chown over / or system paths (or to root) can weaken file permissions and bloats the layer. Scope chown to the app directory targeting the non-root user, or set ownership at copy time with COPY --chown.",
		references: ["CWE-732", "NIST 800-190", "CIS Docker Benchmark"]
	},
	"DOCKER_CHMOD_777": {
		pattern: "RUN chmod -R 777 /app",
		fix: "RUN chown -R appuser:appuser /app && chmod -R 755 /app",
		explanation: "chmod 777 makes files world-writable, so any user or process can tamper with them. Grant the minimal permissions needed (755 for executables, 644 for data) and set ownership with chown instead.",
		references: ["CWE-732", "NIST 800-190", "CIS Docker Benchmark"]
	},
	"DOCKER_COMPOSE_BIND_ALL_INTERFACES": {
		pattern: "services:\n  db:\n    ports:\n      - '5432:5432'   # binds 0.0.0.0",
		fix: "services:\n  db:\n    ports:\n      - '127.0.0.1:5432:5432'",
		explanation: "Publishing a port as 0.0.0.0 makes the service reachable on every host interface, including public ones. Bind sensitive ports to 127.0.0.1 and use a firewall/security group to control any port that must be external.",
		references: ["CWE-668", "NIST 800-190", "CIS Docker Benchmark 5.7"]
	},
	"DOCKER_COMPOSE_BUILD_ARG_SECRET": {
		pattern: "services:\n  app:\n    build:\n      args:\n        NPM_TOKEN: ${NPM_TOKEN}",
		fix: "# docker-compose.yml passes no secret args; use BuildKit secrets:\n#   docker build --secret id=npm,src=$HOME/.npmrc .\n# Dockerfile:\n#   RUN --mount=type=secret,id=npm npm ci",
		explanation: "A secret passed via build.args becomes a build ARG that is baked into image history and recoverable with docker history. Use BuildKit secret mounts that never persist in a layer, and source runtime secrets from a secrets manager.",
		references: ["CWE-200", "CWE-522", "NIST 800-190"]
	},
	"DOCKER_COMPOSE_DANGEROUS_CAP": {
		pattern: "services:\n  app:\n    cap_add:\n      - SYS_ADMIN",
		fix: "services:\n  app:\n    cap_drop:\n      - ALL\n    cap_add:\n      - NET_BIND_SERVICE   # only the specific cap needed",
		explanation: "Adding SYS_ADMIN, NET_ADMIN, or ALL grants capabilities that enable container escape to the host. Drop ALL capabilities and add back only the specific, non-dangerous capability the workload requires.",
		references: ["CWE-250", "CWE-269", "NIST 800-190", "CIS Docker Benchmark 5.3"]
	},
	"DOCKER_COMPOSE_ENV_FILE_SECRET": {
		pattern: "services:\n  app:\n    env_file:\n      - .env.production   # committed, holds credentials",
		fix: "services:\n  app:\n    secrets:\n      - db_password\nsecrets:\n  db_password:\n    external: true   # from a secrets manager, .env git-ignored",
		explanation: "An env_file referencing a committed secrets file leaks credentials into version control and the build context. Keep secret env files out of Git (.gitignore/.dockerignore) and use Compose top-level secrets or a secrets manager.",
		references: ["CWE-538", "CWE-522", "NIST 800-190"]
	},
	"DOCKER_COMPOSE_EXTRA_HOSTS_SPOOF": {
		pattern: "services:\n  app:\n    extra_hosts:\n      - 'api.internal:10.0.0.99'",
		fix: "services:\n  app: {}   # rely on real DNS; remove static host overrides",
		explanation: "An extra_hosts entry pins a hostname to a static IP, which can spoof or override DNS for the container and redirect traffic. Remove unnecessary entries so hostname resolution stays verifiable; document and restrict any mapping that is genuinely required.",
		references: ["CWE-350", "NIST 800-190"]
	},
	"DOCKER_COMPOSE_HEALTHCHECK_DISABLED": {
		pattern: "services:\n  app:\n    healthcheck:\n      disable: true",
		fix: "services:\n  app:\n    healthcheck:\n      test: ['CMD', 'curl', '-f', 'http://localhost:8080/health']\n      interval: 30s\n      timeout: 5s\n      retries: 3",
		explanation: "Disabling the healthcheck means the orchestrator cannot detect a hung or compromised container and keeps routing traffic to it. Define a real healthcheck and ensure the orchestrator acts on the unhealthy status.",
		references: ["CWE-754", "NIST 800-190"]
	},
	"DOCKER_COMPOSE_HOST_DEVICE": {
		pattern: "services:\n  app:\n    devices:\n      - '/dev/sda:/dev/sda'",
		fix: "services:\n  app: {}   # no host device mapping\n# If a device is truly required, scope it narrowly and add cap_drop + seccomp.",
		explanation: "Mapping a host /dev device into the container gives direct hardware access that can be abused to reach the host or other tenants. Remove the devices mapping unless strictly required, never map block devices, and combine minimal device access with dropped capabilities.",
		references: ["CWE-668", "NIST 800-190", "CIS Docker Benchmark 5.17"]
	},
	"DOCKER_COMPOSE_HOST_NAMESPACE": {
		pattern: "services:\n  app:\n    pid: host\n    network_mode: host",
		fix: "services:\n  app:\n    # default private namespaces + bridge networking\n    ports:\n      - '127.0.0.1:8080:8080'",
		explanation: "Sharing a host namespace (pid/network/ipc/userns: host) breaks container isolation from the host. Use private namespaces and bridge networking, exposing only the specific ports needed via the ports mapping.",
		references: ["CWE-668", "NIST 800-190", "CIS Docker Benchmark 5.9"]
	},
	"DOCKER_COMPOSE_IPC_HOST": {
		pattern: "services:\n  app:\n    ipc: host",
		fix: "services:\n  app: {}   # default private IPC namespace\n# For shared memory between specific services use: ipc: shareable",
		explanation: "ipc: host shares the host IPC namespace (shared memory), breaking isolation between the container and host. Use the default private IPC namespace, or ipc: shareable scoped only to the services that need shared memory.",
		references: ["CWE-668", "NIST 800-190", "CIS Docker Benchmark 5.16"]
	},
	"DOCKER_COMPOSE_LABEL_SECRET": {
		pattern: "services:\n  app:\n    labels:\n      api_key: 'YOUR_API_KEY'",
		fix: "services:\n  app:\n    labels:\n      app: payments   # non-sensitive metadata only\n    secrets:\n      - api_key",
		explanation: "Labels are visible via docker inspect to anyone with daemon access, so embedding a secret in a label exposes it. Remove secret values from labels and deliver them via Compose secrets or a secrets manager.",
		references: ["CWE-200", "CWE-522", "NIST 800-190"]
	},
	"DOCKER_COMPOSE_NO_RESOURCE_LIMIT": {
		pattern: "services:\n  app:\n    mem_limit: 0",
		fix: "services:\n  app:\n    mem_limit: 512m\n    cpus: 1.0\n    # or deploy.resources.limits under Swarm",
		explanation: "An unbounded resource value (mem_limit/cpus: 0) lets one container exhaust host CPU/memory and cause a local DoS. Set concrete memory and CPU limits for every service so no container can starve the host or co-tenants.",
		references: ["CWE-770", "NIST 800-190", "CIS Docker Benchmark 5.10"]
	},
	"DOCKER_COMPOSE_PRIVILEGED": {
		pattern: "services:\n  app:\n    privileged: true",
		fix: "services:\n  app:\n    privileged: false\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true",
		explanation: "privileged: true grants all capabilities and disables isolation, enabling host takeover. Remove it, grant only the specific cap_add the workload needs, and keep default seccomp/apparmor profiles.",
		references: ["CWE-250", "CWE-269", "NIST 800-190", "CIS Docker Benchmark 5.4"]
	},
	"DOCKER_COMPOSE_SENSITIVE_BIND_MOUNT": {
		pattern: "services:\n  app:\n    volumes:\n      - '/etc:/host-etc'",
		fix: "services:\n  app:\n    volumes:\n      - './data:/app/data:ro'   # only the needed dir, read-only",
		explanation: "Bind-mounting a sensitive host path (/, /etc, /root, /proc, /sys, ~/.ssh) gives the container read/write access to host secrets and config. Mount only the specific data directory the service needs, read-only where possible.",
		references: ["CWE-668", "NIST 800-190", "CIS Docker Benchmark 5.5"]
	},
	"DOCKER_COMPOSE_TMPFS_EXEC": {
		pattern: "services:\n  app:\n    tmpfs:\n      - /tmp:exec",
		fix: "services:\n  app:\n    tmpfs:\n      - /tmp:noexec,nosuid,nodev",
		explanation: "A tmpfs mounted with exec is a writable, executable in-memory filesystem where an attacker can stage and run payloads. Mount tmpfs with noexec,nosuid,nodev unless execution is genuinely required.",
		references: ["CWE-732", "NIST 800-190"]
	},
	"DOCKER_COMPOSE_UNCONFINED": {
		pattern: "services:\n  app:\n    security_opt:\n      - seccomp:unconfined",
		fix: "services:\n  app:\n    security_opt:\n      - no-new-privileges:true   # keep default seccomp/apparmor",
		explanation: "security_opt seccomp:unconfined or apparmor:unconfined removes the syscall sandbox that protects the host. Keep the default profiles; if a specific syscall is needed, supply a tailored seccomp profile rather than disabling it entirely.",
		references: ["CWE-693", "NIST 800-190", "CIS Docker Benchmark 5.21"]
	},
	"DOCKER_COMPOSE_UNTRUSTED_DNS": {
		pattern: "services:\n  app:\n    dns:\n      - 8.8.8.8",
		fix: "services:\n  app: {}   # use the org's approved resolver / default DNS",
		explanation: "Pinning a public DNS resolver overrides the corporate resolver and can bypass internal name resolution and DNS-based egress controls. Use the organization's approved resolver and enforce DNS egress policy at the network layer.",
		references: ["CWE-350", "NIST 800-190"]
	},
	"DOCKER_COMPOSE_USER_ROOT": {
		pattern: "services:\n  app:\n    user: root",
		fix: "services:\n  app:\n    user: '1000:1000'",
		explanation: "Running the service as user root (uid 0) maximizes the blast radius of any compromise. Set user to a non-root uid:gid and ensure the image owns its working directories as that user.",
		references: ["CWE-250", "NIST 800-190", "CIS Docker Benchmark 5.4"]
	},
	"DOCKER_COPY_FROM_SECRET": {
		pattern: "FROM builder AS build\n# ...\nFROM base\nCOPY --from=build /root/.npmrc /root/.npmrc",
		fix: "# Use a BuildKit secret mount instead of copying the file into the image:\nRUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci\n# no .npmrc / key / .env is present in the final layer",
		explanation: "A multi-stage COPY --from that pulls a key, .pem, .env, or .npmrc into the final image persists that secret in the runtime layer. Use BuildKit secret mounts that never land in a layer and inject credentials at runtime from a secrets manager.",
		references: ["CWE-522", "CWE-200", "NIST 800-190"]
	},
	"DOCKER_COPY_GIT_DIR": {
		pattern: "COPY .git /app/.git",
		fix: "# .dockerignore:\n#   .git\nCOPY dist/ /app/   # copy only built artifacts",
		explanation: "Copying the .git directory into the image leaks full repository history, including rotated secrets and deploy keys ever committed. Add .git to .dockerignore, copy only the artifacts needed at runtime, and rotate any credential that was in history.",
		references: ["CWE-538", "CWE-200", "NIST 800-190"]
	},
	"DOCKER_COPY_WHOLE_CONTEXT": {
		pattern: "COPY . .",
		fix: "COPY package*.json ./\nRUN npm ci\nCOPY src/ ./src/\n# plus a comprehensive .dockerignore (.git, .env, secrets, node_modules)",
		explanation: "COPY . . copies the entire build context into the image, leaking .git, .env, keys, and source not needed at runtime. Copy only the specific files required and add a comprehensive .dockerignore.",
		references: ["CWE-538", "CWE-200", "NIST 800-190"]
	},
	"DOCKER_DAEMON_TCP_EXPOSED": {
		pattern: "# dockerd -H tcp://0.0.0.0:2375",
		fix: "# Use the local unix socket only:\n#   dockerd -H unix:///var/run/docker.sock\n# If remote is required, require mutual TLS on 2376 and firewall to known hosts.",
		explanation: "Exposing the Docker daemon over TCP (2375/2376) gives an unauthenticated socket full host root control. Use the local unix socket with restricted permissions; if remote access is unavoidable, require mutual TLS with client certificates and firewall the port.",
		references: ["CWE-306", "NIST 800-190", "CIS Docker Benchmark 2.x"]
	},
	"DOCKER_DEPRECATED_KEY_TRUST": {
		pattern: "RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ABCD1234",
		fix: "RUN curl -fsSL https://example.com/repo.gpg -o /etc/apt/keyrings/example.gpg \\\n && echo 'deb [signed-by=/etc/apt/keyrings/example.gpg] https://example.com/apt stable main' \\\n    > /etc/apt/sources.list.d/example.list",
		explanation: "apt-key adv and gpg --keyserver fetch keys over the network without fingerprint pinning, enabling a key-substitution attack. apt-key is deprecated; download the key over HTTPS, verify its fingerprint, and store it under /etc/apt/keyrings with signed-by.",
		references: ["CWE-494", "CWE-347", "NIST 800-190"]
	},
	"DOCKER_EXPOSE_SENSITIVE_PORT": {
		pattern: "EXPOSE 3306",
		fix: "# Run the database in a dedicated container on an internal network;\n# do not EXPOSE 3306/5432/25/23 from the application image.",
		explanation: "EXPOSEing a database or admin port (3306/5432/25/23) from an app image advertises services that should never be published from that image. Remove the EXPOSE, run those services in dedicated containers on an internal network, and require auth + TLS if reachable.",
		references: ["CWE-668", "NIST 800-190", "CIS Docker Benchmark 5.7"]
	},
	"DOCKER_EXPOSE_SSH": {
		pattern: "EXPOSE 22",
		fix: "# Remove the SSH server and EXPOSE 22; use 'docker exec' / 'kubectl exec' for shells.",
		explanation: "EXPOSEing port 22 to run an SSH daemon inside a container is an anti-pattern that adds a remote-access attack surface. Remove SSH and use docker/kubectl exec; if remote access is truly required, run SSH in a separate hardened, network-restricted service.",
		references: ["CWE-1188", "NIST 800-190", "Docker Best Practices"]
	},
	"DOCKER_IMPLICIT_REGISTRY": {
		pattern: "FROM redis:latest",
		fix: "FROM registry.example.com/library/redis:7.2@sha256:2c8e...   # fully qualified + digest",
		explanation: "A base image with no registry namespace on :latest is implicitly pulled from Docker Hub, exposing it to namespace/tag confusion. Use a fully qualified reference including registry host and namespace, pin by digest, and mirror approved images internally.",
		references: ["CWE-1357", "MITRE ATT&CK T1195.002", "NIST 800-190"]
	},
	"DOCKER_INSECURE_DOWNLOAD_FLAG": {
		pattern: "RUN wget --no-check-certificate https://example.com/tool -O /usr/bin/tool",
		fix: "RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \\\n && wget https://example.com/tool -O /usr/bin/tool   # cert verification on",
		explanation: "Disabling certificate verification (wget --no-check-certificate / curl -k / --insecure) exposes the build to a man-in-the-middle attack. Remove the flag, install the correct CA bundle so HTTPS validation succeeds, and let downloads fail on an invalid certificate.",
		references: ["CWE-295", "NIST 800-190", "OWASP Top 10 A02:2021"]
	},
	"DOCKER_NO_HEALTHCHECK": {
		pattern: "# Dockerfile with no HEALTHCHECK instruction",
		fix: "HEALTHCHECK --interval=30s --timeout=5s --retries=3 \\\n  CMD curl -f http://localhost:8080/health || exit 1",
		explanation: "Without a HEALTHCHECK, orchestrators cannot detect a hung or compromised container and keep routing traffic to it. Add a HEALTHCHECK that verifies the app is actually serving, and configure the orchestrator to act on the status.",
		references: ["CWE-754", "NIST 800-190", "CIS Docker Benchmark 4.6"]
	},
	"DOCKER_NO_SANDBOX_FLAG": {
		pattern: "CMD [\"chrome\", \"--no-sandbox\"]",
		fix: "USER appuser\nCMD [\"chrome\"]   # run as non-root so the sandbox initializes",
		explanation: "--no-sandbox disables the browser/runtime sandbox, removing an exploit containment layer. Run the process as a non-root user so the sandbox can initialize, or use a seccomp-based sandbox rather than disabling sandboxing.",
		references: ["CWE-693", "NIST 800-190"]
	},
	"DOCKER_NO_USER_DIRECTIVE": {
		pattern: "FROM node:20-alpine\nCOPY . /app\nCMD [\"node\", \"server.js\"]",
		fix: "FROM node:20-alpine\nRUN adduser -D -u 1000 appuser\nCOPY --chown=appuser . /app\nUSER appuser\nCMD [\"node\", \"server.js\"]",
		explanation: "With no USER directive, the container runs every process as root, maximizing compromise impact. Create a dedicated low-privilege user and switch to it with USER before CMD/ENTRYPOINT.",
		references: ["CWE-250", "NIST 800-190", "CIS Docker Benchmark 4.1"]
	},
	"DOCKER_NPM_INSECURE": {
		pattern: "RUN npm install --unsafe-perm --registry=http://registry.local",
		fix: "USER appuser\nRUN npm ci --registry=https://registry.npmjs.org   # lockfile + https, non-root",
		explanation: "npm install with --unsafe-perm runs lifecycle scripts as root, and an http:// registry fetches packages over cleartext. Use an https registry, run npm as non-root, and use npm ci with a committed lockfile and integrity hashes.",
		references: ["CWE-494", "CWE-319", "NIST 800-190"]
	},
	"DOCKER_ONBUILD_TRIGGER": {
		pattern: "ONBUILD COPY . /app\nONBUILD RUN make",
		fix: "# Avoid ONBUILD; make build steps explicit in each consuming Dockerfile:\nCOPY . /app\nRUN make",
		explanation: "ONBUILD triggers execute implicitly in any downstream image, hiding behavior from consumers who may not expect it. Avoid ONBUILD and make build steps explicit in each consuming Dockerfile so behavior is visible and auditable.",
		references: ["CWE-829", "NIST 800-190"]
	},
	"DOCKER_PIP_INSECURE_INDEX": {
		pattern: "RUN pip install --trusted-host pypi.internal -i http://pypi.internal/simple foo",
		fix: "RUN pip install --require-hashes -i https://pypi.org/simple -r requirements.txt",
		explanation: "pip install with --trusted-host or an http:// index fetches packages without TLS/host verification, enabling supply-chain injection. Use only https index URLs, drop --trusted-host, and pin packages with hashes via --require-hashes.",
		references: ["CWE-494", "CWE-319", "NIST 800-190"]
	},
	"DOCKER_PLAINTEXT_BUILD_FETCH": {
		pattern: "RUN git clone http://github.com/acme/app.git /src",
		fix: "RUN git clone https://github.com/acme/app.git /src && git -C /src checkout <commit-sha>",
		explanation: "Fetching code or packages over cleartext http:// lets a network attacker MITM the transfer and inject code into the image. Use https (or git+ssh) for all clones and repository sources and pin to a commit or release.",
		references: ["CWE-319", "NIST 800-190", "OWASP Top 10 A02:2021"]
	},
	"DOCKER_PRIVILEGED_FLAG": {
		pattern: "# docker run --privileged myimage   (or privileged: true)",
		fix: "# docker run --cap-drop=ALL --cap-add=NET_ADMIN --security-opt no-new-privileges myimage",
		explanation: "--privileged / privileged:true grants all Linux capabilities and disables container isolation, enabling host takeover. Remove privileged mode and grant only the specific capabilities the workload needs via cap_add.",
		references: ["CWE-250", "CWE-269", "NIST 800-190", "CIS Docker Benchmark 5.4"]
	},
	"DOCKER_RUN_PIPE_TO_SHELL": {
		pattern: "RUN curl -sSL https://get.example.com | bash",
		fix: "RUN curl --fail -sSL https://get.example.com/install.sh -o /tmp/install.sh \\\n && echo \"<sha256>  /tmp/install.sh\" | sha256sum -c - \\\n && bash /tmp/install.sh && rm /tmp/install.sh",
		explanation: "Piping a remote download straight into a shell is unverified remote code execution at build time; a compromised endpoint runs arbitrary code. Fetch to a file, verify a published sha256 or GPG signature, then execute a pinned version.",
		references: ["CWE-494", "NIST 800-190", "OWASP Top 10 A08:2021"]
	},
	"DOCKER_RUN_SECRET_NO_MOUNT": {
		pattern: "RUN echo $GITHUB_TOKEN > /root/.netrc && make fetch",
		fix: "RUN --mount=type=secret,id=gh_token \\\n  GITHUB_TOKEN=$(cat /run/secrets/gh_token) make fetch",
		explanation: "A RUN that consumes a token/password env var without a BuildKit secret mount exposes the secret in build env and may leak it into layers. Provide build-time secrets via RUN --mount=type=secret and read them from /run/secrets only during that step.",
		references: ["CWE-522", "CWE-200", "NIST 800-190"]
	},
	"DOCKER_RUN_SUDO": {
		pattern: "RUN sudo apt-get install -y curl",
		fix: "# Perform privileged steps as root before dropping user, no sudo installed:\nRUN apt-get update && apt-get install -y --no-install-recommends curl\nUSER appuser",
		explanation: "Installing or using sudo inside the image defeats least-privilege and enables in-container privilege escalation. Run privileged build steps before switching to a non-root USER and do not install the sudo package.",
		references: ["CWE-250", "NIST 800-190", "CIS Docker Benchmark 4.1"]
	},
	"DOCKER_SCRATCH_ADD_REMOTE": {
		pattern: "FROM scratch\nADD https://example.com/app /app",
		fix: "FROM alpine AS fetch\nRUN apk add --no-cache ca-certificates curl \\\n && curl --fail -sSL https://example.com/app -o /app \\\n && echo \"<sha256>  /app\" | sha256sum -c -\nFROM scratch\nCOPY --from=fetch /app /app",
		explanation: "FROM scratch has no CA store, so an ADD of a remote URL cannot be TLS-verified and ADD performs no integrity check. Fetch and verify the artifact (checksum/signature) in a builder stage that has a CA bundle, then COPY it into the scratch image.",
		references: ["CWE-494", "CWE-295", "NIST 800-190"]
	},
	"DOCKER_SECRETS_IN_ENV": {
		pattern: "ENV DB_PASSWORD=SuperSecret123",
		fix: "# No secret in ENV; inject at runtime:\n#   docker run -e DB_PASSWORD=... (from a secrets manager) myimage\n# or use Docker secrets / --mount=type=secret at build time.",
		explanation: "An ENV instruction with a secret bakes the credential into the image layer, visible via docker inspect and docker history. Remove secrets from ENV and inject them at container start from a secrets manager; audit layers with docker history --no-trunc.",
		references: ["CWE-798", "CWE-200", "NIST 800-190", "CIS Docker Benchmark 4.10"]
	},
	"DOCKER_SECRET_IN_BUILD_ARG": {
		pattern: "ARG API_KEY\nRUN ./configure --key=$API_KEY",
		fix: "RUN --mount=type=secret,id=api_key \\\n  ./configure --key=\"$(cat /run/secrets/api_key)\"",
		explanation: "ARG values are recorded in image history and visible via docker history, so passing a secret through ARG exposes it. Use BuildKit secret mounts, which are not persisted in layers, and inject runtime credentials via a secrets manager.",
		references: ["CWE-200", "CWE-522", "NIST 800-190"]
	},
	"DOCKER_SETUID_BIT": {
		pattern: "RUN chmod u+s /usr/bin/mytool",
		fix: "# Strip setuid/setgid bits and run as non-root:\nRUN find / -perm /6000 -type f -exec chmod a-s {} \\; || true\nUSER appuser",
		explanation: "A setuid/setgid binary in the image is a classic privilege-escalation primitive. Remove setuid/setgid bits, strip them from unneeded base-image binaries, and run the workload as a non-root user.",
		references: ["CWE-250", "CWE-732", "NIST 800-190"]
	},
	"DOCKER_SHELL_FORM_ENTRYPOINT": {
		pattern: "ENTRYPOINT node server.js",
		fix: "ENTRYPOINT [\"node\", \"server.js\"]   # exec form; PID 1 receives signals",
		explanation: "Shell-form ENTRYPOINT/CMD runs the app under /bin/sh -c as a child of PID 1, so it never receives SIGTERM/SIGINT for graceful shutdown. Use exec (JSON array) form so the process is PID 1 and handles termination signals.",
		references: ["CWE-703", "NIST 800-190", "Docker Best Practices"]
	},
	"DOCKER_SOCKET_MOUNT": {
		pattern: "services:\n  ci:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock",
		fix: "services:\n  ci:\n    # no docker.sock mount; use a socket proxy with restricted API:\n    environment:\n      DOCKER_HOST: tcp://docker-socket-proxy:2375",
		explanation: "Mounting the Docker socket into a container hands it full daemon control, a trivial escape to host root. Remove docker.sock mounts; if Docker-in-Docker is required use rootless Docker or a restricted socket proxy (e.g. docker-socket-proxy).",
		references: ["CWE-668", "CWE-250", "NIST 800-190", "CIS Docker Benchmark 5.31"]
	},
	"DOCKER_TLS_VERIFY_DISABLED": {
		pattern: "ENV NODE_TLS_REJECT_UNAUTHORIZED=0",
		fix: "# Remove the TLS-disabling ENV/ARG and install the correct CA bundle:\nRUN apt-get update && apt-get install -y --no-install-recommends ca-certificates",
		explanation: "An ENV/ARG that disables TLS verification (NODE_TLS_REJECT_UNAUTHORIZED=0, PYTHONHTTPSVERIFY=0, GIT_SSL_NO_VERIFY) enables man-in-the-middle attacks. Remove it and fix the underlying CA-trust problem by installing the correct CA bundle.",
		references: ["CWE-295", "NIST 800-190", "OWASP Top 10 A02:2021"]
	},
	"DOCKER_TMP_DOWNLOAD_EXEC": {
		pattern: "RUN curl -sSL https://example.com/tool -o /tmp/tool && chmod +x /tmp/tool && /tmp/tool",
		fix: "RUN curl --fail -sSL https://example.com/tool -o /opt/build/tool \\\n && echo \"<sha256>  /opt/build/tool\" | sha256sum -c - \\\n && chmod +x /opt/build/tool && /opt/build/tool",
		explanation: "Downloading an artifact into world-writable /tmp and executing it enables build-time code injection. Download to a private directory, verify a checksum or signature, then execute the pinned artifact.",
		references: ["CWE-377", "CWE-494", "NIST 800-190"]
	},
	"DOCKER_UNPINNED_BASE_IMAGE": {
		pattern: "FROM node:20-alpine",
		fix: "FROM node:20-alpine@sha256:6d0f18a1c67dc218c4af50c21256616286a53c09e500fd3a6a1c9c6c7b0c0a2b",
		explanation: "A FROM using a mutable tag with no SHA digest is a supply-chain risk: a compromised or overwritten upstream tag silently changes the base image on every build (ATT&CK T1195.002). Pin the base image to an immutable digest obtained via docker inspect RepoDigests.",
		references: ["CWE-1357", "MITRE ATT&CK T1195.002", "NIST 800-190"]
	},
	"DOCKER_UNTRUSTED_REGISTRY": {
		pattern: "FROM my-registry.example.com:5000/app:latest",
		fix: "FROM registry.example.com/app:1.2.3@sha256:9a1b...   # trusted registry, HTTPS, digest",
		explanation: "A base image pulled from an http/self-hosted registry host:port may be served over cleartext or from an unvetted source. Pull only from a trusted registry over HTTPS, pin by @sha256 digest, and enforce signature verification (cosign / Docker Content Trust).",
		references: ["CWE-494", "NIST 800-190", "MITRE ATT&CK T1195.002"]
	},
	"DOCKER_WORKDIR_ROOT": {
		pattern: "WORKDIR /",
		fix: "WORKDIR /app   # dedicated app dir owned by the non-root user",
		explanation: "WORKDIR / makes subsequent COPY/RUN operate on system directories, risking overwrite of OS files. Set WORKDIR to a dedicated application directory owned by the non-root runtime user.",
		references: ["CWE-668", "NIST 800-190"]
	},
	"DOCKER_WRITE_SSH_DIR": {
		pattern: "RUN mkdir -p /root/.ssh && echo \"$SSH_KEY\" > /root/.ssh/id_rsa",
		fix: "# Do not bake keys in; use BuildKit SSH forwarding for git during build:\nRUN --mount=type=ssh git clone git@github.com:acme/app.git /src",
		explanation: "Writing SSH keys or config into an image directory (/root/.ssh, /etc/ssh, ~/.ssh) bakes credentials into the image and leaks them. Mount keys at runtime or use BuildKit SSH forwarding (RUN --mount=type=ssh) for git operations during build.",
		references: ["CWE-522", "CWE-798", "NIST 800-190"]
	},
	"FLUX_AUTOPRUNE_NO_DECRYPTION": {
		pattern: "kind: Kustomization\nspec:\n  interval: 5m\n  prune: true\n  sourceRef: { kind: GitRepository, name: app }",
		fix: "kind: Kustomization\nspec:\n  interval: 10m\n  prune: true\n  decryption:\n    provider: sops\n    secretRef: { name: sops-age }\n  sourceRef: { kind: GitRepository, name: app }",
		explanation: "A Kustomization/HelmRelease that auto-prunes on an interval with no decryption block leaves secrets unmanaged and auto-applies upstream changes. Add a spec.decryption (SOPS) block so Secrets are decrypted in-cluster, and pin the source to a verified revision before enabling prune.",
		references: ["CWE-311", "CWE-522", "NIST 800-190", "NIST 800-53 SC-28"]
	},
	"FLUX_BUCKET_INSECURE": {
		pattern: "kind: Bucket\nspec:\n  endpoint: minio.example.com:9000\n  insecure: true",
		fix: "kind: Bucket\nspec:\n  endpoint: minio.example.com:9000\n  # insecure removed -> TLS enforced\n  secretRef: { name: minio-creds }",
		explanation: "A Flux Bucket source over plaintext/insecure transport or a public endpoint makes fetched manifests tamperable and unauthenticated. Use an HTTPS/TLS endpoint, remove insecure: true, authenticate via a secretRef, and restrict the bucket policy to the Flux identity.",
		references: ["CWE-319", "CWE-306", "NIST 800-190", "NIST 800-53 SC-8"]
	},
	"FLUX_HELMRELEASE_INLINE_SECRET": {
		pattern: "kind: HelmRelease\nspec:\n  values:\n    database:\n      password: SuperSecret123",
		fix: "kind: HelmRelease\nspec:\n  valuesFrom:\n    - kind: Secret\n      name: db-credentials   # SOPS-decrypted\n  decryption:\n    provider: sops\n    secretRef: { name: sops-age }",
		explanation: "A HelmRelease with secret-like values (password/apiKey/token) inline under spec.values and no decryption commits credentials in plaintext. Move secrets to valuesFrom a SOPS-decrypted Secret, configure spec.decryption, and rotate any inline credential.",
		references: ["CWE-798", "CWE-522", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"FLUX_HELM_REPO_HTTP": {
		pattern: "kind: HelmRepository\nspec:\n  url: http://charts.example.com",
		fix: "kind: HelmRepository\nspec:\n  url: https://charts.example.com\n  # or oci://registry.example.com/charts",
		explanation: "A HelmRepository/chart source over plaintext HTTP makes chart payloads MITM-tamperable in transit. Use https:// or oci:// for all chart URLs, supply a certSecretRef for private registries rather than disabling TLS, and enable chart provenance verification.",
		references: ["CWE-319", "NIST 800-190", "OWASP Top 10 A02:2021"]
	},
	"FLUX_IMAGE_AUTOMATION_PUSH_PROTECTED_BRANCH": {
		pattern: "kind: ImageUpdateAutomation\nspec:\n  git:\n    push:\n      branch: main   # protected/deploy branch",
		fix: "kind: ImageUpdateAutomation\nspec:\n  git:\n    push:\n      branch: flux-image-updates   # dedicated automation branch\n# require a reviewed PR to merge into the deploy branch",
		explanation: "An ImageUpdateAutomation that pushes directly to a protected/deploy branch bypasses PR review and protected-branch controls for automated image bumps. Push to a dedicated automation branch, require a reviewed PR to merge, and verify cosign signatures before promotion.",
		references: ["CWE-284", "MITRE ATT&CK T1195", "NIST 800-53 CM-3"]
	},
	"FLUX_IMAGE_AUTOUPDATE_FLOATING_TAG": {
		pattern: "kind: ImagePolicy\nspec:\n  policy:\n    semver: { range: '>=1.0.0' }",
		fix: "kind: ImagePolicy\nspec:\n  policy:\n    semver: { range: '1.4.x' }\n# require cosign verification (Kyverno/policy-controller) before admission,\n# and gate ImageUpdateAutomation commits behind a protected branch + PR review",
		explanation: "An ImagePolicy/ImageUpdateAutomation that auto-deploys a semver range or :latest auto-pulls and rolls out a poisoned upstream image. Pin images to an immutable digest, require cosign signature verification before admission, and gate auto-update commits behind PR review.",
		references: ["CWE-494", "CWE-829", "MITRE ATT&CK T1195.002", "NIST 800-190"]
	},
	"FLUX_KUSTOMIZATION_PATH_TRAVERSAL": {
		pattern: "kind: Kustomization\nspec:\n  path: ../../other-team/overlays/prod",
		fix: "kind: Kustomization\nspec:\n  path: ./apps/myapp/overlays/prod   # fixed subdir, no '../'",
		explanation: "A Kustomization spec.path with ../ traversal can point the reconciler outside its intended directory to apply sibling manifests or reach other teams' secrets. Set spec.path to a fixed subdirectory and use per-app GitRepository sources instead of traversing.",
		references: ["CWE-22", "NIST 800-190", "NIST 800-53 AC-6"]
	},
	"FLUX_KUSTOMIZATION_VALIDATION_DISABLED": {
		pattern: "kind: Kustomization\nspec:\n  validation: none",
		fix: "kind: Kustomization\nspec:\n  # 'validation' removed; Flux applies with server-side schema validation\n  sourceRef: { kind: GitRepository, name: app }",
		explanation: "validation: none applies reconciled manifests without client/server schema validation, so malformed or malicious resources pass unchecked. Remove it (modern Flux validates server-side), keep Gatekeeper/Kyverno admission enforcing, and pin the source to a verified revision.",
		references: ["CWE-20", "NIST 800-190", "NIST 800-53 SI-10"]
	},
	"FLUX_KUSTOMIZE_ENABLE_HELM": {
		pattern: "kind: Kustomization\nspec:\n  # kustomize build --enable-helm renders arbitrary remote charts\n  path: ./with-helm-charts",
		fix: "# Prefer a HelmRelease with verify + decryption over --enable-helm.\n# If unavoidable, pin chart name+version+repo and vendor it:\nhelmGlobals:\n  chartHome: ./vendored-charts   # reviewed, not pulled at build time",
		explanation: "Enabling the Kustomize Helm inflator (--enable-helm / helmGlobals) renders arbitrary remote charts, running chart hooks and templating as a code-execution sink. Use a HelmRelease with verify and decryption instead, or pin and vendor the chart and verify provenance.",
		references: ["CWE-94", "CWE-829", "NIST 800-190", "MITRE ATT&CK T1195"]
	},
	"FLUX_NO_DEPENDS_ON_ORDERING": {
		pattern: "# Multiple Kustomizations, none declare dependsOn\nkind: Kustomization\nmetadata: { name: apps }\nspec:\n  path: ./apps",
		fix: "kind: Kustomization\nmetadata: { name: apps }\nspec:\n  path: ./apps\n  dependsOn:\n    - { name: namespaces }\n    - { name: network-policies }\n    - { name: rbac }\n  healthChecks:\n    - { kind: NetworkPolicy, name: default-deny, namespace: prod }",
		explanation: "When multiple Kustomizations declare no dependsOn, apply ordering is unenforced, so NetworkPolicies, RBAC, or PSA may be applied after the workloads they protect. Declare spec.dependsOn so security prerequisites reconcile first, gated by health checks.",
		references: ["CWE-696", "NIST 800-190", "NIST 800-53 CM-6"]
	},
	"FLUX_OCI_FLOATING_TAG_NO_VERIFY": {
		pattern: "kind: OCIRepository\nspec:\n  ref: { tag: latest }",
		fix: "kind: OCIRepository\nspec:\n  ref: { digest: sha256:9a1b... }\n  verify:\n    provider: cosign\n    matchOIDCIdentity:\n      - issuer: https://token.actions.githubusercontent.com\n        subject: https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1",
		explanation: "An OCIRepository tracking a floating tag (latest/main/stable) with no verify.provider auto-pulls and applies a re-pushed tag with no signature check. Pin ref to an immutable digest and add spec.verify.provider: cosign with the publisher identity so unsigned artifacts are rejected.",
		references: ["CWE-494", "CWE-345", "MITRE ATT&CK T1195.002", "NIST 800-190"]
	},
	"FLUX_POSTBUILD_SUBSTITUTE_INJECTION": {
		pattern: "kind: Kustomization\nspec:\n  postBuild:\n    substituteFrom:\n      - kind: ConfigMap\n        name: app-vars   # if attacker-writable, injects into manifests",
		fix: "kind: Kustomization\nspec:\n  postBuild:\n    substituteFrom:\n      - kind: ConfigMap\n        name: app-vars\n        optional: false   # fail closed; source lives in a locked-down ns\n# never substitute into image/securityContext/serviceAccountName",
		explanation: "postBuild.substituteFrom pulls variables from a ConfigMap/Secret into rendered manifests, enabling variable injection if that source is attacker-writable. Source substituteFrom only from controller-only namespaces with locked-down RBAC, never substitute into security fields, and fail closed.",
		references: ["CWE-94", "CWE-20", "NIST 800-190", "NIST 800-53 SI-10"]
	},
	"FLUX_RECEIVER_WEAK_TOKEN": {
		pattern: "kind: Receiver\nspec:\n  type: github\n  # no secretRef / weak token",
		fix: "kind: Receiver\nspec:\n  type: generic-hmac\n  secretRef: { name: receiver-token }   # high-entropy HMAC secret\n# restrict the receiver Ingress to the provider's IP ranges",
		explanation: "A Flux Receiver webhook without a strong HMAC secretRef lets anyone who reaches the URL force-reconcile and trigger deploys. Use type: generic-hmac with a high-entropy secretRef, restrict the Ingress to the provider's IP ranges, and rotate the token periodically.",
		references: ["CWE-306", "CWE-347", "NIST 800-190", "NIST 800-53 IA-5"]
	},
	"FLUX_SERVICEACCOUNT_IMPERSONATION": {
		pattern: "kind: Kustomization\nspec:\n  serviceAccountName: default   # or cluster-admin-bound SA",
		fix: "kind: Kustomization\nspec:\n  serviceAccountName: team-a-reconciler   # least-privilege, ns-scoped\n# run flux with --default-service-account and --no-cross-namespace-refs",
		explanation: "A Kustomization/HelmRelease with a privileged serviceAccountName (default/cluster-admin/controller SA) applies manifests with broad RBAC, so a malicious manifest inherits cluster-admin. Set a dedicated least-privilege SA scoped to the target namespace and enable Flux multi-tenancy lockdown.",
		references: ["CWE-269", "CWE-266", "NIST 800-190", "NIST 800-53 AC-6"]
	},
	"FLUX_SOURCE_UNVERIFIED": {
		pattern: "kind: GitRepository\nspec:\n  url: https://github.com/acme/app.git\n  ref: { branch: main }   # no verify block",
		fix: "kind: GitRepository\nspec:\n  url: https://github.com/acme/app.git\n  ref: { tag: v1.4.2 }\n  verify:\n    mode: HEAD\n    secretRef: { name: cosign-pubkeys }",
		explanation: "A GitRepository/OCIRepository with no verify block (or insecure: true) makes Flux pull and apply unauthenticated, tamperable source. Add a spec.verify block (cosign or pgp) so Flux rejects unsigned revisions, remove insecure, and pin to an immutable tag/digest.",
		references: ["CWE-345", "CWE-494", "MITRE ATT&CK T1195", "NIST 800-190"]
	},
	"GITOPS_PLAINTEXT_SECRET": {
		pattern: "apiVersion: v1\nkind: Secret\nmetadata: { name: db }\nstringData:\n  password: SuperSecret123",
		fix: "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata: { name: db }\nspec:\n  encryptedData:\n    password: AgB2c1f...   # encrypted, decryptable only in-cluster",
		explanation: "A plaintext kind: Secret committed to a GitOps repo (with no Sealed Secrets/SOPS/External Secrets) exposes credentials to anyone with repo read access. Move Secrets to Sealed Secrets, SOPS, or External Secrets, rotate anything ever committed, and add a CI guard blocking raw Secret manifests.",
		references: ["CWE-798", "CWE-312", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"HELM_CHART_LOCK_DIGEST_MISSING": {
		pattern: "# Chart.yaml declares dependencies but no Chart.lock is committed\ndependencies:\n  - name: postgresql\n    version: 12.5.6\n    repository: https://charts.bitnami.com/bitnami",
		fix: "# Chart.lock committed after `helm dependency update`:\ndependencies:\n  - name: postgresql\n    version: 12.5.6\n    repository: https://charts.bitnami.com/bitnami\ndigest: sha256:1a2b3c...\ngenerated: \"2026-07-06T00:00:00Z\"",
		explanation: "Declaring chart dependencies with no Chart.lock (sha256 digests) makes dependency resolution non-reproducible, so a mutated upstream chart can be silently pulled. Run helm dependency update, commit Chart.lock, pin exact versions, and verify the lock digest in CI.",
		references: ["CWE-494", "CWE-1357", "SLSA L2", "NIST 800-190"]
	},
	"HELM_DEPENDENCY_HTTP_REPO": {
		pattern: "dependencies:\n  - name: redis\n    version: 18.1.5\n    repository: http://charts.example.com",
		fix: "dependencies:\n  - name: redis\n    version: 18.1.5\n    repository: https://charts.example.com\n    # or oci://registry.example.com/charts",
		explanation: "A Chart.yaml dependency from a plaintext http:// (or alias) repository makes subchart payloads MITM-tamperable and unverified. Use https:// or oci:// repositories, pin each dependency to an exact version, commit Chart.lock, and verify provenance.",
		references: ["CWE-319", "CWE-494", "NIST 800-190", "OWASP Top 10 A02:2021"]
	},
	"HELM_FILES_GET_SECRET": {
		pattern: "# templates/secret.yaml\ndata:\n  tls.key: {{ .Files.Get \"secrets/tls.key\" | b64enc }}",
		fix: "# Do not embed secret files; deliver via a managed Secret:\ndata:\n  tls.key: {{ (lookup \"v1\" \"Secret\" .Release.Namespace \"tls\").data.\"tls.key\" }}\n# and add 'secrets/' to .helmignore",
		explanation: ".Files.Get reading a secret/key/password file into rendered output bakes secret material into manifests that may land in ConfigMaps or the packaged chart. Provide secrets via valuesFrom a managed Secret at deploy time, exclude secret files via .helmignore, and use SOPS/Sealed/External Secrets.",
		references: ["CWE-538", "CWE-522", "NIST 800-190", "NIST 800-53 IA-5"]
	},
	"HELM_SET_PRIVILEGED_OVERRIDE": {
		pattern: "helm upgrade app ./chart --set securityContext.privileged=true --set securityContext.runAsUser=0",
		fix: "# Keep hardening in reviewed values files, not ad-hoc --set:\nhelm upgrade app ./chart -f values-prod.yaml\n# and enforce a restricted PodSecurity standard / Gatekeeper policy",
		explanation: "A helm --set that injects privileged=true, runAsUser=0, or allowPrivilegeEscalation=true overrides chart hardening at deploy time, granting container-escape primitives. Remove such overrides, keep securityContext hardening in reviewed values files, and enforce a restricted PodSecurity/Gatekeeper policy.",
		references: ["CWE-250", "CWE-269", "CIS Kubernetes Benchmark 5.2.1", "NIST 800-190"]
	},
	"HELM_UNPINNED_CHART_VERSION": {
		pattern: "dependencies:\n  - name: nginx\n    version: ^15.0.0\n    repository: https://charts.example.com",
		fix: "dependencies:\n  - name: nginx\n    version: 15.4.2\n    repository: https://charts.example.com\n# commit Chart.lock so resolved versions/digests are reproducible",
		explanation: "A chart/dependency version using a range or wildcard (^, ~, >, *, x) auto-pulls a new upstream release, enabling supply-chain auto-update of subcharts. Pin to an exact semver, commit Chart.lock, and bump versions deliberately via PR.",
		references: ["CWE-1357", "CWE-494", "SLSA L2", "NIST 800-190"]
	},
	"IAC_ANSIBLE_INSECURE_TASK": {
		pattern: "- name: fetch config\n  uri:\n    url: https://api.example.com\n    validate_certs: no\n  vars:\n    ansible_become_pass: SuperSecret",
		fix: "- name: fetch config\n  uri:\n    url: https://api.example.com\n    validate_certs: yes\n  no_log: true\n# ansible_become_pass sourced from ansible-vault, never inline",
		explanation: "An Ansible task that disables TLS verification, logs secrets, or hardcodes a privileged password exposes credentials and enables MITM. Set validate_certs: yes, no_log: true on secret-handling tasks, and store become/ssh passwords in ansible-vault or a secret manager.",
		references: ["CWE-295", "CWE-798", "CWE-532", "NIST 800-53 IA-5"]
	},
	"IAC_BICEP_INSECURE_NETWORK": {
		pattern: "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  properties: {\n    publicNetworkAccess: 'Enabled'\n    allowBlobPublicAccess: true\n    minimumTlsVersion: 'TLS1_0'\n  }\n}",
		fix: "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  properties: {\n    publicNetworkAccess: 'Disabled'\n    allowBlobPublicAccess: false\n    supportsHttpsTrafficOnly: true\n    minimumTlsVersion: 'TLS1_2'\n    networkAcls: { defaultAction: 'Deny' }\n  }\n}",
		explanation: "A Bicep/ARM resource with public network access, weak TLS, public blob access, or allow-all network ACLs is internet-exposed and interceptable. Set publicNetworkAccess to Disabled with Private Endpoints, enforce HTTPS + TLS1_2, disable public blob access, and default-deny network ACLs.",
		references: ["CWE-668", "CWE-319", "CIS Azure Foundations Benchmark", "NIST 800-53 SC-7"]
	},
	"IAC_BICEP_PRIVILEGED_ROLE": {
		pattern: "resource ra 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n  properties: {\n    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', ownerRoleId)\n  }\n}",
		fix: "resource ra 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n  scope: storageAccount   // narrowest scope, not the subscription\n  properties: {\n    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataReaderId)\n  }\n}",
		explanation: "A Bicep/ARM role assignment granting built-in Owner or Contributor confers broad subscription/resource-group control. Replace it with a least-privilege built-in or custom role scoped to the specific resource, and use PIM for just-in-time elevation instead of standing Owner.",
		references: ["CWE-269", "CIS Azure Foundations Benchmark", "NIST 800-53 AC-6"]
	},
	"IAC_CDK_INSECURE_CONSTRUCT": {
		pattern: "const bucket = new s3.Bucket(this, 'Data', { removalPolicy: RemovalPolicy.DESTROY });\nrole.addToPolicy(new iam.PolicyStatement({ actions: ['*'], resources: ['*'] }));",
		fix: "const bucket = new s3.Bucket(this, 'Data', {\n  removalPolicy: RemovalPolicy.RETAIN,\n  encryption: s3.BucketEncryption.KMS,\n  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,\n});\nrole.addToPolicy(new iam.PolicyStatement({ actions: ['s3:GetObject'], resources: [bucket.arnForObjects('*')] }));",
		explanation: "A CDK escape hatch granting wildcard IAM, or RemovalPolicy.DESTROY on a data store, violates least privilege and risks irreversible data loss. Scope IAM actions/resources to the minimum needed and set RemovalPolicy.RETAIN (with encryption and public-access block) on stateful resources.",
		references: ["CWE-269", "CWE-732", "NIST 800-53 AC-6", "AWS Well-Architected"]
	},
	"IAC_CDK_SAM_OPEN_CORS": {
		pattern: "Cors:\n  AllowOrigin: \"'*'\"\n  AllowCredentials: true",
		fix: "Cors:\n  AllowOrigin: \"'https://app.example.com'\"   # explicit allowlist\n  AllowMethods: \"'GET,POST'\"\n  AllowHeaders: \"'Authorization,Content-Type'\"",
		explanation: "A SAM/CDK API with AllowOrigin '*' lets any website call the API, and combined with AllowCredentials: true it exposes credentialed responses cross-origin. Replace the wildcard with an explicit origin allowlist, never pair it with credentials, and scope methods/headers per route.",
		references: ["CWE-942", "OWASP Top 10 A05:2021", "NIST 800-53 AC-4"]
	},
	"IAC_CFN_CLOUDTRAIL_WEAK": {
		pattern: "Trail:\n  Type: AWS::CloudTrail::Trail\n  Properties:\n    IsMultiRegionTrail: false\n    EnableLogFileValidation: false",
		fix: "Trail:\n  Type: AWS::CloudTrail::Trail\n  Properties:\n    IsMultiRegionTrail: true\n    EnableLogFileValidation: true\n    IncludeGlobalServiceEvents: true",
		explanation: "A CloudFormation CloudTrail that is not multi-region or has log-file validation disabled leaves audit gaps and tamper risk. Set IsMultiRegionTrail and EnableLogFileValidation to true, include global service events, and deliver logs to a dedicated cross-account bucket with MFA delete + Object Lock.",
		references: ["CWE-778", "CIS AWS Foundations Benchmark 3.1", "NIST 800-53 AU-2"]
	},
	"IAC_CFN_DB_PUBLIC": {
		pattern: "DB:\n  Type: AWS::RDS::DBInstance\n  Properties:\n    PubliclyAccessible: true",
		fix: "DB:\n  Type: AWS::RDS::DBInstance\n  Properties:\n    PubliclyAccessible: false\n    DBSubnetGroupName: !Ref PrivateSubnetGroup",
		explanation: "A CloudFormation RDS/Redshift resource with PubliclyAccessible: true is reachable from the internet. Set PubliclyAccessible: false, place databases in private subnets with no internet route, and restrict the DB security group to application subnets.",
		references: ["CWE-668", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-7"]
	},
	"IAC_CFN_ENCRYPTION_DISABLED": {
		pattern: "DB:\n  Type: AWS::RDS::DBInstance\n  Properties:\n    StorageEncrypted: false",
		fix: "DB:\n  Type: AWS::RDS::DBInstance\n  Properties:\n    StorageEncrypted: true\n    KmsKeyId: !Ref DataKey",
		explanation: "A CloudFormation resource with encryption explicitly disabled or missing (StorageEncrypted/Encrypted/SSE) stores data at rest unprotected. Enable encryption (StorageEncrypted, Encrypted, S3 BucketEncryption SSE), specify a customer-managed KmsKeyId for regulated data, and enforce it org-wide with Config/SCPs.",
		references: ["CWE-311", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-28"]
	},
	"IAC_CFN_IAM_PASSROLE_WILDCARD": {
		pattern: "Policy:\n  Statement:\n    - Effect: Allow\n      Action: iam:PassRole\n      Resource: '*'",
		fix: "Policy:\n  Statement:\n    - Effect: Allow\n      Action: iam:PassRole\n      Resource: arn:aws:iam::111122223333:role/app-task-role\n      Condition:\n        StringEquals: { 'iam:PassedToService': ecs-tasks.amazonaws.com }",
		explanation: "A CloudFormation IAM policy granting iam:PassRole on '*' (or iam:*) enables privilege escalation to any role. Scope iam:PassRole to specific role ARNs with an iam:PassedToService condition, never grant iam:*, and audit PassRole grants with IAM Access Analyzer.",
		references: ["CWE-269", "CWE-732", "MITRE ATT&CK T1078.004", "NIST 800-53 AC-6"]
	},
	"IAC_CFN_IAM_USER_ACCESS_KEY": {
		pattern: "Key:\n  Type: AWS::IAM::AccessKey\n  Properties:\n    UserName: !Ref AppUser",
		fix: "# Use a role assumed via STS instead of a static user key:\nAppRole:\n  Type: AWS::IAM::Role\n  Properties:\n    AssumeRolePolicyDocument: { ... }   # IRSA / instance profile / OIDC",
		explanation: "A CloudFormation AWS::IAM::AccessKey provisions long-lived static credentials embedded in templates. Replace IAM users + keys with IAM roles and STS short-lived credentials (instance profiles/IRSA/Workload Identity); if a key is unavoidable, store it in Secrets Manager and rotate.",
		references: ["CWE-798", "CWE-522", "CIS AWS Foundations Benchmark", "NIST 800-53 IA-5"]
	},
	"IAC_CFN_IAM_WILDCARD": {
		pattern: "Policy:\n  Statement:\n    - Effect: Allow\n      Action: '*'\n      Resource: '*'",
		fix: "Policy:\n  Statement:\n    - Effect: Allow\n      Action: ['s3:GetObject', 's3:PutObject']\n      Resource: !Sub 'arn:aws:s3:::${DataBucket}/*'",
		explanation: "A CloudFormation/inline IAM policy with wildcard Action or Resource violates least privilege. Replace Action '*' with the explicit minimal action list, replace Resource '*' with specific ARNs, add NoEcho to secret parameters, and validate templates with cfn-lint/cfn_nag/Checkov in CI.",
		references: ["CWE-732", "CWE-269", "CIS AWS Foundations Benchmark", "NIST 800-53 AC-6"]
	},
	"IAC_CFN_IMDSV1_ALLOWED": {
		pattern: "Instance:\n  Type: AWS::EC2::Instance\n  Properties:\n    MetadataOptions:\n      HttpTokens: optional",
		fix: "Instance:\n  Type: AWS::EC2::Instance\n  Properties:\n    MetadataOptions:\n      HttpTokens: required\n      HttpPutResponseHopLimit: 1",
		explanation: "CloudFormation MetadataOptions with HttpTokens: optional leaves IMDSv1 reachable, so an SSRF can steal IAM credentials from 169.254.169.254. Set HttpTokens: required to enforce IMDSv2, set HttpPutResponseHopLimit: 1, and enforce IMDSv2 account-wide.",
		references: ["CWE-918", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-7"]
	},
	"IAC_CFN_INLINE_SECRET": {
		pattern: "DB:\n  Type: AWS::RDS::DBInstance\n  Properties:\n    MasterUserPassword: SuperSecret123",
		fix: "DB:\n  Type: AWS::RDS::DBInstance\n  Properties:\n    MasterUserPassword: '{{resolve:secretsmanager:prod/db:SecretString:password}}'",
		explanation: "A CloudFormation template with a hardcoded secret literal (MasterUserPassword/SecretString/Token) exposes the credential in source and stack history. Remove and rotate the secret, use a dynamic reference {{resolve:secretsmanager:...}} or a generated secret, and add a template secret scanner to CI.",
		references: ["CWE-798", "CWE-312", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"IAC_CFN_LAMBDA_URL_PUBLIC": {
		pattern: "Url:\n  Type: AWS::Lambda::Url\n  Properties:\n    AuthType: NONE",
		fix: "Url:\n  Type: AWS::Lambda::Url\n  Properties:\n    AuthType: AWS_IAM",
		explanation: "A CloudFormation Lambda FunctionUrlConfig with AuthType: NONE makes the function publicly invocable by anyone. Set AuthType: AWS_IAM, or front it with API Gateway (IAM/Cognito) or CloudFront signed URLs, and add throttling + WAF if a public endpoint is required.",
		references: ["CWE-306", "NIST 800-53 AC-3", "OWASP API Security Top 10 API2:2023"]
	},
	"IAC_CFN_NO_DELETION_POLICY": {
		pattern: "DB:\n  Type: AWS::RDS::DBInstance\n  Properties: { ... }   # no DeletionPolicy",
		fix: "DB:\n  Type: AWS::RDS::DBInstance\n  DeletionPolicy: Retain\n  UpdateReplacePolicy: Retain\n  Properties: { ... }",
		explanation: "A CloudFormation stateful resource (RDS/DynamoDB/S3) with no DeletionPolicy: Retain is destroyed when the stack is deleted. Add DeletionPolicy and UpdateReplacePolicy: Retain, enable termination protection on prod stacks, and take final snapshots before deletion.",
		references: ["CWE-693", "NIST 800-53 CP-9", "AWS Well-Architected"]
	},
	"IAC_CFN_PARAM_NO_NOECHO": {
		pattern: "Parameters:\n  DbPassword:\n    Type: String",
		fix: "Parameters:\n  DbPassword:\n    Type: String\n    NoEcho: true\n# better: resolve at deploy via {{resolve:secretsmanager:...}}",
		explanation: "A CloudFormation parameter that carries a secret without NoEcho: true leaks the value in the console and describe-stacks output. Add NoEcho: true to every secret parameter, prefer dynamic references to Secrets Manager/SSM, and never pass secrets as plaintext CLI parameters.",
		references: ["CWE-532", "CWE-200", "NIST 800-53 IA-5"]
	},
	"IAC_CFN_RESOURCE_POLICY_PUBLIC": {
		pattern: "TopicPolicy:\n  Type: AWS::SNS::TopicPolicy\n  Properties:\n    PolicyDocument:\n      Statement:\n        - Effect: Allow\n          Principal: '*'\n          Action: sns:Publish",
		fix: "TopicPolicy:\n  Type: AWS::SNS::TopicPolicy\n  Properties:\n    PolicyDocument:\n      Statement:\n        - Effect: Allow\n          Principal: { AWS: 'arn:aws:iam::111122223333:root' }\n          Action: sns:Publish\n          Condition: { StringEquals: { 'aws:SourceAccount': '111122223333' } }",
		explanation: "A CloudFormation resource policy with Principal '*' opens an SNS/SQS/Lambda resource to all AWS accounts. Replace '*' with specific account IDs, service principals, or org-id conditions, add aws:SourceArn/aws:SourceAccount conditions, and review with IAM Access Analyzer.",
		references: ["CWE-284", "CWE-732", "NIST 800-53 AC-4", "AWS Well-Architected"]
	},
	"IAC_CFN_S3_PUBLIC": {
		pattern: "Bucket:\n  Type: AWS::S3::Bucket\n  Properties:\n    AccessControl: PublicRead",
		fix: "Bucket:\n  Type: AWS::S3::Bucket\n  Properties:\n    PublicAccessBlockConfiguration:\n      BlockPublicAcls: true\n      BlockPublicPolicy: true\n      IgnorePublicAcls: true\n      RestrictPublicBuckets: true",
		explanation: "A CloudFormation S3 bucket that disables Public Access Block or sets a public ACL/policy exposes objects to the internet. Set all four PublicAccessBlockConfiguration fields to true, remove public AccessControl and Principal '*' policies, and front public assets with CloudFront + Origin Access Control.",
		references: ["CWE-668", "CIS AWS Foundations Benchmark", "NIST 800-53 AC-3"]
	},
	"IAC_CFN_SG_OPEN_INGRESS": {
		pattern: "SG:\n  Type: AWS::EC2::SecurityGroup\n  Properties:\n    SecurityGroupIngress:\n      - IpProtocol: tcp\n        FromPort: 22\n        ToPort: 22\n        CidrIp: 0.0.0.0/0",
		fix: "SG:\n  Type: AWS::EC2::SecurityGroup\n  Properties:\n    SecurityGroupIngress:\n      - IpProtocol: tcp\n        FromPort: 22\n        ToPort: 22\n        CidrIp: 10.0.0.0/8   # known CIDR; prefer SSM Session Manager",
		explanation: "A CloudFormation SecurityGroup ingress allowing 0.0.0.0/0 or ::/0 is open to the entire internet. Restrict CidrIp/CidrIpv6 to specific known ranges, use a bastion or SSM Session Manager for admin access, and reference source security-group IDs for intra-VPC traffic.",
		references: ["CWE-284", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-7"]
	},
	"IAC_CFN_UNTRUSTED_TEMPLATE_URL": {
		pattern: "Stack:\n  Type: AWS::CloudFormation::Stack\n  Properties:\n    TemplateURL: http://example.com/nested.yaml",
		fix: "Stack:\n  Type: AWS::CloudFormation::Stack\n  Properties:\n    TemplateURL: https://my-templates.s3.amazonaws.com/nested.yaml",
		explanation: "A CloudFormation nested-stack or cfn-init source over plaintext HTTP / an untrusted URL is subject to MITM and template tampering. Use HTTPS S3 URLs, host nested templates in an access-restricted bucket, and verify artifact integrity before cfn-init fetches them.",
		references: ["CWE-319", "CWE-494", "NIST 800-53 SC-8"]
	},
	"IAC_HARDCODED_SECRET": {
		pattern: "resource \"aws_db_instance\" \"db\" {\n  password = \"SuperSecret123\"\n}",
		fix: "resource \"aws_db_instance\" \"db\" {\n  password = data.aws_secretsmanager_secret_version.db.secret_string\n}\n# secret injected at runtime; rotate the exposed value immediately",
		explanation: "A hardcoded credential or private key in IaC source is exposed to everyone with repo access and lives in Git history. Remove and rotate it immediately, reference it via a secret-manager data source or TF_VAR_ env var, and add a pre-commit secret scanner while purging history.",
		references: ["CWE-798", "CWE-312", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"IAC_PUBLIC_RESOURCE": {
		pattern: "resource \"aws_s3_bucket_acl\" \"b\" {\n  acl = \"public-read\"\n}",
		fix: "resource \"aws_s3_bucket_public_access_block\" \"b\" {\n  bucket                  = aws_s3_bucket.b.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
		explanation: "IaC that creates a publicly exposed resource (public-read ACL or publicly_accessible database) puts data on the open internet. Remove public ACLs in favor of scoped bucket policies, set publicly_accessible = false with private subnets, enable S3 Block Public Access, and front legitimate public assets with CloudFront + OAC.",
		references: ["CWE-668", "CIS AWS Foundations Benchmark", "NIST 800-53 AC-3"]
	},
	"IAC_PULUMI_PLAINTEXT_SECRET": {
		pattern: "const provider = new aws.Provider(\"aws\", { accessKey: \"AKIA...\", secretKey: \"abc123\" });\nconst dbPass = \"SuperSecret123\";",
		fix: "// pulumi config set --secret dbPassword <value>\nconst dbPass = config.requireSecret(\"dbPassword\");\nconst provider = new aws.Provider(\"aws\", {});  // creds via env / OIDC",
		explanation: "A Pulumi config secret stored in plaintext, or provider credentials hardcoded inline, exposes them in the stack file, state, and logs. Set secrets with pulumi config set --secret, wrap sensitive values with pulumi.secret(), source provider creds from env/OIDC, and use a KMS-backed secrets provider.",
		references: ["CWE-798", "CWE-312", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"IAC_TF_APIGW_PUBLIC_RESOURCE_POLICY": {
		pattern: "resource \"aws_api_gateway_rest_api_policy\" \"p\" {\n  policy = jsonencode({ Statement=[{ Effect=\"Allow\", Principal=\"*\", Action=\"execute-api:Invoke\", Resource=\"*\" }] })\n}",
		fix: "resource \"aws_api_gateway_rest_api_policy\" \"p\" {\n  policy = jsonencode({ Statement=[{\n    Effect=\"Allow\", Principal=\"*\", Action=\"execute-api:Invoke\", Resource=\"*\",\n    Condition = { StringEquals = { \"aws:SourceVpce\" = aws_vpc_endpoint.api.id } }\n  }] })\n}",
		explanation: "An API Gateway resource policy with Principal \"*\" and no condition makes the API invocable by any unauthenticated caller on the internet. Scope the principal to specific account/role ARNs, or add a VPC-endpoint / org-id condition so only trusted callers reach it.",
		references: ["CWE-284", "NIST 800-53 AC-3", "OWASP API Security Top 10 API2:2023"]
	},
	"IAC_TF_AUTO_APPROVE_SCRIPT": {
		pattern: "#!/bin/sh\nterraform apply -auto-approve",
		fix: "terraform plan -out=tfplan\n# human/PR review of tfplan, then:\nterraform apply tfplan",
		explanation: "A committed script running terraform apply/destroy with -auto-approve makes unreviewed, non-interactive changes to infrastructure. Require a reviewed plan artifact before applying, gate apply behind CI approval, and restrict who can run destroy.",
		references: ["CWE-284", "NIST 800-53 CM-3", "SLSA L2"]
	},
	"IAC_TF_BACKEND_HTTP": {
		pattern: "terraform {\n  backend \"http\" {\n    address = \"http://tfstate.example.com/state\"\n  }\n}",
		fix: "terraform {\n  backend \"s3\" {\n    bucket         = \"my-tfstate\"\n    key            = \"prod/terraform.tfstate\"\n    region         = \"us-east-1\"\n    encrypt        = true\n    dynamodb_table = \"tf-locks\"\n  }\n}",
		explanation: "The Terraform http backend transfers state over an unauthenticated/plaintext channel, risking MITM of state that contains plaintext secrets. Use S3+DynamoDB, GCS, or Terraform Cloud; if http is mandatory, require HTTPS with authenticated lock/unlock addresses.",
		references: ["CWE-319", "NIST 800-53 SC-8", "CWE-311"]
	},
	"IAC_TF_BACKEND_NO_KMS": {
		pattern: "terraform {\n  backend \"s3\" {\n    bucket  = \"my-tfstate\"\n    key     = \"prod.tfstate\"\n    encrypt = true\n  }\n}",
		fix: "terraform {\n  backend \"s3\" {\n    bucket     = \"my-tfstate\"\n    key        = \"prod/terraform.tfstate\"\n    region     = \"us-east-1\"\n    encrypt    = true\n    kms_key_id = \"arn:aws:kms:us-east-1:111122223333:key/abcd-...\"\n    dynamodb_table = \"tf-locks\"\n  }\n}",
		explanation: "A Terraform S3 backend with no kms_key_id encrypts state (which holds plaintext secrets) only with the default AWS key, not a customer-managed key. Set kms_key_id to a CMK so key policy and rotation are controlled.",
		references: ["CWE-311", "NIST 800-53 SC-28", "CIS AWS Foundations Benchmark"]
	},
	"IAC_TF_CBD_SECURITY_GROUP": {
		pattern: "resource \"aws_security_group\" \"sg\" {\n  lifecycle { create_before_destroy = true }\n}",
		fix: "# Manage rules as separate resources so the group itself is not replaced:\nresource \"aws_vpc_security_group_ingress_rule\" \"https\" {\n  security_group_id = aws_security_group.sg.id\n  from_port = 443\n  to_port   = 443\n  ip_protocol = \"tcp\"\n  cidr_ipv4 = \"10.0.0.0/8\"\n}",
		explanation: "create_before_destroy on a security group means both the old and new group exist briefly during replacement, transiently widening exposure. Manage rules as separate aws_vpc_security_group_ingress_rule resources so the group is not replaced, and check plans for unintended -/+ replacements.",
		references: ["CWE-284", "NIST 800-53 SC-7", "CIS AWS Foundations Benchmark"]
	},
	"IAC_TF_CLOUDTRAIL_MISSING_OR_SINGLE_REGION": {
		pattern: "# No aws_cloudtrail resource, or is_multi_region_trail = false",
		fix: "resource \"aws_cloudtrail\" \"main\" {\n  name                          = \"org-trail\"\n  s3_bucket_name                = aws_s3_bucket.trail.id\n  is_multi_region_trail         = true\n  enable_log_file_validation    = true\n  include_global_service_events = true\n  kms_key_id                    = aws_kms_key.trail.arn\n}",
		explanation: "No multi-region CloudTrail means API activity in other regions is unlogged, blinding incident response. Define an account/org CloudTrail that is multi-region and tamper-evident, and deliver logs to a dedicated access-restricted account with Object Lock + MFA delete.",
		references: ["CWE-778", "CIS AWS Foundations Benchmark 3.1", "NIST 800-53 AU-2"]
	},
	"IAC_TF_CLOUDTRAIL_NO_VALIDATION": {
		pattern: "resource \"aws_cloudtrail\" \"main\" {\n  enable_log_file_validation = false\n}",
		fix: "resource \"aws_cloudtrail\" \"main\" {\n  enable_log_file_validation = true\n  is_multi_region_trail      = true\n  kms_key_id                 = aws_kms_key.trail.arn\n}",
		explanation: "aws_cloudtrail with enable_log_file_validation = false means delivered logs can be tampered with undetected. Enable log file validation (and multi-region + KMS) so log integrity can be cryptographically verified.",
		references: ["CWE-778", "CIS AWS Foundations Benchmark 3.2", "NIST 800-53 AU-9"]
	},
	"IAC_TF_DEFAULT_VPC": {
		pattern: "resource \"aws_default_vpc\" \"default\" {}\nresource \"aws_default_security_group\" \"default\" {}",
		fix: "# Provision purpose-built networking instead of adopting AWS defaults:\nresource \"aws_vpc\" \"main\" { cidr_block = \"10.0.0.0/16\" }\nresource \"aws_security_group\" \"app\" {\n  vpc_id = aws_vpc.main.id\n  # explicit, scoped ingress/egress rules only\n}",
		explanation: "Managing the AWS default VPC/security group/subnet adopts permissive defaults (the default SG allows all intra-group traffic). Provision purpose-built VPCs, subnets, and security groups with explicit scoped rules, and restrict or delete the default VPC.",
		references: ["CWE-1188", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-7"]
	},
	"IAC_TF_EKS_ECR_PUBLIC": {
		pattern: "resource \"aws_eks_cluster\" \"c\" {\n  vpc_config { endpoint_public_access = true }\n}\nresource \"aws_ecr_repository\" \"app\" { image_tag_mutability = \"MUTABLE\" }",
		fix: "resource \"aws_eks_cluster\" \"c\" {\n  vpc_config {\n    endpoint_public_access  = false\n    endpoint_private_access = true\n  }\n}\nresource \"aws_ecr_repository\" \"app\" {\n  image_tag_mutability = \"IMMUTABLE\"\n  image_scanning_configuration { scan_on_push = true }\n}",
		explanation: "An EKS public endpoint, public ECR repository, or mutable image tags expose the control plane or make images tamperable. Set the EKS endpoint private, make ECR tags immutable, and enable scan-on-push.",
		references: ["CWE-668", "CWE-1357", "CIS EKS Benchmark", "NIST 800-190"]
	},
	"IAC_TF_HTTP_PLAINTEXT": {
		pattern: "data \"http\" \"cfg\" {\n  url = \"http://config.example.com/app.json\"\n}",
		fix: "data \"http\" \"cfg\" {\n  url = \"https://config.example.com/app.json\"\n}\n# validate fetched content (checksum) before using it",
		explanation: "A Terraform http data source or remote state over plaintext HTTP is subject to MITM and data tampering at plan time. Use HTTPS endpoints, validate fetched content with checksums, and prefer a native data source over fetching arbitrary URLs.",
		references: ["CWE-319", "NIST 800-53 SC-8", "CWE-494"]
	},
	"IAC_TF_IAM_ACCESS_KEY_RESOURCE": {
		pattern: "resource \"aws_iam_access_key\" \"app\" {\n  user = aws_iam_user.app.name\n}",
		fix: "resource \"aws_iam_role\" \"app\" {\n  assume_role_policy = data.aws_iam_policy_document.trust.json\n}\n# workloads use IRSA / instance profiles / OIDC, not static keys",
		explanation: "An aws_iam_access_key resource provisions long-lived static credentials that are hard to rotate and easy to leak. Replace static user keys with assumable roles and short-lived STS credentials (IRSA/instance profiles/OIDC); if a key is unavoidable, store it in Secrets Manager and rotate on a schedule.",
		references: ["CWE-798", "CWE-522", "CIS AWS Foundations Benchmark", "NIST 800-53 IA-5"]
	},
	"IAC_TF_IAM_PRIVILEGE_ESCALATION": {
		pattern: "statement {\n  actions   = [\"iam:PassRole\"]\n  resources = [\"*\"]\n}",
		fix: "statement {\n  actions   = [\"iam:PassRole\"]\n  resources = [\"arn:aws:iam::111122223333:role/app-task-role\"]\n  condition {\n    test     = \"StringEquals\"\n    variable = \"iam:PassedToService\"\n    values   = [\"ecs-tasks.amazonaws.com\"]\n  }\n}",
		explanation: "An IAM policy/trust enabling privilege escalation (iam:PassRole to *, CreatePolicyVersion/PutUserPolicy, or AssumeRole trust to \"*\") lets a principal become any role. Scope iam:PassRole to specific role ARNs with an iam:PassedToService condition and never trust \"*\" in assume-role policies.",
		references: ["CWE-269", "MITRE ATT&CK T1078.004", "NIST 800-53 AC-6"]
	},
	"IAC_TF_IAM_WILDCARD_HCL": {
		pattern: "data \"aws_iam_policy_document\" \"app\" {\n  statement {\n    actions   = [\"*\"]\n    resources = [\"*\"]\n  }\n}",
		fix: "data \"aws_iam_policy_document\" \"app\" {\n  statement {\n    actions   = [\"s3:GetObject\"]\n    resources = [\"${aws_s3_bucket.data.arn}/*\"]\n  }\n}",
		explanation: "A Terraform IAM policy document with a wildcard action, resource, or Principal \"*\" violates least privilege. Enumerate explicit actions and resource ARNs, and replace any Principal \"*\" with specific trusted principals.",
		references: ["CWE-732", "CWE-269", "CIS AWS Foundations Benchmark", "NIST 800-53 AC-6"]
	},
	"IAC_TF_IGNORE_CHANGES_ALL": {
		pattern: "lifecycle {\n  ignore_changes = all\n}",
		fix: "lifecycle {\n  ignore_changes = [tags[\"LastModified\"]]   # only fields that legitimately drift\n}",
		explanation: "lifecycle { ignore_changes = all } masks all configuration drift, so tampering with the live resource goes undetected by Terraform. Scope ignore_changes to the specific attributes that legitimately drift, never all.",
		references: ["CWE-778", "NIST 800-53 CM-6", "CWE-1053"]
	},
	"IAC_TF_IMDSV1_OPTIONAL": {
		pattern: "resource \"aws_instance\" \"web\" {\n  metadata_options { http_tokens = \"optional\" }\n}",
		fix: "resource \"aws_instance\" \"web\" {\n  metadata_options {\n    http_endpoint               = \"enabled\"\n    http_tokens                 = \"required\"\n    http_put_response_hop_limit = 1\n  }\n}",
		explanation: "aws_instance metadata_options with http_tokens = \"optional\" leaves IMDSv1 reachable, so an SSRF can steal IAM credentials. Set http_tokens = \"required\" to enforce IMDSv2 and set the hop limit to 1.",
		references: ["CWE-918", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-7"]
	},
	"IAC_TF_INSECURE_TLS": {
		pattern: "provider \"vsphere\" {\n  allow_unverified_ssl = true\n}",
		fix: "provider \"vsphere\" {\n  allow_unverified_ssl = false   # trust the proper CA bundle\n}",
		explanation: "A Terraform provider that disables TLS verification (insecure / allow_unverified_ssl / skip_tls_verify = true) is vulnerable to MITM. Remove the flag, trust the proper CA bundle, and for a private CA distribute its root cert rather than turning off verification.",
		references: ["CWE-295", "NIST 800-53 SC-8", "OWASP Top 10 A02:2021"]
	},
	"IAC_TF_KMS_NO_ROTATION": {
		pattern: "resource \"aws_kms_key\" \"this\" {\n  enable_key_rotation = false\n}",
		fix: "resource \"aws_kms_key\" \"this\" {\n  description         = \"app data key\"\n  enable_key_rotation = true\n}",
		explanation: "An aws_kms_key with enable_key_rotation = false is never rotated, increasing the blast radius of a key compromise. Enable automatic annual key rotation.",
		references: ["CWE-320", "CIS AWS Foundations Benchmark 3.8", "NIST 800-53 SC-12"]
	},
	"IAC_TF_LAMBDA_ENV_PLAINTEXT_SECRET": {
		pattern: "resource \"aws_lambda_function\" \"f\" {\n  environment { variables = { DB_PASSWORD = \"SuperSecret123\" } }\n}",
		fix: "resource \"aws_lambda_function\" \"f\" {\n  kms_key_arn = aws_kms_key.lambda.arn\n  # fetch the secret at runtime from Secrets Manager using the exec role\n  # secretsmanager.get_secret_value(SecretId=\"prod/app\")\n}",
		explanation: "A Lambda environment variable holding a plaintext secret is readable via GetFunctionConfiguration and stored unencrypted in state. Remove and rotate the credential, fetch it at runtime from Secrets Manager/SSM SecureString, grant only GetSecretValue on that ARN, and set kms_key_arn for remaining env vars.",
		references: ["CWE-798", "CWE-312", "NIST 800-53 IA-5"]
	},
	"IAC_TF_LOG_RETENTION_NEVER_EXPIRES": {
		pattern: "resource \"aws_cloudwatch_log_group\" \"app\" {\n  retention_in_days = 0\n}",
		fix: "resource \"aws_cloudwatch_log_group\" \"app\" {\n  name              = \"/app/prod\"\n  retention_in_days = 365\n  kms_key_id        = aws_kms_key.logs.arn\n}",
		explanation: "A log group with retention_in_days = 0 keeps logs forever with no defined, immutable retention window. Set an explicit compliance-driven retention period, and for long-term tamper-proof retention export to an S3 bucket with Object Lock.",
		references: ["CWE-778", "NIST 800-53 AU-11", "CIS AWS Foundations Benchmark"]
	},
	"IAC_TF_MODULE_GIT_HTTP": {
		pattern: "module \"vpc\" {\n  source = \"git::http://github.com/org/tf-vpc.git//modules/vpc\"\n}",
		fix: "module \"vpc\" {\n  source = \"git::https://github.com/org/tf-vpc.git//modules/vpc?ref=v3.2.1\"\n}",
		explanation: "A Terraform module source over plaintext git::http:// can be tampered with in transit. Use https or ssh and pin to an immutable tag or commit SHA; for registry modules add an exact version.",
		references: ["CWE-319", "CWE-829", "MITRE ATT&CK T1195", "NIST 800-53 SC-8"]
	},
	"IAC_TF_NULL_RESOURCE_EXEC": {
		pattern: "resource \"null_resource\" \"setup\" {\n  provisioner \"local-exec\" { command = \"./setup.sh ${var.input}\" }\n}",
		fix: "# Avoid null_resource + local-exec; use a proper provider or config-mgmt tool.\n# If retained, never interpolate untrusted vars and run only from a hardened CI runner.",
		explanation: "A Terraform null_resource typically wraps local-exec, an arbitrary-command RCE surface during apply. Avoid null_resource + local-exec for provisioning; if retained, never interpolate untrusted variables into the command and run apply only from a hardened CI runner with scoped credentials.",
		references: ["CWE-78", "NIST 800-53 SI-10", "CWE-94"]
	},
	"IAC_TF_OUTPUT_NOT_SENSITIVE": {
		pattern: "output \"db_password\" {\n  value = aws_db_instance.db.password\n}",
		fix: "output \"db_password\" {\n  value     = aws_db_instance.db.password\n  sensitive = true\n}\n# better: do not export secrets; read them on demand from the secret manager",
		explanation: "A Terraform output exposing a secret without sensitive = true leaks the value to plan/CI logs and state. Mark each secret output sensitive, or better, do not export secrets at all and read them on demand from the secret manager.",
		references: ["CWE-532", "CWE-200", "NIST 800-53 IA-5"]
	},
	"IAC_TF_PREVENT_DESTROY_FALSE": {
		pattern: "resource \"aws_db_instance\" \"db\" {\n  lifecycle { prevent_destroy = false }\n}",
		fix: "resource \"aws_db_instance\" \"db\" {\n  deletion_protection = true\n  skip_final_snapshot = false\n  lifecycle { prevent_destroy = true }\n}",
		explanation: "lifecycle { prevent_destroy = false } explicitly allows destruction of a likely stateful resource. Set prevent_destroy = true on stateful resources and pair it with provider-level guards (deletion_protection, final snapshots).",
		references: ["CWE-693", "NIST 800-53 CP-9", "AWS Well-Architected"]
	},
	"IAC_TF_PROVIDER_HARDCODED_CREDS": {
		pattern: "provider \"aws\" {\n  access_key = \"AKIAIOSFODNN7EXAMPLE\"\n  secret_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n}",
		fix: "provider \"aws\" {\n  region = var.region   # creds via env, SSO, or IRSA/OIDC, never inline\n}",
		explanation: "A Terraform provider authenticating with hardcoded credentials, a committed credentials file, or an inline key exposes long-lived cloud access. Remove and rotate the credential, authenticate via the default chain/OIDC/Workload Identity, gitignore any key path, and purge it from history.",
		references: ["CWE-798", "CWE-522", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"IAC_TF_PROVISIONER_EXEC": {
		pattern: "resource \"aws_instance\" \"web\" {\n  provisioner \"remote-exec\" { inline = [\"curl ${var.url} | sh\"] }\n}",
		fix: "# Remove provisioners; use cloud-init / a config-management tool instead.\n# If unavoidable, use fixed args (no untrusted interpolation) and run from hardened CI.",
		explanation: "A local-exec/remote-exec provisioner is a command-injection and RCE surface during apply. Remove provisioners in favor of cloud-init or a config-management tool; if unavoidable, never interpolate untrusted variables and run apply only from a hardened CI runner.",
		references: ["CWE-78", "CWE-94", "NIST 800-53 SI-10"]
	},
	"IAC_TF_RDS_WEAK_HARDENING": {
		pattern: "resource \"aws_db_instance\" \"db\" {\n  storage_encrypted                   = false\n  iam_database_authentication_enabled = false\n}",
		fix: "resource \"aws_db_instance\" \"db\" {\n  storage_encrypted                   = true\n  kms_key_id                          = aws_kms_key.rds.arn\n  iam_database_authentication_enabled = true\n  publicly_accessible                 = false\n  deletion_protection                 = true\n}",
		explanation: "An aws_db_instance with storage_encrypted = false or iam_database_authentication_enabled = false stores data unencrypted and relies on static DB passwords. Enable storage encryption with a CMK, IAM database authentication, and keep the DB private with deletion protection.",
		references: ["CWE-311", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-28"]
	},
	"IAC_TF_REQUIRED_VERSION_UNPINNED": {
		pattern: "terraform {\n  required_version = \">= 1.0\"\n}",
		fix: "terraform {\n  required_version = \"~> 1.7.0\"\n  required_providers {\n    aws = { source = \"hashicorp/aws\", version = \"~> 5.40\" }\n  }\n}",
		explanation: "An open >= required_version constraint with no upper bound lets an unexpected Terraform CLI upgrade break or alter behavior. Pin the CLI to a bounded range, pin providers too, and commit .terraform.lock.hcl.",
		references: ["CWE-1104", "SLSA L2", "NIST 800-53 CM-2"]
	},
	"IAC_TF_S3_MISSING_HARDENING": {
		pattern: "resource \"aws_s3_bucket\" \"this\" {\n  bucket = \"my-bucket\"\n}",
		fix: "resource \"aws_s3_bucket_server_side_encryption_configuration\" \"this\" {\n  bucket = aws_s3_bucket.this.id\n  rule { apply_server_side_encryption_by_default { sse_algorithm = \"aws:kms\" } }\n}\nresource \"aws_s3_bucket_public_access_block\" \"this\" {\n  bucket                  = aws_s3_bucket.this.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
		explanation: "An aws_s3_bucket with no server-side encryption and/or no public access block may store data unencrypted or be publicly exposable. Add a server-side encryption configuration (KMS) and a public access block resource with all four fields true.",
		references: ["CWE-311", "CWE-668", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-28"]
	},
	"IAC_TF_SENSITIVE_FALSE": {
		pattern: "variable \"db_password\" {\n  type      = string\n  sensitive = false\n}",
		fix: "variable \"db_password\" {\n  type      = string\n  sensitive = true\n}",
		explanation: "A Terraform variable/output that explicitly sets sensitive = false renders the value in plan output and logs, overriding Terraform's redaction. Set sensitive = true on any variable/output holding a credential or PII and scrub CI logs that may already contain it.",
		references: ["CWE-532", "CWE-200", "NIST 800-53 IA-5"]
	},
	"IAC_TF_SG_OPEN_WORLD": {
		pattern: "resource \"aws_security_group_rule\" \"ssh\" {\n  type        = \"ingress\"\n  from_port   = 22\n  to_port     = 22\n  protocol    = \"tcp\"\n  cidr_blocks = [\"0.0.0.0/0\"]\n}",
		fix: "resource \"aws_security_group_rule\" \"ssh\" {\n  type              = \"ingress\"\n  from_port         = 22\n  to_port           = 22\n  protocol          = \"tcp\"\n  cidr_blocks       = [\"10.0.0.0/8\"]   # or source_security_group_id\n  security_group_id = aws_security_group.app.id\n}",
		explanation: "A security group rule allowing 0.0.0.0/0 (or ::/0), typically on SSH/RDP/all ports, is open to the entire internet. Restrict ingress to known CIDRs or reference a source security-group ID, and prefer SSM Session Manager for admin access.",
		references: ["CWE-284", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-7"]
	},
	"IAC_TF_SQS_SNS_UNENCRYPTED": {
		pattern: "resource \"aws_sqs_queue\" \"q\" {\n  name = \"jobs\"\n}",
		fix: "resource \"aws_sqs_queue\" \"q\" {\n  name                              = \"jobs\"\n  kms_master_key_id                 = aws_kms_key.sqs.id\n  kms_data_key_reuse_period_seconds = 300\n}",
		explanation: "An SQS queue or SNS topic with no server-side encryption stores message payloads unencrypted at rest. Encrypt with a customer-managed KMS key (kms_master_key_id) rather than the default aws/sqs or aws/sns key so key policy and rotation are controlled.",
		references: ["CWE-311", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-28"]
	},
	"IAC_TF_STATE_INSECURE": {
		pattern: "terraform {\n  backend \"local\" { path = \"terraform.tfstate\" }\n}",
		fix: "terraform {\n  backend \"s3\" {\n    bucket         = \"my-tfstate\"\n    key            = \"prod/terraform.tfstate\"\n    region         = \"us-east-1\"\n    encrypt        = true\n    kms_key_id     = \"arn:aws:kms:...:key/abcd\"\n    dynamodb_table = \"tf-locks\"\n  }\n}",
		explanation: "Terraform remote state that is unencrypted, unlocked, or on a local backend exposes plaintext secrets and risks concurrent-apply corruption. Use S3+DynamoDB (or TFC/GCS) with encrypt = true, a CMK, state locking, a restrictive bucket policy, and blocked public access.",
		references: ["CWE-311", "CWE-312", "NIST 800-53 SC-28"]
	},
	"IAC_TF_TFVARS_SECRET": {
		pattern: "# prod.auto.tfvars\ndb_password = \"SuperSecret123\"",
		fix: "# do not commit secrets in .tfvars; inject at runtime:\n#   export TF_VAR_db_password=... (from a secret manager)\n# and gitignore *.tfvars (except examples)",
		explanation: "A hardcoded secret in a .tfvars/.auto.tfvars file is committed to source and applied automatically. Remove and rotate the secret, inject secret variables via TF_VAR_ env vars or a secret-manager data source, gitignore *.tfvars, and scan history with gitleaks.",
		references: ["CWE-798", "CWE-312", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"IAC_TF_UNPINNED_SOURCE": {
		pattern: "module \"vpc\" {\n  source = \"git::https://github.com/org/tf-vpc.git//modules/vpc\"\n}",
		fix: "module \"vpc\" {\n  source = \"git::https://github.com/org/tf-vpc.git//modules/vpc?ref=3f2b1c9d4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c\"\n}\n# registry modules: version = \"5.1.0\"; commit .terraform.lock.hcl",
		explanation: "A Terraform module or provider source that is unpinned/mutable enables supply-chain tampering via a moving ref. Pin git module sources to an immutable commit SHA, pin registry modules to an exact version, add pinned required_providers, and commit .terraform.lock.hcl.",
		references: ["CWE-829", "CWE-1357", "MITRE ATT&CK T1195", "NIST 800-53 CM-2"]
	},
	"IAC_TF_UNSAFE_DESTROY": {
		pattern: "resource \"aws_db_instance\" \"db\" {\n  skip_final_snapshot = true\n}\nresource \"aws_s3_bucket\" \"b\" { force_destroy = true }",
		fix: "resource \"aws_db_instance\" \"db\" {\n  skip_final_snapshot = false\n  lifecycle { prevent_destroy = true }\n}\nresource \"aws_s3_bucket\" \"b\" { force_destroy = false }",
		explanation: "A destructive or validation-skipping toggle (force_destroy / skip_final_snapshot / disable_rollback) allows irreversible data loss. Set skip_final_snapshot = false, remove force_destroy on buckets with real data, add prevent_destroy to critical resources, and keep disable_rollback at its safe default.",
		references: ["CWE-693", "NIST 800-53 CP-9", "AWS Well-Architected"]
	},
	"IAC_TF_USERDATA_SECRET": {
		pattern: "resource \"aws_instance\" \"web\" {\n  user_data = \"export DB_PASSWORD=SuperSecret123\"\n}",
		fix: "resource \"aws_instance\" \"web\" {\n  user_data = <<-EOF\n    #!/bin/bash\n    DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id prod/app --query SecretString --output text)\n  EOF\n}",
		explanation: "Credentials embedded in user_data/templatefile/cloud-init land in EC2 metadata (readable via IMDS) and in the state file. Fetch secrets at boot from a secret manager, grant the instance role only GetSecretValue on that ARN, and mark user_data variables sensitive.",
		references: ["CWE-798", "CWE-312", "NIST 800-53 IA-5"]
	},
	"IAC_TF_VAR_DEFAULT_SECRET": {
		pattern: "variable \"api_key\" {\n  type    = string\n  default = \"YOUR_API_KEY\"\n}",
		fix: "variable \"api_key\" {\n  type      = string\n  sensitive = true\n  # no default; supplied via TF_VAR_api_key or a secret-manager data source\n}",
		explanation: "A Terraform variable default containing a real-looking secret (AWS key/GitHub PAT/OpenAI key/PEM) commits the credential to source. Remove the default and rotate the secret, declare the variable without a default and inject it at runtime, and purge it from history.",
		references: ["CWE-798", "CWE-312", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"IAC_TF_VAULT_TOKEN_INLINE": {
		pattern: "provider \"vault\" {\n  address = \"https://vault.example.com\"\n  token   = \"hvs.CAESIroottoken\"\n}",
		fix: "provider \"vault\" {\n  address = \"https://vault.example.com\"\n  # token from VAULT_TOKEN env or an auth method (AppRole/OIDC/AWS)\n}",
		explanation: "A Terraform Vault provider configured with an inline token places a long-lived root/admin token in source. Source the token from VAULT_TOKEN or an auth method (AppRole/OIDC/AWS), use short-lived least-privilege tokens per run, and revoke any committed token.",
		references: ["CWE-798", "CWE-522", "NIST 800-53 IA-5"]
	},
	"IAC_TF_VOLUME_UNENCRYPTED": {
		pattern: "resource \"aws_instance\" \"web\" {\n  root_block_device { encrypted = false }\n}",
		fix: "resource \"aws_instance\" \"web\" {\n  root_block_device {\n    encrypted  = true\n    kms_key_id = aws_kms_key.ebs.arn\n  }\n}",
		explanation: "A root or EBS block device with encrypted = false holds data at rest unencrypted. Encrypt every block device with a KMS key and enable account-wide EBS encryption by default.",
		references: ["CWE-311", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-28"]
	},
	"IAC_TF_VPC_NO_FLOW_LOGS": {
		pattern: "resource \"aws_vpc\" \"main\" {\n  cidr_block = \"10.0.0.0/16\"\n}\n# no aws_flow_log",
		fix: "resource \"aws_flow_log\" \"vpc\" {\n  vpc_id          = aws_vpc.main.id\n  traffic_type    = \"ALL\"\n  log_destination = aws_cloudwatch_log_group.flow.arn\n  iam_role_arn    = aws_iam_role.flow.arn\n}",
		explanation: "A VPC/subnet with no Flow Logs capturing ALL traffic provides no network telemetry to detect lateral movement or exfiltration. Attach a flow log to every VPC capturing ALL traffic, send it to a retained destination, and alert on anomalous egress.",
		references: ["CWE-778", "CIS AWS Foundations Benchmark 3.9", "NIST 800-53 AU-2"]
	},
	"INFRA_AZURE_PUBLIC_NETWORK_ACCESS": {
		pattern: "resource \"azurerm_storage_account\" \"sa\" {\n  public_network_access_enabled = true\n}",
		fix: "resource \"azurerm_storage_account\" \"sa\" {\n  public_network_access_enabled = false\n}\n# add a azurerm_private_endpoint + private DNS zone for internal access",
		explanation: "An Azure managed service with public_network_access_enabled = true is reachable from the internet. Set it to false and use Private Endpoints with Private DNS Zones, applying NSG/Azure Firewall rules to any legitimately public service.",
		references: ["CWE-668", "CIS Azure Foundations Benchmark", "NIST 800-53 SC-7"]
	},
	"INFRA_CLOUDTRAIL_NOT_MULTIREGION": {
		pattern: "resource \"aws_cloudtrail\" \"main\" {\n  is_multi_region_trail = false\n}",
		fix: "resource \"aws_cloudtrail\" \"main\" {\n  is_multi_region_trail         = true\n  include_global_service_events = true\n  enable_log_file_validation    = true\n}",
		explanation: "A CloudTrail that is not multi-region leaves attacker actions in secondary regions unlogged. Set is_multi_region_trail = true, include global service events, and deliver logs to a dedicated cross-account bucket with MFA delete.",
		references: ["CWE-778", "CIS AWS Foundations Benchmark 3.1", "NIST 800-53 AU-2"]
	},
	"INFRA_CROSS_ACCOUNT_NO_EXTERNAL_ID": {
		pattern: "assume_role_policy = jsonencode({\n  Statement = [{ Effect=\"Allow\", Principal={ AWS=\"arn:aws:iam::999:root\" }, Action=\"sts:AssumeRole\" }]\n})",
		fix: "assume_role_policy = jsonencode({\n  Statement = [{\n    Effect=\"Allow\", Principal={ AWS=\"arn:aws:iam::999:root\" }, Action=\"sts:AssumeRole\",\n    Condition = { StringEquals = { \"sts:ExternalId\" = var.external_id } }\n  }]\n})",
		explanation: "A cross-account AssumeRole trust without an sts:ExternalId condition is vulnerable to the confused-deputy attack. Add a Condition with a unique, unguessable sts:ExternalId per third-party relationship, rotate it periodically, and audit trusts with IAM Access Analyzer.",
		references: ["CWE-441", "CIS AWS Foundations Benchmark", "NIST 800-53 AC-4"]
	},
	"INFRA_DB_NO_DELETION_PROTECTION": {
		pattern: "resource \"aws_db_instance\" \"db\" {\n  deletion_protection = false\n}",
		fix: "resource \"aws_db_instance\" \"db\" {\n  deletion_protection      = true\n  backup_retention_period  = 7\n  skip_final_snapshot      = false\n  lifecycle { prevent_destroy = true }\n}",
		explanation: "A database resource without deletion protection can be permanently destroyed by a single terraform apply. Set deletion_protection = true on all DB instances/clusters, enable backups with at least 7-day retention, and add a prevent_destroy lifecycle rule.",
		references: ["CWE-693", "CIS AWS Foundations Benchmark", "NIST 800-53 CP-9"]
	},
	"INFRA_ECR_NO_SCAN": {
		pattern: "resource \"aws_ecr_repository\" \"app\" {\n  name = \"app\"\n}",
		fix: "resource \"aws_ecr_repository\" \"app\" {\n  name                 = \"app\"\n  image_tag_mutability = \"IMMUTABLE\"\n  image_scanning_configuration { scan_on_push = true }\n}",
		explanation: "An ECR repository with scan-on-push disabled deploys container images without CVE scanning. Set scan_on_push = true, enable ECR Enhanced Scanning for continuous monitoring, and gate deployments on zero critical/high CVEs in CI.",
		references: ["CWE-1104", "NIST 800-190", "NIST 800-53 RA-5"]
	},
	"INFRA_ECS_HOST_NETWORK": {
		pattern: "resource \"aws_ecs_task_definition\" \"app\" {\n  network_mode = \"host\"\n}",
		fix: "resource \"aws_ecs_task_definition\" \"app\" {\n  network_mode = \"awsvpc\"   # task-level ENI + security groups\n}",
		explanation: "An ECS task using host network mode bypasses container network isolation and exposes all host ports to the container. Use awsvpc mode (Fargate) or bridge (EC2) and apply security groups at the task level.",
		references: ["CWE-668", "NIST 800-190", "NIST 800-53 SC-7"]
	},
	"INFRA_GCP_DEFAULT_SERVICE_ACCOUNT": {
		pattern: "resource \"google_compute_instance\" \"vm\" {\n  service_account { scopes = [\"cloud-platform\"] }  # default SA",
		fix: "resource \"google_compute_instance\" \"vm\" {\n  service_account {\n    email  = google_service_account.vm.email   # dedicated, least-privilege\n    scopes = [\"https://www.googleapis.com/auth/logging.write\"]\n  }\n}",
		explanation: "A GCP instance using the default Compute Engine service account inherits broad project-level API permissions. Create a dedicated least-privilege service account per resource, disable the default SA or remove its Editor role, and prefer Workload Identity Federation.",
		references: ["CWE-269", "CIS GCP Foundations Benchmark", "NIST 800-53 AC-6"]
	},
	"INFRA_GCP_EXTERNAL_IP": {
		pattern: "resource \"google_compute_instance\" \"vm\" {\n  network_interface {\n    access_config {}   # ephemeral external IP\n  }\n}",
		fix: "resource \"google_compute_instance\" \"vm\" {\n  network_interface {\n    # no access_config -> no external IP; use Cloud NAT / IAP\n    subnetwork = google_compute_subnetwork.private.id\n  }\n}",
		explanation: "A GCP compute instance with an external IP is directly internet-reachable without a load balancer. Remove the access_config block, route traffic through a Cloud Load Balancer or Cloud NAT, and use Identity-Aware Proxy for admin access.",
		references: ["CWE-668", "CIS GCP Foundations Benchmark", "NIST 800-53 SC-7"]
	},
	"INFRA_GCP_PROJECT_SSH_KEYS": {
		pattern: "resource \"google_compute_project_metadata\" \"m\" {\n  metadata = { ssh-keys = \"admin:ssh-rsa AAAA...\" }\n}",
		fix: "# Use OS Login instead of project-wide SSH keys:\nresource \"google_compute_project_metadata_item\" \"oslogin\" {\n  key   = \"enable-oslogin\"\n  value = \"TRUE\"\n}",
		explanation: "Project-level SSH keys mean a single key compromise grants access to every instance in the project. Remove project-level keys, prefer OS Login for centralized IAM-controlled access, and rotate any existing project keys.",
		references: ["CWE-522", "CIS GCP Foundations Benchmark", "NIST 800-53 AC-6"]
	},
	"INFRA_GUARDDUTY_MISSING": {
		pattern: "# No aws_guardduty_detector resource in the configuration",
		fix: "resource \"aws_guardduty_detector\" \"main\" {\n  enable = true\n  datasources { s3_logs { enable = true } }\n}",
		explanation: "With no GuardDuty detector, threat detection for credential misuse and crypto-mining is disabled. Add an aws_guardduty_detector with enable = true in every region, aggregate findings into a delegated admin account, and route high-severity alerts to on-call.",
		references: ["CWE-778", "CIS AWS Foundations Benchmark", "NIST 800-53 SI-4"]
	},
	"INFRA_IMDSV1_ACCESSIBLE": {
		pattern: "resource \"aws_instance\" \"web\" {\n  # no metadata_options -> IMDSv1 reachable\n}",
		fix: "resource \"aws_instance\" \"web\" {\n  metadata_options {\n    http_endpoint               = \"enabled\"\n    http_tokens                 = \"required\"   # IMDSv2 only\n    http_put_response_hop_limit = 1\n  }\n}",
		explanation: "IMDSv1 still accessible on EC2 lets an SSRF attacker reach 169.254.169.254 and steal IAM credentials. Set http_tokens = \"required\" to enforce IMDSv2, set hop limit to 1, and enforce IMDSv2-only account-wide via default metadata options.",
		references: ["CWE-918", "CIS AWS Foundations Benchmark", "NIST 800-53 SC-7"]
	},
	"INFRA_LAMBDA_URL_NO_AUTH": {
		pattern: "resource \"aws_lambda_function_url\" \"u\" {\n  authorization_type = \"NONE\"\n}",
		fix: "resource \"aws_lambda_function_url\" \"u\" {\n  authorization_type = \"AWS_IAM\"\n}",
		explanation: "A Lambda function URL with authorization_type NONE is publicly invocable by anyone. Set authorization_type = \"AWS_IAM\", or front the function with CloudFront signed URLs or API Gateway with IAM/Cognito; if public, add CORS restrictions and rate limiting.",
		references: ["CWE-306", "NIST 800-53 AC-3", "OWASP API Security Top 10 API2:2023"]
	},
	"INFRA_NO_VPC_ENDPOINT": {
		pattern: "# No aws_vpc_endpoint resources; AWS API traffic routes over the public internet",
		fix: "resource \"aws_vpc_endpoint\" \"s3\" {\n  vpc_id       = aws_vpc.main.id\n  service_name = \"com.amazonaws.us-east-1.s3\"\n  vpc_endpoint_type = \"Gateway\"\n}",
		explanation: "With no VPC endpoints, traffic to AWS services routes over the public internet. Create aws_vpc_endpoint resources for S3, ECR (api + dkr), and other frequently used services, using Gateway endpoints for S3/DynamoDB and Interface endpoints elsewhere with restrictive policies.",
		references: ["CWE-319", "NIST 800-53 SC-7", "AWS Well-Architected"]
	},
	"INFRA_S3_NO_ACCESS_LOGGING": {
		pattern: "resource \"aws_s3_bucket\" \"data\" {\n  bucket = \"my-data\"\n}",
		fix: "resource \"aws_s3_bucket_logging\" \"data\" {\n  bucket        = aws_s3_bucket.data.id\n  target_bucket = aws_s3_bucket.logs.id\n  target_prefix = \"s3-access/\"\n}",
		explanation: "S3 server access logging disabled makes exfiltration events undetectable after an incident. Configure server access logging with a target_bucket, supplement with CloudTrail S3 data events, and retain logs at least 90 days in a SIEM.",
		references: ["CWE-778", "CIS AWS Foundations Benchmark 3.6", "NIST 800-53 AU-2"]
	},
	"INFRA_SECURITY_HUB_MISSING": {
		pattern: "# No aws_securityhub_account resource in the configuration",
		fix: "resource \"aws_securityhub_account\" \"main\" {}\nresource \"aws_securityhub_standards_subscription\" \"fsbp\" {\n  standards_arn = \"arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices/v/1.0.0\"\n}",
		explanation: "Without Security Hub, findings from GuardDuty, Inspector, and Macie are not centrally aggregated. Add an aws_securityhub_account, enable the AWS Foundational Security Best Practices and CIS standards, and aggregate findings into a delegated admin.",
		references: ["CWE-778", "CIS AWS Foundations Benchmark", "NIST 800-53 SI-4"]
	},
	"INFRA_VPC_NO_FLOW_LOGS": {
		pattern: "# No aws_flow_log resource; VPC network traffic is unlogged",
		fix: "resource \"aws_flow_log\" \"vpc\" {\n  vpc_id          = aws_vpc.main.id\n  traffic_type    = \"ALL\"\n  log_destination = aws_cloudwatch_log_group.flow.arn\n  iam_role_arn    = aws_iam_role.flow.arn\n}",
		explanation: "With no VPC Flow Logs, network traffic is unlogged and lateral movement or exfiltration is undetectable. Add an aws_flow_log for each VPC capturing ALL traffic, use a 1-minute aggregation interval, and alarm on rejected-traffic spikes.",
		references: ["CWE-778", "CIS AWS Foundations Benchmark 3.9", "NIST 800-53 AU-2"]
	},
	"K8S_ADMISSION_WEBHOOK_EXTERNAL_URL": {
		pattern: "webhooks:\n  - clientConfig:\n      url: https://external.example.com/validate\n    failurePolicy: Ignore",
		fix: "webhooks:\n  - clientConfig:\n      service: { name: webhook-svc, namespace: security, path: /validate }\n      caBundle: <base64 CA>\n    failurePolicy: Fail\n    namespaceSelector: { matchLabels: { webhook: enabled } }",
		explanation: "A webhook clientConfig pointing at an external url intercepts every admitted object and can be MITM'd, repointed, or made to fail-open. Point clientConfig at an in-cluster Service with a pinned caBundle, set failurePolicy: Fail, and scope selectors so it only sees required objects.",
		references: ["CWE-295", "CWE-306", "CIS Kubernetes Benchmark", "NIST 800-53 SC-8"]
	},
	"K8S_ALLOW_PRIV_ESC_NOT_FALSE": {
		pattern: "securityContext:\n  runAsNonRoot: true",
		fix: "securityContext:\n  runAsNonRoot: true\n  allowPrivilegeEscalation: false",
		explanation: "Without allowPrivilegeEscalation: false, a setuid binary or file capabilities can let a process gain more privileges than its parent, a building block for container escape. Explicitly set allowPrivilegeEscalation: false on every container.",
		references: ["CWE-250", "CWE-269", "CIS Kubernetes Benchmark 5.2.5", "NIST 800-190"]
	},
	"K8S_APISERVER_INSECURE_FLAGS": {
		pattern: "kube-apiserver\n  --authorization-mode=AlwaysAllow\n  --insecure-port=8080",
		fix: "kube-apiserver\n  --authorization-mode=Node,RBAC\n  # no --insecure-port / --insecure-bind-address; TLS client auth required",
		explanation: "--authorization-mode=AlwaysAllow disables RBAC and --insecure-port exposes an unauthenticated API endpoint. Set --authorization-mode=Node,RBAC, remove all insecure-port flags, and require TLS client authentication on the API server.",
		references: ["CWE-306", "CWE-284", "CIS Kubernetes Benchmark 1.2", "NIST 800-53 AC-3"]
	},
	"K8S_API_ANONYMOUS_AUTH": {
		pattern: "kube-apiserver\n  --anonymous-auth=true",
		fix: "kube-apiserver\n  --anonymous-auth=false\n# remove any ClusterRoleBindings for system:anonymous",
		explanation: "--anonymous-auth=true processes unauthenticated requests as system:anonymous. Set --anonymous-auth=false and remove any ClusterRoleBindings for system:anonymous.",
		references: ["CWE-306", "CIS Kubernetes Benchmark 1.2.1", "NIST 800-53 AC-3"]
	},
	"K8S_APPARMOR_UNCONFINED": {
		pattern: "metadata:\n  annotations:\n    container.apparmor.security.beta.kubernetes.io/app: unconfined",
		fix: "securityContext:\n  appArmorProfile:\n    type: RuntimeDefault",
		explanation: "An unconfined AppArmor profile removes mandatory access control over file and capability use inside the container. Set appArmorProfile.type: RuntimeDefault (or a Localhost profile) and remove any unconfined apparmor annotation.",
		references: ["CWE-693", "CIS Kubernetes Benchmark 5.2.7", "NIST 800-190"]
	},
	"K8S_BIND_SYSTEM_AUTHENTICATED": {
		pattern: "subjects:\n  - kind: Group\n    name: system:authenticated",
		fix: "subjects:\n  - kind: ServiceAccount\n    name: app\n    namespace: prod   # specific principals that require the role",
		explanation: "system:authenticated includes every authenticated identity in the cluster, so binding any non-trivial role to it is effectively cluster-wide access. Replace the system:authenticated subject with the specific users/groups/ServiceAccounts that require the role.",
		references: ["CWE-269", "CWE-284", "CIS Kubernetes Benchmark 5.1.3", "NIST 800-53 AC-6"]
	},
	"K8S_CAPABILITIES_NOT_DROPPED": {
		pattern: "securityContext:\n  capabilities:\n    add: [\"NET_BIND_SERVICE\"]",
		fix: "securityContext:\n  capabilities:\n    drop: [\"ALL\"]\n    add: [\"NET_BIND_SERVICE\"]",
		explanation: "Not dropping capabilities leaves powerful defaults like NET_RAW and SYS_PTRACE available for host attacks. Add capabilities.drop: [ALL] to every container and re-add only the minimal capabilities the workload needs.",
		references: ["CWE-250", "CWE-269", "CIS Kubernetes Benchmark 5.2.9", "NIST 800-190"]
	},
	"K8S_CLUSTER_ADMIN_BINDING": {
		pattern: "kind: ClusterRoleBinding\nroleRef:\n  kind: ClusterRole\n  name: cluster-admin",
		fix: "kind: RoleBinding   # namespaced, least-privilege\nroleRef:\n  kind: Role\n  name: app-deployer   # only the permissions actually needed",
		explanation: "A ClusterRoleBinding to cluster-admin grants unrestricted control of the entire cluster. Remove cluster-admin bindings and apply scoped Roles/ClusterRoles with only the permissions actually needed.",
		references: ["CWE-269", "CWE-284", "CIS Kubernetes Benchmark 5.1.1", "NIST 800-53 AC-6"]
	},
	"K8S_CONTAINER_RUNS_AS_ROOT": {
		pattern: "securityContext:\n  runAsUser: 0",
		fix: "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
		explanation: "A container explicitly running as root (runAsUser: 0) means a container escape yields immediate host root. Set runAsNonRoot: true and a non-zero runAsUser UID in all container securityContexts.",
		references: ["CWE-250", "CIS Kubernetes Benchmark 5.2.6", "NIST 800-190"]
	},
	"K8S_CRB_DEFAULT_SA": {
		pattern: "subjects:\n  - kind: ServiceAccount\n    name: default\n    namespace: prod",
		fix: "subjects:\n  - kind: ServiceAccount\n    name: app-sa   # dedicated, named SA\n    namespace: prod\n# set the pod's serviceAccountName: app-sa explicitly",
		explanation: "Binding cluster permissions to the default SA gives every pod in that namespace (which uses default unless overridden) those permissions. Bind to a dedicated, named ServiceAccount with least privilege and set the pod's serviceAccountName explicitly.",
		references: ["CWE-269", "CWE-284", "CIS Kubernetes Benchmark 5.1.5", "NIST 800-53 AC-6"]
	},
	"K8S_DANGEROUS_CAPABILITY_ADDED": {
		pattern: "securityContext:\n  capabilities:\n    add: [\"SYS_ADMIN\", \"SYS_PTRACE\"]",
		fix: "securityContext:\n  capabilities:\n    drop: [\"ALL\"]\n    add: [\"NET_BIND_SERVICE\"]   # only minimal, non-dangerous caps",
		explanation: "SYS_ADMIN is nearly root; SYS_PTRACE debugs host processes; SYS_MODULE loads kernel modules; DAC_READ_SEARCH bypasses file permissions; BPF and NET_RAW enable kernel/network attacks. Remove these from capabilities.add, drop ALL, and re-add only minimal non-dangerous capabilities.",
		references: ["CWE-250", "CWE-269", "CIS Kubernetes Benchmark 5.2.9", "NIST 800-190"]
	},
	"K8S_DEFAULT_NAMESPACE": {
		pattern: "metadata:\n  name: app\n  # no namespace -> default",
		fix: "metadata:\n  name: app\n  namespace: team-a   # dedicated namespace",
		explanation: "Deploying into the default namespace (or omitting namespace) prevents scoping RBAC and NetworkPolicies per application/team. Create dedicated namespaces for each app/team and apply RBAC and NetworkPolicies scoped to them.",
		references: ["CWE-668", "CIS Kubernetes Benchmark 5.7.1", "NIST 800-53 SC-7"]
	},
	"K8S_DEFAULT_SA_TOKEN_AUTOMOUNT": {
		pattern: "apiVersion: v1\nkind: ServiceAccount\nmetadata: { name: default, namespace: prod }\n# automountServiceAccountToken not disabled",
		fix: "apiVersion: v1\nkind: ServiceAccount\nmetadata: { name: default, namespace: prod }\nautomountServiceAccountToken: false\n# opt back in per-pod only for workloads that call the API",
		explanation: "Every pod that omits serviceAccountName runs as the namespace default SA; if it automounts its token, a compromised pod immediately holds an API credential it never needed. Patch the default SA to automountServiceAccountToken: false and opt back in only for workloads that call the API.",
		references: ["CWE-250", "CWE-522", "CIS Kubernetes Benchmark 5.1.6", "NIST 800-190"]
	},
	"K8S_DEPRECATED_PSP": {
		pattern: "apiVersion: policy/v1beta1\nkind: PodSecurityPolicy",
		fix: "# PSP removed in 1.25; use Pod Security Admission:\napiVersion: v1\nkind: Namespace\nmetadata:\n  labels: { pod-security.kubernetes.io/enforce: restricted }",
		explanation: "PodSecurityPolicy was removed in Kubernetes 1.25, so it is silently non-enforcing on modern clusters and leaves pods unconstrained. Migrate to Pod Security Admission (restricted) and/or a policy engine (Kyverno/Gatekeeper).",
		references: ["CWE-693", "CIS Kubernetes Benchmark 5.2", "NIST 800-190"]
	},
	"K8S_DNS_POLICY_DEFAULT": {
		pattern: "spec:\n  dnsPolicy: Default",
		fix: "spec:\n  dnsPolicy: ClusterFirst",
		explanation: "dnsPolicy: Default inherits the node's resolver, bypassing cluster DNS policy and any DNS-based egress controls. Use dnsPolicy: ClusterFirst so pods resolve through CoreDNS and are subject to cluster DNS controls.",
		references: ["CWE-350", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"K8S_DOCKER_SOCKET_MOUNT": {
		pattern: "volumes:\n  - name: dockersock\n    hostPath: { path: /var/run/docker.sock }",
		fix: "# Remove the docker.sock mount; build images with Kaniko/Buildah instead:\nvolumes: []",
		explanation: "Mounting the Docker socket into a pod lets the container control the host Docker daemon, a trivial escape to root. Remove /var/run/docker.sock mounts and use a rootless in-cluster image builder (Kaniko, Buildah) or a registry.",
		references: ["CWE-668", "CWE-250", "CIS Kubernetes Benchmark 5.2", "NIST 800-190"]
	},
	"K8S_ENV_LITERAL_SECRET": {
		pattern: "env:\n  - name: DB_PASSWORD\n    value: SuperSecret123",
		fix: "env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef: { name: db-credentials, key: password }",
		explanation: "A literal env value containing a password/token is baked into the pod spec and visible to anyone with get pod / describe access. Use valueFrom.secretKeyRef to reference a Secret, and prefer mounting secrets as files over env vars.",
		references: ["CWE-798", "CWE-522", "CIS Kubernetes Benchmark", "NIST 800-53 IA-5"]
	},
	"K8S_EPHEMERAL_CONTAINERS": {
		pattern: "spec:\n  ephemeralContainers:\n    - name: debug\n      image: busybox",
		fix: "spec: {}   # remove ephemeralContainers from committed manifests\n# gate 'kubectl debug' behind RBAC and audit logging",
		explanation: "Ephemeral/debug containers can attach to a running pod's namespaces and read its process memory and mounted secrets, bypassing the original container's securityContext. Remove ephemeralContainers from committed manifests and gate kubectl debug behind RBAC and audit logging.",
		references: ["CWE-668", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"K8S_ETCD_NO_TLS": {
		pattern: "etcd\n  --client-cert-auth=false\n  --listen-client-urls=http://0.0.0.0:2379",
		fix: "etcd\n  --client-cert-auth=true\n  --listen-client-urls=https://127.0.0.1:2379\n  --peer-client-cert-auth=true",
		explanation: "etcd holds every cluster Secret in plaintext, so a plaintext or unauthenticated etcd endpoint is total cluster compromise. Set --client-cert-auth=true, serve only https client URLs, and enable peer TLS.",
		references: ["CWE-306", "CWE-319", "CIS Kubernetes Benchmark 2.1", "NIST 800-53 SC-8"]
	},
	"K8S_HELM_HOOK_PRIVILEGED": {
		pattern: "metadata:\n  annotations: { \"helm.sh/hook\": pre-install }\nspec:\n  containers:\n    - securityContext: { privileged: true }",
		fix: "metadata:\n  annotations: { \"helm.sh/hook\": pre-install }\nspec:\n  containers:\n    - securityContext:\n        privileged: false\n        runAsNonRoot: true\n        allowPrivilegeEscalation: false\n        capabilities: { drop: [\"ALL\"] }",
		explanation: "A privileged Helm pre/post-install hook runs with full host access during every release, so a compromised chart gains node root. Drop privileged from hook jobs, run them as non-root with a minimal securityContext, and review third-party chart hooks.",
		references: ["CWE-250", "CWE-269", "CIS Kubernetes Benchmark 5.2.1", "NIST 800-190"]
	},
	"K8S_HOSTNETWORK_PRIVILEGED_COMBO": {
		pattern: "spec:\n  hostNetwork: true\n  containers:\n    - securityContext: { privileged: true }",
		fix: "spec:\n  hostNetwork: false\n  containers:\n    - securityContext:\n        privileged: false\n        capabilities: { drop: [\"ALL\"] }",
		explanation: "hostNetwork combined with privileged gives the container the node's network stack and full device access, so it can sniff all node traffic and trivially escape to host root. Remove both settings; if host networking is unavoidable, drop privileged and all unnecessary capabilities.",
		references: ["CWE-250", "CWE-668", "CIS Kubernetes Benchmark 5.2.4", "NIST 800-190"]
	},
	"K8S_HOST_ALIASES_SPOOF": {
		pattern: "spec:\n  hostAliases:\n    - ip: 10.0.0.99\n      hostnames: [ \"api.internal\" ]",
		fix: "spec: {}   # rely on cluster DNS; remove hostAliases\n# if static mapping is required, validate the IP against an allowlist",
		explanation: "hostAliases override /etc/hosts and can spoof internal service names to redirect traffic to an attacker-controlled IP. Remove hostAliases and rely on cluster DNS; if a static mapping is required, validate the IPs against an allowlist.",
		references: ["CWE-350", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"K8S_HOST_NAMESPACE": {
		pattern: "spec:\n  hostPID: true\n  hostNetwork: true\n  hostIPC: true",
		fix: "spec:\n  hostPID: false\n  hostNetwork: false\n  hostIPC: false",
		explanation: "Host namespace sharing (hostPID/hostNetwork/hostIPC) breaks container isolation and exposes the host's processes, network, and IPC. Remove these settings from pod specs.",
		references: ["CWE-668", "CIS Kubernetes Benchmark 5.2.2", "NIST 800-190"]
	},
	"K8S_HOST_PORT_BINDING": {
		pattern: "ports:\n  - containerPort: 8080\n    hostPort: 8080",
		fix: "ports:\n  - containerPort: 8080\n# expose via a Service/Ingress instead of hostPort",
		explanation: "hostPort binds the container's port directly on the node's network interface, bypassing Services/NetworkPolicies and exposing it on the node IP. Remove hostPort and expose the workload through a Service or Ingress.",
		references: ["CWE-668", "CIS Kubernetes Benchmark 5.2.4", "NIST 800-53 SC-7"]
	},
	"K8S_HOST_USERS_TRUE": {
		pattern: "spec:\n  hostUsers: true",
		fix: "spec:\n  hostUsers: false   # enable user-namespace remapping",
		explanation: "hostUsers: true disables the user namespace, so container UID 0 maps directly to host root and an escape yields immediate host root. Set hostUsers: false to enable user-namespace remapping.",
		references: ["CWE-250", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"K8S_IMAGE_NO_DIGEST_PIN": {
		pattern: "containers:\n  - image: myapp:1.2.3",
		fix: "containers:\n  - image: myapp:1.2.3@sha256:9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
		explanation: "A mutable tag can be repointed to a malicious image after review; only a @sha256 digest is immutable. Pin every image to image@sha256:<digest> and verify signatures with Cosign / sigstore policy-controller.",
		references: ["CWE-1357", "MITRE ATT&CK T1195.002", "NIST 800-190"]
	},
	"K8S_IMAGE_PULL_POLICY_CACHE": {
		pattern: "containers:\n  - image: myapp:1.2.3\n    imagePullPolicy: IfNotPresent",
		fix: "containers:\n  - image: myapp@sha256:9a1b...\n    imagePullPolicy: Always",
		explanation: "With Never/IfNotPresent a pod can run a same-tagged image already cached on the node by another tenant, bypassing registry auth and admission scanning. Use imagePullPolicy: Always with digest-pinned images so the node fetches and verifies the intended image.",
		references: ["CWE-349", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"K8S_INGRESS_NO_TLS": {
		pattern: "kind: Ingress\nspec:\n  rules:\n    - host: app.example.com",
		fix: "kind: Ingress\nspec:\n  tls:\n    - hosts: [ app.example.com ]\n      secretName: app-tls\n  rules:\n    - host: app.example.com",
		explanation: "An Ingress with no tls block serves traffic over plaintext HTTP, exposing credentials and sessions to interception. Add a tls section with a valid certificate (cert-manager) and enforce HTTPS redirects.",
		references: ["CWE-319", "OWASP Top 10 A02:2021", "NIST 800-53 SC-8"]
	},
	"K8S_INLINE_DOCKERCONFIG": {
		pattern: "kind: Secret\ntype: kubernetes.io/dockerconfigjson\ndata:\n  .dockerconfigjson: eyJhdXRocyI6...   # committed",
		fix: "# Deliver registry creds via External Secrets / Sealed Secrets, referenced as imagePullSecrets:\nspec:\n  imagePullSecrets:\n    - name: regcred   # synced from a secrets manager, not committed",
		explanation: "An inline .dockerconfigjson in a committed manifest leaks registry credentials that can be base64-decoded from git history. Store registry creds in a sealed/external Secret and reference via imagePullSecrets, never inline in version control.",
		references: ["CWE-798", "CWE-522", "NIST 800-53 IA-5", "CIS Kubernetes Benchmark"]
	},
	"K8S_KUBELET_ANON_AUTH": {
		pattern: "# kubelet config\nauthentication:\n  anonymous: { enabled: true }",
		fix: "authentication:\n  anonymous: { enabled: false }\n  x509: { clientCAFile: /etc/kubernetes/pki/ca.crt }\n  webhook: { enabled: true }",
		explanation: "Anonymous kubelet auth lets unauthenticated callers exec into pods and read node secrets on port 10250. Set authentication.anonymous.enabled: false and require X509/Webhook auth on the kubelet.",
		references: ["CWE-306", "CIS Kubernetes Benchmark 4.2.1", "NIST 800-53 AC-3"]
	},
	"K8S_KUBELET_INSECURE_CONFIG": {
		pattern: "# kubelet config\nreadOnlyPort: 10255\nauthorization: { mode: AlwaysAllow }",
		fix: "readOnlyPort: 0\nauthentication:\n  anonymous: { enabled: false }\nauthorization:\n  mode: Webhook",
		explanation: "The kubelet read-only port (10255) exposes pod and node data unauthenticated, and authorization AlwaysAllow lets any caller hit the kubelet API. Set readOnlyPort: 0, disable anonymous auth, and set authorization.mode: Webhook.",
		references: ["CWE-306", "CWE-284", "CIS Kubernetes Benchmark 4.2", "NIST 800-53 AC-3"]
	},
	"K8S_LATEST_IMAGE_TAG": {
		pattern: "containers:\n  - image: myapp:latest",
		fix: "containers:\n  - image: myapp@sha256:9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
		explanation: "Using the :latest tag leads to unpredictable, unreviewed deployments and enables a supply-chain image swap. Pin container images to an immutable digest and never use :latest in production.",
		references: ["CWE-1357", "MITRE ATT&CK T1195.002", "NIST 800-190"]
	},
	"K8S_LB_OPEN_SOURCE_RANGES": {
		pattern: "kind: Service\nspec:\n  type: LoadBalancer\n  # no loadBalancerSourceRanges (or 0.0.0.0/0)",
		fix: "kind: Service\nspec:\n  type: LoadBalancer\n  loadBalancerSourceRanges:\n    - 203.0.113.0/24   # specific trusted CIDRs",
		explanation: "A LoadBalancer without source-range restriction is reachable from the entire internet, bypassing any WAF. Set loadBalancerSourceRanges to specific trusted CIDRs, or front the service with an Ingress/API gateway and a WAF.",
		references: ["CWE-284", "NIST 800-53 SC-7", "CIS Kubernetes Benchmark"]
	},
	"K8S_MISSING_RUN_AS_NONROOT": {
		pattern: "securityContext:\n  runAsUser: 1000",
		fix: "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
		explanation: "Without runAsNonRoot: true the kubelet will start an image whose default user is root, maximizing escape blast radius. Set securityContext.runAsNonRoot: true and a non-zero runAsUser on every container.",
		references: ["CWE-250", "CIS Kubernetes Benchmark 5.2.6", "NIST 800-190"]
	},
	"K8S_MTLS_NOT_STRICT": {
		pattern: "kind: PeerAuthentication\nspec:\n  mtls: { mode: PERMISSIVE }",
		fix: "kind: PeerAuthentication\nspec:\n  mtls: { mode: STRICT }",
		explanation: "An Istio/Linkerd PeerAuthentication in PERMISSIVE or DISABLE mode allows plaintext inter-service traffic. Set mode: STRICT in all PeerAuthentication resources to enforce mTLS for all inter-service communication.",
		references: ["CWE-319", "NIST 800-53 SC-8", "CIS Kubernetes Benchmark"]
	},
	"K8S_NETPOL_ALLOW_ALL_EGRESS": {
		pattern: "kind: NetworkPolicy\nspec:\n  podSelector: {}\n  policyTypes: [ Egress ]\n  egress:\n    - {}",
		fix: "kind: NetworkPolicy\nspec:\n  podSelector: { matchLabels: { app: web } }\n  policyTypes: [ Egress ]\n  egress:\n    - to:\n        - ipBlock: { cidr: 10.0.0.0/16 }\n      ports: [ { protocol: TCP, port: 5432 } ]",
		explanation: "An empty podSelector selecting all pods combined with an open egress rule lets any compromised pod exfiltrate data anywhere on the internet. Scope the podSelector and restrict egress to the specific destinations each workload needs.",
		references: ["CWE-284", "NIST 800-53 SC-7", "CIS Kubernetes Benchmark 5.3.2"]
	},
	"K8S_NETPOL_EMPTY_NAMESPACE_SELECTOR": {
		pattern: "ingress:\n  - from:\n      - namespaceSelector: {}",
		fix: "ingress:\n  - from:\n      - namespaceSelector:\n          matchLabels: { network-tier: frontend }\n        podSelector:\n          matchLabels: { app: gateway }",
		explanation: "An empty namespaceSelector matches ALL namespaces, so the rule allows traffic from every workload in the cluster, defeating namespace isolation. Scope the selector with explicit labels, combine with a podSelector, and keep a default-deny policy in the namespace.",
		references: ["CWE-284", "NIST 800-53 SC-7", "CIS Kubernetes Benchmark 5.3.2"]
	},
	"K8S_NODEPORT_EXPOSURE": {
		pattern: "kind: Service\nspec:\n  type: NodePort",
		fix: "kind: Service\nspec:\n  type: ClusterIP   # front with LoadBalancer/Ingress + WAF",
		explanation: "A NodePort service is exposed on every node's public IP and bypasses a WAF. Replace NodePort services with LoadBalancer or Ingress resources fronted by a WAF/API gateway.",
		references: ["CWE-668", "NIST 800-53 SC-7", "CIS Kubernetes Benchmark"]
	},
	"K8S_NO_NETWORK_POLICY": {
		pattern: "# No NetworkPolicy in the namespace -> all pod-to-pod traffic allowed",
		fix: "kind: NetworkPolicy\nmetadata: { name: default-deny }\nspec:\n  podSelector: {}\n  policyTypes: [ Ingress, Egress ]   # then add explicit allow rules",
		explanation: "With no NetworkPolicy, all pod-to-pod traffic is allowed, so a compromised pod can reach any other. Create NetworkPolicy resources that default-deny all traffic and only allow explicitly required paths.",
		references: ["CWE-284", "NIST 800-53 SC-7", "CIS Kubernetes Benchmark 5.3.2"]
	},
	"K8S_NO_POD_DISRUPTION_BUDGET": {
		pattern: "# Deployment with replicas but no PodDisruptionBudget",
		fix: "kind: PodDisruptionBudget\nspec:\n  minAvailable: 2\n  selector: { matchLabels: { app: web } }",
		explanation: "Without a PodDisruptionBudget, a node drain or voluntary disruption can take all replicas down at once, an availability/DoS risk. Add a PodDisruptionBudget with minAvailable (or maxUnavailable) for each critical workload.",
		references: ["CWE-770", "NIST 800-53 CP-2", "Kubernetes Best Practices"]
	},
	"K8S_NO_POLICY_ENGINE": {
		pattern: "# No OPA Gatekeeper / Kyverno admission controller deployed",
		fix: "# Deploy Kyverno and enforce policy as code, e.g.:\nkind: ClusterPolicy\nspec:\n  validationFailureAction: Enforce\n  rules:\n    - name: disallow-privileged\n      validate: { pattern: { spec: { containers: [ { securityContext: { privileged: \"false\" } } ] } } }",
		explanation: "Without an admission policy engine, security invariants (no privileged, image-signature required, etc.) are not enforced at admission time. Deploy Kyverno or OPA Gatekeeper and codify pod-security and supply-chain policies as enforced constraints.",
		references: ["CWE-693", "NIST 800-53 CM-6", "CIS Kubernetes Benchmark 5.2"]
	},
	"K8S_NO_PSA_LABEL": {
		pattern: "apiVersion: v1\nkind: Namespace\nmetadata: { name: prod }",
		fix: "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: prod\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\n    pod-security.kubernetes.io/warn: restricted",
		explanation: "A Namespace missing the Pod Security Admission enforce label leaves pod security rules unenforced. Add pod-security.kubernetes.io/enforce: restricted to all Namespace manifests, and optionally enforce via a Gatekeeper/Kyverno constraint.",
		references: ["CWE-693", "CIS Kubernetes Benchmark 5.2.1", "NIST 800-190"]
	},
	"K8S_NO_READONLY_ROOT": {
		pattern: "securityContext:\n  runAsNonRoot: true",
		fix: "securityContext:\n  runAsNonRoot: true\n  readOnlyRootFilesystem: true\n# mount writable paths explicitly via emptyDir where needed",
		explanation: "A writable root filesystem lets an attacker modify binaries or write persistence mechanisms. Set readOnlyRootFilesystem: true in all container securityContexts and mount writable paths explicitly via emptyDir volumes where legitimately needed.",
		references: ["CWE-732", "CIS Kubernetes Benchmark 5.2.12", "NIST 800-190"]
	},
	"K8S_NO_RESOURCE_LIMITS": {
		pattern: "containers:\n  - name: app\n    image: myapp:1.0   # no resources.limits",
		fix: "containers:\n  - name: app\n    image: myapp:1.0\n    resources:\n      limits: { cpu: \"1\", memory: 512Mi }\n      requests: { cpu: \"250m\", memory: 256Mi }",
		explanation: "Missing resource limits allow a single container to starve the entire node (DoS). Add resources.limits (cpu, memory) to all containers.",
		references: ["CWE-770", "NIST 800-53 SC-6", "CIS Kubernetes Benchmark"]
	},
	"K8S_NO_RUNTIME_CLASS": {
		pattern: "spec:\n  containers:\n    - name: app\n      image: untrusted:1.0",
		fix: "spec:\n  runtimeClassName: gvisor   # or kata, for untrusted/multi-tenant workloads\n  containers:\n    - name: app\n      image: untrusted:1.0",
		explanation: "Without a sandboxed runtimeClass (gVisor/Kata), a kernel exploit in the container reaches the shared host kernel directly. For untrusted or multi-tenant workloads set runtimeClassName to a gVisor (runsc) or Kata runtime.",
		references: ["CWE-693", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"K8S_PRIVILEGE_ESCALATION": {
		pattern: "securityContext:\n  allowPrivilegeEscalation: true",
		fix: "securityContext:\n  allowPrivilegeEscalation: false",
		explanation: "allowPrivilegeEscalation: true lets child processes gain more privileges than their parent. Set allowPrivilegeEscalation: false in all container securityContexts.",
		references: ["CWE-250", "CWE-269", "CIS Kubernetes Benchmark 5.2.5", "NIST 800-190"]
	},
	"K8S_PROCMOUNT_UNMASKED": {
		pattern: "securityContext:\n  procMount: Unmasked",
		fix: "securityContext:\n  procMount: Default",
		explanation: "procMount: Unmasked exposes the full host /proc (including /proc/sysrq-trigger and kcore), enabling host inspection and several escape techniques. Remove procMount: Unmasked and use the Default masked /proc.",
		references: ["CWE-668", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"K8S_PROJECTED_TOKEN_NO_AUDIENCE": {
		pattern: "volumes:\n  - name: token\n    projected:\n      sources:\n        - serviceAccountToken: { path: token }   # no audience/expiration",
		fix: "volumes:\n  - name: token\n    projected:\n      sources:\n        - serviceAccountToken:\n            path: token\n            audience: vault\n            expirationSeconds: 3600",
		explanation: "A projected SA token with no audience is valid against the API server and can be replayed broadly, and no expirationSeconds makes it long-lived. Set a specific audience and a short expirationSeconds on every projected serviceAccountToken volume.",
		references: ["CWE-613", "CWE-522", "NIST 800-53 IA-5", "CIS Kubernetes Benchmark"]
	},
	"K8S_PSA_EXEMPTION_OR_SECCOMP_OVERRIDE": {
		pattern: "# PodSecurity config with exemptions, or legacy annotation:\nexemptions:\n  namespaces: [ payments ]\n# seccomp.security.alpha.kubernetes.io/pod: unconfined",
		fix: "# Remove exemptions; enforce restricted and set the modern seccomp field:\nsecurityContext:\n  seccompProfile: { type: RuntimeDefault }\n# namespace label: pod-security.kubernetes.io/enforce: restricted",
		explanation: "A PodSecurity exemption (by username, runtimeClass, or namespace) lets exempt workloads run privileged/hostPath/root even where enforce: restricted is set, and the legacy unconfined seccomp annotation disables syscall filtering. Remove exemptions, set seccompProfile.type: RuntimeDefault, and enforce restricted plus a Kyverno/Gatekeeper policy.",
		references: ["CWE-693", "CWE-284", "CIS Kubernetes Benchmark 5.2.1", "NIST 800-190"]
	},
	"K8S_PSA_NOT_RESTRICTED": {
		pattern: "metadata:\n  labels: { pod-security.kubernetes.io/enforce: baseline }",
		fix: "metadata:\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\n    pod-security.kubernetes.io/warn: restricted",
		explanation: "enforce: baseline still permits hostPath, running as root, and added capabilities; privileged permits everything. Set pod-security.kubernetes.io/enforce: restricted on application namespaces and warn/audit at restricted too.",
		references: ["CWE-693", "CIS Kubernetes Benchmark 5.2.1", "NIST 800-190"]
	},
	"K8S_RBAC_CLUSTER_SECRETS": {
		pattern: "kind: ClusterRole\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"secrets\"]\n    verbs: [\"get\", \"list\", \"watch\"]",
		fix: "kind: Role   # namespaced, or restrict to named secrets\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"secrets\"]\n    resourceNames: [\"app-db\"]\n    verbs: [\"get\"]",
		explanation: "Cluster-scoped get/list/watch on Secrets exposes every Secret in every namespace, including SA tokens, registry creds, and TLS keys. Replace the ClusterRole with namespaced Roles, or restrict it to specific named Secrets via resourceNames.",
		references: ["CWE-269", "CWE-522", "CIS Kubernetes Benchmark 5.1.2", "NIST 800-53 AC-6"]
	},
	"K8S_RBAC_CSR_APPROVE": {
		pattern: "rules:\n  - apiGroups: [\"certificates.k8s.io\"]\n    resources: [\"certificatesigningrequests/approval\"]\n    verbs: [\"update\"]",
		fix: "# Remove CSR approve/sign from all subjects except controller-manager.\nrules: []",
		explanation: "Approving CSRs lets an attacker issue client certs for arbitrary identities (e.g. CN=system:masters) and authenticate as cluster-admin, bypassing RBAC entirely. Remove CSR approve/sign permissions from all subjects except the controller-manager and audit all approved CSRs.",
		references: ["CWE-269", "CWE-295", "CIS Kubernetes Benchmark 5.1", "NIST 800-53 AC-6"]
	},
	"K8S_RBAC_ESCALATE_VERB": {
		pattern: "rules:\n  - apiGroups: [\"rbac.authorization.k8s.io\"]\n    resources: [\"roles\", \"clusterroles\"]\n    verbs: [\"escalate\", \"bind\", \"impersonate\"]",
		fix: "# Remove escalate/bind/impersonate unless the subject is a trusted controller.\nrules:\n  - apiGroups: [\"rbac.authorization.k8s.io\"]\n    resources: [\"roles\"]\n    verbs: [\"get\", \"list\"]",
		explanation: "The escalate verb lets a subject grant itself permissions it does not have, bind lets it create bindings to any role, and impersonate lets it act as any user/group/SA, each a direct path to cluster-admin. Remove these verbs from all Roles/ClusterRoles unless the subject is a trusted controller, and scope impersonate to specific named users.",
		references: ["CWE-269", "CWE-266", "CIS Kubernetes Benchmark 5.1.3", "NIST 800-53 AC-6"]
	},
	"K8S_RBAC_NODES_PROXY": {
		pattern: "rules:\n  - apiGroups: [\"\"]\n    resources: [\"nodes/proxy\"]\n    verbs: [\"get\", \"create\"]",
		fix: "# Remove nodes/proxy; use pods/exec with audit logging for debugging.\nrules: []",
		explanation: "nodes/proxy exposes the kubelet API, allowing exec into any pod on the node and bypassing pod-level RBAC. Remove nodes/proxy from all roles and use the API server's pods/exec with audit logging for legitimate debugging.",
		references: ["CWE-269", "CWE-284", "CIS Kubernetes Benchmark 5.1", "NIST 800-53 AC-6"]
	},
	"K8S_RBAC_PODS_EXEC": {
		pattern: "rules:\n  - apiGroups: [\"\"]\n    resources: [\"pods/exec\", \"pods/attach\", \"pods/portforward\"]\n    verbs: [\"create\"]",
		fix: "# Restrict to a tightly scoped break-glass role gated by audit logging + MFA.\nrules: []",
		explanation: "pods/exec, pods/attach, and pods/portforward give an interactive shell into running pods, letting an attacker read mounted Secrets and SA tokens and pivot laterally. Remove these subresources from general-purpose roles and restrict to a tightly scoped break-glass role gated by audit logging and MFA.",
		references: ["CWE-269", "CWE-284", "CIS Kubernetes Benchmark 5.1", "NIST 800-53 AC-6"]
	},
	"K8S_RBAC_SA_TOKEN_CREATE": {
		pattern: "rules:\n  - apiGroups: [\"\"]\n    resources: [\"serviceaccounts/token\"]\n    verbs: [\"create\"]",
		fix: "rules:\n  - apiGroups: [\"\"]\n    resources: [\"serviceaccounts/token\"]\n    resourceNames: [\"app-sa\"]   # scope to the one SA needed\n    verbs: [\"create\"]",
		explanation: "create on serviceaccounts/token lets a subject mint short-lived tokens for any ServiceAccount it can name, effectively impersonating those SAs. Remove the permission, or scope it via resourceNames to the single SA the controller legitimately needs.",
		references: ["CWE-269", "CWE-266", "CIS Kubernetes Benchmark 5.1", "NIST 800-53 AC-6"]
	},
	"K8S_RBAC_SUPERUSER_SUBJECT": {
		pattern: "subjects:\n  - kind: Group\n    name: system:masters",
		fix: "subjects:\n  - kind: User\n    name: alice@example.com   # scoped admin, never system:masters",
		explanation: "system:masters bypasses all RBAC (a hardcoded superuser), and binding roles to system:anonymous or system:unauthenticated grants unauthenticated callers access. Remove all bindings to these subjects and use scoped admin roles instead.",
		references: ["CWE-269", "CWE-284", "CIS Kubernetes Benchmark 5.1.1", "NIST 800-53 AC-6"]
	},
	"K8S_RBAC_WILDCARD": {
		pattern: "rules:\n  - apiGroups: [\"*\"]\n    resources: [\"*\"]\n    verbs: [\"*\"]",
		fix: "rules:\n  - apiGroups: [\"apps\"]\n    resources: [\"deployments\"]\n    verbs: [\"get\", \"list\", \"watch\"]",
		explanation: "Wildcard verbs/resources/apiGroups grant effective cluster-admin: any holder can read all Secrets and create workloads to harvest other ServiceAccount tokens. Replace wildcards with the explicit minimal apiGroups, resources, and verbs the subject needs.",
		references: ["CWE-269", "CWE-732", "CIS Kubernetes Benchmark 5.1.3", "NIST 800-53 AC-6"]
	},
	"K8S_RBAC_WORKLOAD_CREATE": {
		pattern: "rules:\n  - apiGroups: [\"apps\"]\n    resources: [\"deployments\", \"daemonsets\"]\n    verbs: [\"create\", \"patch\"]",
		fix: "# Restrict workload create/patch to CI/controller identities only, and\n# enforce a Kyverno/Gatekeeper policy blocking pods that mount privileged SA tokens.\nrules: []",
		explanation: "create/patch on pods/deployments/daemonsets lets an attacker schedule a pod mounting any ServiceAccount token (including privileged ones) and exfiltrate it, a well-known privilege-escalation primitive. Restrict workload create/patch to CI/controller identities and enforce a policy blocking pods that mount privileged SA tokens.",
		references: ["CWE-269", "CWE-266", "CIS Kubernetes Benchmark 5.1", "NIST 800-53 AC-6"]
	},
	"K8S_SA_DEFAULT_AUTOMOUNT": {
		pattern: "apiVersion: v1\nkind: ServiceAccount\nmetadata: { name: app }\n# automountServiceAccountToken not disabled",
		fix: "apiVersion: v1\nkind: ServiceAccount\nmetadata: { name: app }\nautomountServiceAccountToken: false",
		explanation: "ServiceAccounts default to automounting their token into every pod, handing an attacker an API credential on container compromise. Set automountServiceAccountToken: false on the ServiceAccount and opt in per-pod only where API access is required.",
		references: ["CWE-250", "CWE-522", "CIS Kubernetes Benchmark 5.1.6", "NIST 800-190"]
	},
	"K8S_SA_PATH_MOUNT": {
		pattern: "volumeMounts:\n  - name: sa\n    mountPath: /var/run/secrets/kubernetes.io/serviceaccount",
		fix: "# Remove the explicit SA token mount; let the kubelet project a scoped token\n# only for workloads that call the API.\nvolumeMounts: []",
		explanation: "Explicitly mounting /var/run/secrets/kubernetes.io into an untrusted container hands it the API credential even when automount is disabled. Remove explicit hostPath/volume mounts of the SA token path and let the kubelet project a scoped token only where needed.",
		references: ["CWE-522", "CWE-250", "CIS Kubernetes Benchmark 5.1.6", "NIST 800-190"]
	},
	"K8S_SA_TOKEN_AUTOMOUNT_TRUE": {
		pattern: "spec:\n  automountServiceAccountToken: true",
		fix: "spec:\n  automountServiceAccountToken: false\n# for API-calling workloads, mount a scoped projected token instead",
		explanation: "Auto-mounting the SA token into every pod hands an attacker who compromises the container a credential to call the Kubernetes API. Set automountServiceAccountToken: false at the pod and ServiceAccount level unless the workload genuinely calls the API; then mount a scoped projected token.",
		references: ["CWE-250", "CWE-522", "CIS Kubernetes Benchmark 5.1.6", "NIST 800-190"]
	},
	"K8S_SECCOMP_UNCONFINED": {
		pattern: "securityContext:\n  seccompProfile: { type: Unconfined }",
		fix: "securityContext:\n  seccompProfile: { type: RuntimeDefault }",
		explanation: "seccompProfile: Unconfined removes syscall filtering, exposing the full kernel attack surface (keyctl, unshare, etc.) used in container-escape exploits. Set seccompProfile.type: RuntimeDefault (or a tighter Localhost profile) on every pod/container.",
		references: ["CWE-693", "CIS Kubernetes Benchmark 5.2.2", "NIST 800-190"]
	},
	"K8S_SECRET_IN_CONFIGMAP": {
		pattern: "kind: ConfigMap\ndata:\n  DB_PASSWORD: SuperSecret123",
		fix: "kind: Secret\nmetadata: { name: db }\nstringData:\n  DB_PASSWORD: SuperSecret123   # better: Sealed Secrets / External Secrets / Vault",
		explanation: "ConfigMaps are not encrypted at rest by default, so storing a password/secret/key/token in one exposes it. Move secrets to Kubernetes Secrets objects or a secrets manager (Vault, AWS SM) and never store plaintext credentials in ConfigMaps.",
		references: ["CWE-312", "CWE-522", "CIS Kubernetes Benchmark", "NIST 800-53 IA-5"]
	},
	"K8S_SECRET_PLAINTEXT_STRINGDATA": {
		pattern: "kind: Secret\nstringData:\n  password: SuperSecret123",
		fix: "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nspec:\n  encryptedData:\n    password: AgB2c1f...   # encrypted; or SOPS / External Secrets",
		explanation: "stringData stores the credential as plaintext in the committed manifest and git history, so anyone with repo read access gets the secret. Remove plaintext secrets from manifests and use Sealed Secrets, External Secrets Operator, or SOPS-encrypted values referencing a KMS.",
		references: ["CWE-798", "CWE-312", "OWASP Top 10 A07:2021", "NIST 800-53 IA-5"]
	},
	"K8S_SERVICE_EXTERNAL_IPS": {
		pattern: "kind: Service\nspec:\n  externalIPs: [ 192.0.2.10 ]",
		fix: "kind: Service\nspec:\n  type: LoadBalancer\n  loadBalancerSourceRanges: [ 203.0.113.0/24 ]   # no externalIPs",
		explanation: "externalIPs route arbitrary node-destined traffic to the service and have historically enabled traffic-hijack / MITM between tenants. Remove externalIPs and expose services via LoadBalancer or Ingress with explicit source restrictions.",
		references: ["CWE-668", "NIST 800-53 SC-7", "CIS Kubernetes Benchmark"]
	},
	"K8S_SHARE_PROCESS_NAMESPACE": {
		pattern: "spec:\n  shareProcessNamespace: true",
		fix: "spec:\n  shareProcessNamespace: false",
		explanation: "shareProcessNamespace lets every container in the pod see and signal other containers' processes and read their /proc memory, so a sidecar can steal secrets from the main container. Remove shareProcessNamespace: true unless required, and never combine it with untrusted sidecars.",
		references: ["CWE-668", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"K8S_SYSTEM_CRITICAL_PRIORITY": {
		pattern: "spec:\n  priorityClassName: system-cluster-critical",
		fix: "spec:\n  priorityClassName: app-normal   # custom PriorityClass for app workloads",
		explanation: "system-*-critical priority lets a pod preempt and evict legitimate workloads, enabling a DoS or guaranteeing scheduling for a malicious pod. Reserve system-*-critical for genuine control-plane components and use a normal/custom PriorityClass for application workloads.",
		references: ["CWE-770", "NIST 800-53 SC-6", "CIS Kubernetes Benchmark"]
	},
	"K8S_TILLER_HELM_V2": {
		pattern: "kind: Deployment\nmetadata: { name: tiller-deploy, namespace: kube-system }",
		fix: "# Migrate to Helm v3 (no Tiller). Remove tiller-deploy Deployment and its SA:\n#   kubectl -n kube-system delete deployment tiller-deploy\n#   kubectl -n kube-system delete serviceaccount tiller",
		explanation: "Helm v2 Tiller is an unauthenticated cluster-admin gRPC endpoint inside the cluster. Migrate to Helm v3, which eliminates Tiller entirely, and remove all tiller-deploy Deployments and ServiceAccounts.",
		references: ["CWE-306", "CWE-269", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"K8S_UNSAFE_SYSCTLS": {
		pattern: "securityContext:\n  sysctls:\n    - { name: kernel.shm_rmid_forced, value: \"1\" }",
		fix: "securityContext: {}   # remove sysctls unless required\n# allow only specific safe sysctls via kubelet --allowed-unsafe-sysctls",
		explanation: "Unsafe sysctls (e.g. kernel.* or namespaced net.* tunables) can weaken host kernel protections or disrupt the node. Remove sysctls unless required, and allow only specific safe sysctls via the kubelet --allowed-unsafe-sysctls allowlist.",
		references: ["CWE-693", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"K8S_WINDOWS_HOSTPROCESS": {
		pattern: "securityContext:\n  windowsOptions:\n    hostProcess: true",
		fix: "securityContext:\n  windowsOptions:\n    hostProcess: false",
		explanation: "A Windows hostProcess container runs directly on the host with the node's privileges, equivalent to privileged on Linux, and an escape is full node compromise. Remove hostProcess: true, run the workload as a normal Windows container, or isolate host-management pods on dedicated restricted nodes.",
		references: ["CWE-250", "CWE-269", "NIST 800-190", "CIS Kubernetes Benchmark"]
	},
	"RUNTIME_CERT_EXPIRED": {
		pattern: "# Live endpoint served a TLS certificate whose notAfter date is in the past",
		fix: "# Renew immediately and automate renewal (example: certbot):\ncertbot renew --deploy-hook 'systemctl reload nginx'\n# add a monitored cron/systemd timer so renewals run well before expiry",
		explanation: "An expired TLS certificate breaks trust and causes clients to reject or bypass verification. Renew the certificate immediately and set up automated renewal (e.g. Let's Encrypt with certbot) with monitoring so it never lapses again.",
		references: ["CWE-298", "CWE-295", "NIST 800-52 Rev 2", "PCI DSS 4.0 Req 4.2"]
	},
	"RUNTIME_CERT_EXPIRING": {
		pattern: "# Live endpoint TLS certificate expires within the alert window (e.g. < 30 days)",
		fix: "# Renew ahead of expiry and verify auto-renewal is actually running:\ncertbot renew --dry-run\n# alert on certificate age so renewal happens with margin",
		explanation: "A TLS certificate nearing expiry risks an outage or trust failure if renewal does not complete in time. Renew before expiry and verify auto-renewal is configured and working so the certificate is replaced with margin.",
		references: ["CWE-298", "NIST 800-52 Rev 2", "PCI DSS 4.0 Req 4.2"]
	},
	"RUNTIME_HEADER_MISSING": {
		pattern: "# Response missing a security header, e.g. no Strict-Transport-Security / CSP",
		fix: "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\nadd_header Content-Security-Policy \"default-src 'self'\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"DENY\" always;",
		explanation: "A missing security header (HSTS, CSP, X-Content-Type-Options, X-Frame-Options) leaves clients exposed to downgrade, injection, MIME-sniffing, or clickjacking attacks. Set the headers with 'always' so they apply to all routes including error pages.",
		references: ["CWE-693", "OWASP Secure Headers Project", "OWASP Top 10 A05:2021"]
	},
	"RUNTIME_TLS_WEAK": {
		pattern: "# Endpoint presents a self-signed / untrusted certificate or negotiates a weak protocol",
		fix: "# Use a CA-issued cert and disable legacy protocols/ciphers:\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\nssl_prefer_server_ciphers on;",
		explanation: "A self-signed or untrusted certificate (or weak TLS protocol/cipher) lets clients be MITM'd or forces insecure negotiation. Replace it with a certificate from a trusted CA (Let's Encrypt or your PKI) and restrict to TLS 1.2+ with strong AEAD ciphers.",
		references: ["CWE-295", "CWE-326", "NIST 800-52 Rev 2", "PCI DSS 4.0 Req 4.2"]
	},
};
