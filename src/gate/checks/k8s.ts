/**
 * Kubernetes manifest security checks.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";

type K8sContext = {
	files: string[];
	contents: Map<string, string>;
};

function matching(ctx: K8sContext, pattern: RegExp): string[] {
	return ctx.files.filter((f) => pattern.test(ctx.contents.get(f) ?? "")).slice(0, 10);
}

function filterFiles(ctx: K8sContext, predicate: (content: string) => boolean): string[] {
	return ctx.files.filter((f) => predicate(ctx.contents.get(f) ?? "")).slice(0, 10);
}

async function loadK8sManifests(): Promise<K8sContext> {
	const yamlFiles = await fg(["**/*.yaml", "**/*.yml"], {
		ignore: ["**/node_modules/**", "**/dist/**", "**/.git/**"]
	});
	const files: string[] = [];
	const contents = new Map<string, string>();
	for (const file of yamlFiles) {
		try {
			const content = await readFileSafe(file);
			if (/kind\s*:/.test(content)) {
				files.push(file);
				contents.set(file, content);
			}
		} catch {
			// skip unreadable files
		}
	}
	return { files, contents };
}

function checkContainerSecurity(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];

	const privilegedFiles = matching(ctx, /privileged:\s*true/);
	if (privilegedFiles.length > 0) {
		findings.push({
			id: "K8S_PRIVILEGED_CONTAINER",
			title: "Kubernetes manifests with privileged containers detected",
			severity: "CRITICAL",
			files: privilegedFiles,
			requiredActions: [
				"Remove privileged: true from all container securityContexts.",
				"Use specific capability grants (e.g. NET_ADMIN) instead of full privileged mode."
			]
		});
	}

	const escFiles = matching(ctx, /allowPrivilegeEscalation:\s*true/);
	if (escFiles.length > 0) {
		findings.push({
			id: "K8S_PRIVILEGE_ESCALATION",
			title: "Kubernetes manifests allow privilege escalation",
			severity: "HIGH",
			files: escFiles,
			requiredActions: [
				"Set allowPrivilegeEscalation: false in all container securityContexts.",
				"This prevents child processes from gaining more privileges than their parent."
			]
		});
	}

	const hostNsFiles = matching(ctx, /hostPID:\s*true|hostNetwork:\s*true|hostIPC:\s*true/);
	if (hostNsFiles.length > 0) {
		findings.push({
			id: "K8S_HOST_NAMESPACE",
			title: "Kubernetes manifests use host namespaces (hostPID/hostNetwork/hostIPC)",
			severity: "HIGH",
			files: hostNsFiles,
			requiredActions: [
				"Remove hostPID, hostNetwork, and hostIPC settings from pod specs.",
				"Host namespace sharing breaks container isolation and exposes the host."
			]
		});
	}

	const missingSecCtxFiles = filterFiles(ctx, (c) => /containers:/.test(c) && !/securityContext:/.test(c));
	if (missingSecCtxFiles.length > 0) {
		findings.push({
			id: "K8S_NO_SECURITY_CONTEXT",
			title: "Kubernetes manifests with containers but no securityContext",
			severity: "MEDIUM",
			files: missingSecCtxFiles,
			requiredActions: [
				"Add securityContext to all containers with runAsNonRoot: true, readOnlyRootFilesystem: true.",
				"Set allowPrivilegeEscalation: false and drop all capabilities."
			]
		});
	}

	const noReadOnlyRootFiles = filterFiles(
		ctx,
		(c) => /containers:/.test(c) && !/readOnlyRootFilesystem:\s*true/.test(c)
	);
	if (noReadOnlyRootFiles.length > 0) {
		findings.push({
			id: "K8S_NO_READONLY_ROOT",
			title: "Kubernetes containers without readOnlyRootFilesystem: true",
			severity: "MEDIUM",
			files: noReadOnlyRootFiles,
			requiredActions: [
				"Set `readOnlyRootFilesystem: true` in all container securityContexts.",
				"A writable root filesystem allows an attacker to modify binaries or write persistence mechanisms.",
				"Mount writable paths explicitly via emptyDir volumes for directories that legitimately need writes."
			]
		});
	}

	const runsAsRootFiles = matching(ctx, /runAsUser:\s*0/);
	if (runsAsRootFiles.length > 0) {
		findings.push({
			id: "K8S_CONTAINER_RUNS_AS_ROOT",
			title: "Container explicitly runs as root (runAsUser: 0)",
			severity: "HIGH",
			files: runsAsRootFiles,
			requiredActions: [
				"Container explicitly runs as root (runAsUser: 0) — container escape yields immediate host root.",
				"Set runAsNonRoot: true and use a non-zero runAsUser UID (e.g. 1000) in all container securityContexts."
			]
		});
	}

	// Use /capabilities:/ as the anchor so pod-level securityContext (which has no capabilities)
	// doesn't cause a false positive, and YAML comments don't trigger a match.
	const capsNotDroppedFiles = filterFiles(
		ctx,
		(c) => /capabilities:/.test(c) && !/drop:/.test(c)
	);
	if (capsNotDroppedFiles.length > 0) {
		findings.push({
			id: "K8S_CAPABILITIES_NOT_DROPPED",
			title: "Container capabilities not dropped",
			severity: "HIGH",
			files: capsNotDroppedFiles,
			requiredActions: [
				"Container capabilities not dropped — NET_RAW/SYS_PTRACE available for host attacks.",
				"Add capabilities.drop: [ALL] to all container securityContexts and explicitly re-add only required capabilities."
			]
		});
	}

	return findings;
}

function checkRbacAndConfig(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];

	const configMapFiles = filterFiles(
		ctx,
		(c) => /kind:\s*ConfigMap/.test(c) && /password|secret|key|token/i.test(c)
	);
	if (configMapFiles.length > 0) {
		findings.push({
			id: "K8S_SECRET_IN_CONFIGMAP",
			title: "Sensitive data (password/secret/key/token) found in Kubernetes ConfigMap",
			severity: "CRITICAL",
			files: configMapFiles,
			requiredActions: [
				"Move secrets to Kubernetes Secrets objects or a secrets manager (Vault, AWS SM).",
				"Never store plaintext credentials in ConfigMaps — they are not encrypted at rest by default."
			]
		});
	}

	const clusterAdminFiles = filterFiles(
		ctx,
		(c) => /kind:\s*ClusterRoleBinding/.test(c) && /cluster-admin/.test(c)
	);
	if (clusterAdminFiles.length > 0) {
		findings.push({
			id: "K8S_CLUSTER_ADMIN_BINDING",
			title: "ClusterRoleBinding to cluster-admin detected",
			severity: "CRITICAL",
			files: clusterAdminFiles,
			requiredActions: [
				"Remove cluster-admin bindings and apply least-privilege RBAC roles.",
				"Create scoped Roles/ClusterRoles with only the permissions actually needed."
			]
		});
	}

	const noLimitsFiles = filterFiles(ctx, (c) => /containers:/.test(c) && !/limits:/.test(c));
	if (noLimitsFiles.length > 0) {
		findings.push({
			id: "K8S_NO_RESOURCE_LIMITS",
			title: "Kubernetes containers without resource limits detected",
			severity: "MEDIUM",
			files: noLimitsFiles,
			requiredActions: [
				"Add resources.limits (cpu, memory) to all containers.",
				"Missing limits allow a single container to starve the entire node (DoS)."
			]
		});
	}

	const defaultNsFiles = filterFiles(
		ctx,
		(c) =>
			/namespace:\s*default/.test(c) ||
			(!/namespace:/.test(c) && /kind:\s*(?:Deployment|Service|Pod|StatefulSet)/.test(c))
	);
	if (defaultNsFiles.length > 0) {
		findings.push({
			id: "K8S_DEFAULT_NAMESPACE",
			title: "Kubernetes manifests use default namespace or have no namespace set",
			severity: "LOW",
			files: defaultNsFiles,
			requiredActions: [
				"Create dedicated namespaces for each application/team.",
				"Apply RBAC and NetworkPolicies scoped to those namespaces."
			]
		});
	}

	const latestTagFiles = matching(ctx, /:latest\b/);
	if (latestTagFiles.length > 0) {
		findings.push({
			id: "K8S_LATEST_IMAGE_TAG",
			title: "Kubernetes manifests use ':latest' image tag",
			severity: "HIGH",
			files: latestTagFiles,
			requiredActions: [
				"Pin container images to an immutable digest (e.g. image@sha256:...).",
				"Never use :latest in production — it leads to unpredictable deployments."
			]
		});
	}

	const nodePortFiles = matching(ctx, /type:\s*NodePort/);
	if (nodePortFiles.length > 0) {
		findings.push({
			id: "K8S_NODEPORT_EXPOSURE",
			title: "Kubernetes NodePort service detected",
			severity: "MEDIUM",
			files: nodePortFiles,
			requiredActions: [
				"Kubernetes NodePort service detected — service exposed on every node's public IP, bypasses WAF.",
				"Replace NodePort services with LoadBalancer or Ingress resources fronted by a WAF/API gateway."
			]
		});
	}

	// Also match YAML-quoted forms: anonymous-auth: 'true' and anonymous-auth: "true"
	const anonAuthFiles = matching(ctx, /--anonymous-auth=true|anonymous-auth:\s*['"]?true['"]?/);
	if (anonAuthFiles.length > 0) {
		findings.push({
			id: "K8S_API_ANONYMOUS_AUTH",
			title: "Kubernetes API server has --anonymous-auth=true",
			severity: "CRITICAL",
			files: anonAuthFiles,
			requiredActions: [
				"Kubernetes API server has --anonymous-auth=true — unauthenticated requests processed as system:anonymous.",
				"Set --anonymous-auth=false in the kube-apiserver configuration and remove any ClusterRoleBindings for system:anonymous."
			]
		});
	}

	return findings;
}

function checkDockerSocketMount(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];

	const dockerSocketFiles = matching(ctx, /\/var\/run\/docker\.sock/);
	if (dockerSocketFiles.length > 0) {
		findings.push({
			id: "K8S_DOCKER_SOCKET_MOUNT",
			title: "Docker socket mounted inside Kubernetes pod",
			severity: "CRITICAL",
			files: dockerSocketFiles,
			requiredActions: [
				"Docker socket mounted inside Kubernetes pod — container controls host Docker daemon, trivial escape to root.",
				"Remove /var/run/docker.sock volume mounts. Use a dedicated sidecar image builder (e.g. Kaniko, Buildah) or an in-cluster container registry instead."
			]
		});
	}

	return findings;
}

function checkTillerHelm(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];

	const tillerFiles = matching(ctx, /tiller-deploy|gcr\.io\/kubernetes-helm\/tiller/);
	if (tillerFiles.length > 0) {
		findings.push({
			id: "K8S_TILLER_HELM_V2",
			title: "Helm v2 Tiller detected",
			severity: "CRITICAL",
			files: tillerFiles,
			requiredActions: [
				"Helm v2 Tiller detected — unauthenticated cluster-admin gRPC endpoint inside cluster.",
				"Migrate to Helm v3 which eliminates Tiller entirely. Remove all tiller-deploy Deployments and ServiceAccounts."
			]
		});
	}

	return findings;
}

function checkMtlsPolicy(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];

	// PeerAuthentication is Istio-specific. Linkerd uses Server/AuthorizationPolicy CRDs
	// (linkerd.io/v1alpha2) — those are not covered here.
	const mtlsPermissiveFiles = filterFiles(
		ctx,
		(c) => /kind:\s*PeerAuthentication/.test(c) && /mode:\s*(?:PERMISSIVE|DISABLE)/.test(c)
	);
	if (mtlsPermissiveFiles.length > 0) {
		findings.push({
			id: "K8S_MTLS_NOT_STRICT",
			title: "Istio PeerAuthentication in PERMISSIVE or DISABLE mode",
			severity: "HIGH",
			files: mtlsPermissiveFiles,
			requiredActions: [
				"Istio/Linkerd PeerAuthentication in PERMISSIVE or DISABLE mode — plaintext inter-service traffic allowed.",
				"Set mode: STRICT in all PeerAuthentication resources to enforce mTLS for all inter-service communication."
			]
		});
	}

	return findings;
}

async function checkNetworkAndAdmission(ctx: K8sContext): Promise<Finding[]> {
	const findings: Finding[] = [];

	// Filename-only glob misses NetworkPolicy manifests in files like policies.yaml;
	// fall back to content-scanning already-loaded ctx files as the authoritative check.
	const networkPolicyFiles = ctx.files.filter((f) =>
		/kind:\s*NetworkPolicy/.test(ctx.contents.get(f) ?? "")
	);
	if (networkPolicyFiles.length === 0) {
		findings.push({
			id: "K8S_NO_NETWORK_POLICY",
			title: "No Kubernetes NetworkPolicy found — all pod-to-pod traffic is allowed",
			severity: "HIGH",
			requiredActions: [
				"Create NetworkPolicy resources to restrict ingress and egress traffic.",
				"Default-deny all traffic and only allow explicitly required paths."
			]
		});
	}

	const nsWithoutPsa = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /kind:\s*Namespace/.test(c) && !/pod-security\.kubernetes\.io\/enforce/.test(c);
		})
		.slice(0, 10);
	if (nsWithoutPsa.length > 0) {
		findings.push({
			id: "K8S_NO_PSA_LABEL",
			title: "Kubernetes Namespace missing PodSecurityAdmission enforce label",
			severity: "HIGH",
			files: nsWithoutPsa,
			requiredActions: [
				"Add `pod-security.kubernetes.io/enforce: restricted` label to all Namespace manifests.",
				"PodSecurityAdmission (PSA) is the replacement for PodSecurityPolicy — without it, pod security rules are not enforced.",
				"Enforce via OPA Gatekeeper ConstraintTemplate — run `security_generate_opa_rego` to generate policy."
			]
		});
	}

	const hostPathFiles = matching(ctx, /hostPath\s*:/);
	if (hostPathFiles.length > 0) {
		findings.push({
			id: "K8S_HOSTPATH_MOUNT",
			title: "Kubernetes manifests mount host filesystem paths (hostPath)",
			severity: "HIGH",
			files: hostPathFiles,
			requiredActions: [
				"Remove hostPath volume mounts — they expose the node's filesystem to the container.",
				"Use emptyDir, PersistentVolumeClaims, or ConfigMaps instead.",
				"Enforce via OPA Gatekeeper ConstraintTemplate — run `security_generate_opa_rego` to generate policy."
			]
		});
	}

	return findings;
}

/**
 * RBAC privilege-escalation depth — wildcard verbs/resources/apiGroups, dangerous
 * verbs, workload-create token theft paths, and binding to system superuser groups.
 */
function checkRbacEscalationDepth(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];
	const isRbac = (c: string) => /kind:\s*(?:Cluster)?Role\b/.test(c);

	const wildcardFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return (
				isRbac(c) &&
				(/verbs:\s*\[?\s*["']?\*/.test(c) ||
					/resources:\s*\[?\s*["']?\*/.test(c) ||
					/apiGroups:\s*\[?\s*["']?\*/.test(c))
			);
		})
		.slice(0, 10);
	if (wildcardFiles.length > 0) {
		findings.push({
			id: "K8S_RBAC_WILDCARD",
			title: "RBAC Role/ClusterRole grants wildcard verbs, resources, or apiGroups",
			severity: "CRITICAL",
			files: wildcardFiles,
			requiredActions: [
				"Wildcard ('*') verbs/resources/apiGroups grant effective cluster-admin — any holder can read all Secrets and create workloads to harvest other ServiceAccount tokens.",
				"Replace '*' with the explicit minimal verbs (e.g. [\"get\",\"list\"]) and named resources/apiGroups each subject actually requires."
			]
		});
	}

	const escalateVerbFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return isRbac(c) && /["']?(?:escalate|bind|impersonate)["']?/.test(c) && /verbs:/.test(c);
		})
		.slice(0, 10);
	if (escalateVerbFiles.length > 0) {
		findings.push({
			id: "K8S_RBAC_ESCALATE_VERB",
			title: "RBAC grants escalate / bind / impersonate verbs",
			severity: "CRITICAL",
			files: escalateVerbFiles,
			requiredActions: [
				"The escalate verb lets a subject grant itself permissions it does not have; bind lets it create bindings to any role; impersonate lets it act as any user/group/SA — each is a direct path to cluster-admin.",
				"Remove escalate, bind, and impersonate verbs from all Roles/ClusterRoles unless the subject is a trusted controller, and scope impersonate to specific named users."
			]
		});
	}

	const execFiles = matching(ctx, /pods\/(?:exec|attach|portforward)/);
	if (execFiles.length > 0) {
		findings.push({
			id: "K8S_RBAC_PODS_EXEC",
			title: "RBAC grants pods/exec, pods/attach, or pods/portforward",
			severity: "HIGH",
			files: execFiles,
			requiredActions: [
				"pods/exec, pods/attach, and pods/portforward give an interactive shell into running pods — an attacker can read mounted Secrets and SA tokens and pivot laterally.",
				"Remove these subresources from general-purpose roles; restrict to a tightly scoped break-glass role gated by audit logging and MFA."
			]
		});
	}

	const workloadCreateFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return (
				isRbac(c) &&
				/verbs:[\s\S]{0,80}(?:create|patch)/.test(c) &&
				/resources:[\s\S]{0,80}(?:pods|deployments|daemonsets|statefulsets|replicasets|jobs|cronjobs)/.test(c)
			);
		})
		.slice(0, 10);
	if (workloadCreateFiles.length > 0) {
		findings.push({
			id: "K8S_RBAC_WORKLOAD_CREATE",
			title: "RBAC allows create/patch on workload resources (token theft path)",
			severity: "HIGH",
			files: workloadCreateFiles,
			requiredActions: [
				"create/patch on pods/deployments/daemonsets lets an attacker schedule a pod mounting any ServiceAccount token (including privileged ones) and exfiltrate it — a well-known privilege-escalation primitive.",
				"Restrict workload create/patch to CI/controller identities only and enforce a Gatekeeper/Kyverno policy blocking pods that mount privileged SA tokens."
			]
		});
	}

	const clusterSecretFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /kind:\s*ClusterRole\b/.test(c) && /resources:[\s\S]{0,60}secrets/.test(c) && /verbs:[\s\S]{0,60}(?:get|list|watch)/.test(c);
		})
		.slice(0, 10);
	if (clusterSecretFiles.length > 0) {
		findings.push({
			id: "K8S_RBAC_CLUSTER_SECRETS",
			title: "ClusterRole grants get/list/watch on Secrets at cluster scope",
			severity: "CRITICAL",
			files: clusterSecretFiles,
			requiredActions: [
				"Cluster-scoped get/list/watch on Secrets exposes every Secret in every namespace, including SA tokens, registry creds, and TLS keys.",
				"Replace the ClusterRole with namespaced Roles, or restrict the ClusterRole to specific named Secrets via resourceNames."
			]
		});
	}

	const tokenCreateFiles = matching(ctx, /serviceaccounts\/token/);
	if (tokenCreateFiles.length > 0) {
		findings.push({
			id: "K8S_RBAC_SA_TOKEN_CREATE",
			title: "RBAC grants create on serviceaccounts/token (TokenRequest abuse)",
			severity: "HIGH",
			files: tokenCreateFiles,
			requiredActions: [
				"create on serviceaccounts/token lets a subject mint short-lived tokens for any ServiceAccount it can name — effectively impersonating those SAs.",
				"Remove serviceaccounts/token create permission, or scope it via resourceNames to the single SA the controller legitimately needs."
			]
		});
	}

	const nodesProxyFiles = matching(ctx, /nodes\/proxy/);
	if (nodesProxyFiles.length > 0) {
		findings.push({
			id: "K8S_RBAC_NODES_PROXY",
			title: "RBAC grants nodes/proxy (kubelet API access)",
			severity: "HIGH",
			files: nodesProxyFiles,
			requiredActions: [
				"nodes/proxy exposes the kubelet API, allowing exec into any pod on the node and bypassing pod-level RBAC.",
				"Remove nodes/proxy from all roles; use the API server's pods/exec with audit logging for any legitimate debugging need."
			]
		});
	}

	const csrApproveFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /certificatesigningrequests/.test(c) && /approve|signers/.test(c);
		})
		.slice(0, 10);
	if (csrApproveFiles.length > 0) {
		findings.push({
			id: "K8S_RBAC_CSR_APPROVE",
			title: "RBAC grants approve on certificatesigningrequests",
			severity: "CRITICAL",
			files: csrApproveFiles,
			requiredActions: [
				"Approving CSRs lets an attacker issue client certs for arbitrary identities (e.g. CN=system:masters) and authenticate as cluster-admin, bypassing RBAC entirely.",
				"Remove CSR approve/sign permissions from all subjects except the controller-manager; audit all approved CSRs."
			]
		});
	}

	const superuserBindFiles = matching(ctx, /system:masters|system:anonymous|system:unauthenticated/);
	if (superuserBindFiles.length > 0) {
		findings.push({
			id: "K8S_RBAC_SUPERUSER_SUBJECT",
			title: "RBAC binding references system:masters / system:anonymous / system:unauthenticated",
			severity: "CRITICAL",
			files: superuserBindFiles,
			requiredActions: [
				"system:masters bypasses all RBAC (hardcoded superuser); binding roles to system:anonymous or system:unauthenticated grants unauthenticated callers access.",
				"Remove all bindings to these subjects. Never add users to system:masters — use scoped admin roles instead."
			]
		});
	}

	return findings;
}

/**
 * Pod / workload container-escape depth — securityContext gaps, dangerous added
 * capabilities, host user namespace, unconfined profiles, token automounting.
 */
function checkPodEscapeDepth(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];
	const hasContainers = (c: string) => /containers:/.test(c);

	const apeMissingFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return hasContainers(c) && !/allowPrivilegeEscalation:\s*false/.test(c);
		})
		.slice(0, 10);
	if (apeMissingFiles.length > 0) {
		findings.push({
			id: "K8S_ALLOW_PRIV_ESC_NOT_FALSE",
			title: "Container does not set allowPrivilegeEscalation: false",
			severity: "HIGH",
			files: apeMissingFiles,
			requiredActions: [
				"Without allowPrivilegeEscalation: false, a setuid binary or file capabilities can let a process gain more privileges than its parent — a building block for escape.",
				"Explicitly set securityContext.allowPrivilegeEscalation: false on every container."
			]
		});
	}

	const procMountFiles = matching(ctx, /procMount:\s*Unmasked/);
	if (procMountFiles.length > 0) {
		findings.push({
			id: "K8S_PROCMOUNT_UNMASKED",
			title: "Container uses procMount: Unmasked",
			severity: "HIGH",
			files: procMountFiles,
			requiredActions: [
				"procMount: Unmasked exposes the full host /proc (including /proc/sysrq-trigger and kcore), enabling host inspection and several escape techniques.",
				"Remove procMount: Unmasked and use the Default masked /proc."
			]
		});
	}

	const shareProcFiles = matching(ctx, /shareProcessNamespace:\s*true/);
	if (shareProcFiles.length > 0) {
		findings.push({
			id: "K8S_SHARE_PROCESS_NAMESPACE",
			title: "Pod sets shareProcessNamespace: true",
			severity: "MEDIUM",
			files: shareProcFiles,
			requiredActions: [
				"shareProcessNamespace lets every container in the pod see and signal other containers' processes and read their /proc memory — a sidecar can steal secrets from the main container.",
				"Remove shareProcessNamespace: true unless required, and never combine it with untrusted sidecars."
			]
		});
	}

	const hostUsersFiles = matching(ctx, /hostUsers:\s*true/);
	if (hostUsersFiles.length > 0) {
		findings.push({
			id: "K8S_HOST_USERS_TRUE",
			title: "Pod sets hostUsers: true (no user namespace isolation)",
			severity: "HIGH",
			files: hostUsersFiles,
			requiredActions: [
				"hostUsers: true disables the user namespace, so container UID 0 maps directly to host root — a container escape yields immediate host root.",
				"Set hostUsers: false to enable user-namespace remapping (UserNamespacesSupport)."
			]
		});
	}

	const seccompUnconfinedFiles = matching(ctx, /seccompProfile:[\s\S]{0,40}Unconfined|type:\s*Unconfined/);
	if (seccompUnconfinedFiles.length > 0) {
		findings.push({
			id: "K8S_SECCOMP_UNCONFINED",
			title: "seccompProfile set to Unconfined",
			severity: "HIGH",
			files: seccompUnconfinedFiles,
			requiredActions: [
				"seccompProfile: Unconfined removes syscall filtering, exposing the full kernel attack surface (keyctl, unshare, etc.) used in container-escape exploits.",
				"Set seccompProfile.type: RuntimeDefault (or a tighter Localhost profile) on every pod/container."
			]
		});
	}

	const apparmorUnconfinedFiles = matching(ctx, /appArmorProfile:[\s\S]{0,40}Unconfined|apparmor[^\n]*unconfined/);
	if (apparmorUnconfinedFiles.length > 0) {
		findings.push({
			id: "K8S_APPARMOR_UNCONFINED",
			title: "AppArmor profile set to unconfined",
			severity: "HIGH",
			files: apparmorUnconfinedFiles,
			requiredActions: [
				"An unconfined AppArmor profile removes mandatory access control on file and capability use inside the container.",
				"Set appArmorProfile.type: RuntimeDefault or a Localhost profile, and remove any container.apparmor.security.beta.kubernetes.io/*: unconfined annotation."
			]
		});
	}

	const dangerousCapsFiles = matching(ctx, /SYS_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|\bBPF\b|\bNET_RAW\b/);
	if (dangerousCapsFiles.length > 0) {
		findings.push({
			id: "K8S_DANGEROUS_CAPABILITY_ADDED",
			title: "Dangerous Linux capability added (SYS_ADMIN/SYS_PTRACE/SYS_MODULE/DAC_READ_SEARCH/BPF/NET_RAW)",
			severity: "CRITICAL",
			files: dangerousCapsFiles,
			requiredActions: [
				"SYS_ADMIN ≈ root; SYS_PTRACE allows debugging host processes; SYS_MODULE loads kernel modules; DAC_READ_SEARCH bypasses file permissions (CVE-2014-9357 style); BPF and NET_RAW enable kernel/network attacks.",
				"Remove these from capabilities.add. Drop ALL capabilities and re-add only the minimal non-dangerous ones the workload needs."
			]
		});
	}

	const automountFiles = matching(ctx, /automountServiceAccountToken:\s*true/);
	if (automountFiles.length > 0) {
		findings.push({
			id: "K8S_SA_TOKEN_AUTOMOUNT_TRUE",
			title: "automountServiceAccountToken: true explicitly set",
			severity: "MEDIUM",
			files: automountFiles,
			requiredActions: [
				"Auto-mounting the SA token into every pod hands an attacker who compromises the container a credential to call the Kubernetes API.",
				"Set automountServiceAccountToken: false at the pod and ServiceAccount level unless the workload genuinely calls the API; then mount a scoped projected token."
			]
		});
	}

	const ephemeralFiles = matching(ctx, /ephemeralContainers:/);
	if (ephemeralFiles.length > 0) {
		findings.push({
			id: "K8S_EPHEMERAL_CONTAINERS",
			title: "ephemeralContainers declared in manifest",
			severity: "MEDIUM",
			files: ephemeralFiles,
			requiredActions: [
				"Ephemeral/debug containers can attach to a running pod's namespaces and read its process memory and mounted secrets, bypassing the original container's securityContext.",
				"Remove ephemeralContainers from committed manifests; gate kubectl debug behind RBAC and audit logging."
			]
		});
	}

	const hostAliasesFiles = matching(ctx, /hostAliases:/);
	if (hostAliasesFiles.length > 0) {
		findings.push({
			id: "K8S_HOST_ALIASES_SPOOF",
			title: "hostAliases entries injected into /etc/hosts",
			severity: "LOW",
			files: hostAliasesFiles,
			requiredActions: [
				"hostAliases override /etc/hosts and can spoof internal service names to redirect traffic to an attacker-controlled IP.",
				"Remove hostAliases and rely on cluster DNS; if static mapping is required, validate the IPs against an allowlist."
			]
		});
	}

	const sysctlFiles = matching(ctx, /sysctls:|securityContext\.sysctls/);
	if (sysctlFiles.length > 0) {
		findings.push({
			id: "K8S_UNSAFE_SYSCTLS",
			title: "Pod sets sysctls (potentially unsafe kernel tunables)",
			severity: "MEDIUM",
			files: sysctlFiles,
			requiredActions: [
				"Unsafe sysctls (e.g. kernel.* , net.* namespaced tunables) can weaken host kernel protections or be used to disrupt the node.",
				"Remove sysctls unless required; allow only specific safe sysctls via the kubelet --allowed-unsafe-sysctls allowlist."
			]
		});
	}

	const saPathMountFiles = matching(ctx, /\/var\/run\/secrets\/kubernetes\.io|\/var\/run\/secrets\/serviceaccount/);
	if (saPathMountFiles.length > 0) {
		findings.push({
			id: "K8S_SA_PATH_MOUNT",
			title: "ServiceAccount token path explicitly mounted as a volume",
			severity: "HIGH",
			files: saPathMountFiles,
			requiredActions: [
				"Mounting /var/run/secrets/kubernetes.io into an untrusted container hands it the API credential even when automount is disabled.",
				"Remove explicit hostPath/volume mounts of the SA token path; let the kubelet project a scoped token only where needed."
			]
		});
	}

	const hostPortFiles = matching(ctx, /hostPort:\s*\d+/);
	if (hostPortFiles.length > 0) {
		findings.push({
			id: "K8S_HOST_PORT_BINDING",
			title: "Container binds a hostPort",
			severity: "MEDIUM",
			files: hostPortFiles,
			requiredActions: [
				"hostPort binds the container's port directly on the node's network interface, bypassing Services/NetworkPolicies and exposing it on the node IP.",
				"Remove hostPort and expose the workload through a Service/Ingress instead."
			]
		});
	}

	const projectedTokenFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /serviceAccountToken:/.test(c) && !/audience:/.test(c);
		})
		.slice(0, 10);
	if (projectedTokenFiles.length > 0) {
		findings.push({
			id: "K8S_PROJECTED_TOKEN_NO_AUDIENCE",
			title: "Projected ServiceAccount token without an audience / expirationSeconds",
			severity: "MEDIUM",
			files: projectedTokenFiles,
			requiredActions: [
				"A projected SA token with no audience is valid against the API server and can be replayed broadly; no expirationSeconds means it is long-lived.",
				"Set a specific audience and a short expirationSeconds (e.g. 3600) on every projected serviceAccountToken volume."
			]
		});
	}

	return findings;
}

/**
 * Supply-chain & image integrity — digest pinning, pull policy cache poisoning,
 * inline pull secrets, runAsNonRoot, PodDisruptionBudget.
 */
function checkSupplyChainIntegrity(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];

	// image: ... with a tag but no @sha256 digest
	const noDigestFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /image:\s*["']?[\w./-]+:[\w.-]+/.test(c) && !/@sha256:/.test(c);
		})
		.slice(0, 10);
	if (noDigestFiles.length > 0) {
		findings.push({
			id: "K8S_IMAGE_NO_DIGEST_PIN",
			title: "Container image referenced by tag without a sha256 digest pin",
			severity: "MEDIUM",
			files: noDigestFiles,
			requiredActions: [
				"A mutable tag can be repointed to a malicious image after review (supply-chain attack); only a @sha256 digest is immutable.",
				"Pin every image to image@sha256:<digest> and verify signatures with Cosign / sigstore policy-controller."
			]
		});
	}

	const pullPolicyFiles = matching(ctx, /imagePullPolicy:\s*(?:Never|IfNotPresent)/);
	if (pullPolicyFiles.length > 0) {
		findings.push({
			id: "K8S_IMAGE_PULL_POLICY_CACHE",
			title: "imagePullPolicy Never/IfNotPresent enables node image-cache poisoning",
			severity: "LOW",
			files: pullPolicyFiles,
			requiredActions: [
				"With Never/IfNotPresent a pod can run a same-tagged image already cached on the node by another tenant, bypassing registry auth and admission scanning.",
				"Use imagePullPolicy: Always together with digest-pinned images so the node fetches and verifies the intended image."
			]
		});
	}

	const inlineDockercfgFiles = matching(ctx, /\.dockerconfigjson|dockercfg/);
	if (inlineDockercfgFiles.length > 0) {
		findings.push({
			id: "K8S_INLINE_DOCKERCONFIG",
			title: "Inline dockerconfigjson / dockercfg registry credentials in manifest",
			severity: "HIGH",
			files: inlineDockercfgFiles,
			requiredActions: [
				"Embedding .dockerconfigjson in a committed manifest leaks registry credentials that can be base64-decoded from git history.",
				"Store registry creds in a sealed/external Secret (e.g. External Secrets Operator) and reference via imagePullSecrets, never inline in version control."
			]
		});
	}

	const noRunAsNonRootFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /containers:/.test(c) && !/runAsNonRoot:\s*true/.test(c);
		})
		.slice(0, 10);
	if (noRunAsNonRootFiles.length > 0) {
		findings.push({
			id: "K8S_MISSING_RUN_AS_NONROOT",
			title: "Container does not set runAsNonRoot: true",
			severity: "MEDIUM",
			files: noRunAsNonRootFiles,
			requiredActions: [
				"Without runAsNonRoot: true the kubelet will happily start an image whose default user is root, maximizing escape blast radius.",
				"Set securityContext.runAsNonRoot: true and a non-zero runAsUser on every container."
			]
		});
	}

	const hasPdb = ctx.files.some((f) => /kind:\s*PodDisruptionBudget/.test(ctx.contents.get(f) ?? ""));
	const hasWorkload = ctx.files.some((f) =>
		/kind:\s*(?:Deployment|StatefulSet|ReplicaSet)/.test(ctx.contents.get(f) ?? "")
	);
	if (hasWorkload && !hasPdb) {
		findings.push({
			id: "K8S_NO_POD_DISRUPTION_BUDGET",
			title: "Workloads present but no PodDisruptionBudget defined",
			severity: "LOW",
			requiredActions: [
				"Without a PodDisruptionBudget, a node drain or voluntary disruption can take all replicas down at once (availability/DoS risk).",
				"Add a PodDisruptionBudget with minAvailable (or maxUnavailable) for each critical workload."
			]
		});
	}

	return findings;
}

/**
 * Network & exposure depth — LoadBalancer source ranges, Ingress TLS, externalIPs,
 * hostNetwork+privileged combo, allow-all egress NetworkPolicy, dnsPolicy.
 */
function checkNetworkExposureDepth(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];

	const lbOpenFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /type:\s*LoadBalancer/.test(c) && (!/loadBalancerSourceRanges:/.test(c) || /0\.0\.0\.0\/0/.test(c));
		})
		.slice(0, 10);
	if (lbOpenFiles.length > 0) {
		findings.push({
			id: "K8S_LB_OPEN_SOURCE_RANGES",
			title: "LoadBalancer Service with no loadBalancerSourceRanges or 0.0.0.0/0",
			severity: "HIGH",
			files: lbOpenFiles,
			requiredActions: [
				"A LoadBalancer without source-range restriction is reachable from the entire internet, bypassing any WAF.",
				"Set loadBalancerSourceRanges to the specific trusted CIDRs, or front the service with an Ingress/API gateway and a WAF."
			]
		});
	}

	const ingressNoTlsFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /kind:\s*Ingress/.test(c) && !/tls:/.test(c);
		})
		.slice(0, 10);
	if (ingressNoTlsFiles.length > 0) {
		findings.push({
			id: "K8S_INGRESS_NO_TLS",
			title: "Ingress without a tls: block",
			severity: "HIGH",
			files: ingressNoTlsFiles,
			requiredActions: [
				"An Ingress with no tls block serves traffic over plaintext HTTP, exposing credentials and sessions to interception.",
				"Add a tls: section with a valid certificate (cert-manager) and enforce HTTPS redirects."
			]
		});
	}

	const externalIpFiles = matching(ctx, /externalIPs:/);
	if (externalIpFiles.length > 0) {
		findings.push({
			id: "K8S_SERVICE_EXTERNAL_IPS",
			title: "Service sets externalIPs",
			severity: "MEDIUM",
			files: externalIpFiles,
			requiredActions: [
				"externalIPs route arbitrary node-destined traffic to the service and have historically enabled traffic-hijack / MITM between tenants.",
				"Remove externalIPs; expose services via LoadBalancer or Ingress with explicit source restrictions."
			]
		});
	}

	const hostNetPrivFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /hostNetwork:\s*true/.test(c) && /privileged:\s*true/.test(c);
		})
		.slice(0, 10);
	if (hostNetPrivFiles.length > 0) {
		findings.push({
			id: "K8S_HOSTNETWORK_PRIVILEGED_COMBO",
			title: "Pod combines hostNetwork: true with privileged: true",
			severity: "CRITICAL",
			files: hostNetPrivFiles,
			requiredActions: [
				"hostNetwork + privileged gives the container the node's network stack and full device access — it can sniff all node traffic and trivially escape to host root.",
				"Remove both settings; if host networking is unavoidable, drop privileged and all unnecessary capabilities."
			]
		});
	}

	const allowAllEgressFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /kind:\s*NetworkPolicy/.test(c) && /podSelector:\s*\{\s*\}/.test(c) && /egress:/.test(c);
		})
		.slice(0, 10);
	if (allowAllEgressFiles.length > 0) {
		findings.push({
			id: "K8S_NETPOL_ALLOW_ALL_EGRESS",
			title: "NetworkPolicy with empty podSelector allows all egress",
			severity: "MEDIUM",
			files: allowAllEgressFiles,
			requiredActions: [
				"An empty podSelector ({}) selecting all pods combined with an open egress rule lets any compromised pod exfiltrate data anywhere on the internet.",
				"Scope the podSelector and restrict egress to the specific destinations (CIDRs/namespaces/ports) each workload needs."
			]
		});
	}

	const dnsDefaultFiles = matching(ctx, /dnsPolicy:\s*Default/);
	if (dnsDefaultFiles.length > 0) {
		findings.push({
			id: "K8S_DNS_POLICY_DEFAULT",
			title: "Pod uses dnsPolicy: Default (node resolver)",
			severity: "LOW",
			files: dnsDefaultFiles,
			requiredActions: [
				"dnsPolicy: Default inherits the node's resolver, bypassing cluster DNS policy and any DNS-based egress controls.",
				"Use dnsPolicy: ClusterFirst so pods resolve through CoreDNS and are subject to cluster DNS controls."
			]
		});
	}

	return findings;
}

/**
 * Secrets & ServiceAccount config — plaintext stringData creds, literal secret env,
 * default token automounting on ServiceAccounts.
 */
function checkSecretsConfig(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];

	const stringDataCredFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /kind:\s*Secret/.test(c) && /stringData:/.test(c) && /password|token|apikey|api_key|secret/i.test(c);
		})
		.slice(0, 10);
	if (stringDataCredFiles.length > 0) {
		findings.push({
			id: "K8S_SECRET_PLAINTEXT_STRINGDATA",
			title: "Secret manifest contains plaintext credentials in stringData",
			severity: "HIGH",
			files: stringDataCredFiles,
			requiredActions: [
				"stringData stores the credential as plaintext in the committed manifest and git history — anyone with repo read access gets the secret.",
				"Remove plaintext secrets from manifests; use Sealed Secrets, External Secrets Operator, or SOPS-encrypted values referencing a KMS."
			]
		});
	}

	const literalEnvSecretFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /env:/.test(c) && /value:\s*["']?[^\n]*(?:password|secret|token|apikey)/i.test(c) && !/valueFrom:/.test(c);
		})
		.slice(0, 10);
	if (literalEnvSecretFiles.length > 0) {
		findings.push({
			id: "K8S_ENV_LITERAL_SECRET",
			title: "Literal secret value in container env (no valueFrom)",
			severity: "HIGH",
			files: literalEnvSecretFiles,
			requiredActions: [
				"A literal env value: containing a password/token is baked into the pod spec and is visible to anyone with get pod / describe access.",
				"Use valueFrom.secretKeyRef to reference a Secret, and prefer mounting secrets as files over env vars."
			]
		});
	}

	const saAutomountFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /kind:\s*ServiceAccount/.test(c) && !/automountServiceAccountToken:\s*false/.test(c);
		})
		.slice(0, 10);
	if (saAutomountFiles.length > 0) {
		findings.push({
			id: "K8S_SA_DEFAULT_AUTOMOUNT",
			title: "ServiceAccount does not disable automountServiceAccountToken",
			severity: "MEDIUM",
			files: saAutomountFiles,
			requiredActions: [
				"ServiceAccounts default to automounting their token into every pod, handing an attacker an API credential on container compromise.",
				"Set automountServiceAccountToken: false on the ServiceAccount and opt in per-pod only where API access is required."
			]
		});
	}

	return findings;
}

/**
 * Admission, API server, kubelet & etcd policy — PSA enforce level, deprecated PSP,
 * policy-engine presence, dangerous apiserver/kubelet flags, etcd TLS.
 */
function checkAdmissionAndComponents(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];

	const psaNotRestrictedFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /pod-security\.kubernetes\.io\/enforce:\s*(?:baseline|privileged)/.test(c);
		})
		.slice(0, 10);
	if (psaNotRestrictedFiles.length > 0) {
		findings.push({
			id: "K8S_PSA_NOT_RESTRICTED",
			title: "PodSecurityAdmission enforce level is baseline/privileged, not restricted",
			severity: "MEDIUM",
			files: psaNotRestrictedFiles,
			requiredActions: [
				"enforce: baseline still permits hostPath, running as root, and added capabilities; privileged permits everything.",
				"Set pod-security.kubernetes.io/enforce: restricted on application namespaces and warn/audit at restricted too."
			]
		});
	}

	const pspFiles = matching(ctx, /kind:\s*PodSecurityPolicy|policy\/v1beta1.*PodSecurityPolicy/);
	if (pspFiles.length > 0) {
		findings.push({
			id: "K8S_DEPRECATED_PSP",
			title: "Deprecated PodSecurityPolicy still referenced",
			severity: "MEDIUM",
			files: pspFiles,
			requiredActions: [
				"PodSecurityPolicy was removed in Kubernetes 1.25 — it is silently non-enforcing on modern clusters, leaving pods unconstrained.",
				"Migrate to PodSecurityAdmission (restricted) and/or a policy engine (Kyverno / Gatekeeper)."
			]
		});
	}

	// Heuristic LOW: no policy engine present anywhere in the manifests
	const hasPolicyEngine = ctx.files.some((f) => {
		const c = ctx.contents.get(f) ?? "";
		return /gatekeeper|ConstraintTemplate|kyverno|kind:\s*ClusterPolicy|kind:\s*Policy\b/i.test(c);
	});
	if (!hasPolicyEngine) {
		findings.push({
			id: "K8S_NO_POLICY_ENGINE",
			title: "No admission policy engine (OPA Gatekeeper / Kyverno) detected",
			severity: "LOW",
			requiredActions: [
				"Without a policy engine, security invariants (no privileged, image-signature required, etc.) are not enforced at admission time.",
				"Deploy Kyverno or OPA Gatekeeper and codify your pod-security and supply-chain policies as enforced constraints."
			]
		});
	}

	const apiserverFlagFiles = matching(ctx, /--authorization-mode=AlwaysAllow|--insecure-port=[1-9]|--insecure-bind-address/);
	if (apiserverFlagFiles.length > 0) {
		findings.push({
			id: "K8S_APISERVER_INSECURE_FLAGS",
			title: "kube-apiserver started with AlwaysAllow / insecure-port flags",
			severity: "CRITICAL",
			files: apiserverFlagFiles,
			requiredActions: [
				"--authorization-mode=AlwaysAllow disables RBAC; --insecure-port / --insecure-bind-address expose an unauthenticated API endpoint.",
				"Set --authorization-mode=Node,RBAC, remove all insecure-port flags, and require TLS client auth on the API server."
			]
		});
	}

	const kubeletFlagFiles = matching(ctx, /--read-only-port=(?!0)\d|readOnlyPort:\s*(?!0)\d|authorization-mode.*AlwaysAllow|authorization:[\s\S]{0,40}AlwaysAllow/);
	if (kubeletFlagFiles.length > 0) {
		findings.push({
			id: "K8S_KUBELET_INSECURE_CONFIG",
			title: "Kubelet read-only port enabled or authorization mode AlwaysAllow",
			severity: "HIGH",
			files: kubeletFlagFiles,
			requiredActions: [
				"The kubelet read-only port (10255) exposes pod and node data unauthenticated; authorization AlwaysAllow lets any caller hit the kubelet API.",
				"Set readOnlyPort: 0, authentication.anonymous.enabled: false, and authorization.mode: Webhook in the kubelet config."
			]
		});
	}

	const kubeletAnonFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /kind:\s*KubeletConfiguration/.test(c) && /anonymous:[\s\S]{0,40}enabled:\s*true|--anonymous-auth=true/.test(c);
		})
		.slice(0, 10);
	if (kubeletAnonFiles.length > 0) {
		findings.push({
			id: "K8S_KUBELET_ANON_AUTH",
			title: "Kubelet anonymous authentication enabled",
			severity: "CRITICAL",
			files: kubeletAnonFiles,
			requiredActions: [
				"Anonymous kubelet auth lets unauthenticated callers exec into pods and read node secrets on port 10250.",
				"Set authentication.anonymous.enabled: false and require X509/Webhook auth on the kubelet."
			]
		});
	}

	const etcdNoTlsFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /etcd/i.test(c) && (/--client-cert-auth=false/.test(c) || (/--listen-client-urls=http:/.test(c) && !/https:/.test(c)));
		})
		.slice(0, 10);
	if (etcdNoTlsFiles.length > 0) {
		findings.push({
			id: "K8S_ETCD_NO_TLS",
			title: "etcd configured without client-cert TLS",
			severity: "CRITICAL",
			files: etcdNoTlsFiles,
			requiredActions: [
				"etcd holds every Secret in the cluster in plaintext; a plaintext/unauthenticated etcd endpoint is total cluster compromise.",
				"Set --client-cert-auth=true, serve only https client URLs, and enable peer TLS (--peer-client-cert-auth=true)."
			]
		});
	}

	return findings;
}

/**
 * CRD / operator & miscellaneous — default-SA bindings, broad system:authenticated
 * group grants, privileged Helm hooks, critical priorityClass, missing runtimeClass,
 * Windows hostProcess.
 */
function checkCrdOperatorMisc(ctx: K8sContext): Finding[] {
	const findings: Finding[] = [];

	const defaultSaBindingFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /kind:\s*ClusterRoleBinding/.test(c) && /kind:\s*ServiceAccount[\s\S]{0,60}name:\s*default/.test(c);
		})
		.slice(0, 10);
	if (defaultSaBindingFiles.length > 0) {
		findings.push({
			id: "K8S_CRB_DEFAULT_SA",
			title: "ClusterRoleBinding grants a role to a 'default' ServiceAccount",
			severity: "HIGH",
			files: defaultSaBindingFiles,
			requiredActions: [
				"Binding cluster permissions to the default SA gives every pod in that namespace (which uses default unless overridden) those permissions.",
				"Bind to a dedicated, named ServiceAccount with least privilege and set the pod's serviceAccountName explicitly."
			]
		});
	}

	const systemAuthGroupFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /kind:\s*Group[\s\S]{0,40}system:authenticated|name:\s*system:authenticated/.test(c);
		})
		.slice(0, 10);
	if (systemAuthGroupFiles.length > 0) {
		findings.push({
			id: "K8S_BIND_SYSTEM_AUTHENTICATED",
			title: "RBAC binding to the system:authenticated group",
			severity: "HIGH",
			files: systemAuthGroupFiles,
			requiredActions: [
				"system:authenticated includes every authenticated identity in the cluster — binding any non-trivial role to it is effectively cluster-wide access.",
				"Replace the system:authenticated subject with specific users/groups/ServiceAccounts that require the role."
			]
		});
	}

	const helmHookPrivFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /helm\.sh\/hook/.test(c) && /privileged:\s*true/.test(c);
		})
		.slice(0, 10);
	if (helmHookPrivFiles.length > 0) {
		findings.push({
			id: "K8S_HELM_HOOK_PRIVILEGED",
			title: "Helm hook job runs as a privileged container",
			severity: "HIGH",
			files: helmHookPrivFiles,
			requiredActions: [
				"A privileged Helm pre/post-install hook runs with full host access during every release — a compromised chart gains node root.",
				"Drop privileged from hook jobs, run them as non-root with a minimal securityContext, and review third-party chart hooks."
			]
		});
	}

	const criticalPriorityFiles = matching(ctx, /priorityClassName:\s*system-(?:cluster|node)-critical/);
	if (criticalPriorityFiles.length > 0) {
		findings.push({
			id: "K8S_SYSTEM_CRITICAL_PRIORITY",
			title: "Untrusted workload uses system-cluster-critical / system-node-critical priorityClass",
			severity: "MEDIUM",
			files: criticalPriorityFiles,
			requiredActions: [
				"system-*-critical priority lets the pod preempt and evict legitimate workloads, enabling a DoS or guaranteeing scheduling for a malicious pod.",
				"Reserve system-*-critical for genuine control-plane components; use a normal/custom PriorityClass for application workloads."
			]
		});
	}

	const noRuntimeClassFiles = ctx.files
		.filter((f) => {
			const c = ctx.contents.get(f) ?? "";
			return /kind:\s*(?:Pod|Deployment)/.test(c) && /containers:/.test(c) && !/runtimeClassName:/.test(c);
		})
		.slice(0, 10);
	if (noRuntimeClassFiles.length > 0) {
		findings.push({
			id: "K8S_NO_RUNTIME_CLASS",
			title: "Workload does not set a hardened runtimeClassName (gVisor/Kata)",
			severity: "LOW",
			files: noRuntimeClassFiles,
			requiredActions: [
				"Without a sandboxed runtimeClass (gVisor/Kata), a kernel exploit in the container reaches the shared host kernel directly.",
				"For untrusted or multi-tenant workloads set runtimeClassName to a gVisor (runsc) or Kata Containers runtime."
			]
		});
	}

	const hostProcessFiles = matching(ctx, /hostProcess:\s*true/);
	if (hostProcessFiles.length > 0) {
		findings.push({
			id: "K8S_WINDOWS_HOSTPROCESS",
			title: "Windows hostProcess container (hostProcess: true)",
			severity: "CRITICAL",
			files: hostProcessFiles,
			requiredActions: [
				"A Windows hostProcess container runs directly on the host with the node's privileges — equivalent to privileged on Linux, full node compromise on escape.",
				"Remove hostProcess: true; run the workload as a normal Windows container, or isolate host-management pods on dedicated, restricted nodes."
			]
		});
	}

	return findings;
}

export async function checkKubernetes(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	try {
		const ctx = await loadK8sManifests();
		if (ctx.files.length === 0) return [];

		const networkFindings = await checkNetworkAndAdmission(ctx);

		return [
			...checkContainerSecurity(ctx),
			...checkRbacAndConfig(ctx),
			...checkDockerSocketMount(ctx),
			...checkTillerHelm(ctx),
			...checkMtlsPolicy(ctx),
			...networkFindings,
			...checkRbacEscalationDepth(ctx),
			...checkPodEscapeDepth(ctx),
			...checkSupplyChainIntegrity(ctx),
			...checkNetworkExposureDepth(ctx),
			...checkSecretsConfig(ctx),
			...checkAdmissionAndComponents(ctx),
			...checkCrdOperatorMisc(ctx)
		];
	} catch (err) {
		console.warn("[checkKubernetes] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
		return [];
	}
}
