/**
 * Kubernetes manifest security checks.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import fg from "fast-glob";
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

	return findings;
}

async function checkNetworkAndAdmission(ctx: K8sContext): Promise<Finding[]> {
	const findings: Finding[] = [];

	const networkPolicyFiles = await fg(
		["**/NetworkPolicy*.yaml", "**/*network-policy*.yaml", "**/NetworkPolicy*.yml", "**/*network-policy*.yml"],
		{ ignore: ["**/node_modules/**", "**/dist/**", "**/.git/**"] }
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

export async function checkKubernetes(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	try {
		const ctx = await loadK8sManifests();
		if (ctx.files.length === 0) return [];

		const networkFindings = await checkNetworkAndAdmission(ctx);

		return [
			...checkContainerSecurity(ctx),
			...checkRbacAndConfig(ctx),
			...networkFindings
		];
	} catch (err) {
		console.warn("[checkKubernetes] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
		return [];
	}
}
