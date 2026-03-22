/**
 * Kubernetes manifest security checks.
 */
import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

export async function checkKubernetes(_opts: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		// 1. Glob YAML files and filter to K8s manifests
		const yamlFiles = await fg(["**/*.yaml", "**/*.yml"], {
			ignore: ["**/node_modules/**", "**/dist/**", "**/.git/**"]
		});

		const k8sFiles: string[] = [];
		const k8sContents = new Map<string, string>();

		for (const file of yamlFiles) {
			try {
				const content = await readFileSafe(file);
				if (/kind\s*:/.test(content)) {
					k8sFiles.push(file);
					k8sContents.set(file, content);
				}
			} catch {
				// skip unreadable files
			}
		}

		if (k8sFiles.length === 0) {
			return [];
		}

		// Helper to collect files matching a pattern
		function filesMatching(pattern: RegExp): string[] {
			return k8sFiles.filter((f) => pattern.test(k8sContents.get(f) ?? "")).slice(0, 10);
		}

		// 3. Privileged containers
		const privilegedFiles = filesMatching(/privileged:\s*true/);
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

		// 4. allowPrivilegeEscalation
		const escFiles = filesMatching(/allowPrivilegeEscalation:\s*true/);
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

		// 5. Host namespaces
		const hostNsFiles = filesMatching(/hostPID:\s*true|hostNetwork:\s*true|hostIPC:\s*true/);
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

		// 6. Missing securityContext
		const missingSecCtxFiles = k8sFiles.filter((f) => {
			const c = k8sContents.get(f) ?? "";
			return /containers:/.test(c) && !/securityContext:/.test(c);
		}).slice(0, 10);
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

		// 7. Secrets in ConfigMap
		const configMapFiles = k8sFiles.filter((f) => {
			const c = k8sContents.get(f) ?? "";
			return /kind:\s*ConfigMap/.test(c) && /password|secret|key|token/i.test(c);
		}).slice(0, 10);
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

		// 8. ClusterAdmin binding
		const clusterAdminFiles = k8sFiles.filter((f) => {
			const c = k8sContents.get(f) ?? "";
			return /kind:\s*ClusterRoleBinding/.test(c) && /cluster-admin/.test(c);
		}).slice(0, 10);
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

		// 9. No resource limits
		const noLimitsFiles = k8sFiles.filter((f) => {
			const c = k8sContents.get(f) ?? "";
			return /containers:/.test(c) && !/limits:/.test(c);
		}).slice(0, 10);
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

		// 10. Default namespace
		const defaultNsFiles = k8sFiles.filter((f) => {
			const c = k8sContents.get(f) ?? "";
			return /namespace:\s*default/.test(c) || (!/namespace:/.test(c) && /kind:\s*(?:Deployment|Service|Pod|StatefulSet)/.test(c));
		}).slice(0, 10);
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

		// 11. Latest image tag
		const latestTagFiles = filesMatching(/:latest\b/);
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

		// 12. No network policy
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
	} catch (err) {
		console.warn("[checkKubernetes] Internal error:", err instanceof Error ? err.message : String(err));
	}

	return findings;
}
