import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "K8S_PRIVILEGED_CONTAINER",
    check: "kubernetes",
    positive: {
      file: "k8s/pod-privileged.yaml",
      content: `apiVersion: v1
kind: Pod
metadata:
  name: legacy-debug-pod
  namespace: default
spec:
  containers:
    - name: debug-tools
      image: debug-tools:1.4.0
      securityContext:
        privileged: true
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
`
    },
    negative: {
      file: "k8s/pod-privileged.yaml",
      content: `apiVersion: v1
kind: Pod
metadata:
  name: debug-pod
  namespace: default
spec:
  containers:
    - name: debug-tools
      image: debug-tools:1.4.0
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
`
    },
    note: "Negative explicitly sets privileged: false and drops all capabilities instead of just deleting the line, so the same debugging container still works with least privilege."
  },
  {
    ruleId: "K8S_HOST_NAMESPACE",
    check: "kubernetes",
    positive: {
      file: "k8s/monitoring-agent.yaml",
      content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: monitoring-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: monitoring-agent
  template:
    metadata:
      labels:
        app: monitoring-agent
    spec:
      hostPID: true
      hostNetwork: true
      containers:
        - name: agent
          image: monitoring-agent:2.1.0
`
    },
    negative: {
      file: "k8s/monitoring-agent.yaml",
      content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: monitoring-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: monitoring-agent
  template:
    metadata:
      labels:
        app: monitoring-agent
    spec:
      containers:
        - name: agent
          image: monitoring-agent:2.1.0
          securityContext:
            runAsNonRoot: true
            readOnlyRootFilesystem: true
`
    },
    note: "Negative reads host metrics through the kubelet/metrics-server API instead of sharing the host PID and network namespaces, so it needs neither hostPID nor hostNetwork."
  },
  {
    ruleId: "K8S_NO_READONLY_ROOT",
    check: "kubernetes",
    positive: {
      file: "k8s/api-server.yaml",
      content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-server
  template:
    metadata:
      labels:
        app: api-server
    spec:
      containers:
        - name: api
          image: api-server:3.2.0
          securityContext:
            runAsNonRoot: true
          resources:
            limits:
              cpu: "1"
              memory: "512Mi"
`
    },
    negative: {
      file: "k8s/api-server.yaml",
      content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-server
  template:
    metadata:
      labels:
        app: api-server
    spec:
      containers:
        - name: api
          image: api-server:3.2.0
          securityContext:
            runAsNonRoot: true
            readOnlyRootFilesystem: true
          volumeMounts:
            - name: tmp
              mountPath: /tmp
          resources:
            limits:
              cpu: "1"
              memory: "512Mi"
      volumes:
        - name: tmp
          emptyDir: {}
`
    },
    note: "Negative sets readOnlyRootFilesystem: true and mounts an explicit emptyDir at /tmp for the one path the app legitimately writes to, rather than leaving the whole root filesystem writable."
  },
  {
    ruleId: "K8S_CONTAINER_RUNS_AS_ROOT",
    check: "kubernetes",
    positive: {
      file: "k8s/legacy-worker.yaml",
      content: `apiVersion: v1
kind: Pod
metadata:
  name: legacy-worker
spec:
  containers:
    - name: worker
      image: legacy-worker:1.0.0
      securityContext:
        runAsUser: 0
`
    },
    negative: {
      file: "k8s/legacy-worker.yaml",
      content: `apiVersion: v1
kind: Pod
metadata:
  name: worker
spec:
  containers:
    - name: worker
      image: legacy-worker:1.0.0
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
`
    },
    note: "Negative pins a real non-zero UID/GID (1000) rather than merely removing the runAsUser field, which would leave the image's own default user (often root) in effect."
  },
  {
    ruleId: "K8S_CAPABILITIES_NOT_DROPPED",
    check: "kubernetes",
    positive: {
      file: "k8s/net-tool.yaml",
      content: `apiVersion: v1
kind: Pod
metadata:
  name: net-tool
spec:
  containers:
    - name: net-tool
      image: net-tool:1.0.0
      securityContext:
        capabilities:
          add: ["NET_ADMIN"]
`
    },
    negative: {
      file: "k8s/net-tool.yaml",
      content: `apiVersion: v1
kind: Pod
metadata:
  name: net-tool
spec:
  containers:
    - name: net-tool
      image: net-tool:1.0.0
      securityContext:
        capabilities:
          drop: ["ALL"]
          add: ["NET_BIND_SERVICE"]
`
    },
    note: "Negative drops ALL capabilities first and re-adds only the one narrow capability (NET_BIND_SERVICE) the container actually needs, instead of leaving the default capability set untouched."
  },
  {
    ruleId: "K8S_ALLOW_PRIV_ESC_NOT_FALSE",
    check: "kubernetes",
    positive: {
      file: "k8s/web-frontend.yaml",
      content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-frontend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web-frontend
  template:
    metadata:
      labels:
        app: web-frontend
    spec:
      containers:
        - name: web
          image: web-frontend:4.0.0
          securityContext:
            runAsNonRoot: true
`
    },
    negative: {
      file: "k8s/web-frontend.yaml",
      content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-frontend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web-frontend
  template:
    metadata:
      labels:
        app: web-frontend
    spec:
      containers:
        - name: web
          image: web-frontend:4.0.0
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
`
    },
    note: "Negative adds the explicit allowPrivilegeEscalation: false the rule requires, not merely a comment or unrelated hardening field."
  },
  {
    ruleId: "K8S_MISSING_RUN_AS_NONROOT",
    check: "kubernetes",
    positive: {
      file: "k8s/batch-processor.yaml",
      content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: batch-processor
spec:
  replicas: 1
  selector:
    matchLabels:
      app: batch-processor
  template:
    metadata:
      labels:
        app: batch-processor
    spec:
      containers:
        - name: processor
          image: batch-processor:1.5.0
          securityContext:
            allowPrivilegeEscalation: false
`
    },
    negative: {
      file: "k8s/batch-processor.yaml",
      content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: batch-processor
spec:
  replicas: 1
  selector:
    matchLabels:
      app: batch-processor
  template:
    metadata:
      labels:
        app: batch-processor
    spec:
      containers:
        - name: processor
          image: batch-processor:1.5.0
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 1000
`
    },
    note: "Negative adds runAsNonRoot: true plus a concrete non-zero runAsUser, the actual fix the rule asks for, on top of the privilege-escalation setting already present in the positive."
  },
  {
    ruleId: "K8S_HOSTPATH_MOUNT",
    check: "kubernetes",
    positive: {
      file: "k8s/log-collector.yaml",
      content: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: log-collector
spec:
  selector:
    matchLabels:
      app: log-collector
  template:
    metadata:
      labels:
        app: log-collector
    spec:
      containers:
        - name: collector
          image: log-collector:2.0.0
          volumeMounts:
            - name: varlog
              mountPath: /var/log
      volumes:
        - name: varlog
          hostPath:
            path: /var/log
`
    },
    negative: {
      file: "k8s/log-collector.yaml",
      content: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: log-collector
spec:
  selector:
    matchLabels:
      app: log-collector
  template:
    metadata:
      labels:
        app: log-collector
    spec:
      containers:
        - name: collector
          image: log-collector:2.0.0
          volumeMounts:
            - name: buffer
              mountPath: /var/log/buffer
      volumes:
        - name: buffer
          persistentVolumeClaim:
            claimName: log-collector-buffer
`
    },
    note: "Negative replaces the raw host filesystem mount with a PersistentVolumeClaim, so the node's real /var/log is never exposed to the container."
  },
  {
    ruleId: "K8S_CLUSTER_ADMIN_BINDING",
    check: "kubernetes",
    positive: {
      file: "k8s/ci-pipeline-binding.yaml",
      content: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-pipeline-binding
subjects:
  - kind: ServiceAccount
    name: ci-pipeline
    namespace: ci
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
`
    },
    negative: {
      file: "k8s/ci-pipeline-binding.yaml",
      content: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-pipeline-binding
subjects:
  - kind: ServiceAccount
    name: ci-pipeline
    namespace: ci
roleRef:
  kind: ClusterRole
  name: ci-deployer
  apiGroup: rbac.authorization.k8s.io
`
    },
    note: "Negative binds to a purpose-built ci-deployer ClusterRole scoped to deployment resources instead of cluster-admin: a different, named role, not a disguised admin grant."
  },
  {
    ruleId: "K8S_RBAC_WILDCARD",
    check: "kubernetes",
    positive: {
      file: "k8s/legacy-full-access.yaml",
      content: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: legacy-full-access
  namespace: payments
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`
    },
    negative: {
      file: "k8s/legacy-full-access.yaml",
      content: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payments-reader
  namespace: payments
rules:
  - apiGroups: [""]
    resources: ["pods", "services"]
    verbs: ["get", "list", "watch"]
`
    },
    note: "Negative enumerates the exact apiGroups, resources, and verbs the workload needs (read-only on pods/services) instead of any wildcard."
  },
  {
    ruleId: "K8S_RBAC_PODS_EXEC",
    check: "kubernetes",
    positive: {
      file: "k8s/debug-access.yaml",
      content: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: debug-access
  namespace: staging
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/exec"]
    verbs: ["get", "create"]
`
    },
    negative: {
      file: "k8s/debug-access.yaml",
      content: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: log-viewer
  namespace: staging
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list"]
`
    },
    note: "Negative grants pods/log (read-only log streaming) instead of pods/exec, so it can never open an interactive shell into a running container."
  },
  {
    ruleId: "K8S_RBAC_SUPERUSER_SUBJECT",
    check: "kubernetes",
    positive: {
      file: "k8s/legacy-master-binding.yaml",
      content: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: legacy-master-binding
subjects:
  - kind: Group
    name: system:masters
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
`
    },
    negative: {
      file: "k8s/legacy-master-binding.yaml",
      content: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: platform-admins-binding
subjects:
  - kind: Group
    name: platform-admins
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
`
    },
    note: "Negative binds a real, named IdP group (platform-admins) instead of the hardcoded superuser group system:masters."
  },
  {
    ruleId: "K8S_SECRET_IN_CONFIGMAP",
    check: "kubernetes",
    positive: {
      file: "k8s/app-config.yaml",
      content: `apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  DB_HOST: "db.internal"
  DB_PASSWORD: "SuperSecret123"
`
    },
    negative: {
      file: "k8s/app-config.yaml",
      content: `apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  DB_HOST: "db.internal"
  LOG_LEVEL: "info"
  MAX_CONNECTIONS: "50"
  FEATURE_FLAGS: "beta-checkout=false"
`
    },
    note: "Negative only carries non-sensitive tuning values; the credential itself was moved out to a real Secret and is referenced via secretKeyRef, not just renamed to dodge the keyword scan."
  },
  {
    ruleId: "K8S_SECRET_PLAINTEXT_STRINGDATA",
    check: "kubernetes",
    positive: {
      file: "k8s/db-credentials.yaml",
      content: `apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: default
type: Opaque
stringData:
  password: "hunter2"
  username: "app_user"
`
    },
    negative: {
      file: "k8s/db-credentials.yaml",
      content: `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-credentials
  namespace: default
spec:
  encryptedData:
    password: AgBy8hCiXwR3n0k9f2m1QwErTyUiOpAsDfGhJkLzXcVbNm==
    username: AgCkT2mZq9wErTyOpLkJhGfDsAqWsXeDrCfVgBhNjMkOl==
  template:
    metadata:
      name: db-credentials
      namespace: default
    type: Opaque
`
    },
    note: "Negative is a bitnami-controller SealedSecret whose values are asymmetrically encrypted ciphertext (encryptedData), safe to commit to git: a genuinely different, non-reversible representation, not plaintext relabeled."
  },
  {
    ruleId: "K8S_NO_NETWORK_POLICY",
    check: "kubernetes",
    positive: {
      file: "k8s/checkout-service.yaml",
      content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: checkout-service
  namespace: shop
spec:
  replicas: 3
  selector:
    matchLabels:
      app: checkout-service
  template:
    metadata:
      labels:
        app: checkout-service
    spec:
      containers:
        - name: checkout
          image: checkout-service:5.0.0
`
    },
    negative: {
      file: "k8s/checkout-service.yaml",
      content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: checkout-service
  namespace: shop
spec:
  replicas: 3
  selector:
    matchLabels:
      app: checkout-service
  template:
    metadata:
      labels:
        app: checkout-service
    spec:
      containers:
        - name: checkout
          image: checkout-service:5.0.0
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: checkout-service-policy
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: checkout-service
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              network-tier: frontend
      ports:
        - port: 8080
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              network-tier: database
      ports:
        - port: 5432
`
    },
    note: "Negative ships the Deployment together with a scoped NetworkPolicy restricting both ingress and egress to named peers, in the same manifest, not just a NetworkPolicy dropped in unrelated to this workload."
  },
  {
    ruleId: "K8S_NETPOL_ALLOW_ALL_EGRESS",
    check: "kubernetes",
    positive: {
      file: "k8s/allow-all-egress.yaml",
      content: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-egress
  namespace: shop
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - {}
`
    },
    negative: {
      file: "k8s/allow-all-egress.yaml",
      content: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: checkout-egress
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: checkout-service
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              network-tier: database
      ports:
        - protocol: TCP
          port: 5432
`
    },
    note: "Negative scopes podSelector to the one workload it governs (not an empty selector matching every pod) and restricts egress to a specific namespace and port instead of an open {} rule."
  },
  {
    ruleId: "K8S_NODEPORT_EXPOSURE",
    check: "kubernetes",
    positive: {
      file: "k8s/admin-dashboard-svc.yaml",
      content: `apiVersion: v1
kind: Service
metadata:
  name: admin-dashboard
  namespace: internal-tools
spec:
  type: NodePort
  selector:
    app: admin-dashboard
  ports:
    - port: 8080
      targetPort: 8080
      nodePort: 30080
`
    },
    negative: {
      file: "k8s/admin-dashboard-svc.yaml",
      content: `apiVersion: v1
kind: Service
metadata:
  name: admin-dashboard
  namespace: internal-tools
spec:
  type: ClusterIP
  selector:
    app: admin-dashboard
  ports:
    - port: 8080
      targetPort: 8080
`
    },
    note: "Negative uses ClusterIP and relies on an Ingress/gateway in front for any external access, instead of exposing the raw port on every node's IP."
  },
  {
    ruleId: "K8S_INGRESS_NO_TLS",
    check: "kubernetes",
    positive: {
      file: "k8s/shop-ingress.yaml",
      content: `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shop-ingress
  namespace: shop
spec:
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: checkout-service
                port:
                  number: 8080
`
    },
    negative: {
      file: "k8s/shop-ingress.yaml",
      content: `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shop-ingress
  namespace: shop
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - shop.example.com
      secretName: shop-tls-cert
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: checkout-service
                port:
                  number: 8080
`
    },
    note: "Negative adds a real tls block with a cert-manager-issued secretName, not just an annotation implying TLS is handled elsewhere."
  },
  {
    ruleId: "K8S_NO_PSA_LABEL",
    check: "kubernetes",
    positive: {
      file: "k8s/payments-namespace.yaml",
      content: `apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    team: payments
`
    },
    negative: {
      file: "k8s/payments-namespace.yaml",
      content: `apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    team: payments
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
`
    },
    note: "Negative sets the actual PodSecurityAdmission enforce (plus audit/warn) labels at the restricted level, which is what makes admission actually reject unsafe pods in this namespace."
  },
  {
    ruleId: "K8S_API_ANONYMOUS_AUTH",
    check: "kubernetes",
    positive: {
      file: "k8s/kube-apiserver.yaml",
      content: `apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      image: k8s.gcr.io/kube-apiserver:v1.28.0
      command:
        - kube-apiserver
        - --anonymous-auth=true
        - --authorization-mode=Node,RBAC
`
    },
    negative: {
      file: "k8s/kube-apiserver.yaml",
      content: `apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      image: k8s.gcr.io/kube-apiserver:v1.28.0
      command:
        - kube-apiserver
        - --anonymous-auth=false
        - --authorization-mode=Node,RBAC
`
    },
    note: "Negative flips the same static-pod flag to --anonymous-auth=false, the exact remediation the rule requires, rather than deleting the flag, which would leave the effective value ambiguous."
  }
];
