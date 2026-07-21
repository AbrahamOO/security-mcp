import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "K8S_INGRESS_NGINX_SNIPPET_INJECTION",
    check: "emerging-cloud",
    positive: {
      file: "k8s/ingress.yaml",
      content: `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
    nginx.ingress.kubernetes.io/server-snippet: |
      proxy_set_header X-Forwarded-For $remote_addr;
      if ($request_uri ~* "wp-admin") { return 403; }
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web
                port:
                  number: 80
`
    },
    negative: {
      file: "k8s/ingress.yaml",
      content: `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web
                port:
                  number: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ingress-nginx-controller
spec:
  template:
    spec:
      containers:
        - name: controller
          image: registry.k8s.io/ingress-nginx/controller:v1.12.1
`
    },
    note: "Negative carries no configuration-snippet/server-snippet/stream-snippet/auth-snippet annotation (only rewrite-target/ssl-redirect), and pins the controller to v1.12.1 which isVulnerableIngressNginxTag reports as patched (1.12.x fixed at patch>=1) — so neither the snippet-annotation branch nor the vulnerable-image branch of the id fires."
  },
  {
    ruleId: "IAC_AWS_PASSROLE_PRIVESC_CHAIN",
    check: "emerging-cloud",
    positive: {
      file: "infra/iam/deploy-policy.json",
      content: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassAnyRoleAndLaunch",
      "Effect": "Allow",
      "Action": ["iam:PassRole", "ec2:RunInstances"],
      "Resource": "*"
    }
  ]
}
`
    },
    negative: {
      file: "infra/iam/deploy-policy.json",
      content: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassDeployRoleToEc2Only",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::111122223333:role/app-instance-role",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "ec2.amazonaws.com"
        }
      }
    }
  ]
}
`
    },
    note: "The check pushes IAC_AWS_PASSROLE_PRIVESC_CHAIN whenever iam:PassRole and any launch action (ec2:RunInstances/lambda:CreateFunction/ecs:RunTask/glue:CreateDevEndpoint/bedrock-agentcore:*CodeInterpreter) co-occur ANYWHERE in the file, regardless of conditions — condition-scoping only affects severity, not whether it fires. A genuine safe variant must therefore not grant a launch action in the same policy as PassRole at all: this negative scopes PassRole to one exact role ARN with an iam:PassedToService condition and grants no launch action, following requiredActions' 'never [grant the launch action] to the same principal that can pass arbitrary roles' — the launch permission lives in a separate CI/CD pipeline role's policy, not shown here."
  },
  {
    ruleId: "IAC_TF_MODULE_GIT_UNPINNED_REF",
    check: "emerging-cloud",
    positive: {
      file: "infra/main.tf",
      content: `module "vpc" {
  source = "git::https://github.com/org/tf-vpc.git?ref=main"
}
`
    },
    negative: {
      file: "infra/main.tf",
      content: `module "vpc" {
  source = "git::https://github.com/org/tf-vpc.git//modules/vpc?ref=4b825dc642cb6eb9a060e54bf8d69288fbee4904"
}
`
    },
    note: "Negative pins the git module to a full 40-char lowercase-hex commit SHA (the git empty-tree hash, used only as a realistic-looking pin), which PINNED_SHA_REF_RE matches — unlike a branch (?ref=main) or tag, this ref cannot be force-moved by the upstream repo owner."
  },
  {
    ruleId: "IAC_GCP_TOKEN_CREATOR_PROJECT_BINDING",
    check: "emerging-cloud",
    positive: {
      file: "infra/gcp/iam.tf",
      content: `resource "google_project_iam_member" "token_creator" {
  project = "my-project"
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "serviceAccount:ci-deployer@my-project.iam.gserviceaccount.com"
}
`
    },
    negative: {
      file: "infra/gcp/iam.tf",
      content: `resource "google_service_account_iam_member" "token_creator" {
  service_account_id = google_service_account.target.name
  role                = "roles/iam.serviceAccountTokenCreator"
  member              = "serviceAccount:ci-deployer@my-project.iam.gserviceaccount.com"
}
`
    },
    note: "Negative grants the identical role string but via google_service_account_iam_member (SA-scoped), the exact safe alternative shown in the rule's own requiredActions — GCP_PROJECT_IAM_BINDING_PATTERN only matches google_project_iam_member/_binding/_policy resource blocks, none of which appear here, so the project-scope co-occurrence condition never activates."
  },
  {
    ruleId: "K8S_RUNC_ESCAPE_DELIVERY_SURFACE",
    check: "emerging-cloud",
    positive: {
      file: "k8s/build-agent-pod.yaml",
      content: `apiVersion: v1
kind: Pod
metadata:
  name: build-agent
spec:
  containers:
    - name: agent
      image: myregistry/build-agent:latest
      securityContext:
        privileged: true
`
    },
    negative: {
      file: "k8s/build-agent-pod.yaml",
      content: `apiVersion: v1
kind: Pod
metadata:
  name: build-agent
spec:
  hostUsers: false
  containers:
    - name: agent
      image: myregistry/build-agent:latest
      securityContext:
        privileged: true
`
    },
    note: "Negative keeps privileged: true (the workload genuinely needs it) but adds hostUsers: false, the exact user-namespace remap requiredActions recommends — this sets hasUserNsRemap true, so the `(isPrivileged || hasHostPath) && !hasUserNsRemap` condition is false even though the workload is still privileged. Not a trivial deletion of the dangerous setting."
  }
];
