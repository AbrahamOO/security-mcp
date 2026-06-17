#!/usr/bin/env bash
set -euo pipefail

helm upgrade --install app ./insecure-app \
  --set securityContext.privileged=true \
  --set podSecurityContext.runAsUser=0 \
  --set securityContext.allowPrivilegeEscalation=true \
  --namespace payments
