#!/usr/bin/env bash
set -euo pipefail

# Insecure CI wrapper: applies infrastructure with no plan review.
terraform init
terraform apply -auto-approve
terraform destroy -target=aws_instance.app -auto-approve
