provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMIabcdEFGHIK7MDENGbPxRfiCYEXA"
}

resource "aws_db_instance" "db" {
  username = "admin"
  password = "Sup3rS3cretDbPass"
}

resource "tls_private_key" "leak" {
  private_key_pem = "-----BEGIN RSA PRIVATE KEY-----"
}

locals {
  github_token  = "ghp_aBcDeFgHiJkLmNoPqRsT"
  api_key       = "key_abc123def456ghi789"
  client_secret = "csZ9aB7cD2eF1gH3"
}
