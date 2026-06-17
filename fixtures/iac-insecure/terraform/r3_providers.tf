provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "./creds/aws.txt"
  access_key              = "AKIAIOSFODNN7EXAMPLE"
  secret_key              = "wJalrXUtnFEMIabcdEFGHIK7MDENGbPxRfiCYEXA"
}

provider "google" {
  project     = "demo"
  credentials = file("./creds/gcp-sa.json")
}

provider "azurerm" {
  features {}
  client_secret = "AzureClientSecretValue1"
}

provider "helm" {
  kubernetes {
    insecure = true
  }
}

provider "consul" {
  skip_tls_verify = true
}
