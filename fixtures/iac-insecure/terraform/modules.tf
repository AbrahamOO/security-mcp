module "vpc" {
  source = "git::https://github.com/example/terraform-vpc.git?ref=main"
}

module "eks" {
  source = "github.com/example/terraform-eks?ref=master"
}

module "registry" {
  source = "terraform-aws-modules/rds/aws?ref=HEAD"
}

provider "google" {
  project = "demo"
}

provider "azurerm" {
  features {}
}
