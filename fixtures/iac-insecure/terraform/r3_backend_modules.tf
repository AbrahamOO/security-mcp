terraform {
  required_version = ">= 1.0"

  backend "http" {
    address = "http://state.internal/myproject"
  }
}

module "vpc" {
  source = "git::http://git.internal/org/tf-vpc.git"
}

module "legacy" {
  source = "http://modules.internal/legacy.zip"
}
