terraform {
  backend "s3" {
    bucket  = "my-shared-tfstate"
    key     = "prod/terraform.tfstate"
    region  = "us-east-1"
    encrypt = false
  }
}

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
}
