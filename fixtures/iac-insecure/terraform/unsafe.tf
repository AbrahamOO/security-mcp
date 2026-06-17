resource "aws_db_instance" "prod" {
  identifier          = "prod-db"
  skip_final_snapshot = true
}

resource "aws_s3_bucket" "data" {
  bucket        = "prod-data"
  force_destroy = true
}

provider "azurerm" {
  skip_provider_registration = true
}

resource "aws_cloudformation_stack" "x" {
  disable_rollback = true
}
