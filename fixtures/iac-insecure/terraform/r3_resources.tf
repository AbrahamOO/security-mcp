resource "aws_db_instance" "db" {
  engine                              = "postgres"
  storage_encrypted                   = false
  iam_database_authentication_enabled = false
}

resource "aws_kms_key" "data" {
  description         = "app data key"
  enable_key_rotation = false
}

resource "aws_iam_access_key" "svc" {
  user = aws_iam_user.svc.name
}

resource "aws_cloudtrail" "main" {
  name                       = "main"
  s3_bucket_name             = "trail-bucket"
  enable_log_file_validation = false
}

resource "aws_instance" "app" {
  ami           = "ami-123456"
  instance_type = "t3.micro"

  root_block_device {
    encrypted = false
  }

  ebs_block_device {
    device_name = "/dev/sdf"
    encrypted   = false
  }

  lifecycle {
    ignore_changes = all
  }
}

resource "aws_db_instance" "replica" {
  engine = "postgres"
  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_security_group" "app" {
  name = "app-sg"
  lifecycle {
    create_before_destroy = true
  }
}

variable "admin_password" {
  type    = string
  default = "ghp_aBcDeFgHiJkLmNoPqRsTuVwX"
}

variable "openai_key" {
  type    = string
  default = "sk-aBcDeFgHiJkLmNoPqRsT"
}
