resource "aws_instance" "api" {
  ami           = "ami-123456"
  instance_type = "t3.micro"
}

resource "aws_db_instance" "primary" {
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = true
  skip_final_snapshot = true
}

resource "aws_s3_bucket" "assets" {
  bucket = "fixture-assets-bucket"
  acl    = "public-read"
}

resource "aws_kms_key" "data" {
  description = "fixture key without rotation"
}

resource "aws_lambda_function_url" "public" {
  function_name      = "fixture-fn"
  authorization_type = "NONE"
}
