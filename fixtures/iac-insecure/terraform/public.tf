resource "aws_s3_bucket_acl" "public" {
  bucket = "assets"
  acl    = "public-read"
}

resource "aws_s3_bucket_acl" "wideopen" {
  bucket = "uploads"
  acl    = "public-read-write"
}

resource "aws_db_instance" "exposed" {
  identifier          = "exposed-db"
  publicly_accessible = true
}
