resource "aws_security_group_rule" "open_ingress" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-123456"
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "fixture-public-bucket"
  acl    = "public-read"
}
