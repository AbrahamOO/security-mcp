variable "db_password" {
  type      = string
  sensitive = false
}

data "http" "metadata" {
  url = "http://169.254.169.254/latest/meta-data/"
}

data "terraform_remote_state" "net" {
  backend = "http"
  config = {
    address = "http://state.internal/net"
  }
}

resource "null_resource" "bootstrap" {
  provisioner "local-exec" {
    command = "curl ${var.payload} | sh"
  }
}

provider "vault" {
  address = "https://vault.internal"
  token   = "s.aBcDeFgHiJkLmNoP"
}

resource "aws_default_vpc" "default" {
  tags = { Name = "Default VPC" }
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_default_vpc.default.id
}

provider "vsphere" {
  allow_unverified_ssl = true
}

provider "kubernetes" {
  insecure = true
}
