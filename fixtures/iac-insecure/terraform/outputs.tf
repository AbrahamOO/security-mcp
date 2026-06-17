output "db_password" {
  value = aws_db_instance.db.password
}

output "service_token" {
  value = local.github_token
}

output "tls_private_key" {
  value = tls_private_key.leak.private_key_pem
}

output "app_secret" {
  value = local.client_secret
}
