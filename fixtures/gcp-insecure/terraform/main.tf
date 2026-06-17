resource "google_sql_database_instance" "db" {
  name             = "fixture-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
    }
  }
}

resource "google_storage_bucket" "data" {
  name     = "fixture-bucket"
  location = "US"
}

resource "google_container_cluster" "primary" {
  name     = "fixture-gke"
  location = "us-central1"
}
