# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "GOOGLE_CLOUD_PROJECT_ID" {}

provider "google" {
  // Credentials and configuration derived from the environment
  // Uncomment if you wish to configure the provider explicitly
  // credentials = "${file("account.json")}"
  // region      = "us-central1"
  // zone        = "us-central1-c

  project = var.GOOGLE_CLOUD_PROJECT_ID
}

resource "google_project_service" "vault_gcp_tests_resources" {
  service = "cloudresourcemanager.googleapis.com"

  disable_dependent_services = true
  disable_on_destroy         = false
}

resource "google_project_service" "vault_gcp_tests_iam" {
  service = "iam.googleapis.com"

  disable_dependent_services = true
  disable_on_destroy         = false
}

resource "google_service_account" "vault_gcp_tests" {
  account_id   = "vault-tester"
  display_name = "vault-tester"
}

resource "google_project_iam_binding" "vault_gcp_tests_viewer" {
  project = var.GOOGLE_CLOUD_PROJECT_ID
  role    = "roles/viewer"

  members = [
    "serviceAccount:${google_service_account.vault_gcp_tests.email}"
  ]
}

resource "google_project_iam_binding" "vault_gcp_tests_key_admin" {
  project = var.GOOGLE_CLOUD_PROJECT_ID
  role    = "roles/iam.serviceAccountKeyAdmin"

  members = [
    "serviceAccount:${google_service_account.vault_gcp_tests.email}"
  ]
}

resource "google_project_iam_binding" "vault_gcp_tests_token_creator" {
  project = var.GOOGLE_CLOUD_PROJECT_ID
  role    = "roles/iam.serviceAccountTokenCreator"

  members = [
    "serviceAccount:${google_service_account.vault_gcp_tests.email}"
  ]
}

resource "google_service_account_key" "vault_gcp_tests" {
  service_account_id = google_service_account.vault_gcp_tests.name
}

resource "local_file" "vault_gcp_tests" {
  content  = base64decode(google_service_account_key.vault_gcp_tests.private_key)
  filename = "${path.module}/vault-tester.json"
}

resource "local_file" "setup_environment_file" {
  filename = "local_environment_setup.sh"
  content  = <<EOF
export GOOGLE_TEST_CREDENTIALS=${path.cwd}/${local_file.vault_gcp_tests.filename} &&\
export GOOGLE_CLOUD_PROJECT_ID=${var.GOOGLE_CLOUD_PROJECT_ID}
EOF
}
