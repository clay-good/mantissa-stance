# GCP IAM Module for Mantissa Stance
#
# Creates service accounts and assigns read-only permissions for
# security posture collection.

# Service account for Stance operations
resource "google_service_account" "stance" {
  account_id   = "${var.name_prefix}-sa"
  display_name = "Mantissa Stance Service Account"
  description  = "Service account for Stance CSPM security scanning"
  project      = var.project_id
}

# Custom role for read-only security collection
resource "google_project_iam_custom_role" "stance_collector" {
  role_id     = replace("${var.name_prefix}_collector", "-", "_")
  title       = "Stance Security Collector"
  description = "Read-only permissions for Stance security posture collection"
  project     = var.project_id

  permissions = [
    # Compute Engine - read only
    "compute.instances.list",
    "compute.instances.get",
    "compute.firewalls.list",
    "compute.firewalls.get",
    "compute.networks.list",
    "compute.networks.get",
    "compute.subnetworks.list",
    "compute.subnetworks.get",
    "compute.disks.list",
    "compute.disks.get",

    # IAM - read only
    "iam.serviceAccounts.list",
    "iam.serviceAccounts.get",
    "iam.serviceAccountKeys.list",
    "iam.roles.list",
    "iam.roles.get",
    "resourcemanager.projects.getIamPolicy",

    # Cloud Storage - read only (for scanning buckets, not our data bucket)
    "storage.buckets.list",
    "storage.buckets.get",
    "storage.buckets.getIamPolicy",

    # Cloud SQL - read only
    "cloudsql.instances.list",
    "cloudsql.instances.get",

    # GKE - read only
    "container.clusters.list",
    "container.clusters.get",

    # Cloud KMS - read only
    "cloudkms.keyRings.list",
    "cloudkms.cryptoKeys.list",
    "cloudkms.cryptoKeys.getIamPolicy",

    # Security Command Center - read only
    "securitycenter.findings.list",
    "securitycenter.findings.get",
    "securitycenter.sources.list",

    # Resource Manager - read only
    "resourcemanager.projects.get",
    "resourcemanager.folders.get",
    "resourcemanager.organizations.get",

    # Logging - read only
    "logging.sinks.list",
    "logging.sinks.get",
  ]
}

# Bind custom role to service account
resource "google_project_iam_member" "stance_collector" {
  project = var.project_id
  role    = google_project_iam_custom_role.stance_collector.id
  member  = "serviceAccount:${google_service_account.stance.email}"
}

# Storage bucket permissions - write access to our data bucket only
resource "google_storage_bucket_iam_member" "stance_storage" {
  bucket = var.storage_bucket
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.stance.email}"
}

# BigQuery permissions - write access to our dataset only
resource "google_bigquery_dataset_iam_member" "stance_bigquery" {
  count = var.bigquery_dataset != null ? 1 : 0

  project    = var.project_id
  dataset_id = var.bigquery_dataset
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.stance.email}"
}

# Cloud Functions invoker (for scheduled triggers)
resource "google_project_iam_member" "stance_functions_invoker" {
  project = var.project_id
  role    = "roles/cloudfunctions.invoker"
  member  = "serviceAccount:${google_service_account.stance.email}"
}
