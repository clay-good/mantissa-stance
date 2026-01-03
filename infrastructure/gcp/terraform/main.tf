# Mantissa Stance - GCP Infrastructure
#
# This Terraform configuration deploys the Stance CSPM infrastructure on
# Google Cloud Platform using Cloud Functions, Cloud Storage, and BigQuery.

terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Local values for common configuration
locals {
  # Common labels for all resources
  common_labels = {
    project     = "mantissa-stance"
    environment = var.environment
    managed_by  = "terraform"
  }

  # Resource naming prefix
  name_prefix = "stance-${var.environment}"
}

# Enable required APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "cloudfunctions.googleapis.com",
    "cloudscheduler.googleapis.com",
    "storage.googleapis.com",
    "bigquery.googleapis.com",
    "iam.googleapis.com",
    "compute.googleapis.com",
    "securitycenter.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# Storage module - Cloud Storage bucket and BigQuery dataset
module "storage" {
  source = "./modules/storage"

  project_id     = var.project_id
  region         = var.region
  name_prefix    = local.name_prefix
  labels         = local.common_labels
  retention_days = var.log_retention_days
  enable_bigquery = var.enable_bigquery

  depends_on = [google_project_service.apis]
}

# IAM module - Service accounts and permissions
module "iam" {
  source = "./modules/iam"

  project_id      = var.project_id
  name_prefix     = local.name_prefix
  storage_bucket  = module.storage.bucket_name
  bigquery_dataset = module.storage.bigquery_dataset_id

  depends_on = [google_project_service.apis]
}

# Compute module - Cloud Functions
module "compute" {
  source = "./modules/compute"

  project_id           = var.project_id
  region               = var.region
  name_prefix          = local.name_prefix
  labels               = local.common_labels
  storage_bucket       = module.storage.bucket_name
  service_account_email = module.iam.service_account_email
  log_retention_days   = var.log_retention_days

  # Scan configuration
  enable_scheduled_scans = var.enable_scheduled_scans
  scan_schedule          = var.scan_schedule

  depends_on = [
    google_project_service.apis,
    module.storage,
    module.iam,
  ]
}

# Catalog module - BigQuery tables and views
module "catalog" {
  source = "./modules/catalog"

  project_id               = var.project_id
  dataset_id               = module.storage.bigquery_dataset_id
  location                 = var.region
  deletion_protection      = var.environment == "prod"
  enable_scheduled_queries = var.enable_scheduled_queries
  service_account_email    = module.iam.service_account_email
  labels                   = local.common_labels

  depends_on = [
    google_project_service.apis,
    module.storage,
    module.iam,
  ]
}

# Monitoring module - Cloud Monitoring dashboard and alerts
module "monitoring" {
  source = "./modules/monitoring"

  project_id                  = var.project_id
  notification_email          = var.notification_email
  enable_alerts               = var.enable_alerts
  scan_failure_threshold      = var.scan_failure_threshold
  no_activity_threshold_hours = var.no_activity_threshold_hours
  labels                      = local.common_labels

  depends_on = [
    google_project_service.apis,
  ]
}
