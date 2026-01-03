# Mantissa Stance - Azure Infrastructure
#
# This Terraform configuration deploys the Stance CSPM infrastructure on
# Microsoft Azure using Azure Functions, Blob Storage, and Azure Synapse.

terraform {
  required_version = ">= 1.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# Local values for common configuration
locals {
  # Common tags for all resources
  common_tags = {
    project     = "mantissa-stance"
    environment = var.environment
    managed_by  = "terraform"
  }

  # Resource naming prefix (Azure has stricter naming rules)
  name_prefix = "stance${var.environment}"

  # Location short names for resource naming
  location_short = {
    "eastus"         = "eus"
    "eastus2"        = "eus2"
    "westus"         = "wus"
    "westus2"        = "wus2"
    "centralus"      = "cus"
    "westeurope"     = "weu"
    "northeurope"    = "neu"
    "southeastasia"  = "sea"
  }
}

# Resource Group
resource "azurerm_resource_group" "stance" {
  name     = "rg-${local.name_prefix}-${lookup(local.location_short, var.location, var.location)}"
  location = var.location
  tags     = local.common_tags
}

# Storage module - Storage Account and containers
module "storage" {
  source = "./modules/storage"

  resource_group_name = azurerm_resource_group.stance.name
  location            = azurerm_resource_group.stance.location
  name_prefix         = local.name_prefix
  tags                = local.common_tags
  retention_days      = var.log_retention_days
  enable_synapse      = var.enable_synapse
}

# IAM module - Managed identities and role assignments
module "iam" {
  source = "./modules/iam"

  resource_group_name  = azurerm_resource_group.stance.name
  resource_group_id    = azurerm_resource_group.stance.id
  location             = azurerm_resource_group.stance.location
  name_prefix          = local.name_prefix
  subscription_id      = var.subscription_id
  storage_account_id   = module.storage.storage_account_id
  storage_account_name = module.storage.storage_account_name
  tags                 = local.common_tags
}

# Compute module - Azure Functions
module "compute" {
  source = "./modules/compute"

  resource_group_name        = azurerm_resource_group.stance.name
  location                   = azurerm_resource_group.stance.location
  name_prefix                = local.name_prefix
  tags                       = local.common_tags
  storage_account_name       = module.storage.storage_account_name
  storage_container          = module.storage.data_container_name
  managed_identity_id        = module.iam.managed_identity_id
  managed_identity_client_id = module.iam.managed_identity_client_id
  log_retention_days         = var.log_retention_days

  # Scan configuration
  enable_scheduled_scans = var.enable_scheduled_scans
  scan_schedule          = var.scan_schedule

  depends_on = [
    module.storage,
    module.iam,
  ]
}

# Catalog module - Synapse serverless SQL and external tables
module "catalog" {
  count  = var.enable_synapse ? 1 : 0
  source = "./modules/catalog"

  name_prefix          = local.name_prefix
  resource_group_name  = azurerm_resource_group.stance.name
  location             = azurerm_resource_group.stance.location
  storage_account_id   = module.storage.storage_account_id
  storage_account_name = module.storage.storage_account_name
  sql_admin_login      = var.synapse_sql_admin_login
  sql_admin_password   = var.synapse_sql_admin_password
  deploy_sql_objects   = var.deploy_synapse_sql_objects
  tags                 = local.common_tags

  depends_on = [
    module.storage,
  ]
}

# Monitoring module - Azure Monitor and Application Insights
module "monitoring" {
  source = "./modules/monitoring"

  name_prefix                 = local.name_prefix
  resource_group_name         = azurerm_resource_group.stance.name
  location                    = azurerm_resource_group.stance.location
  log_retention_days          = var.log_retention_days
  notification_email          = var.notification_email
  enable_alerts               = var.enable_alerts
  function_app_id             = module.compute.function_app_id
  no_activity_threshold_hours = var.no_activity_threshold_hours
  tags                        = local.common_tags

  depends_on = [
    module.compute,
  ]
}
