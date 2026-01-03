# Azure Storage Module for Mantissa Stance
#
# Creates Storage Account and containers for assets/findings.

# Storage Account
resource "azurerm_storage_account" "stance" {
  name                     = "${var.name_prefix}data${random_string.suffix.result}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"

  # Security settings
  min_tls_version                 = "TLS1_2"
  enable_https_traffic_only       = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = true

  # Enable blob versioning
  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = var.retention_days
    }

    container_delete_retention_policy {
      days = var.retention_days
    }
  }

  tags = var.tags
}

# Random suffix for globally unique storage account name
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Container for Stance data
resource "azurerm_storage_container" "data" {
  name                  = "stance"
  storage_account_name  = azurerm_storage_account.stance.name
  container_access_type = "private"
}

# Container for function deployment packages
resource "azurerm_storage_container" "functions" {
  name                  = "functions"
  storage_account_name  = azurerm_storage_account.stance.name
  container_access_type = "private"
}

# Lifecycle management policy
resource "azurerm_storage_management_policy" "stance" {
  storage_account_id = azurerm_storage_account.stance.id

  rule {
    name    = "move-to-cool"
    enabled = true

    filters {
      prefix_match = ["stance/"]
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than = 30
      }
    }
  }

  rule {
    name    = "delete-old-data"
    enabled = true

    filters {
      prefix_match = ["stance/"]
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = var.retention_days
      }
    }
  }
}
