# Azure Compute Module for Mantissa Stance
#
# Creates Azure Functions for collection and evaluation.

# App Service Plan (Consumption)
resource "azurerm_service_plan" "stance" {
  name                = "${var.name_prefix}-plan"
  resource_group_name = var.resource_group_name
  location            = var.location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption plan

  tags = var.tags
}

# Storage account for function app
resource "azurerm_storage_account" "functions" {
  name                     = "${var.name_prefix}func${random_string.suffix.result}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  min_tls_version           = "TLS1_2"
  enable_https_traffic_only = true

  tags = var.tags
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Application Insights for monitoring
resource "azurerm_application_insights" "stance" {
  name                = "${var.name_prefix}-insights"
  resource_group_name = var.resource_group_name
  location            = var.location
  application_type    = "other"
  retention_in_days   = var.log_retention_days

  tags = var.tags
}

# Function App
resource "azurerm_linux_function_app" "stance" {
  name                = "${var.name_prefix}-functions"
  resource_group_name = var.resource_group_name
  location            = var.location

  storage_account_name       = azurerm_storage_account.functions.name
  storage_account_access_key = azurerm_storage_account.functions.primary_access_key
  service_plan_id            = azurerm_service_plan.stance.id

  # Managed identity
  identity {
    type         = "UserAssigned"
    identity_ids = [var.managed_identity_id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }

    application_insights_key               = azurerm_application_insights.stance.instrumentation_key
    application_insights_connection_string = azurerm_application_insights.stance.connection_string
  }

  app_settings = {
    # Storage configuration
    STORAGE_ACCOUNT_NAME = var.storage_account_name
    STORAGE_CONTAINER    = var.storage_container

    # Function configuration
    FUNCTIONS_WORKER_RUNTIME       = "python"
    AzureWebJobsFeatureFlags       = "EnableWorkerIndexing"
    SCM_DO_BUILD_DURING_DEPLOYMENT = "true"

    # Logging
    LOG_LEVEL = "INFO"

    # Managed identity client ID (passed from IAM module)
    AZURE_CLIENT_ID = var.managed_identity_client_id
  }

  tags = var.tags

  lifecycle {
    ignore_changes = [
      app_settings["WEBSITE_RUN_FROM_PACKAGE"],
    ]
  }
}
