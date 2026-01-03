# Azure IAM Module for Mantissa Stance
#
# Creates managed identity and assigns read-only permissions for
# security posture collection.

# User-assigned Managed Identity for Stance
resource "azurerm_user_assigned_identity" "stance" {
  name                = "${var.name_prefix}-identity"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

# Custom role for read-only security collection
resource "azurerm_role_definition" "stance_collector" {
  name        = "${var.name_prefix}-collector"
  scope       = "/subscriptions/${var.subscription_id}"
  description = "Read-only permissions for Stance security posture collection"

  permissions {
    actions = [
      # Compute - read only
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Compute/disks/read",
      "Microsoft.Compute/virtualMachineScaleSets/read",

      # Network - read only
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Network/virtualNetworks/read",
      "Microsoft.Network/networkInterfaces/read",
      "Microsoft.Network/publicIPAddresses/read",
      "Microsoft.Network/loadBalancers/read",
      "Microsoft.Network/applicationGateways/read",

      # Storage - read only
      "Microsoft.Storage/storageAccounts/read",
      "Microsoft.Storage/storageAccounts/blobServices/read",
      "Microsoft.Storage/storageAccounts/listkeys/action",

      # Identity - read only
      "Microsoft.Authorization/roleAssignments/read",
      "Microsoft.Authorization/roleDefinitions/read",
      "Microsoft.ManagedIdentity/userAssignedIdentities/read",

      # Key Vault - read only
      "Microsoft.KeyVault/vaults/read",
      "Microsoft.KeyVault/vaults/keys/read",
      "Microsoft.KeyVault/vaults/secrets/read",

      # SQL - read only
      "Microsoft.Sql/servers/read",
      "Microsoft.Sql/servers/databases/read",
      "Microsoft.Sql/servers/firewallRules/read",

      # Security Center - read only
      "Microsoft.Security/securityStatuses/read",
      "Microsoft.Security/alerts/read",
      "Microsoft.Security/assessments/read",
      "Microsoft.Security/complianceResults/read",

      # Resource Manager - read only
      "Microsoft.Resources/subscriptions/read",
      "Microsoft.Resources/subscriptions/resourceGroups/read",

      # Activity Log - read only
      "Microsoft.Insights/ActivityLogAlerts/read",
      "Microsoft.Insights/DiagnosticSettings/read",
    ]

    not_actions = []
  }

  assignable_scopes = [
    "/subscriptions/${var.subscription_id}"
  ]
}

# Assign custom role to managed identity at subscription level
resource "azurerm_role_assignment" "stance_collector" {
  scope              = "/subscriptions/${var.subscription_id}"
  role_definition_id = azurerm_role_definition.stance_collector.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.stance.principal_id
}

# Storage Blob Data Contributor on Stance storage account
resource "azurerm_role_assignment" "stance_storage" {
  scope                = var.storage_account_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.stance.principal_id
}

# Reader role on resource group
resource "azurerm_role_assignment" "stance_reader" {
  scope                = var.resource_group_id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.stance.principal_id
}
