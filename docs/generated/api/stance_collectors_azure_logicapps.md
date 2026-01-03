# stance.collectors.azure_logicapps

Azure Logic Apps collector for Mantissa Stance.

Collects Azure Logic Apps (Workflows) and their security configurations
for security posture assessment.

## Contents

### Classes

- [AzureLogicAppsCollector](#azurelogicappscollector)

## AzureLogicAppsCollector

**Inherits from:** BaseCollector

Collects Azure Logic Apps (Workflows) resources and configuration.

Gathers Logic Apps with their security settings including:
- Workflow state (enabled/disabled)
- Access control configuration (IP restrictions)
- Trigger configuration (HTTP, recurrence, etc.)
- Managed identity configuration
- Integration service environment
- Workflow definition analysis (connection references)
- Diagnostic settings

Supports both Consumption (multi-tenant) and Standard (single-tenant) Logic Apps.

All API calls are read-only.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str, credential: Any | None, **kwargs: Any) -> None`

Initialize the Azure Logic Apps collector.

**Parameters:**

- `subscription_id` (`str`) - Azure subscription ID to collect from.
- `credential` (`Any | None`) - Optional Azure credential object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Azure Logic Apps resources.

**Returns:**

`AssetCollection` - Collection of Azure Logic Apps assets
