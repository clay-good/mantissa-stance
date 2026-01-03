# stance.collectors.azure_security

Azure Security collector for Mantissa Stance.

Collects security findings from Microsoft Defender for Cloud (formerly Azure Security Center)
for vulnerability and threat detection.

## Contents

### Classes

- [AzureSecurityCollector](#azuresecuritycollector)

## AzureSecurityCollector

**Inherits from:** BaseCollector

Collects security findings from Microsoft Defender for Cloud.

Gathers security alerts, assessments, and recommendations.
All API calls are read-only.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str, credential: Any | None, **kwargs: Any) -> None`

Initialize the Azure Security collector.

**Parameters:**

- `subscription_id` (`str`) - Azure subscription ID to collect from.
- `credential` (`Any | None`) - Optional Azure credential object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect security service assets (Defender for Cloud configuration).

**Returns:**

`AssetCollection` - Collection of security service assets

#### `collect_findings(self) -> FindingCollection`

Collect security findings from Defender for Cloud.

**Returns:**

`FindingCollection` - Collection of security findings
