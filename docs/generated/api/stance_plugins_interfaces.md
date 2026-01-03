# stance.plugins.interfaces

Plugin interfaces for Mantissa Stance.

Defines the abstract interfaces that specific plugin types must implement.

## Contents

### Classes

- [CollectorPlugin](#collectorplugin)
- [PolicyPlugin](#policyplugin)
- [EnricherPlugin](#enricherplugin)
- [AlertDestinationPlugin](#alertdestinationplugin)
- [ReportFormatPlugin](#reportformatplugin)

## CollectorPlugin

**Inherits from:** Plugin

Interface for custom collector plugins.

Collector plugins gather assets from cloud providers or other sources.

### Methods

#### `collect(self, region: str | None) -> 'AssetCollection'`

**Decorators:** @abstractmethod

Collect assets from the source.

**Parameters:**

- `region` (`str | None`) - Optional region to collect from

**Returns:**

`'AssetCollection'` - AssetCollection with discovered assets

#### `get_supported_resource_types(self) -> list[str]`

**Decorators:** @abstractmethod

Get list of resource types this collector handles.

**Returns:**

`list[str]` - List of resource type strings (e.g., ["aws_s3_bucket", "aws_ec2_instance"])

### Class Methods

#### `get_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod

Get plugin metadata with collector type.

**Returns:**

`PluginMetadata`

#### `_get_collector_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod, @abstractmethod

Get collector-specific metadata.  Subclasses should override this instead of get_metadata().

**Returns:**

`PluginMetadata` - PluginMetadata for this collector

## PolicyPlugin

**Inherits from:** Plugin

Interface for custom policy plugins.

Policy plugins define security rules and evaluation logic.

### Methods

#### `evaluate(self, asset: 'Asset') -> list['Finding']`

**Decorators:** @abstractmethod

Evaluate an asset against this policy.

**Parameters:**

- `asset` (`'Asset'`) - Asset to evaluate

**Returns:**

`list['Finding']` - List of findings (empty if asset passes)

#### `get_resource_types(self) -> list[str]`

**Decorators:** @abstractmethod

Get resource types this policy applies to.

**Returns:**

`list[str]` - List of resource type strings

#### `get_severity(self) -> str`

**Decorators:** @abstractmethod

Get policy severity.

**Returns:**

`str` - Severity string ("critical", "high", "medium", "low", "info")

### Class Methods

#### `get_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod

Get plugin metadata with policy type.

**Returns:**

`PluginMetadata`

#### `_get_policy_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod, @abstractmethod

Get policy-specific metadata.

**Returns:**

`PluginMetadata` - PluginMetadata for this policy

## EnricherPlugin

**Inherits from:** Plugin

Interface for custom enricher plugins.

Enricher plugins add additional context to assets or findings.

### Methods

#### `enrich_asset(self, asset: 'Asset') -> 'Asset'`

**Decorators:** @abstractmethod

Enrich an asset with additional context.

**Parameters:**

- `asset` (`'Asset'`) - Asset to enrich

**Returns:**

`'Asset'` - Enriched asset (may be same instance, modified)

#### `enrich_finding(self, finding: 'Finding', asset: 'Asset') -> 'Finding'`

**Decorators:** @abstractmethod

Enrich a finding with additional context.

**Parameters:**

- `finding` (`'Finding'`) - Finding to enrich
- `asset` (`'Asset'`) - Related asset

**Returns:**

`'Finding'` - Enriched finding

#### `get_supported_resource_types(self) -> list[str]`

Get resource types this enricher handles.

**Returns:**

`list[str]` - List of resource types, or empty for all types

### Class Methods

#### `get_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod

Get plugin metadata with enricher type.

**Returns:**

`PluginMetadata`

#### `_get_enricher_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod, @abstractmethod

Get enricher-specific metadata.

**Returns:**

`PluginMetadata` - PluginMetadata for this enricher

## AlertDestinationPlugin

**Inherits from:** Plugin

Interface for custom alert destination plugins.

Alert destination plugins send findings to external systems.

### Methods

#### `send_alert(self, finding: 'Finding', context: dict[(str, Any)]) -> bool`

**Decorators:** @abstractmethod

Send an alert for a finding.

**Parameters:**

- `finding` (`'Finding'`) - Finding to alert about
- `context` (`dict[(str, Any)]`) - Additional context (snapshot_id, etc.)

**Returns:**

`bool` - True if alert was sent successfully

#### `send_batch_alerts(self, findings: list['Finding'], context: dict[(str, Any)]) -> tuple[(int, int)]`

**Decorators:** @abstractmethod

Send alerts for multiple findings.

**Parameters:**

- `findings` (`list['Finding']`) - Findings to alert about
- `context` (`dict[(str, Any)]`) - Additional context

**Returns:**

`tuple[(int, int)]` - Tuple of (successful_count, failed_count)

#### `test_connection(self) -> tuple[(bool, str)]`

Test connectivity to the alert destination.

**Returns:**

`tuple[(bool, str)]` - Tuple of (success, message)

### Class Methods

#### `get_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod

Get plugin metadata with alert destination type.

**Returns:**

`PluginMetadata`

#### `_get_alert_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod, @abstractmethod

Get alert destination-specific metadata.

**Returns:**

`PluginMetadata` - PluginMetadata for this alert destination

## ReportFormatPlugin

**Inherits from:** Plugin

Interface for custom report format plugins.

Report format plugins generate reports in custom formats.

### Methods

#### `get_format_name(self) -> str`

**Decorators:** @abstractmethod

Get the format name (used in CLI).

**Returns:**

`str` - Format name string (e.g., "pdf", "xlsx", "markdown")

#### `get_file_extension(self) -> str`

**Decorators:** @abstractmethod

Get the file extension for this format.

**Returns:**

`str` - File extension including dot (e.g., ".pdf", ".xlsx")

#### `generate_report(self, findings: 'FindingCollection', assets: 'AssetCollection', context: dict[(str, Any)]) -> bytes`

**Decorators:** @abstractmethod

Generate a report in this format.

**Parameters:**

- `findings` (`'FindingCollection'`) - Findings to include
- `assets` (`'AssetCollection'`) - Assets to include
- `context` (`dict[(str, Any)]`) - Additional context (snapshot_id, timestamp, etc.)

**Returns:**

`bytes` - Report content as bytes

#### `get_mime_type(self) -> str`

Get MIME type for this format.

**Returns:**

`str` - MIME type string

### Class Methods

#### `get_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod

Get plugin metadata with report format type.

**Returns:**

`PluginMetadata`

#### `_get_report_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod, @abstractmethod

Get report format-specific metadata.

**Returns:**

`PluginMetadata` - PluginMetadata for this report format
