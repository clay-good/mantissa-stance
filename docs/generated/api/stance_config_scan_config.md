# stance.config.scan_config

Scan configuration for Mantissa Stance.

Provides configuration management for scan parameters including
collectors, regions, accounts, schedules, and policies.

## Contents

### Classes

- [CloudProvider](#cloudprovider)
- [ScanMode](#scanmode)
- [CollectorConfig](#collectorconfig)
- [AccountConfig](#accountconfig)
- [ScheduleConfig](#scheduleconfig)
- [PolicyConfig](#policyconfig)
- [StorageConfig](#storageconfig)
- [NotificationConfig](#notificationconfig)
- [ScanConfiguration](#scanconfiguration)
- [ConfigurationManager](#configurationmanager)

### Functions

- [load_config_from_env](#load_config_from_env)
- [create_default_config](#create_default_config)

## CloudProvider

**Inherits from:** Enum

Supported cloud providers.

## ScanMode

**Inherits from:** Enum

Scan operation modes.

## CollectorConfig

**Tags:** dataclass

Configuration for a specific collector.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `enabled` | `bool` | `True` |
| `regions` | `list[str]` | `field(...)` |
| `resource_types` | `list[str]` | `field(...)` |
| `options` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> CollectorConfig`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`CollectorConfig`

## AccountConfig

**Tags:** dataclass

Configuration for a cloud account to scan.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `account_id` | `str` | - |
| `cloud_provider` | `CloudProvider` | - |
| `name` | `str` | `` |
| `regions` | `list[str]` | `field(...)` |
| `assume_role_arn` | `str` | `` |
| `project_id` | `str` | `` |
| `subscription_id` | `str` | `` |
| `enabled` | `bool` | `True` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> AccountConfig`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`AccountConfig`

## ScheduleConfig

**Tags:** dataclass

Configuration for scheduled scans.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `enabled` | `bool` | `True` |
| `expression` | `str` | `rate(1 hour)` |
| `timezone` | `str` | `UTC` |
| `full_scan_expression` | `str` | `cron(0 0 * * ? *)` |
| `incremental_enabled` | `bool` | `True` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> ScheduleConfig`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`ScheduleConfig`

## PolicyConfig

**Tags:** dataclass

Configuration for policy evaluation.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `policy_dirs` | `list[str]` | `field(...)` |
| `enabled_policies` | `list[str]` | `field(...)` |
| `disabled_policies` | `list[str]` | `field(...)` |
| `severity_threshold` | `str` | `info` |
| `frameworks` | `list[str]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> PolicyConfig`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`PolicyConfig`

## StorageConfig

**Tags:** dataclass

Configuration for storage backends.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `backend` | `str` | `local` |
| `local_path` | `str` | `~/.stance` |
| `s3_bucket` | `str` | `` |
| `s3_prefix` | `str` | `stance` |
| `gcs_bucket` | `str` | `` |
| `gcs_prefix` | `str` | `stance` |
| `azure_container` | `str` | `` |
| `azure_prefix` | `str` | `stance` |
| `retention_days` | `int` | `90` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> StorageConfig`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`StorageConfig`

## NotificationConfig

**Tags:** dataclass

Configuration for notifications.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `enabled` | `bool` | `False` |
| `destinations` | `list[dict[(str, Any)]]` | `field(...)` |
| `severity_threshold` | `str` | `high` |
| `rate_limit_per_hour` | `int` | `100` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> NotificationConfig`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`NotificationConfig`

## ScanConfiguration

**Tags:** dataclass

Complete scan configuration.

This is the main configuration class that contains all settings
for running Stance scans.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | `default` |
| `description` | `str` | `` |
| `mode` | `ScanMode` | `"Attribute(value=Name(id='ScanMode', ctx=Load()), attr='FULL', ctx=Load())"` |
| `collectors` | `list[CollectorConfig]` | `field(...)` |
| `accounts` | `list[AccountConfig]` | `field(...)` |
| `schedule` | `ScheduleConfig` | `field(...)` |
| `policies` | `PolicyConfig` | `field(...)` |
| `storage` | `StorageConfig` | `field(...)` |
| `notifications` | `NotificationConfig` | `field(...)` |
| `created_at` | `datetime` | `field(...)` |
| `updated_at` | `datetime` | `field(...)` |

### Methods

#### `get_enabled_collectors(self) -> list[str]`

Get list of enabled collector names.

**Returns:**

`list[str]`

#### `get_enabled_accounts(self) -> list[AccountConfig]`

Get list of enabled accounts.

**Returns:**

`list[AccountConfig]`

#### `get_regions_for_account(self, account_id: str) -> list[str]`

Get configured regions for an account.

**Parameters:**

- `account_id` (`str`)

**Returns:**

`list[str]`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

#### `to_json(self, indent: int = 2) -> str`

Convert to JSON string.

**Parameters:**

- `indent` (`int`) - default: `2`

**Returns:**

`str`

#### `save(self, path: str) -> None`

Save configuration to file.

**Parameters:**

- `path` (`str`)

**Returns:**

`None`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> ScanConfiguration`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`ScanConfiguration`

#### `from_json(cls, json_str: str) -> ScanConfiguration`

**Decorators:** @classmethod

Create from JSON string.

**Parameters:**

- `json_str` (`str`)

**Returns:**

`ScanConfiguration`

#### `from_file(cls, path: str) -> ScanConfiguration`

**Decorators:** @classmethod

Load configuration from file.

**Parameters:**

- `path` (`str`)

**Returns:**

`ScanConfiguration`

## ConfigurationManager

Manages scan configurations.

Provides methods for loading, saving, and managing multiple
scan configurations.

### Methods

#### `__init__(self, config_dir: str = ~/.stance/config)`

Initialize configuration manager.

**Parameters:**

- `config_dir` (`str`) - default: `~/.stance/config` - Directory for storing configurations

#### `list_configurations(self) -> list[str]`

List available configuration names.

**Returns:**

`list[str]`

#### `load(self, name: str = default) -> ScanConfiguration`

Load a configuration by name.

**Parameters:**

- `name` (`str`) - default: `default` - Configuration name

**Returns:**

`ScanConfiguration` - ScanConfiguration instance

#### `save(self, config: ScanConfiguration, format: str = json) -> str`

Save a configuration.

**Parameters:**

- `config` (`ScanConfiguration`) - Configuration to save
- `format` (`str`) - default: `json` - Output format (json or yaml)

**Returns:**

`str` - Path to saved file

#### `delete(self, name: str) -> bool`

Delete a configuration.

**Parameters:**

- `name` (`str`) - Configuration name

**Returns:**

`bool` - True if deleted, False if not found

#### `get_default(self) -> ScanConfiguration`

Get or create the default configuration.

**Returns:**

`ScanConfiguration`

#### `set_default(self, config: ScanConfiguration) -> str`

Set a configuration as the default.

**Parameters:**

- `config` (`ScanConfiguration`) - Configuration to set as default

**Returns:**

`str` - Path to saved file

### `load_config_from_env() -> ScanConfiguration`

Load configuration from environment variables.  Environment variables: STANCE_CONFIG_FILE: Path to configuration file STANCE_COLLECTORS: Comma-separated list of collectors STANCE_REGIONS: Comma-separated list of regions STANCE_STORAGE_BACKEND: Storage backend (local, s3, gcs, azure_blob) STANCE_S3_BUCKET: S3 bucket name STANCE_GCS_BUCKET: GCS bucket name STANCE_AZURE_CONTAINER: Azure container name STANCE_POLICY_DIRS: Comma-separated policy directories STANCE_SEVERITY_THRESHOLD: Minimum severity to report

**Returns:**

`ScanConfiguration` - ScanConfiguration instance

### `create_default_config() -> ScanConfiguration`

Create a default scan configuration.

**Returns:**

`ScanConfiguration` - ScanConfiguration with sensible defaults
