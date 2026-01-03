# stance.cloud.base

Base classes for cloud provider abstraction.

This module defines the abstract interfaces that all cloud providers
must implement, enabling Mantissa Stance to work with multiple clouds.

## Contents

### Classes

- [CloudProviderError](#cloudprovidererror)
- [AuthenticationError](#authenticationerror)
- [ConfigurationError](#configurationerror)
- [ResourceNotFoundError](#resourcenotfounderror)
- [PermissionDeniedError](#permissiondeniederror)
- [CloudRegion](#cloudregion)
- [CloudCredentials](#cloudcredentials)
- [CloudAccount](#cloudaccount)
- [CloudProvider](#cloudprovider)

## CloudProviderError

**Inherits from:** Exception

Base exception for cloud provider errors.

## AuthenticationError

**Inherits from:** CloudProviderError

Raised when authentication fails.

## ConfigurationError

**Inherits from:** CloudProviderError

Raised when configuration is invalid.

## ResourceNotFoundError

**Inherits from:** CloudProviderError

Raised when a resource is not found.

## PermissionDeniedError

**Inherits from:** CloudProviderError

Raised when permission is denied.

## CloudRegion

**Tags:** dataclass

Represents a cloud provider region.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `provider` | `str` | - |
| `region_id` | `str` | - |
| `display_name` | `str` | - |
| `is_default` | `bool` | `False` |

## CloudCredentials

**Tags:** dataclass

Cloud provider credentials container.

This is a flexible container that can hold credentials for any
cloud provider. Unused fields should be left as None.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `aws_access_key_id` | `str | None` | - |
| `aws_secret_access_key` | `str | None` | - |
| `aws_session_token` | `str | None` | - |
| `aws_profile` | `str | None` | - |
| `aws_role_arn` | `str | None` | - |
| `gcp_project_id` | `str | None` | - |
| `gcp_service_account_key` | `str | None` | - |
| `gcp_service_account_file` | `str | None` | - |
| `azure_subscription_id` | `str | None` | - |
| `azure_tenant_id` | `str | None` | - |
| `azure_client_id` | `str | None` | - |
| `azure_client_secret` | `str | None` | - |
| `extra` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `get(self, key: str, default: Any) -> Any`

Get a credential value by key.

**Parameters:**

- `key` (`str`)
- `default` (`Any`)

**Returns:**

`Any`

## CloudAccount

**Tags:** dataclass

Represents a cloud account/project/subscription.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `provider` | `str` | - |
| `account_id` | `str` | - |
| `display_name` | `str | None` | - |
| `regions` | `list[CloudRegion]` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

## CloudProvider

**Inherits from:** ABC

Abstract base class for cloud providers.

Each cloud provider (AWS, GCP, Azure) must implement this interface
to enable Mantissa Stance to collect security posture data.

### Properties

#### `provider_name(self) -> str`

**Decorators:** @property, @abstractmethod

Return the provider name (aws, gcp, azure).

**Returns:**

`str`

#### `display_name(self) -> str`

**Decorators:** @property, @abstractmethod

Return human-readable provider name.

**Returns:**

`str`

### Methods

#### `__init__(self, credentials: CloudCredentials | None, **kwargs: Any) -> None`

Initialize the cloud provider.

**Parameters:**

- `credentials` (`CloudCredentials | None`) - Optional credentials object. If None, uses environment defaults (e.g., boto3 default chain). **kwargs: Provider-specific configuration options.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `initialize(self) -> None`

**Decorators:** @abstractmethod

Initialize the provider connection.  This should validate credentials and establish any necessary connections. Called lazily on first use.

**Returns:**

`None`

**Raises:**

- `AuthenticationError`: If credentials are invalid.
- `ConfigurationError`: If configuration is invalid.

#### `validate_credentials(self) -> bool`

**Decorators:** @abstractmethod

Validate that credentials are valid and usable.

**Returns:**

`bool` - True if credentials are valid.

**Raises:**

- `AuthenticationError`: If credentials are invalid.

#### `get_account(self) -> CloudAccount`

**Decorators:** @abstractmethod

Get the current account/project/subscription info.

**Returns:**

`CloudAccount` - CloudAccount with current account details.

#### `list_regions(self) -> list[CloudRegion]`

**Decorators:** @abstractmethod

List available regions for this provider.

**Returns:**

`list[CloudRegion]` - List of CloudRegion objects.

#### `get_collectors(self) -> list[BaseCollector]`

**Decorators:** @abstractmethod

Get the collectors for this cloud provider.

**Returns:**

`list[BaseCollector]` - List of collector instances configured for this provider.

#### `get_storage_backend(self, storage_type: str = default, **kwargs: Any) -> StorageBackend`

**Decorators:** @abstractmethod

Get a storage backend for this cloud provider.

**Parameters:**

- `storage_type` (`str`) - default: `default` - Type of storage (e.g., "s3", "gcs", "blob") **kwargs: Storage-specific configuration.
- `**kwargs` (`Any`)

**Returns:**

`StorageBackend` - Configured StorageBackend instance.

#### `get_config(self, key: str, default: Any) -> Any`

Get a configuration value.

**Parameters:**

- `key` (`str`)
- `default` (`Any`)

**Returns:**

`Any`

### Class Methods

#### `is_available(cls) -> bool`

**Decorators:** @classmethod, @abstractmethod

Check if this provider's SDK is available.

**Returns:**

`bool` - True if the required SDK is installed.

#### `get_required_packages(cls) -> list[str]`

**Decorators:** @classmethod

Return list of required Python packages for this provider.

**Returns:**

`list[str]` - List of package names (e.g., ["boto3"]).
