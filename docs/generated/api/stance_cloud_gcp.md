# stance.cloud.gcp

Google Cloud Platform provider implementation.

This module provides GCP-specific implementation of the CloudProvider
interface, using the google-cloud SDK.

## Contents

### Classes

- [GCPProvider](#gcpprovider)

## GCPProvider

**Inherits from:** CloudProvider

Google Cloud Platform provider implementation.

Uses google-cloud SDK for all GCP API interactions. Supports
service account authentication and application default credentials.

### Properties

#### `provider_name(self) -> str`

**Returns:**

`str`

#### `display_name(self) -> str`

**Returns:**

`str`

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, credentials: CloudCredentials | None, project_id: str | None, region: str = us-central1, **kwargs: Any) -> None`

Initialize GCP provider.

**Parameters:**

- `credentials` (`CloudCredentials | None`) - Optional credentials with GCP service account.
- `project_id` (`str | None`) - GCP project ID. Required unless set in credentials.
- `region` (`str`) - default: `us-central1` - Default GCP region. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `initialize(self) -> None`

Initialize GCP credentials and validate project.

**Returns:**

`None`

#### `validate_credentials(self) -> bool`

Validate GCP credentials.

**Returns:**

`bool`

#### `get_account(self) -> CloudAccount`

Get GCP project information.

**Returns:**

`CloudAccount`

#### `list_regions(self) -> list[CloudRegion]`

List available GCP regions.

**Returns:**

`list[CloudRegion]`

#### `get_collectors(self) -> list[BaseCollector]`

Get GCP collectors.

**Returns:**

`list[BaseCollector]`

#### `get_storage_backend(self, storage_type: str = gcs, **kwargs: Any) -> StorageBackend`

Get GCP storage backend (Cloud Storage).

**Parameters:**

- `storage_type` (`str`) - default: `gcs`
- `**kwargs` (`Any`)

**Returns:**

`StorageBackend`

#### `get_credentials(self)`

Get the GCP credentials for direct use.

### Class Methods

#### `is_available(cls) -> bool`

**Decorators:** @classmethod

Check if google-cloud SDK is installed.

**Returns:**

`bool`

#### `get_required_packages(cls) -> list[str]`

**Decorators:** @classmethod

**Returns:**

`list[str]`
