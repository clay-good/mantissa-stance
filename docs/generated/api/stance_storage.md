# stance.storage

Storage backends for Mantissa Stance.

This package provides storage implementations for persisting assets and findings:

- LocalStorage: SQLite-based storage for development and single-user scenarios
- S3Storage: S3-based storage for AWS production deployments with Athena support
- GCSStorage: GCS-based storage for GCP deployments with BigQuery support
- AzureBlobStorage: Azure Blob storage for Azure deployments with Synapse support

Use the get_storage() factory function to get the appropriate backend.

## Contents

### Functions

- [get_storage](#get_storage)
- [list_available_backends](#list_available_backends)

## Constants

### `_GCS_AVAILABLE`

Type: `bool`

Value: `False`

### `_AZURE_AVAILABLE`

Type: `bool`

Value: `False`

### `get_storage(backend: str = local, **kwargs) -> StorageBackend`

Factory function to get the appropriate storage backend.

**Parameters:**

- `backend` (`str`) - default: `local` - Storage backend type. Supported values: - "local": SQLite-based local storage - "s3": AWS S3 storage (requires boto3) - "gcs": Google Cloud Storage (requires google-cloud-storage) - "azure", "blob": Azure Blob Storage (requires azure-storage-blob) **kwargs: Backend-specific configuration options
- `**kwargs`

**Returns:**

`StorageBackend` - Configured StorageBackend instance

**Raises:**

- `ValueError`: If backend type is unknown
- `ImportError`: If required SDK is not installed

**Examples:**

```python
# Local storage with default path
    storage = get_storage("local")

    # Local storage with custom path
    storage = get_storage("local", db_path="/tmp/stance.db")

    # AWS S3 storage
    storage = get_storage("s3", bucket="my-bucket", prefix="stance")

    # GCP Cloud Storage
    storage = get_storage("gcs", bucket="my-bucket", project_id="my-project")

    # Azure Blob Storage
    storage = get_storage("azure", account_name="mystorageaccount",
                          container="stance")
```

### `list_available_backends() -> list[str]`

List available storage backends.

**Returns:**

`list[str]` - List of available backend names
