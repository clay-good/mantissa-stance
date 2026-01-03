"""
Storage backends for Mantissa Stance.

This package provides storage implementations for persisting assets and findings:

- LocalStorage: SQLite-based storage for development and single-user scenarios
- S3Storage: S3-based storage for AWS production deployments with Athena support
- GCSStorage: GCS-based storage for GCP deployments with BigQuery support
- AzureBlobStorage: Azure Blob storage for Azure deployments with Synapse support

Use the get_storage() factory function to get the appropriate backend.
"""

from stance.storage.base import StorageBackend, generate_snapshot_id
from stance.storage.local import LocalStorage
from stance.storage.s3 import S3Storage

# Lazy imports for optional cloud storage backends
_GCS_AVAILABLE = False
_AZURE_AVAILABLE = False

try:
    from stance.storage.gcs import GCSStorage
    _GCS_AVAILABLE = True
except ImportError:
    GCSStorage = None  # type: ignore

try:
    from stance.storage.azure_blob import AzureBlobStorage
    _AZURE_AVAILABLE = True
except ImportError:
    AzureBlobStorage = None  # type: ignore


def get_storage(backend: str = "local", **kwargs) -> StorageBackend:
    """
    Factory function to get the appropriate storage backend.

    Args:
        backend: Storage backend type. Supported values:
            - "local": SQLite-based local storage
            - "s3": AWS S3 storage (requires boto3)
            - "gcs": Google Cloud Storage (requires google-cloud-storage)
            - "azure", "blob": Azure Blob Storage (requires azure-storage-blob)
        **kwargs: Backend-specific configuration options

    Returns:
        Configured StorageBackend instance

    Raises:
        ValueError: If backend type is unknown
        ImportError: If required SDK is not installed

    Examples:
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
    """
    backend = backend.lower()

    if backend == "local":
        return LocalStorage(**kwargs)

    elif backend == "s3":
        return S3Storage(**kwargs)

    elif backend == "gcs":
        if not _GCS_AVAILABLE:
            raise ImportError(
                "google-cloud-storage is required for GCS storage. "
                "Install with: pip install google-cloud-storage"
            )
        return GCSStorage(**kwargs)

    elif backend in ("azure", "blob", "azure_blob"):
        if not _AZURE_AVAILABLE:
            raise ImportError(
                "azure-storage-blob is required for Azure Blob storage. "
                "Install with: pip install azure-storage-blob"
            )
        return AzureBlobStorage(**kwargs)

    else:
        raise ValueError(
            f"Unknown storage backend: {backend}. "
            "Supported backends: 'local', 's3', 'gcs', 'azure'"
        )


def list_available_backends() -> list[str]:
    """
    List available storage backends.

    Returns:
        List of available backend names
    """
    backends = ["local"]

    # Check S3
    try:
        import boto3  # noqa: F401
        backends.append("s3")
    except ImportError:
        pass

    # Check GCS
    if _GCS_AVAILABLE:
        backends.append("gcs")

    # Check Azure
    if _AZURE_AVAILABLE:
        backends.append("azure")

    return backends


__all__ = [
    # Base
    "StorageBackend",
    "generate_snapshot_id",
    # Implementations
    "LocalStorage",
    "S3Storage",
    "GCSStorage",
    "AzureBlobStorage",
    # Factory
    "get_storage",
    "list_available_backends",
]
