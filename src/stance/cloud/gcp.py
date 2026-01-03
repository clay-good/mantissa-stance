"""
Google Cloud Platform provider implementation.

This module provides GCP-specific implementation of the CloudProvider
interface, using the google-cloud SDK.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from stance.cloud.base import (
    CloudProvider,
    CloudCredentials,
    CloudAccount,
    CloudRegion,
    AuthenticationError,
    ConfigurationError,
)

if TYPE_CHECKING:
    from stance.collectors.base import BaseCollector
    from stance.storage.base import StorageBackend


class GCPProvider(CloudProvider):
    """
    Google Cloud Platform provider implementation.

    Uses google-cloud SDK for all GCP API interactions. Supports
    service account authentication and application default credentials.
    """

    def __init__(
        self,
        credentials: CloudCredentials | None = None,
        project_id: str | None = None,
        region: str = "us-central1",
        **kwargs: Any,
    ) -> None:
        """
        Initialize GCP provider.

        Args:
            credentials: Optional credentials with GCP service account.
            project_id: GCP project ID. Required unless set in credentials.
            region: Default GCP region.
            **kwargs: Additional configuration.
        """
        super().__init__(credentials, **kwargs)
        self._project_id = (
            project_id or
            (credentials.gcp_project_id if credentials else None)
        )
        self._region = region
        self._credentials = None

    @property
    def provider_name(self) -> str:
        return "gcp"

    @property
    def display_name(self) -> str:
        return "Google Cloud Platform"

    @classmethod
    def is_available(cls) -> bool:
        """Check if google-cloud SDK is installed."""
        try:
            from google.cloud import storage  # noqa: F401
            from google.auth import default  # noqa: F401
            return True
        except ImportError:
            return False

    @classmethod
    def get_required_packages(cls) -> list[str]:
        return [
            "google-cloud-storage",
            "google-cloud-compute",
            "google-cloud-iam",
            "google-cloud-resource-manager",
            "google-cloud-securitycenter",
        ]

    def initialize(self) -> None:
        """Initialize GCP credentials and validate project."""
        if not self.is_available():
            raise ConfigurationError(
                "google-cloud SDK is not installed. Install with: "
                "pip install google-cloud-storage google-cloud-compute"
            )

        try:
            from google.auth import default as get_default_credentials
            from google.oauth2 import service_account

            # Use service account file if provided
            if self.credentials.gcp_service_account_file:
                self._credentials = (
                    service_account.Credentials.from_service_account_file(
                        self.credentials.gcp_service_account_file
                    )
                )
            # Use service account key JSON if provided
            elif self.credentials.gcp_service_account_key:
                import json
                key_info = json.loads(self.credentials.gcp_service_account_key)
                self._credentials = (
                    service_account.Credentials.from_service_account_info(key_info)
                )
            else:
                # Use application default credentials
                self._credentials, project = get_default_credentials()
                if not self._project_id and project:
                    self._project_id = project

            if not self._project_id:
                raise ConfigurationError(
                    "GCP project_id is required. Set via project_id parameter "
                    "or GOOGLE_CLOUD_PROJECT environment variable."
                )

            # Validate credentials by making a simple API call
            self._validate_project_access()
            self._initialized = True

        except Exception as e:
            if isinstance(e, (AuthenticationError, ConfigurationError)):
                raise
            raise AuthenticationError(f"Failed to initialize GCP credentials: {e}")

    def _validate_project_access(self) -> None:
        """Validate we can access the project."""
        try:
            from google.cloud import storage
            client = storage.Client(
                project=self._project_id,
                credentials=self._credentials,
            )
            # Try to list buckets (limited to 1) to validate access
            list(client.list_buckets(max_results=1))
        except Exception as e:
            raise AuthenticationError(
                f"Failed to access GCP project {self._project_id}: {e}"
            )

    def validate_credentials(self) -> bool:
        """Validate GCP credentials."""
        self._ensure_initialized()
        try:
            self._validate_project_access()
            return True
        except Exception:
            return False

    def get_account(self) -> CloudAccount:
        """Get GCP project information."""
        self._ensure_initialized()

        display_name = None
        try:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.ProjectsClient(
                credentials=self._credentials
            )
            project = client.get_project(name=f"projects/{self._project_id}")
            display_name = project.display_name
        except Exception:
            pass

        return CloudAccount(
            provider="gcp",
            account_id=self._project_id,
            display_name=display_name or self._project_id,
            regions=self.list_regions(),
            metadata={"region": self._region},
        )

    def list_regions(self) -> list[CloudRegion]:
        """List available GCP regions."""
        self._ensure_initialized()

        try:
            from google.cloud import compute_v1

            client = compute_v1.RegionsClient(credentials=self._credentials)
            regions = []
            for region in client.list(project=self._project_id):
                regions.append(
                    CloudRegion(
                        provider="gcp",
                        region_id=region.name,
                        display_name=region.description or region.name,
                        is_default=(region.name == self._region),
                    )
                )
            return regions
        except Exception:
            # Return common regions if API call fails
            common_regions = [
                ("us-central1", "Iowa"),
                ("us-east1", "South Carolina"),
                ("us-west1", "Oregon"),
                ("europe-west1", "Belgium"),
                ("europe-west2", "London"),
                ("asia-east1", "Taiwan"),
                ("asia-southeast1", "Singapore"),
            ]
            return [
                CloudRegion(
                    provider="gcp",
                    region_id=r[0],
                    display_name=r[1],
                    is_default=(r[0] == self._region),
                )
                for r in common_regions
            ]

    def get_collectors(self) -> list[BaseCollector]:
        """Get GCP collectors."""
        self._ensure_initialized()

        # Import GCP collectors when available
        collectors = []

        try:
            from stance.collectors.gcp_iam import GCPIAMCollector
            collectors.append(
                GCPIAMCollector(
                    project_id=self._project_id,
                    credentials=self._credentials,
                )
            )
        except ImportError:
            pass

        try:
            from stance.collectors.gcp_storage import GCPStorageCollector
            collectors.append(
                GCPStorageCollector(
                    project_id=self._project_id,
                    credentials=self._credentials,
                )
            )
        except ImportError:
            pass

        try:
            from stance.collectors.gcp_compute import GCPComputeCollector
            collectors.append(
                GCPComputeCollector(
                    project_id=self._project_id,
                    credentials=self._credentials,
                )
            )
        except ImportError:
            pass

        return collectors

    def get_storage_backend(
        self,
        storage_type: str = "gcs",
        **kwargs: Any,
    ) -> StorageBackend:
        """Get GCP storage backend (Cloud Storage)."""
        self._ensure_initialized()

        if storage_type == "local":
            from stance.storage.local import LocalStorage
            return LocalStorage(**kwargs)

        if storage_type in ("gcs", "default"):
            from stance.storage.gcs import GCSStorage

            bucket = kwargs.get("bucket")
            if not bucket:
                raise ConfigurationError(
                    "GCS storage requires 'bucket' parameter"
                )

            return GCSStorage(
                bucket=bucket,
                prefix=kwargs.get("prefix", "stance"),
                project_id=self._project_id,
                credentials=self._credentials,
            )

        raise ConfigurationError(f"Unknown storage type for GCP: {storage_type}")

    def get_credentials(self):
        """Get the GCP credentials for direct use."""
        self._ensure_initialized()
        return self._credentials

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id
