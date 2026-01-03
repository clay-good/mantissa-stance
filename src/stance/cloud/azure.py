"""
Microsoft Azure provider implementation.

This module provides Azure-specific implementation of the CloudProvider
interface, using the Azure SDK for Python.
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


class AzureProvider(CloudProvider):
    """
    Microsoft Azure provider implementation.

    Uses Azure SDK for Python for all Azure API interactions. Supports
    service principal authentication and Azure CLI credentials.
    """

    def __init__(
        self,
        credentials: CloudCredentials | None = None,
        subscription_id: str | None = None,
        region: str = "eastus",
        **kwargs: Any,
    ) -> None:
        """
        Initialize Azure provider.

        Args:
            credentials: Optional credentials with Azure service principal.
            subscription_id: Azure subscription ID. Required.
            region: Default Azure region.
            **kwargs: Additional configuration.
        """
        super().__init__(credentials, **kwargs)
        self._subscription_id = (
            subscription_id or
            (credentials.azure_subscription_id if credentials else None)
        )
        self._region = region
        self._credential = None

    @property
    def provider_name(self) -> str:
        return "azure"

    @property
    def display_name(self) -> str:
        return "Microsoft Azure"

    @classmethod
    def is_available(cls) -> bool:
        """Check if Azure SDK is installed."""
        try:
            from azure.identity import DefaultAzureCredential  # noqa: F401
            from azure.mgmt.resource import SubscriptionClient  # noqa: F401
            return True
        except ImportError:
            return False

    @classmethod
    def get_required_packages(cls) -> list[str]:
        return [
            "azure-identity",
            "azure-mgmt-resource",
            "azure-mgmt-storage",
            "azure-mgmt-compute",
            "azure-mgmt-network",
            "azure-mgmt-security",
            "azure-storage-blob",
        ]

    def initialize(self) -> None:
        """Initialize Azure credentials and validate subscription."""
        if not self.is_available():
            raise ConfigurationError(
                "Azure SDK is not installed. Install with: "
                "pip install azure-identity azure-mgmt-resource azure-storage-blob"
            )

        try:
            from azure.identity import (
                DefaultAzureCredential,
                ClientSecretCredential,
            )

            # Use service principal if credentials provided
            if (
                self.credentials.azure_tenant_id and
                self.credentials.azure_client_id and
                self.credentials.azure_client_secret
            ):
                self._credential = ClientSecretCredential(
                    tenant_id=self.credentials.azure_tenant_id,
                    client_id=self.credentials.azure_client_id,
                    client_secret=self.credentials.azure_client_secret,
                )
            else:
                # Use default credential chain (CLI, managed identity, etc.)
                self._credential = DefaultAzureCredential()

            if not self._subscription_id:
                # Try to get subscription from environment or first available
                self._subscription_id = self._get_default_subscription()

            if not self._subscription_id:
                raise ConfigurationError(
                    "Azure subscription_id is required. Set via subscription_id "
                    "parameter or AZURE_SUBSCRIPTION_ID environment variable."
                )

            # Validate credentials
            self._validate_subscription_access()
            self._initialized = True

        except Exception as e:
            if isinstance(e, (AuthenticationError, ConfigurationError)):
                raise
            raise AuthenticationError(f"Failed to initialize Azure credentials: {e}")

    def _get_default_subscription(self) -> str | None:
        """Get the default subscription ID."""
        import os

        # Check environment variable
        sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
        if sub_id:
            return sub_id

        # Try to get first subscription
        try:
            from azure.mgmt.resource import SubscriptionClient

            client = SubscriptionClient(credential=self._credential)
            for sub in client.subscriptions.list():
                return sub.subscription_id
        except Exception:
            pass

        return None

    def _validate_subscription_access(self) -> None:
        """Validate we can access the subscription."""
        try:
            from azure.mgmt.resource import SubscriptionClient

            client = SubscriptionClient(credential=self._credential)
            sub = client.subscriptions.get(self._subscription_id)
            if not sub:
                raise AuthenticationError(
                    f"Subscription {self._subscription_id} not found"
                )
        except Exception as e:
            raise AuthenticationError(
                f"Failed to access Azure subscription {self._subscription_id}: {e}"
            )

    def validate_credentials(self) -> bool:
        """Validate Azure credentials."""
        self._ensure_initialized()
        try:
            self._validate_subscription_access()
            return True
        except Exception:
            return False

    def get_account(self) -> CloudAccount:
        """Get Azure subscription information."""
        self._ensure_initialized()

        display_name = None
        try:
            from azure.mgmt.resource import SubscriptionClient

            client = SubscriptionClient(credential=self._credential)
            sub = client.subscriptions.get(self._subscription_id)
            display_name = sub.display_name
        except Exception:
            pass

        return CloudAccount(
            provider="azure",
            account_id=self._subscription_id,
            display_name=display_name or self._subscription_id,
            regions=self.list_regions(),
            metadata={"region": self._region},
        )

    def list_regions(self) -> list[CloudRegion]:
        """List available Azure regions."""
        self._ensure_initialized()

        try:
            from azure.mgmt.resource import SubscriptionClient

            client = SubscriptionClient(credential=self._credential)
            regions = []
            for location in client.subscriptions.list_locations(
                self._subscription_id
            ):
                regions.append(
                    CloudRegion(
                        provider="azure",
                        region_id=location.name,
                        display_name=location.display_name,
                        is_default=(location.name == self._region),
                    )
                )
            return regions
        except Exception:
            # Return common regions if API call fails
            common_regions = [
                ("eastus", "East US"),
                ("eastus2", "East US 2"),
                ("westus", "West US"),
                ("westus2", "West US 2"),
                ("centralus", "Central US"),
                ("westeurope", "West Europe"),
                ("northeurope", "North Europe"),
                ("southeastasia", "Southeast Asia"),
            ]
            return [
                CloudRegion(
                    provider="azure",
                    region_id=r[0],
                    display_name=r[1],
                    is_default=(r[0] == self._region),
                )
                for r in common_regions
            ]

    def get_collectors(self) -> list[BaseCollector]:
        """Get Azure collectors."""
        self._ensure_initialized()

        collectors = []

        try:
            from stance.collectors.azure_iam import AzureIAMCollector
            collectors.append(
                AzureIAMCollector(
                    subscription_id=self._subscription_id,
                    credential=self._credential,
                )
            )
        except ImportError:
            pass

        try:
            from stance.collectors.azure_storage import AzureStorageCollector
            collectors.append(
                AzureStorageCollector(
                    subscription_id=self._subscription_id,
                    credential=self._credential,
                )
            )
        except ImportError:
            pass

        try:
            from stance.collectors.azure_compute import AzureComputeCollector
            collectors.append(
                AzureComputeCollector(
                    subscription_id=self._subscription_id,
                    credential=self._credential,
                )
            )
        except ImportError:
            pass

        return collectors

    def get_storage_backend(
        self,
        storage_type: str = "blob",
        **kwargs: Any,
    ) -> StorageBackend:
        """Get Azure storage backend (Blob Storage)."""
        self._ensure_initialized()

        if storage_type == "local":
            from stance.storage.local import LocalStorage
            return LocalStorage(**kwargs)

        if storage_type in ("blob", "default"):
            from stance.storage.azure_blob import AzureBlobStorage

            account_name = kwargs.get("account_name")
            container = kwargs.get("container")
            if not account_name or not container:
                raise ConfigurationError(
                    "Azure Blob storage requires 'account_name' and 'container' "
                    "parameters"
                )

            return AzureBlobStorage(
                account_name=account_name,
                container=container,
                prefix=kwargs.get("prefix", "stance"),
                credential=self._credential,
            )

        raise ConfigurationError(f"Unknown storage type for Azure: {storage_type}")

    def get_credential(self):
        """Get the Azure credential for direct use."""
        self._ensure_initialized()
        return self._credential

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id
