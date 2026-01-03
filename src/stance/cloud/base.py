"""
Base classes for cloud provider abstraction.

This module defines the abstract interfaces that all cloud providers
must implement, enabling Mantissa Stance to work with multiple clouds.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from stance.collectors.base import BaseCollector
    from stance.storage.base import StorageBackend


# Exceptions


class CloudProviderError(Exception):
    """Base exception for cloud provider errors."""

    pass


class AuthenticationError(CloudProviderError):
    """Raised when authentication fails."""

    pass


class ConfigurationError(CloudProviderError):
    """Raised when configuration is invalid."""

    pass


class ResourceNotFoundError(CloudProviderError):
    """Raised when a resource is not found."""

    pass


class PermissionDeniedError(CloudProviderError):
    """Raised when permission is denied."""

    pass


# Data classes


@dataclass(frozen=True)
class CloudRegion:
    """Represents a cloud provider region."""

    provider: str
    region_id: str
    display_name: str
    is_default: bool = False

    def __str__(self) -> str:
        return self.region_id


@dataclass
class CloudCredentials:
    """
    Cloud provider credentials container.

    This is a flexible container that can hold credentials for any
    cloud provider. Unused fields should be left as None.
    """

    # AWS credentials
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    aws_profile: str | None = None
    aws_role_arn: str | None = None

    # GCP credentials
    gcp_project_id: str | None = None
    gcp_service_account_key: str | None = None
    gcp_service_account_file: str | None = None

    # Azure credentials
    azure_subscription_id: str | None = None
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None

    # Generic
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a credential value by key."""
        if hasattr(self, key):
            return getattr(self, key) or default
        return self.extra.get(key, default)


@dataclass
class CloudAccount:
    """Represents a cloud account/project/subscription."""

    provider: str
    account_id: str
    display_name: str | None = None
    regions: list[CloudRegion] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.provider}:{self.account_id}"


# Abstract base class


class CloudProvider(ABC):
    """
    Abstract base class for cloud providers.

    Each cloud provider (AWS, GCP, Azure) must implement this interface
    to enable Mantissa Stance to collect security posture data.
    """

    def __init__(
        self,
        credentials: CloudCredentials | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the cloud provider.

        Args:
            credentials: Optional credentials object. If None, uses
                        environment defaults (e.g., boto3 default chain).
            **kwargs: Provider-specific configuration options.
        """
        self.credentials = credentials or CloudCredentials()
        self._config = kwargs
        self._initialized = False

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (aws, gcp, azure)."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Return human-readable provider name."""
        pass

    @abstractmethod
    def initialize(self) -> None:
        """
        Initialize the provider connection.

        This should validate credentials and establish any necessary
        connections. Called lazily on first use.

        Raises:
            AuthenticationError: If credentials are invalid.
            ConfigurationError: If configuration is invalid.
        """
        pass

    @abstractmethod
    def validate_credentials(self) -> bool:
        """
        Validate that credentials are valid and usable.

        Returns:
            True if credentials are valid.

        Raises:
            AuthenticationError: If credentials are invalid.
        """
        pass

    @abstractmethod
    def get_account(self) -> CloudAccount:
        """
        Get the current account/project/subscription info.

        Returns:
            CloudAccount with current account details.
        """
        pass

    @abstractmethod
    def list_regions(self) -> list[CloudRegion]:
        """
        List available regions for this provider.

        Returns:
            List of CloudRegion objects.
        """
        pass

    @abstractmethod
    def get_collectors(self) -> list[BaseCollector]:
        """
        Get the collectors for this cloud provider.

        Returns:
            List of collector instances configured for this provider.
        """
        pass

    @abstractmethod
    def get_storage_backend(
        self,
        storage_type: str = "default",
        **kwargs: Any,
    ) -> StorageBackend:
        """
        Get a storage backend for this cloud provider.

        Args:
            storage_type: Type of storage (e.g., "s3", "gcs", "blob")
            **kwargs: Storage-specific configuration.

        Returns:
            Configured StorageBackend instance.
        """
        pass

    @classmethod
    @abstractmethod
    def is_available(cls) -> bool:
        """
        Check if this provider's SDK is available.

        Returns:
            True if the required SDK is installed.
        """
        pass

    @classmethod
    def get_required_packages(cls) -> list[str]:
        """
        Return list of required Python packages for this provider.

        Returns:
            List of package names (e.g., ["boto3"]).
        """
        return []

    def _ensure_initialized(self) -> None:
        """Ensure the provider is initialized."""
        if not self._initialized:
            self.initialize()
            self._initialized = True

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self._config.get(key, default)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(provider={self.provider_name})"
