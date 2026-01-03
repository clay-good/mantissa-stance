"""
Cloud provider abstraction layer for Mantissa Stance.

This module provides a unified interface for interacting with multiple
cloud providers (AWS, GCP, Azure). It enables the same codebase to
collect security posture data from any supported cloud.

Supported Providers:
- AWS (Amazon Web Services)
- GCP (Google Cloud Platform)
- Azure (Microsoft Azure)

Usage:
    from stance.cloud import get_cloud_provider, CloudProvider

    # Get provider for specific cloud
    provider = get_cloud_provider("aws", region="us-east-1")

    # Get collectors for this provider
    collectors = provider.get_collectors()

    # Run collection
    for collector in collectors:
        assets = collector.collect()
"""

from __future__ import annotations

from stance.cloud.base import (
    CloudProvider,
    CloudCredentials,
    CloudRegion,
    CloudProviderError,
    AuthenticationError,
    ConfigurationError,
)
from stance.cloud.aws import AWSProvider
from stance.cloud.gcp import GCPProvider
from stance.cloud.azure import AzureProvider

# Registry of available cloud providers
PROVIDERS: dict[str, type[CloudProvider]] = {
    "aws": AWSProvider,
    "gcp": GCPProvider,
    "azure": AzureProvider,
}


def get_cloud_provider(
    provider_name: str,
    credentials: CloudCredentials | None = None,
    **kwargs,
) -> CloudProvider:
    """
    Factory function to get a cloud provider instance.

    Args:
        provider_name: Name of the cloud provider ("aws", "gcp", "azure")
        credentials: Optional credentials object
        **kwargs: Provider-specific configuration options

    Returns:
        Configured CloudProvider instance

    Raises:
        ValueError: If provider_name is not supported
        ConfigurationError: If provider cannot be configured

    Examples:
        # AWS with default credentials
        aws = get_cloud_provider("aws", region="us-east-1")

        # GCP with project ID
        gcp = get_cloud_provider("gcp", project_id="my-project")

        # Azure with subscription
        azure = get_cloud_provider("azure", subscription_id="xxx-xxx")
    """
    provider_name = provider_name.lower()

    if provider_name not in PROVIDERS:
        supported = ", ".join(sorted(PROVIDERS.keys()))
        raise ValueError(
            f"Unknown cloud provider: {provider_name}. "
            f"Supported providers: {supported}"
        )

    provider_class = PROVIDERS[provider_name]
    return provider_class(credentials=credentials, **kwargs)


def list_providers() -> list[str]:
    """Return list of supported cloud provider names."""
    return sorted(PROVIDERS.keys())


def is_provider_available(provider_name: str) -> bool:
    """
    Check if a cloud provider's SDK is available.

    Args:
        provider_name: Name of the cloud provider

    Returns:
        True if the provider's SDK is installed and available
    """
    provider_name = provider_name.lower()

    if provider_name not in PROVIDERS:
        return False

    provider_class = PROVIDERS[provider_name]
    return provider_class.is_available()


__all__ = [
    # Base classes
    "CloudProvider",
    "CloudCredentials",
    "CloudRegion",
    # Exceptions
    "CloudProviderError",
    "AuthenticationError",
    "ConfigurationError",
    # Provider implementations
    "AWSProvider",
    "GCPProvider",
    "AzureProvider",
    # Factory functions
    "get_cloud_provider",
    "list_providers",
    "is_provider_available",
    # Registry
    "PROVIDERS",
]
