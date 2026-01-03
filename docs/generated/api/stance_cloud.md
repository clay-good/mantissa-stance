# stance.cloud

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

## Contents

### Functions

- [get_cloud_provider](#get_cloud_provider)
- [list_providers](#list_providers)
- [is_provider_available](#is_provider_available)

### `get_cloud_provider(provider_name: str, credentials: CloudCredentials | None, **kwargs) -> CloudProvider`

Factory function to get a cloud provider instance.

**Parameters:**

- `provider_name` (`str`) - Name of the cloud provider ("aws", "gcp", "azure")
- `credentials` (`CloudCredentials | None`) - Optional credentials object **kwargs: Provider-specific configuration options
- `**kwargs`

**Returns:**

`CloudProvider` - Configured CloudProvider instance

**Raises:**

- `ValueError`: If provider_name is not supported
- `ConfigurationError`: If provider cannot be configured

**Examples:**

```python
# AWS with default credentials
    aws = get_cloud_provider("aws", region="us-east-1")

    # GCP with project ID
    gcp = get_cloud_provider("gcp", project_id="my-project")

    # Azure with subscription
    azure = get_cloud_provider("azure", subscription_id="xxx-xxx")
```

### `list_providers() -> list[str]`

Return list of supported cloud provider names.

**Returns:**

`list[str]`

### `is_provider_available(provider_name: str) -> bool`

Check if a cloud provider's SDK is available.

**Parameters:**

- `provider_name` (`str`) - Name of the cloud provider

**Returns:**

`bool` - True if the provider's SDK is installed and available
