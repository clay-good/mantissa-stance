# stance.cloud.aws

AWS cloud provider implementation.

This module provides AWS-specific implementation of the CloudProvider
interface, wrapping boto3 functionality.

## Contents

### Classes

- [AWSProvider](#awsprovider)

## AWSProvider

**Inherits from:** CloudProvider

AWS cloud provider implementation.

Uses boto3 for all AWS API interactions. Supports multiple
authentication methods including environment variables,
IAM roles, and explicit credentials.

### Properties

#### `provider_name(self) -> str`

**Returns:**

`str`

#### `display_name(self) -> str`

**Returns:**

`str`

### Methods

#### `__init__(self, credentials: CloudCredentials | None, region: str = us-east-1, **kwargs: Any) -> None`

Initialize AWS provider.

**Parameters:**

- `credentials` (`CloudCredentials | None`) - Optional credentials. If None, uses boto3 default credential chain.
- `region` (`str`) - default: `us-east-1` - Default AWS region. **kwargs: Additional configuration: - profile: AWS profile name - role_arn: IAM role to assume
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `initialize(self) -> None`

Initialize boto3 session.

**Returns:**

`None`

#### `validate_credentials(self) -> bool`

Validate AWS credentials.

**Returns:**

`bool`

#### `get_account(self) -> CloudAccount`

Get AWS account information.

**Returns:**

`CloudAccount`

#### `list_regions(self) -> list[CloudRegion]`

List available AWS regions.

**Returns:**

`list[CloudRegion]`

#### `get_collectors(self) -> list[BaseCollector]`

Get AWS collectors configured with this provider's session.

**Returns:**

`list[BaseCollector]`

#### `get_storage_backend(self, storage_type: str = s3, **kwargs: Any) -> StorageBackend`

Get AWS storage backend (S3).

**Parameters:**

- `storage_type` (`str`) - default: `s3`
- `**kwargs` (`Any`)

**Returns:**

`StorageBackend`

#### `get_session(self)`

Get the boto3 session for direct use.

#### `get_client(self, service: str, **kwargs: Any)`

Get a boto3 client for a specific service.

**Parameters:**

- `service` (`str`)
- `**kwargs` (`Any`)

#### `get_resource(self, service: str, **kwargs: Any)`

Get a boto3 resource for a specific service.

**Parameters:**

- `service` (`str`)
- `**kwargs` (`Any`)

### Class Methods

#### `is_available(cls) -> bool`

**Decorators:** @classmethod

Check if boto3 is installed.

**Returns:**

`bool`

#### `get_required_packages(cls) -> list[str]`

**Decorators:** @classmethod

**Returns:**

`list[str]`
