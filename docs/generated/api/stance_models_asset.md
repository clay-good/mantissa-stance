# stance.models.asset

Asset data model for Mantissa Stance.

This module defines the Asset class representing cloud resources
and AssetCollection for managing groups of assets.

## Contents

### Classes

- [Asset](#asset)
- [AssetCollection](#assetcollection)

## Constants

### `NETWORK_EXPOSURE_INTERNET`

Type: `str`

Value: `internet_facing`

### `NETWORK_EXPOSURE_INTERNAL`

Type: `str`

Value: `internal`

### `NETWORK_EXPOSURE_ISOLATED`

Type: `str`

Value: `isolated`

## Asset

**Tags:** dataclass

Represents a cloud resource.

Assets are immutable snapshots of cloud resource configurations
collected during a scan. Each asset has a unique identifier (ARN for AWS),
metadata about its location and type, and a raw configuration snapshot.

Attributes:
    id: Unique identifier (ARN for AWS resources)
    cloud_provider: Cloud provider name (e.g., "aws")
    account_id: Cloud account identifier
    region: Geographic region where resource is located
    resource_type: Type of resource (e.g., "aws_s3_bucket")
    name: Human-readable name of the resource
    tags: Resource tags as key-value pairs
    network_exposure: Network exposure level (internet_facing, internal, isolated)
    created_at: When the resource was created
    last_seen: When we last observed this resource
    raw_config: Full configuration snapshot as collected

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `cloud_provider` | `str` | - |
| `account_id` | `str` | - |
| `region` | `str` | - |
| `resource_type` | `str` | - |
| `name` | `str` | - |
| `tags` | `dict[(str, str)]` | `field(...)` |
| `network_exposure` | `str` | `NETWORK_EXPOSURE_INTERNAL` |
| `created_at` | `datetime | None` | - |
| `last_seen` | `datetime | None` | - |
| `raw_config` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `is_internet_facing(self) -> bool`

Check if this asset is exposed to the internet.

**Returns:**

`bool` - True if network_exposure is "internet_facing"

#### `get_tag(self, key: str, default: str = ) -> str`

Get a tag value by key.

**Parameters:**

- `key` (`str`) - Tag key to look up
- `default` (`str`) - default: `` - Default value if tag not found

**Returns:**

`str` - Tag value or default

#### `to_dict(self) -> dict[(str, Any)]`

Convert asset to dictionary representation.

**Returns:**

`dict[(str, Any)]` - Dictionary with all asset fields, suitable for JSON serialization

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> Asset`

**Decorators:** @classmethod

Create an Asset from a dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`) - Dictionary with asset fields

**Returns:**

`Asset` - New Asset instance

## AssetCollection

A collection of Asset objects with filtering capabilities.

Provides methods to filter assets by various criteria and
convert the collection to different formats.

Attributes:
    assets: List of Asset objects in this collection

### Properties

#### `assets(self) -> list[Asset]`

Get the list of assets.

**Returns:**

`list[Asset]`

### Methods

#### `__init__(self, assets: list[Asset] | None) -> None`

Initialize collection with optional list of assets.

**Parameters:**

- `assets` (`list[Asset] | None`) - Initial list of assets (defaults to empty list)

**Returns:**

`None`

#### `add(self, asset: Asset) -> None`

Add an asset to the collection.

**Parameters:**

- `asset` (`Asset`) - Asset to add

**Returns:**

`None`

#### `extend(self, assets: list[Asset]) -> None`

Add multiple assets to the collection.

**Parameters:**

- `assets` (`list[Asset]`) - List of assets to add

**Returns:**

`None`

#### `filter_by_type(self, resource_type: str) -> AssetCollection`

Filter assets by resource type.

**Parameters:**

- `resource_type` (`str`) - Resource type to filter by (e.g., "aws_s3_bucket")

**Returns:**

`AssetCollection` - New AssetCollection containing only matching assets

#### `filter_by_region(self, region: str) -> AssetCollection`

Filter assets by region.

**Parameters:**

- `region` (`str`) - Region to filter by (e.g., "us-east-1")

**Returns:**

`AssetCollection` - New AssetCollection containing only matching assets

#### `filter_by_tag(self, key: str, value: str) -> AssetCollection`

Filter assets by tag key-value pair.

**Parameters:**

- `key` (`str`) - Tag key to match
- `value` (`str`) - Tag value to match

**Returns:**

`AssetCollection` - New AssetCollection containing only matching assets

#### `filter_by_account(self, account_id: str) -> AssetCollection`

Filter assets by account ID.

**Parameters:**

- `account_id` (`str`) - Account ID to filter by

**Returns:**

`AssetCollection` - New AssetCollection containing only matching assets

#### `filter_internet_facing(self) -> AssetCollection`

Filter to only internet-facing assets.

**Returns:**

`AssetCollection` - New AssetCollection containing only internet-facing assets

#### `get_by_id(self, asset_id: str) -> Asset | None`

Get an asset by its ID.

**Parameters:**

- `asset_id` (`str`) - Asset ID to find

**Returns:**

`Asset | None` - Asset if found, None otherwise

#### `to_list(self) -> list[dict[(str, Any)]]`

Convert collection to list of dictionaries.

**Returns:**

`list[dict[(str, Any)]]` - List of asset dictionaries

#### `to_json(self) -> str`

Convert collection to JSON string.

**Returns:**

`str` - JSON string representation

#### `count_by_type(self) -> dict[(str, int)]`

Count assets grouped by resource type.

**Returns:**

`dict[(str, int)]` - Dictionary mapping resource type to count

#### `count_by_region(self) -> dict[(str, int)]`

Count assets grouped by region.

**Returns:**

`dict[(str, int)]` - Dictionary mapping region to count

#### `merge(self, other: AssetCollection) -> AssetCollection`

Merge with another collection.

**Parameters:**

- `other` (`AssetCollection`) - Another AssetCollection to merge

**Returns:**

`AssetCollection` - New AssetCollection with assets from both collections

### Class Methods

#### `from_list(cls, data: list[dict[(str, Any)]]) -> AssetCollection`

**Decorators:** @classmethod

Create collection from list of dictionaries.

**Parameters:**

- `data` (`list[dict[(str, Any)]]`) - List of asset dictionaries

**Returns:**

`AssetCollection` - New AssetCollection
