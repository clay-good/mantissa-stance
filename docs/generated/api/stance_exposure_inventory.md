# stance.exposure.inventory

Public Asset Inventory for Exposure Management.

Aggregates publicly accessible cloud resources from collector data
and correlates with DSPM classification results for risk assessment.

## Contents

### Classes

- [DSPMClassification](#dspmclassification)
- [PublicAssetInventory](#publicassetinventory)

### Functions

- [create_inventory_from_assets](#create_inventory_from_assets)

## DSPMClassification

**Tags:** dataclass

Data classification from DSPM scan results.

Attributes:
    resource_id: Resource identifier
    classification_level: Classification level (public, internal, etc.)
    data_categories: List of data categories found
    scan_date: When the scan was performed

### Attributes

| Name | Type | Default |
|------|------|---------|
| `resource_id` | `str` | - |
| `classification_level` | `str` | - |
| `data_categories` | `list[str]` | `field(...)` |
| `scan_date` | `datetime | None` | - |

## PublicAssetInventory

**Inherits from:** BaseExposureAnalyzer

Aggregates and analyzes publicly accessible cloud resources.

Discovers public assets from collector data (Asset objects) and
correlates with DSPM classification results for comprehensive
exposure analysis.

### Methods

#### `__init__(self, config: ExposureConfig | None, assets: AssetCollection | list[Asset] | None)`

Initialize the public asset inventory.

**Parameters:**

- `config` (`ExposureConfig | None`) - Optional configuration for analysis
- `assets` (`AssetCollection | list[Asset] | None`) - Collection of assets to analyze

#### `register_assets(self, assets: AssetCollection | list[Asset]) -> None`

Register assets for analysis.

**Parameters:**

- `assets` (`AssetCollection | list[Asset]`) - Assets to add to the inventory

**Returns:**

`None`

#### `register_dspm_classification(self, resource_id: str, classification_level: str, data_categories: list[str] | None, scan_date: datetime | None) -> None`

Register DSPM classification for a resource.

**Parameters:**

- `resource_id` (`str`) - Resource identifier
- `classification_level` (`str`) - Classification level
- `data_categories` (`list[str] | None`) - Data categories found
- `scan_date` (`datetime | None`) - When the scan was performed

**Returns:**

`None`

#### `register_dspm_classifications(self, classifications: dict[(str, DSPMClassification)]) -> None`

Register multiple DSPM classifications.

**Parameters:**

- `classifications` (`dict[(str, DSPMClassification)]`) - Dictionary mapping resource_id to classification

**Returns:**

`None`

#### `discover_public_assets(self) -> Iterator[PublicAsset]`

Discover publicly accessible assets from registered assets.  Filters assets to those with internet-facing network exposure and converts them to PublicAsset objects.  Yields: Public assets found

**Returns:**

`Iterator[PublicAsset]`

#### `analyze_asset(self, asset: PublicAsset) -> list[ExposureFinding]`

Analyze a public asset for exposure findings.

**Parameters:**

- `asset` (`PublicAsset`) - Public asset to analyze

**Returns:**

`list[ExposureFinding]` - List of findings for this asset

#### `run_inventory(self) -> ExposureInventoryResult`

Run the full public asset inventory analysis.  Discovers all public assets, analyzes each for findings, and generates a comprehensive result.

**Returns:**

`ExposureInventoryResult` - Complete inventory result

#### `get_public_assets_by_type(self, exposure_type: ExposureType) -> list[PublicAsset]`

Get public assets filtered by exposure type.

**Parameters:**

- `exposure_type` (`ExposureType`) - Type of exposure to filter by

**Returns:**

`list[PublicAsset]` - List of public assets of the specified type

#### `get_public_assets_by_cloud(self, cloud_provider: str) -> list[PublicAsset]`

Get public assets filtered by cloud provider.

**Parameters:**

- `cloud_provider` (`str`) - Cloud provider to filter by

**Returns:**

`list[PublicAsset]` - List of public assets from the specified cloud

#### `get_sensitive_public_assets(self) -> list[PublicAsset]`

Get public assets that contain sensitive data.

**Returns:**

`list[PublicAsset]` - List of public assets with sensitive data

### `create_inventory_from_assets(assets: AssetCollection | list[Asset], dspm_results: dict[(str, dict[(str, Any)])] | None, config: ExposureConfig | None) -> ExposureInventoryResult`

Convenience function to create an exposure inventory from assets.

**Parameters:**

- `assets` (`AssetCollection | list[Asset]`) - Collection of assets to analyze
- `dspm_results` (`dict[(str, dict[(str, Any)])] | None`) - Optional DSPM scan results keyed by resource_id
- `config` (`ExposureConfig | None`) - Optional configuration

**Returns:**

`ExposureInventoryResult` - Complete inventory result
