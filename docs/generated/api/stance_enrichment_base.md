# stance.enrichment.base

Base enricher for Mantissa Stance.

Provides abstract interface for finding and asset enrichment.

## Contents

### Classes

- [EnrichmentType](#enrichmenttype)
- [EnrichmentData](#enrichmentdata)
- [EnrichedFinding](#enrichedfinding)
- [EnrichedAsset](#enrichedasset)
- [BaseEnricher](#baseenricher)
- [FindingEnricher](#findingenricher)
- [AssetEnricher](#assetenricher)
- [EnrichmentResult](#enrichmentresult)
- [EnrichmentPipeline](#enrichmentpipeline)

## Constants

### `T`

Type: `str`

Value: `TypeVar(...)`

## EnrichmentType

**Inherits from:** Enum

Types of enrichment data.

## EnrichmentData

**Tags:** dataclass

Container for enrichment data.

Attributes:
    enrichment_type: Type of enrichment
    source: Source of the enrichment data
    data: Enrichment data dictionary
    confidence: Confidence score (0.0 to 1.0)
    cached: Whether this data was from cache
    fetched_at: When the data was fetched
    expires_at: When the data expires

### Attributes

| Name | Type | Default |
|------|------|---------|
| `enrichment_type` | `EnrichmentType` | - |
| `source` | `str` | - |
| `data` | `dict[(str, Any)]` | - |
| `confidence` | `float` | `1.0` |
| `cached` | `bool` | `False` |
| `fetched_at` | `datetime` | `field(...)` |
| `expires_at` | `datetime | None` | - |

### Methods

#### `is_expired(self) -> bool`

Check if enrichment data has expired.

**Returns:**

`bool`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## EnrichedFinding

**Tags:** dataclass

Finding with enrichment data attached.

Attributes:
    finding: Original finding
    enrichments: List of enrichment data

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding` | `Finding` | - |
| `enrichments` | `list[EnrichmentData]` | `field(...)` |

### Methods

#### `get_enrichment(self, enrichment_type: EnrichmentType) -> EnrichmentData | None`

Get enrichment data by type.

**Parameters:**

- `enrichment_type` (`EnrichmentType`)

**Returns:**

`EnrichmentData | None`

#### `has_enrichment(self, enrichment_type: EnrichmentType) -> bool`

Check if enrichment type exists.

**Parameters:**

- `enrichment_type` (`EnrichmentType`)

**Returns:**

`bool`

#### `add_enrichment(self, enrichment: EnrichmentData) -> None`

Add enrichment data.

**Parameters:**

- `enrichment` (`EnrichmentData`)

**Returns:**

`None`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## EnrichedAsset

**Tags:** dataclass

Asset with enrichment data attached.

Attributes:
    asset: Original asset
    enrichments: List of enrichment data

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset` | `Asset` | - |
| `enrichments` | `list[EnrichmentData]` | `field(...)` |

### Methods

#### `get_enrichment(self, enrichment_type: EnrichmentType) -> EnrichmentData | None`

Get enrichment data by type.

**Parameters:**

- `enrichment_type` (`EnrichmentType`)

**Returns:**

`EnrichmentData | None`

#### `has_enrichment(self, enrichment_type: EnrichmentType) -> bool`

Check if enrichment type exists.

**Parameters:**

- `enrichment_type` (`EnrichmentType`)

**Returns:**

`bool`

#### `add_enrichment(self, enrichment: EnrichmentData) -> None`

Add enrichment data.

**Parameters:**

- `enrichment` (`EnrichmentData`)

**Returns:**

`None`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## BaseEnricher

**Inherits from:** ABC, Generic[T]

Abstract base class for enrichers.

Enrichers add contextual information to findings or assets
from external data sources.

### Properties

#### `enricher_name(self) -> str`

**Decorators:** @property, @abstractmethod

Return the enricher name.

**Returns:**

`str`

#### `enrichment_types(self) -> list[EnrichmentType]`

**Decorators:** @property, @abstractmethod

Return the types of enrichment this enricher provides.

**Returns:**

`list[EnrichmentType]`

### Methods

#### `enrich(self, item: T) -> list[EnrichmentData]`

**Decorators:** @abstractmethod

Enrich a single finding or asset.

**Parameters:**

- `item` (`T`) - Finding or Asset to enrich

**Returns:**

`list[EnrichmentData]` - List of enrichment data

#### `enrich_batch(self, items: list[T]) -> dict[(str, list[EnrichmentData])]`

Enrich multiple items.  Default implementation calls enrich() for each item. Subclasses may override for batch optimization.

**Parameters:**

- `items` (`list[T]`) - List of findings or assets to enrich

**Returns:**

`dict[(str, list[EnrichmentData])]` - Dictionary mapping item ID to enrichment data

#### `is_available(self) -> bool`

Check if enricher is available and configured.

**Returns:**

`bool` - True if enricher can be used

## FindingEnricher

**Inherits from:** BaseEnricher[Finding]

Base class for finding enrichers.

## AssetEnricher

**Inherits from:** BaseEnricher[Asset]

Base class for asset enrichers.

## EnrichmentResult

**Tags:** dataclass

Result of an enrichment operation.

Attributes:
    enriched_findings: Findings with enrichment data
    enriched_assets: Assets with enrichment data
    enrichers_used: Names of enrichers that were used
    errors: Errors encountered during enrichment
    duration_seconds: Time taken for enrichment

### Attributes

| Name | Type | Default |
|------|------|---------|
| `enriched_findings` | `list[EnrichedFinding]` | `field(...)` |
| `enriched_assets` | `list[EnrichedAsset]` | `field(...)` |
| `enrichers_used` | `list[str]` | `field(...)` |
| `errors` | `list[str]` | `field(...)` |
| `duration_seconds` | `float` | `0.0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## EnrichmentPipeline

Pipeline for running multiple enrichers.

Runs enrichers in sequence, accumulating enrichment data.

### Methods

#### `__init__(self, finding_enrichers: list[FindingEnricher] | None, asset_enrichers: list[AssetEnricher] | None)`

Initialize enrichment pipeline.

**Parameters:**

- `finding_enrichers` (`list[FindingEnricher] | None`) - Enrichers for findings
- `asset_enrichers` (`list[AssetEnricher] | None`) - Enrichers for assets

#### `enrich_findings(self, findings: list[Finding]) -> list[EnrichedFinding]`

Enrich a list of findings.

**Parameters:**

- `findings` (`list[Finding]`) - Findings to enrich

**Returns:**

`list[EnrichedFinding]` - Enriched findings

#### `enrich_assets(self, assets: list[Asset]) -> list[EnrichedAsset]`

Enrich a list of assets.

**Parameters:**

- `assets` (`list[Asset]`) - Assets to enrich

**Returns:**

`list[EnrichedAsset]` - Enriched assets

#### `add_finding_enricher(self, enricher: FindingEnricher) -> None`

Add a finding enricher to the pipeline.

**Parameters:**

- `enricher` (`FindingEnricher`)

**Returns:**

`None`

#### `add_asset_enricher(self, enricher: AssetEnricher) -> None`

Add an asset enricher to the pipeline.

**Parameters:**

- `enricher` (`AssetEnricher`)

**Returns:**

`None`
