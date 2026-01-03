# stance.enrichment

Finding and asset enrichment for Mantissa Stance.

Provides enrichment capabilities including IP geolocation,
threat intelligence, CVE details, and asset context.

## Contents

### Functions

- [create_default_pipeline](#create_default_pipeline)
- [enrich_findings](#enrich_findings)
- [enrich_assets](#enrich_assets)

### `create_default_pipeline() -> EnrichmentPipeline`

Create a default enrichment pipeline with all enrichers.

**Returns:**

`EnrichmentPipeline` - Configured EnrichmentPipeline

### `enrich_findings(findings: list, pipeline: EnrichmentPipeline | None) -> list[EnrichedFinding]`

Enrich a list of findings.

**Parameters:**

- `findings` (`list`) - Findings to enrich
- `pipeline` (`EnrichmentPipeline | None`) - Optional custom pipeline

**Returns:**

`list[EnrichedFinding]` - List of enriched findings

### `enrich_assets(assets: list, pipeline: EnrichmentPipeline | None) -> list[EnrichedAsset]`

Enrich a list of assets.

**Parameters:**

- `assets` (`list`) - Assets to enrich
- `pipeline` (`EnrichmentPipeline | None`) - Optional custom pipeline

**Returns:**

`list[EnrichedAsset]` - List of enriched assets
