# stance.enrichment.asset_enrichment

Asset enrichment for Mantissa Stance.

Provides asset context enrichment including tag-based context,
business unit mapping, and criticality assessment.

## Contents

### Classes

- [BusinessUnitMapping](#businessunitmapping)
- [CriticalityRule](#criticalityrule)
- [AssetContextEnricher](#assetcontextenricher)
- [TagEnricher](#tagenricher)

## Constants

### `DEFAULT_BUSINESS_UNITS`

Type: `list`

Value: `['BusinessUnitMapping(...)', 'BusinessUnitMapping(...)', 'BusinessUnitMapping(...)', 'BusinessUnitMapping(...)', 'BusinessUnitMapping(...)']`

### `DEFAULT_CRITICALITY_RULES`

Type: `list`

Value: `['CriticalityRule(...)', 'CriticalityRule(...)', 'CriticalityRule(...)', 'CriticalityRule(...)', 'CriticalityRule(...)', 'CriticalityRule(...)', 'CriticalityRule(...)']`

## BusinessUnitMapping

**Tags:** dataclass

Mapping configuration for business units.

Attributes:
    name: Business unit name
    patterns: Tag patterns to match (regex)
    tag_key: Tag key to match
    tag_values: Tag values to match
    owners: Default owners for this business unit
    contacts: Contact information

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `patterns` | `list[str]` | `field(...)` |
| `tag_key` | `str` | `business_unit` |
| `tag_values` | `list[str]` | `field(...)` |
| `owners` | `list[str]` | `field(...)` |
| `contacts` | `dict[(str, str)]` | `field(...)` |

## CriticalityRule

**Tags:** dataclass

Rule for determining asset criticality.

Attributes:
    level: Criticality level (critical, high, medium, low)
    resource_types: Resource types this rule applies to
    tag_patterns: Tag patterns that indicate this criticality
    name_patterns: Name patterns that indicate this criticality
    conditions: Additional conditions (key-value pairs)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `level` | `str` | - |
| `resource_types` | `list[str]` | `field(...)` |
| `tag_patterns` | `dict[(str, str)]` | `field(...)` |
| `name_patterns` | `list[str]` | `field(...)` |
| `conditions` | `dict[(str, Any)]` | `field(...)` |

## AssetContextEnricher

**Inherits from:** BaseAssetEnricher

Enriches assets with contextual information.

Provides:
- Business unit identification
- Owner identification
- Criticality assessment
- Environment classification

### Properties

#### `enricher_name(self) -> str`

**Returns:**

`str`

#### `enrichment_types(self) -> list[EnrichmentType]`

**Returns:**

`list[EnrichmentType]`

### Methods

#### `__init__(self, business_units: list[BusinessUnitMapping] | None, criticality_rules: list[CriticalityRule] | None)`

Initialize asset context enricher.

**Parameters:**

- `business_units` (`list[BusinessUnitMapping] | None`) - Custom business unit mappings
- `criticality_rules` (`list[CriticalityRule] | None`) - Custom criticality rules

#### `enrich(self, asset: Asset) -> list[EnrichmentData]`

Enrich asset with contextual information.

**Parameters:**

- `asset` (`Asset`) - Asset to enrich

**Returns:**

`list[EnrichmentData]` - List of enrichment data

#### `add_business_unit(self, mapping: BusinessUnitMapping) -> None`

Add a custom business unit mapping.

**Parameters:**

- `mapping` (`BusinessUnitMapping`)

**Returns:**

`None`

#### `add_criticality_rule(self, rule: CriticalityRule) -> None`

Add a custom criticality rule.

**Parameters:**

- `rule` (`CriticalityRule`)

**Returns:**

`None`

## TagEnricher

**Inherits from:** BaseAssetEnricher

Enriches assets based on tag analysis.

Provides tag-based insights and compliance checking.

### Properties

#### `enricher_name(self) -> str`

**Returns:**

`str`

#### `enrichment_types(self) -> list[EnrichmentType]`

**Returns:**

`list[EnrichmentType]`

### Methods

#### `__init__(self, required_tags: dict[(str, list[str])] | None)`

Initialize tag enricher.

**Parameters:**

- `required_tags` (`dict[(str, list[str])] | None`) - Custom required tag definitions

#### `enrich(self, asset: Asset) -> list[EnrichmentData]`

Enrich asset with tag analysis.

**Parameters:**

- `asset` (`Asset`) - Asset to enrich

**Returns:**

`list[EnrichmentData]` - List of enrichment data
