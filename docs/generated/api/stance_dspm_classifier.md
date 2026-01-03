# stance.dspm.classifier

Data classification engine for Mantissa Stance DSPM.

Classifies data assets based on sensitivity level and data categories
such as PII, PCI, PHI, and confidential business data.

## Contents

### Classes

- [ClassificationLevel](#classificationlevel)
- [DataCategory](#datacategory)
- [ClassificationRule](#classificationrule)
- [ClassificationResult](#classificationresult)
- [DataClassification](#dataclassification)
- [DataClassifier](#dataclassifier)

## ClassificationLevel

**Inherits from:** Enum

Data sensitivity classification levels.

### Properties

#### `severity_score(self) -> int`

Get numeric severity score for classification level.

**Returns:**

`int`

## DataCategory

**Inherits from:** Enum

Categories of sensitive data.

## ClassificationRule

**Tags:** dataclass

Rule for classifying data based on patterns and context.

Attributes:
    name: Rule identifier
    description: Human-readable description
    category: Data category this rule detects
    level: Classification level to assign
    patterns: Regex patterns to match
    field_patterns: Field name patterns suggesting this data type
    min_confidence: Minimum confidence threshold
    enabled: Whether rule is active

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `description` | `str` | - |
| `category` | `DataCategory` | - |
| `level` | `ClassificationLevel` | - |
| `patterns` | `list[str]` | `field(...)` |
| `field_patterns` | `list[str]` | `field(...)` |
| `min_confidence` | `float` | `0.7` |
| `enabled` | `bool` | `True` |

## ClassificationResult

**Tags:** dataclass

Result of data classification.

Attributes:
    level: Assigned classification level
    categories: Detected data categories
    confidence: Confidence score (0.0-1.0)
    matched_rules: Rules that matched
    evidence: Evidence supporting classification
    recommendations: Security recommendations

### Attributes

| Name | Type | Default |
|------|------|---------|
| `level` | `ClassificationLevel` | - |
| `categories` | `list[DataCategory]` | `field(...)` |
| `confidence` | `float` | `0.0` |
| `matched_rules` | `list[str]` | `field(...)` |
| `evidence` | `list[str]` | `field(...)` |
| `recommendations` | `list[str]` | `field(...)` |

## DataClassification

**Tags:** dataclass

Classification metadata for a data asset.

Attributes:
    asset_id: Identifier of the classified asset
    asset_type: Type of asset (s3_bucket, database, etc.)
    classification: Classification result
    location: Geographic location of data
    encryption_status: Whether data is encrypted
    access_level: Current access configuration
    compliance_frameworks: Relevant compliance frameworks
    last_scanned: Timestamp of last scan

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `asset_type` | `str` | - |
| `classification` | `ClassificationResult` | - |
| `location` | `str` | `` |
| `encryption_status` | `str` | `unknown` |
| `access_level` | `str` | `unknown` |
| `compliance_frameworks` | `list[str]` | `field(...)` |
| `last_scanned` | `str` | `` |

## DataClassifier

Classifies data assets based on content and metadata analysis.

Analyzes data to determine sensitivity level and applicable
compliance requirements (PCI-DSS, HIPAA, GDPR, etc.).

### Methods

#### `__init__(self, config: dict[(str, Any)] | None)`

Initialize data classifier.

**Parameters:**

- `config` (`dict[(str, Any)] | None`) - Optional configuration overrides

#### `add_rule(self, rule: ClassificationRule) -> None`

Add a custom classification rule.

**Parameters:**

- `rule` (`ClassificationRule`) - Classification rule to add

**Returns:**

`None`

#### `remove_rule(self, rule_name: str) -> bool`

Remove a classification rule by name.

**Parameters:**

- `rule_name` (`str`) - Name of rule to remove

**Returns:**

`bool` - True if rule was removed, False if not found

#### `classify(self, content: str | None, field_name: str | None, metadata: dict[(str, Any)] | None) -> ClassificationResult`

Classify data based on content, field name, and metadata.

**Parameters:**

- `content` (`str | None`) - Data content to analyze
- `field_name` (`str | None`) - Name of field containing data
- `metadata` (`dict[(str, Any)] | None`) - Additional metadata about the data

**Returns:**

`ClassificationResult` - Classification result with level, categories, and confidence

#### `classify_asset(self, asset_id: str, asset_type: str, samples: list[dict[(str, Any)]], metadata: dict[(str, Any)] | None) -> DataClassification`

Classify a data asset based on sampled data.

**Parameters:**

- `asset_id` (`str`) - Unique identifier for the asset
- `asset_type` (`str`) - Type of asset (s3_bucket, rds_database, etc.)
- `samples` (`list[dict[(str, Any)]]`) - Sample records from the asset
- `metadata` (`dict[(str, Any)] | None`) - Asset metadata

**Returns:**

`DataClassification` - Complete data classification for the asset

#### `get_rules(self) -> list[ClassificationRule]`

Get all classification rules.

**Returns:**

`list[ClassificationRule]`

#### `get_rule(self, name: str) -> ClassificationRule | None`

Get a specific rule by name.

**Parameters:**

- `name` (`str`)

**Returns:**

`ClassificationRule | None`
