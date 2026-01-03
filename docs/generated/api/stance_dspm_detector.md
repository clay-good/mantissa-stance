# stance.dspm.detector

Sensitive data detection for Mantissa Stance DSPM.

Scans cloud storage and databases to detect sensitive data
patterns and report findings.

## Contents

### Classes

- [PatternType](#patterntype)
- [DataPattern](#datapattern)
- [PatternMatch](#patternmatch)
- [DetectionResult](#detectionresult)
- [SensitiveDataDetector](#sensitivedatadetector)

## PatternType

**Inherits from:** Enum

Types of detection patterns.

## DataPattern

**Tags:** dataclass

Pattern definition for sensitive data detection.

Attributes:
    name: Pattern identifier
    description: Human-readable description
    pattern_type: Type of pattern matching
    pattern: Pattern string (regex or keyword)
    category: Data category this pattern detects
    confidence: Base confidence score for matches
    validation: Optional validation function name
    enabled: Whether pattern is active

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `description` | `str` | - |
| `pattern_type` | `PatternType` | - |
| `pattern` | `str` | - |
| `category` | `DataCategory` | - |
| `confidence` | `float` | `0.8` |
| `validation` | `str | None` | - |
| `enabled` | `bool` | `True` |

## PatternMatch

**Tags:** dataclass

A match found by a detection pattern.

Attributes:
    pattern_name: Name of pattern that matched
    category: Data category detected
    value: Matched value (may be redacted)
    location: Location in source (line, column, field)
    confidence: Confidence score for this match
    context: Surrounding context
    redacted_value: Redacted version of matched value

### Attributes

| Name | Type | Default |
|------|------|---------|
| `pattern_name` | `str` | - |
| `category` | `DataCategory` | - |
| `value` | `str` | - |
| `location` | `dict[(str, Any)]` | - |
| `confidence` | `float` | - |
| `context` | `str` | `` |
| `redacted_value` | `str` | `` |

## DetectionResult

**Tags:** dataclass

Result of sensitive data detection scan.

Attributes:
    asset_id: Identifier of scanned asset
    asset_type: Type of asset scanned
    matches: List of pattern matches found
    total_records_scanned: Number of records analyzed
    scan_coverage: Percentage of asset scanned
    highest_classification: Highest classification found
    categories_found: Unique categories detected
    scan_duration_ms: Duration of scan in milliseconds

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `asset_type` | `str` | - |
| `matches` | `list[PatternMatch]` | `field(...)` |
| `total_records_scanned` | `int` | `0` |
| `scan_coverage` | `float` | `100.0` |
| `highest_classification` | `ClassificationLevel` | `"Attribute(value=Name(id='ClassificationLevel', ctx=Load()), attr='PUBLIC', ctx=Load())"` |
| `categories_found` | `list[DataCategory]` | `field(...)` |
| `scan_duration_ms` | `int` | `0` |

### Properties

#### `has_sensitive_data(self) -> bool`

Check if sensitive data was detected.

**Returns:**

`bool`

#### `match_count(self) -> int`

Get total number of matches.

**Returns:**

`int`

### Methods

#### `get_matches_by_category(self, category: DataCategory) -> list[PatternMatch]`

Get matches for a specific category.

**Parameters:**

- `category` (`DataCategory`)

**Returns:**

`list[PatternMatch]`

## SensitiveDataDetector

Detects sensitive data in cloud storage and databases.

Scans data samples to identify PII, PCI, PHI, and other
sensitive data types using pattern matching and heuristics.

### Methods

#### `__init__(self, config: dict[(str, Any)] | None)`

Initialize sensitive data detector.

**Parameters:**

- `config` (`dict[(str, Any)] | None`) - Optional configuration overrides

#### `add_pattern(self, pattern: DataPattern) -> None`

Add a custom detection pattern.

**Parameters:**

- `pattern` (`DataPattern`) - Detection pattern to add

**Returns:**

`None`

#### `remove_pattern(self, pattern_name: str) -> bool`

Remove a detection pattern by name.

**Parameters:**

- `pattern_name` (`str`) - Name of pattern to remove

**Returns:**

`bool` - True if pattern was removed, False if not found

#### `scan_content(self, content: str, field_name: str | None, location: dict[(str, Any)] | None) -> list[PatternMatch]`

Scan content for sensitive data patterns.

**Parameters:**

- `content` (`str`) - Text content to scan
- `field_name` (`str | None`) - Optional field name for context
- `location` (`dict[(str, Any)] | None`) - Location metadata

**Returns:**

`list[PatternMatch]` - List of pattern matches found

#### `scan_records(self, records: Iterator[dict[(str, Any)]] | list[dict[(str, Any)]], asset_id: str, asset_type: str, sample_size: int | None) -> DetectionResult`

Scan multiple records for sensitive data.

**Parameters:**

- `records` (`Iterator[dict[(str, Any)]] | list[dict[(str, Any)]]`) - Iterator or list of records to scan
- `asset_id` (`str`) - Identifier of the asset
- `asset_type` (`str`) - Type of asset
- `sample_size` (`int | None`) - Maximum records to scan (None for all)

**Returns:**

`DetectionResult` - Detection result with all matches

#### `get_patterns(self) -> list[DataPattern]`

Get all detection patterns.

**Returns:**

`list[DataPattern]`

#### `get_pattern(self, name: str) -> DataPattern | None`

Get a specific pattern by name.

**Parameters:**

- `name` (`str`)

**Returns:**

`DataPattern | None`
