# stance.dspm.analyzer

Data flow and access analysis for Mantissa Stance DSPM.

Analyzes how sensitive data flows between systems and who has access.

## Contents

### Classes

- [FlowDirection](#flowdirection)
- [AccessType](#accesstype)
- [DataFlow](#dataflow)
- [ResidencyViolation](#residencyviolation)
- [AccessPattern](#accesspattern)
- [DataFlowAnalyzer](#dataflowanalyzer)
- [DataResidencyChecker](#dataresidencychecker)
- [DataAccessAnalyzer](#dataaccessanalyzer)

## FlowDirection

**Inherits from:** Enum

Direction of data flow.

## AccessType

**Inherits from:** Enum

Type of data access.

## DataFlow

**Tags:** dataclass

Represents a data flow between systems.

Attributes:
    flow_id: Unique identifier for this flow
    source_asset: Source asset ID
    destination_asset: Destination asset ID
    direction: Direction of flow
    data_categories: Categories of data flowing
    classification_level: Highest classification in flow
    encryption_in_transit: Whether data is encrypted in transit
    volume_estimate: Estimated data volume
    frequency: How often flow occurs
    last_observed: When flow was last observed

### Attributes

| Name | Type | Default |
|------|------|---------|
| `flow_id` | `str` | - |
| `source_asset` | `str` | - |
| `destination_asset` | `str` | - |
| `direction` | `FlowDirection` | - |
| `data_categories` | `list[DataCategory]` | `field(...)` |
| `classification_level` | `ClassificationLevel` | `"Attribute(value=Name(id='ClassificationLevel', ctx=Load()), attr='PUBLIC', ctx=Load())"` |
| `encryption_in_transit` | `bool` | `False` |
| `volume_estimate` | `str` | `unknown` |
| `frequency` | `str` | `unknown` |
| `last_observed` | `datetime | None` | - |

### Properties

#### `is_cross_boundary(self) -> bool`

Check if flow crosses security boundaries.

**Returns:**

`bool`

#### `requires_encryption(self) -> bool`

Check if flow should require encryption.

**Returns:**

`bool`

## ResidencyViolation

**Tags:** dataclass

Data residency compliance violation.

Attributes:
    violation_id: Unique identifier
    asset_id: Asset with violation
    data_categories: Categories of data affected
    required_regions: Regions where data should reside
    actual_region: Where data actually resides
    compliance_frameworks: Affected compliance frameworks
    severity: Severity of violation
    remediation: Suggested remediation

### Attributes

| Name | Type | Default |
|------|------|---------|
| `violation_id` | `str` | - |
| `asset_id` | `str` | - |
| `data_categories` | `list[DataCategory]` | - |
| `required_regions` | `list[str]` | - |
| `actual_region` | `str` | - |
| `compliance_frameworks` | `list[str]` | `field(...)` |
| `severity` | `str` | `high` |
| `remediation` | `str` | `` |

## AccessPattern

**Tags:** dataclass

Data access pattern analysis.

Attributes:
    asset_id: Asset being accessed
    principal_id: Who is accessing
    principal_type: Type of principal (user, role, service)
    access_type: Type of access
    frequency: Access frequency
    last_access: When last accessed
    is_anomalous: Whether access pattern is anomalous
    risk_score: Risk score for this pattern

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `principal_id` | `str` | - |
| `principal_type` | `str` | - |
| `access_type` | `AccessType` | - |
| `frequency` | `str` | `unknown` |
| `last_access` | `datetime | None` | - |
| `is_anomalous` | `bool` | `False` |
| `risk_score` | `float` | `0.0` |

## DataFlowAnalyzer

Analyzes data flows between systems to identify risks.

Tracks how sensitive data moves through the environment
and identifies potential security and compliance issues.

### Methods

#### `__init__(self, config: dict[(str, Any)] | None)`

Initialize data flow analyzer.

**Parameters:**

- `config` (`dict[(str, Any)] | None`) - Optional configuration

#### `add_flow(self, flow: DataFlow) -> None`

Register a data flow.

**Parameters:**

- `flow` (`DataFlow`) - Data flow to register

**Returns:**

`None`

#### `get_flow(self, flow_id: str) -> DataFlow | None`

Get a specific flow by ID.

**Parameters:**

- `flow_id` (`str`)

**Returns:**

`DataFlow | None`

#### `get_flows_for_asset(self, asset_id: str) -> list[DataFlow]`

Get all flows involving an asset.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`list[DataFlow]`

#### `analyze_flow_risks(self, flow: DataFlow) -> list[dict[(str, Any)]]`

Analyze risks associated with a data flow.

**Parameters:**

- `flow` (`DataFlow`) - Data flow to analyze

**Returns:**

`list[dict[(str, Any)]]` - List of identified risks

#### `get_all_risks(self) -> list[dict[(str, Any)]]`

Analyze risks for all registered flows.

**Returns:**

`list[dict[(str, Any)]]`

#### `get_flow_graph(self) -> dict[(str, Any)]`

Generate a graph representation of data flows.

**Returns:**

`dict[(str, Any)]` - Graph with nodes (assets) and edges (flows)

## DataResidencyChecker

Checks data residency compliance.

Ensures sensitive data resides in approved geographic regions
based on compliance requirements.

### Methods

#### `__init__(self, config: dict[(str, Any)] | None)`

Initialize residency checker.

**Parameters:**

- `config` (`dict[(str, Any)] | None`) - Optional configuration with residency rules

#### `add_rule(self, framework: str, allowed_regions: list[str]) -> None`

Add a residency rule.

**Parameters:**

- `framework` (`str`) - Compliance framework name
- `allowed_regions` (`list[str]`) - List of allowed regions

**Returns:**

`None`

#### `check_compliance(self, asset_id: str, actual_region: str, data_categories: list[DataCategory]) -> list[ResidencyViolation]`

Check if asset location complies with residency requirements.

**Parameters:**

- `asset_id` (`str`) - Asset to check
- `actual_region` (`str`) - Where asset is located
- `data_categories` (`list[DataCategory]`) - Categories of data in asset

**Returns:**

`list[ResidencyViolation]` - List of residency violations

## DataAccessAnalyzer

Analyzes data access patterns to identify risks.

Tracks who accesses sensitive data and identifies
anomalous or risky access patterns.

### Methods

#### `__init__(self, config: dict[(str, Any)] | None)`

Initialize access analyzer.

**Parameters:**

- `config` (`dict[(str, Any)] | None`) - Optional configuration

#### `record_access(self, pattern: AccessPattern) -> None`

Record an access pattern.

**Parameters:**

- `pattern` (`AccessPattern`) - Access pattern to record

**Returns:**

`None`

#### `analyze_access_risks(self, asset_id: str, classification_level: ClassificationLevel) -> list[dict[(str, Any)]]`

Analyze access risks for an asset.

**Parameters:**

- `asset_id` (`str`) - Asset to analyze
- `classification_level` (`ClassificationLevel`) - Classification level of asset

**Returns:**

`list[dict[(str, Any)]]` - List of identified access risks

#### `get_access_summary(self, asset_id: str) -> dict[(str, Any)]`

Get access summary for an asset.

**Parameters:**

- `asset_id` (`str`) - Asset to summarize

**Returns:**

`dict[(str, Any)]` - Summary of access patterns

#### `detect_anomalies(self, pattern: AccessPattern, threshold: float = 2.0) -> bool`

Detect if an access pattern is anomalous.

**Parameters:**

- `pattern` (`AccessPattern`) - Access pattern to check
- `threshold` (`float`) - default: `2.0` - Standard deviation threshold

**Returns:**

`bool` - True if pattern is anomalous

#### `get_patterns(self) -> list[AccessPattern]`

Get all recorded access patterns.

**Returns:**

`list[AccessPattern]`

#### `clear_patterns(self) -> None`

Clear all recorded patterns.

**Returns:**

`None`
