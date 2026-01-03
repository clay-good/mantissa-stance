# stance.models.finding

Finding data model for Mantissa Stance.

This module defines the Finding class representing security findings
(both CSPM misconfigurations and vulnerabilities) and FindingCollection
for managing groups of findings.

## Contents

### Classes

- [FindingType](#findingtype)
- [Severity](#severity)
- [FindingStatus](#findingstatus)
- [Finding](#finding)
- [FindingCollection](#findingcollection)

## FindingType

**Inherits from:** Enum

Type of security finding.

## Severity

**Inherits from:** Enum

Severity level of a finding.

### Class Methods

#### `from_string(cls, value: str) -> Severity`

**Decorators:** @classmethod

Create Severity from string value.

**Parameters:**

- `value` (`str`) - String representation (case-insensitive)

**Returns:**

`Severity` - Matching Severity enum value

**Raises:**

- `ValueError`: If value is not a valid severity

## FindingStatus

**Inherits from:** Enum

Status of a finding.

### Class Methods

#### `from_string(cls, value: str) -> FindingStatus`

**Decorators:** @classmethod

Create FindingStatus from string value.

**Parameters:**

- `value` (`str`) - String representation (case-insensitive)

**Returns:**

`FindingStatus` - Matching FindingStatus enum value

**Raises:**

- `ValueError`: If value is not a valid status

## Finding

**Tags:** dataclass

Represents a security finding (misconfiguration or vulnerability).

Findings are generated when a policy evaluation fails or when
vulnerability data is collected from security services. This is
a unified model that handles both CSPM and vulnerability findings.

Attributes:
    id: Unique finding identifier
    asset_id: Reference to the affected asset
    finding_type: Type of finding (misconfiguration or vulnerability)
    severity: Severity level
    status: Current status of the finding
    title: Short description of the finding
    description: Detailed explanation
    first_seen: When the finding was first detected
    last_seen: When the finding was last observed
    rule_id: Policy rule that triggered (for misconfigurations)
    resource_path: Path to non-compliant field (for misconfigurations)
    expected_value: Expected configuration value
    actual_value: Actual configuration value found
    cve_id: CVE identifier (for vulnerabilities)
    cvss_score: CVSS score (for vulnerabilities)
    package_name: Affected package name (for vulnerabilities)
    installed_version: Currently installed version
    fixed_version: Version that fixes the vulnerability
    compliance_frameworks: List of compliance framework controls
    remediation_guidance: Steps to remediate the finding

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `asset_id` | `str` | - |
| `finding_type` | `FindingType` | - |
| `severity` | `Severity` | - |
| `status` | `FindingStatus` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `first_seen` | `datetime | None` | - |
| `last_seen` | `datetime | None` | - |
| `rule_id` | `str | None` | - |
| `resource_path` | `str | None` | - |
| `expected_value` | `str | None` | - |
| `actual_value` | `str | None` | - |
| `cve_id` | `str | None` | - |
| `cvss_score` | `float | None` | - |
| `package_name` | `str | None` | - |
| `installed_version` | `str | None` | - |
| `fixed_version` | `str | None` | - |
| `compliance_frameworks` | `list[str]` | `field(...)` |
| `remediation_guidance` | `str` | `` |

### Methods

#### `is_critical(self) -> bool`

Check if this finding has critical severity.

**Returns:**

`bool` - True if severity is CRITICAL

#### `is_high_or_critical(self) -> bool`

Check if this finding has high or critical severity.

**Returns:**

`bool` - True if severity is HIGH or CRITICAL

#### `is_vulnerability(self) -> bool`

Check if this is a vulnerability finding.

**Returns:**

`bool` - True if finding_type is VULNERABILITY

#### `is_misconfiguration(self) -> bool`

Check if this is a misconfiguration finding.

**Returns:**

`bool` - True if finding_type is MISCONFIGURATION

#### `is_open(self) -> bool`

Check if this finding is still open.

**Returns:**

`bool` - True if status is OPEN

#### `has_fix_available(self) -> bool`

Check if a fix is available (for vulnerabilities).

**Returns:**

`bool` - True if fixed_version is set

#### `to_dict(self) -> dict[(str, Any)]`

Convert finding to dictionary representation.

**Returns:**

`dict[(str, Any)]` - Dictionary with all finding fields

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> Finding`

**Decorators:** @classmethod

Create a Finding from a dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`) - Dictionary with finding fields

**Returns:**

`Finding` - New Finding instance

## FindingCollection

A collection of Finding objects with filtering capabilities.

Provides methods to filter findings by various criteria,
count by severity, and convert to different formats.

Attributes:
    findings: List of Finding objects in this collection

### Properties

#### `findings(self) -> list[Finding]`

Get the list of findings.

**Returns:**

`list[Finding]`

### Methods

#### `__init__(self, findings: list[Finding] | None) -> None`

Initialize collection with optional list of findings.

**Parameters:**

- `findings` (`list[Finding] | None`) - Initial list of findings (defaults to empty list)

**Returns:**

`None`

#### `add(self, finding: Finding) -> None`

Add a finding to the collection.

**Parameters:**

- `finding` (`Finding`) - Finding to add

**Returns:**

`None`

#### `extend(self, findings: list[Finding]) -> None`

Add multiple findings to the collection.

**Parameters:**

- `findings` (`list[Finding]`) - List of findings to add

**Returns:**

`None`

#### `filter_by_severity(self, severity: Severity) -> FindingCollection`

Filter findings by severity.

**Parameters:**

- `severity` (`Severity`) - Severity level to filter by

**Returns:**

`FindingCollection` - New FindingCollection containing only matching findings

#### `filter_by_status(self, status: FindingStatus) -> FindingCollection`

Filter findings by status.

**Parameters:**

- `status` (`FindingStatus`) - Status to filter by

**Returns:**

`FindingCollection` - New FindingCollection containing only matching findings

#### `filter_by_type(self, finding_type: FindingType) -> FindingCollection`

Filter findings by type.

**Parameters:**

- `finding_type` (`FindingType`) - Finding type to filter by

**Returns:**

`FindingCollection` - New FindingCollection containing only matching findings

#### `filter_by_asset(self, asset_id: str) -> FindingCollection`

Filter findings by asset ID.

**Parameters:**

- `asset_id` (`str`) - Asset ID to filter by

**Returns:**

`FindingCollection` - New FindingCollection containing only matching findings

#### `filter_by_rule(self, rule_id: str) -> FindingCollection`

Filter findings by rule ID.

**Parameters:**

- `rule_id` (`str`) - Rule ID to filter by

**Returns:**

`FindingCollection` - New FindingCollection containing only matching findings

#### `filter_critical(self) -> FindingCollection`

Filter to only critical findings.

**Returns:**

`FindingCollection` - New FindingCollection containing only critical findings

#### `filter_open(self) -> FindingCollection`

Filter to only open findings.

**Returns:**

`FindingCollection` - New FindingCollection containing only open findings

#### `filter_vulnerabilities(self) -> FindingCollection`

Filter to only vulnerability findings.

**Returns:**

`FindingCollection` - New FindingCollection containing only vulnerabilities

#### `filter_misconfigurations(self) -> FindingCollection`

Filter to only misconfiguration findings.

**Returns:**

`FindingCollection` - New FindingCollection containing only misconfigurations

#### `get_by_id(self, finding_id: str) -> Finding | None`

Get a finding by its ID.

**Parameters:**

- `finding_id` (`str`) - Finding ID to find

**Returns:**

`Finding | None` - Finding if found, None otherwise

#### `count_by_severity(self) -> dict[(Severity, int)]`

Count findings grouped by severity.

**Returns:**

`dict[(Severity, int)]` - Dictionary mapping Severity to count

#### `count_by_severity_dict(self) -> dict[(str, int)]`

Count findings grouped by severity (string keys).

**Returns:**

`dict[(str, int)]` - Dictionary mapping severity string to count

#### `count_by_status(self) -> dict[(FindingStatus, int)]`

Count findings grouped by status.

**Returns:**

`dict[(FindingStatus, int)]` - Dictionary mapping FindingStatus to count

#### `count_by_type(self) -> dict[(FindingType, int)]`

Count findings grouped by type.

**Returns:**

`dict[(FindingType, int)]` - Dictionary mapping FindingType to count

#### `to_list(self) -> list[dict[(str, Any)]]`

Convert collection to list of dictionaries.

**Returns:**

`list[dict[(str, Any)]]` - List of finding dictionaries

#### `to_json(self) -> str`

Convert collection to JSON string.

**Returns:**

`str` - JSON string representation

#### `merge(self, other: FindingCollection) -> FindingCollection`

Merge with another collection.

**Parameters:**

- `other` (`FindingCollection`) - Another FindingCollection to merge

**Returns:**

`FindingCollection` - New FindingCollection with findings from both collections

### Class Methods

#### `from_list(cls, data: list[dict[(str, Any)]]) -> FindingCollection`

**Decorators:** @classmethod

Create collection from list of dictionaries.

**Parameters:**

- `data` (`list[dict[(str, Any)]]`) - List of finding dictionaries

**Returns:**

`FindingCollection` - New FindingCollection
