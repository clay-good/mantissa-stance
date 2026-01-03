# stance.aggregation.aggregator

Findings aggregator for multi-cloud deployments.

Collects and aggregates findings from multiple cloud accounts and providers
into a unified view for centralized security posture management.

## Contents

### Classes

- [CloudAccount](#cloudaccount)
- [AggregationResult](#aggregationresult)
- [NormalizedFinding](#normalizedfinding)
- [FindingsAggregator](#findingsaggregator)

## CloudAccount

**Tags:** dataclass

Represents a cloud account/project/subscription.

Attributes:
    id: Account identifier (AWS account ID, GCP project ID, Azure subscription ID)
    provider: Cloud provider (aws, gcp, azure)
    name: Human-readable account name
    region: Primary region (optional)
    metadata: Additional account metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `provider` | `str` | - |
| `name` | `str` | - |
| `region` | `str | None` | - |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

## AggregationResult

**Tags:** dataclass

Result of an aggregation operation.

Attributes:
    total_findings: Total number of findings before deduplication
    unique_findings: Number of unique findings after deduplication
    duplicates_removed: Number of duplicates removed
    findings_by_severity: Count of findings by severity
    findings_by_provider: Count of findings by cloud provider
    findings_by_account: Count of findings by account
    aggregated_at: Timestamp of aggregation
    source_accounts: List of accounts included
    metadata: Additional aggregation metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `total_findings` | `int` | `0` |
| `unique_findings` | `int` | `0` |
| `duplicates_removed` | `int` | `0` |
| `findings_by_severity` | `dict[(str, int)]` | `field(...)` |
| `findings_by_provider` | `dict[(str, int)]` | `field(...)` |
| `findings_by_account` | `dict[(str, int)]` | `field(...)` |
| `aggregated_at` | `datetime` | `field(...)` |
| `source_accounts` | `list[CloudAccount]` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## NormalizedFinding

**Tags:** dataclass

A finding normalized to common format for cross-cloud comparison.

Attributes:
    original: The original Finding object
    normalized_key: Unique key for deduplication
    provider: Cloud provider
    account_id: Cloud account identifier
    canonical_resource_type: Normalized resource type
    canonical_rule_id: Normalized rule identifier

### Attributes

| Name | Type | Default |
|------|------|---------|
| `original` | `Finding` | - |
| `normalized_key` | `str` | - |
| `provider` | `str` | - |
| `account_id` | `str` | - |
| `canonical_resource_type` | `str` | - |
| `canonical_rule_id` | `str` | - |

## FindingsAggregator

Aggregates findings from multiple cloud accounts.

Collects findings from multiple AWS accounts, GCP projects, and Azure
subscriptions, normalizes them to a common format, deduplicates across
accounts, and generates aggregate reports.

Example:
    >>> aggregator = FindingsAggregator()
    >>> aggregator.add_account(CloudAccount("123456789012", "aws", "Production"))
    >>> aggregator.add_account(CloudAccount("my-project", "gcp", "GCP Prod"))
    >>> aggregator.add_findings("123456789012", findings_aws)
    >>> aggregator.add_findings("my-project", findings_gcp)
    >>> result = aggregator.aggregate()
    >>> print(f"Unique findings: {result.unique_findings}")

### Methods

#### `__init__(self, dedup_window_hours: int = 24, custom_normalizer: Callable[([Finding, str], NormalizedFinding)] | None) -> None`

Initialize the findings aggregator.

**Parameters:**

- `dedup_window_hours` (`int`) - default: `24` - Time window for deduplication (findings within this window are considered potential duplicates)
- `custom_normalizer` (`Callable[([Finding, str], NormalizedFinding)] | None`) - Optional custom function to normalize findings

**Returns:**

`None`

#### `add_account(self, account: CloudAccount) -> None`

Add a cloud account to the aggregation.

**Parameters:**

- `account` (`CloudAccount`) - CloudAccount to add

**Returns:**

`None`

#### `add_findings(self, account_id: str, findings: FindingCollection | list[Finding]) -> None`

Add findings from a cloud account.

**Parameters:**

- `account_id` (`str`) - Account identifier
- `findings` (`FindingCollection | list[Finding]`) - Findings to add

**Returns:**

`None`

**Raises:**

- `ValueError`: If account has not been added

#### `add_assets(self, account_id: str, assets: AssetCollection | list[Asset]) -> None`

Add assets from a cloud account for correlation.

**Parameters:**

- `account_id` (`str`) - Account identifier
- `assets` (`AssetCollection | list[Asset]`) - Assets to add

**Returns:**

`None`

**Raises:**

- `ValueError`: If account has not been added

#### `aggregate(self, deduplicate: bool = True, severity_filter: Severity | None) -> tuple[(FindingCollection, AggregationResult)]`

Aggregate findings from all registered accounts.

**Parameters:**

- `deduplicate` (`bool`) - default: `True` - Whether to remove duplicate findings
- `severity_filter` (`Severity | None`) - Optional filter to include only specific severity

**Returns:**

`tuple[(FindingCollection, AggregationResult)]` - Tuple of (aggregated findings, aggregation result)

#### `get_cross_account_findings(self, min_accounts: int = 2) -> FindingCollection`

Get findings that appear in multiple accounts.  Useful for identifying systemic issues that affect multiple accounts and should be prioritized.

**Parameters:**

- `min_accounts` (`int`) - default: `2` - Minimum number of accounts a finding must appear in

**Returns:**

`FindingCollection` - FindingCollection of cross-account findings

#### `generate_summary_report(self) -> dict[(str, Any)]`

Generate a summary report of aggregated findings.

**Returns:**

`dict[(str, Any)]` - Dictionary containing summary statistics

#### `clear(self) -> None`

Clear all accounts and findings.

**Returns:**

`None`
