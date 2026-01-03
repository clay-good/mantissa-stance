# stance.scanning.multi_account

Multi-Account Scanner for Mantissa Stance.

Provides orchestration for scanning multiple cloud accounts across AWS, GCP,
and Azure, with parallel execution, progress tracking, and aggregated results.

## Contents

### Classes

- [AccountStatus](#accountstatus)
- [ScanOptions](#scanoptions)
- [AccountScanResult](#accountscanresult)
- [ScanProgress](#scanprogress)
- [OrganizationScan](#organizationscan)
- [MultiAccountScanner](#multiaccountscanner)

## AccountStatus

**Inherits from:** Enum

Status of an account scan.

## ScanOptions

**Tags:** dataclass

Options for multi-account scanning.

Attributes:
    parallel_accounts: Number of accounts to scan in parallel
    timeout_per_account: Maximum time per account scan (seconds)
    continue_on_error: Continue scanning other accounts if one fails
    severity_threshold: Minimum severity to include in results
    collectors: List of collectors to run (None = all)
    regions: List of regions to scan (None = all configured)
    skip_accounts: Account IDs to skip
    include_disabled: Include disabled accounts

### Attributes

| Name | Type | Default |
|------|------|---------|
| `parallel_accounts` | `int` | `3` |
| `timeout_per_account` | `int` | `300` |
| `continue_on_error` | `bool` | `True` |
| `severity_threshold` | `Severity | None` | - |
| `collectors` | `list[str] | None` | - |
| `regions` | `list[str] | None` | - |
| `skip_accounts` | `list[str]` | `field(...)` |
| `include_disabled` | `bool` | `False` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## AccountScanResult

**Tags:** dataclass

Result of scanning a single account.

Attributes:
    account_id: Account identifier
    account_name: Human-readable account name
    provider: Cloud provider
    status: Scan status
    started_at: When scan started
    completed_at: When scan completed
    findings_count: Number of findings discovered
    assets_count: Number of assets scanned
    findings: Findings from this account
    assets: Assets discovered in this account
    error: Error message if scan failed
    regions_scanned: Regions that were scanned
    collectors_used: Collectors that were run

### Attributes

| Name | Type | Default |
|------|------|---------|
| `account_id` | `str` | - |
| `account_name` | `str` | - |
| `provider` | `CloudProvider` | - |
| `status` | `AccountStatus` | `"Attribute(value=Name(id='AccountStatus', ctx=Load()), attr='PENDING', ctx=Load())"` |
| `started_at` | `datetime | None` | - |
| `completed_at` | `datetime | None` | - |
| `findings_count` | `int` | `0` |
| `assets_count` | `int` | `0` |
| `findings` | `FindingCollection | None` | - |
| `assets` | `AssetCollection | None` | - |
| `error` | `str` | `` |
| `regions_scanned` | `list[str]` | `field(...)` |
| `collectors_used` | `list[str]` | `field(...)` |

### Properties

#### `duration(self) -> timedelta | None`

Get scan duration.

**Returns:**

`timedelta | None`

#### `is_success(self) -> bool`

Check if scan was successful.

**Returns:**

`bool`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ScanProgress

**Tags:** dataclass

Real-time progress of a multi-account scan.

Attributes:
    scan_id: Unique scan identifier
    total_accounts: Total accounts to scan
    completed_accounts: Accounts completed
    failed_accounts: Accounts that failed
    skipped_accounts: Accounts that were skipped
    current_accounts: Accounts currently being scanned
    findings_so_far: Findings discovered so far
    started_at: When scan started
    estimated_completion: Estimated completion time

### Attributes

| Name | Type | Default |
|------|------|---------|
| `scan_id` | `str` | - |
| `total_accounts` | `int` | `0` |
| `completed_accounts` | `int` | `0` |
| `failed_accounts` | `int` | `0` |
| `skipped_accounts` | `int` | `0` |
| `current_accounts` | `list[str]` | `field(...)` |
| `findings_so_far` | `int` | `0` |
| `started_at` | `datetime` | `field(...)` |
| `estimated_completion` | `datetime | None` | - |

### Properties

#### `pending_accounts(self) -> int`

Get number of pending accounts.

**Returns:**

`int`

#### `progress_percent(self) -> float`

Get progress as percentage.

**Returns:**

`float`

#### `is_complete(self) -> bool`

Check if scan is complete.

**Returns:**

`bool`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## OrganizationScan

**Tags:** dataclass

Complete result of an organization-level scan.

Attributes:
    scan_id: Unique scan identifier
    config_name: Configuration used for the scan
    started_at: When scan started
    completed_at: When scan completed
    options: Scan options used
    account_results: Results for each account
    aggregated_findings: Deduplicated findings across all accounts
    aggregation_result: Aggregation statistics
    cross_account_findings: Findings appearing in multiple accounts
    summary: Summary statistics

### Attributes

| Name | Type | Default |
|------|------|---------|
| `scan_id` | `str` | - |
| `config_name` | `str` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `options` | `ScanOptions` | `field(...)` |
| `account_results` | `list[AccountScanResult]` | `field(...)` |
| `aggregated_findings` | `FindingCollection | None` | - |
| `aggregation_result` | `AggregationResult | None` | - |
| `cross_account_findings` | `FindingCollection | None` | - |
| `summary` | `dict[(str, Any)]` | `field(...)` |

### Properties

#### `duration(self) -> timedelta | None`

Get total scan duration.

**Returns:**

`timedelta | None`

#### `success_count(self) -> int`

Get number of successful account scans.

**Returns:**

`int`

#### `failure_count(self) -> int`

Get number of failed account scans.

**Returns:**

`int`

#### `total_findings(self) -> int`

Get total findings count.

**Returns:**

`int`

#### `total_assets(self) -> int`

Get total assets count.

**Returns:**

`int`

### Methods

#### `get_findings_by_severity(self) -> dict[(str, int)]`

Get findings count by severity.

**Returns:**

`dict[(str, int)]`

#### `get_findings_by_account(self) -> dict[(str, int)]`

Get findings count by account.

**Returns:**

`dict[(str, int)]`

#### `get_findings_by_provider(self) -> dict[(str, int)]`

Get findings count by provider.

**Returns:**

`dict[(str, int)]`

#### `get_failed_accounts(self) -> list[AccountScanResult]`

Get list of failed account scans.

**Returns:**

`list[AccountScanResult]`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## MultiAccountScanner

Orchestrates scanning across multiple cloud accounts.

Provides parallel execution, progress tracking, and cross-account
findings aggregation for organization-level security assessments.

### Methods

#### `__init__(self, config: ScanConfiguration | None, account_scanner: Callable[([AccountConfig, ScanOptions], AccountScanResult)] | None)`

Initialize the multi-account scanner.

**Parameters:**

- `config` (`ScanConfiguration | None`) - Scan configuration with account definitions
- `account_scanner` (`Callable[([AccountConfig, ScanOptions], AccountScanResult)] | None`) - Function to scan a single account

#### `set_config(self, config: ScanConfiguration) -> None`

Set the scan configuration.

**Parameters:**

- `config` (`ScanConfiguration`)

**Returns:**

`None`

#### `set_account_scanner(self, scanner: Callable[([AccountConfig, ScanOptions], AccountScanResult)]) -> None`

Set the account scanner function.

**Parameters:**

- `scanner` (`Callable[([AccountConfig, ScanOptions], AccountScanResult)]`)

**Returns:**

`None`

#### `add_progress_callback(self, callback: Callable[([ScanProgress], None)]) -> None`

Add a callback for progress updates.

**Parameters:**

- `callback` (`Callable[([ScanProgress], None)]`)

**Returns:**

`None`

#### `get_progress(self) -> ScanProgress | None`

Get current scan progress.

**Returns:**

`ScanProgress | None`

#### `is_running(self) -> bool`

Check if a scan is currently running.

**Returns:**

`bool`

#### `get_accounts_to_scan(self, options: ScanOptions | None) -> list[AccountConfig]`

Get list of accounts that will be scanned.

**Parameters:**

- `options` (`ScanOptions | None`) - Scan options for filtering

**Returns:**

`list[AccountConfig]` - List of accounts to scan

#### `scan(self, options: ScanOptions | None) -> OrganizationScan`

Scan all configured accounts.

**Parameters:**

- `options` (`ScanOptions | None`) - Scan options

**Returns:**

`OrganizationScan` - Complete organization scan result

#### `scan_single_account(self, account: AccountConfig, options: ScanOptions | None) -> AccountScanResult`

Scan a single account.

**Parameters:**

- `account` (`AccountConfig`) - Account to scan
- `options` (`ScanOptions | None`) - Scan options

**Returns:**

`AccountScanResult` - Account scan result

#### `generate_report(self, org_scan: OrganizationScan) -> dict[(str, Any)]`

Generate a detailed report for an organization scan.

**Parameters:**

- `org_scan` (`OrganizationScan`) - Completed organization scan

**Returns:**

`dict[(str, Any)]` - Report dictionary
