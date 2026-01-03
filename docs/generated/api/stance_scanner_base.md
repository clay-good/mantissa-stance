# stance.scanner.base

Base classes for container image scanning.

This module provides the abstract base class and data models for
container image vulnerability scanning.

## Contents

### Classes

- [VulnerabilitySeverity](#vulnerabilityseverity)
- [Vulnerability](#vulnerability)
- [ScanResult](#scanresult)
- [ScannerError](#scannererror)
- [ScannerNotAvailableError](#scannernotavailableerror)
- [ScannerTimeoutError](#scannertimeouterror)
- [ImageScanner](#imagescanner)

## VulnerabilitySeverity

**Inherits from:** Enum

Severity levels for vulnerabilities.

### Methods

#### `to_stance_severity(self) -> Severity`

Convert to Stance Severity enum.

**Returns:**

`Severity`

### Class Methods

#### `from_string(cls, value: str) -> 'VulnerabilitySeverity'`

**Decorators:** @classmethod

Convert string to severity enum.

**Parameters:**

- `value` (`str`)

**Returns:**

`'VulnerabilitySeverity'`

## Vulnerability

**Tags:** dataclass

Represents a single vulnerability in a container image.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `vulnerability_id` | `str` | - |
| `package_name` | `str` | - |
| `installed_version` | `str` | - |
| `severity` | `VulnerabilitySeverity` | - |
| `cvss_score` | `float | None` | - |
| `cvss_vector` | `str | None` | - |
| `fixed_version` | `str | None` | - |
| `is_fixable` | `bool` | `False` |
| `title` | `str | None` | - |
| `description` | `str | None` | - |
| `references` | `list[str]` | `field(...)` |
| `package_type` | `str | None` | - |
| `package_path` | `str | None` | - |
| `published_date` | `datetime | None` | - |
| `last_modified_date` | `datetime | None` | - |
| `data_source` | `str | None` | - |
| `primary_url` | `str | None` | - |
| `cwe_ids` | `list[str]` | `field(...)` |

### Methods

#### `to_finding(self, image_reference: str, asset_id: str | None, scan_timestamp: datetime | None) -> Finding`

Convert vulnerability to a Stance Finding.

**Parameters:**

- `image_reference` (`str`)
- `asset_id` (`str | None`)
- `scan_timestamp` (`datetime | None`)

**Returns:**

`Finding`

## ScanResult

**Tags:** dataclass

Result from scanning a container image.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `image_reference` | `str` | - |
| `image_digest` | `str | None` | - |
| `scanner_name` | `str` | `unknown` |
| `scanner_version` | `str | None` | - |
| `scan_timestamp` | `datetime` | `field(...)` |
| `scan_duration_seconds` | `float` | `0.0` |
| `vulnerabilities` | `list[Vulnerability]` | `field(...)` |
| `errors` | `list[str]` | `field(...)` |
| `os_family` | `str | None` | - |
| `os_version` | `str | None` | - |
| `architecture` | `str | None` | - |
| `image_size_bytes` | `int | None` | - |
| `skip_db_update` | `bool` | `False` |
| `ignore_unfixed` | `bool` | `False` |

### Properties

#### `success(self) -> bool`

Check if scan completed without errors.

**Returns:**

`bool`

#### `vulnerability_count(self) -> int`

Total number of vulnerabilities found.

**Returns:**

`int`

#### `critical_count(self) -> int`

Number of critical vulnerabilities.

**Returns:**

`int`

#### `high_count(self) -> int`

Number of high severity vulnerabilities.

**Returns:**

`int`

#### `medium_count(self) -> int`

Number of medium severity vulnerabilities.

**Returns:**

`int`

#### `low_count(self) -> int`

Number of low severity vulnerabilities.

**Returns:**

`int`

#### `fixable_count(self) -> int`

Number of vulnerabilities with available fixes.

**Returns:**

`int`

### Methods

#### `get_vulnerabilities_by_severity(self, severity: VulnerabilitySeverity) -> list[Vulnerability]`

Get vulnerabilities filtered by severity.

**Parameters:**

- `severity` (`VulnerabilitySeverity`)

**Returns:**

`list[Vulnerability]`

#### `get_vulnerabilities_by_package(self, package_name: str) -> list[Vulnerability]`

Get vulnerabilities for a specific package.

**Parameters:**

- `package_name` (`str`)

**Returns:**

`list[Vulnerability]`

#### `to_findings(self, asset_id: str | None) -> list[Finding]`

Convert all vulnerabilities to Stance Findings.

**Parameters:**

- `asset_id` (`str | None`)

**Returns:**

`list[Finding]`

#### `summary(self) -> dict[(str, Any)]`

Get a summary of scan results.

**Returns:**

`dict[(str, Any)]`

## ScannerError

**Inherits from:** Exception

Base exception for scanner errors.

## ScannerNotAvailableError

**Inherits from:** ScannerError

Raised when the scanner binary is not available.

## ScannerTimeoutError

**Inherits from:** ScannerError

Raised when a scan times out.

## ImageScanner

**Inherits from:** ABC

Abstract base class for container image scanners.

Implementations should wrap external scanning tools like Trivy or Grype
to provide vulnerability scanning for container images.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `scanner_name` | `str` | `unknown` |

### Methods

#### `is_available(self) -> bool`

**Decorators:** @abstractmethod

Check if the scanner is available on the system.

**Returns:**

`bool` - True if scanner is installed and functional

#### `get_version(self) -> str | None`

**Decorators:** @abstractmethod

Get the scanner version.

**Returns:**

`str | None` - Version string or None if not available

#### `scan(self, image_reference: str, timeout_seconds: int = 300, skip_db_update: bool = False, ignore_unfixed: bool = False) -> ScanResult`

**Decorators:** @abstractmethod

Scan a container image for vulnerabilities.

**Parameters:**

- `image_reference` (`str`) - Image to scan (e.g., nginx:latest, ghcr.io/org/app:v1)
- `timeout_seconds` (`int`) - default: `300` - Maximum time to wait for scan
- `skip_db_update` (`bool`) - default: `False` - Skip vulnerability database update
- `ignore_unfixed` (`bool`) - default: `False` - Exclude vulnerabilities without fixes

**Returns:**

`ScanResult` - ScanResult with vulnerabilities found

**Raises:**

- `ScannerNotAvailableError`: Scanner not installed
- `ScannerTimeoutError`: Scan exceeded timeout
- `ScannerError`: Other scanning errors

#### `scan_batch(self, image_references: list[str], timeout_seconds: int = 300, skip_db_update: bool = False, ignore_unfixed: bool = False, continue_on_error: bool = True) -> list[ScanResult]`

Scan multiple container images.

**Parameters:**

- `image_references` (`list[str]`) - List of images to scan
- `timeout_seconds` (`int`) - default: `300` - Maximum time per scan
- `skip_db_update` (`bool`) - default: `False` - Skip vulnerability database update
- `ignore_unfixed` (`bool`) - default: `False` - Exclude vulnerabilities without fixes
- `continue_on_error` (`bool`) - default: `True` - Continue scanning if one image fails

**Returns:**

`list[ScanResult]` - List of ScanResults (one per image)
