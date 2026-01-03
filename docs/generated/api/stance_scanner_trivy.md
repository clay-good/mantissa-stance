# stance.scanner.trivy

Trivy scanner implementation.

Provides container image vulnerability scanning using Trivy.
Trivy is an open source vulnerability scanner for containers and
other artifacts.

https://github.com/aquasecurity/trivy

## Contents

### Classes

- [TrivyScanner](#trivyscanner)

### Functions

- [scan_image](#scan_image)
- [scan_images](#scan_images)

## TrivyScanner

**Inherits from:** ImageScanner

Container image scanner using Trivy.

Trivy is a comprehensive vulnerability scanner that supports:
- Container images
- Filesystems
- Git repositories
- Kubernetes clusters

This implementation focuses on container image scanning.

Installation:
    brew install trivy
    # or
    apt-get install trivy
    # or
    docker run aquasec/trivy image <image>

Usage:
    scanner = TrivyScanner()
    if scanner.is_available():
        result = scanner.scan("nginx:latest")
        print(f"Found {result.vulnerability_count} vulnerabilities")

### Attributes

| Name | Type | Default |
|------|------|---------|
| `scanner_name` | `str` | `trivy` |

### Methods

#### `__init__(self, trivy_path: str | None, cache_dir: str | None)`

Initialize TrivyScanner.

**Parameters:**

- `trivy_path` (`str | None`) - Path to trivy binary (auto-detected if None)
- `cache_dir` (`str | None`) - Directory for Trivy cache (uses default if None)

#### `is_available(self) -> bool`

Check if Trivy is available on the system.

**Returns:**

`bool`

#### `get_version(self) -> str | None`

Get the Trivy version.

**Returns:**

`str | None`

#### `scan(self, image_reference: str, timeout_seconds: int = 300, skip_db_update: bool = False, ignore_unfixed: bool = False) -> ScanResult`

Scan a container image using Trivy.

**Parameters:**

- `image_reference` (`str`) - Image to scan (e.g., nginx:latest)
- `timeout_seconds` (`int`) - default: `300` - Maximum time to wait for scan
- `skip_db_update` (`bool`) - default: `False` - Skip vulnerability database update
- `ignore_unfixed` (`bool`) - default: `False` - Exclude vulnerabilities without fixes

**Returns:**

`ScanResult` - ScanResult with vulnerabilities found

### `scan_image(image_reference: str, timeout_seconds: int = 300, skip_db_update: bool = False, ignore_unfixed: bool = False) -> ScanResult`

Convenience function to scan a single image with Trivy.

**Parameters:**

- `image_reference` (`str`) - Image to scan (e.g., nginx:latest)
- `timeout_seconds` (`int`) - default: `300` - Maximum time to wait for scan
- `skip_db_update` (`bool`) - default: `False` - Skip vulnerability database update
- `ignore_unfixed` (`bool`) - default: `False` - Exclude vulnerabilities without fixes

**Returns:**

`ScanResult` - ScanResult with vulnerabilities found

**Examples:**

```python
>>> result = scan_image("nginx:1.21")
    >>> print(f"Found {result.vulnerability_count} vulnerabilities")
    >>> for v in result.get_vulnerabilities_by_severity(VulnerabilitySeverity.CRITICAL):
    ...     print(f"  {v.vulnerability_id}: {v.package_name}")
```

### `scan_images(image_references: list[str], timeout_seconds: int = 300, skip_db_update: bool = False, ignore_unfixed: bool = False, continue_on_error: bool = True) -> list[ScanResult]`

Convenience function to scan multiple images with Trivy.

**Parameters:**

- `image_references` (`list[str]`) - List of images to scan
- `timeout_seconds` (`int`) - default: `300` - Maximum time per scan
- `skip_db_update` (`bool`) - default: `False` - Skip vulnerability database update
- `ignore_unfixed` (`bool`) - default: `False` - Exclude vulnerabilities without fixes
- `continue_on_error` (`bool`) - default: `True` - Continue scanning if one image fails

**Returns:**

`list[ScanResult]` - List of ScanResults (one per image)
