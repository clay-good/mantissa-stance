# stance.dspm.scanners.gcs

Google Cloud Storage Data Scanner for DSPM.

Scans GCS buckets to detect sensitive data using sampling and
pattern matching.

## Contents

### Classes

- [GCSDataScanner](#gcsdatascanner)

## GCSDataScanner

**Inherits from:** BaseDataScanner

Google Cloud Storage scanner for sensitive data detection.

Samples objects from GCS buckets and scans content to identify
PII, PCI, PHI, and other sensitive data patterns.

All operations are read-only.

### Methods

#### `__init__(self, config: ScanConfig | None, project: str | None, credentials: Any | None)`

Initialize GCS scanner.

**Parameters:**

- `config` (`ScanConfig | None`) - Optional scan configuration
- `project` (`str | None`) - GCP project ID
- `credentials` (`Any | None`) - Optional credentials object

#### `scan_bucket(self, bucket_name: str) -> ScanResult`

Scan a GCS bucket for sensitive data.

**Parameters:**

- `bucket_name` (`str`) - Name of the GCS bucket

**Returns:**

`ScanResult` - Scan result with findings and summary

#### `scan_object(self, bucket_name: str, object_key: str) -> ScanFinding | None`

Scan a specific GCS object for sensitive data.

**Parameters:**

- `bucket_name` (`str`) - GCS bucket name
- `object_key` (`str`) - Object name/key

**Returns:**

`ScanFinding | None` - ScanFinding if sensitive data found, None otherwise

#### `list_objects(self, bucket_name: str, prefix: str = ) -> Iterator[dict[(str, Any)]]`

List objects in a GCS bucket.

**Parameters:**

- `bucket_name` (`str`) - GCS bucket name
- `prefix` (`str`) - default: `` - Optional prefix filter

**Returns:**

`Iterator[dict[(str, Any)]]`

#### `get_object_content(self, bucket_name: str, object_key: str, max_bytes: int | None) -> bytes | None`

Get GCS object content (or sample).

**Parameters:**

- `bucket_name` (`str`) - GCS bucket name
- `object_key` (`str`) - Object name
- `max_bytes` (`int | None`) - Maximum bytes to read

**Returns:**

`bytes | None` - Object content as bytes

#### `get_bucket_metadata(self, bucket_name: str) -> dict[(str, Any)]`

Get GCS bucket metadata.

**Parameters:**

- `bucket_name` (`str`) - GCS bucket name

**Returns:**

`dict[(str, Any)]` - Bucket metadata including encryption, public access status

#### `get_bucket_location(self, bucket_name: str) -> str`

Get the location where a bucket is stored.

**Parameters:**

- `bucket_name` (`str`) - GCS bucket name

**Returns:**

`str` - GCS location (e.g., US, EU, us-central1)
