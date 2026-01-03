# stance.dspm.scanners.s3

AWS S3 Data Scanner for DSPM.

Scans S3 buckets to detect sensitive data using sampling and
pattern matching.

## Contents

### Classes

- [S3DataScanner](#s3datascanner)

## S3DataScanner

**Inherits from:** BaseDataScanner

AWS S3 storage scanner for sensitive data detection.

Samples objects from S3 buckets and scans content to identify
PII, PCI, PHI, and other sensitive data patterns.

All operations are read-only.

### Methods

#### `__init__(self, config: ScanConfig | None, session: Any | None, region: str = us-east-1)`

Initialize S3 scanner.

**Parameters:**

- `config` (`ScanConfig | None`) - Optional scan configuration
- `session` (`Any | None`) - Optional boto3 Session
- `region` (`str`) - default: `us-east-1` - AWS region

#### `scan_bucket(self, bucket_name: str) -> ScanResult`

Scan an S3 bucket for sensitive data.

**Parameters:**

- `bucket_name` (`str`) - Name of the S3 bucket

**Returns:**

`ScanResult` - Scan result with findings and summary

#### `scan_object(self, bucket_name: str, object_key: str) -> ScanFinding | None`

Scan a specific S3 object for sensitive data.

**Parameters:**

- `bucket_name` (`str`) - S3 bucket name
- `object_key` (`str`) - Object key

**Returns:**

`ScanFinding | None` - ScanFinding if sensitive data found, None otherwise

#### `list_objects(self, bucket_name: str, prefix: str = ) -> Iterator[dict[(str, Any)]]`

List objects in an S3 bucket.

**Parameters:**

- `bucket_name` (`str`) - S3 bucket name
- `prefix` (`str`) - default: `` - Optional prefix filter

**Returns:**

`Iterator[dict[(str, Any)]]`

#### `get_object_content(self, bucket_name: str, object_key: str, max_bytes: int | None) -> bytes | None`

Get S3 object content (or sample).

**Parameters:**

- `bucket_name` (`str`) - S3 bucket name
- `object_key` (`str`) - Object key
- `max_bytes` (`int | None`) - Maximum bytes to read

**Returns:**

`bytes | None` - Object content as bytes

#### `get_bucket_metadata(self, bucket_name: str) -> dict[(str, Any)]`

Get S3 bucket metadata.

**Parameters:**

- `bucket_name` (`str`) - S3 bucket name

**Returns:**

`dict[(str, Any)]` - Bucket metadata including encryption, public access status

#### `get_bucket_location(self, bucket_name: str) -> str`

Get the region where a bucket is located.

**Parameters:**

- `bucket_name` (`str`) - S3 bucket name

**Returns:**

`str` - AWS region name
