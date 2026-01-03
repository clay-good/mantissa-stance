# stance.dspm.scanners.azure_blob

Azure Blob Storage Data Scanner for DSPM.

Scans Azure Blob containers to detect sensitive data using sampling
and pattern matching.

## Contents

### Classes

- [AzureBlobDataScanner](#azureblobdatascanner)

## AzureBlobDataScanner

**Inherits from:** BaseDataScanner

Azure Blob Storage scanner for sensitive data detection.

Samples blobs from Azure containers and scans content to identify
PII, PCI, PHI, and other sensitive data patterns.

All operations are read-only.

### Methods

#### `__init__(self, config: ScanConfig | None, connection_string: str | None, account_url: str | None, credential: Any | None)`

Initialize Azure Blob scanner.

**Parameters:**

- `config` (`ScanConfig | None`) - Optional scan configuration
- `connection_string` (`str | None`) - Azure Storage connection string
- `account_url` (`str | None`) - Storage account URL (alternative to connection_string)
- `credential` (`Any | None`) - Credential for authentication (used with account_url)

#### `scan_bucket(self, bucket_name: str) -> ScanResult`

Scan an Azure Blob container for sensitive data.

**Parameters:**

- `bucket_name` (`str`) - Name of the container (bucket_name used for API consistency)

**Returns:**

`ScanResult` - Scan result with findings and summary

#### `scan_object(self, bucket_name: str, object_key: str) -> ScanFinding | None`

Scan a specific Azure blob for sensitive data.

**Parameters:**

- `bucket_name` (`str`) - Container name
- `object_key` (`str`) - Blob name

**Returns:**

`ScanFinding | None` - ScanFinding if sensitive data found, None otherwise

#### `list_objects(self, bucket_name: str, prefix: str = ) -> Iterator[dict[(str, Any)]]`

List blobs in an Azure container.

**Parameters:**

- `bucket_name` (`str`) - Container name
- `prefix` (`str`) - default: `` - Optional prefix filter

**Returns:**

`Iterator[dict[(str, Any)]]`

#### `get_object_content(self, bucket_name: str, object_key: str, max_bytes: int | None) -> bytes | None`

Get Azure blob content (or sample).

**Parameters:**

- `bucket_name` (`str`) - Container name
- `object_key` (`str`) - Blob name
- `max_bytes` (`int | None`) - Maximum bytes to read

**Returns:**

`bytes | None` - Blob content as bytes

#### `get_bucket_metadata(self, bucket_name: str) -> dict[(str, Any)]`

Get Azure container metadata.

**Parameters:**

- `bucket_name` (`str`) - Container name

**Returns:**

`dict[(str, Any)]` - Container metadata including encryption, public access status

#### `get_storage_account_info(self) -> dict[(str, Any)]`

Get storage account information.

**Returns:**

`dict[(str, Any)]` - Storage account metadata

#### `list_containers(self) -> Iterator[dict[(str, Any)]]`

List all containers in the storage account.  Yields: Container metadata dictionaries

**Returns:**

`Iterator[dict[(str, Any)]]`
