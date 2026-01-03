# stance.dspm.extended.google_drive

Google Drive Data Scanner for DSPM.

Scans Google Drive files to detect sensitive data using
API-based file sampling.

## Contents

### Classes

- [GoogleDriveConfig](#googledriveconfig)
- [DriveFileInfo](#drivefileinfo)
- [GoogleDriveScanner](#googledrivescanner)

### Functions

- [scan_google_drive](#scan_google_drive)

## GoogleDriveConfig

**Tags:** dataclass

Configuration for Google Drive connection.

Attributes:
    service_account_file: Path to service account JSON file
    service_account_info: Service account info dict (alternative to file)
    delegated_user: User email to impersonate (for domain-wide delegation)
    scopes: OAuth scopes to request

### Attributes

| Name | Type | Default |
|------|------|---------|
| `service_account_file` | `str | None` | - |
| `service_account_info` | `dict[(str, Any)] | None` | - |
| `delegated_user` | `str | None` | - |
| `scopes` | `list[str]` | `field(...)` |

## DriveFileInfo

**Tags:** dataclass

Information about a Google Drive file.

Attributes:
    id: File ID
    name: File name
    mime_type: MIME type
    size: File size in bytes
    created_time: Creation timestamp
    modified_time: Last modified timestamp
    owners: List of owner email addresses
    shared: Whether file is shared
    web_view_link: Link to view file
    parents: Parent folder IDs

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `name` | `str` | - |
| `mime_type` | `str` | - |
| `size` | `int` | `0` |
| `created_time` | `datetime | None` | - |
| `modified_time` | `datetime | None` | - |
| `owners` | `list[str]` | `field(...)` |
| `shared` | `bool` | `False` |
| `web_view_link` | `str | None` | - |
| `parents` | `list[str]` | `field(...)` |

### Properties

#### `is_folder(self) -> bool`

Check if this is a folder.

**Returns:**

`bool`

#### `is_google_doc(self) -> bool`

Check if this is a Google Docs/Sheets/Slides file.

**Returns:**

`bool`

#### `extension(self) -> str`

Get file extension.

**Returns:**

`str`

## GoogleDriveScanner

**Inherits from:** BaseExtendedScanner

Google Drive scanner for sensitive data detection.

Samples files from Google Drive and scans content to identify
PII, PCI, PHI, and other sensitive data patterns.

All operations are read-only.

### Methods

#### `__init__(self, drive_config: GoogleDriveConfig, scan_config: ExtendedScanConfig | None)`

Initialize Google Drive scanner.

**Parameters:**

- `drive_config` (`GoogleDriveConfig`) - Google Drive connection configuration
- `scan_config` (`ExtendedScanConfig | None`) - Optional scan configuration

#### `test_connection(self) -> bool`

Test connection to Google Drive.

**Returns:**

`bool` - True if connection successful

#### `scan(self, target: str) -> ExtendedScanResult`

Scan a Google Drive folder for sensitive data.

**Parameters:**

- `target` (`str`) - Folder ID to scan (use 'root' for root folder)

**Returns:**

`ExtendedScanResult` - Scan result with findings and summary

#### `list_scannable_objects(self, target: str) -> list[dict[(str, Any)]]`

List files that can be scanned in the folder.

**Parameters:**

- `target` (`str`) - Folder ID

**Returns:**

`list[dict[(str, Any)]]` - List of file metadata dictionaries

#### `scan_file(self, file_id: str) -> ExtendedScanResult`

Scan a specific file for sensitive data.

**Parameters:**

- `file_id` (`str`) - File ID to scan

**Returns:**

`ExtendedScanResult` - Scan result with findings

### `scan_google_drive(drive_config: GoogleDriveConfig, folder_id: str = root, scan_config: ExtendedScanConfig | None) -> ExtendedScanResult`

Convenience function to scan a Google Drive folder.

**Parameters:**

- `drive_config` (`GoogleDriveConfig`) - Google Drive connection configuration
- `folder_id` (`str`) - default: `root` - Folder ID to scan (default: 'root')
- `scan_config` (`ExtendedScanConfig | None`) - Optional scan configuration

**Returns:**

`ExtendedScanResult` - Scan result with findings
