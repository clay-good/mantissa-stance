# stance.dspm.extended.snowflake

Snowflake Data Scanner for DSPM.

Scans Snowflake data warehouses to detect sensitive data using
read-only column sampling queries.

## Contents

### Classes

- [SnowflakeConfig](#snowflakeconfig)
- [SnowflakeColumnInfo](#snowflakecolumninfo)
- [SnowflakeTableInfo](#snowflaketableinfo)
- [SnowflakeScanner](#snowflakescanner)

### Functions

- [scan_snowflake](#scan_snowflake)

## SnowflakeConfig

**Tags:** dataclass

Configuration for Snowflake connection.

Attributes:
    account: Snowflake account identifier
    user: Username for authentication
    password: Password (use key_path for key-pair auth)
    warehouse: Warehouse to use for queries
    database: Default database
    schema: Default schema
    role: Role to use
    key_path: Path to private key file (for key-pair auth)
    key_passphrase: Passphrase for private key
    authenticator: Authentication method (snowflake, externalbrowser, etc.)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `account` | `str` | - |
| `user` | `str` | - |
| `password` | `str | None` | - |
| `warehouse` | `str` | `COMPUTE_WH` |
| `database` | `str | None` | - |
| `schema` | `str | None` | - |
| `role` | `str | None` | - |
| `key_path` | `str | None` | - |
| `key_passphrase` | `str | None` | - |
| `authenticator` | `str` | `snowflake` |

### Methods

#### `to_connection_params(self) -> dict[(str, Any)]`

Convert to snowflake connector parameters.

**Returns:**

`dict[(str, Any)]`

## SnowflakeColumnInfo

**Tags:** dataclass

Information about a Snowflake column.

Attributes:
    name: Column name
    data_type: Column data type
    is_nullable: Whether column allows nulls
    comment: Column comment
    sample_values: Sampled values from column

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `data_type` | `str` | - |
| `is_nullable` | `bool` | `True` |
| `comment` | `str | None` | - |
| `sample_values` | `list[Any]` | `field(...)` |

## SnowflakeTableInfo

**Tags:** dataclass

Information about a Snowflake table.

Attributes:
    database: Database name
    schema: Schema name
    name: Table name
    table_type: Type (TABLE, VIEW, etc.)
    row_count: Approximate row count
    bytes: Table size in bytes
    columns: List of columns
    comment: Table comment

### Attributes

| Name | Type | Default |
|------|------|---------|
| `database` | `str` | - |
| `schema` | `str` | - |
| `name` | `str` | - |
| `table_type` | `str` | `TABLE` |
| `row_count` | `int` | `0` |
| `bytes` | `int` | `0` |
| `columns` | `list[SnowflakeColumnInfo]` | `field(...)` |
| `comment` | `str | None` | - |

### Properties

#### `full_name(self) -> str`

Get fully qualified table name.

**Returns:**

`str`

## SnowflakeScanner

**Inherits from:** BaseExtendedScanner

Snowflake data warehouse scanner for sensitive data detection.

Samples data from Snowflake tables and columns to identify
PII, PCI, PHI, and other sensitive data patterns.

All operations are read-only using SELECT queries with LIMIT.

### Methods

#### `__init__(self, snowflake_config: SnowflakeConfig, scan_config: ExtendedScanConfig | None)`

Initialize Snowflake scanner.

**Parameters:**

- `snowflake_config` (`SnowflakeConfig`) - Snowflake connection configuration
- `scan_config` (`ExtendedScanConfig | None`) - Optional scan configuration

#### `test_connection(self) -> bool`

Test connection to Snowflake.

**Returns:**

`bool` - True if connection successful

#### `scan(self, target: str) -> ExtendedScanResult`

Scan a Snowflake database for sensitive data.

**Parameters:**

- `target` (`str`) - Database name to scan

**Returns:**

`ExtendedScanResult` - Scan result with findings and summary

#### `list_scannable_objects(self, target: str) -> list[dict[(str, Any)]]`

List tables that can be scanned in the database.

**Parameters:**

- `target` (`str`) - Database name

**Returns:**

`list[dict[(str, Any)]]` - List of table metadata dictionaries

#### `scan_table(self, database: str, schema: str, table_name: str) -> ExtendedScanResult`

Scan a specific table for sensitive data.

**Parameters:**

- `database` (`str`) - Database name
- `schema` (`str`) - Schema name
- `table_name` (`str`) - Table name

**Returns:**

`ExtendedScanResult` - Scan result with findings

### `scan_snowflake(snowflake_config: SnowflakeConfig, database: str, scan_config: ExtendedScanConfig | None) -> ExtendedScanResult`

Convenience function to scan a Snowflake database.

**Parameters:**

- `snowflake_config` (`SnowflakeConfig`) - Snowflake connection configuration
- `database` (`str`) - Database name to scan
- `scan_config` (`ExtendedScanConfig | None`) - Optional scan configuration

**Returns:**

`ExtendedScanResult` - Scan result with findings
