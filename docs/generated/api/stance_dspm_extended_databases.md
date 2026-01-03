# stance.dspm.extended.databases

Database Scanners for DSPM.

Scans relational databases (RDS, Cloud SQL, Azure SQL) to detect
sensitive data using read-only column sampling queries.

## Contents

### Classes

- [DatabaseType](#databasetype)
- [DatabaseConfig](#databaseconfig)
- [ColumnInfo](#columninfo)
- [TableInfo](#tableinfo)
- [DatabaseScanner](#databasescanner)
- [RDSScanner](#rdsscanner)
- [CloudSQLScanner](#cloudsqlscanner)
- [AzureSQLScanner](#azuresqlscanner)

### Functions

- [scan_database](#scan_database)

## DatabaseType

**Inherits from:** Enum

Supported database types.

## DatabaseConfig

**Tags:** dataclass

Configuration for database connection.

Attributes:
    host: Database host
    port: Database port
    database: Database name
    user: Username
    password: Password
    db_type: Database type
    ssl_mode: SSL mode (disable, require, verify-ca, verify-full)
    ssl_ca: Path to CA certificate
    connect_timeout: Connection timeout in seconds

### Attributes

| Name | Type | Default |
|------|------|---------|
| `host` | `str` | - |
| `port` | `int` | - |
| `database` | `str` | - |
| `user` | `str` | - |
| `password` | `str` | - |
| `db_type` | `DatabaseType` | `"Attribute(value=Name(id='DatabaseType', ctx=Load()), attr='POSTGRESQL', ctx=Load())"` |
| `ssl_mode` | `str` | `prefer` |
| `ssl_ca` | `str | None` | - |
| `connect_timeout` | `int` | `30` |

### Properties

#### `port_default(self) -> int`

Get default port for database type.

**Returns:**

`int`

## ColumnInfo

**Tags:** dataclass

Information about a database column.

Attributes:
    name: Column name
    data_type: Column data type
    is_nullable: Whether column allows nulls
    max_length: Maximum length for string columns
    is_primary_key: Whether column is part of primary key
    sample_values: Sampled values from column

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `data_type` | `str` | - |
| `is_nullable` | `bool` | `True` |
| `max_length` | `int | None` | - |
| `is_primary_key` | `bool` | `False` |
| `sample_values` | `list[Any]` | `field(...)` |

## TableInfo

**Tags:** dataclass

Information about a database table.

Attributes:
    schema: Schema name
    name: Table name
    table_type: Type (TABLE, VIEW)
    row_count: Approximate row count
    columns: List of columns

### Attributes

| Name | Type | Default |
|------|------|---------|
| `schema` | `str` | - |
| `name` | `str` | - |
| `table_type` | `str` | `TABLE` |
| `row_count` | `int` | `0` |
| `columns` | `list[ColumnInfo]` | `field(...)` |

### Properties

#### `full_name(self) -> str`

Get fully qualified table name.

**Returns:**

`str`

## DatabaseScanner

**Inherits from:** BaseExtendedScanner

Base database scanner for sensitive data detection.

Samples data from database tables and columns to identify
PII, PCI, PHI, and other sensitive data patterns.

All operations are read-only using SELECT queries with LIMIT.

### Methods

#### `__init__(self, db_config: DatabaseConfig, scan_config: ExtendedScanConfig | None)`

Initialize database scanner.

**Parameters:**

- `db_config` (`DatabaseConfig`) - Database connection configuration
- `scan_config` (`ExtendedScanConfig | None`) - Optional scan configuration

#### `test_connection(self) -> bool`

Test connection to the database.

**Returns:**

`bool` - True if connection successful

#### `scan(self, target: str) -> ExtendedScanResult`

Scan a database for sensitive data.

**Parameters:**

- `target` (`str`) - Database identifier (used for logging)

**Returns:**

`ExtendedScanResult` - Scan result with findings and summary

#### `list_scannable_objects(self, target: str) -> list[dict[(str, Any)]]`

List tables that can be scanned.

**Parameters:**

- `target` (`str`) - Database identifier (unused, for interface compliance)

**Returns:**

`list[dict[(str, Any)]]` - List of table metadata dictionaries

## RDSScanner

**Inherits from:** DatabaseScanner

AWS RDS database scanner.

Supports PostgreSQL and MySQL databases on AWS RDS.

### Methods

#### `__init__(self, db_config: DatabaseConfig, scan_config: ExtendedScanConfig | None)`

Initialize RDS scanner.

**Parameters:**

- `db_config` (`DatabaseConfig`) - Database connection configuration
- `scan_config` (`ExtendedScanConfig | None`) - Optional scan configuration

## CloudSQLScanner

**Inherits from:** DatabaseScanner

Google Cloud SQL database scanner.

Supports PostgreSQL and MySQL databases on Cloud SQL.
Uses the same implementation as RDSScanner.

### Methods

#### `__init__(self, db_config: DatabaseConfig, scan_config: ExtendedScanConfig | None)`

Initialize Cloud SQL scanner.

**Parameters:**

- `db_config` (`DatabaseConfig`) - Database connection configuration
- `scan_config` (`ExtendedScanConfig | None`) - Optional scan configuration

## AzureSQLScanner

**Inherits from:** DatabaseScanner

Azure SQL Database scanner.

Supports Azure SQL Database and Azure SQL Managed Instance.

### Methods

#### `__init__(self, db_config: DatabaseConfig, scan_config: ExtendedScanConfig | None)`

Initialize Azure SQL scanner.

**Parameters:**

- `db_config` (`DatabaseConfig`) - Database connection configuration
- `scan_config` (`ExtendedScanConfig | None`) - Optional scan configuration

### `scan_database(db_config: DatabaseConfig, scan_config: ExtendedScanConfig | None) -> ExtendedScanResult`

Convenience function to scan a database.  Automatically selects the appropriate scanner based on database type.

**Parameters:**

- `db_config` (`DatabaseConfig`) - Database connection configuration
- `scan_config` (`ExtendedScanConfig | None`) - Optional scan configuration

**Returns:**

`ExtendedScanResult` - Scan result with findings
