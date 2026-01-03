# stance.query.base

Base query engine for Mantissa Stance.

Provides abstract interface for cloud-native query engines (Athena, BigQuery, Synapse).
All implementations are read-only and support only SELECT queries.

## Contents

### Classes

- [QueryResult](#queryresult)
- [TableSchema](#tableschema)
- [CostEstimate](#costestimate)
- [QueryValidationError](#queryvalidationerror)
- [QueryExecutionError](#queryexecutionerror)
- [QueryEngine](#queryengine)

### Functions

- [get_common_schemas](#get_common_schemas)

## Constants

### `ASSETS_SCHEMA`

Type: `str`

Value: `TableSchema(...)`

### `FINDINGS_SCHEMA`

Type: `str`

Value: `TableSchema(...)`

## QueryResult

**Tags:** dataclass

Result from a query execution.

Attributes:
    rows: List of result rows as dictionaries
    columns: List of column names
    row_count: Number of rows returned
    bytes_scanned: Bytes scanned (for cost tracking)
    execution_time_ms: Query execution time in milliseconds
    query_id: Unique identifier for the query execution
    metadata: Additional provider-specific metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `rows` | `list[dict[(str, Any)]]` | - |
| `columns` | `list[str]` | - |
| `row_count` | `int` | - |
| `bytes_scanned` | `int` | `0` |
| `execution_time_ms` | `int` | `0` |
| `query_id` | `str` | `` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_list(self) -> list[dict[(str, Any)]]`

Return rows as list of dictionaries.

**Returns:**

`list[dict[(str, Any)]]`

#### `to_dict(self) -> dict[(str, Any)]`

Return full result as dictionary.

**Returns:**

`dict[(str, Any)]`

## TableSchema

**Tags:** dataclass

Schema information for a table.

Attributes:
    table_name: Name of the table
    columns: List of column definitions
    description: Table description
    row_count: Estimated row count (if available)
    size_bytes: Estimated size in bytes (if available)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `table_name` | `str` | - |
| `columns` | `list[dict[(str, Any)]]` | - |
| `description` | `str` | `` |
| `row_count` | `int | None` | - |
| `size_bytes` | `int | None` | - |

### Methods

#### `get_column_names(self) -> list[str]`

Get list of column names.

**Returns:**

`list[str]`

#### `get_column_types(self) -> dict[(str, str)]`

Get mapping of column names to types.

**Returns:**

`dict[(str, str)]`

## CostEstimate

**Tags:** dataclass

Estimated cost for a query.

Attributes:
    estimated_bytes: Estimated bytes to be scanned
    estimated_cost_usd: Estimated cost in USD
    warnings: List of warnings about the query

### Attributes

| Name | Type | Default |
|------|------|---------|
| `estimated_bytes` | `int` | `0` |
| `estimated_cost_usd` | `float` | `0.0` |
| `warnings` | `list[str]` | `field(...)` |

## QueryValidationError

**Inherits from:** Exception

Raised when a query fails validation.

## QueryExecutionError

**Inherits from:** Exception

Raised when a query fails execution.

## QueryEngine

**Inherits from:** ABC

Abstract base class for cloud-native query engines.

All implementations must be read-only and support only SELECT queries.
This provides a unified interface for querying assets and findings
stored in cloud-native data warehouses.

### Properties

#### `engine_name(self) -> str`

**Decorators:** @property, @abstractmethod

Return the name of this query engine.

**Returns:**

`str`

#### `provider(self) -> str`

**Decorators:** @property, @abstractmethod

Return the cloud provider (aws, gcp, azure).

**Returns:**

`str`

### Methods

#### `__init__(self) -> None`

Initialize the query engine.

**Returns:**

`None`

#### `connect(self) -> None`

**Decorators:** @abstractmethod

Establish connection to the query engine.

**Returns:**

`None`

**Raises:**

- `QueryExecutionError`: If connection fails

#### `disconnect(self) -> None`

**Decorators:** @abstractmethod

Close connection to the query engine.

**Returns:**

`None`

#### `execute_query(self, sql: str, parameters: dict[(str, Any)] | None, timeout_seconds: int = 300) -> QueryResult`

**Decorators:** @abstractmethod

Execute a SQL query and return results.

**Parameters:**

- `sql` (`str`) - SQL query to execute (must be SELECT only)
- `parameters` (`dict[(str, Any)] | None`) - Optional query parameters for parameterized queries
- `timeout_seconds` (`int`) - default: `300` - Maximum time to wait for query completion

**Returns:**

`QueryResult` - QueryResult with rows and metadata

**Raises:**

- `QueryValidationError`: If query is not valid (e.g., not SELECT)
- `QueryExecutionError`: If query execution fails

#### `get_table_schema(self, table_name: str) -> TableSchema`

**Decorators:** @abstractmethod

Get schema information for a table.

**Parameters:**

- `table_name` (`str`) - Name of the table

**Returns:**

`TableSchema` - TableSchema with column definitions

**Raises:**

- `QueryExecutionError`: If table does not exist

#### `list_tables(self) -> list[str]`

**Decorators:** @abstractmethod

List all available tables.

**Returns:**

`list[str]` - List of table names

#### `estimate_cost(self, sql: str) -> CostEstimate`

**Decorators:** @abstractmethod

Estimate the cost of a query before execution.

**Parameters:**

- `sql` (`str`) - SQL query to estimate

**Returns:**

`CostEstimate` - CostEstimate with bytes and cost estimation

#### `validate_query(self, sql: str) -> list[str]`

Validate that a query is safe to execute.  Checks: - Query starts with SELECT - No forbidden keywords (INSERT, UPDATE, DELETE, etc.) - No SQL comments that could hide malicious code - No multiple statements (semicolons)

**Parameters:**

- `sql` (`str`) - SQL query to validate

**Returns:**

`list[str]` - List of validation errors (empty if valid)

#### `execute_safe(self, sql: str, parameters: dict[(str, Any)] | None, timeout_seconds: int = 300) -> QueryResult`

Execute a query with validation.  This is the recommended method for executing queries as it validates the query before execution.

**Parameters:**

- `sql` (`str`) - SQL query to execute
- `parameters` (`dict[(str, Any)] | None`) - Optional query parameters
- `timeout_seconds` (`int`) - default: `300` - Maximum time to wait

**Returns:**

`QueryResult` - QueryResult with rows and metadata

**Raises:**

- `QueryValidationError`: If query fails validation
- `QueryExecutionError`: If query execution fails

#### `is_connected(self) -> bool`

Check if the engine is connected.

**Returns:**

`bool`

### `get_common_schemas() -> dict[(str, TableSchema)]`

Get common table schemas for Stance data.

**Returns:**

`dict[(str, TableSchema)]`
