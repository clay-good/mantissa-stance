# stance.query.athena

AWS Athena query engine for Mantissa Stance.

Provides SQL query capabilities using AWS Athena for querying
assets and findings stored in S3.

## Contents

### Classes

- [AthenaQueryEngine](#athenaqueryengine)

## Constants

### `ATHENA_PRICE_PER_TB_USD`

Type: `float`

Value: `5.0`

## AthenaQueryEngine

**Inherits from:** QueryEngine

AWS Athena query engine implementation.

Uses Athena to query data stored in S3. Supports cost tracking
based on bytes scanned.

Example:
    >>> engine = AthenaQueryEngine(
    ...     database="stance_data",
    ...     workgroup="stance-workgroup",
    ...     output_location="s3://bucket/athena-results/"
    ... )
    >>> with engine:
    ...     result = engine.execute_safe("SELECT * FROM assets LIMIT 10")
    ...     print(f"Found {result.row_count} assets")

### Properties

#### `engine_name(self) -> str`

Return the name of this query engine.

**Returns:**

`str`

#### `provider(self) -> str`

Return the cloud provider.

**Returns:**

`str`

#### `database(self) -> str`

Get the database name.

**Returns:**

`str`

#### `workgroup(self) -> str`

Get the workgroup name.

**Returns:**

`str`

### Methods

#### `__init__(self, database: str, workgroup: str = primary, output_location: str | None, region: str = us-east-1, session: Any | None) -> None`

Initialize the Athena query engine.

**Parameters:**

- `database` (`str`) - Athena/Glue database name
- `workgroup` (`str`) - default: `primary` - Athena workgroup name
- `output_location` (`str | None`) - S3 location for query results
- `region` (`str`) - default: `us-east-1` - AWS region
- `session` (`Any | None`) - Optional boto3 session

**Returns:**

`None`

#### `connect(self) -> None`

Establish connection to Athena.

**Returns:**

`None`

#### `disconnect(self) -> None`

Close connection to Athena.

**Returns:**

`None`

#### `execute_query(self, sql: str, parameters: dict[(str, Any)] | None, timeout_seconds: int = 300) -> QueryResult`

Execute a SQL query using Athena.

**Parameters:**

- `sql` (`str`) - SQL query to execute
- `parameters` (`dict[(str, Any)] | None`) - Not supported by Athena (ignored)
- `timeout_seconds` (`int`) - default: `300` - Maximum time to wait for query completion

**Returns:**

`QueryResult` - QueryResult with rows and metadata

**Raises:**

- `QueryValidationError`: If query is not valid
- `QueryExecutionError`: If query execution fails

#### `get_table_schema(self, table_name: str) -> TableSchema`

Get schema information for a table.

**Parameters:**

- `table_name` (`str`) - Name of the table

**Returns:**

`TableSchema` - TableSchema with column definitions

#### `list_tables(self) -> list[str]`

List all tables in the database.

**Returns:**

`list[str]` - List of table names

#### `estimate_cost(self, sql: str) -> CostEstimate`

Estimate the cost of a query.  Note: Athena doesn't provide pre-execution cost estimates. This method provides a rough estimate based on table sizes.

**Parameters:**

- `sql` (`str`) - SQL query to estimate

**Returns:**

`CostEstimate` - CostEstimate with estimated bytes and cost
