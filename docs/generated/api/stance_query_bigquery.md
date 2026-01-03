# stance.query.bigquery

Google BigQuery query engine for Mantissa Stance.

Provides SQL query capabilities using BigQuery for querying
assets and findings stored in Cloud Storage.

## Contents

### Classes

- [BigQueryEngine](#bigqueryengine)

## Constants

### `BIGQUERY_PRICE_PER_TB_USD`

Type: `float`

Value: `6.25`

## BigQueryEngine

**Inherits from:** QueryEngine

Google BigQuery query engine implementation.

Uses BigQuery to query data stored in Cloud Storage or BigQuery
native tables. Supports cost tracking based on bytes processed.

Example:
    >>> engine = BigQueryEngine(
    ...     project_id="my-project",
    ...     dataset_id="stance_data"
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

#### `project_id(self) -> str`

Get the project ID.

**Returns:**

`str`

#### `dataset_id(self) -> str`

Get the dataset ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, dataset_id: str, location: str = US, credentials: Any | None) -> None`

Initialize the BigQuery query engine.

**Parameters:**

- `project_id` (`str`) - GCP project ID
- `dataset_id` (`str`) - BigQuery dataset ID
- `location` (`str`) - default: `US` - BigQuery location/region
- `credentials` (`Any | None`) - Optional google-auth credentials

**Returns:**

`None`

#### `connect(self) -> None`

Establish connection to BigQuery.

**Returns:**

`None`

#### `disconnect(self) -> None`

Close connection to BigQuery.

**Returns:**

`None`

#### `execute_query(self, sql: str, parameters: dict[(str, Any)] | None, timeout_seconds: int = 300) -> QueryResult`

Execute a SQL query using BigQuery.

**Parameters:**

- `sql` (`str`) - SQL query to execute
- `parameters` (`dict[(str, Any)] | None`) - Query parameters for parameterized queries
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

List all tables in the dataset.

**Returns:**

`list[str]` - List of table names

#### `estimate_cost(self, sql: str) -> CostEstimate`

Estimate the cost of a query using BigQuery dry run.  BigQuery supports dry runs that provide accurate byte estimates without actually executing the query.

**Parameters:**

- `sql` (`str`) - SQL query to estimate

**Returns:**

`CostEstimate` - CostEstimate with estimated bytes and cost

#### `run_scheduled_query(self, sql: str, schedule: str, destination_table: str, display_name: str) -> str`

Create a scheduled query in BigQuery.

**Parameters:**

- `sql` (`str`) - SQL query to schedule
- `schedule` (`str`) - Schedule in cron format
- `destination_table` (`str`) - Target table for results
- `display_name` (`str`) - Name for the scheduled query

**Returns:**

`str` - Scheduled query resource name
