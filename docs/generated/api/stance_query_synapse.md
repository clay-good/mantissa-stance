# stance.query.synapse

Azure Synapse Analytics query engine for Mantissa Stance.

Provides SQL query capabilities using Azure Synapse serverless SQL pools
for querying assets and findings stored in Azure Data Lake Storage.

## Contents

### Classes

- [SynapseQueryEngine](#synapsequeryengine)

## Constants

### `SYNAPSE_PRICE_PER_TB_USD`

Type: `float`

Value: `5.0`

## SynapseQueryEngine

**Inherits from:** QueryEngine

Azure Synapse Analytics serverless SQL pool query engine.

Uses Synapse serverless SQL pools to query data stored in Azure
Data Lake Storage Gen2. Supports cost tracking based on data processed.

Example:
    >>> engine = SynapseQueryEngine(
    ...     server="myworkspace.sql.azuresynapse.net",
    ...     database="stance_db"
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

#### `server(self) -> str`

Get the server endpoint.

**Returns:**

`str`

#### `database(self) -> str`

Get the database name.

**Returns:**

`str`

### Methods

#### `__init__(self, server: str, database: str, credential: Any | None, connection_string: str | None) -> None`

Initialize the Synapse query engine.

**Parameters:**

- `server` (`str`) - Synapse serverless SQL endpoint (e.g., workspace.sql.azuresynapse.net)
- `database` (`str`) - Database name
- `credential` (`Any | None`) - Optional Azure credential (DefaultAzureCredential or similar)
- `connection_string` (`str | None`) - Optional full connection string (overrides server/database)

**Returns:**

`None`

#### `connect(self) -> None`

Establish connection to Synapse.

**Returns:**

`None`

#### `disconnect(self) -> None`

Close connection to Synapse.

**Returns:**

`None`

#### `execute_query(self, sql: str, parameters: dict[(str, Any)] | None, timeout_seconds: int = 300) -> QueryResult`

Execute a SQL query using Synapse serverless SQL pool.

**Parameters:**

- `sql` (`str`) - SQL query to execute
- `parameters` (`dict[(str, Any)] | None`) - Query parameters (named parameters with @name syntax)
- `timeout_seconds` (`int`) - default: `300` - Maximum time to wait for query completion

**Returns:**

`QueryResult` - QueryResult with rows and metadata

**Raises:**

- `QueryValidationError`: If query is not valid
- `QueryExecutionError`: If query execution fails

#### `get_table_schema(self, table_name: str) -> TableSchema`

Get schema information for a table.

**Parameters:**

- `table_name` (`str`) - Name of the table (can include schema prefix)

**Returns:**

`TableSchema` - TableSchema with column definitions

#### `list_tables(self) -> list[str]`

List all tables in the database.

**Returns:**

`list[str]` - List of table names (schema.table format)

#### `list_external_tables(self) -> list[str]`

List external tables pointing to Data Lake Storage.

**Returns:**

`list[str]` - List of external table names

#### `estimate_cost(self, sql: str) -> CostEstimate`

Estimate the cost of a query.  Synapse serverless doesn't provide pre-execution cost estimates like BigQuery's dry run. This provides a rough estimate based on table sizes referenced in the query.

**Parameters:**

- `sql` (`str`) - SQL query to estimate

**Returns:**

`CostEstimate` - CostEstimate with estimated bytes and cost

#### `create_external_table(self, table_name: str, data_source: str, location: str, file_format: str, columns: list[dict[(str, str)]], schema: str = dbo) -> None`

Create an external table pointing to Data Lake Storage.

**Parameters:**

- `table_name` (`str`) - Name of the table to create
- `data_source` (`str`) - Name of the external data source
- `location` (`str`) - Path within the data source (e.g., '/assets/')
- `file_format` (`str`) - File format name (e.g., 'ParquetFormat')
- `columns` (`list[dict[(str, str)]]`) - List of column definitions with 'name' and 'type'
- `schema` (`str`) - default: `dbo` - Schema name (default: dbo)

**Returns:**

`None`

#### `create_external_data_source(self, name: str, storage_account: str, container: str, credential: str | None) -> None`

Create an external data source for Azure Data Lake Storage.

**Parameters:**

- `name` (`str`) - Name of the data source
- `storage_account` (`str`) - Azure Storage account name
- `container` (`str`) - Container/filesystem name
- `credential` (`str | None`) - Optional database scoped credential name

**Returns:**

`None`

#### `create_file_format(self, name: str, format_type: str = PARQUET) -> None`

Create an external file format.

**Parameters:**

- `name` (`str`) - Name of the file format
- `format_type` (`str`) - default: `PARQUET` - Type of format (PARQUET, DELTA, CSV, JSON)

**Returns:**

`None`
