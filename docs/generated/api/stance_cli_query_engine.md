# stance.cli_query_engine

CLI commands for query engine operations.

Provides CLI access to the query module for:
- Executing SQL queries on cloud data warehouses (Athena, BigQuery, Synapse)
- Cost estimation before query execution
- Table schema introspection
- Listing available tables

## Contents

### Classes

- [_DemoQueryEngine](#_demoqueryengine)

### Functions

- [cmd_sql](#cmd_sql)
- [add_sql_parser](#add_sql_parser)

## _DemoQueryEngine

**Inherits from:** QueryEngine

Demo query engine for testing without cloud backends.

### Properties

#### `engine_name(self) -> str`

**Returns:**

`str`

#### `provider(self) -> str`

**Returns:**

`str`

### Methods

#### `connect(self) -> None`

**Returns:**

`None`

#### `disconnect(self) -> None`

**Returns:**

`None`

#### `execute_query(self, sql: str, parameters: dict[(str, Any)] | None, timeout_seconds: int = 300) -> QueryResult`

**Parameters:**

- `sql` (`str`)
- `parameters` (`dict[(str, Any)] | None`)
- `timeout_seconds` (`int`) - default: `300`

**Returns:**

`QueryResult`

#### `get_table_schema(self, table_name: str) -> TableSchema`

**Parameters:**

- `table_name` (`str`)

**Returns:**

`TableSchema`

#### `list_tables(self) -> list[str]`

**Returns:**

`list[str]`

#### `estimate_cost(self, sql: str) -> CostEstimate`

**Parameters:**

- `sql` (`str`)

**Returns:**

`CostEstimate`

### `cmd_sql(args: argparse.Namespace) -> int`

Handle sql subcommands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`

### `add_sql_parser(subparsers: argparse._SubParsersAction) -> None`

Add sql command parser.

**Parameters:**

- `subparsers` (`argparse._SubParsersAction`)

**Returns:**

`None`
