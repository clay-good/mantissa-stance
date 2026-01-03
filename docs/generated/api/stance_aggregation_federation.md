# stance.aggregation.federation

Federated query support for cross-cloud deployments.

Enables querying across multiple cloud backends with result merging
and cross-cloud correlation capabilities.

## Contents

### Classes

- [QueryStrategy](#querystrategy)
- [MergeStrategy](#mergestrategy)
- [BackendConfig](#backendconfig)
- [FederatedQueryResult](#federatedqueryresult)
- [FederatedQuery](#federatedquery)

## QueryStrategy

**Inherits from:** Enum

Strategy for executing federated queries.

## MergeStrategy

**Inherits from:** Enum

Strategy for merging results from multiple backends.

## BackendConfig

**Tags:** dataclass

Configuration for a query backend.

Attributes:
    name: Unique name for this backend
    engine: Query engine instance
    provider: Cloud provider (aws, gcp, azure)
    priority: Priority for PRIORITY merge (lower = higher priority)
    enabled: Whether this backend is active
    timeout_seconds: Query timeout for this backend
    metadata: Additional backend metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `engine` | `QueryEngine` | - |
| `provider` | `str` | - |
| `priority` | `int` | `0` |
| `enabled` | `bool` | `True` |
| `timeout_seconds` | `int` | `300` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

## FederatedQueryResult

**Tags:** dataclass

Result from a federated query across multiple backends.

Attributes:
    rows: Combined result rows
    columns: Column names
    row_count: Total number of rows
    backends_queried: Number of backends that were queried
    backends_succeeded: Number of backends that returned results
    backend_results: Individual results from each backend
    merge_strategy: Strategy used to merge results
    execution_time_ms: Total execution time
    errors: Errors from failed backends

### Attributes

| Name | Type | Default |
|------|------|---------|
| `rows` | `list[dict[(str, Any)]]` | - |
| `columns` | `list[str]` | - |
| `row_count` | `int` | `0` |
| `backends_queried` | `int` | `0` |
| `backends_succeeded` | `int` | `0` |
| `backend_results` | `dict[(str, QueryResult)]` | `field(...)` |
| `merge_strategy` | `MergeStrategy` | `"Attribute(value=Name(id='MergeStrategy', ctx=Load()), attr='UNION', ctx=Load())"` |
| `execution_time_ms` | `int` | `0` |
| `errors` | `dict[(str, str)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## FederatedQuery

Executes queries across multiple cloud backends.

Provides a unified query interface that can span AWS Athena,
GCP BigQuery, and Azure Synapse, with configurable merging
and correlation capabilities.

Example:
    >>> federation = FederatedQuery()
    >>> federation.add_backend(BackendConfig(
    ...     name="aws-prod",
    ...     engine=athena_engine,
    ...     provider="aws"
    ... ))
    >>> federation.add_backend(BackendConfig(
    ...     name="gcp-prod",
    ...     engine=bigquery_engine,
    ...     provider="gcp"
    ... ))
    >>> result = federation.query(
    ...     "SELECT * FROM findings WHERE severity = 'critical'",
    ...     merge_strategy=MergeStrategy.UNION
    ... )

### Methods

#### `__init__(self, max_workers: int = 5, default_timeout: int = 300) -> None`

Initialize federated query executor.

**Parameters:**

- `max_workers` (`int`) - default: `5` - Maximum concurrent queries
- `default_timeout` (`int`) - default: `300` - Default timeout for queries

**Returns:**

`None`

#### `add_backend(self, config: BackendConfig) -> None`

Add a query backend.

**Parameters:**

- `config` (`BackendConfig`) - Backend configuration

**Returns:**

`None`

#### `remove_backend(self, name: str) -> None`

Remove a query backend.

**Parameters:**

- `name` (`str`) - Backend name to remove

**Returns:**

`None`

#### `set_query_transformer(self, provider: str, transformer: Callable[([str], str)]) -> None`

Set a query transformer for a specific provider.  Query transformers adapt SQL syntax for different backends. For example, converting LIMIT/OFFSET syntax.

**Parameters:**

- `provider` (`str`) - Cloud provider (aws, gcp, azure)
- `transformer` (`Callable[([str], str)]`) - Function that transforms SQL

**Returns:**

`None`

#### `query(self, sql: str, backends: list[str] | None, strategy: QueryStrategy = "Attribute(value=Name(id='QueryStrategy', ctx=Load()), attr='PARALLEL', ctx=Load())", merge_strategy: MergeStrategy = "Attribute(value=Name(id='MergeStrategy', ctx=Load()), attr='UNION', ctx=Load())", parameters: dict[(str, Any)] | None) -> FederatedQueryResult`

Execute a query across configured backends.

**Parameters:**

- `sql` (`str`) - SQL query to execute
- `backends` (`list[str] | None`) - List of backend names to query (None = all enabled)
- `strategy` (`QueryStrategy`) - default: `"Attribute(value=Name(id='QueryStrategy', ctx=Load()), attr='PARALLEL', ctx=Load())"` - Execution strategy
- `merge_strategy` (`MergeStrategy`) - default: `"Attribute(value=Name(id='MergeStrategy', ctx=Load()), attr='UNION', ctx=Load())"` - Result merging strategy
- `parameters` (`dict[(str, Any)] | None`) - Query parameters

**Returns:**

`FederatedQueryResult` - FederatedQueryResult with merged results

#### `correlate(self, left_sql: str, right_sql: str, left_backend: str, right_backend: str, join_keys: list[str], correlation_type: str = inner) -> FederatedQueryResult`

Correlate results from two different backends.  Executes queries on two backends and joins results based on specified keys.

**Parameters:**

- `left_sql` (`str`) - SQL query for left side
- `right_sql` (`str`) - SQL query for right side
- `left_backend` (`str`) - Backend name for left query
- `right_backend` (`str`) - Backend name for right query
- `join_keys` (`list[str]`) - Column names to join on
- `correlation_type` (`str`) - default: `inner` - Join type (inner, left, right, full)

**Returns:**

`FederatedQueryResult` - FederatedQueryResult with correlated data

#### `get_backend_status(self) -> dict[(str, dict[(str, Any)])]`

Get status of all configured backends.

**Returns:**

`dict[(str, dict[(str, Any)])]`

#### `list_backends(self) -> list[str]`

List all backend names.

**Returns:**

`list[str]`

#### `disconnect_all(self) -> None`

Disconnect all backends.

**Returns:**

`None`
