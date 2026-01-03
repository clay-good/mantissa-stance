"""
Federated query support for cross-cloud deployments.

Enables querying across multiple cloud backends with result merging
and cross-cloud correlation capabilities.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable

from stance.query.base import QueryEngine, QueryResult, QueryExecutionError

logger = logging.getLogger(__name__)


class QueryStrategy(Enum):
    """Strategy for executing federated queries."""

    PARALLEL = "parallel"  # Execute on all backends in parallel
    SEQUENTIAL = "sequential"  # Execute one at a time
    FIRST_SUCCESS = "first_success"  # Return first successful result
    BEST_EFFORT = "best_effort"  # Return whatever succeeds


class MergeStrategy(Enum):
    """Strategy for merging results from multiple backends."""

    UNION = "union"  # Combine all rows
    UNION_DISTINCT = "union_distinct"  # Combine and deduplicate
    INTERSECT = "intersect"  # Only rows present in all backends
    PRIORITY = "priority"  # Use priority order, fallback if empty


@dataclass
class BackendConfig:
    """
    Configuration for a query backend.

    Attributes:
        name: Unique name for this backend
        engine: Query engine instance
        provider: Cloud provider (aws, gcp, azure)
        priority: Priority for PRIORITY merge (lower = higher priority)
        enabled: Whether this backend is active
        timeout_seconds: Query timeout for this backend
        metadata: Additional backend metadata
    """

    name: str
    engine: QueryEngine
    provider: str
    priority: int = 0
    enabled: bool = True
    timeout_seconds: int = 300
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FederatedQueryResult:
    """
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
    """

    rows: list[dict[str, Any]]
    columns: list[str]
    row_count: int = 0
    backends_queried: int = 0
    backends_succeeded: int = 0
    backend_results: dict[str, QueryResult] = field(default_factory=dict)
    merge_strategy: MergeStrategy = MergeStrategy.UNION
    execution_time_ms: int = 0
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "rows": self.rows,
            "columns": self.columns,
            "row_count": self.row_count,
            "backends_queried": self.backends_queried,
            "backends_succeeded": self.backends_succeeded,
            "merge_strategy": self.merge_strategy.value,
            "execution_time_ms": self.execution_time_ms,
            "errors": self.errors,
            "backend_details": {
                name: {
                    "row_count": result.row_count,
                    "bytes_scanned": result.bytes_scanned,
                    "execution_time_ms": result.execution_time_ms,
                }
                for name, result in self.backend_results.items()
            },
        }


class FederatedQuery:
    """
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
    """

    def __init__(
        self,
        max_workers: int = 5,
        default_timeout: int = 300,
    ) -> None:
        """
        Initialize federated query executor.

        Args:
            max_workers: Maximum concurrent queries
            default_timeout: Default timeout for queries
        """
        self._backends: dict[str, BackendConfig] = {}
        self._max_workers = max_workers
        self._default_timeout = default_timeout
        self._query_transformers: dict[str, Callable[[str], str]] = {}

    def add_backend(self, config: BackendConfig) -> None:
        """
        Add a query backend.

        Args:
            config: Backend configuration
        """
        self._backends[config.name] = config
        logger.info(f"Added backend: {config.name} ({config.provider})")

    def remove_backend(self, name: str) -> None:
        """
        Remove a query backend.

        Args:
            name: Backend name to remove
        """
        if name in self._backends:
            del self._backends[name]
            logger.info(f"Removed backend: {name}")

    def set_query_transformer(
        self,
        provider: str,
        transformer: Callable[[str], str],
    ) -> None:
        """
        Set a query transformer for a specific provider.

        Query transformers adapt SQL syntax for different backends.
        For example, converting LIMIT/OFFSET syntax.

        Args:
            provider: Cloud provider (aws, gcp, azure)
            transformer: Function that transforms SQL
        """
        self._query_transformers[provider] = transformer

    def query(
        self,
        sql: str,
        backends: list[str] | None = None,
        strategy: QueryStrategy = QueryStrategy.PARALLEL,
        merge_strategy: MergeStrategy = MergeStrategy.UNION,
        parameters: dict[str, Any] | None = None,
    ) -> FederatedQueryResult:
        """
        Execute a query across configured backends.

        Args:
            sql: SQL query to execute
            backends: List of backend names to query (None = all enabled)
            strategy: Execution strategy
            merge_strategy: Result merging strategy
            parameters: Query parameters

        Returns:
            FederatedQueryResult with merged results
        """
        start_time = datetime.utcnow()

        # Determine backends to query
        target_backends = self._get_target_backends(backends)
        if not target_backends:
            return FederatedQueryResult(
                rows=[],
                columns=[],
                errors={"federation": "No backends available"},
            )

        # Execute queries based on strategy
        if strategy == QueryStrategy.PARALLEL:
            backend_results = self._execute_parallel(sql, target_backends, parameters)
        elif strategy == QueryStrategy.SEQUENTIAL:
            backend_results = self._execute_sequential(sql, target_backends, parameters)
        elif strategy == QueryStrategy.FIRST_SUCCESS:
            backend_results = self._execute_first_success(sql, target_backends, parameters)
        else:  # BEST_EFFORT
            backend_results = self._execute_best_effort(sql, target_backends, parameters)

        # Merge results
        merged = self._merge_results(backend_results, merge_strategy)

        # Calculate execution time
        execution_time_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        # Collect errors
        errors = {
            name: str(result.metadata.get("error", ""))
            for name, result in backend_results.items()
            if result.metadata.get("error")
        }

        return FederatedQueryResult(
            rows=merged["rows"],
            columns=merged["columns"],
            row_count=len(merged["rows"]),
            backends_queried=len(target_backends),
            backends_succeeded=len(backend_results) - len(errors),
            backend_results=backend_results,
            merge_strategy=merge_strategy,
            execution_time_ms=execution_time_ms,
            errors=errors,
        )

    def _get_target_backends(
        self, backend_names: list[str] | None
    ) -> list[BackendConfig]:
        """Get list of backends to query."""
        if backend_names:
            return [
                self._backends[name]
                for name in backend_names
                if name in self._backends and self._backends[name].enabled
            ]
        else:
            return [b for b in self._backends.values() if b.enabled]

    def _transform_sql(self, sql: str, provider: str) -> str:
        """Transform SQL for specific provider if transformer exists."""
        if provider in self._query_transformers:
            return self._query_transformers[provider](sql)
        return sql

    def _execute_parallel(
        self,
        sql: str,
        backends: list[BackendConfig],
        parameters: dict[str, Any] | None,
    ) -> dict[str, QueryResult]:
        """Execute queries on all backends in parallel."""
        results: dict[str, QueryResult] = {}

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {
                executor.submit(
                    self._execute_single,
                    sql,
                    backend,
                    parameters,
                ): backend.name
                for backend in backends
            }

            for future in as_completed(futures):
                backend_name = futures[future]
                try:
                    result = future.result()
                    results[backend_name] = result
                except Exception as e:
                    logger.error(f"Query failed on {backend_name}: {e}")
                    results[backend_name] = QueryResult(
                        rows=[],
                        columns=[],
                        row_count=0,
                        metadata={"error": str(e)},
                    )

        return results

    def _execute_sequential(
        self,
        sql: str,
        backends: list[BackendConfig],
        parameters: dict[str, Any] | None,
    ) -> dict[str, QueryResult]:
        """Execute queries on backends one at a time."""
        results: dict[str, QueryResult] = {}

        for backend in backends:
            try:
                result = self._execute_single(sql, backend, parameters)
                results[backend.name] = result
            except Exception as e:
                logger.error(f"Query failed on {backend.name}: {e}")
                results[backend.name] = QueryResult(
                    rows=[],
                    columns=[],
                    row_count=0,
                    metadata={"error": str(e)},
                )

        return results

    def _execute_first_success(
        self,
        sql: str,
        backends: list[BackendConfig],
        parameters: dict[str, Any] | None,
    ) -> dict[str, QueryResult]:
        """Execute until first successful result."""
        # Sort by priority
        sorted_backends = sorted(backends, key=lambda b: b.priority)

        for backend in sorted_backends:
            try:
                result = self._execute_single(sql, backend, parameters)
                if result.row_count > 0 or not result.metadata.get("error"):
                    return {backend.name: result}
            except Exception as e:
                logger.warning(f"Query failed on {backend.name}, trying next: {e}")
                continue

        return {}

    def _execute_best_effort(
        self,
        sql: str,
        backends: list[BackendConfig],
        parameters: dict[str, Any] | None,
    ) -> dict[str, QueryResult]:
        """Execute on all backends, return whatever succeeds."""
        results = self._execute_parallel(sql, backends, parameters)
        # Filter out failed results for merging, but keep for reporting
        return results

    def _execute_single(
        self,
        sql: str,
        backend: BackendConfig,
        parameters: dict[str, Any] | None,
    ) -> QueryResult:
        """Execute query on a single backend."""
        # Transform SQL for this provider
        transformed_sql = self._transform_sql(sql, backend.provider)

        # Ensure connected
        if not backend.engine.is_connected():
            backend.engine.connect()

        # Execute
        return backend.engine.execute_query(
            transformed_sql,
            parameters=parameters,
            timeout_seconds=backend.timeout_seconds,
        )

    def _merge_results(
        self,
        results: dict[str, QueryResult],
        strategy: MergeStrategy,
    ) -> dict[str, Any]:
        """Merge results from multiple backends."""
        if not results:
            return {"rows": [], "columns": []}

        # Get all unique columns
        all_columns: set[str] = set()
        for result in results.values():
            all_columns.update(result.columns)
        columns = sorted(all_columns)

        # Collect all rows
        all_rows: list[dict[str, Any]] = []
        for backend_name, result in results.items():
            if not result.metadata.get("error"):
                for row in result.rows:
                    # Add backend source
                    enriched_row = {**row, "_source_backend": backend_name}
                    all_rows.append(enriched_row)

        if strategy == MergeStrategy.UNION:
            return {"rows": all_rows, "columns": columns + ["_source_backend"]}

        elif strategy == MergeStrategy.UNION_DISTINCT:
            # Deduplicate based on non-metadata columns
            seen: set[str] = set()
            unique_rows: list[dict[str, Any]] = []
            for row in all_rows:
                # Create key from non-metadata values
                key_data = {k: v for k, v in row.items() if not k.startswith("_")}
                key = str(sorted(key_data.items()))
                if key not in seen:
                    seen.add(key)
                    unique_rows.append(row)
            return {"rows": unique_rows, "columns": columns + ["_source_backend"]}

        elif strategy == MergeStrategy.INTERSECT:
            # Find rows present in all backends
            # Group rows by their data (excluding metadata)
            row_counts: dict[str, int] = {}
            row_data: dict[str, dict[str, Any]] = {}
            num_backends = len([r for r in results.values() if not r.metadata.get("error")])

            for row in all_rows:
                key_data = {k: v for k, v in row.items() if not k.startswith("_")}
                key = str(sorted(key_data.items()))
                row_counts[key] = row_counts.get(key, 0) + 1
                if key not in row_data:
                    row_data[key] = row

            intersect_rows = [
                row_data[key]
                for key, count in row_counts.items()
                if count >= num_backends
            ]
            return {"rows": intersect_rows, "columns": columns + ["_source_backend"]}

        elif strategy == MergeStrategy.PRIORITY:
            # Use results from highest priority backend that has data
            sorted_backends = sorted(
                [(name, results[name]) for name in results],
                key=lambda x: self._backends.get(x[0], BackendConfig(x[0], None, "")).priority  # type: ignore
            )
            for backend_name, result in sorted_backends:
                if result.rows and not result.metadata.get("error"):
                    enriched = [
                        {**row, "_source_backend": backend_name}
                        for row in result.rows
                    ]
                    return {"rows": enriched, "columns": columns + ["_source_backend"]}
            return {"rows": [], "columns": columns}

        return {"rows": all_rows, "columns": columns + ["_source_backend"]}

    def correlate(
        self,
        left_sql: str,
        right_sql: str,
        left_backend: str,
        right_backend: str,
        join_keys: list[str],
        correlation_type: str = "inner",
    ) -> FederatedQueryResult:
        """
        Correlate results from two different backends.

        Executes queries on two backends and joins results based
        on specified keys.

        Args:
            left_sql: SQL query for left side
            right_sql: SQL query for right side
            left_backend: Backend name for left query
            right_backend: Backend name for right query
            join_keys: Column names to join on
            correlation_type: Join type (inner, left, right, full)

        Returns:
            FederatedQueryResult with correlated data
        """
        start_time = datetime.utcnow()

        # Get backend configs
        left_config = self._backends.get(left_backend)
        right_config = self._backends.get(right_backend)

        if not left_config or not right_config:
            return FederatedQueryResult(
                rows=[],
                columns=[],
                errors={"federation": "Backend not found"},
            )

        # Execute both queries in parallel
        with ThreadPoolExecutor(max_workers=2) as executor:
            left_future = executor.submit(
                self._execute_single, left_sql, left_config, None
            )
            right_future = executor.submit(
                self._execute_single, right_sql, right_config, None
            )

            try:
                left_result = left_future.result()
                right_result = right_future.result()
            except Exception as e:
                return FederatedQueryResult(
                    rows=[],
                    columns=[],
                    errors={"federation": str(e)},
                )

        # Perform correlation/join
        correlated_rows = self._perform_join(
            left_result.rows,
            right_result.rows,
            join_keys,
            correlation_type,
            left_backend,
            right_backend,
        )

        # Combine columns
        all_columns = list(set(left_result.columns + right_result.columns))

        execution_time_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        return FederatedQueryResult(
            rows=correlated_rows,
            columns=all_columns + ["_left_backend", "_right_backend"],
            row_count=len(correlated_rows),
            backends_queried=2,
            backends_succeeded=2,
            backend_results={
                left_backend: left_result,
                right_backend: right_result,
            },
            execution_time_ms=execution_time_ms,
        )

    def _perform_join(
        self,
        left_rows: list[dict[str, Any]],
        right_rows: list[dict[str, Any]],
        join_keys: list[str],
        join_type: str,
        left_name: str,
        right_name: str,
    ) -> list[dict[str, Any]]:
        """Perform join operation on two result sets."""
        # Build index on right side
        right_index: dict[tuple, list[dict[str, Any]]] = {}
        for row in right_rows:
            key = tuple(row.get(k) for k in join_keys)
            if key not in right_index:
                right_index[key] = []
            right_index[key].append(row)

        result: list[dict[str, Any]] = []
        matched_right_keys: set[tuple] = set()

        for left_row in left_rows:
            key = tuple(left_row.get(k) for k in join_keys)
            right_matches = right_index.get(key, [])

            if right_matches:
                matched_right_keys.add(key)
                for right_row in right_matches:
                    merged = {**left_row, **right_row}
                    merged["_left_backend"] = left_name
                    merged["_right_backend"] = right_name
                    result.append(merged)
            elif join_type in ("left", "full"):
                # No match, include left row with null right values
                merged = {**left_row, "_left_backend": left_name, "_right_backend": None}
                result.append(merged)

        # For right/full join, add unmatched right rows
        if join_type in ("right", "full"):
            for key, right_rows_list in right_index.items():
                if key not in matched_right_keys:
                    for right_row in right_rows_list:
                        merged = {**right_row, "_left_backend": None, "_right_backend": right_name}
                        result.append(merged)

        return result

    def get_backend_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all configured backends."""
        status: dict[str, dict[str, Any]] = {}

        for name, config in self._backends.items():
            status[name] = {
                "provider": config.provider,
                "enabled": config.enabled,
                "priority": config.priority,
                "connected": config.engine.is_connected() if config.engine else False,
                "engine_name": config.engine.engine_name if config.engine else None,
            }

        return status

    def list_backends(self) -> list[str]:
        """List all backend names."""
        return list(self._backends.keys())

    def disconnect_all(self) -> None:
        """Disconnect all backends."""
        for config in self._backends.values():
            try:
                if config.engine and config.engine.is_connected():
                    config.engine.disconnect()
            except Exception as e:
                logger.warning(f"Error disconnecting {config.name}: {e}")
