"""
AWS Athena query engine for Mantissa Stance.

Provides SQL query capabilities using AWS Athena for querying
assets and findings stored in S3.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from stance.query.base import (
    QueryEngine,
    QueryResult,
    TableSchema,
    CostEstimate,
    QueryExecutionError,
    QueryValidationError,
)

logger = logging.getLogger(__name__)

# Athena pricing per TB scanned (as of 2024)
ATHENA_PRICE_PER_TB_USD = 5.00


class AthenaQueryEngine(QueryEngine):
    """
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
    """

    def __init__(
        self,
        database: str,
        workgroup: str = "primary",
        output_location: str | None = None,
        region: str = "us-east-1",
        session: Any | None = None,
    ) -> None:
        """
        Initialize the Athena query engine.

        Args:
            database: Athena/Glue database name
            workgroup: Athena workgroup name
            output_location: S3 location for query results
            region: AWS region
            session: Optional boto3 session
        """
        super().__init__()
        self._database = database
        self._workgroup = workgroup
        self._output_location = output_location
        self._region = region
        self._session = session
        self._client: Any = None

    @property
    def engine_name(self) -> str:
        """Return the name of this query engine."""
        return "athena"

    @property
    def provider(self) -> str:
        """Return the cloud provider."""
        return "aws"

    @property
    def database(self) -> str:
        """Get the database name."""
        return self._database

    @property
    def workgroup(self) -> str:
        """Get the workgroup name."""
        return self._workgroup

    def _get_client(self) -> Any:
        """Get or create the Athena client."""
        if self._client is None:
            try:
                import boto3

                if self._session:
                    self._client = self._session.client("athena", region_name=self._region)
                else:
                    self._client = boto3.client("athena", region_name=self._region)
            except ImportError:
                raise QueryExecutionError(
                    "boto3 is required for Athena query engine. "
                    "Install with: pip install boto3"
                )
        return self._client

    def connect(self) -> None:
        """Establish connection to Athena."""
        try:
            client = self._get_client()
            # Verify workgroup exists
            client.get_work_group(WorkGroup=self._workgroup)
            self._connected = True
            logger.info(f"Connected to Athena workgroup: {self._workgroup}")
        except Exception as e:
            raise QueryExecutionError(f"Failed to connect to Athena: {e}")

    def disconnect(self) -> None:
        """Close connection to Athena."""
        self._client = None
        self._connected = False
        logger.info("Disconnected from Athena")

    def execute_query(
        self,
        sql: str,
        parameters: dict[str, Any] | None = None,
        timeout_seconds: int = 300,
    ) -> QueryResult:
        """
        Execute a SQL query using Athena.

        Args:
            sql: SQL query to execute
            parameters: Not supported by Athena (ignored)
            timeout_seconds: Maximum time to wait for query completion

        Returns:
            QueryResult with rows and metadata

        Raises:
            QueryValidationError: If query is not valid
            QueryExecutionError: If query execution fails
        """
        # Validate query first
        errors = self.validate_query(sql)
        if errors:
            raise QueryValidationError(f"Query validation failed: {'; '.join(errors)}")

        client = self._get_client()
        start_time = time.time()

        try:
            # Start query execution
            execution_params: dict[str, Any] = {
                "QueryString": sql,
                "QueryExecutionContext": {"Database": self._database},
                "WorkGroup": self._workgroup,
            }

            if self._output_location:
                execution_params["ResultConfiguration"] = {
                    "OutputLocation": self._output_location
                }

            response = client.start_query_execution(**execution_params)
            query_id = response["QueryExecutionId"]
            logger.debug(f"Started Athena query: {query_id}")

            # Wait for query to complete
            state = self._wait_for_query(client, query_id, timeout_seconds)

            if state != "SUCCEEDED":
                # Get error details
                execution = client.get_query_execution(QueryExecutionId=query_id)
                reason = execution["QueryExecution"]["Status"].get(
                    "StateChangeReason", "Unknown error"
                )
                raise QueryExecutionError(f"Query failed with state {state}: {reason}")

            # Get results
            rows, columns = self._get_query_results(client, query_id)

            # Get execution statistics
            execution = client.get_query_execution(QueryExecutionId=query_id)
            stats = execution["QueryExecution"].get("Statistics", {})
            bytes_scanned = stats.get("DataScannedInBytes", 0)
            execution_time_ms = stats.get("TotalExecutionTimeInMillis", 0)

            return QueryResult(
                rows=rows,
                columns=columns,
                row_count=len(rows),
                bytes_scanned=bytes_scanned,
                execution_time_ms=execution_time_ms,
                query_id=query_id,
                metadata={
                    "database": self._database,
                    "workgroup": self._workgroup,
                    "state": state,
                    "engine_execution_time_ms": stats.get("EngineExecutionTimeInMillis"),
                    "query_queue_time_ms": stats.get("QueryQueueTimeInMillis"),
                    "service_processing_time_ms": stats.get("ServiceProcessingTimeInMillis"),
                },
            )

        except QueryExecutionError:
            raise
        except Exception as e:
            raise QueryExecutionError(f"Athena query execution failed: {e}")

    def _wait_for_query(
        self,
        client: Any,
        query_id: str,
        timeout_seconds: int,
    ) -> str:
        """
        Wait for a query to complete.

        Args:
            client: Athena client
            query_id: Query execution ID
            timeout_seconds: Maximum wait time

        Returns:
            Final query state
        """
        start_time = time.time()
        poll_interval = 0.5  # Start with 500ms

        while True:
            response = client.get_query_execution(QueryExecutionId=query_id)
            state = response["QueryExecution"]["Status"]["State"]

            if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
                return state

            elapsed = time.time() - start_time
            if elapsed > timeout_seconds:
                # Cancel the query
                try:
                    client.stop_query_execution(QueryExecutionId=query_id)
                except Exception:
                    pass
                raise QueryExecutionError(
                    f"Query timed out after {timeout_seconds} seconds"
                )

            time.sleep(poll_interval)
            # Increase poll interval up to 2 seconds
            poll_interval = min(poll_interval * 1.5, 2.0)

    def _get_query_results(
        self,
        client: Any,
        query_id: str,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """
        Get results from a completed query.

        Args:
            client: Athena client
            query_id: Query execution ID

        Returns:
            Tuple of (rows, column_names)
        """
        rows: list[dict[str, Any]] = []
        columns: list[str] = []
        next_token: str | None = None
        first_page = True

        while True:
            params: dict[str, Any] = {"QueryExecutionId": query_id}
            if next_token:
                params["NextToken"] = next_token

            response = client.get_query_results(**params)

            # Extract column names from first page
            if first_page:
                result_set = response.get("ResultSet", {})
                metadata = result_set.get("ResultSetMetadata", {})
                columns = [
                    col.get("Name", f"col_{i}")
                    for i, col in enumerate(metadata.get("ColumnInfo", []))
                ]
                first_page = False

            # Extract rows
            result_rows = response.get("ResultSet", {}).get("Rows", [])

            # Skip header row on first page
            start_idx = 1 if len(rows) == 0 and result_rows else 0

            for row in result_rows[start_idx:]:
                row_data = {}
                data = row.get("Data", [])
                for i, col_name in enumerate(columns):
                    if i < len(data):
                        row_data[col_name] = data[i].get("VarCharValue")
                    else:
                        row_data[col_name] = None
                rows.append(row_data)

            # Check for more pages
            next_token = response.get("NextToken")
            if not next_token:
                break

        return rows, columns

    def get_table_schema(self, table_name: str) -> TableSchema:
        """
        Get schema information for a table.

        Args:
            table_name: Name of the table

        Returns:
            TableSchema with column definitions
        """
        client = self._get_client()

        try:
            # Use Glue to get table metadata
            import boto3

            if self._session:
                glue = self._session.client("glue", region_name=self._region)
            else:
                glue = boto3.client("glue", region_name=self._region)

            response = glue.get_table(DatabaseName=self._database, Name=table_name)
            table = response["Table"]

            columns = []
            for col in table.get("StorageDescriptor", {}).get("Columns", []):
                columns.append({
                    "name": col.get("Name"),
                    "type": col.get("Type"),
                    "description": col.get("Comment", ""),
                })

            # Add partition columns
            for col in table.get("PartitionKeys", []):
                columns.append({
                    "name": col.get("Name"),
                    "type": col.get("Type"),
                    "description": col.get("Comment", ""),
                    "is_partition": True,
                })

            return TableSchema(
                table_name=table_name,
                columns=columns,
                description=table.get("Description", ""),
            )

        except Exception as e:
            raise QueryExecutionError(f"Failed to get table schema: {e}")

    def list_tables(self) -> list[str]:
        """
        List all tables in the database.

        Returns:
            List of table names
        """
        client = self._get_client()

        try:
            import boto3

            if self._session:
                glue = self._session.client("glue", region_name=self._region)
            else:
                glue = boto3.client("glue", region_name=self._region)

            tables: list[str] = []
            next_token: str | None = None

            while True:
                params: dict[str, Any] = {"DatabaseName": self._database}
                if next_token:
                    params["NextToken"] = next_token

                response = glue.get_tables(**params)

                for table in response.get("TableList", []):
                    tables.append(table.get("Name", ""))

                next_token = response.get("NextToken")
                if not next_token:
                    break

            return sorted(tables)

        except Exception as e:
            raise QueryExecutionError(f"Failed to list tables: {e}")

    def estimate_cost(self, sql: str) -> CostEstimate:
        """
        Estimate the cost of a query.

        Note: Athena doesn't provide pre-execution cost estimates.
        This method provides a rough estimate based on table sizes.

        Args:
            sql: SQL query to estimate

        Returns:
            CostEstimate with estimated bytes and cost
        """
        warnings: list[str] = []
        estimated_bytes = 0

        # Athena doesn't support EXPLAIN for cost estimation
        # We can only provide rough estimates based on table metadata
        warnings.append(
            "Athena cost estimates are approximate. "
            "Actual bytes scanned may vary based on query predicates and partitions."
        )

        # Try to extract table names from query
        sql_upper = sql.upper()
        if "FROM" in sql_upper:
            # This is a simplified extraction - real parsing would be more complex
            tables = self.list_tables()
            for table in tables:
                if table.upper() in sql_upper:
                    # Add a rough estimate per table
                    # Without actual table stats, assume 1GB per table
                    estimated_bytes += 1 * 1024 * 1024 * 1024
                    warnings.append(f"Assumed 1GB for table '{table}' (no actual stats available)")

        # Calculate cost
        estimated_tb = estimated_bytes / (1024**4)
        estimated_cost = estimated_tb * ATHENA_PRICE_PER_TB_USD

        # Athena has a minimum of 10MB per query
        if estimated_bytes < 10 * 1024 * 1024:
            estimated_bytes = 10 * 1024 * 1024
            estimated_cost = (10 / 1024 / 1024) * ATHENA_PRICE_PER_TB_USD

        return CostEstimate(
            estimated_bytes=estimated_bytes,
            estimated_cost_usd=estimated_cost,
            warnings=warnings,
        )
