"""
Google BigQuery query engine for Mantissa Stance.

Provides SQL query capabilities using BigQuery for querying
assets and findings stored in Cloud Storage.
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

# BigQuery pricing per TB processed (as of 2024, on-demand pricing)
BIGQUERY_PRICE_PER_TB_USD = 6.25


class BigQueryEngine(QueryEngine):
    """
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
    """

    def __init__(
        self,
        project_id: str,
        dataset_id: str,
        location: str = "US",
        credentials: Any | None = None,
    ) -> None:
        """
        Initialize the BigQuery query engine.

        Args:
            project_id: GCP project ID
            dataset_id: BigQuery dataset ID
            location: BigQuery location/region
            credentials: Optional google-auth credentials
        """
        super().__init__()
        self._project_id = project_id
        self._dataset_id = dataset_id
        self._location = location
        self._credentials = credentials
        self._client: Any = None

    @property
    def engine_name(self) -> str:
        """Return the name of this query engine."""
        return "bigquery"

    @property
    def provider(self) -> str:
        """Return the cloud provider."""
        return "gcp"

    @property
    def project_id(self) -> str:
        """Get the project ID."""
        return self._project_id

    @property
    def dataset_id(self) -> str:
        """Get the dataset ID."""
        return self._dataset_id

    def _get_client(self) -> Any:
        """Get or create the BigQuery client."""
        if self._client is None:
            try:
                from google.cloud import bigquery

                self._client = bigquery.Client(
                    project=self._project_id,
                    credentials=self._credentials,
                    location=self._location,
                )
            except ImportError:
                raise QueryExecutionError(
                    "google-cloud-bigquery is required for BigQuery query engine. "
                    "Install with: pip install google-cloud-bigquery"
                )
        return self._client

    def connect(self) -> None:
        """Establish connection to BigQuery."""
        try:
            client = self._get_client()
            # Verify dataset exists
            dataset_ref = f"{self._project_id}.{self._dataset_id}"
            client.get_dataset(dataset_ref)
            self._connected = True
            logger.info(f"Connected to BigQuery dataset: {dataset_ref}")
        except Exception as e:
            raise QueryExecutionError(f"Failed to connect to BigQuery: {e}")

    def disconnect(self) -> None:
        """Close connection to BigQuery."""
        if self._client:
            self._client.close()
        self._client = None
        self._connected = False
        logger.info("Disconnected from BigQuery")

    def execute_query(
        self,
        sql: str,
        parameters: dict[str, Any] | None = None,
        timeout_seconds: int = 300,
    ) -> QueryResult:
        """
        Execute a SQL query using BigQuery.

        Args:
            sql: SQL query to execute
            parameters: Query parameters for parameterized queries
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
            from google.cloud import bigquery

            # Configure job
            job_config = bigquery.QueryJobConfig(
                default_dataset=f"{self._project_id}.{self._dataset_id}",
                use_legacy_sql=False,
            )

            # Add query parameters if provided
            if parameters:
                query_params = []
                for name, value in parameters.items():
                    if isinstance(value, str):
                        query_params.append(
                            bigquery.ScalarQueryParameter(name, "STRING", value)
                        )
                    elif isinstance(value, int):
                        query_params.append(
                            bigquery.ScalarQueryParameter(name, "INT64", value)
                        )
                    elif isinstance(value, float):
                        query_params.append(
                            bigquery.ScalarQueryParameter(name, "FLOAT64", value)
                        )
                    elif isinstance(value, bool):
                        query_params.append(
                            bigquery.ScalarQueryParameter(name, "BOOL", value)
                        )
                job_config.query_parameters = query_params

            # Execute query
            query_job = client.query(sql, job_config=job_config)

            # Wait for results with timeout
            try:
                result = query_job.result(timeout=timeout_seconds)
            except TimeoutError:
                query_job.cancel()
                raise QueryExecutionError(
                    f"Query timed out after {timeout_seconds} seconds"
                )

            # Convert to rows
            rows = []
            columns = [field.name for field in result.schema]

            for row in result:
                row_dict = {}
                for i, col_name in enumerate(columns):
                    value = row[i]
                    # Convert BigQuery-specific types to Python native
                    if hasattr(value, "isoformat"):
                        value = value.isoformat()
                    row_dict[col_name] = value
                rows.append(row_dict)

            # Get execution statistics
            bytes_processed = query_job.total_bytes_processed or 0
            execution_time_ms = int((time.time() - start_time) * 1000)

            # Get slot usage if available
            slot_millis = query_job.slot_millis or 0

            return QueryResult(
                rows=rows,
                columns=columns,
                row_count=len(rows),
                bytes_scanned=bytes_processed,
                execution_time_ms=execution_time_ms,
                query_id=query_job.job_id,
                metadata={
                    "project_id": self._project_id,
                    "dataset_id": self._dataset_id,
                    "location": query_job.location,
                    "slot_millis": slot_millis,
                    "bytes_billed": query_job.total_bytes_billed,
                    "cache_hit": query_job.cache_hit,
                    "num_dml_affected_rows": query_job.num_dml_affected_rows,
                    "statement_type": query_job.statement_type,
                },
            )

        except QueryExecutionError:
            raise
        except Exception as e:
            raise QueryExecutionError(f"BigQuery query execution failed: {e}")

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
            table_ref = f"{self._project_id}.{self._dataset_id}.{table_name}"
            table = client.get_table(table_ref)

            columns = []
            for field in table.schema:
                columns.append({
                    "name": field.name,
                    "type": field.field_type,
                    "mode": field.mode,
                    "description": field.description or "",
                })

            return TableSchema(
                table_name=table_name,
                columns=columns,
                description=table.description or "",
                row_count=table.num_rows,
                size_bytes=table.num_bytes,
            )

        except Exception as e:
            raise QueryExecutionError(f"Failed to get table schema: {e}")

    def list_tables(self) -> list[str]:
        """
        List all tables in the dataset.

        Returns:
            List of table names
        """
        client = self._get_client()

        try:
            dataset_ref = f"{self._project_id}.{self._dataset_id}"
            tables = list(client.list_tables(dataset_ref))
            return sorted([table.table_id for table in tables])

        except Exception as e:
            raise QueryExecutionError(f"Failed to list tables: {e}")

    def estimate_cost(self, sql: str) -> CostEstimate:
        """
        Estimate the cost of a query using BigQuery dry run.

        BigQuery supports dry runs that provide accurate byte estimates
        without actually executing the query.

        Args:
            sql: SQL query to estimate

        Returns:
            CostEstimate with estimated bytes and cost
        """
        client = self._get_client()
        warnings: list[str] = []

        try:
            from google.cloud import bigquery

            # Configure dry run job
            job_config = bigquery.QueryJobConfig(
                dry_run=True,
                use_query_cache=False,
                default_dataset=f"{self._project_id}.{self._dataset_id}",
                use_legacy_sql=False,
            )

            # Execute dry run
            query_job = client.query(sql, job_config=job_config)

            estimated_bytes = query_job.total_bytes_processed or 0

            # Calculate cost
            estimated_tb = estimated_bytes / (1024**4)
            estimated_cost = estimated_tb * BIGQUERY_PRICE_PER_TB_USD

            # Add warning about minimum billing
            if estimated_bytes > 0 and estimated_bytes < 10 * 1024 * 1024:
                warnings.append("BigQuery has a 10MB minimum billing per query")
                estimated_bytes = 10 * 1024 * 1024
                estimated_cost = (10 / 1024 / 1024) * BIGQUERY_PRICE_PER_TB_USD

            # Check for potential cache hit
            warnings.append(
                "Actual cost may be lower if results are cached from a previous query"
            )

            return CostEstimate(
                estimated_bytes=estimated_bytes,
                estimated_cost_usd=estimated_cost,
                warnings=warnings,
            )

        except Exception as e:
            logger.warning(f"Failed to estimate cost via dry run: {e}")
            return CostEstimate(
                estimated_bytes=0,
                estimated_cost_usd=0.0,
                warnings=[f"Cost estimation failed: {e}"],
            )

    def run_scheduled_query(
        self,
        sql: str,
        schedule: str,
        destination_table: str,
        display_name: str,
    ) -> str:
        """
        Create a scheduled query in BigQuery.

        Args:
            sql: SQL query to schedule
            schedule: Schedule in cron format
            destination_table: Target table for results
            display_name: Name for the scheduled query

        Returns:
            Scheduled query resource name
        """
        try:
            from google.cloud import bigquery_datatransfer

            client = bigquery_datatransfer.DataTransferServiceClient(
                credentials=self._credentials
            )

            parent = f"projects/{self._project_id}/locations/{self._location}"

            transfer_config = bigquery_datatransfer.TransferConfig(
                display_name=display_name,
                data_source_id="scheduled_query",
                schedule=schedule,
                destination_dataset_id=self._dataset_id,
                params={
                    "query": sql,
                    "destination_table_name_template": destination_table,
                    "write_disposition": "WRITE_TRUNCATE",
                },
            )

            result = client.create_transfer_config(
                parent=parent,
                transfer_config=transfer_config,
            )

            return result.name

        except ImportError:
            raise QueryExecutionError(
                "google-cloud-bigquery-datatransfer is required for scheduled queries. "
                "Install with: pip install google-cloud-bigquery-datatransfer"
            )
        except Exception as e:
            raise QueryExecutionError(f"Failed to create scheduled query: {e}")
