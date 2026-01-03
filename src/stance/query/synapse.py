"""
Azure Synapse Analytics query engine for Mantissa Stance.

Provides SQL query capabilities using Azure Synapse serverless SQL pools
for querying assets and findings stored in Azure Data Lake Storage.
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

# Synapse serverless pricing per TB processed (as of 2024)
SYNAPSE_PRICE_PER_TB_USD = 5.00


class SynapseQueryEngine(QueryEngine):
    """
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
    """

    def __init__(
        self,
        server: str,
        database: str,
        credential: Any | None = None,
        connection_string: str | None = None,
    ) -> None:
        """
        Initialize the Synapse query engine.

        Args:
            server: Synapse serverless SQL endpoint (e.g., workspace.sql.azuresynapse.net)
            database: Database name
            credential: Optional Azure credential (DefaultAzureCredential or similar)
            connection_string: Optional full connection string (overrides server/database)
        """
        super().__init__()
        self._server = server
        self._database = database
        self._credential = credential
        self._connection_string = connection_string
        self._connection: Any = None

    @property
    def engine_name(self) -> str:
        """Return the name of this query engine."""
        return "synapse"

    @property
    def provider(self) -> str:
        """Return the cloud provider."""
        return "azure"

    @property
    def server(self) -> str:
        """Get the server endpoint."""
        return self._server

    @property
    def database(self) -> str:
        """Get the database name."""
        return self._database

    def _get_connection(self) -> Any:
        """Get or create the database connection."""
        if self._connection is None:
            try:
                import pyodbc
            except ImportError:
                raise QueryExecutionError(
                    "pyodbc is required for Synapse query engine. "
                    "Install with: pip install pyodbc"
                )

            try:
                if self._connection_string:
                    self._connection = pyodbc.connect(self._connection_string)
                else:
                    # Build connection string for Azure AD authentication
                    conn_str = self._build_connection_string()
                    self._connection = pyodbc.connect(conn_str)
            except Exception as e:
                raise QueryExecutionError(f"Failed to connect to Synapse: {e}")

        return self._connection

    def _build_connection_string(self) -> str:
        """Build ODBC connection string for Synapse."""
        # Use Azure AD authentication by default
        conn_parts = [
            f"DRIVER={{ODBC Driver 18 for SQL Server}}",
            f"SERVER={self._server}",
            f"DATABASE={self._database}",
            "Authentication=ActiveDirectoryDefault",
            "Encrypt=yes",
            "TrustServerCertificate=no",
        ]
        return ";".join(conn_parts)

    def connect(self) -> None:
        """Establish connection to Synapse."""
        try:
            conn = self._get_connection()
            # Verify connection with simple query
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            self._connected = True
            logger.info(f"Connected to Synapse: {self._server}/{self._database}")
        except Exception as e:
            raise QueryExecutionError(f"Failed to connect to Synapse: {e}")

    def disconnect(self) -> None:
        """Close connection to Synapse."""
        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass
        self._connection = None
        self._connected = False
        logger.info("Disconnected from Synapse")

    def execute_query(
        self,
        sql: str,
        parameters: dict[str, Any] | None = None,
        timeout_seconds: int = 300,
    ) -> QueryResult:
        """
        Execute a SQL query using Synapse serverless SQL pool.

        Args:
            sql: SQL query to execute
            parameters: Query parameters (named parameters with @name syntax)
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

        conn = self._get_connection()
        start_time = time.time()

        try:
            cursor = conn.cursor()
            cursor.timeout = timeout_seconds

            # Execute query with parameters if provided
            if parameters:
                # Convert dict parameters to ordered tuple for ODBC
                # Synapse uses @param_name syntax
                param_values = tuple(parameters.values())
                cursor.execute(sql, param_values)
            else:
                cursor.execute(sql)

            # Get column names
            columns = [desc[0] for desc in cursor.description] if cursor.description else []

            # Fetch all rows
            rows = []
            for row in cursor.fetchall():
                row_dict = {}
                for i, col_name in enumerate(columns):
                    value = row[i]
                    # Convert datetime objects to ISO format
                    if hasattr(value, "isoformat"):
                        value = value.isoformat()
                    # Convert Decimal to float
                    elif hasattr(value, "as_tuple"):
                        value = float(value)
                    row_dict[col_name] = value
                rows.append(row_dict)

            execution_time_ms = int((time.time() - start_time) * 1000)

            # Try to get bytes processed from session stats
            bytes_processed = self._get_bytes_processed(cursor)

            cursor.close()

            return QueryResult(
                rows=rows,
                columns=columns,
                row_count=len(rows),
                bytes_scanned=bytes_processed,
                execution_time_ms=execution_time_ms,
                query_id="",  # Synapse doesn't expose query ID easily
                metadata={
                    "server": self._server,
                    "database": self._database,
                },
            )

        except QueryExecutionError:
            raise
        except Exception as e:
            raise QueryExecutionError(f"Synapse query execution failed: {e}")

    def _get_bytes_processed(self, cursor: Any) -> int:
        """
        Try to get bytes processed for cost estimation.

        Synapse serverless tracks data processed, but accessing it
        requires querying sys.dm_exec_requests or similar.
        """
        try:
            cursor.execute(
                """
                SELECT TOP 1 total_elapsed_time, data_processed_bytes
                FROM sys.dm_exec_requests
                WHERE session_id = @@SPID
                """
            )
            row = cursor.fetchone()
            if row and row[1]:
                return int(row[1])
        except Exception:
            pass
        return 0

    def get_table_schema(self, table_name: str) -> TableSchema:
        """
        Get schema information for a table.

        Args:
            table_name: Name of the table (can include schema prefix)

        Returns:
            TableSchema with column definitions
        """
        conn = self._get_connection()

        try:
            cursor = conn.cursor()

            # Parse table name for schema
            if "." in table_name:
                schema_name, table_only = table_name.rsplit(".", 1)
            else:
                schema_name = "dbo"
                table_only = table_name

            # Get column information
            cursor.execute(
                """
                SELECT
                    c.COLUMN_NAME,
                    c.DATA_TYPE,
                    c.IS_NULLABLE,
                    COALESCE(ep.value, '') as DESCRIPTION
                FROM INFORMATION_SCHEMA.COLUMNS c
                LEFT JOIN sys.extended_properties ep
                    ON ep.major_id = OBJECT_ID(c.TABLE_SCHEMA + '.' + c.TABLE_NAME)
                    AND ep.minor_id = c.ORDINAL_POSITION
                    AND ep.name = 'MS_Description'
                WHERE c.TABLE_SCHEMA = ?
                    AND c.TABLE_NAME = ?
                ORDER BY c.ORDINAL_POSITION
                """,
                (schema_name, table_only),
            )

            columns = []
            for row in cursor.fetchall():
                columns.append(
                    {
                        "name": row[0],
                        "type": row[1],
                        "nullable": row[2] == "YES",
                        "description": row[3] or "",
                    }
                )

            # Try to get table description
            cursor.execute(
                """
                SELECT COALESCE(ep.value, '') as DESCRIPTION
                FROM sys.tables t
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                LEFT JOIN sys.extended_properties ep
                    ON ep.major_id = t.object_id
                    AND ep.minor_id = 0
                    AND ep.name = 'MS_Description'
                WHERE s.name = ?
                    AND t.name = ?
                """,
                (schema_name, table_only),
            )
            desc_row = cursor.fetchone()
            description = desc_row[0] if desc_row else ""

            cursor.close()

            return TableSchema(
                table_name=table_name,
                columns=columns,
                description=description,
            )

        except Exception as e:
            raise QueryExecutionError(f"Failed to get table schema: {e}")

    def list_tables(self) -> list[str]:
        """
        List all tables in the database.

        Returns:
            List of table names (schema.table format)
        """
        conn = self._get_connection()

        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT TABLE_SCHEMA + '.' + TABLE_NAME as full_name
                FROM INFORMATION_SCHEMA.TABLES
                WHERE TABLE_TYPE = 'BASE TABLE'
                ORDER BY TABLE_SCHEMA, TABLE_NAME
                """
            )

            tables = [row[0] for row in cursor.fetchall()]
            cursor.close()

            return tables

        except Exception as e:
            raise QueryExecutionError(f"Failed to list tables: {e}")

    def list_external_tables(self) -> list[str]:
        """
        List external tables pointing to Data Lake Storage.

        Returns:
            List of external table names
        """
        conn = self._get_connection()

        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.name + '.' + t.name as full_name
                FROM sys.external_tables t
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                ORDER BY s.name, t.name
                """
            )

            tables = [row[0] for row in cursor.fetchall()]
            cursor.close()

            return tables

        except Exception as e:
            raise QueryExecutionError(f"Failed to list external tables: {e}")

    def estimate_cost(self, sql: str) -> CostEstimate:
        """
        Estimate the cost of a query.

        Synapse serverless doesn't provide pre-execution cost estimates
        like BigQuery's dry run. This provides a rough estimate based on
        table sizes referenced in the query.

        Args:
            sql: SQL query to estimate

        Returns:
            CostEstimate with estimated bytes and cost
        """
        warnings: list[str] = []
        estimated_bytes = 0

        warnings.append(
            "Synapse serverless cost estimates are approximate. "
            "Actual data processed depends on query predicates and file pruning."
        )

        # Try to identify tables in the query and estimate based on size
        conn = self._get_connection()

        try:
            cursor = conn.cursor()

            # Get list of all tables to check against query
            cursor.execute(
                """
                SELECT TABLE_SCHEMA + '.' + TABLE_NAME as full_name
                FROM INFORMATION_SCHEMA.TABLES
                """
            )
            tables = [row[0] for row in cursor.fetchall()]

            sql_upper = sql.upper()
            for table in tables:
                if table.upper() in sql_upper or table.split(".")[-1].upper() in sql_upper:
                    # Assume 1GB per referenced table as rough estimate
                    estimated_bytes += 1 * 1024 * 1024 * 1024
                    warnings.append(
                        f"Assumed 1GB for table '{table}' (actual size unknown)"
                    )

            cursor.close()

        except Exception as e:
            warnings.append(f"Could not estimate table sizes: {e}")

        # Calculate cost
        estimated_tb = estimated_bytes / (1024**4)
        estimated_cost = estimated_tb * SYNAPSE_PRICE_PER_TB_USD

        # Synapse has 10MB minimum billing
        if 0 < estimated_bytes < 10 * 1024 * 1024:
            estimated_bytes = 10 * 1024 * 1024
            estimated_cost = (10 / 1024 / 1024) * SYNAPSE_PRICE_PER_TB_USD
            warnings.append("Synapse has a 10MB minimum billing per query")

        return CostEstimate(
            estimated_bytes=estimated_bytes,
            estimated_cost_usd=estimated_cost,
            warnings=warnings,
        )

    def create_external_table(
        self,
        table_name: str,
        data_source: str,
        location: str,
        file_format: str,
        columns: list[dict[str, str]],
        schema: str = "dbo",
    ) -> None:
        """
        Create an external table pointing to Data Lake Storage.

        Args:
            table_name: Name of the table to create
            data_source: Name of the external data source
            location: Path within the data source (e.g., '/assets/')
            file_format: File format name (e.g., 'ParquetFormat')
            columns: List of column definitions with 'name' and 'type'
            schema: Schema name (default: dbo)
        """
        conn = self._get_connection()

        try:
            cursor = conn.cursor()

            # Build column definitions
            col_defs = ", ".join(
                f"[{col['name']}] {col['type']}" for col in columns
            )

            # Create external table
            sql = f"""
                CREATE EXTERNAL TABLE [{schema}].[{table_name}] (
                    {col_defs}
                )
                WITH (
                    LOCATION = '{location}',
                    DATA_SOURCE = [{data_source}],
                    FILE_FORMAT = [{file_format}]
                )
            """

            cursor.execute(sql)
            cursor.commit()
            cursor.close()

            logger.info(f"Created external table: {schema}.{table_name}")

        except Exception as e:
            raise QueryExecutionError(f"Failed to create external table: {e}")

    def create_external_data_source(
        self,
        name: str,
        storage_account: str,
        container: str,
        credential: str | None = None,
    ) -> None:
        """
        Create an external data source for Azure Data Lake Storage.

        Args:
            name: Name of the data source
            storage_account: Azure Storage account name
            container: Container/filesystem name
            credential: Optional database scoped credential name
        """
        conn = self._get_connection()

        try:
            cursor = conn.cursor()

            location = f"https://{storage_account}.dfs.core.windows.net/{container}"

            if credential:
                sql = f"""
                    CREATE EXTERNAL DATA SOURCE [{name}]
                    WITH (
                        LOCATION = '{location}',
                        CREDENTIAL = [{credential}]
                    )
                """
            else:
                sql = f"""
                    CREATE EXTERNAL DATA SOURCE [{name}]
                    WITH (
                        LOCATION = '{location}'
                    )
                """

            cursor.execute(sql)
            cursor.commit()
            cursor.close()

            logger.info(f"Created external data source: {name}")

        except Exception as e:
            raise QueryExecutionError(f"Failed to create external data source: {e}")

    def create_file_format(
        self,
        name: str,
        format_type: str = "PARQUET",
    ) -> None:
        """
        Create an external file format.

        Args:
            name: Name of the file format
            format_type: Type of format (PARQUET, DELTA, CSV, JSON)
        """
        conn = self._get_connection()

        try:
            cursor = conn.cursor()

            if format_type.upper() == "CSV":
                sql = f"""
                    CREATE EXTERNAL FILE FORMAT [{name}]
                    WITH (
                        FORMAT_TYPE = DELIMITEDTEXT,
                        FORMAT_OPTIONS (
                            FIELD_TERMINATOR = ',',
                            STRING_DELIMITER = '"',
                            FIRST_ROW = 2
                        )
                    )
                """
            elif format_type.upper() == "JSON":
                sql = f"""
                    CREATE EXTERNAL FILE FORMAT [{name}]
                    WITH (
                        FORMAT_TYPE = DELIMITEDTEXT,
                        FORMAT_OPTIONS (
                            FIELD_TERMINATOR = '0x0b',
                            STRING_DELIMITER = '0x0b'
                        )
                    )
                """
            else:
                # PARQUET or DELTA
                sql = f"""
                    CREATE EXTERNAL FILE FORMAT [{name}]
                    WITH (
                        FORMAT_TYPE = {format_type.upper()}
                    )
                """

            cursor.execute(sql)
            cursor.commit()
            cursor.close()

            logger.info(f"Created external file format: {name}")

        except Exception as e:
            raise QueryExecutionError(f"Failed to create file format: {e}")
