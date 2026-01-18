"""
Redshift Scanner for DSPM.

Scans Amazon Redshift data warehouse to detect sensitive data
using read-only column sampling queries.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.dspm.extended.base import (
    BaseExtendedScanner,
    ExtendedSourceType,
    ExtendedScanConfig,
    ExtendedScanResult,
    ExtendedScanFinding,
    ExtendedScanSummary,
)
from stance.dspm.scanners.base import FindingSeverity

logger = logging.getLogger(__name__)

# Optional Redshift import (uses psycopg2)
try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    psycopg2 = None  # type: ignore
    HAS_PSYCOPG2 = False


@dataclass
class RedshiftConfig:
    """
    Configuration for Redshift connection.

    Attributes:
        host: Redshift cluster endpoint
        port: Redshift port (default 5439)
        database: Database name
        user: Username
        password: Password
        ssl_mode: SSL mode (disable, require, verify-ca, verify-full)
        ssl_ca: Path to CA certificate
        connect_timeout: Connection timeout in seconds
        include_schemas: Schemas to include (None for all)
        exclude_schemas: Schemas to exclude
    """

    host: str
    database: str
    user: str
    password: str
    port: int = 5439
    ssl_mode: str = "require"
    ssl_ca: str | None = None
    connect_timeout: int = 30
    include_schemas: list[str] | None = None
    exclude_schemas: list[str] = field(
        default_factory=lambda: [
            "information_schema",
            "pg_catalog",
            "pg_internal",
            "catalog_history",
        ]
    )

    @property
    def connection_string(self) -> str:
        """Get psycopg2 connection string."""
        params = {
            "host": self.host,
            "port": self.port,
            "dbname": self.database,
            "user": self.user,
            "password": self.password,
            "connect_timeout": self.connect_timeout,
            "sslmode": self.ssl_mode,
        }

        if self.ssl_ca:
            params["sslrootcert"] = self.ssl_ca

        return " ".join(f"{k}={v}" for k, v in params.items())


@dataclass
class RedshiftColumnInfo:
    """
    Information about a Redshift column.

    Attributes:
        name: Column name
        data_type: Redshift data type
        max_length: Maximum length for VARCHAR
        is_nullable: Whether column allows nulls
        is_distkey: Whether column is distribution key
        is_sortkey: Whether column is sort key
        encoding: Column encoding
        sample_values: Sampled values from column
    """

    name: str
    data_type: str
    max_length: int | None = None
    is_nullable: bool = True
    is_distkey: bool = False
    is_sortkey: bool = False
    encoding: str = "none"
    sample_values: list[Any] = field(default_factory=list)


@dataclass
class RedshiftTableInfo:
    """
    Information about a Redshift table.

    Attributes:
        schema: Schema name
        name: Table name
        table_type: Type (TABLE, VIEW, EXTERNAL TABLE)
        diststyle: Distribution style (KEY, EVEN, ALL, AUTO)
        sortkey: Sort key columns
        row_count: Approximate row count
        size_mb: Table size in MB
        columns: List of columns
    """

    schema: str
    name: str
    table_type: str = "TABLE"
    diststyle: str = "AUTO"
    sortkey: list[str] = field(default_factory=list)
    row_count: int = 0
    size_mb: float = 0.0
    columns: list[RedshiftColumnInfo] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        """Get fully qualified table name."""
        return f"{self.schema}.{self.name}"


class RedshiftScanner(BaseExtendedScanner):
    """
    Redshift scanner for sensitive data detection.

    Samples data from Redshift tables and columns to identify
    PII, PCI, PHI, and other sensitive data patterns.

    All operations are read-only using SELECT queries with LIMIT.
    """

    source_type = ExtendedSourceType.REDSHIFT

    # Data types that should be scanned for sensitive data
    SCANNABLE_TYPES = {
        # Character types
        "character", "char", "character varying", "varchar", "nchar", "nvarchar",
        "text", "bpchar",
        # Numeric types
        "smallint", "integer", "int", "int2", "int4", "int8", "bigint",
        "decimal", "numeric", "real", "float", "float4", "float8", "double precision",
        # Special types
        "super",  # Redshift SUPER type for semi-structured data
    }

    # Data types to skip
    SKIP_TYPES = {
        "date", "time", "timetz", "timestamp", "timestamptz",
        "boolean", "bool",
        "geometry", "geography",
        "varbyte", "binary", "bytea",
        "hllsketch",  # Redshift HyperLogLog
    }

    def __init__(
        self,
        rs_config: RedshiftConfig,
        scan_config: ExtendedScanConfig | None = None,
    ):
        """
        Initialize Redshift scanner.

        Args:
            rs_config: Redshift connection configuration
            scan_config: Optional scan configuration
        """
        super().__init__(scan_config)
        self._rs_config = rs_config
        self._connection: Any = None

        if not HAS_PSYCOPG2:
            logger.warning(
                "psycopg2 not installed. "
                "Install with: pip install psycopg2-binary"
            )

    def _get_connection(self) -> Any:
        """Get or create database connection."""
        if self._connection is not None:
            return self._connection

        if not HAS_PSYCOPG2:
            raise ImportError(
                "psycopg2 is required for Redshift scanning. "
                "Install with: pip install psycopg2-binary"
            )

        self._connection = psycopg2.connect(self._rs_config.connection_string)
        return self._connection

    def _close_connection(self) -> None:
        """Close database connection."""
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception as e:
                logger.warning(f"Error closing Redshift connection: {type(e).__name__}: {e}")
            self._connection = None

    def test_connection(self) -> bool:
        """
        Test connection to Redshift.

        Returns:
            True if connection successful
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Redshift connection test failed: {type(e).__name__}: {e}")
            return False
        finally:
            self._close_connection()

    def _list_schemas(self) -> list[str]:
        """List schemas in the database."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = """
            SELECT DISTINCT schema_name
            FROM svv_all_schemas
            WHERE schema_owner != 'rdsdb'
            ORDER BY schema_name
        """

        try:
            cursor.execute(query)
            schemas = []
            for row in cursor.fetchall():
                schema_name = row[0]

                # Check exclusion filter
                if schema_name.lower() in [s.lower() for s in self._rs_config.exclude_schemas]:
                    continue

                # Check inclusion filter
                if self._rs_config.include_schemas:
                    if schema_name.lower() not in [s.lower() for s in self._rs_config.include_schemas]:
                        continue

                schemas.append(schema_name)

            return schemas
        finally:
            cursor.close()

    def _list_tables(self, schema: str) -> Iterator[RedshiftTableInfo]:
        """List tables in a schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Query to get table info including size and row count
        query = """
            SELECT
                t.table_schema,
                t.table_name,
                t.table_type,
                COALESCE(ts.diststyle, 'AUTO') as diststyle,
                COALESCE(ts.sortkey1, '') as sortkey,
                COALESCE(ts.tbl_rows, 0) as num_rows,
                COALESCE(ts.size, 0) as size_mb
            FROM svv_tables t
            LEFT JOIN svv_table_info ts
                ON t.table_schema = ts.schema
                AND t.table_name = ts.table
            WHERE t.table_schema = %s
            ORDER BY t.table_name
        """

        try:
            cursor.execute(query, (schema,))
            for row in cursor.fetchall():
                table_info = RedshiftTableInfo(
                    schema=row[0],
                    name=row[1],
                    table_type=row[2] or "TABLE",
                    diststyle=row[3] or "AUTO",
                    sortkey=[row[4]] if row[4] else [],
                    row_count=int(row[5] or 0),
                    size_mb=float(row[6] or 0),
                )

                # Get columns for this table
                table_info.columns = self._get_table_columns(schema, table_info.name)

                yield table_info

        finally:
            cursor.close()

    def _get_table_columns(self, schema: str, table: str) -> list[RedshiftColumnInfo]:
        """Get columns for a table."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = """
            SELECT
                column_name,
                data_type,
                character_maximum_length,
                is_nullable,
                CASE WHEN column_name IN (
                    SELECT column_name
                    FROM svv_table_info ti
                    JOIN information_schema.columns c ON ti.table = c.table_name
                    WHERE ti.diststyle = 'KEY' AND ti.schema = %s AND ti.table = %s
                ) THEN true ELSE false END as is_distkey,
                false as is_sortkey
            FROM information_schema.columns
            WHERE table_schema = %s AND table_name = %s
            ORDER BY ordinal_position
        """

        try:
            cursor.execute(query, (schema, table, schema, table))
            columns = []
            for row in cursor.fetchall():
                columns.append(RedshiftColumnInfo(
                    name=row[0],
                    data_type=row[1],
                    max_length=row[2],
                    is_nullable=row[3] == "YES",
                    is_distkey=row[4] if row[4] else False,
                    is_sortkey=row[5] if row[5] else False,
                ))
            return columns
        finally:
            cursor.close()

    def _should_scan_table(self, table: RedshiftTableInfo) -> bool:
        """Check if table should be scanned."""
        # Skip views and external tables by default
        if table.table_type.upper() not in ("TABLE", "BASE TABLE"):
            return False

        if table.name.lower() in [t.lower() for t in self._config.exclude_tables]:
            return False

        if self._config.include_tables:
            if table.name.lower() not in [t.lower() for t in self._config.include_tables]:
                return False

        return True

    def _should_scan_column(self, column: RedshiftColumnInfo) -> bool:
        """Check if column should be scanned."""
        col_type = column.data_type.lower()

        # Skip known non-scannable types
        if col_type in self.SKIP_TYPES:
            return False

        # Scan known text/numeric types
        if col_type in self.SCANNABLE_TYPES:
            return True

        # Check for partial matches
        if any(t in col_type for t in ["char", "text", "varchar", "string"]):
            return True

        return False

    def _sample_column(
        self,
        cursor: Any,
        schema: str,
        table: str,
        column: str,
    ) -> list[Any]:
        """
        Sample values from a column.

        Args:
            cursor: Database cursor
            schema: Schema name
            table: Table name
            column: Column name

        Returns:
            List of sampled values
        """
        # Redshift uses LIMIT like PostgreSQL
        query = f"""
            SELECT "{column}"
            FROM "{schema}"."{table}"
            WHERE "{column}" IS NOT NULL
            LIMIT {self._config.sample_rows_per_column}
        """

        try:
            cursor.execute(query)
            values = []
            for row in cursor.fetchall():
                val = row[0]
                if val is not None:
                    values.append(str(val))
            return values
        except Exception as e:
            logger.warning(
                f"Failed to sample column {schema}.{table}.{column}: {e}"
            )
            return []

    def _scan_table(
        self,
        conn: Any,
        table: RedshiftTableInfo,
    ) -> list[ExtendedScanFinding]:
        """
        Scan a single table for sensitive data.

        Args:
            conn: Database connection
            table: Table to scan

        Returns:
            List of findings for the table
        """
        findings: list[ExtendedScanFinding] = []
        cursor = conn.cursor()
        columns_scanned = 0

        try:
            for column in table.columns:
                if columns_scanned >= self._config.max_columns_per_table:
                    break

                if not self._should_scan_column(column):
                    continue

                # Sample column values
                sample_values = self._sample_column(
                    cursor, table.schema, table.name, column.name
                )

                if not sample_values:
                    continue

                columns_scanned += 1

                # Detect sensitive data using scan_records
                combined_text = "\n".join(sample_values)
                detection_result = self.detector.scan_records(
                    records=[{"content": combined_text}],
                    asset_id=f"redshift://{self._rs_config.host}/{self._rs_config.database}/{table.full_name}.{column.name}",
                    asset_type="redshift_column",
                    sample_size=1,
                )

                if detection_result.has_sensitive_data:
                    finding = self._create_finding_from_detection(
                        source_location=f"{self._rs_config.host}/{self._rs_config.database}/{table.full_name}",
                        object_type="column",
                        object_name=column.name,
                        detection_result=detection_result,
                        metadata={
                            "cluster": self._rs_config.host,
                            "database": self._rs_config.database,
                            "schema": table.schema,
                            "table": table.name,
                            "column_type": column.data_type,
                            "is_distkey": column.is_distkey,
                            "is_sortkey": column.is_sortkey,
                            "table_rows": table.row_count,
                            "table_size_mb": table.size_mb,
                            "diststyle": table.diststyle,
                            "samples_checked": len(sample_values),
                        },
                    )
                    if finding:
                        findings.append(finding)

        finally:
            cursor.close()

        return findings

    def scan(self, target: str) -> ExtendedScanResult:
        """
        Scan Redshift database for sensitive data.

        Args:
            target: Database identifier (used for logging)

        Returns:
            Scan result with findings and summary
        """
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting Redshift scan: {self._rs_config.host}/{self._rs_config.database}, "
            f"scan_id={scan_id}"
        )

        result = ExtendedScanResult(
            scan_id=scan_id,
            source_type=self.source_type,
            target=target or f"{self._rs_config.host}/{self._rs_config.database}",
            config=self._config,
            started_at=started_at,
        )

        summary = ExtendedScanSummary()
        findings: list[ExtendedScanFinding] = []

        try:
            conn = self._get_connection()
            tables_scanned = 0

            # Get schemas to scan
            schemas = self._list_schemas()

            for schema in schemas:
                # Get tables in schema
                for table in self._list_tables(schema):
                    if tables_scanned >= self._config.max_tables:
                        logger.info(f"Reached max tables limit: {self._config.max_tables}")
                        break

                    # Check table filters
                    if not self._should_scan_table(table):
                        summary.total_objects_skipped += 1
                        continue

                    # Scan the table
                    table_findings = self._scan_table(conn, table)
                    findings.extend(table_findings)

                    tables_scanned += 1
                    summary.total_objects_scanned += 1
                    summary.total_rows_sampled += (
                        self._config.sample_rows_per_column * len(table.columns)
                    )

                    # Update counts
                    for finding in table_findings:
                        summary.total_findings += 1
                        sev = finding.severity.value
                        summary.findings_by_severity[sev] = (
                            summary.findings_by_severity.get(sev, 0) + 1
                        )
                        for cat in finding.categories:
                            cat_val = cat.value
                            summary.findings_by_category[cat_val] = (
                                summary.findings_by_category.get(cat_val, 0) + 1
                            )

                if tables_scanned >= self._config.max_tables:
                    break

        except Exception as e:
            error_msg = f"Redshift error: {type(e).__name__}: {str(e)}"
            summary.errors.append(error_msg)
            logger.error(error_msg)
        finally:
            self._close_connection()

        # Finalize result
        completed_at = datetime.now(timezone.utc)
        summary.scan_duration_seconds = (completed_at - started_at).total_seconds()

        result.findings = findings
        result.summary = summary
        result.completed_at = completed_at

        logger.info(
            f"Redshift scan complete: {summary.total_objects_scanned} tables, "
            f"{summary.total_findings} findings, "
            f"{summary.scan_duration_seconds:.2f}s"
        )

        return result

    def list_scannable_objects(self, target: str) -> list[dict[str, Any]]:
        """
        List tables that can be scanned in Redshift.

        Args:
            target: Database identifier (unused, for interface compliance)

        Returns:
            List of table metadata dictionaries
        """
        tables: list[dict[str, Any]] = []

        try:
            self._get_connection()
            schemas = self._list_schemas()

            for schema in schemas:
                for table in self._list_tables(schema):
                    tables.append({
                        "cluster": self._rs_config.host,
                        "database": self._rs_config.database,
                        "schema": table.schema,
                        "name": table.name,
                        "full_name": table.full_name,
                        "table_type": table.table_type,
                        "diststyle": table.diststyle,
                        "row_count": table.row_count,
                        "size_mb": table.size_mb,
                        "column_count": len(table.columns),
                    })

        except Exception as e:
            logger.error(f"Failed to list Redshift tables: {e}")
        finally:
            self._close_connection()

        return tables


def scan_redshift(
    host: str,
    database: str,
    user: str,
    password: str,
    port: int = 5439,
    include_schemas: list[str] | None = None,
    exclude_schemas: list[str] | None = None,
    sample_rows: int = 100,
    max_tables: int = 50,
) -> ExtendedScanResult:
    """
    Convenience function to scan Redshift for sensitive data.

    Args:
        host: Redshift cluster endpoint
        database: Database name
        user: Username
        password: Password
        port: Port number (default 5439)
        include_schemas: Schemas to include
        exclude_schemas: Schemas to exclude
        sample_rows: Number of rows to sample per column
        max_tables: Maximum tables to scan

    Returns:
        Scan result with findings and summary
    """
    rs_config = RedshiftConfig(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
        include_schemas=include_schemas,
        exclude_schemas=exclude_schemas or [
            "information_schema",
            "pg_catalog",
            "pg_internal",
            "catalog_history",
        ],
    )

    scan_config = ExtendedScanConfig(
        sample_rows_per_column=sample_rows,
        max_tables=max_tables,
    )

    scanner = RedshiftScanner(rs_config=rs_config, scan_config=scan_config)
    return scanner.scan(f"{host}/{database}")
