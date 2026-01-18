"""
BigQuery Scanner for DSPM.

Scans Google BigQuery datasets and tables to detect sensitive data
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

# Optional BigQuery import
try:
    from google.cloud import bigquery
    from google.oauth2 import service_account
    HAS_BIGQUERY = True
except ImportError:
    bigquery = None  # type: ignore
    service_account = None  # type: ignore
    HAS_BIGQUERY = False


@dataclass
class BigQueryConfig:
    """
    Configuration for BigQuery connection.

    Attributes:
        project_id: Google Cloud project ID
        credentials_path: Path to service account JSON key file
        credentials_info: Credentials as a dictionary (alternative to path)
        location: Default location for queries (e.g., 'US', 'EU')
        include_datasets: Datasets to include (None for all)
        exclude_datasets: Datasets to exclude
        max_bytes_billed: Maximum bytes to bill per query (safety limit)
        use_legacy_sql: Whether to use legacy SQL syntax
    """

    project_id: str
    credentials_path: str | None = None
    credentials_info: dict[str, Any] | None = None
    location: str = "US"
    include_datasets: list[str] | None = None
    exclude_datasets: list[str] = field(default_factory=lambda: ["INFORMATION_SCHEMA"])
    max_bytes_billed: int = 10 * 1024 * 1024 * 1024  # 10 GB default limit
    use_legacy_sql: bool = False

    def __post_init__(self):
        """Validate configuration."""
        if not self.credentials_path and not self.credentials_info:
            # Will use application default credentials
            pass


@dataclass
class BigQueryColumnInfo:
    """
    Information about a BigQuery column.

    Attributes:
        name: Column name
        field_type: BigQuery field type (STRING, INTEGER, etc.)
        mode: Column mode (NULLABLE, REQUIRED, REPEATED)
        description: Column description
        is_partitioning: Whether column is used for partitioning
        sample_values: Sampled values from column
    """

    name: str
    field_type: str
    mode: str = "NULLABLE"
    description: str = ""
    is_partitioning: bool = False
    sample_values: list[Any] = field(default_factory=list)


@dataclass
class BigQueryTableInfo:
    """
    Information about a BigQuery table.

    Attributes:
        dataset_id: Dataset ID
        table_id: Table ID
        table_type: Type (TABLE, VIEW, EXTERNAL, etc.)
        num_rows: Number of rows
        num_bytes: Size in bytes
        created: Creation time
        modified: Last modification time
        columns: List of columns
        is_partitioned: Whether table is partitioned
        partition_field: Partitioning field name
    """

    dataset_id: str
    table_id: str
    table_type: str = "TABLE"
    num_rows: int = 0
    num_bytes: int = 0
    created: datetime | None = None
    modified: datetime | None = None
    columns: list[BigQueryColumnInfo] = field(default_factory=list)
    is_partitioned: bool = False
    partition_field: str | None = None

    @property
    def full_name(self) -> str:
        """Get fully qualified table name."""
        return f"{self.dataset_id}.{self.table_id}"


class BigQueryScanner(BaseExtendedScanner):
    """
    BigQuery scanner for sensitive data detection.

    Samples data from BigQuery tables and columns to identify
    PII, PCI, PHI, and other sensitive data patterns.

    All operations are read-only using SELECT queries with LIMIT.
    """

    source_type = ExtendedSourceType.BIGQUERY

    # Field types that should be scanned for sensitive data
    SCANNABLE_TYPES = {
        "STRING", "BYTES",
        "INTEGER", "INT64", "FLOAT", "FLOAT64", "NUMERIC", "BIGNUMERIC",
        "JSON",
    }

    # Field types to skip
    SKIP_TYPES = {
        "DATE", "TIME", "DATETIME", "TIMESTAMP",
        "BOOLEAN", "BOOL",
        "GEOGRAPHY", "GEOMETRY",
        "STRUCT", "RECORD",
        "ARRAY",
    }

    def __init__(
        self,
        bq_config: BigQueryConfig,
        scan_config: ExtendedScanConfig | None = None,
    ):
        """
        Initialize BigQuery scanner.

        Args:
            bq_config: BigQuery connection configuration
            scan_config: Optional scan configuration
        """
        super().__init__(scan_config)
        self._bq_config = bq_config
        self._client: Any = None

        if not HAS_BIGQUERY:
            logger.warning(
                "google-cloud-bigquery not installed. "
                "Install with: pip install google-cloud-bigquery"
            )

    def _get_client(self) -> Any:
        """Get or create BigQuery client."""
        if self._client is not None:
            return self._client

        if not HAS_BIGQUERY:
            raise ImportError(
                "google-cloud-bigquery is required for BigQuery scanning. "
                "Install with: pip install google-cloud-bigquery"
            )

        if self._bq_config.credentials_path:
            credentials = service_account.Credentials.from_service_account_file(
                self._bq_config.credentials_path
            )
            self._client = bigquery.Client(
                project=self._bq_config.project_id,
                credentials=credentials,
                location=self._bq_config.location,
            )
        elif self._bq_config.credentials_info:
            credentials = service_account.Credentials.from_service_account_info(
                self._bq_config.credentials_info
            )
            self._client = bigquery.Client(
                project=self._bq_config.project_id,
                credentials=credentials,
                location=self._bq_config.location,
            )
        else:
            # Use application default credentials
            self._client = bigquery.Client(
                project=self._bq_config.project_id,
                location=self._bq_config.location,
            )

        return self._client

    def _close_client(self) -> None:
        """Close BigQuery client."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def test_connection(self) -> bool:
        """
        Test connection to BigQuery.

        Returns:
            True if connection successful
        """
        try:
            client = self._get_client()
            # Test by listing datasets (limited to 1)
            list(client.list_datasets(max_results=1))
            return True
        except Exception as e:
            logger.error(f"BigQuery connection test failed: {type(e).__name__}: {e}")
            return False
        finally:
            self._close_client()

    def _list_datasets(self) -> list[str]:
        """List datasets in the project."""
        client = self._get_client()
        datasets = []

        for dataset in client.list_datasets():
            dataset_id = dataset.dataset_id

            # Check exclusion filter
            if dataset_id in self._bq_config.exclude_datasets:
                continue

            # Check inclusion filter
            if self._bq_config.include_datasets:
                if dataset_id not in self._bq_config.include_datasets:
                    continue

            datasets.append(dataset_id)

        return datasets

    def _list_tables(self, dataset_id: str) -> Iterator[BigQueryTableInfo]:
        """List tables in a dataset."""
        client = self._get_client()
        dataset_ref = client.dataset(dataset_id)

        for table_item in client.list_tables(dataset_ref):
            try:
                # Get full table metadata
                table = client.get_table(table_item.reference)

                # Extract column info
                columns = [
                    BigQueryColumnInfo(
                        name=field.name,
                        field_type=field.field_type,
                        mode=field.mode,
                        description=field.description or "",
                    )
                    for field in table.schema
                ]

                # Check for partitioning
                is_partitioned = table.time_partitioning is not None
                partition_field = None
                if is_partitioned and table.time_partitioning:
                    partition_field = table.time_partitioning.field

                yield BigQueryTableInfo(
                    dataset_id=dataset_id,
                    table_id=table.table_id,
                    table_type=table.table_type,
                    num_rows=table.num_rows or 0,
                    num_bytes=table.num_bytes or 0,
                    created=table.created,
                    modified=table.modified,
                    columns=columns,
                    is_partitioned=is_partitioned,
                    partition_field=partition_field,
                )

            except Exception as e:
                logger.warning(f"Failed to get table metadata for {dataset_id}.{table_item.table_id}: {e}")
                continue

    def _should_scan_table(self, table: BigQueryTableInfo) -> bool:
        """Check if table should be scanned."""
        # Skip views and external tables by default
        if table.table_type not in ("TABLE", "SNAPSHOT"):
            return False

        if table.table_id.lower() in [t.lower() for t in self._config.exclude_tables]:
            return False

        if self._config.include_tables:
            if table.table_id.lower() not in [t.lower() for t in self._config.include_tables]:
                return False

        return True

    def _should_scan_column(self, column: BigQueryColumnInfo) -> bool:
        """Check if column should be scanned."""
        field_type = column.field_type.upper()

        # Skip known non-scannable types
        if field_type in self.SKIP_TYPES:
            return False

        # Scan known text/numeric types
        if field_type in self.SCANNABLE_TYPES:
            return True

        return False

    def _sample_column(
        self,
        table: BigQueryTableInfo,
        column: BigQueryColumnInfo,
    ) -> list[Any]:
        """
        Sample values from a BigQuery column.

        Args:
            table: Table information
            column: Column to sample

        Returns:
            List of sampled values
        """
        client = self._get_client()
        project_id = self._bq_config.project_id
        full_table_name = f"`{project_id}.{table.dataset_id}.{table.table_id}`"

        # Build query with LIMIT
        query = f"""
            SELECT `{column.name}`
            FROM {full_table_name}
            WHERE `{column.name}` IS NOT NULL
            LIMIT {self._config.sample_rows_per_column}
        """

        job_config = bigquery.QueryJobConfig(
            use_legacy_sql=self._bq_config.use_legacy_sql,
            maximum_bytes_billed=self._bq_config.max_bytes_billed,
        )

        try:
            query_job = client.query(query, job_config=job_config)
            results = query_job.result()

            values = []
            for row in results:
                val = row[0]
                if val is not None:
                    values.append(str(val))

            return values

        except Exception as e:
            logger.warning(
                f"Failed to sample column {table.full_name}.{column.name}: {e}"
            )
            return []

    def _scan_table(self, table: BigQueryTableInfo) -> list[ExtendedScanFinding]:
        """
        Scan a single table for sensitive data.

        Args:
            table: Table to scan

        Returns:
            List of findings for the table
        """
        findings: list[ExtendedScanFinding] = []
        columns_scanned = 0
        project_id = self._bq_config.project_id

        for column in table.columns:
            if columns_scanned >= self._config.max_columns_per_table:
                break

            if not self._should_scan_column(column):
                continue

            # Sample column values
            sample_values = self._sample_column(table, column)

            if not sample_values:
                continue

            columns_scanned += 1

            # Detect sensitive data using scan_records
            combined_text = "\n".join(sample_values)
            detection_result = self.detector.scan_records(
                records=[{"content": combined_text}],
                asset_id=f"bigquery://{project_id}.{table.full_name}.{column.name}",
                asset_type="bigquery_column",
                sample_size=1,
            )

            if detection_result.has_sensitive_data:
                finding = self._create_finding_from_detection(
                    source_location=f"{project_id}.{table.full_name}",
                    object_type="column",
                    object_name=column.name,
                    detection_result=detection_result,
                    metadata={
                        "project_id": project_id,
                        "dataset_id": table.dataset_id,
                        "table_id": table.table_id,
                        "column_type": column.field_type,
                        "column_mode": column.mode,
                        "table_rows": table.num_rows,
                        "table_bytes": table.num_bytes,
                        "is_partitioned": table.is_partitioned,
                        "samples_checked": len(sample_values),
                    },
                )
                if finding:
                    findings.append(finding)

        return findings

    def scan(self, target: str) -> ExtendedScanResult:
        """
        Scan BigQuery datasets for sensitive data.

        Args:
            target: Project ID or dataset name to scan

        Returns:
            Scan result with findings and summary
        """
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting BigQuery scan: project={self._bq_config.project_id}, "
            f"scan_id={scan_id}"
        )

        result = ExtendedScanResult(
            scan_id=scan_id,
            source_type=self.source_type,
            target=target or self._bq_config.project_id,
            config=self._config,
            started_at=started_at,
        )

        summary = ExtendedScanSummary()
        findings: list[ExtendedScanFinding] = []

        try:
            tables_scanned = 0

            # Get datasets to scan
            datasets = self._list_datasets()

            for dataset_id in datasets:
                # Get tables in dataset
                for table in self._list_tables(dataset_id):
                    if tables_scanned >= self._config.max_tables:
                        logger.info(f"Reached max tables limit: {self._config.max_tables}")
                        break

                    # Check table filters
                    if not self._should_scan_table(table):
                        summary.total_objects_skipped += 1
                        continue

                    # Scan the table
                    table_findings = self._scan_table(table)
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
            error_msg = f"BigQuery error: {type(e).__name__}: {str(e)}"
            summary.errors.append(error_msg)
            logger.error(error_msg)
        finally:
            self._close_client()

        # Finalize result
        completed_at = datetime.now(timezone.utc)
        summary.scan_duration_seconds = (completed_at - started_at).total_seconds()

        result.findings = findings
        result.summary = summary
        result.completed_at = completed_at

        logger.info(
            f"BigQuery scan complete: {summary.total_objects_scanned} tables, "
            f"{summary.total_findings} findings, "
            f"{summary.scan_duration_seconds:.2f}s"
        )

        return result

    def list_scannable_objects(self, target: str) -> list[dict[str, Any]]:
        """
        List tables that can be scanned in BigQuery.

        Args:
            target: Project ID or dataset name

        Returns:
            List of table metadata dictionaries
        """
        tables: list[dict[str, Any]] = []

        try:
            datasets = self._list_datasets()

            for dataset_id in datasets:
                for table in self._list_tables(dataset_id):
                    tables.append({
                        "project_id": self._bq_config.project_id,
                        "dataset_id": table.dataset_id,
                        "table_id": table.table_id,
                        "full_name": f"{self._bq_config.project_id}.{table.full_name}",
                        "table_type": table.table_type,
                        "num_rows": table.num_rows,
                        "num_bytes": table.num_bytes,
                        "column_count": len(table.columns),
                        "is_partitioned": table.is_partitioned,
                    })

        except Exception as e:
            logger.error(f"Failed to list BigQuery tables: {e}")
        finally:
            self._close_client()

        return tables


def scan_bigquery(
    project_id: str,
    credentials_path: str | None = None,
    credentials_info: dict[str, Any] | None = None,
    include_datasets: list[str] | None = None,
    exclude_datasets: list[str] | None = None,
    sample_rows: int = 100,
    max_tables: int = 50,
) -> ExtendedScanResult:
    """
    Convenience function to scan BigQuery for sensitive data.

    Args:
        project_id: Google Cloud project ID
        credentials_path: Path to service account JSON key file
        credentials_info: Credentials as a dictionary
        include_datasets: Datasets to include
        exclude_datasets: Datasets to exclude
        sample_rows: Number of rows to sample per column
        max_tables: Maximum tables to scan

    Returns:
        Scan result with findings and summary
    """
    bq_config = BigQueryConfig(
        project_id=project_id,
        credentials_path=credentials_path,
        credentials_info=credentials_info,
        include_datasets=include_datasets,
        exclude_datasets=exclude_datasets or ["INFORMATION_SCHEMA"],
    )

    scan_config = ExtendedScanConfig(
        sample_rows_per_column=sample_rows,
        max_tables=max_tables,
    )

    scanner = BigQueryScanner(bq_config=bq_config, scan_config=scan_config)
    return scanner.scan(project_id)
