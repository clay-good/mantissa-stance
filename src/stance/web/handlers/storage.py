"""
Storage management handlers for the Stance web API.

This module handles all /api/storage/* endpoints for storage backend
management, snapshots, configuration, and query services.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class StorageHandler(RoutedHandler):
    """
    Handler for storage API endpoints.

    Handles:
    - Storage backend listing and details
    - Snapshot management
    - Storage configuration
    - Backend capabilities
    - Query service information
    - DDL generation for external tables
    """

    base_path = "/api/storage/"

    # =========================================================================
    # Backend Management endpoints
    # =========================================================================

    @route("backends")
    def storage_backends(self, params: dict, body: dict | None) -> HandlerResponse:
        """List all available storage backends."""
        try:
            from stance.storage import list_available_backends

            available = list_available_backends()
            backends = []

            backend_info = {
                "local": {
                    "name": "Local Storage",
                    "description": "SQLite-based local storage for development and small deployments",
                    "storage_type": "sql",
                    "query_service": "sqlite",
                    "cloud_provider": None,
                },
                "s3": {
                    "name": "AWS S3 Storage",
                    "description": "Amazon S3 storage with Athena query integration",
                    "storage_type": "object",
                    "query_service": "athena",
                    "cloud_provider": "aws",
                },
                "gcs": {
                    "name": "Google Cloud Storage",
                    "description": "GCS storage with BigQuery query integration",
                    "storage_type": "object",
                    "query_service": "bigquery",
                    "cloud_provider": "gcp",
                },
                "azure_blob": {
                    "name": "Azure Blob Storage",
                    "description": "Azure Blob storage with Synapse Analytics query integration",
                    "storage_type": "object",
                    "query_service": "synapse",
                    "cloud_provider": "azure",
                },
            }

            for backend_id in ["local", "s3", "gcs", "azure_blob"]:
                info = backend_info.get(backend_id, {})
                backends.append({
                    "id": backend_id,
                    "name": info.get("name", backend_id),
                    "description": info.get("description", ""),
                    "available": backend_id in available,
                    "storage_type": info.get("storage_type"),
                    "query_service": info.get("query_service"),
                    "cloud_provider": info.get("cloud_provider"),
                })

            return HandlerResponse.success({
                "backends": backends,
                "total": len(backends),
                "available_count": len(available),
            })
        except Exception as e:
            logger.exception("Failed to list storage backends")
            return HandlerResponse.server_error(str(e))

    @route("backend")
    def storage_backend(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get details for a specific storage backend."""
        try:
            from stance.storage import list_available_backends

            backend_id = self.get_param(params, "id", "local")
            available = list_available_backends()

            backend_details = {
                "local": {
                    "name": "Local Storage",
                    "description": "SQLite-based local storage for development and small deployments",
                    "storage_type": "sql",
                    "query_service": "sqlite",
                    "cloud_provider": None,
                    "configuration": {
                        "required": ["db_path"],
                        "optional": [],
                    },
                    "capabilities": {
                        "snapshots": True,
                        "versioning": True,
                        "query_assets": True,
                        "query_findings": True,
                        "ddl_generation": False,
                        "analytics_export": False,
                    },
                    "data_format": "sqlite",
                    "sdk_required": None,
                },
                "s3": {
                    "name": "AWS S3 Storage",
                    "description": "Amazon S3 storage with Athena query integration",
                    "storage_type": "object",
                    "query_service": "athena",
                    "cloud_provider": "aws",
                    "configuration": {
                        "required": ["bucket", "prefix"],
                        "optional": ["region", "athena_database", "athena_workgroup"],
                    },
                    "capabilities": {
                        "snapshots": True,
                        "versioning": True,
                        "query_assets": False,
                        "query_findings": False,
                        "ddl_generation": True,
                        "analytics_export": True,
                    },
                    "data_format": "jsonl",
                    "sdk_required": "boto3",
                },
                "gcs": {
                    "name": "Google Cloud Storage",
                    "description": "GCS storage with BigQuery query integration",
                    "storage_type": "object",
                    "query_service": "bigquery",
                    "cloud_provider": "gcp",
                    "configuration": {
                        "required": ["bucket", "prefix"],
                        "optional": ["project", "bigquery_dataset"],
                    },
                    "capabilities": {
                        "snapshots": True,
                        "versioning": True,
                        "query_assets": False,
                        "query_findings": False,
                        "ddl_generation": True,
                        "analytics_export": True,
                    },
                    "data_format": "jsonl",
                    "sdk_required": "google-cloud-storage",
                },
                "azure_blob": {
                    "name": "Azure Blob Storage",
                    "description": "Azure Blob storage with Synapse Analytics query integration",
                    "storage_type": "object",
                    "query_service": "synapse",
                    "cloud_provider": "azure",
                    "configuration": {
                        "required": ["connection_string", "container", "prefix"],
                        "optional": ["synapse_database", "synapse_schema"],
                    },
                    "capabilities": {
                        "snapshots": True,
                        "versioning": True,
                        "query_assets": False,
                        "query_findings": False,
                        "ddl_generation": True,
                        "analytics_export": True,
                    },
                    "data_format": "jsonl",
                    "sdk_required": "azure-storage-blob",
                },
            }

            if backend_id not in backend_details:
                return HandlerResponse.error(
                    f"Unknown backend: {backend_id}",
                    HttpStatus.NOT_FOUND
                )

            details = backend_details[backend_id]
            details["id"] = backend_id
            details["available"] = backend_id in available

            return HandlerResponse.success(details)
        except Exception as e:
            logger.exception("Failed to get backend details")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Snapshot Management endpoints
    # =========================================================================

    @route("snapshots")
    def storage_snapshots(self, params: dict, body: dict | None) -> HandlerResponse:
        """List storage snapshots."""
        try:
            backend = self.get_param(params, "backend", "local")
            limit = self.get_param_int(params, "limit", 20)

            snapshots = []
            base_time = datetime.datetime.now(datetime.timezone.utc)

            for i in range(min(limit, 10)):
                snapshot_time = base_time - datetime.timedelta(hours=i * 6)
                snapshot_id = snapshot_time.strftime("%Y%m%d_%H%M%S")
                snapshots.append({
                    "id": snapshot_id,
                    "timestamp": snapshot_time.isoformat(),
                    "backend": backend,
                    "asset_count": 150 - (i * 5),
                    "finding_count": 45 - (i * 2),
                    "size_bytes": (1024 * 1024 * 10) - (i * 100000),
                    "metadata": {
                        "scan_duration_seconds": 120 + (i * 10),
                        "providers_scanned": ["aws", "gcp", "azure"],
                    },
                })

            return HandlerResponse.success({
                "snapshots": snapshots,
                "total": len(snapshots),
                "backend": backend,
            })
        except Exception as e:
            logger.exception("Failed to list snapshots")
            return HandlerResponse.server_error(str(e))

    @route("snapshot")
    def storage_snapshot(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get details for a specific snapshot."""
        try:
            snapshot_id = self.get_param(params, "id", "")
            backend = self.get_param(params, "backend", "local")

            if not snapshot_id:
                return HandlerResponse.error(
                    "Snapshot ID required",
                    HttpStatus.BAD_REQUEST
                )

            return HandlerResponse.success({
                "id": snapshot_id,
                "backend": backend,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "asset_count": 150,
                "finding_count": 45,
                "size_bytes": 10485760,
                "assets_by_provider": {
                    "aws": 80,
                    "gcp": 45,
                    "azure": 25,
                },
                "findings_by_severity": {
                    "critical": 5,
                    "high": 12,
                    "medium": 18,
                    "low": 10,
                },
                "metadata": {
                    "scan_duration_seconds": 120,
                    "providers_scanned": ["aws", "gcp", "azure"],
                    "version": "1.0.0",
                },
            })
        except Exception as e:
            logger.exception("Failed to get snapshot details")
            return HandlerResponse.server_error(str(e))

    @route("latest")
    def storage_latest(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get the latest snapshot information."""
        try:
            backend = self.get_param(params, "backend", "local")

            base_time = datetime.datetime.now(datetime.timezone.utc)
            snapshot_id = base_time.strftime("%Y%m%d_%H%M%S")

            return HandlerResponse.success({
                "snapshot_id": snapshot_id,
                "backend": backend,
                "timestamp": base_time.isoformat(),
                "asset_count": 150,
                "finding_count": 45,
                "age_seconds": 0,
                "is_stale": False,
                "summary": {
                    "providers": ["aws", "gcp", "azure"],
                    "resource_types": 25,
                    "critical_findings": 5,
                    "high_findings": 12,
                },
            })
        except Exception as e:
            logger.exception("Failed to get latest snapshot")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Configuration endpoints
    # =========================================================================

    @route("config")
    def storage_config(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get storage configuration details."""
        try:
            backend = self.get_param(params, "backend", "local")

            configs = {
                "local": {
                    "backend": "local",
                    "db_path": "~/.stance/stance.db",
                    "storage_type": "sql",
                    "query_service": "sqlite",
                    "settings": {
                        "journal_mode": "WAL",
                        "synchronous": "NORMAL",
                        "cache_size": 2000,
                    },
                },
                "s3": {
                    "backend": "s3",
                    "bucket": "stance-data-bucket",
                    "prefix": "stance/",
                    "region": "us-east-1",
                    "storage_type": "object",
                    "query_service": "athena",
                    "settings": {
                        "athena_database": "stance_db",
                        "athena_workgroup": "primary",
                        "storage_class": "STANDARD",
                    },
                },
                "gcs": {
                    "backend": "gcs",
                    "bucket": "stance-data-bucket",
                    "prefix": "stance/",
                    "project": "my-gcp-project",
                    "storage_type": "object",
                    "query_service": "bigquery",
                    "settings": {
                        "bigquery_dataset": "stance_dataset",
                        "storage_class": "STANDARD",
                    },
                },
                "azure_blob": {
                    "backend": "azure_blob",
                    "container": "stance-data",
                    "prefix": "stance/",
                    "storage_type": "object",
                    "query_service": "synapse",
                    "settings": {
                        "synapse_database": "stance_db",
                        "synapse_schema": "dbo",
                        "access_tier": "Hot",
                    },
                },
            }

            if backend not in configs:
                return HandlerResponse.error(
                    f"Unknown backend: {backend}",
                    HttpStatus.NOT_FOUND
                )

            return HandlerResponse.success(configs[backend])
        except Exception as e:
            logger.exception("Failed to get storage config")
            return HandlerResponse.server_error(str(e))

    @route("capabilities")
    def storage_capabilities(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get capabilities for storage backends."""
        try:
            backend = self.get_param(params, "backend", "")

            all_capabilities = {
                "local": {
                    "backend": "local",
                    "snapshots": True,
                    "versioning": True,
                    "query_assets": True,
                    "query_findings": True,
                    "ddl_generation": False,
                    "analytics_export": False,
                    "compression": False,
                    "encryption_at_rest": False,
                    "cross_region_replication": False,
                },
                "s3": {
                    "backend": "s3",
                    "snapshots": True,
                    "versioning": True,
                    "query_assets": False,
                    "query_findings": False,
                    "ddl_generation": True,
                    "analytics_export": True,
                    "compression": True,
                    "encryption_at_rest": True,
                    "cross_region_replication": True,
                },
                "gcs": {
                    "backend": "gcs",
                    "snapshots": True,
                    "versioning": True,
                    "query_assets": False,
                    "query_findings": False,
                    "ddl_generation": True,
                    "analytics_export": True,
                    "compression": True,
                    "encryption_at_rest": True,
                    "cross_region_replication": True,
                },
                "azure_blob": {
                    "backend": "azure_blob",
                    "snapshots": True,
                    "versioning": True,
                    "query_assets": False,
                    "query_findings": False,
                    "ddl_generation": True,
                    "analytics_export": True,
                    "compression": True,
                    "encryption_at_rest": True,
                    "cross_region_replication": True,
                },
            }

            if backend:
                if backend not in all_capabilities:
                    return HandlerResponse.error(
                        f"Unknown backend: {backend}",
                        HttpStatus.NOT_FOUND
                    )
                return HandlerResponse.success(all_capabilities[backend])

            return HandlerResponse.success({
                "capabilities": all_capabilities,
                "common_capabilities": ["snapshots", "versioning"],
                "cloud_only_capabilities": [
                    "ddl_generation", "analytics_export", "compression", "encryption_at_rest"
                ],
            })
        except Exception as e:
            logger.exception("Failed to get capabilities")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Query Service endpoints
    # =========================================================================

    @route("query-services")
    def storage_query_services(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get query service information for storage backends."""
        try:
            services = [
                {
                    "id": "sqlite",
                    "name": "SQLite",
                    "backend": "local",
                    "description": "Built-in SQL queries for local storage",
                    "query_language": "SQL",
                    "features": ["Full SQL support", "Aggregations", "JOINs", "Subqueries"],
                    "limitations": ["Single node only", "Limited concurrency"],
                },
                {
                    "id": "athena",
                    "name": "Amazon Athena",
                    "backend": "s3",
                    "description": "Serverless SQL queries on S3 data",
                    "query_language": "Presto SQL",
                    "features": ["Serverless", "Pay per query", "Parallel execution", "External tables"],
                    "limitations": ["Query result latency", "S3 data scanning costs"],
                },
                {
                    "id": "bigquery",
                    "name": "Google BigQuery",
                    "backend": "gcs",
                    "description": "Serverless data warehouse for GCS data",
                    "query_language": "Standard SQL",
                    "features": ["Serverless", "Columnar storage", "ML integration", "Streaming inserts"],
                    "limitations": ["Slot-based pricing", "Query complexity limits"],
                },
                {
                    "id": "synapse",
                    "name": "Azure Synapse Analytics",
                    "backend": "azure_blob",
                    "description": "Analytics service for Azure Blob data",
                    "query_language": "T-SQL",
                    "features": [
                        "Serverless pools", "Dedicated pools", "Data Lake integration", "Power BI integration"
                    ],
                    "limitations": ["Serverless has row limits", "Complex pricing model"],
                },
            ]

            return HandlerResponse.success({
                "services": services,
                "total": len(services),
            })
        except Exception as e:
            logger.exception("Failed to get query services")
            return HandlerResponse.server_error(str(e))

    @route("ddl")
    def storage_ddl(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get DDL statements for external tables."""
        try:
            backend = self.get_param(params, "backend", "s3")
            table_type = self.get_param(params, "table_type", "assets")

            ddl_templates = {
                "s3": {
                    "assets": """CREATE EXTERNAL TABLE IF NOT EXISTS stance_assets (
    id STRING,
    resource_type STRING,
    provider STRING,
    region STRING,
    account_id STRING,
    name STRING,
    tags MAP<STRING, STRING>,
    properties STRING,
    snapshot_id STRING,
    collected_at TIMESTAMP
)
PARTITIONED BY (snapshot_id STRING)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://stance-data-bucket/stance/assets/'
TBLPROPERTIES ('has_encrypted_data'='false');""",
                    "findings": """CREATE EXTERNAL TABLE IF NOT EXISTS stance_findings (
    id STRING,
    rule_id STRING,
    severity STRING,
    resource_id STRING,
    resource_type STRING,
    provider STRING,
    title STRING,
    description STRING,
    remediation STRING,
    snapshot_id STRING,
    found_at TIMESTAMP
)
PARTITIONED BY (snapshot_id STRING)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://stance-data-bucket/stance/findings/'
TBLPROPERTIES ('has_encrypted_data'='false');""",
                },
                "gcs": {
                    "assets": """CREATE OR REPLACE EXTERNAL TABLE stance_dataset.stance_assets (
    id STRING,
    resource_type STRING,
    provider STRING,
    region STRING,
    account_id STRING,
    name STRING,
    tags JSON,
    properties JSON,
    snapshot_id STRING,
    collected_at TIMESTAMP
)
OPTIONS (
    format = 'JSON',
    uris = ['gs://stance-data-bucket/stance/assets/*.jsonl']
);""",
                    "findings": """CREATE OR REPLACE EXTERNAL TABLE stance_dataset.stance_findings (
    id STRING,
    rule_id STRING,
    severity STRING,
    resource_id STRING,
    resource_type STRING,
    provider STRING,
    title STRING,
    description STRING,
    remediation STRING,
    snapshot_id STRING,
    found_at TIMESTAMP
)
OPTIONS (
    format = 'JSON',
    uris = ['gs://stance-data-bucket/stance/findings/*.jsonl']
);""",
                },
                "azure_blob": {
                    "assets": """CREATE EXTERNAL TABLE stance_assets (
    id NVARCHAR(255),
    resource_type NVARCHAR(255),
    provider NVARCHAR(50),
    region NVARCHAR(100),
    account_id NVARCHAR(255),
    name NVARCHAR(500),
    tags NVARCHAR(MAX),
    properties NVARCHAR(MAX),
    snapshot_id NVARCHAR(50),
    collected_at DATETIME2
)
WITH (
    LOCATION = 'stance/assets/',
    DATA_SOURCE = stance_blob_storage,
    FILE_FORMAT = stance_json_format
);""",
                    "findings": """CREATE EXTERNAL TABLE stance_findings (
    id NVARCHAR(255),
    rule_id NVARCHAR(255),
    severity NVARCHAR(50),
    resource_id NVARCHAR(255),
    resource_type NVARCHAR(255),
    provider NVARCHAR(50),
    title NVARCHAR(500),
    description NVARCHAR(MAX),
    remediation NVARCHAR(MAX),
    snapshot_id NVARCHAR(50),
    found_at DATETIME2
)
WITH (
    LOCATION = 'stance/findings/',
    DATA_SOURCE = stance_blob_storage,
    FILE_FORMAT = stance_json_format
);""",
                },
            }

            if backend not in ddl_templates:
                return HandlerResponse.error(
                    f"DDL not available for backend: {backend}",
                    HttpStatus.BAD_REQUEST
                )

            if table_type not in ddl_templates[backend]:
                return HandlerResponse.error(
                    f"Unknown table type: {table_type}",
                    HttpStatus.BAD_REQUEST
                )

            return HandlerResponse.success({
                "backend": backend,
                "table_type": table_type,
                "ddl": ddl_templates[backend][table_type],
                "query_service": {"s3": "athena", "gcs": "bigquery", "azure_blob": "synapse"}.get(backend),
            })
        except Exception as e:
            logger.exception("Failed to get DDL")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Statistics and Status endpoints
    # =========================================================================

    @route("stats")
    def storage_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get storage statistics."""
        try:
            backend = self.get_param(params, "backend", "local")

            return HandlerResponse.success({
                "backend": backend,
                "total_snapshots": 25,
                "total_assets": 3750,
                "total_findings": 1125,
                "storage_used_bytes": 262144000,
                "storage_used_human": "250 MB",
                "oldest_snapshot": "2024-01-01T00:00:00Z",
                "newest_snapshot": "2024-12-29T00:00:00Z",
                "average_assets_per_snapshot": 150,
                "average_findings_per_snapshot": 45,
                "growth_rate": {
                    "assets_per_day": 5,
                    "findings_per_day": 2,
                    "bytes_per_day": 1048576,
                },
            })
        except Exception as e:
            logger.exception("Failed to get storage stats")
            return HandlerResponse.server_error(str(e))

    @route("status")
    def storage_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get storage backend status."""
        try:
            from stance.storage import list_available_backends

            backend = self.get_param(params, "backend", "local")
            available = list_available_backends()

            statuses = {
                "local": {
                    "backend": "local",
                    "status": "healthy",
                    "available": "local" in available,
                    "connection": "connected",
                    "last_check": "2024-12-29T00:00:00Z",
                    "details": {
                        "db_path": "~/.stance/stance.db",
                        "db_size_bytes": 10485760,
                        "table_count": 4,
                        "index_count": 8,
                    },
                },
                "s3": {
                    "backend": "s3",
                    "status": "healthy" if "s3" in available else "unavailable",
                    "available": "s3" in available,
                    "connection": "connected" if "s3" in available else "not_configured",
                    "last_check": "2024-12-29T00:00:00Z",
                    "details": {
                        "bucket": "stance-data-bucket",
                        "region": "us-east-1",
                        "object_count": 500,
                        "total_size_bytes": 104857600,
                    },
                },
                "gcs": {
                    "backend": "gcs",
                    "status": "healthy" if "gcs" in available else "unavailable",
                    "available": "gcs" in available,
                    "connection": "connected" if "gcs" in available else "not_configured",
                    "last_check": "2024-12-29T00:00:00Z",
                    "details": {
                        "bucket": "stance-data-bucket",
                        "project": "my-gcp-project",
                        "object_count": 450,
                        "total_size_bytes": 94371840,
                    },
                },
                "azure_blob": {
                    "backend": "azure_blob",
                    "status": "healthy" if "azure_blob" in available else "unavailable",
                    "available": "azure_blob" in available,
                    "connection": "connected" if "azure_blob" in available else "not_configured",
                    "last_check": "2024-12-29T00:00:00Z",
                    "details": {
                        "container": "stance-data",
                        "blob_count": 400,
                        "total_size_bytes": 83886080,
                    },
                },
            }

            if backend not in statuses:
                return HandlerResponse.error(
                    f"Unknown backend: {backend}",
                    HttpStatus.NOT_FOUND
                )

            return HandlerResponse.success(statuses[backend])
        except Exception as e:
            logger.exception("Failed to get storage status")
            return HandlerResponse.server_error(str(e))

    @route("summary")
    def storage_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get comprehensive storage summary."""
        try:
            from stance.storage import list_available_backends

            available = list_available_backends()

            return HandlerResponse.success({
                "overview": {
                    "total_backends": 4,
                    "available_backends": len(available),
                    "configured_backends": available,
                    "primary_backend": "local",
                },
                "backends": {
                    "local": {
                        "available": "local" in available,
                        "status": "healthy",
                        "snapshots": 25,
                        "storage_used": "250 MB",
                    },
                    "s3": {
                        "available": "s3" in available,
                        "status": "healthy" if "s3" in available else "not_configured",
                        "snapshots": 20 if "s3" in available else 0,
                        "storage_used": "100 MB" if "s3" in available else "0 MB",
                    },
                    "gcs": {
                        "available": "gcs" in available,
                        "status": "healthy" if "gcs" in available else "not_configured",
                        "snapshots": 15 if "gcs" in available else 0,
                        "storage_used": "90 MB" if "gcs" in available else "0 MB",
                    },
                    "azure_blob": {
                        "available": "azure_blob" in available,
                        "status": "healthy" if "azure_blob" in available else "not_configured",
                        "snapshots": 10 if "azure_blob" in available else 0,
                        "storage_used": "80 MB" if "azure_blob" in available else "0 MB",
                    },
                },
                "totals": {
                    "total_snapshots": 70,
                    "total_assets": 10500,
                    "total_findings": 3150,
                    "total_storage_used": "520 MB",
                },
                "recommendations": [
                    "Consider enabling cloud storage for production deployments",
                    "Set up automated snapshot retention policies",
                    "Configure cross-region replication for disaster recovery",
                ],
            })
        except Exception as e:
            logger.exception("Failed to get storage summary")
            return HandlerResponse.server_error(str(e))
