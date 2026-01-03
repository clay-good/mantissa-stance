"""
Unit tests for Web API Storage endpoints.

Tests the REST API endpoints for the Storage module.
"""

import pytest
from unittest.mock import MagicMock

from stance.web.server import StanceRequestHandler


@pytest.fixture
def handler():
    """Create a mock request handler."""
    handler = MagicMock(spec=StanceRequestHandler)
    handler.storage = None

    # Copy the actual methods to the mock
    handler._storage_backends = StanceRequestHandler._storage_backends.__get__(handler)
    handler._storage_backend = StanceRequestHandler._storage_backend.__get__(handler)
    handler._storage_snapshots = StanceRequestHandler._storage_snapshots.__get__(handler)
    handler._storage_snapshot = StanceRequestHandler._storage_snapshot.__get__(handler)
    handler._storage_latest = StanceRequestHandler._storage_latest.__get__(handler)
    handler._storage_config = StanceRequestHandler._storage_config.__get__(handler)
    handler._storage_capabilities = StanceRequestHandler._storage_capabilities.__get__(handler)
    handler._storage_query_services = StanceRequestHandler._storage_query_services.__get__(handler)
    handler._storage_ddl = StanceRequestHandler._storage_ddl.__get__(handler)
    handler._storage_stats = StanceRequestHandler._storage_stats.__get__(handler)
    handler._storage_status = StanceRequestHandler._storage_status.__get__(handler)
    handler._storage_summary = StanceRequestHandler._storage_summary.__get__(handler)

    return handler


class TestStorageBackendsEndpoint:
    """Tests for /api/storage/backends endpoint."""

    def test_backends_returns_list(self, handler):
        """Test that backends returns a list."""
        result = handler._storage_backends({})
        assert "backends" in result
        assert "total" in result
        assert isinstance(result["backends"], list)

    def test_backends_structure(self, handler):
        """Test backend structure."""
        result = handler._storage_backends({})
        assert len(result["backends"]) == 4
        assert result["total"] == 4

        backend = result["backends"][0]
        assert "id" in backend
        assert "name" in backend
        assert "description" in backend
        assert "available" in backend
        assert "storage_type" in backend
        assert "query_service" in backend

    def test_backends_includes_expected(self, handler):
        """Test that expected backends are included."""
        result = handler._storage_backends({})
        ids = {b["id"] for b in result["backends"]}
        assert "local" in ids
        assert "s3" in ids
        assert "gcs" in ids
        assert "azure_blob" in ids

    def test_backends_available_count(self, handler):
        """Test available backends count."""
        result = handler._storage_backends({})
        assert "available_count" in result
        assert result["available_count"] >= 1  # At least local is available


class TestStorageBackendEndpoint:
    """Tests for /api/storage/backend endpoint."""

    def test_backend_default_local(self, handler):
        """Test default backend is local."""
        result = handler._storage_backend({})
        assert result["id"] == "local"

    def test_backend_returns_details(self, handler):
        """Test that backend returns details for valid ID."""
        result = handler._storage_backend({"id": "local"})
        assert result["id"] == "local"
        assert result["name"] == "Local Storage"

    def test_backend_structure(self, handler):
        """Test backend detail structure."""
        result = handler._storage_backend({"id": "s3"})
        assert "id" in result
        assert "name" in result
        assert "description" in result
        assert "storage_type" in result
        assert "query_service" in result
        assert "configuration" in result
        assert "capabilities" in result
        assert "data_format" in result

    def test_backend_not_found(self, handler):
        """Test error for invalid backend ID."""
        result = handler._storage_backend({"id": "invalid"})
        assert "error" in result

    def test_backend_local_details(self, handler):
        """Test local backend details."""
        result = handler._storage_backend({"id": "local"})
        assert result["storage_type"] == "sql"
        assert result["query_service"] == "sqlite"
        assert result["data_format"] == "sqlite"

    def test_backend_s3_details(self, handler):
        """Test S3 backend details."""
        result = handler._storage_backend({"id": "s3"})
        assert result["storage_type"] == "object"
        assert result["query_service"] == "athena"
        assert result["cloud_provider"] == "aws"
        assert result["data_format"] == "jsonl"
        assert result["sdk_required"] == "boto3"

    def test_backend_gcs_details(self, handler):
        """Test GCS backend details."""
        result = handler._storage_backend({"id": "gcs"})
        assert result["storage_type"] == "object"
        assert result["query_service"] == "bigquery"
        assert result["cloud_provider"] == "gcp"

    def test_backend_azure_details(self, handler):
        """Test Azure backend details."""
        result = handler._storage_backend({"id": "azure_blob"})
        assert result["storage_type"] == "object"
        assert result["query_service"] == "synapse"
        assert result["cloud_provider"] == "azure"


class TestStorageSnapshotsEndpoint:
    """Tests for /api/storage/snapshots endpoint."""

    def test_snapshots_returns_list(self, handler):
        """Test that snapshots returns a list."""
        result = handler._storage_snapshots({})
        assert "snapshots" in result
        assert "total" in result
        assert isinstance(result["snapshots"], list)

    def test_snapshots_structure(self, handler):
        """Test snapshot structure."""
        result = handler._storage_snapshots({})
        assert len(result["snapshots"]) > 0

        snapshot = result["snapshots"][0]
        assert "id" in snapshot
        assert "timestamp" in snapshot
        assert "backend" in snapshot
        assert "asset_count" in snapshot
        assert "finding_count" in snapshot
        assert "size_bytes" in snapshot

    def test_snapshots_with_limit(self, handler):
        """Test snapshots with custom limit."""
        result = handler._storage_snapshots({"limit": "5"})
        assert len(result["snapshots"]) <= 5

    def test_snapshots_with_backend(self, handler):
        """Test snapshots filtered by backend."""
        result = handler._storage_snapshots({"backend": "s3"})
        assert result["backend"] == "s3"
        for snapshot in result["snapshots"]:
            assert snapshot["backend"] == "s3"


class TestStorageSnapshotEndpoint:
    """Tests for /api/storage/snapshot endpoint."""

    def test_snapshot_requires_id(self, handler):
        """Test that snapshot_id is required."""
        result = handler._storage_snapshot({})
        assert "error" in result

    def test_snapshot_returns_details(self, handler):
        """Test that snapshot returns details for valid ID."""
        result = handler._storage_snapshot({"id": "20241229_120000"})
        assert result["id"] == "20241229_120000"

    def test_snapshot_structure(self, handler):
        """Test snapshot detail structure."""
        result = handler._storage_snapshot({"id": "20241229_120000"})
        assert "id" in result
        assert "backend" in result
        assert "timestamp" in result
        assert "asset_count" in result
        assert "finding_count" in result
        assert "assets_by_provider" in result
        assert "findings_by_severity" in result
        assert "metadata" in result


class TestStorageLatestEndpoint:
    """Tests for /api/storage/latest endpoint."""

    def test_latest_returns_snapshot(self, handler):
        """Test that latest returns snapshot info."""
        result = handler._storage_latest({})
        assert "snapshot_id" in result
        assert "timestamp" in result
        assert "backend" in result

    def test_latest_structure(self, handler):
        """Test latest snapshot structure."""
        result = handler._storage_latest({})
        assert "snapshot_id" in result
        assert "timestamp" in result
        assert "asset_count" in result
        assert "finding_count" in result
        assert "age_seconds" in result
        assert "is_stale" in result
        assert "summary" in result

    def test_latest_with_backend(self, handler):
        """Test latest with specific backend."""
        result = handler._storage_latest({"backend": "s3"})
        assert result["backend"] == "s3"


class TestStorageConfigEndpoint:
    """Tests for /api/storage/config endpoint."""

    def test_config_returns_dict(self, handler):
        """Test that config returns a dictionary."""
        result = handler._storage_config({})
        assert isinstance(result, dict)

    def test_config_structure(self, handler):
        """Test config structure."""
        result = handler._storage_config({})
        assert "backend" in result
        assert "storage_type" in result
        assert "query_service" in result
        assert "settings" in result

    def test_config_local(self, handler):
        """Test local config."""
        result = handler._storage_config({"backend": "local"})
        assert result["backend"] == "local"
        assert "db_path" in result
        assert result["storage_type"] == "sql"

    def test_config_s3(self, handler):
        """Test S3 config."""
        result = handler._storage_config({"backend": "s3"})
        assert result["backend"] == "s3"
        assert "bucket" in result
        assert "prefix" in result
        assert "region" in result

    def test_config_unknown(self, handler):
        """Test error for unknown backend."""
        result = handler._storage_config({"backend": "invalid"})
        assert "error" in result


class TestStorageCapabilitiesEndpoint:
    """Tests for /api/storage/capabilities endpoint."""

    def test_capabilities_all_returns_dict(self, handler):
        """Test that capabilities returns all backends."""
        result = handler._storage_capabilities({})
        assert "capabilities" in result
        assert "common_capabilities" in result
        assert "cloud_only_capabilities" in result

    def test_capabilities_structure(self, handler):
        """Test capabilities structure."""
        result = handler._storage_capabilities({})
        assert "local" in result["capabilities"]
        assert "s3" in result["capabilities"]
        assert "gcs" in result["capabilities"]
        assert "azure_blob" in result["capabilities"]

    def test_capabilities_single_backend(self, handler):
        """Test capabilities for single backend."""
        result = handler._storage_capabilities({"backend": "s3"})
        assert result["backend"] == "s3"
        assert "snapshots" in result
        assert "versioning" in result
        assert "ddl_generation" in result

    def test_capabilities_unknown_backend(self, handler):
        """Test error for unknown backend."""
        result = handler._storage_capabilities({"backend": "invalid"})
        assert "error" in result

    def test_capabilities_local(self, handler):
        """Test local backend capabilities."""
        result = handler._storage_capabilities({"backend": "local"})
        assert result["snapshots"] is True
        assert result["query_assets"] is True
        assert result["ddl_generation"] is False

    def test_capabilities_cloud(self, handler):
        """Test cloud backend capabilities."""
        result = handler._storage_capabilities({"backend": "s3"})
        assert result["ddl_generation"] is True
        assert result["analytics_export"] is True
        assert result["encryption_at_rest"] is True


class TestStorageQueryServicesEndpoint:
    """Tests for /api/storage/query-services endpoint."""

    def test_query_services_returns_list(self, handler):
        """Test that query_services returns a list."""
        result = handler._storage_query_services({})
        assert "services" in result
        assert "total" in result
        assert isinstance(result["services"], list)

    def test_query_services_structure(self, handler):
        """Test query service structure."""
        result = handler._storage_query_services({})
        assert len(result["services"]) == 4

        service = result["services"][0]
        assert "id" in service
        assert "name" in service
        assert "backend" in service
        assert "description" in service
        assert "query_language" in service
        assert "features" in service
        assert "limitations" in service

    def test_query_services_includes_expected(self, handler):
        """Test that expected query services are included."""
        result = handler._storage_query_services({})
        ids = {s["id"] for s in result["services"]}
        assert "sqlite" in ids
        assert "athena" in ids
        assert "bigquery" in ids
        assert "synapse" in ids


class TestStorageDDLEndpoint:
    """Tests for /api/storage/ddl endpoint."""

    def test_ddl_default_s3_assets(self, handler):
        """Test DDL default is S3 assets."""
        result = handler._storage_ddl({})
        assert result["backend"] == "s3"
        assert result["table_type"] == "assets"
        assert "ddl" in result

    def test_ddl_s3_assets(self, handler):
        """Test DDL for S3 assets."""
        result = handler._storage_ddl({"backend": "s3", "table_type": "assets"})
        assert result["backend"] == "s3"
        assert result["table_type"] == "assets"
        assert "CREATE EXTERNAL TABLE" in result["ddl"]
        assert result["query_service"] == "athena"

    def test_ddl_s3_findings(self, handler):
        """Test DDL for S3 findings."""
        result = handler._storage_ddl({"backend": "s3", "table_type": "findings"})
        assert result["table_type"] == "findings"
        assert "stance_findings" in result["ddl"]

    def test_ddl_gcs_assets(self, handler):
        """Test DDL for GCS assets."""
        result = handler._storage_ddl({"backend": "gcs", "table_type": "assets"})
        assert result["backend"] == "gcs"
        assert "CREATE OR REPLACE EXTERNAL TABLE" in result["ddl"]
        assert result["query_service"] == "bigquery"

    def test_ddl_azure_assets(self, handler):
        """Test DDL for Azure assets."""
        result = handler._storage_ddl({"backend": "azure_blob", "table_type": "assets"})
        assert result["backend"] == "azure_blob"
        assert "CREATE EXTERNAL TABLE" in result["ddl"]
        assert result["query_service"] == "synapse"

    def test_ddl_unknown_backend(self, handler):
        """Test error for unknown backend."""
        result = handler._storage_ddl({"backend": "invalid"})
        assert "error" in result

    def test_ddl_unknown_table_type(self, handler):
        """Test error for unknown table type."""
        result = handler._storage_ddl({"backend": "s3", "table_type": "invalid"})
        assert "error" in result


class TestStorageStatsEndpoint:
    """Tests for /api/storage/stats endpoint."""

    def test_stats_returns_dict(self, handler):
        """Test that stats returns a dictionary."""
        result = handler._storage_stats({})
        assert isinstance(result, dict)

    def test_stats_structure(self, handler):
        """Test stats structure."""
        result = handler._storage_stats({})
        assert "backend" in result
        assert "total_snapshots" in result
        assert "total_assets" in result
        assert "total_findings" in result
        assert "storage_used_bytes" in result
        assert "storage_used_human" in result
        assert "oldest_snapshot" in result
        assert "newest_snapshot" in result
        assert "growth_rate" in result

    def test_stats_with_backend(self, handler):
        """Test stats with specific backend."""
        result = handler._storage_stats({"backend": "s3"})
        assert result["backend"] == "s3"


class TestStorageStatusEndpoint:
    """Tests for /api/storage/status endpoint."""

    def test_status_returns_dict(self, handler):
        """Test that status returns a dictionary."""
        result = handler._storage_status({})
        assert isinstance(result, dict)

    def test_status_structure(self, handler):
        """Test status structure."""
        result = handler._storage_status({})
        assert "backend" in result
        assert "status" in result
        assert "available" in result
        assert "connection" in result
        assert "last_check" in result
        assert "details" in result

    def test_status_local(self, handler):
        """Test local backend status."""
        result = handler._storage_status({"backend": "local"})
        assert result["backend"] == "local"
        assert result["status"] == "healthy"
        assert "db_path" in result["details"]

    def test_status_unknown(self, handler):
        """Test error for unknown backend."""
        result = handler._storage_status({"backend": "invalid"})
        assert "error" in result


class TestStorageSummaryEndpoint:
    """Tests for /api/storage/summary endpoint."""

    def test_summary_returns_dict(self, handler):
        """Test that summary returns a dictionary."""
        result = handler._storage_summary({})
        assert isinstance(result, dict)

    def test_summary_structure(self, handler):
        """Test summary structure."""
        result = handler._storage_summary({})
        assert "overview" in result
        assert "backends" in result
        assert "totals" in result
        assert "recommendations" in result

    def test_summary_overview(self, handler):
        """Test summary overview."""
        result = handler._storage_summary({})
        overview = result["overview"]
        assert "total_backends" in overview
        assert "available_backends" in overview
        assert "configured_backends" in overview
        assert "primary_backend" in overview

    def test_summary_backends(self, handler):
        """Test summary backends."""
        result = handler._storage_summary({})
        backends = result["backends"]
        assert "local" in backends
        assert "s3" in backends
        assert "gcs" in backends
        assert "azure_blob" in backends

    def test_summary_totals(self, handler):
        """Test summary totals."""
        result = handler._storage_summary({})
        totals = result["totals"]
        assert "total_snapshots" in totals
        assert "total_assets" in totals
        assert "total_findings" in totals
        assert "total_storage_used" in totals

    def test_summary_recommendations(self, handler):
        """Test summary recommendations."""
        result = handler._storage_summary({})
        assert isinstance(result["recommendations"], list)
        assert len(result["recommendations"]) > 0


class TestStorageEndpointRouting:
    """Tests for Storage endpoint routing in do_GET."""

    def test_get_endpoints_exist(self):
        """Test that all Storage GET endpoints are routed."""
        endpoints = [
            "/api/storage/backends",
            "/api/storage/backend",
            "/api/storage/snapshots",
            "/api/storage/snapshot",
            "/api/storage/latest",
            "/api/storage/config",
            "/api/storage/capabilities",
            "/api/storage/query-services",
            "/api/storage/ddl",
            "/api/storage/stats",
            "/api/storage/status",
            "/api/storage/summary",
        ]

        for endpoint in endpoints:
            # Handle hyphenated names
            method_name = "_storage_" + endpoint.split("/")[-1].replace("-", "_")
            assert hasattr(StanceRequestHandler, method_name), f"Method {method_name} not found"


class TestStorageBackendAvailability:
    """Tests for backend availability checking."""

    def test_local_always_available(self, handler):
        """Test that local backend is always available."""
        result = handler._storage_backends({})
        local = next(b for b in result["backends"] if b["id"] == "local")
        assert local["available"] is True

    def test_backend_sdk_requirements(self, handler):
        """Test backend SDK requirements are documented."""
        result = handler._storage_backend({"id": "s3"})
        assert result["sdk_required"] == "boto3"

        result = handler._storage_backend({"id": "gcs"})
        assert result["sdk_required"] == "google-cloud-storage"

        result = handler._storage_backend({"id": "azure_blob"})
        assert result["sdk_required"] == "azure-storage-blob"

        result = handler._storage_backend({"id": "local"})
        assert result["sdk_required"] is None


class TestStorageQueryIntegration:
    """Tests for storage query integration."""

    def test_query_service_mapping(self, handler):
        """Test query service to backend mapping."""
        services = handler._storage_query_services({})["services"]

        sqlite_svc = next(s for s in services if s["id"] == "sqlite")
        assert sqlite_svc["backend"] == "local"

        athena_svc = next(s for s in services if s["id"] == "athena")
        assert athena_svc["backend"] == "s3"

        bigquery_svc = next(s for s in services if s["id"] == "bigquery")
        assert bigquery_svc["backend"] == "gcs"

        synapse_svc = next(s for s in services if s["id"] == "synapse")
        assert synapse_svc["backend"] == "azure_blob"

    def test_ddl_query_service_mapping(self, handler):
        """Test DDL returns correct query service."""
        result = handler._storage_ddl({"backend": "s3"})
        assert result["query_service"] == "athena"

        result = handler._storage_ddl({"backend": "gcs"})
        assert result["query_service"] == "bigquery"

        result = handler._storage_ddl({"backend": "azure_blob"})
        assert result["query_service"] == "synapse"
