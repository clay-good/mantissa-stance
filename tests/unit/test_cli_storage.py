"""
Unit tests for CLI Storage commands.

Tests the CLI commands for the Storage module.
"""

import argparse
import pytest
from unittest.mock import patch
from io import StringIO

from stance.cli_storage import (
    add_storage_parser,
    cmd_storage,
    _handle_backends,
    _handle_backend,
    _handle_snapshots,
    _handle_snapshot,
    _handle_latest,
    _handle_config,
    _handle_capabilities,
    _handle_query_services,
    _handle_ddl,
    _handle_stats,
    _handle_status,
    _handle_summary,
    _get_available_backends,
    _get_backend_details,
    _get_sample_snapshots,
    _get_sample_snapshot,
    _get_latest_snapshot,
    _get_storage_config,
    _get_backend_capabilities,
    _get_query_services,
    _get_ddl,
    _get_storage_stats,
    _get_storage_status,
    _get_storage_summary,
)


class TestAddStorageParser:
    """Tests for add_storage_parser function."""

    def test_parser_added(self):
        """Test that storage parser is added to subparsers."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_storage_parser(subparsers)

        # Parse a simple command
        args = parser.parse_args(["storage", "backends"])
        assert args.storage_action == "backends"

    def test_backends_parser(self):
        """Test backends subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_storage_parser(subparsers)

        args = parser.parse_args(["storage", "backends", "--format", "json"])
        assert args.storage_action == "backends"
        assert args.format == "json"

    def test_backend_parser(self):
        """Test backend subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_storage_parser(subparsers)

        args = parser.parse_args(["storage", "backend", "local"])
        assert args.storage_action == "backend"
        assert args.backend_name == "local"

    def test_snapshots_parser(self):
        """Test snapshots subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_storage_parser(subparsers)

        args = parser.parse_args(["storage", "snapshots", "--limit", "5"])
        assert args.storage_action == "snapshots"
        assert args.limit == 5

    def test_snapshot_parser(self):
        """Test snapshot subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_storage_parser(subparsers)

        args = parser.parse_args(["storage", "snapshot", "20251229-120000"])
        assert args.storage_action == "snapshot"
        assert args.snapshot_id == "20251229-120000"

    def test_ddl_parser(self):
        """Test ddl subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_storage_parser(subparsers)

        args = parser.parse_args(["storage", "ddl", "s3", "--table", "findings"])
        assert args.storage_action == "ddl"
        assert args.backend == "s3"
        assert args.table == "findings"


class TestCmdStorage:
    """Tests for cmd_storage function."""

    def test_no_action(self):
        """Test handling of no action specified."""
        args = argparse.Namespace(storage_action=None)
        result = cmd_storage(args)
        assert result == 1

    def test_backends_action(self):
        """Test backends action routing."""
        args = argparse.Namespace(
            storage_action="backends",
            format="table",
        )
        result = cmd_storage(args)
        assert result == 0

    def test_unknown_action(self):
        """Test handling of unknown action."""
        args = argparse.Namespace(storage_action="unknown")
        result = cmd_storage(args)
        assert result == 1


class TestHandleBackends:
    """Tests for _handle_backends function."""

    def test_backends_table_output(self):
        """Test backends with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_backends(args)
        assert result == 0

    def test_backends_json_output(self, capsys):
        """Test backends with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_backends(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "backends" in captured.out
        assert "total" in captured.out


class TestHandleBackend:
    """Tests for _handle_backend function."""

    def test_backend_local(self):
        """Test local backend details."""
        args = argparse.Namespace(
            backend_name="local",
            format="table",
        )
        result = _handle_backend(args)
        assert result == 0

    def test_backend_s3(self):
        """Test s3 backend details."""
        args = argparse.Namespace(
            backend_name="s3",
            format="table",
        )
        result = _handle_backend(args)
        assert result == 0

    def test_backend_json_output(self, capsys):
        """Test backend with JSON output."""
        args = argparse.Namespace(
            backend_name="local",
            format="json",
        )
        result = _handle_backend(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "backend" in captured.out


class TestHandleSnapshots:
    """Tests for _handle_snapshots function."""

    def test_snapshots_table_output(self):
        """Test snapshots with table output."""
        args = argparse.Namespace(
            limit=10,
            format="table",
        )
        result = _handle_snapshots(args)
        assert result == 0

    def test_snapshots_json_output(self, capsys):
        """Test snapshots with JSON output."""
        args = argparse.Namespace(
            limit=5,
            format="json",
        )
        result = _handle_snapshots(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "snapshots" in captured.out
        assert "total" in captured.out

    def test_snapshots_with_limit(self, capsys):
        """Test snapshots with custom limit."""
        args = argparse.Namespace(
            limit=3,
            format="json",
        )
        result = _handle_snapshots(args)
        assert result == 0


class TestHandleSnapshot:
    """Tests for _handle_snapshot function."""

    def test_snapshot_found(self):
        """Test snapshot found."""
        args = argparse.Namespace(
            snapshot_id="20251229-120000",
            format="table",
        )
        result = _handle_snapshot(args)
        assert result == 0

    def test_snapshot_not_found(self):
        """Test snapshot not found."""
        args = argparse.Namespace(
            snapshot_id="nonexistent",
            format="table",
        )
        result = _handle_snapshot(args)
        assert result == 1

    def test_snapshot_json_output(self, capsys):
        """Test snapshot with JSON output."""
        args = argparse.Namespace(
            snapshot_id="20251229-120000",
            format="json",
        )
        result = _handle_snapshot(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "snapshot" in captured.out


class TestHandleLatest:
    """Tests for _handle_latest function."""

    def test_latest_table_output(self):
        """Test latest with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_latest(args)
        assert result == 0

    def test_latest_json_output(self, capsys):
        """Test latest with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_latest(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "snapshot" in captured.out


class TestHandleConfig:
    """Tests for _handle_config function."""

    def test_config_table_output(self):
        """Test config with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_config(args)
        assert result == 0

    def test_config_json_output(self, capsys):
        """Test config with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_config(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "active_backend" in captured.out


class TestHandleCapabilities:
    """Tests for _handle_capabilities function."""

    def test_capabilities_table_output(self):
        """Test capabilities with table output."""
        args = argparse.Namespace(format="table", backend=None)
        result = _handle_capabilities(args)
        assert result == 0

    def test_capabilities_json_output(self, capsys):
        """Test capabilities with JSON output."""
        args = argparse.Namespace(format="json", backend=None)
        result = _handle_capabilities(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "capabilities" in captured.out

    def test_capabilities_filter_backend(self, capsys):
        """Test capabilities filtered by backend."""
        args = argparse.Namespace(format="json", backend="s3")
        result = _handle_capabilities(args)
        assert result == 0


class TestHandleQueryServices:
    """Tests for _handle_query_services function."""

    def test_query_services_table_output(self):
        """Test query services with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_query_services(args)
        assert result == 0

    def test_query_services_json_output(self, capsys):
        """Test query services with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_query_services(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "query_services" in captured.out


class TestHandleDDL:
    """Tests for _handle_ddl function."""

    def test_ddl_s3_assets(self):
        """Test DDL for S3 assets."""
        args = argparse.Namespace(
            backend="s3",
            table="assets",
            format="table",
        )
        result = _handle_ddl(args)
        assert result == 0

    def test_ddl_gcs_findings(self):
        """Test DDL for GCS findings."""
        args = argparse.Namespace(
            backend="gcs",
            table="findings",
            format="table",
        )
        result = _handle_ddl(args)
        assert result == 0

    def test_ddl_json_output(self, capsys):
        """Test DDL with JSON output."""
        args = argparse.Namespace(
            backend="azure",
            table="assets",
            format="json",
        )
        result = _handle_ddl(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "ddl" in captured.out


class TestHandleStats:
    """Tests for _handle_stats function."""

    def test_stats_table_output(self):
        """Test stats with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_stats(args)
        assert result == 0

    def test_stats_json_output(self, capsys):
        """Test stats with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_stats(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "total_snapshots" in captured.out


class TestHandleStatus:
    """Tests for _handle_status function."""

    def test_status_table_output(self):
        """Test status with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_status(args)
        assert result == 0

    def test_status_json_output(self, capsys):
        """Test status with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "module" in captured.out


class TestHandleSummary:
    """Tests for _handle_summary function."""

    def test_summary_table_output(self):
        """Test summary with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_summary(args)
        assert result == 0

    def test_summary_json_output(self, capsys):
        """Test summary with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "module" in captured.out


class TestSampleDataGenerators:
    """Tests for sample data generator functions."""

    def test_get_available_backends(self):
        """Test getting available backends."""
        backends = _get_available_backends()
        assert isinstance(backends, list)
        assert len(backends) == 4
        assert backends[0]["name"] == "local"
        assert "description" in backends[0]
        assert "available" in backends[0]

    def test_get_backend_details_local(self):
        """Test getting local backend details."""
        backend = _get_backend_details("local")
        assert backend["name"] == "local"
        assert "description" in backend
        assert "config_options" in backend
        assert "features" in backend

    def test_get_backend_details_s3(self):
        """Test getting S3 backend details."""
        backend = _get_backend_details("s3")
        assert backend["name"] == "s3"
        assert backend["query_service"] == "Amazon Athena"
        assert any(opt["name"] == "bucket" for opt in backend["config_options"])

    def test_get_backend_details_gcs(self):
        """Test getting GCS backend details."""
        backend = _get_backend_details("gcs")
        assert backend["name"] == "gcs"
        assert backend["query_service"] == "BigQuery"

    def test_get_backend_details_azure(self):
        """Test getting Azure backend details."""
        backend = _get_backend_details("azure")
        assert backend["name"] == "azure"
        assert backend["query_service"] == "Azure Synapse"

    def test_get_backend_details_unknown(self):
        """Test getting unknown backend."""
        backend = _get_backend_details("unknown")
        assert "error" in backend

    def test_get_sample_snapshots(self):
        """Test getting sample snapshots."""
        snapshots = _get_sample_snapshots(10)
        assert isinstance(snapshots, list)
        assert len(snapshots) <= 10
        assert "id" in snapshots[0]
        assert "created_at" in snapshots[0]
        assert "asset_count" in snapshots[0]

    def test_get_sample_snapshots_with_limit(self):
        """Test getting sample snapshots with limit."""
        snapshots = _get_sample_snapshots(3)
        assert len(snapshots) == 3

    def test_get_sample_snapshot_found(self):
        """Test getting existing snapshot."""
        snapshot = _get_sample_snapshot("20251229-120000")
        assert snapshot is not None
        assert snapshot["id"] == "20251229-120000"
        assert "by_severity" in snapshot
        assert "by_resource_type" in snapshot

    def test_get_sample_snapshot_not_found(self):
        """Test getting non-existent snapshot."""
        snapshot = _get_sample_snapshot("nonexistent")
        assert snapshot is None

    def test_get_latest_snapshot(self):
        """Test getting latest snapshot."""
        snapshot = _get_latest_snapshot()
        assert snapshot is not None
        assert "id" in snapshot
        assert "created_at" in snapshot

    def test_get_storage_config(self):
        """Test getting storage config."""
        config = _get_storage_config()
        assert "active_backend" in config
        assert "backend_status" in config
        assert "settings" in config
        assert "paths" in config

    def test_get_backend_capabilities_all(self):
        """Test getting all backend capabilities."""
        capabilities = _get_backend_capabilities(None)
        assert "local" in capabilities
        assert "s3" in capabilities
        assert "gcs" in capabilities
        assert "azure" in capabilities

    def test_get_backend_capabilities_specific(self):
        """Test getting specific backend capabilities."""
        capabilities = _get_backend_capabilities("s3")
        assert "s3" in capabilities
        assert len(capabilities) == 1
        assert capabilities["s3"]["multi_region"] is True

    def test_get_query_services(self):
        """Test getting query services."""
        services = _get_query_services()
        assert isinstance(services, list)
        assert len(services) == 4
        assert services[0]["name"] == "SQLite"
        assert services[1]["name"] == "Amazon Athena"

    def test_get_ddl_s3_assets(self):
        """Test getting DDL for S3 assets."""
        ddl = _get_ddl("s3", "assets")
        assert ddl["backend"] == "s3"
        assert ddl["table"] == "assets"
        assert "CREATE EXTERNAL TABLE" in ddl["statement"]

    def test_get_ddl_gcs_findings(self):
        """Test getting DDL for GCS findings."""
        ddl = _get_ddl("gcs", "findings")
        assert ddl["backend"] == "gcs"
        assert ddl["table"] == "findings"
        assert "CREATE OR REPLACE EXTERNAL TABLE" in ddl["statement"]

    def test_get_ddl_azure(self):
        """Test getting DDL for Azure."""
        ddl = _get_ddl("azure", "assets")
        assert ddl["backend"] == "azure"
        assert "CREATE EXTERNAL TABLE" in ddl["statement"]

    def test_get_storage_stats(self):
        """Test getting storage stats."""
        stats = _get_storage_stats()
        assert "total_snapshots" in stats
        assert "total_assets" in stats
        assert "total_findings" in stats
        assert "storage_size" in stats
        assert "by_backend" in stats

    def test_get_storage_status(self):
        """Test getting storage status."""
        status = _get_storage_status()
        assert status["module"] == "storage"
        assert status["status"] == "operational"
        assert "backends" in status
        assert "capabilities" in status

    def test_get_storage_summary(self):
        """Test getting storage summary."""
        summary = _get_storage_summary()
        assert summary["module"] == "Storage"
        assert "backends_available" in summary
        assert "data" in summary
        assert "features" in summary
        assert len(summary["features"]) > 0


class TestStorageEndpointRouting:
    """Tests for storage CLI routing."""

    def test_all_actions_available(self):
        """Test that all actions are routed."""
        actions = [
            "backends",
            "backend",
            "snapshots",
            "snapshot",
            "latest",
            "config",
            "capabilities",
            "query-services",
            "ddl",
            "stats",
            "status",
            "summary",
        ]

        for action in actions:
            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers()
            add_storage_parser(subparsers)

            if action == "backend":
                args = parser.parse_args(["storage", action, "local"])
            elif action == "snapshot":
                args = parser.parse_args(["storage", action, "test-id"])
            elif action == "ddl":
                args = parser.parse_args(["storage", action, "s3"])
            else:
                args = parser.parse_args(["storage", action])

            assert args.storage_action == action


class TestBackendValidation:
    """Tests for backend validation."""

    def test_backend_choices(self):
        """Test backend choices validation."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_storage_parser(subparsers)

        # Valid backends
        for backend in ["local", "s3", "gcs", "azure"]:
            args = parser.parse_args(["storage", "backend", backend])
            assert args.backend_name == backend

    def test_ddl_backend_choices(self):
        """Test DDL backend choices validation."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_storage_parser(subparsers)

        # Valid DDL backends (no local)
        for backend in ["s3", "gcs", "azure"]:
            args = parser.parse_args(["storage", "ddl", backend])
            assert args.backend == backend


class TestFormatOptions:
    """Tests for format options."""

    def test_table_format_default(self):
        """Test table format is default."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_storage_parser(subparsers)

        args = parser.parse_args(["storage", "backends"])
        assert args.format == "table"

    def test_json_format_option(self):
        """Test JSON format option."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_storage_parser(subparsers)

        args = parser.parse_args(["storage", "backends", "--format", "json"])
        assert args.format == "json"


class TestStorageIntegration:
    """Integration tests for storage CLI."""

    def test_full_workflow(self, capsys):
        """Test a full storage workflow."""
        # List backends
        args = argparse.Namespace(format="json")
        result = _handle_backends(args)
        assert result == 0

        # Get backend details
        args = argparse.Namespace(backend_name="local", format="json")
        result = _handle_backend(args)
        assert result == 0

        # List snapshots
        args = argparse.Namespace(limit=5, format="json")
        result = _handle_snapshots(args)
        assert result == 0

        # Get storage stats
        args = argparse.Namespace(format="json")
        result = _handle_stats(args)
        assert result == 0

        # Get storage summary
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0
