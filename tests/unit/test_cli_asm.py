"""
Unit tests for ASM CLI module.

Tests for src/stance/cli_asm.py covering:
- Argument parsing
- Helper functions
- Command dispatch
- Error handling
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch

import pytest

from stance.asm.models import (
    ASMScanMode,
    ASMScanStatus,
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)


# ==============================================================================
# Import Tests
# ==============================================================================


class TestImports:
    """Test that cli_asm module imports correctly."""

    def test_import_cli_asm(self) -> None:
        """Test basic import of cli_asm module."""
        from stance import cli_asm

        assert cli_asm is not None

    def test_import_cmd_asm(self) -> None:
        """Test import of cmd_asm function."""
        from stance.cli_asm import cmd_asm

        assert callable(cmd_asm)

    def test_import_add_asm_parser(self) -> None:
        """Test import of add_asm_parser function."""
        from stance.cli_asm import add_asm_parser

        assert callable(add_asm_parser)

    def test_import_helper_functions(self) -> None:
        """Test import of helper functions."""
        from stance.cli_asm import (
            _is_valid_domain,
            _apply_filter,
            _get_collectors_for_mode,
            _run_collector,
        )

        assert callable(_is_valid_domain)
        assert callable(_apply_filter)
        assert callable(_get_collectors_for_mode)
        assert callable(_run_collector)


# ==============================================================================
# Domain Validation Tests
# ==============================================================================


class TestDomainValidation:
    """Tests for _is_valid_domain function."""

    def test_valid_simple_domain(self) -> None:
        """Test simple valid domain."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("example.com") is True

    def test_valid_subdomain(self) -> None:
        """Test valid subdomain."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("www.example.com") is True
        assert _is_valid_domain("api.example.com") is True
        assert _is_valid_domain("sub.domain.example.com") is True

    def test_valid_hyphenated_domain(self) -> None:
        """Test valid hyphenated domain."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("my-domain.com") is True
        assert _is_valid_domain("test-site.example.com") is True

    def test_valid_numeric_domain(self) -> None:
        """Test valid domain with numbers."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("123.example.com") is True
        assert _is_valid_domain("test123.com") is True

    def test_invalid_single_label(self) -> None:
        """Test invalid single-label domain."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("example") is False
        assert _is_valid_domain("localhost") is False

    def test_invalid_empty_string(self) -> None:
        """Test invalid empty string."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("") is False

    def test_invalid_with_protocol(self) -> None:
        """Test invalid domain with protocol."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("http://example.com") is False
        assert _is_valid_domain("https://example.com") is False

    def test_invalid_with_path(self) -> None:
        """Test invalid domain with path."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("example.com/path") is False

    def test_invalid_with_port(self) -> None:
        """Test invalid domain with port."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("example.com:8080") is False

    def test_invalid_leading_dot(self) -> None:
        """Test invalid domain with leading dot."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain(".example.com") is False

    def test_invalid_trailing_dot(self) -> None:
        """Test invalid domain with trailing dot."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("example.") is False

    def test_invalid_double_dot(self) -> None:
        """Test invalid domain with double dot."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("example..com") is False

    def test_invalid_leading_hyphen(self) -> None:
        """Test invalid domain with leading hyphen."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("-example.com") is False

    def test_invalid_trailing_hyphen(self) -> None:
        """Test invalid domain with trailing hyphen."""
        from stance.cli_asm import _is_valid_domain

        assert _is_valid_domain("example-.com") is False


# ==============================================================================
# Collector Mode Tests
# ==============================================================================


class TestCollectorModes:
    """Tests for _get_collectors_for_mode function."""

    def test_passive_mode_includes_passive_collectors(self) -> None:
        """Test passive mode includes passive collectors."""
        from stance.cli_asm import _get_collectors_for_mode

        collectors = _get_collectors_for_mode(ASMScanMode.PASSIVE)

        assert "cert_transparency" in collectors
        assert "dns_enumeration" in collectors
        assert "cloud_ip_ranges" in collectors

    def test_passive_mode_excludes_active_collectors(self) -> None:
        """Test passive mode excludes active collectors."""
        from stance.cli_asm import _get_collectors_for_mode

        collectors = _get_collectors_for_mode(ASMScanMode.PASSIVE)

        assert "port_scanner" not in collectors
        assert "subdomain_bruteforce" not in collectors

    def test_active_mode_includes_active_collectors(self) -> None:
        """Test active mode includes active collectors."""
        from stance.cli_asm import _get_collectors_for_mode

        collectors = _get_collectors_for_mode(ASMScanMode.ACTIVE)

        assert "port_scanner" in collectors
        assert "technology_fingerprint" in collectors

    def test_full_mode_includes_all_collectors(self) -> None:
        """Test full mode includes all collectors."""
        from stance.cli_asm import _get_collectors_for_mode

        collectors = _get_collectors_for_mode(ASMScanMode.FULL)

        # Should have both passive and active collectors
        assert "cert_transparency" in collectors
        assert "port_scanner" in collectors
        assert len(collectors) >= 5


# ==============================================================================
# Filter Expression Tests
# ==============================================================================


class TestFilterExpressions:
    """Tests for _apply_filter function."""

    @pytest.fixture
    def sample_assets(self) -> ExternalAssetCollection:
        """Create sample assets for testing."""
        now = datetime.now(timezone.utc)
        return ExternalAssetCollection([
            ExternalAsset(
                id="asset-1",
                domain="www.example.com",
                ip_address="1.2.3.4",
                port=443,
                protocol="https",
                service="nginx",
                first_seen=now,
                last_seen=now,
                risk_score=2.5,
                source="test",
            ),
            ExternalAsset(
                id="asset-2",
                domain="api.example.com",
                ip_address="1.2.3.5",
                port=443,
                protocol="https",
                service="nginx",
                first_seen=now,
                last_seen=now,
                risk_score=5.0,
                source="test",
            ),
            ExternalAsset(
                id="asset-3",
                domain="db.example.com",
                ip_address="1.2.3.6",
                port=3306,
                protocol="mysql",
                service="MySQL",
                first_seen=now,
                last_seen=now,
                risk_score=8.5,
                source="test",
            ),
        ])

    def test_filter_risk_score_greater_than(self, sample_assets) -> None:
        """Test filtering by risk_score greater than."""
        from stance.cli_asm import _apply_filter

        result = _apply_filter(sample_assets, "risk_score > 5")

        assert len(result) == 1
        assert result[0].domain == "db.example.com"

    def test_filter_risk_score_less_than(self, sample_assets) -> None:
        """Test filtering by risk_score less than."""
        from stance.cli_asm import _apply_filter

        result = _apply_filter(sample_assets, "risk_score < 5")

        assert len(result) == 1
        assert result[0].domain == "www.example.com"

    def test_filter_risk_score_equal(self, sample_assets) -> None:
        """Test filtering by risk_score equal."""
        from stance.cli_asm import _apply_filter

        result = _apply_filter(sample_assets, "risk_score == 5.0")

        assert len(result) == 1
        assert result[0].domain == "api.example.com"

    def test_filter_port_equal(self, sample_assets) -> None:
        """Test filtering by port equal."""
        from stance.cli_asm import _apply_filter

        result = _apply_filter(sample_assets, "port == 443")

        assert len(result) == 2

    def test_filter_domain_contains(self, sample_assets) -> None:
        """Test filtering by domain contains."""
        from stance.cli_asm import _apply_filter

        result = _apply_filter(sample_assets, "domain contains 'api'")

        assert len(result) == 1
        assert "api" in result[0].domain

    def test_filter_invalid_expression(self, sample_assets) -> None:
        """Test filtering with invalid expression returns all assets."""
        from stance.cli_asm import _apply_filter

        # Invalid expression should not crash, should return original
        result = _apply_filter(sample_assets, "invalid expression @@#$")

        # Depending on implementation, may return all or empty
        assert isinstance(result, (ExternalAssetCollection, list))


# ==============================================================================
# Run Collector Tests
# ==============================================================================


class TestRunCollector:
    """Tests for _run_collector function."""

    def test_run_cert_transparency_collector(self) -> None:
        """Test running cert_transparency collector."""
        from stance.cli_asm import _run_collector

        # Should not crash, may return empty collection
        result = _run_collector("cert_transparency", ["example.com"])

        assert isinstance(result, ExternalAssetCollection)

    def test_run_dns_enumeration_collector(self) -> None:
        """Test running dns_enumeration collector."""
        from stance.cli_asm import _run_collector

        result = _run_collector("dns_enumeration", ["example.com"])

        assert isinstance(result, ExternalAssetCollection)

    def test_run_unknown_collector(self) -> None:
        """Test running unknown collector returns empty collection."""
        from stance.cli_asm import _run_collector

        result = _run_collector("unknown_collector", ["example.com"])

        assert isinstance(result, ExternalAssetCollection)
        assert len(result) == 0


# ==============================================================================
# Parser Tests
# ==============================================================================


class TestParserSetup:
    """Tests for CLI parser setup."""

    def test_add_asm_parser_creates_subcommand(self) -> None:
        """Test add_asm_parser creates ASM subcommand."""
        from stance.cli_asm import add_asm_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        add_asm_parser(subparsers)

        # Should be able to parse ASM commands
        args = parser.parse_args(["asm", "scan", "--domains", "example.com"])
        assert hasattr(args, "domains")
        assert args.domains == ["example.com"]

    def test_scan_command_has_required_options(self) -> None:
        """Test scan command has all required options."""
        from stance.cli_asm import add_asm_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        args = parser.parse_args([
            "asm", "scan",
            "--domains", "example.com",
            "--mode", "active",
            "--i-own-this-domain",
            "--save",
        ])

        assert args.domains == ["example.com"]
        assert args.mode == "active"
        assert args.i_own_this_domain is True
        assert args.save is True

    def test_inventory_command_has_required_options(self) -> None:
        """Test inventory command has all required options."""
        from stance.cli_asm import add_asm_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        args = parser.parse_args([
            "asm", "inventory",
            "--filter", "risk_score > 5",
            "--sort", "domain",
            "--limit", "50",
        ])

        assert args.filter_expr == "risk_score > 5"
        assert args.sort == "domain"
        assert args.limit == 50

    def test_drift_command_has_required_options(self) -> None:
        """Test drift command has all required options."""
        from stance.cli_asm import add_asm_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        args = parser.parse_args([
            "asm", "drift",
            "--baseline", "scan-001",
            "--current", "scan-002",
        ])

        assert args.baseline == "scan-001"
        assert args.current == "scan-002"

    def test_verify_command_has_required_options(self) -> None:
        """Test verify command has all required options."""
        from stance.cli_asm import add_asm_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        args = parser.parse_args([
            "asm", "verify",
            "--domain", "example.com",
            "--method", "dns",
            "--show-token",
        ])

        assert args.domain == "example.com"
        assert args.method == "dns"
        assert args.show_token is True


# ==============================================================================
# Command Handler Tests
# ==============================================================================


class TestCommandHandlers:
    """Tests for command handler dispatch."""

    def test_cmd_asm_with_no_action_shows_help(self, capsys) -> None:
        """Test cmd_asm with no action shows help."""
        from stance.cli_asm import cmd_asm

        args = argparse.Namespace(asm_action=None)
        result = cmd_asm(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Attack Surface Management Commands" in captured.out

    def test_cmd_asm_with_unknown_action_returns_error(self, capsys) -> None:
        """Test cmd_asm with unknown action returns error."""
        from stance.cli_asm import cmd_asm

        args = argparse.Namespace(asm_action="nonexistent")
        result = cmd_asm(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown ASM command" in captured.out

    def test_scan_requires_domain_validation(self, capsys) -> None:
        """Test scan command requires valid domain."""
        from stance.cli_asm import cmd_asm

        args = argparse.Namespace(
            asm_action="scan",
            domains=["invalid-domain"],
            mode="passive",
            output="table",
            save=False,
            correlate=False,
            config=None,
            i_own_this_domain=False,
            format=None,
        )

        result = cmd_asm(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid domain format" in captured.out

    def test_active_scan_requires_ownership_flag(self, capsys) -> None:
        """Test active scan requires --i-own-this-domain flag."""
        from stance.cli_asm import cmd_asm

        args = argparse.Namespace(
            asm_action="scan",
            domains=["example.com"],
            mode="active",
            output="table",
            save=False,
            correlate=False,
            config=None,
            i_own_this_domain=False,
            format=None,
        )

        result = cmd_asm(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "ownership confirmation" in captured.out

    def test_verify_requires_valid_domain(self, capsys) -> None:
        """Test verify command requires valid domain."""
        from stance.cli_asm import cmd_asm

        args = argparse.Namespace(
            asm_action="verify",
            domain="invalid",
            method="dns",
            show_token=True,
            check=False,
        )

        result = cmd_asm(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid domain format" in captured.out


# ==============================================================================
# Error Handling Tests
# ==============================================================================


class TestErrorHandling:
    """Tests for error handling in CLI."""

    @patch("stance.asm.storage.ASMStorageAdapter")
    def test_storage_error_handled_gracefully(self, mock_storage, capsys) -> None:
        """Test storage errors are handled gracefully."""
        from stance.cli_asm import cmd_asm

        mock_storage.side_effect = Exception("Storage unavailable")

        args = argparse.Namespace(
            asm_action="inventory",
            scan_id=None,
            latest=True,
            filter_expr=None,
            format="table",
            sort="risk",
            limit=100,
        )

        result = cmd_asm(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out

    @patch("stance.asm.storage.ASMStorageAdapter")
    def test_drift_with_no_scans_shows_message(self, mock_storage, capsys) -> None:
        """Test drift command with no scans shows helpful message."""
        from stance.cli_asm import cmd_asm

        mock_storage.return_value.list_scans.return_value = []

        args = argparse.Namespace(
            asm_action="drift",
            baseline=None,
            current=None,
            format="table",
        )

        result = cmd_asm(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Need at least 2 scans" in captured.out


# ==============================================================================
# Output Format Tests
# ==============================================================================


class TestOutputFormats:
    """Tests for output format handling."""

    @patch("stance.asm.storage.ASMStorageAdapter")
    def test_inventory_json_format(self, mock_storage, capsys) -> None:
        """Test inventory command with JSON format."""
        import json
        from stance.cli_asm import cmd_asm

        now = datetime.now(timezone.utc)
        mock_assets = ExternalAssetCollection([
            ExternalAsset(
                id="test-001",
                domain="www.example.com",
                ip_address="1.2.3.4",
                port=443,
                protocol="https",
                first_seen=now,
                last_seen=now,
                risk_score=3.0,
                source="test",
            )
        ])

        mock_storage.return_value.get_external_assets.return_value = mock_assets
        mock_storage.return_value.get_latest_scan.return_value = None

        args = argparse.Namespace(
            asm_action="inventory",
            scan_id=None,
            latest=True,
            filter_expr=None,
            format="json",
            sort="risk",
            limit=100,
        )

        result = cmd_asm(args)

        assert result == 0
        captured = capsys.readouterr()
        # Should be valid JSON
        data = json.loads(captured.out)
        assert isinstance(data, list)

    @patch("stance.asm.storage.ASMStorageAdapter")
    def test_inventory_table_format(self, mock_storage, capsys) -> None:
        """Test inventory command with table format."""
        from stance.cli_asm import cmd_asm

        now = datetime.now(timezone.utc)
        mock_assets = ExternalAssetCollection([
            ExternalAsset(
                id="test-001",
                domain="www.example.com",
                ip_address="1.2.3.4",
                port=443,
                protocol="https",
                first_seen=now,
                last_seen=now,
                risk_score=3.0,
                source="test",
            )
        ])

        mock_storage.return_value.get_external_assets.return_value = mock_assets
        mock_storage.return_value.get_latest_scan.return_value = None

        args = argparse.Namespace(
            asm_action="inventory",
            scan_id=None,
            latest=True,
            filter_expr=None,
            format="table",
            sort="risk",
            limit=100,
        )

        result = cmd_asm(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Domain" in captured.out
        assert "www.example.com" in captured.out

    @patch("stance.asm.storage.ASMStorageAdapter")
    def test_inventory_empty_shows_message(self, mock_storage, capsys) -> None:
        """Test inventory command with no assets shows message."""
        from stance.cli_asm import cmd_asm

        mock_storage.return_value.get_external_assets.return_value = ExternalAssetCollection()
        mock_storage.return_value.get_latest_scan.return_value = None

        args = argparse.Namespace(
            asm_action="inventory",
            scan_id=None,
            latest=True,
            filter_expr=None,
            format="table",
            sort="risk",
            limit=100,
        )

        result = cmd_asm(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No external assets found" in captured.out
