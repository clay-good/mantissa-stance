"""
Integration tests for ASM CLI commands.

Tests cover:
- All ASM CLI commands with mocked collectors
- Argument parsing
- Output formatting
- Error handling
"""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from stance.asm.models import (
    ASMScanMode,
    ASMScanResult,
    ASMScanStatus,
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.asm.storage import ASMStorageAdapter, generate_scan_id
from stance.cli_asm import (
    cmd_asm,
    add_asm_parser,
    _is_valid_domain,
    _apply_filter,
    _get_collectors_for_mode,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_db_path():
    """Create a temporary database path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield f.name


@pytest.fixture
def mock_assets():
    """Create mock external assets."""
    now = datetime.now(timezone.utc)
    return ExternalAssetCollection([
        ExternalAsset(
            id="ext-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            service="nginx",
            first_seen=now - timedelta(days=30),
            last_seen=now,
            risk_score=2.5,
            source="cert_transparency",
        ),
        ExternalAsset(
            id="ext-002",
            domain="api.example.com",
            ip_address="1.2.3.5",
            port=443,
            protocol="https",
            service="nginx",
            first_seen=now - timedelta(days=7),
            last_seen=now,
            risk_score=4.5,
            source="dns_enumeration",
        ),
        ExternalAsset(
            id="ext-003",
            domain="db.example.com",
            ip_address="1.2.3.6",
            port=3306,
            protocol="mysql",
            service="MySQL",
            first_seen=now - timedelta(days=1),
            last_seen=now,
            risk_score=8.0,
            source="port_scan",
        ),
    ])


@pytest.fixture
def populated_storage(temp_db_path, mock_assets):
    """Create storage with pre-populated scan data."""
    storage = ASMStorageAdapter(temp_db_path)
    now = datetime.now(timezone.utc)

    # Create scan
    scan = ASMScanResult(
        scan_id="test-scan-001",
        started_at=now,
        target_domains=["example.com"],
        scan_mode=ASMScanMode.PASSIVE,
        status=ASMScanStatus.COMPLETED,
    )
    scan.complete(mock_assets, findings_count=3)

    storage.store_scan_result(scan)
    storage.store_external_assets(mock_assets, scan.scan_id)

    return storage


# =============================================================================
# Domain Validation Tests
# =============================================================================


class TestDomainValidation:
    """Tests for domain validation."""

    def test_valid_domains(self) -> None:
        """Test valid domain formats are accepted."""
        valid_domains = [
            "example.com",
            "www.example.com",
            "api.example.com",
            "sub.domain.example.com",
            "example.co.uk",
            "example-test.com",
            "test123.example.com",
        ]
        for domain in valid_domains:
            assert _is_valid_domain(domain) is True, f"Should accept: {domain}"

    def test_invalid_domains(self) -> None:
        """Test invalid domain formats are rejected."""
        invalid_domains = [
            "example",
            "example.",
            ".example.com",
            "example..com",
            "http://example.com",
            "example.com/path",
            "example.com:8080",
            "-example.com",
            "example-.com",
            "",
        ]
        for domain in invalid_domains:
            assert _is_valid_domain(domain) is False, f"Should reject: {domain}"


# =============================================================================
# Filter Expression Tests
# =============================================================================


class TestFilterExpressions:
    """Tests for filter expression parsing."""

    def test_filter_by_risk_score(self, mock_assets) -> None:
        """Test filtering by risk score."""
        # risk_score > 5
        filtered = _apply_filter(mock_assets, "risk_score > 5")
        assert len(filtered) == 1
        assert filtered[0].risk_score > 5

        # risk_score >= 4.5
        filtered = _apply_filter(mock_assets, "risk_score >= 4.5")
        assert len(filtered) == 2

        # risk_score < 5
        filtered = _apply_filter(mock_assets, "risk_score < 5")
        assert len(filtered) == 2

    def test_filter_by_port(self, mock_assets) -> None:
        """Test filtering by port."""
        # port == 443
        filtered = _apply_filter(mock_assets, "port == 443")
        assert len(filtered) == 2

        # port > 1000
        filtered = _apply_filter(mock_assets, "port > 1000")
        assert len(filtered) == 1
        assert filtered[0].port == 3306

    def test_filter_by_domain_contains(self, mock_assets) -> None:
        """Test filtering by domain substring."""
        # domain contains "api"
        filtered = _apply_filter(mock_assets, "domain contains 'api'")
        assert len(filtered) == 1
        assert "api" in filtered[0].domain

        # domain contains "example"
        filtered = _apply_filter(mock_assets, "domain contains 'example'")
        assert len(filtered) == 3


# =============================================================================
# Collector Selection Tests
# =============================================================================


class TestCollectorSelection:
    """Tests for collector selection by scan mode."""

    def test_passive_mode_collectors(self) -> None:
        """Test collectors for passive mode."""
        collectors = _get_collectors_for_mode(ASMScanMode.PASSIVE)

        assert "cert_transparency" in collectors
        assert "dns_enumeration" in collectors
        assert "cloud_ip_ranges" in collectors
        assert "port_scanner" not in collectors

    def test_active_mode_collectors(self) -> None:
        """Test collectors for active mode."""
        collectors = _get_collectors_for_mode(ASMScanMode.ACTIVE)

        # Should include both passive and active collectors
        assert "cert_transparency" in collectors
        assert "port_scanner" in collectors
        assert "technology_fingerprint" in collectors

    def test_full_mode_collectors(self) -> None:
        """Test collectors for full mode."""
        collectors = _get_collectors_for_mode(ASMScanMode.FULL)

        # Should include all collectors
        assert len(collectors) >= 5


# =============================================================================
# CLI Parser Tests
# =============================================================================


class TestCLIParser:
    """Tests for CLI argument parsing."""

    def test_add_asm_parser(self) -> None:
        """Test ASM parser is added correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        add_asm_parser(subparsers)

        # Should be able to parse ASM command
        args = parser.parse_args(["asm", "scan", "--domains", "example.com"])
        assert args.domains == ["example.com"]

    def test_scan_command_parsing(self) -> None:
        """Test scan command argument parsing."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        # Basic scan
        args = parser.parse_args(["asm", "scan", "--domains", "example.com"])
        assert args.domains == ["example.com"]
        assert args.mode == "passive"

        # With mode
        args = parser.parse_args([
            "asm", "scan",
            "--domains", "example.com",
            "--mode", "active",
            "--i-own-this-domain"
        ])
        assert args.mode == "active"
        assert args.i_own_this_domain is True

        # With output format
        args = parser.parse_args([
            "asm", "scan",
            "--domains", "example.com",
            "--output", "json"
        ])
        assert args.output == "json"

    def test_inventory_command_parsing(self) -> None:
        """Test inventory command argument parsing."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        # With filter
        args = parser.parse_args([
            "asm", "inventory",
            "--filter", "risk_score > 7"
        ])
        assert args.filter_expr == "risk_score > 7"

        # With sort and limit
        args = parser.parse_args([
            "asm", "inventory",
            "--sort", "domain",
            "--limit", "50"
        ])
        assert args.sort == "domain"
        assert args.limit == 50

    def test_drift_command_parsing(self) -> None:
        """Test drift command argument parsing."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        args = parser.parse_args([
            "asm", "drift",
            "--baseline", "scan-001",
            "--current", "scan-002",
            "--format", "summary"
        ])
        assert args.baseline == "scan-001"
        assert args.current == "scan-002"
        assert args.format == "summary"

    def test_verify_command_parsing(self) -> None:
        """Test verify command argument parsing."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        args = parser.parse_args([
            "asm", "verify",
            "--domain", "example.com",
            "--method", "dns",
            "--show-token"
        ])
        assert args.domain == "example.com"
        assert args.method == "dns"
        assert args.show_token is True

    def test_monitor_command_parsing(self) -> None:
        """Test monitor command argument parsing."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        args = parser.parse_args([
            "asm", "monitor",
            "--domains", "example.com", "test.com",
            "--interval", "12",
            "--notify"
        ])
        assert args.domains == ["example.com", "test.com"]
        assert args.interval == 12
        assert args.notify is True

    def test_policies_command_parsing(self) -> None:
        """Test policies command argument parsing."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        # List policies
        args = parser.parse_args(["asm", "policies", "--list"])
        assert args.list is True

        # Show specific policy
        args = parser.parse_args(["asm", "policies", "--show", "policy-001"])
        assert args.show == "policy-001"

    def test_scans_command_parsing(self) -> None:
        """Test scans command argument parsing."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_asm_parser(subparsers)

        args = parser.parse_args([
            "asm", "scans",
            "--limit", "50",
            "--format", "json"
        ])
        assert args.limit == 50
        assert args.format == "json"


# =============================================================================
# CLI Command Handler Tests
# =============================================================================


class TestCLICommandHandlers:
    """Tests for CLI command handlers."""

    def test_cmd_asm_no_action(self, capsys) -> None:
        """Test cmd_asm with no action shows help."""
        args = argparse.Namespace(asm_action=None)
        result = cmd_asm(args)

        assert result == 0

        captured = capsys.readouterr()
        assert "Attack Surface Management Commands" in captured.out

    def test_cmd_asm_unknown_action(self, capsys) -> None:
        """Test cmd_asm with unknown action returns error."""
        args = argparse.Namespace(asm_action="unknown")
        result = cmd_asm(args)

        assert result == 1

        captured = capsys.readouterr()
        assert "Unknown ASM command" in captured.out

    @patch("stance.asm.storage.ASMStorageAdapter")
    def test_inventory_no_data(self, mock_storage, capsys) -> None:
        """Test inventory command with no stored data."""
        mock_storage.return_value.get_external_assets.return_value = ExternalAssetCollection()

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

    @patch("stance.asm.storage.ASMStorageAdapter")
    def test_scans_no_data(self, mock_storage, capsys) -> None:
        """Test scans command with no stored scans."""
        mock_storage.return_value.list_scans.return_value = []

        args = argparse.Namespace(
            asm_action="scans",
            limit=20,
            format="table",
        )

        result = cmd_asm(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "No ASM scans found" in captured.out


# =============================================================================
# Scan Command Tests
# =============================================================================


class TestScanCommand:
    """Tests for scan command."""

    def test_scan_requires_valid_domain(self, capsys) -> None:
        """Test scan command rejects invalid domain."""
        args = argparse.Namespace(
            asm_action="scan",
            domains=["invalid"],
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

    def test_active_scan_requires_ownership_confirmation(self, capsys) -> None:
        """Test active scan requires --i-own-this-domain flag."""
        args = argparse.Namespace(
            asm_action="scan",
            domains=["example.com"],
            mode="active",
            output="table",
            save=False,
            correlate=False,
            config=None,
            i_own_this_domain=False,  # Not confirmed
            format=None,
        )

        result = cmd_asm(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "ownership confirmation" in captured.out

    @patch("stance.cli_asm._run_collector")
    def test_scan_with_collector_mocks(self, mock_run_collector, capsys) -> None:
        """Test scan with mocked collectors."""
        now = datetime.now(timezone.utc)

        # Mock collector to return assets
        mock_run_collector.return_value = ExternalAssetCollection([
            ExternalAsset(
                id="ext-001",
                domain="www.example.com",
                ip_address="1.2.3.4",
                port=443,
                protocol="https",
                first_seen=now,
                last_seen=now,
            )
        ])

        args = argparse.Namespace(
            asm_action="scan",
            domains=["example.com"],
            mode="passive",
            output="table",
            save=False,
            correlate=False,
            config=None,
            i_own_this_domain=False,
            format=None,
        )

        result = cmd_asm(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Scan completed" in captured.out


# =============================================================================
# Verify Command Tests
# =============================================================================


class TestVerifyCommand:
    """Tests for verify command."""

    def test_verify_show_token(self, capsys) -> None:
        """Test verify command shows token."""
        args = argparse.Namespace(
            asm_action="verify",
            domain="example.com",
            method="dns",
            show_token=True,
            check=False,
        )

        result = cmd_asm(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Domain Ownership Verification" in captured.out
        assert "TXT record" in captured.out
        assert "_stance-verify" in captured.out

    def test_verify_http_method(self, capsys) -> None:
        """Test verify command with HTTP method."""
        args = argparse.Namespace(
            asm_action="verify",
            domain="example.com",
            method="http",
            show_token=True,
            check=False,
        )

        result = cmd_asm(args)
        assert result == 0

        captured = capsys.readouterr()
        assert ".well-known/stance-verify.txt" in captured.out

    def test_verify_invalid_domain(self, capsys) -> None:
        """Test verify command rejects invalid domain."""
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


# =============================================================================
# Output Format Tests
# =============================================================================


class TestOutputFormats:
    """Tests for output format handling."""

    @patch("stance.asm.storage.ASMStorageAdapter")
    def test_inventory_json_output(self, mock_storage, mock_assets, capsys) -> None:
        """Test inventory command with JSON output."""
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
        assert len(data) == 3

    @patch("stance.asm.storage.ASMStorageAdapter")
    def test_inventory_table_output(self, mock_storage, mock_assets, capsys) -> None:
        """Test inventory command with table output."""
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
    def test_scans_json_output(self, mock_storage, capsys) -> None:
        """Test scans command with JSON output."""
        now = datetime.now(timezone.utc)

        mock_scan = MagicMock()
        mock_scan.scan_id = "scan-001"
        mock_scan.started_at = now
        mock_scan.completed_at = now
        mock_scan.status = ASMScanStatus.COMPLETED
        mock_scan.target_domains = ["example.com"]
        mock_scan.scan_mode = ASMScanMode.PASSIVE
        mock_scan.assets_discovered = 5
        mock_scan.findings_count = 2
        mock_scan.duration_seconds = 30.0

        mock_storage.return_value.list_scans.return_value = [mock_scan]

        args = argparse.Namespace(
            asm_action="scans",
            limit=20,
            format="json",
        )

        result = cmd_asm(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["scan_id"] == "scan-001"


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    @patch("stance.asm.storage.ASMStorageAdapter")
    def test_storage_error_handling(self, mock_storage, capsys) -> None:
        """Test storage errors are handled gracefully."""
        mock_storage.side_effect = Exception("Database connection failed")

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
    def test_drift_insufficient_scans(self, mock_storage, capsys) -> None:
        """Test drift command with insufficient scans."""
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
