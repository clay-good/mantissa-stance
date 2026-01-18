"""
Unit tests for API Security CLI commands.

Tests the CLI interface for API security testing:
- API discovery
- Security analysis
- Authentication testing
- API listing
- Status and info commands
"""

from __future__ import annotations

import argparse
import json
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_api_security import (
    add_api_security_parser,
    cmd_api_security,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_api_inventory():
    """Create mock API inventory."""
    inventory = MagicMock()
    inventory.total_endpoints = 5
    inventory.public_endpoints = 2
    inventory.authenticated_endpoints = 3
    inventory.unauthenticated_endpoints = 2
    inventory.by_provider = {"aws": 3, "azure": 2}
    inventory.by_protocol = {"REST": 4, "HTTP": 1}
    inventory.endpoints = []
    inventory.to_dict.return_value = {
        "total_endpoints": 5,
        "public_endpoints": 2,
        "authenticated_endpoints": 3,
        "by_provider": {"aws": 3, "azure": 2},
    }
    return inventory


@pytest.fixture
def mock_api_endpoint():
    """Create mock API endpoint."""
    endpoint = MagicMock()
    endpoint.name = "MyAPI"
    endpoint.cloud_provider = "aws"
    endpoint.region = "us-east-1"
    endpoint.protocol = MagicMock()
    endpoint.protocol.value = "REST"
    endpoint.is_public = True
    endpoint.authentication_required = True
    endpoint.authentication_type = MagicMock()
    endpoint.authentication_type.value = "IAM"
    endpoint.url = "https://api.example.com"
    endpoint.has_waf = True
    endpoint.to_dict.return_value = {
        "name": "MyAPI",
        "cloud_provider": "aws",
        "is_public": True,
    }
    return endpoint


@pytest.fixture
def mock_security_report():
    """Create mock security report."""
    report = MagicMock()
    report.total_endpoints = 5
    report.endpoints_with_findings = 2
    report.total_findings = 3
    report.critical_count = 0
    report.high_count = 1
    report.medium_count = 1
    report.low_count = 1
    report.info_count = 0
    report.by_category = {"authentication": 2, "cors": 1}
    report.findings = []
    report.analysis_duration_ms = 100
    report.to_dict.return_value = {
        "total_endpoints": 5,
        "total_findings": 3,
        "critical_count": 0,
        "high_count": 1,
    }
    return report


@pytest.fixture
def mock_auth_test_report():
    """Create mock authentication test report."""
    report = MagicMock()
    report.endpoint_name = "MyAPI"
    report.authentication_type = "IAM"
    report.passed_count = 3
    report.failed_count = 0
    report.warning_count = 1
    report.results = []
    report.to_dict.return_value = {
        "endpoint_name": "MyAPI",
        "passed_count": 3,
        "failed_count": 0,
    }
    return report


# =============================================================================
# Parser Tests
# =============================================================================


class TestAPISecurityParser:
    """Tests for API security argument parser setup."""

    def test_add_api_security_parser(self):
        """Test API security parser is added correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        add_api_security_parser(subparsers)

        args = parser.parse_args(["api-security", "discover"])
        assert args.api_security_command == "discover"

    def test_discover_subcommand_args(self):
        """Test discover subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_api_security_parser(subparsers)

        args = parser.parse_args([
            "api-security", "discover",
            "--from-scan",
            "--provider", "aws",
            "--json",
        ])

        assert args.api_security_command == "discover"
        assert args.from_scan is True
        assert args.provider == "aws"
        assert args.json is True

    def test_discover_openapi_arg(self):
        """Test discover with OpenAPI file argument."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_api_security_parser(subparsers)

        args = parser.parse_args([
            "api-security", "discover",
            "--openapi", "/path/to/api.yaml",
        ])

        assert args.openapi == "/path/to/api.yaml"

    def test_analyze_subcommand_args(self):
        """Test analyze subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_api_security_parser(subparsers)

        args = parser.parse_args([
            "api-security", "analyze",
            "--from-scan",
            "--min-severity", "high",
            "--fail-on", "critical",
            "--json",
        ])

        assert args.api_security_command == "analyze"
        assert args.from_scan is True
        assert args.min_severity == "high"
        assert args.fail_on == "critical"
        assert args.json is True

    def test_test_auth_subcommand_args(self):
        """Test test-auth subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_api_security_parser(subparsers)

        args = parser.parse_args([
            "api-security", "test-auth",
            "--from-scan",
            "--json",
        ])

        assert args.api_security_command == "test-auth"
        assert args.from_scan is True
        assert args.json is True

    def test_list_subcommand_args(self):
        """Test list subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_api_security_parser(subparsers)

        args = parser.parse_args([
            "api-security", "list",
            "--provider", "gcp",
            "--public-only",
            "--unauthenticated-only",
            "--json",
        ])

        assert args.api_security_command == "list"
        assert args.provider == "gcp"
        assert args.public_only is True
        assert args.unauthenticated_only is True
        assert args.json is True

    def test_status_subcommand_args(self):
        """Test status subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_api_security_parser(subparsers)

        args = parser.parse_args([
            "api-security", "status",
            "--json",
        ])

        assert args.api_security_command == "status"
        assert args.json is True

    def test_info_subcommand_args(self):
        """Test info subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_api_security_parser(subparsers)

        args = parser.parse_args([
            "api-security", "info",
            "--json",
        ])

        assert args.api_security_command == "info"
        assert args.json is True

    def test_provider_choices(self):
        """Test provider choices."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_api_security_parser(subparsers)

        for provider in ["aws", "azure", "gcp", "all"]:
            args = parser.parse_args(["api-security", "discover", "--provider", provider])
            assert args.provider == provider

    def test_severity_choices(self):
        """Test severity choices for analyze command."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_api_security_parser(subparsers)

        for sev in ["critical", "high", "medium", "low", "info"]:
            args = parser.parse_args(["api-security", "analyze", "--min-severity", sev])
            assert args.min_severity == sev


# =============================================================================
# Command Dispatch Tests
# =============================================================================


class TestAPISecurityCommandDispatch:
    """Tests for API security command routing."""

    def test_cmd_api_security_no_command(self, capsys):
        """Test cmd_api_security with no command shows usage."""
        args = argparse.Namespace(api_security_command=None)

        result = cmd_api_security(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Usage:" in captured.out
        assert "discover" in captured.out

    def test_cmd_api_security_missing_attr(self, capsys):
        """Test cmd_api_security with missing attribute shows usage."""
        args = argparse.Namespace()

        result = cmd_api_security(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Available commands:" in captured.out

    @patch("stance.cli_api_security._handle_discover")
    def test_cmd_dispatch_discover(self, mock_fn):
        """Test cmd_api_security dispatches to discover handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(api_security_command="discover")

        result = cmd_api_security(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_api_security._handle_analyze")
    def test_cmd_dispatch_analyze(self, mock_fn):
        """Test cmd_api_security dispatches to analyze handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(api_security_command="analyze")

        result = cmd_api_security(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_api_security._handle_test_auth")
    def test_cmd_dispatch_test_auth(self, mock_fn):
        """Test cmd_api_security dispatches to test-auth handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(api_security_command="test-auth")

        result = cmd_api_security(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_api_security._handle_list")
    def test_cmd_dispatch_list(self, mock_fn):
        """Test cmd_api_security dispatches to list handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(api_security_command="list")

        result = cmd_api_security(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_api_security._handle_status")
    def test_cmd_dispatch_status(self, mock_fn):
        """Test cmd_api_security dispatches to status handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(api_security_command="status")

        result = cmd_api_security(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_api_security._handle_info")
    def test_cmd_dispatch_info(self, mock_fn):
        """Test cmd_api_security dispatches to info handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(api_security_command="info")

        result = cmd_api_security(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    def test_cmd_dispatch_unknown_command(self, capsys):
        """Test cmd_api_security with unknown command."""
        args = argparse.Namespace(api_security_command="unknown")

        result = cmd_api_security(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown command" in captured.out


# =============================================================================
# Discover Command Tests
# =============================================================================


class TestHandleDiscover:
    """Tests for discover command handler."""

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    @patch("stance.cli_api_security.APIInventory")
    def test_discover_from_scan_table(
        self, mock_inventory_class, mock_discoverer_class,
        mock_get_assets, mock_api_inventory, capsys
    ):
        """Test discover from scan with table output."""
        from stance.cli_api_security import _handle_discover

        mock_get_assets.return_value = [MagicMock()]
        mock_discoverer_class.return_value.discover_from_assets.return_value = mock_api_inventory

        args = argparse.Namespace(
            from_scan=True,
            openapi=None,
            provider="all",
            json=False,
        )

        result = _handle_discover(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "API Discovery Results" in captured.out

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    @patch("stance.cli_api_security.APIInventory")
    def test_discover_from_scan_json(
        self, mock_inventory_class, mock_discoverer_class,
        mock_get_assets, mock_api_inventory, capsys
    ):
        """Test discover from scan with JSON output."""
        from stance.cli_api_security import _handle_discover

        mock_get_assets.return_value = [MagicMock()]
        mock_discoverer_class.return_value.discover_from_assets.return_value = mock_api_inventory

        args = argparse.Namespace(
            from_scan=True,
            openapi=None,
            provider="all",
            json=True,
        )

        result = _handle_discover(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "total_endpoints" in output

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    @patch("stance.cli_api_security.APIInventory")
    def test_discover_no_assets(
        self, mock_inventory_class, mock_discoverer_class,
        mock_get_assets, capsys
    ):
        """Test discover when no assets found."""
        from stance.cli_api_security import _handle_discover

        mock_get_assets.return_value = []
        empty_inventory = MagicMock()
        empty_inventory.total_endpoints = 0
        empty_inventory.public_endpoints = 0
        empty_inventory.authenticated_endpoints = 0
        empty_inventory.unauthenticated_endpoints = 0
        empty_inventory.by_provider = {}
        empty_inventory.by_protocol = {}
        empty_inventory.endpoints = []
        mock_inventory_class.return_value = empty_inventory

        args = argparse.Namespace(
            from_scan=False,
            openapi=None,
            provider="all",
            json=False,
        )

        result = _handle_discover(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total Endpoints: 0" in captured.out


# =============================================================================
# Analyze Command Tests
# =============================================================================


class TestHandleAnalyze:
    """Tests for analyze command handler."""

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    @patch("stance.cli_api_security.APISecurityAnalyzer")
    @patch("stance.cli_api_security.APIInventory")
    def test_analyze_from_scan_table(
        self, mock_inventory_class, mock_analyzer_class,
        mock_discoverer_class, mock_get_assets,
        mock_api_inventory, mock_security_report, capsys
    ):
        """Test analyze from scan with table output."""
        from stance.cli_api_security import _handle_analyze

        mock_get_assets.return_value = [MagicMock()]
        mock_discoverer_class.return_value.discover_from_assets.return_value = mock_api_inventory
        mock_analyzer_class.return_value.analyze.return_value = mock_security_report

        args = argparse.Namespace(
            from_scan=True,
            openapi=None,
            min_severity="info",
            fail_on=None,
            json=False,
        )

        result = _handle_analyze(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "API Security Analysis Report" in captured.out
        assert "Severity Breakdown:" in captured.out

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    @patch("stance.cli_api_security.APISecurityAnalyzer")
    @patch("stance.cli_api_security.APIInventory")
    def test_analyze_from_scan_json(
        self, mock_inventory_class, mock_analyzer_class,
        mock_discoverer_class, mock_get_assets,
        mock_api_inventory, mock_security_report, capsys
    ):
        """Test analyze from scan with JSON output."""
        from stance.cli_api_security import _handle_analyze

        mock_get_assets.return_value = [MagicMock()]
        mock_discoverer_class.return_value.discover_from_assets.return_value = mock_api_inventory
        mock_analyzer_class.return_value.analyze.return_value = mock_security_report

        args = argparse.Namespace(
            from_scan=True,
            openapi=None,
            min_severity="info",
            fail_on=None,
            json=True,
        )

        result = _handle_analyze(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "total_endpoints" in output

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    @patch("stance.cli_api_security.APISecurityAnalyzer")
    @patch("stance.cli_api_security.APIInventory")
    def test_analyze_fail_on_critical(
        self, mock_inventory_class, mock_analyzer_class,
        mock_discoverer_class, mock_get_assets,
        mock_api_inventory, capsys
    ):
        """Test analyze with fail-on critical returns 1."""
        from stance.cli_api_security import _handle_analyze

        mock_get_assets.return_value = [MagicMock()]
        mock_discoverer_class.return_value.discover_from_assets.return_value = mock_api_inventory

        # Report with critical finding
        critical_report = MagicMock()
        critical_report.total_endpoints = 5
        critical_report.endpoints_with_findings = 1
        critical_report.total_findings = 1
        critical_report.critical_count = 1
        critical_report.high_count = 0
        critical_report.medium_count = 0
        critical_report.low_count = 0
        critical_report.info_count = 0
        critical_report.by_category = {}
        critical_report.findings = []
        critical_report.analysis_duration_ms = 100
        critical_report.to_dict.return_value = {}
        mock_analyzer_class.return_value.analyze.return_value = critical_report

        args = argparse.Namespace(
            from_scan=True,
            openapi=None,
            min_severity="info",
            fail_on="critical",
            json=False,
        )

        result = _handle_analyze(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "FAILED" in captured.out


# =============================================================================
# Test Auth Command Tests
# =============================================================================


class TestHandleTestAuth:
    """Tests for test-auth command handler."""

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    @patch("stance.cli_api_security.AuthenticationTester")
    def test_test_auth_table(
        self, mock_tester_class, mock_discoverer_class,
        mock_get_assets, mock_api_endpoint, mock_auth_test_report, capsys
    ):
        """Test test-auth with table output."""
        from stance.cli_api_security import _handle_test_auth

        mock_get_assets.return_value = [MagicMock()]

        mock_inventory = MagicMock()
        mock_inventory.endpoints = [mock_api_endpoint]
        mock_discoverer_class.return_value.discover_from_assets.return_value = mock_inventory
        mock_tester_class.return_value.test_endpoint.return_value = mock_auth_test_report

        args = argparse.Namespace(
            from_scan=True,
            json=False,
        )

        result = _handle_test_auth(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "API Authentication Test Results" in captured.out
        assert "Endpoints Tested:" in captured.out

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    @patch("stance.cli_api_security.AuthenticationTester")
    def test_test_auth_json(
        self, mock_tester_class, mock_discoverer_class,
        mock_get_assets, mock_api_endpoint, mock_auth_test_report, capsys
    ):
        """Test test-auth with JSON output."""
        from stance.cli_api_security import _handle_test_auth

        mock_get_assets.return_value = [MagicMock()]

        mock_inventory = MagicMock()
        mock_inventory.endpoints = [mock_api_endpoint]
        mock_discoverer_class.return_value.discover_from_assets.return_value = mock_inventory
        mock_tester_class.return_value.test_endpoint.return_value = mock_auth_test_report

        args = argparse.Namespace(
            from_scan=True,
            json=True,
        )

        result = _handle_test_auth(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "summary" in output
        assert "reports" in output

    @patch("stance.cli_api_security._get_api_gateway_assets")
    def test_test_auth_no_assets(self, mock_get_assets, capsys):
        """Test test-auth when no assets found."""
        from stance.cli_api_security import _handle_test_auth

        mock_get_assets.return_value = []

        args = argparse.Namespace(
            from_scan=True,
            json=False,
        )

        result = _handle_test_auth(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "No API assets found" in captured.out


# =============================================================================
# List Command Tests
# =============================================================================


class TestHandleList:
    """Tests for list command handler."""

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    def test_list_table(
        self, mock_discoverer_class, mock_get_assets,
        mock_api_endpoint, capsys
    ):
        """Test list with table output."""
        from stance.cli_api_security import _handle_list

        mock_get_assets.return_value = [MagicMock()]

        mock_inventory = MagicMock()
        mock_inventory.endpoints = [mock_api_endpoint]
        mock_discoverer_class.return_value.discover_from_assets.return_value = mock_inventory

        args = argparse.Namespace(
            provider="all",
            public_only=False,
            unauthenticated_only=False,
            json=False,
        )

        result = _handle_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "API Endpoints" in captured.out
        assert "MyAPI" in captured.out

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    def test_list_json(
        self, mock_discoverer_class, mock_get_assets,
        mock_api_endpoint, capsys
    ):
        """Test list with JSON output."""
        from stance.cli_api_security import _handle_list

        mock_get_assets.return_value = [MagicMock()]

        mock_inventory = MagicMock()
        mock_inventory.endpoints = [mock_api_endpoint]
        mock_discoverer_class.return_value.discover_from_assets.return_value = mock_inventory

        args = argparse.Namespace(
            provider="all",
            public_only=False,
            unauthenticated_only=False,
            json=True,
        )

        result = _handle_list(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "endpoints" in output
        assert "total" in output

    @patch("stance.cli_api_security._get_api_gateway_assets")
    def test_list_no_assets(self, mock_get_assets, capsys):
        """Test list when no assets found."""
        from stance.cli_api_security import _handle_list

        mock_get_assets.return_value = []

        args = argparse.Namespace(
            provider="all",
            public_only=False,
            unauthenticated_only=False,
            json=False,
        )

        result = _handle_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No API endpoints found" in captured.out


# =============================================================================
# Status Command Tests
# =============================================================================


class TestHandleStatus:
    """Tests for status command handler."""

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    @patch("stance.cli_api_security.APIInventory")
    def test_status_table(
        self, mock_inventory_class, mock_discoverer_class,
        mock_get_assets, mock_api_inventory, capsys
    ):
        """Test status with table output."""
        from stance.cli_api_security import _handle_status

        mock_get_assets.return_value = []
        mock_inventory_class.return_value = mock_api_inventory

        args = argparse.Namespace(json=False)

        result = _handle_status(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "API Security Module Status" in captured.out
        assert "Components:" in captured.out

    @patch("stance.cli_api_security._get_api_gateway_assets")
    @patch("stance.cli_api_security.APIDiscoverer")
    @patch("stance.cli_api_security.APIInventory")
    def test_status_json(
        self, mock_inventory_class, mock_discoverer_class,
        mock_get_assets, mock_api_inventory, capsys
    ):
        """Test status with JSON output."""
        from stance.cli_api_security import _handle_status

        mock_get_assets.return_value = []
        mock_inventory_class.return_value = mock_api_inventory

        args = argparse.Namespace(json=True)

        result = _handle_status(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "status" in output
        assert "components" in output


# =============================================================================
# Info Command Tests
# =============================================================================


class TestHandleInfo:
    """Tests for info command handler."""

    def test_info_table(self, capsys):
        """Test info with table output."""
        from stance.cli_api_security import _handle_info

        args = argparse.Namespace(json=False)

        result = _handle_info(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "API Security Testing Module" in captured.out
        assert "Capabilities:" in captured.out
        assert "Components:" in captured.out

    def test_info_json(self, capsys):
        """Test info with JSON output."""
        from stance.cli_api_security import _handle_info

        args = argparse.Namespace(json=True)

        result = _handle_info(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "module" in output
        assert "capabilities" in output
        assert "components" in output
        assert "supported_providers" in output
