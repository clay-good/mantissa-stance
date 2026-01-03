"""
Unit tests for Scanner CLI module.

Tests the command-line interface for container image vulnerability scanning.
"""

import pytest
import argparse
from unittest.mock import MagicMock, patch

from stance.cli_scanner import (
    add_scanner_parser,
    cmd_scanner,
    _handle_scanners,
    _handle_check,
    _handle_version,
    _handle_scan,
    _handle_enrich,
    _handle_epss,
    _handle_kev,
    _handle_severity_levels,
    _handle_priority_factors,
    _handle_package_types,
    _handle_stats,
    _handle_status,
    _handle_summary,
)


class TestAddScannerParser:
    """Tests for add_scanner_parser function."""

    def test_parser_creation(self):
        """Test that parser is created correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_scanner_parser(subparsers)

        # Should not raise
        args = parser.parse_args(["scanner", "status"])
        assert args.scanner_action == "status"

    def test_all_subcommands_available(self):
        """Test that all subcommands are available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_scanner_parser(subparsers)

        commands = [
            ("scanners", []),
            ("check", []),
            ("version", []),
            ("scan", ["nginx:latest"]),
            ("enrich", ["CVE-2021-44228"]),
            ("epss", ["CVE-2021-44228"]),
            ("kev", ["CVE-2021-44228"]),
            ("severity-levels", []),
            ("priority-factors", []),
            ("package-types", []),
            ("stats", []),
            ("status", []),
            ("summary", []),
        ]

        for cmd, extra_args in commands:
            args = parser.parse_args(["scanner", cmd] + extra_args)
            assert args.scanner_action == cmd


class TestCmdScanner:
    """Tests for cmd_scanner handler."""

    def test_no_action_shows_error(self, capsys):
        """Test that no action shows error."""
        args = argparse.Namespace(scanner_action=None)
        result = cmd_scanner(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "No scanner action specified" in captured.out

    def test_unknown_action_shows_error(self, capsys):
        """Test that unknown action shows error."""
        args = argparse.Namespace(scanner_action="unknown")
        result = cmd_scanner(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Unknown action" in captured.out

    def test_valid_action_routes_correctly(self):
        """Test that valid actions route to correct handlers."""
        args = argparse.Namespace(
            scanner_action="status",
            format="json",
        )
        result = cmd_scanner(args)
        assert result == 0


class TestHandleScanners:
    """Tests for scanners command handler."""

    def test_scanners_table(self, capsys):
        """Test listing scanners in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_scanners(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Available Scanners" in captured.out
        assert "Trivy" in captured.out

    def test_scanners_json(self, capsys):
        """Test listing scanners in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_scanners(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "total" in data
        assert "scanners" in data
        assert len(data["scanners"]) >= 1


class TestHandleCheck:
    """Tests for check command handler."""

    def test_check_table(self, capsys):
        """Test checking scanner in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_check(args)
        # Result depends on whether Trivy is installed
        assert result in [0, 1]

        captured = capsys.readouterr()
        assert "Scanner: Trivy" in captured.out

    def test_check_json(self, capsys):
        """Test checking scanner in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_check(args)

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "scanner" in data
        assert "available" in data
        assert data["scanner"] == "trivy"


class TestHandleVersion:
    """Tests for version command handler."""

    def test_version_json(self, capsys):
        """Test getting version in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_version(args)

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "scanner" in data
        assert "available" in data


class TestHandleScan:
    """Tests for scan command handler."""

    @patch("stance.scanner.TrivyScanner")
    def test_scan_trivy_not_available(self, mock_scanner_class, capsys):
        """Test scan when Trivy is not available."""
        mock_scanner = MagicMock()
        mock_scanner.is_available.return_value = False
        mock_scanner_class.return_value = mock_scanner

        args = argparse.Namespace(
            image="nginx:latest",
            timeout=300,
            skip_db_update=False,
            ignore_unfixed=False,
            enrich=False,
            format="table",
        )
        result = _handle_scan(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "not installed" in captured.out.lower()


class TestHandleEnrich:
    """Tests for enrich command handler."""

    def test_enrich_invalid_cve(self, capsys):
        """Test enriching with invalid CVE ID."""
        args = argparse.Namespace(
            cve_id="invalid",
            format="table",
        )
        result = _handle_enrich(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Invalid CVE ID" in captured.out

    def test_enrich_valid_cve_json(self, capsys):
        """Test enriching with valid CVE ID (JSON)."""
        args = argparse.Namespace(
            cve_id="CVE-2021-44228",
            format="json",
        )
        result = _handle_enrich(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["cve_id"] == "CVE-2021-44228"
        assert "epss" in data or data["epss"] is None
        assert "kev" in data


class TestHandleEpss:
    """Tests for epss command handler."""

    def test_epss_invalid_cve(self, capsys):
        """Test EPSS with invalid CVE ID."""
        args = argparse.Namespace(
            cve_id="invalid",
            format="table",
        )
        result = _handle_epss(args)
        assert result == 1

    def test_epss_valid_cve(self, capsys):
        """Test EPSS with valid CVE ID."""
        args = argparse.Namespace(
            cve_id="CVE-2021-44228",
            format="json",
        )
        result = _handle_epss(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["cve_id"] == "CVE-2021-44228"
        assert "found" in data


class TestHandleKev:
    """Tests for kev command handler."""

    def test_kev_invalid_cve(self, capsys):
        """Test KEV with invalid CVE ID."""
        args = argparse.Namespace(
            cve_id="invalid",
            format="table",
        )
        result = _handle_kev(args)
        assert result == 1

    def test_kev_valid_cve(self, capsys):
        """Test KEV with valid CVE ID."""
        args = argparse.Namespace(
            cve_id="CVE-2021-44228",
            format="json",
        )
        result = _handle_kev(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["cve_id"] == "CVE-2021-44228"
        assert "in_catalog" in data


class TestHandleSeverityLevels:
    """Tests for severity-levels command handler."""

    def test_severity_levels_table(self, capsys):
        """Test listing severity levels in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_severity_levels(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Vulnerability Severity Levels" in captured.out
        assert "CRITICAL" in captured.out
        assert "HIGH" in captured.out

    def test_severity_levels_json(self, capsys):
        """Test listing severity levels in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_severity_levels(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["total"] == 5
        assert len(data["levels"]) == 5


class TestHandlePriorityFactors:
    """Tests for priority-factors command handler."""

    def test_priority_factors_table(self, capsys):
        """Test listing priority factors in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_priority_factors(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Vulnerability Priority Scoring" in captured.out
        assert "Severity" in captured.out
        assert "EPSS" in captured.out

    def test_priority_factors_json(self, capsys):
        """Test listing priority factors in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_priority_factors(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["max_score"] == 100
        assert len(data["factors"]) == 6


class TestHandlePackageTypes:
    """Tests for package-types command handler."""

    def test_package_types_table(self, capsys):
        """Test listing package types in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_package_types(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Supported Package Types" in captured.out
        assert "npm" in captured.out
        assert "pip" in captured.out

    def test_package_types_json(self, capsys):
        """Test listing package types in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_package_types(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["total"] == 12
        assert len(data["package_types"]) == 12


class TestHandleStats:
    """Tests for stats command handler."""

    def test_stats_table(self, capsys):
        """Test showing stats in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Scanner Statistics" in captured.out

    def test_stats_json(self, capsys):
        """Test showing stats in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "scanner" in data
        assert "severity_levels" in data
        assert "package_types" in data


class TestHandleStatus:
    """Tests for status command handler."""

    def test_status_table(self, capsys):
        """Test showing status in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Scanner Module Status" in captured.out
        assert "Components:" in captured.out

    def test_status_json(self, capsys):
        """Test showing status in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["module"] == "scanner"
        assert "status" in data
        assert "components" in data
        assert "capabilities" in data


class TestHandleSummary:
    """Tests for summary command handler."""

    def test_summary_table(self, capsys):
        """Test showing summary in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Scanner Module Summary" in captured.out
        assert "Features:" in captured.out

    def test_summary_json(self, capsys):
        """Test showing summary in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["module"] == "scanner"
        assert "features" in data
        assert "enrichment" in data
        assert "supported_ecosystems" in data


class TestCLIRouting:
    """Tests for CLI command routing."""

    def test_all_handlers_exist(self):
        """Test that all handlers exist."""
        handlers = [
            _handle_scanners,
            _handle_check,
            _handle_version,
            _handle_scan,
            _handle_enrich,
            _handle_epss,
            _handle_kev,
            _handle_severity_levels,
            _handle_priority_factors,
            _handle_package_types,
            _handle_stats,
            _handle_status,
            _handle_summary,
        ]

        for handler in handlers:
            assert callable(handler)

    def test_cmd_scanner_routes_to_all_handlers(self, capsys):
        """Test that cmd_scanner routes to all handlers."""
        actions = [
            ("status", {}),
            ("summary", {}),
            ("stats", {}),
            ("scanners", {}),
            ("severity-levels", {}),
            ("priority-factors", {}),
            ("package-types", {}),
        ]

        for action, extra_args in actions:
            args = argparse.Namespace(
                scanner_action=action,
                format="json",
                **extra_args,
            )
            result = cmd_scanner(args)
            assert result == 0, f"Handler for {action} failed"


class TestScannerModuleIntegration:
    """Integration tests with actual scanner module."""

    def test_severity_levels_structure(self, capsys):
        """Test severity levels have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_severity_levels(args)

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)

        for level in data["levels"]:
            assert "level" in level
            assert "description" in level
            assert "cvss_range" in level
            assert "examples" in level

    def test_priority_factors_structure(self, capsys):
        """Test priority factors have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_priority_factors(args)

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)

        for factor in data["factors"]:
            assert "factor" in factor
            assert "max_points" in factor
            assert "description" in factor

    def test_package_types_structure(self, capsys):
        """Test package types have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_package_types(args)

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)

        for pt in data["package_types"]:
            assert "type" in pt
            assert "ecosystem" in pt
            assert "description" in pt

    def test_status_components_structure(self, capsys):
        """Test status components have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_status(args)

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)

        assert "TrivyScanner" in data["components"]
        assert "CVEEnricher" in data["components"]
        assert "EPSSClient" in data["components"]
        assert "KEVClient" in data["components"]


class TestCVEValidation:
    """Tests for CVE ID validation."""

    def test_enrich_requires_cve_prefix(self, capsys):
        """Test that enrich requires CVE- prefix."""
        args = argparse.Namespace(
            cve_id="2021-44228",
            format="table",
        )
        result = _handle_enrich(args)
        assert result == 1

    def test_epss_requires_cve_prefix(self, capsys):
        """Test that EPSS requires CVE- prefix."""
        args = argparse.Namespace(
            cve_id="2021-44228",
            format="table",
        )
        result = _handle_epss(args)
        assert result == 1

    def test_kev_requires_cve_prefix(self, capsys):
        """Test that KEV requires CVE- prefix."""
        args = argparse.Namespace(
            cve_id="2021-44228",
            format="table",
        )
        result = _handle_kev(args)
        assert result == 1

    def test_cve_id_uppercase(self, capsys):
        """Test that CVE ID is converted to uppercase."""
        args = argparse.Namespace(
            cve_id="cve-2021-44228",
            format="json",
        )
        result = _handle_enrich(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["cve_id"] == "CVE-2021-44228"
