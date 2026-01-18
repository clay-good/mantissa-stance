"""
Unit tests for CIS Benchmark CLI commands.

Tests the CLI interface for:
- Benchmark status checks
- Benchmark listing
- Control listing
- Gap analysis
"""

from __future__ import annotations

import argparse
import json
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_benchmark import (
    add_benchmark_parser,
    cmd_benchmark,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_storage():
    """Create mock storage with sample data."""
    storage = MagicMock()
    storage.get_findings.return_value = []
    storage.get_assets.return_value = []
    return storage


@pytest.fixture
def mock_benchmark_score():
    """Create mock benchmark score."""
    score = MagicMock()
    score.benchmark_id = "cis-aws"
    score.benchmark_name = "CIS AWS Foundations Benchmark"
    score.version = "1.5.0"
    score.score_percentage = 85.0
    score.controls_passed = 51
    score.controls_failed = 9
    score.controls_total = 60
    score.control_statuses = []
    return score


@pytest.fixture
def mock_control_status():
    """Create mock control status."""
    control = MagicMock()
    control.control_id = "1.1"
    control.control_name = "Ensure MFA is enabled for root"
    control.status = "pass"
    control.resources_evaluated = 1
    control.findings = []
    return control


@pytest.fixture
def mock_failing_control():
    """Create mock failing control."""
    control = MagicMock()
    control.control_id = "1.4"
    control.control_name = "Ensure access keys are rotated"
    control.status = "fail"
    control.resources_evaluated = 5
    control.findings = ["finding-001"]
    return control


@pytest.fixture
def mock_finding():
    """Create mock finding."""
    finding = MagicMock()
    finding.id = "finding-001"
    finding.title = "Access key older than 90 days"
    finding.severity = MagicMock()
    finding.severity.value = "HIGH"
    finding.resource_id = "AKIA1234567890ABCDEF"
    return finding


# =============================================================================
# Parser Tests
# =============================================================================


class TestBenchmarkParser:
    """Tests for benchmark argument parser setup."""

    def test_add_benchmark_parser(self):
        """Test benchmark parser is added correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        add_benchmark_parser(subparsers)

        args = parser.parse_args(["benchmark", "status"])
        assert args.benchmark_action == "status"

    def test_status_subcommand_args(self):
        """Test status subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_benchmark_parser(subparsers)

        args = parser.parse_args([
            "benchmark", "status",
            "--benchmark", "cis-aws",
            "--format", "json",
        ])

        assert args.benchmark_action == "status"
        assert args.benchmark == "cis-aws"
        assert args.format == "json"

    def test_status_default_benchmark_is_all(self):
        """Test default benchmark is 'all'."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_benchmark_parser(subparsers)

        args = parser.parse_args(["benchmark", "status"])
        assert args.benchmark == "all"

    def test_list_subcommand_args(self):
        """Test list subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_benchmark_parser(subparsers)

        args = parser.parse_args([
            "benchmark", "list",
            "--format", "json",
        ])

        assert args.benchmark_action == "list"
        assert args.format == "json"

    def test_controls_subcommand_args(self):
        """Test controls subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_benchmark_parser(subparsers)

        args = parser.parse_args([
            "benchmark", "controls",
            "--benchmark", "cis-gcp",
            "--status", "fail",
            "--format", "json",
        ])

        assert args.benchmark_action == "controls"
        assert args.benchmark == "cis-gcp"
        assert args.status == "fail"
        assert args.format == "json"

    def test_gaps_subcommand_args(self):
        """Test gaps subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_benchmark_parser(subparsers)

        args = parser.parse_args([
            "benchmark", "gaps",
            "--benchmark", "cis-azure",
            "--severity", "critical",
            "--format", "table",
        ])

        assert args.benchmark_action == "gaps"
        assert args.benchmark == "cis-azure"
        assert args.severity == "critical"
        assert args.format == "table"

    def test_benchmark_choices(self):
        """Test benchmark choices for status command."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_benchmark_parser(subparsers)

        # Valid choices should work
        for bm in ["cis-aws", "cis-gcp", "cis-azure", "all"]:
            args = parser.parse_args(["benchmark", "status", "--benchmark", bm])
            assert args.benchmark == bm


# =============================================================================
# Command Dispatch Tests
# =============================================================================


class TestBenchmarkCommandDispatch:
    """Tests for benchmark command routing."""

    def test_cmd_benchmark_no_action(self, capsys):
        """Test cmd_benchmark with no action shows usage."""
        args = argparse.Namespace(benchmark_action=None)

        result = cmd_benchmark(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Usage:" in captured.out
        assert "status" in captured.out
        assert "Attestful" in captured.out

    @patch("stance.cli_benchmark._benchmark_status")
    def test_cmd_benchmark_status_dispatch(self, mock_fn):
        """Test cmd_benchmark dispatches to status handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(benchmark_action="status")

        result = cmd_benchmark(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_benchmark._list_benchmarks")
    def test_cmd_benchmark_list_dispatch(self, mock_fn):
        """Test cmd_benchmark dispatches to list handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(benchmark_action="list")

        result = cmd_benchmark(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_benchmark._list_controls")
    def test_cmd_benchmark_controls_dispatch(self, mock_fn):
        """Test cmd_benchmark dispatches to controls handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(benchmark_action="controls")

        result = cmd_benchmark(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_benchmark._show_gaps")
    def test_cmd_benchmark_gaps_dispatch(self, mock_fn):
        """Test cmd_benchmark dispatches to gaps handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(benchmark_action="gaps")

        result = cmd_benchmark(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0


# =============================================================================
# Status Command Tests
# =============================================================================


class TestBenchmarkStatus:
    """Tests for benchmark status command."""

    @patch("stance.storage.get_storage")
    @patch("stance.engine.benchmark.BenchmarkCalculator")
    @patch("stance.engine.loader.PolicyLoader")
    def test_status_single_benchmark_table(
        self, mock_loader_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_benchmark_score, capsys
    ):
        """Test status command for single benchmark with table output."""
        from stance.cli_benchmark import _benchmark_status

        mock_get_storage.return_value = mock_storage
        mock_loader_class.return_value.load_all.return_value = []
        mock_calc_class.return_value.get_benchmark_score.return_value = mock_benchmark_score

        args = argparse.Namespace(
            benchmark="cis-aws",
            format="table",
        )

        result = _benchmark_status(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "CIS Benchmark Status" in captured.out
        assert "cis-aws" in captured.out

    @patch("stance.storage.get_storage")
    @patch("stance.engine.benchmark.BenchmarkCalculator")
    @patch("stance.engine.loader.PolicyLoader")
    def test_status_single_benchmark_json(
        self, mock_loader_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_benchmark_score, capsys
    ):
        """Test status command for single benchmark with JSON output."""
        from stance.cli_benchmark import _benchmark_status

        mock_get_storage.return_value = mock_storage
        mock_loader_class.return_value.load_all.return_value = []
        mock_calc_class.return_value.get_benchmark_score.return_value = mock_benchmark_score

        args = argparse.Namespace(
            benchmark="cis-aws",
            format="json",
        )

        result = _benchmark_status(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "benchmarks" in output
        assert len(output["benchmarks"]) == 1
        assert output["benchmarks"][0]["benchmark"] == "cis-aws"

    @patch("stance.storage.get_storage")
    @patch("stance.engine.benchmark.BenchmarkCalculator")
    @patch("stance.engine.loader.PolicyLoader")
    def test_status_all_benchmarks(
        self, mock_loader_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_benchmark_score, capsys
    ):
        """Test status command for all benchmarks."""
        from stance.cli_benchmark import _benchmark_status

        mock_get_storage.return_value = mock_storage
        mock_loader_class.return_value.load_all.return_value = []

        # Create mock report
        mock_report = MagicMock()
        mock_report.benchmarks = [mock_benchmark_score]
        mock_calc_class.return_value.calculate_scores.return_value = mock_report

        args = argparse.Namespace(
            benchmark="all",
            format="json",
        )

        result = _benchmark_status(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "benchmarks" in output

    @patch("stance.storage.get_storage")
    def test_status_error_handling(self, mock_get_storage, capsys):
        """Test status command error handling."""
        from stance.cli_benchmark import _benchmark_status

        mock_get_storage.side_effect = Exception("Storage error")

        args = argparse.Namespace(
            benchmark="cis-aws",
            format="table",
        )

        result = _benchmark_status(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out


# =============================================================================
# List Benchmarks Command Tests
# =============================================================================


class TestListBenchmarks:
    """Tests for list benchmarks command."""

    def test_list_benchmarks_table(self, capsys):
        """Test list benchmarks with table output."""
        from stance.cli_benchmark import _list_benchmarks

        args = argparse.Namespace(format="table")

        result = _list_benchmarks(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Supported CIS Benchmarks" in captured.out
        assert "cis-aws" in captured.out
        assert "cis-gcp" in captured.out
        assert "cis-azure" in captured.out
        assert "Attestful" in captured.out

    def test_list_benchmarks_json(self, capsys):
        """Test list benchmarks with JSON output."""
        from stance.cli_benchmark import _list_benchmarks

        args = argparse.Namespace(format="json")

        result = _list_benchmarks(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "benchmarks" in output
        assert len(output["benchmarks"]) == 3
        benchmark_ids = [b["id"] for b in output["benchmarks"]]
        assert "cis-aws" in benchmark_ids
        assert "cis-gcp" in benchmark_ids
        assert "cis-azure" in benchmark_ids


# =============================================================================
# List Controls Command Tests
# =============================================================================


class TestListControls:
    """Tests for list controls command."""

    @patch("stance.storage.get_storage")
    @patch("stance.engine.benchmark.BenchmarkCalculator")
    @patch("stance.engine.loader.PolicyLoader")
    def test_list_controls_table(
        self, mock_loader_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_benchmark_score, mock_control_status, capsys
    ):
        """Test list controls with table output."""
        from stance.cli_benchmark import _list_controls

        mock_get_storage.return_value = mock_storage
        mock_loader_class.return_value.load_all.return_value = []
        mock_benchmark_score.control_statuses = [mock_control_status]
        mock_calc_class.return_value.get_benchmark_score.return_value = mock_benchmark_score

        args = argparse.Namespace(
            benchmark="cis-aws",
            status=None,
            format="table",
        )

        result = _list_controls(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Controls for CIS-AWS" in captured.out
        assert "1.1" in captured.out

    @patch("stance.storage.get_storage")
    @patch("stance.engine.benchmark.BenchmarkCalculator")
    @patch("stance.engine.loader.PolicyLoader")
    def test_list_controls_json(
        self, mock_loader_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_benchmark_score, mock_control_status, capsys
    ):
        """Test list controls with JSON output."""
        from stance.cli_benchmark import _list_controls

        mock_get_storage.return_value = mock_storage
        mock_loader_class.return_value.load_all.return_value = []
        mock_benchmark_score.control_statuses = [mock_control_status]
        mock_calc_class.return_value.get_benchmark_score.return_value = mock_benchmark_score

        args = argparse.Namespace(
            benchmark="cis-aws",
            status=None,
            format="json",
        )

        result = _list_controls(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "benchmark" in output
        assert "controls" in output
        assert output["benchmark"] == "cis-aws"

    @patch("stance.storage.get_storage")
    @patch("stance.engine.benchmark.BenchmarkCalculator")
    @patch("stance.engine.loader.PolicyLoader")
    def test_list_controls_status_filter(
        self, mock_loader_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_benchmark_score, mock_control_status, mock_failing_control, capsys
    ):
        """Test list controls with status filter."""
        from stance.cli_benchmark import _list_controls

        mock_get_storage.return_value = mock_storage
        mock_loader_class.return_value.load_all.return_value = []
        mock_benchmark_score.control_statuses = [mock_control_status, mock_failing_control]
        mock_calc_class.return_value.get_benchmark_score.return_value = mock_benchmark_score

        args = argparse.Namespace(
            benchmark="cis-aws",
            status="fail",
            format="json",
        )

        result = _list_controls(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        # Only failing controls should be in results
        assert len(output["controls"]) == 1
        assert output["controls"][0]["status"] == "fail"

    @patch("stance.storage.get_storage")
    def test_list_controls_error_handling(self, mock_get_storage, capsys):
        """Test list controls error handling."""
        from stance.cli_benchmark import _list_controls

        mock_get_storage.side_effect = Exception("Storage error")

        args = argparse.Namespace(
            benchmark="cis-aws",
            status=None,
            format="table",
        )

        result = _list_controls(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out


# =============================================================================
# Show Gaps Command Tests
# =============================================================================


class TestShowGaps:
    """Tests for show gaps command."""

    @patch("stance.storage.get_storage")
    @patch("stance.engine.benchmark.BenchmarkCalculator")
    @patch("stance.engine.loader.PolicyLoader")
    def test_show_gaps_table(
        self, mock_loader_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_benchmark_score, mock_failing_control, mock_finding, capsys
    ):
        """Test show gaps with table output."""
        from stance.cli_benchmark import _show_gaps

        mock_storage.get_findings.return_value = [mock_finding]
        mock_get_storage.return_value = mock_storage
        mock_loader_class.return_value.load_all.return_value = []
        mock_benchmark_score.control_statuses = [mock_failing_control]
        mock_calc_class.return_value.get_benchmark_score.return_value = mock_benchmark_score

        args = argparse.Namespace(
            benchmark="cis-aws",
            severity=None,
            format="table",
        )

        result = _show_gaps(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "CIS Benchmark Gaps" in captured.out

    @patch("stance.storage.get_storage")
    @patch("stance.engine.benchmark.BenchmarkCalculator")
    @patch("stance.engine.loader.PolicyLoader")
    def test_show_gaps_json(
        self, mock_loader_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_benchmark_score, mock_failing_control, mock_finding, capsys
    ):
        """Test show gaps with JSON output."""
        from stance.cli_benchmark import _show_gaps

        mock_storage.get_findings.return_value = [mock_finding]
        mock_get_storage.return_value = mock_storage
        mock_loader_class.return_value.load_all.return_value = []
        mock_benchmark_score.control_statuses = [mock_failing_control]
        mock_calc_class.return_value.get_benchmark_score.return_value = mock_benchmark_score

        args = argparse.Namespace(
            benchmark="cis-aws",
            severity=None,
            format="json",
        )

        result = _show_gaps(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "benchmark" in output
        assert "gaps" in output
        assert output["benchmark"] == "cis-aws"

    @patch("stance.storage.get_storage")
    @patch("stance.engine.benchmark.BenchmarkCalculator")
    @patch("stance.engine.loader.PolicyLoader")
    def test_show_gaps_no_gaps(
        self, mock_loader_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_benchmark_score, mock_control_status, capsys
    ):
        """Test show gaps when no gaps exist."""
        from stance.cli_benchmark import _show_gaps

        mock_get_storage.return_value = mock_storage
        mock_loader_class.return_value.load_all.return_value = []
        # Only passing controls, no gaps
        mock_benchmark_score.control_statuses = [mock_control_status]
        mock_calc_class.return_value.get_benchmark_score.return_value = mock_benchmark_score

        args = argparse.Namespace(
            benchmark="cis-aws",
            severity=None,
            format="table",
        )

        result = _show_gaps(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No benchmark gaps found" in captured.out

    @patch("stance.storage.get_storage")
    @patch("stance.engine.benchmark.BenchmarkCalculator")
    @patch("stance.engine.loader.PolicyLoader")
    def test_show_gaps_severity_filter(
        self, mock_loader_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_benchmark_score, mock_failing_control, mock_finding, capsys
    ):
        """Test show gaps with severity filter."""
        from stance.cli_benchmark import _show_gaps

        # Create a low severity finding
        low_finding = MagicMock()
        low_finding.id = "finding-002"
        low_finding.title = "Minor issue"
        low_finding.severity = MagicMock()
        low_finding.severity.value = "LOW"
        low_finding.resource_id = "resource-002"

        mock_storage.get_findings.return_value = [mock_finding, low_finding]
        mock_get_storage.return_value = mock_storage
        mock_loader_class.return_value.load_all.return_value = []

        # Update failing control to include both findings
        mock_failing_control.findings = ["finding-001", "finding-002"]
        mock_benchmark_score.control_statuses = [mock_failing_control]
        mock_calc_class.return_value.get_benchmark_score.return_value = mock_benchmark_score

        args = argparse.Namespace(
            benchmark="cis-aws",
            severity="high",
            format="json",
        )

        result = _show_gaps(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        # Only high severity gaps should be in results
        assert len(output["gaps"]) == 1
        assert output["gaps"][0]["severity"] == "HIGH"

    @patch("stance.storage.get_storage")
    def test_show_gaps_error_handling(self, mock_get_storage, capsys):
        """Test show gaps error handling."""
        from stance.cli_benchmark import _show_gaps

        mock_get_storage.side_effect = Exception("Storage error")

        args = argparse.Namespace(
            benchmark="cis-aws",
            severity=None,
            format="table",
        )

        result = _show_gaps(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out
