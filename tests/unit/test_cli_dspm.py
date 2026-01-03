"""
Unit tests for the DSPM CLI commands.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_dspm import (
    cmd_dspm,
    _cmd_dspm_scan,
    _cmd_dspm_access,
    _cmd_dspm_cost,
    _cmd_dspm_classify,
)


class TestCmdDspm:
    """Tests for cmd_dspm routing function."""

    def test_no_action_shows_help(self, capsys):
        """Test that no action shows help text."""
        args = argparse.Namespace(dspm_action=None)

        result = cmd_dspm(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Usage: stance dspm" in captured.out
        assert "scan" in captured.out
        assert "access" in captured.out
        assert "cost" in captured.out
        assert "classify" in captured.out

    def test_unknown_action_fails(self, capsys):
        """Test that unknown action returns error."""
        args = argparse.Namespace(dspm_action="unknown")

        result = cmd_dspm(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown" in captured.out

    def test_routes_to_scan(self):
        """Test routing to scan command."""
        with patch("stance.cli_dspm._cmd_dspm_scan") as mock_scan:
            mock_scan.return_value = 0
            args = argparse.Namespace(dspm_action="scan")

            result = cmd_dspm(args)

            mock_scan.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_access(self):
        """Test routing to access command."""
        with patch("stance.cli_dspm._cmd_dspm_access") as mock_access:
            mock_access.return_value = 0
            args = argparse.Namespace(dspm_action="access")

            result = cmd_dspm(args)

            mock_access.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_cost(self):
        """Test routing to cost command."""
        with patch("stance.cli_dspm._cmd_dspm_cost") as mock_cost:
            mock_cost.return_value = 0
            args = argparse.Namespace(dspm_action="cost")

            result = cmd_dspm(args)

            mock_cost.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_classify(self):
        """Test routing to classify command."""
        with patch("stance.cli_dspm._cmd_dspm_classify") as mock_classify:
            mock_classify.return_value = 0
            args = argparse.Namespace(dspm_action="classify")

            result = cmd_dspm(args)

            mock_classify.assert_called_once_with(args)
            assert result == 0


class TestCmdDspmScan:
    """Tests for _cmd_dspm_scan function."""

    def test_scan_aws_table_output(self, capsys):
        """Test scanning AWS bucket with table output."""
        with patch("stance.cli_dspm.S3DataScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "my-bucket"
            mock_result.cloud_provider = "aws"
            mock_result.started_at = datetime.now(timezone.utc)
            mock_result.completed_at = datetime.now(timezone.utc)
            mock_result.summary = MagicMock()
            mock_result.summary.total_objects = 100
            mock_result.summary.objects_scanned = 50
            mock_result.summary.findings_count = 3
            mock_result.findings = []
            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            args = argparse.Namespace(
                target="my-bucket",
                cloud="aws",
                format="table",
                sample_size=100,
                max_file_size=10485760,
                include=None,
                exclude=None,
            )

            result = _cmd_dspm_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "my-bucket" in captured.out
            assert "aws" in captured.out

    def test_scan_gcp_json_output(self, capsys):
        """Test scanning GCP bucket with JSON output."""
        with patch("stance.cli_dspm.GCSDataScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "gcs-bucket"
            mock_result.cloud_provider = "gcp"
            mock_result.started_at = datetime.now(timezone.utc)
            mock_result.completed_at = datetime.now(timezone.utc)
            mock_result.summary = MagicMock()
            mock_result.summary.total_objects = 200
            mock_result.summary.objects_scanned = 100
            mock_result.summary.findings_count = 5
            mock_result.findings = []
            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            args = argparse.Namespace(
                target="gcs-bucket",
                cloud="gcp",
                format="json",
                sample_size=100,
                max_file_size=10485760,
                include=None,
                exclude=None,
            )

            result = _cmd_dspm_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["target"] == "gcs-bucket"
            assert data["cloud"] == "gcp"

    def test_scan_azure(self, capsys):
        """Test scanning Azure container."""
        with patch("stance.cli_dspm.AzureBlobDataScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "azure-container"
            mock_result.cloud_provider = "azure"
            mock_result.started_at = None
            mock_result.completed_at = None
            mock_result.summary = None
            mock_result.findings = []
            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            args = argparse.Namespace(
                target="azure-container",
                cloud="azure",
                format="table",
                sample_size=50,
                max_file_size=5242880,
                include="*.csv",
                exclude="*.log",
            )

            result = _cmd_dspm_scan(args)

            assert result == 0

    def test_scan_unknown_cloud_fails(self, capsys):
        """Test scanning with unknown cloud provider fails."""
        args = argparse.Namespace(
            target="bucket",
            cloud="unknown",
            format="table",
            sample_size=100,
            max_file_size=10485760,
            include=None,
            exclude=None,
        )

        result = _cmd_dspm_scan(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown cloud provider" in captured.out

    def test_scan_with_findings(self, capsys):
        """Test scanning with sensitive data findings."""
        with patch("stance.cli_dspm.S3DataScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "my-bucket"
            mock_result.cloud_provider = "aws"
            mock_result.started_at = datetime.now(timezone.utc)
            mock_result.completed_at = datetime.now(timezone.utc)
            mock_result.summary = MagicMock()
            mock_result.summary.total_objects = 100
            mock_result.summary.objects_scanned = 50
            mock_result.summary.findings_count = 2

            mock_finding1 = MagicMock()
            mock_finding1.object_key = "data/customers.csv"
            mock_finding1.classification = MagicMock()
            mock_finding1.classification.name = "CONFIDENTIAL"
            mock_finding1.severity = MagicMock()
            mock_finding1.severity.value = "high"
            mock_finding1.categories = []
            mock_finding1.patterns_matched = ["SSN", "EMAIL"]

            mock_finding2 = MagicMock()
            mock_finding2.object_key = "logs/access.log"
            mock_finding2.classification = MagicMock()
            mock_finding2.classification.name = "INTERNAL"
            mock_finding2.severity = MagicMock()
            mock_finding2.severity.value = "medium"
            mock_finding2.categories = []
            mock_finding2.patterns_matched = ["IP_ADDRESS"]

            mock_result.findings = [mock_finding1, mock_finding2]
            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            args = argparse.Namespace(
                target="my-bucket",
                cloud="aws",
                format="table",
                sample_size=100,
                max_file_size=10485760,
                include=None,
                exclude=None,
            )

            result = _cmd_dspm_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Sensitive Data Findings" in captured.out
            assert "customers.csv" in captured.out

    def test_scan_handles_exception(self, capsys):
        """Test scan handles exceptions gracefully."""
        with patch("stance.cli_dspm.S3DataScanner") as mock_scanner_class:
            mock_scanner_class.side_effect = Exception("Connection failed")

            args = argparse.Namespace(
                target="my-bucket",
                cloud="aws",
                format="table",
                sample_size=100,
                max_file_size=10485760,
                include=None,
                exclude=None,
            )

            result = _cmd_dspm_scan(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Error" in captured.out


class TestCmdDspmAccess:
    """Tests for _cmd_dspm_access function."""

    def test_access_aws_table_output(self, capsys):
        """Test access analysis for AWS with table output."""
        with patch("stance.cli_dspm.CloudTrailAccessAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "my-bucket"
            mock_result.cloud_provider = "aws"
            mock_result.analysis_period_days = 180
            mock_result.summary = MagicMock()
            mock_result.summary.total_principals = 50
            mock_result.summary.stale_access_count = 10
            mock_result.summary.over_privileged_count = 5
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                target="my-bucket",
                cloud="aws",
                format="table",
                stale_days=90,
                lookback_days=180,
            )

            result = _cmd_dspm_access(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "my-bucket" in captured.out

    def test_access_gcp_json_output(self, capsys):
        """Test access analysis for GCP with JSON output."""
        with patch("stance.cli_dspm.GCPAuditLogAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "gcs-bucket"
            mock_result.cloud_provider = "gcp"
            mock_result.analysis_period_days = 90
            mock_result.summary = MagicMock()
            mock_result.summary.total_principals = 30
            mock_result.summary.stale_access_count = 5
            mock_result.summary.over_privileged_count = 2
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                target="gcs-bucket",
                cloud="gcp",
                format="json",
                stale_days=90,
                lookback_days=90,
            )

            result = _cmd_dspm_access(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["target"] == "gcs-bucket"
            assert data["cloud"] == "gcp"

    def test_access_unknown_cloud_fails(self, capsys):
        """Test access with unknown cloud provider fails."""
        args = argparse.Namespace(
            target="bucket",
            cloud="unknown",
            format="table",
            stale_days=90,
            lookback_days=180,
        )

        result = _cmd_dspm_access(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown cloud provider" in captured.out


class TestCmdDspmCost:
    """Tests for _cmd_dspm_cost function."""

    def test_cost_aws_table_output(self, capsys):
        """Test cost analysis for AWS with table output."""
        with patch("stance.cli_dspm.S3CostAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "my-bucket"
            mock_result.cloud_provider = "aws"
            mock_result.metrics = MagicMock()
            mock_result.metrics.total_size_bytes = 10 * 1024 * 1024 * 1024  # 10 GB
            mock_result.metrics.object_count = 1000
            mock_result.metrics.estimated_monthly_cost = 25.50
            mock_result.potential_monthly_savings = 10.25
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                target="my-bucket",
                cloud="aws",
                format="table",
                cold_days=90,
                archive_days=180,
                delete_days=365,
            )

            result = _cmd_dspm_cost(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "my-bucket" in captured.out
            assert "$" in captured.out

    def test_cost_json_output(self, capsys):
        """Test cost analysis with JSON output."""
        with patch("stance.cli_dspm.S3CostAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "my-bucket"
            mock_result.cloud_provider = "aws"
            mock_result.metrics = MagicMock()
            mock_result.metrics.total_size_bytes = 5 * 1024 * 1024 * 1024
            mock_result.metrics.object_count = 500
            mock_result.metrics.estimated_monthly_cost = 12.50
            mock_result.potential_monthly_savings = 5.00
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                target="my-bucket",
                cloud="aws",
                format="json",
                cold_days=90,
                archive_days=180,
                delete_days=365,
            )

            result = _cmd_dspm_cost(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "potential_savings" in data
            assert "metrics" in data


class TestCmdDspmClassify:
    """Tests for _cmd_dspm_classify function."""

    def test_classify_text_table_output(self, capsys):
        """Test classification with text input."""
        with patch("stance.cli_dspm.DataClassifier") as mock_classifier_class, \
             patch("stance.cli_dspm.SensitiveDataDetector") as mock_detector_class:

            mock_classifier = MagicMock()
            mock_classification = MagicMock()
            mock_classification.level = MagicMock()
            mock_classification.level.value = "CONFIDENTIAL"
            mock_classification.categories = []
            mock_classification.confidence = 0.95
            mock_classifier.classify.return_value = mock_classification
            mock_classifier_class.return_value = mock_classifier

            mock_detector = MagicMock()
            mock_detection = MagicMock()
            mock_detection.matches = []
            mock_detector.detect.return_value = mock_detection
            mock_detector_class.return_value = mock_detector

            args = argparse.Namespace(
                text="SSN: 123-45-6789",
                file=None,
                format="table",
            )

            result = _cmd_dspm_classify(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Classification" in captured.out

    def test_classify_no_text_or_file_fails(self, capsys):
        """Test classification without text or file fails."""
        with patch("stance.cli_dspm.DataClassifier") as mock_classifier_class, \
             patch("stance.cli_dspm.SensitiveDataDetector") as mock_detector_class:

            args = argparse.Namespace(
                text=None,
                file=None,
                format="table",
            )

            result = _cmd_dspm_classify(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "No text provided" in captured.out

    def test_classify_json_output(self, capsys):
        """Test classification with JSON output."""
        with patch("stance.cli_dspm.DataClassifier") as mock_classifier_class, \
             patch("stance.cli_dspm.SensitiveDataDetector") as mock_detector_class:

            mock_classifier = MagicMock()
            mock_classification = MagicMock()
            mock_classification.level = MagicMock()
            mock_classification.level.value = "INTERNAL"
            mock_classification.categories = []
            mock_classification.confidence = 0.85
            mock_classifier.classify.return_value = mock_classification
            mock_classifier_class.return_value = mock_classifier

            mock_detector = MagicMock()
            mock_detection = MagicMock()
            mock_detection.matches = []
            mock_detector.detect.return_value = mock_detection
            mock_detector_class.return_value = mock_detector

            args = argparse.Namespace(
                text="Test data",
                file=None,
                format="json",
            )

            result = _cmd_dspm_classify(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "classification" in data
            assert "patterns_detected" in data
