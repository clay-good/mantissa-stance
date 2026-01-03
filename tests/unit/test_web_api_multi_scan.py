"""
Unit tests for Multi-Account Scanning Web API endpoints.

Tests the REST API endpoints for multi-account scanning orchestration.
"""

import pytest
import json
from unittest.mock import MagicMock, patch


class MockStanceRequestHandler:
    """Mock handler for testing API endpoints."""

    storage = None

    def __init__(self):
        from stance.web.server import StanceRequestHandler
        self._handler_class = StanceRequestHandler

    def call_endpoint(self, method_name, params=None):
        """Call an endpoint method with optional params."""
        handler = self._handler_class.__new__(self._handler_class)
        handler.storage = self.storage
        method = getattr(handler, method_name)
        return method(params or {})


@pytest.fixture
def handler():
    """Create mock handler fixture."""
    return MockStanceRequestHandler()


class TestMultiScanScanAPI:
    """Tests for /api/multi-scan/scan endpoint."""

    def test_scan_default_params(self, handler):
        """Test scan with default parameters."""
        result = handler.call_endpoint("_multi_scan_scan", {})
        assert "action" in result
        assert "config" in result
        assert "options" in result

    def test_scan_with_config(self, handler):
        """Test scan with specific config."""
        result = handler.call_endpoint("_multi_scan_scan", {
            "config": ["production"],
            "parallel": ["5"],
            "timeout": ["600"],
        })
        assert result["config"] == "production"
        assert result["options"]["parallel_accounts"] == 5
        assert result["options"]["timeout_per_account"] == 600


class TestMultiScanProgressAPI:
    """Tests for /api/multi-scan/progress endpoint."""

    def test_progress_default_params(self, handler):
        """Test progress with default parameters."""
        result = handler.call_endpoint("_multi_scan_progress", {})
        assert "scan_id" in result
        assert "total_accounts" in result
        assert "completed_accounts" in result
        assert "progress_percent" in result

    def test_progress_with_scan_id(self, handler):
        """Test progress with specific scan ID."""
        result = handler.call_endpoint("_multi_scan_progress", {
            "scan_id": ["custom-scan-123"],
        })
        assert result["scan_id"] == "custom-scan-123"

    def test_progress_has_all_fields(self, handler):
        """Test progress has all required fields."""
        result = handler.call_endpoint("_multi_scan_progress", {})
        assert "pending_accounts" in result
        assert "failed_accounts" in result
        assert "current_accounts" in result
        assert "findings_so_far" in result
        assert "is_complete" in result


class TestMultiScanResultsAPI:
    """Tests for /api/multi-scan/results endpoint."""

    def test_results_default_params(self, handler):
        """Test results with default parameters."""
        result = handler.call_endpoint("_multi_scan_results", {})
        assert "scan_id" in result
        assert "summary" in result
        assert "findings_by_severity" in result

    def test_results_with_scan_id(self, handler):
        """Test results with specific scan ID."""
        result = handler.call_endpoint("_multi_scan_results", {
            "scan_id": ["my-scan"],
        })
        assert result["scan_id"] == "my-scan"

    def test_results_with_account_filter(self, handler):
        """Test results with account filter."""
        result = handler.call_endpoint("_multi_scan_results", {
            "account": ["123456789012"],
        })
        assert "filter" in result
        assert result["filter"]["account"] == "123456789012"


class TestMultiScanAccountsAPI:
    """Tests for /api/multi-scan/accounts endpoint."""

    def test_accounts_default_params(self, handler):
        """Test accounts with default parameters."""
        result = handler.call_endpoint("_multi_scan_accounts", {})
        assert "total" in result
        assert "accounts" in result
        # Should exclude disabled by default
        assert all(a["enabled"] for a in result["accounts"])

    def test_accounts_include_disabled(self, handler):
        """Test accounts with disabled included."""
        result = handler.call_endpoint("_multi_scan_accounts", {
            "include_disabled": ["true"],
        })
        # Should include disabled accounts
        assert any(not a["enabled"] for a in result["accounts"])

    def test_accounts_structure(self, handler):
        """Test account structure."""
        result = handler.call_endpoint("_multi_scan_accounts", {})
        for account in result["accounts"]:
            assert "account_id" in account
            assert "name" in account
            assert "provider" in account
            assert "enabled" in account
            assert "regions" in account


class TestMultiScanReportAPI:
    """Tests for /api/multi-scan/report endpoint."""

    def test_report_default_params(self, handler):
        """Test report with default parameters."""
        result = handler.call_endpoint("_multi_scan_report", {})
        assert "scan_id" in result
        assert "summary" in result
        assert "findings_by_severity" in result

    def test_report_with_scan_id(self, handler):
        """Test report with specific scan ID."""
        result = handler.call_endpoint("_multi_scan_report", {
            "scan_id": ["report-scan"],
        })
        assert result["scan_id"] == "report-scan"

    def test_report_has_all_sections(self, handler):
        """Test report has all sections."""
        result = handler.call_endpoint("_multi_scan_report", {})
        assert "findings_by_provider" in result
        assert "top_accounts_by_findings" in result
        assert "accounts_with_critical_findings" in result
        assert "failed_accounts" in result


class TestMultiScanAccountStatusesAPI:
    """Tests for /api/multi-scan/account-statuses endpoint."""

    def test_account_statuses_returns_all(self, handler):
        """Test that account-statuses returns all statuses."""
        result = handler.call_endpoint("_multi_scan_account_statuses", {})
        assert "total" in result
        assert "statuses" in result
        assert result["total"] == 5
        assert len(result["statuses"]) == 5

    def test_account_statuses_structure(self, handler):
        """Test account status structure."""
        result = handler.call_endpoint("_multi_scan_account_statuses", {})
        for status in result["statuses"]:
            assert "status" in status
            assert "description" in status
            assert "indicator" in status

    def test_account_statuses_contains_expected(self, handler):
        """Test that all expected statuses are present."""
        result = handler.call_endpoint("_multi_scan_account_statuses", {})
        status_names = [s["status"] for s in result["statuses"]]
        assert "pending" in status_names
        assert "running" in status_names
        assert "completed" in status_names
        assert "failed" in status_names
        assert "skipped" in status_names


class TestMultiScanOptionsAPI:
    """Tests for /api/multi-scan/options endpoint."""

    def test_options_returns_all(self, handler):
        """Test that options returns all options."""
        result = handler.call_endpoint("_multi_scan_options", {})
        assert "total" in result
        assert "options" in result
        assert result["total"] == 8
        assert len(result["options"]) == 8

    def test_options_structure(self, handler):
        """Test option structure."""
        result = handler.call_endpoint("_multi_scan_options", {})
        for opt in result["options"]:
            assert "option" in opt
            assert "type" in opt
            assert "default" in opt
            assert "description" in opt

    def test_options_contains_expected(self, handler):
        """Test that key options are present."""
        result = handler.call_endpoint("_multi_scan_options", {})
        option_names = [o["option"] for o in result["options"]]
        assert "parallel_accounts" in option_names
        assert "timeout_per_account" in option_names
        assert "continue_on_error" in option_names
        assert "severity_threshold" in option_names


class TestMultiScanProvidersAPI:
    """Tests for /api/multi-scan/providers endpoint."""

    def test_providers_returns_all(self, handler):
        """Test that providers returns all providers."""
        result = handler.call_endpoint("_multi_scan_providers", {})
        assert "total" in result
        assert "providers" in result
        assert result["total"] == 3
        assert len(result["providers"]) == 3

    def test_providers_structure(self, handler):
        """Test provider structure."""
        result = handler.call_endpoint("_multi_scan_providers", {})
        for provider in result["providers"]:
            assert "provider" in provider
            assert "name" in provider
            assert "account_format" in provider
            assert "collectors" in provider

    def test_providers_contains_expected(self, handler):
        """Test that all expected providers are present."""
        result = handler.call_endpoint("_multi_scan_providers", {})
        provider_names = [p["provider"] for p in result["providers"]]
        assert "aws" in provider_names
        assert "gcp" in provider_names
        assert "azure" in provider_names


class TestMultiScanStatsAPI:
    """Tests for /api/multi-scan/stats endpoint."""

    def test_stats_returns_correct_values(self, handler):
        """Test that stats returns correct values."""
        result = handler.call_endpoint("_multi_scan_stats", {})
        assert result["account_statuses"] == 5
        assert result["scan_options"] == 8
        assert result["cloud_providers"] == 3

    def test_stats_has_features(self, handler):
        """Test that stats includes features."""
        result = handler.call_endpoint("_multi_scan_stats", {})
        assert "features" in result
        assert result["features"]["parallel_execution"] is True
        assert result["features"]["progress_tracking"] is True

    def test_stats_has_default_settings(self, handler):
        """Test that stats includes default settings."""
        result = handler.call_endpoint("_multi_scan_stats", {})
        assert "default_settings" in result
        assert result["default_settings"]["parallel_accounts"] == 3
        assert result["default_settings"]["timeout_per_account"] == 300


class TestMultiScanStatusAPI:
    """Tests for /api/multi-scan/status endpoint."""

    def test_status_is_operational(self, handler):
        """Test that status reports operational."""
        result = handler.call_endpoint("_multi_scan_status", {})
        assert result["module"] == "scanning"
        assert result["status"] == "operational"

    def test_status_has_components(self, handler):
        """Test that status includes components."""
        result = handler.call_endpoint("_multi_scan_status", {})
        assert "components" in result
        assert "MultiAccountScanner" in result["components"]
        assert "ScanOptions" in result["components"]
        assert "ScanProgress" in result["components"]
        assert "AccountScanResult" in result["components"]
        assert "OrganizationScan" in result["components"]

    def test_status_has_capabilities(self, handler):
        """Test that status includes capabilities."""
        result = handler.call_endpoint("_multi_scan_status", {})
        assert "capabilities" in result
        assert "parallel_account_scanning" in result["capabilities"]
        assert "progress_tracking" in result["capabilities"]
        assert "cross_account_aggregation" in result["capabilities"]

    def test_status_has_integrations(self, handler):
        """Test that status includes integrations."""
        result = handler.call_endpoint("_multi_scan_status", {})
        assert "integrations" in result
        assert "aggregation" in result["integrations"]
        assert "config" in result["integrations"]


class TestMultiScanSummaryAPI:
    """Tests for /api/multi-scan/summary endpoint."""

    def test_summary_module_info(self, handler):
        """Test that summary includes module info."""
        result = handler.call_endpoint("_multi_scan_summary", {})
        assert result["module"] == "scanning"
        assert result["version"] == "1.0.0"
        assert "description" in result

    def test_summary_has_features(self, handler):
        """Test that summary includes features."""
        result = handler.call_endpoint("_multi_scan_summary", {})
        assert "features" in result
        assert len(result["features"]) >= 5

    def test_summary_has_workflow(self, handler):
        """Test that summary includes scan workflow."""
        result = handler.call_endpoint("_multi_scan_summary", {})
        assert "scan_workflow" in result
        assert len(result["scan_workflow"]) >= 5

    def test_summary_has_data_classes(self, handler):
        """Test that summary includes data classes."""
        result = handler.call_endpoint("_multi_scan_summary", {})
        assert "data_classes" in result
        assert "ScanOptions" in result["data_classes"]
        assert "AccountScanResult" in result["data_classes"]
        assert "ScanProgress" in result["data_classes"]
        assert "OrganizationScan" in result["data_classes"]

    def test_summary_has_cloud_support(self, handler):
        """Test that summary includes cloud support."""
        result = handler.call_endpoint("_multi_scan_summary", {})
        assert "cloud_support" in result
        assert "aws" in result["cloud_support"]
        assert "gcp" in result["cloud_support"]
        assert "azure" in result["cloud_support"]


class TestAPIParameterParsing:
    """Tests for API parameter parsing."""

    def test_scan_parses_list_params(self, handler):
        """Test that scan parses list-format parameters."""
        result = handler.call_endpoint("_multi_scan_scan", {
            "config": ["my-config"],
            "parallel": ["10"],
            "timeout": ["120"],
        })
        assert isinstance(result, dict)
        assert result["config"] == "my-config"

    def test_accounts_parses_include_disabled(self, handler):
        """Test that accounts parses include_disabled correctly."""
        result = handler.call_endpoint("_multi_scan_accounts", {
            "include_disabled": ["true"],
        })
        assert len(result["accounts"]) == 4  # All accounts


class TestAPIResponseFormat:
    """Tests for API response format consistency."""

    def test_all_info_endpoints_return_dict(self, handler):
        """Test that all info endpoints return dictionaries."""
        endpoints = [
            "_multi_scan_account_statuses",
            "_multi_scan_options",
            "_multi_scan_providers",
            "_multi_scan_stats",
            "_multi_scan_status",
            "_multi_scan_summary",
        ]
        for endpoint in endpoints:
            result = handler.call_endpoint(endpoint, {})
            assert isinstance(result, dict), f"{endpoint} should return dict"

    def test_all_data_endpoints_return_dict(self, handler):
        """Test that all data endpoints return dictionaries."""
        endpoints = [
            ("_multi_scan_scan", {}),
            ("_multi_scan_progress", {}),
            ("_multi_scan_results", {}),
            ("_multi_scan_accounts", {}),
            ("_multi_scan_report", {}),
        ]
        for endpoint, params in endpoints:
            result = handler.call_endpoint(endpoint, params)
            assert isinstance(result, dict), f"{endpoint} should return dict"


class TestAPIIntegration:
    """Integration tests for API endpoints."""

    def test_stats_counts_match_endpoints(self, handler):
        """Test that stats counts match actual endpoint data."""
        stats = handler.call_endpoint("_multi_scan_stats", {})
        statuses = handler.call_endpoint("_multi_scan_account_statuses", {})
        options = handler.call_endpoint("_multi_scan_options", {})
        providers = handler.call_endpoint("_multi_scan_providers", {})

        assert stats["account_statuses"] == statuses["total"]
        assert stats["scan_options"] == options["total"]
        assert stats["cloud_providers"] == providers["total"]

    def test_status_capabilities_are_valid(self, handler):
        """Test that status capabilities are valid."""
        result = handler.call_endpoint("_multi_scan_status", {})
        expected_capabilities = [
            "parallel_account_scanning",
            "progress_tracking",
            "timeout_handling",
            "error_recovery",
            "cross_account_aggregation",
        ]
        for cap in expected_capabilities:
            assert cap in result["capabilities"]

    def test_summary_features_non_empty(self, handler):
        """Test that summary features list is non-empty."""
        result = handler.call_endpoint("_multi_scan_summary", {})
        assert len(result["features"]) >= 5

    def test_progress_percentage_valid(self, handler):
        """Test that progress percentage is valid."""
        result = handler.call_endpoint("_multi_scan_progress", {})
        assert 0 <= result["progress_percent"] <= 100


class TestCloudProviderSupport:
    """Tests for cloud provider support."""

    def test_aws_provider_info(self, handler):
        """Test AWS provider info."""
        result = handler.call_endpoint("_multi_scan_providers", {})
        aws = next(p for p in result["providers"] if p["provider"] == "aws")
        assert aws["name"] == "Amazon Web Services"
        assert "iam" in aws["collectors"]
        assert "s3" in aws["collectors"]

    def test_gcp_provider_info(self, handler):
        """Test GCP provider info."""
        result = handler.call_endpoint("_multi_scan_providers", {})
        gcp = next(p for p in result["providers"] if p["provider"] == "gcp")
        assert gcp["name"] == "Google Cloud Platform"
        assert "iam" in gcp["collectors"]

    def test_azure_provider_info(self, handler):
        """Test Azure provider info."""
        result = handler.call_endpoint("_multi_scan_providers", {})
        azure = next(p for p in result["providers"] if p["provider"] == "azure")
        assert azure["name"] == "Microsoft Azure"
        assert "identity" in azure["collectors"]


class TestReportContent:
    """Tests for report content."""

    def test_report_summary_complete(self, handler):
        """Test that report summary is complete."""
        result = handler.call_endpoint("_multi_scan_report", {})
        summary = result["summary"]
        assert "accounts_scanned" in summary
        assert "accounts_successful" in summary
        assert "accounts_failed" in summary
        assert "total_findings" in summary
        assert "unique_findings" in summary

    def test_report_has_severity_breakdown(self, handler):
        """Test that report has severity breakdown."""
        result = handler.call_endpoint("_multi_scan_report", {})
        severities = result["findings_by_severity"]
        assert "critical" in severities
        assert "high" in severities
        assert "medium" in severities
        assert "low" in severities

    def test_report_has_provider_breakdown(self, handler):
        """Test that report has provider breakdown."""
        result = handler.call_endpoint("_multi_scan_report", {})
        providers = result["findings_by_provider"]
        assert "aws" in providers
        assert "gcp" in providers
        assert "azure" in providers
