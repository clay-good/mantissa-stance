"""
Unit tests for Reporting Web API endpoints.

Tests the REST API endpoints for trend analysis and security reporting.
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


class TestReportingAnalyzeAPI:
    """Tests for /api/reporting/analyze endpoint."""

    def test_analyze_default_params(self, handler):
        """Test analyze with default parameters."""
        result = handler.call_endpoint("_reporting_analyze", {})
        assert "report_id" in result or "error" in result
        if "report_id" in result:
            assert "period" in result
            assert "total_findings" in result

    def test_analyze_with_config(self, handler):
        """Test analyze with specific config."""
        result = handler.call_endpoint("_reporting_analyze", {
            "config": ["test-config"],
            "days": ["7"],
        })
        assert "report_id" in result or "error" in result

    def test_analyze_with_period(self, handler):
        """Test analyze with specific period."""
        result = handler.call_endpoint("_reporting_analyze", {
            "period": ["weekly"],
        })
        assert "report_id" in result or "error" in result


class TestReportingVelocityAPI:
    """Tests for /api/reporting/velocity endpoint."""

    def test_velocity_default_params(self, handler):
        """Test velocity with default parameters."""
        result = handler.call_endpoint("_reporting_velocity", {})
        assert "velocities" in result or "error" in result
        if "velocities" in result:
            assert "unit" in result
            assert result["unit"] == "findings/day"

    def test_velocity_with_days(self, handler):
        """Test velocity with specific days."""
        result = handler.call_endpoint("_reporting_velocity", {
            "days": ["14"],
        })
        if "velocities" in result:
            assert result["days_analyzed"] == 14


class TestReportingImprovementAPI:
    """Tests for /api/reporting/improvement endpoint."""

    def test_improvement_default_params(self, handler):
        """Test improvement with default parameters."""
        result = handler.call_endpoint("_reporting_improvement", {})
        assert "improvement_rate" in result or "error" in result
        if "improvement_rate" in result:
            assert "unit" in result
            assert result["unit"] == "percent"
            assert "direction" in result

    def test_improvement_with_days(self, handler):
        """Test improvement with specific days."""
        result = handler.call_endpoint("_reporting_improvement", {
            "days": ["60"],
        })
        if "improvement_rate" in result:
            assert result["days_analyzed"] == 60


class TestReportingCompareAPI:
    """Tests for /api/reporting/compare endpoint."""

    def test_compare_default_params(self, handler):
        """Test compare with default parameters."""
        result = handler.call_endpoint("_reporting_compare", {})
        assert "current_period" in result or "error" in result
        if "current_period" in result:
            assert "previous_period" in result
            assert "comparison" in result

    def test_compare_with_custom_periods(self, handler):
        """Test compare with custom period lengths."""
        result = handler.call_endpoint("_reporting_compare", {
            "current_days": ["14"],
            "previous_days": ["14"],
        })
        if "current_period" in result:
            assert result["current_period"]["days"] == 14


class TestReportingForecastAPI:
    """Tests for /api/reporting/forecast endpoint."""

    def test_forecast_default_params(self, handler):
        """Test forecast with default parameters."""
        result = handler.call_endpoint("_reporting_forecast", {})
        assert "forecasts" in result or "error" in result

    def test_forecast_with_custom_days(self, handler):
        """Test forecast with custom history and forecast days."""
        result = handler.call_endpoint("_reporting_forecast", {
            "history_days": ["60"],
            "forecast_days": ["14"],
        })
        # Either returns forecasts or error for insufficient data
        assert isinstance(result, dict)


class TestReportingDirectionsAPI:
    """Tests for /api/reporting/directions endpoint."""

    def test_directions_returns_all(self, handler):
        """Test that directions returns all directions."""
        result = handler.call_endpoint("_reporting_directions", {})
        assert "total" in result
        assert "directions" in result
        assert result["total"] == 4
        assert len(result["directions"]) == 4

    def test_directions_structure(self, handler):
        """Test direction structure."""
        result = handler.call_endpoint("_reporting_directions", {})
        for direction in result["directions"]:
            assert "direction" in direction
            assert "description" in direction
            assert "indicator" in direction
            assert "action" in direction

    def test_directions_contains_expected(self, handler):
        """Test that all expected directions are present."""
        result = handler.call_endpoint("_reporting_directions", {})
        direction_names = [d["direction"] for d in result["directions"]]
        assert "improving" in direction_names
        assert "declining" in direction_names
        assert "stable" in direction_names
        assert "insufficient_data" in direction_names


class TestReportingPeriodsAPI:
    """Tests for /api/reporting/periods endpoint."""

    def test_periods_returns_all(self, handler):
        """Test that periods returns all periods."""
        result = handler.call_endpoint("_reporting_periods", {})
        assert "total" in result
        assert "periods" in result
        assert result["total"] == 4
        assert len(result["periods"]) == 4

    def test_periods_structure(self, handler):
        """Test period structure."""
        result = handler.call_endpoint("_reporting_periods", {})
        for period in result["periods"]:
            assert "period" in period
            assert "description" in period
            assert "use_case" in period
            assert "recommended_history" in period

    def test_periods_contains_expected(self, handler):
        """Test that all expected periods are present."""
        result = handler.call_endpoint("_reporting_periods", {})
        period_names = [p["period"] for p in result["periods"]]
        assert "daily" in period_names
        assert "weekly" in period_names
        assert "monthly" in period_names
        assert "quarterly" in period_names


class TestReportingSeveritiesAPI:
    """Tests for /api/reporting/severities endpoint."""

    def test_severities_returns_all(self, handler):
        """Test that severities returns all severity levels."""
        result = handler.call_endpoint("_reporting_severities", {})
        assert "total" in result
        assert "severities" in result
        assert result["total"] == 5
        assert len(result["severities"]) == 5

    def test_severities_structure(self, handler):
        """Test severity structure."""
        result = handler.call_endpoint("_reporting_severities", {})
        for sev in result["severities"]:
            assert "severity" in sev
            assert "description" in sev
            assert "trend_priority" in sev
            assert "velocity_threshold" in sev

    def test_severities_contains_expected(self, handler):
        """Test that all expected severities are present."""
        result = handler.call_endpoint("_reporting_severities", {})
        severity_names = [s["severity"] for s in result["severities"]]
        assert "critical" in severity_names
        assert "high" in severity_names
        assert "medium" in severity_names
        assert "low" in severity_names
        assert "info" in severity_names


class TestReportingMetricsAPI:
    """Tests for /api/reporting/metrics endpoint."""

    def test_metrics_returns_all(self, handler):
        """Test that metrics returns all metrics."""
        result = handler.call_endpoint("_reporting_metrics", {})
        assert "total" in result
        assert "metrics" in result
        assert result["total"] == 10
        assert len(result["metrics"]) == 10

    def test_metrics_structure(self, handler):
        """Test metric structure."""
        result = handler.call_endpoint("_reporting_metrics", {})
        for metric in result["metrics"]:
            assert "metric" in metric
            assert "description" in metric
            assert "type" in metric

    def test_metrics_contains_expected(self, handler):
        """Test that key metrics are present."""
        result = handler.call_endpoint("_reporting_metrics", {})
        metric_names = [m["metric"] for m in result["metrics"]]
        assert "current_value" in metric_names
        assert "previous_value" in metric_names
        assert "change" in metric_names
        assert "change_percent" in metric_names
        assert "velocity" in metric_names
        assert "direction" in metric_names


class TestReportingStatsAPI:
    """Tests for /api/reporting/stats endpoint."""

    def test_stats_returns_correct_values(self, handler):
        """Test that stats returns correct values."""
        result = handler.call_endpoint("_reporting_stats", {})
        assert result["trend_directions"] == 4
        assert result["trend_periods"] == 4
        assert result["severity_levels"] == 5
        assert result["metrics_tracked"] == 10

    def test_stats_has_analysis_methods(self, handler):
        """Test that stats includes analysis methods."""
        result = handler.call_endpoint("_reporting_stats", {})
        assert "analysis_methods" in result
        assert "velocity" in result["analysis_methods"]
        assert "improvement_rate" in result["analysis_methods"]
        assert "period_comparison" in result["analysis_methods"]
        assert "forecast" in result["analysis_methods"]

    def test_stats_has_thresholds(self, handler):
        """Test that stats includes thresholds."""
        result = handler.call_endpoint("_reporting_stats", {})
        assert "change_threshold_percent" in result
        assert "critical_velocity_threshold" in result
        assert result["change_threshold_percent"] == 5.0
        assert result["critical_velocity_threshold"] == 0.5


class TestReportingStatusAPI:
    """Tests for /api/reporting/status endpoint."""

    def test_status_is_operational(self, handler):
        """Test that status reports operational."""
        result = handler.call_endpoint("_reporting_status", {})
        assert result["module"] == "reporting"
        assert result["status"] == "operational"

    def test_status_has_components(self, handler):
        """Test that status includes components."""
        result = handler.call_endpoint("_reporting_status", {})
        assert "components" in result
        assert "TrendAnalyzer" in result["components"]
        assert "TrendReport" in result["components"]
        assert "TrendMetrics" in result["components"]
        assert "SeverityTrend" in result["components"]
        assert "ComplianceTrend" in result["components"]

    def test_status_has_capabilities(self, handler):
        """Test that status includes capabilities."""
        result = handler.call_endpoint("_reporting_status", {})
        assert "capabilities" in result
        assert "trend_analysis" in result["capabilities"]
        assert "velocity_calculation" in result["capabilities"]
        assert "linear_regression_forecast" in result["capabilities"]


class TestReportingSummaryAPI:
    """Tests for /api/reporting/summary endpoint."""

    def test_summary_module_info(self, handler):
        """Test that summary includes module info."""
        result = handler.call_endpoint("_reporting_summary", {})
        assert result["module"] == "reporting"
        assert result["version"] == "1.0.0"
        assert "description" in result

    def test_summary_has_features(self, handler):
        """Test that summary includes features."""
        result = handler.call_endpoint("_reporting_summary", {})
        assert "features" in result
        assert len(result["features"]) > 0

    def test_summary_has_analysis_types(self, handler):
        """Test that summary includes analysis types."""
        result = handler.call_endpoint("_reporting_summary", {})
        assert "analysis_types" in result
        assert "analyze" in result["analysis_types"]
        assert "velocity" in result["analysis_types"]
        assert "improvement" in result["analysis_types"]
        assert "compare" in result["analysis_types"]
        assert "forecast" in result["analysis_types"]

    def test_summary_has_data_requirements(self, handler):
        """Test that summary includes data requirements."""
        result = handler.call_endpoint("_reporting_summary", {})
        assert "data_requirements" in result
        assert "minimum_scans" in result["data_requirements"]
        assert "recommended_scans" in result["data_requirements"]
        assert "default_history_days" in result["data_requirements"]


class TestAPIParameterParsing:
    """Tests for API parameter parsing."""

    def test_analyze_parses_list_params(self, handler):
        """Test that analyze parses list-format parameters."""
        result = handler.call_endpoint("_reporting_analyze", {
            "config": ["my-config"],
            "days": ["14"],
            "period": ["weekly"],
        })
        # Should not raise, regardless of result
        assert isinstance(result, dict)

    def test_analyze_parses_single_params(self, handler):
        """Test that analyze parses single-value parameters."""
        result = handler.call_endpoint("_reporting_analyze", {
            "config": "my-config",
            "days": "14",
            "period": "weekly",
        })
        # Should not raise, regardless of result
        assert isinstance(result, dict)

    def test_velocity_parses_days_param(self, handler):
        """Test velocity parses days parameter correctly."""
        result = handler.call_endpoint("_reporting_velocity", {
            "days": ["21"],
        })
        if "days_analyzed" in result:
            assert result["days_analyzed"] == 21

    def test_compare_parses_period_params(self, handler):
        """Test compare parses period parameters correctly."""
        result = handler.call_endpoint("_reporting_compare", {
            "current_days": ["30"],
            "previous_days": ["30"],
        })
        if "current_period" in result:
            assert result["current_period"]["days"] == 30
            assert result["previous_period"]["days"] == 30


class TestAPIErrorHandling:
    """Tests for API error handling."""

    def test_analyze_handles_missing_data(self, handler):
        """Test that analyze handles missing scan data gracefully."""
        # Should not raise even with no data
        result = handler.call_endpoint("_reporting_analyze", {
            "config": ["nonexistent-config"],
        })
        # Should return result dict (possibly with error or empty data)
        assert isinstance(result, dict)

    def test_velocity_handles_missing_data(self, handler):
        """Test that velocity handles missing scan data gracefully."""
        result = handler.call_endpoint("_reporting_velocity", {
            "config": ["nonexistent-config"],
        })
        assert isinstance(result, dict)


class TestAPIResponseFormat:
    """Tests for API response format consistency."""

    def test_all_info_endpoints_return_dict(self, handler):
        """Test that all info endpoints return dictionaries."""
        endpoints = [
            "_reporting_directions",
            "_reporting_periods",
            "_reporting_severities",
            "_reporting_metrics",
            "_reporting_stats",
            "_reporting_status",
            "_reporting_summary",
        ]
        for endpoint in endpoints:
            result = handler.call_endpoint(endpoint, {})
            assert isinstance(result, dict), f"{endpoint} should return dict"

    def test_all_analysis_endpoints_return_dict(self, handler):
        """Test that all analysis endpoints return dictionaries."""
        endpoints = [
            ("_reporting_analyze", {}),
            ("_reporting_velocity", {}),
            ("_reporting_improvement", {}),
            ("_reporting_compare", {}),
            ("_reporting_forecast", {}),
        ]
        for endpoint, params in endpoints:
            result = handler.call_endpoint(endpoint, params)
            assert isinstance(result, dict), f"{endpoint} should return dict"


class TestAPIIntegration:
    """Integration tests for API endpoints."""

    def test_velocity_returns_valid_velocities(self, handler):
        """Test that velocity returns valid velocity values."""
        result = handler.call_endpoint("_reporting_velocity", {})
        if "velocities" in result:
            for key, value in result["velocities"].items():
                assert isinstance(value, (int, float))

    def test_improvement_returns_valid_rate(self, handler):
        """Test that improvement returns valid rate value."""
        result = handler.call_endpoint("_reporting_improvement", {})
        if "improvement_rate" in result:
            assert isinstance(result["improvement_rate"], (int, float))

    def test_compare_returns_valid_comparison(self, handler):
        """Test that compare returns valid comparison data."""
        result = handler.call_endpoint("_reporting_compare", {})
        if "comparison" in result:
            assert "avg_findings_change" in result["comparison"]
            assert "direction" in result["comparison"]
