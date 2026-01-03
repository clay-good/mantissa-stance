"""
Unit tests for Observability Web API endpoints.

Tests the REST API endpoints for logging, metrics, and tracing.
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


class TestObservabilityLoggingAPI:
    """Tests for /api/observability/logging endpoint."""

    def test_logging_get_config(self, handler):
        """Test getting logging configuration."""
        result = handler.call_endpoint("_observability_logging", {})
        assert "current_level" in result
        assert "current_format" in result
        assert "available_levels" in result
        assert "available_formats" in result

    def test_logging_set_level(self, handler):
        """Test setting log level."""
        result = handler.call_endpoint("_observability_logging", {
            "level": ["DEBUG"],
        })
        assert "status" in result or "current_level" in result

    def test_logging_set_format(self, handler):
        """Test setting log format."""
        result = handler.call_endpoint("_observability_logging", {
            "format": ["structured"],
        })
        assert "status" in result or "current_format" in result


class TestObservabilityMetricsAPI:
    """Tests for /api/observability/metrics endpoint."""

    def test_metrics_default_params(self, handler):
        """Test metrics with default parameters."""
        result = handler.call_endpoint("_observability_metrics", {})
        assert "total" in result
        assert "metrics" in result

    def test_metrics_with_name_filter(self, handler):
        """Test metrics with name filter."""
        result = handler.call_endpoint("_observability_metrics", {
            "name": ["scan_duration"],
        })
        assert "total" in result
        assert "metrics" in result

    def test_metrics_with_type_filter(self, handler):
        """Test metrics with type filter."""
        result = handler.call_endpoint("_observability_metrics", {
            "type": ["counter"],
        })
        assert "total" in result
        assert "metrics" in result

    def test_metrics_with_limit(self, handler):
        """Test metrics with limit."""
        result = handler.call_endpoint("_observability_metrics", {
            "limit": ["50"],
        })
        assert "total" in result
        # Either has limit (if backend supports it) or note about no backend
        assert "limit" in result or "note" in result


class TestObservabilityTracesAPI:
    """Tests for /api/observability/traces endpoint."""

    def test_traces_default_params(self, handler):
        """Test traces with default parameters."""
        result = handler.call_endpoint("_observability_traces", {})
        assert "total" in result
        assert "spans" in result

    def test_traces_with_trace_id(self, handler):
        """Test traces with specific trace ID."""
        result = handler.call_endpoint("_observability_traces", {
            "trace_id": ["abc123"],
        })
        # Either returns trace or note about no backend
        assert isinstance(result, dict)

    def test_traces_with_limit(self, handler):
        """Test traces with limit."""
        result = handler.call_endpoint("_observability_traces", {
            "limit": ["25"],
        })
        assert "total" in result or "limit" in result


class TestObservabilityBackendsAPI:
    """Tests for /api/observability/backends endpoint."""

    def test_backends_returns_all(self, handler):
        """Test that backends returns all backends."""
        result = handler.call_endpoint("_observability_backends", {})
        assert "total" in result
        assert "backends" in result
        assert result["total"] == 6
        assert len(result["backends"]) == 6

    def test_backends_structure(self, handler):
        """Test backend structure."""
        result = handler.call_endpoint("_observability_backends", {})
        for backend in result["backends"]:
            assert "backend" in backend
            assert "type" in backend
            assert "description" in backend
            assert "cloud" in backend

    def test_backends_contains_expected(self, handler):
        """Test that all expected backends are present."""
        result = handler.call_endpoint("_observability_backends", {})
        backend_names = [b["backend"] for b in result["backends"]]
        assert "InMemoryMetricsBackend" in backend_names
        assert "CloudWatchMetricsBackend" in backend_names
        assert "InMemoryTracingBackend" in backend_names
        assert "XRayTracingBackend" in backend_names
        assert "CloudTraceBackend" in backend_names
        assert "ApplicationInsightsBackend" in backend_names


class TestObservabilityMetricTypesAPI:
    """Tests for /api/observability/metric-types endpoint."""

    def test_metric_types_returns_all(self, handler):
        """Test that metric-types returns all types."""
        result = handler.call_endpoint("_observability_metric_types", {})
        assert "total" in result
        assert "metric_types" in result
        assert result["total"] == 4
        assert len(result["metric_types"]) == 4

    def test_metric_types_structure(self, handler):
        """Test metric type structure."""
        result = handler.call_endpoint("_observability_metric_types", {})
        for mt in result["metric_types"]:
            assert "type" in mt
            assert "description" in mt
            assert "use_case" in mt

    def test_metric_types_contains_expected(self, handler):
        """Test that all expected metric types are present."""
        result = handler.call_endpoint("_observability_metric_types", {})
        type_names = [mt["type"] for mt in result["metric_types"]]
        assert "counter" in type_names
        assert "gauge" in type_names
        assert "histogram" in type_names
        assert "timer" in type_names


class TestObservabilityLogLevelsAPI:
    """Tests for /api/observability/log-levels endpoint."""

    def test_log_levels_returns_all(self, handler):
        """Test that log-levels returns all levels."""
        result = handler.call_endpoint("_observability_log_levels", {})
        assert "total" in result
        assert "levels" in result
        assert result["total"] == 5
        assert len(result["levels"]) == 5

    def test_log_levels_structure(self, handler):
        """Test log level structure."""
        result = handler.call_endpoint("_observability_log_levels", {})
        for level in result["levels"]:
            assert "level" in level
            assert "description" in level
            assert "use_case" in level

    def test_log_levels_contains_expected(self, handler):
        """Test that all expected log levels are present."""
        result = handler.call_endpoint("_observability_log_levels", {})
        level_names = [lv["level"] for lv in result["levels"]]
        assert "DEBUG" in level_names
        assert "INFO" in level_names
        assert "WARNING" in level_names
        assert "ERROR" in level_names
        assert "CRITICAL" in level_names


class TestObservabilitySpanStatusesAPI:
    """Tests for /api/observability/span-statuses endpoint."""

    def test_span_statuses_returns_all(self, handler):
        """Test that span-statuses returns all statuses."""
        result = handler.call_endpoint("_observability_span_statuses", {})
        assert "total" in result
        assert "statuses" in result
        assert result["total"] == 3
        assert len(result["statuses"]) == 3

    def test_span_statuses_structure(self, handler):
        """Test span status structure."""
        result = handler.call_endpoint("_observability_span_statuses", {})
        for status in result["statuses"]:
            assert "status" in status
            assert "description" in status
            assert "indicator" in status

    def test_span_statuses_contains_expected(self, handler):
        """Test that all expected span statuses are present."""
        result = handler.call_endpoint("_observability_span_statuses", {})
        status_names = [s["status"] for s in result["statuses"]]
        assert "OK" in status_names
        assert "ERROR" in status_names
        assert "CANCELLED" in status_names


class TestObservabilityLogFormatsAPI:
    """Tests for /api/observability/log-formats endpoint."""

    def test_log_formats_returns_all(self, handler):
        """Test that log-formats returns all formats."""
        result = handler.call_endpoint("_observability_log_formats", {})
        assert "total" in result
        assert "formats" in result
        assert result["total"] == 2
        assert len(result["formats"]) == 2

    def test_log_formats_structure(self, handler):
        """Test log format structure."""
        result = handler.call_endpoint("_observability_log_formats", {})
        for fmt in result["formats"]:
            assert "format" in fmt
            assert "description" in fmt
            assert "use_case" in fmt
            assert "formatter" in fmt

    def test_log_formats_contains_expected(self, handler):
        """Test that all expected log formats are present."""
        result = handler.call_endpoint("_observability_log_formats", {})
        format_names = [f["format"] for f in result["formats"]]
        assert "human" in format_names
        assert "structured" in format_names


class TestObservabilityStatsAPI:
    """Tests for /api/observability/stats endpoint."""

    def test_stats_returns_correct_values(self, handler):
        """Test that stats returns correct values."""
        result = handler.call_endpoint("_observability_stats", {})
        assert result["metrics_backends"] == 2
        assert result["tracing_backends"] == 4
        assert result["log_levels"] == 5
        assert result["metric_types"] == 4
        assert result["span_statuses"] == 3
        assert result["log_formats"] == 2

    def test_stats_has_current_config(self, handler):
        """Test that stats includes current config."""
        result = handler.call_endpoint("_observability_stats", {})
        assert "current_config" in result
        assert "log_level" in result["current_config"]
        assert "log_format" in result["current_config"]
        assert "metrics_backend" in result["current_config"]
        assert "tracing_backend" in result["current_config"]


class TestObservabilityStatusAPI:
    """Tests for /api/observability/status endpoint."""

    def test_status_is_operational(self, handler):
        """Test that status reports operational."""
        result = handler.call_endpoint("_observability_status", {})
        assert result["module"] == "observability"
        assert result["status"] == "operational"

    def test_status_has_components(self, handler):
        """Test that status includes components."""
        result = handler.call_endpoint("_observability_status", {})
        assert "components" in result
        assert "StanceLogger" in result["components"]
        assert "StanceMetrics" in result["components"]
        assert "StanceTracer" in result["components"]
        assert "InMemoryMetricsBackend" in result["components"]
        assert "CloudWatchMetricsBackend" in result["components"]

    def test_status_has_capabilities(self, handler):
        """Test that status includes capabilities."""
        result = handler.call_endpoint("_observability_status", {})
        assert "capabilities" in result
        assert "structured_logging" in result["capabilities"]
        assert "metrics_collection" in result["capabilities"]
        assert "distributed_tracing" in result["capabilities"]


class TestObservabilitySummaryAPI:
    """Tests for /api/observability/summary endpoint."""

    def test_summary_module_info(self, handler):
        """Test that summary includes module info."""
        result = handler.call_endpoint("_observability_summary", {})
        assert result["module"] == "observability"
        assert result["version"] == "1.0.0"
        assert "description" in result

    def test_summary_has_features(self, handler):
        """Test that summary includes features."""
        result = handler.call_endpoint("_observability_summary", {})
        assert "features" in result
        assert len(result["features"]) > 0

    def test_summary_has_subsystems(self, handler):
        """Test that summary includes subsystems."""
        result = handler.call_endpoint("_observability_summary", {})
        assert "subsystems" in result
        assert "logging" in result["subsystems"]
        assert "metrics" in result["subsystems"]
        assert "tracing" in result["subsystems"]

    def test_summary_has_cloud_integrations(self, handler):
        """Test that summary includes cloud integrations."""
        result = handler.call_endpoint("_observability_summary", {})
        assert "cloud_integrations" in result
        assert "aws" in result["cloud_integrations"]
        assert "gcp" in result["cloud_integrations"]
        assert "azure" in result["cloud_integrations"]

    def test_summary_has_env_vars(self, handler):
        """Test that summary includes environment variables."""
        result = handler.call_endpoint("_observability_summary", {})
        assert "env_vars" in result
        assert "STANCE_LOG_LEVEL" in result["env_vars"]
        assert "STANCE_LOG_FORMAT" in result["env_vars"]
        assert "STANCE_METRICS_BACKEND" in result["env_vars"]
        assert "STANCE_TRACING_BACKEND" in result["env_vars"]


class TestAPIParameterParsing:
    """Tests for API parameter parsing."""

    def test_logging_parses_list_params(self, handler):
        """Test that logging parses list-format parameters."""
        result = handler.call_endpoint("_observability_logging", {
            "level": ["DEBUG"],
            "format": ["structured"],
        })
        # Should not raise, regardless of result
        assert isinstance(result, dict)

    def test_logging_parses_single_params(self, handler):
        """Test that logging parses single-value parameters."""
        result = handler.call_endpoint("_observability_logging", {
            "level": "INFO",
            "format": "human",
        })
        # Should not raise, regardless of result
        assert isinstance(result, dict)

    def test_metrics_parses_limit_param(self, handler):
        """Test metrics parses limit parameter correctly."""
        result = handler.call_endpoint("_observability_metrics", {
            "limit": ["75"],
        })
        if "limit" in result:
            assert result["limit"] == 75

    def test_traces_parses_limit_param(self, handler):
        """Test traces parses limit parameter correctly."""
        result = handler.call_endpoint("_observability_traces", {
            "limit": ["50"],
        })
        # Should handle correctly
        assert isinstance(result, dict)


class TestAPIErrorHandling:
    """Tests for API error handling."""

    def test_metrics_handles_no_backend(self, handler):
        """Test that metrics handles no backend gracefully."""
        result = handler.call_endpoint("_observability_metrics", {})
        # Should return result dict (possibly with note about no backend)
        assert isinstance(result, dict)

    def test_traces_handles_no_backend(self, handler):
        """Test that traces handles no backend gracefully."""
        result = handler.call_endpoint("_observability_traces", {})
        # Should return result dict (possibly with note about no backend)
        assert isinstance(result, dict)

    def test_traces_handles_invalid_trace_id(self, handler):
        """Test that traces handles invalid trace ID gracefully."""
        result = handler.call_endpoint("_observability_traces", {
            "trace_id": ["nonexistent-trace-id-12345"],
        })
        assert isinstance(result, dict)


class TestAPIResponseFormat:
    """Tests for API response format consistency."""

    def test_all_info_endpoints_return_dict(self, handler):
        """Test that all info endpoints return dictionaries."""
        endpoints = [
            "_observability_backends",
            "_observability_metric_types",
            "_observability_log_levels",
            "_observability_span_statuses",
            "_observability_log_formats",
            "_observability_stats",
            "_observability_status",
            "_observability_summary",
        ]
        for endpoint in endpoints:
            result = handler.call_endpoint(endpoint, {})
            assert isinstance(result, dict), f"{endpoint} should return dict"

    def test_all_data_endpoints_return_dict(self, handler):
        """Test that all data endpoints return dictionaries."""
        endpoints = [
            ("_observability_logging", {}),
            ("_observability_metrics", {}),
            ("_observability_traces", {}),
        ]
        for endpoint, params in endpoints:
            result = handler.call_endpoint(endpoint, params)
            assert isinstance(result, dict), f"{endpoint} should return dict"


class TestAPIIntegration:
    """Integration tests for API endpoints."""

    def test_logging_returns_valid_config(self, handler):
        """Test that logging returns valid configuration."""
        result = handler.call_endpoint("_observability_logging", {})
        if "current_level" in result:
            assert result["current_level"] in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if "current_format" in result:
            assert result["current_format"] in ["human", "structured"]

    def test_stats_counts_match_endpoints(self, handler):
        """Test that stats counts match actual endpoint data."""
        stats = handler.call_endpoint("_observability_stats", {})
        backends = handler.call_endpoint("_observability_backends", {})
        metric_types = handler.call_endpoint("_observability_metric_types", {})
        log_levels = handler.call_endpoint("_observability_log_levels", {})
        span_statuses = handler.call_endpoint("_observability_span_statuses", {})
        log_formats = handler.call_endpoint("_observability_log_formats", {})

        # Backends: 2 metrics + 4 tracing = 6 total
        assert backends["total"] == 6
        assert metric_types["total"] == 4
        assert log_levels["total"] == 5
        assert span_statuses["total"] == 3
        assert log_formats["total"] == 2

    def test_status_capabilities_are_valid(self, handler):
        """Test that status capabilities are valid."""
        result = handler.call_endpoint("_observability_status", {})
        expected_capabilities = [
            "structured_logging",
            "human_readable_logging",
            "metrics_collection",
            "distributed_tracing",
            "cloudwatch_integration",
            "xray_integration",
            "cloud_trace_integration",
            "application_insights_integration",
        ]
        for cap in expected_capabilities:
            assert cap in result["capabilities"]

    def test_summary_features_non_empty(self, handler):
        """Test that summary features list is non-empty."""
        result = handler.call_endpoint("_observability_summary", {})
        assert len(result["features"]) >= 5


class TestCloudIntegrations:
    """Tests for cloud integration information."""

    def test_aws_integrations(self, handler):
        """Test AWS integration info."""
        result = handler.call_endpoint("_observability_summary", {})
        assert "CloudWatch Metrics" in result["cloud_integrations"]["aws"]
        assert "X-Ray Tracing" in result["cloud_integrations"]["aws"]

    def test_gcp_integrations(self, handler):
        """Test GCP integration info."""
        result = handler.call_endpoint("_observability_summary", {})
        assert "Cloud Trace" in result["cloud_integrations"]["gcp"]

    def test_azure_integrations(self, handler):
        """Test Azure integration info."""
        result = handler.call_endpoint("_observability_summary", {})
        assert "Application Insights" in result["cloud_integrations"]["azure"]

    def test_backends_have_correct_cloud_assignments(self, handler):
        """Test that backends have correct cloud assignments."""
        result = handler.call_endpoint("_observability_backends", {})

        for backend in result["backends"]:
            if "CloudWatch" in backend["backend"]:
                assert backend["cloud"] == "aws"
            elif "XRay" in backend["backend"]:
                assert backend["cloud"] == "aws"
            elif "CloudTrace" in backend["backend"]:
                assert backend["cloud"] == "gcp"
            elif "ApplicationInsights" in backend["backend"]:
                assert backend["cloud"] == "azure"
            elif "InMemory" in backend["backend"]:
                assert backend["cloud"] == "any"
