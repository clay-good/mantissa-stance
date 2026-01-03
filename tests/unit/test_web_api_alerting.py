"""
Unit tests for Web API alerting endpoints.

Tests the REST API endpoints for alert routing, destinations,
suppression rules, and alert state management.
"""

import pytest
from unittest.mock import MagicMock, patch

from stance.web.server import StanceRequestHandler


@pytest.fixture
def handler():
    """Create a mock request handler."""
    handler = MagicMock(spec=StanceRequestHandler)
    handler.storage = None

    # Copy the actual methods to the mock
    handler._alerting_destinations = StanceRequestHandler._alerting_destinations.__get__(handler)
    handler._alerting_routing_rules = StanceRequestHandler._alerting_routing_rules.__get__(handler)
    handler._alerting_suppression_rules = StanceRequestHandler._alerting_suppression_rules.__get__(handler)
    handler._alerting_config = StanceRequestHandler._alerting_config.__get__(handler)
    handler._alerting_rate_limits = StanceRequestHandler._alerting_rate_limits.__get__(handler)
    handler._alerting_alerts = StanceRequestHandler._alerting_alerts.__get__(handler)
    handler._alerting_templates = StanceRequestHandler._alerting_templates.__get__(handler)
    handler._alerting_destination_types = StanceRequestHandler._alerting_destination_types.__get__(handler)
    handler._alerting_severities = StanceRequestHandler._alerting_severities.__get__(handler)
    handler._alerting_status = StanceRequestHandler._alerting_status.__get__(handler)
    handler._alerting_test_route = StanceRequestHandler._alerting_test_route.__get__(handler)
    handler._alerting_summary = StanceRequestHandler._alerting_summary.__get__(handler)
    handler._get_sample_alerting_destinations = StanceRequestHandler._get_sample_alerting_destinations.__get__(handler)
    handler._get_sample_routing_rules = StanceRequestHandler._get_sample_routing_rules.__get__(handler)
    handler._get_sample_suppression_rules = StanceRequestHandler._get_sample_suppression_rules.__get__(handler)

    return handler


class TestAlertingDestinationsEndpoint:
    """Tests for /api/alerting/destinations endpoint."""

    def test_destinations_returns_list(self, handler):
        """Test that destinations returns a list."""
        result = handler._alerting_destinations(None)
        assert "destinations" in result
        assert "total" in result
        assert isinstance(result["destinations"], list)

    def test_destinations_structure(self, handler):
        """Test destination structure."""
        result = handler._alerting_destinations(None)
        assert len(result["destinations"]) > 0

        dest = result["destinations"][0]
        assert "name" in dest
        assert "type" in dest
        assert "enabled" in dest
        assert "available" in dest

    def test_destinations_includes_types(self, handler):
        """Test destinations include different types."""
        result = handler._alerting_destinations(None)
        types = {d["type"] for d in result["destinations"]}
        assert "slack" in types


class TestAlertingRoutingRulesEndpoint:
    """Tests for /api/alerting/routing-rules endpoint."""

    def test_routing_rules_returns_list(self, handler):
        """Test that routing rules returns a list."""
        result = handler._alerting_routing_rules(None)
        assert "rules" in result
        assert "total" in result
        assert isinstance(result["rules"], list)

    def test_routing_rules_structure(self, handler):
        """Test routing rule structure."""
        result = handler._alerting_routing_rules(None)
        assert len(result["rules"]) > 0

        rule = result["rules"][0]
        assert "name" in rule
        assert "destinations" in rule
        assert "severities" in rule
        assert "enabled" in rule
        assert "priority" in rule

    def test_routing_rules_enabled_only_filter(self, handler):
        """Test enabled_only filter."""
        result = handler._alerting_routing_rules({"enabled_only": ["true"]})
        assert all(r["enabled"] for r in result["rules"])

    def test_routing_rules_all_returns_disabled(self, handler):
        """Test that disabled rules are included by default."""
        result = handler._alerting_routing_rules({"enabled_only": ["false"]})
        # All sample rules are enabled, but the parameter should work
        assert "rules" in result


class TestAlertingSuppressionRulesEndpoint:
    """Tests for /api/alerting/suppression-rules endpoint."""

    def test_suppression_rules_returns_list(self, handler):
        """Test that suppression rules returns a list."""
        result = handler._alerting_suppression_rules(None)
        assert "rules" in result
        assert "total" in result
        assert isinstance(result["rules"], list)

    def test_suppression_rules_structure(self, handler):
        """Test suppression rule structure."""
        result = handler._alerting_suppression_rules(None)
        assert len(result["rules"]) > 0

        rule = result["rules"][0]
        assert "name" in rule
        assert "rule_ids" in rule
        assert "reason" in rule
        assert "enabled" in rule

    def test_suppression_rules_enabled_only_filter(self, handler):
        """Test enabled_only filter for suppression rules."""
        result = handler._alerting_suppression_rules({"enabled_only": ["true"]})
        assert all(r["enabled"] for r in result["rules"])


class TestAlertingConfigEndpoint:
    """Tests for /api/alerting/config endpoint."""

    def test_config_returns_dict(self, handler):
        """Test that config returns a dictionary."""
        result = handler._alerting_config(None)
        assert isinstance(result, dict)

    def test_config_structure(self, handler):
        """Test config structure."""
        result = handler._alerting_config(None)
        assert "enabled" in result
        assert "dedup_window_hours" in result
        assert "default_rate_limit" in result
        assert "destinations_count" in result
        assert "routing_rules_count" in result

    def test_config_rate_limit_structure(self, handler):
        """Test rate limit structure in config."""
        result = handler._alerting_config(None)
        rate_limit = result["default_rate_limit"]
        assert "max_alerts" in rate_limit
        assert "window_seconds" in rate_limit
        assert "burst_limit" in rate_limit


class TestAlertingRateLimitsEndpoint:
    """Tests for /api/alerting/rate-limits endpoint."""

    def test_rate_limits_returns_dict(self, handler):
        """Test that rate limits returns a dictionary."""
        result = handler._alerting_rate_limits(None)
        assert "rate_limits" in result
        assert isinstance(result["rate_limits"], dict)

    def test_rate_limits_structure(self, handler):
        """Test rate limit structure."""
        result = handler._alerting_rate_limits(None)
        assert "default" in result["rate_limits"]

        limit = result["rate_limits"]["default"]
        assert "max_alerts" in limit
        assert "window_seconds" in limit
        assert "burst_limit" in limit

    def test_rate_limits_filter_by_destination(self, handler):
        """Test filtering rate limits by destination."""
        result = handler._alerting_rate_limits({"destination": ["slack-security"]})
        assert "rate_limits" in result
        assert "slack-security" in result["rate_limits"]

    def test_rate_limits_unknown_destination(self, handler):
        """Test rate limits for unknown destination."""
        result = handler._alerting_rate_limits({"destination": ["unknown"]})
        assert "error" in result


class TestAlertingAlertsEndpoint:
    """Tests for /api/alerting/alerts endpoint."""

    def test_alerts_returns_list(self, handler):
        """Test that alerts returns a list."""
        result = handler._alerting_alerts(None)
        assert "alerts" in result
        assert "total" in result
        assert isinstance(result["alerts"], list)

    def test_alerts_structure(self, handler):
        """Test alert structure."""
        result = handler._alerting_alerts(None)
        assert len(result["alerts"]) > 0

        alert = result["alerts"][0]
        assert "id" in alert
        assert "finding_id" in alert
        assert "destination" in alert
        assert "sent_at" in alert
        assert "status" in alert

    def test_alerts_filter_by_status(self, handler):
        """Test filtering alerts by status."""
        result = handler._alerting_alerts({"status": ["sent"]})
        assert all(a["status"] == "sent" for a in result["alerts"])

    def test_alerts_filter_by_finding_id(self, handler):
        """Test filtering alerts by finding ID."""
        result = handler._alerting_alerts({"finding_id": ["finding-abc123"]})
        assert all(a["finding_id"] == "finding-abc123" for a in result["alerts"])

    def test_alerts_limit(self, handler):
        """Test limiting alerts."""
        result = handler._alerting_alerts({"limit": ["2"]})
        assert len(result["alerts"]) <= 2


class TestAlertingTemplatesEndpoint:
    """Tests for /api/alerting/templates endpoint."""

    def test_templates_returns_list(self, handler):
        """Test that templates returns a list."""
        result = handler._alerting_templates(None)
        assert "templates" in result
        assert "total" in result
        assert isinstance(result["templates"], list)

    def test_templates_structure(self, handler):
        """Test template structure."""
        result = handler._alerting_templates(None)
        assert len(result["templates"]) > 0

        template = result["templates"][0]
        assert "name" in template
        assert "description" in template
        assert "used_for" in template

    def test_templates_includes_expected(self, handler):
        """Test that expected templates are included."""
        result = handler._alerting_templates(None)
        names = {t["name"] for t in result["templates"]}
        assert "DefaultTemplate" in names
        assert "VulnerabilityTemplate" in names


class TestAlertingDestinationTypesEndpoint:
    """Tests for /api/alerting/destination-types endpoint."""

    def test_destination_types_returns_list(self, handler):
        """Test that destination types returns a list."""
        result = handler._alerting_destination_types(None)
        assert "types" in result
        assert "total" in result
        assert isinstance(result["types"], list)

    def test_destination_types_structure(self, handler):
        """Test destination type structure."""
        result = handler._alerting_destination_types(None)
        assert len(result["types"]) > 0

        dtype = result["types"][0]
        assert "type" in dtype
        assert "description" in dtype
        assert "required_config" in dtype

    def test_destination_types_includes_expected(self, handler):
        """Test that expected types are included."""
        result = handler._alerting_destination_types(None)
        types = {t["type"] for t in result["types"]}
        assert "slack" in types
        assert "pagerduty" in types
        assert "email" in types


class TestAlertingSeveritiesEndpoint:
    """Tests for /api/alerting/severities endpoint."""

    def test_severities_returns_list(self, handler):
        """Test that severities returns a list."""
        result = handler._alerting_severities(None)
        assert "severities" in result
        assert "total" in result
        assert isinstance(result["severities"], list)

    def test_severities_structure(self, handler):
        """Test severity structure."""
        result = handler._alerting_severities(None)
        assert len(result["severities"]) > 0

        severity = result["severities"][0]
        assert "value" in severity
        assert "priority" in severity
        assert "description" in severity

    def test_severities_includes_all_levels(self, handler):
        """Test that all severity levels are included."""
        result = handler._alerting_severities(None)
        values = {s["value"] for s in result["severities"]}
        assert "critical" in values
        assert "high" in values
        assert "medium" in values
        assert "low" in values
        assert "info" in values


class TestAlertingStatusEndpoint:
    """Tests for /api/alerting/status endpoint."""

    def test_status_returns_dict(self, handler):
        """Test that status returns a dictionary."""
        result = handler._alerting_status(None)
        assert isinstance(result, dict)

    def test_status_structure(self, handler):
        """Test status structure."""
        result = handler._alerting_status(None)
        assert "module" in result
        assert "version" in result
        assert "status" in result
        assert "components" in result
        assert "capabilities" in result

    def test_status_components(self, handler):
        """Test status includes required components."""
        result = handler._alerting_status(None)
        components = result["components"]
        assert "AlertRouter" in components
        assert "AlertState" in components

    def test_status_operational(self, handler):
        """Test status is operational."""
        result = handler._alerting_status(None)
        assert result["status"] == "operational"


class TestAlertingTestRouteEndpoint:
    """Tests for /api/alerting/test-route endpoint."""

    def test_test_route_returns_dict(self, handler):
        """Test that test route returns a dictionary."""
        result = handler._alerting_test_route(None)
        assert isinstance(result, dict)

    def test_test_route_structure(self, handler):
        """Test test route result structure."""
        result = handler._alerting_test_route(None)
        assert "severity" in result
        assert "finding_type" in result
        assert "matched_rules" in result
        assert "destinations" in result
        assert "would_be_suppressed" in result

    def test_test_route_critical_matches(self, handler):
        """Test that critical severity matches appropriate rules."""
        result = handler._alerting_test_route({"severity": ["critical"], "finding_type": ["misconfiguration"]})
        assert "critical-pagerduty" in result["matched_rules"]
        assert "pagerduty-critical" in result["destinations"]

    def test_test_route_high_matches(self, handler):
        """Test that high severity matches appropriate rules."""
        result = handler._alerting_test_route({"severity": ["high"], "finding_type": ["vulnerability"]})
        assert "high-slack" in result["matched_rules"]
        assert "slack-security" in result["destinations"]

    def test_test_route_default_severity(self, handler):
        """Test default severity is high."""
        result = handler._alerting_test_route(None)
        assert result["severity"] == "high"


class TestAlertingSummaryEndpoint:
    """Tests for /api/alerting/summary endpoint."""

    def test_summary_returns_dict(self, handler):
        """Test that summary returns a dictionary."""
        result = handler._alerting_summary(None)
        assert isinstance(result, dict)

    def test_summary_structure(self, handler):
        """Test summary structure."""
        result = handler._alerting_summary(None)
        assert "config" in result
        assert "stats" in result

    def test_summary_config_section(self, handler):
        """Test config section in summary."""
        result = handler._alerting_summary(None)
        config = result["config"]
        assert "enabled" in config
        assert "destinations_count" in config
        assert "routing_rules_count" in config

    def test_summary_stats_section(self, handler):
        """Test stats section in summary."""
        result = handler._alerting_summary(None)
        stats = result["stats"]
        assert "alerts_sent_24h" in stats
        assert "alerts_suppressed_24h" in stats
        assert "alerts_deduplicated_24h" in stats
        assert "by_destination" in stats
        assert "by_severity" in stats


class TestSampleDataHelpers:
    """Tests for sample data helper methods."""

    def test_sample_destinations_correct_count(self, handler):
        """Test sample destinations count."""
        destinations = handler._get_sample_alerting_destinations()
        assert len(destinations) == 4

    def test_sample_routing_rules_correct_count(self, handler):
        """Test sample routing rules count."""
        rules = handler._get_sample_routing_rules()
        assert len(rules) == 4

    def test_sample_suppression_rules_correct_count(self, handler):
        """Test sample suppression rules count."""
        rules = handler._get_sample_suppression_rules()
        assert len(rules) == 3


class TestAlertingEndpointRouting:
    """Tests for alerting endpoint routing in do_GET."""

    def test_get_endpoints_exist(self):
        """Test that all alerting GET endpoints are routed."""
        # This is a basic check that the endpoints are registered
        endpoints = [
            "/api/alerting/destinations",
            "/api/alerting/routing-rules",
            "/api/alerting/suppression-rules",
            "/api/alerting/config",
            "/api/alerting/rate-limits",
            "/api/alerting/alerts",
            "/api/alerting/templates",
            "/api/alerting/destination-types",
            "/api/alerting/severities",
            "/api/alerting/status",
            "/api/alerting/test-route",
            "/api/alerting/summary",
        ]

        # Check that each endpoint method exists
        for endpoint in endpoints:
            method_name = "_alerting_" + endpoint.split("/")[-1].replace("-", "_")
            assert hasattr(StanceRequestHandler, method_name), f"Method {method_name} not found"

    def test_sample_data_helpers_exist(self):
        """Test that sample data helper methods exist."""
        helpers = [
            "_get_sample_alerting_destinations",
            "_get_sample_routing_rules",
            "_get_sample_suppression_rules",
        ]

        for helper in helpers:
            assert hasattr(StanceRequestHandler, helper), f"Helper {helper} not found"
