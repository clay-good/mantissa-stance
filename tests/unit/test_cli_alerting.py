"""
Unit tests for CLI alerting commands.

Tests the alerting CLI commands for managing alert routing,
destinations, suppression rules, and alert state.
"""

import argparse
import pytest
from unittest.mock import patch

from stance.cli_alerting import (
    cmd_alerting,
    add_alerting_parser,
    _handle_destinations,
    _handle_routing_rules,
    _handle_suppression_rules,
    _handle_config,
    _handle_rate_limits,
    _handle_alerts,
    _handle_templates,
    _handle_destination_types,
    _handle_severities,
    _handle_status,
    _handle_test_route,
    _handle_summary,
    _get_sample_destinations,
    _get_sample_routing_rules,
    _get_sample_suppression_rules,
    _get_sample_config,
    _get_sample_rate_limits,
    _get_sample_alerts,
    _get_available_templates,
    _get_destination_types,
    _get_alerting_status,
    _test_routing,
    _get_alerting_summary,
)


class TestAddAlertingParser:
    """Tests for add_alerting_parser function."""

    def test_parser_is_added(self):
        """Test that alerting parser is added to subparsers."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_alerting_parser(subparsers)

        # Parse alerting command
        args = parser.parse_args(["alerting", "status"])
        assert args.command == "alerting"
        assert args.alerting_command == "status"

    def test_destinations_subcommand(self):
        """Test destinations subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_alerting_parser(subparsers)

        args = parser.parse_args(["alerting", "destinations", "--format", "json"])
        assert args.alerting_command == "destinations"
        assert args.format == "json"

    def test_routing_rules_subcommand(self):
        """Test routing-rules subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_alerting_parser(subparsers)

        args = parser.parse_args(["alerting", "routing-rules", "--enabled-only"])
        assert args.alerting_command == "routing-rules"
        assert args.enabled_only is True

    def test_suppression_rules_subcommand(self):
        """Test suppression-rules subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_alerting_parser(subparsers)

        args = parser.parse_args(["alerting", "suppression-rules", "--enabled-only"])
        assert args.alerting_command == "suppression-rules"
        assert args.enabled_only is True

    def test_config_subcommand(self):
        """Test config subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_alerting_parser(subparsers)

        args = parser.parse_args(["alerting", "config"])
        assert args.alerting_command == "config"

    def test_alerts_subcommand(self):
        """Test alerts subcommand with filters."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_alerting_parser(subparsers)

        args = parser.parse_args(["alerting", "alerts", "--status", "sent", "--limit", "10"])
        assert args.alerting_command == "alerts"
        assert args.status == "sent"
        assert args.limit == 10

    def test_test_route_subcommand(self):
        """Test test-route subcommand with parameters."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_alerting_parser(subparsers)

        args = parser.parse_args(["alerting", "test-route", "--severity", "critical", "--finding-type", "vulnerability"])
        assert args.alerting_command == "test-route"
        assert args.severity == "critical"
        assert args.finding_type == "vulnerability"


class TestCmdAlerting:
    """Tests for cmd_alerting main handler."""

    def test_no_command_returns_error(self):
        """Test that no subcommand returns error."""
        args = argparse.Namespace(alerting_command=None)
        result = cmd_alerting(args)
        assert result == 1

    def test_unknown_command_returns_error(self):
        """Test that unknown command returns error."""
        args = argparse.Namespace(alerting_command="unknown")
        result = cmd_alerting(args)
        assert result == 1

    def test_status_command_succeeds(self):
        """Test that status command succeeds."""
        args = argparse.Namespace(alerting_command="status", format="text")
        result = cmd_alerting(args)
        assert result == 0

    def test_destinations_command_succeeds(self):
        """Test that destinations command succeeds."""
        args = argparse.Namespace(alerting_command="destinations", format="text")
        result = cmd_alerting(args)
        assert result == 0


class TestHandleDestinations:
    """Tests for _handle_destinations handler."""

    def test_text_format(self):
        """Test destinations output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_destinations(args)
        assert result == 0

    def test_json_format(self):
        """Test destinations output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_destinations(args)
        assert result == 0


class TestHandleRoutingRules:
    """Tests for _handle_routing_rules handler."""

    def test_text_format(self):
        """Test routing rules output in text format."""
        args = argparse.Namespace(format="text", enabled_only=False)
        result = _handle_routing_rules(args)
        assert result == 0

    def test_json_format(self):
        """Test routing rules output in JSON format."""
        args = argparse.Namespace(format="json", enabled_only=False)
        result = _handle_routing_rules(args)
        assert result == 0

    def test_enabled_only_filter(self):
        """Test routing rules with enabled_only filter."""
        args = argparse.Namespace(format="text", enabled_only=True)
        result = _handle_routing_rules(args)
        assert result == 0


class TestHandleSuppressionRules:
    """Tests for _handle_suppression_rules handler."""

    def test_text_format(self):
        """Test suppression rules output in text format."""
        args = argparse.Namespace(format="text", enabled_only=False)
        result = _handle_suppression_rules(args)
        assert result == 0

    def test_enabled_only_filter(self):
        """Test suppression rules with enabled_only filter."""
        args = argparse.Namespace(format="text", enabled_only=True)
        result = _handle_suppression_rules(args)
        assert result == 0


class TestHandleConfig:
    """Tests for _handle_config handler."""

    def test_text_format(self):
        """Test config output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_config(args)
        assert result == 0

    def test_json_format(self):
        """Test config output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_config(args)
        assert result == 0


class TestHandleRateLimits:
    """Tests for _handle_rate_limits handler."""

    def test_text_format(self):
        """Test rate limits output in text format."""
        args = argparse.Namespace(format="text", destination=None)
        result = _handle_rate_limits(args)
        assert result == 0

    def test_specific_destination(self):
        """Test rate limits for specific destination."""
        args = argparse.Namespace(format="text", destination="slack-security")
        result = _handle_rate_limits(args)
        assert result == 0


class TestHandleAlerts:
    """Tests for _handle_alerts handler."""

    def test_text_format(self):
        """Test alerts output in text format."""
        args = argparse.Namespace(format="text", finding_id=None, status=None, limit=50)
        result = _handle_alerts(args)
        assert result == 0

    def test_status_filter(self):
        """Test alerts with status filter."""
        args = argparse.Namespace(format="text", finding_id=None, status="sent", limit=50)
        result = _handle_alerts(args)
        assert result == 0

    def test_finding_id_filter(self):
        """Test alerts with finding_id filter."""
        args = argparse.Namespace(format="text", finding_id="finding-abc123", status=None, limit=50)
        result = _handle_alerts(args)
        assert result == 0


class TestHandleTemplates:
    """Tests for _handle_templates handler."""

    def test_text_format(self):
        """Test templates output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_templates(args)
        assert result == 0

    def test_json_format(self):
        """Test templates output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_templates(args)
        assert result == 0


class TestHandleDestinationTypes:
    """Tests for _handle_destination_types handler."""

    def test_text_format(self):
        """Test destination types output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_destination_types(args)
        assert result == 0

    def test_json_format(self):
        """Test destination types output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_destination_types(args)
        assert result == 0


class TestHandleSeverities:
    """Tests for _handle_severities handler."""

    def test_text_format(self):
        """Test severities output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_severities(args)
        assert result == 0

    def test_json_format(self):
        """Test severities output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_severities(args)
        assert result == 0


class TestHandleStatus:
    """Tests for _handle_status handler."""

    def test_text_format(self):
        """Test status output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_status(args)
        assert result == 0

    def test_json_format(self):
        """Test status output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0


class TestHandleTestRoute:
    """Tests for _handle_test_route handler."""

    def test_text_format(self):
        """Test test route output in text format."""
        args = argparse.Namespace(format="text", severity="high", finding_type="misconfiguration")
        result = _handle_test_route(args)
        assert result == 0

    def test_critical_severity(self):
        """Test routing with critical severity."""
        args = argparse.Namespace(format="text", severity="critical", finding_type="misconfiguration")
        result = _handle_test_route(args)
        assert result == 0

    def test_vulnerability_type(self):
        """Test routing with vulnerability type."""
        args = argparse.Namespace(format="text", severity="high", finding_type="vulnerability")
        result = _handle_test_route(args)
        assert result == 0


class TestHandleSummary:
    """Tests for _handle_summary handler."""

    def test_text_format(self):
        """Test summary output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_summary(args)
        assert result == 0

    def test_json_format(self):
        """Test summary output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0


class TestSampleDataGenerators:
    """Tests for sample data generator functions."""

    def test_get_sample_destinations(self):
        """Test sample destinations data structure."""
        destinations = _get_sample_destinations()
        assert isinstance(destinations, list)
        assert len(destinations) > 0

        dest = destinations[0]
        assert "name" in dest
        assert "type" in dest
        assert "enabled" in dest
        assert "available" in dest

    def test_get_sample_routing_rules(self):
        """Test sample routing rules data structure."""
        rules = _get_sample_routing_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0

        rule = rules[0]
        assert "name" in rule
        assert "destinations" in rule
        assert "severities" in rule
        assert "enabled" in rule
        assert "priority" in rule

    def test_get_sample_suppression_rules(self):
        """Test sample suppression rules data structure."""
        rules = _get_sample_suppression_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0

        rule = rules[0]
        assert "name" in rule
        assert "rule_ids" in rule
        assert "reason" in rule
        assert "enabled" in rule

    def test_get_sample_config(self):
        """Test sample config data structure."""
        config = _get_sample_config()
        assert isinstance(config, dict)
        assert "enabled" in config
        assert "dedup_window_hours" in config
        assert "default_rate_limit" in config
        assert "destinations" in config
        assert "routing_rules" in config

    def test_get_sample_rate_limits(self):
        """Test sample rate limits data structure."""
        rate_limits = _get_sample_rate_limits()
        assert isinstance(rate_limits, dict)
        assert "default" in rate_limits

        limit = rate_limits["default"]
        assert "max_alerts" in limit
        assert "window_seconds" in limit
        assert "burst_limit" in limit

    def test_get_sample_alerts(self):
        """Test sample alerts data structure."""
        alerts = _get_sample_alerts()
        assert isinstance(alerts, list)
        assert len(alerts) > 0

        alert = alerts[0]
        assert "id" in alert
        assert "finding_id" in alert
        assert "destination" in alert
        assert "sent_at" in alert
        assert "status" in alert

    def test_get_available_templates(self):
        """Test available templates data structure."""
        templates = _get_available_templates()
        assert isinstance(templates, list)
        assert len(templates) > 0

        template = templates[0]
        assert "name" in template
        assert "description" in template
        assert "used_for" in template

    def test_get_destination_types(self):
        """Test destination types data structure."""
        types = _get_destination_types()
        assert isinstance(types, list)
        assert len(types) > 0

        dtype = types[0]
        assert "type" in dtype
        assert "description" in dtype
        assert "required_config" in dtype

    def test_get_alerting_status(self):
        """Test alerting status data structure."""
        status = _get_alerting_status()
        assert isinstance(status, dict)
        assert "module" in status
        assert "version" in status
        assert "status" in status
        assert "components" in status
        assert "capabilities" in status

    def test_get_alerting_summary(self):
        """Test alerting summary data structure."""
        summary = _get_alerting_summary()
        assert isinstance(summary, dict)
        assert "config" in summary
        assert "stats" in summary
        assert "alerts_sent_24h" in summary["stats"]


class TestRoutingLogic:
    """Tests for routing logic."""

    def test_test_routing_critical_matches_pagerduty(self):
        """Test that critical severity matches pagerduty rule."""
        result = _test_routing("critical", "misconfiguration")
        assert "critical-pagerduty" in result["matched_rules"]
        assert "pagerduty-critical" in result["destinations"]

    def test_test_routing_high_matches_slack(self):
        """Test that high severity matches slack rule."""
        result = _test_routing("high", "vulnerability")
        assert "high-slack" in result["matched_rules"]
        assert "slack-security" in result["destinations"]

    def test_test_routing_misconfiguration_matches_email(self):
        """Test that misconfiguration finding type matches email rule."""
        result = _test_routing("medium", "misconfiguration")
        assert "compliance-email" in result["matched_rules"]
        assert "email-team" in result["destinations"]

    def test_test_routing_returns_structure(self):
        """Test routing result structure."""
        result = _test_routing("high", "misconfiguration")
        assert "severity" in result
        assert "finding_type" in result
        assert "matched_rules" in result
        assert "destinations" in result
        assert "would_be_suppressed" in result
