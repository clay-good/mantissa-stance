"""
Unit tests for CLI automation commands.

Tests the automation CLI commands for managing notification automation,
configuration, and notification history.
"""

import argparse
import pytest

from stance.cli_automation import (
    cmd_automation,
    add_automation_parser,
    _handle_config,
    _handle_types,
    _handle_history,
    _handle_thresholds,
    _handle_triggers,
    _handle_callbacks,
    _handle_severities,
    _handle_status,
    _handle_test,
    _handle_summary,
    _handle_workflows,
    _handle_events,
    _get_sample_config,
    _get_notification_types,
    _get_sample_history,
    _get_thresholds,
    _get_triggers,
    _get_callbacks,
    _get_automation_status,
    _test_notification,
    _get_automation_summary,
    _get_workflows,
    _get_events,
)


class TestAddAutomationParser:
    """Tests for add_automation_parser function."""

    def test_parser_is_added(self):
        """Test that automation parser is added to subparsers."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_automation_parser(subparsers)

        args = parser.parse_args(["automation", "status"])
        assert args.command == "automation"
        assert args.automation_command == "status"

    def test_config_subcommand(self):
        """Test config subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_automation_parser(subparsers)

        args = parser.parse_args(["automation", "config", "--format", "json"])
        assert args.automation_command == "config"
        assert args.format == "json"

    def test_types_subcommand(self):
        """Test types subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_automation_parser(subparsers)

        args = parser.parse_args(["automation", "types"])
        assert args.automation_command == "types"

    def test_history_subcommand(self):
        """Test history subcommand with filters."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_automation_parser(subparsers)

        args = parser.parse_args(["automation", "history", "--type", "scan_complete", "--limit", "10"])
        assert args.automation_command == "history"
        assert args.type == "scan_complete"
        assert args.limit == 10

    def test_test_subcommand(self):
        """Test test subcommand with type parameter."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_automation_parser(subparsers)

        args = parser.parse_args(["automation", "test", "--type", "critical_finding"])
        assert args.automation_command == "test"
        assert args.type == "critical_finding"

    def test_workflows_subcommand(self):
        """Test workflows subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_automation_parser(subparsers)

        args = parser.parse_args(["automation", "workflows"])
        assert args.automation_command == "workflows"

    def test_events_subcommand(self):
        """Test events subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_automation_parser(subparsers)

        args = parser.parse_args(["automation", "events"])
        assert args.automation_command == "events"


class TestCmdAutomation:
    """Tests for cmd_automation main handler."""

    def test_no_command_returns_error(self):
        """Test that no subcommand returns error."""
        args = argparse.Namespace(automation_command=None)
        result = cmd_automation(args)
        assert result == 1

    def test_unknown_command_returns_error(self):
        """Test that unknown command returns error."""
        args = argparse.Namespace(automation_command="unknown")
        result = cmd_automation(args)
        assert result == 1

    def test_status_command_succeeds(self):
        """Test that status command succeeds."""
        args = argparse.Namespace(automation_command="status", format="text")
        result = cmd_automation(args)
        assert result == 0

    def test_config_command_succeeds(self):
        """Test that config command succeeds."""
        args = argparse.Namespace(automation_command="config", format="text")
        result = cmd_automation(args)
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


class TestHandleTypes:
    """Tests for _handle_types handler."""

    def test_text_format(self):
        """Test types output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_types(args)
        assert result == 0

    def test_json_format(self):
        """Test types output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_types(args)
        assert result == 0


class TestHandleHistory:
    """Tests for _handle_history handler."""

    def test_text_format(self):
        """Test history output in text format."""
        args = argparse.Namespace(format="text", type=None, limit=50)
        result = _handle_history(args)
        assert result == 0

    def test_type_filter(self):
        """Test history with type filter."""
        args = argparse.Namespace(format="text", type="scan_complete", limit=50)
        result = _handle_history(args)
        assert result == 0

    def test_limit(self):
        """Test history with limit."""
        args = argparse.Namespace(format="text", type=None, limit=2)
        result = _handle_history(args)
        assert result == 0


class TestHandleThresholds:
    """Tests for _handle_thresholds handler."""

    def test_text_format(self):
        """Test thresholds output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_thresholds(args)
        assert result == 0

    def test_json_format(self):
        """Test thresholds output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_thresholds(args)
        assert result == 0


class TestHandleTriggers:
    """Tests for _handle_triggers handler."""

    def test_text_format(self):
        """Test triggers output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_triggers(args)
        assert result == 0

    def test_json_format(self):
        """Test triggers output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_triggers(args)
        assert result == 0


class TestHandleCallbacks:
    """Tests for _handle_callbacks handler."""

    def test_text_format(self):
        """Test callbacks output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_callbacks(args)
        assert result == 0

    def test_json_format(self):
        """Test callbacks output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_callbacks(args)
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


class TestHandleTest:
    """Tests for _handle_test handler."""

    def test_text_format(self):
        """Test test output in text format."""
        args = argparse.Namespace(format="text", type="scan_complete")
        result = _handle_test(args)
        assert result == 0

    def test_critical_finding_type(self):
        """Test test with critical_finding type."""
        args = argparse.Namespace(format="text", type="critical_finding")
        result = _handle_test(args)
        assert result == 0

    def test_trend_alert_type(self):
        """Test test with trend_alert type."""
        args = argparse.Namespace(format="text", type="trend_alert")
        result = _handle_test(args)
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


class TestHandleWorkflows:
    """Tests for _handle_workflows handler."""

    def test_text_format(self):
        """Test workflows output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_workflows(args)
        assert result == 0

    def test_json_format(self):
        """Test workflows output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_workflows(args)
        assert result == 0


class TestHandleEvents:
    """Tests for _handle_events handler."""

    def test_text_format(self):
        """Test events output in text format."""
        args = argparse.Namespace(format="text")
        result = _handle_events(args)
        assert result == 0

    def test_json_format(self):
        """Test events output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_events(args)
        assert result == 0


class TestSampleDataGenerators:
    """Tests for sample data generator functions."""

    def test_get_sample_config(self):
        """Test sample config data structure."""
        config = _get_sample_config()
        assert isinstance(config, dict)
        assert "notify_on_scan_complete" in config
        assert "notify_on_critical" in config
        assert "min_severity_for_new" in config
        assert "critical_threshold" in config

    def test_get_notification_types(self):
        """Test notification types data structure."""
        types = _get_notification_types()
        assert isinstance(types, list)
        assert len(types) == 7

        ntype = types[0]
        assert "value" in ntype
        assert "description" in ntype
        assert "trigger" in ntype

    def test_get_sample_history(self):
        """Test sample history data structure."""
        history = _get_sample_history()
        assert isinstance(history, list)
        assert len(history) > 0

        entry = history[0]
        assert "notification_type" in entry
        assert "timestamp" in entry
        assert "message" in entry

    def test_get_thresholds(self):
        """Test thresholds data structure."""
        thresholds = _get_thresholds()
        assert isinstance(thresholds, list)
        assert len(thresholds) == 3

        threshold = thresholds[0]
        assert "name" in threshold
        assert "value" in threshold
        assert "description" in threshold

    def test_get_triggers(self):
        """Test triggers data structure."""
        triggers = _get_triggers()
        assert isinstance(triggers, list)
        assert len(triggers) == 6

        trigger = triggers[0]
        assert "name" in trigger
        assert "event" in trigger
        assert "enabled" in trigger

    def test_get_callbacks(self):
        """Test callbacks data structure."""
        callbacks = _get_callbacks()
        assert isinstance(callbacks, list)
        assert len(callbacks) == 3

        callback = callbacks[0]
        assert "name" in callback
        assert "type" in callback
        assert "description" in callback

    def test_get_automation_status(self):
        """Test automation status data structure."""
        status = _get_automation_status()
        assert isinstance(status, dict)
        assert "module" in status
        assert "version" in status
        assert "status" in status
        assert "components" in status
        assert "capabilities" in status

    def test_get_automation_summary(self):
        """Test automation summary data structure."""
        summary = _get_automation_summary()
        assert isinstance(summary, dict)
        assert "config" in summary
        assert "stats" in summary
        assert "notifications_sent_24h" in summary["stats"]

    def test_get_workflows(self):
        """Test workflows data structure."""
        workflows = _get_workflows()
        assert isinstance(workflows, list)
        assert len(workflows) == 4

        workflow = workflows[0]
        assert "name" in workflow
        assert "trigger" in workflow
        assert "actions" in workflow
        assert "enabled" in workflow

    def test_get_events(self):
        """Test events data structure."""
        events = _get_events()
        assert isinstance(events, list)
        assert len(events) == 6

        event = events[0]
        assert "name" in event
        assert "source" in event
        assert "description" in event
        assert "data_fields" in event


class TestNotificationTesting:
    """Tests for notification testing logic."""

    def test_test_notification_scan_complete(self):
        """Test notification test for scan_complete."""
        result = _test_notification("scan_complete")
        assert result["test_type"] == "scan_complete"
        assert result["would_trigger"] is True
        assert "notification" in result
        assert "matching_triggers" in result

    def test_test_notification_critical_finding(self):
        """Test notification test for critical_finding."""
        result = _test_notification("critical_finding")
        assert result["test_type"] == "critical_finding"
        assert result["would_trigger"] is True
        assert "Critical Findings" in result["matching_triggers"]

    def test_test_notification_scan_failed(self):
        """Test notification test for scan_failed."""
        result = _test_notification("scan_failed")
        assert result["test_type"] == "scan_failed"
        assert result["would_trigger"] is True

    def test_test_notification_result_structure(self):
        """Test notification test result structure."""
        result = _test_notification("new_findings")
        assert "test_type" in result
        assert "would_trigger" in result
        assert "notification" in result
        assert "matching_triggers" in result

        notification = result["notification"]
        assert "notification_type" in notification
        assert "timestamp" in notification
        assert "message" in notification
