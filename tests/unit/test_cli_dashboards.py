"""
Unit tests for CLI dashboards commands.

Tests the dashboards CLI commands for managing dashboards, widgets, reports,
scheduled reports, and visualizations.

Part of Phase 91: Advanced Reporting & Dashboards
"""

import argparse
import pytest

from stance.cli_dashboards import (
    cmd_dashboards,
    add_dashboards_parser,
    _handle_list,
    _handle_show,
    _handle_create,
    _handle_widgets,
    _handle_charts,
    _handle_themes,
    _handle_time_ranges,
    _handle_reports,
    _handle_generate,
    _handle_schedules,
    _handle_schedule_create,
    _handle_frequencies,
    _handle_formats,
    _handle_templates,
    _handle_metrics,
    _handle_status,
    _get_sample_dashboards,
    _get_sample_reports,
    _get_sample_schedules,
)


class TestAddDashboardsParser:
    """Tests for add_dashboards_parser function."""

    def test_parser_is_added(self):
        """Test that dashboards parser is added to subparsers."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "status"])
        assert args.command == "dashboards"
        assert args.dashboards_command == "status"

    def test_list_subcommand(self):
        """Test list subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "list", "--format", "json"])
        assert args.dashboards_command == "list"
        assert args.format == "json"

    def test_list_with_filters(self):
        """Test list subcommand with filters."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "list", "--owner", "security-team", "--tag", "executive"])
        assert args.owner == "security-team"
        assert args.tag == "executive"

    def test_show_subcommand(self):
        """Test show subcommand with dashboard ID."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "show", "dash-001"])
        assert args.dashboards_command == "show"
        assert args.dashboard_id == "dash-001"

    def test_create_subcommand(self):
        """Test create subcommand with required name."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args([
            "dashboards", "create",
            "--name", "My Dashboard",
            "--template", "executive",
            "--theme", "dark"
        ])
        assert args.dashboards_command == "create"
        assert args.name == "My Dashboard"
        assert args.template == "executive"
        assert args.theme == "dark"

    def test_widgets_subcommand(self):
        """Test widgets subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "widgets"])
        assert args.dashboards_command == "widgets"

    def test_charts_subcommand(self):
        """Test charts subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "charts"])
        assert args.dashboards_command == "charts"

    def test_themes_subcommand(self):
        """Test themes subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "themes"])
        assert args.dashboards_command == "themes"

    def test_time_ranges_subcommand(self):
        """Test time-ranges subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "time-ranges"])
        assert args.dashboards_command == "time-ranges"

    def test_reports_subcommand(self):
        """Test reports subcommand with filters."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "reports", "--limit", "10", "--format-filter", "pdf"])
        assert args.dashboards_command == "reports"
        assert args.limit == 10
        assert args.format_filter == "pdf"

    def test_generate_subcommand(self):
        """Test generate subcommand with options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args([
            "dashboards", "generate",
            "--title", "Weekly Report",
            "--template", "compliance",
            "--output-format", "html"
        ])
        assert args.dashboards_command == "generate"
        assert args.title == "Weekly Report"
        assert args.template == "compliance"
        assert args.output_format == "html"

    def test_schedules_subcommand(self):
        """Test schedules subcommand with enabled-only filter."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "schedules", "--enabled-only"])
        assert args.dashboards_command == "schedules"
        assert args.enabled_only is True

    def test_schedule_create_subcommand(self):
        """Test schedule-create subcommand with options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args([
            "dashboards", "schedule-create",
            "--name", "Weekly Report",
            "--frequency", "weekly",
            "--recipients", "user@example.com"
        ])
        assert args.dashboards_command == "schedule-create"
        assert args.name == "Weekly Report"
        assert args.frequency == "weekly"
        assert args.recipients == "user@example.com"

    def test_frequencies_subcommand(self):
        """Test frequencies subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "frequencies"])
        assert args.dashboards_command == "frequencies"

    def test_formats_subcommand(self):
        """Test formats subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "formats"])
        assert args.dashboards_command == "formats"

    def test_templates_subcommand(self):
        """Test templates subcommand is available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "templates"])
        assert args.dashboards_command == "templates"

    def test_metrics_subcommand(self):
        """Test metrics subcommand with time range."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_dashboards_parser(subparsers)

        args = parser.parse_args(["dashboards", "metrics", "--time-range", "last_30_days"])
        assert args.dashboards_command == "metrics"
        assert args.time_range == "last_30_days"


class TestCmdDashboards:
    """Tests for cmd_dashboards main handler."""

    def test_no_command_returns_error(self):
        """Test that no subcommand returns error."""
        args = argparse.Namespace(dashboards_command=None)
        result = cmd_dashboards(args)
        assert result == 1

    def test_unknown_command_returns_error(self):
        """Test that unknown command returns error."""
        args = argparse.Namespace(dashboards_command="unknown")
        result = cmd_dashboards(args)
        assert result == 1

    def test_status_command_succeeds(self):
        """Test that status command succeeds."""
        args = argparse.Namespace(dashboards_command="status", format="table")
        result = cmd_dashboards(args)
        assert result == 0

    def test_list_command_succeeds(self):
        """Test that list command succeeds."""
        args = argparse.Namespace(dashboards_command="list", format="table", owner=None, tag=None)
        result = cmd_dashboards(args)
        assert result == 0


class TestHandleList:
    """Tests for _handle_list handler."""

    def test_table_format(self):
        """Test list output in table format."""
        args = argparse.Namespace(format="table", owner=None, tag=None)
        result = _handle_list(args)
        assert result == 0

    def test_json_format(self):
        """Test list output in JSON format."""
        args = argparse.Namespace(format="json", owner=None, tag=None)
        result = _handle_list(args)
        assert result == 0

    def test_filter_by_owner(self):
        """Test filtering by owner."""
        args = argparse.Namespace(format="json", owner="security-team", tag=None)
        result = _handle_list(args)
        assert result == 0

    def test_filter_by_tag(self):
        """Test filtering by tag."""
        args = argparse.Namespace(format="json", owner=None, tag="executive")
        result = _handle_list(args)
        assert result == 0


class TestHandleShow:
    """Tests for _handle_show handler."""

    def test_show_existing_dashboard(self):
        """Test showing an existing dashboard."""
        args = argparse.Namespace(dashboard_id="dash-exec-001", format="table")
        result = _handle_show(args)
        assert result == 0

    def test_show_nonexistent_dashboard(self):
        """Test showing a non-existent dashboard."""
        args = argparse.Namespace(dashboard_id="nonexistent", format="table")
        result = _handle_show(args)
        assert result == 1


class TestHandleCreate:
    """Tests for _handle_create handler."""

    def test_create_dashboard(self):
        """Test creating a new dashboard."""
        args = argparse.Namespace(
            name="Test Dashboard",
            template="security_ops",
            description="Test description",
            theme="dark",
            format="table"
        )
        result = _handle_create(args)
        assert result == 0

    def test_create_dashboard_json_format(self):
        """Test creating a dashboard with JSON output."""
        args = argparse.Namespace(
            name="Test Dashboard",
            template="executive",
            description="",
            theme="light",
            format="json"
        )
        result = _handle_create(args)
        assert result == 0


class TestHandleWidgets:
    """Tests for _handle_widgets handler."""

    def test_widgets_table_format(self):
        """Test widgets output in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_widgets(args)
        assert result == 0

    def test_widgets_json_format(self):
        """Test widgets output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_widgets(args)
        assert result == 0


class TestHandleCharts:
    """Tests for _handle_charts handler."""

    def test_charts_table_format(self):
        """Test charts output in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_charts(args)
        assert result == 0

    def test_charts_json_format(self):
        """Test charts output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_charts(args)
        assert result == 0


class TestHandleThemes:
    """Tests for _handle_themes handler."""

    def test_themes_table_format(self):
        """Test themes output in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_themes(args)
        assert result == 0

    def test_themes_json_format(self):
        """Test themes output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_themes(args)
        assert result == 0


class TestHandleTimeRanges:
    """Tests for _handle_time_ranges handler."""

    def test_time_ranges_table_format(self):
        """Test time ranges output in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_time_ranges(args)
        assert result == 0

    def test_time_ranges_json_format(self):
        """Test time ranges output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_time_ranges(args)
        assert result == 0


class TestHandleReports:
    """Tests for _handle_reports handler."""

    def test_reports_table_format(self):
        """Test reports output in table format."""
        args = argparse.Namespace(format="table", limit=20, format_filter=None)
        result = _handle_reports(args)
        assert result == 0

    def test_reports_json_format(self):
        """Test reports output in JSON format."""
        args = argparse.Namespace(format="json", limit=10, format_filter=None)
        result = _handle_reports(args)
        assert result == 0

    def test_reports_with_format_filter(self):
        """Test reports with format filter."""
        args = argparse.Namespace(format="json", limit=20, format_filter="pdf")
        result = _handle_reports(args)
        assert result == 0


class TestHandleGenerate:
    """Tests for _handle_generate handler."""

    def test_generate_report(self):
        """Test generating a report."""
        args = argparse.Namespace(
            title="Test Report",
            template="executive_summary",
            output_format="pdf",
            time_range="last_30_days",
            output=None,
            format="table"
        )
        result = _handle_generate(args)
        assert result == 0

    def test_generate_report_with_output(self):
        """Test generating a report with output file."""
        args = argparse.Namespace(
            title="Test Report",
            template="compliance",
            output_format="html",
            time_range="last_7_days",
            output="/tmp/report.html",
            format="json"
        )
        result = _handle_generate(args)
        assert result == 0


class TestHandleSchedules:
    """Tests for _handle_schedules handler."""

    def test_schedules_table_format(self):
        """Test schedules output in table format."""
        args = argparse.Namespace(format="table", enabled_only=False)
        result = _handle_schedules(args)
        assert result == 0

    def test_schedules_json_format(self):
        """Test schedules output in JSON format."""
        args = argparse.Namespace(format="json", enabled_only=False)
        result = _handle_schedules(args)
        assert result == 0

    def test_schedules_enabled_only(self):
        """Test schedules with enabled-only filter."""
        args = argparse.Namespace(format="json", enabled_only=True)
        result = _handle_schedules(args)
        assert result == 0


class TestHandleScheduleCreate:
    """Tests for _handle_schedule_create handler."""

    def test_create_schedule(self):
        """Test creating a scheduled report."""
        args = argparse.Namespace(
            name="Weekly Report",
            template="executive_summary",
            frequency="weekly",
            output_format="pdf",
            recipients="user@example.com",
            format="table"
        )
        result = _handle_schedule_create(args)
        assert result == 0

    def test_create_schedule_without_recipients(self):
        """Test creating a schedule without recipients."""
        args = argparse.Namespace(
            name="Daily Report",
            template="technical_detail",
            frequency="daily",
            output_format="html",
            recipients=None,
            format="json"
        )
        result = _handle_schedule_create(args)
        assert result == 0


class TestHandleFrequencies:
    """Tests for _handle_frequencies handler."""

    def test_frequencies_table_format(self):
        """Test frequencies output in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_frequencies(args)
        assert result == 0

    def test_frequencies_json_format(self):
        """Test frequencies output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_frequencies(args)
        assert result == 0


class TestHandleFormats:
    """Tests for _handle_formats handler."""

    def test_formats_table_format(self):
        """Test formats output in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_formats(args)
        assert result == 0

    def test_formats_json_format(self):
        """Test formats output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_formats(args)
        assert result == 0


class TestHandleTemplates:
    """Tests for _handle_templates handler."""

    def test_templates_table_format(self):
        """Test templates output in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_templates(args)
        assert result == 0

    def test_templates_json_format(self):
        """Test templates output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_templates(args)
        assert result == 0


class TestHandleMetrics:
    """Tests for _handle_metrics handler."""

    def test_metrics_table_format(self):
        """Test metrics output in table format."""
        args = argparse.Namespace(format="table", time_range="last_7_days")
        result = _handle_metrics(args)
        assert result == 0

    def test_metrics_json_format(self):
        """Test metrics output in JSON format."""
        args = argparse.Namespace(format="json", time_range="last_30_days")
        result = _handle_metrics(args)
        assert result == 0


class TestHandleStatus:
    """Tests for _handle_status handler."""

    def test_status_table_format(self):
        """Test status output in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_status(args)
        assert result == 0

    def test_status_json_format(self):
        """Test status output in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0


class TestSampleDataFunctions:
    """Tests for sample data functions."""

    def test_get_sample_dashboards(self):
        """Test getting sample dashboards."""
        dashboards = _get_sample_dashboards()
        assert len(dashboards) > 0
        assert all("id" in d for d in dashboards)
        assert all("name" in d for d in dashboards)

    def test_get_sample_reports(self):
        """Test getting sample reports."""
        reports = _get_sample_reports()
        assert len(reports) > 0
        assert all("id" in r for r in reports)
        assert all("title" in r for r in reports)

    def test_get_sample_schedules(self):
        """Test getting sample schedules."""
        schedules = _get_sample_schedules()
        assert len(schedules) > 0
        assert all("id" in s for s in schedules)
        assert all("name" in s for s in schedules)
        assert all("frequency" in s for s in schedules)


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_dashboard_id_show(self):
        """Test show with empty dashboard ID still works."""
        args = argparse.Namespace(dashboard_id="", format="table")
        # Should return 1 for not found
        result = _handle_show(args)
        assert result == 1

    def test_special_characters_in_name(self):
        """Test creating dashboard with special characters in name."""
        args = argparse.Namespace(
            name="Test Dashboard <>&\"'",
            template="custom",
            description="Test with special chars",
            theme="light",
            format="json"
        )
        result = _handle_create(args)
        assert result == 0

    def test_multiple_recipients(self):
        """Test schedule creation with multiple recipients."""
        args = argparse.Namespace(
            name="Multi-recipient Report",
            template="executive_summary",
            frequency="weekly",
            output_format="pdf",
            recipients="user1@example.com,user2@example.com,user3@example.com",
            format="json"
        )
        result = _handle_schedule_create(args)
        assert result == 0
