"""
Unit tests for CLI infrastructure modules.

Tests for:
- CliFormatter: Unified output formatting
- ParserBuilder: Argument standardization
- CommandRegistry: Command routing
- Decorators: Error handling and validation
- BaseCommand: Base command class
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from enum import Enum
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_utils.formatters import (
    CliFormatter,
    OutputFormat,
    TableConfig,
    format_assets_table,
    format_findings_table,
)
from stance.cli_utils.parser_builder import ParserBuilder, create_subparser
from stance.cli_utils.command_registry import (
    CommandRegistry,
    NestedCommandRegistry,
    create_registry_from_module,
)
from stance.cli_utils.decorators import (
    cli_command,
    require_storage,
    require_scan_data,
    validate_args,
    requires_confirmation,
    with_output_handling,
)
from stance.cli_utils.base_command import BaseCommand, ListCommand


# =============================================================================
# CliFormatter Tests
# =============================================================================


class TestCliFormatter:
    """Tests for CliFormatter class."""

    def test_format_empty_list_table(self):
        """Test formatting empty list as table."""
        result = CliFormatter.format([], "table")
        assert result == "No data to display."

    def test_format_empty_list_json(self):
        """Test formatting empty list as JSON."""
        result = CliFormatter.format([], "json")
        assert json.loads(result) == []

    def test_format_empty_dict_json(self):
        """Test formatting empty dict as JSON."""
        result = CliFormatter.format({}, "json")
        assert json.loads(result) == {}

    def test_format_single_dict_json(self):
        """Test formatting single dict as JSON."""
        data = {"name": "test", "value": 42}
        result = CliFormatter.format(data, "json")
        parsed = json.loads(result)
        assert parsed == data

    def test_format_list_of_dicts_json(self):
        """Test formatting list of dicts as JSON."""
        data = [
            {"name": "item1", "value": 1},
            {"name": "item2", "value": 2},
        ]
        result = CliFormatter.format(data, "json")
        parsed = json.loads(result)
        assert parsed == data

    def test_format_list_of_dicts_table(self):
        """Test formatting list of dicts as table."""
        data = [
            {"name": "alice", "age": 30},
            {"name": "bob", "age": 25},
        ]
        result = CliFormatter.format(data, "table")
        assert "name" in result
        assert "age" in result
        assert "alice" in result
        assert "bob" in result
        # Check separator line exists
        assert "---" in result

    def test_format_list_of_dicts_csv(self):
        """Test formatting list of dicts as CSV."""
        data = [
            {"name": "alice", "age": 30},
            {"name": "bob", "age": 25},
        ]
        result = CliFormatter.format(data, "csv")
        assert "name,age" in result
        assert "alice,30" in result
        assert "bob,25" in result

    def test_format_with_datetime(self):
        """Test formatting data with datetime values."""
        dt = datetime(2025, 1, 15, 10, 30, 0)
        data = [{"timestamp": dt, "value": 100}]
        result = CliFormatter.format(data, "json")
        parsed = json.loads(result)
        assert parsed["timestamp"] == dt.isoformat()

    def test_format_with_enum(self):
        """Test formatting data with enum values."""

        class Status(Enum):
            ACTIVE = "active"
            INACTIVE = "inactive"

        data = [{"name": "test", "status": Status.ACTIVE}]
        result = CliFormatter.format(data, "json")
        parsed = json.loads(result)
        assert parsed["status"] == "active"

    def test_format_with_include_fields(self):
        """Test formatting with field inclusion filter."""
        data = [{"name": "test", "age": 30, "city": "NYC"}]
        result = CliFormatter.format(data, "json", include_fields=["name", "age"])
        parsed = json.loads(result)
        assert "name" in parsed
        assert "age" in parsed
        assert "city" not in parsed

    def test_format_with_exclude_fields(self):
        """Test formatting with field exclusion filter."""
        data = [{"name": "test", "age": 30, "secret": "hidden"}]
        result = CliFormatter.format(data, "json", exclude_fields=["secret"])
        parsed = json.loads(result)
        assert "name" in parsed
        assert "secret" not in parsed

    def test_format_with_sort(self):
        """Test formatting with sorting."""
        data = [
            {"name": "charlie", "score": 85},
            {"name": "alice", "score": 90},
            {"name": "bob", "score": 80},
        ]
        result = CliFormatter.format(data, "json", sort_by="name")
        parsed = json.loads(result)
        assert parsed[0]["name"] == "alice"
        assert parsed[1]["name"] == "bob"
        assert parsed[2]["name"] == "charlie"

    def test_format_with_sort_reverse(self):
        """Test formatting with reverse sorting."""
        data = [
            {"name": "alice", "score": 90},
            {"name": "bob", "score": 80},
        ]
        result = CliFormatter.format(data, "json", sort_by="score", sort_reverse=True)
        parsed = json.loads(result)
        assert parsed[0]["score"] == 90

    def test_format_output_format_enum(self):
        """Test using OutputFormat enum."""
        data = [{"x": 1}]
        result = CliFormatter.format(data, OutputFormat.JSON)
        assert json.loads(result)["x"] == 1

    def test_truncate_short_string(self):
        """Test truncate with string shorter than max."""
        result = CliFormatter.truncate("short", 10)
        assert result == "short"

    def test_truncate_long_string(self):
        """Test truncate with string longer than max."""
        result = CliFormatter.truncate("this is a very long string", 10)
        assert len(result) == 10
        assert result.endswith("...")

    def test_truncate_exact_length(self):
        """Test truncate with string exactly at max."""
        result = CliFormatter.truncate("exactly10!", 10)
        assert result == "exactly10!"

    def test_truncate_custom_suffix(self):
        """Test truncate with custom suffix."""
        result = CliFormatter.truncate("very long string", 10, suffix="~")
        assert result.endswith("~")
        assert len(result) == 10

    def test_format_value_none(self):
        """Test format_value with None."""
        result = CliFormatter.format_value(None)
        assert result == "-"

    def test_format_value_bool_true(self):
        """Test format_value with True."""
        result = CliFormatter.format_value(True, "bool")
        assert result == "Yes"

    def test_format_value_bool_false(self):
        """Test format_value with False."""
        result = CliFormatter.format_value(False, "bool")
        assert result == "No"

    def test_format_value_datetime(self):
        """Test format_value with datetime."""
        dt = datetime(2025, 1, 15, 10, 30, 0)
        result = CliFormatter.format_value(dt)
        assert "2025-01-15" in result
        assert "10:30:00" in result

    def test_format_value_list(self):
        """Test format_value with list."""
        result = CliFormatter.format_value(["a", "b", "c"])
        assert "a" in result
        assert "b" in result
        assert "c" in result

    def test_format_value_long_list(self):
        """Test format_value with long list shows count."""
        result = CliFormatter.format_value(["a", "b", "c", "d", "e"])
        assert "(+2 more)" in result

    def test_format_error_table(self):
        """Test format_error for table output."""
        result = CliFormatter.format_error("Something went wrong", "table")
        assert result == "Error: Something went wrong"

    def test_format_error_json(self):
        """Test format_error for JSON output."""
        result = CliFormatter.format_error("Something went wrong", "json")
        parsed = json.loads(result)
        assert parsed["error"] == "Something went wrong"

    def test_format_success_table(self):
        """Test format_success for table output."""
        result = CliFormatter.format_success("Operation completed", "table")
        assert result == "Success: Operation completed"

    def test_format_success_json(self):
        """Test format_success for JSON output."""
        result = CliFormatter.format_success("Operation completed", "json")
        parsed = json.loads(result)
        assert parsed["status"] == "success"
        assert parsed["message"] == "Operation completed"


class TestTableConfig:
    """Tests for TableConfig class."""

    def test_default_values(self):
        """Test default configuration values."""
        config = TableConfig()
        assert config.max_column_width == 50
        assert config.min_column_width == 5
        assert config.truncate_suffix == "..."
        assert config.show_row_numbers is False

    def test_custom_values(self):
        """Test custom configuration values."""
        config = TableConfig(
            max_column_width=30,
            min_column_width=10,
            show_row_numbers=True,
        )
        assert config.max_column_width == 30
        assert config.min_column_width == 10
        assert config.show_row_numbers is True

    def test_column_widths(self):
        """Test custom column widths."""
        config = TableConfig(column_widths={"name": 20, "id": 15})
        assert config.column_widths["name"] == 20
        assert config.column_widths["id"] == 15

    def test_column_alignments(self):
        """Test column alignments."""
        config = TableConfig(column_alignments={"score": "right", "name": "left"})
        assert config.column_alignments["score"] == "right"


class TestFormatHelpers:
    """Tests for format helper functions."""

    def test_format_findings_table_empty(self):
        """Test format_findings_table with empty list."""
        result = format_findings_table([])
        assert "No data" in result

    def test_format_findings_table_with_data(self):
        """Test format_findings_table with data."""

        class MockFinding:
            id = "finding-123"
            title = "Test Finding"

            class severity:
                value = "HIGH"

            class status:
                value = "OPEN"

            resource_path = "aws/s3/bucket"

        result = format_findings_table([MockFinding()])
        assert "finding-123" in result
        assert "Test Finding" in result
        assert "HIGH" in result

    def test_format_assets_table_empty(self):
        """Test format_assets_table with empty list."""
        result = format_assets_table([])
        assert "No data" in result

    def test_format_assets_table_with_data(self):
        """Test format_assets_table with data."""

        class MockAsset:
            id = "asset-456"
            name = "my-bucket"
            resource_type = "aws_s3_bucket"
            cloud_provider = "aws"
            region = "us-east-1"

        result = format_assets_table([MockAsset()])
        assert "asset-456" in result
        assert "my-bucket" in result
        assert "aws" in result


# =============================================================================
# ParserBuilder Tests
# =============================================================================


class TestParserBuilder:
    """Tests for ParserBuilder class."""

    @pytest.fixture
    def parser(self):
        """Create a test argument parser."""
        return argparse.ArgumentParser()

    def test_add_format_argument(self, parser):
        """Test adding format argument."""
        ParserBuilder.add_format_argument(parser)
        args = parser.parse_args([])
        assert args.format == "table"

    def test_add_format_argument_json(self, parser):
        """Test format argument with JSON value."""
        ParserBuilder.add_format_argument(parser)
        args = parser.parse_args(["--format", "json"])
        assert args.format == "json"

    def test_add_format_argument_short(self, parser):
        """Test format argument with short flag."""
        ParserBuilder.add_format_argument(parser)
        args = parser.parse_args(["-f", "csv"])
        assert args.format == "csv"

    def test_add_format_argument_custom_choices(self, parser):
        """Test format argument with custom choices."""
        ParserBuilder.add_format_argument(parser, choices=["table", "json"])
        with pytest.raises(SystemExit):
            parser.parse_args(["--format", "csv"])

    def test_add_limit_argument(self, parser):
        """Test adding limit argument."""
        ParserBuilder.add_limit_argument(parser)
        args = parser.parse_args([])
        assert args.limit == 100

    def test_add_limit_argument_custom(self, parser):
        """Test limit argument with custom value."""
        ParserBuilder.add_limit_argument(parser)
        args = parser.parse_args(["--limit", "50"])
        assert args.limit == 50

    def test_add_output_argument(self, parser):
        """Test adding output argument."""
        ParserBuilder.add_output_argument(parser)
        args = parser.parse_args(["--output", "/tmp/out.json"])
        assert args.output == "/tmp/out.json"

    def test_add_storage_argument(self, parser):
        """Test adding storage argument."""
        ParserBuilder.add_storage_argument(parser)
        args = parser.parse_args([])
        assert args.storage == "local"

    def test_add_storage_argument_s3(self, parser):
        """Test storage argument with S3."""
        ParserBuilder.add_storage_argument(parser)
        args = parser.parse_args(["--storage", "s3"])
        assert args.storage == "s3"

    def test_add_filter_argument(self, parser):
        """Test adding filter argument."""
        ParserBuilder.add_filter_argument(parser)
        args = parser.parse_args(["--filter", "severity==HIGH"])
        assert args.filter == "severity==HIGH"

    def test_add_verbose_argument(self, parser):
        """Test adding verbose argument."""
        ParserBuilder.add_verbose_argument(parser)
        args = parser.parse_args(["-v"])
        assert args.verbose is True

    def test_add_quiet_argument(self, parser):
        """Test adding quiet argument."""
        ParserBuilder.add_quiet_argument(parser)
        args = parser.parse_args(["-q"])
        assert args.quiet is True

    def test_add_severity_argument(self, parser):
        """Test adding severity argument."""
        ParserBuilder.add_severity_argument(parser)
        args = parser.parse_args(["--severity", "high"])
        assert args.severity == "high"

    def test_add_status_argument(self, parser):
        """Test adding status argument."""
        ParserBuilder.add_status_argument(parser)
        args = parser.parse_args(["--status", "open"])
        assert args.status == "open"

    def test_add_dry_run_argument(self, parser):
        """Test adding dry-run argument."""
        ParserBuilder.add_dry_run_argument(parser)
        args = parser.parse_args(["--dry-run"])
        assert args.dry_run is True

    def test_add_common_list_arguments(self, parser):
        """Test adding common list arguments."""
        ParserBuilder.add_common_list_arguments(parser)
        args = parser.parse_args([])
        assert hasattr(args, "format")
        assert hasattr(args, "limit")
        assert hasattr(args, "filter")
        assert hasattr(args, "sort")
        assert hasattr(args, "output")

    def test_builder_pattern(self, parser):
        """Test using builder pattern."""
        builder = ParserBuilder(parser)
        builder.add_format().add_limit().add_output()
        args = parser.parse_args([])
        assert args.format == "table"
        assert args.limit == 100
        assert args.output is None


class TestCreateSubparser:
    """Tests for create_subparser function."""

    def test_create_subparser(self):
        """Test creating a subparser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        sub = create_subparser(subparsers, "test", "Test command")
        assert sub is not None

    def test_create_subparser_with_handler(self):
        """Test creating a subparser with handler."""

        def handler(args):
            return 0

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        sub = create_subparser(subparsers, "test", "Test command", handler=handler)
        args = parser.parse_args(["test"])
        assert args.func == handler


# =============================================================================
# CommandRegistry Tests
# =============================================================================


class TestCommandRegistry:
    """Tests for CommandRegistry class."""

    def test_register_command(self):
        """Test registering a command."""
        registry = CommandRegistry()
        handler = lambda args: 0
        registry.register("test", handler)
        assert "test" in registry

    def test_route_to_handler(self):
        """Test routing to registered handler."""
        registry = CommandRegistry()
        called = []

        def handler(args):
            called.append(True)
            return 0

        registry.register("test", handler)
        args = argparse.Namespace(action="test")
        result = registry.route(args)
        assert result == 0
        assert len(called) == 1

    def test_route_with_alias(self):
        """Test routing with alias."""
        registry = CommandRegistry()
        handler = lambda args: 42
        registry.register("list", handler, aliases=["ls", "l"])
        args = argparse.Namespace(action="ls")
        result = registry.route(args)
        assert result == 42

    def test_route_unknown_action(self):
        """Test routing with unknown action."""
        registry = CommandRegistry()
        args = argparse.Namespace(action="unknown")
        result = registry.route(args)
        assert result == 1

    def test_route_no_action(self):
        """Test routing with no action."""
        registry = CommandRegistry()
        args = argparse.Namespace(action=None)
        result = registry.route(args)
        assert result == 1

    def test_route_default_handler(self):
        """Test routing with default handler."""
        registry = CommandRegistry(default_handler=lambda args: 99)
        args = argparse.Namespace(action=None)
        result = registry.route(args)
        assert result == 99

    def test_route_custom_action_attr(self):
        """Test routing with custom action attribute."""
        registry = CommandRegistry()
        registry.register("show", lambda args: 5)
        args = argparse.Namespace(subcommand="show")
        result = registry.route(args, action_attr="subcommand")
        assert result == 5

    def test_unregister_command(self):
        """Test unregistering a command."""
        registry = CommandRegistry()
        registry.register("test", lambda args: 0)
        assert "test" in registry
        registry.unregister("test")
        assert "test" not in registry

    def test_list_commands(self):
        """Test listing registered commands."""
        registry = CommandRegistry()
        registry.register("list", lambda args: 0)
        registry.register("show", lambda args: 0)
        commands = registry.list_commands()
        assert "list" in commands
        assert "show" in commands

    def test_get_handler(self):
        """Test getting handler by name."""
        registry = CommandRegistry()
        handler = lambda args: 0
        registry.register("test", handler)
        assert registry.get_handler("test") == handler

    def test_get_handler_not_found(self):
        """Test getting non-existent handler."""
        registry = CommandRegistry()
        assert registry.get_handler("missing") is None

    def test_builder_pattern(self):
        """Test using builder pattern for registration."""
        registry = (
            CommandRegistry()
            .register("list", lambda args: 1)
            .register("show", lambda args: 2)
            .set_default(lambda args: 0)
        )
        assert "list" in registry
        assert "show" in registry

    def test_register_subcommand(self):
        """Test registering subcommands."""
        registry = CommandRegistry()
        registry.register("users", lambda args: 0)
        registry.register_subcommand("users", "list", lambda args: 10)
        registry.register_subcommand("users", "create", lambda args: 20)

        # Route to parent
        args = argparse.Namespace(action="users", sub_action=None)
        result = registry.route(args)
        assert result == 0

        # Route to subcommand
        args = argparse.Namespace(action="users", sub_action="list")
        result = registry.route(args, subaction_attr="sub_action")
        assert result == 10


class TestNestedCommandRegistry:
    """Tests for NestedCommandRegistry class."""

    def test_register_nested_command(self):
        """Test registering nested commands."""
        registry = NestedCommandRegistry()
        registry.register(["auth", "users", "list"], lambda args: 1)
        registry.register(["auth", "users", "create"], lambda args: 2)
        registry.register(["auth", "status"], lambda args: 3)

        # Route to nested command
        args = argparse.Namespace(auth_action="users", users_action="list")
        result = registry.route(args, ["auth_action", "users_action"])
        assert result == 1

    def test_register_with_default(self):
        """Test nested registry with defaults."""
        registry = NestedCommandRegistry()
        registry.register(["scan", "full"], lambda args: 1)
        registry.set_default(["scan"], lambda args: 99)

        # Route with missing subaction uses default
        args = argparse.Namespace(action="scan", subaction=None)
        result = registry.route(args, ["action", "subaction"])
        assert result == 99


class TestCreateRegistryFromModule:
    """Tests for create_registry_from_module function."""

    def test_auto_register_from_module(self):
        """Test auto-registering commands from module."""

        # Create mock module
        class MockModule:
            @staticmethod
            def cmd_list(args):
                return 1

            @staticmethod
            def cmd_show(args):
                return 2

            @staticmethod
            def other_function(args):
                return 3

        registry = create_registry_from_module(MockModule)
        assert "list" in registry
        assert "show" in registry
        assert "other_function" not in registry


# =============================================================================
# Decorators Tests
# =============================================================================


class TestCliCommandDecorator:
    """Tests for cli_command decorator."""

    def test_successful_command(self):
        """Test decorator with successful command."""

        @cli_command
        def cmd_test(args):
            return 0

        args = argparse.Namespace(format="table")
        result = cmd_test(args)
        assert result == 0

    def test_exception_handling(self, capsys):
        """Test decorator catches exceptions."""

        @cli_command
        def cmd_test(args):
            raise ValueError("test error")

        args = argparse.Namespace(format="table")
        result = cmd_test(args)
        assert result == 1
        captured = capsys.readouterr()
        assert "test error" in captured.err

    def test_exception_json_format(self, capsys):
        """Test decorator outputs JSON error for JSON format."""

        @cli_command
        def cmd_test(args):
            raise ValueError("json error")

        args = argparse.Namespace(format="json")
        result = cmd_test(args)
        assert result == 1
        captured = capsys.readouterr()
        # JSON error goes to stdout for JSON format (multi-line formatted)
        output = captured.out
        assert "json error" in output
        # Parse the complete JSON block
        lines = output.split("\n")
        json_lines = []
        in_json = False
        for line in lines:
            if line.strip().startswith("{"):
                in_json = True
            if in_json:
                json_lines.append(line)
            if in_json and line.strip() == "}":
                break
        json_str = "\n".join(json_lines)
        error_data = json.loads(json_str)
        assert error_data["error"] == "json error"


class TestRequireStorageDecorator:
    """Tests for require_storage decorator."""

    def test_storage_passed_to_handler(self):
        """Test storage is passed to handler."""
        mock_storage = MagicMock()

        @require_storage(lambda args: mock_storage)
        def cmd_test(args, storage):
            assert storage == mock_storage
            return 0

        args = argparse.Namespace()
        result = cmd_test(args)
        assert result == 0


class TestValidateArgsDecorator:
    """Tests for validate_args decorator."""

    def test_valid_args(self):
        """Test with valid arguments."""

        @validate_args({"port": lambda p: True if 1 <= p <= 65535 else "Invalid port"})
        def cmd_test(args):
            return 0

        args = argparse.Namespace(port=8080, format="table")
        result = cmd_test(args)
        assert result == 0

    def test_invalid_args(self, capsys):
        """Test with invalid arguments."""

        @validate_args({"port": lambda p: True if 1 <= p <= 65535 else "Invalid port"})
        def cmd_test(args):
            return 0

        args = argparse.Namespace(port=99999, format="table")
        result = cmd_test(args)
        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid port" in captured.err


class TestRequiresConfirmationDecorator:
    """Tests for requires_confirmation decorator."""

    def test_skip_with_yes_flag(self):
        """Test confirmation is skipped with --yes flag."""

        @requires_confirmation("Are you sure?")
        def cmd_test(args):
            return 0

        args = argparse.Namespace(yes=True)
        result = cmd_test(args)
        assert result == 0

    def test_skip_with_force_flag(self):
        """Test confirmation is skipped with --force flag."""

        @requires_confirmation("Are you sure?")
        def cmd_test(args):
            return 0

        args = argparse.Namespace(yes=False, force=True)
        result = cmd_test(args)
        assert result == 0


# =============================================================================
# BaseCommand Tests
# =============================================================================


class TestBaseCommand:
    """Tests for BaseCommand class."""

    def test_format_property(self):
        """Test format property."""

        class TestCommand(BaseCommand):
            def execute(self):
                return 0

        args = argparse.Namespace(format="json")
        cmd = TestCommand(args)
        assert cmd.format == "json"

    def test_format_default(self):
        """Test format default value."""

        class TestCommand(BaseCommand):
            def execute(self):
                return 0

        args = argparse.Namespace()
        cmd = TestCommand(args)
        assert cmd.format == "table"

    def test_verbose_property(self):
        """Test verbose property."""

        class TestCommand(BaseCommand):
            def execute(self):
                return 0

        args = argparse.Namespace(verbose=True)
        cmd = TestCommand(args)
        assert cmd.verbose is True

    def test_output_method(self, capsys):
        """Test output method."""

        class TestCommand(BaseCommand):
            def execute(self):
                self.output([{"name": "test"}])
                return 0

        args = argparse.Namespace(format="json", output=None)
        cmd = TestCommand(args)
        cmd.execute()
        captured = capsys.readouterr()
        assert '"name": "test"' in captured.out

    def test_error_method(self, capsys):
        """Test error method."""

        class TestCommand(BaseCommand):
            def execute(self):
                return self.error("Something went wrong")

        args = argparse.Namespace(format="table", output=None)
        cmd = TestCommand(args)
        result = cmd.execute()
        assert result == 1
        captured = capsys.readouterr()
        assert "Something went wrong" in captured.err

    def test_success_method(self, capsys):
        """Test success method."""

        class TestCommand(BaseCommand):
            def execute(self):
                self.success("Done!")
                return 0

        args = argparse.Namespace(format="table", quiet=False, output=None)
        cmd = TestCommand(args)
        cmd.execute()
        captured = capsys.readouterr()
        assert "Done!" in captured.out

    def test_info_suppressed_for_json(self, capsys):
        """Test info is suppressed for JSON format."""

        class TestCommand(BaseCommand):
            def execute(self):
                self.info("Info message")
                return 0

        args = argparse.Namespace(format="json", quiet=False, output=None)
        cmd = TestCommand(args)
        cmd.execute()
        captured = capsys.readouterr()
        assert "Info message" not in captured.out

    def test_run_catches_exceptions(self, capsys):
        """Test run() catches exceptions."""

        class TestCommand(BaseCommand):
            def execute(self):
                raise RuntimeError("Oops!")

        args = argparse.Namespace(format="table", output=None)
        cmd = TestCommand(args)
        result = cmd.run()
        assert result == 1
        captured = capsys.readouterr()
        assert "Oops!" in captured.err


class TestListCommand:
    """Tests for ListCommand class."""

    def test_filter_data(self):
        """Test filter_data method."""

        class TestCommand(ListCommand):
            def execute(self):
                return 0

        args = argparse.Namespace(filter="name==alice", format="table", output=None)
        cmd = TestCommand(args)
        data = [
            {"name": "alice", "age": 30},
            {"name": "bob", "age": 25},
        ]
        result = cmd.filter_data(data)
        assert len(result) == 1
        assert result[0]["name"] == "alice"

    def test_filter_data_contains(self):
        """Test filter_data with contains operator."""

        class TestCommand(ListCommand):
            def execute(self):
                return 0

        args = argparse.Namespace(filter="name~=ali", format="table", output=None)
        cmd = TestCommand(args)
        data = [
            {"name": "alice", "age": 30},
            {"name": "bob", "age": 25},
        ]
        result = cmd.filter_data(data)
        assert len(result) == 1
        assert result[0]["name"] == "alice"

    def test_sort_data(self):
        """Test sort_data method."""

        class TestCommand(ListCommand):
            def execute(self):
                return 0

        args = argparse.Namespace(sort="name", reverse=False, format="table", output=None)
        cmd = TestCommand(args)
        data = [
            {"name": "charlie"},
            {"name": "alice"},
            {"name": "bob"},
        ]
        result = cmd.sort_data(data)
        assert result[0]["name"] == "alice"
        assert result[1]["name"] == "bob"
        assert result[2]["name"] == "charlie"

    def test_paginate_data(self):
        """Test paginate_data method."""

        class TestCommand(ListCommand):
            def execute(self):
                return 0

        args = argparse.Namespace(limit=2, format="table", output=None)
        cmd = TestCommand(args)
        data = [{"i": 1}, {"i": 2}, {"i": 3}, {"i": 4}]
        result = cmd.paginate_data(data)
        assert len(result) == 2

    def test_process_data_combines_operations(self):
        """Test process_data applies filter, sort, and pagination."""

        class TestCommand(ListCommand):
            def execute(self):
                return 0

        args = argparse.Namespace(
            filter="score>80",
            sort="name",
            reverse=False,
            limit=2,
            format="table",
            output=None,
        )
        cmd = TestCommand(args)
        data = [
            {"name": "charlie", "score": 85},
            {"name": "alice", "score": 90},
            {"name": "bob", "score": 75},  # Filtered out
            {"name": "dave", "score": 95},
        ]
        result = cmd.process_data(data)
        assert len(result) == 2
        assert result[0]["name"] == "alice"
        assert result[1]["name"] == "charlie"
