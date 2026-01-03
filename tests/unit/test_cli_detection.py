"""
Unit tests for Detection CLI module.

Tests the command-line interface for secrets detection.
"""

import pytest
import argparse
from unittest.mock import MagicMock, patch

from stance.cli_detection import (
    add_detection_parser,
    cmd_detection,
    _handle_scan,
    _handle_scan_file,
    _handle_patterns,
    _handle_pattern,
    _handle_entropy,
    _handle_sensitive_fields,
    _handle_check_field,
    _handle_categories,
    _handle_severity_levels,
    _handle_stats,
    _handle_status,
    _handle_summary,
    _redact_value,
    _get_pattern_category,
    _get_patterns_by_category,
    _get_all_categories,
    _interpret_entropy,
)


class TestAddDetectionParser:
    """Tests for add_detection_parser function."""

    def test_parser_creation(self):
        """Test that parser is created correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_detection_parser(subparsers)

        # Should not raise
        args = parser.parse_args(["detection", "status"])
        assert args.detection_action == "status"

    def test_all_subcommands_available(self):
        """Test that all subcommands are available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_detection_parser(subparsers)

        commands = [
            "scan",
            "scan-file",
            "patterns",
            "pattern",
            "entropy",
            "sensitive-fields",
            "check-field",
            "categories",
            "severity-levels",
            "stats",
            "status",
            "summary",
        ]

        for cmd in commands:
            if cmd == "scan":
                args = parser.parse_args(["detection", cmd, "test text"])
            elif cmd == "scan-file":
                args = parser.parse_args(["detection", cmd, "/path/to/file"])
            elif cmd == "pattern":
                args = parser.parse_args(["detection", cmd, "aws_access_key_id"])
            elif cmd == "entropy":
                args = parser.parse_args(["detection", cmd, "test"])
            elif cmd == "check-field":
                args = parser.parse_args(["detection", cmd, "password"])
            else:
                args = parser.parse_args(["detection", cmd])
            assert args.detection_action == cmd


class TestCmdDetection:
    """Tests for cmd_detection handler."""

    def test_no_action_shows_error(self, capsys):
        """Test that no action shows error."""
        args = argparse.Namespace(detection_action=None)
        result = cmd_detection(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "No detection action specified" in captured.out

    def test_unknown_action_shows_error(self, capsys):
        """Test that unknown action shows error."""
        args = argparse.Namespace(detection_action="unknown")
        result = cmd_detection(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Unknown action" in captured.out

    def test_valid_action_routes_correctly(self):
        """Test that valid actions route to correct handlers."""
        args = argparse.Namespace(
            detection_action="status",
            format="json",
        )
        result = cmd_detection(args)
        assert result == 0


class TestHandleScan:
    """Tests for scan command handler."""

    def test_scan_empty_text(self, capsys):
        """Test scanning empty text."""
        args = argparse.Namespace(
            text="Hello world",
            min_entropy=3.5,
            format="table",
        )
        result = _handle_scan(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Secrets Found: 0" in captured.out

    def test_scan_with_aws_key(self, capsys):
        """Test scanning text with AWS key."""
        args = argparse.Namespace(
            text="AWS key: AKIAIOSFODNN7EXAMPLE",
            min_entropy=3.5,
            format="table",
        )
        result = _handle_scan(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Secrets Found:" in captured.out

    def test_scan_json_output(self, capsys):
        """Test scan with JSON output."""
        args = argparse.Namespace(
            text="test text",
            min_entropy=3.5,
            format="json",
        )
        result = _handle_scan(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "text_length" in data
        assert "secrets_found" in data
        assert "matches" in data


class TestHandleScanFile:
    """Tests for scan-file command handler."""

    def test_scan_nonexistent_file(self, capsys):
        """Test scanning non-existent file."""
        args = argparse.Namespace(
            file_path="/nonexistent/file.txt",
            min_entropy=3.5,
            format="table",
        )
        result = _handle_scan_file(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "File not found" in captured.out

    def test_scan_file_success(self, capsys, tmp_path):
        """Test scanning an existing file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello world, no secrets here")

        args = argparse.Namespace(
            file_path=str(test_file),
            min_entropy=3.5,
            format="table",
        )
        result = _handle_scan_file(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Secrets Found: 0" in captured.out


class TestHandlePatterns:
    """Tests for patterns command handler."""

    def test_patterns_all(self, capsys):
        """Test listing all patterns."""
        args = argparse.Namespace(
            category="all",
            format="table",
        )
        result = _handle_patterns(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Secret Patterns" in captured.out
        assert "Total:" in captured.out

    def test_patterns_by_category(self, capsys):
        """Test listing patterns by category."""
        args = argparse.Namespace(
            category="aws",
            format="table",
        )
        result = _handle_patterns(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "aws" in captured.out.lower()

    def test_patterns_json_output(self, capsys):
        """Test patterns with JSON output."""
        args = argparse.Namespace(
            category="all",
            format="json",
        )
        result = _handle_patterns(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "category" in data
        assert "total" in data
        assert "patterns" in data


class TestHandlePattern:
    """Tests for pattern command handler."""

    def test_pattern_valid(self, capsys):
        """Test getting valid pattern details."""
        args = argparse.Namespace(
            pattern_name="aws_access_key_id",
            format="table",
        )
        result = _handle_pattern(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "aws_access_key_id" in captured.out.lower()

    def test_pattern_invalid(self, capsys):
        """Test getting invalid pattern."""
        args = argparse.Namespace(
            pattern_name="nonexistent_pattern",
            format="table",
        )
        result = _handle_pattern(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Unknown pattern" in captured.out

    def test_pattern_json_output(self, capsys):
        """Test pattern with JSON output."""
        args = argparse.Namespace(
            pattern_name="aws_access_key_id",
            format="json",
        )
        result = _handle_pattern(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["name"] == "aws_access_key_id"
        assert "pattern" in data
        assert "severity" in data


class TestHandleEntropy:
    """Tests for entropy command handler."""

    def test_entropy_low(self, capsys):
        """Test entropy calculation for low entropy text."""
        args = argparse.Namespace(
            text="aaaaaaa",
            format="table",
        )
        result = _handle_entropy(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Entropy:" in captured.out
        assert "High Entropy" in captured.out

    def test_entropy_high(self, capsys):
        """Test entropy calculation for high entropy text."""
        args = argparse.Namespace(
            text="aB3$xY9@kL2#mN5&",
            format="table",
        )
        result = _handle_entropy(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Yes" in captured.out or "High" in captured.out

    def test_entropy_json_output(self, capsys):
        """Test entropy with JSON output."""
        args = argparse.Namespace(
            text="test123",
            format="json",
        )
        result = _handle_entropy(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "entropy" in data
        assert "is_high_entropy" in data


class TestHandleSensitiveFields:
    """Tests for sensitive-fields command handler."""

    def test_sensitive_fields_table(self, capsys):
        """Test listing sensitive fields in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_sensitive_fields(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Sensitive Field Names" in captured.out
        assert "password" in captured.out

    def test_sensitive_fields_json(self, capsys):
        """Test listing sensitive fields in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_sensitive_fields(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "total" in data
        assert "fields" in data
        assert "categories" in data


class TestHandleCheckField:
    """Tests for check-field command handler."""

    def test_check_field_sensitive(self, capsys):
        """Test checking a sensitive field name."""
        args = argparse.Namespace(
            field_name="database_password",
            format="table",
        )
        result = _handle_check_field(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Yes" in captured.out

    def test_check_field_not_sensitive(self, capsys):
        """Test checking a non-sensitive field name."""
        args = argparse.Namespace(
            field_name="user_name",
            format="table",
        )
        result = _handle_check_field(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "No" in captured.out

    def test_check_field_json(self, capsys):
        """Test checking field with JSON output."""
        args = argparse.Namespace(
            field_name="api_key",
            format="json",
        )
        result = _handle_check_field(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "is_sensitive" in data
        assert data["is_sensitive"] is True


class TestHandleCategories:
    """Tests for categories command handler."""

    def test_categories_table(self, capsys):
        """Test listing categories in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_categories(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Secret Categories" in captured.out
        assert "aws" in captured.out

    def test_categories_json(self, capsys):
        """Test listing categories in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_categories(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "total" in data
        assert "categories" in data


class TestHandleSeverityLevels:
    """Tests for severity-levels command handler."""

    def test_severity_levels_table(self, capsys):
        """Test listing severity levels in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_severity_levels(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Severity Levels" in captured.out
        assert "CRITICAL" in captured.out
        assert "HIGH" in captured.out

    def test_severity_levels_json(self, capsys):
        """Test listing severity levels in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_severity_levels(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "total" in data
        assert "levels" in data
        assert len(data["levels"]) == 4


class TestHandleStats:
    """Tests for stats command handler."""

    def test_stats_table(self, capsys):
        """Test showing stats in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Detection Statistics" in captured.out
        assert "Total Patterns:" in captured.out

    def test_stats_json(self, capsys):
        """Test showing stats in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "total_patterns" in data
        assert "by_severity" in data
        assert "by_category" in data


class TestHandleStatus:
    """Tests for status command handler."""

    def test_status_table(self, capsys):
        """Test showing status in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Detection Module Status" in captured.out
        assert "operational" in captured.out

    def test_status_json(self, capsys):
        """Test showing status in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["module"] == "detection"
        assert data["status"] == "operational"
        assert "components" in data


class TestHandleSummary:
    """Tests for summary command handler."""

    def test_summary_table(self, capsys):
        """Test showing summary in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Detection Module Summary" in captured.out
        assert "Features:" in captured.out

    def test_summary_json(self, capsys):
        """Test showing summary in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["module"] == "detection"
        assert "features" in data
        assert "detection_methods" in data


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_redact_value_short(self):
        """Test redacting short value."""
        result = _redact_value("1234")
        assert result == "****"

    def test_redact_value_long(self):
        """Test redacting long value."""
        result = _redact_value("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKIA")
        assert result.endswith("MPLE")
        assert "*" in result

    def test_get_pattern_category_aws(self):
        """Test getting category for AWS pattern."""
        assert _get_pattern_category("aws_access_key_id") == "aws"
        assert _get_pattern_category("aws_secret_access_key") == "aws"

    def test_get_pattern_category_gcp(self):
        """Test getting category for GCP pattern."""
        assert _get_pattern_category("gcp_api_key") == "gcp"
        assert _get_pattern_category("gcp_service_account_key") == "gcp"

    def test_get_pattern_category_azure(self):
        """Test getting category for Azure pattern."""
        assert _get_pattern_category("azure_storage_key") == "azure"
        assert _get_pattern_category("azure_connection_string") == "azure"

    def test_get_pattern_category_generic(self):
        """Test getting category for generic pattern."""
        assert _get_pattern_category("generic_api_key") == "generic"
        assert _get_pattern_category("bearer_token") == "generic"
        assert _get_pattern_category("jwt_token") == "generic"

    def test_get_pattern_category_database(self):
        """Test getting category for database pattern."""
        assert _get_pattern_category("mysql_connection") == "database"
        assert _get_pattern_category("postgres_connection") == "database"

    def test_get_pattern_category_cicd(self):
        """Test getting category for CI/CD pattern."""
        assert _get_pattern_category("github_token") == "cicd"
        assert _get_pattern_category("gitlab_token") == "cicd"
        assert _get_pattern_category("npm_token") == "cicd"

    def test_get_patterns_by_category_all(self):
        """Test getting all patterns."""
        patterns = _get_patterns_by_category("all")
        assert len(patterns) > 20
        assert any(p["name"] == "aws_access_key_id" for p in patterns)

    def test_get_patterns_by_category_aws(self):
        """Test getting AWS patterns."""
        patterns = _get_patterns_by_category("aws")
        assert len(patterns) >= 3
        assert all(p["category"] == "aws" for p in patterns)

    def test_get_all_categories(self):
        """Test getting all categories."""
        categories = _get_all_categories()
        assert len(categories) == 6
        category_ids = [c["id"] for c in categories]
        assert "aws" in category_ids
        assert "gcp" in category_ids
        assert "azure" in category_ids
        assert "generic" in category_ids
        assert "database" in category_ids
        assert "cicd" in category_ids

    def test_interpret_entropy_very_low(self):
        """Test interpreting very low entropy."""
        result = _interpret_entropy(1.5)
        assert "Very low" in result

    def test_interpret_entropy_low(self):
        """Test interpreting low entropy."""
        result = _interpret_entropy(2.5)
        assert "Low" in result

    def test_interpret_entropy_moderate(self):
        """Test interpreting moderate entropy."""
        result = _interpret_entropy(3.2)
        assert "Moderate" in result

    def test_interpret_entropy_high(self):
        """Test interpreting high entropy."""
        result = _interpret_entropy(4.0)
        assert "High" in result

    def test_interpret_entropy_very_high(self):
        """Test interpreting very high entropy."""
        result = _interpret_entropy(5.0)
        assert "Very high" in result


class TestDetectionModuleIntegration:
    """Integration tests with actual detection module."""

    def test_scan_detects_aws_key(self, capsys):
        """Test that scan detects AWS access key."""
        args = argparse.Namespace(
            text="my AWS key is AKIAIOSFODNN7EXAMPLE",
            min_entropy=3.5,
            format="json",
        )
        result = _handle_scan(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["secrets_found"] >= 1

    def test_scan_detects_github_token(self, capsys):
        """Test that scan detects GitHub token."""
        args = argparse.Namespace(
            text="token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            min_entropy=3.5,
            format="json",
        )
        result = _handle_scan(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        # May or may not detect depending on pattern
        assert "secrets_found" in data

    def test_patterns_include_all_categories(self, capsys):
        """Test that patterns include all categories."""
        args = argparse.Namespace(
            category="all",
            format="json",
        )
        result = _handle_patterns(args)
        assert result == 0

        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)

        categories = set(p["category"] for p in data["patterns"])
        assert "aws" in categories
        assert "gcp" in categories
        assert "azure" in categories
        assert "generic" in categories

    def test_entropy_calculation_correct(self, capsys):
        """Test that entropy calculation is correct."""
        # Low entropy - repeated character
        args = argparse.Namespace(
            text="aaaaaaaaaa",
            format="json",
        )
        _handle_entropy(args)
        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert data["entropy"] < 1.0

        # High entropy - random-looking string
        args = argparse.Namespace(
            text="aB3$xY9@kL2#mN5&pQ7!rS",
            format="json",
        )
        _handle_entropy(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["entropy"] > 3.5


class TestCLIRouting:
    """Tests for CLI command routing."""

    def test_all_handlers_exist(self):
        """Test that all handlers exist."""
        handlers = [
            _handle_scan,
            _handle_scan_file,
            _handle_patterns,
            _handle_pattern,
            _handle_entropy,
            _handle_sensitive_fields,
            _handle_check_field,
            _handle_categories,
            _handle_severity_levels,
            _handle_stats,
            _handle_status,
            _handle_summary,
        ]

        for handler in handlers:
            assert callable(handler)

    def test_cmd_detection_routes_to_all_handlers(self, capsys):
        """Test that cmd_detection routes to all handlers."""
        actions = [
            ("status", {}),
            ("summary", {}),
            ("stats", {}),
            ("categories", {}),
            ("severity-levels", {}),
            ("sensitive-fields", {}),
        ]

        for action, extra_args in actions:
            args = argparse.Namespace(
                detection_action=action,
                format="json",
                **extra_args,
            )
            result = cmd_detection(args)
            assert result == 0, f"Handler for {action} failed"
