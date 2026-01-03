"""
Unit tests for CLI Engine commands.

Tests the CLI commands for the Policy Engine module.
"""

import argparse
import pytest
from unittest.mock import patch
from io import StringIO

from stance.cli_engine import (
    add_engine_parser,
    cmd_engine,
    _handle_policies,
    _handle_policy,
    _handle_validate,
    _handle_evaluate,
    _handle_validate_expression,
    _handle_compliance,
    _handle_frameworks,
    _handle_operators,
    _handle_check_types,
    _handle_severity_levels,
    _handle_stats,
    _handle_status,
    _handle_summary,
    _get_sample_policies,
    _get_sample_policy,
    _validate_policies,
    _evaluate_expression,
    _validate_expression_syntax,
    _get_sample_compliance_scores,
    _get_sample_frameworks,
    _get_expression_operators,
    _get_check_types,
    _get_severity_levels,
    _get_engine_stats,
    _get_engine_status,
    _get_engine_summary,
)


class TestAddEngineParser:
    """Tests for add_engine_parser function."""

    def test_parser_added(self):
        """Test that engine parser is added to subparsers."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_engine_parser(subparsers)

        # Parse a simple command
        args = parser.parse_args(["engine", "operators"])
        assert args.engine_action == "operators"

    def test_policies_parser(self):
        """Test policies subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_engine_parser(subparsers)

        args = parser.parse_args(["engine", "policies", "--enabled-only", "--severity", "high"])
        assert args.engine_action == "policies"
        assert args.enabled_only is True
        assert args.severity == "high"

    def test_policy_parser(self):
        """Test policy subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_engine_parser(subparsers)

        args = parser.parse_args(["engine", "policy", "aws-s3-encryption"])
        assert args.engine_action == "policy"
        assert args.policy_id == "aws-s3-encryption"

    def test_evaluate_parser(self):
        """Test evaluate subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_engine_parser(subparsers)

        args = parser.parse_args(["engine", "evaluate", "resource.enabled == true"])
        assert args.engine_action == "evaluate"
        assert args.expression == "resource.enabled == true"


class TestCmdEngine:
    """Tests for cmd_engine function."""

    def test_no_action(self):
        """Test handling of no action specified."""
        args = argparse.Namespace(engine_action=None)
        result = cmd_engine(args)
        assert result == 1

    def test_policies_action(self):
        """Test policies action routing."""
        args = argparse.Namespace(
            engine_action="policies",
            format="text",
            enabled_only=False,
            severity=None,
            resource_type=None,
            framework=None,
            path=None,
        )
        result = cmd_engine(args)
        assert result == 0

    def test_unknown_action(self):
        """Test handling of unknown action."""
        args = argparse.Namespace(engine_action="unknown")
        result = cmd_engine(args)
        assert result == 1


class TestHandlePolicies:
    """Tests for _handle_policies function."""

    def test_policies_text_output(self):
        """Test policies with text output."""
        args = argparse.Namespace(
            format="text",
            enabled_only=False,
            severity=None,
            resource_type=None,
            framework=None,
            path=None,
        )
        result = _handle_policies(args)
        assert result == 0

    def test_policies_json_output(self, capsys):
        """Test policies with JSON output."""
        args = argparse.Namespace(
            format="json",
            enabled_only=False,
            severity=None,
            resource_type=None,
            framework=None,
            path=None,
        )
        result = _handle_policies(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "policies" in captured.out

    def test_policies_enabled_only(self, capsys):
        """Test filtering only enabled policies."""
        args = argparse.Namespace(
            format="json",
            enabled_only=True,
            severity=None,
            resource_type=None,
            framework=None,
            path=None,
        )
        result = _handle_policies(args)
        assert result == 0

    def test_policies_filter_by_severity(self, capsys):
        """Test filtering policies by severity."""
        args = argparse.Namespace(
            format="json",
            enabled_only=False,
            severity="critical",
            resource_type=None,
            framework=None,
            path=None,
        )
        result = _handle_policies(args)
        assert result == 0


class TestHandlePolicy:
    """Tests for _handle_policy function."""

    def test_policy_found(self):
        """Test policy found."""
        args = argparse.Namespace(
            policy_id="aws-s3-encryption",
            format="text",
            path=None,
        )
        result = _handle_policy(args)
        assert result == 0

    def test_policy_not_found(self):
        """Test policy not found."""
        args = argparse.Namespace(
            policy_id="nonexistent",
            format="text",
            path=None,
        )
        result = _handle_policy(args)
        assert result == 1

    def test_policy_json_output(self, capsys):
        """Test policy with JSON output."""
        args = argparse.Namespace(
            policy_id="aws-s3-encryption",
            format="json",
            path=None,
        )
        result = _handle_policy(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "policy" in captured.out


class TestHandleValidate:
    """Tests for _handle_validate function."""

    def test_validate_text_output(self):
        """Test validate with text output."""
        args = argparse.Namespace(format="text", path=None)
        result = _handle_validate(args)
        assert result == 0

    def test_validate_json_output(self, capsys):
        """Test validate with JSON output."""
        args = argparse.Namespace(format="json", path=None)
        result = _handle_validate(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "valid" in captured.out


class TestHandleEvaluate:
    """Tests for _handle_evaluate function."""

    def test_evaluate_simple_expression(self):
        """Test evaluating simple expression."""
        args = argparse.Namespace(
            expression="resource.enabled == true",
            context='{"resource": {"enabled": true}}',
            format="text",
        )
        result = _handle_evaluate(args)
        assert result == 0

    def test_evaluate_invalid_context(self):
        """Test evaluating with invalid context."""
        args = argparse.Namespace(
            expression="resource.enabled == true",
            context="not valid json",
            format="text",
        )
        result = _handle_evaluate(args)
        assert result == 1

    def test_evaluate_json_output(self, capsys):
        """Test evaluate with JSON output."""
        args = argparse.Namespace(
            expression="resource.name == 'test'",
            context='{"resource": {"name": "test"}}',
            format="json",
        )
        result = _handle_evaluate(args)
        captured = capsys.readouterr()
        assert "result" in captured.out


class TestHandleValidateExpression:
    """Tests for _handle_validate_expression function."""

    def test_valid_expression(self):
        """Test validating valid expression."""
        args = argparse.Namespace(
            expression="resource.enabled == true",
            format="text",
        )
        result = _handle_validate_expression(args)
        assert result == 0

    def test_invalid_expression(self):
        """Test validating invalid expression."""
        args = argparse.Namespace(
            expression="",
            format="text",
        )
        result = _handle_validate_expression(args)
        assert result == 1

    def test_validate_expression_json(self, capsys):
        """Test validate expression with JSON output."""
        args = argparse.Namespace(
            expression="resource.id exists",
            format="json",
        )
        result = _handle_validate_expression(args)
        captured = capsys.readouterr()
        assert "valid" in captured.out


class TestHandleCompliance:
    """Tests for _handle_compliance function."""

    def test_compliance_text_output(self):
        """Test compliance with text output."""
        args = argparse.Namespace(format="text", framework=None)
        result = _handle_compliance(args)
        assert result == 0

    def test_compliance_json_output(self, capsys):
        """Test compliance with JSON output."""
        args = argparse.Namespace(format="json", framework=None)
        result = _handle_compliance(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "overall_score" in captured.out

    def test_compliance_filter_by_framework(self, capsys):
        """Test compliance filtered by framework."""
        args = argparse.Namespace(format="json", framework="cis-aws")
        result = _handle_compliance(args)
        assert result == 0


class TestHandleFrameworks:
    """Tests for _handle_frameworks function."""

    def test_frameworks_text_output(self):
        """Test frameworks with text output."""
        args = argparse.Namespace(format="text")
        result = _handle_frameworks(args)
        assert result == 0

    def test_frameworks_json_output(self, capsys):
        """Test frameworks with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_frameworks(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "frameworks" in captured.out


class TestHandleOperators:
    """Tests for _handle_operators function."""

    def test_operators_text_output(self):
        """Test operators with text output."""
        args = argparse.Namespace(format="text")
        result = _handle_operators(args)
        assert result == 0

    def test_operators_json_output(self, capsys):
        """Test operators with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_operators(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "operators" in captured.out


class TestHandleCheckTypes:
    """Tests for _handle_check_types function."""

    def test_check_types_text_output(self):
        """Test check types with text output."""
        args = argparse.Namespace(format="text")
        result = _handle_check_types(args)
        assert result == 0

    def test_check_types_json_output(self, capsys):
        """Test check types with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_check_types(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "check_types" in captured.out


class TestHandleSeverityLevels:
    """Tests for _handle_severity_levels function."""

    def test_severity_levels_text_output(self):
        """Test severity levels with text output."""
        args = argparse.Namespace(format="text")
        result = _handle_severity_levels(args)
        assert result == 0

    def test_severity_levels_json_output(self, capsys):
        """Test severity levels with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_severity_levels(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "severity_levels" in captured.out


class TestHandleStats:
    """Tests for _handle_stats function."""

    def test_stats_text_output(self):
        """Test stats with text output."""
        args = argparse.Namespace(format="text", path=None)
        result = _handle_stats(args)
        assert result == 0

    def test_stats_json_output(self, capsys):
        """Test stats with JSON output."""
        args = argparse.Namespace(format="json", path=None)
        result = _handle_stats(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "total_policies" in captured.out


class TestHandleStatus:
    """Tests for _handle_status function."""

    def test_status_text_output(self):
        """Test status with text output."""
        args = argparse.Namespace(format="text")
        result = _handle_status(args)
        assert result == 0

    def test_status_json_output(self, capsys):
        """Test status with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "module" in captured.out


class TestHandleSummary:
    """Tests for _handle_summary function."""

    def test_summary_text_output(self):
        """Test summary with text output."""
        args = argparse.Namespace(format="text")
        result = _handle_summary(args)
        assert result == 0

    def test_summary_json_output(self, capsys):
        """Test summary with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "module" in captured.out


class TestSampleDataGenerators:
    """Tests for sample data generator functions."""

    def test_get_sample_policies(self):
        """Test getting sample policies."""
        policies = _get_sample_policies()
        assert isinstance(policies, list)
        assert len(policies) > 0
        assert "id" in policies[0]
        assert "name" in policies[0]
        assert "severity" in policies[0]

    def test_get_sample_policy_found(self):
        """Test getting existing policy."""
        policy = _get_sample_policy("aws-s3-encryption")
        assert policy is not None
        assert policy["id"] == "aws-s3-encryption"

    def test_get_sample_policy_not_found(self):
        """Test getting non-existent policy."""
        policy = _get_sample_policy("nonexistent")
        assert policy is None

    def test_validate_policies(self):
        """Test validating policies."""
        result = _validate_policies(None)
        assert "valid" in result
        assert "total_files" in result
        assert result["valid"] is True

    def test_evaluate_expression_success(self):
        """Test evaluating expression successfully."""
        result = _evaluate_expression(
            "resource.enabled == true",
            {"resource": {"enabled": True}},
        )
        assert result["success"] is True
        assert result["result"] is True

    def test_evaluate_expression_false(self):
        """Test evaluating expression that returns false."""
        result = _evaluate_expression(
            "resource.enabled == true",
            {"resource": {"enabled": False}},
        )
        assert result["success"] is True
        assert result["result"] is False

    def test_validate_expression_syntax_valid(self):
        """Test validating valid expression syntax."""
        result = _validate_expression_syntax("resource.name == 'test'")
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_validate_expression_syntax_invalid(self):
        """Test validating invalid expression syntax."""
        result = _validate_expression_syntax("")
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_get_sample_compliance_scores(self):
        """Test getting sample compliance scores."""
        scores = _get_sample_compliance_scores(None)
        assert "overall_score" in scores
        assert "frameworks" in scores
        assert len(scores["frameworks"]) > 0

    def test_get_sample_frameworks(self):
        """Test getting sample frameworks."""
        frameworks = _get_sample_frameworks()
        assert isinstance(frameworks, list)
        assert len(frameworks) > 0
        assert "id" in frameworks[0]
        assert "name" in frameworks[0]

    def test_get_expression_operators(self):
        """Test getting expression operators."""
        operators = _get_expression_operators()
        assert isinstance(operators, list)
        assert len(operators) > 0
        assert "operator" in operators[0]
        assert "description" in operators[0]

    def test_get_check_types(self):
        """Test getting check types."""
        types = _get_check_types()
        assert isinstance(types, list)
        assert len(types) == 2
        assert types[0]["type"] in ["expression", "sql"]

    def test_get_severity_levels(self):
        """Test getting severity levels."""
        levels = _get_severity_levels()
        assert isinstance(levels, list)
        assert len(levels) == 5
        assert levels[0]["level"] == "critical"

    def test_get_engine_stats(self):
        """Test getting engine stats."""
        stats = _get_engine_stats()
        assert "total_policies" in stats
        assert "by_severity" in stats
        assert "frameworks_count" in stats

    def test_get_engine_status(self):
        """Test getting engine status."""
        status = _get_engine_status()
        assert status["module"] == "engine"
        assert status["status"] == "operational"
        assert "components" in status
        assert "capabilities" in status

    def test_get_engine_summary(self):
        """Test getting engine summary."""
        summary = _get_engine_summary()
        assert summary["module"] == "Policy Engine"
        assert "policies" in summary
        assert "compliance" in summary
        assert "features" in summary


class TestEngineEndpointRouting:
    """Tests for engine CLI routing."""

    def test_all_actions_available(self):
        """Test that all actions are routed."""
        actions = [
            "policies",
            "policy",
            "validate",
            "evaluate",
            "validate-expression",
            "compliance",
            "frameworks",
            "operators",
            "check-types",
            "severity-levels",
            "stats",
            "status",
            "summary",
        ]

        for action in actions:
            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers()
            add_engine_parser(subparsers)

            if action in ["policy", "evaluate", "validate-expression"]:
                # These require arguments
                if action == "policy":
                    args = parser.parse_args(["engine", action, "test-id"])
                elif action in ["evaluate", "validate-expression"]:
                    args = parser.parse_args(["engine", action, "test == true"])
            else:
                args = parser.parse_args(["engine", action])

            assert args.engine_action == action
