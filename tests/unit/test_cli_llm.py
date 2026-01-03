"""
Unit tests for CLI LLM commands.

Tests the CLI commands for the LLM module.
"""

import argparse
import pytest
from unittest.mock import patch
from io import StringIO

from stance.cli_llm import (
    add_llm_parser,
    cmd_llm,
    _handle_providers,
    _handle_provider,
    _handle_generate_query,
    _handle_validate_query,
    _handle_explain_finding,
    _handle_generate_policy,
    _handle_suggest_policies,
    _handle_sanitize,
    _handle_check_sensitive,
    _handle_resource_types,
    _handle_frameworks,
    _handle_models,
    _handle_status,
    _handle_summary,
    _get_available_providers,
    _get_provider_details,
    _generate_query_demo,
    _validate_query,
    _get_demo_explanation,
    _generate_policy_demo,
    _get_policy_suggestions,
    _sanitize_text,
    _check_sensitive_data,
    _get_resource_types,
    _get_compliance_frameworks,
    _get_available_models,
    _get_llm_status,
    _get_llm_summary,
)


class TestAddLLMParser:
    """Tests for add_llm_parser function."""

    def test_parser_added(self):
        """Test that LLM parser is added to subparsers."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_llm_parser(subparsers)

        args = parser.parse_args(["llm", "providers"])
        assert args.llm_action == "providers"

    def test_providers_parser(self):
        """Test providers subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_llm_parser(subparsers)

        args = parser.parse_args(["llm", "providers", "--format", "json"])
        assert args.llm_action == "providers"
        assert args.format == "json"

    def test_provider_parser(self):
        """Test provider subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_llm_parser(subparsers)

        args = parser.parse_args(["llm", "provider", "anthropic"])
        assert args.llm_action == "provider"
        assert args.provider_name == "anthropic"

    def test_generate_query_parser(self):
        """Test generate-query subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_llm_parser(subparsers)

        args = parser.parse_args(["llm", "generate-query", "Find all critical findings"])
        assert args.llm_action == "generate-query"
        assert args.question == "Find all critical findings"

    def test_validate_query_parser(self):
        """Test validate-query subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_llm_parser(subparsers)

        args = parser.parse_args(["llm", "validate-query", "SELECT * FROM findings"])
        assert args.llm_action == "validate-query"
        assert args.sql == "SELECT * FROM findings"

    def test_generate_policy_parser(self):
        """Test generate-policy subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_llm_parser(subparsers)

        args = parser.parse_args([
            "llm", "generate-policy", "Ensure S3 bucket encryption",
            "--cloud", "aws", "--severity", "high"
        ])
        assert args.llm_action == "generate-policy"
        assert args.description == "Ensure S3 bucket encryption"
        assert args.cloud == "aws"
        assert args.severity == "high"


class TestCmdLLM:
    """Tests for cmd_llm function."""

    def test_no_action(self):
        """Test handling of no action specified."""
        args = argparse.Namespace(llm_action=None)
        result = cmd_llm(args)
        assert result == 1

    def test_providers_action(self):
        """Test providers action routing."""
        args = argparse.Namespace(
            llm_action="providers",
            format="table",
        )
        result = cmd_llm(args)
        assert result == 0

    def test_unknown_action(self):
        """Test handling of unknown action."""
        args = argparse.Namespace(llm_action="unknown")
        result = cmd_llm(args)
        assert result == 1


class TestHandleProviders:
    """Tests for _handle_providers function."""

    def test_providers_table_output(self):
        """Test providers with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_providers(args)
        assert result == 0

    def test_providers_json_output(self, capsys):
        """Test providers with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_providers(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "providers" in captured.out
        assert "total" in captured.out


class TestHandleProvider:
    """Tests for _handle_provider function."""

    def test_provider_anthropic(self):
        """Test anthropic provider details."""
        args = argparse.Namespace(
            provider_name="anthropic",
            format="table",
        )
        result = _handle_provider(args)
        assert result == 0

    def test_provider_openai(self):
        """Test openai provider details."""
        args = argparse.Namespace(
            provider_name="openai",
            format="table",
        )
        result = _handle_provider(args)
        assert result == 0

    def test_provider_json_output(self, capsys):
        """Test provider with JSON output."""
        args = argparse.Namespace(
            provider_name="anthropic",
            format="json",
        )
        result = _handle_provider(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "anthropic" in captured.out


class TestHandleGenerateQuery:
    """Tests for _handle_generate_query function."""

    def test_generate_query_table_output(self):
        """Test generate query with table output."""
        args = argparse.Namespace(
            question="Find all critical findings",
            provider="anthropic",
            format="table",
        )
        result = _handle_generate_query(args)
        assert result == 0

    def test_generate_query_json_output(self, capsys):
        """Test generate query with JSON output."""
        args = argparse.Namespace(
            question="Show S3 buckets",
            provider="anthropic",
            format="json",
        )
        result = _handle_generate_query(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "sql" in captured.out
        assert "is_valid" in captured.out


class TestHandleValidateQuery:
    """Tests for _handle_validate_query function."""

    def test_validate_valid_query(self):
        """Test validating a valid query."""
        args = argparse.Namespace(
            sql="SELECT * FROM findings WHERE severity = 'critical'",
            format="table",
        )
        result = _handle_validate_query(args)
        assert result == 0

    def test_validate_invalid_query(self):
        """Test validating an invalid query."""
        args = argparse.Namespace(
            sql="DELETE FROM findings",
            format="table",
        )
        result = _handle_validate_query(args)
        assert result == 0


class TestHandleExplainFinding:
    """Tests for _handle_explain_finding function."""

    def test_explain_finding_demo(self):
        """Test explain finding in demo mode."""
        args = argparse.Namespace(
            finding_id="demo",
            provider="anthropic",
            demo=True,
            format="table",
        )
        result = _handle_explain_finding(args)
        assert result == 0

    def test_explain_finding_json_output(self, capsys):
        """Test explain finding with JSON output."""
        args = argparse.Namespace(
            finding_id="demo",
            provider="anthropic",
            demo=True,
            format="json",
        )
        result = _handle_explain_finding(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "summary" in captured.out
        assert "remediation_steps" in captured.out


class TestHandleGeneratePolicy:
    """Tests for _handle_generate_policy function."""

    def test_generate_policy_table_output(self):
        """Test generate policy with table output."""
        args = argparse.Namespace(
            description="Ensure S3 bucket encryption",
            provider="anthropic",
            cloud="aws",
            severity="high",
            resource_type=None,
            output=None,
            format="table",
        )
        result = _handle_generate_policy(args)
        assert result == 0

    def test_generate_policy_json_output(self, capsys):
        """Test generate policy with JSON output."""
        args = argparse.Namespace(
            description="Ensure IAM MFA enabled",
            provider="anthropic",
            cloud="aws",
            severity="critical",
            resource_type=None,
            output=None,
            format="json",
        )
        result = _handle_generate_policy(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "yaml_content" in captured.out
        assert "is_valid" in captured.out


class TestHandleSuggestPolicies:
    """Tests for _handle_suggest_policies function."""

    def test_suggest_policies_table_output(self):
        """Test suggest policies with table output."""
        args = argparse.Namespace(
            resource_type="aws_s3_bucket",
            provider="anthropic",
            count=5,
            format="table",
        )
        result = _handle_suggest_policies(args)
        assert result == 0

    def test_suggest_policies_json_output(self, capsys):
        """Test suggest policies with JSON output."""
        args = argparse.Namespace(
            resource_type="aws_iam_user",
            provider="anthropic",
            count=3,
            format="json",
        )
        result = _handle_suggest_policies(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "suggestions" in captured.out


class TestHandleSanitize:
    """Tests for _handle_sanitize function."""

    def test_sanitize_table_output(self):
        """Test sanitize with table output."""
        args = argparse.Namespace(
            text="My API key is AKIAIOSFODNN7EXAMPLE",
            redact_emails=False,
            redact_ips=False,
            redact_account_ids=False,
            format="table",
        )
        result = _handle_sanitize(args)
        assert result == 0

    def test_sanitize_json_output(self, capsys):
        """Test sanitize with JSON output."""
        args = argparse.Namespace(
            text="Test text with password=secret123",
            redact_emails=False,
            redact_ips=False,
            redact_account_ids=False,
            format="json",
        )
        result = _handle_sanitize(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "sanitized_text" in captured.out
        assert "redactions_made" in captured.out


class TestHandleCheckSensitive:
    """Tests for _handle_check_sensitive function."""

    def test_check_sensitive_table_output(self):
        """Test check sensitive with table output."""
        args = argparse.Namespace(
            text="Normal text without secrets",
            format="table",
        )
        result = _handle_check_sensitive(args)
        assert result == 0

    def test_check_sensitive_json_output(self, capsys):
        """Test check sensitive with JSON output."""
        args = argparse.Namespace(
            text="API key: sk-1234567890abcdef",
            format="json",
        )
        result = _handle_check_sensitive(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "is_sensitive" in captured.out


class TestHandleResourceTypes:
    """Tests for _handle_resource_types function."""

    def test_resource_types_all(self):
        """Test resource types without filter."""
        args = argparse.Namespace(
            cloud=None,
            format="table",
        )
        result = _handle_resource_types(args)
        assert result == 0

    def test_resource_types_filtered(self):
        """Test resource types filtered by cloud."""
        args = argparse.Namespace(
            cloud="aws",
            format="table",
        )
        result = _handle_resource_types(args)
        assert result == 0

    def test_resource_types_json(self, capsys):
        """Test resource types JSON output."""
        args = argparse.Namespace(
            cloud=None,
            format="json",
        )
        result = _handle_resource_types(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "resource_types" in captured.out
        assert "total" in captured.out


class TestHandleFrameworks:
    """Tests for _handle_frameworks function."""

    def test_frameworks_table_output(self):
        """Test frameworks with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_frameworks(args)
        assert result == 0

    def test_frameworks_json_output(self, capsys):
        """Test frameworks with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_frameworks(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "frameworks" in captured.out


class TestHandleModels:
    """Tests for _handle_models function."""

    def test_models_all(self):
        """Test models without filter."""
        args = argparse.Namespace(
            provider=None,
            format="table",
        )
        result = _handle_models(args)
        assert result == 0

    def test_models_filtered(self):
        """Test models filtered by provider."""
        args = argparse.Namespace(
            provider="anthropic",
            format="table",
        )
        result = _handle_models(args)
        assert result == 0


class TestHandleStatus:
    """Tests for _handle_status function."""

    def test_status_table_output(self):
        """Test status with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_status(args)
        assert result == 0

    def test_status_json_output(self, capsys):
        """Test status with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "module" in captured.out
        assert "providers" in captured.out


class TestHandleSummary:
    """Tests for _handle_summary function."""

    def test_summary_table_output(self):
        """Test summary with table output."""
        args = argparse.Namespace(format="table")
        result = _handle_summary(args)
        assert result == 0

    def test_summary_json_output(self, capsys):
        """Test summary with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "module" in captured.out
        assert "features" in captured.out


class TestSampleDataGenerators:
    """Tests for sample data generator functions."""

    def test_get_available_providers(self):
        """Test getting available providers."""
        providers = _get_available_providers()
        assert isinstance(providers, list)
        assert len(providers) == 3
        assert providers[0]["id"] == "anthropic"
        assert "available" in providers[0]

    def test_get_provider_details_anthropic(self):
        """Test getting anthropic provider details."""
        provider = _get_provider_details("anthropic")
        assert provider["id"] == "anthropic"
        assert "models" in provider
        assert "capabilities" in provider

    def test_get_provider_details_openai(self):
        """Test getting openai provider details."""
        provider = _get_provider_details("openai")
        assert provider["id"] == "openai"
        assert "gpt" in provider["default_model"]

    def test_get_provider_details_gemini(self):
        """Test getting gemini provider details."""
        provider = _get_provider_details("gemini")
        assert provider["id"] == "gemini"
        assert "gemini" in provider["default_model"]

    def test_generate_query_demo_critical(self):
        """Test generating query for critical findings."""
        result = _generate_query_demo("Find critical findings", "anthropic")
        assert "critical" in result["sql"].lower()
        assert result["is_valid"] is True

    def test_generate_query_demo_s3(self):
        """Test generating query for S3 buckets."""
        result = _generate_query_demo("Show all S3 buckets", "anthropic")
        assert "s3_bucket" in result["sql"]
        assert result["is_valid"] is True

    def test_validate_query_valid(self):
        """Test validating a valid query."""
        result = _validate_query("SELECT * FROM findings")
        assert result["is_valid"] is True
        assert len(result["errors"]) == 0

    def test_validate_query_invalid(self):
        """Test validating an invalid query."""
        result = _validate_query("DELETE FROM findings")
        assert result["is_valid"] is False
        assert len(result["errors"]) > 0

    def test_get_demo_explanation(self):
        """Test getting demo explanation."""
        explanation = _get_demo_explanation()
        assert "finding_id" in explanation
        assert "summary" in explanation
        assert "remediation_steps" in explanation
        assert explanation["is_valid"] is True

    def test_generate_policy_demo(self):
        """Test generating demo policy."""
        result = _generate_policy_demo(
            "Ensure S3 encryption",
            "anthropic",
            "aws",
            "high",
            None,
        )
        assert "yaml_content" in result
        assert result["is_valid"] is True
        assert "s3" in result["policy_id"].lower()

    def test_get_policy_suggestions(self):
        """Test getting policy suggestions."""
        result = _get_policy_suggestions("aws_s3_bucket", 5)
        assert "suggestions" in result
        assert len(result["suggestions"]) <= 5

    def test_sanitize_text(self):
        """Test sanitizing text."""
        result = _sanitize_text("API key: AKIAIOSFODNN7EXAMPLE", False, False, False)
        assert "sanitized_text" in result
        assert result["redactions_made"] >= 0

    def test_check_sensitive_data(self):
        """Test checking for sensitive data."""
        result = _check_sensitive_data("Normal text")
        assert "is_sensitive" in result
        assert "types_found" in result

    def test_get_resource_types(self):
        """Test getting resource types."""
        result = _get_resource_types(None)
        assert "resource_types" in result
        assert "total" in result
        assert result["total"] > 0

    def test_get_resource_types_filtered(self):
        """Test getting filtered resource types."""
        result = _get_resource_types("aws")
        assert "aws" in result["resource_types"]

    def test_get_compliance_frameworks(self):
        """Test getting compliance frameworks."""
        result = _get_compliance_frameworks()
        assert "frameworks" in result
        assert result["total"] > 0

    def test_get_available_models(self):
        """Test getting available models."""
        result = _get_available_models(None)
        assert "models" in result
        assert "anthropic" in result["models"]
        assert "openai" in result["models"]

    def test_get_llm_status(self):
        """Test getting LLM status."""
        status = _get_llm_status()
        assert status["module"] == "llm"
        assert "providers" in status
        assert "capabilities" in status

    def test_get_llm_summary(self):
        """Test getting LLM summary."""
        summary = _get_llm_summary()
        assert summary["module"] == "LLM"
        assert "features" in summary
        assert summary["providers_total"] == 3


class TestLLMEndpointRouting:
    """Tests for LLM CLI routing."""

    def test_all_actions_available(self):
        """Test that all actions are routed."""
        actions = [
            "providers",
            "provider",
            "generate-query",
            "validate-query",
            "explain-finding",
            "generate-policy",
            "suggest-policies",
            "sanitize",
            "check-sensitive",
            "resource-types",
            "frameworks",
            "models",
            "status",
            "summary",
        ]

        for action in actions:
            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers()
            add_llm_parser(subparsers)

            if action == "provider":
                args = parser.parse_args(["llm", action, "anthropic"])
            elif action == "generate-query":
                args = parser.parse_args(["llm", action, "test question"])
            elif action == "validate-query":
                args = parser.parse_args(["llm", action, "SELECT * FROM test"])
            elif action == "explain-finding":
                args = parser.parse_args(["llm", action, "test-id", "--demo"])
            elif action == "generate-policy":
                args = parser.parse_args(["llm", action, "test description"])
            elif action == "suggest-policies":
                args = parser.parse_args(["llm", action, "aws_s3_bucket"])
            elif action == "sanitize":
                args = parser.parse_args(["llm", action, "test text"])
            elif action == "check-sensitive":
                args = parser.parse_args(["llm", action, "test text"])
            else:
                args = parser.parse_args(["llm", action])

            assert args.llm_action == action


class TestProviderChoices:
    """Tests for provider choices validation."""

    def test_provider_choices(self):
        """Test provider choices validation."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_llm_parser(subparsers)

        # Valid providers
        for provider in ["anthropic", "openai", "gemini"]:
            args = parser.parse_args(["llm", "provider", provider])
            assert args.provider_name == provider


class TestFormatOptions:
    """Tests for format options."""

    def test_table_format_default(self):
        """Test table format is default."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_llm_parser(subparsers)

        args = parser.parse_args(["llm", "providers"])
        assert args.format == "table"

    def test_json_format_option(self):
        """Test JSON format option."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_llm_parser(subparsers)

        args = parser.parse_args(["llm", "providers", "--format", "json"])
        assert args.format == "json"


class TestLLMIntegration:
    """Integration tests for LLM CLI."""

    def test_full_workflow(self, capsys):
        """Test a full LLM workflow."""
        # List providers
        args = argparse.Namespace(format="json")
        result = _handle_providers(args)
        assert result == 0

        # Get provider details
        args = argparse.Namespace(provider_name="anthropic", format="json")
        result = _handle_provider(args)
        assert result == 0

        # Generate query
        args = argparse.Namespace(
            question="Find critical findings",
            provider="anthropic",
            format="json",
        )
        result = _handle_generate_query(args)
        assert result == 0

        # Get status
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0

        # Get summary
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0
