"""
Unit tests for CLI Cloud module.

Tests the CLI commands for cloud provider management including listing,
validation, account info, and region discovery.
"""

from __future__ import annotations

import argparse
import json
from typing import Any
from unittest import mock

import pytest


class TestAddCloudParser:
    """Tests for add_cloud_parser function."""

    def test_parser_creation(self):
        """Test that cloud parser is created correctly."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        # Parse a valid cloud command
        args = parser.parse_args(["cloud", "list"])
        assert args.cloud_action == "list"

    def test_list_command_with_format(self):
        """Test list command with format option."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "list", "--format", "json"])
        assert args.cloud_action == "list"
        assert args.format == "json"

    def test_info_command(self):
        """Test info command."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "info", "aws"])
        assert args.cloud_action == "info"
        assert args.provider_name == "aws"

    def test_validate_command(self):
        """Test validate command."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "validate", "aws", "--region", "us-west-2"])
        assert args.cloud_action == "validate"
        assert args.provider_name == "aws"
        assert args.region == "us-west-2"

    def test_account_command(self):
        """Test account command."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "account", "aws", "--profile", "prod"])
        assert args.cloud_action == "account"
        assert args.provider_name == "aws"
        assert args.profile == "prod"

    def test_regions_command(self):
        """Test regions command."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "regions", "aws"])
        assert args.cloud_action == "regions"
        assert args.provider_name == "aws"

    def test_availability_command(self):
        """Test availability command."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "availability"])
        assert args.cloud_action == "availability"

    def test_packages_command(self):
        """Test packages command."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "packages", "--provider", "aws"])
        assert args.cloud_action == "packages"
        assert args.provider == "aws"

    def test_credentials_command(self):
        """Test credentials command."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "credentials"])
        assert args.cloud_action == "credentials"

    def test_exceptions_command(self):
        """Test exceptions command."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "exceptions"])
        assert args.cloud_action == "exceptions"

    def test_status_command(self):
        """Test status command."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "status"])
        assert args.cloud_action == "status"

    def test_summary_command(self):
        """Test summary command."""
        from stance.cli_cloud import add_cloud_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_cloud_parser(subparsers)

        args = parser.parse_args(["cloud", "summary"])
        assert args.cloud_action == "summary"


class TestCmdCloud:
    """Tests for cmd_cloud function."""

    def test_no_action_shows_help(self, capsys):
        """Test that no action shows help."""
        from stance.cli_cloud import cmd_cloud

        args = argparse.Namespace(cloud_action=None)
        result = cmd_cloud(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Available actions:" in captured.out

    def test_unknown_action_returns_error(self, capsys):
        """Test that unknown action returns error."""
        from stance.cli_cloud import cmd_cloud

        args = argparse.Namespace(cloud_action="unknown")
        result = cmd_cloud(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown cloud action" in captured.out


class TestHandleList:
    """Tests for _handle_list function."""

    def test_list_providers_table(self, capsys):
        """Test listing providers in table format."""
        from stance.cli_cloud import _handle_list

        args = argparse.Namespace(format="table")
        result = _handle_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Supported Cloud Providers" in captured.out
        assert "aws" in captured.out
        assert "gcp" in captured.out
        assert "azure" in captured.out

    def test_list_providers_json(self, capsys):
        """Test listing providers in JSON format."""
        from stance.cli_cloud import _handle_list

        args = argparse.Namespace(format="json")
        result = _handle_list(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 3

        provider_names = [p["name"] for p in data]
        assert "aws" in provider_names
        assert "gcp" in provider_names
        assert "azure" in provider_names


class TestHandleInfo:
    """Tests for _handle_info function."""

    def test_info_aws_table(self, capsys):
        """Test info for AWS in table format."""
        from stance.cli_cloud import _handle_info

        args = argparse.Namespace(format="table", provider_name="aws")
        result = _handle_info(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Amazon Web Services" in captured.out
        assert "boto3" in captured.out
        assert "us-east-1" in captured.out

    def test_info_aws_json(self, capsys):
        """Test info for AWS in JSON format."""
        from stance.cli_cloud import _handle_info

        args = argparse.Namespace(format="json", provider_name="aws")
        result = _handle_info(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["name"] == "aws"
        assert data["display_name"] == "Amazon Web Services"
        assert "boto3" in data["packages"]
        assert "aws_access_key_id" in data["credential_fields"]

    def test_info_gcp(self, capsys):
        """Test info for GCP."""
        from stance.cli_cloud import _handle_info

        args = argparse.Namespace(format="json", provider_name="gcp")
        result = _handle_info(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["name"] == "gcp"
        assert "gcp_project_id" in data["credential_fields"]

    def test_info_azure(self, capsys):
        """Test info for Azure."""
        from stance.cli_cloud import _handle_info

        args = argparse.Namespace(format="json", provider_name="azure")
        result = _handle_info(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["name"] == "azure"
        assert "azure_subscription_id" in data["credential_fields"]


class TestHandleValidate:
    """Tests for _handle_validate function."""

    def test_validate_unavailable_sdk(self, capsys):
        """Test validate when SDK is not available."""
        from stance.cli_cloud import _handle_validate

        with mock.patch("stance.cloud.is_provider_available", return_value=False):
            args = argparse.Namespace(
                format="table",
                provider_name="gcp",
                region=None,
                profile=None,
                project=None,
                subscription=None,
            )
            result = _handle_validate(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "FAILED" in captured.out

    def test_validate_success_mock(self, capsys):
        """Test successful validation with mocked provider."""
        from stance.cli_cloud import _handle_validate

        mock_provider = mock.MagicMock()
        mock_provider.validate_credentials.return_value = True
        mock_provider._account_id = "123456789012"

        with mock.patch("stance.cloud.is_provider_available", return_value=True):
            with mock.patch("stance.cloud.get_cloud_provider", return_value=mock_provider):
                args = argparse.Namespace(
                    format="json",
                    provider_name="aws",
                    region="us-east-1",
                    profile=None,
                    project=None,
                    subscription=None,
                )
                result = _handle_validate(args)

                assert result == 0
                captured = capsys.readouterr()
                data = json.loads(captured.out)
                assert data["valid"] is True
                assert data["account_id"] == "123456789012"


class TestHandleAvailability:
    """Tests for _handle_availability function."""

    def test_availability_table(self, capsys):
        """Test availability in table format."""
        from stance.cli_cloud import _handle_availability

        args = argparse.Namespace(format="table")
        result = _handle_availability(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Cloud SDK Availability" in captured.out
        assert "AWS" in captured.out
        assert "GCP" in captured.out
        assert "AZURE" in captured.out

    def test_availability_json(self, capsys):
        """Test availability in JSON format."""
        from stance.cli_cloud import _handle_availability

        args = argparse.Namespace(format="json")
        result = _handle_availability(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 3

        for item in data:
            assert "provider" in item
            assert "available" in item
            assert "install" in item


class TestHandlePackages:
    """Tests for _handle_packages function."""

    def test_packages_all_table(self, capsys):
        """Test packages listing in table format."""
        from stance.cli_cloud import _handle_packages

        args = argparse.Namespace(format="table", provider=None)
        result = _handle_packages(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Required Packages" in captured.out

    def test_packages_all_json(self, capsys):
        """Test packages listing in JSON format."""
        from stance.cli_cloud import _handle_packages

        args = argparse.Namespace(format="json", provider=None)
        result = _handle_packages(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 3

    def test_packages_filtered(self, capsys):
        """Test packages listing filtered by provider."""
        from stance.cli_cloud import _handle_packages

        args = argparse.Namespace(format="json", provider="aws")
        result = _handle_packages(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["provider"] == "aws"


class TestHandleCredentials:
    """Tests for _handle_credentials function."""

    def test_credentials_all_table(self, capsys):
        """Test credentials listing in table format."""
        from stance.cli_cloud import _handle_credentials

        args = argparse.Namespace(format="table", provider=None)
        result = _handle_credentials(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Credential Configuration" in captured.out
        assert "AWS" in captured.out
        assert "GCP" in captured.out
        assert "AZURE" in captured.out

    def test_credentials_all_json(self, capsys):
        """Test credentials listing in JSON format."""
        from stance.cli_cloud import _handle_credentials

        args = argparse.Namespace(format="json", provider=None)
        result = _handle_credentials(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 3

        for item in data:
            assert "fields" in item
            assert "env_vars" in item
            assert "auth_methods" in item

    def test_credentials_filtered(self, capsys):
        """Test credentials listing filtered by provider."""
        from stance.cli_cloud import _handle_credentials

        args = argparse.Namespace(format="json", provider="aws")
        result = _handle_credentials(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["provider"] == "aws"


class TestHandleExceptions:
    """Tests for _handle_exceptions function."""

    def test_exceptions_table(self, capsys):
        """Test exceptions listing in table format."""
        from stance.cli_cloud import _handle_exceptions

        args = argparse.Namespace(format="table")
        result = _handle_exceptions(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Exception Types" in captured.out
        assert "CloudProviderError" in captured.out
        assert "AuthenticationError" in captured.out

    def test_exceptions_json(self, capsys):
        """Test exceptions listing in JSON format."""
        from stance.cli_cloud import _handle_exceptions

        args = argparse.Namespace(format="json")
        result = _handle_exceptions(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 5

        exception_names = [e["name"] for e in data]
        assert "CloudProviderError" in exception_names
        assert "AuthenticationError" in exception_names
        assert "ConfigurationError" in exception_names


class TestHandleStatus:
    """Tests for _handle_status function."""

    def test_status_table(self, capsys):
        """Test status in table format."""
        from stance.cli_cloud import _handle_status

        args = argparse.Namespace(format="table")
        result = _handle_status(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Cloud Module Status" in captured.out
        assert "CloudProvider" in captured.out

    def test_status_json(self, capsys):
        """Test status in JSON format."""
        from stance.cli_cloud import _handle_status

        args = argparse.Namespace(format="json")
        result = _handle_status(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "cloud"
        assert "components" in data
        assert "providers" in data
        assert "capabilities" in data


class TestHandleSummary:
    """Tests for _handle_summary function."""

    def test_summary_table(self, capsys):
        """Test summary in table format."""
        from stance.cli_cloud import _handle_summary

        args = argparse.Namespace(format="table")
        result = _handle_summary(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Cloud Module Summary" in captured.out
        assert "Features:" in captured.out

    def test_summary_json(self, capsys):
        """Test summary in JSON format."""
        from stance.cli_cloud import _handle_summary

        args = argparse.Namespace(format="json")
        result = _handle_summary(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "overview" in data
        assert "features" in data
        assert "architecture" in data
        assert "exception_hierarchy" in data


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_provider_metadata(self):
        """Test _get_provider_metadata function."""
        from stance.cli_cloud import _get_provider_metadata

        metadata = _get_provider_metadata()
        assert len(metadata) == 3

        provider_names = [p["name"] for p in metadata]
        assert "aws" in provider_names
        assert "gcp" in provider_names
        assert "azure" in provider_names

        for p in metadata:
            assert "display_name" in p
            assert "available" in p
            assert "packages" in p
            assert "description" in p

    def test_get_display_name(self):
        """Test _get_display_name function."""
        from stance.cli_cloud import _get_display_name

        assert _get_display_name("aws") == "Amazon Web Services"
        assert _get_display_name("gcp") == "Google Cloud Platform"
        assert _get_display_name("azure") == "Microsoft Azure"
        assert _get_display_name("unknown") == "UNKNOWN"

    def test_get_credential_fields(self):
        """Test _get_credential_fields function."""
        from stance.cli_cloud import _get_credential_fields

        aws_fields = _get_credential_fields("aws")
        assert "aws_access_key_id" in aws_fields
        assert "aws_secret_access_key" in aws_fields

        gcp_fields = _get_credential_fields("gcp")
        assert "gcp_project_id" in gcp_fields

        azure_fields = _get_credential_fields("azure")
        assert "azure_subscription_id" in azure_fields

    def test_get_default_region(self):
        """Test _get_default_region function."""
        from stance.cli_cloud import _get_default_region

        assert _get_default_region("aws") == "us-east-1"
        assert _get_default_region("gcp") == "us-central1"
        assert _get_default_region("azure") == "eastus"

    def test_get_storage_types(self):
        """Test _get_storage_types function."""
        from stance.cli_cloud import _get_storage_types

        aws_types = _get_storage_types("aws")
        assert "s3" in aws_types
        assert "local" in aws_types

        gcp_types = _get_storage_types("gcp")
        assert "gcs" in gcp_types

        azure_types = _get_storage_types("azure")
        assert "blob" in azure_types


class TestCloudCliIntegration:
    """Integration tests for cloud CLI."""

    def test_all_actions_have_handlers(self):
        """Test that all defined actions have handlers."""
        from stance.cli_cloud import cmd_cloud

        # Actions that don't require additional args
        simple_actions = [
            "list", "availability", "credentials", "exceptions", "status", "summary"
        ]

        for action in simple_actions:
            args = argparse.Namespace(
                cloud_action=action,
                format="table",
                provider=None,
            )
            result = cmd_cloud(args)
            assert result == 0, f"Handler for '{action}' failed"

    def test_info_action_all_providers(self):
        """Test info action for all providers."""
        from stance.cli_cloud import _handle_info

        for provider in ["aws", "gcp", "azure"]:
            args = argparse.Namespace(format="json", provider_name=provider)
            result = _handle_info(args)
            assert result == 0, f"Info for '{provider}' failed"

    def test_packages_action_all_providers(self):
        """Test packages action for all providers."""
        from stance.cli_cloud import _handle_packages

        for provider in ["aws", "gcp", "azure"]:
            args = argparse.Namespace(format="json", provider=provider)
            result = _handle_packages(args)
            assert result == 0, f"Packages for '{provider}' failed"

    def test_json_output_is_valid(self, capsys):
        """Test that JSON output is always valid."""
        from stance.cli_cloud import (
            _handle_list,
            _handle_availability,
            _handle_packages,
            _handle_credentials,
            _handle_exceptions,
            _handle_status,
            _handle_summary,
        )

        handlers = [
            (_handle_list, {"format": "json"}),
            (_handle_availability, {"format": "json"}),
            (_handle_packages, {"format": "json", "provider": None}),
            (_handle_credentials, {"format": "json", "provider": None}),
            (_handle_exceptions, {"format": "json"}),
            (_handle_status, {"format": "json"}),
            (_handle_summary, {"format": "json"}),
        ]

        for handler, attrs in handlers:
            args = argparse.Namespace(**attrs)
            handler(args)
            captured = capsys.readouterr()

            try:
                json.loads(captured.out)
            except json.JSONDecodeError:
                pytest.fail(f"Invalid JSON from {handler.__name__}")
