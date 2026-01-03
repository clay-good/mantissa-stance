"""
Unit tests for CLI Collectors module.

Tests the CLI commands for collector management including listing,
viewing details, provider information, and registry inspection.
"""

from __future__ import annotations

import argparse
import json
from typing import Any
from unittest import mock

import pytest


class TestAddCollectorsParser:
    """Tests for add_collectors_parser function."""

    def test_parser_creation(self):
        """Test that collectors parser is created correctly."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        # Parse a valid collectors command
        args = parser.parse_args(["collectors", "list"])
        assert args.collectors_action == "list"

    def test_list_command_with_provider(self):
        """Test list command with provider option."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "list", "--provider", "aws"])
        assert args.collectors_action == "list"
        assert args.provider == "aws"

    def test_list_command_with_format(self):
        """Test list command with format option."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "list", "--format", "json"])
        assert args.collectors_action == "list"
        assert args.format == "json"

    def test_info_command(self):
        """Test info command."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "info", "aws_iam"])
        assert args.collectors_action == "info"
        assert args.collector_name == "aws_iam"

    def test_providers_command(self):
        """Test providers command."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "providers"])
        assert args.collectors_action == "providers"

    def test_resources_command_with_options(self):
        """Test resources command with options."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "resources", "--provider", "aws", "--collector", "aws_iam"])
        assert args.collectors_action == "resources"
        assert args.provider == "aws"
        assert args.collector == "aws_iam"

    def test_registry_command(self):
        """Test registry command."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "registry"])
        assert args.collectors_action == "registry"

    def test_availability_command(self):
        """Test availability command."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "availability"])
        assert args.collectors_action == "availability"

    def test_categories_command(self):
        """Test categories command."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "categories"])
        assert args.collectors_action == "categories"

    def test_count_command(self):
        """Test count command."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "count"])
        assert args.collectors_action == "count"

    def test_stats_command(self):
        """Test stats command."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "stats"])
        assert args.collectors_action == "stats"

    def test_status_command(self):
        """Test status command."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "status"])
        assert args.collectors_action == "status"

    def test_summary_command(self):
        """Test summary command."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        args = parser.parse_args(["collectors", "summary"])
        assert args.collectors_action == "summary"


class TestCmdCollectors:
    """Tests for cmd_collectors function."""

    def test_no_action_shows_help(self, capsys):
        """Test that no action shows help."""
        from stance.cli_collectors import cmd_collectors

        args = argparse.Namespace(collectors_action=None)
        result = cmd_collectors(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Available actions:" in captured.out

    def test_unknown_action_returns_error(self, capsys):
        """Test that unknown action returns error."""
        from stance.cli_collectors import cmd_collectors

        args = argparse.Namespace(collectors_action="unknown")
        result = cmd_collectors(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown collectors action" in captured.out


class TestHandleList:
    """Tests for _handle_list function."""

    def test_list_all_collectors_table(self, capsys):
        """Test listing all collectors in table format."""
        from stance.cli_collectors import _handle_list

        args = argparse.Namespace(format="table", provider=None)
        result = _handle_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Collectors" in captured.out
        assert "aws_iam" in captured.out
        assert "identity" in captured.out

    def test_list_all_collectors_json(self, capsys):
        """Test listing all collectors in JSON format."""
        from stance.cli_collectors import _handle_list

        args = argparse.Namespace(format="json", provider=None)
        result = _handle_list(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) > 0
        # Check AWS collectors are present
        aws_names = [c["name"] for c in data if c.get("provider") == "aws"]
        assert "aws_iam" in aws_names

    def test_list_filtered_by_provider(self, capsys):
        """Test listing collectors filtered by provider."""
        from stance.cli_collectors import _handle_list

        args = argparse.Namespace(format="table", provider="aws")
        result = _handle_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "AWS" in captured.out
        assert "aws_iam" in captured.out

    def test_list_filtered_by_provider_json(self, capsys):
        """Test listing collectors filtered by provider in JSON format."""
        from stance.cli_collectors import _handle_list

        args = argparse.Namespace(format="json", provider="aws")
        result = _handle_list(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        # All should be AWS collectors
        for c in data:
            assert "aws" in c.get("name", "") or c.get("provider", "") == "aws"


class TestHandleInfo:
    """Tests for _handle_info function."""

    def test_info_existing_collector_table(self, capsys):
        """Test info for existing collector in table format."""
        from stance.cli_collectors import _handle_info

        args = argparse.Namespace(format="table", collector_name="aws_iam")
        result = _handle_info(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "aws_iam" in captured.out
        assert "Provider:" in captured.out
        assert "aws" in captured.out
        assert "identity" in captured.out

    def test_info_existing_collector_json(self, capsys):
        """Test info for existing collector in JSON format."""
        from stance.cli_collectors import _handle_info

        args = argparse.Namespace(format="json", collector_name="aws_iam")
        result = _handle_info(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["name"] == "aws_iam"
        assert data["provider"] == "aws"
        assert data["category"] == "identity"
        assert data["available"] is True

    def test_info_nonexistent_collector(self, capsys):
        """Test info for nonexistent collector."""
        from stance.cli_collectors import _handle_info

        args = argparse.Namespace(format="table", collector_name="nonexistent")
        result = _handle_info(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestHandleProviders:
    """Tests for _handle_providers function."""

    def test_providers_table(self, capsys):
        """Test providers in table format."""
        from stance.cli_collectors import _handle_providers

        args = argparse.Namespace(format="table")
        result = _handle_providers(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Cloud Providers" in captured.out
        assert "aws" in captured.out
        assert "gcp" in captured.out
        assert "azure" in captured.out
        assert "kubernetes" in captured.out

    def test_providers_json(self, capsys):
        """Test providers in JSON format."""
        from stance.cli_collectors import _handle_providers

        args = argparse.Namespace(format="json")
        result = _handle_providers(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 4
        providers = [p["provider"] for p in data]
        assert "aws" in providers
        assert "gcp" in providers
        assert "azure" in providers
        assert "kubernetes" in providers


class TestHandleResources:
    """Tests for _handle_resources function."""

    def test_resources_all_table(self, capsys):
        """Test resources listing in table format."""
        from stance.cli_collectors import _handle_resources

        args = argparse.Namespace(format="table", provider=None, collector=None)
        result = _handle_resources(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Resource Types" in captured.out

    def test_resources_all_json(self, capsys):
        """Test resources listing in JSON format."""
        from stance.cli_collectors import _handle_resources

        args = argparse.Namespace(format="json", provider=None, collector=None)
        result = _handle_resources(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)

    def test_resources_filtered_by_provider(self, capsys):
        """Test resources filtered by provider."""
        from stance.cli_collectors import _handle_resources

        args = argparse.Namespace(format="table", provider="aws", collector=None)
        result = _handle_resources(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Resource Types" in captured.out

    def test_resources_filtered_by_collector(self, capsys):
        """Test resources filtered by collector."""
        from stance.cli_collectors import _handle_resources

        args = argparse.Namespace(format="table", provider=None, collector="aws_iam")
        result = _handle_resources(args)

        assert result == 0
        captured = capsys.readouterr()
        # Should only show IAM resource types


class TestHandleRegistry:
    """Tests for _handle_registry function."""

    def test_registry_table(self, capsys):
        """Test registry in table format."""
        from stance.cli_collectors import _handle_registry

        args = argparse.Namespace(format="table")
        result = _handle_registry(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Collector Registry" in captured.out
        assert "AWS" in captured.out

    def test_registry_json(self, capsys):
        """Test registry in JSON format."""
        from stance.cli_collectors import _handle_registry

        args = argparse.Namespace(format="json")
        result = _handle_registry(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "aws" in data
        assert isinstance(data["aws"], list)


class TestHandleAvailability:
    """Tests for _handle_availability function."""

    def test_availability_table(self, capsys):
        """Test availability in table format."""
        from stance.cli_collectors import _handle_availability

        args = argparse.Namespace(format="table")
        result = _handle_availability(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Collector Availability" in captured.out
        assert "AWS" in captured.out
        assert "[+]" in captured.out  # AWS should be available

    def test_availability_json(self, capsys):
        """Test availability in JSON format."""
        from stance.cli_collectors import _handle_availability

        args = argparse.Namespace(format="json")
        result = _handle_availability(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 4

        # AWS should always be available
        aws = [a for a in data if a["provider"] == "aws"][0]
        assert aws["available"] is True


class TestHandleCategories:
    """Tests for _handle_categories function."""

    def test_categories_table(self, capsys):
        """Test categories in table format."""
        from stance.cli_collectors import _handle_categories

        args = argparse.Namespace(format="table")
        result = _handle_categories(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Collector Categories" in captured.out
        assert "IDENTITY" in captured.out
        assert "STORAGE" in captured.out
        assert "COMPUTE" in captured.out
        assert "SECURITY" in captured.out

    def test_categories_json(self, capsys):
        """Test categories in JSON format."""
        from stance.cli_collectors import _handle_categories

        args = argparse.Namespace(format="json")
        result = _handle_categories(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)

        categories = [c["category"] for c in data]
        assert "identity" in categories
        assert "storage" in categories
        assert "compute" in categories
        assert "security" in categories


class TestHandleCount:
    """Tests for _handle_count function."""

    def test_count_table(self, capsys):
        """Test count in table format."""
        from stance.cli_collectors import _handle_count

        args = argparse.Namespace(format="table")
        result = _handle_count(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Collector Counts" in captured.out
        assert "aws" in captured.out
        assert "Total" in captured.out

    def test_count_json(self, capsys):
        """Test count in JSON format."""
        from stance.cli_collectors import _handle_count

        args = argparse.Namespace(format="json")
        result = _handle_count(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "counts" in data
        assert "total" in data
        assert isinstance(data["counts"], list)


class TestHandleStats:
    """Tests for _handle_stats function."""

    def test_stats_table(self, capsys):
        """Test stats in table format."""
        from stance.cli_collectors import _handle_stats

        args = argparse.Namespace(format="table")
        result = _handle_stats(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Collector Statistics" in captured.out
        assert "Total Collectors:" in captured.out
        assert "Available Providers:" in captured.out

    def test_stats_json(self, capsys):
        """Test stats in JSON format."""
        from stance.cli_collectors import _handle_stats

        args = argparse.Namespace(format="json")
        result = _handle_stats(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "total_collectors" in data
        assert "available_providers" in data
        assert "by_provider" in data
        assert "sdk_availability" in data


class TestHandleStatus:
    """Tests for _handle_status function."""

    def test_status_table(self, capsys):
        """Test status in table format."""
        from stance.cli_collectors import _handle_status

        args = argparse.Namespace(format="table")
        result = _handle_status(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Collectors Module Status" in captured.out
        assert "collectors" in captured.out
        assert "Components:" in captured.out
        assert "BaseCollector" in captured.out

    def test_status_json(self, capsys):
        """Test status in JSON format."""
        from stance.cli_collectors import _handle_status

        args = argparse.Namespace(format="json")
        result = _handle_status(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "collectors"
        assert "components" in data
        assert "providers" in data
        assert "capabilities" in data


class TestHandleSummary:
    """Tests for _handle_summary function."""

    def test_summary_table(self, capsys):
        """Test summary in table format."""
        from stance.cli_collectors import _handle_summary

        args = argparse.Namespace(format="table")
        result = _handle_summary(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Collectors Module Summary" in captured.out
        assert "Providers:" in captured.out
        assert "Categories:" in captured.out
        assert "Features:" in captured.out

    def test_summary_json(self, capsys):
        """Test summary in JSON format."""
        from stance.cli_collectors import _handle_summary

        args = argparse.Namespace(format="json")
        result = _handle_summary(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "overview" in data
        assert "categories" in data
        assert "features" in data
        assert "architecture" in data


class TestGetCollectorMetadata:
    """Tests for _get_collector_metadata helper function."""

    def test_metadata_structure(self):
        """Test metadata structure."""
        from stance.cli_collectors import _get_collector_metadata

        metadata = _get_collector_metadata()

        assert "aws" in metadata
        assert "gcp" in metadata
        assert "azure" in metadata
        assert "kubernetes" in metadata

        # AWS collectors should always be present
        assert len(metadata["aws"]) == 10

        # Check collector structure
        for collector in metadata["aws"]:
            assert "name" in collector
            assert "description" in collector
            assert "category" in collector

    def test_aws_collectors_always_present(self):
        """Test that AWS collectors are always present."""
        from stance.cli_collectors import _get_collector_metadata

        metadata = _get_collector_metadata()
        aws_names = [c["name"] for c in metadata["aws"]]

        expected_aws = [
            "aws_iam", "aws_s3", "aws_ec2", "aws_security", "aws_rds",
            "aws_lambda", "aws_dynamodb", "aws_apigateway", "aws_ecr", "aws_eks"
        ]

        for name in expected_aws:
            assert name in aws_names


class TestGetResourceTypes:
    """Tests for _get_resource_types helper function."""

    def test_get_resource_types_aws_iam(self):
        """Test getting resource types for aws_iam collector."""
        from stance.cli_collectors import _get_resource_types

        resource_types = _get_resource_types("aws_iam")

        # Should return list of resource types from collector class
        assert isinstance(resource_types, list)

    def test_get_resource_types_nonexistent(self):
        """Test getting resource types for nonexistent collector."""
        from stance.cli_collectors import _get_resource_types

        resource_types = _get_resource_types("nonexistent")

        assert resource_types == []


class TestCollectorsCliIntegration:
    """Integration tests for collectors CLI."""

    def test_all_actions_have_handlers(self):
        """Test that all defined actions have handlers."""
        from stance.cli_collectors import cmd_collectors

        actions = [
            "list", "info", "providers", "resources", "registry",
            "availability", "categories", "count", "stats", "status", "summary"
        ]

        for action in actions:
            if action == "info":
                # info requires collector_name
                args = argparse.Namespace(
                    collectors_action=action,
                    collector_name="aws_iam",
                    format="table"
                )
            else:
                args = argparse.Namespace(
                    collectors_action=action,
                    format="table",
                    provider=None,
                    collector=None
                )

            result = cmd_collectors(args)
            # All handlers should return 0 for valid actions
            assert result == 0, f"Handler for '{action}' failed"

    def test_output_format_options(self):
        """Test that all commands support table and JSON formats."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        # Test table format
        args = parser.parse_args(["collectors", "list", "--format", "table"])
        assert args.format == "table"

        # Test JSON format
        args = parser.parse_args(["collectors", "list", "--format", "json"])
        assert args.format == "json"

    def test_provider_filter_options(self):
        """Test provider filter options."""
        from stance.cli_collectors import add_collectors_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_collectors_parser(subparsers)

        providers = ["aws", "gcp", "azure", "kubernetes"]
        for provider in providers:
            args = parser.parse_args(["collectors", "list", "--provider", provider])
            assert args.provider == provider


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_provider_collectors(self, capsys):
        """Test handling of empty provider collectors list."""
        from stance.cli_collectors import _handle_list

        # Mock GCP not available
        with mock.patch("stance.collectors.GCP_COLLECTORS_AVAILABLE", False):
            args = argparse.Namespace(format="table", provider="gcp")
            result = _handle_list(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "No collectors found" in captured.out

    def test_json_output_is_valid(self, capsys):
        """Test that JSON output is always valid JSON."""
        from stance.cli_collectors import (
            _handle_list,
            _handle_providers,
            _handle_availability,
            _handle_categories,
            _handle_count,
            _handle_stats,
            _handle_status,
            _handle_summary,
        )

        handlers = [
            (_handle_list, {"format": "json", "provider": None}),
            (_handle_providers, {"format": "json"}),
            (_handle_availability, {"format": "json"}),
            (_handle_categories, {"format": "json"}),
            (_handle_count, {"format": "json"}),
            (_handle_stats, {"format": "json"}),
            (_handle_status, {"format": "json"}),
            (_handle_summary, {"format": "json"}),
        ]

        for handler, attrs in handlers:
            args = argparse.Namespace(**attrs)
            handler(args)
            captured = capsys.readouterr()

            # Should be valid JSON
            try:
                json.loads(captured.out)
            except json.JSONDecodeError:
                pytest.fail(f"Invalid JSON from {handler.__name__}")

    def test_info_with_different_collectors(self, capsys):
        """Test info command with different AWS collectors."""
        from stance.cli_collectors import _handle_info

        collectors = ["aws_iam", "aws_s3", "aws_ec2", "aws_rds", "aws_lambda"]

        for collector in collectors:
            args = argparse.Namespace(format="json", collector_name=collector)
            result = _handle_info(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["name"] == collector
            assert data["provider"] == "aws"
