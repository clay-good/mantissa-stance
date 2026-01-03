"""
Tests for CLI aggregation commands.
"""

import argparse
import json
from datetime import datetime
from io import StringIO
from unittest import TestCase
from unittest.mock import patch, MagicMock

from stance.cli_aggregation import (
    cmd_aggregation,
    _cmd_aggregate,
    _cmd_cross_account,
    _cmd_summary,
    _cmd_sync,
    _cmd_sync_status,
    _cmd_federate,
    _cmd_backends,
    _cmd_status,
    _get_sample_aggregation_data,
    _get_sample_backends,
    add_aggregation_parser,
)
from stance.aggregation import (
    FindingsAggregator,
    CloudAccount,
    AggregationResult,
    SyncConfig,
    SyncDirection,
    ConflictResolution,
    QueryStrategy,
    MergeStrategy,
)
from stance.models.finding import Finding, Severity


class TestCmdAggregation(TestCase):
    """Tests for the main aggregation command router."""

    def test_no_subcommand_shows_help(self):
        """Test that no subcommand shows usage."""
        args = argparse.Namespace(aggregation_command=None)
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Usage: stance aggregation", output)
        self.assertIn("aggregate", output)
        self.assertIn("cross-account", output)
        self.assertIn("summary", output)
        self.assertIn("sync", output)
        self.assertIn("federate", output)
        self.assertIn("backends", output)
        self.assertIn("status", output)

    def test_unknown_command(self):
        """Test that unknown command returns error."""
        args = argparse.Namespace(aggregation_command="unknown")
        with patch("sys.stdout", new_callable=StringIO):
            result = cmd_aggregation(args)

        self.assertEqual(result, 1)

    def test_aggregate_command_routes(self):
        """Test aggregate command is routed correctly."""
        args = argparse.Namespace(
            aggregation_command="aggregate",
            format="json",
            severity=None,
            deduplicate=True,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("result", data)
        self.assertIn("findings", data)

    def test_cross_account_command_routes(self):
        """Test cross-account command is routed correctly."""
        args = argparse.Namespace(
            aggregation_command="cross-account",
            format="json",
            min_accounts=2,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("min_accounts", data)
        self.assertIn("count", data)

    def test_summary_command_routes(self):
        """Test summary command is routed correctly."""
        args = argparse.Namespace(
            aggregation_command="summary",
            format="json",
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("summary", data)

    def test_status_command_routes(self):
        """Test status command is routed correctly."""
        args = argparse.Namespace(
            aggregation_command="status",
            format="json",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertEqual(data["module"], "aggregation")


class TestCmdAggregate(TestCase):
    """Tests for the aggregate command."""

    def test_aggregate_json_format(self):
        """Test aggregate command with JSON output."""
        args = argparse.Namespace(
            format="json",
            severity=None,
            deduplicate=True,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_aggregate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("result", data)
        self.assertIn("findings", data)
        self.assertIn("total_findings", data["result"])
        self.assertIn("unique_findings", data["result"])
        self.assertIn("duplicates_removed", data["result"])

    def test_aggregate_table_format(self):
        """Test aggregate command with table output."""
        args = argparse.Namespace(
            format="table",
            severity=None,
            deduplicate=True,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_aggregate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Aggregation Result", output)
        self.assertIn("Total Findings", output)
        self.assertIn("Unique Findings", output)

    def test_aggregate_with_severity_filter(self):
        """Test aggregate command with severity filter."""
        args = argparse.Namespace(
            format="json",
            severity="critical",
            deduplicate=True,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_aggregate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        # Should only include critical findings
        for finding in data["findings"]:
            self.assertEqual(finding["severity"], "critical")

    def test_aggregate_with_invalid_severity(self):
        """Test aggregate command with invalid severity."""
        args = argparse.Namespace(
            format="json",
            severity="invalid",
            deduplicate=True,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO):
            result = _cmd_aggregate(args)

        self.assertEqual(result, 1)

    def test_aggregate_without_deduplication(self):
        """Test aggregate command without deduplication."""
        args = argparse.Namespace(
            format="json",
            severity=None,
            deduplicate=False,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_aggregate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        # Without dedup, total == unique
        self.assertEqual(
            data["result"]["total_findings"],
            data["result"]["unique_findings"]
        )


class TestCmdCrossAccount(TestCase):
    """Tests for the cross-account command."""

    def test_cross_account_json_format(self):
        """Test cross-account command with JSON output."""
        args = argparse.Namespace(
            format="json",
            min_accounts=2,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_cross_account(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("min_accounts", data)
        self.assertIn("count", data)
        self.assertIn("findings", data)
        self.assertEqual(data["min_accounts"], 2)

    def test_cross_account_table_format(self):
        """Test cross-account command with table output."""
        args = argparse.Namespace(
            format="table",
            min_accounts=2,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_cross_account(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Cross-Account Findings", output)

    def test_cross_account_higher_threshold(self):
        """Test cross-account with higher threshold."""
        args = argparse.Namespace(
            format="json",
            min_accounts=5,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_cross_account(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        # With only 3 sample accounts, no findings should appear in 5+
        self.assertEqual(data["count"], 0)


class TestCmdSummary(TestCase):
    """Tests for the summary command."""

    def test_summary_json_format(self):
        """Test summary command with JSON output."""
        args = argparse.Namespace(
            format="json",
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_summary(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("summary", data)
        self.assertIn("by_severity", data)
        self.assertIn("by_provider", data)

    def test_summary_table_format(self):
        """Test summary command with table output."""
        args = argparse.Namespace(
            format="table",
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_summary(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Aggregation Summary Report", output)
        self.assertIn("Overview", output)
        self.assertIn("Findings by Severity", output)


class TestCmdSync(TestCase):
    """Tests for the sync command."""

    def test_sync_requires_bucket(self):
        """Test sync command requires bucket parameter."""
        args = argparse.Namespace(
            format="table",
            bucket=None,
            prefix="aggregated",
            direction="push",
            conflict_resolution="latest_wins",
            dry_run=False,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_sync(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("--bucket is required", output)

    def test_sync_dry_run_json(self):
        """Test sync dry run with JSON output."""
        args = argparse.Namespace(
            format="json",
            bucket="my-bucket",
            prefix="aggregated",
            direction="push",
            conflict_resolution="latest_wins",
            dry_run=True,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_sync(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertTrue(data["dry_run"])
        self.assertEqual(data["config"]["bucket"], "my-bucket")

    def test_sync_dry_run_table(self):
        """Test sync dry run with table output."""
        args = argparse.Namespace(
            format="table",
            bucket="my-bucket",
            prefix="aggregated",
            direction="push",
            conflict_resolution="latest_wins",
            dry_run=True,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_sync(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Sync Configuration (Dry Run)", output)
        self.assertIn("my-bucket", output)

    def test_sync_invalid_direction(self):
        """Test sync with invalid direction."""
        args = argparse.Namespace(
            format="table",
            bucket="my-bucket",
            prefix="aggregated",
            direction="invalid",
            conflict_resolution="latest_wins",
            dry_run=True,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_sync(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("Invalid direction", output)

    def test_sync_invalid_conflict_resolution(self):
        """Test sync with invalid conflict resolution."""
        args = argparse.Namespace(
            format="table",
            bucket="my-bucket",
            prefix="aggregated",
            direction="push",
            conflict_resolution="invalid",
            dry_run=True,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_sync(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("Invalid conflict resolution", output)


class TestCmdSyncStatus(TestCase):
    """Tests for the sync-status command."""

    def test_sync_status_json(self):
        """Test sync-status with JSON output."""
        args = argparse.Namespace(format="json")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_sync_status(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("sync_enabled", data)
        self.assertIn("last_sync", data)
        self.assertIn("pending_records", data)

    def test_sync_status_table(self):
        """Test sync-status with table output."""
        args = argparse.Namespace(format="table")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_sync_status(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Sync Status", output)
        self.assertIn("Sync Enabled", output)


class TestCmdFederate(TestCase):
    """Tests for the federate command."""

    def test_federate_requires_query(self):
        """Test federate command requires query parameter."""
        args = argparse.Namespace(
            format="table",
            query=None,
            backends=None,
            strategy="parallel",
            merge="union",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_federate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("--query is required", output)

    def test_federate_json(self):
        """Test federate with JSON output."""
        args = argparse.Namespace(
            format="json",
            query="SELECT * FROM findings",
            backends=None,
            strategy="parallel",
            merge="union",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_federate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertEqual(data["query"], "SELECT * FROM findings")
        self.assertEqual(data["strategy"], "parallel")

    def test_federate_with_specific_backends(self):
        """Test federate with specific backends."""
        args = argparse.Namespace(
            format="json",
            query="SELECT * FROM findings",
            backends="aws-prod,gcp-prod",
            strategy="parallel",
            merge="union",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_federate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertEqual(data["backends_requested"], ["aws-prod", "gcp-prod"])

    def test_federate_invalid_strategy(self):
        """Test federate with invalid strategy."""
        args = argparse.Namespace(
            format="table",
            query="SELECT * FROM findings",
            backends=None,
            strategy="invalid",
            merge="union",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_federate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("Invalid query strategy", output)

    def test_federate_invalid_merge(self):
        """Test federate with invalid merge strategy."""
        args = argparse.Namespace(
            format="table",
            query="SELECT * FROM findings",
            backends=None,
            strategy="parallel",
            merge="invalid",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_federate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("Invalid merge strategy", output)


class TestCmdBackends(TestCase):
    """Tests for the backends command."""

    def test_backends_list_json(self):
        """Test backends list with JSON output."""
        args = argparse.Namespace(
            format="json",
            action="list",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_backends(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertTrue(len(data) > 0)
        self.assertIn("name", data[0])
        self.assertIn("provider", data[0])

    def test_backends_list_table(self):
        """Test backends list with table output."""
        args = argparse.Namespace(
            format="table",
            action="list",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_backends(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Query Backends", output)
        self.assertIn("Name", output)
        self.assertIn("Provider", output)

    def test_backends_status_json(self):
        """Test backends status with JSON output."""
        args = argparse.Namespace(
            format="json",
            action="status",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_backends(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("backends", data)
        self.assertIn("total", data)
        self.assertIn("enabled", data)

    def test_backends_invalid_action(self):
        """Test backends with invalid action."""
        args = argparse.Namespace(
            format="table",
            action="invalid",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_backends(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("Unknown action", output)


class TestCmdStatus(TestCase):
    """Tests for the status command."""

    def test_status_json(self):
        """Test status with JSON output."""
        args = argparse.Namespace(format="json")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_status(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertEqual(data["module"], "aggregation")
        self.assertIn("capabilities", data)
        self.assertIn("supported_providers", data)

    def test_status_table(self):
        """Test status with table output."""
        args = argparse.Namespace(format="table")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_status(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Aggregation Module Status", output)
        self.assertIn("Capabilities", output)
        self.assertIn("multi_account_aggregation", output.lower().replace("_", " "))


class TestSampleData(TestCase):
    """Tests for sample data generation."""

    def test_get_sample_aggregation_data(self):
        """Test sample aggregation data generation."""
        accounts, findings_by_account = _get_sample_aggregation_data()

        self.assertEqual(len(accounts), 3)
        self.assertEqual(len(findings_by_account), 3)

        # Check account structure
        aws_account = accounts[0]
        self.assertEqual(aws_account.provider, "aws")
        self.assertEqual(aws_account.id, "123456789012")

        # Check findings
        self.assertIn("123456789012", findings_by_account)
        self.assertTrue(len(findings_by_account["123456789012"]) > 0)

    def test_get_sample_backends(self):
        """Test sample backends generation."""
        backends = _get_sample_backends()

        self.assertEqual(len(backends), 3)

        # Check backend structure
        aws_backend = backends[0]
        self.assertEqual(aws_backend["provider"], "aws")
        self.assertEqual(aws_backend["engine"], "Athena")
        self.assertIn("enabled", aws_backend)
        self.assertIn("priority", aws_backend)


class TestAddAggregationParser(TestCase):
    """Tests for CLI parser configuration."""

    def test_add_aggregation_parser(self):
        """Test aggregation parser is added correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")

        add_aggregation_parser(subparsers)

        # Parse aggregation command
        args = parser.parse_args(["aggregation", "status", "--format", "json"])
        self.assertEqual(args.command, "aggregation")
        self.assertEqual(args.aggregation_command, "status")
        self.assertEqual(args.format, "json")

    def test_aggregate_subparser(self):
        """Test aggregate subparser options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_aggregation_parser(subparsers)

        args = parser.parse_args([
            "aggregation", "aggregate",
            "--severity", "critical",
            "--no-deduplicate",
            "--format", "json",
        ])
        self.assertEqual(args.aggregation_command, "aggregate")
        self.assertEqual(args.severity, "critical")
        self.assertFalse(args.deduplicate)

    def test_sync_subparser(self):
        """Test sync subparser options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_aggregation_parser(subparsers)

        args = parser.parse_args([
            "aggregation", "sync",
            "--bucket", "my-bucket",
            "--direction", "push",
            "--conflict-resolution", "latest_wins",
            "--dry-run",
        ])
        self.assertEqual(args.aggregation_command, "sync")
        self.assertEqual(args.bucket, "my-bucket")
        self.assertEqual(args.direction, "push")
        self.assertTrue(args.dry_run)

    def test_federate_subparser(self):
        """Test federate subparser options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_aggregation_parser(subparsers)

        args = parser.parse_args([
            "aggregation", "federate",
            "--query", "SELECT * FROM findings",
            "--backends", "aws,gcp",
            "--strategy", "parallel",
            "--merge", "union",
        ])
        self.assertEqual(args.aggregation_command, "federate")
        self.assertEqual(args.query, "SELECT * FROM findings")
        self.assertEqual(args.backends, "aws,gcp")
        self.assertEqual(args.strategy, "parallel")


class TestCLIIntegration(TestCase):
    """Integration tests for CLI aggregation commands."""

    def test_full_aggregation_workflow(self):
        """Test complete aggregation workflow."""
        # Step 1: Check status
        args = argparse.Namespace(aggregation_command="status", format="json")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            status = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertTrue(status["capabilities"]["multi_account_aggregation"])

        # Step 2: Run aggregation
        args = argparse.Namespace(
            aggregation_command="aggregate",
            format="json",
            severity=None,
            deduplicate=True,
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            agg_result = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertIn("result", agg_result)

        # Step 3: Get summary
        args = argparse.Namespace(
            aggregation_command="summary",
            format="json",
            accounts_file=None,
            findings_dir=None,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            summary = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertIn("summary", summary)

    def test_sync_workflow(self):
        """Test sync workflow with dry run."""
        # Step 1: Check sync status
        args = argparse.Namespace(
            aggregation_command="sync-status",
            format="json",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            status = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertFalse(status["sync_enabled"])

        # Step 2: Dry run sync
        args = argparse.Namespace(
            aggregation_command="sync",
            format="json",
            bucket="test-bucket",
            prefix="aggregated",
            direction="push",
            conflict_resolution="latest_wins",
            dry_run=True,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            sync_result = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertTrue(sync_result["dry_run"])

    def test_backends_workflow(self):
        """Test backends management workflow."""
        # List backends
        args = argparse.Namespace(
            aggregation_command="backends",
            format="json",
            action="list",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            backends = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertIsInstance(backends, list)

        # Check status
        args = argparse.Namespace(
            aggregation_command="backends",
            format="json",
            action="status",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_aggregation(args)
            status = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertIn("total", status)
