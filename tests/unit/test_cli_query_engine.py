"""
Tests for CLI query engine commands.
"""

import argparse
import json
from io import StringIO
from unittest import TestCase
from unittest.mock import patch, MagicMock

from stance.cli_query_engine import (
    cmd_sql,
    _cmd_execute,
    _cmd_estimate,
    _cmd_tables,
    _cmd_schema,
    _cmd_validate,
    _cmd_backends,
    _cmd_status,
    _get_engine,
    _DemoQueryEngine,
    _execute_demo_query,
    _get_sample_assets,
    _get_sample_findings,
    add_sql_parser,
)
from stance.query import (
    QueryResult,
    TableSchema,
    CostEstimate,
    QueryValidationError,
    QueryExecutionError,
)


class TestCmdSql(TestCase):
    """Tests for the main sql command router."""

    def test_no_subcommand_shows_help(self):
        """Test that no subcommand shows usage."""
        args = argparse.Namespace(sql_command=None)
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_sql(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Usage: stance sql", output)
        self.assertIn("execute", output)
        self.assertIn("estimate", output)
        self.assertIn("tables", output)
        self.assertIn("schema", output)
        self.assertIn("validate", output)

    def test_unknown_command(self):
        """Test that unknown command returns error."""
        args = argparse.Namespace(sql_command="unknown")
        with patch("sys.stdout", new_callable=StringIO):
            result = cmd_sql(args)

        self.assertEqual(result, 1)

    def test_execute_command_routes(self):
        """Test execute command is routed correctly."""
        args = argparse.Namespace(
            sql_command="execute",
            sql="SELECT * FROM assets LIMIT 1",
            backend="demo",
            format="json",
            timeout=300,
            limit=None,
            dry_run=False,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_sql(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("rows", data)

    def test_status_command_routes(self):
        """Test status command is routed correctly."""
        args = argparse.Namespace(sql_command="status", format="json")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_sql(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertEqual(data["module"], "query_engine")


class TestCmdExecute(TestCase):
    """Tests for the execute command."""

    def test_execute_requires_sql(self):
        """Test execute requires sql parameter."""
        args = argparse.Namespace(
            sql=None,
            backend="demo",
            format="table",
            timeout=300,
            limit=None,
            dry_run=False,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_execute(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("--sql is required", output)

    def test_execute_json_format(self):
        """Test execute with JSON output."""
        args = argparse.Namespace(
            sql="SELECT * FROM assets",
            backend="demo",
            format="json",
            timeout=300,
            limit=None,
            dry_run=False,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_execute(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("rows", data)
        self.assertIn("columns", data)
        self.assertIn("row_count", data)

    def test_execute_table_format(self):
        """Test execute with table output."""
        args = argparse.Namespace(
            sql="SELECT * FROM assets",
            backend="demo",
            format="table",
            timeout=300,
            limit=None,
            dry_run=False,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_execute(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Query Results", output)

    def test_execute_with_limit(self):
        """Test execute with limit parameter."""
        args = argparse.Namespace(
            sql="SELECT * FROM assets",
            backend="demo",
            format="json",
            timeout=300,
            limit=1,
            dry_run=False,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_execute(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertEqual(len(data["rows"]), 1)

    def test_execute_dry_run_json(self):
        """Test execute dry run with JSON output."""
        args = argparse.Namespace(
            sql="SELECT * FROM assets",
            backend="demo",
            format="json",
            timeout=300,
            limit=None,
            dry_run=True,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_execute(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertTrue(data["dry_run"])
        self.assertTrue(data["valid"])
        self.assertIn("estimate", data)

    def test_execute_dry_run_table(self):
        """Test execute dry run with table output."""
        args = argparse.Namespace(
            sql="SELECT * FROM assets",
            backend="demo",
            format="table",
            timeout=300,
            limit=None,
            dry_run=True,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_execute(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Query Preview (Dry Run)", output)
        self.assertIn("Valid:    Yes", output)

    def test_execute_invalid_query_dry_run(self):
        """Test execute dry run with invalid query."""
        args = argparse.Namespace(
            sql="DELETE FROM assets",
            backend="demo",
            format="json",
            timeout=300,
            limit=None,
            dry_run=True,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_execute(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        data = json.loads(output)
        self.assertFalse(data["valid"])
        self.assertIn("Forbidden keyword", data["errors"][0])


class TestCmdEstimate(TestCase):
    """Tests for the estimate command."""

    def test_estimate_requires_sql(self):
        """Test estimate requires sql parameter."""
        args = argparse.Namespace(
            sql=None,
            backend="demo",
            format="table",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_estimate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("--sql is required", output)

    def test_estimate_json(self):
        """Test estimate with JSON output."""
        args = argparse.Namespace(
            sql="SELECT * FROM findings",
            backend="demo",
            format="json",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_estimate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("estimated_bytes", data)
        self.assertIn("estimated_cost_usd", data)
        self.assertIn("warnings", data)

    def test_estimate_table(self):
        """Test estimate with table output."""
        args = argparse.Namespace(
            sql="SELECT * FROM assets",
            backend="demo",
            format="table",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_estimate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Query Cost Estimate", output)
        self.assertIn("Estimated Cost", output)

    def test_estimate_invalid_query(self):
        """Test estimate with invalid query."""
        args = argparse.Namespace(
            sql="DROP TABLE assets",
            backend="demo",
            format="json",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_estimate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        data = json.loads(output)
        self.assertFalse(data["valid"])


class TestCmdTables(TestCase):
    """Tests for the tables command."""

    def test_tables_json(self):
        """Test tables with JSON output."""
        args = argparse.Namespace(backend="demo", format="json")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_tables(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("tables", data)
        self.assertIn("count", data)
        self.assertIn("assets", data["tables"])
        self.assertIn("findings", data["tables"])

    def test_tables_table(self):
        """Test tables with table output."""
        args = argparse.Namespace(backend="demo", format="table")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_tables(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Available Tables", output)
        self.assertIn("assets", output)
        self.assertIn("findings", output)


class TestCmdSchema(TestCase):
    """Tests for the schema command."""

    def test_schema_requires_table(self):
        """Test schema requires table parameter."""
        args = argparse.Namespace(table=None, backend="demo", format="table")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_schema(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("--table is required", output)

    def test_schema_json(self):
        """Test schema with JSON output."""
        args = argparse.Namespace(table="assets", backend="demo", format="json")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_schema(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertEqual(data["table_name"], "assets")
        self.assertIn("columns", data)
        self.assertIn("column_count", data)

    def test_schema_table(self):
        """Test schema with table output."""
        args = argparse.Namespace(table="findings", backend="demo", format="table")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_schema(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Table: findings", output)
        self.assertIn("Column", output)
        self.assertIn("Type", output)

    def test_schema_table_not_found(self):
        """Test schema with non-existent table."""
        args = argparse.Namespace(table="nonexistent", backend="demo", format="table")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_schema(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("Table not found", output)


class TestCmdValidate(TestCase):
    """Tests for the validate command."""

    def test_validate_requires_sql(self):
        """Test validate requires sql parameter."""
        args = argparse.Namespace(sql=None, backend="demo", format="table")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_validate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        self.assertIn("--sql is required", output)

    def test_validate_valid_query_json(self):
        """Test validate with valid query JSON output."""
        args = argparse.Namespace(
            sql="SELECT * FROM assets WHERE region = 'us-east-1'",
            backend="demo",
            format="json",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_validate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertTrue(data["valid"])
        self.assertEqual(data["errors"], [])

    def test_validate_invalid_query_json(self):
        """Test validate with invalid query JSON output."""
        args = argparse.Namespace(
            sql="INSERT INTO assets VALUES (1, 2, 3)",
            backend="demo",
            format="json",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_validate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        data = json.loads(output)
        self.assertFalse(data["valid"])
        self.assertTrue(len(data["errors"]) > 0)

    def test_validate_table_format(self):
        """Test validate with table output."""
        args = argparse.Namespace(
            sql="SELECT * FROM findings",
            backend="demo",
            format="table",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_validate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Query Validation", output)
        self.assertIn("Valid: Yes", output)

    def test_validate_detects_forbidden_keywords(self):
        """Test validate detects various forbidden keywords."""
        forbidden_queries = [
            "DELETE FROM assets",
            "UPDATE assets SET name = 'test'",
            "DROP TABLE findings",
            "CREATE TABLE new_table",
            "ALTER TABLE assets ADD COLUMN x",
            "TRUNCATE TABLE assets",
        ]

        for query in forbidden_queries:
            args = argparse.Namespace(sql=query, backend="demo", format="json")
            with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
                result = _cmd_validate(args)
                output = mock_stdout.getvalue()

            self.assertEqual(result, 1, f"Should reject: {query}")
            data = json.loads(output)
            self.assertFalse(data["valid"], f"Should be invalid: {query}")

    def test_validate_detects_comments(self):
        """Test validate detects SQL comments."""
        args = argparse.Namespace(
            sql="SELECT * FROM assets -- comment",
            backend="demo",
            format="json",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_validate(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 1)
        data = json.loads(output)
        self.assertIn("comments", data["errors"][0].lower())


class TestCmdBackends(TestCase):
    """Tests for the backends command."""

    def test_backends_json(self):
        """Test backends with JSON output."""
        args = argparse.Namespace(format="json")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_backends(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertTrue(len(data) >= 4)

        # Check demo backend is present
        demo = next((b for b in data if b["name"] == "demo"), None)
        self.assertIsNotNone(demo)
        self.assertTrue(demo["configured"])

    def test_backends_table(self):
        """Test backends with table output."""
        args = argparse.Namespace(format="table")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_backends(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Query Backends", output)
        self.assertIn("athena", output)
        self.assertIn("bigquery", output)
        self.assertIn("synapse", output)
        self.assertIn("demo", output)


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
        self.assertEqual(data["module"], "query_engine")
        self.assertIn("capabilities", data)
        self.assertIn("supported_backends", data)
        self.assertIn("security", data)

    def test_status_table(self):
        """Test status with table output."""
        args = argparse.Namespace(format="table")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_status(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Query Engine Status", output)
        self.assertIn("Capabilities", output)
        self.assertIn("Security Features", output)

    def test_status_capabilities(self):
        """Test status shows all capabilities."""
        args = argparse.Namespace(format="json")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = _cmd_status(args)
            output = mock_stdout.getvalue()

        data = json.loads(output)
        caps = data["capabilities"]
        self.assertTrue(caps["sql_execution"])
        self.assertTrue(caps["cost_estimation"])
        self.assertTrue(caps["schema_introspection"])
        self.assertTrue(caps["query_validation"])


class TestDemoQueryEngine(TestCase):
    """Tests for the demo query engine."""

    def test_engine_properties(self):
        """Test demo engine properties."""
        engine = _DemoQueryEngine()
        self.assertEqual(engine.engine_name, "demo")
        self.assertEqual(engine.provider, "local")

    def test_connect_disconnect(self):
        """Test connect and disconnect."""
        engine = _DemoQueryEngine()
        self.assertFalse(engine.is_connected())

        engine.connect()
        self.assertTrue(engine.is_connected())

        engine.disconnect()
        self.assertFalse(engine.is_connected())

    def test_execute_query(self):
        """Test query execution."""
        engine = _DemoQueryEngine()
        result = engine.execute_query("SELECT * FROM assets")

        self.assertIsInstance(result, QueryResult)
        self.assertTrue(len(result.rows) > 0)

    def test_execute_invalid_query(self):
        """Test invalid query raises exception."""
        engine = _DemoQueryEngine()
        with self.assertRaises(QueryValidationError):
            engine.execute_query("DELETE FROM assets")

    def test_list_tables(self):
        """Test list tables."""
        engine = _DemoQueryEngine()
        tables = engine.list_tables()

        self.assertIn("assets", tables)
        self.assertIn("findings", tables)

    def test_get_table_schema(self):
        """Test get table schema."""
        engine = _DemoQueryEngine()
        schema = engine.get_table_schema("assets")

        self.assertEqual(schema.table_name, "assets")
        self.assertTrue(len(schema.columns) > 0)

    def test_get_table_schema_not_found(self):
        """Test get schema for non-existent table."""
        engine = _DemoQueryEngine()
        with self.assertRaises(QueryExecutionError):
            engine.get_table_schema("nonexistent")

    def test_estimate_cost(self):
        """Test cost estimation."""
        engine = _DemoQueryEngine()
        estimate = engine.estimate_cost("SELECT * FROM assets")

        self.assertIsInstance(estimate, CostEstimate)
        self.assertEqual(estimate.estimated_bytes, 0)
        self.assertEqual(estimate.estimated_cost_usd, 0.0)


class TestSampleData(TestCase):
    """Tests for sample data generation."""

    def test_sample_assets(self):
        """Test sample assets generation."""
        assets = _get_sample_assets()

        self.assertEqual(len(assets), 3)
        self.assertIn("id", assets[0])
        self.assertIn("cloud_provider", assets[0])
        self.assertIn("name", assets[0])

    def test_sample_findings(self):
        """Test sample findings generation."""
        findings = _get_sample_findings()

        self.assertEqual(len(findings), 3)
        self.assertIn("id", findings[0])
        self.assertIn("severity", findings[0])
        self.assertIn("title", findings[0])

    def test_execute_demo_query_assets(self):
        """Test demo query execution for assets."""
        result = _execute_demo_query("SELECT * FROM assets")

        self.assertIn("rows", result.to_dict())
        self.assertTrue(result.row_count > 0)

    def test_execute_demo_query_findings(self):
        """Test demo query execution for findings."""
        result = _execute_demo_query("SELECT * FROM findings")

        self.assertIn("rows", result.to_dict())
        self.assertTrue(result.row_count > 0)

    def test_execute_demo_query_with_limit(self):
        """Test demo query with LIMIT."""
        result = _execute_demo_query("SELECT * FROM assets LIMIT 1")

        self.assertEqual(result.row_count, 1)


class TestAddSqlParser(TestCase):
    """Tests for CLI parser configuration."""

    def test_add_sql_parser(self):
        """Test sql parser is added correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")

        add_sql_parser(subparsers)

        # Parse sql command
        args = parser.parse_args(["sql", "status", "--format", "json"])
        self.assertEqual(args.command, "sql")
        self.assertEqual(args.sql_command, "status")
        self.assertEqual(args.format, "json")

    def test_execute_subparser(self):
        """Test execute subparser options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_sql_parser(subparsers)

        args = parser.parse_args([
            "sql", "execute",
            "--sql", "SELECT * FROM assets",
            "--backend", "demo",
            "--limit", "10",
            "--dry-run",
        ])
        self.assertEqual(args.sql_command, "execute")
        self.assertEqual(args.sql, "SELECT * FROM assets")
        self.assertEqual(args.backend, "demo")
        self.assertEqual(args.limit, 10)
        self.assertTrue(args.dry_run)

    def test_schema_subparser(self):
        """Test schema subparser options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        add_sql_parser(subparsers)

        args = parser.parse_args([
            "sql", "schema",
            "--table", "findings",
            "--format", "json",
        ])
        self.assertEqual(args.sql_command, "schema")
        self.assertEqual(args.table, "findings")


class TestCLIIntegration(TestCase):
    """Integration tests for CLI query engine commands."""

    def test_full_query_workflow(self):
        """Test complete query workflow."""
        # Step 1: Check status
        args = argparse.Namespace(sql_command="status", format="json")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_sql(args)
            status = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertTrue(status["capabilities"]["sql_execution"])

        # Step 2: List tables
        args = argparse.Namespace(sql_command="tables", backend="demo", format="json")
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_sql(args)
            tables = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertIn("assets", tables["tables"])

        # Step 3: Get schema
        args = argparse.Namespace(
            sql_command="schema",
            table="assets",
            backend="demo",
            format="json",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_sql(args)
            schema = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertEqual(schema["table_name"], "assets")

        # Step 4: Validate query
        args = argparse.Namespace(
            sql_command="validate",
            sql="SELECT * FROM assets",
            backend="demo",
            format="json",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_sql(args)
            validation = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertTrue(validation["valid"])

        # Step 5: Execute query
        args = argparse.Namespace(
            sql_command="execute",
            sql="SELECT * FROM assets LIMIT 2",
            backend="demo",
            format="json",
            timeout=300,
            limit=None,
            dry_run=False,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_sql(args)
            query_result = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertEqual(query_result["row_count"], 2)

    def test_cost_estimation_workflow(self):
        """Test cost estimation before execution."""
        # Estimate first
        args = argparse.Namespace(
            sql_command="estimate",
            sql="SELECT * FROM findings",
            backend="demo",
            format="json",
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_sql(args)
            estimate = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertIn("estimated_cost_usd", estimate)

        # Then execute with dry-run
        args = argparse.Namespace(
            sql_command="execute",
            sql="SELECT * FROM findings",
            backend="demo",
            format="json",
            timeout=300,
            limit=None,
            dry_run=True,
        )
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            result = cmd_sql(args)
            preview = json.loads(mock_stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertTrue(preview["dry_run"])
