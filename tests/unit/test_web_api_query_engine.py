"""
Tests for Web API query engine endpoints.
"""

import json
from unittest import TestCase
from unittest.mock import patch, MagicMock

from stance.web.server import StanceRequestHandler


class TestQueryExecuteEndpoint(TestCase):
    """Tests for /api/query/execute endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_execute_requires_sql(self):
        """Test execute requires sql parameter."""
        result = self.handler._query_execute({})

        self.assertIn("error", result)
        self.assertIn("sql parameter is required", result["error"])

    def test_execute_basic(self):
        """Test basic query execution."""
        result = self.handler._query_execute({
            "sql": ["SELECT * FROM assets"],
        })

        self.assertIn("sql", result)
        self.assertIn("backend", result)
        self.assertIn("result", result)

    def test_execute_with_limit_param(self):
        """Test execute with limit parameter."""
        result = self.handler._query_execute({
            "sql": ["SELECT * FROM assets"],
            "limit": ["1"],
        })

        self.assertIn("result", result)
        rows = result["result"]["rows"]
        self.assertEqual(len(rows), 1)

    def test_execute_assets_query(self):
        """Test query against assets table."""
        result = self.handler._query_execute({
            "sql": ["SELECT * FROM assets LIMIT 2"],
        })

        self.assertIn("result", result)
        self.assertEqual(result["result"]["row_count"], 2)
        self.assertIn("id", result["result"]["rows"][0])

    def test_execute_findings_query(self):
        """Test query against findings table."""
        result = self.handler._query_execute({
            "sql": ["SELECT * FROM findings"],
        })

        self.assertIn("result", result)
        rows = result["result"]["rows"]
        self.assertTrue(len(rows) > 0)
        self.assertIn("severity", rows[0])

    def test_execute_invalid_query(self):
        """Test execute with invalid query."""
        result = self.handler._query_execute({
            "sql": ["DELETE FROM assets"],
        })

        self.assertIn("result", result)
        self.assertIn("error", result["result"])


class TestQueryEstimateEndpoint(TestCase):
    """Tests for /api/query/estimate endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_estimate_requires_sql(self):
        """Test estimate requires sql parameter."""
        result = self.handler._query_estimate({})

        self.assertIn("error", result)
        self.assertIn("sql parameter is required", result["error"])

    def test_estimate_basic(self):
        """Test basic cost estimation."""
        result = self.handler._query_estimate({
            "sql": ["SELECT * FROM assets"],
        })

        self.assertIn("sql", result)
        self.assertIn("valid", result)
        self.assertIn("estimated_bytes", result)
        self.assertIn("estimated_cost_usd", result)

    def test_estimate_valid_query(self):
        """Test estimate with valid query."""
        result = self.handler._query_estimate({
            "sql": ["SELECT * FROM findings WHERE severity = 'critical'"],
        })

        self.assertTrue(result["valid"])
        self.assertIsInstance(result["estimated_bytes"], int)

    def test_estimate_invalid_query(self):
        """Test estimate with invalid query."""
        result = self.handler._query_estimate({
            "sql": ["UPDATE assets SET name = 'test'"],
        })

        self.assertFalse(result["valid"])
        self.assertIn("errors", result)

    def test_estimate_with_warnings(self):
        """Test estimate includes warnings."""
        result = self.handler._query_estimate({
            "sql": ["SELECT * FROM assets"],
            "backend": ["demo"],
        })

        self.assertIn("warnings", result)
        self.assertIsInstance(result["warnings"], list)


class TestQueryTablesEndpoint(TestCase):
    """Tests for /api/query/tables endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_tables_basic(self):
        """Test tables endpoint."""
        result = self.handler._query_tables({})

        self.assertIn("tables", result)
        self.assertIn("count", result)
        self.assertIn("assets", result["tables"])
        self.assertIn("findings", result["tables"])

    def test_tables_with_backend(self):
        """Test tables with backend parameter."""
        result = self.handler._query_tables({
            "backend": ["demo"],
        })

        self.assertEqual(result["backend"], "demo")
        self.assertTrue(result["count"] >= 2)

    def test_tables_count_matches(self):
        """Test tables count matches list."""
        result = self.handler._query_tables({})

        self.assertEqual(result["count"], len(result["tables"]))


class TestQuerySchemaEndpoint(TestCase):
    """Tests for /api/query/schema endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_schema_requires_table(self):
        """Test schema requires table parameter."""
        result = self.handler._query_schema({})

        self.assertIn("error", result)
        self.assertIn("table parameter is required", result["error"])
        self.assertIn("available_tables", result)

    def test_schema_assets(self):
        """Test schema for assets table."""
        result = self.handler._query_schema({
            "table": ["assets"],
        })

        self.assertEqual(result["table_name"], "assets")
        self.assertIn("columns", result)
        self.assertIn("column_count", result)
        self.assertTrue(result["column_count"] > 0)

    def test_schema_findings(self):
        """Test schema for findings table."""
        result = self.handler._query_schema({
            "table": ["findings"],
        })

        self.assertEqual(result["table_name"], "findings")
        self.assertIn("description", result)

    def test_schema_table_not_found(self):
        """Test schema for non-existent table."""
        result = self.handler._query_schema({
            "table": ["nonexistent"],
        })

        self.assertIn("error", result)
        self.assertIn("Table not found", result["error"])
        self.assertIn("available_tables", result)

    def test_schema_column_structure(self):
        """Test schema columns have correct structure."""
        result = self.handler._query_schema({
            "table": ["assets"],
        })

        columns = result["columns"]
        self.assertTrue(len(columns) > 0)

        first_col = columns[0]
        self.assertIn("name", first_col)
        self.assertIn("type", first_col)


class TestQueryValidateEndpoint(TestCase):
    """Tests for /api/query/validate endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_validate_requires_sql(self):
        """Test validate requires sql parameter."""
        result = self.handler._query_validate({})

        self.assertIn("error", result)
        self.assertIn("sql parameter is required", result["error"])

    def test_validate_valid_select(self):
        """Test validation of valid SELECT query."""
        result = self.handler._query_validate({
            "sql": ["SELECT * FROM assets WHERE id = '123'"],
        })

        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_validate_valid_with_clause(self):
        """Test validation of valid WITH (CTE) query."""
        result = self.handler._query_validate({
            "sql": ["WITH cte AS (SELECT * FROM assets) SELECT * FROM cte"],
        })

        self.assertTrue(result["valid"])

    def test_validate_invalid_delete(self):
        """Test validation rejects DELETE."""
        result = self.handler._query_validate({
            "sql": ["DELETE FROM assets"],
        })

        self.assertFalse(result["valid"])
        self.assertTrue(any("DELETE" in e for e in result["errors"]))

    def test_validate_invalid_insert(self):
        """Test validation rejects INSERT."""
        result = self.handler._query_validate({
            "sql": ["INSERT INTO assets VALUES (1, 2, 3)"],
        })

        self.assertFalse(result["valid"])

    def test_validate_invalid_update(self):
        """Test validation rejects UPDATE."""
        result = self.handler._query_validate({
            "sql": ["UPDATE assets SET name = 'test'"],
        })

        self.assertFalse(result["valid"])

    def test_validate_invalid_drop(self):
        """Test validation rejects DROP."""
        result = self.handler._query_validate({
            "sql": ["DROP TABLE assets"],
        })

        self.assertFalse(result["valid"])

    def test_validate_rejects_comments(self):
        """Test validation rejects SQL comments."""
        result = self.handler._query_validate({
            "sql": ["SELECT * FROM assets -- comment"],
        })

        self.assertFalse(result["valid"])
        self.assertTrue(any("comment" in e.lower() for e in result["errors"]))

    def test_validate_rejects_multiple_statements(self):
        """Test validation rejects multiple statements."""
        result = self.handler._query_validate({
            "sql": ["SELECT * FROM assets; DELETE FROM assets"],
        })

        self.assertFalse(result["valid"])


class TestQueryBackendsEndpoint(TestCase):
    """Tests for /api/query/backends endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_backends_basic(self):
        """Test backends endpoint."""
        result = self.handler._query_backends({})

        self.assertIn("backends", result)
        self.assertIn("total", result)
        self.assertIn("configured", result)

    def test_backends_structure(self):
        """Test backends list structure."""
        result = self.handler._query_backends({})

        backends = result["backends"]
        self.assertTrue(len(backends) >= 4)

        for backend in backends:
            self.assertIn("name", backend)
            self.assertIn("provider", backend)
            self.assertIn("description", backend)
            self.assertIn("configured", backend)

    def test_backends_demo_configured(self):
        """Test demo backend is configured."""
        result = self.handler._query_backends({})

        demo = next((b for b in result["backends"] if b["name"] == "demo"), None)
        self.assertIsNotNone(demo)
        self.assertTrue(demo["configured"])

    def test_backends_providers(self):
        """Test backends include all providers."""
        result = self.handler._query_backends({})

        names = [b["name"] for b in result["backends"]]
        self.assertIn("athena", names)
        self.assertIn("bigquery", names)
        self.assertIn("synapse", names)
        self.assertIn("demo", names)


class TestQueryStatusEndpoint(TestCase):
    """Tests for /api/query/status endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_status_basic(self):
        """Test status endpoint."""
        result = self.handler._query_status({})

        self.assertEqual(result["module"], "query_engine")
        self.assertIn("version", result)
        self.assertIn("capabilities", result)

    def test_status_capabilities(self):
        """Test status capabilities."""
        result = self.handler._query_status({})

        caps = result["capabilities"]
        self.assertTrue(caps["sql_execution"])
        self.assertTrue(caps["cost_estimation"])
        self.assertTrue(caps["schema_introspection"])
        self.assertTrue(caps["query_validation"])

    def test_status_supported_backends(self):
        """Test status supported backends."""
        result = self.handler._query_status({})

        backends = result["supported_backends"]
        self.assertIn("athena", backends)
        self.assertIn("bigquery", backends)
        self.assertIn("synapse", backends)
        self.assertIn("demo", backends)

    def test_status_security_info(self):
        """Test status includes security info."""
        result = self.handler._query_status({})

        security = result["security"]
        self.assertTrue(security["read_only"])
        self.assertIn("forbidden_keywords", security)
        self.assertIn("DELETE", security["forbidden_keywords"])


class TestSqlValidation(TestCase):
    """Tests for SQL validation helper."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_validate_select(self):
        """Test validation of SELECT."""
        errors = self.handler._validate_sql("SELECT * FROM table")
        self.assertEqual(errors, [])

    def test_validate_with_cte(self):
        """Test validation of WITH clause."""
        errors = self.handler._validate_sql("WITH cte AS (SELECT 1) SELECT * FROM cte")
        self.assertEqual(errors, [])

    def test_validate_not_select(self):
        """Test validation of non-SELECT."""
        errors = self.handler._validate_sql("CALL procedure()")
        self.assertTrue(any("SELECT" in e for e in errors))

    def test_validate_forbidden_keywords(self):
        """Test all forbidden keywords are detected."""
        forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE"]

        for keyword in forbidden:
            errors = self.handler._validate_sql(f"{keyword} FROM table")
            self.assertTrue(
                any(keyword in e for e in errors),
                f"Should detect {keyword}"
            )

    def test_validate_comments(self):
        """Test comment detection."""
        comment_types = [
            "SELECT * -- comment",
            "SELECT * /* comment */",
            "SELECT * # comment",
        ]

        for sql in comment_types:
            errors = self.handler._validate_sql(sql)
            self.assertTrue(
                any("comment" in e.lower() for e in errors),
                f"Should detect comment in: {sql}"
            )

    def test_validate_semicolon(self):
        """Test multiple statement detection."""
        errors = self.handler._validate_sql("SELECT 1; SELECT 2")
        self.assertTrue(any("statement" in e.lower() for e in errors))

    def test_validate_string_with_semicolon(self):
        """Test semicolon inside string is allowed."""
        # This is a valid query - semicolon is inside a string
        errors = self.handler._validate_sql("SELECT * FROM t WHERE x = 'a;b'")
        self.assertEqual(errors, [])


class TestDemoQueryExecution(TestCase):
    """Tests for demo query execution."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_execute_assets(self):
        """Test demo execution for assets."""
        result = self.handler._execute_demo_query("SELECT * FROM assets")

        self.assertIn("rows", result)
        self.assertIn("columns", result)
        self.assertTrue(len(result["rows"]) > 0)

    def test_execute_findings(self):
        """Test demo execution for findings."""
        result = self.handler._execute_demo_query("SELECT * FROM findings")

        self.assertIn("rows", result)
        self.assertTrue(len(result["rows"]) > 0)

    def test_execute_with_limit(self):
        """Test demo execution with LIMIT."""
        result = self.handler._execute_demo_query("SELECT * FROM assets LIMIT 1")

        self.assertEqual(len(result["rows"]), 1)

    def test_execute_invalid_query(self):
        """Test demo execution with invalid query."""
        result = self.handler._execute_demo_query("DELETE FROM assets")

        self.assertIn("error", result)

    def test_execute_metadata(self):
        """Test demo execution includes metadata."""
        result = self.handler._execute_demo_query("SELECT * FROM assets")

        self.assertIn("query_id", result)
        self.assertIn("execution_time_ms", result)
        self.assertIn("bytes_scanned", result)


class TestSampleQueryData(TestCase):
    """Tests for sample query data."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_sample_assets(self):
        """Test sample assets generation."""
        assets = self.handler._get_sample_query_assets()

        self.assertEqual(len(assets), 3)
        self.assertIn("id", assets[0])
        self.assertIn("cloud_provider", assets[0])

    def test_sample_findings(self):
        """Test sample findings generation."""
        findings = self.handler._get_sample_query_findings()

        self.assertEqual(len(findings), 3)
        self.assertIn("id", findings[0])
        self.assertIn("severity", findings[0])

    def test_sample_assets_providers(self):
        """Test sample assets include multiple providers."""
        assets = self.handler._get_sample_query_assets()

        providers = [a["cloud_provider"] for a in assets]
        self.assertIn("aws", providers)
        self.assertIn("gcp", providers)

    def test_sample_findings_severities(self):
        """Test sample findings have various severities."""
        findings = self.handler._get_sample_query_findings()

        severities = [f["severity"] for f in findings]
        self.assertIn("critical", severities)
        self.assertIn("high", severities)
        self.assertIn("medium", severities)


class TestQueryAPIRouting(TestCase):
    """Tests for API routing of query endpoints."""

    def test_query_endpoints_exist(self):
        """Test that all query endpoints methods exist."""
        method_names = [
            "_query_execute",
            "_query_estimate",
            "_query_tables",
            "_query_schema",
            "_query_validate",
            "_query_backends",
            "_query_status",
            "_validate_sql",
            "_execute_demo_query",
        ]

        for method_name in method_names:
            self.assertTrue(
                hasattr(StanceRequestHandler, method_name),
                f"Method {method_name} should exist"
            )


class TestQueryIntegration(TestCase):
    """Integration tests for query API endpoints."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_full_query_workflow(self):
        """Test complete query workflow via API."""
        # Step 1: Check module status
        status = self.handler._query_status({})
        self.assertTrue(status["capabilities"]["sql_execution"])

        # Step 2: List available tables
        tables = self.handler._query_tables({})
        self.assertIn("assets", tables["tables"])

        # Step 3: Get schema for table
        schema = self.handler._query_schema({"table": ["assets"]})
        self.assertEqual(schema["table_name"], "assets")

        # Step 4: Validate query
        validation = self.handler._query_validate({
            "sql": ["SELECT * FROM assets WHERE region = 'us-east-1'"],
        })
        self.assertTrue(validation["valid"])

        # Step 5: Estimate cost
        estimate = self.handler._query_estimate({
            "sql": ["SELECT * FROM assets"],
        })
        self.assertIn("estimated_cost_usd", estimate)

        # Step 6: Execute query
        result = self.handler._query_execute({
            "sql": ["SELECT * FROM assets LIMIT 2"],
        })
        self.assertEqual(result["result"]["row_count"], 2)

    def test_validation_before_execution(self):
        """Test that invalid queries are rejected."""
        # Invalid query should fail validation
        validation = self.handler._query_validate({
            "sql": ["DROP TABLE assets"],
        })
        self.assertFalse(validation["valid"])

        # Invalid query should also fail execution
        result = self.handler._query_execute({
            "sql": ["DROP TABLE assets"],
        })
        self.assertIn("error", result["result"])

    def test_schema_to_query_workflow(self):
        """Test using schema to build queries."""
        # Get schema
        schema = self.handler._query_schema({"table": ["findings"]})
        columns = schema["columns"]

        # Use column names in query
        col_names = [c["name"] for c in columns[:3]]
        sql = f"SELECT {', '.join(col_names)} FROM findings"

        # Validate and execute
        validation = self.handler._query_validate({"sql": [sql]})
        self.assertTrue(validation["valid"])

        result = self.handler._query_execute({"sql": [sql]})
        self.assertIn("result", result)
