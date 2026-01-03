"""
Unit tests for query engines.

Tests the cloud-native query engine abstractions including Athena, BigQuery,
and Synapse implementations.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from stance.query import (
    QueryEngine,
    QueryResult,
    TableSchema,
    CostEstimate,
    QueryExecutionError,
    QueryValidationError,
    AthenaQueryEngine,
    BigQueryEngine,
    SynapseQueryEngine,
    ASSETS_SCHEMA,
    FINDINGS_SCHEMA,
    get_common_schemas,
    get_query_engine,
)


# ============================================================================
# QueryResult Tests
# ============================================================================


class TestQueryResult:
    """Tests for QueryResult dataclass."""

    def test_query_result_creation(self) -> None:
        """Test QueryResult can be created with required fields."""
        result = QueryResult(
            rows=[{"id": "1", "name": "test"}],
            columns=["id", "name"],
            row_count=1,
        )

        assert len(result.rows) == 1
        assert result.columns == ["id", "name"]
        assert result.row_count == 1
        assert result.bytes_scanned == 0
        assert result.execution_time_ms == 0
        assert result.query_id == ""
        assert result.metadata == {}

    def test_query_result_with_all_fields(self) -> None:
        """Test QueryResult with all fields populated."""
        result = QueryResult(
            rows=[{"id": "1"}, {"id": "2"}],
            columns=["id"],
            row_count=2,
            bytes_scanned=1024,
            execution_time_ms=100,
            query_id="query-123",
            metadata={"engine": "athena"},
        )

        assert result.bytes_scanned == 1024
        assert result.execution_time_ms == 100
        assert result.query_id == "query-123"
        assert result.metadata["engine"] == "athena"

    def test_query_result_to_list(self) -> None:
        """Test to_list returns rows."""
        rows = [{"id": "1"}, {"id": "2"}]
        result = QueryResult(rows=rows, columns=["id"], row_count=2)

        assert result.to_list() == rows

    def test_query_result_to_dict(self) -> None:
        """Test to_dict returns full result."""
        result = QueryResult(
            rows=[{"id": "1"}],
            columns=["id"],
            row_count=1,
            bytes_scanned=512,
            execution_time_ms=50,
            query_id="q-1",
            metadata={"test": True},
        )

        d = result.to_dict()
        assert d["rows"] == [{"id": "1"}]
        assert d["columns"] == ["id"]
        assert d["row_count"] == 1
        assert d["bytes_scanned"] == 512
        assert d["execution_time_ms"] == 50
        assert d["query_id"] == "q-1"
        assert d["metadata"]["test"] is True


# ============================================================================
# TableSchema Tests
# ============================================================================


class TestTableSchema:
    """Tests for TableSchema dataclass."""

    def test_table_schema_creation(self) -> None:
        """Test TableSchema can be created with required fields."""
        schema = TableSchema(
            table_name="assets",
            columns=[
                {"name": "id", "type": "STRING"},
                {"name": "name", "type": "STRING"},
            ],
        )

        assert schema.table_name == "assets"
        assert len(schema.columns) == 2
        assert schema.description == ""
        assert schema.row_count is None
        assert schema.size_bytes is None

    def test_table_schema_with_all_fields(self) -> None:
        """Test TableSchema with all fields populated."""
        schema = TableSchema(
            table_name="findings",
            columns=[{"name": "id", "type": "STRING"}],
            description="Security findings table",
            row_count=1000,
            size_bytes=1048576,
        )

        assert schema.description == "Security findings table"
        assert schema.row_count == 1000
        assert schema.size_bytes == 1048576

    def test_get_column_names(self) -> None:
        """Test get_column_names returns list of column names."""
        schema = TableSchema(
            table_name="test",
            columns=[
                {"name": "id", "type": "STRING"},
                {"name": "name", "type": "STRING"},
                {"name": "created_at", "type": "TIMESTAMP"},
            ],
        )

        assert schema.get_column_names() == ["id", "name", "created_at"]

    def test_get_column_types(self) -> None:
        """Test get_column_types returns mapping of names to types."""
        schema = TableSchema(
            table_name="test",
            columns=[
                {"name": "id", "type": "STRING"},
                {"name": "count", "type": "INTEGER"},
            ],
        )

        types = schema.get_column_types()
        assert types["id"] == "STRING"
        assert types["count"] == "INTEGER"


# ============================================================================
# CostEstimate Tests
# ============================================================================


class TestCostEstimate:
    """Tests for CostEstimate dataclass."""

    def test_cost_estimate_defaults(self) -> None:
        """Test CostEstimate with default values."""
        estimate = CostEstimate()

        assert estimate.estimated_bytes == 0
        assert estimate.estimated_cost_usd == 0.0
        assert estimate.warnings == []

    def test_cost_estimate_with_values(self) -> None:
        """Test CostEstimate with populated values."""
        estimate = CostEstimate(
            estimated_bytes=1073741824,  # 1 GB
            estimated_cost_usd=0.005,
            warnings=["Estimate based on table size"],
        )

        assert estimate.estimated_bytes == 1073741824
        assert estimate.estimated_cost_usd == 0.005
        assert len(estimate.warnings) == 1


# ============================================================================
# Common Schemas Tests
# ============================================================================


class TestCommonSchemas:
    """Tests for common schema definitions."""

    def test_assets_schema(self) -> None:
        """Test ASSETS_SCHEMA is properly defined."""
        assert ASSETS_SCHEMA.table_name == "assets"
        assert len(ASSETS_SCHEMA.columns) > 0

        column_names = ASSETS_SCHEMA.get_column_names()
        assert "id" in column_names
        assert "cloud_provider" in column_names
        assert "resource_type" in column_names

    def test_findings_schema(self) -> None:
        """Test FINDINGS_SCHEMA is properly defined."""
        assert FINDINGS_SCHEMA.table_name == "findings"
        assert len(FINDINGS_SCHEMA.columns) > 0

        column_names = FINDINGS_SCHEMA.get_column_names()
        assert "id" in column_names
        assert "severity" in column_names
        assert "status" in column_names

    def test_get_common_schemas(self) -> None:
        """Test get_common_schemas returns both schemas."""
        schemas = get_common_schemas()

        assert "assets" in schemas
        assert "findings" in schemas
        assert schemas["assets"] is ASSETS_SCHEMA
        assert schemas["findings"] is FINDINGS_SCHEMA


# ============================================================================
# Query Validation Tests
# ============================================================================


class TestQueryValidation:
    """Tests for query validation logic."""

    @pytest.fixture
    def engine(self) -> AthenaQueryEngine:
        """Create engine for validation tests."""
        return AthenaQueryEngine(database="test_db")

    def test_valid_select_query(self, engine: AthenaQueryEngine) -> None:
        """Test valid SELECT query passes validation."""
        errors = engine.validate_query("SELECT * FROM assets")
        assert errors == []

    def test_valid_select_with_where(self, engine: AthenaQueryEngine) -> None:
        """Test SELECT with WHERE clause passes validation."""
        errors = engine.validate_query(
            "SELECT id, name FROM assets WHERE severity = 'critical'"
        )
        assert errors == []

    def test_valid_with_cte(self, engine: AthenaQueryEngine) -> None:
        """Test WITH (CTE) query passes validation."""
        errors = engine.validate_query(
            "WITH cte AS (SELECT * FROM assets) SELECT * FROM cte"
        )
        assert errors == []

    def test_invalid_insert_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test INSERT query is rejected."""
        errors = engine.validate_query("INSERT INTO assets VALUES ('test')")
        assert len(errors) > 0
        assert any("INSERT" in e for e in errors)

    def test_invalid_update_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test UPDATE query is rejected."""
        errors = engine.validate_query("UPDATE assets SET name = 'test'")
        assert len(errors) > 0
        assert any("UPDATE" in e for e in errors)

    def test_invalid_delete_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test DELETE query is rejected."""
        errors = engine.validate_query("DELETE FROM assets WHERE id = '1'")
        assert len(errors) > 0
        assert any("DELETE" in e for e in errors)

    def test_invalid_drop_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test DROP query is rejected."""
        errors = engine.validate_query("DROP TABLE assets")
        assert len(errors) > 0
        assert any("DROP" in e for e in errors)

    def test_invalid_create_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test CREATE query is rejected."""
        errors = engine.validate_query("CREATE TABLE test (id STRING)")
        assert len(errors) > 0
        assert any("CREATE" in e for e in errors)

    def test_invalid_truncate_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test TRUNCATE query is rejected."""
        errors = engine.validate_query("TRUNCATE TABLE assets")
        assert len(errors) > 0
        assert any("TRUNCATE" in e for e in errors)

    def test_invalid_grant_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test GRANT query is rejected."""
        errors = engine.validate_query("GRANT SELECT ON assets TO user")
        assert len(errors) > 0
        assert any("GRANT" in e for e in errors)

    def test_comments_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test SQL comments are rejected."""
        errors = engine.validate_query("SELECT * FROM assets -- comment")
        assert len(errors) > 0
        assert any("comment" in e.lower() for e in errors)

    def test_block_comments_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test block comments are rejected."""
        errors = engine.validate_query("SELECT /* comment */ * FROM assets")
        assert len(errors) > 0
        assert any("comment" in e.lower() for e in errors)

    def test_multiple_statements_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test multiple statements are rejected."""
        errors = engine.validate_query("SELECT * FROM assets; DROP TABLE assets")
        assert len(errors) > 0
        assert any("Multiple" in e for e in errors)

    def test_semicolon_in_string_allowed(self, engine: AthenaQueryEngine) -> None:
        """Test semicolon inside string literals is allowed."""
        errors = engine.validate_query("SELECT * FROM assets WHERE name = 'a;b'")
        assert errors == []

    def test_not_select_rejected(self, engine: AthenaQueryEngine) -> None:
        """Test non-SELECT queries are rejected."""
        errors = engine.validate_query("SHOW TABLES")
        assert len(errors) > 0
        assert any("SELECT" in e or "WITH" in e for e in errors)


# ============================================================================
# AthenaQueryEngine Tests
# ============================================================================


class TestAthenaQueryEngine:
    """Tests for AthenaQueryEngine."""

    def test_engine_creation(self) -> None:
        """Test AthenaQueryEngine can be created."""
        engine = AthenaQueryEngine(
            database="test_db",
            workgroup="test-wg",
            output_location="s3://bucket/results/",
            region="us-west-2",
        )

        assert engine.database == "test_db"
        assert engine.workgroup == "test-wg"
        assert engine.engine_name == "athena"
        assert engine.provider == "aws"

    def test_engine_defaults(self) -> None:
        """Test AthenaQueryEngine default values."""
        engine = AthenaQueryEngine(database="test_db")

        assert engine.workgroup == "primary"
        assert engine.engine_name == "athena"
        assert engine.is_connected() is False

    def test_engine_is_query_engine(self) -> None:
        """Test AthenaQueryEngine is a QueryEngine."""
        engine = AthenaQueryEngine(database="test")
        assert isinstance(engine, QueryEngine)

    def test_engine_has_required_methods(self) -> None:
        """Test AthenaQueryEngine has all required methods."""
        engine = AthenaQueryEngine(database="test")

        assert hasattr(engine, "connect")
        assert hasattr(engine, "disconnect")
        assert hasattr(engine, "execute_query")
        assert hasattr(engine, "execute_safe")
        assert hasattr(engine, "get_table_schema")
        assert hasattr(engine, "list_tables")
        assert hasattr(engine, "estimate_cost")
        assert hasattr(engine, "validate_query")

    @patch("boto3.client")
    def test_execute_safe_validates(self, mock_boto: MagicMock) -> None:
        """Test execute_safe validates queries before execution."""
        engine = AthenaQueryEngine(database="test")

        with pytest.raises(QueryValidationError) as exc_info:
            engine.execute_safe("DROP TABLE assets")

        assert "DROP" in str(exc_info.value)


# ============================================================================
# BigQueryEngine Tests
# ============================================================================


class TestBigQueryEngine:
    """Tests for BigQueryEngine."""

    def test_engine_creation(self) -> None:
        """Test BigQueryEngine can be created."""
        engine = BigQueryEngine(
            project_id="my-project",
            dataset_id="stance_data",
            location="US",
        )

        assert engine.project_id == "my-project"
        assert engine.dataset_id == "stance_data"
        assert engine.engine_name == "bigquery"
        assert engine.provider == "gcp"

    def test_engine_defaults(self) -> None:
        """Test BigQueryEngine default values."""
        engine = BigQueryEngine(
            project_id="project",
            dataset_id="dataset",
        )

        # Location is internal (_location), verify engine is not connected by default
        assert engine.is_connected() is False
        assert engine.project_id == "project"
        assert engine.dataset_id == "dataset"

    def test_engine_is_query_engine(self) -> None:
        """Test BigQueryEngine is a QueryEngine."""
        engine = BigQueryEngine(project_id="p", dataset_id="d")
        assert isinstance(engine, QueryEngine)

    def test_engine_has_required_methods(self) -> None:
        """Test BigQueryEngine has all required methods."""
        engine = BigQueryEngine(project_id="p", dataset_id="d")

        assert hasattr(engine, "connect")
        assert hasattr(engine, "disconnect")
        assert hasattr(engine, "execute_query")
        assert hasattr(engine, "execute_safe")
        assert hasattr(engine, "get_table_schema")
        assert hasattr(engine, "list_tables")
        assert hasattr(engine, "estimate_cost")
        assert hasattr(engine, "validate_query")


# ============================================================================
# SynapseQueryEngine Tests
# ============================================================================


class TestSynapseQueryEngine:
    """Tests for SynapseQueryEngine."""

    def test_engine_creation(self) -> None:
        """Test SynapseQueryEngine can be created."""
        engine = SynapseQueryEngine(
            server="workspace.sql.azuresynapse.net",
            database="stance_db",
        )

        assert engine.server == "workspace.sql.azuresynapse.net"
        assert engine.database == "stance_db"
        assert engine.engine_name == "synapse"
        assert engine.provider == "azure"

    def test_engine_is_query_engine(self) -> None:
        """Test SynapseQueryEngine is a QueryEngine."""
        engine = SynapseQueryEngine(server="s", database="d")
        assert isinstance(engine, QueryEngine)

    def test_engine_has_required_methods(self) -> None:
        """Test SynapseQueryEngine has all required methods."""
        engine = SynapseQueryEngine(server="s", database="d")

        assert hasattr(engine, "connect")
        assert hasattr(engine, "disconnect")
        assert hasattr(engine, "execute_query")
        assert hasattr(engine, "execute_safe")
        assert hasattr(engine, "get_table_schema")
        assert hasattr(engine, "list_tables")
        assert hasattr(engine, "estimate_cost")
        assert hasattr(engine, "validate_query")


# ============================================================================
# Factory Function Tests
# ============================================================================


class TestGetQueryEngine:
    """Tests for get_query_engine factory function."""

    def test_get_aws_engine(self) -> None:
        """Test getting AWS Athena engine."""
        engine = get_query_engine(
            "aws",
            database="test_db",
            workgroup="test-wg",
        )

        assert isinstance(engine, AthenaQueryEngine)
        assert engine.provider == "aws"

    def test_get_gcp_engine(self) -> None:
        """Test getting GCP BigQuery engine."""
        engine = get_query_engine(
            "gcp",
            project_id="my-project",
            dataset_id="my-dataset",
        )

        assert isinstance(engine, BigQueryEngine)
        assert engine.provider == "gcp"

    def test_get_azure_engine(self) -> None:
        """Test getting Azure Synapse engine."""
        engine = get_query_engine(
            "azure",
            server="test.sql.azuresynapse.net",
            database="test_db",
        )

        assert isinstance(engine, SynapseQueryEngine)
        assert engine.provider == "azure"

    def test_provider_case_insensitive(self) -> None:
        """Test provider name is case insensitive."""
        engine1 = get_query_engine("AWS", database="test")
        engine2 = get_query_engine("Aws", database="test")

        assert isinstance(engine1, AthenaQueryEngine)
        assert isinstance(engine2, AthenaQueryEngine)

    def test_unknown_provider_raises(self) -> None:
        """Test unknown provider raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            get_query_engine("unknown")

        assert "Unsupported provider" in str(exc_info.value)


# ============================================================================
# Context Manager Tests
# ============================================================================


class TestQueryEngineContextManager:
    """Tests for QueryEngine context manager support."""

    @patch.object(AthenaQueryEngine, "connect")
    @patch.object(AthenaQueryEngine, "disconnect")
    def test_context_manager_calls_connect_disconnect(
        self, mock_disconnect: MagicMock, mock_connect: MagicMock
    ) -> None:
        """Test context manager calls connect and disconnect."""
        engine = AthenaQueryEngine(database="test")

        with engine:
            mock_connect.assert_called_once()

        mock_disconnect.assert_called_once()

    @patch.object(AthenaQueryEngine, "connect")
    @patch.object(AthenaQueryEngine, "disconnect")
    def test_context_manager_disconnect_on_exception(
        self, mock_disconnect: MagicMock, mock_connect: MagicMock
    ) -> None:
        """Test context manager calls disconnect even on exception."""
        engine = AthenaQueryEngine(database="test")

        with pytest.raises(RuntimeError):
            with engine:
                raise RuntimeError("Test error")

        mock_disconnect.assert_called_once()


# ============================================================================
# Exception Tests
# ============================================================================


class TestQueryExceptions:
    """Tests for query exception classes."""

    def test_query_validation_error(self) -> None:
        """Test QueryValidationError can be raised and caught."""
        with pytest.raises(QueryValidationError) as exc_info:
            raise QueryValidationError("Invalid query")

        assert "Invalid query" in str(exc_info.value)

    def test_query_execution_error(self) -> None:
        """Test QueryExecutionError can be raised and caught."""
        with pytest.raises(QueryExecutionError) as exc_info:
            raise QueryExecutionError("Query failed")

        assert "Query failed" in str(exc_info.value)

    def test_exceptions_are_exceptions(self) -> None:
        """Test query exceptions inherit from Exception."""
        assert issubclass(QueryValidationError, Exception)
        assert issubclass(QueryExecutionError, Exception)
