"""
Integration tests for query interface.

Tests cover:
- Natural language to SQL translation
- Query validation
- Query execution against storage
- LLM provider integration
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import tempfile

import pytest

from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    Severity,
    FindingStatus,
    NETWORK_EXPOSURE_INTERNAL,
)
from stance.storage import LocalStorage, generate_snapshot_id
from stance.llm import (
    LLMProvider,
    AnthropicProvider,
    OpenAIProvider,
    GeminiProvider,
    QueryGenerator,
    get_llm_provider,
)
from stance.query import (
    QueryEngine,
    AthenaQueryEngine,
    BigQueryEngine,
    SynapseQueryEngine,
    QueryResult,
)


@pytest.fixture
def populated_storage(tmp_path):
    """Create storage with sample data."""
    db_path = str(tmp_path / "test.db")
    storage = LocalStorage(db_path=db_path)
    snapshot_id = "20240115-120000"

    # Create sample assets
    assets = AssetCollection([
        Asset(
            id=f"arn:aws:s3:::bucket-{i}",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1" if i % 2 == 0 else "us-west-2",
            resource_type="aws_s3_bucket",
            name=f"bucket-{i}",
            tags={"Environment": "prod" if i < 5 else "dev"},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            created_at=datetime(2024, 1, i + 1, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={"encryption": {"enabled": i % 2 == 0}},
        )
        for i in range(10)
    ])
    storage.store_assets(assets, snapshot_id)

    # Create sample findings
    findings = FindingCollection([
        Finding(
            id=f"finding-{i:03d}",
            asset_id=f"arn:aws:s3:::bucket-{i % 10}",
            finding_type=FindingType.MISCONFIGURATION if i % 2 == 0 else FindingType.VULNERABILITY,
            severity=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW][i % 4],
            status=FindingStatus.OPEN if i < 8 else FindingStatus.RESOLVED,
            title=f"Finding {i}",
            description=f"Description for finding {i}",
            rule_id=f"rule-{i % 3:03d}" if i % 2 == 0 else None,
            cve_id=f"CVE-2024-{i:04d}" if i % 2 == 1 else None,
            first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        )
        for i in range(20)
    ])
    storage.store_findings(findings, snapshot_id)

    return storage


class TestQueryValidation:
    """Test SQL query validation."""

    def test_valid_select_query(self):
        """Test valid SELECT query passes validation."""
        engine = AthenaQueryEngine(
            database="test",
            workgroup="test",
            output_location="s3://test",
        )

        errors = engine.validate_query("SELECT * FROM assets")
        assert errors == []

    def test_invalid_insert_rejected(self):
        """Test INSERT query is rejected."""
        engine = AthenaQueryEngine(
            database="test",
            workgroup="test",
            output_location="s3://test",
        )

        errors = engine.validate_query("INSERT INTO assets VALUES ('test')")
        assert len(errors) > 0
        assert any("INSERT" in e.upper() for e in errors)

    def test_invalid_update_rejected(self):
        """Test UPDATE query is rejected."""
        engine = AthenaQueryEngine(
            database="test",
            workgroup="test",
            output_location="s3://test",
        )

        errors = engine.validate_query("UPDATE assets SET name = 'test'")
        assert len(errors) > 0

    def test_invalid_delete_rejected(self):
        """Test DELETE query is rejected."""
        engine = AthenaQueryEngine(
            database="test",
            workgroup="test",
            output_location="s3://test",
        )

        errors = engine.validate_query("DELETE FROM assets")
        assert len(errors) > 0

    def test_invalid_drop_rejected(self):
        """Test DROP query is rejected."""
        engine = AthenaQueryEngine(
            database="test",
            workgroup="test",
            output_location="s3://test",
        )

        errors = engine.validate_query("DROP TABLE assets")
        assert len(errors) > 0


class TestQueryGeneration:
    """Test natural language to SQL generation."""

    def test_query_generator_creation(self):
        """Test QueryGenerator can be created."""
        mock_llm = MagicMock(spec=LLMProvider)
        generator = QueryGenerator(mock_llm)
        assert generator is not None

    @patch.object(AnthropicProvider, "generate")
    def test_generate_sql_from_natural_language(self, mock_generate):
        """Test generating SQL from natural language."""
        mock_generate.return_value = "SELECT * FROM findings WHERE severity = 'critical'"

        mock_llm = MagicMock(spec=LLMProvider)
        mock_llm.generate.return_value = "SELECT * FROM findings WHERE severity = 'critical'"

        generator = QueryGenerator(mock_llm)
        result = generator.generate_query("show me all critical findings")

        assert result.sql is not None
        assert "SELECT" in result.sql.upper()

    def test_generated_query_validation(self):
        """Test that generated queries are validated."""
        mock_llm = MagicMock(spec=LLMProvider)
        mock_llm.generate.return_value = "SELECT * FROM findings"

        generator = QueryGenerator(mock_llm)
        result = generator.generate_query("show all findings")

        assert result.is_valid is True
        assert result.validation_errors == []

    def test_malicious_query_rejected(self):
        """Test that malicious generated queries are rejected."""
        mock_llm = MagicMock(spec=LLMProvider)
        mock_llm.generate.return_value = "DROP TABLE findings; SELECT * FROM findings"

        generator = QueryGenerator(mock_llm)
        result = generator.generate_query("delete everything")

        # Should fail validation
        assert result.is_valid is False or "DROP" in str(result.validation_errors)


class TestLLMProviders:
    """Test LLM provider creation and configuration."""

    def test_get_anthropic_provider(self):
        """Test creating Anthropic provider."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            provider = get_llm_provider("anthropic")
            assert isinstance(provider, AnthropicProvider)
            assert provider.provider_name == "anthropic"

    def test_get_openai_provider(self):
        """Test creating OpenAI provider."""
        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}):
            provider = get_llm_provider("openai")
            assert isinstance(provider, OpenAIProvider)
            assert provider.provider_name == "openai"

    def test_get_gemini_provider(self):
        """Test creating Gemini provider."""
        with patch.dict("os.environ", {"GOOGLE_API_KEY": "test-key"}):
            provider = get_llm_provider("gemini")
            assert isinstance(provider, GeminiProvider)
            assert provider.provider_name == "gemini"

    def test_unknown_provider_raises(self):
        """Test unknown provider raises error."""
        with pytest.raises(ValueError):
            get_llm_provider("unknown-provider")


class TestQueryEngines:
    """Test query engine implementations."""

    def test_athena_engine_creation(self):
        """Test Athena query engine creation."""
        engine = AthenaQueryEngine(
            database="test_db",
            workgroup="primary",
            output_location="s3://test-bucket/results",
        )
        assert engine is not None
        # engine_name property, not provider_name
        assert engine.engine_name == "athena"

    def test_bigquery_engine_creation(self):
        """Test BigQuery engine creation."""
        # BigQuery uses project_id and dataset_id
        engine = BigQueryEngine(
            project_id="test-project",
            dataset_id="test_dataset",
        )
        assert engine is not None
        assert engine.engine_name == "bigquery"

    def test_synapse_engine_creation(self):
        """Test Synapse query engine creation."""
        # Synapse uses server and database
        engine = SynapseQueryEngine(
            server="test-workspace.sql.azuresynapse.net",
            database="test_db",
        )
        assert engine is not None
        assert engine.engine_name == "synapse"


class TestQueryExecution:
    """Test query execution against storage."""

    def test_query_assets_from_storage(self, populated_storage):
        """Test querying assets from local storage."""
        # LocalStorage provides query methods
        results = populated_storage.query_assets(
            "SELECT * FROM assets WHERE region = 'us-east-1'"
        )

        # Should return assets in us-east-1 (even indices)
        assert len(results) == 5

    def test_query_findings_by_severity(self, populated_storage):
        """Test querying findings by severity."""
        results = populated_storage.query_findings(
            "SELECT * FROM findings WHERE severity = 'critical'"
        )

        # Findings 0, 4, 8, 12, 16 have CRITICAL severity (index % 4 == 0)
        assert len(results) == 5

    def test_query_open_findings(self, populated_storage):
        """Test querying open findings."""
        results = populated_storage.query_findings(
            "SELECT * FROM findings WHERE status = 'open'"
        )

        # First 8 findings are OPEN
        assert len(results) == 8


class TestQueryResults:
    """Test QueryResult structure."""

    def test_query_result_creation(self):
        """Test QueryResult dataclass."""
        result = QueryResult(
            rows=[{"id": "1", "name": "test"}],
            columns=["id", "name"],
            row_count=1,
            execution_time_ms=100.0,
        )

        assert result.row_count == 1
        assert len(result.columns) == 2

    def test_query_result_empty(self):
        """Test empty QueryResult."""
        result = QueryResult(
            rows=[],
            columns=["id"],
            row_count=0,
            execution_time_ms=50.0,
        )

        assert result.row_count == 0
        assert len(result.rows) == 0


class TestIntegratedQueryWorkflow:
    """Test complete query workflow."""

    def test_natural_language_to_results(self, populated_storage):
        """Test complete flow from natural language to results."""
        # Mock the LLM to return a valid SQL query
        mock_llm = MagicMock(spec=LLMProvider)
        mock_llm.generate.return_value = "SELECT * FROM findings WHERE severity = 'critical'"

        # Generate query
        generator = QueryGenerator(mock_llm)
        generated = generator.generate_query("show critical findings")

        # Validate
        assert generated.is_valid

        # Execute against storage
        results = populated_storage.query_findings(generated.sql)

        # Should get results
        assert len(results) > 0

    def test_query_with_complex_filter(self, populated_storage):
        """Test query with complex WHERE clause."""
        results = populated_storage.query_findings(
            """
            SELECT * FROM findings
            WHERE severity IN ('critical', 'high')
            AND status = 'open'
            """
        )

        # Filter for critical/high severity AND open status
        for finding in results:
            assert finding["severity"] in ("critical", "high")
            assert finding["status"] == "open"
