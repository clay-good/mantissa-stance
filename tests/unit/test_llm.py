"""
Tests for Mantissa Stance LLM providers and query generation.

Tests cover:
- LLM provider base classes
- Provider factory function
- Query generator and validation
- Provider interface compliance
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from stance.llm import (
    LLMProvider,
    LLMResponse,
    LLMError,
    RateLimitError,
    AuthenticationError,
    AnthropicProvider,
    OpenAIProvider,
    GeminiProvider,
    QueryGenerator,
    GeneratedQuery,
    POSTURE_SCHEMA,
    get_llm_provider,
)


class TestLLMError:
    """Tests for LLM error classes."""

    def test_llm_error_basic(self):
        """Test basic LLMError creation."""
        error = LLMError("Test error")
        assert str(error) == "Test error"

    def test_llm_error_with_details(self):
        """Test LLMError with all details."""
        error = LLMError(
            "API error",
            provider="anthropic",
            status_code=500,
            retry_after=30,
        )

        assert "API error" in str(error)
        assert error.provider == "anthropic"
        assert error.status_code == 500
        assert error.retry_after == 30

    def test_rate_limit_error(self):
        """Test RateLimitError is subclass of LLMError."""
        error = RateLimitError("Rate limit exceeded", retry_after=60)

        assert isinstance(error, LLMError)
        assert error.retry_after == 60

    def test_authentication_error(self):
        """Test AuthenticationError is subclass of LLMError."""
        error = AuthenticationError("Invalid API key", provider="openai")

        assert isinstance(error, LLMError)
        assert error.provider == "openai"


class TestLLMResponse:
    """Tests for LLMResponse dataclass."""

    def test_llm_response_creation(self):
        """Test LLMResponse creation."""
        response = LLMResponse(
            text="Generated text",
            provider="anthropic",
            model="claude-3-haiku-20240307",
            tokens_used=100,
            duration_seconds=1.5,
        )

        assert response.text == "Generated text"
        assert response.provider == "anthropic"
        assert response.model == "claude-3-haiku-20240307"
        assert response.tokens_used == 100
        assert response.duration_seconds == 1.5


class TestGetLLMProvider:
    """Tests for the get_llm_provider factory function."""

    def test_get_anthropic_provider(self):
        """Test getting Anthropic provider."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            provider = get_llm_provider("anthropic")

            assert isinstance(provider, AnthropicProvider)
            assert provider.provider_name == "anthropic"

    def test_get_openai_provider(self):
        """Test getting OpenAI provider."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            provider = get_llm_provider("openai")

            assert isinstance(provider, OpenAIProvider)
            assert provider.provider_name == "openai"

    def test_get_gemini_provider(self):
        """Test getting Gemini provider."""
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"}):
            provider = get_llm_provider("gemini")

            assert isinstance(provider, GeminiProvider)
            assert provider.provider_name == "gemini"

    def test_case_insensitive_provider_name(self):
        """Test provider name is case insensitive."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            provider1 = get_llm_provider("ANTHROPIC")
            provider2 = get_llm_provider("Anthropic")
            provider3 = get_llm_provider("anthropic")

            assert isinstance(provider1, AnthropicProvider)
            assert isinstance(provider2, AnthropicProvider)
            assert isinstance(provider3, AnthropicProvider)

    def test_unknown_provider_raises(self):
        """Test unknown provider raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            get_llm_provider("unknown")

        assert "Unknown LLM provider" in str(exc_info.value)

    def test_custom_model_passed(self):
        """Test custom model is passed to provider."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            provider = get_llm_provider("openai", model="gpt-4-turbo")

            assert provider.model_name == "gpt-4-turbo"

    def test_custom_api_key_passed(self):
        """Test custom API key is passed to provider."""
        provider = get_llm_provider("anthropic", api_key="custom-key")

        assert provider._api_key == "custom-key"


class TestAnthropicProvider:
    """Tests for AnthropicProvider."""

    def test_provider_name(self):
        """Test provider name."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            provider = AnthropicProvider()
            assert provider.provider_name == "anthropic"

    def test_default_model(self):
        """Test default model name."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            provider = AnthropicProvider()
            assert "claude" in provider.model_name.lower()

    def test_custom_model(self):
        """Test custom model name."""
        provider = AnthropicProvider(api_key="test", model="claude-3-opus-20240229")
        assert provider.model_name == "claude-3-opus-20240229"

    def test_is_llm_provider(self):
        """Test AnthropicProvider is LLMProvider."""
        provider = AnthropicProvider(api_key="test")
        assert isinstance(provider, LLMProvider)

    def test_has_generate_method(self):
        """Test has generate method."""
        provider = AnthropicProvider(api_key="test")
        assert hasattr(provider, "generate")
        assert callable(provider.generate)


class TestOpenAIProvider:
    """Tests for OpenAIProvider."""

    def test_provider_name(self):
        """Test provider name."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            provider = OpenAIProvider()
            assert provider.provider_name == "openai"

    def test_default_model(self):
        """Test default model name."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            provider = OpenAIProvider()
            assert "gpt" in provider.model_name.lower()

    def test_custom_model(self):
        """Test custom model name."""
        provider = OpenAIProvider(api_key="test", model="gpt-4-turbo")
        assert provider.model_name == "gpt-4-turbo"

    def test_is_llm_provider(self):
        """Test OpenAIProvider is LLMProvider."""
        provider = OpenAIProvider(api_key="test")
        assert isinstance(provider, LLMProvider)


class TestGeminiProvider:
    """Tests for GeminiProvider."""

    def test_provider_name(self):
        """Test provider name."""
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"}):
            provider = GeminiProvider()
            assert provider.provider_name == "gemini"

    def test_default_model(self):
        """Test default model name."""
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"}):
            provider = GeminiProvider()
            assert "gemini" in provider.model_name.lower()

    def test_custom_model(self):
        """Test custom model name."""
        provider = GeminiProvider(api_key="test", model="gemini-1.5-pro")
        assert provider.model_name == "gemini-1.5-pro"

    def test_is_llm_provider(self):
        """Test GeminiProvider is LLMProvider."""
        provider = GeminiProvider(api_key="test")
        assert isinstance(provider, LLMProvider)


class TestGeneratedQuery:
    """Tests for GeneratedQuery dataclass."""

    def test_generated_query_creation(self):
        """Test GeneratedQuery creation."""
        query = GeneratedQuery(
            question="Show critical findings",
            sql="SELECT * FROM findings WHERE severity = 'critical'",
            explanation="Lists all critical findings",
            is_valid=True,
            validation_errors=[],
        )

        assert query.question == "Show critical findings"
        assert "SELECT" in query.sql
        assert query.is_valid is True
        assert query.validation_errors == []

    def test_generated_query_with_errors(self):
        """Test GeneratedQuery with validation errors."""
        query = GeneratedQuery(
            question="Delete all findings",
            sql="DELETE FROM findings",
            explanation="",
            is_valid=False,
            validation_errors=["Query must start with SELECT", "Query cannot contain DELETE"],
        )

        assert query.is_valid is False
        assert len(query.validation_errors) == 2


class TestQueryGenerator:
    """Tests for QueryGenerator."""

    @pytest.fixture
    def mock_llm(self):
        """Create a mock LLM provider."""
        mock = MagicMock(spec=LLMProvider)
        mock.provider_name = "mock"
        mock.model_name = "mock-model"
        return mock

    @pytest.fixture
    def generator(self, mock_llm):
        """Create a QueryGenerator with mock LLM."""
        return QueryGenerator(mock_llm)

    def test_generator_init(self, mock_llm):
        """Test QueryGenerator initialization."""
        generator = QueryGenerator(mock_llm)
        assert generator._llm == mock_llm
        assert generator._schema == POSTURE_SCHEMA

    def test_generator_custom_schema(self, mock_llm):
        """Test QueryGenerator with custom schema."""
        custom_schema = "Custom table schema"
        generator = QueryGenerator(mock_llm, schema_context=custom_schema)
        assert generator._schema == custom_schema

    def test_generate_query_success(self, generator, mock_llm):
        """Test successful query generation."""
        mock_llm.generate.return_value = "SELECT * FROM findings WHERE severity = 'critical'"

        result = generator.generate_query("Show critical findings")

        assert isinstance(result, GeneratedQuery)
        assert result.question == "Show critical findings"
        assert result.sql == "SELECT * FROM findings WHERE severity = 'critical'"
        assert result.is_valid is True
        assert result.validation_errors == []

    def test_generate_query_cleans_markdown(self, generator, mock_llm):
        """Test that markdown code blocks are cleaned from output."""
        mock_llm.generate.return_value = "```sql\nSELECT * FROM findings\n```"

        result = generator.generate_query("Show all findings")

        assert "```" not in result.sql
        assert result.sql == "SELECT * FROM findings"

    def test_generate_query_with_llm_error(self, generator, mock_llm):
        """Test query generation with LLM error."""
        mock_llm.generate.side_effect = LLMError("API error")

        result = generator.generate_query("Show findings")

        assert result.is_valid is False
        assert "LLM error" in result.validation_errors[0]

    def test_validate_query_empty(self, generator):
        """Test validation of empty query."""
        errors = generator.validate_query("")
        assert "Empty query" in errors

    def test_validate_query_not_select(self, generator):
        """Test validation rejects non-SELECT queries."""
        errors = generator.validate_query("UPDATE findings SET status = 'closed'")
        assert any("SELECT" in e for e in errors)
        assert any("UPDATE" in e for e in errors)

    def test_validate_query_delete(self, generator):
        """Test validation rejects DELETE."""
        errors = generator.validate_query("DELETE FROM findings")
        assert any("DELETE" in e for e in errors)

    def test_validate_query_drop(self, generator):
        """Test validation rejects DROP."""
        errors = generator.validate_query("DROP TABLE findings")
        assert any("DROP" in e for e in errors)

    def test_validate_query_insert(self, generator):
        """Test validation rejects INSERT."""
        errors = generator.validate_query("INSERT INTO findings VALUES (1, 'test')")
        assert any("INSERT" in e for e in errors)

    def test_validate_query_create(self, generator):
        """Test validation rejects CREATE."""
        errors = generator.validate_query("CREATE TABLE evil (id INT)")
        assert any("CREATE" in e for e in errors)

    def test_validate_query_alter(self, generator):
        """Test validation rejects ALTER."""
        errors = generator.validate_query("ALTER TABLE findings ADD COLUMN evil TEXT")
        assert any("ALTER" in e for e in errors)

    def test_validate_query_truncate(self, generator):
        """Test validation rejects TRUNCATE."""
        errors = generator.validate_query("TRUNCATE TABLE findings")
        assert any("TRUNCATE" in e for e in errors)

    def test_validate_query_sql_comments(self, generator):
        """Test validation rejects SQL comments."""
        errors = generator.validate_query("SELECT * FROM findings -- hidden code")
        assert any("comment" in e.lower() for e in errors)

    def test_validate_query_block_comments(self, generator):
        """Test validation rejects block comments."""
        errors = generator.validate_query("SELECT * FROM findings /* hidden */")
        assert any("comment" in e.lower() for e in errors)

    def test_validate_query_multiple_statements(self, generator):
        """Test validation rejects multiple statements."""
        errors = generator.validate_query("SELECT * FROM findings; DROP TABLE assets")
        assert any("multiple" in e.lower() for e in errors)

    def test_validate_query_valid_select(self, generator):
        """Test validation accepts valid SELECT."""
        errors = generator.validate_query(
            "SELECT f.*, a.name FROM findings f JOIN assets a ON f.asset_id = a.id WHERE f.severity = 'critical'"
        )
        assert errors == []

    def test_validate_query_trailing_semicolon(self, generator):
        """Test validation accepts trailing semicolon."""
        errors = generator.validate_query("SELECT * FROM findings;")
        assert errors == []

    def test_validate_query_case_insensitive(self, generator):
        """Test validation works case insensitively."""
        errors = generator.validate_query("select * from findings where severity = 'critical'")
        assert errors == []


class TestPostureSchema:
    """Tests for POSTURE_SCHEMA constant."""

    def test_schema_contains_assets(self):
        """Test schema contains assets table."""
        assert "assets" in POSTURE_SCHEMA

    def test_schema_contains_findings(self):
        """Test schema contains findings table."""
        assert "findings" in POSTURE_SCHEMA

    def test_schema_contains_severity(self):
        """Test schema mentions severity."""
        assert "severity" in POSTURE_SCHEMA

    def test_schema_contains_resource_type(self):
        """Test schema mentions resource_type."""
        assert "resource_type" in POSTURE_SCHEMA


class TestLLMProviderInterface:
    """Tests to verify LLMProvider interface compliance."""

    def test_llm_provider_is_abstract(self):
        """Test LLMProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            LLMProvider()

    def test_anthropic_provider_has_required_methods(self):
        """Test AnthropicProvider has all required methods."""
        provider = AnthropicProvider(api_key="test")

        assert hasattr(provider, "generate")
        assert hasattr(provider, "provider_name")
        assert hasattr(provider, "model_name")

    def test_openai_provider_has_required_methods(self):
        """Test OpenAIProvider has all required methods."""
        provider = OpenAIProvider(api_key="test")

        assert hasattr(provider, "generate")
        assert hasattr(provider, "provider_name")
        assert hasattr(provider, "model_name")

    def test_gemini_provider_has_required_methods(self):
        """Test GeminiProvider has all required methods."""
        provider = GeminiProvider(api_key="test")

        assert hasattr(provider, "generate")
        assert hasattr(provider, "provider_name")
        assert hasattr(provider, "model_name")
