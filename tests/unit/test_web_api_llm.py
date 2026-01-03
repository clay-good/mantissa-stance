"""
Unit tests for Web API LLM endpoints.

Tests the REST API endpoints for the LLM module.
"""

import pytest
from unittest.mock import MagicMock

from stance.web.server import StanceRequestHandler


@pytest.fixture
def handler():
    """Create a mock request handler."""
    handler = MagicMock(spec=StanceRequestHandler)

    # Copy the actual methods to the mock
    handler._llm_providers = StanceRequestHandler._llm_providers.__get__(handler)
    handler._llm_provider = StanceRequestHandler._llm_provider.__get__(handler)
    handler._llm_generate_query = StanceRequestHandler._llm_generate_query.__get__(handler)
    handler._generate_demo_sql = StanceRequestHandler._generate_demo_sql.__get__(handler)
    handler._llm_validate_query = StanceRequestHandler._llm_validate_query.__get__(handler)
    handler._llm_explain_finding = StanceRequestHandler._llm_explain_finding.__get__(handler)
    handler._llm_generate_policy = StanceRequestHandler._llm_generate_policy.__get__(handler)
    handler._llm_suggest_policies = StanceRequestHandler._llm_suggest_policies.__get__(handler)
    handler._llm_sanitize = StanceRequestHandler._llm_sanitize.__get__(handler)
    handler._llm_check_sensitive = StanceRequestHandler._llm_check_sensitive.__get__(handler)
    handler._llm_resource_types = StanceRequestHandler._llm_resource_types.__get__(handler)
    handler._llm_frameworks = StanceRequestHandler._llm_frameworks.__get__(handler)
    handler._llm_models = StanceRequestHandler._llm_models.__get__(handler)
    handler._llm_status = StanceRequestHandler._llm_status.__get__(handler)
    handler._llm_summary = StanceRequestHandler._llm_summary.__get__(handler)

    return handler


class TestLLMProvidersEndpoint:
    """Tests for /api/llm/providers endpoint."""

    def test_providers_returns_list(self, handler):
        """Test that providers returns a list."""
        result = handler._llm_providers({})
        assert "providers" in result
        assert "total" in result
        assert isinstance(result["providers"], list)

    def test_providers_structure(self, handler):
        """Test provider structure."""
        result = handler._llm_providers({})
        assert len(result["providers"]) == 3
        assert result["total"] == 3

        provider = result["providers"][0]
        assert "id" in provider
        assert "name" in provider
        assert "available" in provider
        assert "default_model" in provider

    def test_providers_includes_expected(self, handler):
        """Test that expected providers are included."""
        result = handler._llm_providers({})
        ids = {p["id"] for p in result["providers"]}
        assert "anthropic" in ids
        assert "openai" in ids
        assert "gemini" in ids

    def test_providers_available_count(self, handler):
        """Test available providers count."""
        result = handler._llm_providers({})
        assert "available_count" in result
        assert result["available_count"] >= 0


class TestLLMProviderEndpoint:
    """Tests for /api/llm/provider endpoint."""

    def test_provider_default_anthropic(self, handler):
        """Test default provider is anthropic."""
        result = handler._llm_provider({})
        assert result["id"] == "anthropic"

    def test_provider_returns_details(self, handler):
        """Test that provider returns details for valid ID."""
        result = handler._llm_provider({"id": "anthropic"})
        assert result["id"] == "anthropic"
        assert result["name"] == "Anthropic Claude"

    def test_provider_structure(self, handler):
        """Test provider detail structure."""
        result = handler._llm_provider({"id": "openai"})
        assert "id" in result
        assert "name" in result
        assert "description" in result
        assert "models" in result
        assert "capabilities" in result

    def test_provider_not_found(self, handler):
        """Test error for invalid provider ID."""
        result = handler._llm_provider({"id": "invalid"})
        assert "error" in result


class TestLLMGenerateQueryEndpoint:
    """Tests for /api/llm/generate-query endpoint."""

    def test_generate_query_requires_question(self, handler):
        """Test that question is required."""
        result = handler._llm_generate_query({})
        assert "error" in result

    def test_generate_query_returns_sql(self, handler):
        """Test that query returns SQL."""
        result = handler._llm_generate_query({"question": "Find all critical findings"})
        assert "sql" in result
        assert "is_valid" in result

    def test_generate_query_critical_findings(self, handler):
        """Test query for critical findings."""
        result = handler._llm_generate_query({"question": "Show critical findings"})
        assert "critical" in result["sql"].lower()

    def test_generate_query_s3_buckets(self, handler):
        """Test query for S3 buckets."""
        result = handler._llm_generate_query({"question": "Show S3 buckets"})
        assert "s3_bucket" in result["sql"]


class TestLLMValidateQueryEndpoint:
    """Tests for /api/llm/validate-query endpoint."""

    def test_validate_query_requires_sql(self, handler):
        """Test that SQL is required."""
        result = handler._llm_validate_query({})
        assert "error" in result

    def test_validate_query_valid(self, handler):
        """Test validating a valid query."""
        result = handler._llm_validate_query({"sql": "SELECT * FROM findings"})
        assert result["is_valid"] is True
        assert len(result["errors"]) == 0

    def test_validate_query_invalid(self, handler):
        """Test validating an invalid query."""
        result = handler._llm_validate_query({"sql": "DELETE FROM findings"})
        assert result["is_valid"] is False
        assert len(result["errors"]) > 0


class TestLLMExplainFindingEndpoint:
    """Tests for /api/llm/explain-finding endpoint."""

    def test_explain_finding_returns_explanation(self, handler):
        """Test that explanation is returned."""
        result = handler._llm_explain_finding({"finding_id": "test-123"})
        assert "summary" in result
        assert "risk_explanation" in result
        assert "remediation_steps" in result

    def test_explain_finding_structure(self, handler):
        """Test explanation structure."""
        result = handler._llm_explain_finding({})
        assert "finding_id" in result
        assert "summary" in result
        assert "business_impact" in result
        assert "technical_details" in result
        assert "references" in result


class TestLLMGeneratePolicyEndpoint:
    """Tests for /api/llm/generate-policy endpoint."""

    def test_generate_policy_requires_description(self, handler):
        """Test that description is required."""
        result = handler._llm_generate_policy({})
        assert "error" in result

    def test_generate_policy_returns_yaml(self, handler):
        """Test that policy returns YAML."""
        result = handler._llm_generate_policy({"description": "Ensure S3 encryption"})
        assert "yaml_content" in result
        assert "is_valid" in result

    def test_generate_policy_s3(self, handler):
        """Test policy generation for S3."""
        result = handler._llm_generate_policy({"description": "Ensure S3 bucket encryption"})
        assert "s3" in result["resource_type"]
        assert result["is_valid"] is True

    def test_generate_policy_iam(self, handler):
        """Test policy generation for IAM."""
        result = handler._llm_generate_policy({"description": "Ensure IAM MFA enabled"})
        assert "iam" in result["resource_type"]


class TestLLMSuggestPoliciesEndpoint:
    """Tests for /api/llm/suggest-policies endpoint."""

    def test_suggest_policies_returns_list(self, handler):
        """Test that suggestions are returned."""
        result = handler._llm_suggest_policies({})
        assert "suggestions" in result
        assert "total" in result

    def test_suggest_policies_s3(self, handler):
        """Test suggestions for S3."""
        result = handler._llm_suggest_policies({"resource_type": "aws_s3_bucket"})
        assert len(result["suggestions"]) > 0

    def test_suggest_policies_with_count(self, handler):
        """Test suggestions with custom count."""
        result = handler._llm_suggest_policies({"resource_type": "aws_s3_bucket", "count": "3"})
        assert len(result["suggestions"]) <= 3


class TestLLMSanitizeEndpoint:
    """Tests for /api/llm/sanitize endpoint."""

    def test_sanitize_requires_text(self, handler):
        """Test that text is required."""
        result = handler._llm_sanitize({})
        assert "error" in result

    def test_sanitize_returns_result(self, handler):
        """Test that sanitization returns result."""
        result = handler._llm_sanitize({"text": "Test text"})
        assert "sanitized_text" in result
        assert "redactions_made" in result

    def test_sanitize_with_sensitive_data(self, handler):
        """Test sanitization with sensitive data."""
        result = handler._llm_sanitize({"text": "API key: AKIAIOSFODNN7EXAMPLE"})
        assert "sanitized_text" in result


class TestLLMCheckSensitiveEndpoint:
    """Tests for /api/llm/check-sensitive endpoint."""

    def test_check_sensitive_requires_text(self, handler):
        """Test that text is required."""
        result = handler._llm_check_sensitive({})
        assert "error" in result

    def test_check_sensitive_returns_result(self, handler):
        """Test that check returns result."""
        result = handler._llm_check_sensitive({"text": "Normal text"})
        assert "is_sensitive" in result
        assert "types_found" in result


class TestLLMResourceTypesEndpoint:
    """Tests for /api/llm/resource-types endpoint."""

    def test_resource_types_returns_list(self, handler):
        """Test that resource types are returned."""
        result = handler._llm_resource_types({})
        assert "resource_types" in result
        assert "total" in result

    def test_resource_types_filtered(self, handler):
        """Test resource types filtered by cloud."""
        result = handler._llm_resource_types({"cloud": "aws"})
        assert "aws" in result["resource_types"]


class TestLLMFrameworksEndpoint:
    """Tests for /api/llm/frameworks endpoint."""

    def test_frameworks_returns_list(self, handler):
        """Test that frameworks are returned."""
        result = handler._llm_frameworks({})
        assert "frameworks" in result
        assert "total" in result
        assert result["total"] > 0


class TestLLMModelsEndpoint:
    """Tests for /api/llm/models endpoint."""

    def test_models_returns_all(self, handler):
        """Test that all models are returned."""
        result = handler._llm_models({})
        assert "models" in result
        assert "anthropic" in result["models"]
        assert "openai" in result["models"]
        assert "gemini" in result["models"]

    def test_models_filtered(self, handler):
        """Test models filtered by provider."""
        result = handler._llm_models({"provider": "anthropic"})
        assert "anthropic" in result["models"]
        assert len(result["models"]) == 1


class TestLLMStatusEndpoint:
    """Tests for /api/llm/status endpoint."""

    def test_status_returns_dict(self, handler):
        """Test that status returns a dictionary."""
        result = handler._llm_status({})
        assert isinstance(result, dict)

    def test_status_structure(self, handler):
        """Test status structure."""
        result = handler._llm_status({})
        assert "module" in result
        assert "status" in result
        assert "providers" in result
        assert "capabilities" in result
        assert "components" in result


class TestLLMSummaryEndpoint:
    """Tests for /api/llm/summary endpoint."""

    def test_summary_returns_dict(self, handler):
        """Test that summary returns a dictionary."""
        result = handler._llm_summary({})
        assert isinstance(result, dict)

    def test_summary_structure(self, handler):
        """Test summary structure."""
        result = handler._llm_summary({})
        assert "module" in result
        assert "version" in result
        assert "providers_available" in result
        assert "providers_total" in result
        assert "features" in result
        assert "resource_types_count" in result
        assert "frameworks_count" in result


class TestLLMEndpointRouting:
    """Tests for LLM endpoint routing in do_GET."""

    def test_get_endpoints_exist(self):
        """Test that all LLM GET endpoints are routed."""
        endpoints = [
            "/api/llm/providers",
            "/api/llm/provider",
            "/api/llm/generate-query",
            "/api/llm/validate-query",
            "/api/llm/explain-finding",
            "/api/llm/generate-policy",
            "/api/llm/suggest-policies",
            "/api/llm/sanitize",
            "/api/llm/check-sensitive",
            "/api/llm/resource-types",
            "/api/llm/frameworks",
            "/api/llm/models",
            "/api/llm/status",
            "/api/llm/summary",
        ]

        for endpoint in endpoints:
            # Handle hyphenated names
            method_name = "_llm_" + endpoint.split("/")[-1].replace("-", "_")
            assert hasattr(StanceRequestHandler, method_name), f"Method {method_name} not found"


class TestLLMQueryValidation:
    """Tests for query validation."""

    def test_select_query_valid(self, handler):
        """Test that SELECT queries are valid."""
        result = handler._llm_validate_query({"sql": "SELECT * FROM findings"})
        assert result["is_valid"] is True

    def test_delete_query_invalid(self, handler):
        """Test that DELETE queries are invalid."""
        result = handler._llm_validate_query({"sql": "DELETE FROM findings"})
        assert result["is_valid"] is False

    def test_drop_query_invalid(self, handler):
        """Test that DROP queries are invalid."""
        result = handler._llm_validate_query({"sql": "DROP TABLE findings"})
        assert result["is_valid"] is False


class TestLLMPolicyGeneration:
    """Tests for policy generation."""

    def test_policy_has_required_fields(self, handler):
        """Test that generated policy has required fields."""
        result = handler._llm_generate_policy({"description": "Test policy"})
        assert "id:" in result["yaml_content"]
        assert "name:" in result["yaml_content"]
        assert "severity:" in result["yaml_content"]
        assert "resource_type:" in result["yaml_content"]
        assert "check:" in result["yaml_content"]


class TestLLMSanitization:
    """Tests for data sanitization."""

    def test_sanitize_preserves_safe_text(self, handler):
        """Test that safe text is preserved."""
        result = handler._llm_sanitize({"text": "Hello world"})
        assert result["sanitized_text"] == "Hello world"
        assert result["redactions_made"] == 0
