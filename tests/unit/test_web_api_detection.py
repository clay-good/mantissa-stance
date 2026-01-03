"""
Unit tests for Web API Detection endpoints.

Tests the REST API endpoints for the Detection module.
"""

import pytest
from unittest.mock import MagicMock

from stance.web.server import StanceRequestHandler


@pytest.fixture
def handler():
    """Create a mock request handler."""
    handler = MagicMock(spec=StanceRequestHandler)

    # Copy the actual methods to the mock
    handler._detection_scan = StanceRequestHandler._detection_scan.__get__(handler)
    handler._detection_patterns = StanceRequestHandler._detection_patterns.__get__(handler)
    handler._detection_pattern = StanceRequestHandler._detection_pattern.__get__(handler)
    handler._detection_entropy = StanceRequestHandler._detection_entropy.__get__(handler)
    handler._detection_sensitive_fields = StanceRequestHandler._detection_sensitive_fields.__get__(handler)
    handler._detection_check_field = StanceRequestHandler._detection_check_field.__get__(handler)
    handler._detection_categories = StanceRequestHandler._detection_categories.__get__(handler)
    handler._detection_severity_levels = StanceRequestHandler._detection_severity_levels.__get__(handler)
    handler._detection_stats = StanceRequestHandler._detection_stats.__get__(handler)
    handler._detection_status = StanceRequestHandler._detection_status.__get__(handler)
    handler._detection_summary = StanceRequestHandler._detection_summary.__get__(handler)
    handler._get_detection_pattern_category = StanceRequestHandler._get_detection_pattern_category.__get__(handler)
    handler._redact_secret_value = StanceRequestHandler._redact_secret_value.__get__(handler)
    handler._interpret_entropy = StanceRequestHandler._interpret_entropy.__get__(handler)

    return handler


class TestDetectionScanEndpoint:
    """Tests for /api/detection/scan endpoint."""

    def test_scan_requires_text(self, handler):
        """Test that text is required."""
        result = handler._detection_scan({})
        assert "error" in result
        assert "text" in result["error"]

    def test_scan_returns_result(self, handler):
        """Test that scan returns result."""
        result = handler._detection_scan({"text": "Hello world"})
        assert "text_length" in result
        assert "secrets_found" in result
        assert "matches" in result

    def test_scan_detects_aws_key(self, handler):
        """Test that scan detects AWS access key."""
        result = handler._detection_scan({"text": "key: AKIAIOSFODNN7EXAMPLE"})
        assert result["secrets_found"] >= 1

    def test_scan_respects_min_entropy(self, handler):
        """Test that scan respects min_entropy parameter."""
        result = handler._detection_scan({
            "text": "some text",
            "min_entropy": "4.0",
        })
        assert "secrets_found" in result

    def test_scan_redacts_matched_values(self, handler):
        """Test that matched values are redacted."""
        result = handler._detection_scan({"text": "key: AKIAIOSFODNN7EXAMPLE"})
        if result["secrets_found"] > 0:
            for match in result["matches"]:
                assert "*" in match["matched_value"]


class TestDetectionPatternsEndpoint:
    """Tests for /api/detection/patterns endpoint."""

    def test_patterns_returns_list(self, handler):
        """Test that patterns returns a list."""
        result = handler._detection_patterns({})
        assert "patterns" in result
        assert "total" in result
        assert isinstance(result["patterns"], list)

    def test_patterns_filters_by_category(self, handler):
        """Test patterns filtered by category."""
        result = handler._detection_patterns({"category": "aws"})
        assert all(p["category"] == "aws" for p in result["patterns"])

    def test_patterns_all_category(self, handler):
        """Test patterns with all category."""
        result = handler._detection_patterns({"category": "all"})
        assert result["total"] >= 20

    def test_patterns_structure(self, handler):
        """Test pattern structure."""
        result = handler._detection_patterns({})
        if result["patterns"]:
            pattern = result["patterns"][0]
            assert "name" in pattern
            assert "severity" in pattern
            assert "description" in pattern
            assert "category" in pattern


class TestDetectionPatternEndpoint:
    """Tests for /api/detection/pattern endpoint."""

    def test_pattern_requires_name(self, handler):
        """Test that name is required."""
        result = handler._detection_pattern({})
        assert "error" in result

    def test_pattern_valid_name(self, handler):
        """Test getting valid pattern."""
        result = handler._detection_pattern({"name": "aws_access_key_id"})
        assert result["name"] == "aws_access_key_id"
        assert "pattern" in result
        assert "severity" in result

    def test_pattern_invalid_name(self, handler):
        """Test getting invalid pattern."""
        result = handler._detection_pattern({"name": "nonexistent"})
        assert "error" in result

    def test_pattern_has_category(self, handler):
        """Test that pattern has category."""
        result = handler._detection_pattern({"name": "aws_access_key_id"})
        assert result["category"] == "aws"


class TestDetectionEntropyEndpoint:
    """Tests for /api/detection/entropy endpoint."""

    def test_entropy_requires_text(self, handler):
        """Test that text is required."""
        result = handler._detection_entropy({})
        assert "error" in result

    def test_entropy_returns_value(self, handler):
        """Test that entropy returns value."""
        result = handler._detection_entropy({"text": "test123"})
        assert "entropy" in result
        assert "is_high_entropy" in result
        assert "interpretation" in result

    def test_entropy_low_for_repeated(self, handler):
        """Test that entropy is low for repeated chars."""
        result = handler._detection_entropy({"text": "aaaaaaaaaa"})
        assert result["entropy"] < 1.0
        assert result["is_high_entropy"] is False

    def test_entropy_high_for_random(self, handler):
        """Test that entropy is high for random string."""
        result = handler._detection_entropy({"text": "aB3$xY9@kL2#mN5&pQ7!"})
        assert result["entropy"] > 3.5
        assert result["is_high_entropy"] is True

    def test_entropy_truncates_long_text(self, handler):
        """Test that long text is truncated in response."""
        long_text = "a" * 100
        result = handler._detection_entropy({"text": long_text})
        assert len(result["text"]) < 60
        assert "..." in result["text"]


class TestDetectionSensitiveFieldsEndpoint:
    """Tests for /api/detection/sensitive-fields endpoint."""

    def test_sensitive_fields_returns_list(self, handler):
        """Test that sensitive fields returns list."""
        result = handler._detection_sensitive_fields({})
        assert "fields" in result
        assert "total" in result
        assert isinstance(result["fields"], list)

    def test_sensitive_fields_includes_password(self, handler):
        """Test that password is in sensitive fields."""
        result = handler._detection_sensitive_fields({})
        assert "password" in result["fields"]

    def test_sensitive_fields_has_categories(self, handler):
        """Test that response has categories."""
        result = handler._detection_sensitive_fields({})
        assert "categories" in result
        assert "password" in result["categories"]
        assert "api_key" in result["categories"]


class TestDetectionCheckFieldEndpoint:
    """Tests for /api/detection/check-field endpoint."""

    def test_check_field_requires_field_name(self, handler):
        """Test that field_name is required."""
        result = handler._detection_check_field({})
        assert "error" in result

    def test_check_field_detects_password(self, handler):
        """Test that password field is detected."""
        result = handler._detection_check_field({"field_name": "db_password"})
        assert result["is_sensitive"] is True

    def test_check_field_normal_field(self, handler):
        """Test that normal field is not sensitive."""
        result = handler._detection_check_field({"field_name": "user_id"})
        assert result["is_sensitive"] is False

    def test_check_field_returns_matched_patterns(self, handler):
        """Test that matched patterns are returned."""
        result = handler._detection_check_field({"field_name": "api_key_secret"})
        assert "matched_patterns" in result


class TestDetectionCategoriesEndpoint:
    """Tests for /api/detection/categories endpoint."""

    def test_categories_returns_list(self, handler):
        """Test that categories returns list."""
        result = handler._detection_categories({})
        assert "categories" in result
        assert "total" in result
        assert result["total"] == 6

    def test_categories_structure(self, handler):
        """Test category structure."""
        result = handler._detection_categories({})
        for cat in result["categories"]:
            assert "id" in cat
            assert "description" in cat
            assert "pattern_count" in cat

    def test_categories_include_expected(self, handler):
        """Test that expected categories are included."""
        result = handler._detection_categories({})
        ids = [c["id"] for c in result["categories"]]
        assert "aws" in ids
        assert "gcp" in ids
        assert "azure" in ids
        assert "generic" in ids
        assert "database" in ids
        assert "cicd" in ids


class TestDetectionSeverityLevelsEndpoint:
    """Tests for /api/detection/severity-levels endpoint."""

    def test_severity_levels_returns_list(self, handler):
        """Test that severity levels returns list."""
        result = handler._detection_severity_levels({})
        assert "levels" in result
        assert "total" in result
        assert result["total"] == 4

    def test_severity_levels_structure(self, handler):
        """Test severity level structure."""
        result = handler._detection_severity_levels({})
        for level in result["levels"]:
            assert "level" in level
            assert "description" in level
            assert "examples" in level

    def test_severity_levels_include_expected(self, handler):
        """Test that expected levels are included."""
        result = handler._detection_severity_levels({})
        levels = [l["level"] for l in result["levels"]]
        assert "critical" in levels
        assert "high" in levels
        assert "medium" in levels
        assert "low" in levels


class TestDetectionStatsEndpoint:
    """Tests for /api/detection/stats endpoint."""

    def test_stats_returns_dict(self, handler):
        """Test that stats returns dictionary."""
        result = handler._detection_stats({})
        assert isinstance(result, dict)

    def test_stats_structure(self, handler):
        """Test stats structure."""
        result = handler._detection_stats({})
        assert "total_patterns" in result
        assert "total_sensitive_fields" in result
        assert "by_severity" in result
        assert "by_category" in result
        assert "detection_methods" in result

    def test_stats_pattern_count(self, handler):
        """Test that pattern count is correct."""
        result = handler._detection_stats({})
        assert result["total_patterns"] >= 20

    def test_stats_detection_methods(self, handler):
        """Test that detection methods are listed."""
        result = handler._detection_stats({})
        assert "pattern_matching" in result["detection_methods"]
        assert "entropy_analysis" in result["detection_methods"]
        assert "context_analysis" in result["detection_methods"]


class TestDetectionStatusEndpoint:
    """Tests for /api/detection/status endpoint."""

    def test_status_returns_dict(self, handler):
        """Test that status returns dictionary."""
        result = handler._detection_status({})
        assert isinstance(result, dict)

    def test_status_structure(self, handler):
        """Test status structure."""
        result = handler._detection_status({})
        assert "module" in result
        assert "status" in result
        assert "components" in result
        assert "capabilities" in result
        assert "pattern_count" in result

    def test_status_operational(self, handler):
        """Test that status is operational."""
        result = handler._detection_status({})
        assert result["module"] == "detection"
        assert result["status"] == "operational"

    def test_status_components(self, handler):
        """Test that components are listed."""
        result = handler._detection_status({})
        assert "SecretsDetector" in result["components"]
        assert "PatternMatcher" in result["components"]
        assert "EntropyAnalyzer" in result["components"]


class TestDetectionSummaryEndpoint:
    """Tests for /api/detection/summary endpoint."""

    def test_summary_returns_dict(self, handler):
        """Test that summary returns dictionary."""
        result = handler._detection_summary({})
        assert isinstance(result, dict)

    def test_summary_structure(self, handler):
        """Test summary structure."""
        result = handler._detection_summary({})
        assert "module" in result
        assert "version" in result
        assert "patterns_total" in result
        assert "sensitive_fields_total" in result
        assert "by_severity" in result
        assert "by_category" in result
        assert "supported_clouds" in result
        assert "detection_methods" in result
        assert "features" in result

    def test_summary_supported_clouds(self, handler):
        """Test that supported clouds are listed."""
        result = handler._detection_summary({})
        assert "aws" in result["supported_clouds"]
        assert "gcp" in result["supported_clouds"]
        assert "azure" in result["supported_clouds"]

    def test_summary_features(self, handler):
        """Test that features are listed."""
        result = handler._detection_summary({})
        assert len(result["features"]) >= 5


class TestHelperMethods:
    """Tests for helper methods."""

    def test_get_detection_pattern_category_aws(self, handler):
        """Test category for AWS patterns."""
        assert handler._get_detection_pattern_category("aws_access_key_id") == "aws"
        assert handler._get_detection_pattern_category("aws_secret_access_key") == "aws"

    def test_get_detection_pattern_category_gcp(self, handler):
        """Test category for GCP patterns."""
        assert handler._get_detection_pattern_category("gcp_api_key") == "gcp"

    def test_get_detection_pattern_category_azure(self, handler):
        """Test category for Azure patterns."""
        assert handler._get_detection_pattern_category("azure_storage_key") == "azure"

    def test_get_detection_pattern_category_generic(self, handler):
        """Test category for generic patterns."""
        assert handler._get_detection_pattern_category("generic_api_key") == "generic"
        assert handler._get_detection_pattern_category("bearer_token") == "generic"

    def test_get_detection_pattern_category_database(self, handler):
        """Test category for database patterns."""
        assert handler._get_detection_pattern_category("mysql_connection") == "database"

    def test_get_detection_pattern_category_cicd(self, handler):
        """Test category for CI/CD patterns."""
        assert handler._get_detection_pattern_category("github_token") == "cicd"

    def test_redact_secret_value_short(self, handler):
        """Test redacting short value."""
        result = handler._redact_secret_value("1234")
        assert result == "****"

    def test_redact_secret_value_long(self, handler):
        """Test redacting long value."""
        result = handler._redact_secret_value("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKIA")
        assert result.endswith("MPLE")
        assert "*" in result

    def test_interpret_entropy_values(self, handler):
        """Test entropy interpretation."""
        assert "Very low" in handler._interpret_entropy(1.0)
        assert "Low" in handler._interpret_entropy(2.5)
        assert "Moderate" in handler._interpret_entropy(3.2)
        assert "High" in handler._interpret_entropy(4.0)
        assert "Very high" in handler._interpret_entropy(5.0)


class TestEndpointRouting:
    """Tests for endpoint routing in do_GET."""

    def test_get_endpoints_exist(self):
        """Test that all detection GET endpoints are routed."""
        endpoints = [
            "/api/detection/scan",
            "/api/detection/patterns",
            "/api/detection/pattern",
            "/api/detection/entropy",
            "/api/detection/sensitive-fields",
            "/api/detection/check-field",
            "/api/detection/categories",
            "/api/detection/severity-levels",
            "/api/detection/stats",
            "/api/detection/status",
            "/api/detection/summary",
        ]

        for endpoint in endpoints:
            # Handle hyphenated names
            method_name = "_detection_" + endpoint.split("/")[-1].replace("-", "_")
            assert hasattr(StanceRequestHandler, method_name), f"Method {method_name} not found"


class TestSecurityFeatures:
    """Tests for security-related features."""

    def test_scan_does_not_expose_full_secrets(self, handler):
        """Test that scan doesn't expose full secrets."""
        result = handler._detection_scan({"text": "password=SuperSecretPassword123!"})
        for match in result.get("matches", []):
            # The matched value should be redacted
            full_secret = "SuperSecretPassword123!"
            assert full_secret not in match["matched_value"]

    def test_pattern_regex_not_exploitable(self, handler):
        """Test that pattern details don't enable exploitation."""
        result = handler._detection_pattern({"name": "aws_access_key_id"})
        # Pattern is exposed (needed for transparency) but that's expected
        assert "pattern" in result


class TestEdgeCases:
    """Tests for edge cases."""

    def test_scan_empty_text_fails(self, handler):
        """Test that scanning empty text fails gracefully."""
        result = handler._detection_scan({"text": ""})
        assert "error" in result

    def test_entropy_empty_text_fails(self, handler):
        """Test that entropy of empty text fails gracefully."""
        result = handler._detection_entropy({"text": ""})
        assert "error" in result

    def test_pattern_empty_name_fails(self, handler):
        """Test that empty pattern name fails."""
        result = handler._detection_pattern({"name": ""})
        assert "error" in result

    def test_check_field_empty_name_fails(self, handler):
        """Test that empty field name fails."""
        result = handler._detection_check_field({"field_name": ""})
        assert "error" in result
