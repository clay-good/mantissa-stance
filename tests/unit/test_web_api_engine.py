"""
Unit tests for Web API Engine endpoints.

Tests the REST API endpoints for the Policy Engine module.
"""

import pytest
from unittest.mock import MagicMock

from stance.web.server import StanceRequestHandler


@pytest.fixture
def handler():
    """Create a mock request handler."""
    handler = MagicMock(spec=StanceRequestHandler)
    handler.storage = None

    # Copy the actual methods to the mock
    handler._engine_policies = StanceRequestHandler._engine_policies.__get__(handler)
    handler._engine_policy = StanceRequestHandler._engine_policy.__get__(handler)
    handler._engine_validate = StanceRequestHandler._engine_validate.__get__(handler)
    handler._engine_evaluate = StanceRequestHandler._engine_evaluate.__get__(handler)
    handler._engine_validate_expression = StanceRequestHandler._engine_validate_expression.__get__(handler)
    handler._engine_compliance = StanceRequestHandler._engine_compliance.__get__(handler)
    handler._engine_frameworks = StanceRequestHandler._engine_frameworks.__get__(handler)
    handler._engine_operators = StanceRequestHandler._engine_operators.__get__(handler)
    handler._engine_check_types = StanceRequestHandler._engine_check_types.__get__(handler)
    handler._engine_severity_levels = StanceRequestHandler._engine_severity_levels.__get__(handler)
    handler._engine_stats = StanceRequestHandler._engine_stats.__get__(handler)
    handler._engine_status = StanceRequestHandler._engine_status.__get__(handler)
    handler._engine_summary = StanceRequestHandler._engine_summary.__get__(handler)
    handler._get_sample_engine_policies = StanceRequestHandler._get_sample_engine_policies.__get__(handler)

    return handler


class TestEnginePoliciesEndpoint:
    """Tests for /api/engine/policies endpoint."""

    def test_policies_returns_list(self, handler):
        """Test that policies returns a list."""
        result = handler._engine_policies(None)
        assert "policies" in result
        assert "total" in result
        assert isinstance(result["policies"], list)

    def test_policies_structure(self, handler):
        """Test policy structure."""
        result = handler._engine_policies(None)
        assert len(result["policies"]) > 0

        policy = result["policies"][0]
        assert "id" in policy
        assert "name" in policy
        assert "severity" in policy
        assert "resource_type" in policy
        assert "enabled" in policy

    def test_policies_filter_enabled_only(self, handler):
        """Test filtering only enabled policies."""
        result = handler._engine_policies({"enabled_only": ["true"]})
        for p in result["policies"]:
            assert p["enabled"] is True

    def test_policies_filter_by_severity(self, handler):
        """Test filtering policies by severity."""
        result = handler._engine_policies({"severity": ["critical"]})
        for p in result["policies"]:
            assert p["severity"] == "critical"

    def test_policies_filter_by_resource_type(self, handler):
        """Test filtering policies by resource type."""
        result = handler._engine_policies({"resource_type": ["aws_s3_bucket"]})
        for p in result["policies"]:
            assert p["resource_type"] == "aws_s3_bucket"

    def test_policies_filter_by_framework(self, handler):
        """Test filtering policies by framework."""
        result = handler._engine_policies({"framework": ["cis"]})
        for p in result["policies"]:
            assert any("CIS" in f for f in p.get("frameworks", []))


class TestEnginePolicyEndpoint:
    """Tests for /api/engine/policy endpoint."""

    def test_policy_requires_id(self, handler):
        """Test that policy_id is required."""
        result = handler._engine_policy(None)
        assert "error" in result

    def test_policy_returns_details(self, handler):
        """Test that policy returns details for valid ID."""
        result = handler._engine_policy({"policy_id": ["aws-s3-encryption"]})
        assert "policy" in result
        assert result["policy"]["id"] == "aws-s3-encryption"

    def test_policy_structure(self, handler):
        """Test policy detail structure."""
        result = handler._engine_policy({"policy_id": ["aws-s3-encryption"]})
        policy = result["policy"]
        assert "id" in policy
        assert "name" in policy
        assert "description" in policy
        assert "severity" in policy
        assert "check" in policy
        assert "remediation" in policy

    def test_policy_not_found(self, handler):
        """Test error for invalid policy ID."""
        result = handler._engine_policy({"policy_id": ["invalid-policy"]})
        assert "error" in result


class TestEngineValidateEndpoint:
    """Tests for /api/engine/validate endpoint."""

    def test_validate_returns_result(self, handler):
        """Test that validate returns a result."""
        result = handler._engine_validate(None)
        assert "valid" in result
        assert "total_files" in result

    def test_validate_structure(self, handler):
        """Test validate result structure."""
        result = handler._engine_validate(None)
        assert "valid" in result
        assert "valid_count" in result
        assert "invalid_count" in result
        assert "errors" in result

    def test_validate_with_path(self, handler):
        """Test validate with custom path."""
        result = handler._engine_validate({"path": ["/custom/path"]})
        assert result["path"] == "/custom/path"


class TestEngineEvaluateEndpoint:
    """Tests for /api/engine/evaluate endpoint."""

    def test_evaluate_requires_expression(self, handler):
        """Test that expression is required."""
        result = handler._engine_evaluate(None)
        assert "error" in result

    def test_evaluate_simple_expression(self, handler):
        """Test evaluating simple expression."""
        result = handler._engine_evaluate({
            "expression": ["resource.enabled == true"],
            "context": ['{"resource": {"enabled": true}}'],
        })
        assert result["success"] is True
        assert result["result"] is True

    def test_evaluate_invalid_context(self, handler):
        """Test evaluating with invalid context."""
        result = handler._engine_evaluate({
            "expression": ["resource.enabled == true"],
            "context": ["not json"],
        })
        assert result["success"] is False
        assert "error" in result

    def test_evaluate_returns_result(self, handler):
        """Test that evaluate returns expected fields."""
        result = handler._engine_evaluate({
            "expression": ["resource.name == 'test'"],
            "context": ['{"resource": {"name": "test"}}'],
        })
        assert "expression" in result
        assert "context" in result
        assert "result" in result


class TestEngineValidateExpressionEndpoint:
    """Tests for /api/engine/validate-expression endpoint."""

    def test_validate_expression_requires_expression(self, handler):
        """Test that expression is required."""
        result = handler._engine_validate_expression(None)
        assert "error" in result

    def test_validate_expression_valid(self, handler):
        """Test validating valid expression."""
        result = handler._engine_validate_expression({
            "expression": ["resource.enabled == true"],
        })
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_validate_expression_invalid(self, handler):
        """Test validating invalid expression."""
        result = handler._engine_validate_expression({
            "expression": [""],
        })
        assert result["valid"] is False
        assert len(result["errors"]) > 0


class TestEngineComplianceEndpoint:
    """Tests for /api/engine/compliance endpoint."""

    def test_compliance_returns_dict(self, handler):
        """Test that compliance returns a dictionary."""
        result = handler._engine_compliance(None)
        assert "overall_score" in result
        assert "frameworks" in result

    def test_compliance_structure(self, handler):
        """Test compliance structure."""
        result = handler._engine_compliance(None)
        assert len(result["frameworks"]) > 0

        fw = result["frameworks"][0]
        assert "id" in fw
        assert "name" in fw
        assert "score" in fw
        assert "controls_passed" in fw
        assert "controls_total" in fw

    def test_compliance_filter_by_framework(self, handler):
        """Test filtering compliance by framework."""
        result = handler._engine_compliance({"framework": ["cis-aws"]})
        assert len(result["frameworks"]) == 1
        assert result["frameworks"][0]["id"] == "cis-aws"


class TestEngineFrameworksEndpoint:
    """Tests for /api/engine/frameworks endpoint."""

    def test_frameworks_returns_list(self, handler):
        """Test that frameworks returns a list."""
        result = handler._engine_frameworks(None)
        assert "frameworks" in result
        assert "total" in result
        assert isinstance(result["frameworks"], list)

    def test_frameworks_structure(self, handler):
        """Test framework structure."""
        result = handler._engine_frameworks(None)
        assert result["total"] == 7

        fw = result["frameworks"][0]
        assert "id" in fw
        assert "name" in fw
        assert "version" in fw
        assert "controls_count" in fw
        assert "policies_mapped" in fw

    def test_frameworks_includes_expected(self, handler):
        """Test that expected frameworks are included."""
        result = handler._engine_frameworks(None)
        ids = {f["id"] for f in result["frameworks"]}
        assert "cis-aws" in ids
        assert "pci-dss" in ids
        assert "soc2" in ids


class TestEngineOperatorsEndpoint:
    """Tests for /api/engine/operators endpoint."""

    def test_operators_returns_list(self, handler):
        """Test that operators returns a list."""
        result = handler._engine_operators(None)
        assert "operators" in result
        assert "total" in result
        assert isinstance(result["operators"], list)

    def test_operators_structure(self, handler):
        """Test operator structure."""
        result = handler._engine_operators(None)
        assert result["total"] == 17

        op = result["operators"][0]
        assert "operator" in op
        assert "category" in op
        assert "description" in op
        assert "example" in op

    def test_operators_includes_expected(self, handler):
        """Test that expected operators are included."""
        result = handler._engine_operators(None)
        ops = {o["operator"] for o in result["operators"]}
        assert "==" in ops
        assert "!=" in ops
        assert "in" in ops
        assert "exists" in ops
        assert "and" in ops


class TestEngineCheckTypesEndpoint:
    """Tests for /api/engine/check-types endpoint."""

    def test_check_types_returns_list(self, handler):
        """Test that check_types returns a list."""
        result = handler._engine_check_types(None)
        assert "check_types" in result
        assert "total" in result
        assert isinstance(result["check_types"], list)

    def test_check_types_structure(self, handler):
        """Test check type structure."""
        result = handler._engine_check_types(None)
        assert result["total"] == 2

        ct = result["check_types"][0]
        assert "type" in ct
        assert "description" in ct
        assert "fields" in ct
        assert "example" in ct

    def test_check_types_includes_expected(self, handler):
        """Test that expected check types are included."""
        result = handler._engine_check_types(None)
        types = {ct["type"] for ct in result["check_types"]}
        assert "expression" in types
        assert "sql" in types


class TestEngineSeverityLevelsEndpoint:
    """Tests for /api/engine/severity-levels endpoint."""

    def test_severity_levels_returns_list(self, handler):
        """Test that severity_levels returns a list."""
        result = handler._engine_severity_levels(None)
        assert "severity_levels" in result
        assert "total" in result
        assert isinstance(result["severity_levels"], list)

    def test_severity_levels_structure(self, handler):
        """Test severity level structure."""
        result = handler._engine_severity_levels(None)
        assert result["total"] == 5

        level = result["severity_levels"][0]
        assert "level" in level
        assert "priority" in level
        assert "description" in level
        assert "response_time" in level

    def test_severity_levels_includes_all(self, handler):
        """Test that all severity levels are included."""
        result = handler._engine_severity_levels(None)
        levels = {l["level"] for l in result["severity_levels"]}
        assert "critical" in levels
        assert "high" in levels
        assert "medium" in levels
        assert "low" in levels
        assert "info" in levels


class TestEngineStatsEndpoint:
    """Tests for /api/engine/stats endpoint."""

    def test_stats_returns_dict(self, handler):
        """Test that stats returns a dictionary."""
        result = handler._engine_stats(None)
        assert isinstance(result, dict)

    def test_stats_structure(self, handler):
        """Test stats structure."""
        result = handler._engine_stats(None)
        assert "total_policies" in result
        assert "enabled_policies" in result
        assert "disabled_policies" in result
        assert "by_severity" in result
        assert "by_resource_type" in result
        assert "frameworks_count" in result


class TestEngineStatusEndpoint:
    """Tests for /api/engine/status endpoint."""

    def test_status_returns_dict(self, handler):
        """Test that status returns a dictionary."""
        result = handler._engine_status(None)
        assert isinstance(result, dict)

    def test_status_structure(self, handler):
        """Test status structure."""
        result = handler._engine_status(None)
        assert result["module"] == "engine"
        assert result["version"] == "1.0.0"
        assert result["status"] == "operational"
        assert "components" in result
        assert "capabilities" in result

    def test_status_components(self, handler):
        """Test status components."""
        result = handler._engine_status(None)
        components = result["components"]
        assert "ExpressionEvaluator" in components
        assert "PolicyLoader" in components
        assert "PolicyEvaluator" in components
        assert "ComplianceCalculator" in components


class TestEngineSummaryEndpoint:
    """Tests for /api/engine/summary endpoint."""

    def test_summary_returns_dict(self, handler):
        """Test that summary returns a dictionary."""
        result = handler._engine_summary(None)
        assert "summary" in result
        assert isinstance(result["summary"], dict)

    def test_summary_structure(self, handler):
        """Test summary structure."""
        result = handler._engine_summary(None)
        summary = result["summary"]
        assert "module" in summary
        assert "version" in summary
        assert "status" in summary
        assert "policies" in summary
        assert "compliance" in summary
        assert "expression_engine" in summary
        assert "features" in summary

    def test_summary_status(self, handler):
        """Test summary status."""
        result = handler._engine_summary(None)
        assert result["summary"]["status"] == "operational"


class TestEngineEndpointRouting:
    """Tests for Engine endpoint routing in do_GET."""

    def test_get_endpoints_exist(self):
        """Test that all Engine GET endpoints are routed."""
        endpoints = [
            "/api/engine/policies",
            "/api/engine/policy",
            "/api/engine/validate",
            "/api/engine/evaluate",
            "/api/engine/validate-expression",
            "/api/engine/compliance",
            "/api/engine/frameworks",
            "/api/engine/operators",
            "/api/engine/check-types",
            "/api/engine/severity-levels",
            "/api/engine/stats",
            "/api/engine/status",
            "/api/engine/summary",
        ]

        for endpoint in endpoints:
            # Handle hyphenated names
            method_name = "_engine_" + endpoint.split("/")[-1].replace("-", "_")
            assert hasattr(StanceRequestHandler, method_name), f"Method {method_name} not found"
