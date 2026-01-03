"""
Unit tests for Web API IaC endpoints.

Tests the REST API endpoints for Infrastructure as Code scanning.
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
    handler._iac_scan = StanceRequestHandler._iac_scan.__get__(handler)
    handler._iac_policies = StanceRequestHandler._iac_policies.__get__(handler)
    handler._iac_policy = StanceRequestHandler._iac_policy.__get__(handler)
    handler._iac_formats = StanceRequestHandler._iac_formats.__get__(handler)
    handler._iac_validate = StanceRequestHandler._iac_validate.__get__(handler)
    handler._iac_resources = StanceRequestHandler._iac_resources.__get__(handler)
    handler._iac_stats = StanceRequestHandler._iac_stats.__get__(handler)
    handler._iac_compliance = StanceRequestHandler._iac_compliance.__get__(handler)
    handler._iac_providers = StanceRequestHandler._iac_providers.__get__(handler)
    handler._iac_resource_types = StanceRequestHandler._iac_resource_types.__get__(handler)
    handler._iac_severity_levels = StanceRequestHandler._iac_severity_levels.__get__(handler)
    handler._iac_summary = StanceRequestHandler._iac_summary.__get__(handler)

    return handler


class TestIacScanEndpoint:
    """Tests for /api/iac/scan endpoint."""

    def test_scan_returns_dict(self, handler):
        """Test that scan returns a dictionary."""
        result = handler._iac_scan(None)
        assert isinstance(result, dict)

    def test_scan_structure(self, handler):
        """Test scan result structure."""
        result = handler._iac_scan(None)
        assert "findings" in result
        assert "summary" in result
        assert isinstance(result["findings"], list)

    def test_scan_summary_structure(self, handler):
        """Test scan summary structure."""
        result = handler._iac_scan(None)
        summary = result["summary"]
        assert "files_scanned" in summary
        assert "resources_found" in summary
        assert "findings_count" in summary
        assert "by_severity" in summary

    def test_scan_with_severity_filter(self, handler):
        """Test scan with severity filter."""
        result = handler._iac_scan({"severity": ["critical"]})
        for f in result["findings"]:
            assert f["severity"] == "critical"

    def test_scan_with_path(self, handler):
        """Test scan with custom path."""
        result = handler._iac_scan({"path": ["/custom/path"]})
        assert result["summary"]["path"] == "/custom/path"


class TestIacPoliciesEndpoint:
    """Tests for /api/iac/policies endpoint."""

    def test_policies_returns_list(self, handler):
        """Test that policies returns a list."""
        result = handler._iac_policies(None)
        assert "policies" in result
        assert "total" in result
        assert isinstance(result["policies"], list)

    def test_policies_structure(self, handler):
        """Test policy structure."""
        result = handler._iac_policies(None)
        assert len(result["policies"]) > 0

        policy = result["policies"][0]
        assert "id" in policy
        assert "name" in policy
        assert "severity" in policy
        assert "providers" in policy
        assert "enabled" in policy

    def test_policies_filter_by_provider(self, handler):
        """Test filtering policies by provider."""
        result = handler._iac_policies({"provider": ["aws"]})
        for p in result["policies"]:
            assert "aws" in p["providers"] or not p["providers"]

    def test_policies_filter_by_severity(self, handler):
        """Test filtering policies by severity."""
        result = handler._iac_policies({"severity": ["critical"]})
        for p in result["policies"]:
            assert p["severity"] == "critical"

    def test_policies_enabled_only(self, handler):
        """Test filtering only enabled policies."""
        result = handler._iac_policies({"enabled_only": ["true"]})
        for p in result["policies"]:
            assert p["enabled"] is True


class TestIacPolicyEndpoint:
    """Tests for /api/iac/policy endpoint."""

    def test_policy_requires_id(self, handler):
        """Test that policy_id is required."""
        result = handler._iac_policy(None)
        assert "error" in result

    def test_policy_returns_details(self, handler):
        """Test that policy returns details for valid ID."""
        result = handler._iac_policy({"policy_id": ["iac-aws-s3-encryption"]})
        assert "policy" in result
        assert result["policy"]["id"] == "iac-aws-s3-encryption"

    def test_policy_structure(self, handler):
        """Test policy detail structure."""
        result = handler._iac_policy({"policy_id": ["iac-aws-s3-encryption"]})
        policy = result["policy"]
        assert "id" in policy
        assert "name" in policy
        assert "description" in policy
        assert "severity" in policy
        assert "check" in policy
        assert "remediation" in policy

    def test_policy_not_found(self, handler):
        """Test error for invalid policy ID."""
        result = handler._iac_policy({"policy_id": ["invalid-policy"]})
        assert "error" in result


class TestIacFormatsEndpoint:
    """Tests for /api/iac/formats endpoint."""

    def test_formats_returns_list(self, handler):
        """Test that formats returns a list."""
        result = handler._iac_formats(None)
        assert "formats" in result
        assert "total" in result
        assert isinstance(result["formats"], list)

    def test_formats_structure(self, handler):
        """Test format structure."""
        result = handler._iac_formats(None)
        assert result["total"] == 6

        fmt = result["formats"][0]
        assert "name" in fmt
        assert "value" in fmt
        assert "extensions" in fmt
        assert "description" in fmt

    def test_formats_includes_expected(self, handler):
        """Test that expected formats are included."""
        result = handler._iac_formats(None)
        values = {f["value"] for f in result["formats"]}
        assert "terraform" in values
        assert "cloudformation" in values
        assert "arm" in values
        assert "kubernetes" in values


class TestIacValidateEndpoint:
    """Tests for /api/iac/validate endpoint."""

    def test_validate_requires_path(self, handler):
        """Test that path is required."""
        result = handler._iac_validate(None)
        assert "error" in result

    def test_validate_terraform(self, handler):
        """Test validating terraform file."""
        result = handler._iac_validate({"path": ["main.tf"]})
        assert result["valid"] is True
        assert result["format"] == "terraform"

    def test_validate_yaml(self, handler):
        """Test validating YAML file."""
        result = handler._iac_validate({"path": ["template.yaml"]})
        assert result["valid"] is True
        assert result["format"] == "cloudformation"

    def test_validate_unknown(self, handler):
        """Test validating unknown file type."""
        result = handler._iac_validate({"path": ["unknown.xyz"]})
        assert result["valid"] is False


class TestIacResourcesEndpoint:
    """Tests for /api/iac/resources endpoint."""

    def test_resources_returns_list(self, handler):
        """Test that resources returns a list."""
        result = handler._iac_resources(None)
        assert "resources" in result
        assert "total" in result
        assert isinstance(result["resources"], list)

    def test_resources_structure(self, handler):
        """Test resource structure."""
        result = handler._iac_resources(None)
        assert len(result["resources"]) > 0

        resource = result["resources"][0]
        assert "type" in resource
        assert "name" in resource
        assert "provider" in resource
        assert "file" in resource

    def test_resources_filter_by_type(self, handler):
        """Test filtering resources by type."""
        result = handler._iac_resources({"type": ["aws_s3_bucket"]})
        for r in result["resources"]:
            assert r["type"] == "aws_s3_bucket"

    def test_resources_filter_by_provider(self, handler):
        """Test filtering resources by provider."""
        result = handler._iac_resources({"provider": ["aws"]})
        for r in result["resources"]:
            assert r["provider"] == "aws"


class TestIacStatsEndpoint:
    """Tests for /api/iac/stats endpoint."""

    def test_stats_returns_dict(self, handler):
        """Test that stats returns a dictionary."""
        result = handler._iac_stats(None)
        assert isinstance(result, dict)

    def test_stats_structure(self, handler):
        """Test stats structure."""
        result = handler._iac_stats(None)
        assert "total_files" in result
        assert "total_resources" in result
        assert "parse_errors" in result
        assert "by_format" in result
        assert "by_provider" in result
        assert "top_resource_types" in result

    def test_stats_with_path(self, handler):
        """Test stats with custom path."""
        result = handler._iac_stats({"path": ["/custom/path"]})
        assert result["path"] == "/custom/path"


class TestIacComplianceEndpoint:
    """Tests for /api/iac/compliance endpoint."""

    def test_compliance_returns_dict(self, handler):
        """Test that compliance returns a dictionary."""
        result = handler._iac_compliance(None)
        assert "frameworks" in result
        assert "total_frameworks" in result
        assert "total_mappings" in result

    def test_compliance_structure(self, handler):
        """Test compliance structure."""
        result = handler._iac_compliance(None)
        assert len(result["frameworks"]) > 0

        fw = result["frameworks"][0]
        assert "name" in fw
        assert "version" in fw
        assert "mappings" in fw

    def test_compliance_filter_by_framework(self, handler):
        """Test filtering compliance by framework."""
        result = handler._iac_compliance({"framework": ["CIS AWS"]})
        assert len(result["frameworks"]) == 1
        assert "CIS AWS" in result["frameworks"][0]["name"]


class TestIacProvidersEndpoint:
    """Tests for /api/iac/providers endpoint."""

    def test_providers_returns_list(self, handler):
        """Test that providers returns a list."""
        result = handler._iac_providers(None)
        assert "providers" in result
        assert "total" in result
        assert isinstance(result["providers"], list)

    def test_providers_structure(self, handler):
        """Test provider structure."""
        result = handler._iac_providers(None)
        assert result["total"] == 4

        provider = result["providers"][0]
        assert "name" in provider
        assert "value" in provider
        assert "resource_prefix" in provider
        assert "policy_count" in provider

    def test_providers_includes_expected(self, handler):
        """Test that expected providers are included."""
        result = handler._iac_providers(None)
        values = {p["value"] for p in result["providers"]}
        assert "aws" in values
        assert "gcp" in values
        assert "azure" in values
        assert "kubernetes" in values


class TestIacResourceTypesEndpoint:
    """Tests for /api/iac/resource-types endpoint."""

    def test_resource_types_returns_list(self, handler):
        """Test that resource_types returns a list."""
        result = handler._iac_resource_types(None)
        assert "resource_types" in result
        assert "total" in result
        assert isinstance(result["resource_types"], list)

    def test_resource_types_structure(self, handler):
        """Test resource type structure."""
        result = handler._iac_resource_types(None)
        assert len(result["resource_types"]) > 0

        rt = result["resource_types"][0]
        assert "type" in rt
        assert "provider" in rt

    def test_resource_types_filter_by_provider(self, handler):
        """Test filtering resource types by provider."""
        result = handler._iac_resource_types({"provider": ["aws"]})
        for rt in result["resource_types"]:
            assert rt["provider"] == "aws"


class TestIacSeverityLevelsEndpoint:
    """Tests for /api/iac/severity-levels endpoint."""

    def test_severity_levels_returns_list(self, handler):
        """Test that severity_levels returns a list."""
        result = handler._iac_severity_levels(None)
        assert "severity_levels" in result
        assert "total" in result
        assert isinstance(result["severity_levels"], list)

    def test_severity_levels_structure(self, handler):
        """Test severity level structure."""
        result = handler._iac_severity_levels(None)
        assert result["total"] == 5

        level = result["severity_levels"][0]
        assert "value" in level
        assert "priority" in level
        assert "description" in level
        assert "indicator" in level

    def test_severity_levels_includes_all(self, handler):
        """Test that all severity levels are included."""
        result = handler._iac_severity_levels(None)
        values = {l["value"] for l in result["severity_levels"]}
        assert "critical" in values
        assert "high" in values
        assert "medium" in values
        assert "low" in values
        assert "info" in values


class TestIacSummaryEndpoint:
    """Tests for /api/iac/summary endpoint."""

    def test_summary_returns_dict(self, handler):
        """Test that summary returns a dictionary."""
        result = handler._iac_summary(None)
        assert "summary" in result
        assert isinstance(result["summary"], dict)

    def test_summary_structure(self, handler):
        """Test summary structure."""
        result = handler._iac_summary(None)
        summary = result["summary"]
        assert "module" in summary
        assert "version" in summary
        assert "status" in summary
        assert "formats" in summary
        assert "policies" in summary
        assert "capabilities" in summary
        assert "components" in summary

    def test_summary_status(self, handler):
        """Test summary status."""
        result = handler._iac_summary(None)
        assert result["summary"]["status"] == "operational"

    def test_summary_components(self, handler):
        """Test summary components."""
        result = handler._iac_summary(None)
        components = result["summary"]["components"]
        assert "TerraformParser" in components
        assert "CloudFormationParser" in components
        assert "ARMTemplateParser" in components
        assert "IaCPolicyEvaluator" in components


class TestIacEndpointRouting:
    """Tests for IaC endpoint routing in do_GET."""

    def test_get_endpoints_exist(self):
        """Test that all IaC GET endpoints are routed."""
        endpoints = [
            "/api/iac/scan",
            "/api/iac/policies",
            "/api/iac/policy",
            "/api/iac/formats",
            "/api/iac/validate",
            "/api/iac/resources",
            "/api/iac/stats",
            "/api/iac/compliance",
            "/api/iac/providers",
            "/api/iac/resource-types",
            "/api/iac/severity-levels",
            "/api/iac/summary",
        ]

        for endpoint in endpoints:
            # Handle hyphenated names
            method_name = "_iac_" + endpoint.split("/")[-1].replace("-", "_")
            assert hasattr(StanceRequestHandler, method_name), f"Method {method_name} not found"
