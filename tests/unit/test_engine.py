"""
Tests for Mantissa Stance policy engine.

Tests ExpressionEvaluator, PolicyLoader, and PolicyEvaluator.
"""

from __future__ import annotations

import tempfile
import os

import pytest

from stance.engine import (
    ExpressionEvaluator,
    ExpressionError,
    PolicyLoader,
    PolicyLoadError,
    PolicyEvaluator,
    EvaluationResult,
)
from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    Policy,
    PolicyCollection,
    Severity,
    Check,
    CheckType,
)


class TestExpressionEvaluator:
    """Tests for the ExpressionEvaluator class."""

    @pytest.fixture
    def evaluator(self) -> ExpressionEvaluator:
        """Return an ExpressionEvaluator instance."""
        return ExpressionEvaluator()

    @pytest.fixture
    def sample_context(self) -> dict:
        """Return a sample context for evaluation."""
        return {
            "resource": {
                "encryption": {"enabled": True, "algorithm": "AES256"},
                "versioning": {"status": "Enabled"},
                "public_access": False,
                "name": "test-bucket",
                "tags": {"Environment": "prod", "Team": "security"},
                "password_policy": {
                    "min_length": 14,
                    "require_symbols": True,
                },
                "ports": [80, 443, 8080],
                "cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
            }
        }

    def test_expression_simple_equality(self, evaluator, sample_context):
        """Test 'resource.field == value'."""
        assert evaluator.evaluate("resource.name == 'test-bucket'", sample_context)
        assert not evaluator.evaluate("resource.name == 'other'", sample_context)

    def test_expression_boolean(self, evaluator, sample_context):
        """Test boolean expressions."""
        assert evaluator.evaluate("resource.encryption.enabled == true", sample_context)
        assert evaluator.evaluate("resource.public_access == false", sample_context)

    def test_expression_nested_path(self, evaluator, sample_context):
        """Test 'resource.nested.deep.field == value'."""
        assert evaluator.evaluate(
            "resource.encryption.algorithm == 'AES256'", sample_context
        )
        assert evaluator.evaluate(
            "resource.versioning.status == 'Enabled'", sample_context
        )

    def test_expression_comparison_operators(self, evaluator, sample_context):
        """Test >, <, >=, <=, !=."""
        assert evaluator.evaluate(
            "resource.password_policy.min_length >= 14", sample_context
        )
        assert evaluator.evaluate(
            "resource.password_policy.min_length > 10", sample_context
        )
        assert evaluator.evaluate(
            "resource.password_policy.min_length < 20", sample_context
        )
        assert evaluator.evaluate(
            "resource.password_policy.min_length <= 14", sample_context
        )
        assert evaluator.evaluate("resource.name != 'other'", sample_context)

    def test_expression_membership_in(self, evaluator, sample_context):
        """Test 'in' operator."""
        assert evaluator.evaluate("443 in resource.ports", sample_context)
        assert not evaluator.evaluate("22 in resource.ports", sample_context)

    def test_expression_membership_not_in(self, evaluator, sample_context):
        """Test 'not_in' operator."""
        assert evaluator.evaluate("22 not_in resource.ports", sample_context)
        assert evaluator.evaluate(
            "'0.0.0.0/0' not_in resource.cidrs", sample_context
        )
        assert not evaluator.evaluate("443 not_in resource.ports", sample_context)

    def test_expression_contains(self, evaluator, sample_context):
        """Test 'contains' operator."""
        assert evaluator.evaluate("resource.name contains 'test'", sample_context)
        assert not evaluator.evaluate("resource.name contains 'xyz'", sample_context)

    def test_expression_starts_with(self, evaluator, sample_context):
        """Test 'starts_with' operator."""
        assert evaluator.evaluate("resource.name starts_with 'test'", sample_context)
        assert not evaluator.evaluate(
            "resource.name starts_with 'bucket'", sample_context
        )

    def test_expression_ends_with(self, evaluator, sample_context):
        """Test 'ends_with' operator."""
        assert evaluator.evaluate("resource.name ends_with 'bucket'", sample_context)
        assert not evaluator.evaluate(
            "resource.name ends_with 'test'", sample_context
        )

    def test_expression_matches(self, evaluator, sample_context):
        """Test 'matches' regex operator."""
        assert evaluator.evaluate("resource.name matches '^test-.*'", sample_context)
        assert evaluator.evaluate(
            "resource.name matches '.*bucket$'", sample_context
        )
        assert not evaluator.evaluate(
            "resource.name matches '^prod-.*'", sample_context
        )

    def test_expression_exists(self, evaluator, sample_context):
        """Test 'exists' operator."""
        assert evaluator.evaluate("resource.encryption exists", sample_context)
        assert evaluator.evaluate("resource.name exists", sample_context)

    def test_expression_not_exists(self, evaluator, sample_context):
        """Test 'not_exists' operator."""
        assert evaluator.evaluate("resource.missing not_exists", sample_context)
        assert not evaluator.evaluate("resource.name not_exists", sample_context)

    def test_expression_boolean_and(self, evaluator, sample_context):
        """Test 'and' operator."""
        assert evaluator.evaluate(
            "resource.encryption.enabled == true and resource.versioning.status == 'Enabled'",
            sample_context,
        )
        assert not evaluator.evaluate(
            "resource.encryption.enabled == true and resource.public_access == true",
            sample_context,
        )

    def test_expression_boolean_or(self, evaluator, sample_context):
        """Test 'or' operator."""
        assert evaluator.evaluate(
            "resource.public_access == true or resource.encryption.enabled == true",
            sample_context,
        )
        assert not evaluator.evaluate(
            "resource.public_access == true or resource.name == 'other'",
            sample_context,
        )

    def test_expression_boolean_not(self, evaluator, sample_context):
        """Test 'not' operator."""
        assert evaluator.evaluate("not resource.public_access", sample_context)
        assert evaluator.evaluate(
            "not resource.public_access == true", sample_context
        )

    def test_expression_validate_valid(self, evaluator):
        """Test validation of valid expressions."""
        errors = evaluator.validate("resource.field == 'value'")
        assert len(errors) == 0

        errors = evaluator.validate("resource.field >= 10 and resource.other == true")
        assert len(errors) == 0

    def test_expression_validate_invalid(self, evaluator):
        """Test validation catches invalid expressions."""
        errors = evaluator.validate("")
        assert len(errors) > 0

        errors = evaluator.validate("invalid syntax @@")
        assert len(errors) > 0

    def test_expression_missing_path(self, evaluator, sample_context):
        """Test handling of missing paths."""
        # Missing path should return None, comparison should fail safely
        result = evaluator.evaluate("resource.missing == 'value'", sample_context)
        assert not result

    def test_expression_null_literal(self, evaluator, sample_context):
        """Test null literal handling."""
        assert evaluator.evaluate("resource.missing == null", sample_context)


class TestPolicyLoader:
    """Tests for the PolicyLoader class."""

    @pytest.fixture
    def policy_dir(self, tmp_path):
        """Create a temporary policy directory with sample policies."""
        policy_content = """
id: test-policy-001
name: Test Policy
description: A test policy for unit testing
enabled: true
severity: high
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.encryption.enabled == true"
compliance:
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "2.1.1"
remediation:
  guidance: Enable encryption
  automation_supported: false
tags:
  - s3
  - encryption
references:
  - https://example.com
"""
        policy_path = tmp_path / "aws" / "s3"
        policy_path.mkdir(parents=True)
        (policy_path / "encryption.yaml").write_text(policy_content)
        return tmp_path

    def test_policy_loader_discover_policies(self, policy_dir):
        """Test policy file discovery."""
        loader = PolicyLoader(policy_dirs=[str(policy_dir)])
        files = loader.discover_policies()

        assert len(files) == 1
        assert files[0].endswith("encryption.yaml")

    def test_policy_loader_load_policy(self, policy_dir):
        """Test loading a single policy."""
        loader = PolicyLoader(policy_dirs=[str(policy_dir)])
        files = loader.discover_policies()

        policy = loader.load_policy(files[0])

        assert policy.id == "test-policy-001"
        assert policy.name == "Test Policy"
        assert policy.severity == Severity.HIGH
        assert policy.check.check_type == CheckType.EXPRESSION
        assert len(policy.compliance) == 1

    def test_policy_loader_load_all(self, policy_dir):
        """Test loading all policies."""
        loader = PolicyLoader(policy_dirs=[str(policy_dir)])
        policies = loader.load_all()

        assert len(policies) == 1
        assert policies.get_by_id("test-policy-001") is not None

    def test_policy_loader_validate_policy(self, policy_dir, sample_policy):
        """Test policy validation."""
        loader = PolicyLoader(policy_dirs=[str(policy_dir)])
        errors = loader.validate_policy(sample_policy)

        # Valid policy should have no errors
        assert len(errors) == 0

    def test_policy_loader_validate_invalid_policy(self, policy_dir):
        """Test validation catches invalid policies."""
        from stance.models import Check, CheckType, Remediation

        # Policy missing required check expression
        invalid_policy = Policy(
            id="",  # Empty ID
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.HIGH,
            resource_type="aws_s3_bucket",
            check=Check(check_type=CheckType.EXPRESSION, expression=""),
            compliance=[],
            remediation=Remediation(guidance="", automation_supported=False),
            tags=[],
            references=[],
        )

        loader = PolicyLoader(policy_dirs=[str(policy_dir)])
        errors = loader.validate_policy(invalid_policy)

        assert len(errors) > 0


class TestPolicyEvaluator:
    """Tests for the PolicyEvaluator class."""

    @pytest.fixture
    def evaluator(self) -> PolicyEvaluator:
        """Return a PolicyEvaluator instance."""
        return PolicyEvaluator()

    def test_evaluator_compliant_resource(
        self,
        evaluator: PolicyEvaluator,
        sample_asset: Asset,
        sample_policy: Policy,
    ):
        """Test resource that passes policy."""
        # sample_asset has encryption.enabled = True, policy requires it
        finding = evaluator.evaluate_asset(sample_policy, sample_asset)

        # Compliant resource should not generate a finding
        assert finding is None

    def test_evaluator_non_compliant_resource(
        self,
        evaluator: PolicyEvaluator,
        sample_internet_facing_asset: Asset,
        sample_policy: Policy,
    ):
        """Test resource that fails policy generates finding."""
        # sample_internet_facing_asset has encryption.enabled = False
        finding = evaluator.evaluate_asset(sample_policy, sample_internet_facing_asset)

        # Non-compliant resource should generate a finding
        assert finding is not None
        assert finding.severity == sample_policy.severity
        assert finding.rule_id == sample_policy.id

    def test_evaluator_resource_type_filtering(
        self,
        evaluator: PolicyEvaluator,
        sample_ec2_asset: Asset,
        sample_policy: Policy,
    ):
        """Test only matching resource types are evaluated."""
        # sample_ec2_asset is aws_ec2_instance, policy targets aws_s3_bucket
        finding = evaluator.evaluate_asset(sample_policy, sample_ec2_asset)

        # Should not evaluate because resource type doesn't match
        assert finding is None

    def test_evaluator_evaluate_all(
        self,
        evaluator: PolicyEvaluator,
        asset_collection: AssetCollection,
        policy_collection: PolicyCollection,
    ):
        """Test evaluating all policies against all assets."""
        findings, result = evaluator.evaluate_all(policy_collection, asset_collection)

        assert isinstance(findings, FindingCollection)
        assert isinstance(result, EvaluationResult)
        assert result.policies_evaluated > 0
        assert result.assets_evaluated > 0

    def test_evaluator_finding_id_deterministic(
        self,
        evaluator: PolicyEvaluator,
        sample_internet_facing_asset: Asset,
        sample_policy: Policy,
    ):
        """Test same resource+policy produces same finding ID."""
        finding1 = evaluator.evaluate_asset(sample_policy, sample_internet_facing_asset)
        finding2 = evaluator.evaluate_asset(sample_policy, sample_internet_facing_asset)

        # Same finding should have same ID
        assert finding1 is not None
        assert finding2 is not None
        assert finding1.id == finding2.id

    def test_evaluator_disabled_policy_skipped(
        self,
        evaluator: PolicyEvaluator,
        sample_internet_facing_asset: Asset,
    ):
        """Test disabled policies are not evaluated."""
        from stance.models import Check, CheckType, Remediation

        disabled_policy = Policy(
            id="disabled-policy",
            name="Disabled",
            description="Test",
            enabled=False,  # Disabled
            severity=Severity.HIGH,
            resource_type="aws_s3_bucket",
            check=Check(
                check_type=CheckType.EXPRESSION,
                expression="resource.encryption.enabled == true",
            ),
            compliance=[],
            remediation=Remediation(guidance="", automation_supported=False),
            tags=[],
            references=[],
        )

        policies = PolicyCollection([disabled_policy])
        assets = AssetCollection([sample_internet_facing_asset])

        findings, result = evaluator.evaluate_all(policies, assets)

        # Disabled policy should not generate findings
        assert len(findings) == 0
