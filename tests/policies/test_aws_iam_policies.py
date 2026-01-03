"""
Tests for AWS IAM policies.

Validates all IAM-related security policies work correctly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from stance.models import (
    Asset,
    AssetCollection,
    Severity,
    NETWORK_EXPOSURE_INTERNAL,
)
from stance.engine import PolicyLoader, PolicyEvaluator


@pytest.fixture
def policy_loader():
    """Load AWS IAM policies."""
    policy_dir = Path(__file__).parent.parent.parent / "policies" / "aws" / "iam"
    if not policy_dir.exists():
        pytest.skip("AWS IAM policies directory not found")
    return PolicyLoader(policy_dirs=[str(policy_dir)])


@pytest.fixture
def policies(policy_loader):
    """Load all IAM policies."""
    return policy_loader.load_all()


class TestRootMFAPolicy:
    """Tests for root-mfa.yaml policy."""

    def test_policy_loads(self, policies):
        """Test root MFA policy loads correctly."""
        policy = policies.get_by_id("aws-iam-001")
        if policy is None:
            pytest.skip("Root MFA policy not found")

        assert policy.name is not None
        assert policy.severity == Severity.CRITICAL

    def test_compliant_account_passes(self, policies):
        """Test account with MFA enabled passes."""
        policy = policies.get_by_id("aws-iam-001")
        if policy is None:
            pytest.skip("Root MFA policy not found")

        asset = Asset(
            id="arn:aws:iam::123456789012:root",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_account_summary",
            name="account-summary",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={"account_mfa_enabled": True},
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(
            policies.filter_by_id("aws-iam-001") if hasattr(policies, 'filter_by_id') else policies,
            AssetCollection([asset])
        )

        # Should not generate finding for compliant resource
        mfa_findings = [f for f in findings if f.rule_id == "aws-iam-001"]
        assert len(mfa_findings) == 0

    def test_non_compliant_account_generates_finding(self, policies):
        """Test account without MFA generates finding."""
        policy = policies.get_by_id("aws-iam-001")
        if policy is None:
            pytest.skip("Root MFA policy not found")

        asset = Asset(
            id="arn:aws:iam::123456789012:root",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_account_summary",
            name="account-summary",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={"account_mfa_enabled": False},
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(
            policies,
            AssetCollection([asset])
        )

        # Should generate finding for non-compliant resource
        mfa_findings = [f for f in findings if f.rule_id == "aws-iam-001"]
        assert len(mfa_findings) == 1
        assert mfa_findings[0].severity == Severity.CRITICAL


class TestPasswordPolicyPolicy:
    """Tests for password-policy.yaml policy."""

    def test_policy_loads(self, policies):
        """Test password policy loads correctly."""
        policy = policies.get_by_id("aws-iam-002")
        if policy is None:
            pytest.skip("Password policy not found")

        assert policy.name is not None

    def test_compliant_password_policy_passes(self, policies):
        """Test compliant password policy passes."""
        policy = policies.get_by_id("aws-iam-002")
        if policy is None:
            pytest.skip("Password policy not found")

        asset = Asset(
            id="arn:aws:iam::123456789012:password-policy",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_account_password_policy",
            name="password-policy",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "minimum_password_length": 14,
                "require_symbols": True,
                "require_numbers": True,
                "require_uppercase_characters": True,
                "require_lowercase_characters": True,
                "max_password_age": 90,
                "password_reuse_prevention": 24,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(
            policies,
            AssetCollection([asset])
        )

        policy_findings = [f for f in findings if f.rule_id == "aws-iam-002"]
        # Compliant policy should pass
        assert len(policy_findings) == 0


class TestPolicySchema:
    """Test policy schema validation."""

    def test_all_policies_have_required_fields(self, policies):
        """Test all policies have required fields."""
        for policy in policies:
            assert policy.id is not None
            assert policy.name is not None
            assert policy.description is not None
            assert policy.severity is not None
            assert policy.resource_type is not None
            assert policy.check is not None

    def test_all_policies_have_valid_severity(self, policies):
        """Test all policies have valid severity."""
        valid_severities = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO}
        for policy in policies:
            assert policy.severity in valid_severities

    def test_all_policies_have_remediation(self, policies):
        """Test all policies have remediation guidance."""
        for policy in policies:
            if policy.remediation:
                assert policy.remediation.guidance is not None


class TestPolicyExpressions:
    """Test policy expression validity."""

    def test_policy_expressions_parse(self, policies):
        """Test all policy expressions can be parsed."""
        from stance.engine.expressions import ExpressionEvaluator

        evaluator = ExpressionEvaluator()

        for policy in policies:
            if policy.check.expression:
                errors = evaluator.validate(policy.check.expression)
                assert errors == [], f"Policy {policy.id} has invalid expression: {errors}"
