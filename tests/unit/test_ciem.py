"""
Unit tests for CIEM (Cloud Infrastructure Entitlement Management) module.

Tests for:
- Effective permissions calculation
- Overprivileged identity detection
- Trust relationship analysis
- Privilege escalation path detection
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta
from typing import Any

from stance.models.asset import Asset, AssetCollection
from stance.models.finding import Severity
from stance.ciem import (
    # Effective permissions
    EffectivePermissionsCalculator,
    PermissionSet,
    EffectiveAccess,
    # Overprivileged detection
    OverprivilegedDetector,
    OverprivilegedFinding,
    UnusedPermission,
    # Trust analysis
    TrustAnalyzer,
    TrustRelationship,
    CrossAccountAccess,
    TrustRisk,
    # Privilege escalation
    PrivilegeEscalationAnalyzer,
    EscalationPath,
)
from stance.ciem.effective_permissions import Permission, PermissionEffect
from stance.ciem.privilege_escalation import EscalationType, EscalationStep
from stance.ciem.trust_analysis import TrustType


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def aws_user_asset() -> Asset:
    """Create a sample AWS IAM user asset."""
    return Asset(
        id="arn:aws:iam::123456789012:user/test-user",
        name="test-user",
        cloud_provider="aws",
        account_id="123456789012",
        region="global",
        resource_type="aws_iam_user",
        raw_config={
            "attached_policies": [
                "arn:aws:iam::123456789012:policy/TestPolicy"
            ],
        },
    )


@pytest.fixture
def aws_role_asset() -> Asset:
    """Create a sample AWS IAM role asset."""
    return Asset(
        id="arn:aws:iam::123456789012:role/test-role",
        name="test-role",
        cloud_provider="aws",
        account_id="123456789012",
        region="global",
        resource_type="aws_iam_role",
        raw_config={
            "attached_policies": [
                "arn:aws:iam::aws:policy/AdministratorAccess"
            ],
            "assume_role_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
        },
    )


@pytest.fixture
def admin_policy_asset() -> Asset:
    """Create an admin policy asset."""
    return Asset(
        id="arn:aws:iam::aws:policy/AdministratorAccess",
        name="AdministratorAccess",
        cloud_provider="aws",
        account_id="aws",
        region="global",
        resource_type="aws_iam_policy",
        raw_config={
            "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            },
        },
    )


@pytest.fixture
def limited_policy_asset() -> Asset:
    """Create a limited S3 read-only policy asset."""
    return Asset(
        id="arn:aws:iam::123456789012:policy/S3ReadOnly",
        name="S3ReadOnly",
        cloud_provider="aws",
        account_id="123456789012",
        region="global",
        resource_type="aws_iam_policy",
        raw_config={
            "arn": "arn:aws:iam::123456789012:policy/S3ReadOnly",
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:HeadObject",
                        ],
                        "Resource": "*",
                    }
                ],
            },
        },
    )


@pytest.fixture
def sensitive_policy_asset() -> Asset:
    """Create a policy with sensitive permissions."""
    return Asset(
        id="arn:aws:iam::123456789012:policy/SensitivePolicy",
        name="SensitivePolicy",
        cloud_provider="aws",
        account_id="123456789012",
        region="global",
        resource_type="aws_iam_policy",
        raw_config={
            "arn": "arn:aws:iam::123456789012:policy/SensitivePolicy",
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:CreateUser",
                            "iam:AttachUserPolicy",
                            "iam:CreateAccessKey",
                            "sts:AssumeRole",
                        ],
                        "Resource": "*",
                    }
                ],
            },
        },
    )


# =============================================================================
# Effective Permissions Calculator Tests
# =============================================================================


class TestPermission:
    """Tests for Permission dataclass."""

    def test_permission_creation(self):
        """Test basic permission creation."""
        perm = Permission(
            service="s3",
            action="GetObject",
            resource="*",
            effect=PermissionEffect.ALLOW,
        )

        assert perm.service == "s3"
        assert perm.action == "GetObject"
        assert perm.resource == "*"
        assert perm.effect == PermissionEffect.ALLOW

    def test_is_wildcard_action(self):
        """Test wildcard action detection."""
        wildcard = Permission(
            service="s3",
            action="*",
            resource="*",
            effect=PermissionEffect.ALLOW,
        )
        assert wildcard.is_wildcard_action is True

        specific = Permission(
            service="s3",
            action="GetObject",
            resource="*",
            effect=PermissionEffect.ALLOW,
        )
        assert specific.is_wildcard_action is False

    def test_is_wildcard_resource(self):
        """Test wildcard resource detection."""
        wildcard = Permission(
            service="s3",
            action="GetObject",
            resource="*",
            effect=PermissionEffect.ALLOW,
        )
        assert wildcard.is_wildcard_resource is True

        specific = Permission(
            service="s3",
            action="GetObject",
            resource="arn:aws:s3:::my-bucket/*",
            effect=PermissionEffect.ALLOW,
        )
        assert specific.is_wildcard_resource is False

    def test_is_admin(self):
        """Test admin permission detection."""
        admin = Permission(
            service="*",
            action="*",
            resource="*",
            effect=PermissionEffect.ALLOW,
        )
        assert admin.is_admin is True

        deny_all = Permission(
            service="*",
            action="*",
            resource="*",
            effect=PermissionEffect.DENY,
        )
        assert deny_all.is_admin is False

        partial = Permission(
            service="s3",
            action="*",
            resource="*",
            effect=PermissionEffect.ALLOW,
        )
        assert partial.is_admin is False

    def test_permission_to_dict(self):
        """Test permission serialization."""
        perm = Permission(
            service="s3",
            action="GetObject",
            resource="*",
            effect=PermissionEffect.ALLOW,
            conditions={"StringEquals": {"s3:x-amz-acl": "public-read"}},
        )

        data = perm.to_dict()
        assert data["service"] == "s3"
        assert data["action"] == "GetObject"
        assert data["effect"] == "allow"
        assert "StringEquals" in data["conditions"]


class TestPermissionSet:
    """Tests for PermissionSet dataclass."""

    def test_permission_set_creation(self):
        """Test permission set creation."""
        perm_set = PermissionSet(
            identity_id="arn:aws:iam::123456789012:user/test",
            identity_type="user",
        )

        assert perm_set.identity_id == "arn:aws:iam::123456789012:user/test"
        assert perm_set.identity_type == "user"
        assert len(perm_set.permissions) == 0

    def test_has_admin_access(self):
        """Test admin access detection in permission set."""
        admin_perm = Permission(
            service="*",
            action="*",
            resource="*",
            effect=PermissionEffect.ALLOW,
        )

        perm_set = PermissionSet(
            identity_id="test",
            identity_type="user",
            permissions=[admin_perm],
        )

        assert perm_set.has_admin_access is True

    def test_service_count(self):
        """Test service count calculation."""
        perms = [
            Permission("s3", "GetObject", "*", PermissionEffect.ALLOW),
            Permission("s3", "PutObject", "*", PermissionEffect.ALLOW),
            Permission("ec2", "DescribeInstances", "*", PermissionEffect.ALLOW),
            Permission("iam", "GetUser", "*", PermissionEffect.ALLOW),
        ]

        perm_set = PermissionSet(
            identity_id="test",
            identity_type="user",
            permissions=perms,
        )

        assert perm_set.service_count == 3

    def test_action_count(self):
        """Test action count calculation."""
        perms = [
            Permission("s3", "GetObject", "*", PermissionEffect.ALLOW),
            Permission("s3", "PutObject", "*", PermissionEffect.DENY),
            Permission("ec2", "DescribeInstances", "*", PermissionEffect.ALLOW),
        ]

        perm_set = PermissionSet(
            identity_id="test",
            identity_type="user",
            permissions=perms,
        )

        # Only counts ALLOW permissions
        assert perm_set.action_count == 2

    def test_get_services(self):
        """Test getting unique services."""
        perms = [
            Permission("s3", "GetObject", "*", PermissionEffect.ALLOW),
            Permission("s3", "PutObject", "*", PermissionEffect.ALLOW),
            Permission("ec2", "DescribeInstances", "*", PermissionEffect.ALLOW),
        ]

        perm_set = PermissionSet(
            identity_id="test",
            identity_type="user",
            permissions=perms,
        )

        services = perm_set.get_services()
        assert "s3" in services
        assert "ec2" in services
        assert len(services) == 2

    def test_get_actions_for_service(self):
        """Test getting actions for a specific service."""
        perms = [
            Permission("s3", "GetObject", "*", PermissionEffect.ALLOW),
            Permission("s3", "PutObject", "*", PermissionEffect.ALLOW),
            Permission("s3", "DeleteObject", "*", PermissionEffect.DENY),
            Permission("ec2", "DescribeInstances", "*", PermissionEffect.ALLOW),
        ]

        perm_set = PermissionSet(
            identity_id="test",
            identity_type="user",
            permissions=perms,
        )

        s3_actions = perm_set.get_actions_for_service("s3")
        assert "GetObject" in s3_actions
        assert "PutObject" in s3_actions
        # DENY actions not included
        assert "DeleteObject" not in s3_actions


class TestEffectivePermissionsCalculator:
    """Tests for EffectivePermissionsCalculator."""

    def test_calculator_initialization(self):
        """Test calculator initialization."""
        calc = EffectivePermissionsCalculator(provider="aws")
        assert calc.provider == "aws"

    def test_calculate_admin_permissions(
        self,
        aws_user_asset: Asset,
        admin_policy_asset: Asset,
    ):
        """Test calculation with admin policy."""
        calc = EffectivePermissionsCalculator(provider="aws")

        access = calc.calculate_effective_permissions(
            identity=aws_user_asset,
            policies=[admin_policy_asset],
        )

        assert access.is_admin is True
        assert access.risk_score == 100.0
        assert access.identity_name == "test-user"

    def test_calculate_limited_permissions(
        self,
        aws_user_asset: Asset,
        limited_policy_asset: Asset,
    ):
        """Test calculation with limited policy."""
        calc = EffectivePermissionsCalculator(provider="aws")

        access = calc.calculate_effective_permissions(
            identity=aws_user_asset,
            policies=[limited_policy_asset],
        )

        assert access.is_admin is False
        assert access.risk_score < 100.0
        assert "s3" in access.permission_set.get_services()

    def test_calculate_sensitive_permissions(
        self,
        aws_user_asset: Asset,
        sensitive_policy_asset: Asset,
    ):
        """Test calculation detects sensitive permissions."""
        calc = EffectivePermissionsCalculator(provider="aws")

        access = calc.calculate_effective_permissions(
            identity=aws_user_asset,
            policies=[sensitive_policy_asset],
        )

        assert len(access.sensitive_permissions) > 0
        assert any("iam:" in p for p in access.sensitive_permissions)

    def test_effective_access_to_dict(
        self,
        aws_user_asset: Asset,
        limited_policy_asset: Asset,
    ):
        """Test EffectiveAccess serialization."""
        calc = EffectivePermissionsCalculator(provider="aws")

        access = calc.calculate_effective_permissions(
            identity=aws_user_asset,
            policies=[limited_policy_asset],
        )

        data = access.to_dict()
        assert "identity_id" in data
        assert "identity_name" in data
        assert "is_admin" in data
        assert "risk_score" in data
        assert "service_count" in data


# =============================================================================
# Overprivileged Detection Tests
# =============================================================================


class TestUnusedPermission:
    """Tests for UnusedPermission dataclass."""

    def test_unused_permission_creation(self):
        """Test unused permission creation."""
        unused = UnusedPermission(
            service="s3",
            action="PutObject",
            last_used=None,
            days_unused=90,
            source_policy="arn:aws:iam::123456789012:policy/TestPolicy",
        )

        assert unused.service == "s3"
        assert unused.action == "PutObject"
        assert unused.last_used is None
        assert unused.days_unused == 90

    def test_unused_permission_to_dict(self):
        """Test unused permission serialization."""
        last_used = datetime(2024, 1, 1, tzinfo=timezone.utc)
        unused = UnusedPermission(
            service="s3",
            action="PutObject",
            last_used=last_used,
            days_unused=30,
            source_policy="test-policy",
        )

        data = unused.to_dict()
        assert data["service"] == "s3"
        assert data["last_used"] == last_used.isoformat()


class TestOverprivilegedFinding:
    """Tests for OverprivilegedFinding dataclass."""

    def test_finding_creation(self):
        """Test finding creation."""
        finding = OverprivilegedFinding(
            identity_id="test-user",
            identity_name="test-user",
            identity_type="user",
            total_permissions=10,
            used_permissions=2,
        )

        assert finding.identity_id == "test-user"
        assert finding.total_permissions == 10
        assert finding.used_permissions == 2

    def test_unused_percentage(self):
        """Test unused percentage calculation."""
        unused = [
            UnusedPermission("s3", "PutObject", None, 90, "policy"),
            UnusedPermission("s3", "DeleteObject", None, 90, "policy"),
        ]

        finding = OverprivilegedFinding(
            identity_id="test-user",
            identity_name="test-user",
            identity_type="user",
            unused_permissions=unused,
            total_permissions=10,
            used_permissions=8,
        )

        assert finding.unused_percentage == 20.0

    def test_severity_high(self):
        """Test severity calculation for high unused percentage."""
        unused = [UnusedPermission("s3", f"Action{i}", None, 90, "policy") for i in range(9)]

        finding = OverprivilegedFinding(
            identity_id="test-user",
            identity_name="test-user",
            identity_type="user",
            unused_permissions=unused,
            total_permissions=10,
            used_permissions=1,
        )

        assert finding.unused_percentage == 90.0
        assert finding.severity == Severity.HIGH

    def test_severity_medium(self):
        """Test severity calculation for medium unused percentage."""
        unused = [UnusedPermission("s3", f"Action{i}", None, 90, "policy") for i in range(6)]

        finding = OverprivilegedFinding(
            identity_id="test-user",
            identity_name="test-user",
            identity_type="user",
            unused_permissions=unused,
            total_permissions=10,
            used_permissions=4,
        )

        assert finding.unused_percentage == 60.0
        assert finding.severity == Severity.MEDIUM

    def test_to_finding(self):
        """Test conversion to Finding object."""
        unused = [UnusedPermission("s3", "PutObject", None, 90, "policy")]

        overprivileged = OverprivilegedFinding(
            identity_id="test-user",
            identity_name="test-user",
            identity_type="user",
            unused_permissions=unused,
            unused_services=["s3"],
            total_permissions=2,
            used_permissions=1,
            recommendation="Remove unused permissions",
        )

        finding = overprivileged.to_finding()
        assert "overprivileged" in finding.id
        assert finding.asset_id == "test-user"
        assert "unused" in finding.description.lower()


class TestOverprivilegedDetector:
    """Tests for OverprivilegedDetector."""

    def test_detector_initialization(self):
        """Test detector initialization with defaults."""
        detector = OverprivilegedDetector()

        assert detector.lookback_days == 90
        assert detector.unused_threshold_days == 90
        assert detector.min_unused_percentage == 20.0

    def test_detector_custom_config(self):
        """Test detector with custom configuration."""
        detector = OverprivilegedDetector(
            lookback_days=30,
            unused_threshold_days=30,
            min_unused_percentage=50.0,
        )

        assert detector.lookback_days == 30
        assert detector.unused_threshold_days == 30
        assert detector.min_unused_percentage == 50.0

    def test_detect_overprivileged(self):
        """Test detection of overprivileged identity."""
        detector = OverprivilegedDetector(min_unused_percentage=10.0)

        perms = [
            Permission("s3", "GetObject", "*", PermissionEffect.ALLOW),
            Permission("s3", "PutObject", "*", PermissionEffect.ALLOW),
            Permission("s3", "DeleteObject", "*", PermissionEffect.ALLOW),
            Permission("ec2", "DescribeInstances", "*", PermissionEffect.ALLOW),
        ]

        perm_set = PermissionSet(
            identity_id="test-user",
            identity_type="user",
            permissions=perms,
        )

        effective_access = EffectiveAccess(
            identity_id="test-user",
            identity_name="test-user",
            identity_type="user",
            permission_set=perm_set,
            risk_score=30.0,
        )

        # Only GetObject was used recently
        now = datetime.now(timezone.utc)
        usage_data = {
            "s3:GetObject": now - timedelta(days=1),
        }

        finding = detector.detect(effective_access, usage_data)

        assert finding is not None
        assert len(finding.unused_permissions) == 3
        assert finding.used_permissions == 1

    def test_detect_not_overprivileged(self):
        """Test detection when identity is not overprivileged."""
        detector = OverprivilegedDetector(min_unused_percentage=50.0)

        perms = [
            Permission("s3", "GetObject", "*", PermissionEffect.ALLOW),
            Permission("s3", "PutObject", "*", PermissionEffect.ALLOW),
        ]

        perm_set = PermissionSet(
            identity_id="test-user",
            identity_type="user",
            permissions=perms,
        )

        effective_access = EffectiveAccess(
            identity_id="test-user",
            identity_name="test-user",
            identity_type="user",
            permission_set=perm_set,
            risk_score=10.0,
        )

        # Both permissions used
        now = datetime.now(timezone.utc)
        usage_data = {
            "s3:GetObject": now - timedelta(days=1),
            "s3:PutObject": now - timedelta(days=2),
        }

        finding = detector.detect(effective_access, usage_data)

        assert finding is None

    def test_detect_all(self):
        """Test detection across multiple identities."""
        detector = OverprivilegedDetector(min_unused_percentage=10.0)

        # Create two identities
        access_list = []
        for i in range(2):
            perms = [
                Permission("s3", "GetObject", "*", PermissionEffect.ALLOW),
                Permission("s3", "PutObject", "*", PermissionEffect.ALLOW),
            ]

            perm_set = PermissionSet(
                identity_id=f"user-{i}",
                identity_type="user",
                permissions=perms,
            )

            access_list.append(
                EffectiveAccess(
                    identity_id=f"user-{i}",
                    identity_name=f"user-{i}",
                    identity_type="user",
                    permission_set=perm_set,
                    risk_score=20.0,
                )
            )

        # Only first user has usage data
        now = datetime.now(timezone.utc)
        usage_data = {
            "user-0": {
                "s3:GetObject": now - timedelta(days=1),
                "s3:PutObject": now - timedelta(days=1),
            },
            "user-1": {},  # No usage
        }

        findings = detector.detect_all(access_list, usage_data)

        # Only user-1 should be overprivileged
        assert len(findings) == 1
        assert findings[0].identity_id == "user-1"


# =============================================================================
# Trust Analysis Tests
# =============================================================================


class TestTrustRelationship:
    """Tests for TrustRelationship dataclass."""

    def test_trust_relationship_creation(self):
        """Test trust relationship creation."""
        trust = TrustRelationship(
            source_id="arn:aws:iam::123456789012:role/test-role",
            source_name="test-role",
            source_account="123456789012",
            target_principal="arn:aws:iam::111111111111:root",
            target_type="AWS",
            trust_type=TrustType.CROSS_ACCOUNT,
            risk=TrustRisk.MEDIUM,
        )

        assert trust.source_name == "test-role"
        assert trust.is_cross_account is True
        assert trust.is_public is False

    def test_public_trust(self):
        """Test public trust detection."""
        trust = TrustRelationship(
            source_id="test-role",
            source_name="test-role",
            source_account="123456789012",
            target_principal="*",
            target_type="AWS",
            trust_type=TrustType.PUBLIC,
            risk=TrustRisk.CRITICAL,
        )

        assert trust.is_public is True
        assert trust.risk == TrustRisk.CRITICAL

    def test_trust_with_conditions(self):
        """Test trust with conditions."""
        trust = TrustRelationship(
            source_id="test-role",
            source_name="test-role",
            source_account="123456789012",
            target_principal="arn:aws:iam::111111111111:root",
            target_type="AWS",
            trust_type=TrustType.CROSS_ACCOUNT,
            conditions={"StringEquals": {"sts:ExternalId": "secret"}},
            risk=TrustRisk.LOW,
        )

        assert trust.has_conditions is True

    def test_trust_to_dict(self):
        """Test trust serialization."""
        trust = TrustRelationship(
            source_id="test-role",
            source_name="test-role",
            source_account="123456789012",
            target_principal="arn:aws:iam::111111111111:root",
            target_type="AWS",
            trust_type=TrustType.CROSS_ACCOUNT,
            risk=TrustRisk.MEDIUM,
        )

        data = trust.to_dict()
        assert data["source_name"] == "test-role"
        assert data["trust_type"] == "cross_account"
        assert data["is_cross_account"] is True


class TestCrossAccountAccess:
    """Tests for CrossAccountAccess dataclass."""

    def test_cross_account_access_creation(self):
        """Test cross account access summary creation."""
        access = CrossAccountAccess(account_id="123456789012")

        assert access.account_id == "123456789012"
        assert len(access.trusts_out) == 0
        assert len(access.trusts_in) == 0

    def test_external_account_count(self):
        """Test external account counting."""
        trusts = [
            TrustRelationship(
                source_id="role1",
                source_name="role1",
                source_account="123456789012",
                target_principal="111111111111",
                target_type="AWS",
                trust_type=TrustType.CROSS_ACCOUNT,
            ),
            TrustRelationship(
                source_id="role2",
                source_name="role2",
                source_account="123456789012",
                target_principal="222222222222",
                target_type="AWS",
                trust_type=TrustType.CROSS_ACCOUNT,
            ),
            TrustRelationship(
                source_id="role3",
                source_name="role3",
                source_account="123456789012",
                target_principal="111111111111",  # Same as first
                target_type="AWS",
                trust_type=TrustType.CROSS_ACCOUNT,
            ),
        ]

        access = CrossAccountAccess(
            account_id="123456789012",
            trusts_out=trusts,
        )

        assert access.external_account_count == 2


class TestTrustAnalyzer:
    """Tests for TrustAnalyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = TrustAnalyzer(own_accounts=["123456789012", "123456789013"])

        assert "123456789012" in analyzer.own_accounts

    def test_analyze_role_cross_account(self, aws_role_asset: Asset):
        """Test analyzing role with cross-account trust."""
        analyzer = TrustAnalyzer(own_accounts=["123456789012"])

        trusts = analyzer.analyze_role(aws_role_asset)

        assert len(trusts) == 1
        assert trusts[0].trust_type == TrustType.EXTERNAL_IDENTITY
        assert trusts[0].target_principal == "arn:aws:iam::111111111111:root"

    def test_analyze_role_public_trust(self):
        """Test analyzing role with public trust (critical)."""
        role = Asset(
            id="arn:aws:iam::123456789012:role/public-role",
            name="public-role",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_role",
            raw_config={
                "assume_role_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
            },
        )

        analyzer = TrustAnalyzer()
        trusts = analyzer.analyze_role(role)

        assert len(trusts) == 1
        assert trusts[0].trust_type == TrustType.PUBLIC
        assert trusts[0].risk == TrustRisk.CRITICAL

    def test_analyze_role_service_principal(self):
        """Test analyzing role with service principal trust."""
        role = Asset(
            id="arn:aws:iam::123456789012:role/lambda-role",
            name="lambda-role",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_role",
            raw_config={
                "assume_role_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
            },
        )

        analyzer = TrustAnalyzer()
        trusts = analyzer.analyze_role(role)

        assert len(trusts) == 1
        assert trusts[0].trust_type == TrustType.SERVICE_PRINCIPAL
        assert trusts[0].risk == TrustRisk.LOW

    def test_get_cross_account_summary(self):
        """Test cross-account summary generation."""
        analyzer = TrustAnalyzer(own_accounts=["123456789012"])

        trusts = [
            TrustRelationship(
                source_id="role1",
                source_name="role1",
                source_account="123456789012",
                target_principal="*",
                target_type="AWS",
                trust_type=TrustType.PUBLIC,
                risk=TrustRisk.CRITICAL,
            ),
            TrustRelationship(
                source_id="role2",
                source_name="role2",
                source_account="123456789012",
                target_principal="111111111111",
                target_type="AWS",
                trust_type=TrustType.CROSS_ACCOUNT,
                risk=TrustRisk.HIGH,
            ),
        ]

        summary = analyzer.get_cross_account_summary(trusts, "123456789012")

        assert len(summary.trusts_out) == 2
        # Both CRITICAL and HIGH are counted as high risk
        assert len(summary.high_risk_trusts) == 2
        assert len(summary.public_trusts) == 1

    def test_generate_findings(self):
        """Test findings generation from trust analysis."""
        analyzer = TrustAnalyzer()

        trusts = [
            TrustRelationship(
                source_id="arn:aws:iam::123456789012:role/public-role",
                source_name="public-role",
                source_account="123456789012",
                target_principal="*",
                target_type="AWS",
                trust_type=TrustType.PUBLIC,
                risk=TrustRisk.CRITICAL,
            ),
        ]

        findings = analyzer.generate_findings(trusts)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "critical trust" in findings[0].title.lower()


# =============================================================================
# Privilege Escalation Tests
# =============================================================================


class TestEscalationStep:
    """Tests for EscalationStep dataclass."""

    def test_step_creation(self):
        """Test escalation step creation."""
        step = EscalationStep(
            order=1,
            action="Create malicious policy",
            permission_used="iam:CreatePolicy",
            target="New IAM policy",
            description="Create a policy granting admin access",
        )

        assert step.order == 1
        assert step.action == "Create malicious policy"

    def test_step_to_dict(self):
        """Test step serialization."""
        step = EscalationStep(
            order=1,
            action="Create malicious policy",
            permission_used="iam:CreatePolicy",
            target="New IAM policy",
            description="Create a policy granting admin access",
        )

        data = step.to_dict()
        assert data["order"] == 1
        assert data["action"] == "Create malicious policy"


class TestEscalationPath:
    """Tests for EscalationPath dataclass."""

    def test_path_creation(self):
        """Test escalation path creation."""
        path = EscalationPath(
            identity_id="arn:aws:iam::123456789012:user/attacker",
            identity_name="attacker",
            escalation_type=EscalationType.ATTACH_POLICY,
            final_access="Admin access",
            severity=Severity.CRITICAL,
        )

        assert path.identity_name == "attacker"
        assert path.escalation_type == EscalationType.ATTACH_POLICY
        assert path.severity == Severity.CRITICAL

    def test_path_to_finding(self):
        """Test conversion to Finding object."""
        steps = [
            EscalationStep(
                order=1,
                action="Attach admin policy",
                permission_used="iam:AttachUserPolicy",
                target="attacker",
                description="Attach AdministratorAccess to self",
            ),
        ]

        path = EscalationPath(
            identity_id="arn:aws:iam::123456789012:user/attacker",
            identity_name="attacker",
            escalation_type=EscalationType.ATTACH_POLICY,
            steps=steps,
            final_access="Admin access",
            severity=Severity.CRITICAL,
        )

        finding = path.to_finding()
        assert "privesc" in finding.id
        assert finding.severity == Severity.CRITICAL
        assert "privilege escalation" in finding.title.lower()


class TestPrivilegeEscalationAnalyzer:
    """Tests for PrivilegeEscalationAnalyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = PrivilegeEscalationAnalyzer(provider="aws")

        assert analyzer.provider == "aws"
        assert len(analyzer.escalation_permissions) > 0

    def test_analyze_attach_policy_escalation(self, aws_user_asset: Asset):
        """Test detection of attach policy escalation."""
        analyzer = PrivilegeEscalationAnalyzer(provider="aws")

        # User has permission to attach policies
        permissions = [
            "iam:AttachUserPolicy",
            "s3:GetObject",
        ]

        paths = analyzer.analyze(aws_user_asset, permissions)

        # Should detect attach policy escalation path
        attach_paths = [p for p in paths if p.escalation_type == EscalationType.ATTACH_POLICY]
        assert len(attach_paths) >= 1

    def test_analyze_create_access_key_escalation(self, aws_user_asset: Asset):
        """Test detection of create access key escalation."""
        analyzer = PrivilegeEscalationAnalyzer(provider="aws")

        permissions = [
            "iam:CreateAccessKey",
            "s3:GetObject",
        ]

        paths = analyzer.analyze(aws_user_asset, permissions)

        key_paths = [p for p in paths if p.escalation_type == EscalationType.CREATE_ACCESS_KEY]
        assert len(key_paths) >= 1

    def test_analyze_assume_role_escalation(self, aws_user_asset: Asset):
        """Test detection of assume role escalation."""
        analyzer = PrivilegeEscalationAnalyzer(provider="aws")

        # Create an admin role that can be assumed
        admin_role = Asset(
            id="arn:aws:iam::123456789012:role/AdminRole",
            name="AdminRole",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_role",
            raw_config={
                "attached_policies": [
                    "arn:aws:iam::aws:policy/AdministratorAccess"
                ],
            },
        )

        roles = AssetCollection([admin_role])

        permissions = [
            "sts:AssumeRole",
            "s3:GetObject",
        ]

        paths = analyzer.analyze(aws_user_asset, permissions, roles)

        assume_paths = [p for p in paths if p.escalation_type == EscalationType.ASSUME_ROLE]
        assert len(assume_paths) >= 1

    def test_analyze_no_escalation(self, aws_user_asset: Asset):
        """Test when no escalation paths exist."""
        analyzer = PrivilegeEscalationAnalyzer(provider="aws")

        # User only has read permissions
        permissions = [
            "s3:GetObject",
            "s3:ListBucket",
            "ec2:DescribeInstances",
        ]

        paths = analyzer.analyze(aws_user_asset, permissions)

        assert len(paths) == 0

    def test_analyze_all(self):
        """Test analyzing multiple identities."""
        analyzer = PrivilegeEscalationAnalyzer(provider="aws")

        user1 = Asset(
            id="arn:aws:iam::123456789012:user/user1",
            name="user1",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_user",
        )

        user2 = Asset(
            id="arn:aws:iam::123456789012:user/user2",
            name="user2",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_user",
        )

        identities = AssetCollection([user1, user2])

        permissions_map = {
            user1.id: ["iam:AttachUserPolicy", "s3:GetObject"],
            user2.id: ["s3:GetObject", "s3:PutObject"],
        }

        paths = analyzer.analyze_all(identities, permissions_map)

        # Only user1 should have escalation paths
        assert len(paths) >= 1
        assert all(p.identity_id == user1.id for p in paths)

    def test_gcp_escalation_permissions(self):
        """Test GCP escalation detection."""
        analyzer = PrivilegeEscalationAnalyzer(provider="gcp")

        user = Asset(
            id="projects/my-project/serviceAccounts/test@my-project.iam.gserviceaccount.com",
            name="test",
            cloud_provider="gcp",
            account_id="my-project",
            region="global",
            resource_type="gcp_service_account",
        )

        permissions = [
            "iam.serviceAccountKeys.create",
            "storage.objects.get",
        ]

        paths = analyzer.analyze(user, permissions)

        # Should detect create access key escalation
        key_paths = [p for p in paths if p.escalation_type == EscalationType.CREATE_ACCESS_KEY]
        assert len(key_paths) >= 1


# =============================================================================
# Integration Tests
# =============================================================================


class TestCIEMIntegration:
    """Integration tests for CIEM module components."""

    def test_full_ciem_analysis_workflow(self):
        """Test complete CIEM analysis workflow."""
        # Create test data
        user = Asset(
            id="arn:aws:iam::123456789012:user/developer",
            name="developer",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_user",
            raw_config={
                "attached_policies": [
                    "arn:aws:iam::123456789012:policy/DevPolicy"
                ],
            },
        )

        policy = Asset(
            id="arn:aws:iam::123456789012:policy/DevPolicy",
            name="DevPolicy",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_policy",
            raw_config={
                "arn": "arn:aws:iam::123456789012:policy/DevPolicy",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "s3:GetObject",
                                "s3:PutObject",
                                "s3:DeleteObject",
                                "ec2:DescribeInstances",
                                "iam:AttachUserPolicy",  # Risky!
                            ],
                            "Resource": "*",
                        }
                    ],
                },
            },
        )

        # Step 1: Calculate effective permissions
        calc = EffectivePermissionsCalculator(provider="aws")
        access = calc.calculate_effective_permissions(
            identity=user,
            policies=[policy],
        )

        assert access.is_admin is False
        assert len(access.sensitive_permissions) > 0

        # Step 2: Check for overprivileged (with usage data)
        detector = OverprivilegedDetector(min_unused_percentage=10.0)

        now = datetime.now(timezone.utc)
        usage_data = {
            "s3:GetObject": now - timedelta(days=1),
            # PutObject, DeleteObject, ec2, iam never used
        }

        finding = detector.detect(access, usage_data)

        assert finding is not None
        assert len(finding.unused_permissions) >= 3

        # Step 3: Check for privilege escalation
        privesc = PrivilegeEscalationAnalyzer(provider="aws")
        permissions = [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject",
            "ec2:DescribeInstances",
            "iam:AttachUserPolicy",
        ]

        paths = privesc.analyze(user, permissions)

        assert len(paths) >= 1
        assert any(p.escalation_type == EscalationType.ATTACH_POLICY for p in paths)

    def test_exports_from_init(self):
        """Test that all expected classes are exported from __init__."""
        from stance.ciem import (
            EffectivePermissionsCalculator,
            PermissionSet,
            EffectiveAccess,
            OverprivilegedDetector,
            OverprivilegedFinding,
            UnusedPermission,
            TrustAnalyzer,
            TrustRelationship,
            CrossAccountAccess,
            TrustRisk,
            PrivilegeEscalationAnalyzer,
            EscalationPath,
        )

        # All imports should succeed
        assert EffectivePermissionsCalculator is not None
        assert OverprivilegedDetector is not None
        assert TrustAnalyzer is not None
        assert PrivilegeEscalationAnalyzer is not None
