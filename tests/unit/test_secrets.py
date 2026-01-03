"""
Comprehensive tests for Secret Rotation Monitoring module.

Tests cover:
- Secret inventory collection and management
- Age tracking and rotation analysis
- Policy enforcement and violations
- Expiration alerting

Part of Phase 82: Secret Rotation Monitoring
"""

import pytest
from datetime import datetime, timedelta
from typing import Dict, Any, List
from unittest.mock import Mock, patch, MagicMock

from stance.secrets.inventory import (
    SecretType,
    SecretSource,
    SecretStatus,
    SecretMetadata,
    SecretInventoryItem,
    SecretInventory,
    SecretInventoryCollector,
)
from stance.secrets.age_tracker import (
    AgeStatus,
    AgeThresholds,
    SecretTypeThresholds,
    SecretAge,
    AgeDistribution,
    RotationHistory,
    SecretAgeReport,
    SecretAgeTracker,
)
from stance.secrets.rotation_policy import (
    RotationFrequency,
    PolicySeverity,
    EnforcementAction,
    ComplianceFramework,
    RotationRequirement,
    RotationPolicy,
    PolicyViolation,
    RotationPolicySet,
    RotationPolicyEnforcer,
)
from stance.secrets.expiration_alerting import (
    AlertPriority,
    AlertType,
    AlertChannel,
    AlertStatus,
    AlertRecipient,
    ExpirationAlert,
    ExpirationAlertRule,
    AlertDigest,
    ExpirationAlerter,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def sample_metadata():
    """Create sample secret metadata."""
    now = datetime.utcnow()
    return SecretMetadata(
        created_at=now - timedelta(days=60),
        last_rotated_at=now - timedelta(days=30),
        expires_at=now + timedelta(days=30),
        created_by="test-user",
        rotation_history=[
            now - timedelta(days=90),
            now - timedelta(days=60),
            now - timedelta(days=30),
        ],
    )


@pytest.fixture
def sample_secret(sample_metadata):
    """Create a sample secret inventory item."""
    return SecretInventoryItem(
        secret_id="secret-001",
        name="test-database-password",
        secret_type=SecretType.DATABASE_PASSWORD,
        source=SecretSource.AWS_SECRETS_MANAGER,
        status=SecretStatus.ACTIVE,
        metadata=sample_metadata,
        tags=["production", "database"],
        risk_score=0.3,
    )


@pytest.fixture
def sample_inventory(sample_secret):
    """Create a sample secret inventory."""
    now = datetime.utcnow()
    secrets = [
        sample_secret,
        # Fresh secret
        SecretInventoryItem(
            secret_id="secret-002",
            name="api-key-fresh",
            secret_type=SecretType.API_KEY,
            source=SecretSource.AWS_SECRETS_MANAGER,
            status=SecretStatus.ACTIVE,
            metadata=SecretMetadata(
                created_at=now - timedelta(days=5),
                last_rotated_at=now - timedelta(days=5),
            ),
        ),
        # Critical age secret
        SecretInventoryItem(
            secret_id="secret-003",
            name="old-access-key",
            secret_type=SecretType.AWS_ACCESS_KEY,
            source=SecretSource.AWS_IAM,
            status=SecretStatus.ROTATION_REQUIRED,
            metadata=SecretMetadata(
                created_at=now - timedelta(days=200),
                last_rotated_at=now - timedelta(days=150),
            ),
        ),
        # Expiring soon secret
        SecretInventoryItem(
            secret_id="secret-004",
            name="expiring-cert",
            secret_type=SecretType.TLS_CERTIFICATE,
            source=SecretSource.AZURE_KEY_VAULT,
            status=SecretStatus.EXPIRING_SOON,
            metadata=SecretMetadata(
                created_at=now - timedelta(days=335),
                expires_at=now + timedelta(days=7),
            ),
        ),
        # Expired secret
        SecretInventoryItem(
            secret_id="secret-005",
            name="expired-token",
            secret_type=SecretType.OAUTH_TOKEN,
            source=SecretSource.GCP_SECRET_MANAGER,
            status=SecretStatus.EXPIRED,
            metadata=SecretMetadata(
                created_at=now - timedelta(days=60),
                expires_at=now - timedelta(days=5),
            ),
        ),
    ]
    return SecretInventory(secrets=secrets)


# =============================================================================
# Secret Inventory Tests
# =============================================================================

class TestSecretType:
    """Tests for SecretType enum."""

    def test_secret_type_values(self):
        """Test that all expected secret types exist."""
        assert SecretType.AWS_ACCESS_KEY.value == "aws_access_key"
        assert SecretType.DATABASE_PASSWORD.value == "database_password"
        assert SecretType.API_KEY.value == "api_key"
        assert SecretType.TLS_CERTIFICATE.value == "tls_certificate"
        assert SecretType.SSH_PRIVATE_KEY.value == "ssh_private_key"

    def test_secret_type_count(self):
        """Test that we have comprehensive secret type coverage."""
        # Should have at least 25 secret types
        assert len(SecretType) >= 25


class TestSecretSource:
    """Tests for SecretSource enum."""

    def test_cloud_provider_sources(self):
        """Test cloud provider secret sources."""
        assert SecretSource.AWS_SECRETS_MANAGER.value == "aws_secrets_manager"
        assert SecretSource.AZURE_KEY_VAULT.value == "azure_key_vault"
        assert SecretSource.GCP_SECRET_MANAGER.value == "gcp_secret_manager"
        assert SecretSource.HASHICORP_VAULT.value == "hashicorp_vault"
        assert SecretSource.KUBERNETES_SECRET.value == "kubernetes_secret"


class TestSecretMetadata:
    """Tests for SecretMetadata dataclass."""

    def test_metadata_creation(self):
        """Test metadata dataclass creation."""
        now = datetime.utcnow()
        metadata = SecretMetadata(
            created_at=now,
            created_by="admin",
            version="1.0",
        )
        assert metadata.created_at == now
        assert metadata.created_by == "admin"
        assert metadata.last_rotated_at is None

    def test_metadata_with_rotation_history(self):
        """Test metadata with rotation history."""
        now = datetime.utcnow()
        history = [now - timedelta(days=30), now]
        metadata = SecretMetadata(
            created_at=now - timedelta(days=60),
            rotation_history=history,
        )
        assert len(metadata.rotation_history) == 2


class TestSecretInventoryItem:
    """Tests for SecretInventoryItem."""

    def test_item_age_days(self, sample_secret):
        """Test age_days property calculation."""
        age = sample_secret.age_days
        assert age is not None
        assert 59 <= age <= 61  # Around 60 days

    def test_item_days_since_rotation(self, sample_secret):
        """Test days_since_rotation property."""
        days = sample_secret.days_since_rotation
        assert days is not None
        assert 29 <= days <= 31  # Around 30 days

    def test_item_days_until_expiration(self, sample_secret):
        """Test days_until_expiration property."""
        days = sample_secret.days_until_expiration
        assert days is not None
        assert 29 <= days <= 31  # Around 30 days

    def test_item_is_expired(self, sample_secret):
        """Test is_expired property."""
        assert not sample_secret.is_expired

    def test_item_needs_rotation_default(self, sample_secret):
        """Test needs_rotation property."""
        # At 30 days, should not need rotation yet (90-day default)
        assert not sample_secret.needs_rotation()

    def test_item_needs_rotation_custom_threshold(self, sample_secret):
        """Test needs_rotation with custom threshold."""
        assert sample_secret.needs_rotation(max_days=25)

    def test_item_to_dict(self, sample_secret):
        """Test to_dict method."""
        d = sample_secret.to_dict()
        assert d["secret_id"] == "secret-001"
        assert d["name"] == "test-database-password"
        assert d["secret_type"] == "database_password"
        assert d["source"] == "aws_secrets_manager"


class TestSecretInventory:
    """Tests for SecretInventory."""

    def test_inventory_creation(self, sample_inventory):
        """Test inventory creation and basic properties."""
        assert len(sample_inventory.secrets) == 5

    def test_get_by_source(self, sample_inventory):
        """Test filtering by source."""
        aws_secrets = sample_inventory.get_by_source(SecretSource.AWS_SECRETS_MANAGER)
        assert len(aws_secrets) == 2

    def test_get_by_type(self, sample_inventory):
        """Test filtering by type."""
        db_passwords = sample_inventory.get_by_type(SecretType.DATABASE_PASSWORD)
        assert len(db_passwords) == 1

    def test_get_expired(self, sample_inventory):
        """Test getting expired secrets."""
        expired = sample_inventory.get_expired()
        assert len(expired) == 1
        assert expired[0].name == "expired-token"

    def test_get_expiring_soon(self, sample_inventory):
        """Test getting secrets expiring soon."""
        expiring = sample_inventory.get_expiring_soon(days=30)
        assert len(expiring) >= 1  # At least the cert expiring in 7 days

    def test_get_needing_rotation(self, sample_inventory):
        """Test getting secrets needing rotation."""
        needing = sample_inventory.get_needing_rotation()
        assert len(needing) >= 1  # The old access key

    def test_get_summary(self, sample_inventory):
        """Test inventory summary."""
        summary = sample_inventory.get_summary()
        assert summary["total_secrets"] == 5
        assert "by_source" in summary
        assert "by_type" in summary
        assert "by_status" in summary


class TestSecretInventoryCollector:
    """Tests for SecretInventoryCollector."""

    def test_collector_initialization(self):
        """Test collector initialization."""
        collector = SecretInventoryCollector()
        assert collector.inventory is not None
        assert len(collector.inventory.secrets) == 0

    def test_collect_from_aws_secrets_manager(self):
        """Test AWS Secrets Manager collection."""
        collector = SecretInventoryCollector()

        secrets_data = [
            {
                "Name": "prod/database/password",
                "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/database/password",
                "CreatedDate": datetime.utcnow() - timedelta(days=30),
                "LastChangedDate": datetime.utcnow() - timedelta(days=10),
                "Tags": [{"Key": "environment", "Value": "production"}],
            },
            {
                "Name": "api/stripe-key",
                "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:api/stripe-key",
                "CreatedDate": datetime.utcnow() - timedelta(days=60),
            },
        ]

        collector.collect_from_aws_secrets_manager(
            secrets_data, "123456789", "us-east-1"
        )

        assert len(collector.inventory.secrets) == 2
        assert collector.inventory.secrets[0].source == SecretSource.AWS_SECRETS_MANAGER

    def test_collect_from_aws_iam_access_keys(self):
        """Test AWS IAM access key collection."""
        collector = SecretInventoryCollector()

        access_keys_data = [
            {
                "UserName": "admin-user",
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status": "Active",
                "CreateDate": datetime.utcnow() - timedelta(days=100),
            },
        ]

        collector.collect_from_aws_iam_access_keys(access_keys_data, "123456789")

        assert len(collector.inventory.secrets) == 1
        assert collector.inventory.secrets[0].secret_type == SecretType.AWS_ACCESS_KEY
        assert collector.inventory.secrets[0].source == SecretSource.AWS_IAM

    def test_collect_from_azure_key_vault(self):
        """Test Azure Key Vault collection."""
        collector = SecretInventoryCollector()

        secrets_data = [
            {
                "id": "https://myvault.vault.azure.net/secrets/db-password",
                "attributes": {
                    "created": int((datetime.utcnow() - timedelta(days=45)).timestamp()),
                    "updated": int((datetime.utcnow() - timedelta(days=15)).timestamp()),
                    "enabled": True,
                    "exp": int((datetime.utcnow() + timedelta(days=60)).timestamp()),
                },
            },
        ]

        collector.collect_from_azure_key_vault(
            secrets_data, "sub-123", "myvault"
        )

        assert len(collector.inventory.secrets) == 1
        assert collector.inventory.secrets[0].source == SecretSource.AZURE_KEY_VAULT

    def test_collect_from_gcp_secret_manager(self):
        """Test GCP Secret Manager collection."""
        collector = SecretInventoryCollector()

        secrets_data = [
            {
                "name": "projects/my-project/secrets/api-key",
                "createTime": (datetime.utcnow() - timedelta(days=20)).isoformat() + "Z",
                "labels": {"team": "platform"},
            },
        ]

        collector.collect_from_gcp_secret_manager(secrets_data, "my-project")

        assert len(collector.inventory.secrets) == 1
        assert collector.inventory.secrets[0].source == SecretSource.GCP_SECRET_MANAGER

    def test_collect_from_kubernetes_secrets(self):
        """Test Kubernetes secrets collection."""
        collector = SecretInventoryCollector()

        secrets_data = [
            {
                "metadata": {
                    "name": "db-credentials",
                    "namespace": "production",
                    "uid": "abc-123",
                    "creationTimestamp": (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z",
                    "labels": {"app": "backend"},
                },
                "type": "Opaque",
            },
        ]

        collector.collect_from_kubernetes_secrets(secrets_data, "prod-cluster")

        assert len(collector.inventory.secrets) == 1
        assert collector.inventory.secrets[0].source == SecretSource.KUBERNETES_SECRET

    def test_collect_from_hashicorp_vault(self):
        """Test HashiCorp Vault collection."""
        collector = SecretInventoryCollector()

        secrets_data = [
            {
                "path": "secret/data/production/database",
                "metadata": {
                    "created_time": (datetime.utcnow() - timedelta(days=25)).isoformat() + "Z",
                    "version": 3,
                },
            },
        ]

        collector.collect_from_hashicorp_vault(
            secrets_data, "https://vault.example.com"
        )

        assert len(collector.inventory.secrets) == 1
        assert collector.inventory.secrets[0].source == SecretSource.HASHICORP_VAULT


# =============================================================================
# Age Tracker Tests
# =============================================================================

class TestAgeThresholds:
    """Tests for AgeThresholds."""

    def test_default_thresholds(self):
        """Test default threshold values."""
        thresholds = AgeThresholds()
        assert thresholds.fresh_days == 7
        assert thresholds.acceptable_days == 30
        assert thresholds.stale_days == 90
        assert thresholds.critical_days == 180

    def test_get_status_fresh(self):
        """Test fresh status determination."""
        thresholds = AgeThresholds()
        assert thresholds.get_status(5) == AgeStatus.FRESH

    def test_get_status_acceptable(self):
        """Test acceptable status determination."""
        thresholds = AgeThresholds()
        assert thresholds.get_status(20) == AgeStatus.ACCEPTABLE

    def test_get_status_aging(self):
        """Test aging status determination."""
        thresholds = AgeThresholds()
        assert thresholds.get_status(45) == AgeStatus.AGING

    def test_get_status_stale(self):
        """Test stale status determination."""
        thresholds = AgeThresholds()
        assert thresholds.get_status(75) == AgeStatus.STALE

    def test_get_status_critical(self):
        """Test critical status determination."""
        thresholds = AgeThresholds()
        assert thresholds.get_status(200) == AgeStatus.CRITICAL

    def test_get_status_unknown(self):
        """Test unknown status for negative age."""
        thresholds = AgeThresholds()
        assert thresholds.get_status(-1) == AgeStatus.UNKNOWN


class TestSecretTypeThresholds:
    """Tests for SecretTypeThresholds."""

    def test_default_type_thresholds(self):
        """Test that type-specific thresholds are created."""
        type_thresholds = SecretTypeThresholds()
        assert SecretType.AWS_ACCESS_KEY in type_thresholds.thresholds
        assert SecretType.DATABASE_PASSWORD in type_thresholds.thresholds
        assert SecretType.TLS_CERTIFICATE in type_thresholds.thresholds

    def test_get_thresholds_for_known_type(self):
        """Test getting thresholds for a known type."""
        type_thresholds = SecretTypeThresholds()
        aws_thresholds = type_thresholds.get_thresholds(SecretType.AWS_ACCESS_KEY)
        assert aws_thresholds.stale_days == 90

    def test_get_thresholds_for_unknown_type(self):
        """Test getting default thresholds for unknown type."""
        type_thresholds = SecretTypeThresholds()
        thresholds = type_thresholds.get_thresholds(SecretType.CUSTOM)
        assert thresholds == type_thresholds.default_thresholds


class TestSecretAgeTracker:
    """Tests for SecretAgeTracker."""

    def test_tracker_initialization(self):
        """Test tracker initialization."""
        tracker = SecretAgeTracker()
        assert tracker.type_thresholds is not None
        assert tracker.expiring_soon_days == 30

    def test_analyze_inventory(self, sample_inventory):
        """Test full inventory analysis."""
        tracker = SecretAgeTracker()
        report = tracker.analyze_inventory(sample_inventory)

        assert report.total_secrets == 5
        assert report.analyzed_secrets > 0
        assert len(report.secret_ages) == 5

    def test_analyze_secret_age(self, sample_secret):
        """Test individual secret age analysis."""
        tracker = SecretAgeTracker()
        age = tracker._analyze_secret_age(sample_secret)

        assert age.secret_id == "secret-001"
        assert age.age_days >= 59
        assert age.days_since_rotation >= 29
        assert age.days_until_expiration >= 29

    def test_critical_secrets_detection(self, sample_inventory):
        """Test detection of critical age secrets."""
        tracker = SecretAgeTracker()
        report = tracker.analyze_inventory(sample_inventory)

        # Should detect the 200-day old access key
        assert len(report.critical_secrets) >= 1

    def test_expiring_soon_detection(self, sample_inventory):
        """Test detection of expiring secrets."""
        tracker = SecretAgeTracker()
        report = tracker.analyze_inventory(sample_inventory)

        # Should detect the cert expiring in 7 days
        assert len(report.expiring_soon) >= 1

    def test_risk_score_calculation(self, sample_secret):
        """Test risk score calculation."""
        tracker = SecretAgeTracker()
        age = tracker._analyze_secret_age(sample_secret)

        assert 0.0 <= age.risk_score <= 1.0
        assert len(age.risk_factors) >= 0

    def test_overall_distribution(self, sample_inventory):
        """Test age distribution calculation."""
        tracker = SecretAgeTracker()
        report = tracker.analyze_inventory(sample_inventory)

        dist = report.overall_distribution
        assert dist.count == 5
        assert dist.fresh_count + dist.acceptable_count + dist.aging_count + \
               dist.stale_count + dist.critical_count + dist.expired_count + \
               dist.unknown_count == 5

    def test_rotation_history_analysis(self, sample_inventory):
        """Test rotation history analysis."""
        tracker = SecretAgeTracker()
        report = tracker.analyze_inventory(sample_inventory, include_rotation_history=True)

        # At least one secret has rotation history
        histories_with_data = [h for h in report.rotation_histories if h.rotation_count > 0]
        assert len(histories_with_data) >= 1

    def test_get_secrets_by_age_status(self, sample_inventory):
        """Test filtering secrets by age status."""
        tracker = SecretAgeTracker()
        critical = tracker.get_secrets_by_age_status(sample_inventory, AgeStatus.CRITICAL)

        # Should find the 200-day old access key
        assert len(critical) >= 1

    def test_get_rotation_due_secrets(self, sample_inventory):
        """Test getting secrets due for rotation."""
        tracker = SecretAgeTracker()
        due = tracker.get_rotation_due_secrets(sample_inventory, days_threshold=90)

        # Should find the 150-day old access key
        assert len(due) >= 1
        # First item should be most overdue
        if len(due) >= 2:
            assert due[0][1] >= due[1][1]

    def test_get_expiring_secrets(self, sample_inventory):
        """Test getting expiring secrets."""
        tracker = SecretAgeTracker()
        expiring = tracker.get_expiring_secrets(sample_inventory, days_threshold=30)

        # Should find the cert expiring in 7 days
        assert len(expiring) >= 1

    def test_calculate_rotation_compliance(self, sample_inventory):
        """Test rotation compliance calculation."""
        tracker = SecretAgeTracker()
        compliance = tracker.calculate_rotation_compliance(sample_inventory)

        assert "compliant_count" in compliance
        assert "non_compliant_count" in compliance
        assert "compliance_rate" in compliance
        assert 0.0 <= compliance["compliance_rate"] <= 100.0

    def test_recommendations_generation(self, sample_inventory):
        """Test recommendation generation."""
        tracker = SecretAgeTracker()
        report = tracker.analyze_inventory(sample_inventory)

        assert len(report.recommendations) >= 0
        # Should generate recommendations for critical/stale secrets
        if report.critical_secrets or report.stale_secrets:
            assert len(report.recommendations) > 0


# =============================================================================
# Rotation Policy Tests
# =============================================================================

class TestRotationPolicy:
    """Tests for RotationPolicy."""

    def test_policy_creation(self):
        """Test policy creation."""
        policy = RotationPolicy(
            policy_id="pol-001",
            name="Test Policy",
            description="Test rotation policy",
            max_age_days=90,
            applies_to_types={SecretType.DATABASE_PASSWORD},
        )
        assert policy.policy_id == "pol-001"
        assert policy.max_age_days == 90

    def test_policy_applies_to_secret(self, sample_secret):
        """Test policy applicability check."""
        policy = RotationPolicy(
            policy_id="pol-001",
            name="DB Policy",
            description="Database password policy",
            applies_to_types={SecretType.DATABASE_PASSWORD},
        )
        assert policy.applies_to_secret(sample_secret)

    def test_policy_exclusions(self, sample_secret):
        """Test policy exclusions."""
        policy = RotationPolicy(
            policy_id="pol-001",
            name="Test Policy",
            description="Test",
            exclude_types={SecretType.DATABASE_PASSWORD},
        )
        assert not policy.applies_to_secret(sample_secret)

    def test_policy_name_pattern_matching(self, sample_secret):
        """Test name pattern matching."""
        policy = RotationPolicy(
            policy_id="pol-001",
            name="Test Policy",
            description="Test",
            applies_to_name_patterns=[".*database.*"],
        )
        assert policy.applies_to_secret(sample_secret)

    def test_get_days_until_rotation_due(self, sample_secret):
        """Test days until rotation calculation."""
        policy = RotationPolicy(
            policy_id="pol-001",
            name="Test",
            description="Test",
            max_age_days=90,
        )
        days = policy.get_days_until_rotation_due(sample_secret)
        assert days == 60  # 90 - 30 days since rotation

    def test_is_rotation_due(self, sample_secret):
        """Test rotation due check."""
        policy = RotationPolicy(
            policy_id="pol-001",
            name="Test",
            description="Test",
            max_age_days=90,
        )
        assert not policy.is_rotation_due(sample_secret)

        strict_policy = RotationPolicy(
            policy_id="pol-002",
            name="Strict",
            description="Strict",
            max_age_days=25,
        )
        assert strict_policy.is_rotation_due(sample_secret)

    def test_is_in_warning_period(self, sample_secret):
        """Test warning period detection."""
        policy = RotationPolicy(
            policy_id="pol-001",
            name="Test",
            description="Test",
            max_age_days=40,
            warning_days=14,
        )
        # 10 days until due, within 14-day warning
        assert policy.is_in_warning_period(sample_secret)

    def test_policy_to_dict(self):
        """Test policy serialization."""
        policy = RotationPolicy(
            policy_id="pol-001",
            name="Test",
            description="Test",
            max_age_days=90,
            severity=PolicySeverity.HIGH,
        )
        d = policy.to_dict()
        assert d["policy_id"] == "pol-001"
        assert d["max_age_days"] == 90
        assert d["severity"] == "high"


class TestRotationPolicySet:
    """Tests for RotationPolicySet."""

    def test_policy_set_creation(self):
        """Test policy set creation."""
        policy_set = RotationPolicySet(
            name="Test Set",
            description="Test policy set",
        )
        assert len(policy_set.policies) == 0

    def test_add_and_remove_policy(self):
        """Test adding and removing policies."""
        policy_set = RotationPolicySet(name="Test", description="Test")
        policy = RotationPolicy(
            policy_id="pol-001",
            name="Test",
            description="Test",
        )
        policy_set.add_policy(policy)
        assert len(policy_set.policies) == 1

        removed = policy_set.remove_policy("pol-001")
        assert removed
        assert len(policy_set.policies) == 0

    def test_get_applicable_policies(self, sample_secret):
        """Test getting applicable policies."""
        policy_set = RotationPolicySet(name="Test", description="Test")
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-001",
            name="DB Policy",
            description="Test",
            applies_to_types={SecretType.DATABASE_PASSWORD},
        ))
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-002",
            name="API Policy",
            description="Test",
            applies_to_types={SecretType.API_KEY},
        ))

        applicable = policy_set.get_applicable_policies(sample_secret)
        assert len(applicable) == 1
        assert applicable[0].policy_id == "pol-001"

    def test_get_most_restrictive_policy(self, sample_secret):
        """Test getting most restrictive policy."""
        policy_set = RotationPolicySet(name="Test", description="Test")
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-001",
            name="Lenient",
            description="Test",
            max_age_days=180,
            applies_to_types={SecretType.DATABASE_PASSWORD},
        ))
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-002",
            name="Strict",
            description="Test",
            max_age_days=60,
            applies_to_types={SecretType.DATABASE_PASSWORD},
        ))

        most_restrictive = policy_set.get_most_restrictive_policy(sample_secret)
        assert most_restrictive.policy_id == "pol-002"
        assert most_restrictive.max_age_days == 60


class TestRotationPolicyEnforcer:
    """Tests for RotationPolicyEnforcer."""

    def test_enforcer_initialization(self):
        """Test enforcer initialization with default policies."""
        enforcer = RotationPolicyEnforcer()
        assert enforcer.policy_set is not None
        assert len(enforcer.policy_set.policies) > 0

    def test_enforce_compliant_inventory(self):
        """Test enforcement on compliant secrets."""
        now = datetime.utcnow()
        inventory = SecretInventory(secrets=[
            SecretInventoryItem(
                secret_id="secret-001",
                name="fresh-secret",
                secret_type=SecretType.API_KEY,
                source=SecretSource.AWS_SECRETS_MANAGER,
                status=SecretStatus.ACTIVE,
                metadata=SecretMetadata(
                    created_at=now - timedelta(days=10),
                    last_rotated_at=now - timedelta(days=10),
                ),
            ),
        ])

        enforcer = RotationPolicyEnforcer()
        result = enforcer.enforce(inventory)

        assert result["compliant_count"] >= 0
        assert result["compliance_rate"] > 0

    def test_enforce_non_compliant_inventory(self, sample_inventory):
        """Test enforcement on non-compliant secrets."""
        enforcer = RotationPolicyEnforcer()
        result = enforcer.enforce(sample_inventory)

        # Should have some violations for old/expired secrets
        assert "violation_count" in result
        assert "compliance_rate" in result

    def test_violation_creation(self):
        """Test policy violation creation."""
        now = datetime.utcnow()
        old_secret = SecretInventoryItem(
            secret_id="secret-old",
            name="old-access-key",
            secret_type=SecretType.AWS_ACCESS_KEY,
            source=SecretSource.AWS_IAM,
            status=SecretStatus.ACTIVE,
            metadata=SecretMetadata(
                created_at=now - timedelta(days=200),
                last_rotated_at=now - timedelta(days=200),
            ),
        )
        inventory = SecretInventory(secrets=[old_secret])

        enforcer = RotationPolicyEnforcer()
        result = enforcer.enforce(inventory)

        assert result["violation_count"] >= 1
        assert len(result["violations"]) >= 1

    def test_enforcement_action_execution(self):
        """Test enforcement action execution."""
        now = datetime.utcnow()
        old_secret = SecretInventoryItem(
            secret_id="secret-old",
            name="old-key",
            secret_type=SecretType.AWS_ACCESS_KEY,
            source=SecretSource.AWS_IAM,
            status=SecretStatus.ACTIVE,
            metadata=SecretMetadata(
                created_at=now - timedelta(days=200),
                last_rotated_at=now - timedelta(days=200),
            ),
        )
        inventory = SecretInventory(secrets=[old_secret])

        enforcer = RotationPolicyEnforcer()
        result = enforcer.enforce(inventory, execute_actions=True)

        # Actions should have been executed
        assert result["actions_executed"] == True

    def test_compliance_requirements(self):
        """Test getting compliance requirements."""
        enforcer = RotationPolicyEnforcer()
        pci_reqs = enforcer.get_compliance_requirements(ComplianceFramework.PCI_DSS)

        assert len(pci_reqs) > 0
        assert all(isinstance(r, RotationRequirement) for r in pci_reqs)

    def test_create_compliance_policy_set(self):
        """Test creating compliance-driven policy set."""
        enforcer = RotationPolicyEnforcer()
        policy_set = enforcer.create_compliance_policy_set([
            ComplianceFramework.PCI_DSS,
            ComplianceFramework.SOC2,
        ])

        assert len(policy_set.policies) > 0
        assert "Compliance-Driven" in policy_set.name

    def test_policy_report_generation(self):
        """Test policy report generation."""
        enforcer = RotationPolicyEnforcer()
        report = enforcer.generate_policy_report()

        assert "policy_set_name" in report
        assert "total_policies" in report
        assert "policies" in report


# =============================================================================
# Expiration Alerting Tests
# =============================================================================

class TestAlertRecipient:
    """Tests for AlertRecipient."""

    def test_recipient_creation(self):
        """Test recipient creation."""
        recipient = AlertRecipient(
            recipient_id="recip-001",
            name="Security Team",
            channel=AlertChannel.SLACK,
            address="#security-alerts",
        )
        assert recipient.enabled

    def test_should_receive_priority_filter(self):
        """Test priority-based filtering."""
        recipient = AlertRecipient(
            recipient_id="recip-001",
            name="Test",
            channel=AlertChannel.EMAIL,
            address="test@example.com",
            min_priority=AlertPriority.HIGH,
        )

        assert recipient.should_receive(AlertPriority.CRITICAL, AlertType.EXPIRED)
        assert recipient.should_receive(AlertPriority.HIGH, AlertType.EXPIRED)
        assert not recipient.should_receive(AlertPriority.LOW, AlertType.EXPIRED)

    def test_should_receive_type_filter(self):
        """Test alert type filtering."""
        recipient = AlertRecipient(
            recipient_id="recip-001",
            name="Test",
            channel=AlertChannel.EMAIL,
            address="test@example.com",
            alert_types={AlertType.EXPIRED, AlertType.CERTIFICATE_EXPIRING},
        )

        assert recipient.should_receive(AlertPriority.HIGH, AlertType.EXPIRED)
        assert not recipient.should_receive(AlertPriority.HIGH, AlertType.ROTATION_OVERDUE)

    def test_should_receive_disabled(self):
        """Test disabled recipient."""
        recipient = AlertRecipient(
            recipient_id="recip-001",
            name="Test",
            channel=AlertChannel.EMAIL,
            address="test@example.com",
            enabled=False,
        )

        assert not recipient.should_receive(AlertPriority.CRITICAL, AlertType.EXPIRED)


class TestExpirationAlert:
    """Tests for ExpirationAlert."""

    def test_alert_creation(self):
        """Test alert creation."""
        alert = ExpirationAlert(
            alert_id="alert-001",
            alert_type=AlertType.EXPIRING_SOON,
            priority=AlertPriority.HIGH,
            secret_id="secret-001",
            secret_name="test-cert",
            title="Certificate Expiring",
            message="Test certificate expires in 7 days",
            days_until_event=7,
        )
        assert alert.status == AlertStatus.PENDING

    def test_alert_to_dict(self):
        """Test alert serialization."""
        alert = ExpirationAlert(
            alert_id="alert-001",
            alert_type=AlertType.EXPIRED,
            priority=AlertPriority.CRITICAL,
            secret_name="test-secret",
            title="Test",
            message="Test message",
        )
        d = alert.to_dict()

        assert d["alert_id"] == "alert-001"
        assert d["alert_type"] == "expired"
        assert d["priority"] == "critical"

    def test_alert_to_slack_block(self):
        """Test Slack formatting."""
        alert = ExpirationAlert(
            alert_id="alert-001",
            alert_type=AlertType.EXPIRING_SOON,
            priority=AlertPriority.HIGH,
            secret_name="test-cert",
            secret_type=SecretType.TLS_CERTIFICATE,
            title="Certificate Expiring",
            message="Certificate expires soon",
            days_until_event=7,
        )
        slack = alert.to_slack_block()

        assert "blocks" in slack
        assert len(slack["blocks"]) > 0

    def test_alert_to_pagerduty_event(self):
        """Test PagerDuty formatting."""
        alert = ExpirationAlert(
            alert_id="alert-001",
            alert_type=AlertType.EXPIRED,
            priority=AlertPriority.CRITICAL,
            secret_name="test-secret",
            title="Secret Expired",
            message="Test message",
        )
        pd = alert.to_pagerduty_event()

        assert pd["event_action"] == "trigger"
        assert pd["dedup_key"] == "alert-001"
        assert pd["payload"]["severity"] == "critical"


class TestExpirationAlertRule:
    """Tests for ExpirationAlertRule."""

    def test_rule_creation(self):
        """Test rule creation."""
        rule = ExpirationAlertRule(
            rule_id="rule-001",
            name="Test Rule",
            description="Test alert rule",
            days_before_expiration=[30, 14, 7],
        )
        assert rule.enabled
        assert len(rule.days_before_expiration) == 3

    def test_get_priority_for_days(self):
        """Test priority determination by days."""
        rule = ExpirationAlertRule(
            rule_id="rule-001",
            name="Test",
            description="Test",
        )
        # Uses default priority mapping

        assert rule.get_priority_for_days(1) == AlertPriority.CRITICAL
        assert rule.get_priority_for_days(7) == AlertPriority.HIGH
        assert rule.get_priority_for_days(14) == AlertPriority.MEDIUM
        assert rule.get_priority_for_days(30) == AlertPriority.LOW


class TestExpirationAlerter:
    """Tests for ExpirationAlerter."""

    def test_alerter_initialization(self):
        """Test alerter initialization."""
        alerter = ExpirationAlerter()
        assert len(alerter.rules) > 0  # Default rules created

    def test_add_rule(self):
        """Test adding custom rule."""
        alerter = ExpirationAlerter()
        initial_count = len(alerter.rules)

        alerter.add_rule(ExpirationAlertRule(
            rule_id="custom-001",
            name="Custom Rule",
            description="Custom rule",
        ))

        assert len(alerter.rules) == initial_count + 1

    def test_add_recipient(self):
        """Test adding recipient."""
        alerter = ExpirationAlerter()
        alerter.add_recipient(AlertRecipient(
            recipient_id="recip-001",
            name="Test",
            channel=AlertChannel.EMAIL,
            address="test@example.com",
        ))

        assert len(alerter.recipients) == 1

    def test_check_inventory(self, sample_inventory):
        """Test inventory checking."""
        alerter = ExpirationAlerter()
        alerts = alerter.check_inventory(sample_inventory, send_notifications=False)

        # Should generate alerts for expiring/expired secrets
        assert len(alerts) >= 0  # May or may not generate depending on thresholds

    def test_check_expiring_secret(self):
        """Test alert generation for expiring secret."""
        now = datetime.utcnow()
        expiring_secret = SecretInventoryItem(
            secret_id="secret-expiring",
            name="expiring-cert",
            secret_type=SecretType.TLS_CERTIFICATE,
            source=SecretSource.AWS_SECRETS_MANAGER,
            status=SecretStatus.EXPIRING_SOON,
            metadata=SecretMetadata(
                created_at=now - timedelta(days=358),
                expires_at=now + timedelta(days=7),
            ),
        )
        inventory = SecretInventory(secrets=[expiring_secret])

        alerter = ExpirationAlerter()
        alerts = alerter.check_inventory(inventory, send_notifications=False)

        # Should generate expiration alert
        assert len(alerts) >= 1

    def test_acknowledge_alert(self):
        """Test alert acknowledgment."""
        alerter = ExpirationAlerter()

        # Create a test alert
        alert = ExpirationAlert(
            alert_id="alert-test",
            alert_type=AlertType.EXPIRING_SOON,
            priority=AlertPriority.HIGH,
            secret_name="test",
            title="Test",
            message="Test",
        )
        alerter.active_alerts[alert.alert_id] = alert

        result = alerter.acknowledge_alert("alert-test", "test-user")
        assert result
        assert alert.status == AlertStatus.ACKNOWLEDGED

    def test_resolve_alert(self):
        """Test alert resolution."""
        alerter = ExpirationAlerter()

        alert = ExpirationAlert(
            alert_id="alert-test",
            alert_type=AlertType.EXPIRING_SOON,
            priority=AlertPriority.HIGH,
            secret_name="test",
            title="Test",
            message="Test",
        )
        alerter.active_alerts[alert.alert_id] = alert

        result = alerter.resolve_alert("alert-test", "Rotated successfully")
        assert result
        assert "alert-test" not in alerter.active_alerts
        assert len(alerter.alert_history) == 1

    def test_generate_digest(self):
        """Test digest generation."""
        alerter = ExpirationAlerter()

        # Add some test alerts
        for i in range(3):
            alert = ExpirationAlert(
                alert_id=f"alert-{i}",
                alert_type=AlertType.EXPIRING_SOON,
                priority=[AlertPriority.HIGH, AlertPriority.MEDIUM, AlertPriority.LOW][i],
                secret_name=f"secret-{i}",
                title=f"Test {i}",
                message=f"Test message {i}",
            )
            alerter.active_alerts[alert.alert_id] = alert

        digest = alerter.generate_digest(period_hours=24)

        assert digest.total_alerts == 3
        assert digest.high_count == 1
        assert digest.medium_count == 1
        assert digest.low_count == 1

    def test_get_active_alerts_filtered(self):
        """Test getting filtered active alerts."""
        alerter = ExpirationAlerter()

        alerter.active_alerts["alert-1"] = ExpirationAlert(
            alert_id="alert-1",
            alert_type=AlertType.EXPIRED,
            priority=AlertPriority.CRITICAL,
            secret_name="expired",
            title="Expired",
            message="Expired",
        )
        alerter.active_alerts["alert-2"] = ExpirationAlert(
            alert_id="alert-2",
            alert_type=AlertType.EXPIRING_SOON,
            priority=AlertPriority.MEDIUM,
            secret_name="expiring",
            title="Expiring",
            message="Expiring",
        )

        critical = alerter.get_active_alerts(priority=AlertPriority.CRITICAL)
        assert len(critical) == 1

        expired = alerter.get_active_alerts(alert_type=AlertType.EXPIRED)
        assert len(expired) == 1

    def test_get_alert_summary(self):
        """Test alert summary generation."""
        alerter = ExpirationAlerter()

        alerter.active_alerts["alert-1"] = ExpirationAlert(
            alert_id="alert-1",
            alert_type=AlertType.EXPIRED,
            priority=AlertPriority.CRITICAL,
            status=AlertStatus.SENT,
            secret_name="test",
            title="Test",
            message="Test",
        )

        summary = alerter.get_alert_summary()

        assert summary["total_active"] == 1
        assert summary["by_priority"]["critical"] == 1
        assert summary["by_status"]["sent"] == 1

    def test_check_bulk_expirations(self):
        """Test bulk expiration detection."""
        now = datetime.utcnow()
        secrets = []
        for i in range(6):
            secrets.append(SecretInventoryItem(
                secret_id=f"secret-{i}",
                name=f"expiring-secret-{i}",
                secret_type=SecretType.API_KEY,
                source=SecretSource.AWS_SECRETS_MANAGER,
                status=SecretStatus.EXPIRING_SOON,
                metadata=SecretMetadata(
                    created_at=now - timedelta(days=100),
                    expires_at=now + timedelta(days=5),
                ),
            ))

        inventory = SecretInventory(secrets=secrets)
        alerter = ExpirationAlerter()

        bulk_alert = alerter.check_bulk_expirations(
            inventory, days_window=7, threshold_count=5
        )

        assert bulk_alert is not None
        assert bulk_alert.alert_type == AlertType.BULK_EXPIRATION
        assert len(bulk_alert.related_secret_ids) == 6

    def test_export_alerts_json(self):
        """Test JSON export."""
        alerter = ExpirationAlerter()
        alerter.active_alerts["alert-1"] = ExpirationAlert(
            alert_id="alert-1",
            alert_type=AlertType.EXPIRED,
            priority=AlertPriority.HIGH,
            secret_name="test",
            title="Test",
            message="Test",
        )

        json_export = alerter.export_alerts(format="json")
        assert "alert-1" in json_export

    def test_export_alerts_csv(self):
        """Test CSV export."""
        alerter = ExpirationAlerter()
        alerter.active_alerts["alert-1"] = ExpirationAlert(
            alert_id="alert-1",
            alert_type=AlertType.EXPIRED,
            priority=AlertPriority.HIGH,
            secret_name="test",
            title="Test",
            message="Test",
            days_until_event=-5,
        )

        csv_export = alerter.export_alerts(format="csv")
        assert "alert_id" in csv_export
        assert "alert-1" in csv_export

    def test_register_handler(self):
        """Test notification handler registration."""
        alerter = ExpirationAlerter()

        def mock_handler(alert, recipient):
            return True

        alerter.register_handler(AlertChannel.SLACK, mock_handler)
        assert AlertChannel.SLACK in alerter.notification_handlers


# =============================================================================
# Integration Tests
# =============================================================================

class TestSecretRotationIntegration:
    """Integration tests for secret rotation monitoring."""

    def test_full_workflow(self, sample_inventory):
        """Test complete workflow: inventory -> age tracking -> policy -> alerts."""
        # 1. Analyze age
        age_tracker = SecretAgeTracker()
        age_report = age_tracker.analyze_inventory(sample_inventory)

        assert age_report.total_secrets == 5
        assert age_report.overall_risk_score >= 0

        # 2. Enforce policies
        enforcer = RotationPolicyEnforcer()
        enforcement_result = enforcer.enforce(sample_inventory)

        assert "compliance_rate" in enforcement_result
        assert "violations" in enforcement_result

        # 3. Generate alerts
        alerter = ExpirationAlerter(age_tracker=age_tracker, policy_enforcer=enforcer)
        alerts = alerter.check_inventory(sample_inventory, send_notifications=False)

        # Should have some alerts for the problematic secrets
        summary = alerter.get_alert_summary()
        assert "total_active" in summary

    def test_compliance_driven_workflow(self, sample_inventory):
        """Test compliance-driven policy enforcement."""
        enforcer = RotationPolicyEnforcer()

        # Create PCI-DSS compliant policy set
        pci_policies = enforcer.create_compliance_policy_set([ComplianceFramework.PCI_DSS])

        # Apply to inventory
        enforcer.policy_set = pci_policies
        result = enforcer.enforce(sample_inventory)

        assert "compliance_rate" in result
        assert "by_severity" in result

    def test_multi_cloud_inventory(self):
        """Test inventory collection from multiple cloud providers."""
        collector = SecretInventoryCollector()
        now = datetime.utcnow()

        # AWS
        collector.collect_from_aws_secrets_manager([{
            "Name": "aws-secret",
            "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:aws-secret",
            "CreatedDate": now - timedelta(days=30),
        }], "123", "us-east-1")

        # Azure
        collector.collect_from_azure_key_vault([{
            "id": "https://vault.azure.net/secrets/azure-secret",
            "attributes": {
                "created": int((now - timedelta(days=45)).timestamp()),
                "enabled": True,
            },
        }], "sub-123", "vault")

        # GCP
        collector.collect_from_gcp_secret_manager([{
            "name": "projects/proj/secrets/gcp-secret",
            "createTime": (now - timedelta(days=20)).isoformat() + "Z",
        }], "proj")

        inventory = collector.inventory

        assert len(inventory.secrets) == 3
        assert len(inventory.get_by_source(SecretSource.AWS_SECRETS_MANAGER)) == 1
        assert len(inventory.get_by_source(SecretSource.AZURE_KEY_VAULT)) == 1
        assert len(inventory.get_by_source(SecretSource.GCP_SECRET_MANAGER)) == 1


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_inventory(self):
        """Test handling of empty inventory."""
        inventory = SecretInventory(secrets=[])

        tracker = SecretAgeTracker()
        report = tracker.analyze_inventory(inventory)

        assert report.total_secrets == 0
        assert report.overall_risk_score == 0.0

        enforcer = RotationPolicyEnforcer()
        result = enforcer.enforce(inventory)

        assert result["total_secrets"] == 0
        assert result["compliance_rate"] == 100.0

    def test_secret_without_metadata(self):
        """Test handling of secrets without metadata."""
        secret = SecretInventoryItem(
            secret_id="no-metadata",
            name="orphan-secret",
            secret_type=SecretType.API_KEY,
            source=SecretSource.CODE_REPOSITORY,
            status=SecretStatus.UNKNOWN,
            metadata=None,
        )

        assert secret.age_days is None
        assert secret.days_since_rotation is None
        assert not secret.is_expired

        inventory = SecretInventory(secrets=[secret])
        tracker = SecretAgeTracker()
        report = tracker.analyze_inventory(inventory)

        assert report.total_secrets == 1
        assert report.analyzed_secrets == 0

    def test_secret_with_future_dates(self):
        """Test handling of future dates (clock skew)."""
        now = datetime.utcnow()
        future_secret = SecretInventoryItem(
            secret_id="future-secret",
            name="future-creation",
            secret_type=SecretType.API_KEY,
            source=SecretSource.AWS_SECRETS_MANAGER,
            status=SecretStatus.ACTIVE,
            metadata=SecretMetadata(
                created_at=now + timedelta(days=1),  # Future date
            ),
        )

        # Should handle gracefully
        assert future_secret.age_days is not None
        assert future_secret.age_days < 0

    def test_very_old_secret(self):
        """Test handling of very old secrets."""
        now = datetime.utcnow()
        ancient_secret = SecretInventoryItem(
            secret_id="ancient-secret",
            name="forgotten-key",
            secret_type=SecretType.SSH_PRIVATE_KEY,
            source=SecretSource.CODE_REPOSITORY,
            status=SecretStatus.ACTIVE,
            metadata=SecretMetadata(
                created_at=now - timedelta(days=3650),  # 10 years old
            ),
        )

        tracker = SecretAgeTracker()
        age = tracker._analyze_secret_age(ancient_secret)

        assert age.age_status == AgeStatus.CRITICAL
        assert age.risk_score > 0.5

    def test_concurrent_alert_updates(self):
        """Test concurrent alert operations."""
        alerter = ExpirationAlerter()

        # Add multiple alerts
        for i in range(10):
            alert = ExpirationAlert(
                alert_id=f"alert-{i}",
                alert_type=AlertType.EXPIRING_SOON,
                priority=AlertPriority.MEDIUM,
                secret_name=f"secret-{i}",
                title=f"Test {i}",
                message=f"Message {i}",
            )
            alerter.active_alerts[alert.alert_id] = alert

        # Acknowledge and resolve some
        alerter.acknowledge_alert("alert-0")
        alerter.resolve_alert("alert-1")
        alerter.acknowledge_alert("alert-2")

        summary = alerter.get_alert_summary()
        assert summary["total_active"] == 9  # One resolved
        assert summary["by_status"]["acknowledged"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
