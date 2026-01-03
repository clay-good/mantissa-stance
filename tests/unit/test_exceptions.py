"""
Tests for Policy Exceptions and Suppressions.

Tests exception models, matching, storage, and management.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from stance.exceptions.models import (
    ExceptionType,
    ExceptionScope,
    ExceptionStatus,
    PolicyException,
    ExceptionMatch,
    ExceptionResult,
)
from stance.exceptions.matcher import ExceptionMatcher, match_exception
from stance.exceptions.store import LocalExceptionStore
from stance.exceptions.manager import ExceptionManager


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_finding():
    """Create a mock finding for testing."""
    finding = MagicMock()
    finding.id = "finding-001"
    finding.asset_id = "arn:aws:s3:::my-bucket"
    finding.rule_id = "s3-public-access"
    finding.title = "S3 bucket is publicly accessible"
    finding.description = "The S3 bucket allows public access"
    finding.severity = MagicMock()
    finding.severity.value = "high"
    finding.status = MagicMock()
    finding.status.value = "open"
    return finding


@pytest.fixture
def mock_asset():
    """Create a mock asset for testing."""
    asset = MagicMock()
    asset.id = "arn:aws:s3:::my-bucket"
    asset.resource_type = "aws_s3_bucket"
    asset.account_id = "123456789012"
    asset.tags = {
        "Environment": "production",
        "Team": "security",
    }
    return asset


@pytest.fixture
def temp_store():
    """Create a temporary exception store."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "exceptions.json"
        store = LocalExceptionStore(store_path)
        yield store
        store.clear()


@pytest.fixture
def manager(temp_store):
    """Create an exception manager with temp store."""
    return ExceptionManager(store=temp_store)


# =============================================================================
# ExceptionType Tests
# =============================================================================


class TestExceptionType:
    """Tests for ExceptionType enum."""

    def test_all_types_exist(self):
        """Test all exception types are defined."""
        assert ExceptionType.SUPPRESSION.value == "suppression"
        assert ExceptionType.TEMPORARY.value == "temporary"
        assert ExceptionType.FALSE_POSITIVE.value == "false_positive"
        assert ExceptionType.RISK_ACCEPTED.value == "risk_accepted"
        assert ExceptionType.COMPENSATING_CONTROL.value == "compensating_control"

    def test_type_count(self):
        """Test expected number of types."""
        assert len(ExceptionType) == 5


# =============================================================================
# ExceptionScope Tests
# =============================================================================


class TestExceptionScope:
    """Tests for ExceptionScope enum."""

    def test_all_scopes_exist(self):
        """Test all scopes are defined."""
        assert ExceptionScope.FINDING.value == "finding"
        assert ExceptionScope.ASSET.value == "asset"
        assert ExceptionScope.POLICY.value == "policy"
        assert ExceptionScope.ASSET_POLICY.value == "asset_policy"
        assert ExceptionScope.RESOURCE_TYPE.value == "resource_type"
        assert ExceptionScope.TAG.value == "tag"
        assert ExceptionScope.ACCOUNT.value == "account"
        assert ExceptionScope.GLOBAL.value == "global"

    def test_scope_count(self):
        """Test expected number of scopes."""
        assert len(ExceptionScope) == 8


# =============================================================================
# ExceptionStatus Tests
# =============================================================================


class TestExceptionStatus:
    """Tests for ExceptionStatus enum."""

    def test_all_statuses_exist(self):
        """Test all statuses are defined."""
        assert ExceptionStatus.PENDING.value == "pending"
        assert ExceptionStatus.APPROVED.value == "approved"
        assert ExceptionStatus.REJECTED.value == "rejected"
        assert ExceptionStatus.EXPIRED.value == "expired"
        assert ExceptionStatus.REVOKED.value == "revoked"


# =============================================================================
# PolicyException Tests
# =============================================================================


class TestPolicyException:
    """Tests for PolicyException dataclass."""

    def test_default_values(self):
        """Test default exception values."""
        exc = PolicyException()
        assert exc.id is not None
        assert exc.exception_type == ExceptionType.SUPPRESSION
        assert exc.scope == ExceptionScope.FINDING
        assert exc.status == ExceptionStatus.APPROVED
        assert exc.is_active is True
        assert exc.is_expired is False

    def test_is_active_approved(self):
        """Test is_active for approved exception."""
        exc = PolicyException(status=ExceptionStatus.APPROVED)
        assert exc.is_active is True

    def test_is_active_not_approved(self):
        """Test is_active for non-approved exception."""
        exc = PolicyException(status=ExceptionStatus.PENDING)
        assert exc.is_active is False

        exc = PolicyException(status=ExceptionStatus.REVOKED)
        assert exc.is_active is False

    def test_is_active_expired(self):
        """Test is_active for expired exception."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        exc = PolicyException(
            status=ExceptionStatus.APPROVED,
            expires_at=past,
        )
        assert exc.is_active is False
        assert exc.is_expired is True

    def test_is_active_not_expired(self):
        """Test is_active for non-expired exception."""
        future = datetime.now(timezone.utc) + timedelta(days=30)
        exc = PolicyException(
            status=ExceptionStatus.APPROVED,
            expires_at=future,
        )
        assert exc.is_active is True
        assert exc.is_expired is False

    def test_days_until_expiry(self):
        """Test days_until_expiry calculation."""
        future = datetime.now(timezone.utc) + timedelta(days=30)
        exc = PolicyException(expires_at=future)
        # Allow for slight timing variations
        assert exc.days_until_expiry in (29, 30)

    def test_days_until_expiry_none(self):
        """Test days_until_expiry when no expiry."""
        exc = PolicyException()
        assert exc.days_until_expiry is None

    def test_to_dict(self):
        """Test dictionary conversion."""
        exc = PolicyException(
            exception_type=ExceptionType.RISK_ACCEPTED,
            scope=ExceptionScope.ASSET,
            reason="Accepted by security team",
            asset_id="arn:aws:s3:::test-bucket",
        )
        d = exc.to_dict()

        assert d["exception_type"] == "risk_accepted"
        assert d["scope"] == "asset"
        assert d["reason"] == "Accepted by security team"
        assert d["asset_id"] == "arn:aws:s3:::test-bucket"
        assert "is_active" in d
        assert "is_expired" in d

    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "id": "exc-001",
            "exception_type": "temporary",
            "scope": "policy",
            "status": "approved",
            "reason": "Testing",
            "policy_id": "s3-public-access",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        }
        exc = PolicyException.from_dict(data)

        assert exc.id == "exc-001"
        assert exc.exception_type == ExceptionType.TEMPORARY
        assert exc.scope == ExceptionScope.POLICY
        assert exc.policy_id == "s3-public-access"
        assert exc.expires_at is not None


# =============================================================================
# ExceptionMatcher Tests
# =============================================================================


class TestExceptionMatcher:
    """Tests for ExceptionMatcher."""

    def test_empty_matcher(self, mock_finding):
        """Test matcher with no exceptions."""
        matcher = ExceptionMatcher()
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is False
        assert result.matches == []

    def test_finding_scope_match(self, mock_finding):
        """Test matching by finding ID."""
        exc = PolicyException(
            scope=ExceptionScope.FINDING,
            finding_id="finding-001",
            reason="Known issue",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is True
        assert len(result.matches) == 1
        assert result.applied_exception == exc

    def test_finding_scope_no_match(self, mock_finding):
        """Test non-matching finding ID."""
        exc = PolicyException(
            scope=ExceptionScope.FINDING,
            finding_id="different-finding",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is False

    def test_asset_scope_match(self, mock_finding):
        """Test matching by asset ID."""
        exc = PolicyException(
            scope=ExceptionScope.ASSET,
            asset_id="arn:aws:s3:::my-bucket",
            reason="Known configuration",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is True

    def test_asset_scope_wildcard(self, mock_finding):
        """Test asset matching with wildcard."""
        exc = PolicyException(
            scope=ExceptionScope.ASSET,
            asset_id="arn:aws:s3:::my-*",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is True

    def test_policy_scope_match(self, mock_finding):
        """Test matching by policy ID."""
        exc = PolicyException(
            scope=ExceptionScope.POLICY,
            policy_id="s3-public-access",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is True

    def test_asset_policy_scope_match(self, mock_finding):
        """Test matching by asset + policy combination."""
        exc = PolicyException(
            scope=ExceptionScope.ASSET_POLICY,
            asset_id="arn:aws:s3:::my-bucket",
            policy_id="s3-public-access",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is True

    def test_asset_policy_scope_partial_no_match(self, mock_finding):
        """Test asset + policy when only one matches."""
        exc = PolicyException(
            scope=ExceptionScope.ASSET_POLICY,
            asset_id="arn:aws:s3:::my-bucket",
            policy_id="different-policy",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is False

    def test_resource_type_scope_match(self, mock_finding, mock_asset):
        """Test matching by resource type."""
        exc = PolicyException(
            scope=ExceptionScope.RESOURCE_TYPE,
            resource_type="aws_s3_bucket",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding, mock_asset)

        assert result.is_excepted is True

    def test_resource_type_with_policy(self, mock_finding, mock_asset):
        """Test resource type + policy matching."""
        exc = PolicyException(
            scope=ExceptionScope.RESOURCE_TYPE,
            resource_type="aws_s3_bucket",
            policy_id="s3-public-access",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding, mock_asset)

        assert result.is_excepted is True

    def test_tag_scope_match(self, mock_finding, mock_asset):
        """Test matching by tag."""
        exc = PolicyException(
            scope=ExceptionScope.TAG,
            tag_key="Environment",
            tag_value="production",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding, mock_asset)

        assert result.is_excepted is True

    def test_tag_scope_key_only(self, mock_finding, mock_asset):
        """Test matching by tag key only."""
        exc = PolicyException(
            scope=ExceptionScope.TAG,
            tag_key="Environment",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding, mock_asset)

        assert result.is_excepted is True

    def test_account_scope_match(self, mock_finding, mock_asset):
        """Test matching by account ID."""
        exc = PolicyException(
            scope=ExceptionScope.ACCOUNT,
            account_id="123456789012",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding, mock_asset)

        assert result.is_excepted is True

    def test_global_scope_match(self, mock_finding):
        """Test global exception matches everything."""
        exc = PolicyException(
            scope=ExceptionScope.GLOBAL,
            reason="Global suppression",
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is True
        assert "Global" in result.matches[0].match_reason

    def test_inactive_exception_not_matched(self, mock_finding):
        """Test inactive exceptions are not matched."""
        exc = PolicyException(
            scope=ExceptionScope.FINDING,
            finding_id="finding-001",
            status=ExceptionStatus.REVOKED,
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is False

    def test_expired_exception_not_matched(self, mock_finding):
        """Test expired exceptions are not matched."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        exc = PolicyException(
            scope=ExceptionScope.FINDING,
            finding_id="finding-001",
            expires_at=past,
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is False

    def test_multiple_matches_priority(self, mock_finding):
        """Test multiple matches use highest priority."""
        exc1 = PolicyException(
            scope=ExceptionScope.GLOBAL,
            reason="Global",
        )
        exc2 = PolicyException(
            scope=ExceptionScope.FINDING,
            finding_id="finding-001",
            reason="Specific",
        )
        matcher = ExceptionMatcher([exc1, exc2])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is True
        assert len(result.matches) == 2
        # Finding-specific should be applied (higher score)
        assert result.applied_exception == exc2

    def test_condition_severity(self, mock_finding):
        """Test severity condition matching."""
        exc = PolicyException(
            scope=ExceptionScope.POLICY,
            policy_id="s3-public-access",
            conditions={"severity": "high"},
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is True

    def test_condition_severity_no_match(self, mock_finding):
        """Test severity condition not matching."""
        exc = PolicyException(
            scope=ExceptionScope.POLICY,
            policy_id="s3-public-access",
            conditions={"severity": "low"},
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is False

    def test_condition_title_contains(self, mock_finding):
        """Test title_contains condition."""
        exc = PolicyException(
            scope=ExceptionScope.POLICY,
            policy_id="s3-public-access",
            conditions={"title_contains": "publicly accessible"},
        )
        matcher = ExceptionMatcher([exc])
        result = matcher.check_finding(mock_finding)

        assert result.is_excepted is True

    def test_add_remove_exception(self, mock_finding):
        """Test adding and removing exceptions."""
        matcher = ExceptionMatcher()
        exc = PolicyException(
            scope=ExceptionScope.FINDING,
            finding_id="finding-001",
        )

        matcher.add_exception(exc)
        result1 = matcher.check_finding(mock_finding)
        assert result1.is_excepted is True

        matcher.remove_exception(exc.id)
        result2 = matcher.check_finding(mock_finding)
        assert result2.is_excepted is False


# =============================================================================
# LocalExceptionStore Tests
# =============================================================================


class TestLocalExceptionStore:
    """Tests for LocalExceptionStore."""

    def test_save_and_get(self, temp_store):
        """Test saving and retrieving an exception."""
        exc = PolicyException(
            id="test-001",
            scope=ExceptionScope.FINDING,
            finding_id="finding-001",
        )

        assert temp_store.save(exc) is True
        retrieved = temp_store.get("test-001")

        assert retrieved is not None
        assert retrieved.id == "test-001"
        assert retrieved.finding_id == "finding-001"

    def test_get_nonexistent(self, temp_store):
        """Test getting nonexistent exception."""
        assert temp_store.get("nonexistent") is None

    def test_delete(self, temp_store):
        """Test deleting an exception."""
        exc = PolicyException(id="test-001")
        temp_store.save(exc)

        assert temp_store.delete("test-001") is True
        assert temp_store.get("test-001") is None

    def test_delete_nonexistent(self, temp_store):
        """Test deleting nonexistent exception."""
        assert temp_store.delete("nonexistent") is False

    def test_list_all(self, temp_store):
        """Test listing all exceptions."""
        exc1 = PolicyException(id="test-001")
        exc2 = PolicyException(id="test-002")
        temp_store.save(exc1)
        temp_store.save(exc2)

        all_exc = temp_store.list_all()
        assert len(all_exc) == 2

    def test_list_by_status(self, temp_store):
        """Test listing by status."""
        exc1 = PolicyException(id="test-001", status=ExceptionStatus.APPROVED)
        exc2 = PolicyException(id="test-002", status=ExceptionStatus.PENDING)
        temp_store.save(exc1)
        temp_store.save(exc2)

        approved = temp_store.list_all(status=ExceptionStatus.APPROVED)
        assert len(approved) == 1
        assert approved[0].id == "test-001"

    def test_list_by_type(self, temp_store):
        """Test listing by exception type."""
        exc1 = PolicyException(id="test-001", exception_type=ExceptionType.SUPPRESSION)
        exc2 = PolicyException(id="test-002", exception_type=ExceptionType.FALSE_POSITIVE)
        temp_store.save(exc1)
        temp_store.save(exc2)

        suppressions = temp_store.list_all(exception_type=ExceptionType.SUPPRESSION)
        assert len(suppressions) == 1

    def test_list_excludes_expired(self, temp_store):
        """Test list excludes expired by default."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        exc1 = PolicyException(id="test-001", expires_at=past)
        exc2 = PolicyException(id="test-002")
        temp_store.save(exc1)
        temp_store.save(exc2)

        active = temp_store.list_all()
        assert len(active) == 1
        assert active[0].id == "test-002"

        all_exc = temp_store.list_all(include_expired=True)
        assert len(all_exc) == 2

    def test_get_active(self, temp_store):
        """Test getting active exceptions."""
        exc1 = PolicyException(id="test-001", status=ExceptionStatus.APPROVED)
        exc2 = PolicyException(id="test-002", status=ExceptionStatus.REVOKED)
        temp_store.save(exc1)
        temp_store.save(exc2)

        active = temp_store.get_active()
        assert len(active) == 1

    def test_find_by_asset(self, temp_store):
        """Test finding by asset ID."""
        exc1 = PolicyException(id="test-001", asset_id="asset-1")
        exc2 = PolicyException(id="test-002", asset_id="asset-2")
        temp_store.save(exc1)
        temp_store.save(exc2)

        found = temp_store.find_by_asset("asset-1")
        assert len(found) == 1
        assert found[0].id == "test-001"

    def test_find_by_policy(self, temp_store):
        """Test finding by policy ID."""
        exc1 = PolicyException(id="test-001", policy_id="policy-1")
        exc2 = PolicyException(id="test-002", policy_id="policy-2")
        temp_store.save(exc1)
        temp_store.save(exc2)

        found = temp_store.find_by_policy("policy-1")
        assert len(found) == 1

    def test_expire_outdated(self, temp_store):
        """Test marking expired exceptions."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        exc = PolicyException(
            id="test-001",
            status=ExceptionStatus.APPROVED,
            expires_at=past,
        )
        temp_store.save(exc)

        count = temp_store.expire_outdated()
        assert count == 1

        updated = temp_store.get("test-001")
        assert updated.status == ExceptionStatus.EXPIRED

    def test_persistence(self, temp_store):
        """Test persistence across instances."""
        exc = PolicyException(id="test-001", reason="Test reason")
        temp_store.save(exc)

        # Create new store pointing to same file
        new_store = LocalExceptionStore(temp_store._file_path)
        retrieved = new_store.get("test-001")

        assert retrieved is not None
        assert retrieved.reason == "Test reason"


# =============================================================================
# ExceptionManager Tests
# =============================================================================


class TestExceptionManager:
    """Tests for ExceptionManager."""

    def test_create_suppression(self, manager):
        """Test creating a suppression."""
        exc = manager.create_suppression(
            scope=ExceptionScope.FINDING,
            reason="Known issue",
            created_by="admin",
            finding_id="finding-001",
        )

        assert exc.exception_type == ExceptionType.SUPPRESSION
        assert exc.status == ExceptionStatus.APPROVED
        assert exc.finding_id == "finding-001"
        assert exc.expires_at is None

    def test_create_temporary_exception(self, manager):
        """Test creating a temporary exception."""
        exc = manager.create_temporary_exception(
            scope=ExceptionScope.ASSET,
            reason="Temporary fix",
            created_by="admin",
            days=30,
            asset_id="asset-001",
        )

        assert exc.exception_type == ExceptionType.TEMPORARY
        assert exc.expires_at is not None
        # Allow for slight timing variations
        assert exc.days_until_expiry in (29, 30)

    def test_mark_false_positive(self, manager):
        """Test marking as false positive."""
        exc = manager.mark_false_positive(
            finding_id="finding-001",
            reason="Not actually an issue",
            created_by="analyst",
        )

        assert exc.exception_type == ExceptionType.FALSE_POSITIVE
        assert exc.scope == ExceptionScope.FINDING

    def test_accept_risk(self, manager):
        """Test accepting risk."""
        exc = manager.accept_risk(
            scope=ExceptionScope.POLICY,
            reason="Accepted per security review",
            created_by="requester",
            approved_by="ciso",
            policy_id="s3-public-access",
            expires_days=365,
            jira_ticket="SEC-123",
        )

        assert exc.exception_type == ExceptionType.RISK_ACCEPTED
        assert exc.approved_by == "ciso"
        assert exc.jira_ticket == "SEC-123"

    def test_add_compensating_control(self, manager):
        """Test adding compensating control."""
        exc = manager.add_compensating_control(
            scope=ExceptionScope.RESOURCE_TYPE,
            reason="Compensated by WAF",
            created_by="security",
            control_description="WAF rules block public access",
            resource_type="aws_s3_bucket",
        )

        assert exc.exception_type == ExceptionType.COMPENSATING_CONTROL
        assert "WAF" in exc.notes

    def test_get_exception(self, manager):
        """Test getting an exception."""
        exc = manager.create_suppression(
            scope=ExceptionScope.FINDING,
            reason="Test",
            created_by="admin",
        )

        retrieved = manager.get_exception(exc.id)
        assert retrieved is not None
        assert retrieved.id == exc.id

    def test_revoke_exception(self, manager):
        """Test revoking an exception."""
        exc = manager.create_suppression(
            scope=ExceptionScope.FINDING,
            reason="Test",
            created_by="admin",
        )

        assert manager.revoke_exception(exc.id, "No longer needed") is True
        updated = manager.get_exception(exc.id)
        assert updated.status == ExceptionStatus.REVOKED

    def test_delete_exception(self, manager):
        """Test deleting an exception."""
        exc = manager.create_suppression(
            scope=ExceptionScope.FINDING,
            reason="Test",
            created_by="admin",
        )

        assert manager.delete_exception(exc.id) is True
        assert manager.get_exception(exc.id) is None

    def test_list_exceptions(self, manager):
        """Test listing exceptions."""
        manager.create_suppression(
            scope=ExceptionScope.FINDING,
            reason="Test 1",
            created_by="admin",
        )
        manager.create_temporary_exception(
            scope=ExceptionScope.ASSET,
            reason="Test 2",
            created_by="admin",
            days=30,
        )

        all_exc = manager.list_exceptions()
        assert len(all_exc) == 2

        temp_only = manager.list_exceptions(exception_type=ExceptionType.TEMPORARY)
        assert len(temp_only) == 1

    def test_check_finding(self, manager, mock_finding):
        """Test checking a finding against exceptions."""
        manager.create_suppression(
            scope=ExceptionScope.FINDING,
            reason="Known issue",
            created_by="admin",
            finding_id="finding-001",
        )

        result = manager.check_finding(mock_finding)
        assert result.is_excepted is True
        assert result.exception_reason == "Known issue"

    def test_check_finding_no_match(self, manager, mock_finding):
        """Test checking finding with no match."""
        manager.create_suppression(
            scope=ExceptionScope.FINDING,
            reason="Different finding",
            created_by="admin",
            finding_id="finding-999",
        )

        result = manager.check_finding(mock_finding)
        assert result.is_excepted is False


# =============================================================================
# Integration Tests
# =============================================================================


class TestExceptionIntegration:
    """Integration tests for exception handling."""

    def test_full_exception_workflow(self, manager, mock_finding):
        """Test full exception workflow."""
        # Create exception
        exc = manager.create_temporary_exception(
            scope=ExceptionScope.FINDING,
            reason="Temporary fix pending",
            created_by="developer",
            days=14,
            finding_id="finding-001",
            jira_ticket="INFRA-456",
        )

        # Verify it's active
        assert exc.is_active is True

        # Check finding is excepted
        result = manager.check_finding(mock_finding)
        assert result.is_excepted is True
        assert result.applied_exception.jira_ticket == "INFRA-456"

        # Revoke the exception
        manager.revoke_exception(exc.id, "Issue fixed")

        # Check finding is no longer excepted
        result2 = manager.check_finding(mock_finding)
        assert result2.is_excepted is False

    def test_exception_priority_order(self, manager, mock_finding, mock_asset):
        """Test exception priority ordering."""
        # Create multiple overlapping exceptions
        manager.create_suppression(
            scope=ExceptionScope.GLOBAL,
            reason="Global suppression",
            created_by="admin",
        )
        manager.create_suppression(
            scope=ExceptionScope.RESOURCE_TYPE,
            reason="Resource type suppression",
            created_by="admin",
            resource_type="aws_s3_bucket",
        )
        manager.create_suppression(
            scope=ExceptionScope.FINDING,
            reason="Specific finding suppression",
            created_by="admin",
            finding_id="finding-001",
        )

        # Should match the most specific one (finding)
        result = manager.check_finding(mock_finding, mock_asset)
        assert result.is_excepted is True
        assert len(result.matches) == 3
        assert result.applied_exception.reason == "Specific finding suppression"

    def test_match_exception_helper(self, mock_finding):
        """Test match_exception helper function."""
        exceptions = [
            PolicyException(
                scope=ExceptionScope.FINDING,
                finding_id="finding-001",
                reason="Test",
            )
        ]

        result = match_exception(mock_finding, exceptions)
        assert result.is_excepted is True
