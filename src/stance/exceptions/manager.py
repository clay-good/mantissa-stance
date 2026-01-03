"""
Exception manager for Mantissa Stance.

High-level management of policy exceptions and suppressions.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone, timedelta
from typing import TYPE_CHECKING

from stance.exceptions.models import (
    PolicyException,
    ExceptionType,
    ExceptionScope,
    ExceptionStatus,
    ExceptionResult,
)
from stance.exceptions.matcher import ExceptionMatcher
from stance.exceptions.store import ExceptionStore, get_exception_store

if TYPE_CHECKING:
    from stance.models import Finding, Asset, FindingCollection


class ExceptionManager:
    """
    High-level manager for policy exceptions.

    Provides a unified interface for creating, managing, and
    applying policy exceptions to findings.
    """

    def __init__(self, store: ExceptionStore | None = None):
        """
        Initialize the manager.

        Args:
            store: Exception store to use
        """
        self._store = store or get_exception_store()
        self._lock = threading.RLock()
        self._matcher: ExceptionMatcher | None = None

    @property
    def store(self) -> ExceptionStore:
        """Get the exception store."""
        return self._store

    def _get_matcher(self) -> ExceptionMatcher:
        """Get or create the exception matcher."""
        with self._lock:
            if self._matcher is None:
                exceptions = self._store.get_active()
                self._matcher = ExceptionMatcher(exceptions)
            return self._matcher

    def _invalidate_matcher(self) -> None:
        """Invalidate the cached matcher."""
        with self._lock:
            self._matcher = None

    # Exception Creation

    def create_suppression(
        self,
        scope: ExceptionScope,
        reason: str,
        created_by: str,
        policy_id: str | None = None,
        asset_id: str | None = None,
        finding_id: str | None = None,
        resource_type: str | None = None,
        account_id: str | None = None,
        tag_key: str | None = None,
        tag_value: str | None = None,
        conditions: dict | None = None,
        jira_ticket: str | None = None,
    ) -> PolicyException:
        """
        Create a permanent suppression.

        Args:
            scope: Scope of the exception
            reason: Reason for suppression
            created_by: Who created it
            policy_id: Target policy
            asset_id: Target asset
            finding_id: Target finding
            resource_type: Target resource type
            account_id: Target account
            tag_key: Tag key to match
            tag_value: Tag value to match
            conditions: Additional conditions
            jira_ticket: Associated Jira ticket

        Returns:
            Created PolicyException
        """
        exception = PolicyException(
            exception_type=ExceptionType.SUPPRESSION,
            scope=scope,
            status=ExceptionStatus.APPROVED,
            reason=reason,
            created_by=created_by,
            policy_id=policy_id,
            asset_id=asset_id,
            finding_id=finding_id,
            resource_type=resource_type,
            account_id=account_id,
            tag_key=tag_key,
            tag_value=tag_value,
            conditions=conditions or {},
            jira_ticket=jira_ticket,
        )

        self._store.save(exception)
        self._invalidate_matcher()
        return exception

    def create_temporary_exception(
        self,
        scope: ExceptionScope,
        reason: str,
        created_by: str,
        days: int = 30,
        policy_id: str | None = None,
        asset_id: str | None = None,
        finding_id: str | None = None,
        resource_type: str | None = None,
        conditions: dict | None = None,
        jira_ticket: str | None = None,
    ) -> PolicyException:
        """
        Create a temporary (time-limited) exception.

        Args:
            scope: Scope of the exception
            reason: Reason for exception
            created_by: Who created it
            days: Number of days until expiry
            policy_id: Target policy
            asset_id: Target asset
            finding_id: Target finding
            resource_type: Target resource type
            conditions: Additional conditions
            jira_ticket: Associated Jira ticket

        Returns:
            Created PolicyException
        """
        expires_at = datetime.now(timezone.utc) + timedelta(days=days)

        exception = PolicyException(
            exception_type=ExceptionType.TEMPORARY,
            scope=scope,
            status=ExceptionStatus.APPROVED,
            reason=reason,
            created_by=created_by,
            expires_at=expires_at,
            policy_id=policy_id,
            asset_id=asset_id,
            finding_id=finding_id,
            resource_type=resource_type,
            conditions=conditions or {},
            jira_ticket=jira_ticket,
        )

        self._store.save(exception)
        self._invalidate_matcher()
        return exception

    def mark_false_positive(
        self,
        finding_id: str,
        reason: str,
        created_by: str,
        jira_ticket: str | None = None,
    ) -> PolicyException:
        """
        Mark a finding as a false positive.

        Args:
            finding_id: Finding ID
            reason: Reason it's a false positive
            created_by: Who marked it
            jira_ticket: Associated Jira ticket

        Returns:
            Created PolicyException
        """
        exception = PolicyException(
            exception_type=ExceptionType.FALSE_POSITIVE,
            scope=ExceptionScope.FINDING,
            status=ExceptionStatus.APPROVED,
            reason=reason,
            created_by=created_by,
            finding_id=finding_id,
            jira_ticket=jira_ticket,
        )

        self._store.save(exception)
        self._invalidate_matcher()
        return exception

    def accept_risk(
        self,
        scope: ExceptionScope,
        reason: str,
        created_by: str,
        approved_by: str,
        policy_id: str | None = None,
        asset_id: str | None = None,
        resource_type: str | None = None,
        account_id: str | None = None,
        expires_days: int | None = 365,
        jira_ticket: str | None = None,
        notes: str = "",
    ) -> PolicyException:
        """
        Formally accept a risk.

        Args:
            scope: Scope of risk acceptance
            reason: Reason for accepting risk
            created_by: Who created the request
            approved_by: Who approved the risk
            policy_id: Target policy
            asset_id: Target asset
            resource_type: Target resource type
            account_id: Target account
            expires_days: Days until needs review (None for permanent)
            jira_ticket: Associated Jira ticket
            notes: Additional notes

        Returns:
            Created PolicyException
        """
        expires_at = None
        if expires_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

        exception = PolicyException(
            exception_type=ExceptionType.RISK_ACCEPTED,
            scope=scope,
            status=ExceptionStatus.APPROVED,
            reason=reason,
            created_by=created_by,
            approved_by=approved_by,
            expires_at=expires_at,
            policy_id=policy_id,
            asset_id=asset_id,
            resource_type=resource_type,
            account_id=account_id,
            jira_ticket=jira_ticket,
            notes=notes,
        )

        self._store.save(exception)
        self._invalidate_matcher()
        return exception

    def add_compensating_control(
        self,
        scope: ExceptionScope,
        reason: str,
        created_by: str,
        control_description: str,
        policy_id: str | None = None,
        asset_id: str | None = None,
        resource_type: str | None = None,
        jira_ticket: str | None = None,
    ) -> PolicyException:
        """
        Document a compensating control.

        Args:
            scope: Scope of the control
            reason: Why the control is sufficient
            created_by: Who documented it
            control_description: Description of the compensating control
            policy_id: Target policy
            asset_id: Target asset
            resource_type: Target resource type
            jira_ticket: Associated Jira ticket

        Returns:
            Created PolicyException
        """
        exception = PolicyException(
            exception_type=ExceptionType.COMPENSATING_CONTROL,
            scope=scope,
            status=ExceptionStatus.APPROVED,
            reason=reason,
            created_by=created_by,
            policy_id=policy_id,
            asset_id=asset_id,
            resource_type=resource_type,
            jira_ticket=jira_ticket,
            notes=control_description,
        )

        self._store.save(exception)
        self._invalidate_matcher()
        return exception

    # Exception Management

    def get_exception(self, exception_id: str) -> PolicyException | None:
        """Get an exception by ID."""
        return self._store.get(exception_id)

    def update_exception(self, exception: PolicyException) -> bool:
        """Update an exception."""
        result = self._store.save(exception)
        if result:
            self._invalidate_matcher()
        return result

    def revoke_exception(
        self,
        exception_id: str,
        reason: str = "",
    ) -> bool:
        """
        Revoke an exception.

        Args:
            exception_id: Exception to revoke
            reason: Reason for revocation

        Returns:
            True if revoked
        """
        exception = self._store.get(exception_id)
        if not exception:
            return False

        exception.status = ExceptionStatus.REVOKED
        if reason:
            exception.notes = f"{exception.notes}\nRevoked: {reason}".strip()

        self._store.save(exception)
        self._invalidate_matcher()
        return True

    def delete_exception(self, exception_id: str) -> bool:
        """Delete an exception permanently."""
        result = self._store.delete(exception_id)
        if result:
            self._invalidate_matcher()
        return result

    def list_exceptions(
        self,
        status: ExceptionStatus | None = None,
        exception_type: ExceptionType | None = None,
        scope: ExceptionScope | None = None,
        include_expired: bool = False,
    ) -> list[PolicyException]:
        """List exceptions with filters."""
        return self._store.list_all(
            status=status,
            exception_type=exception_type,
            scope=scope,
            include_expired=include_expired,
        )

    def get_active_exceptions(self) -> list[PolicyException]:
        """Get all active exceptions."""
        return self._store.get_active()

    def get_exceptions_for_asset(self, asset_id: str) -> list[PolicyException]:
        """Get exceptions for an asset."""
        return self._store.find_by_asset(asset_id)

    def get_exceptions_for_policy(self, policy_id: str) -> list[PolicyException]:
        """Get exceptions for a policy."""
        return self._store.find_by_policy(policy_id)

    def expire_outdated(self) -> int:
        """Mark expired exceptions as expired."""
        count = self._store.expire_outdated()
        if count > 0:
            self._invalidate_matcher()
        return count

    # Exception Matching

    def check_finding(
        self,
        finding: "Finding",
        asset: "Asset | None" = None,
    ) -> ExceptionResult:
        """
        Check if a finding is excepted.

        Args:
            finding: Finding to check
            asset: Optional asset for additional matching

        Returns:
            ExceptionResult with match information
        """
        matcher = self._get_matcher()
        return matcher.check_finding(finding, asset)

    def apply_exceptions(
        self,
        findings: "FindingCollection",
        assets: dict[str, "Asset"] | None = None,
    ) -> tuple["FindingCollection", list[ExceptionResult]]:
        """
        Apply exceptions to a collection of findings.

        Modifies finding statuses based on matching exceptions.

        Args:
            findings: FindingCollection to process
            assets: Optional dict of asset_id -> Asset for matching

        Returns:
            Tuple of (modified FindingCollection, list of ExceptionResults)
        """
        from stance.models import FindingStatus

        assets = assets or {}
        results: list[ExceptionResult] = []
        modified_findings = []

        for finding in findings:
            asset = assets.get(finding.asset_id)
            result = self.check_finding(finding, asset)
            results.append(result)

            if result.is_excepted and result.applied_exception:
                # Update finding status based on exception type
                exc_type = result.applied_exception.exception_type

                if exc_type == ExceptionType.FALSE_POSITIVE:
                    finding.status = FindingStatus.FALSE_POSITIVE
                else:
                    finding.status = FindingStatus.SUPPRESSED

            modified_findings.append(finding)

        from stance.models import FindingCollection
        return FindingCollection(modified_findings), results


# Global manager instance
_global_manager: ExceptionManager | None = None
_manager_lock = threading.Lock()


def get_exception_manager() -> ExceptionManager:
    """
    Get the global exception manager.

    Returns:
        ExceptionManager instance
    """
    global _global_manager
    with _manager_lock:
        if _global_manager is None:
            _global_manager = ExceptionManager()
        return _global_manager
