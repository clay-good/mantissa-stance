"""
Models for Policy Exceptions and Suppressions.

Defines the data structures for managing policy exceptions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid


class ExceptionType(Enum):
    """Types of policy exceptions."""

    SUPPRESSION = "suppression"  # Permanent suppression
    TEMPORARY = "temporary"  # Time-limited exception
    FALSE_POSITIVE = "false_positive"  # Marked as false positive
    RISK_ACCEPTED = "risk_accepted"  # Risk formally accepted
    COMPENSATING_CONTROL = "compensating_control"  # Alternative control in place


class ExceptionScope(Enum):
    """Scope of the exception."""

    FINDING = "finding"  # Specific finding ID
    ASSET = "asset"  # Specific asset
    POLICY = "policy"  # Specific policy
    ASSET_POLICY = "asset_policy"  # Asset + policy combination
    RESOURCE_TYPE = "resource_type"  # All assets of a type
    TAG = "tag"  # Assets with specific tag
    ACCOUNT = "account"  # Entire account
    GLOBAL = "global"  # Global exception


class ExceptionStatus(Enum):
    """Status of an exception."""

    PENDING = "pending"  # Awaiting approval
    APPROVED = "approved"  # Approved and active
    REJECTED = "rejected"  # Rejected
    EXPIRED = "expired"  # Time limit exceeded
    REVOKED = "revoked"  # Manually revoked


@dataclass
class PolicyException:
    """
    A policy exception or suppression rule.

    Attributes:
        id: Unique exception identifier
        exception_type: Type of exception
        scope: Scope of the exception
        status: Current status
        reason: Human-readable reason
        created_by: Who created the exception
        approved_by: Who approved (if required)
        created_at: When created
        expires_at: When it expires (if temporary)
        policy_id: Target policy ID (if applicable)
        asset_id: Target asset ID (if applicable)
        finding_id: Target finding ID (if applicable)
        resource_type: Target resource type (if applicable)
        account_id: Target account ID (if applicable)
        tag_key: Tag key to match (if scope is TAG)
        tag_value: Tag value to match (if scope is TAG)
        conditions: Additional matching conditions
        metadata: Additional metadata
        jira_ticket: Associated Jira ticket
        notes: Additional notes
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    exception_type: ExceptionType = ExceptionType.SUPPRESSION
    scope: ExceptionScope = ExceptionScope.FINDING
    status: ExceptionStatus = ExceptionStatus.APPROVED
    reason: str = ""
    created_by: str = ""
    approved_by: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    policy_id: str | None = None
    asset_id: str | None = None
    finding_id: str | None = None
    resource_type: str | None = None
    account_id: str | None = None
    tag_key: str | None = None
    tag_value: str | None = None
    conditions: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    jira_ticket: str | None = None
    notes: str = ""

    @property
    def is_active(self) -> bool:
        """Check if exception is currently active."""
        if self.status != ExceptionStatus.APPROVED:
            return False
        if self.expires_at:
            return datetime.now(timezone.utc) < self.expires_at
        return True

    @property
    def is_expired(self) -> bool:
        """Check if exception has expired."""
        if self.expires_at:
            return datetime.now(timezone.utc) >= self.expires_at
        return False

    @property
    def days_until_expiry(self) -> int | None:
        """Get days until expiry."""
        if not self.expires_at:
            return None
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0, delta.days)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "exception_type": self.exception_type.value,
            "scope": self.scope.value,
            "status": self.status.value,
            "reason": self.reason,
            "created_by": self.created_by,
            "approved_by": self.approved_by,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "policy_id": self.policy_id,
            "asset_id": self.asset_id,
            "finding_id": self.finding_id,
            "resource_type": self.resource_type,
            "account_id": self.account_id,
            "tag_key": self.tag_key,
            "tag_value": self.tag_value,
            "conditions": self.conditions,
            "metadata": self.metadata,
            "jira_ticket": self.jira_ticket,
            "notes": self.notes,
            "is_active": self.is_active,
            "is_expired": self.is_expired,
            "days_until_expiry": self.days_until_expiry,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyException":
        """Create from dictionary."""
        # Parse datetime fields
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        elif created_at is None:
            created_at = datetime.now(timezone.utc)

        expires_at = data.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            exception_type=ExceptionType(data.get("exception_type", "suppression")),
            scope=ExceptionScope(data.get("scope", "finding")),
            status=ExceptionStatus(data.get("status", "approved")),
            reason=data.get("reason", ""),
            created_by=data.get("created_by", ""),
            approved_by=data.get("approved_by"),
            created_at=created_at,
            expires_at=expires_at,
            policy_id=data.get("policy_id"),
            asset_id=data.get("asset_id"),
            finding_id=data.get("finding_id"),
            resource_type=data.get("resource_type"),
            account_id=data.get("account_id"),
            tag_key=data.get("tag_key"),
            tag_value=data.get("tag_value"),
            conditions=data.get("conditions", {}),
            metadata=data.get("metadata", {}),
            jira_ticket=data.get("jira_ticket"),
            notes=data.get("notes", ""),
        )


@dataclass
class ExceptionMatch:
    """
    Result of matching a finding against an exception.

    Attributes:
        exception: The matching exception
        match_reason: Why the exception matched
        match_score: Confidence score (0-100)
    """

    exception: PolicyException
    match_reason: str = ""
    match_score: int = 100

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "exception_id": self.exception.id,
            "exception_type": self.exception.exception_type.value,
            "match_reason": self.match_reason,
            "match_score": self.match_score,
        }


@dataclass
class ExceptionResult:
    """
    Result of checking exceptions for a finding.

    Attributes:
        finding_id: The finding that was checked
        is_excepted: Whether finding is excepted
        matches: List of matching exceptions
        applied_exception: The exception that was applied (highest priority)
    """

    finding_id: str
    is_excepted: bool = False
    matches: list[ExceptionMatch] = field(default_factory=list)
    applied_exception: PolicyException | None = None

    @property
    def exception_type(self) -> ExceptionType | None:
        """Get the applied exception type."""
        if self.applied_exception:
            return self.applied_exception.exception_type
        return None

    @property
    def exception_reason(self) -> str:
        """Get the applied exception reason."""
        if self.applied_exception:
            return self.applied_exception.reason
        return ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "is_excepted": self.is_excepted,
            "exception_type": self.exception_type.value if self.exception_type else None,
            "exception_reason": self.exception_reason,
            "match_count": len(self.matches),
            "applied_exception_id": (
                self.applied_exception.id if self.applied_exception else None
            ),
        }
