"""
Exceptions handlers for the Stance web API.

This module handles all /api/exceptions/* endpoints for managing
security exception requests (suppressions, false positives, risk acceptance).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class ExceptionsHandler(RoutedHandler):
    """
    Handler for exceptions API endpoints.

    Handles:
    - Exception listing and details
    - Exception creation and management
    - Suppression, false positive, and risk acceptance workflows
    """

    base_path = "/api/exceptions/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("list")
    def exceptions_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List all exceptions.

        Query params:
            status: Filter by status (pending, approved, rejected, expired, revoked)
            type: Filter by type (suppression, temporary, false_positive, risk_accepted)
            scope: Filter by scope (finding, asset, policy)
            include_expired: Include expired exceptions (true/false)
            active: Show only active exceptions (true/false)
        """
        status_filter = self.get_param(params, "status", "")
        type_filter = self.get_param(params, "type", "")
        scope_filter = self.get_param(params, "scope", "")
        include_expired = self.get_param_bool(params, "include_expired", False)
        active_only = self.get_param_bool(params, "active", False)

        exceptions = self._get_sample_exceptions()

        if status_filter:
            exceptions = [e for e in exceptions if e.get("status") == status_filter]

        if type_filter:
            exceptions = [e for e in exceptions if e.get("exception_type") == type_filter]

        if scope_filter:
            exceptions = [e for e in exceptions if e.get("scope") == scope_filter]

        if active_only:
            exceptions = [e for e in exceptions if e.get("is_active", False)]

        if not include_expired:
            exceptions = [e for e in exceptions if not e.get("is_expired", False)]

        return HandlerResponse.success({
            "exceptions": exceptions,
            "total": len(exceptions),
            "active_count": sum(1 for e in exceptions if e.get("is_active", False)),
        })

    @route("show")
    def exceptions_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Show exception details.

        Query params:
            id: Exception ID (required)
        """
        exception_id = self.get_param(params, "id", "")

        if not exception_id:
            return HandlerResponse.error("Exception ID is required", HttpStatus.BAD_REQUEST)

        exceptions = self._get_sample_exceptions()
        for exc in exceptions:
            if exc.get("id", "").startswith(exception_id):
                return HandlerResponse.success(exc)

        return HandlerResponse.not_found("Exception")

    @route("types")
    def exceptions_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List all exception types."""
        types = [
            {
                "value": "suppression",
                "name": "Suppression",
                "description": "Suppress finding from alerts and reports",
                "requires_approval": False,
                "max_duration_days": None,
            },
            {
                "value": "temporary",
                "name": "Temporary Exception",
                "description": "Temporary exemption with expiration date",
                "requires_approval": True,
                "max_duration_days": 90,
            },
            {
                "value": "false_positive",
                "name": "False Positive",
                "description": "Mark finding as incorrectly detected",
                "requires_approval": False,
                "max_duration_days": None,
            },
            {
                "value": "risk_accepted",
                "name": "Risk Accepted",
                "description": "Formal risk acceptance with approval",
                "requires_approval": True,
                "max_duration_days": 365,
            },
            {
                "value": "compensating_control",
                "name": "Compensating Control",
                "description": "Exception due to compensating control",
                "requires_approval": True,
                "max_duration_days": 365,
            },
        ]

        return HandlerResponse.success({
            "types": types,
            "total": len(types),
        })

    @route("scopes")
    def exceptions_scopes(self, params: dict, body: dict | None) -> HandlerResponse:
        """List all exception scopes."""
        scopes = [
            {
                "value": "finding",
                "name": "Finding",
                "description": "Exception applies to a specific finding",
                "example": "finding-abc123",
            },
            {
                "value": "asset",
                "name": "Asset",
                "description": "Exception applies to all findings on an asset",
                "example": "arn:aws:s3:::my-bucket",
            },
            {
                "value": "policy",
                "name": "Policy",
                "description": "Exception applies to a specific policy",
                "example": "aws-s3-001",
            },
            {
                "value": "resource_type",
                "name": "Resource Type",
                "description": "Exception applies to all resources of a type",
                "example": "aws_s3_bucket",
            },
            {
                "value": "account",
                "name": "Account",
                "description": "Exception applies to all findings in an account",
                "example": "123456789012",
            },
            {
                "value": "global",
                "name": "Global",
                "description": "Exception applies across all accounts",
                "example": "global",
            },
        ]

        return HandlerResponse.success({
            "scopes": scopes,
            "total": len(scopes),
        })

    @route("status")
    def exceptions_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get exceptions module status."""
        exceptions = self._get_sample_exceptions()

        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for exc in exceptions:
            t = exc.get("exception_type", "unknown")
            s = exc.get("status", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
            by_status[s] = by_status.get(s, 0) + 1

        active_count = sum(1 for e in exceptions if e.get("is_active", False))
        expired_count = sum(1 for e in exceptions if e.get("is_expired", False))

        return HandlerResponse.success({
            "module": "exceptions",
            "version": "1.0.0",
            "status": "active",
            "total_exceptions": len(exceptions),
            "active_count": active_count,
            "expired_count": expired_count,
            "pending_approval": by_status.get("pending", 0),
            "by_type": by_type,
            "by_status": by_status,
            "capabilities": {
                "suppression": True,
                "temporary": True,
                "false_positive": True,
                "risk_accepted": True,
                "compensating_control": True,
                "approval_workflow": True,
                "expiration": True,
            },
        })

    @route("summary")
    def exceptions_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get exceptions summary."""
        exceptions = self._get_sample_exceptions()

        active_count = sum(1 for e in exceptions if e.get("is_active", False))
        expired_count = sum(1 for e in exceptions if e.get("is_expired", False))

        return HandlerResponse.success({
            "total_exceptions": len(exceptions),
            "active_count": active_count,
            "expired_count": expired_count,
            "pending_approval": 0,
        })

    # =========================================================================
    # POST-style endpoints (using GET for demo)
    # =========================================================================

    @route("create")
    def exceptions_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Create a new exception.

        Query params:
            type: Exception type
            scope: Exception scope
            reason: Reason for exception (required)
            created_by: Creator identifier
            policy: Target policy ID
            asset: Target asset ID
            finding: Target finding ID
            days: Days until expiry (for temporary)
        """
        exc_type = self.get_param(params, "type", "suppression")
        scope = self.get_param(params, "scope", "finding")
        reason = self.get_param(params, "reason", "")
        created_by = self.get_param(params, "created_by", "api")
        policy_id = self.get_param(params, "policy")
        asset_id = self.get_param(params, "asset")
        finding_id = self.get_param(params, "finding")
        days_str = self.get_param(params, "days", "")
        jira_ticket = self.get_param(params, "jira")

        if not reason:
            return HandlerResponse.error("Reason is required", HttpStatus.BAD_REQUEST)

        exc_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = None

        if days_str:
            try:
                expires_at = (now + timedelta(days=int(days_str))).isoformat()
            except ValueError:
                return HandlerResponse.error(f"Invalid days value: {days_str}", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "success": True,
            "id": exc_id,
            "exception_type": exc_type,
            "scope": scope,
            "status": "approved",
            "reason": reason,
            "created_by": created_by,
            "created_at": now.isoformat(),
            "expires_at": expires_at,
            "policy_id": policy_id,
            "asset_id": asset_id,
            "finding_id": finding_id,
            "jira_ticket": jira_ticket,
            "is_active": True,
            "message": "Exception created successfully (demo mode)",
        }, HttpStatus.CREATED)

    @route("suppress")
    def exceptions_suppress(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a suppression exception."""
        # Add type to params
        new_params = dict(params)
        new_params["type"] = ["suppression"]
        return self.exceptions_create(new_params, body)

    @route("false-positive")
    def exceptions_false_positive(self, params: dict, body: dict | None) -> HandlerResponse:
        """Mark finding as false positive."""
        finding_id = self.get_param(params, "finding", "")
        reason = self.get_param(params, "reason", "")

        if not finding_id:
            return HandlerResponse.error("Finding ID is required", HttpStatus.BAD_REQUEST)

        if not reason:
            return HandlerResponse.error("Reason is required", HttpStatus.BAD_REQUEST)

        new_params = dict(params)
        new_params["type"] = ["false_positive"]
        new_params["scope"] = ["finding"]
        return self.exceptions_create(new_params, body)

    @route("accept-risk")
    def exceptions_accept_risk(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a risk acceptance."""
        approved_by = self.get_param(params, "approved_by", "")
        reason = self.get_param(params, "reason", "")

        if not reason:
            return HandlerResponse.error("Reason is required", HttpStatus.BAD_REQUEST)

        if not approved_by:
            return HandlerResponse.error("Approver is required (approved_by)", HttpStatus.BAD_REQUEST)

        new_params = dict(params)
        new_params["type"] = ["risk_accepted"]
        if "days" not in params or not params["days"]:
            new_params["days"] = ["365"]
        return self.exceptions_create(new_params, body)

    @route("revoke")
    def exceptions_revoke(self, params: dict, body: dict | None) -> HandlerResponse:
        """Revoke an exception."""
        exception_id = self.get_param(params, "id", "")
        reason = self.get_param(params, "reason", "")

        if not exception_id:
            return HandlerResponse.error("Exception ID is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "success": True,
            "id": exception_id,
            "status": "revoked",
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "revoke_reason": reason or "No reason provided",
            "message": "Exception revoked successfully (demo mode)",
        })

    @route("delete")
    def exceptions_delete(self, params: dict, body: dict | None) -> HandlerResponse:
        """Delete an exception."""
        exception_id = self.get_param(params, "id", "")

        if not exception_id:
            return HandlerResponse.error("Exception ID is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "success": True,
            "id": exception_id,
            "deleted": True,
            "message": "Exception deleted successfully (demo mode)",
        })

    @route("expire")
    def exceptions_expire(self, params: dict, body: dict | None) -> HandlerResponse:
        """Expire an exception immediately."""
        exception_id = self.get_param(params, "id", "")

        if not exception_id:
            return HandlerResponse.error("Exception ID is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "success": True,
            "id": exception_id,
            "status": "expired",
            "expired_at": datetime.now(timezone.utc).isoformat(),
            "message": "Exception expired successfully (demo mode)",
        })

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _get_sample_exceptions(self) -> list[dict[str, Any]]:
        """Get sample exception data."""
        now = datetime.now(timezone.utc)
        return [
            {
                "id": "exc-001-abcd-1234",
                "exception_type": "suppression",
                "scope": "finding",
                "status": "approved",
                "reason": "Legacy system, migrating next quarter",
                "finding_id": "finding-abc123",
                "policy_id": "aws-s3-001",
                "asset_id": None,
                "created_by": "security-team",
                "created_at": (now - timedelta(days=30)).isoformat(),
                "expires_at": None,
                "is_active": True,
                "is_expired": False,
            },
            {
                "id": "exc-002-efgh-5678",
                "exception_type": "risk_accepted",
                "scope": "asset",
                "status": "approved",
                "reason": "Accepted risk per CISO approval",
                "finding_id": None,
                "policy_id": None,
                "asset_id": "arn:aws:s3:::legacy-bucket",
                "created_by": "ciso@example.com",
                "approved_by": "ciso@example.com",
                "created_at": (now - timedelta(days=60)).isoformat(),
                "expires_at": (now + timedelta(days=305)).isoformat(),
                "is_active": True,
                "is_expired": False,
                "jira_ticket": "SEC-1234",
            },
            {
                "id": "exc-003-ijkl-9012",
                "exception_type": "false_positive",
                "scope": "finding",
                "status": "approved",
                "reason": "Not applicable to our environment",
                "finding_id": "finding-xyz789",
                "policy_id": "aws-iam-001",
                "asset_id": None,
                "created_by": "dev-team",
                "created_at": (now - timedelta(days=15)).isoformat(),
                "expires_at": None,
                "is_active": True,
                "is_expired": False,
            },
            {
                "id": "exc-004-mnop-3456",
                "exception_type": "temporary",
                "scope": "policy",
                "status": "approved",
                "reason": "Temporary exemption for migration",
                "finding_id": None,
                "policy_id": "aws-ec2-001",
                "asset_id": None,
                "created_by": "platform-team",
                "created_at": (now - timedelta(days=45)).isoformat(),
                "expires_at": (now + timedelta(days=45)).isoformat(),
                "is_active": True,
                "is_expired": False,
            },
            {
                "id": "exc-005-qrst-7890",
                "exception_type": "suppression",
                "scope": "finding",
                "status": "expired",
                "reason": "Old exception",
                "finding_id": "finding-old123",
                "policy_id": None,
                "asset_id": None,
                "created_by": "security-team",
                "created_at": (now - timedelta(days=120)).isoformat(),
                "expires_at": (now - timedelta(days=30)).isoformat(),
                "is_active": False,
                "is_expired": True,
            },
        ]
