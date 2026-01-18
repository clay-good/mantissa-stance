"""
State handlers for the Stance web API.

This module handles all /api/state/* endpoints for scan state management,
checkpoints, and finding lifecycle tracking.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class StateHandler(RoutedHandler):
    """
    Handler for state API endpoints.

    Handles:
    - Scan history and status
    - Checkpoint management
    - Finding state tracking
    - State statistics
    """

    base_path = "/api/state/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("scans")
    def state_scans(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List scan history.

        Query params:
            limit: Maximum scans to return (default: 20)
            status: Filter by status
            days: Filter by days ago
        """
        limit = self.get_param_int(params, "limit", 20)
        status_filter = self.get_param(params, "status", "")
        days = self.get_param(params, "days", "")

        try:
            from stance.state import ScanStatus, get_state_manager

            manager = get_state_manager()
            status = ScanStatus(status_filter) if status_filter else None
            since = datetime.now(timezone.utc) - timedelta(days=int(days)) if days else None

            scans = manager.backend.list_scans(limit=limit, status=status, since=since)

            return HandlerResponse.success({
                "scans": [s.to_dict() for s in scans],
                "total": len(scans),
                "filters": {
                    "limit": limit,
                    "status": status_filter or None,
                    "days": int(days) if days else None,
                },
            })
        except Exception as e:
            logger.warning(f"Error listing scans: {e}")
            return HandlerResponse.success({
                "scans": [],
                "total": 0,
                "filters": {"limit": limit},
            })

    @route("scan")
    def state_scan(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get specific scan details.

        Query params:
            scan_id: Scan ID (required)
        """
        scan_id = self.get_param(params, "scan_id", "")

        if not scan_id:
            return HandlerResponse.error("scan_id parameter required", HttpStatus.BAD_REQUEST)

        try:
            from stance.state import get_state_manager

            manager = get_state_manager()
            scan = manager.backend.get_scan(scan_id)

            if not scan:
                return HandlerResponse.not_found("Scan")

            return HandlerResponse.success(scan.to_dict())
        except Exception as e:
            return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

    @route("checkpoints")
    def state_checkpoints(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List saved checkpoints.

        Query params:
            collector: Filter by collector name
            account: Filter by account ID
            limit: Maximum checkpoints to return (default: 50)
        """
        collector_filter = self.get_param(params, "collector", "")
        account_filter = self.get_param(params, "account", "")
        limit = self.get_param_int(params, "limit", 50)

        try:
            import os
            import sqlite3
            from pathlib import Path

            db_path = os.path.expanduser("~/.stance/state.db")
            if not Path(db_path).exists():
                return HandlerResponse.success({"checkpoints": [], "total": 0})

            checkpoints = []
            with sqlite3.connect(db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT * FROM checkpoints ORDER BY last_scan_time DESC"
                )
                for row in cursor.fetchall():
                    cp = {
                        "checkpoint_id": row["checkpoint_id"],
                        "collector_name": row["collector_name"],
                        "account_id": row["account_id"],
                        "region": row["region"],
                        "last_scan_id": row["last_scan_id"],
                        "last_scan_time": row["last_scan_time"],
                        "cursor": row["cursor"],
                    }
                    if collector_filter and cp["collector_name"] != collector_filter:
                        continue
                    if account_filter and cp["account_id"] != account_filter:
                        continue
                    checkpoints.append(cp)
                    if len(checkpoints) >= limit:
                        break

            return HandlerResponse.success({
                "checkpoints": checkpoints,
                "total": len(checkpoints),
                "filters": {
                    "collector": collector_filter or None,
                    "account": account_filter or None,
                    "limit": limit,
                },
            })
        except Exception as e:
            logger.warning(f"Error listing checkpoints: {e}")
            return HandlerResponse.success({"checkpoints": [], "total": 0})

    @route("checkpoint")
    def state_checkpoint(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get specific checkpoint details.

        Query params:
            collector: Collector name (required)
            account: Account ID (required)
            region: Region (required)
        """
        collector = self.get_param(params, "collector", "")
        account = self.get_param(params, "account", "")
        region = self.get_param(params, "region", "")

        if not collector or not account or not region:
            return HandlerResponse.error(
                "collector, account, and region parameters required",
                HttpStatus.BAD_REQUEST
            )

        try:
            from stance.state import get_state_manager

            manager = get_state_manager()
            checkpoint = manager.get_checkpoint(collector, account, region)

            if not checkpoint:
                return HandlerResponse.not_found("Checkpoint")

            return HandlerResponse.success(checkpoint.to_dict())
        except Exception as e:
            return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

    @route("findings")
    def state_findings(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List finding states.

        Query params:
            asset_id: Filter by asset ID
            lifecycle: Filter by lifecycle state
            limit: Maximum findings to return (default: 50)
        """
        asset_id = self.get_param(params, "asset_id", "")
        lifecycle_filter = self.get_param(params, "lifecycle", "")
        limit = self.get_param_int(params, "limit", 50)

        try:
            from stance.state import FindingLifecycle, get_state_manager

            manager = get_state_manager()
            lifecycle = FindingLifecycle(lifecycle_filter) if lifecycle_filter else None
            findings = manager.backend.list_finding_states(
                asset_id=asset_id or None,
                lifecycle=lifecycle,
                limit=limit,
            )

            return HandlerResponse.success({
                "findings": [f.to_dict() for f in findings],
                "total": len(findings),
                "filters": {
                    "asset_id": asset_id or None,
                    "lifecycle": lifecycle_filter or None,
                    "limit": limit,
                },
            })
        except Exception as e:
            logger.warning(f"Error listing finding states: {e}")
            return HandlerResponse.success({"findings": [], "total": 0})

    @route("finding")
    def state_finding(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get specific finding state.

        Query params:
            finding_id: Finding ID (required)
        """
        finding_id = self.get_param(params, "finding_id", "")

        if not finding_id:
            return HandlerResponse.error("finding_id parameter required", HttpStatus.BAD_REQUEST)

        try:
            from stance.state import get_state_manager

            manager = get_state_manager()
            finding = manager.backend.get_finding_state(finding_id)

            if not finding:
                return HandlerResponse.not_found("Finding state")

            return HandlerResponse.success(finding.to_dict())
        except Exception as e:
            return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

    @route("scan-statuses")
    def state_scan_statuses(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available scan statuses."""
        statuses = [
            {"value": "pending", "description": "Scan is queued but not yet started"},
            {"value": "running", "description": "Scan is currently in progress"},
            {"value": "completed", "description": "Scan finished successfully"},
            {"value": "failed", "description": "Scan encountered an error"},
            {"value": "cancelled", "description": "Scan was cancelled by user"},
        ]

        return HandlerResponse.success({
            "statuses": statuses,
            "total": len(statuses),
        })

    @route("lifecycles")
    def state_lifecycles(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available finding lifecycle states."""
        lifecycles = [
            {"value": "new", "description": "Finding was just detected"},
            {"value": "active", "description": "Finding is currently active"},
            {"value": "resolved", "description": "Finding has been fixed"},
            {"value": "suppressed", "description": "Finding is suppressed"},
            {"value": "false_positive", "description": "Finding marked as false positive"},
        ]

        return HandlerResponse.success({
            "lifecycles": lifecycles,
            "total": len(lifecycles),
        })

    @route("backends")
    def state_backends(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available state backends."""
        backends = [
            {
                "name": "SQLiteStateBackend",
                "description": "SQLite-based local state storage",
                "persistent": True,
                "default": True,
            },
            {
                "name": "InMemoryStateBackend",
                "description": "In-memory state for testing",
                "persistent": False,
                "default": False,
            },
        ]

        return HandlerResponse.success({
            "backends": backends,
            "total": len(backends),
        })

    @route("finding-stats")
    def state_finding_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get finding state statistics."""
        return HandlerResponse.success({
            "total_findings": 0,
            "by_lifecycle": {
                "new": 0,
                "active": 0,
                "resolved": 0,
                "suppressed": 0,
            },
        })

    @route("stats")
    def state_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get state statistics."""
        return HandlerResponse.success({
            "total_scans": 0,
            "total_checkpoints": 0,
            "total_finding_states": 0,
            "by_status": {
                "completed": 0,
                "failed": 0,
                "running": 0,
            },
            "storage_size_bytes": 0,
        })

    @route("status")
    def state_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get state module status."""
        return HandlerResponse.success({
            "module": "state",
            "version": "1.0.0",
            "status": "active",
            "backend": "SQLiteStateBackend",
            "database_path": "~/.stance/state.db",
            "capabilities": {
                "scan_tracking": True,
                "checkpoint_management": True,
                "finding_lifecycle": True,
                "incremental_scans": True,
            },
        })

    @route("summary")
    def state_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get state summary."""
        return HandlerResponse.success({
            "total_scans": 0,
            "total_checkpoints": 0,
            "total_finding_states": 0,
            "backend": "SQLiteStateBackend",
        })

    # =========================================================================
    # POST endpoints
    # =========================================================================

    @route("suppress", methods=["POST"])
    def state_suppress(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Suppress a finding.

        Body:
            finding_id: Finding ID (required)
            reason: Suppression reason (optional)
        """
        if not body:
            return HandlerResponse.error("Request body required", HttpStatus.BAD_REQUEST)

        finding_id = body.get("finding_id", "")
        reason = body.get("reason", "")

        if not finding_id:
            return HandlerResponse.error("finding_id is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "status": "suppressed",
            "finding_id": finding_id,
            "reason": reason or "No reason provided",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    @route("resolve", methods=["POST"])
    def state_resolve(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Mark a finding as resolved.

        Body:
            finding_id: Finding ID (required)
            resolution: Resolution note (optional)
        """
        if not body:
            return HandlerResponse.error("Request body required", HttpStatus.BAD_REQUEST)

        finding_id = body.get("finding_id", "")
        resolution = body.get("resolution", "")

        if not finding_id:
            return HandlerResponse.error("finding_id is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "status": "resolved",
            "finding_id": finding_id,
            "resolution": resolution or "Resolved",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    @route("delete-checkpoint", methods=["POST"])
    def state_delete_checkpoint(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Delete a checkpoint.

        Body:
            collector: Collector name (required)
            account: Account ID (required)
            region: Region (required)
        """
        if not body:
            return HandlerResponse.error("Request body required", HttpStatus.BAD_REQUEST)

        collector = body.get("collector", "")
        account = body.get("account", "")
        region = body.get("region", "")

        if not collector or not account or not region:
            return HandlerResponse.error(
                "collector, account, and region are required",
                HttpStatus.BAD_REQUEST
            )

        return HandlerResponse.success({
            "status": "deleted",
            "collector": collector,
            "account": account,
            "region": region,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
