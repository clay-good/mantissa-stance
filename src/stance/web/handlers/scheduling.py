"""
Scheduling handlers for the Stance web API.

This module handles all /api/scheduling/* endpoints for job
scheduling and history management.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class SchedulingHandler(RoutedHandler):
    """
    Handler for scheduling API endpoints.

    Handles:
    - Job management
    - Schedule history
    - Trend analysis
    - Diff comparison
    """

    base_path = "/api/scheduling/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("jobs")
    def scheduling_jobs(self, params: dict, body: dict | None) -> HandlerResponse:
        """List scheduled jobs."""
        jobs = [
            {
                "id": "scan-daily",
                "name": "Daily Security Scan",
                "schedule": "0 2 * * *",
                "schedule_type": "cron",
                "enabled": True,
                "last_run": None,
                "next_run": datetime.now(timezone.utc).isoformat(),
            },
            {
                "id": "report-weekly",
                "name": "Weekly Compliance Report",
                "schedule": "0 8 * * 1",
                "schedule_type": "cron",
                "enabled": True,
                "last_run": None,
                "next_run": datetime.now(timezone.utc).isoformat(),
            },
        ]
        return HandlerResponse.success({"jobs": jobs, "total": len(jobs)})

    @route("job")
    def scheduling_job(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get specific job details."""
        job_id = self.get_param(params, "id", "")
        if not job_id:
            return HandlerResponse.error("Missing required parameter: id", HttpStatus.BAD_REQUEST)

        jobs = {
            "scan-daily": {
                "id": "scan-daily",
                "name": "Daily Security Scan",
                "description": "Run daily security scan on all configured accounts",
                "schedule": "0 2 * * *",
                "schedule_type": "cron",
                "enabled": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        }

        job = jobs.get(job_id)
        if not job:
            return HandlerResponse.not_found(f"Job: {job_id}")

        return HandlerResponse.success(job)

    @route("history")
    def scheduling_history(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get job execution history."""
        job_id = self.get_param(params, "job_id", "")
        limit = self.get_param_int(params, "limit", 10)

        history = [
            {
                "id": "exec-001",
                "job_id": job_id or "scan-daily",
                "status": "completed",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": 120,
            },
        ]

        return HandlerResponse.success({"history": history, "total": len(history)})

    @route("history-entry")
    def scheduling_history_entry(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get specific history entry."""
        entry_id = self.get_param(params, "id", "")
        if not entry_id:
            return HandlerResponse.error("Missing required parameter: id", HttpStatus.BAD_REQUEST)

        entry = {
            "id": entry_id,
            "job_id": "scan-daily",
            "status": "completed",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": 120,
            "result": {"findings": 15, "assets": 42},
        }

        return HandlerResponse.success(entry)

    @route("compare")
    def scheduling_compare(self, params: dict, body: dict | None) -> HandlerResponse:
        """Compare two scan results."""
        scan_a = self.get_param(params, "scan_a", "")
        scan_b = self.get_param(params, "scan_b", "")

        if not scan_a or not scan_b:
            return HandlerResponse.error("Missing required parameters: scan_a, scan_b", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "scan_a": scan_a,
            "scan_b": scan_b,
            "comparison": {
                "findings_added": 3,
                "findings_removed": 1,
                "findings_unchanged": 12,
                "assets_added": 2,
                "assets_removed": 0,
            },
        })

    @route("trend")
    def scheduling_trend(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get trend data for scheduled jobs."""
        job_id = self.get_param(params, "job_id", "")
        days = self.get_param_int(params, "days", 30)

        return HandlerResponse.success({
            "job_id": job_id or "all",
            "days": days,
            "trend": {
                "total_runs": 28,
                "successful": 26,
                "failed": 2,
                "average_duration": 125,
                "findings_trend": [12, 14, 13, 15, 14],
            },
        })

    @route("status")
    def scheduling_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get scheduling module status."""
        return HandlerResponse.success({
            "module": "scheduling",
            "status": "operational",
            "active_jobs": 2,
            "pending_runs": 2,
            "capabilities": [
                "cron_scheduling",
                "interval_scheduling",
                "job_history",
                "trend_analysis",
            ],
        })

    @route("schedule-types")
    def scheduling_schedule_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List schedule types."""
        types = [
            {"type": "cron", "description": "Cron expression scheduling", "example": "0 2 * * *"},
            {"type": "interval", "description": "Fixed interval scheduling", "example": "3600s"},
            {"type": "daily", "description": "Daily at specific time", "example": "02:00"},
            {"type": "weekly", "description": "Weekly at specific day/time", "example": "monday 08:00"},
        ]
        return HandlerResponse.success({"types": types, "total": len(types)})

    @route("diff-types")
    def scheduling_diff_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List diff comparison types."""
        diff_types = [
            {"type": "findings", "description": "Compare security findings"},
            {"type": "assets", "description": "Compare asset inventory"},
            {"type": "compliance", "description": "Compare compliance scores"},
            {"type": "all", "description": "Full comparison"},
        ]
        return HandlerResponse.success({"diff_types": diff_types, "total": len(diff_types)})

    @route("summary")
    def scheduling_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get scheduling module summary."""
        return HandlerResponse.success({
            "module": "scheduling",
            "description": "Job scheduling and execution management",
            "features": [
                "Cron-based scheduling",
                "Interval scheduling",
                "Execution history",
                "Trend analysis",
                "Scan comparison",
            ],
            "active_jobs": 2,
            "supported_schedule_types": ["cron", "interval", "daily", "weekly"],
        })
