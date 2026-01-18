"""
Findings management handlers for the Stance web API.

This module handles all /api/findings/* endpoints for finding operations
including listing, filtering, details, status updates, aggregation,
correlation, and export functionality.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class FindingsHandler(RoutedHandler):
    """
    Handler for findings management API endpoints.

    Handles:
    - Finding listing and filtering
    - Finding details and search
    - Finding aggregation and grouping
    - Finding status updates (suppress, resolve)
    - Finding lifecycle management
    - Finding export and reporting
    """

    base_path = "/api/findings/"

    # =========================================================================
    # Finding Listing GET endpoints
    # =========================================================================

    @route("list")
    def findings_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List findings with pagination and filtering."""
        try:
            limit = self.get_param_int(params, "limit", 50)
            offset = self.get_param_int(params, "offset", 0)
            severity = self.get_param(params, "severity", "")
            status = self.get_param(params, "status", "")
            asset_id = self.get_param(params, "asset_id", "")

            # Demo findings data
            findings = [
                {
                    "id": "finding-001",
                    "title": "S3 bucket public access enabled",
                    "severity": "HIGH",
                    "status": "OPEN",
                    "finding_type": "MISCONFIGURATION",
                    "asset_id": "arn:aws:s3:::my-bucket",
                    "rule_id": "CIS-AWS-1.20",
                    "cve_id": None,
                },
                {
                    "id": "finding-002",
                    "title": "Critical vulnerability in OpenSSL",
                    "severity": "CRITICAL",
                    "status": "OPEN",
                    "finding_type": "VULNERABILITY",
                    "asset_id": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
                    "rule_id": None,
                    "cve_id": "CVE-2024-1234",
                },
                {
                    "id": "finding-003",
                    "title": "IAM user with console access has no MFA",
                    "severity": "MEDIUM",
                    "status": "OPEN",
                    "finding_type": "MISCONFIGURATION",
                    "asset_id": "arn:aws:iam::123456789012:user/admin",
                    "rule_id": "CIS-AWS-1.10",
                    "cve_id": None,
                },
                {
                    "id": "finding-004",
                    "title": "Security group allows unrestricted SSH access",
                    "severity": "HIGH",
                    "status": "SUPPRESSED",
                    "finding_type": "MISCONFIGURATION",
                    "asset_id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345",
                    "rule_id": "CIS-AWS-5.2",
                    "cve_id": None,
                },
                {
                    "id": "finding-005",
                    "title": "Outdated Python package with known vulnerability",
                    "severity": "LOW",
                    "status": "RESOLVED",
                    "finding_type": "VULNERABILITY",
                    "asset_id": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
                    "rule_id": None,
                    "cve_id": "CVE-2023-5678",
                },
            ]

            # Apply filters
            if severity:
                findings = [f for f in findings if f["severity"] == severity.upper()]
            if status:
                findings = [f for f in findings if f["status"] == status.upper()]
            if asset_id:
                findings = [f for f in findings if f["asset_id"] == asset_id]

            total = len(findings)
            findings = findings[offset:offset + limit]

            return HandlerResponse.success({
                "items": findings,
                "total": total,
                "limit": limit,
                "offset": offset,
            })
        except Exception as e:
            logger.exception("Failed to list findings")
            return HandlerResponse.server_error(str(e))

    @route("show")
    def findings_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get detailed information for a specific finding."""
        try:
            finding_id = self.get_param(params, "finding_id", "")

            if not finding_id:
                return HandlerResponse.error("finding_id parameter required", HttpStatus.BAD_REQUEST)

            # Demo finding details
            result = {
                "finding": {
                    "id": finding_id,
                    "title": "S3 bucket public access enabled",
                    "description": "The S3 bucket has public access enabled, which could expose sensitive data to unauthorized users.",
                    "severity": "HIGH",
                    "status": "OPEN",
                    "finding_type": "MISCONFIGURATION",
                    "asset_id": "arn:aws:s3:::my-bucket",
                    "rule_id": "CIS-AWS-1.20",
                    "cve_id": None,
                    "cvss_score": None,
                    "compliance_frameworks": ["CIS AWS v1.4", "SOC 2"],
                    "remediation_guidance": "Disable public access on the S3 bucket using the S3 Block Public Access settings.",
                    "first_seen": "2024-12-01T10:00:00Z",
                    "last_seen": "2024-12-30T10:00:00Z",
                    "resource_path": "$.PublicAccessBlockConfiguration",
                    "expected_value": "BlockPublicAcls: true",
                    "actual_value": "BlockPublicAcls: false",
                    "package_name": None,
                    "installed_version": None,
                    "fixed_version": None,
                },
                "asset": {
                    "id": "arn:aws:s3:::my-bucket",
                    "name": "my-bucket",
                    "resource_type": "aws_s3_bucket",
                    "region": "us-east-1",
                },
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get finding details")
            return HandlerResponse.server_error(str(e))

    @route("search")
    def findings_search(self, params: dict, body: dict | None) -> HandlerResponse:
        """Search findings with full-text query."""
        try:
            query = self.get_param(params, "q", "")
            limit = self.get_param_int(params, "limit", 20)
            search_type = self.get_param(params, "type", "all")

            if not query:
                return HandlerResponse.error("q parameter required", HttpStatus.BAD_REQUEST)

            # Demo search results
            results = [
                {
                    "id": "finding-001",
                    "title": "S3 bucket public access enabled",
                    "severity": "HIGH",
                    "match_score": 0.95,
                    "matched_fields": ["title", "description"],
                },
                {
                    "id": "finding-002",
                    "title": "Critical vulnerability in OpenSSL",
                    "severity": "CRITICAL",
                    "match_score": 0.75,
                    "matched_fields": ["title"],
                },
            ]

            return HandlerResponse.success({
                "query": query,
                "type": search_type,
                "results": results[:limit],
                "total": len(results),
            })
        except Exception as e:
            logger.exception("Failed to search findings")
            return HandlerResponse.server_error(str(e))

    @route("by-severity")
    def findings_by_severity(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get findings grouped by severity."""
        try:
            result = {
                "severity_counts": {
                    "CRITICAL": 5,
                    "HIGH": 23,
                    "MEDIUM": 45,
                    "LOW": 67,
                    "INFO": 12,
                },
                "total": 152,
                "chart_data": [
                    {"severity": "CRITICAL", "count": 5, "color": "#dc2626"},
                    {"severity": "HIGH", "count": 23, "color": "#ea580c"},
                    {"severity": "MEDIUM", "count": 45, "color": "#ca8a04"},
                    {"severity": "LOW", "count": 67, "color": "#16a34a"},
                    {"severity": "INFO", "count": 12, "color": "#0284c7"},
                ],
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get findings by severity")
            return HandlerResponse.server_error(str(e))

    @route("by-status")
    def findings_by_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get findings grouped by status."""
        try:
            result = {
                "status_counts": {
                    "OPEN": 85,
                    "IN_PROGRESS": 25,
                    "RESOLVED": 30,
                    "SUPPRESSED": 10,
                    "FALSE_POSITIVE": 2,
                },
                "total": 152,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get findings by status")
            return HandlerResponse.server_error(str(e))

    @route("by-type")
    def findings_by_type(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get findings grouped by type."""
        try:
            result = {
                "type_counts": {
                    "MISCONFIGURATION": 78,
                    "VULNERABILITY": 45,
                    "COMPLIANCE": 20,
                    "SECRET": 5,
                    "IAC": 4,
                },
                "total": 152,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get findings by type")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Finding Lifecycle GET endpoints
    # =========================================================================

    @route("lifecycles")
    def findings_lifecycles(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available finding lifecycle states."""
        try:
            lifecycles = [
                {
                    "lifecycle": "NEW",
                    "description": "First time this finding was seen",
                    "action": "Investigate and remediate",
                },
                {
                    "lifecycle": "RECURRING",
                    "description": "Seen again in subsequent scans",
                    "action": "Continue remediation",
                },
                {
                    "lifecycle": "RESOLVED",
                    "description": "No longer detected in scans",
                    "action": "Verify fix is complete",
                },
                {
                    "lifecycle": "REOPENED",
                    "description": "Was resolved but detected again",
                    "action": "Investigate regression",
                },
                {
                    "lifecycle": "SUPPRESSED",
                    "description": "Manually suppressed by user",
                    "action": "Review periodically",
                },
                {
                    "lifecycle": "FALSE_POSITIVE",
                    "description": "Marked as not a real issue",
                    "action": "Consider policy tuning",
                },
            ]
            return HandlerResponse.success({
                "lifecycles": lifecycles,
                "total": len(lifecycles),
            })
        except Exception as e:
            logger.exception("Failed to list lifecycles")
            return HandlerResponse.server_error(str(e))

    @route("states")
    def findings_states(self, params: dict, body: dict | None) -> HandlerResponse:
        """List finding states with filtering."""
        try:
            asset_id = self.get_param(params, "asset_id", "")
            lifecycle = self.get_param(params, "lifecycle", "")
            limit = self.get_param_int(params, "limit", 50)

            # Demo finding states
            states = [
                {
                    "finding_id": "finding-001",
                    "lifecycle": "NEW",
                    "first_seen": "2024-12-01T10:00:00Z",
                    "last_seen": "2024-12-30T10:00:00Z",
                    "scan_count": 15,
                    "suppressed_by": None,
                    "suppression_reason": None,
                },
                {
                    "finding_id": "finding-002",
                    "lifecycle": "SUPPRESSED",
                    "first_seen": "2024-11-15T10:00:00Z",
                    "last_seen": "2024-12-30T10:00:00Z",
                    "scan_count": 30,
                    "suppressed_by": "admin@example.com",
                    "suppression_reason": "Risk accepted",
                },
            ]

            # Apply filters
            if lifecycle:
                states = [s for s in states if s["lifecycle"] == lifecycle.upper()]

            return HandlerResponse.success({
                "findings": states[:limit],
                "total": len(states),
                "filters": {
                    "asset_id": asset_id or None,
                    "lifecycle": lifecycle or None,
                    "limit": limit,
                },
            })
        except Exception as e:
            logger.exception("Failed to list finding states")
            return HandlerResponse.server_error(str(e))

    @route("state")
    def findings_state(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get specific finding state."""
        try:
            finding_id = self.get_param(params, "finding_id", "")

            if not finding_id:
                return HandlerResponse.error("finding_id parameter required", HttpStatus.BAD_REQUEST)

            # Demo finding state
            result = {
                "finding_id": finding_id,
                "lifecycle": "NEW",
                "first_seen": "2024-12-01T10:00:00Z",
                "last_seen": "2024-12-30T10:00:00Z",
                "scan_count": 15,
                "resolved_at": None,
                "suppressed_by": None,
                "suppression_reason": None,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get finding state")
            return HandlerResponse.server_error(str(e))

    @route("stats")
    def findings_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get finding statistics by lifecycle."""
        try:
            stats = {
                "NEW": 45,
                "RECURRING": 35,
                "RESOLVED": 30,
                "REOPENED": 5,
                "SUPPRESSED": 25,
                "FALSE_POSITIVE": 12,
            }
            total = sum(stats.values())

            result = {
                "stats": stats,
                "total": total,
                "breakdown": [
                    {
                        "lifecycle": k,
                        "count": v,
                        "percentage": round((v / total * 100), 2) if total > 0 else 0,
                    }
                    for k, v in stats.items()
                ],
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get finding stats")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Finding Aggregation GET endpoints
    # =========================================================================

    @route("aggregate")
    def findings_aggregate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Aggregate findings from multiple accounts."""
        try:
            severity = self.get_param(params, "severity", "")
            deduplicate = self.get_param_bool(params, "deduplicate", True)

            result = {
                "total_findings": 156,
                "unique_findings": 98 if deduplicate else 156,
                "accounts_scanned": 5,
                "deduplicated": deduplicate,
                "findings_by_severity": {
                    "CRITICAL": 12,
                    "HIGH": 35,
                    "MEDIUM": 67,
                    "LOW": 42,
                },
                "findings_by_account": [
                    {"account_id": "123456789012", "count": 45},
                    {"account_id": "234567890123", "count": 38},
                    {"account_id": "345678901234", "count": 32},
                ],
            }

            if severity:
                result["filter"] = {"severity": severity.upper()}

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to aggregate findings")
            return HandlerResponse.server_error(str(e))

    @route("cross-account")
    def findings_cross_account(self, params: dict, body: dict | None) -> HandlerResponse:
        """Find findings appearing in multiple accounts."""
        try:
            min_accounts = self.get_param_int(params, "min_accounts", 2)

            result = {
                "cross_account_findings": [
                    {
                        "finding_signature": "s3-public-access",
                        "title": "S3 bucket public access enabled",
                        "severity": "HIGH",
                        "accounts": ["123456789012", "234567890123", "345678901234"],
                        "account_count": 3,
                    },
                    {
                        "finding_signature": "iam-no-mfa",
                        "title": "IAM user without MFA",
                        "severity": "MEDIUM",
                        "accounts": ["123456789012", "234567890123"],
                        "account_count": 2,
                    },
                ],
                "total": 2,
                "min_accounts": min_accounts,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get cross-account findings")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Finding Correlation GET endpoints
    # =========================================================================

    @route("correlate")
    def findings_correlate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Run correlation analysis on findings."""
        try:
            time_window = self.get_param_int(params, "time_window", 24)
            min_group_size = self.get_param_int(params, "min_group_size", 2)

            result = {
                "correlation_groups": [
                    {
                        "group_id": "corr-001",
                        "type": "attack_path",
                        "findings": ["finding-001", "finding-002", "finding-003"],
                        "severity": "CRITICAL",
                        "description": "Potential attack path from public S3 to EC2 instance",
                    },
                    {
                        "group_id": "corr-002",
                        "type": "same_asset",
                        "findings": ["finding-004", "finding-005"],
                        "severity": "HIGH",
                        "description": "Multiple issues on same security group",
                    },
                ],
                "total_groups": 2,
                "findings_correlated": 5,
                "time_window_hours": time_window,
                "min_group_size": min_group_size,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to correlate findings")
            return HandlerResponse.server_error(str(e))

    @route("groups")
    def findings_groups(self, params: dict, body: dict | None) -> HandlerResponse:
        """List correlation groups."""
        try:
            group_type = self.get_param(params, "type", "")
            min_size = self.get_param_int(params, "min_size", 2)

            groups = [
                {
                    "group_id": "corr-001",
                    "type": "attack_path",
                    "finding_count": 3,
                    "severity": "CRITICAL",
                    "created_at": "2024-12-30T10:00:00Z",
                },
                {
                    "group_id": "corr-002",
                    "type": "same_asset",
                    "finding_count": 2,
                    "severity": "HIGH",
                    "created_at": "2024-12-30T10:00:00Z",
                },
                {
                    "group_id": "corr-003",
                    "type": "same_rule",
                    "finding_count": 5,
                    "severity": "MEDIUM",
                    "created_at": "2024-12-30T10:00:00Z",
                },
            ]

            # Apply filters
            if group_type:
                groups = [g for g in groups if g["type"] == group_type]
            groups = [g for g in groups if g["finding_count"] >= min_size]

            return HandlerResponse.success({
                "groups": groups,
                "total": len(groups),
            })
        except Exception as e:
            logger.exception("Failed to list correlation groups")
            return HandlerResponse.server_error(str(e))

    @route("group")
    def findings_group(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get correlation group details."""
        try:
            group_id = self.get_param(params, "group_id", "")

            if not group_id:
                return HandlerResponse.error("group_id parameter required", HttpStatus.BAD_REQUEST)

            result = {
                "group_id": group_id,
                "type": "attack_path",
                "severity": "CRITICAL",
                "description": "Potential attack path from public S3 to EC2 instance",
                "findings": [
                    {"id": "finding-001", "title": "S3 bucket public access enabled", "severity": "HIGH"},
                    {"id": "finding-002", "title": "EC2 instance with public IP", "severity": "MEDIUM"},
                    {"id": "finding-003", "title": "IAM role with excessive permissions", "severity": "HIGH"},
                ],
                "recommendations": [
                    "Disable public access on S3 bucket",
                    "Move EC2 instance to private subnet",
                    "Apply least privilege to IAM role",
                ],
                "created_at": "2024-12-30T10:00:00Z",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get correlation group")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Finding Enrichment GET endpoints
    # =========================================================================

    @route("enrich")
    def findings_enrich(self, params: dict, body: dict | None) -> HandlerResponse:
        """Enrich findings with threat intelligence."""
        try:
            finding_id = self.get_param(params, "finding_id", "")
            enrich_types = self.get_param(params, "types", "cve,kev,threat")

            result = {
                "finding_id": finding_id or "demo-finding",
                "enrichment_types": enrich_types.split(","),
                "enrichments": {
                    "cve": {
                        "cve_id": "CVE-2024-1234",
                        "cvss_score": 9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "description": "Critical remote code execution vulnerability",
                    },
                    "kev": {
                        "in_catalog": True,
                        "date_added": "2024-01-15",
                        "due_date": "2024-02-15",
                        "ransomware_use": True,
                    },
                    "threat": {
                        "threat_actors": ["APT28", "APT29"],
                        "malware_families": ["Emotet"],
                        "campaigns": ["Operation Harvest"],
                    },
                },
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to enrich finding")
            return HandlerResponse.server_error(str(e))

    @route("explain")
    def findings_explain(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get AI-powered explanation for a finding."""
        try:
            finding_id = self.get_param(params, "finding_id", "")

            if not finding_id:
                return HandlerResponse.error("finding_id parameter required", HttpStatus.BAD_REQUEST)

            result = {
                "finding_id": finding_id,
                "explanation": {
                    "summary": "This S3 bucket has public access enabled, exposing data to the internet.",
                    "risk": "Unauthorized users can read, list, or potentially write to this bucket.",
                    "business_impact": "Sensitive data exposure could lead to compliance violations and reputational damage.",
                    "remediation_steps": [
                        "Navigate to S3 console and select the bucket",
                        "Go to Permissions tab",
                        "Enable Block Public Access settings",
                        "Verify bucket policy does not grant public access",
                    ],
                    "references": [
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                    ],
                },
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to explain finding")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Finding Export GET endpoints
    # =========================================================================

    @route("export-formats")
    def findings_export_formats(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available export formats."""
        try:
            formats = [
                {"format": "json", "description": "JSON format", "content_type": "application/json"},
                {"format": "csv", "description": "CSV spreadsheet", "content_type": "text/csv"},
                {"format": "html", "description": "HTML report", "content_type": "text/html"},
                {"format": "pdf", "description": "PDF document", "content_type": "application/pdf"},
            ]
            return HandlerResponse.success({
                "formats": formats,
                "total": len(formats),
            })
        except Exception as e:
            logger.exception("Failed to list export formats")
            return HandlerResponse.server_error(str(e))

    @route("summary")
    def findings_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get findings module summary."""
        try:
            result = {
                "module": "findings",
                "version": "1.0.0",
                "description": "Security findings management with lifecycle tracking and correlation",
                "features": [
                    "Finding listing and filtering",
                    "Full-text search",
                    "Lifecycle state management",
                    "Cross-account aggregation",
                    "Finding correlation",
                    "Threat intelligence enrichment",
                    "Export to multiple formats",
                ],
                "finding_types": ["MISCONFIGURATION", "VULNERABILITY", "COMPLIANCE", "SECRET", "IAC"],
                "lifecycle_states": ["NEW", "RECURRING", "RESOLVED", "REOPENED", "SUPPRESSED", "FALSE_POSITIVE"],
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get findings summary")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Finding Status Update POST endpoints
    # =========================================================================

    @route("suppress", methods=["POST"])
    def findings_suppress(self, params: dict, body: dict | None) -> HandlerResponse:
        """Suppress a finding."""
        try:
            data = body or {}
            finding_id = data.get("finding_id", "")
            suppressed_by = data.get("by", "api")
            reason = data.get("reason", "")

            if not finding_id:
                return HandlerResponse.error("Missing required field: finding_id", HttpStatus.BAD_REQUEST)

            result = {
                "suppressed": True,
                "finding_id": finding_id,
                "suppressed_by": suppressed_by,
                "reason": reason,
                "lifecycle": "SUPPRESSED",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to suppress finding")
            return HandlerResponse.server_error(str(e))

    @route("resolve", methods=["POST"])
    def findings_resolve(self, params: dict, body: dict | None) -> HandlerResponse:
        """Mark a finding as resolved."""
        try:
            data = body or {}
            finding_id = data.get("finding_id", "")

            if not finding_id:
                return HandlerResponse.error("Missing required field: finding_id", HttpStatus.BAD_REQUEST)

            result = {
                "resolved": True,
                "finding_id": finding_id,
                "lifecycle": "RESOLVED",
                "resolved_at": "2024-12-31T10:00:00Z",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to resolve finding")
            return HandlerResponse.server_error(str(e))

    @route("reopen", methods=["POST"])
    def findings_reopen(self, params: dict, body: dict | None) -> HandlerResponse:
        """Reopen a resolved or suppressed finding."""
        try:
            data = body or {}
            finding_id = data.get("finding_id", "")

            if not finding_id:
                return HandlerResponse.error("Missing required field: finding_id", HttpStatus.BAD_REQUEST)

            result = {
                "reopened": True,
                "finding_id": finding_id,
                "lifecycle": "REOPENED",
                "reopened_at": "2024-12-31T10:00:00Z",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to reopen finding")
            return HandlerResponse.server_error(str(e))

    @route("false-positive", methods=["POST"])
    def findings_false_positive(self, params: dict, body: dict | None) -> HandlerResponse:
        """Mark a finding as false positive."""
        try:
            data = body or {}
            finding_id = data.get("finding_id", "")
            marked_by = data.get("by", "api")
            reason = data.get("reason", "")

            if not finding_id:
                return HandlerResponse.error("Missing required field: finding_id", HttpStatus.BAD_REQUEST)

            result = {
                "marked": True,
                "finding_id": finding_id,
                "marked_by": marked_by,
                "reason": reason,
                "lifecycle": "FALSE_POSITIVE",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to mark finding as false positive")
            return HandlerResponse.server_error(str(e))

    @route("bulk-update", methods=["POST"])
    def findings_bulk_update(self, params: dict, body: dict | None) -> HandlerResponse:
        """Bulk update finding status."""
        try:
            data = body or {}
            finding_ids = data.get("finding_ids", [])
            action = data.get("action", "")
            reason = data.get("reason", "")

            if not finding_ids:
                return HandlerResponse.error("Missing required field: finding_ids", HttpStatus.BAD_REQUEST)
            if not action:
                return HandlerResponse.error("Missing required field: action", HttpStatus.BAD_REQUEST)
            if action not in ["suppress", "resolve", "reopen", "false_positive"]:
                return HandlerResponse.error(
                    "Invalid action. Must be one of: suppress, resolve, reopen, false_positive",
                    HttpStatus.BAD_REQUEST
                )

            result = {
                "success": True,
                "action": action,
                "finding_ids": finding_ids,
                "updated_count": len(finding_ids),
                "reason": reason or None,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to bulk update findings")
            return HandlerResponse.server_error(str(e))

    @route("export", methods=["POST"])
    def findings_export(self, params: dict, body: dict | None) -> HandlerResponse:
        """Export findings to specified format."""
        try:
            data = body or {}
            export_format = data.get("format", "json")
            severity = data.get("severity", "")
            report_type = data.get("report_type", "findings_detail")

            if export_format not in ["json", "csv", "html", "pdf"]:
                return HandlerResponse.error(
                    "Invalid format. Must be one of: json, csv, html, pdf",
                    HttpStatus.BAD_REQUEST
                )

            result = {
                "success": True,
                "format": export_format,
                "report_type": report_type,
                "filters": {
                    "severity": severity or None,
                },
                "download_url": f"/api/findings/download/{report_type}.{export_format}",
                "expires_at": "2024-12-31T11:00:00Z",
            }
            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to export findings")
            return HandlerResponse.server_error(str(e))
