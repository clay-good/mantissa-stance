"""
Scan management handlers for the Stance web API.

This module handles all /api/scan/* endpoints for scan management
including scan execution, history, status, progress, and results.
Also covers multi-account scanning and scanner module operations.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)

# Parameter bounds for API requests
MAX_LIMIT = 1000
DEFAULT_LIMIT = 20
MAX_OFFSET = 100000
MAX_DAYS = 365


def _validate_limit(value: int) -> int:
    """Validate and bound the limit parameter."""
    return max(1, min(MAX_LIMIT, value))


def _validate_offset(value: int) -> int:
    """Validate and bound the offset parameter."""
    return max(0, min(MAX_OFFSET, value))


def _validate_days(value: int) -> int:
    """Validate and bound the days parameter."""
    return max(1, min(MAX_DAYS, value))


class ScanHandler(RoutedHandler):
    """
    Handler for scan management API endpoints.

    Handles:
    - Scan history and status
    - Scan progress and results
    - Multi-account scanning
    - Scanner module operations (trivy, enrichment)
    - Vulnerability scanning
    """

    base_path = "/api/scan/"

    # =========================================================================
    # Scan History and Status GET endpoints
    # =========================================================================

    @route("list")
    def scan_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List scan history."""
        try:
            limit = _validate_limit(self.get_param_int(params, "limit", DEFAULT_LIMIT))
            status_filter = self.get_param(params, "status", "")
            days_param = self.get_param(params, "days", "")
            days = _validate_days(int(days_param)) if days_param else None

            # Demo scan history
            scans = [
                {
                    "scan_id": "scan-001",
                    "status": "completed",
                    "started_at": "2024-12-30T10:00:00Z",
                    "completed_at": "2024-12-30T10:15:00Z",
                    "accounts_scanned": 5,
                    "findings_count": 45,
                    "assets_count": 234,
                },
                {
                    "scan_id": "scan-002",
                    "status": "completed",
                    "started_at": "2024-12-29T10:00:00Z",
                    "completed_at": "2024-12-29T10:12:00Z",
                    "accounts_scanned": 5,
                    "findings_count": 42,
                    "assets_count": 231,
                },
                {
                    "scan_id": "scan-003",
                    "status": "running",
                    "started_at": "2024-12-31T08:00:00Z",
                    "completed_at": None,
                    "accounts_scanned": 3,
                    "findings_count": 12,
                    "assets_count": 98,
                },
            ]

            # Apply filters
            if status_filter:
                scans = [s for s in scans if s["status"] == status_filter]

            scans = scans[:limit]

            return HandlerResponse.success({
                "scans": scans,
                "total": len(scans),
                "filters": {
                    "limit": limit,
                    "status": status_filter or None,
                    "days": int(days) if days else None,
                },
            })
        except Exception as e:
            logger.exception("Failed to list scans")
            return HandlerResponse.server_error(str(e))

    @route("show")
    def scan_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get specific scan details."""
        try:
            scan_id = self.get_param(params, "scan_id", "")

            if not scan_id:
                return HandlerResponse.error("scan_id parameter required", HttpStatus.BAD_REQUEST)

            # Demo scan details
            result = {
                "scan_id": scan_id,
                "status": "completed",
                "started_at": "2024-12-30T10:00:00Z",
                "completed_at": "2024-12-30T10:15:00Z",
                "duration_seconds": 900,
                "config": {
                    "name": "default",
                    "collectors": ["aws_iam", "aws_s3", "aws_ec2"],
                    "regions": ["us-east-1", "us-west-2"],
                },
                "summary": {
                    "accounts_scanned": 5,
                    "findings_count": 45,
                    "assets_count": 234,
                    "critical_findings": 3,
                    "high_findings": 12,
                    "medium_findings": 20,
                    "low_findings": 10,
                },
                "accounts": [
                    {"account_id": "123456789012", "status": "completed", "findings": 15},
                    {"account_id": "234567890123", "status": "completed", "findings": 12},
                ],
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get scan details")
            return HandlerResponse.server_error(str(e))

    @route("status")
    def scan_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get scan module status."""
        try:
            result = {
                "module": "scan",
                "status": "operational",
                "components": {
                    "ScanOrchestrator": "available",
                    "MultiAccountScanner": "available",
                    "StateManager": "available",
                    "CollectorRegistry": "available",
                },
                "capabilities": [
                    "multi_account_scanning",
                    "parallel_execution",
                    "progress_tracking",
                    "incremental_scanning",
                    "state_persistence",
                ],
                "active_scans": 1,
                "queued_scans": 0,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get scan status")
            return HandlerResponse.server_error(str(e))

    @route("statuses")
    def scan_statuses(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available scan statuses."""
        try:
            statuses = [
                {
                    "status": "pending",
                    "description": "Scan is queued but not yet started",
                    "indicator": "[.]",
                },
                {
                    "status": "running",
                    "description": "Scan is currently in progress",
                    "indicator": "[>]",
                },
                {
                    "status": "completed",
                    "description": "Scan completed successfully",
                    "indicator": "[+]",
                },
                {
                    "status": "failed",
                    "description": "Scan failed with error",
                    "indicator": "[!]",
                },
                {
                    "status": "canceled",
                    "description": "Scan was canceled by user",
                    "indicator": "[x]",
                },
            ]
            return HandlerResponse.success({
                "statuses": statuses,
                "total": len(statuses),
            })
        except Exception as e:
            logger.exception("Failed to list scan statuses")
            return HandlerResponse.server_error(str(e))

    @route("progress")
    def scan_progress(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get scan progress."""
        try:
            scan_id = self.get_param(params, "scan_id", "current")

            result = {
                "scan_id": scan_id,
                "total_accounts": 10,
                "completed_accounts": 5,
                "failed_accounts": 1,
                "skipped_accounts": 0,
                "pending_accounts": 4,
                "current_accounts": ["account-006"],
                "findings_so_far": 42,
                "progress_percent": 60.0,
                "is_complete": False,
                "started_at": "2024-01-15T10:00:00Z",
                "estimated_completion": "2024-01-15T10:15:00Z",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get scan progress")
            return HandlerResponse.server_error(str(e))

    @route("results")
    def scan_results(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get scan results."""
        try:
            scan_id = self.get_param(params, "scan_id", "latest")
            account = self.get_param(params, "account", "")

            result = {
                "scan_id": scan_id,
                "config_name": "default",
                "started_at": "2024-01-15T10:00:00Z",
                "completed_at": "2024-01-15T10:20:00Z",
                "duration_seconds": 1200,
                "summary": {
                    "total_accounts": 10,
                    "successful_accounts": 9,
                    "failed_accounts": 1,
                    "total_findings": 156,
                    "unique_findings": 98,
                    "total_assets": 1245,
                },
                "findings_by_severity": {
                    "critical": 12,
                    "high": 35,
                    "medium": 67,
                    "low": 42,
                },
                "account_results": [
                    {"account_id": "123456789012", "status": "completed", "findings": 25},
                    {"account_id": "234567890123", "status": "completed", "findings": 18},
                    {"account_id": "345678901234", "status": "failed", "error": "Access denied"},
                ],
            }

            if account:
                result["filter"] = {"account": account}

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get scan results")
            return HandlerResponse.server_error(str(e))

    @route("report")
    def scan_report(self, params: dict, body: dict | None) -> HandlerResponse:
        """Generate scan report."""
        try:
            scan_id = self.get_param(params, "scan_id", "latest")

            result = {
                "scan_id": scan_id,
                "scan_date": "2024-01-15T10:00:00Z",
                "duration_seconds": 1200,
                "summary": {
                    "accounts_scanned": 10,
                    "accounts_successful": 9,
                    "accounts_failed": 1,
                    "scan_success_rate": 90.0,
                    "total_findings": 156,
                    "unique_findings": 98,
                    "cross_account_findings": 12,
                    "total_assets": 1245,
                },
                "findings_by_severity": {"critical": 12, "high": 35, "medium": 67, "low": 42},
                "findings_by_provider": {"aws": 112, "gcp": 34, "azure": 10},
                "top_accounts_by_findings": [
                    {"account_id": "123456789012", "account_name": "Production-AWS", "findings_count": 45},
                    {"account_id": "234567890123", "account_name": "Staging-AWS", "findings_count": 32},
                ],
                "accounts_with_critical_findings": [
                    {"account_id": "123456789012", "account_name": "Production-AWS", "critical_findings": 8},
                ],
                "failed_accounts": [
                    {"account_id": "345678901234", "account_name": "Test-Azure", "error": "Access denied"},
                ],
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to generate scan report")
            return HandlerResponse.server_error(str(e))

    @route("summary")
    def scan_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get scan module summary."""
        try:
            result = {
                "module": "scan",
                "version": "1.0.0",
                "description": "Multi-account scanning orchestration for organization-level security assessments",
                "features": [
                    "Parallel multi-account scanning",
                    "Progress tracking and status updates",
                    "Timeout handling and error recovery",
                    "Cross-account findings aggregation",
                    "Report generation",
                    "Callback notifications",
                ],
                "scan_types": ["cspm", "vulnerability", "compliance", "iac"],
                "supported_providers": ["aws", "gcp", "azure"],
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get scan summary")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Multi-Account Scanning GET endpoints
    # =========================================================================

    @route("accounts")
    def scan_accounts(self, params: dict, body: dict | None) -> HandlerResponse:
        """List configured accounts for scanning."""
        try:
            include_disabled = self.get_param_bool(params, "include_disabled", False)

            accounts = [
                {"account_id": "123456789012", "name": "Production-AWS", "provider": "aws", "enabled": True, "regions": ["us-east-1", "us-west-2"]},
                {"account_id": "234567890123", "name": "Staging-AWS", "provider": "aws", "enabled": True, "regions": ["us-east-1"]},
                {"account_id": "project-prod-12345", "name": "Production-GCP", "provider": "gcp", "enabled": True, "regions": ["us-central1"]},
                {"account_id": "sub-12345678-abcd", "name": "Production-Azure", "provider": "azure", "enabled": False, "regions": ["eastus"]},
            ]

            if not include_disabled:
                accounts = [a for a in accounts if a["enabled"]]

            return HandlerResponse.success({
                "accounts": accounts,
                "total": len(accounts),
            })
        except Exception as e:
            logger.exception("Failed to list accounts")
            return HandlerResponse.server_error(str(e))

    @route("options")
    def scan_options(self, params: dict, body: dict | None) -> HandlerResponse:
        """List scan options."""
        try:
            options = [
                {"option": "parallel_accounts", "type": "int", "default": 3, "description": "Number of accounts to scan in parallel"},
                {"option": "timeout_per_account", "type": "int", "default": 300, "description": "Maximum time per account scan in seconds"},
                {"option": "continue_on_error", "type": "bool", "default": True, "description": "Continue scanning other accounts if one fails"},
                {"option": "severity_threshold", "type": "enum", "default": None, "description": "Minimum severity to include in results"},
                {"option": "collectors", "type": "list", "default": None, "description": "List of collectors to run (None = all)"},
                {"option": "regions", "type": "list", "default": None, "description": "List of regions to scan (None = all configured)"},
                {"option": "skip_accounts", "type": "list", "default": [], "description": "Account IDs to skip"},
                {"option": "include_disabled", "type": "bool", "default": False, "description": "Include disabled accounts in scan"},
            ]
            return HandlerResponse.success({
                "options": options,
                "total": len(options),
            })
        except Exception as e:
            logger.exception("Failed to list scan options")
            return HandlerResponse.server_error(str(e))

    @route("providers")
    def scan_providers(self, params: dict, body: dict | None) -> HandlerResponse:
        """List cloud providers."""
        try:
            providers = [
                {"provider": "aws", "name": "Amazon Web Services", "account_format": "12-digit account ID", "collectors": ["iam", "s3", "ec2", "security"]},
                {"provider": "gcp", "name": "Google Cloud Platform", "account_format": "Project ID", "collectors": ["iam", "storage", "compute", "security"]},
                {"provider": "azure", "name": "Microsoft Azure", "account_format": "Subscription ID", "collectors": ["identity", "storage", "compute", "security"]},
            ]
            return HandlerResponse.success({
                "providers": providers,
                "total": len(providers),
            })
        except Exception as e:
            logger.exception("Failed to list providers")
            return HandlerResponse.server_error(str(e))

    @route("stats")
    def scan_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show scanning statistics."""
        try:
            result = {
                "account_statuses": 5,
                "scan_options": 8,
                "cloud_providers": 3,
                "features": {
                    "parallel_execution": True,
                    "progress_tracking": True,
                    "cross_account_aggregation": True,
                    "timeout_handling": True,
                    "error_recovery": True,
                },
                "default_settings": {
                    "parallel_accounts": 3,
                    "timeout_per_account": 300,
                    "continue_on_error": True,
                },
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get scan stats")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Scanner Module GET endpoints
    # =========================================================================

    @route("scanners")
    def scan_scanners(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available vulnerability scanners."""
        try:
            scanners = [
                {
                    "id": "trivy",
                    "name": "Trivy",
                    "description": "Comprehensive vulnerability scanner by Aqua Security",
                    "available": True,
                    "version": "0.48.0",
                    "install": "brew install trivy",
                    "supported_targets": ["container_images", "filesystems", "git_repos"],
                },
                {
                    "id": "grype",
                    "name": "Grype",
                    "description": "Vulnerability scanner by Anchore (not yet implemented)",
                    "available": False,
                    "version": None,
                    "install": "brew install grype",
                    "supported_targets": ["container_images", "filesystems"],
                },
            ]

            return HandlerResponse.success({
                "scanners": scanners,
                "total": len(scanners),
                "available": sum(1 for s in scanners if s["available"]),
            })
        except Exception as e:
            logger.exception("Failed to list scanners")
            return HandlerResponse.server_error(str(e))

    @route("scanner/check")
    def scan_scanner_check(self, params: dict, body: dict | None) -> HandlerResponse:
        """Check if scanner is available."""
        try:
            # Demo response - in real impl would check TrivyScanner
            result = {
                "scanner": "trivy",
                "available": True,
                "version": "0.48.0",
                "message": "Trivy is installed and available",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to check scanner")
            return HandlerResponse.server_error(str(e))

    @route("severity-levels")
    def scan_severity_levels(self, params: dict, body: dict | None) -> HandlerResponse:
        """List vulnerability severity levels."""
        try:
            levels = [
                {
                    "level": "CRITICAL",
                    "description": "Severe vulnerability requiring immediate attention",
                    "cvss_range": "9.0 - 10.0",
                    "examples": "Remote code execution, authentication bypass",
                },
                {
                    "level": "HIGH",
                    "description": "High-impact vulnerability requiring prompt remediation",
                    "cvss_range": "7.0 - 8.9",
                    "examples": "Privilege escalation, sensitive data exposure",
                },
                {
                    "level": "MEDIUM",
                    "description": "Moderate vulnerability requiring scheduled remediation",
                    "cvss_range": "4.0 - 6.9",
                    "examples": "Cross-site scripting, information disclosure",
                },
                {
                    "level": "LOW",
                    "description": "Low-impact vulnerability for opportunistic fixing",
                    "cvss_range": "0.1 - 3.9",
                    "examples": "Minor information leaks, DoS with limited impact",
                },
                {
                    "level": "UNKNOWN",
                    "description": "Severity not determined",
                    "cvss_range": "N/A",
                    "examples": "Newly published CVEs without scoring",
                },
            ]

            return HandlerResponse.success({
                "levels": levels,
                "total": len(levels),
            })
        except Exception as e:
            logger.exception("Failed to list severity levels")
            return HandlerResponse.server_error(str(e))

    @route("priority-factors")
    def scan_priority_factors(self, params: dict, body: dict | None) -> HandlerResponse:
        """List vulnerability priority scoring factors."""
        try:
            factors = [
                {
                    "factor": "Severity",
                    "max_points": 40,
                    "description": "Base score from vulnerability severity (CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10)",
                },
                {
                    "factor": "CVSS Score",
                    "max_points": 20,
                    "description": "Contribution from CVSS score (score * 2, capped at 20)",
                },
                {
                    "factor": "EPSS Score",
                    "max_points": 20,
                    "description": "Exploit prediction score (probability * 20)",
                },
                {
                    "factor": "KEV Catalog",
                    "max_points": 20,
                    "description": "In CISA Known Exploited Vulnerabilities catalog",
                },
                {
                    "factor": "Ransomware Use",
                    "max_points": 10,
                    "description": "Known use in ransomware campaigns (requires KEV)",
                },
                {
                    "factor": "Fix Available",
                    "max_points": 5,
                    "description": "Fixed version is available",
                },
            ]

            return HandlerResponse.success({
                "factors": factors,
                "max_score": 100,
            })
        except Exception as e:
            logger.exception("Failed to list priority factors")
            return HandlerResponse.server_error(str(e))

    @route("package-types")
    def scan_package_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List supported package types for scanning."""
        try:
            package_types = [
                {"type": "apk", "ecosystem": "Alpine Linux", "description": "Alpine Package Keeper"},
                {"type": "deb", "ecosystem": "Debian/Ubuntu", "description": "Debian packages"},
                {"type": "rpm", "ecosystem": "RHEL/CentOS/Fedora", "description": "RPM packages"},
                {"type": "gem", "ecosystem": "Ruby", "description": "RubyGems"},
                {"type": "npm", "ecosystem": "Node.js", "description": "NPM packages"},
                {"type": "pip", "ecosystem": "Python", "description": "PyPI packages"},
                {"type": "cargo", "ecosystem": "Rust", "description": "Cargo crates"},
                {"type": "go", "ecosystem": "Go", "description": "Go modules"},
                {"type": "composer", "ecosystem": "PHP", "description": "Composer packages"},
                {"type": "nuget", "ecosystem": "C#/.NET", "description": "NuGet packages"},
                {"type": "maven", "ecosystem": "Java", "description": "Maven artifacts"},
                {"type": "gradle", "ecosystem": "Java", "description": "Gradle dependencies"},
            ]

            return HandlerResponse.success({
                "package_types": package_types,
                "total": len(package_types),
            })
        except Exception as e:
            logger.exception("Failed to list package types")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Scan Execution POST endpoints
    # =========================================================================

    @route("start", methods=["POST"])
    def scan_start(self, params: dict, body: dict | None) -> HandlerResponse:
        """Start a new scan."""
        try:
            data = body or {}
            config_name = data.get("config", "default")
            accounts = data.get("accounts", [])
            collectors = data.get("collectors", [])
            parallel = data.get("parallel", 3)

            # Demo response - in real impl would start scan
            result = {
                "success": True,
                "scan_id": "scan-new-001",
                "status": "pending",
                "config": config_name,
                "accounts": accounts if accounts else "all",
                "collectors": collectors if collectors else "all",
                "options": {
                    "parallel_accounts": parallel,
                    "timeout_per_account": 300,
                    "continue_on_error": True,
                },
                "message": "Scan started successfully",
            }
            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to start scan")
            return HandlerResponse.server_error(str(e))

    @route("stop", methods=["POST"])
    def scan_stop(self, params: dict, body: dict | None) -> HandlerResponse:
        """Stop a running scan."""
        try:
            data = body or {}
            scan_id = data.get("scan_id", "")

            if not scan_id:
                return HandlerResponse.error("Missing required field: scan_id", HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "scan_id": scan_id,
                "status": "canceled",
                "message": f"Scan {scan_id} stopped",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to stop scan")
            return HandlerResponse.server_error(str(e))

    @route("pause", methods=["POST"])
    def scan_pause(self, params: dict, body: dict | None) -> HandlerResponse:
        """Pause a running scan."""
        try:
            data = body or {}
            scan_id = data.get("scan_id", "")

            if not scan_id:
                return HandlerResponse.error("Missing required field: scan_id", HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "scan_id": scan_id,
                "status": "paused",
                "message": f"Scan {scan_id} paused",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to pause scan")
            return HandlerResponse.server_error(str(e))

    @route("resume", methods=["POST"])
    def scan_resume(self, params: dict, body: dict | None) -> HandlerResponse:
        """Resume a paused scan."""
        try:
            data = body or {}
            scan_id = data.get("scan_id", "")

            if not scan_id:
                return HandlerResponse.error("Missing required field: scan_id", HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "scan_id": scan_id,
                "status": "running",
                "message": f"Scan {scan_id} resumed",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to resume scan")
            return HandlerResponse.server_error(str(e))

    @route("enrich", methods=["POST"])
    def scan_enrich(self, params: dict, body: dict | None) -> HandlerResponse:
        """Enrich CVE with EPSS and KEV data."""
        try:
            data = body or {}
            cve_id = data.get("cve_id", "").upper()

            if not cve_id:
                return HandlerResponse.error("Missing required field: cve_id", HttpStatus.BAD_REQUEST)

            if not cve_id.startswith("CVE-"):
                return HandlerResponse.error("Invalid CVE ID format. Expected CVE-YYYY-NNNNN", HttpStatus.BAD_REQUEST)

            # Demo enrichment response
            result = {
                "cve_id": cve_id,
                "epss": {
                    "score": 0.75,
                    "percentile": 95.0,
                    "date": "2024-12-30",
                },
                "kev": {
                    "in_catalog": True,
                    "vendor": "Microsoft",
                    "product": "Windows",
                    "date_added": "2024-01-15",
                    "due_date": "2024-02-15",
                    "ransomware_use": True,
                },
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to enrich CVE")
            return HandlerResponse.server_error(str(e))

    @route("vulnerability", methods=["POST"])
    def scan_vulnerability(self, params: dict, body: dict | None) -> HandlerResponse:
        """Scan for vulnerabilities."""
        try:
            data = body or {}
            target = data.get("target", "")
            target_type = data.get("type", "image")

            if not target:
                return HandlerResponse.error("Missing required field: target", HttpStatus.BAD_REQUEST)

            # Demo vulnerability scan response
            result = {
                "success": True,
                "target": target,
                "type": target_type,
                "scan_id": "vuln-scan-001",
                "status": "completed",
                "summary": {
                    "total_vulnerabilities": 15,
                    "critical": 2,
                    "high": 5,
                    "medium": 6,
                    "low": 2,
                },
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-1234",
                        "severity": "CRITICAL",
                        "package": "openssl",
                        "installed_version": "1.1.1",
                        "fixed_version": "1.1.2",
                    },
                    {
                        "id": "CVE-2024-5678",
                        "severity": "HIGH",
                        "package": "curl",
                        "installed_version": "7.80.0",
                        "fixed_version": "7.85.0",
                    },
                ],
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to scan for vulnerabilities")
            return HandlerResponse.server_error(str(e))
