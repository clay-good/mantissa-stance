"""
Scanner handlers for the Stance web API.

This module handles all /api/scanner/* endpoints for vulnerability
scanning and CVE enrichment.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class ScannerHandler(RoutedHandler):
    """
    Handler for scanner API endpoints.

    Handles:
    - Vulnerability scanner management
    - CVE enrichment (EPSS, KEV)
    - Severity and priority scoring
    """

    base_path = "/api/scanner/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("scanners")
    def scanner_scanners(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available vulnerability scanners."""
        try:
            from stance.scanner import TrivyScanner

            scanner = TrivyScanner()
            trivy_available = scanner.is_available()
            trivy_version = scanner.get_version() if trivy_available else None

            scanners = [
                {
                    "id": "trivy",
                    "name": "Trivy",
                    "description": "Comprehensive vulnerability scanner by Aqua Security",
                    "available": trivy_available,
                    "version": trivy_version,
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
                "total": len(scanners),
                "available": sum(1 for s in scanners if s["available"]),
                "scanners": scanners,
            })
        except ImportError as e:
            return HandlerResponse.error(f"Scanner module not available: {e}")

    @route("check")
    def scanner_check(self, params: dict, body: dict | None) -> HandlerResponse:
        """Check if scanner is available."""
        try:
            from stance.scanner import TrivyScanner

            scanner = TrivyScanner()
            is_available = scanner.is_available()
            version = scanner.get_version() if is_available else None

            return HandlerResponse.success({
                "scanner": "trivy",
                "available": is_available,
                "version": version,
                "message": "Trivy is installed and available" if is_available else "Trivy is not installed",
            })
        except ImportError as e:
            return HandlerResponse.error(f"Scanner module not available: {e}")

    @route("version")
    def scanner_version(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get scanner version."""
        try:
            from stance.scanner import TrivyScanner

            scanner = TrivyScanner()
            version = scanner.get_version()

            return HandlerResponse.success({
                "scanner": "trivy",
                "version": version,
                "available": version is not None,
            })
        except ImportError as e:
            return HandlerResponse.error(f"Scanner module not available: {e}")

    @route("enrich")
    def scanner_enrich(self, params: dict, body: dict | None) -> HandlerResponse:
        """Enrich CVE with EPSS and KEV data."""
        cve_id = self.get_param(params, "cve_id", "").upper()
        if not cve_id:
            return HandlerResponse.error("cve_id parameter is required", HttpStatus.BAD_REQUEST)
        if not cve_id.startswith("CVE-"):
            return HandlerResponse.error("Invalid CVE ID format. Expected CVE-YYYY-NNNNN", HttpStatus.BAD_REQUEST)

        try:
            from stance.scanner import CVEEnricher

            enricher = CVEEnricher()
            epss = enricher._get_epss_score(cve_id)
            kev = enricher._get_kev_entry(cve_id)

            return HandlerResponse.success({
                "cve_id": cve_id,
                "epss": {
                    "score": epss.epss if epss else None,
                    "percentile": epss.percentile if epss else None,
                    "date": epss.date if epss else None,
                } if epss else None,
                "kev": {
                    "in_catalog": kev is not None,
                    "vendor": kev.vendor_project if kev else None,
                    "product": kev.product if kev else None,
                    "date_added": kev.date_added if kev else None,
                    "due_date": kev.due_date if kev else None,
                    "ransomware_use": kev.known_ransomware_campaign_use if kev else None,
                } if kev else {"in_catalog": False},
            })
        except ImportError as e:
            return HandlerResponse.error(f"Scanner module not available: {e}")

    @route("epss")
    def scanner_epss(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get EPSS score for a CVE."""
        cve_id = self.get_param(params, "cve_id", "").upper()
        if not cve_id:
            return HandlerResponse.error("cve_id parameter is required", HttpStatus.BAD_REQUEST)
        if not cve_id.startswith("CVE-"):
            return HandlerResponse.error("Invalid CVE ID format. Expected CVE-YYYY-NNNNN", HttpStatus.BAD_REQUEST)

        try:
            from stance.scanner import CVEEnricher

            enricher = CVEEnricher()
            enricher._batch_fetch_epss([cve_id])
            epss = enricher._get_epss_score(cve_id)

            return HandlerResponse.success({
                "cve_id": cve_id,
                "found": epss is not None,
                "score": epss.epss if epss else None,
                "percentile": epss.percentile if epss else None,
                "date": epss.date if epss else None,
            })
        except ImportError as e:
            return HandlerResponse.error(f"Scanner module not available: {e}")

    @route("kev")
    def scanner_kev(self, params: dict, body: dict | None) -> HandlerResponse:
        """Check if CVE is in CISA KEV catalog."""
        cve_id = self.get_param(params, "cve_id", "").upper()
        if not cve_id:
            return HandlerResponse.error("cve_id parameter is required", HttpStatus.BAD_REQUEST)
        if not cve_id.startswith("CVE-"):
            return HandlerResponse.error("Invalid CVE ID format. Expected CVE-YYYY-NNNNN", HttpStatus.BAD_REQUEST)

        try:
            from stance.scanner import CVEEnricher

            enricher = CVEEnricher()
            kev = enricher._get_kev_entry(cve_id)

            result: dict[str, Any] = {
                "cve_id": cve_id,
                "in_catalog": kev is not None,
            }

            if kev:
                result.update({
                    "vendor": kev.vendor_project,
                    "product": kev.product,
                    "vulnerability_name": kev.vulnerability_name,
                    "date_added": kev.date_added,
                    "short_description": kev.short_description,
                    "required_action": kev.required_action,
                    "due_date": kev.due_date,
                    "ransomware_use": kev.known_ransomware_campaign_use,
                })

            return HandlerResponse.success(result)
        except ImportError as e:
            return HandlerResponse.error(f"Scanner module not available: {e}")

    @route("severity-levels")
    def scanner_severity_levels(self, params: dict, body: dict | None) -> HandlerResponse:
        """List vulnerability severity levels."""
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
            "total": len(levels),
            "levels": levels,
        })

    @route("priority-factors")
    def scanner_priority_factors(self, params: dict, body: dict | None) -> HandlerResponse:
        """List vulnerability priority scoring factors."""
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
            "max_score": 100,
            "factors": factors,
        })

    @route("package-types")
    def scanner_package_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List supported package types for scanning."""
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
            "total": len(package_types),
            "package_types": package_types,
        })

    @route("stats")
    def scanner_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show scanner statistics."""
        try:
            from stance.scanner import TrivyScanner

            scanner = TrivyScanner()
            is_available = scanner.is_available()
            version = scanner.get_version() if is_available else None

            return HandlerResponse.success({
                "scanner": "trivy",
                "available": is_available,
                "version": version,
                "severity_levels": 5,
                "package_types": 12,
                "enrichment_sources": ["EPSS", "KEV"],
                "priority_factors": 6,
                "supported_targets": [
                    "container_images",
                    "filesystems",
                    "git_repos",
                    "kubernetes",
                ],
            })
        except ImportError as e:
            return HandlerResponse.error(f"Scanner module not available: {e}")

    @route("status")
    def scanner_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show scanner module status."""
        try:
            from stance.scanner import TrivyScanner

            scanner = TrivyScanner()
            is_available = scanner.is_available()
            version = scanner.get_version() if is_available else None

            return HandlerResponse.success({
                "module": "scanner",
                "status": "operational" if is_available else "degraded",
                "components": {
                    "TrivyScanner": "available" if is_available else "not_installed",
                    "CVEEnricher": "available",
                    "EPSSClient": "available",
                    "KEVClient": "available",
                },
                "capabilities": [
                    "container_image_scanning",
                    "vulnerability_detection",
                    "cve_enrichment",
                    "epss_scoring",
                    "kev_lookup",
                    "priority_calculation",
                    "batch_scanning",
                ],
                "scanner_version": version,
            })
        except ImportError as e:
            return HandlerResponse.error(f"Scanner module not available: {e}")

    @route("summary")
    def scanner_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get comprehensive scanner module summary."""
        try:
            from stance.scanner import TrivyScanner

            scanner = TrivyScanner()
            is_available = scanner.is_available()
            version = scanner.get_version() if is_available else None

            return HandlerResponse.success({
                "module": "scanner",
                "version": "1.0.0",
                "description": "Container image vulnerability scanning with CVE enrichment",
                "scanner": {
                    "name": "Trivy",
                    "available": is_available,
                    "version": version,
                },
                "enrichment": {
                    "epss": "Exploit Prediction Scoring System from FIRST.org",
                    "kev": "CISA Known Exploited Vulnerabilities catalog",
                },
                "features": [
                    "Trivy-based container image scanning",
                    "Vulnerability detection for 12 package types",
                    "EPSS exploit probability scoring",
                    "CISA KEV catalog integration",
                    "Priority-based vulnerability ranking",
                    "Batch image scanning",
                    "JSON and SARIF output formats",
                    "Fixable vulnerability filtering",
                ],
                "supported_ecosystems": [
                    "Alpine (apk)", "Debian/Ubuntu (deb)", "RHEL/CentOS (rpm)",
                    "Node.js (npm)", "Python (pip)", "Ruby (gem)",
                    "Go (modules)", "Rust (cargo)", "Java (maven/gradle)",
                    "PHP (composer)", ".NET (nuget)",
                ],
            })
        except ImportError as e:
            return HandlerResponse.error(f"Scanner module not available: {e}")
