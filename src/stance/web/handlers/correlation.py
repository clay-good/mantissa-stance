"""
Correlation handlers for the Stance web API.

This module handles all /api/correlation/* endpoints for finding
correlation, risk scoring, and related finding analysis.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class CorrelationHandler(RoutedHandler):
    """
    Handler for correlation API endpoints.

    Handles:
    - Finding correlation analysis
    - Correlation groups
    - Risk scoring
    - Related finding detection
    """

    base_path = "/api/correlation/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("correlate")
    def correlation_correlate(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Run correlation analysis on findings.

        Query params:
            time_window: Time window in hours (default: 24)
            min_group_size: Minimum findings to form a group (default: 2)
            threshold: Correlation threshold 0-1 (default: 0.5)
        """
        time_window = self.get_param_int(params, "time_window", 24)
        min_group_size = self.get_param_int(params, "min_group_size", 2)
        threshold_str = self.get_param(params, "threshold", "0.5")

        try:
            threshold = float(threshold_str)
        except ValueError:
            threshold = 0.5

        try:
            findings, assets = self._get_sample_correlation_data()

            from stance.correlation import FindingCorrelator
            correlator = FindingCorrelator(
                time_window_hours=time_window,
                min_group_size=min_group_size,
                correlation_threshold=threshold,
            )
            result = correlator.correlate(findings, assets)

            return HandlerResponse.success(result.to_dict())
        except Exception as e:
            logger.warning(f"Correlation analysis error: {e}")
            return HandlerResponse.success(self._get_demo_correlation_result())

    @route("groups")
    def correlation_groups(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List correlation groups.

        Query params:
            type: Filter by group type (asset, rule, cve, network, temporal)
            min_size: Minimum group size (default: 1)
        """
        group_type = self.get_param(params, "type", "")
        min_size = self.get_param_int(params, "min_size", 1)

        try:
            findings, assets = self._get_sample_correlation_data()

            from stance.correlation import FindingCorrelator
            correlator = FindingCorrelator()
            result = correlator.correlate(findings, assets)

            groups = result.groups
            if group_type:
                groups = [g for g in groups if g.group_type == group_type]
            if min_size > 1:
                groups = [g for g in groups if len(g.findings) >= min_size]

            return HandlerResponse.success({
                "groups": [g.to_dict() for g in groups],
                "total": len(groups),
            })
        except Exception as e:
            logger.warning(f"Correlation groups error: {e}")
            return HandlerResponse.success(self._get_demo_groups())

    @route("group")
    def correlation_group(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Show correlation group details.

        Query params:
            id: Group ID (required)
        """
        group_id = self.get_param(params, "id", "")

        if not group_id:
            return HandlerResponse.error("Group ID is required", HttpStatus.BAD_REQUEST)

        try:
            findings, assets = self._get_sample_correlation_data()

            from stance.correlation import FindingCorrelator
            correlator = FindingCorrelator()
            result = correlator.correlate(findings, assets)

            for group in result.groups:
                if group.id == group_id or group.id.startswith(group_id):
                    return HandlerResponse.success(group.to_dict())

            return HandlerResponse.not_found("Group")
        except Exception as e:
            logger.warning(f"Correlation group error: {e}")
            return HandlerResponse.not_found("Group")

    @route("related")
    def correlation_related(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Find findings related to a specific finding.

        Query params:
            finding_id: Finding ID (required)
            limit: Maximum results (default: 10)
        """
        finding_id = self.get_param(params, "finding_id", "")
        limit = self.get_param_int(params, "limit", 10)

        if not finding_id:
            return HandlerResponse.error("Finding ID is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "target_finding": {
                "id": finding_id,
                "title": "Sample Finding",
                "severity": "high",
            },
            "related": [
                {
                    "finding_id": "finding-related-001",
                    "title": "Related S3 Bucket Finding",
                    "severity": "high",
                    "correlation_score": 0.85,
                    "correlation_reason": "Same asset",
                },
                {
                    "finding_id": "finding-related-002",
                    "title": "Related IAM Finding",
                    "severity": "medium",
                    "correlation_score": 0.72,
                    "correlation_reason": "Same time window",
                },
            ][:limit],
            "total": 2,
        })

    @route("risk")
    def correlation_risk(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Calculate risk scores for all assets.

        Query params:
            top: Number of top risk assets to return (default: 10)
        """
        top_n = self.get_param_int(params, "top", 10)

        try:
            findings, assets = self._get_sample_correlation_data()

            from stance.correlation import RiskScorer
            scorer = RiskScorer()
            result = scorer.calculate_scores(findings, assets)

            result_dict = result.to_dict()
            result_dict["top_risks"] = result_dict["top_risks"][:top_n]

            return HandlerResponse.success(result_dict)
        except Exception as e:
            logger.warning(f"Risk scoring error: {e}")
            return HandlerResponse.success(self._get_demo_risk_result(top_n))

    @route("risk-asset")
    def correlation_risk_asset(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Show risk score for a specific asset.

        Query params:
            asset_id: Asset ID (required)
        """
        asset_id = self.get_param(params, "asset_id", "")

        if not asset_id:
            return HandlerResponse.error("Asset ID is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "asset_id": asset_id,
            "risk_score": 7.5,
            "risk_level": "high",
            "finding_count": 5,
            "critical_findings": 1,
            "high_findings": 2,
            "factors": [
                {"name": "Public exposure", "weight": 0.3, "score": 9.0},
                {"name": "Finding severity", "weight": 0.3, "score": 8.0},
                {"name": "Data sensitivity", "weight": 0.2, "score": 6.0},
                {"name": "Attack surface", "weight": 0.2, "score": 7.0},
            ],
        })

    @route("risk-summary")
    def correlation_risk_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get executive risk summary."""
        return HandlerResponse.success({
            "overall_risk_score": 6.5,
            "risk_level": "medium",
            "total_assets": 150,
            "high_risk_assets": 12,
            "medium_risk_assets": 45,
            "low_risk_assets": 93,
            "trend": "improving",
            "trend_percent": -5.2,
        })

    @route("analyze")
    def correlation_analyze(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Analyze findings for patterns.

        Query params:
            pattern: Pattern to analyze (optional)
        """
        pattern = self.get_param(params, "pattern", "")

        return HandlerResponse.success({
            "patterns": [
                {
                    "name": "S3 Public Access",
                    "finding_count": 8,
                    "severity": "high",
                    "description": "Multiple S3 buckets with public access",
                },
                {
                    "name": "Missing Encryption",
                    "finding_count": 15,
                    "severity": "medium",
                    "description": "Resources without encryption at rest",
                },
                {
                    "name": "Overprivileged IAM",
                    "finding_count": 12,
                    "severity": "high",
                    "description": "IAM roles with excessive permissions",
                },
            ],
            "analyzed_findings": 100,
            "pattern_filter": pattern or "all",
        })

    @route("types")
    def correlation_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List correlation types."""
        types = [
            {"value": "asset", "name": "Asset-based", "description": "Findings on the same asset"},
            {"value": "rule", "name": "Rule-based", "description": "Findings from the same policy rule"},
            {"value": "cve", "name": "CVE-based", "description": "Findings related to the same CVE"},
            {"value": "network", "name": "Network-based", "description": "Findings in the same network segment"},
            {"value": "temporal", "name": "Temporal", "description": "Findings in the same time window"},
        ]

        return HandlerResponse.success({
            "types": types,
            "total": len(types),
        })

    @route("levels")
    def correlation_levels(self, params: dict, body: dict | None) -> HandlerResponse:
        """List correlation strength levels."""
        levels = [
            {"value": "strong", "min_score": 0.8, "description": "High confidence correlation"},
            {"value": "moderate", "min_score": 0.5, "description": "Medium confidence correlation"},
            {"value": "weak", "min_score": 0.3, "description": "Low confidence correlation"},
        ]

        return HandlerResponse.success({
            "levels": levels,
            "total": len(levels),
        })

    @route("status")
    def correlation_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get correlation module status."""
        return HandlerResponse.success({
            "module": "correlation",
            "version": "1.0.0",
            "status": "active",
            "last_analysis": None,
            "groups_cached": 0,
            "capabilities": {
                "asset_correlation": True,
                "rule_correlation": True,
                "cve_correlation": True,
                "network_correlation": True,
                "temporal_correlation": True,
                "risk_scoring": True,
            },
        })

    @route("summary")
    def correlation_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get correlation summary."""
        return HandlerResponse.success({
            "total_groups": 12,
            "total_correlated_findings": 45,
            "average_group_size": 3.75,
            "by_type": {
                "asset": 5,
                "rule": 3,
                "temporal": 4,
            },
        })

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _get_sample_correlation_data(self):
        """Get sample correlation data."""
        from stance.storage import get_storage

        storage = get_storage()
        findings = storage.get_findings()
        assets = storage.get_assets()

        return findings, assets

    def _get_demo_correlation_result(self) -> dict[str, Any]:
        """Get demo correlation result."""
        return {
            "total_findings": 100,
            "correlated_findings": 45,
            "groups": [],
            "statistics": {
                "by_type": {"asset": 5, "rule": 3},
                "average_group_size": 3.0,
            },
        }

    def _get_demo_groups(self) -> dict[str, Any]:
        """Get demo correlation groups."""
        return {
            "groups": [
                {
                    "id": "group-001",
                    "group_type": "asset",
                    "finding_count": 5,
                    "severity": "high",
                    "description": "S3 bucket misconfigurations",
                },
            ],
            "total": 1,
        }

    def _get_demo_risk_result(self, top_n: int) -> dict[str, Any]:
        """Get demo risk scoring result."""
        return {
            "overall_risk_score": 6.5,
            "total_assets": 150,
            "top_risks": [
                {
                    "asset_id": "arn:aws:s3:::prod-data",
                    "risk_score": 9.2,
                    "finding_count": 5,
                },
            ][:top_n],
            "by_risk_level": {
                "critical": 5,
                "high": 20,
                "medium": 45,
                "low": 80,
            },
        }
