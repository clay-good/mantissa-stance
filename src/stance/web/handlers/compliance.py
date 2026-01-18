"""
Compliance management handlers for the Stance web API.

This module handles all /api/compliance/* endpoints for compliance operations
including framework management, control scoring, compliance reports, trends,
and gap analysis functionality.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class ComplianceHandler(RoutedHandler):
    """
    Handler for compliance management API endpoints.

    Handles:
    - Compliance framework listing and details
    - Compliance scoring and assessment
    - Control status and gap analysis
    - Compliance reports and exports
    - Compliance trends and history
    - Framework mappings and benchmarks
    """

    base_path = "/api/compliance/"

    # =========================================================================
    # Compliance Scoring GET endpoints
    # =========================================================================

    @route("list")
    def compliance_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List compliance scores across all frameworks."""
        try:
            framework_filter = self.get_param(params, "framework", "")

            # Demo compliance data
            frameworks = [
                {
                    "framework_id": "cis-aws",
                    "framework_name": "CIS AWS Foundations Benchmark",
                    "version": "2.0",
                    "score_percentage": 78.5,
                    "controls_passed": 47,
                    "controls_failed": 13,
                    "controls_total": 60,
                },
                {
                    "framework_id": "pci-dss",
                    "framework_name": "PCI DSS",
                    "version": "4.0",
                    "score_percentage": 85.0,
                    "controls_passed": 51,
                    "controls_failed": 9,
                    "controls_total": 60,
                },
                {
                    "framework_id": "soc2",
                    "framework_name": "SOC 2 Type II",
                    "version": "2017",
                    "score_percentage": 72.0,
                    "controls_passed": 36,
                    "controls_failed": 14,
                    "controls_total": 50,
                },
                {
                    "framework_id": "hipaa",
                    "framework_name": "HIPAA Security Rule",
                    "version": "2013",
                    "score_percentage": 68.5,
                    "controls_passed": 29,
                    "controls_failed": 13,
                    "controls_total": 42,
                },
                {
                    "framework_id": "nist-800-53",
                    "framework_name": "NIST 800-53 Rev 5",
                    "version": "Rev 5",
                    "score_percentage": 62.0,
                    "controls_passed": 202,
                    "controls_failed": 123,
                    "controls_total": 325,
                },
            ]

            if framework_filter:
                frameworks = [f for f in frameworks if framework_filter.lower() in f["framework_id"].lower()]

            total_controls = sum(f["controls_total"] for f in frameworks)
            total_passed = sum(f["controls_passed"] for f in frameworks)
            overall_score = (total_passed / total_controls * 100) if total_controls > 0 else 100.0

            return HandlerResponse.success({
                "overall_score": round(overall_score, 1),
                "frameworks": frameworks,
                "total_frameworks": len(frameworks),
            })
        except Exception as e:
            logger.exception("Failed to list compliance scores")
            return HandlerResponse.server_error(str(e))

    @route("show")
    def compliance_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get detailed compliance information for a specific framework."""
        try:
            framework_id = self.get_param(params, "framework_id", "")

            if not framework_id:
                return HandlerResponse.error("framework_id parameter required", HttpStatus.BAD_REQUEST)

            # Demo framework details
            result = {
                "framework": {
                    "id": framework_id,
                    "name": "CIS AWS Foundations Benchmark",
                    "version": "2.0",
                    "description": "Security best practices for AWS cloud infrastructure",
                    "score_percentage": 78.5,
                    "controls_passed": 47,
                    "controls_failed": 13,
                    "controls_total": 60,
                    "last_assessed": "2024-12-30T10:00:00Z",
                },
                "controls": [
                    {
                        "control_id": "1.1",
                        "control_name": "Maintain current contact details",
                        "status": "PASSED",
                        "resources_evaluated": 1,
                        "resources_compliant": 1,
                        "resources_non_compliant": 0,
                    },
                    {
                        "control_id": "1.2",
                        "control_name": "Ensure MFA is enabled for root account",
                        "status": "PASSED",
                        "resources_evaluated": 1,
                        "resources_compliant": 1,
                        "resources_non_compliant": 0,
                    },
                    {
                        "control_id": "1.3",
                        "control_name": "Ensure credentials unused > 90 days are disabled",
                        "status": "FAILED",
                        "resources_evaluated": 15,
                        "resources_compliant": 12,
                        "resources_non_compliant": 3,
                    },
                    {
                        "control_id": "2.1",
                        "control_name": "Ensure CloudTrail is enabled in all regions",
                        "status": "PASSED",
                        "resources_evaluated": 3,
                        "resources_compliant": 3,
                        "resources_non_compliant": 0,
                    },
                    {
                        "control_id": "2.2",
                        "control_name": "Ensure CloudTrail log validation is enabled",
                        "status": "FAILED",
                        "resources_evaluated": 3,
                        "resources_compliant": 1,
                        "resources_non_compliant": 2,
                    },
                ],
                "summary": {
                    "passed_percentage": 78.5,
                    "critical_failures": 3,
                    "high_failures": 5,
                    "medium_failures": 5,
                },
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get compliance details")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Framework Management endpoints
    # =========================================================================

    @route("frameworks")
    def compliance_frameworks(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available compliance frameworks."""
        try:
            enabled_only = self.get_param(params, "enabled", "").lower() == "true"

            frameworks = [
                {
                    "id": "cis-aws",
                    "name": "CIS AWS Foundations Benchmark",
                    "version": "2.0",
                    "controls_count": 60,
                    "policies_mapped": 45,
                    "enabled": True,
                    "category": "Infrastructure Security",
                },
                {
                    "id": "cis-gcp",
                    "name": "CIS GCP Foundations Benchmark",
                    "version": "2.0",
                    "controls_count": 65,
                    "policies_mapped": 41,
                    "enabled": True,
                    "category": "Infrastructure Security",
                },
                {
                    "id": "cis-azure",
                    "name": "CIS Azure Foundations Benchmark",
                    "version": "2.0",
                    "controls_count": 112,
                    "policies_mapped": 47,
                    "enabled": True,
                    "category": "Infrastructure Security",
                },
                {
                    "id": "pci-dss",
                    "name": "PCI DSS",
                    "version": "4.0",
                    "controls_count": 60,
                    "policies_mapped": 52,
                    "enabled": True,
                    "category": "Data Security",
                },
                {
                    "id": "soc2",
                    "name": "SOC 2 Type II",
                    "version": "2017",
                    "controls_count": 50,
                    "policies_mapped": 34,
                    "enabled": True,
                    "category": "Trust Services",
                },
                {
                    "id": "hipaa",
                    "name": "HIPAA Security Rule",
                    "version": "2013",
                    "controls_count": 42,
                    "policies_mapped": 24,
                    "enabled": False,
                    "category": "Healthcare",
                },
                {
                    "id": "nist-800-53",
                    "name": "NIST 800-53 Rev 5",
                    "version": "Rev 5",
                    "controls_count": 325,
                    "policies_mapped": 75,
                    "enabled": False,
                    "category": "Government",
                },
            ]

            if enabled_only:
                frameworks = [f for f in frameworks if f["enabled"]]

            return HandlerResponse.success({
                "frameworks": frameworks,
                "total": len(frameworks),
            })
        except Exception as e:
            logger.exception("Failed to list frameworks")
            return HandlerResponse.server_error(str(e))

    @route("framework")
    def compliance_framework(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get framework metadata and configuration."""
        try:
            framework_id = self.get_param(params, "framework_id", "")

            if not framework_id:
                return HandlerResponse.error("framework_id parameter required", HttpStatus.BAD_REQUEST)

            result = {
                "id": framework_id,
                "name": "CIS AWS Foundations Benchmark",
                "version": "2.0",
                "description": "The CIS AWS Foundations Benchmark provides prescriptive guidance for configuring security options for AWS.",
                "publisher": "Center for Internet Security",
                "last_updated": "2024-06-15",
                "controls_count": 60,
                "policies_mapped": 45,
                "enabled": True,
                "category": "Infrastructure Security",
                "sections": [
                    {"id": "1", "name": "Identity and Access Management", "controls_count": 22},
                    {"id": "2", "name": "Logging", "controls_count": 9},
                    {"id": "3", "name": "Monitoring", "controls_count": 15},
                    {"id": "4", "name": "Networking", "controls_count": 8},
                    {"id": "5", "name": "Storage", "controls_count": 6},
                ],
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get framework details")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Control Management endpoints
    # =========================================================================

    @route("controls")
    def compliance_controls(self, params: dict, body: dict | None) -> HandlerResponse:
        """List controls for a framework."""
        try:
            framework_id = self.get_param(params, "framework_id", "")
            status_filter = self.get_param(params, "status", "")
            section = self.get_param(params, "section", "")

            controls = [
                {
                    "control_id": "1.1",
                    "framework_id": "cis-aws",
                    "section": "1",
                    "name": "Maintain current contact details",
                    "description": "Ensure contact email and phone are up to date",
                    "status": "PASSED",
                    "severity": "LOW",
                    "resources_evaluated": 1,
                    "resources_compliant": 1,
                    "resources_non_compliant": 0,
                },
                {
                    "control_id": "1.2",
                    "framework_id": "cis-aws",
                    "section": "1",
                    "name": "Ensure MFA is enabled for root account",
                    "description": "Root account should have MFA enabled",
                    "status": "PASSED",
                    "severity": "CRITICAL",
                    "resources_evaluated": 1,
                    "resources_compliant": 1,
                    "resources_non_compliant": 0,
                },
                {
                    "control_id": "1.3",
                    "framework_id": "cis-aws",
                    "section": "1",
                    "name": "Ensure credentials unused > 90 days are disabled",
                    "description": "Disable credentials not used in 90+ days",
                    "status": "FAILED",
                    "severity": "HIGH",
                    "resources_evaluated": 15,
                    "resources_compliant": 12,
                    "resources_non_compliant": 3,
                },
                {
                    "control_id": "2.1",
                    "framework_id": "cis-aws",
                    "section": "2",
                    "name": "Ensure CloudTrail is enabled in all regions",
                    "description": "CloudTrail should be enabled for all regions",
                    "status": "PASSED",
                    "severity": "HIGH",
                    "resources_evaluated": 3,
                    "resources_compliant": 3,
                    "resources_non_compliant": 0,
                },
                {
                    "control_id": "2.2",
                    "framework_id": "cis-aws",
                    "section": "2",
                    "name": "Ensure CloudTrail log validation is enabled",
                    "description": "Enable log file validation on CloudTrail",
                    "status": "FAILED",
                    "severity": "MEDIUM",
                    "resources_evaluated": 3,
                    "resources_compliant": 1,
                    "resources_non_compliant": 2,
                },
            ]

            if framework_id:
                controls = [c for c in controls if c["framework_id"] == framework_id]
            if status_filter:
                controls = [c for c in controls if c["status"] == status_filter.upper()]
            if section:
                controls = [c for c in controls if c["section"] == section]

            return HandlerResponse.success({
                "controls": controls,
                "total": len(controls),
            })
        except Exception as e:
            logger.exception("Failed to list controls")
            return HandlerResponse.server_error(str(e))

    @route("control")
    def compliance_control(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get detailed information for a specific control."""
        try:
            control_id = self.get_param(params, "control_id", "")
            framework_id = self.get_param(params, "framework_id", "cis-aws")

            if not control_id:
                return HandlerResponse.error("control_id parameter required", HttpStatus.BAD_REQUEST)

            result = {
                "control_id": control_id,
                "framework_id": framework_id,
                "name": "Ensure credentials unused > 90 days are disabled",
                "description": "AWS IAM users can access AWS resources using different types of credentials. It is recommended that all credentials that have been unused in 90 or greater days be deactivated or removed.",
                "rationale": "Disabling or removing unnecessary credentials will reduce the window of opportunity for credentials to be used.",
                "remediation": "From Console: 1. Login to the AWS Management Console. 2. Navigate to IAM. 3. Select Users. 4. Select the user. 5. Under Security credentials, disable or delete unused credentials.",
                "impact": "Low - May require users to re-enable credentials if needed",
                "status": "FAILED",
                "severity": "HIGH",
                "resources_evaluated": 15,
                "resources_compliant": 12,
                "resources_non_compliant": 3,
                "non_compliant_resources": [
                    {"id": "arn:aws:iam::123456789012:user/old-user-1", "name": "old-user-1", "reason": "Last used 120 days ago"},
                    {"id": "arn:aws:iam::123456789012:user/old-user-2", "name": "old-user-2", "reason": "Last used 95 days ago"},
                    {"id": "arn:aws:iam::123456789012:user/old-user-3", "name": "old-user-3", "reason": "Never used"},
                ],
                "mapped_policies": ["aws-iam-credential-rotation", "aws-iam-unused-credentials"],
                "references": [
                    {"title": "CIS AWS Benchmark v2.0", "url": "https://www.cisecurity.org/benchmark/amazon_web_services"},
                    {"title": "AWS IAM Best Practices", "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"},
                ],
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get control details")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Gap Analysis and Reports endpoints
    # =========================================================================

    @route("gaps")
    def compliance_gaps(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get compliance gaps analysis."""
        try:
            framework_id = self.get_param(params, "framework_id", "")
            severity = self.get_param(params, "severity", "")

            gaps = [
                {
                    "control_id": "1.3",
                    "framework_id": "cis-aws",
                    "framework_name": "CIS AWS Foundations Benchmark",
                    "control_name": "Ensure credentials unused > 90 days are disabled",
                    "severity": "HIGH",
                    "gap_count": 3,
                    "remediation_effort": "LOW",
                    "priority_score": 85,
                },
                {
                    "control_id": "2.2",
                    "framework_id": "cis-aws",
                    "framework_name": "CIS AWS Foundations Benchmark",
                    "control_name": "Ensure CloudTrail log validation is enabled",
                    "severity": "MEDIUM",
                    "gap_count": 2,
                    "remediation_effort": "LOW",
                    "priority_score": 70,
                },
                {
                    "control_id": "3.1",
                    "framework_id": "pci-dss",
                    "framework_name": "PCI DSS",
                    "control_name": "Install and maintain firewall configuration",
                    "severity": "HIGH",
                    "gap_count": 5,
                    "remediation_effort": "MEDIUM",
                    "priority_score": 80,
                },
                {
                    "control_id": "4.1",
                    "framework_id": "soc2",
                    "framework_name": "SOC 2 Type II",
                    "control_name": "Access controls are in place",
                    "severity": "CRITICAL",
                    "gap_count": 2,
                    "remediation_effort": "HIGH",
                    "priority_score": 95,
                },
            ]

            if framework_id:
                gaps = [g for g in gaps if g["framework_id"] == framework_id]
            if severity:
                gaps = [g for g in gaps if g["severity"] == severity.upper()]

            # Sort by priority score descending
            gaps.sort(key=lambda x: x["priority_score"], reverse=True)

            return HandlerResponse.success({
                "gaps": gaps,
                "total": len(gaps),
                "summary": {
                    "critical_gaps": len([g for g in gaps if g["severity"] == "CRITICAL"]),
                    "high_gaps": len([g for g in gaps if g["severity"] == "HIGH"]),
                    "medium_gaps": len([g for g in gaps if g["severity"] == "MEDIUM"]),
                    "low_gaps": len([g for g in gaps if g["severity"] == "LOW"]),
                },
            })
        except Exception as e:
            logger.exception("Failed to get compliance gaps")
            return HandlerResponse.server_error(str(e))

    @route("report")
    def compliance_report(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get compliance report for a framework."""
        try:
            framework_id = self.get_param(params, "framework_id", "cis-aws")
            report_type = self.get_param(params, "type", "summary")

            result = {
                "report_id": f"compliance-{framework_id}-20241230",
                "framework_id": framework_id,
                "framework_name": "CIS AWS Foundations Benchmark",
                "report_type": report_type,
                "generated_at": "2024-12-30T10:00:00Z",
                "period": {
                    "start": "2024-12-01T00:00:00Z",
                    "end": "2024-12-30T23:59:59Z",
                },
                "summary": {
                    "overall_score": 78.5,
                    "controls_passed": 47,
                    "controls_failed": 13,
                    "controls_total": 60,
                    "improvement_from_last": 5.2,
                },
                "by_section": [
                    {"section": "Identity and Access Management", "passed": 18, "failed": 4, "score": 81.8},
                    {"section": "Logging", "passed": 7, "failed": 2, "score": 77.8},
                    {"section": "Monitoring", "passed": 11, "failed": 4, "score": 73.3},
                    {"section": "Networking", "passed": 6, "failed": 2, "score": 75.0},
                    {"section": "Storage", "passed": 5, "failed": 1, "score": 83.3},
                ],
                "top_failures": [
                    {"control_id": "1.3", "name": "Credentials unused > 90 days", "gap_count": 3},
                    {"control_id": "2.2", "name": "CloudTrail log validation", "gap_count": 2},
                    {"control_id": "3.5", "name": "VPC flow logging", "gap_count": 4},
                ],
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to generate compliance report")
            return HandlerResponse.server_error(str(e))

    @route("summary")
    def compliance_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get overall compliance summary."""
        try:
            result = {
                "overall_score": 75.2,
                "frameworks_assessed": 5,
                "total_controls": 537,
                "controls_passed": 404,
                "controls_failed": 133,
                "by_category": {
                    "Infrastructure Security": {"score": 78.5, "frameworks": 3},
                    "Data Security": {"score": 85.0, "frameworks": 1},
                    "Trust Services": {"score": 72.0, "frameworks": 1},
                },
                "trend": {
                    "direction": "improving",
                    "change_7d": 2.3,
                    "change_30d": 5.8,
                },
                "risk_areas": [
                    {"area": "Identity Management", "risk_level": "HIGH", "gap_count": 8},
                    {"area": "Logging & Monitoring", "risk_level": "MEDIUM", "gap_count": 5},
                    {"area": "Network Security", "risk_level": "MEDIUM", "gap_count": 4},
                ],
                "last_assessment": "2024-12-30T10:00:00Z",
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get compliance summary")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Compliance Trends endpoints
    # =========================================================================

    @route("trends")
    def compliance_trends(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get compliance score trends over time."""
        try:
            framework_id = self.get_param(params, "framework_id", "")
            period = self.get_param(params, "period", "30d")

            data_points = [
                {"date": "2024-12-01", "overall_score": 70.2, "controls_passed": 42, "controls_failed": 18},
                {"date": "2024-12-07", "overall_score": 72.5, "controls_passed": 43, "controls_failed": 17},
                {"date": "2024-12-14", "overall_score": 74.0, "controls_passed": 44, "controls_failed": 16},
                {"date": "2024-12-21", "overall_score": 76.5, "controls_passed": 46, "controls_failed": 14},
                {"date": "2024-12-28", "overall_score": 78.5, "controls_passed": 47, "controls_failed": 13},
            ]

            return HandlerResponse.success({
                "framework_id": framework_id or "all",
                "period": period,
                "data_points": data_points,
                "change": {
                    "absolute": 8.3,
                    "percentage": 11.8,
                    "direction": "improving",
                },
            })
        except Exception as e:
            logger.exception("Failed to get compliance trends")
            return HandlerResponse.server_error(str(e))

    @route("history")
    def compliance_history(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get compliance assessment history."""
        try:
            framework_id = self.get_param(params, "framework_id", "")
            limit = self.get_param_int(params, "limit", 10)

            assessments = [
                {
                    "assessment_id": "assess-2024-12-30",
                    "framework_id": "cis-aws",
                    "timestamp": "2024-12-30T10:00:00Z",
                    "score": 78.5,
                    "controls_passed": 47,
                    "controls_failed": 13,
                    "triggered_by": "scheduled",
                },
                {
                    "assessment_id": "assess-2024-12-23",
                    "framework_id": "cis-aws",
                    "timestamp": "2024-12-23T10:00:00Z",
                    "score": 76.5,
                    "controls_passed": 46,
                    "controls_failed": 14,
                    "triggered_by": "scheduled",
                },
                {
                    "assessment_id": "assess-2024-12-16",
                    "framework_id": "cis-aws",
                    "timestamp": "2024-12-16T10:00:00Z",
                    "score": 74.0,
                    "controls_passed": 44,
                    "controls_failed": 16,
                    "triggered_by": "manual",
                },
            ]

            if framework_id:
                assessments = [a for a in assessments if a["framework_id"] == framework_id]

            return HandlerResponse.success({
                "assessments": assessments[:limit],
                "total": len(assessments),
            })
        except Exception as e:
            logger.exception("Failed to get compliance history")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Policy Mappings endpoints
    # =========================================================================

    @route("mappings")
    def compliance_mappings(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policy-to-control mappings."""
        try:
            framework_id = self.get_param(params, "framework_id", "")
            policy_id = self.get_param(params, "policy_id", "")

            mappings = [
                {
                    "policy_id": "aws-iam-credential-rotation",
                    "policy_name": "IAM Credential Rotation",
                    "frameworks": [
                        {"framework_id": "cis-aws", "control_id": "1.3", "control_name": "Credentials unused > 90 days"},
                        {"framework_id": "pci-dss", "control_id": "8.1.4", "control_name": "Remove inactive accounts"},
                    ],
                },
                {
                    "policy_id": "aws-s3-encryption",
                    "policy_name": "S3 Bucket Encryption",
                    "frameworks": [
                        {"framework_id": "cis-aws", "control_id": "2.1.1", "control_name": "S3 bucket encryption"},
                        {"framework_id": "pci-dss", "control_id": "3.4", "control_name": "Render PAN unreadable"},
                        {"framework_id": "hipaa", "control_id": "164.312(a)(2)(iv)", "control_name": "Encryption"},
                    ],
                },
                {
                    "policy_id": "aws-cloudtrail-enabled",
                    "policy_name": "CloudTrail Enabled",
                    "frameworks": [
                        {"framework_id": "cis-aws", "control_id": "2.1", "control_name": "CloudTrail enabled"},
                        {"framework_id": "soc2", "control_id": "CC6.1", "control_name": "Audit logging"},
                    ],
                },
            ]

            if framework_id:
                mappings = [
                    m for m in mappings
                    if any(f["framework_id"] == framework_id for f in m["frameworks"])
                ]
            if policy_id:
                mappings = [m for m in mappings if m["policy_id"] == policy_id]

            return HandlerResponse.success({
                "mappings": mappings,
                "total": len(mappings),
            })
        except Exception as e:
            logger.exception("Failed to get compliance mappings")
            return HandlerResponse.server_error(str(e))

    @route("coverage")
    def compliance_coverage(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policy coverage for a framework."""
        try:
            framework_id = self.get_param(params, "framework_id", "cis-aws")

            result = {
                "framework_id": framework_id,
                "framework_name": "CIS AWS Foundations Benchmark",
                "total_controls": 60,
                "controls_with_policies": 45,
                "controls_without_policies": 15,
                "coverage_percentage": 75.0,
                "uncovered_controls": [
                    {"control_id": "1.20", "name": "Support role restrictions"},
                    {"control_id": "3.8", "name": "S3 block public access"},
                    {"control_id": "4.12", "name": "Default VPC removal"},
                ],
                "policies_mapped": 45,
                "policies_with_multiple_mappings": 12,
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get compliance coverage")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Compliance Operations endpoints
    # =========================================================================

    @route("assess", methods=["POST"])
    def compliance_assess(self, params: dict, body: dict | None) -> HandlerResponse:
        """Trigger a compliance assessment."""
        try:
            body = body or {}
            framework_id = body.get("framework_id") or self.get_param(params, "framework_id", "")
            scope = body.get("scope", "full")

            if not framework_id:
                return HandlerResponse.error("framework_id required", HttpStatus.BAD_REQUEST)

            result = {
                "assessment_id": f"assess-{framework_id}-new",
                "framework_id": framework_id,
                "status": "STARTED",
                "scope": scope,
                "started_at": "2024-12-30T12:00:00Z",
                "estimated_completion": "2024-12-30T12:15:00Z",
                "message": f"Compliance assessment started for {framework_id}",
            }

            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to start compliance assessment")
            return HandlerResponse.server_error(str(e))

    @route("enable", methods=["POST"])
    def compliance_enable(self, params: dict, body: dict | None) -> HandlerResponse:
        """Enable a compliance framework."""
        try:
            body = body or {}
            framework_id = body.get("framework_id") or self.get_param(params, "framework_id", "")

            if not framework_id:
                return HandlerResponse.error("framework_id required", HttpStatus.BAD_REQUEST)

            result = {
                "framework_id": framework_id,
                "enabled": True,
                "message": f"Framework {framework_id} has been enabled",
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to enable framework")
            return HandlerResponse.server_error(str(e))

    @route("disable", methods=["POST"])
    def compliance_disable(self, params: dict, body: dict | None) -> HandlerResponse:
        """Disable a compliance framework."""
        try:
            body = body or {}
            framework_id = body.get("framework_id") or self.get_param(params, "framework_id", "")

            if not framework_id:
                return HandlerResponse.error("framework_id required", HttpStatus.BAD_REQUEST)

            result = {
                "framework_id": framework_id,
                "enabled": False,
                "message": f"Framework {framework_id} has been disabled",
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to disable framework")
            return HandlerResponse.server_error(str(e))

    @route("export", methods=["POST"])
    def compliance_export(self, params: dict, body: dict | None) -> HandlerResponse:
        """Export compliance report."""
        try:
            body = body or {}
            framework_id = body.get("framework_id") or self.get_param(params, "framework_id", "")
            export_format = body.get("format", "pdf")

            if export_format not in ["pdf", "csv", "json", "xlsx"]:
                return HandlerResponse.error(f"Invalid format: {export_format}", HttpStatus.BAD_REQUEST)

            result = {
                "export_id": f"export-compliance-{framework_id or 'all'}",
                "framework_id": framework_id or "all",
                "format": export_format,
                "status": "GENERATING",
                "download_url": f"/api/compliance/exports/export-compliance-{framework_id or 'all'}.{export_format}",
                "expires_at": "2024-12-31T12:00:00Z",
            }

            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to export compliance report")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Compliance Statistics endpoints
    # =========================================================================

    @route("stats")
    def compliance_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get compliance statistics."""
        try:
            result = {
                "total_frameworks": 7,
                "enabled_frameworks": 5,
                "total_controls": 714,
                "controls_assessed": 537,
                "overall_compliance": 75.2,
                "by_severity": {
                    "critical_gaps": 5,
                    "high_gaps": 23,
                    "medium_gaps": 45,
                    "low_gaps": 60,
                },
                "assessments_this_month": 12,
                "average_score_change": 3.5,
                "top_improving_framework": {"id": "cis-aws", "improvement": 8.3},
                "most_gaps_framework": {"id": "nist-800-53", "gap_count": 123},
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get compliance stats")
            return HandlerResponse.server_error(str(e))

    @route("benchmark-comparison")
    def compliance_benchmark_comparison(self, params: dict, body: dict | None) -> HandlerResponse:
        """Compare compliance scores against industry benchmarks."""
        try:
            framework_id = self.get_param(params, "framework_id", "cis-aws")

            result = {
                "framework_id": framework_id,
                "your_score": 78.5,
                "industry_average": 72.0,
                "industry_top_quartile": 85.0,
                "industry_bottom_quartile": 55.0,
                "percentile": 68,
                "comparison": "above_average",
                "areas_above_average": [
                    {"section": "Identity and Access Management", "your_score": 81.8, "industry": 75.0},
                    {"section": "Storage", "your_score": 83.3, "industry": 70.0},
                ],
                "areas_below_average": [
                    {"section": "Monitoring", "your_score": 73.3, "industry": 78.0},
                ],
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get benchmark comparison")
            return HandlerResponse.server_error(str(e))
