"""
AWS Security collector for Mantissa Stance.

Collects security findings from AWS SecurityHub and Inspector
for vulnerability management.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    FindingStatus,
    Severity,
    NETWORK_EXPOSURE_ISOLATED,
)

logger = logging.getLogger(__name__)


class SecurityCollector(BaseCollector):
    """
    Collects security findings from AWS SecurityHub and Inspector.

    Gathers findings from security services and converts them to
    the unified Finding model. All API calls are read-only.
    """

    collector_name = "aws_security"
    resource_types = [
        "aws_securityhub_finding",
        "aws_inspector_finding",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect security service resources (for asset tracking).

        Returns:
            Collection of security service assets
        """
        assets: list[Asset] = []
        now = self._now()

        # Track SecurityHub as an asset if enabled
        try:
            securityhub = self._get_client("securityhub")
            hub = securityhub.describe_hub()
            if hub:
                assets.append(
                    Asset(
                        id=hub.get("HubArn", f"arn:aws:securityhub:{self._region}:{self.account_id}:hub/default"),
                        cloud_provider="aws",
                        account_id=self.account_id,
                        region=self._region,
                        resource_type="aws_securityhub_hub",
                        name="SecurityHub",
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config={
                            "hub_arn": hub.get("HubArn"),
                            "subscribed_at": hub.get("SubscribedAt"),
                            "auto_enable_controls": hub.get("AutoEnableControls"),
                        },
                    )
                )
        except Exception as e:
            logger.debug(f"SecurityHub not enabled or accessible: {e}")

        # Track Inspector as an asset if enabled
        try:
            inspector = self._get_client("inspector2")
            status = inspector.batch_get_account_status(
                accountIds=[self.account_id]
            )
            for account in status.get("accounts", []):
                if account.get("state", {}).get("status") == "ENABLED":
                    assets.append(
                        Asset(
                            id=f"arn:aws:inspector2:{self._region}:{self.account_id}:inspector",
                            cloud_provider="aws",
                            account_id=self.account_id,
                            region=self._region,
                            resource_type="aws_inspector",
                            name="Inspector",
                            network_exposure=NETWORK_EXPOSURE_ISOLATED,
                            last_seen=now,
                            raw_config={
                                "status": account.get("state", {}).get("status"),
                                "resource_state": account.get("resourceState"),
                            },
                        )
                    )
        except Exception as e:
            logger.debug(f"Inspector not enabled or accessible: {e}")

        return AssetCollection(assets)

    def collect_findings(self) -> FindingCollection:
        """
        Collect findings from security services.

        Returns:
            Collection of security findings
        """
        findings: list[Finding] = []

        # Collect SecurityHub findings
        try:
            findings.extend(self._collect_securityhub_findings())
        except Exception as e:
            logger.warning(f"Failed to collect SecurityHub findings: {e}")

        # Collect Inspector findings
        try:
            findings.extend(self._collect_inspector_findings())
        except Exception as e:
            logger.warning(f"Failed to collect Inspector findings: {e}")

        return FindingCollection(findings)

    def _collect_securityhub_findings(self) -> list[Finding]:
        """Collect findings from SecurityHub."""
        securityhub = self._get_client("securityhub")
        findings: list[Finding] = []

        # Filter for active findings
        filters = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [
                {"Value": "NEW", "Comparison": "EQUALS"},
                {"Value": "NOTIFIED", "Comparison": "EQUALS"},
            ],
        }

        try:
            paginator = securityhub.get_paginator("get_findings")
            for page in paginator.paginate(Filters=filters):
                for finding in page.get("Findings", []):
                    converted = self._convert_securityhub_finding(finding)
                    if converted:
                        findings.append(converted)
        except Exception as e:
            logger.warning(f"Error fetching SecurityHub findings: {e}")

        return findings

    def _collect_inspector_findings(self) -> list[Finding]:
        """Collect findings from Inspector."""
        inspector = self._get_client("inspector2")
        findings: list[Finding] = []

        # Filter for active findings
        filter_criteria = {
            "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
        }

        try:
            paginator = inspector.get_paginator("list_findings")
            for page in paginator.paginate(filterCriteria=filter_criteria):
                for finding in page.get("findings", []):
                    converted = self._convert_inspector_finding(finding)
                    if converted:
                        findings.append(converted)
        except Exception as e:
            logger.warning(f"Error fetching Inspector findings: {e}")

        return findings

    def _convert_securityhub_finding(
        self, finding: dict[str, Any]
    ) -> Finding | None:
        """
        Convert a SecurityHub finding to unified Finding model.

        Args:
            finding: Raw SecurityHub finding

        Returns:
            Converted Finding or None if conversion fails
        """
        try:
            # Extract finding ID
            finding_id = finding.get("Id", "")

            # Get resource ARN (first resource)
            resources = finding.get("Resources", [])
            asset_id = resources[0].get("Id", "") if resources else ""

            # Map severity
            severity = self._map_securityhub_severity(
                finding.get("Severity", {})
            )

            # Determine finding type
            finding_types = finding.get("Types", [])
            finding_type = FindingType.MISCONFIGURATION
            for ft in finding_types:
                if "Vulnerability" in ft or "CVE" in ft:
                    finding_type = FindingType.VULNERABILITY
                    break

            # Extract compliance info
            compliance_frameworks = []
            compliance = finding.get("Compliance", {})
            if compliance.get("RelatedRequirements"):
                compliance_frameworks = compliance["RelatedRequirements"]

            # Map status
            workflow_status = finding.get("Workflow", {}).get("Status", "NEW")
            status = FindingStatus.OPEN
            if workflow_status == "RESOLVED":
                status = FindingStatus.RESOLVED
            elif workflow_status == "SUPPRESSED":
                status = FindingStatus.SUPPRESSED

            # Parse timestamps
            first_seen = self._parse_timestamp(finding.get("FirstObservedAt"))
            last_seen = self._parse_timestamp(
                finding.get("LastObservedAt")
            ) or self._now()

            # Extract CVE info if present
            cve_id = None
            cvss_score = None
            vulnerabilities = finding.get("Vulnerabilities", [])
            if vulnerabilities:
                vuln = vulnerabilities[0]
                cve_id = vuln.get("Id")
                cvss = vuln.get("Cvss", [])
                if cvss:
                    cvss_score = cvss[0].get("BaseScore")

            # Get remediation
            remediation = finding.get("Remediation", {})
            recommendation = remediation.get("Recommendation", {})
            remediation_guidance = recommendation.get("Text", "")
            if recommendation.get("Url"):
                remediation_guidance += f"\nReference: {recommendation['Url']}"

            return Finding(
                id=finding_id,
                asset_id=asset_id,
                finding_type=finding_type,
                severity=severity,
                status=status,
                title=finding.get("Title", ""),
                description=finding.get("Description", ""),
                first_seen=first_seen,
                last_seen=last_seen,
                rule_id=finding.get("GeneratorId"),
                resource_path=finding.get("ProductFields", {}).get(
                    "Resources:0/Id"
                ),
                cve_id=cve_id,
                cvss_score=cvss_score,
                compliance_frameworks=compliance_frameworks,
                remediation_guidance=remediation_guidance,
            )

        except Exception as e:
            logger.warning(f"Failed to convert SecurityHub finding: {e}")
            return None

    def _convert_inspector_finding(
        self, finding: dict[str, Any]
    ) -> Finding | None:
        """
        Convert an Inspector finding to unified Finding model.

        Args:
            finding: Raw Inspector finding

        Returns:
            Converted Finding or None if conversion fails
        """
        try:
            # Extract finding ID
            finding_id = finding.get("findingArn", "")

            # Get affected resource
            resources = finding.get("resources", [])
            asset_id = ""
            if resources:
                resource = resources[0]
                asset_id = resource.get("id", "")

            # Map severity
            severity = self._map_inspector_severity(
                finding.get("severity", "INFORMATIONAL")
            )

            # Determine finding type (Inspector is primarily vulnerabilities)
            finding_type = FindingType.VULNERABILITY
            if finding.get("type") == "PACKAGE_VULNERABILITY":
                finding_type = FindingType.VULNERABILITY
            elif finding.get("type") == "NETWORK_REACHABILITY":
                finding_type = FindingType.MISCONFIGURATION

            # Parse timestamps
            first_seen = self._parse_timestamp(finding.get("firstObservedAt"))
            last_seen = self._parse_timestamp(
                finding.get("lastObservedAt")
            ) or self._now()

            # Extract vulnerability details
            cve_id = None
            cvss_score = None
            package_name = None
            installed_version = None
            fixed_version = None

            package_vuln = finding.get("packageVulnerabilityDetails", {})
            if package_vuln:
                cve_id = package_vuln.get("vulnerabilityId")

                # Get CVSS score
                cvss = package_vuln.get("cvss", [])
                if cvss:
                    # Prefer CVSS v3
                    for score in cvss:
                        if score.get("version") == "3.1" or score.get("version") == "3.0":
                            cvss_score = score.get("baseScore")
                            break
                    if not cvss_score and cvss:
                        cvss_score = cvss[0].get("baseScore")

                # Get package info
                vulnerable_packages = package_vuln.get("vulnerablePackages", [])
                if vulnerable_packages:
                    pkg = vulnerable_packages[0]
                    package_name = pkg.get("name")
                    installed_version = pkg.get("version")
                    fixed_version = pkg.get("fixedInVersion")

            # Get remediation
            remediation_guidance = finding.get("remediation", {}).get(
                "recommendation", {}).get("text", "")

            return Finding(
                id=finding_id,
                asset_id=asset_id,
                finding_type=finding_type,
                severity=severity,
                status=FindingStatus.OPEN,
                title=finding.get("title", ""),
                description=finding.get("description", ""),
                first_seen=first_seen,
                last_seen=last_seen,
                cve_id=cve_id,
                cvss_score=cvss_score,
                package_name=package_name,
                installed_version=installed_version,
                fixed_version=fixed_version,
                remediation_guidance=remediation_guidance,
            )

        except Exception as e:
            logger.warning(f"Failed to convert Inspector finding: {e}")
            return None

    def _map_securityhub_severity(
        self, severity_obj: dict[str, Any]
    ) -> Severity:
        """
        Map SecurityHub severity to unified Severity enum.

        Args:
            severity_obj: SecurityHub severity object

        Returns:
            Mapped Severity enum value
        """
        label = severity_obj.get("Label", "INFORMATIONAL").upper()

        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFORMATIONAL": Severity.INFO,
        }

        return severity_map.get(label, Severity.INFO)

    def _map_inspector_severity(self, severity: str) -> Severity:
        """
        Map Inspector severity to unified Severity enum.

        Args:
            severity: Inspector severity string

        Returns:
            Mapped Severity enum value
        """
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFORMATIONAL": Severity.INFO,
            "UNTRIAGED": Severity.INFO,
        }

        return severity_map.get(severity.upper(), Severity.INFO)

    def _parse_timestamp(self, timestamp_str: str | None) -> datetime | None:
        """
        Parse an ISO timestamp string to datetime.

        Args:
            timestamp_str: ISO format timestamp string

        Returns:
            Parsed datetime or None
        """
        if not timestamp_str:
            return None

        try:
            # Handle various ISO formats
            if timestamp_str.endswith("Z"):
                timestamp_str = timestamp_str[:-1] + "+00:00"

            dt = datetime.fromisoformat(timestamp_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception as e:
            logger.debug(f"Failed to parse timestamp {timestamp_str}: {e}")
            return None
