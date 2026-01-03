"""
GCP Security Command Center collector for Mantissa Stance.

Collects security findings from Google Cloud Security Command Center (SCC)
for vulnerability and threat detection.
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
    Severity,
    FindingStatus,
    NETWORK_EXPOSURE_ISOLATED,
)

logger = logging.getLogger(__name__)

# Optional GCP imports
try:
    from google.cloud import securitycenter_v1

    GCP_SCC_AVAILABLE = True
except ImportError:
    GCP_SCC_AVAILABLE = False


class GCPSecurityCollector(BaseCollector):
    """
    Collects security findings from GCP Security Command Center.

    Gathers vulnerability findings, misconfiguration detections,
    and threat findings from SCC. All API calls are read-only.
    """

    collector_name = "gcp_security"
    resource_types = [
        "gcp_scc_finding",
        "gcp_scc_source",
    ]

    def __init__(
        self,
        project_id: str,
        organization_id: str | None = None,
        credentials: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP Security collector.

        Args:
            project_id: GCP project ID to collect from.
            organization_id: Optional GCP organization ID for org-level findings.
            credentials: Optional google-auth credentials object.
            **kwargs: Additional configuration.
        """
        if not GCP_SCC_AVAILABLE:
            raise ImportError(
                "google-cloud-securitycenter is required for GCP security collector. "
                "Install with: pip install google-cloud-securitycenter"
            )

        self._project_id = project_id
        self._organization_id = organization_id
        self._credentials = credentials
        self._client: securitycenter_v1.SecurityCenterClient | None = None

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    def _get_client(self) -> securitycenter_v1.SecurityCenterClient:
        """Get or create Security Center client."""
        if self._client is None:
            self._client = securitycenter_v1.SecurityCenterClient(
                credentials=self._credentials
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect Security Command Center sources.

        Note: The main findings collection is done via collect_findings().

        Returns:
            Collection of SCC source assets (metadata)
        """
        assets: list[Asset] = []

        # Collect SCC sources for tracking what's enabled
        try:
            assets.extend(self._collect_sources())
        except Exception as e:
            logger.warning(f"Failed to collect SCC sources: {e}")

        return AssetCollection(assets)

    def collect_findings(self) -> FindingCollection:
        """
        Collect security findings from SCC.

        Returns:
            Collection of security findings
        """
        findings: list[Finding] = []

        try:
            findings.extend(self._collect_scc_findings())
        except Exception as e:
            logger.warning(f"Failed to collect SCC findings: {e}")

        return FindingCollection(findings)

    def _collect_sources(self) -> list[Asset]:
        """Collect SCC sources (providers of findings)."""
        client = self._get_client()
        assets: list[Asset] = []
        now = self._now()

        # Determine parent - use org if available, else project
        if self._organization_id:
            parent = f"organizations/{self._organization_id}"
        else:
            parent = f"projects/{self._project_id}"

        try:
            request = securitycenter_v1.ListSourcesRequest(parent=parent)

            for source in client.list_sources(request=request):
                source_name = source.name
                display_name = source.display_name or source_name.split("/")[-1]

                raw_config = {
                    "name": source_name,
                    "display_name": display_name,
                    "description": source.description or "",
                    "canonical_name": source.canonical_name or "",
                }

                assets.append(
                    Asset(
                        id=source_name,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region="global",
                        resource_type="gcp_scc_source",
                        name=display_name,
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing SCC sources: {e}")
            # Don't raise - SCC might not be enabled
            logger.info("Security Command Center may not be enabled for this project")

        return assets

    def _collect_scc_findings(self) -> list[Finding]:
        """Collect findings from Security Command Center."""
        client = self._get_client()
        findings: list[Finding] = []
        now = self._now()

        # Determine parent
        if self._organization_id:
            parent = f"organizations/{self._organization_id}/sources/-"
        else:
            parent = f"projects/{self._project_id}/sources/-"

        try:
            # Filter for active findings only
            request = securitycenter_v1.ListFindingsRequest(
                parent=parent,
                filter='state="ACTIVE"',
                order_by="severity desc, event_time desc",
            )

            for finding_result in client.list_findings(request=request):
                scc_finding = finding_result.finding

                # Extract finding details
                finding_name = scc_finding.name
                finding_id = finding_name.split("/")[-1]
                category = scc_finding.category
                resource_name = scc_finding.resource_name

                # Map SCC severity to our Severity enum
                severity = self._map_severity(scc_finding.severity)

                # Determine finding type based on category
                finding_type = self._determine_finding_type(category)

                # Extract timestamps
                first_seen = None
                last_seen = None
                if scc_finding.create_time:
                    first_seen = scc_finding.create_time.replace(tzinfo=timezone.utc)
                if scc_finding.event_time:
                    last_seen = scc_finding.event_time.replace(tzinfo=timezone.utc)

                # Extract CVE if present (for vulnerability findings)
                cve_id = None
                cvss_score = None
                vulnerability = scc_finding.vulnerability
                if vulnerability:
                    if vulnerability.cve:
                        cve_id = vulnerability.cve.id
                        if vulnerability.cve.cvssv3:
                            cvss_score = vulnerability.cve.cvssv3.base_score

                # Build description
                description = scc_finding.description or ""
                if not description:
                    description = f"{category} finding on {resource_name}"

                # Extract compliance standards if available
                compliance_frameworks = []
                compliances = scc_finding.compliances or []
                for compliance in compliances:
                    framework = compliance.standard
                    for control_id in compliance.ids or []:
                        compliance_frameworks.append(f"{framework} {control_id}")

                # Build remediation guidance from external URI if available
                remediation_guidance = ""
                if scc_finding.external_uri:
                    remediation_guidance = (
                        f"See documentation: {scc_finding.external_uri}"
                    )
                if scc_finding.next_steps:
                    remediation_guidance += f"\n\nNext steps: {scc_finding.next_steps}"

                # Map SCC state to our status
                status = FindingStatus.OPEN
                if scc_finding.state == securitycenter_v1.Finding.State.INACTIVE:
                    status = FindingStatus.RESOLVED

                # Create finding
                finding = Finding(
                    id=finding_id,
                    asset_id=resource_name,
                    finding_type=finding_type,
                    severity=severity,
                    status=status,
                    title=f"{category}: {scc_finding.resource_name.split('/')[-1]}",
                    description=description,
                    first_seen=first_seen,
                    last_seen=last_seen or now,
                    rule_id=category,
                    resource_path=resource_name,
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    compliance_frameworks=compliance_frameworks,
                    remediation_guidance=remediation_guidance.strip(),
                )

                findings.append(finding)

        except Exception as e:
            logger.error(f"Error listing SCC findings: {e}")
            # Don't raise - SCC might not be enabled
            logger.info("Security Command Center may not be enabled or accessible")

        return findings

    def _map_severity(self, scc_severity: Any) -> Severity:
        """
        Map SCC severity to our Severity enum.

        Args:
            scc_severity: SCC severity enum value

        Returns:
            Mapped Severity enum value
        """
        severity_map = {
            securitycenter_v1.Finding.Severity.CRITICAL: Severity.CRITICAL,
            securitycenter_v1.Finding.Severity.HIGH: Severity.HIGH,
            securitycenter_v1.Finding.Severity.MEDIUM: Severity.MEDIUM,
            securitycenter_v1.Finding.Severity.LOW: Severity.LOW,
        }
        return severity_map.get(scc_severity, Severity.INFO)

    def _determine_finding_type(self, category: str) -> FindingType:
        """
        Determine finding type based on SCC category.

        Args:
            category: SCC finding category

        Returns:
            FindingType enum value
        """
        # Vulnerability categories typically contain these patterns
        vuln_patterns = [
            "VULNERABILITY",
            "CVE",
            "SOFTWARE_VULNERABILITY",
            "OS_VULNERABILITY",
            "CONTAINER_VULNERABILITY",
        ]

        category_upper = category.upper()
        for pattern in vuln_patterns:
            if pattern in category_upper:
                return FindingType.VULNERABILITY

        # Default to misconfiguration for other findings
        return FindingType.MISCONFIGURATION
