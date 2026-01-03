"""
Azure Security collector for Mantissa Stance.

Collects security findings from Microsoft Defender for Cloud (formerly Azure Security Center)
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

# Optional Azure imports
try:
    from azure.mgmt.security import SecurityCenter
    from azure.identity import DefaultAzureCredential

    AZURE_SECURITY_AVAILABLE = True
except ImportError:
    AZURE_SECURITY_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore


class AzureSecurityCollector(BaseCollector):
    """
    Collects security findings from Microsoft Defender for Cloud.

    Gathers security alerts, assessments, and recommendations.
    All API calls are read-only.
    """

    collector_name = "azure_security"
    resource_types = [
        "azure_security_alert",
        "azure_security_assessment",
        "azure_security_recommendation",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure Security collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_SECURITY_AVAILABLE:
            raise ImportError(
                "azure-mgmt-security is required for Azure security collector. "
                "Install with: pip install azure-mgmt-security azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._client: SecurityCenter | None = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_security_client(self) -> SecurityCenter:
        """Get or create Security Center client."""
        if self._client is None:
            self._client = SecurityCenter(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect security service assets (Defender for Cloud configuration).

        Returns:
            Collection of security service assets
        """
        assets: list[Asset] = []
        now = self._now()

        # Track Defender for Cloud status
        try:
            assets.extend(self._collect_security_contacts())
        except Exception as e:
            logger.warning(f"Failed to collect security contacts: {e}")

        # Collect auto-provisioning settings
        try:
            assets.extend(self._collect_auto_provisioning_settings())
        except Exception as e:
            logger.warning(f"Failed to collect auto-provisioning settings: {e}")

        # Collect security policies
        try:
            assets.extend(self._collect_security_policies())
        except Exception as e:
            logger.warning(f"Failed to collect security policies: {e}")

        return AssetCollection(assets)

    def collect_findings(self) -> FindingCollection:
        """
        Collect security findings from Defender for Cloud.

        Returns:
            Collection of security findings
        """
        findings: list[Finding] = []

        # Collect security alerts
        try:
            findings.extend(self._collect_security_alerts())
        except Exception as e:
            logger.warning(f"Failed to collect security alerts: {e}")

        # Collect security assessments
        try:
            findings.extend(self._collect_security_assessments())
        except Exception as e:
            logger.warning(f"Failed to collect security assessments: {e}")

        return FindingCollection(findings)

    def _collect_security_contacts(self) -> list[Asset]:
        """Collect security contact configurations."""
        client = self._get_security_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for contact in client.security_contacts.list():
                contact_id = contact.id or f"security-contact-{contact.name}"

                raw_config = {
                    "name": contact.name,
                    "email": contact.email,
                    "phone": contact.phone,
                    "alert_notifications": contact.alert_notifications,
                    "alerts_to_admins": contact.alerts_to_admins,
                }

                assets.append(
                    Asset(
                        id=contact_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region="global",
                        resource_type="azure_security_contact",
                        name=contact.name or "security-contact",
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.debug(f"Could not list security contacts: {e}")

        return assets

    def _collect_auto_provisioning_settings(self) -> list[Asset]:
        """Collect auto-provisioning settings."""
        client = self._get_security_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for setting in client.auto_provisioning_settings.list():
                setting_id = setting.id or f"auto-provisioning-{setting.name}"

                raw_config = {
                    "name": setting.name,
                    "auto_provision": setting.auto_provision,
                }

                assets.append(
                    Asset(
                        id=setting_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region="global",
                        resource_type="azure_auto_provisioning_setting",
                        name=setting.name or "auto-provisioning",
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.debug(f"Could not list auto-provisioning settings: {e}")

        return assets

    def _collect_security_policies(self) -> list[Asset]:
        """Collect security policy configurations."""
        client = self._get_security_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            # Get subscription-level policy
            policy = client.pricings.list()

            for pricing in policy:
                pricing_id = pricing.id or f"pricing-{pricing.name}"

                raw_config = {
                    "name": pricing.name,
                    "pricing_tier": pricing.pricing_tier,
                    "free_trial_remaining_time": str(pricing.free_trial_remaining_time)
                    if pricing.free_trial_remaining_time
                    else None,
                }

                # Determine if Defender is enabled for this resource type
                is_enabled = pricing.pricing_tier == "Standard"
                raw_config["defender_enabled"] = is_enabled

                assets.append(
                    Asset(
                        id=pricing_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region="global",
                        resource_type="azure_defender_pricing",
                        name=f"Defender for {pricing.name}",
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.debug(f"Could not list security policies: {e}")

        return assets

    def _collect_security_alerts(self) -> list[Finding]:
        """Collect security alerts from Defender for Cloud."""
        client = self._get_security_client()
        findings: list[Finding] = []
        now = self._now()

        try:
            for alert in client.alerts.list():
                # Extract finding details
                alert_id = alert.id or alert.name
                alert_name = alert.alert_display_name or alert.alert_type

                # Map severity
                severity = self._map_severity(alert.severity)

                # Determine status
                status = FindingStatus.OPEN
                if alert.status:
                    status_lower = alert.status.lower()
                    if status_lower in ("resolved", "dismissed"):
                        status = FindingStatus.RESOLVED
                    elif status_lower == "suppressed":
                        status = FindingStatus.SUPPRESSED

                # Determine finding type based on alert type
                finding_type = FindingType.MISCONFIGURATION
                if alert.alert_type:
                    alert_type_lower = alert.alert_type.lower()
                    if any(word in alert_type_lower for word in [
                        "vulnerability", "cve", "patch", "update"
                    ]):
                        finding_type = FindingType.VULNERABILITY

                # Extract resource info
                resource_path = ""
                asset_id = ""
                if alert.compromised_entity:
                    asset_id = alert.compromised_entity

                # Build description
                description = alert.description or ""
                if alert.remediation_steps:
                    remediation = "\n".join(alert.remediation_steps)
                else:
                    remediation = ""

                # Parse timestamps
                first_seen = None
                if alert.start_time_utc:
                    first_seen = alert.start_time_utc.replace(tzinfo=timezone.utc)

                last_seen = now
                if alert.end_time_utc:
                    last_seen = alert.end_time_utc.replace(tzinfo=timezone.utc)

                # Extract compliance frameworks if available
                compliance_frameworks = []
                if hasattr(alert, 'extended_properties') and alert.extended_properties:
                    ext_props = alert.extended_properties
                    if 'compliance' in ext_props:
                        compliance_frameworks.append(ext_props['compliance'])

                findings.append(
                    Finding(
                        id=alert_id,
                        asset_id=asset_id,
                        finding_type=finding_type,
                        severity=severity,
                        status=status,
                        title=alert_name,
                        description=description,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        rule_id=alert.alert_type,
                        resource_path=resource_path,
                        compliance_frameworks=compliance_frameworks,
                        remediation_guidance=remediation,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing security alerts: {e}")

        return findings

    def _collect_security_assessments(self) -> list[Finding]:
        """Collect security assessments (recommendations) from Defender for Cloud."""
        client = self._get_security_client()
        findings: list[Finding] = []
        now = self._now()

        try:
            # List assessments at subscription scope
            scope = f"/subscriptions/{self._subscription_id}"

            for assessment in client.assessments.list(scope=scope):
                # Skip healthy assessments
                status_code = None
                if assessment.status:
                    status_code = assessment.status.code
                    if status_code and status_code.lower() == "healthy":
                        continue

                assessment_id = assessment.id or assessment.name
                assessment_name = assessment.display_name or assessment.name

                # Map severity from assessment metadata
                severity = Severity.MEDIUM  # Default
                if hasattr(assessment, 'metadata') and assessment.metadata:
                    if assessment.metadata.severity:
                        severity = self._map_severity(assessment.metadata.severity)

                # All assessments are misconfigurations
                finding_type = FindingType.MISCONFIGURATION

                # Determine status
                status = FindingStatus.OPEN
                if status_code:
                    if status_code.lower() == "notapplicable":
                        continue  # Skip not applicable
                    elif status_code.lower() in ("healthy", "resolved"):
                        status = FindingStatus.RESOLVED

                # Extract resource info
                asset_id = ""
                if assessment.resource_details:
                    if hasattr(assessment.resource_details, 'id'):
                        asset_id = assessment.resource_details.id or ""
                    elif hasattr(assessment.resource_details, 'source'):
                        asset_id = assessment.resource_details.source or ""

                # Build description
                description = ""
                remediation = ""
                if hasattr(assessment, 'metadata') and assessment.metadata:
                    description = assessment.metadata.description or ""
                    if assessment.metadata.remediation_description:
                        remediation = assessment.metadata.remediation_description

                # Extract compliance mappings
                compliance_frameworks = []
                if hasattr(assessment, 'metadata') and assessment.metadata:
                    if hasattr(assessment.metadata, 'categories'):
                        categories = assessment.metadata.categories or []
                        for category in categories:
                            compliance_frameworks.append(str(category))

                findings.append(
                    Finding(
                        id=assessment_id,
                        asset_id=asset_id,
                        finding_type=finding_type,
                        severity=severity,
                        status=status,
                        title=assessment_name,
                        description=description,
                        first_seen=None,
                        last_seen=now,
                        rule_id=assessment.name,
                        compliance_frameworks=compliance_frameworks,
                        remediation_guidance=remediation,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing security assessments: {e}")

        return findings

    def _map_severity(self, severity_str: str | None) -> Severity:
        """
        Map Azure severity to unified Severity enum.

        Args:
            severity_str: Azure severity string

        Returns:
            Mapped Severity enum value
        """
        if not severity_str:
            return Severity.INFO

        severity_map = {
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFO,
        }

        return severity_map.get(severity_str.lower(), Severity.INFO)

    def _extract_resource_group(self, resource_id: str) -> str:
        """
        Extract resource group name from Azure resource ID.

        Args:
            resource_id: Full Azure resource ID

        Returns:
            Resource group name
        """
        if not resource_id:
            return ""
        parts = resource_id.split("/")
        try:
            rg_index = parts.index("resourceGroups")
            return parts[rg_index + 1]
        except (ValueError, IndexError):
            return ""
