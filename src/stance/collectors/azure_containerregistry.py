"""
Azure Container Registry collector for Mantissa Stance.

Collects Azure Container Registry (ACR) repositories, images, and their
security configurations for posture assessment. Supports vulnerability
scanning results from Microsoft Defender for Containers.
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
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)

logger = logging.getLogger(__name__)

# Optional Azure imports
try:
    from azure.mgmt.containerregistry import ContainerRegistryManagementClient
    from azure.identity import DefaultAzureCredential

    AZURE_ACR_AVAILABLE = True
except ImportError:
    AZURE_ACR_AVAILABLE = False
    ContainerRegistryManagementClient = Any  # type: ignore
    DefaultAzureCredential = Any  # type: ignore


class AzureContainerRegistryCollector(BaseCollector):
    """
    Collects Azure Container Registry resources and configuration.

    Gathers ACR registries, repositories, images, security settings,
    and vulnerability scan results. All API calls are read-only.
    """

    collector_name = "azure_containerregistry"
    resource_types = [
        "azure_container_registry",
        "azure_container_repository",
        "azure_container_image",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure Container Registry collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_ACR_AVAILABLE:
            raise ImportError(
                "azure-mgmt-containerregistry is required for Azure ACR collector. "
                "Install with: pip install azure-mgmt-containerregistry azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._client: ContainerRegistryManagementClient | None = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_acr_client(self) -> ContainerRegistryManagementClient:
        """Get or create Container Registry Management client."""
        if self._client is None:
            self._client = ContainerRegistryManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Azure Container Registry resources.

        Returns:
            Collection of ACR assets
        """
        assets: list[Asset] = []

        try:
            assets.extend(self._collect_registries())
        except Exception as e:
            logger.warning(f"Failed to collect container registries: {e}")

        return AssetCollection(assets)

    def collect_findings(self) -> FindingCollection:
        """
        Collect vulnerability findings from container image scans.

        Note: Vulnerability scanning requires Microsoft Defender for Containers
        to be enabled on the subscription.

        Returns:
            Collection of vulnerability findings from image scans
        """
        findings: list[Finding] = []

        # Note: Azure ACR vulnerability scanning results are retrieved via
        # Microsoft Defender for Containers / Security Center APIs
        # This is handled by the AzureSecurityCollector
        # Here we collect any registry-level security recommendations

        try:
            findings.extend(self._collect_registry_security_findings())
        except Exception as e:
            logger.warning(f"Failed to collect registry security findings: {e}")

        return FindingCollection(findings)

    def _collect_registries(self) -> list[Asset]:
        """Collect Azure Container Registries with their configurations."""
        client = self._get_acr_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for registry in client.registries.list():
                registry_id = registry.id
                registry_name = registry.name
                resource_group = self._extract_resource_group(registry_id)
                location = registry.location

                # Extract tags
                tags = dict(registry.tags) if registry.tags else {}

                # Build raw config
                raw_config: dict[str, Any] = {
                    "registry_id": registry_id,
                    "registry_name": registry_name,
                    "resource_group": resource_group,
                    "location": location,
                    "login_server": registry.login_server,
                    "provisioning_state": registry.provisioning_state,
                    "creation_date": (
                        registry.creation_date.isoformat()
                        if registry.creation_date
                        else None
                    ),
                    # SKU information
                    "sku_name": registry.sku.name if registry.sku else None,
                    "sku_tier": registry.sku.tier if registry.sku else None,
                }

                # Admin user configuration
                admin_enabled = registry.admin_user_enabled
                raw_config["admin_user_enabled"] = admin_enabled
                raw_config["has_admin_enabled"] = admin_enabled is True

                # Network configuration
                public_network_access = registry.public_network_access
                raw_config["public_network_access"] = public_network_access
                raw_config["allows_public_access"] = (
                    public_network_access is None or
                    public_network_access == "Enabled"
                )

                # Network rule set
                network_rule_set = registry.network_rule_set
                if network_rule_set:
                    raw_config["network_rule_set"] = {
                        "default_action": network_rule_set.default_action,
                        "ip_rules": [
                            {"value": r.ip_address_or_range, "action": r.action}
                            for r in (network_rule_set.ip_rules or [])
                        ],
                    }
                    raw_config["has_network_rules"] = bool(network_rule_set.ip_rules)
                else:
                    raw_config["network_rule_set"] = None
                    raw_config["has_network_rules"] = False

                # Encryption configuration
                encryption = registry.encryption
                if encryption:
                    raw_config["encryption"] = {
                        "status": encryption.status,
                        "key_vault_properties": {
                            "key_identifier": encryption.key_vault_properties.key_identifier
                            if encryption.key_vault_properties
                            else None,
                            "identity": encryption.key_vault_properties.identity
                            if encryption.key_vault_properties
                            else None,
                        } if encryption.key_vault_properties else None,
                    }
                    raw_config["uses_customer_managed_keys"] = (
                        encryption.status == "enabled"
                    )
                else:
                    raw_config["encryption"] = None
                    raw_config["uses_customer_managed_keys"] = False

                # Data endpoint (dedicated data endpoints)
                raw_config["data_endpoint_enabled"] = registry.data_endpoint_enabled

                # Zone redundancy
                raw_config["zone_redundancy"] = registry.zone_redundancy
                raw_config["is_zone_redundant"] = (
                    registry.zone_redundancy == "Enabled"
                )

                # Policies
                policies = registry.policies
                if policies:
                    # Quarantine policy
                    quarantine = policies.quarantine_policy
                    raw_config["quarantine_policy"] = {
                        "status": quarantine.status if quarantine else None,
                    }
                    raw_config["quarantine_enabled"] = (
                        quarantine and quarantine.status == "enabled"
                    )

                    # Trust policy (content trust / image signing)
                    trust = policies.trust_policy
                    raw_config["trust_policy"] = {
                        "type": trust.type if trust else None,
                        "status": trust.status if trust else None,
                    }
                    raw_config["content_trust_enabled"] = (
                        trust and trust.status == "enabled"
                    )

                    # Retention policy
                    retention = policies.retention_policy
                    raw_config["retention_policy"] = {
                        "days": retention.days if retention else None,
                        "status": retention.status if retention else None,
                    }
                    raw_config["retention_policy_enabled"] = (
                        retention and retention.status == "enabled"
                    )

                    # Export policy
                    export = policies.export_policy
                    raw_config["export_policy"] = {
                        "status": export.status if export else None,
                    }
                    raw_config["export_enabled"] = (
                        export and export.status == "enabled"
                    )
                else:
                    raw_config["quarantine_policy"] = None
                    raw_config["quarantine_enabled"] = False
                    raw_config["trust_policy"] = None
                    raw_config["content_trust_enabled"] = False
                    raw_config["retention_policy"] = None
                    raw_config["retention_policy_enabled"] = False
                    raw_config["export_policy"] = None
                    raw_config["export_enabled"] = True  # Default allows export

                # Anonymous pull access
                raw_config["anonymous_pull_enabled"] = registry.anonymous_pull_enabled

                # Private endpoints
                private_endpoints = registry.private_endpoint_connections or []
                raw_config["private_endpoint_connections"] = [
                    {
                        "id": pe.id,
                        "name": pe.name,
                        "provisioning_state": pe.provisioning_state,
                        "status": (
                            pe.private_link_service_connection_state.status
                            if pe.private_link_service_connection_state
                            else None
                        ),
                    }
                    for pe in private_endpoints
                ]
                raw_config["has_private_endpoints"] = len(private_endpoints) > 0

                # Collect replications (geo-replication)
                try:
                    replications = list(
                        client.replications.list(resource_group, registry_name)
                    )
                    raw_config["replications"] = [
                        {
                            "name": r.name,
                            "location": r.location,
                            "provisioning_state": r.provisioning_state,
                            "zone_redundancy": r.zone_redundancy,
                        }
                        for r in replications
                    ]
                    raw_config["replication_count"] = len(replications)
                    raw_config["is_geo_replicated"] = len(replications) > 1
                except Exception as e:
                    logger.debug(f"Could not list replications for {registry_name}: {e}")
                    raw_config["replications"] = []
                    raw_config["replication_count"] = 0
                    raw_config["is_geo_replicated"] = False

                # Collect webhooks
                try:
                    webhooks = list(
                        client.webhooks.list(resource_group, registry_name)
                    )
                    raw_config["webhooks"] = [
                        {
                            "name": w.name,
                            "status": w.status,
                            "scope": w.scope,
                            "actions": list(w.actions) if w.actions else [],
                            "provisioning_state": w.provisioning_state,
                        }
                        for w in webhooks
                    ]
                    raw_config["webhook_count"] = len(webhooks)
                except Exception as e:
                    logger.debug(f"Could not list webhooks for {registry_name}: {e}")
                    raw_config["webhooks"] = []
                    raw_config["webhook_count"] = 0

                # Security summary
                raw_config["is_secure"] = (
                    not admin_enabled and
                    not raw_config.get("allows_public_access", True) and
                    raw_config.get("has_private_endpoints", False) and
                    not raw_config.get("anonymous_pull_enabled", False)
                )

                # Determine network exposure
                network_exposure = NETWORK_EXPOSURE_INTERNAL
                if (
                    raw_config.get("allows_public_access", True) or
                    raw_config.get("anonymous_pull_enabled", False)
                ):
                    network_exposure = NETWORK_EXPOSURE_INTERNET

                created_at = None
                if registry.creation_date:
                    created_at = registry.creation_date.replace(tzinfo=timezone.utc)

                asset = Asset(
                    id=registry_id,
                    cloud_provider="azure",
                    account_id=self._subscription_id,
                    region=location,
                    resource_type="azure_container_registry",
                    name=registry_name,
                    tags=tags,
                    network_exposure=network_exposure,
                    created_at=created_at,
                    last_seen=now,
                    raw_config=raw_config,
                )
                assets.append(asset)

        except Exception as e:
            logger.error(f"Error listing container registries: {e}")
            raise

        return assets

    def _collect_registry_security_findings(self) -> list[Finding]:
        """
        Collect security findings related to registry misconfigurations.

        These are deterministic checks based on registry configuration,
        not vulnerability scan results (which come from Defender).
        """
        findings: list[Finding] = []
        now = self._now()
        client = self._get_acr_client()

        try:
            for registry in client.registries.list():
                registry_id = registry.id
                registry_name = registry.name

                # Check: Admin user enabled
                if registry.admin_user_enabled:
                    findings.append(
                        Finding(
                            id=f"acr-admin-{registry_name}",
                            asset_id=registry_id,
                            finding_type=FindingType.MISCONFIGURATION,
                            severity=Severity.MEDIUM,
                            status=FindingStatus.OPEN,
                            title="ACR admin user is enabled",
                            description=(
                                f"Container registry '{registry_name}' has the admin user "
                                "enabled. Admin accounts should be disabled in favor of "
                                "Azure AD authentication for better security and auditability."
                            ),
                            first_seen=now,
                            last_seen=now,
                            rule_id="azure-acr-001",
                            resource_path="admin_user_enabled",
                            expected_value="false",
                            actual_value="true",
                            compliance_frameworks=["CIS Azure 1.5.0 9.1"],
                            remediation_guidance=(
                                "Disable the admin user and use Azure AD service principals "
                                "or managed identities for authentication."
                            ),
                        )
                    )

                # Check: Public network access enabled
                if (
                    registry.public_network_access is None or
                    registry.public_network_access == "Enabled"
                ):
                    findings.append(
                        Finding(
                            id=f"acr-public-{registry_name}",
                            asset_id=registry_id,
                            finding_type=FindingType.MISCONFIGURATION,
                            severity=Severity.HIGH,
                            status=FindingStatus.OPEN,
                            title="ACR allows public network access",
                            description=(
                                f"Container registry '{registry_name}' allows public network "
                                "access. This exposes the registry to potential attacks from "
                                "the internet."
                            ),
                            first_seen=now,
                            last_seen=now,
                            rule_id="azure-acr-002",
                            resource_path="public_network_access",
                            expected_value="Disabled",
                            actual_value=registry.public_network_access or "Enabled",
                            compliance_frameworks=["CIS Azure 1.5.0 9.2"],
                            remediation_guidance=(
                                "Disable public network access and use private endpoints "
                                "or service endpoints for secure access."
                            ),
                        )
                    )

                # Check: Anonymous pull enabled
                if registry.anonymous_pull_enabled:
                    findings.append(
                        Finding(
                            id=f"acr-anon-pull-{registry_name}",
                            asset_id=registry_id,
                            finding_type=FindingType.MISCONFIGURATION,
                            severity=Severity.HIGH,
                            status=FindingStatus.OPEN,
                            title="ACR allows anonymous pull",
                            description=(
                                f"Container registry '{registry_name}' allows anonymous "
                                "image pulls. This means anyone can pull images without "
                                "authentication."
                            ),
                            first_seen=now,
                            last_seen=now,
                            rule_id="azure-acr-003",
                            resource_path="anonymous_pull_enabled",
                            expected_value="false",
                            actual_value="true",
                            compliance_frameworks=[],
                            remediation_guidance=(
                                "Disable anonymous pull and require authentication for "
                                "all image pulls."
                            ),
                        )
                    )

                # Check: Content trust not enabled (Premium SKU only)
                if registry.sku and registry.sku.name == "Premium":
                    policies = registry.policies
                    if not policies or not policies.trust_policy or policies.trust_policy.status != "enabled":
                        findings.append(
                            Finding(
                                id=f"acr-trust-{registry_name}",
                                asset_id=registry_id,
                                finding_type=FindingType.MISCONFIGURATION,
                                severity=Severity.MEDIUM,
                                status=FindingStatus.OPEN,
                                title="ACR content trust is not enabled",
                                description=(
                                    f"Container registry '{registry_name}' does not have "
                                    "content trust (image signing) enabled. Content trust "
                                    "ensures image integrity and authenticity."
                                ),
                                first_seen=now,
                                last_seen=now,
                                rule_id="azure-acr-004",
                                resource_path="policies.trust_policy.status",
                                expected_value="enabled",
                                actual_value="disabled",
                                compliance_frameworks=[],
                                remediation_guidance=(
                                    "Enable content trust policy to ensure only signed "
                                    "images can be pushed and pulled."
                                ),
                            )
                        )

        except Exception as e:
            logger.debug(f"Error collecting registry security findings: {e}")

        return findings

    def _extract_resource_group(self, resource_id: str) -> str:
        """
        Extract resource group name from Azure resource ID.

        Args:
            resource_id: Full Azure resource ID

        Returns:
            Resource group name
        """
        parts = resource_id.split("/")
        try:
            rg_index = parts.index("resourceGroups")
            return parts[rg_index + 1]
        except (ValueError, IndexError):
            return ""

    def _map_severity(self, azure_severity: str) -> Severity:
        """Map Azure severity to our Severity enum."""
        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
            "Informational": Severity.INFO,
        }
        return severity_map.get(azure_severity, Severity.INFO)
