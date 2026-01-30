"""
Azure Monitor collector for Mantissa Stance.

Collects Azure Monitor resources including Activity Log profiles,
alert rules, Log Analytics workspaces, and diagnostic settings
for security posture assessment.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_ISOLATED,
)

logger = logging.getLogger(__name__)

# Optional Azure imports
try:
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.loganalytics import LogAnalyticsManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.identity import DefaultAzureCredential

    AZURE_MONITOR_AVAILABLE = True
except ImportError:
    AZURE_MONITOR_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore


class AzureMonitorCollector(BaseCollector):
    """
    Collects Azure Monitor resources.

    Gathers Activity Log profiles, alert rules, Log Analytics workspaces,
    and Key Vault diagnostic settings. All API calls are read-only.
    """

    collector_name = "azure_monitor"
    resource_types = [
        "azure_monitor_log_profile",
        "azure_monitor_alert_rule",
        "azure_log_analytics_workspace",
        "azure_key_vault",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure Monitor collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_MONITOR_AVAILABLE:
            raise ImportError(
                "azure-mgmt-monitor and azure-mgmt-loganalytics are required for "
                "Azure Monitor collector. Install with: "
                "pip install azure-mgmt-monitor azure-mgmt-loganalytics azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._monitor_client: Any = None
        self._log_analytics_client: Any = None
        self._keyvault_client: Any = None

    def _get_monitor_client(self) -> Any:
        """Get or create Monitor Management client."""
        if self._monitor_client is None:
            self._monitor_client = MonitorManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._monitor_client

    def _get_log_analytics_client(self) -> Any:
        """Get or create Log Analytics Management client."""
        if self._log_analytics_client is None:
            self._log_analytics_client = LogAnalyticsManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._log_analytics_client

    def _get_keyvault_client(self) -> Any:
        """Get or create Key Vault Management client."""
        if self._keyvault_client is None:
            self._keyvault_client = KeyVaultManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._keyvault_client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Azure Monitor resources.

        Returns:
            Collection of Monitor assets
        """
        assets: list[Asset] = []

        # Collect Activity Log diagnostic settings (replaces deprecated log profiles)
        try:
            assets.extend(self._collect_activity_log_settings())
        except Exception as e:
            logger.warning(f"Failed to collect Activity Log settings: {e}")

        # Collect Activity Log alerts
        try:
            assets.extend(self._collect_activity_log_alerts())
        except Exception as e:
            logger.warning(f"Failed to collect Activity Log alerts: {e}")

        # Collect Log Analytics workspaces
        try:
            assets.extend(self._collect_log_analytics_workspaces())
        except Exception as e:
            logger.warning(f"Failed to collect Log Analytics workspaces: {e}")

        # Collect Key Vaults with diagnostic settings
        try:
            assets.extend(self._collect_key_vaults())
        except Exception as e:
            logger.warning(f"Failed to collect Key Vaults: {e}")

        return AssetCollection(assets)

    def _collect_activity_log_settings(self) -> list[Asset]:
        """
        Collect Activity Log diagnostic settings.

        Note: Log profiles are deprecated. We collect diagnostic settings
        on the subscription level that capture activity logs.
        """
        client = self._get_monitor_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            # Get subscription-level diagnostic settings
            settings = client.diagnostic_settings.list(
                resource_uri=f"/subscriptions/{self._subscription_id}"
            )

            for setting in settings:
                setting_id = setting.id or f"subscription/{self._subscription_id}/diagnosticSettings/{setting.name}"

                # Check log categories
                logs = setting.logs or []
                categories = [log.category for log in logs if log.enabled]

                # Check if all required categories are enabled
                required_categories = [
                    "Administrative",
                    "Security",
                    "ServiceHealth",
                    "Alert",
                    "Recommendation",
                    "Policy",
                    "Autoscale",
                    "ResourceHealth",
                ]
                captures_all_categories = all(
                    cat in categories for cat in required_categories
                )

                # Check retention
                retention_enabled = False
                retention_days = 0
                if setting.storage_account_id:
                    for log in logs:
                        if log.retention_policy and log.retention_policy.enabled:
                            retention_enabled = True
                            retention_days = max(retention_days, log.retention_policy.days or 0)

                # Check if all regions captured (activity logs are global by default)
                captures_all_regions = True  # Activity logs are subscription-wide

                raw_config: dict[str, Any] = {
                    "name": setting.name,
                    "storage_account_id": setting.storage_account_id,
                    "service_bus_rule_id": setting.service_bus_rule_id,
                    "event_hub_authorization_rule_id": setting.event_hub_authorization_rule_id,
                    "event_hub_name": setting.event_hub_name,
                    "workspace_id": setting.workspace_id,
                    "log_categories": categories,
                    "retention_enabled": retention_enabled,
                    "retention_days": retention_days,
                    "captures_all_categories": captures_all_categories,
                    "captures_all_regions": captures_all_regions,
                }

                assets.append(
                    Asset(
                        id=setting_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region="global",
                        resource_type="azure_monitor_log_profile",
                        name=setting.name or "activity-log-settings",
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error collecting Activity Log settings: {e}")
            # Create synthetic asset if no settings found
            assets.append(
                Asset(
                    id=f"/subscriptions/{self._subscription_id}/diagnosticSettings/none",
                    cloud_provider="azure",
                    account_id=self._subscription_id,
                    region="global",
                    resource_type="azure_monitor_log_profile",
                    name="no-activity-log-settings",
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    last_seen=now,
                    raw_config={
                        "retention_enabled": False,
                        "retention_days": 0,
                        "captures_all_categories": False,
                        "captures_all_regions": False,
                        "is_synthetic": True,
                    },
                )
            )

        return assets

    def _collect_activity_log_alerts(self) -> list[Asset]:
        """Collect Activity Log alert rules."""
        client = self._get_monitor_client()
        assets: list[Asset] = []
        now = self._now()

        # Track which security alerts exist
        found_alerts = {
            "nsg_changes": False,
            "policy_changes": False,
            "security_center_changes": False,
            "security_solution_changes": False,
            "sql_firewall_changes": False,
        }

        all_alerts: list[Any] = []

        try:
            # List all activity log alerts
            alerts = client.activity_log_alerts.list_by_subscription_id()
            all_alerts = list(alerts)

            # Analyze which security alerts exist
            for alert in all_alerts:
                if not alert.enabled:
                    continue

                condition = alert.condition
                if not condition or not condition.all_of:
                    continue

                # Check conditions for specific alert types
                for clause in condition.all_of:
                    field = getattr(clause, 'field', '') or ''
                    equals = getattr(clause, 'equals', '') or ''

                    field_lower = field.lower()
                    equals_lower = equals.lower()

                    # NSG changes
                    if 'networksecuritygroup' in equals_lower or 'nsg' in equals_lower:
                        found_alerts["nsg_changes"] = True

                    # Policy changes
                    if 'policyassignment' in equals_lower or 'policy' in equals_lower:
                        found_alerts["policy_changes"] = True

                    # Security Center changes
                    if 'securitycenter' in equals_lower or 'security center' in equals_lower:
                        found_alerts["security_center_changes"] = True

                    # Security solution changes
                    if 'securitysolution' in equals_lower:
                        found_alerts["security_solution_changes"] = True

                    # SQL firewall changes
                    if 'sqlfirewall' in equals_lower or 'sql' in equals_lower and 'firewall' in equals_lower:
                        found_alerts["sql_firewall_changes"] = True

        except Exception as e:
            logger.error(f"Error listing Activity Log alerts: {e}")

        # Create assets for each alert
        for alert in all_alerts:
            alert_id = alert.id or f"alert/{alert.name}"

            raw_config: dict[str, Any] = {
                "name": alert.name,
                "description": alert.description or "",
                "enabled": alert.enabled,
                "scopes": list(alert.scopes) if alert.scopes else [],
                "condition": str(alert.condition) if alert.condition else "",
                "actions": [
                    {"action_group_id": ag.action_group_id}
                    for ag in (alert.actions.action_groups or [])
                ] if alert.actions else [],
                # Alert existence flags
                "alert_for_nsg_changes_exists": found_alerts["nsg_changes"],
                "alert_for_policy_changes_exists": found_alerts["policy_changes"],
                "alert_for_security_center_changes_exists": found_alerts["security_center_changes"],
                "alert_for_security_solution_changes_exists": found_alerts["security_solution_changes"],
                "alert_for_sql_firewall_changes_exists": found_alerts["sql_firewall_changes"],
            }

            assets.append(
                Asset(
                    id=alert_id,
                    cloud_provider="azure",
                    account_id=self._subscription_id,
                    region="global",
                    resource_type="azure_monitor_alert_rule",
                    name=alert.name or "unknown",
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        # If no alerts exist, create synthetic asset to trigger findings
        if not all_alerts:
            assets.append(
                Asset(
                    id=f"/subscriptions/{self._subscription_id}/alertRules/none",
                    cloud_provider="azure",
                    account_id=self._subscription_id,
                    region="global",
                    resource_type="azure_monitor_alert_rule",
                    name="no-activity-log-alerts",
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    last_seen=now,
                    raw_config={
                        "alert_for_nsg_changes_exists": False,
                        "alert_for_policy_changes_exists": False,
                        "alert_for_security_center_changes_exists": False,
                        "alert_for_security_solution_changes_exists": False,
                        "alert_for_sql_firewall_changes_exists": False,
                        "is_synthetic": True,
                    },
                )
            )

        return assets

    def _collect_log_analytics_workspaces(self) -> list[Asset]:
        """Collect Log Analytics workspaces."""
        client = self._get_log_analytics_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            workspaces = client.workspaces.list()

            for workspace in workspaces:
                workspace_id = workspace.id or f"workspace/{workspace.name}"

                raw_config: dict[str, Any] = {
                    "name": workspace.name,
                    "location": workspace.location,
                    "sku": workspace.sku.name if workspace.sku else None,
                    "retention_in_days": workspace.retention_in_days or 30,
                    "workspace_capping": {
                        "daily_quota_gb": workspace.workspace_capping.daily_quota_gb
                        if workspace.workspace_capping else None,
                    },
                    "public_network_access_for_ingestion": (
                        workspace.public_network_access_for_ingestion
                        if hasattr(workspace, 'public_network_access_for_ingestion')
                        else "Enabled"
                    ),
                    "public_network_access_for_query": (
                        workspace.public_network_access_for_query
                        if hasattr(workspace, 'public_network_access_for_query')
                        else "Enabled"
                    ),
                    "provisioning_state": workspace.provisioning_state,
                    "customer_id": workspace.customer_id,
                }

                # Extract resource group from ID
                resource_group = ""
                if workspace.id:
                    parts = workspace.id.split("/")
                    if "resourceGroups" in parts:
                        idx = parts.index("resourceGroups")
                        if idx + 1 < len(parts):
                            resource_group = parts[idx + 1]
                raw_config["resource_group"] = resource_group

                assets.append(
                    Asset(
                        id=workspace_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=workspace.location or "unknown",
                        resource_type="azure_log_analytics_workspace",
                        name=workspace.name or "unknown",
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Log Analytics workspaces: {e}")

        return assets

    def _collect_key_vaults(self) -> list[Asset]:
        """Collect Key Vaults with diagnostic settings."""
        client = self._get_keyvault_client()
        monitor_client = self._get_monitor_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            vaults = client.vaults.list_by_subscription()

            for vault in vaults:
                vault_id = vault.id or f"vault/{vault.name}"

                # Check diagnostic settings
                diagnostic_settings_enabled = False
                try:
                    settings = monitor_client.diagnostic_settings.list(
                        resource_uri=vault_id
                    )
                    for setting in settings:
                        if setting.logs:
                            for log in setting.logs:
                                if log.enabled:
                                    diagnostic_settings_enabled = True
                                    break
                        if diagnostic_settings_enabled:
                            break
                except Exception as e:
                    logger.debug(f"Could not get diagnostic settings for {vault.name}: {e}")

                raw_config: dict[str, Any] = {
                    "name": vault.name,
                    "location": vault.location,
                    "vault_uri": vault.properties.vault_uri if vault.properties else None,
                    "tenant_id": vault.properties.tenant_id if vault.properties else None,
                    "sku": vault.properties.sku.name if vault.properties and vault.properties.sku else None,
                    "enabled_for_deployment": (
                        vault.properties.enabled_for_deployment
                        if vault.properties else False
                    ),
                    "enabled_for_disk_encryption": (
                        vault.properties.enabled_for_disk_encryption
                        if vault.properties else False
                    ),
                    "enabled_for_template_deployment": (
                        vault.properties.enabled_for_template_deployment
                        if vault.properties else False
                    ),
                    "soft_delete_enabled": (
                        vault.properties.enable_soft_delete
                        if vault.properties and hasattr(vault.properties, 'enable_soft_delete')
                        else True  # Default is true for new vaults
                    ),
                    "purge_protection_enabled": (
                        vault.properties.enable_purge_protection
                        if vault.properties and hasattr(vault.properties, 'enable_purge_protection')
                        else False
                    ),
                    "diagnostic_settings_enabled": diagnostic_settings_enabled,
                }

                assets.append(
                    Asset(
                        id=vault_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=vault.location or "unknown",
                        resource_type="azure_key_vault",
                        name=vault.name or "unknown",
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Key Vaults: {e}")

        return assets
