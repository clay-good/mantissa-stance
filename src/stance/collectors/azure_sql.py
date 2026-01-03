"""
Azure SQL Database collector for Mantissa Stance.

Collects Azure SQL servers, databases, and their security configurations
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
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_ISOLATED,
)

logger = logging.getLogger(__name__)

# Optional Azure imports
try:
    from azure.mgmt.sql import SqlManagementClient
    from azure.identity import DefaultAzureCredential

    AZURE_SQL_AVAILABLE = True
except ImportError:
    AZURE_SQL_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore


class AzureSQLCollector(BaseCollector):
    """
    Collects Azure SQL Database resources and configuration.

    Gathers SQL servers, databases, firewall rules, encryption settings,
    auditing configuration, and vulnerability assessments. All API calls
    are read-only.
    """

    collector_name = "azure_sql"
    resource_types = [
        "azure_sql_server",
        "azure_sql_database",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure SQL collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_SQL_AVAILABLE:
            raise ImportError(
                "azure-mgmt-sql is required for Azure SQL collector. "
                "Install with: pip install azure-mgmt-sql azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._client: SqlManagementClient | None = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_sql_client(self) -> SqlManagementClient:
        """Get or create SQL Management client."""
        if self._client is None:
            self._client = SqlManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Azure SQL resources.

        Returns:
            Collection of Azure SQL assets
        """
        assets: list[Asset] = []

        # Collect SQL servers and their databases
        try:
            assets.extend(self._collect_servers())
        except Exception as e:
            logger.warning(f"Failed to collect SQL servers: {e}")

        return AssetCollection(assets)

    def _collect_servers(self) -> list[Asset]:
        """Collect Azure SQL servers with their configurations."""
        client = self._get_sql_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for server in client.servers.list():
                server_id = server.id
                server_name = server.name
                resource_group = self._extract_resource_group(server_id)
                location = server.location

                # Extract tags
                tags = dict(server.tags) if server.tags else {}

                # Basic configuration
                raw_config: dict[str, Any] = {
                    "server_id": server_id,
                    "server_name": server_name,
                    "resource_group": resource_group,
                    "location": location,
                    "kind": server.kind,
                    "version": server.version,
                    "state": server.state,
                    "fully_qualified_domain_name": server.fully_qualified_domain_name,
                    "administrator_login": server.administrator_login,
                    "workspace_feature": server.workspace_feature,
                    "public_network_access": server.public_network_access,
                }

                # Minimal TLS version
                min_tls_version = server.minimal_tls_version
                raw_config["minimal_tls_version"] = min_tls_version
                raw_config["uses_tls_1_2"] = min_tls_version == "1.2" if min_tls_version else False

                # Azure AD authentication
                administrators = server.administrators
                if administrators:
                    raw_config["azure_ad_admin"] = {
                        "admin_type": administrators.administrator_type,
                        "principal_type": administrators.principal_type,
                        "login": administrators.login,
                        "sid": administrators.sid,
                        "tenant_id": administrators.tenant_id,
                        "azure_ad_only_authentication": administrators.azure_ad_only_authentication,
                    }
                    raw_config["azure_ad_only_authentication"] = (
                        administrators.azure_ad_only_authentication or False
                    )
                else:
                    raw_config["azure_ad_admin"] = None
                    raw_config["azure_ad_only_authentication"] = False

                # Private endpoint connections
                private_endpoints = server.private_endpoint_connections or []
                raw_config["private_endpoint_connections"] = [
                    {
                        "id": pe.id,
                        "name": pe.name,
                        "private_endpoint_id": (
                            pe.private_endpoint.id if pe.private_endpoint else None
                        ),
                        "status": (
                            pe.private_link_service_connection_state.status
                            if pe.private_link_service_connection_state
                            else None
                        ),
                    }
                    for pe in private_endpoints
                ]
                raw_config["has_private_endpoints"] = len(private_endpoints) > 0

                # Collect firewall rules
                try:
                    firewall_rules = self._collect_firewall_rules(
                        resource_group, server_name
                    )
                    raw_config["firewall_rules"] = firewall_rules
                    raw_config["firewall_rule_count"] = len(firewall_rules)

                    # Check for dangerous rules
                    allows_all_azure_ips = False
                    allows_any_ip = False
                    for rule in firewall_rules:
                        start_ip = rule.get("start_ip_address", "")
                        end_ip = rule.get("end_ip_address", "")
                        if start_ip == "0.0.0.0" and end_ip == "0.0.0.0":
                            allows_all_azure_ips = True
                        if start_ip == "0.0.0.0" and end_ip == "255.255.255.255":
                            allows_any_ip = True

                    raw_config["allows_all_azure_ips"] = allows_all_azure_ips
                    raw_config["allows_any_ip"] = allows_any_ip
                except Exception as e:
                    logger.debug(f"Could not get firewall rules for {server_name}: {e}")
                    raw_config["firewall_rules"] = []
                    raw_config["allows_any_ip"] = False

                # Collect virtual network rules
                try:
                    vnet_rules = self._collect_vnet_rules(resource_group, server_name)
                    raw_config["virtual_network_rules"] = vnet_rules
                    raw_config["has_vnet_rules"] = len(vnet_rules) > 0
                except Exception as e:
                    logger.debug(f"Could not get vnet rules for {server_name}: {e}")
                    raw_config["virtual_network_rules"] = []
                    raw_config["has_vnet_rules"] = False

                # Collect auditing settings
                try:
                    auditing = self._collect_auditing_settings(
                        resource_group, server_name
                    )
                    raw_config["auditing"] = auditing
                    raw_config["auditing_enabled"] = auditing.get("state") == "Enabled"
                except Exception as e:
                    logger.debug(f"Could not get auditing settings for {server_name}: {e}")
                    raw_config["auditing"] = None
                    raw_config["auditing_enabled"] = False

                # Collect threat detection settings
                try:
                    threat_detection = self._collect_threat_detection(
                        resource_group, server_name
                    )
                    raw_config["threat_detection"] = threat_detection
                    raw_config["threat_detection_enabled"] = (
                        threat_detection.get("state") == "Enabled"
                    )
                except Exception as e:
                    logger.debug(
                        f"Could not get threat detection for {server_name}: {e}"
                    )
                    raw_config["threat_detection"] = None
                    raw_config["threat_detection_enabled"] = False

                # Collect encryption protector (TDE)
                try:
                    encryption = self._collect_encryption_protector(
                        resource_group, server_name
                    )
                    raw_config["encryption_protector"] = encryption
                    raw_config["uses_customer_managed_key"] = (
                        encryption.get("server_key_type") == "AzureKeyVault"
                    )
                except Exception as e:
                    logger.debug(
                        f"Could not get encryption protector for {server_name}: {e}"
                    )
                    raw_config["encryption_protector"] = None
                    raw_config["uses_customer_managed_key"] = False

                # Collect vulnerability assessment settings
                try:
                    vuln_assessment = self._collect_vulnerability_assessment(
                        resource_group, server_name
                    )
                    raw_config["vulnerability_assessment"] = vuln_assessment
                    raw_config["vulnerability_assessment_enabled"] = (
                        vuln_assessment.get("storage_container_path") is not None
                    )
                except Exception as e:
                    logger.debug(
                        f"Could not get vulnerability assessment for {server_name}: {e}"
                    )
                    raw_config["vulnerability_assessment"] = None
                    raw_config["vulnerability_assessment_enabled"] = False

                # Collect databases for this server
                try:
                    databases = self._collect_databases(resource_group, server_name)
                    raw_config["databases"] = databases
                    raw_config["database_count"] = len(databases)
                except Exception as e:
                    logger.debug(f"Could not get databases for {server_name}: {e}")
                    raw_config["databases"] = []
                    raw_config["database_count"] = 0

                # Determine network exposure
                network_exposure = self._determine_network_exposure(raw_config)

                # Security summary
                raw_config["is_secure"] = (
                    raw_config.get("uses_tls_1_2", False) and
                    not raw_config.get("allows_any_ip", False) and
                    raw_config.get("auditing_enabled", False) and
                    raw_config.get("threat_detection_enabled", False)
                )

                assets.append(
                    Asset(
                        id=server_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=location,
                        resource_type="azure_sql_server",
                        name=server_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=None,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

                # Also add individual databases as assets
                for db in raw_config.get("databases", []):
                    db_asset = self._create_database_asset(
                        db, server_name, resource_group, location,
                        self._subscription_id, now, network_exposure
                    )
                    if db_asset:
                        assets.append(db_asset)

        except Exception as e:
            logger.error(f"Error listing SQL servers: {e}")
            raise

        return assets

    def _collect_firewall_rules(
        self, resource_group: str, server_name: str
    ) -> list[dict[str, Any]]:
        """Collect firewall rules for a SQL server."""
        client = self._get_sql_client()
        rules = []

        for rule in client.firewall_rules.list_by_server(resource_group, server_name):
            rules.append({
                "id": rule.id,
                "name": rule.name,
                "start_ip_address": rule.start_ip_address,
                "end_ip_address": rule.end_ip_address,
            })

        return rules

    def _collect_vnet_rules(
        self, resource_group: str, server_name: str
    ) -> list[dict[str, Any]]:
        """Collect virtual network rules for a SQL server."""
        client = self._get_sql_client()
        rules = []

        for rule in client.virtual_network_rules.list_by_server(
            resource_group, server_name
        ):
            rules.append({
                "id": rule.id,
                "name": rule.name,
                "virtual_network_subnet_id": rule.virtual_network_subnet_id,
                "ignore_missing_vnet_service_endpoint": (
                    rule.ignore_missing_vnet_service_endpoint
                ),
                "state": rule.state,
            })

        return rules

    def _collect_auditing_settings(
        self, resource_group: str, server_name: str
    ) -> dict[str, Any]:
        """Collect auditing settings for a SQL server."""
        client = self._get_sql_client()

        # Get blob auditing settings
        auditing = client.server_blob_auditing_policies.get(
            resource_group, server_name
        )

        return {
            "state": auditing.state,
            "storage_endpoint": auditing.storage_endpoint,
            "storage_account_subscription_id": auditing.storage_account_subscription_id,
            "retention_days": auditing.retention_days,
            "audit_actions_and_groups": auditing.audit_actions_and_groups,
            "is_storage_secondary_key_in_use": auditing.is_storage_secondary_key_in_use,
            "is_azure_monitor_target_enabled": auditing.is_azure_monitor_target_enabled,
            "queue_delay_ms": auditing.queue_delay_ms,
            "is_devops_audit_enabled": auditing.is_devops_audit_enabled,
        }

    def _collect_threat_detection(
        self, resource_group: str, server_name: str
    ) -> dict[str, Any]:
        """Collect threat detection settings for a SQL server."""
        client = self._get_sql_client()

        # Get advanced threat protection settings
        policy = client.server_advanced_threat_protection_settings.get(
            resource_group, server_name
        )

        return {
            "state": policy.state,
            "creation_time": (
                policy.creation_time.isoformat() if policy.creation_time else None
            ),
        }

    def _collect_encryption_protector(
        self, resource_group: str, server_name: str
    ) -> dict[str, Any]:
        """Collect encryption protector (TDE) settings for a SQL server."""
        client = self._get_sql_client()

        protector = client.encryption_protectors.get(
            resource_group, server_name, "current"
        )

        return {
            "kind": protector.kind,
            "server_key_name": protector.server_key_name,
            "server_key_type": protector.server_key_type,
            "uri": protector.uri,
            "thumbprint": protector.thumbprint,
            "auto_rotation_enabled": protector.auto_rotation_enabled,
        }

    def _collect_vulnerability_assessment(
        self, resource_group: str, server_name: str
    ) -> dict[str, Any]:
        """Collect vulnerability assessment settings for a SQL server."""
        client = self._get_sql_client()

        assessment = client.server_vulnerability_assessments.get(
            resource_group, server_name, "default"
        )

        recurring_scans = assessment.recurring_scans
        return {
            "storage_container_path": assessment.storage_container_path,
            "storage_container_sas_key_set": bool(
                assessment.storage_container_sas_key
            ),
            "storage_account_access_key_set": bool(
                assessment.storage_account_access_key
            ),
            "recurring_scans": {
                "is_enabled": recurring_scans.is_enabled if recurring_scans else False,
                "email_subscription_admins": (
                    recurring_scans.email_subscription_admins
                    if recurring_scans else False
                ),
                "emails": recurring_scans.emails if recurring_scans else [],
            } if recurring_scans else None,
        }

    def _collect_databases(
        self, resource_group: str, server_name: str
    ) -> list[dict[str, Any]]:
        """Collect databases for a SQL server."""
        client = self._get_sql_client()
        databases = []

        for db in client.databases.list_by_server(resource_group, server_name):
            # Skip master database
            if db.name == "master":
                continue

            db_info: dict[str, Any] = {
                "id": db.id,
                "name": db.name,
                "location": db.location,
                "kind": db.kind,
                "sku_name": db.sku.name if db.sku else None,
                "sku_tier": db.sku.tier if db.sku else None,
                "sku_capacity": db.sku.capacity if db.sku else None,
                "status": db.status,
                "creation_date": (
                    db.creation_date.isoformat() if db.creation_date else None
                ),
                "max_size_bytes": db.max_size_bytes,
                "current_service_objective_name": db.current_service_objective_name,
                "collation": db.collation,
                "catalog_collation": db.catalog_collation,
                # Replication and HA
                "zone_redundant": db.zone_redundant,
                "read_scale": db.read_scale,
                "high_availability_replica_count": db.high_availability_replica_count,
                "secondary_type": db.secondary_type,
                "failover_group_id": db.failover_group_id,
                # Backup and retention
                "earliest_restore_date": (
                    db.earliest_restore_date.isoformat()
                    if db.earliest_restore_date else None
                ),
                "requested_backup_storage_redundancy": (
                    db.requested_backup_storage_redundancy
                ),
                "current_backup_storage_redundancy": db.current_backup_storage_redundancy,
                # Licensing
                "license_type": db.license_type,
                # Ledger
                "is_ledger_on": db.is_ledger_on,
                # Managed backup
                "maintenance_configuration_id": db.maintenance_configuration_id,
                # Tags
                "tags": dict(db.tags) if db.tags else {},
            }

            # Get transparent data encryption status
            try:
                tde = client.transparent_data_encryptions.get(
                    resource_group, server_name, db.name, "current"
                )
                db_info["transparent_data_encryption"] = {
                    "state": tde.state,
                }
                db_info["tde_enabled"] = tde.state == "Enabled"
            except Exception:
                db_info["transparent_data_encryption"] = None
                db_info["tde_enabled"] = True  # Default is enabled

            databases.append(db_info)

        return databases

    def _create_database_asset(
        self,
        db: dict[str, Any],
        server_name: str,
        resource_group: str,
        location: str,
        subscription_id: str,
        now: datetime,
        network_exposure: str,
    ) -> Asset | None:
        """Create an asset for an individual database."""
        db_id = db.get("id")
        db_name = db.get("name")

        if not db_id or not db_name:
            return None

        raw_config = {
            **db,
            "server_name": server_name,
            "resource_group": resource_group,
        }

        return Asset(
            id=db_id,
            cloud_provider="azure",
            account_id=subscription_id,
            region=location,
            resource_type="azure_sql_database",
            name=db_name,
            tags=db.get("tags", {}),
            network_exposure=network_exposure,
            created_at=None,
            last_seen=now,
            raw_config=raw_config,
        )

    def _determine_network_exposure(self, raw_config: dict[str, Any]) -> str:
        """
        Determine network exposure based on server configuration.

        Args:
            raw_config: Server configuration dictionary

        Returns:
            Network exposure level
        """
        # Check if public network access is disabled
        public_access = raw_config.get("public_network_access", "Enabled")
        if public_access == "Disabled":
            if raw_config.get("has_private_endpoints", False):
                return NETWORK_EXPOSURE_INTERNAL
            return NETWORK_EXPOSURE_ISOLATED

        # Check firewall rules
        if raw_config.get("allows_any_ip", False):
            return NETWORK_EXPOSURE_INTERNET

        # Check if there are any firewall rules allowing access
        firewall_rules = raw_config.get("firewall_rules", [])
        if firewall_rules:
            return NETWORK_EXPOSURE_INTERNET

        # Check for Azure services access
        if raw_config.get("allows_all_azure_ips", False):
            return NETWORK_EXPOSURE_INTERNAL

        # Check for VNet rules
        if raw_config.get("has_vnet_rules", False):
            return NETWORK_EXPOSURE_INTERNAL

        # Check for private endpoints
        if raw_config.get("has_private_endpoints", False):
            return NETWORK_EXPOSURE_INTERNAL

        # Default: public access enabled but no rules = internet facing
        # (Azure SQL requires either firewall rules or no public access)
        return NETWORK_EXPOSURE_INTERNET

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
