"""
Azure Cosmos DB collector for Mantissa Stance.

Collects Azure Cosmos DB accounts, databases, and their security configurations
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
    from azure.mgmt.cosmosdb import CosmosDBManagementClient
    from azure.identity import DefaultAzureCredential

    AZURE_COSMOSDB_AVAILABLE = True
except ImportError:
    AZURE_COSMOSDB_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore


class AzureCosmosDBCollector(BaseCollector):
    """
    Collects Azure Cosmos DB resources and configuration.

    Gathers Cosmos DB accounts with their security settings including:
    - Network access controls (firewall, VNet, private endpoints)
    - Encryption configuration (service-managed vs customer-managed keys)
    - Authentication and RBAC settings
    - Backup policies
    - Consistency levels and replication

    All API calls are read-only.
    """

    collector_name = "azure_cosmosdb"
    resource_types = [
        "azure_cosmosdb_account",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure Cosmos DB collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_COSMOSDB_AVAILABLE:
            raise ImportError(
                "azure-mgmt-cosmosdb is required for Azure Cosmos DB collector. "
                "Install with: pip install azure-mgmt-cosmosdb azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._client: CosmosDBManagementClient | None = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_cosmosdb_client(self) -> CosmosDBManagementClient:
        """Get or create Cosmos DB Management client."""
        if self._client is None:
            self._client = CosmosDBManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def _extract_resource_group(self, resource_id: str) -> str:
        """Extract resource group name from resource ID."""
        if not resource_id:
            return ""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""

    def collect(self) -> AssetCollection:
        """
        Collect all Azure Cosmos DB resources.

        Returns:
            Collection of Azure Cosmos DB assets
        """
        assets: list[Asset] = []

        # Collect Cosmos DB accounts
        try:
            assets.extend(self._collect_accounts())
        except Exception as e:
            logger.warning(f"Failed to collect Cosmos DB accounts: {e}")

        return AssetCollection(assets)

    def _collect_accounts(self) -> list[Asset]:
        """Collect Azure Cosmos DB accounts with their configurations."""
        client = self._get_cosmosdb_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for account in client.database_accounts.list():
                account_id = account.id
                account_name = account.name
                resource_group = self._extract_resource_group(account_id)
                location = account.location

                # Extract tags
                tags = dict(account.tags) if account.tags else {}

                # Database account offer type (Standard)
                database_account_offer_type = account.database_account_offer_type

                # API type (SQL, MongoDB, Cassandra, Gremlin, Table)
                kind = account.kind
                api_properties = account.api_properties
                capabilities = account.capabilities or []
                capability_names = [cap.name for cap in capabilities if cap.name]

                # Determine API type from capabilities and kind
                api_type = self._determine_api_type(kind, capability_names)

                # Consistency policy
                consistency_policy = account.consistency_policy
                consistency_config = {}
                if consistency_policy:
                    consistency_config = {
                        "default_consistency_level": consistency_policy.default_consistency_level,
                        "max_staleness_prefix": consistency_policy.max_staleness_prefix,
                        "max_interval_in_seconds": consistency_policy.max_interval_in_seconds,
                    }

                # Locations / geo-replication
                locations = account.locations or []
                location_configs = [
                    {
                        "location_name": loc.location_name,
                        "failover_priority": loc.failover_priority,
                        "is_zone_redundant": loc.is_zone_redundant,
                        "document_endpoint": loc.document_endpoint,
                    }
                    for loc in locations
                ]
                is_multi_region = len(locations) > 1

                # Write locations
                write_locations = account.write_locations or []
                write_location_names = [loc.location_name for loc in write_locations]

                # Read locations
                read_locations = account.read_locations or []
                read_location_names = [loc.location_name for loc in read_locations]

                # Network configuration
                public_network_access = account.public_network_access
                is_public_network_enabled = (
                    public_network_access == "Enabled"
                    if public_network_access
                    else True  # Default is enabled
                )

                # IP rules (firewall)
                ip_rules = account.ip_rules or []
                ip_range_filter = [rule.ip_address_or_range for rule in ip_rules]
                allows_any_ip = "0.0.0.0" in ip_range_filter or "" in ip_range_filter

                # Virtual network rules
                virtual_network_rules = account.virtual_network_rules or []
                vnet_rules = [
                    {
                        "id": rule.id,
                        "ignore_missing_vnet_service_endpoint": rule.ignore_missing_v_net_service_endpoint,
                    }
                    for rule in virtual_network_rules
                ]
                has_vnet_rules = len(vnet_rules) > 0

                # Private endpoint connections
                private_endpoints = account.private_endpoint_connections or []
                private_endpoint_configs = [
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
                has_private_endpoints = len(private_endpoint_configs) > 0

                # Encryption configuration
                key_vault_key_uri = account.key_vault_key_uri
                uses_cmek = bool(key_vault_key_uri)

                # Backup policy
                backup_policy = account.backup_policy
                backup_config = {}
                if backup_policy:
                    backup_type = type(backup_policy).__name__
                    backup_config["backup_type"] = backup_type

                    # Periodic backup policy
                    if hasattr(backup_policy, "periodic_mode_properties"):
                        props = backup_policy.periodic_mode_properties
                        if props:
                            backup_config["backup_interval_in_minutes"] = props.backup_interval_in_minutes
                            backup_config["backup_retention_interval_in_hours"] = props.backup_retention_interval_in_hours
                            backup_config["backup_storage_redundancy"] = props.backup_storage_redundancy

                    # Continuous backup policy
                    if hasattr(backup_policy, "continuous_mode_properties"):
                        props = backup_policy.continuous_mode_properties
                        if props:
                            backup_config["continuous_tier"] = props.tier

                # Authentication and access
                disable_key_based_metadata_write_access = (
                    account.disable_key_based_metadata_write_access or False
                )
                enable_automatic_failover = account.enable_automatic_failover or False
                enable_multiple_write_locations = account.enable_multiple_write_locations or False
                enable_analytical_storage = account.enable_analytical_storage or False
                enable_free_tier = account.enable_free_tier or False

                # CORS settings
                cors = account.cors or []
                cors_rules = [
                    {
                        "allowed_origins": rule.allowed_origins,
                        "allowed_methods": rule.allowed_methods,
                        "allowed_headers": rule.allowed_headers,
                        "exposed_headers": rule.exposed_headers,
                        "max_age_in_seconds": rule.max_age_in_seconds,
                    }
                    for rule in cors
                ]
                allows_all_origins = any(
                    "*" in (rule.allowed_origins or "") for rule in cors
                )

                # Network ACL bypass
                network_acl_bypass = account.network_acl_bypass
                network_acl_bypass_resource_ids = (
                    account.network_acl_bypass_resource_ids or []
                )

                # Minimal TLS version
                minimal_tls_version = account.minimal_tls_version
                uses_tls_1_2 = minimal_tls_version == "Tls12" if minimal_tls_version else False

                # Disable local authentication (keys)
                disable_local_auth = account.disable_local_auth or False

                # Build raw config
                raw_config: dict[str, Any] = {
                    "account_id": account_id,
                    "account_name": account_name,
                    "resource_group": resource_group,
                    "location": location,
                    "kind": kind,
                    "api_type": api_type,
                    "database_account_offer_type": database_account_offer_type,
                    "document_endpoint": account.document_endpoint,
                    "provisioning_state": account.provisioning_state,
                    # Consistency
                    "consistency_policy": consistency_config,
                    # Geo-replication
                    "locations": location_configs,
                    "is_multi_region": is_multi_region,
                    "write_locations": write_location_names,
                    "read_locations": read_location_names,
                    "enable_automatic_failover": enable_automatic_failover,
                    "enable_multiple_write_locations": enable_multiple_write_locations,
                    # Network access
                    "public_network_access": public_network_access,
                    "is_public_network_enabled": is_public_network_enabled,
                    "ip_rules": ip_range_filter,
                    "allows_any_ip": allows_any_ip,
                    "virtual_network_rules": vnet_rules,
                    "has_vnet_rules": has_vnet_rules,
                    "private_endpoint_connections": private_endpoint_configs,
                    "has_private_endpoints": has_private_endpoints,
                    "network_acl_bypass": network_acl_bypass,
                    "network_acl_bypass_resource_ids": network_acl_bypass_resource_ids,
                    # Encryption
                    "key_vault_key_uri": key_vault_key_uri,
                    "uses_cmek": uses_cmek,
                    # Authentication
                    "disable_local_auth": disable_local_auth,
                    "disable_key_based_metadata_write_access": disable_key_based_metadata_write_access,
                    # TLS
                    "minimal_tls_version": minimal_tls_version,
                    "uses_tls_1_2": uses_tls_1_2,
                    # Backup
                    "backup_policy": backup_config,
                    # Features
                    "capabilities": capability_names,
                    "enable_analytical_storage": enable_analytical_storage,
                    "enable_free_tier": enable_free_tier,
                    # CORS
                    "cors_rules": cors_rules,
                    "allows_all_origins": allows_all_origins,
                }

                # Determine network exposure
                network_exposure = self._determine_network_exposure(
                    is_public_network_enabled=is_public_network_enabled,
                    allows_any_ip=allows_any_ip,
                    has_vnet_rules=has_vnet_rules,
                    has_private_endpoints=has_private_endpoints,
                    ip_rules=ip_range_filter,
                )

                asset = Asset(
                    id=account_id,
                    cloud_provider="azure",
                    account_id=self._subscription_id,
                    region=location,
                    resource_type="azure_cosmosdb_account",
                    name=account_name,
                    tags=tags,
                    network_exposure=network_exposure,
                    created_at=now,  # Creation time not exposed by API
                    last_seen=now,
                    raw_config=raw_config,
                )
                assets.append(asset)

        except Exception as e:
            logger.error(f"Error listing Cosmos DB accounts: {e}")
            raise

        return assets

    def _determine_api_type(
        self, kind: str | None, capabilities: list[str]
    ) -> str:
        """
        Determine the Cosmos DB API type from kind and capabilities.

        Args:
            kind: Account kind (GlobalDocumentDB, MongoDB, Parse)
            capabilities: List of capability names

        Returns:
            API type string
        """
        # Check capabilities for specific API types
        capability_set = set(capabilities)

        if "EnableCassandra" in capability_set:
            return "Cassandra"
        if "EnableGremlin" in capability_set:
            return "Gremlin"
        if "EnableTable" in capability_set:
            return "Table"
        if "EnableMongo" in capability_set or kind == "MongoDB":
            return "MongoDB"

        # Default to SQL (Core) API
        return "SQL"

    def _determine_network_exposure(
        self,
        is_public_network_enabled: bool,
        allows_any_ip: bool,
        has_vnet_rules: bool,
        has_private_endpoints: bool,
        ip_rules: list[str],
    ) -> str:
        """
        Determine network exposure level for a Cosmos DB account.

        Args:
            is_public_network_enabled: Whether public network access is enabled
            allows_any_ip: Whether firewall allows 0.0.0.0 (all IPs)
            has_vnet_rules: Whether VNet rules are configured
            has_private_endpoints: Whether private endpoints exist
            ip_rules: List of IP firewall rules

        Returns:
            Network exposure level
        """
        # Private endpoints only = isolated
        if has_private_endpoints and not is_public_network_enabled:
            return NETWORK_EXPOSURE_ISOLATED

        # Public network disabled = internal (VNet or private only)
        if not is_public_network_enabled:
            return NETWORK_EXPOSURE_INTERNAL

        # Public network enabled
        if is_public_network_enabled:
            # No IP rules and no VNet rules = open to internet
            if not ip_rules and not has_vnet_rules:
                return NETWORK_EXPOSURE_INTERNET

            # Allows any IP via firewall
            if allows_any_ip:
                return NETWORK_EXPOSURE_INTERNET

            # Has specific IP rules or VNet rules = restricted but accessible
            if ip_rules or has_vnet_rules:
                return NETWORK_EXPOSURE_INTERNET

        # Default to internal
        return NETWORK_EXPOSURE_INTERNAL
