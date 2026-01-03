"""
Azure Storage collector for Mantissa Stance.

Collects Azure Storage account configurations including blob containers,
access policies, encryption settings, and network rules for security posture assessment.
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
)

logger = logging.getLogger(__name__)

# Optional Azure imports
try:
    from azure.mgmt.storage import StorageManagementClient
    from azure.identity import DefaultAzureCredential

    AZURE_STORAGE_AVAILABLE = True
except ImportError:
    AZURE_STORAGE_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore


class AzureStorageCollector(BaseCollector):
    """
    Collects Azure Storage account resources and configuration.

    Gathers storage accounts, blob containers, access policies,
    encryption settings, and network rules. All API calls are read-only.
    """

    collector_name = "azure_storage"
    resource_types = [
        "azure_storage_account",
        "azure_blob_container",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure Storage collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_STORAGE_AVAILABLE:
            raise ImportError(
                "azure-mgmt-storage is required for Azure storage collector. "
                "Install with: pip install azure-mgmt-storage azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._client: StorageManagementClient | None = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_storage_client(self) -> StorageManagementClient:
        """Get or create Storage Management client."""
        if self._client is None:
            self._client = StorageManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Storage resources.

        Returns:
            Collection of storage assets
        """
        assets: list[Asset] = []

        try:
            assets.extend(self._collect_storage_accounts())
        except Exception as e:
            logger.warning(f"Failed to collect storage accounts: {e}")

        return AssetCollection(assets)

    def _collect_storage_accounts(self) -> list[Asset]:
        """Collect Azure Storage accounts with their configurations."""
        client = self._get_storage_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for account in client.storage_accounts.list():
                account_id = account.id
                account_name = account.name
                resource_group = self._extract_resource_group(account_id)
                location = account.location

                # Extract tags
                tags = dict(account.tags) if account.tags else {}

                # Basic configuration
                raw_config: dict[str, Any] = {
                    "account_id": account_id,
                    "account_name": account_name,
                    "resource_group": resource_group,
                    "location": location,
                    "kind": account.kind,
                    "sku_name": account.sku.name if account.sku else None,
                    "sku_tier": account.sku.tier if account.sku else None,
                    "provisioning_state": account.provisioning_state,
                    "creation_time": (
                        account.creation_time.isoformat()
                        if account.creation_time
                        else None
                    ),
                    "primary_location": account.primary_location,
                    "secondary_location": account.secondary_location,
                    "status_of_primary": account.status_of_primary,
                    "status_of_secondary": account.status_of_secondary,
                }

                # HTTPS-only traffic
                https_only = account.enable_https_traffic_only
                raw_config["https_traffic_only"] = https_only

                # Minimum TLS version
                min_tls = account.minimum_tls_version
                raw_config["minimum_tls_version"] = min_tls
                raw_config["uses_tls_1_2"] = min_tls == "TLS1_2" if min_tls else False

                # Public blob access
                allow_blob_public_access = account.allow_blob_public_access
                raw_config["allow_blob_public_access"] = allow_blob_public_access

                # Shared key access
                allow_shared_key_access = account.allow_shared_key_access
                raw_config["allow_shared_key_access"] = (
                    allow_shared_key_access if allow_shared_key_access is not None else True
                )

                # Network rules
                network_rules = account.network_rule_set
                if network_rules:
                    default_action = network_rules.default_action
                    raw_config["network_rules"] = {
                        "default_action": default_action,
                        "bypass": network_rules.bypass,
                        "virtual_network_rules": [
                            {"id": r.virtual_network_resource_id, "action": r.action}
                            for r in (network_rules.virtual_network_rules or [])
                        ],
                        "ip_rules": [
                            {"value": r.ip_address_or_range, "action": r.action}
                            for r in (network_rules.ip_rules or [])
                        ],
                    }
                    raw_config["allows_public_network_access"] = default_action == "Allow"
                else:
                    raw_config["network_rules"] = None
                    raw_config["allows_public_network_access"] = True

                # Encryption configuration
                encryption = account.encryption
                if encryption:
                    raw_config["encryption"] = {
                        "key_source": encryption.key_source,
                        "require_infrastructure_encryption": (
                            encryption.require_infrastructure_encryption
                        ),
                        "services": {
                            "blob": {
                                "enabled": encryption.services.blob.enabled
                                if encryption.services and encryption.services.blob
                                else False,
                                "key_type": encryption.services.blob.key_type
                                if encryption.services and encryption.services.blob
                                else None,
                            },
                            "file": {
                                "enabled": encryption.services.file.enabled
                                if encryption.services and encryption.services.file
                                else False,
                            },
                            "table": {
                                "enabled": encryption.services.table.enabled
                                if encryption.services and encryption.services.table
                                else False,
                            },
                            "queue": {
                                "enabled": encryption.services.queue.enabled
                                if encryption.services and encryption.services.queue
                                else False,
                            },
                        },
                    }
                    raw_config["uses_customer_managed_keys"] = (
                        encryption.key_source == "Microsoft.Keyvault"
                    )
                else:
                    raw_config["encryption"] = None
                    raw_config["uses_customer_managed_keys"] = False

                # Blob service properties (soft delete, versioning)
                try:
                    blob_props = client.blob_services.get_service_properties(
                        resource_group, account_name
                    )
                    if blob_props:
                        raw_config["blob_service"] = {
                            "delete_retention_enabled": (
                                blob_props.delete_retention_policy.enabled
                                if blob_props.delete_retention_policy
                                else False
                            ),
                            "delete_retention_days": (
                                blob_props.delete_retention_policy.days
                                if blob_props.delete_retention_policy
                                else None
                            ),
                            "container_delete_retention_enabled": (
                                blob_props.container_delete_retention_policy.enabled
                                if blob_props.container_delete_retention_policy
                                else False
                            ),
                            "versioning_enabled": (
                                blob_props.is_versioning_enabled
                                if hasattr(blob_props, "is_versioning_enabled")
                                else False
                            ),
                            "change_feed_enabled": (
                                blob_props.change_feed.enabled
                                if blob_props.change_feed
                                else False
                            ),
                        }
                except Exception as e:
                    logger.debug(f"Could not get blob service properties for {account_name}: {e}")

                # Get blob containers
                try:
                    containers = []
                    public_containers = []
                    for container in client.blob_containers.list(
                        resource_group, account_name
                    ):
                        container_info = {
                            "name": container.name,
                            "public_access": container.public_access,
                            "has_immutability_policy": container.has_immutability_policy,
                            "has_legal_hold": container.has_legal_hold,
                            "deleted": container.deleted,
                            "last_modified": (
                                container.last_modified_time.isoformat()
                                if container.last_modified_time
                                else None
                            ),
                        }
                        containers.append(container_info)

                        # Track public containers
                        if container.public_access and container.public_access != "None":
                            public_containers.append(container.name)

                    raw_config["containers"] = containers
                    raw_config["container_count"] = len(containers)
                    raw_config["public_containers"] = public_containers
                    raw_config["has_public_containers"] = len(public_containers) > 0
                except Exception as e:
                    logger.debug(f"Could not list containers for {account_name}: {e}")

                # Determine network exposure
                network_exposure = NETWORK_EXPOSURE_INTERNAL
                if (
                    raw_config.get("allows_public_network_access", True) or
                    raw_config.get("has_public_containers", False) or
                    allow_blob_public_access
                ):
                    network_exposure = NETWORK_EXPOSURE_INTERNET

                # Security summary flags
                raw_config["is_secure"] = (
                    https_only and
                    raw_config.get("uses_tls_1_2", False) and
                    not raw_config.get("allows_public_network_access", True) and
                    not raw_config.get("has_public_containers", False)
                )

                created_at = None
                if account.creation_time:
                    created_at = account.creation_time.replace(tzinfo=timezone.utc)

                assets.append(
                    Asset(
                        id=account_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=location,
                        resource_type="azure_storage_account",
                        name=account_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing storage accounts: {e}")
            raise

        return assets

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
