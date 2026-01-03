"""
Azure Kubernetes Service (AKS) collector for Mantissa Stance.

Collects Azure AKS clusters, node pools, and security configurations
for posture assessment. Covers Azure AD integration, network policies,
managed identity, and Kubernetes RBAC settings.
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
    from azure.mgmt.containerservice import ContainerServiceClient
    from azure.identity import DefaultAzureCredential

    AZURE_AKS_AVAILABLE = True
except ImportError:
    AZURE_AKS_AVAILABLE = False
    ContainerServiceClient = Any  # type: ignore
    DefaultAzureCredential = Any  # type: ignore


class AzureAKSCollector(BaseCollector):
    """
    Collects Azure Kubernetes Service resources and configuration.

    Gathers AKS clusters, agent pools (node pools), and their security
    configurations including Azure AD integration, network policies,
    managed identity settings, and RBAC. All API calls are read-only.
    """

    collector_name = "azure_aks"
    resource_types = [
        "azure_aks_cluster",
        "azure_aks_nodepool",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure AKS collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_AKS_AVAILABLE:
            raise ImportError(
                "azure-mgmt-containerservice is required for Azure AKS collector. "
                "Install with: pip install azure-mgmt-containerservice azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._client: ContainerServiceClient | None = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_aks_client(self) -> ContainerServiceClient:
        """Get or create Container Service client."""
        if self._client is None:
            self._client = ContainerServiceClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Azure AKS resources.

        Returns:
            Collection of AKS cluster and node pool assets
        """
        assets: list[Asset] = []

        try:
            assets.extend(self._collect_clusters())
        except Exception as e:
            logger.warning(f"Failed to collect AKS clusters: {e}")

        return AssetCollection(assets)

    def _collect_clusters(self) -> list[Asset]:
        """Collect AKS clusters with their configurations."""
        client = self._get_aks_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for cluster in client.managed_clusters.list():
                cluster_id = cluster.id
                cluster_name = cluster.name
                resource_group = self._extract_resource_group(cluster_id)
                location = cluster.location

                # Extract tags
                tags = dict(cluster.tags) if cluster.tags else {}

                raw_config: dict[str, Any] = {
                    "cluster_id": cluster_id,
                    "cluster_name": cluster_name,
                    "resource_group": resource_group,
                    "location": location,
                    "provisioning_state": cluster.provisioning_state,
                    "power_state": (
                        cluster.power_state.code if cluster.power_state else None
                    ),
                    "kubernetes_version": cluster.kubernetes_version,
                    "current_kubernetes_version": cluster.current_kubernetes_version,
                    "dns_prefix": cluster.dns_prefix,
                    "fqdn": cluster.fqdn,
                    "private_fqdn": cluster.private_fqdn,
                    "azure_portal_fqdn": cluster.azure_portal_fqdn,
                }

                # Identity configuration
                identity = cluster.identity
                if identity:
                    raw_config["identity"] = {
                        "type": identity.type,
                        "principal_id": identity.principal_id,
                        "tenant_id": identity.tenant_id,
                        "user_assigned_identities": (
                            list(identity.user_assigned_identities.keys())
                            if identity.user_assigned_identities
                            else []
                        ),
                    }
                    raw_config["uses_managed_identity"] = True
                    raw_config["identity_type"] = identity.type
                else:
                    raw_config["identity"] = None
                    raw_config["uses_managed_identity"] = False
                    raw_config["identity_type"] = None

                # Service principal (legacy)
                service_principal = cluster.service_principal_profile
                if service_principal:
                    raw_config["service_principal"] = {
                        "client_id": service_principal.client_id,
                    }
                    raw_config["uses_service_principal"] = (
                        service_principal.client_id not in [None, "", "msi"]
                    )
                else:
                    raw_config["service_principal"] = None
                    raw_config["uses_service_principal"] = False

                # Azure AD integration (AAD RBAC)
                aad_profile = cluster.aad_profile
                if aad_profile:
                    raw_config["aad_profile"] = {
                        "managed": aad_profile.managed,
                        "enable_azure_rbac": aad_profile.enable_azure_rbac,
                        "admin_group_object_ids": (
                            list(aad_profile.admin_group_object_ids)
                            if aad_profile.admin_group_object_ids
                            else []
                        ),
                        "tenant_id": aad_profile.tenant_id,
                    }
                    raw_config["aad_enabled"] = True
                    raw_config["azure_rbac_enabled"] = aad_profile.enable_azure_rbac
                    raw_config["aad_managed"] = aad_profile.managed
                else:
                    raw_config["aad_profile"] = None
                    raw_config["aad_enabled"] = False
                    raw_config["azure_rbac_enabled"] = False
                    raw_config["aad_managed"] = False

                # Kubernetes RBAC
                raw_config["enable_rbac"] = cluster.enable_rbac

                # API server access profile
                api_server = cluster.api_server_access_profile
                if api_server:
                    raw_config["api_server_access_profile"] = {
                        "authorized_ip_ranges": (
                            list(api_server.authorized_ip_ranges)
                            if api_server.authorized_ip_ranges
                            else []
                        ),
                        "enable_private_cluster": api_server.enable_private_cluster,
                        "private_dns_zone": api_server.private_dns_zone,
                        "enable_private_cluster_public_fqdn": (
                            api_server.enable_private_cluster_public_fqdn
                        ),
                        "disable_run_command": api_server.disable_run_command,
                    }
                    raw_config["is_private_cluster"] = api_server.enable_private_cluster
                    raw_config["has_authorized_ip_ranges"] = bool(
                        api_server.authorized_ip_ranges
                    )
                    raw_config["authorized_ip_ranges"] = (
                        list(api_server.authorized_ip_ranges)
                        if api_server.authorized_ip_ranges
                        else []
                    )
                    raw_config["run_command_disabled"] = api_server.disable_run_command
                else:
                    raw_config["api_server_access_profile"] = None
                    raw_config["is_private_cluster"] = False
                    raw_config["has_authorized_ip_ranges"] = False
                    raw_config["authorized_ip_ranges"] = []
                    raw_config["run_command_disabled"] = False

                # Network profile
                network_profile = cluster.network_profile
                if network_profile:
                    raw_config["network_profile"] = {
                        "network_plugin": network_profile.network_plugin,
                        "network_plugin_mode": network_profile.network_plugin_mode,
                        "network_policy": network_profile.network_policy,
                        "network_mode": network_profile.network_mode,
                        "pod_cidr": network_profile.pod_cidr,
                        "service_cidr": network_profile.service_cidr,
                        "dns_service_ip": network_profile.dns_service_ip,
                        "outbound_type": network_profile.outbound_type,
                        "load_balancer_sku": network_profile.load_balancer_sku,
                        "ip_families": (
                            list(network_profile.ip_families)
                            if network_profile.ip_families
                            else []
                        ),
                    }
                    raw_config["network_plugin"] = network_profile.network_plugin
                    raw_config["network_policy"] = network_profile.network_policy
                    raw_config["has_network_policy"] = network_profile.network_policy is not None
                    raw_config["outbound_type"] = network_profile.outbound_type
                else:
                    raw_config["network_profile"] = None
                    raw_config["network_plugin"] = None
                    raw_config["network_policy"] = None
                    raw_config["has_network_policy"] = False
                    raw_config["outbound_type"] = None

                # Linux profile (SSH access)
                linux_profile = cluster.linux_profile
                if linux_profile:
                    raw_config["linux_profile"] = {
                        "admin_username": linux_profile.admin_username,
                        "ssh_keys": (
                            len(linux_profile.ssh.public_keys)
                            if linux_profile.ssh and linux_profile.ssh.public_keys
                            else 0
                        ),
                    }
                    raw_config["has_ssh_access"] = True
                else:
                    raw_config["linux_profile"] = None
                    raw_config["has_ssh_access"] = False

                # Windows profile
                windows_profile = cluster.windows_profile
                if windows_profile:
                    raw_config["windows_profile"] = {
                        "admin_username": windows_profile.admin_username,
                        "enable_csi_proxy": windows_profile.enable_csi_proxy,
                        "gmsa_profile": (
                            {"enabled": windows_profile.gmsa_profile.enabled}
                            if windows_profile.gmsa_profile
                            else None
                        ),
                    }
                    raw_config["has_windows_nodes"] = True
                else:
                    raw_config["windows_profile"] = None
                    raw_config["has_windows_nodes"] = False

                # Auto upgrade profile
                auto_upgrade = cluster.auto_upgrade_profile
                if auto_upgrade:
                    raw_config["auto_upgrade_profile"] = {
                        "upgrade_channel": auto_upgrade.upgrade_channel,
                        "node_os_upgrade_channel": auto_upgrade.node_os_upgrade_channel,
                    }
                    raw_config["auto_upgrade_enabled"] = (
                        auto_upgrade.upgrade_channel is not None and
                        auto_upgrade.upgrade_channel != "none"
                    )
                    raw_config["upgrade_channel"] = auto_upgrade.upgrade_channel
                else:
                    raw_config["auto_upgrade_profile"] = None
                    raw_config["auto_upgrade_enabled"] = False
                    raw_config["upgrade_channel"] = None

                # Security profile
                security_profile = cluster.security_profile
                if security_profile:
                    raw_config["security_profile"] = {
                        "defender": {
                            "log_analytics_workspace_resource_id": (
                                security_profile.defender.log_analytics_workspace_resource_id
                                if security_profile.defender
                                else None
                            ),
                            "security_monitoring_enabled": (
                                security_profile.defender.security_monitoring.enabled
                                if security_profile.defender and security_profile.defender.security_monitoring
                                else False
                            ),
                        } if security_profile.defender else None,
                        "workload_identity": {
                            "enabled": (
                                security_profile.workload_identity.enabled
                                if security_profile.workload_identity
                                else False
                            ),
                        } if security_profile.workload_identity else None,
                        "image_cleaner": {
                            "enabled": (
                                security_profile.image_cleaner.enabled
                                if security_profile.image_cleaner
                                else False
                            ),
                            "interval_hours": (
                                security_profile.image_cleaner.interval_hours
                                if security_profile.image_cleaner
                                else None
                            ),
                        } if security_profile.image_cleaner else None,
                        "azure_key_vault_kms": {
                            "enabled": (
                                security_profile.azure_key_vault_kms.enabled
                                if security_profile.azure_key_vault_kms
                                else False
                            ),
                            "key_id": (
                                security_profile.azure_key_vault_kms.key_id
                                if security_profile.azure_key_vault_kms
                                else None
                            ),
                        } if security_profile.azure_key_vault_kms else None,
                    }
                    raw_config["defender_enabled"] = (
                        security_profile.defender is not None and
                        security_profile.defender.security_monitoring is not None and
                        security_profile.defender.security_monitoring.enabled
                    )
                    raw_config["workload_identity_enabled"] = (
                        security_profile.workload_identity is not None and
                        security_profile.workload_identity.enabled
                    )
                    raw_config["image_cleaner_enabled"] = (
                        security_profile.image_cleaner is not None and
                        security_profile.image_cleaner.enabled
                    )
                    raw_config["kms_enabled"] = (
                        security_profile.azure_key_vault_kms is not None and
                        security_profile.azure_key_vault_kms.enabled
                    )
                else:
                    raw_config["security_profile"] = None
                    raw_config["defender_enabled"] = False
                    raw_config["workload_identity_enabled"] = False
                    raw_config["image_cleaner_enabled"] = False
                    raw_config["kms_enabled"] = False

                # OIDC issuer profile (for workload identity federation)
                oidc_issuer = cluster.oidc_issuer_profile
                if oidc_issuer:
                    raw_config["oidc_issuer_profile"] = {
                        "enabled": oidc_issuer.enabled,
                        "issuer_url": oidc_issuer.issuer_url,
                    }
                    raw_config["oidc_issuer_enabled"] = oidc_issuer.enabled
                else:
                    raw_config["oidc_issuer_profile"] = None
                    raw_config["oidc_issuer_enabled"] = False

                # HTTP proxy config
                http_proxy = cluster.http_proxy_config
                if http_proxy:
                    raw_config["http_proxy_config"] = {
                        "http_proxy": http_proxy.http_proxy,
                        "https_proxy": http_proxy.https_proxy,
                        "no_proxy": (
                            list(http_proxy.no_proxy) if http_proxy.no_proxy else []
                        ),
                    }
                    raw_config["uses_http_proxy"] = True
                else:
                    raw_config["http_proxy_config"] = None
                    raw_config["uses_http_proxy"] = False

                # Storage profile
                storage_profile = cluster.storage_profile
                if storage_profile:
                    raw_config["storage_profile"] = {
                        "disk_csi_driver": (
                            {"enabled": storage_profile.disk_csi_driver.enabled}
                            if storage_profile.disk_csi_driver
                            else None
                        ),
                        "file_csi_driver": (
                            {"enabled": storage_profile.file_csi_driver.enabled}
                            if storage_profile.file_csi_driver
                            else None
                        ),
                        "blob_csi_driver": (
                            {"enabled": storage_profile.blob_csi_driver.enabled}
                            if storage_profile.blob_csi_driver
                            else None
                        ),
                        "snapshot_controller": (
                            {"enabled": storage_profile.snapshot_controller.enabled}
                            if storage_profile.snapshot_controller
                            else None
                        ),
                    }
                else:
                    raw_config["storage_profile"] = None

                # Addon profiles
                addon_profiles = cluster.addon_profiles or {}
                raw_config["addon_profiles"] = {}
                for addon_name, addon in addon_profiles.items():
                    raw_config["addon_profiles"][addon_name] = {
                        "enabled": addon.enabled,
                        "config": dict(addon.config) if addon.config else {},
                    }

                # Check specific addons
                raw_config["azure_policy_enabled"] = (
                    "azurepolicy" in addon_profiles and
                    addon_profiles["azurepolicy"].enabled
                )
                raw_config["oms_agent_enabled"] = (
                    "omsagent" in addon_profiles and
                    addon_profiles["omsagent"].enabled
                )
                raw_config["key_vault_secrets_provider_enabled"] = (
                    "azureKeyvaultSecretsProvider" in addon_profiles and
                    addon_profiles["azureKeyvaultSecretsProvider"].enabled
                )

                # Disable local accounts (enhanced security)
                raw_config["disable_local_accounts"] = cluster.disable_local_accounts

                # SKU tier
                sku = cluster.sku
                if sku:
                    raw_config["sku"] = {
                        "name": sku.name,
                        "tier": sku.tier,
                    }
                    raw_config["sku_tier"] = sku.tier
                else:
                    raw_config["sku"] = None
                    raw_config["sku_tier"] = None

                # Agent pool profiles (node pools) - collect as separate assets
                node_pools = []
                agent_pool_profiles = cluster.agent_pool_profiles or []
                for pool in agent_pool_profiles:
                    pool_config = self._extract_agent_pool_config(pool, cluster)
                    node_pools.append(pool_config)

                    # Create node pool as separate asset
                    pool_id = f"{cluster_id}/agentPools/{pool.name}"
                    pool_asset = Asset(
                        id=pool_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=location,
                        resource_type="azure_aks_nodepool",
                        name=pool.name,
                        tags=dict(pool.tags) if pool.tags else {},
                        network_exposure=NETWORK_EXPOSURE_INTERNAL,
                        last_seen=now,
                        raw_config=pool_config,
                    )
                    assets.append(pool_asset)

                raw_config["agent_pools"] = node_pools
                raw_config["agent_pool_count"] = len(node_pools)
                raw_config["total_node_count"] = sum(
                    p.get("count", 0) for p in node_pools
                )

                # Determine network exposure
                network_exposure = NETWORK_EXPOSURE_INTERNAL
                if not raw_config.get("is_private_cluster", False):
                    network_exposure = NETWORK_EXPOSURE_INTERNET

                created_at = None
                # AKS doesn't expose creation_date directly, check power_state for running

                cluster_asset = Asset(
                    id=cluster_id,
                    cloud_provider="azure",
                    account_id=self._subscription_id,
                    region=location,
                    resource_type="azure_aks_cluster",
                    name=cluster_name,
                    tags=tags,
                    network_exposure=network_exposure,
                    created_at=created_at,
                    last_seen=now,
                    raw_config=raw_config,
                )
                assets.append(cluster_asset)

        except Exception as e:
            logger.error(f"Error listing AKS clusters: {e}")
            raise

        return assets

    def _extract_agent_pool_config(
        self, pool: Any, cluster: Any
    ) -> dict[str, Any]:
        """
        Extract configuration from an agent pool (node pool).

        Args:
            pool: Agent pool profile object
            cluster: Parent cluster object

        Returns:
            Agent pool configuration dictionary
        """
        config: dict[str, Any] = {
            "name": pool.name,
            "count": pool.count,
            "vm_size": pool.vm_size,
            "os_disk_size_gb": pool.os_disk_size_gb,
            "os_disk_type": pool.os_disk_type,
            "os_type": pool.os_type,
            "os_sku": pool.os_sku,
            "mode": pool.mode,
            "type": pool.type,
            "provisioning_state": pool.provisioning_state,
            "power_state": pool.power_state.code if pool.power_state else None,
            "orchestrator_version": pool.orchestrator_version,
            "current_orchestrator_version": pool.current_orchestrator_version,
            "node_image_version": pool.node_image_version,
        }

        # Availability zones
        config["availability_zones"] = (
            list(pool.availability_zones) if pool.availability_zones else []
        )
        config["uses_availability_zones"] = bool(pool.availability_zones)

        # Autoscaling
        config["enable_auto_scaling"] = pool.enable_auto_scaling
        config["min_count"] = pool.min_count
        config["max_count"] = pool.max_count

        # Spot instances
        config["scale_set_priority"] = pool.scale_set_priority
        config["is_spot_instance"] = pool.scale_set_priority == "Spot"
        config["spot_max_price"] = pool.spot_max_price
        config["scale_set_eviction_policy"] = pool.scale_set_eviction_policy

        # Network
        config["vnet_subnet_id"] = pool.vnet_subnet_id
        config["pod_subnet_id"] = pool.pod_subnet_id
        config["max_pods"] = pool.max_pods
        config["enable_node_public_ip"] = pool.enable_node_public_ip
        config["node_public_ip_prefix_id"] = pool.node_public_ip_prefix_id

        # Node labels and taints
        config["node_labels"] = dict(pool.node_labels) if pool.node_labels else {}
        config["node_taints"] = list(pool.node_taints) if pool.node_taints else []

        # Upgrade settings
        upgrade_settings = pool.upgrade_settings
        if upgrade_settings:
            config["upgrade_settings"] = {
                "max_surge": upgrade_settings.max_surge,
                "drain_timeout_in_minutes": upgrade_settings.drain_timeout_in_minutes,
                "node_soak_duration_in_minutes": (
                    upgrade_settings.node_soak_duration_in_minutes
                ),
            }
        else:
            config["upgrade_settings"] = None

        # Enable FIPS
        config["enable_fips"] = pool.enable_fips

        # Enable encryption at host
        config["enable_encryption_at_host"] = pool.enable_encryption_at_host

        # Ultra SSD enabled
        config["enable_ultra_ssd"] = pool.enable_ultra_ssd

        # GPU instance profile
        config["gpu_instance_profile"] = pool.gpu_instance_profile

        # Kubelet config
        kubelet_config = pool.kubelet_config
        if kubelet_config:
            config["kubelet_config"] = {
                "cpu_manager_policy": kubelet_config.cpu_manager_policy,
                "cpu_cfs_quota": kubelet_config.cpu_cfs_quota,
                "cpu_cfs_quota_period": kubelet_config.cpu_cfs_quota_period,
                "image_gc_high_threshold": kubelet_config.image_gc_high_threshold,
                "image_gc_low_threshold": kubelet_config.image_gc_low_threshold,
                "topology_manager_policy": kubelet_config.topology_manager_policy,
                "allowed_unsafe_sysctls": (
                    list(kubelet_config.allowed_unsafe_sysctls)
                    if kubelet_config.allowed_unsafe_sysctls
                    else []
                ),
                "container_log_max_size_mb": kubelet_config.container_log_max_size_mb,
                "container_log_max_files": kubelet_config.container_log_max_files,
                "pod_max_pids": kubelet_config.pod_max_pids,
            }
        else:
            config["kubelet_config"] = None

        # Linux OS config
        linux_os_config = pool.linux_os_config
        if linux_os_config:
            config["linux_os_config"] = {
                "swap_file_size_mb": linux_os_config.swap_file_size_mb,
                "transparent_huge_page_enabled": linux_os_config.transparent_huge_page_enabled,
                "transparent_huge_page_defrag": linux_os_config.transparent_huge_page_defrag,
            }
        else:
            config["linux_os_config"] = None

        # Creation data
        config["creation_data"] = (
            {"source_resource_id": pool.creation_data.source_resource_id}
            if pool.creation_data
            else None
        )

        # Cluster reference
        config["cluster_id"] = cluster.id
        config["cluster_name"] = cluster.name

        return config

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
