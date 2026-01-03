"""
GCP Google Kubernetes Engine (GKE) collector for Mantissa Stance.

Collects GKE clusters, node pools, and their security configurations
for posture assessment.
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

# Optional GCP imports
try:
    from google.cloud import container_v1

    GCP_CONTAINER_AVAILABLE = True
except ImportError:
    GCP_CONTAINER_AVAILABLE = False


class GKECollector(BaseCollector):
    """
    Collects GCP GKE clusters, node pools, and security configurations.

    Gathers GKE cluster configurations including networking, security,
    Workload Identity, Binary Authorization, and node pool settings.
    All API calls are read-only.
    """

    collector_name = "gcp_gke"
    resource_types = [
        "gcp_gke_cluster",
        "gcp_gke_nodepool",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        location: str | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP GKE collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            location: Optional specific location (region or zone) to collect from.
                      Default: all locations ("-").
            **kwargs: Additional configuration.
        """
        if not GCP_CONTAINER_AVAILABLE:
            raise ImportError(
                "google-cloud-container is required for GCP GKE collector. "
                "Install with: pip install google-cloud-container"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._location = location or "-"  # "-" means all locations
        self._client: container_v1.ClusterManagerClient | None = None

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    def _get_client(self) -> container_v1.ClusterManagerClient:
        """Get or create Cluster Manager client."""
        if self._client is None:
            self._client = container_v1.ClusterManagerClient(
                credentials=self._credentials
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all GKE resources.

        Returns:
            Collection of GKE assets
        """
        assets: list[Asset] = []

        try:
            assets.extend(self._collect_clusters())
        except Exception as e:
            logger.warning(f"Failed to collect GKE clusters: {e}")

        return AssetCollection(assets)

    def _collect_clusters(self) -> list[Asset]:
        """Collect GKE clusters with their configurations."""
        client = self._get_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            # List all clusters in the project/location
            parent = f"projects/{self._project_id}/locations/{self._location}"
            response = client.list_clusters(parent=parent)

            for cluster in response.clusters:
                cluster_name = cluster.name
                cluster_location = cluster.location
                cluster_id = cluster.id

                # Build resource ID
                resource_id = (
                    f"projects/{self._project_id}/locations/{cluster_location}/"
                    f"clusters/{cluster_name}"
                )

                # Extract labels (tags)
                labels = dict(cluster.resource_labels) if cluster.resource_labels else {}

                # Network configuration
                network = cluster.network
                subnetwork = cluster.subnetwork
                cluster_ipv4_cidr = cluster.cluster_ipv4_cidr
                services_ipv4_cidr = cluster.services_ipv4_cidr

                # Private cluster configuration
                private_cluster_config = cluster.private_cluster_config
                is_private_cluster = False
                enable_private_nodes = False
                enable_private_endpoint = False
                master_ipv4_cidr_block = None
                private_endpoint = None
                public_endpoint = None

                if private_cluster_config:
                    is_private_cluster = True
                    enable_private_nodes = private_cluster_config.enable_private_nodes
                    enable_private_endpoint = private_cluster_config.enable_private_endpoint
                    master_ipv4_cidr_block = private_cluster_config.master_ipv4_cidr_block
                    private_endpoint = private_cluster_config.private_endpoint
                    public_endpoint = private_cluster_config.public_endpoint

                # Master authorized networks
                master_authorized_networks_config = cluster.master_authorized_networks_config
                master_authorized_networks_enabled = False
                authorized_cidr_blocks = []

                if master_authorized_networks_config:
                    master_authorized_networks_enabled = (
                        master_authorized_networks_config.enabled
                    )
                    for block in master_authorized_networks_config.cidr_blocks or []:
                        authorized_cidr_blocks.append({
                            "display_name": block.display_name,
                            "cidr_block": block.cidr_block,
                        })

                # Workload Identity configuration
                workload_identity_config = cluster.workload_identity_config
                workload_identity_pool = None
                workload_identity_enabled = False

                if workload_identity_config:
                    workload_identity_pool = workload_identity_config.workload_pool
                    workload_identity_enabled = bool(workload_identity_pool)

                # Binary Authorization
                binary_authorization = cluster.binary_authorization
                binary_authorization_enabled = False
                binary_authorization_evaluation_mode = None

                if binary_authorization:
                    binary_authorization_enabled = binary_authorization.enabled
                    binary_authorization_evaluation_mode = str(
                        binary_authorization.evaluation_mode
                    ) if binary_authorization.evaluation_mode else None

                # Network policy
                network_policy = cluster.network_policy
                network_policy_enabled = False
                network_policy_provider = None

                if network_policy:
                    network_policy_enabled = network_policy.enabled
                    network_policy_provider = str(network_policy.provider) if network_policy.provider else None

                # Addons configuration
                addons_config = cluster.addons_config
                addons = {}
                if addons_config:
                    if addons_config.http_load_balancing:
                        addons["http_load_balancing"] = not addons_config.http_load_balancing.disabled
                    if addons_config.horizontal_pod_autoscaling:
                        addons["horizontal_pod_autoscaling"] = not addons_config.horizontal_pod_autoscaling.disabled
                    if addons_config.network_policy_config:
                        addons["network_policy"] = not addons_config.network_policy_config.disabled
                    if addons_config.dns_cache_config:
                        addons["dns_cache"] = addons_config.dns_cache_config.enabled
                    if addons_config.gce_persistent_disk_csi_driver_config:
                        addons["gce_pd_csi_driver"] = addons_config.gce_persistent_disk_csi_driver_config.enabled
                    if addons_config.gcs_fuse_csi_driver_config:
                        addons["gcs_fuse_csi_driver"] = addons_config.gcs_fuse_csi_driver_config.enabled

                # Shielded nodes
                shielded_nodes = cluster.shielded_nodes
                shielded_nodes_enabled = shielded_nodes.enabled if shielded_nodes else False

                # Legacy ABAC (should be disabled)
                legacy_abac = cluster.legacy_abac
                legacy_abac_enabled = legacy_abac.enabled if legacy_abac else False

                # Master authentication (basic auth should be disabled)
                master_auth = cluster.master_auth
                basic_auth_enabled = False
                client_certificate_enabled = False
                cluster_ca_certificate = None

                if master_auth:
                    # Basic auth is deprecated, but check if username is set
                    basic_auth_enabled = bool(master_auth.username)
                    client_certificate_config = master_auth.client_certificate_config
                    if client_certificate_config:
                        client_certificate_enabled = client_certificate_config.issue_client_certificate
                    cluster_ca_certificate = master_auth.cluster_ca_certificate

                # Database encryption (etcd encryption)
                database_encryption = cluster.database_encryption
                database_encryption_state = None
                database_encryption_key = None

                if database_encryption:
                    database_encryption_state = str(database_encryption.state)
                    database_encryption_key = database_encryption.key_name

                # Logging and monitoring configuration
                logging_service = cluster.logging_service
                monitoring_service = cluster.monitoring_service

                # Release channel
                release_channel = cluster.release_channel
                release_channel_type = None
                if release_channel:
                    release_channel_type = str(release_channel.channel)

                # Maintenance policy
                maintenance_policy = cluster.maintenance_policy
                has_maintenance_window = maintenance_policy is not None

                # Security posture config
                security_posture_config = cluster.security_posture_config
                security_posture_mode = None
                vulnerability_mode = None

                if security_posture_config:
                    security_posture_mode = str(security_posture_config.mode) if security_posture_config.mode else None
                    vulnerability_mode = str(security_posture_config.vulnerability_mode) if security_posture_config.vulnerability_mode else None

                # Notification config
                notification_config = cluster.notification_config
                notifications_enabled = False
                if notification_config and notification_config.pubsub:
                    notifications_enabled = notification_config.pubsub.enabled

                raw_config: dict[str, Any] = {
                    "cluster_id": cluster_id,
                    "cluster_name": cluster_name,
                    "location": cluster_location,
                    "status": str(cluster.status),
                    "current_master_version": cluster.current_master_version,
                    "current_node_version": cluster.current_node_version,
                    "initial_cluster_version": cluster.initial_cluster_version,
                    "endpoint": cluster.endpoint,
                    "create_time": cluster.create_time,
                    "self_link": cluster.self_link,
                    # Network configuration
                    "network": network,
                    "subnetwork": subnetwork,
                    "cluster_ipv4_cidr": cluster_ipv4_cidr,
                    "services_ipv4_cidr": services_ipv4_cidr,
                    # Private cluster
                    "private_cluster_config": {
                        "is_private_cluster": is_private_cluster,
                        "enable_private_nodes": enable_private_nodes,
                        "enable_private_endpoint": enable_private_endpoint,
                        "master_ipv4_cidr_block": master_ipv4_cidr_block,
                        "private_endpoint": private_endpoint,
                        "public_endpoint": public_endpoint,
                    },
                    "is_private_cluster": is_private_cluster,
                    "enable_private_nodes": enable_private_nodes,
                    "enable_private_endpoint": enable_private_endpoint,
                    # Master authorized networks
                    "master_authorized_networks_config": {
                        "enabled": master_authorized_networks_enabled,
                        "cidr_blocks": authorized_cidr_blocks,
                    },
                    "master_authorized_networks_enabled": master_authorized_networks_enabled,
                    # Workload Identity
                    "workload_identity_config": {
                        "workload_pool": workload_identity_pool,
                        "enabled": workload_identity_enabled,
                    },
                    "workload_identity_enabled": workload_identity_enabled,
                    # Binary Authorization
                    "binary_authorization": {
                        "enabled": binary_authorization_enabled,
                        "evaluation_mode": binary_authorization_evaluation_mode,
                    },
                    "binary_authorization_enabled": binary_authorization_enabled,
                    # Network policy
                    "network_policy": {
                        "enabled": network_policy_enabled,
                        "provider": network_policy_provider,
                    },
                    "network_policy_enabled": network_policy_enabled,
                    # Add-ons
                    "addons_config": addons,
                    # Shielded nodes
                    "shielded_nodes_enabled": shielded_nodes_enabled,
                    # Legacy ABAC (should be disabled)
                    "legacy_abac_enabled": legacy_abac_enabled,
                    # Master auth
                    "master_auth": {
                        "basic_auth_enabled": basic_auth_enabled,
                        "client_certificate_enabled": client_certificate_enabled,
                        "has_cluster_ca_certificate": bool(cluster_ca_certificate),
                    },
                    "basic_auth_enabled": basic_auth_enabled,
                    "client_certificate_enabled": client_certificate_enabled,
                    # Database encryption
                    "database_encryption": {
                        "state": database_encryption_state,
                        "key_name": database_encryption_key,
                    },
                    "database_encryption_enabled": database_encryption_state == "ENCRYPTED",
                    # Logging and monitoring
                    "logging_service": logging_service,
                    "monitoring_service": monitoring_service,
                    "cloud_logging_enabled": logging_service and "logging.googleapis.com" in logging_service,
                    "cloud_monitoring_enabled": monitoring_service and "monitoring.googleapis.com" in monitoring_service,
                    # Release channel
                    "release_channel": release_channel_type,
                    "has_release_channel": release_channel_type is not None,
                    # Maintenance
                    "has_maintenance_window": has_maintenance_window,
                    # Security posture
                    "security_posture_config": {
                        "mode": security_posture_mode,
                        "vulnerability_mode": vulnerability_mode,
                    },
                    # Notifications
                    "notifications_enabled": notifications_enabled,
                    # Node pools summary
                    "node_pool_count": len(cluster.node_pools) if cluster.node_pools else 0,
                    # Labels
                    "labels": labels,
                }

                # Determine network exposure
                network_exposure = self._determine_cluster_exposure(
                    is_private_cluster=is_private_cluster,
                    enable_private_endpoint=enable_private_endpoint,
                    master_authorized_networks_enabled=master_authorized_networks_enabled,
                )

                # Parse creation time
                created_at = None
                if cluster.create_time:
                    try:
                        created_at = datetime.fromisoformat(
                            cluster.create_time.replace("Z", "+00:00")
                        )
                    except (ValueError, AttributeError):
                        pass

                assets.append(
                    Asset(
                        id=resource_id,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region=cluster_location,
                        resource_type="gcp_gke_cluster",
                        name=cluster_name,
                        tags=labels,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

                # Collect node pools for this cluster
                try:
                    nodepool_assets = self._collect_nodepools(cluster, resource_id)
                    assets.extend(nodepool_assets)
                except Exception as e:
                    logger.debug(f"Could not collect node pools for {cluster_name}: {e}")

        except Exception as e:
            logger.error(f"Error listing GKE clusters: {e}")
            raise

        return assets

    def _collect_nodepools(
        self, cluster: Any, cluster_resource_id: str
    ) -> list[Asset]:
        """Collect GKE node pools for a cluster."""
        assets: list[Asset] = []
        now = self._now()

        if not cluster.node_pools:
            return assets

        for nodepool in cluster.node_pools:
            nodepool_name = nodepool.name
            resource_id = f"{cluster_resource_id}/nodePools/{nodepool_name}"

            # Node config
            node_config = nodepool.config
            machine_type = None
            disk_size_gb = None
            disk_type = None
            image_type = None
            service_account = None
            oauth_scopes = []
            labels = {}
            metadata = {}
            preemptible = False
            spot = False
            shielded_instance_config = {}
            workload_metadata_config = None
            sandbox_config = None

            if node_config:
                machine_type = node_config.machine_type
                disk_size_gb = node_config.disk_size_gb
                disk_type = node_config.disk_type
                image_type = node_config.image_type
                service_account = node_config.service_account
                oauth_scopes = list(node_config.oauth_scopes) if node_config.oauth_scopes else []
                labels = dict(node_config.labels) if node_config.labels else {}
                metadata = dict(node_config.metadata) if node_config.metadata else {}
                preemptible = node_config.preemptible
                spot = node_config.spot

                # Shielded instance config
                if node_config.shielded_instance_config:
                    shielded_instance_config = {
                        "enable_secure_boot": node_config.shielded_instance_config.enable_secure_boot,
                        "enable_integrity_monitoring": node_config.shielded_instance_config.enable_integrity_monitoring,
                    }

                # Workload metadata config (for Workload Identity)
                if node_config.workload_metadata_config:
                    workload_metadata_config = str(node_config.workload_metadata_config.mode)

                # Sandbox config (gVisor)
                if node_config.sandbox_config:
                    sandbox_config = str(node_config.sandbox_config.type_)

            # Autoscaling
            autoscaling = nodepool.autoscaling
            autoscaling_enabled = False
            min_node_count = 0
            max_node_count = 0

            if autoscaling:
                autoscaling_enabled = autoscaling.enabled
                min_node_count = autoscaling.min_node_count
                max_node_count = autoscaling.max_node_count

            # Management
            management = nodepool.management
            auto_repair = False
            auto_upgrade = False

            if management:
                auto_repair = management.auto_repair
                auto_upgrade = management.auto_upgrade

            # Check for overly permissive scopes
            has_broad_scopes = (
                "https://www.googleapis.com/auth/cloud-platform" in oauth_scopes
            )

            # Check for default service account
            uses_default_sa = (
                service_account is None or
                "-compute@developer.gserviceaccount.com" in (service_account or "")
            )

            raw_config: dict[str, Any] = {
                "cluster_name": cluster.name,
                "cluster_resource_id": cluster_resource_id,
                "nodepool_name": nodepool_name,
                "status": str(nodepool.status),
                "version": nodepool.version,
                "initial_node_count": nodepool.initial_node_count,
                "locations": list(nodepool.locations) if nodepool.locations else [],
                # Node config
                "node_config": {
                    "machine_type": machine_type,
                    "disk_size_gb": disk_size_gb,
                    "disk_type": disk_type,
                    "image_type": image_type,
                    "service_account": service_account,
                    "oauth_scopes": oauth_scopes,
                    "labels": labels,
                    "metadata": metadata,
                    "preemptible": preemptible,
                    "spot": spot,
                    "shielded_instance_config": shielded_instance_config,
                    "workload_metadata_config": workload_metadata_config,
                    "sandbox_config": sandbox_config,
                },
                "machine_type": machine_type,
                "service_account": service_account,
                "uses_default_service_account": uses_default_sa,
                "oauth_scopes": oauth_scopes,
                "has_broad_scopes": has_broad_scopes,
                "preemptible": preemptible,
                "spot": spot,
                # Shielded VM
                "shielded_instance_config": shielded_instance_config,
                "secure_boot_enabled": shielded_instance_config.get("enable_secure_boot", False),
                "integrity_monitoring_enabled": shielded_instance_config.get("enable_integrity_monitoring", False),
                # Workload Identity
                "workload_metadata_config": workload_metadata_config,
                "workload_identity_enabled": workload_metadata_config == "GKE_METADATA",
                # Sandbox (gVisor)
                "sandbox_config": sandbox_config,
                "sandbox_enabled": sandbox_config is not None,
                # Autoscaling
                "autoscaling": {
                    "enabled": autoscaling_enabled,
                    "min_node_count": min_node_count,
                    "max_node_count": max_node_count,
                },
                "autoscaling_enabled": autoscaling_enabled,
                # Management
                "management": {
                    "auto_repair": auto_repair,
                    "auto_upgrade": auto_upgrade,
                },
                "auto_repair_enabled": auto_repair,
                "auto_upgrade_enabled": auto_upgrade,
            }

            # Node pools are internal by default
            network_exposure = NETWORK_EXPOSURE_INTERNAL

            assets.append(
                Asset(
                    id=resource_id,
                    cloud_provider="gcp",
                    account_id=self._project_id,
                    region=cluster.location,
                    resource_type="gcp_gke_nodepool",
                    name=nodepool_name,
                    tags=labels,
                    network_exposure=network_exposure,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _determine_cluster_exposure(
        self,
        is_private_cluster: bool,
        enable_private_endpoint: bool,
        master_authorized_networks_enabled: bool,
    ) -> str:
        """
        Determine network exposure for a GKE cluster.

        Args:
            is_private_cluster: Whether the cluster is private
            enable_private_endpoint: Whether private endpoint is enabled
            master_authorized_networks_enabled: Whether authorized networks are enabled

        Returns:
            Network exposure level string
        """
        # Private endpoint means fully private
        if is_private_cluster and enable_private_endpoint:
            return NETWORK_EXPOSURE_INTERNAL

        # Public endpoint with authorized networks is still internet-facing
        # but more restricted
        if is_private_cluster and not enable_private_endpoint:
            return NETWORK_EXPOSURE_INTERNET

        # Non-private cluster is internet-facing
        return NETWORK_EXPOSURE_INTERNET
