"""
Azure Machine Learning collector for Mantissa Stance.

Collects Azure ML workspaces, compute instances, endpoints, models,
datastores, and environments for AI/ML security posture assessment.
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

# Optional Azure ML imports
try:
    from azure.mgmt.machinelearningservices import MachineLearningServicesMgmtClient
    from azure.identity import DefaultAzureCredential

    AZURE_ML_AVAILABLE = True
except ImportError:
    AZURE_ML_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore


class AzureMLCollector(BaseCollector):
    """
    Collects Azure Machine Learning resources and configuration.

    Gathers Azure ML workspaces, compute instances, compute clusters,
    online endpoints, batch endpoints, models, datastores, and environments.
    All API calls are read-only.
    """

    collector_name = "azure_ml"
    resource_types = [
        "azure_ml_workspace",
        "azure_ml_compute_instance",
        "azure_ml_compute_cluster",
        "azure_ml_online_endpoint",
        "azure_ml_batch_endpoint",
        "azure_ml_model",
        "azure_ml_datastore",
        "azure_ml_environment",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure ML collector.

        Args:
            subscription_id: Azure subscription ID.
            credential: Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_ML_AVAILABLE:
            raise ImportError(
                "azure-mgmt-machinelearningservices is required for Azure ML collector. "
                "Install with: pip install azure-mgmt-machinelearningservices azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._client: MachineLearningServicesMgmtClient | None = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_client(self) -> MachineLearningServicesMgmtClient:
        """Get or create ML client."""
        if self._client is None:
            self._client = MachineLearningServicesMgmtClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._client

    def collect(self) -> AssetCollection:
        """
        Collect all Azure ML resources.

        Returns:
            Collection of Azure ML assets
        """
        assets: list[Asset] = []

        # Collect workspaces and their resources
        try:
            assets.extend(self._collect_workspaces())
        except Exception as e:
            logger.warning(f"Failed to collect Azure ML workspaces: {e}")

        return AssetCollection(assets)

    def _collect_workspaces(self) -> list[Asset]:
        """Collect Azure ML workspaces and their child resources."""
        client = self._get_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            workspaces = list(client.workspaces.list_by_subscription())
        except Exception as e:
            logger.warning(f"Failed to list ML workspaces: {e}")
            return assets

        for workspace in workspaces:
            ws_id = workspace.id
            ws_name = workspace.name
            resource_group = ws_id.split("/")[4] if ws_id else ""
            location = workspace.location

            # Identity configuration
            identity = workspace.identity
            identity_type = identity.type if identity else None
            has_managed_identity = identity_type in ["SystemAssigned", "SystemAssigned,UserAssigned", "UserAssigned"]

            # Encryption configuration
            encryption = workspace.encryption
            has_cmk = bool(encryption and encryption.key_vault_properties)

            # Network configuration
            public_network_access = workspace.public_network_access
            has_public_access = public_network_access == "Enabled"

            # Private endpoint connections
            private_endpoints = workspace.private_endpoint_connections or []
            has_private_endpoints = len(private_endpoints) > 0

            # HBI (High Business Impact) workspace
            hbi_workspace = workspace.hbi_workspace or False

            # Storage account
            storage_account = workspace.storage_account

            # Key vault
            key_vault = workspace.key_vault

            # Application insights
            application_insights = workspace.application_insights

            # Container registry
            container_registry = workspace.container_registry

            raw_config: dict[str, Any] = {
                "id": ws_id,
                "name": ws_name,
                "resource_group": resource_group,
                "location": location,
                "provisioning_state": workspace.provisioning_state,
                # Identity
                "identity": {
                    "type": identity_type,
                    "principal_id": identity.principal_id if identity else None,
                    "tenant_id": identity.tenant_id if identity else None,
                },
                "has_managed_identity": has_managed_identity,
                # Encryption
                "encryption": {
                    "status": encryption.status if encryption else None,
                    "key_vault_properties": {
                        "key_vault_arm_id": encryption.key_vault_properties.key_vault_arm_id,
                        "key_identifier": encryption.key_vault_properties.key_identifier,
                    } if encryption and encryption.key_vault_properties else None,
                } if encryption else None,
                "has_cmk_encryption": has_cmk,
                # Network
                "public_network_access": public_network_access,
                "has_public_access": has_public_access,
                "private_endpoint_connections": [
                    {
                        "id": pe.id,
                        "name": pe.name,
                        "status": pe.private_link_service_connection_state.status if pe.private_link_service_connection_state else None,
                    }
                    for pe in private_endpoints
                ],
                "has_private_endpoints": has_private_endpoints,
                # HBI workspace
                "hbi_workspace": hbi_workspace,
                # Associated resources
                "storage_account": storage_account,
                "key_vault": key_vault,
                "application_insights": application_insights,
                "container_registry": container_registry,
                # Workspace URL
                "workspace_url": workspace.workspace_url,
                "discovery_url": workspace.discovery_url,
                # Tags
                "tags": dict(workspace.tags) if workspace.tags else {},
            }

            network_exposure = NETWORK_EXPOSURE_INTERNET if has_public_access else NETWORK_EXPOSURE_INTERNAL

            asset = Asset(
                asset_id=ws_id,
                asset_type="azure_ml_workspace",
                name=ws_name,
                region=location,
                account_id=self._subscription_id,
                tags=dict(workspace.tags) if workspace.tags else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=network_exposure,
            )
            assets.append(asset)

            # Collect child resources for this workspace
            assets.extend(self._collect_compute_instances(resource_group, ws_name))
            assets.extend(self._collect_compute_clusters(resource_group, ws_name))
            assets.extend(self._collect_online_endpoints(resource_group, ws_name))
            assets.extend(self._collect_batch_endpoints(resource_group, ws_name))
            assets.extend(self._collect_datastores(resource_group, ws_name))

        return assets

    def _collect_compute_instances(self, resource_group: str, workspace_name: str) -> list[Asset]:
        """Collect Azure ML compute instances for a workspace."""
        client = self._get_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            computes = list(client.compute.list(resource_group, workspace_name))
        except Exception as e:
            logger.warning(f"Failed to list compute resources: {e}")
            return assets

        for compute in computes:
            # Filter for compute instances
            if compute.properties and hasattr(compute.properties, "compute_type"):
                compute_type = compute.properties.compute_type
            else:
                continue

            if compute_type != "ComputeInstance":
                continue

            compute_id = compute.id
            compute_name = compute.name
            properties = compute.properties

            # Compute instance specific properties
            vm_size = properties.vm_size if hasattr(properties, "vm_size") else None
            state = properties.state if hasattr(properties, "state") else None

            # SSH settings
            ssh_settings = properties.ssh_settings if hasattr(properties, "ssh_settings") else None
            ssh_public_access = ssh_settings.ssh_public_access if ssh_settings else "Disabled"
            has_ssh_access = ssh_public_access == "Enabled"

            # Subnet
            subnet = properties.subnet if hasattr(properties, "subnet") else None
            in_vnet = bool(subnet and subnet.id)

            raw_config: dict[str, Any] = {
                "id": compute_id,
                "name": compute_name,
                "workspace": workspace_name,
                "resource_group": resource_group,
                "compute_type": compute_type,
                "provisioning_state": compute.provisioning_state,
                "location": compute.location,
                # VM configuration
                "vm_size": vm_size,
                "state": state,
                # SSH settings
                "ssh_settings": {
                    "ssh_public_access": ssh_public_access,
                    "admin_user_name": ssh_settings.admin_user_name if ssh_settings else None,
                } if ssh_settings else None,
                "has_ssh_access": has_ssh_access,
                # Network
                "subnet": {
                    "id": subnet.id if subnet else None,
                } if subnet else None,
                "in_vnet": in_vnet,
                # Identity
                "identity": {
                    "type": compute.identity.type if compute.identity else None,
                } if compute.identity else None,
                # Schedule
                "schedules": properties.schedules if hasattr(properties, "schedules") else None,
            }

            network_exposure = NETWORK_EXPOSURE_INTERNET if has_ssh_access and not in_vnet else NETWORK_EXPOSURE_INTERNAL

            asset = Asset(
                asset_id=compute_id,
                asset_type="azure_ml_compute_instance",
                name=compute_name,
                region=compute.location or "",
                account_id=self._subscription_id,
                tags=dict(compute.tags) if compute.tags else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=network_exposure,
            )
            assets.append(asset)

        return assets

    def _collect_compute_clusters(self, resource_group: str, workspace_name: str) -> list[Asset]:
        """Collect Azure ML compute clusters for a workspace."""
        client = self._get_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            computes = list(client.compute.list(resource_group, workspace_name))
        except Exception as e:
            logger.warning(f"Failed to list compute resources: {e}")
            return assets

        for compute in computes:
            # Filter for AmlCompute (clusters)
            if compute.properties and hasattr(compute.properties, "compute_type"):
                compute_type = compute.properties.compute_type
            else:
                continue

            if compute_type != "AmlCompute":
                continue

            compute_id = compute.id
            compute_name = compute.name
            properties = compute.properties

            # Cluster properties
            vm_size = properties.vm_size if hasattr(properties, "vm_size") else None
            vm_priority = properties.vm_priority if hasattr(properties, "vm_priority") else None

            # Scale settings
            scale_settings = properties.scale_settings if hasattr(properties, "scale_settings") else None
            min_node_count = scale_settings.min_node_count if scale_settings else 0
            max_node_count = scale_settings.max_node_count if scale_settings else 0

            # Subnet
            subnet = properties.subnet if hasattr(properties, "subnet") else None
            in_vnet = bool(subnet and subnet.id)

            # Remote login port public access
            remote_login_port_public_access = properties.remote_login_port_public_access if hasattr(properties, "remote_login_port_public_access") else "Enabled"
            has_public_ssh = remote_login_port_public_access == "Enabled"

            # Enable node public IP
            enable_node_public_ip = properties.enable_node_public_ip if hasattr(properties, "enable_node_public_ip") else True

            raw_config: dict[str, Any] = {
                "id": compute_id,
                "name": compute_name,
                "workspace": workspace_name,
                "resource_group": resource_group,
                "compute_type": compute_type,
                "provisioning_state": compute.provisioning_state,
                "location": compute.location,
                # VM configuration
                "vm_size": vm_size,
                "vm_priority": vm_priority,
                # Scale settings
                "scale_settings": {
                    "min_node_count": min_node_count,
                    "max_node_count": max_node_count,
                    "node_idle_time_before_scale_down": str(scale_settings.node_idle_time_before_scale_down) if scale_settings else None,
                } if scale_settings else None,
                # Network
                "subnet": {
                    "id": subnet.id if subnet else None,
                } if subnet else None,
                "in_vnet": in_vnet,
                "remote_login_port_public_access": remote_login_port_public_access,
                "has_public_ssh": has_public_ssh,
                "enable_node_public_ip": enable_node_public_ip,
                # User account credentials (not the actual credentials)
                "user_account_credentials": {
                    "admin_user_name": properties.user_account_credentials.admin_user_name if hasattr(properties, "user_account_credentials") and properties.user_account_credentials else None,
                } if hasattr(properties, "user_account_credentials") else None,
                # Allocation state
                "allocation_state": properties.allocation_state if hasattr(properties, "allocation_state") else None,
                "current_node_count": properties.current_node_count if hasattr(properties, "current_node_count") else 0,
            }

            network_exposure = NETWORK_EXPOSURE_INTERNET if (has_public_ssh or enable_node_public_ip) and not in_vnet else NETWORK_EXPOSURE_INTERNAL

            asset = Asset(
                asset_id=compute_id,
                asset_type="azure_ml_compute_cluster",
                name=compute_name,
                region=compute.location or "",
                account_id=self._subscription_id,
                tags=dict(compute.tags) if compute.tags else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=network_exposure,
            )
            assets.append(asset)

        return assets

    def _collect_online_endpoints(self, resource_group: str, workspace_name: str) -> list[Asset]:
        """Collect Azure ML online endpoints for a workspace."""
        client = self._get_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            endpoints = list(client.online_endpoints.list(resource_group, workspace_name))
        except Exception as e:
            logger.warning(f"Failed to list online endpoints: {e}")
            return assets

        for endpoint in endpoints:
            endpoint_id = endpoint.id
            endpoint_name = endpoint.name
            properties = endpoint.properties

            # Auth mode
            auth_mode = properties.auth_mode if properties else None

            # Public network access
            public_network_access = properties.public_network_access if properties else "Enabled"
            has_public_access = public_network_access == "Enabled"

            # Traffic configuration
            traffic = properties.traffic if properties else {}

            raw_config: dict[str, Any] = {
                "id": endpoint_id,
                "name": endpoint_name,
                "workspace": workspace_name,
                "resource_group": resource_group,
                "location": endpoint.location,
                "provisioning_state": properties.provisioning_state if properties else None,
                # Auth
                "auth_mode": auth_mode,
                # Network
                "public_network_access": public_network_access,
                "has_public_access": has_public_access,
                # Scoring URI
                "scoring_uri": properties.scoring_uri if properties else None,
                # Traffic
                "traffic": dict(traffic) if traffic else {},
                # Identity
                "identity": {
                    "type": endpoint.identity.type if endpoint.identity else None,
                } if endpoint.identity else None,
                # Kind
                "kind": endpoint.kind,
                # Tags
                "tags": dict(endpoint.tags) if endpoint.tags else {},
            }

            network_exposure = NETWORK_EXPOSURE_INTERNET if has_public_access else NETWORK_EXPOSURE_INTERNAL

            asset = Asset(
                asset_id=endpoint_id,
                asset_type="azure_ml_online_endpoint",
                name=endpoint_name,
                region=endpoint.location or "",
                account_id=self._subscription_id,
                tags=dict(endpoint.tags) if endpoint.tags else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=network_exposure,
            )
            assets.append(asset)

        return assets

    def _collect_batch_endpoints(self, resource_group: str, workspace_name: str) -> list[Asset]:
        """Collect Azure ML batch endpoints for a workspace."""
        client = self._get_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            endpoints = list(client.batch_endpoints.list(resource_group, workspace_name))
        except Exception as e:
            logger.warning(f"Failed to list batch endpoints: {e}")
            return assets

        for endpoint in endpoints:
            endpoint_id = endpoint.id
            endpoint_name = endpoint.name
            properties = endpoint.properties

            # Auth mode
            auth_mode = properties.auth_mode if properties else None

            raw_config: dict[str, Any] = {
                "id": endpoint_id,
                "name": endpoint_name,
                "workspace": workspace_name,
                "resource_group": resource_group,
                "location": endpoint.location,
                "provisioning_state": properties.provisioning_state if properties else None,
                # Auth
                "auth_mode": auth_mode,
                # Scoring URI
                "scoring_uri": properties.scoring_uri if properties else None,
                # Defaults
                "defaults": properties.defaults if properties else None,
                # Identity
                "identity": {
                    "type": endpoint.identity.type if endpoint.identity else None,
                } if endpoint.identity else None,
                # Kind
                "kind": endpoint.kind,
                # Tags
                "tags": dict(endpoint.tags) if endpoint.tags else {},
            }

            asset = Asset(
                asset_id=endpoint_id,
                asset_type="azure_ml_batch_endpoint",
                name=endpoint_name,
                region=endpoint.location or "",
                account_id=self._subscription_id,
                tags=dict(endpoint.tags) if endpoint.tags else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,  # Batch endpoints are internal
            )
            assets.append(asset)

        return assets

    def _collect_datastores(self, resource_group: str, workspace_name: str) -> list[Asset]:
        """Collect Azure ML datastores for a workspace."""
        client = self._get_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            datastores = list(client.datastores.list(resource_group, workspace_name))
        except Exception as e:
            logger.warning(f"Failed to list datastores: {e}")
            return assets

        for datastore in datastores:
            ds_id = datastore.id
            ds_name = datastore.name
            properties = datastore.properties

            # Datastore type
            ds_type = properties.datastore_type if properties else None

            # Credentials type (not the actual credentials)
            credentials = properties.credentials if properties else None
            credentials_type = credentials.credentials_type if credentials else None

            # Is default
            is_default = properties.is_default if properties else False

            raw_config: dict[str, Any] = {
                "id": ds_id,
                "name": ds_name,
                "workspace": workspace_name,
                "resource_group": resource_group,
                # Type
                "datastore_type": ds_type,
                # Credentials
                "credentials_type": credentials_type,
                # Default
                "is_default": is_default,
                # Tags
                "tags": properties.tags if properties and hasattr(properties, "tags") else {},
            }

            asset = Asset(
                asset_id=ds_id,
                asset_type="azure_ml_datastore",
                name=ds_name,
                region="",
                account_id=self._subscription_id,
                tags={},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _now(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
