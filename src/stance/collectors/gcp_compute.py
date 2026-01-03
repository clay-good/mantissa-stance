"""
GCP Compute Engine collector for Mantissa Stance.

Collects Compute Engine instances, firewall rules, VPC networks,
and related network configuration for security posture assessment.
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

# Optional GCP imports
try:
    from google.cloud import compute_v1

    GCP_COMPUTE_AVAILABLE = True
except ImportError:
    GCP_COMPUTE_AVAILABLE = False


class GCPComputeCollector(BaseCollector):
    """
    Collects GCP Compute Engine resources and configuration.

    Gathers VM instances, firewall rules, VPC networks, and subnetworks.
    All API calls are read-only.
    """

    collector_name = "gcp_compute"
    resource_types = [
        "gcp_compute_instance",
        "gcp_compute_firewall",
        "gcp_compute_network",
        "gcp_compute_subnetwork",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        zone: str | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP Compute collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            zone: Optional specific zone to collect from (default: all zones).
            **kwargs: Additional configuration.
        """
        if not GCP_COMPUTE_AVAILABLE:
            raise ImportError(
                "google-cloud-compute is required for GCP compute collector. "
                "Install with: pip install google-cloud-compute"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._zone = zone
        self._clients: dict[str, Any] = {}

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    def _get_instances_client(self) -> compute_v1.InstancesClient:
        """Get or create Instances client."""
        if "instances" not in self._clients:
            self._clients["instances"] = compute_v1.InstancesClient(
                credentials=self._credentials
            )
        return self._clients["instances"]

    def _get_firewalls_client(self) -> compute_v1.FirewallsClient:
        """Get or create Firewalls client."""
        if "firewalls" not in self._clients:
            self._clients["firewalls"] = compute_v1.FirewallsClient(
                credentials=self._credentials
            )
        return self._clients["firewalls"]

    def _get_networks_client(self) -> compute_v1.NetworksClient:
        """Get or create Networks client."""
        if "networks" not in self._clients:
            self._clients["networks"] = compute_v1.NetworksClient(
                credentials=self._credentials
            )
        return self._clients["networks"]

    def _get_subnetworks_client(self) -> compute_v1.SubnetworksClient:
        """Get or create Subnetworks client."""
        if "subnetworks" not in self._clients:
            self._clients["subnetworks"] = compute_v1.SubnetworksClient(
                credentials=self._credentials
            )
        return self._clients["subnetworks"]

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Compute Engine resources.

        Returns:
            Collection of compute assets
        """
        assets: list[Asset] = []

        # Collect instances
        try:
            assets.extend(self._collect_instances())
        except Exception as e:
            logger.warning(f"Failed to collect compute instances: {e}")

        # Collect firewall rules
        try:
            assets.extend(self._collect_firewalls())
        except Exception as e:
            logger.warning(f"Failed to collect firewall rules: {e}")

        # Collect VPC networks
        try:
            assets.extend(self._collect_networks())
        except Exception as e:
            logger.warning(f"Failed to collect VPC networks: {e}")

        return AssetCollection(assets)

    def _collect_instances(self) -> list[Asset]:
        """Collect Compute Engine instances."""
        client = self._get_instances_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            # Use aggregated list to get instances across all zones
            request = compute_v1.AggregatedListInstancesRequest(
                project=self._project_id
            )

            for zone, instances_scoped_list in client.aggregated_list(request=request):
                if not instances_scoped_list.instances:
                    continue

                for instance in instances_scoped_list.instances:
                    instance_id = str(instance.id)
                    instance_name = instance.name
                    zone_name = zone.replace("zones/", "")

                    # Build resource ID
                    resource_id = (
                        f"projects/{self._project_id}/zones/{zone_name}/"
                        f"instances/{instance_name}"
                    )

                    # Extract network interfaces
                    network_interfaces = []
                    has_external_ip = False
                    external_ips = []
                    internal_ips = []

                    for nic in instance.network_interfaces or []:
                        nic_info = {
                            "name": nic.name,
                            "network": nic.network,
                            "subnetwork": nic.subnetwork,
                            "network_ip": nic.network_i_p,
                        }
                        internal_ips.append(nic.network_i_p)

                        # Check for external IPs
                        access_configs = []
                        for ac in nic.access_configs or []:
                            access_configs.append({
                                "name": ac.name,
                                "type": ac.type_,
                                "nat_ip": ac.nat_i_p,
                            })
                            if ac.nat_i_p:
                                has_external_ip = True
                                external_ips.append(ac.nat_i_p)

                        nic_info["access_configs"] = access_configs
                        network_interfaces.append(nic_info)

                    # Extract service accounts
                    service_accounts = []
                    for sa in instance.service_accounts or []:
                        service_accounts.append({
                            "email": sa.email,
                            "scopes": list(sa.scopes) if sa.scopes else [],
                        })

                    # Check for default service account with broad scopes
                    uses_default_sa = any(
                        "-compute@developer.gserviceaccount.com" in sa["email"]
                        for sa in service_accounts
                    )
                    has_broad_scopes = any(
                        "https://www.googleapis.com/auth/cloud-platform" in sa.get("scopes", [])
                        for sa in service_accounts
                    )

                    # Extract metadata
                    metadata_items = {}
                    enable_serial_port = False
                    enable_os_login = False
                    block_project_ssh_keys = False

                    if instance.metadata and instance.metadata.items:
                        for item in instance.metadata.items:
                            metadata_items[item.key] = item.value
                            if item.key == "serial-port-enable":
                                enable_serial_port = item.value.lower() == "true"
                            if item.key == "enable-oslogin":
                                enable_os_login = item.value.lower() == "true"
                            if item.key == "block-project-ssh-keys":
                                block_project_ssh_keys = item.value.lower() == "true"

                    # Extract labels (tags)
                    labels = dict(instance.labels) if instance.labels else {}

                    # Extract disks
                    disks = []
                    for disk in instance.disks or []:
                        disk_info = {
                            "device_name": disk.device_name,
                            "boot": disk.boot,
                            "auto_delete": disk.auto_delete,
                            "mode": disk.mode,
                            "source": disk.source,
                        }
                        # Check disk encryption
                        if disk.disk_encryption_key:
                            disk_info["encryption"] = {
                                "type": "customer_managed",
                                "kms_key": disk.disk_encryption_key.kms_key_name,
                            }
                        else:
                            disk_info["encryption"] = {"type": "google_managed"}
                        disks.append(disk_info)

                    # Check shielded VM config
                    shielded_config = {}
                    if instance.shielded_instance_config:
                        shielded_config = {
                            "enable_secure_boot": (
                                instance.shielded_instance_config.enable_secure_boot
                            ),
                            "enable_vtpm": (
                                instance.shielded_instance_config.enable_vtpm
                            ),
                            "enable_integrity_monitoring": (
                                instance.shielded_instance_config.enable_integrity_monitoring
                            ),
                        }

                    raw_config = {
                        "instance_id": instance_id,
                        "name": instance_name,
                        "zone": zone_name,
                        "machine_type": instance.machine_type,
                        "status": instance.status,
                        "creation_timestamp": instance.creation_timestamp,
                        "network_interfaces": network_interfaces,
                        "has_external_ip": has_external_ip,
                        "external_ips": external_ips,
                        "internal_ips": internal_ips,
                        "service_accounts": service_accounts,
                        "uses_default_service_account": uses_default_sa,
                        "has_broad_scopes": has_broad_scopes,
                        "disks": disks,
                        "labels": labels,
                        "metadata": metadata_items,
                        "serial_port_enabled": enable_serial_port,
                        "os_login_enabled": enable_os_login,
                        "block_project_ssh_keys": block_project_ssh_keys,
                        "shielded_vm_config": shielded_config,
                        "can_ip_forward": instance.can_ip_forward,
                        "deletion_protection": instance.deletion_protection,
                    }

                    # Determine network exposure
                    network_exposure = NETWORK_EXPOSURE_INTERNAL
                    if has_external_ip:
                        network_exposure = NETWORK_EXPOSURE_INTERNET

                    created_at = None
                    if instance.creation_timestamp:
                        try:
                            created_at = datetime.fromisoformat(
                                instance.creation_timestamp.replace("Z", "+00:00")
                            )
                        except (ValueError, AttributeError):
                            pass

                    assets.append(
                        Asset(
                            id=resource_id,
                            cloud_provider="gcp",
                            account_id=self._project_id,
                            region=zone_name,
                            resource_type="gcp_compute_instance",
                            name=instance_name,
                            tags=labels,
                            network_exposure=network_exposure,
                            created_at=created_at,
                            last_seen=now,
                            raw_config=raw_config,
                        )
                    )

        except Exception as e:
            logger.error(f"Error listing compute instances: {e}")
            raise

        return assets

    def _collect_firewalls(self) -> list[Asset]:
        """Collect VPC firewall rules."""
        client = self._get_firewalls_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = compute_v1.ListFirewallsRequest(project=self._project_id)

            for firewall in client.list(request=request):
                firewall_name = firewall.name
                resource_id = (
                    f"projects/{self._project_id}/global/firewalls/{firewall_name}"
                )

                # Parse allowed rules
                allowed_rules = []
                for allowed in firewall.allowed or []:
                    allowed_rules.append({
                        "protocol": allowed.I_p_protocol,
                        "ports": list(allowed.ports) if allowed.ports else ["all"],
                    })

                # Parse denied rules
                denied_rules = []
                for denied in firewall.denied or []:
                    denied_rules.append({
                        "protocol": denied.I_p_protocol,
                        "ports": list(denied.ports) if denied.ports else ["all"],
                    })

                # Check for overly permissive rules
                allows_all_ingress = False
                allows_ssh_from_internet = False
                allows_rdp_from_internet = False
                risky_ports_open = []

                source_ranges = list(firewall.source_ranges or [])
                is_ingress = firewall.direction == "INGRESS"

                if is_ingress and "0.0.0.0/0" in source_ranges:
                    allows_all_ingress = True

                    # Check for specific risky ports
                    risky_port_checks = {
                        "22": "SSH",
                        "3389": "RDP",
                        "3306": "MySQL",
                        "5432": "PostgreSQL",
                        "27017": "MongoDB",
                        "6379": "Redis",
                        "23": "Telnet",
                    }

                    for allowed in allowed_rules:
                        ports = allowed.get("ports", [])
                        if "all" in ports or not ports:
                            risky_ports_open = list(risky_port_checks.values())
                            break

                        for port in ports:
                            # Handle port ranges like "22-80"
                            if "-" in str(port):
                                start, end = port.split("-")
                                for risky_port, name in risky_port_checks.items():
                                    if int(start) <= int(risky_port) <= int(end):
                                        risky_ports_open.append(name)
                            elif str(port) in risky_port_checks:
                                risky_ports_open.append(risky_port_checks[str(port)])

                    if "SSH" in risky_ports_open:
                        allows_ssh_from_internet = True
                    if "RDP" in risky_ports_open:
                        allows_rdp_from_internet = True

                raw_config = {
                    "name": firewall_name,
                    "id": str(firewall.id),
                    "network": firewall.network,
                    "priority": firewall.priority,
                    "direction": firewall.direction,
                    "disabled": firewall.disabled,
                    "description": firewall.description or "",
                    "source_ranges": source_ranges,
                    "destination_ranges": list(firewall.destination_ranges or []),
                    "source_tags": list(firewall.source_tags or []),
                    "target_tags": list(firewall.target_tags or []),
                    "source_service_accounts": list(
                        firewall.source_service_accounts or []
                    ),
                    "target_service_accounts": list(
                        firewall.target_service_accounts or []
                    ),
                    "allowed": allowed_rules,
                    "denied": denied_rules,
                    "log_config": {
                        "enabled": bool(
                            firewall.log_config and firewall.log_config.enable
                        ),
                    },
                    "allows_all_ingress_from_internet": allows_all_ingress,
                    "allows_ssh_from_internet": allows_ssh_from_internet,
                    "allows_rdp_from_internet": allows_rdp_from_internet,
                    "risky_ports_open_to_internet": risky_ports_open,
                    "is_risky": len(risky_ports_open) > 0,
                }

                # Firewall rules are global resources but affect network security
                network_exposure = NETWORK_EXPOSURE_ISOLATED
                if allows_all_ingress and len(risky_ports_open) > 0:
                    network_exposure = NETWORK_EXPOSURE_INTERNET

                created_at = None
                if firewall.creation_timestamp:
                    try:
                        created_at = datetime.fromisoformat(
                            firewall.creation_timestamp.replace("Z", "+00:00")
                        )
                    except (ValueError, AttributeError):
                        pass

                assets.append(
                    Asset(
                        id=resource_id,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region="global",
                        resource_type="gcp_compute_firewall",
                        name=firewall_name,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing firewall rules: {e}")
            raise

        return assets

    def _collect_networks(self) -> list[Asset]:
        """Collect VPC networks."""
        client = self._get_networks_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = compute_v1.ListNetworksRequest(project=self._project_id)

            for network in client.list(request=request):
                network_name = network.name
                resource_id = (
                    f"projects/{self._project_id}/global/networks/{network_name}"
                )

                # Get subnetworks
                subnetworks = list(network.subnetworks or [])

                raw_config = {
                    "name": network_name,
                    "id": str(network.id),
                    "description": network.description or "",
                    "auto_create_subnetworks": network.auto_create_subnetworks,
                    "routing_mode": (
                        network.routing_config.routing_mode
                        if network.routing_config
                        else None
                    ),
                    "mtu": network.mtu,
                    "subnetworks": subnetworks,
                    "subnetwork_count": len(subnetworks),
                    "peerings": [
                        {
                            "name": p.name,
                            "network": p.network,
                            "state": p.state,
                            "auto_create_routes": p.auto_create_routes,
                            "export_custom_routes": p.export_custom_routes,
                            "import_custom_routes": p.import_custom_routes,
                        }
                        for p in (network.peerings or [])
                    ],
                    "is_default": network_name == "default",
                }

                created_at = None
                if network.creation_timestamp:
                    try:
                        created_at = datetime.fromisoformat(
                            network.creation_timestamp.replace("Z", "+00:00")
                        )
                    except (ValueError, AttributeError):
                        pass

                assets.append(
                    Asset(
                        id=resource_id,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region="global",
                        resource_type="gcp_compute_network",
                        name=network_name,
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing VPC networks: {e}")
            raise

        return assets
