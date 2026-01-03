"""
Azure Compute collector for Mantissa Stance.

Collects Azure Virtual Machines, Network Security Groups, Virtual Networks,
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

# Optional Azure imports
try:
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.identity import DefaultAzureCredential

    AZURE_COMPUTE_AVAILABLE = True
except ImportError:
    AZURE_COMPUTE_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore

# Sensitive ports that should not be exposed to the internet
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    1434: "MSSQL Browser",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5601: "Kibana",
    8080: "HTTP Alt",
    23: "Telnet",
    21: "FTP",
    445: "SMB",
    135: "RPC",
    139: "NetBIOS",
}


class AzureComputeCollector(BaseCollector):
    """
    Collects Azure Compute resources and network configuration.

    Gathers virtual machines, network security groups, virtual networks,
    and subnets. All API calls are read-only.
    """

    collector_name = "azure_compute"
    resource_types = [
        "azure_virtual_machine",
        "azure_network_security_group",
        "azure_virtual_network",
        "azure_subnet",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure Compute collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_COMPUTE_AVAILABLE:
            raise ImportError(
                "azure-mgmt-compute and azure-mgmt-network are required for "
                "Azure compute collector. Install with: "
                "pip install azure-mgmt-compute azure-mgmt-network azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._compute_client: ComputeManagementClient | None = None
        self._network_client: NetworkManagementClient | None = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_compute_client(self) -> ComputeManagementClient:
        """Get or create Compute Management client."""
        if self._compute_client is None:
            self._compute_client = ComputeManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._compute_client

    def _get_network_client(self) -> NetworkManagementClient:
        """Get or create Network Management client."""
        if self._network_client is None:
            self._network_client = NetworkManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._network_client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Compute and Network resources.

        Returns:
            Collection of compute and network assets
        """
        assets: list[Asset] = []

        # Collect virtual machines
        try:
            assets.extend(self._collect_virtual_machines())
        except Exception as e:
            logger.warning(f"Failed to collect virtual machines: {e}")

        # Collect network security groups
        try:
            assets.extend(self._collect_network_security_groups())
        except Exception as e:
            logger.warning(f"Failed to collect network security groups: {e}")

        # Collect virtual networks
        try:
            assets.extend(self._collect_virtual_networks())
        except Exception as e:
            logger.warning(f"Failed to collect virtual networks: {e}")

        return AssetCollection(assets)

    def _collect_virtual_machines(self) -> list[Asset]:
        """Collect Azure Virtual Machines with their configurations."""
        compute_client = self._get_compute_client()
        network_client = self._get_network_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for vm in compute_client.virtual_machines.list_all():
                vm_id = vm.id
                vm_name = vm.name
                resource_group = self._extract_resource_group(vm_id)
                location = vm.location

                # Extract tags
                tags = dict(vm.tags) if vm.tags else {}

                raw_config: dict[str, Any] = {
                    "vm_id": vm_id,
                    "vm_name": vm_name,
                    "resource_group": resource_group,
                    "location": location,
                    "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
                    "provisioning_state": vm.provisioning_state,
                }

                # OS profile
                if vm.os_profile:
                    raw_config["os_profile"] = {
                        "computer_name": vm.os_profile.computer_name,
                        "admin_username": vm.os_profile.admin_username,
                        "linux_configuration": None,
                        "windows_configuration": None,
                    }
                    if vm.os_profile.linux_configuration:
                        linux_config = vm.os_profile.linux_configuration
                        raw_config["os_profile"]["linux_configuration"] = {
                            "disable_password_authentication": (
                                linux_config.disable_password_authentication
                            ),
                            "provision_vm_agent": linux_config.provision_vm_agent,
                        }
                        raw_config["password_auth_disabled"] = (
                            linux_config.disable_password_authentication or False
                        )
                    if vm.os_profile.windows_configuration:
                        win_config = vm.os_profile.windows_configuration
                        raw_config["os_profile"]["windows_configuration"] = {
                            "provision_vm_agent": win_config.provision_vm_agent,
                            "enable_automatic_updates": win_config.enable_automatic_updates,
                        }
                        raw_config["auto_updates_enabled"] = (
                            win_config.enable_automatic_updates or False
                        )

                # Storage profile
                if vm.storage_profile:
                    os_disk = vm.storage_profile.os_disk
                    raw_config["storage_profile"] = {
                        "os_disk": {
                            "name": os_disk.name if os_disk else None,
                            "os_type": os_disk.os_type if os_disk else None,
                            "caching": os_disk.caching if os_disk else None,
                        } if os_disk else None,
                        "data_disks": [
                            {
                                "name": disk.name,
                                "lun": disk.lun,
                                "caching": disk.caching,
                                "disk_size_gb": disk.disk_size_gb,
                            }
                            for disk in (vm.storage_profile.data_disks or [])
                        ],
                    }
                    # Check disk encryption
                    if os_disk and os_disk.encryption_settings:
                        raw_config["os_disk_encrypted"] = os_disk.encryption_settings.enabled
                    else:
                        raw_config["os_disk_encrypted"] = None

                # Network interfaces
                network_interfaces = []
                has_public_ip = False
                public_ips = []
                private_ips = []
                associated_nsgs = []

                if vm.network_profile and vm.network_profile.network_interfaces:
                    for nic_ref in vm.network_profile.network_interfaces:
                        nic_id = nic_ref.id
                        nic_name = nic_id.split("/")[-1] if nic_id else None
                        nic_rg = self._extract_resource_group(nic_id) if nic_id else None

                        # Get NIC details
                        try:
                            if nic_name and nic_rg:
                                nic = network_client.network_interfaces.get(
                                    nic_rg, nic_name
                                )
                                nic_info = {
                                    "id": nic.id,
                                    "name": nic.name,
                                    "primary": nic_ref.primary,
                                    "mac_address": nic.mac_address,
                                    "enable_ip_forwarding": nic.enable_ip_forwarding,
                                    "enable_accelerated_networking": (
                                        nic.enable_accelerated_networking
                                    ),
                                }

                                # Check for NSG
                                if nic.network_security_group:
                                    nic_info["network_security_group"] = (
                                        nic.network_security_group.id
                                    )
                                    associated_nsgs.append(nic.network_security_group.id)

                                # IP configurations
                                ip_configs = []
                                for ip_config in (nic.ip_configurations or []):
                                    ip_info = {
                                        "name": ip_config.name,
                                        "private_ip_address": ip_config.private_ip_address,
                                        "private_ip_allocation_method": (
                                            ip_config.private_ip_allocation_method
                                        ),
                                        "primary": ip_config.primary,
                                    }
                                    if ip_config.private_ip_address:
                                        private_ips.append(ip_config.private_ip_address)

                                    # Check for public IP
                                    if ip_config.public_ip_address:
                                        pub_ip_id = ip_config.public_ip_address.id
                                        ip_info["public_ip_address_id"] = pub_ip_id
                                        has_public_ip = True

                                        # Get actual public IP address
                                        try:
                                            pub_ip_name = pub_ip_id.split("/")[-1]
                                            pub_ip_rg = self._extract_resource_group(pub_ip_id)
                                            pub_ip = network_client.public_ip_addresses.get(
                                                pub_ip_rg, pub_ip_name
                                            )
                                            if pub_ip.ip_address:
                                                public_ips.append(pub_ip.ip_address)
                                                ip_info["public_ip_address"] = pub_ip.ip_address
                                        except Exception as e:
                                            logger.debug(
                                                f"Could not get public IP details: {e}"
                                            )

                                    ip_configs.append(ip_info)

                                nic_info["ip_configurations"] = ip_configs
                                network_interfaces.append(nic_info)

                        except Exception as e:
                            logger.debug(f"Could not get NIC details for {nic_id}: {e}")

                raw_config["network_interfaces"] = network_interfaces
                raw_config["has_public_ip"] = has_public_ip
                raw_config["public_ips"] = public_ips
                raw_config["private_ips"] = private_ips
                raw_config["associated_nsgs"] = associated_nsgs

                # Identity configuration
                if vm.identity:
                    raw_config["identity"] = {
                        "type": vm.identity.type,
                        "principal_id": vm.identity.principal_id,
                        "tenant_id": vm.identity.tenant_id,
                        "user_assigned_identities": (
                            list(vm.identity.user_assigned_identities.keys())
                            if vm.identity.user_assigned_identities
                            else []
                        ),
                    }
                    raw_config["has_managed_identity"] = True
                else:
                    raw_config["has_managed_identity"] = False

                # Boot diagnostics
                if vm.diagnostics_profile and vm.diagnostics_profile.boot_diagnostics:
                    boot_diag = vm.diagnostics_profile.boot_diagnostics
                    raw_config["boot_diagnostics"] = {
                        "enabled": boot_diag.enabled,
                        "storage_uri": boot_diag.storage_uri,
                    }
                    raw_config["boot_diagnostics_enabled"] = boot_diag.enabled
                else:
                    raw_config["boot_diagnostics_enabled"] = False

                # Availability configuration
                raw_config["availability_set"] = (
                    vm.availability_set.id if vm.availability_set else None
                )
                raw_config["zones"] = list(vm.zones) if vm.zones else []

                # Determine network exposure
                network_exposure = NETWORK_EXPOSURE_INTERNAL
                if has_public_ip:
                    network_exposure = NETWORK_EXPOSURE_INTERNET

                created_at = None
                if vm.time_created:
                    created_at = vm.time_created.replace(tzinfo=timezone.utc)

                assets.append(
                    Asset(
                        id=vm_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=location,
                        resource_type="azure_virtual_machine",
                        name=vm_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing virtual machines: {e}")
            raise

        return assets

    def _collect_network_security_groups(self) -> list[Asset]:
        """Collect Network Security Groups with their rules."""
        network_client = self._get_network_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for nsg in network_client.network_security_groups.list_all():
                nsg_id = nsg.id
                nsg_name = nsg.name
                resource_group = self._extract_resource_group(nsg_id)
                location = nsg.location

                # Extract tags
                tags = dict(nsg.tags) if nsg.tags else {}

                # Process security rules
                inbound_rules = []
                outbound_rules = []
                dangerous_inbound = []

                for rule in (nsg.security_rules or []):
                    rule_info = self._process_security_rule(rule)

                    if rule.direction == "Inbound":
                        inbound_rules.append(rule_info)
                        if rule_info.get("is_risky"):
                            dangerous_inbound.append(rule_info)
                    else:
                        outbound_rules.append(rule_info)

                # Also process default rules
                for rule in (nsg.default_security_rules or []):
                    rule_info = self._process_security_rule(rule, is_default=True)
                    if rule.direction == "Inbound":
                        inbound_rules.append(rule_info)
                    else:
                        outbound_rules.append(rule_info)

                # Check for specific dangerous configurations
                allows_ssh_from_internet = any(
                    r.get("allows_ssh_from_internet") for r in dangerous_inbound
                )
                allows_rdp_from_internet = any(
                    r.get("allows_rdp_from_internet") for r in dangerous_inbound
                )
                allows_all_from_internet = any(
                    r.get("allows_all_from_internet") for r in dangerous_inbound
                )

                raw_config: dict[str, Any] = {
                    "nsg_id": nsg_id,
                    "nsg_name": nsg_name,
                    "resource_group": resource_group,
                    "location": location,
                    "provisioning_state": nsg.provisioning_state,
                    "inbound_rules": inbound_rules,
                    "outbound_rules": outbound_rules,
                    "dangerous_inbound_rules": dangerous_inbound,
                    "has_dangerous_rules": len(dangerous_inbound) > 0,
                    "allows_ssh_from_internet": allows_ssh_from_internet,
                    "allows_rdp_from_internet": allows_rdp_from_internet,
                    "allows_all_from_internet": allows_all_from_internet,
                    "associated_network_interfaces": [
                        nic.id for nic in (nsg.network_interfaces or [])
                    ],
                    "associated_subnets": [
                        subnet.id for subnet in (nsg.subnets or [])
                    ],
                }

                # Determine network exposure based on rules
                network_exposure = NETWORK_EXPOSURE_ISOLATED
                if len(dangerous_inbound) > 0:
                    network_exposure = NETWORK_EXPOSURE_INTERNET

                assets.append(
                    Asset(
                        id=nsg_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=location,
                        resource_type="azure_network_security_group",
                        name=nsg_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing network security groups: {e}")
            raise

        return assets

    def _collect_virtual_networks(self) -> list[Asset]:
        """Collect Virtual Networks with their subnets."""
        network_client = self._get_network_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for vnet in network_client.virtual_networks.list_all():
                vnet_id = vnet.id
                vnet_name = vnet.name
                resource_group = self._extract_resource_group(vnet_id)
                location = vnet.location

                # Extract tags
                tags = dict(vnet.tags) if vnet.tags else {}

                # Address space
                address_space = []
                if vnet.address_space and vnet.address_space.address_prefixes:
                    address_space = list(vnet.address_space.address_prefixes)

                # DHCP options
                dhcp_options = []
                if vnet.dhcp_options and vnet.dhcp_options.dns_servers:
                    dhcp_options = list(vnet.dhcp_options.dns_servers)

                # Collect subnets
                subnets = []
                for subnet in (vnet.subnets or []):
                    subnet_info = {
                        "id": subnet.id,
                        "name": subnet.name,
                        "address_prefix": subnet.address_prefix,
                        "provisioning_state": subnet.provisioning_state,
                        "network_security_group": (
                            subnet.network_security_group.id
                            if subnet.network_security_group
                            else None
                        ),
                        "route_table": (
                            subnet.route_table.id if subnet.route_table else None
                        ),
                        "service_endpoints": [
                            {
                                "service": ep.service,
                                "locations": list(ep.locations) if ep.locations else [],
                            }
                            for ep in (subnet.service_endpoints or [])
                        ],
                        "private_endpoint_network_policies": (
                            subnet.private_endpoint_network_policies
                        ),
                        "private_link_service_network_policies": (
                            subnet.private_link_service_network_policies
                        ),
                    }
                    subnets.append(subnet_info)

                    # Also create subnet as separate asset
                    subnet_asset = Asset(
                        id=subnet.id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=location,
                        resource_type="azure_subnet",
                        name=subnet.name,
                        network_exposure=NETWORK_EXPOSURE_INTERNAL,
                        last_seen=now,
                        raw_config=subnet_info,
                    )
                    assets.append(subnet_asset)

                # VNet peerings
                peerings = []
                for peering in (vnet.virtual_network_peerings or []):
                    peerings.append({
                        "id": peering.id,
                        "name": peering.name,
                        "peering_state": peering.peering_state,
                        "remote_virtual_network": (
                            peering.remote_virtual_network.id
                            if peering.remote_virtual_network
                            else None
                        ),
                        "allow_virtual_network_access": peering.allow_virtual_network_access,
                        "allow_forwarded_traffic": peering.allow_forwarded_traffic,
                        "allow_gateway_transit": peering.allow_gateway_transit,
                        "use_remote_gateways": peering.use_remote_gateways,
                    })

                raw_config: dict[str, Any] = {
                    "vnet_id": vnet_id,
                    "vnet_name": vnet_name,
                    "resource_group": resource_group,
                    "location": location,
                    "provisioning_state": vnet.provisioning_state,
                    "address_space": address_space,
                    "dhcp_options": dhcp_options,
                    "subnets": subnets,
                    "subnet_count": len(subnets),
                    "peerings": peerings,
                    "peering_count": len(peerings),
                    "enable_ddos_protection": vnet.enable_ddos_protection or False,
                    "ddos_protection_plan": (
                        vnet.ddos_protection_plan.id
                        if vnet.ddos_protection_plan
                        else None
                    ),
                    "enable_vm_protection": vnet.enable_vm_protection or False,
                }

                assets.append(
                    Asset(
                        id=vnet_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=location,
                        resource_type="azure_virtual_network",
                        name=vnet_name,
                        tags=tags,
                        network_exposure=NETWORK_EXPOSURE_INTERNAL,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing virtual networks: {e}")
            raise

        return assets

    def _process_security_rule(
        self, rule: Any, is_default: bool = False
    ) -> dict[str, Any]:
        """
        Process an NSG security rule into a normalized format.

        Args:
            rule: Security rule object from Azure
            is_default: Whether this is a default rule

        Returns:
            Normalized rule dictionary
        """
        # Parse port range
        from_port = None
        to_port = None
        port_range = rule.destination_port_range

        if port_range == "*":
            from_port = 0
            to_port = 65535
        elif port_range and "-" in port_range:
            parts = port_range.split("-")
            from_port = int(parts[0])
            to_port = int(parts[1])
        elif port_range:
            from_port = to_port = int(port_range)

        # Parse source addresses
        source_addresses = []
        if rule.source_address_prefix:
            source_addresses.append(rule.source_address_prefix)
        if rule.source_address_prefixes:
            source_addresses.extend(rule.source_address_prefixes)

        # Check if allows from internet
        allows_from_internet = (
            "*" in source_addresses or
            "Internet" in source_addresses or
            "0.0.0.0/0" in source_addresses
        )

        processed: dict[str, Any] = {
            "name": rule.name,
            "priority": rule.priority,
            "direction": rule.direction,
            "access": rule.access,
            "protocol": rule.protocol,
            "source_address_prefix": rule.source_address_prefix,
            "source_address_prefixes": list(rule.source_address_prefixes or []),
            "destination_address_prefix": rule.destination_address_prefix,
            "destination_address_prefixes": list(rule.destination_address_prefixes or []),
            "source_port_range": rule.source_port_range,
            "source_port_ranges": list(rule.source_port_ranges or []),
            "destination_port_range": rule.destination_port_range,
            "destination_port_ranges": list(rule.destination_port_ranges or []),
            "from_port": from_port,
            "to_port": to_port,
            "is_default": is_default,
            "allows_from_internet": allows_from_internet,
        }

        # Check if this is a risky rule (Allow from internet)
        is_risky = False
        allows_ssh_from_internet = False
        allows_rdp_from_internet = False
        allows_all_from_internet = False
        risky_ports = []

        if rule.access == "Allow" and allows_from_internet:
            is_risky = True

            if from_port is not None and to_port is not None:
                # Check for all ports
                if from_port == 0 and to_port == 65535:
                    allows_all_from_internet = True
                    risky_ports = list(SENSITIVE_PORTS.values())
                else:
                    # Check specific sensitive ports
                    for port, service in SENSITIVE_PORTS.items():
                        if from_port <= port <= to_port:
                            risky_ports.append(service)
                            if port == 22:
                                allows_ssh_from_internet = True
                            if port == 3389:
                                allows_rdp_from_internet = True

        processed["is_risky"] = is_risky
        processed["allows_ssh_from_internet"] = allows_ssh_from_internet
        processed["allows_rdp_from_internet"] = allows_rdp_from_internet
        processed["allows_all_from_internet"] = allows_all_from_internet
        processed["risky_ports_exposed"] = risky_ports

        return processed

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
