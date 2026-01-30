"""
Azure Network collector for Mantissa Stance.

Collects Azure network resources including Application Gateway, Front Door,
Load Balancers, VPN Gateways, ExpressRoute, and DNS zones
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
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.frontdoor import FrontDoorManagementClient
    from azure.mgmt.dns import DnsManagementClient
    from azure.identity import DefaultAzureCredential

    AZURE_NETWORK_ADVANCED_AVAILABLE = True
except ImportError:
    AZURE_NETWORK_ADVANCED_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore


class AzureNetworkCollector(BaseCollector):
    """
    Collects Azure advanced network resources.

    Gathers Application Gateways, Front Door, Load Balancers, VPN Gateways,
    ExpressRoute connections, Azure Firewall, and DNS zones.
    All API calls are read-only.
    """

    collector_name = "azure_network"
    resource_types = [
        "azure_application_gateway",
        "azure_front_door",
        "azure_load_balancer",
        "azure_vpn_gateway_connection",
        "azure_express_route",
        "azure_firewall",
        "azure_dns_zone",
        "azure_network_watcher",
        "azure_private_endpoint",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure Network collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_NETWORK_ADVANCED_AVAILABLE:
            raise ImportError(
                "azure-mgmt-network, azure-mgmt-frontdoor, and azure-mgmt-dns are required for "
                "Azure Network collector. Install with: "
                "pip install azure-mgmt-network azure-mgmt-frontdoor azure-mgmt-dns azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._network_client: Any = None
        self._frontdoor_client: Any = None
        self._dns_client: Any = None

    def _get_network_client(self) -> Any:
        """Get or create Network Management client."""
        if self._network_client is None:
            self._network_client = NetworkManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._network_client

    def _get_frontdoor_client(self) -> Any:
        """Get or create Front Door Management client."""
        if self._frontdoor_client is None:
            self._frontdoor_client = FrontDoorManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._frontdoor_client

    def _get_dns_client(self) -> Any:
        """Get or create DNS Management client."""
        if self._dns_client is None:
            self._dns_client = DnsManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._dns_client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Azure network resources.

        Returns:
            Collection of network assets
        """
        assets: list[Asset] = []

        # Collect Application Gateways
        try:
            assets.extend(self._collect_application_gateways())
        except Exception as e:
            logger.warning(f"Failed to collect Application Gateways: {e}")

        # Collect Front Door
        try:
            assets.extend(self._collect_front_doors())
        except Exception as e:
            logger.warning(f"Failed to collect Front Doors: {e}")

        # Collect Load Balancers
        try:
            assets.extend(self._collect_load_balancers())
        except Exception as e:
            logger.warning(f"Failed to collect Load Balancers: {e}")

        # Collect VPN Gateways and connections
        try:
            assets.extend(self._collect_vpn_connections())
        except Exception as e:
            logger.warning(f"Failed to collect VPN connections: {e}")

        # Collect ExpressRoute circuits
        try:
            assets.extend(self._collect_expressroute_circuits())
        except Exception as e:
            logger.warning(f"Failed to collect ExpressRoute circuits: {e}")

        # Collect Azure Firewalls
        try:
            assets.extend(self._collect_azure_firewalls())
        except Exception as e:
            logger.warning(f"Failed to collect Azure Firewalls: {e}")

        # Collect DNS Zones
        try:
            assets.extend(self._collect_dns_zones())
        except Exception as e:
            logger.warning(f"Failed to collect DNS zones: {e}")

        # Collect Network Watchers
        try:
            assets.extend(self._collect_network_watchers())
        except Exception as e:
            logger.warning(f"Failed to collect Network Watchers: {e}")

        # Collect Private Endpoints
        try:
            assets.extend(self._collect_private_endpoints())
        except Exception as e:
            logger.warning(f"Failed to collect Private Endpoints: {e}")

        return AssetCollection(assets)

    def _collect_application_gateways(self) -> list[Asset]:
        """Collect Application Gateways with WAF configuration."""
        client = self._get_network_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            gateways = client.application_gateways.list_all()

            for gw in gateways:
                gw_id = gw.id or f"appgw/{gw.name}"

                # Check WAF configuration
                waf_enabled = False
                waf_mode = None
                if gw.web_application_firewall_configuration:
                    waf_enabled = gw.web_application_firewall_configuration.enabled
                    waf_mode = gw.web_application_firewall_configuration.firewall_mode

                # Check if using WAF v2 SKU
                sku_tier = gw.sku.tier if gw.sku else None
                is_waf_sku = sku_tier in ["WAF_v2", "WAF"]

                raw_config: dict[str, Any] = {
                    "name": gw.name,
                    "location": gw.location,
                    "sku_name": gw.sku.name if gw.sku else None,
                    "sku_tier": sku_tier,
                    "sku_capacity": gw.sku.capacity if gw.sku else None,
                    "waf_enabled": waf_enabled or is_waf_sku,
                    "waf_mode": waf_mode,
                    "ssl_policy": {
                        "policy_type": gw.ssl_policy.policy_type if gw.ssl_policy else None,
                        "policy_name": gw.ssl_policy.policy_name if gw.ssl_policy else None,
                        "min_protocol_version": (
                            gw.ssl_policy.min_protocol_version if gw.ssl_policy else None
                        ),
                    },
                    "frontend_ip_configurations": len(gw.frontend_ip_configurations or []),
                    "http_listeners": len(gw.http_listeners or []),
                    "backend_pools": len(gw.backend_address_pools or []),
                    "provisioning_state": gw.provisioning_state,
                }

                assets.append(
                    Asset(
                        id=gw_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=gw.location or "unknown",
                        resource_type="azure_application_gateway",
                        name=gw.name or "unknown",
                        network_exposure=NETWORK_EXPOSURE_INTERNET,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Application Gateways: {e}")

        return assets

    def _collect_front_doors(self) -> list[Asset]:
        """Collect Azure Front Door with WAF configuration."""
        client = self._get_frontdoor_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            front_doors = client.front_doors.list()

            for fd in front_doors:
                fd_id = fd.id or f"frontdoor/{fd.name}"

                # Check WAF policy association
                waf_enabled = False
                if fd.frontend_endpoints:
                    for endpoint in fd.frontend_endpoints:
                        if hasattr(endpoint, 'web_application_firewall_policy_link'):
                            if endpoint.web_application_firewall_policy_link:
                                waf_enabled = True
                                break

                raw_config: dict[str, Any] = {
                    "name": fd.name,
                    "location": fd.location,
                    "friendly_name": fd.friendly_name,
                    "waf_enabled": waf_enabled,
                    "frontend_endpoints_count": len(fd.frontend_endpoints or []),
                    "backend_pools_count": len(fd.backend_pools or []),
                    "routing_rules_count": len(fd.routing_rules or []),
                    "health_probe_settings_count": len(fd.health_probe_settings or []),
                    "enabled_state": fd.enabled_state,
                    "provisioning_state": fd.provisioning_state,
                }

                assets.append(
                    Asset(
                        id=fd_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region="global",
                        resource_type="azure_front_door",
                        name=fd.name or "unknown",
                        network_exposure=NETWORK_EXPOSURE_INTERNET,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Front Doors: {e}")

        return assets

    def _collect_load_balancers(self) -> list[Asset]:
        """Collect Load Balancers with diagnostic settings."""
        client = self._get_network_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            lbs = client.load_balancers.list_all()

            for lb in lbs:
                lb_id = lb.id or f"loadbalancer/{lb.name}"

                # Determine if public or internal
                is_public = False
                if lb.frontend_ip_configurations:
                    for fip in lb.frontend_ip_configurations:
                        if fip.public_ip_address:
                            is_public = True
                            break

                raw_config: dict[str, Any] = {
                    "name": lb.name,
                    "location": lb.location,
                    "sku_name": lb.sku.name if lb.sku else None,
                    "sku_tier": lb.sku.tier if lb.sku else None,
                    "is_public": is_public,
                    "frontend_ip_count": len(lb.frontend_ip_configurations or []),
                    "backend_pool_count": len(lb.backend_address_pools or []),
                    "load_balancing_rules_count": len(lb.load_balancing_rules or []),
                    "inbound_nat_rules_count": len(lb.inbound_nat_rules or []),
                    "probes_count": len(lb.probes or []),
                    "provisioning_state": lb.provisioning_state,
                    # Diagnostic settings would require separate Monitor API call
                    "diagnostic_settings_enabled": False,  # Placeholder
                }

                network_exposure = (
                    NETWORK_EXPOSURE_INTERNET if is_public else NETWORK_EXPOSURE_INTERNAL
                )

                assets.append(
                    Asset(
                        id=lb_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=lb.location or "unknown",
                        resource_type="azure_load_balancer",
                        name=lb.name or "unknown",
                        network_exposure=network_exposure,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Load Balancers: {e}")

        return assets

    def _collect_vpn_connections(self) -> list[Asset]:
        """Collect VPN Gateway connections."""
        client = self._get_network_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            # Get all VPN gateways first
            gateways = client.virtual_network_gateways.list_all()

            for gw in gateways:
                if gw.gateway_type != "Vpn":
                    continue

                # Get connections for this gateway
                resource_group = ""
                if gw.id:
                    parts = gw.id.split("/")
                    if "resourceGroups" in parts:
                        idx = parts.index("resourceGroups")
                        if idx + 1 < len(parts):
                            resource_group = parts[idx + 1]

                if not resource_group:
                    continue

                try:
                    connections = client.virtual_network_gateway_connections.list(
                        resource_group_name=resource_group
                    )

                    for conn in connections:
                        conn_id = conn.id or f"vpnconnection/{conn.name}"

                        # Check IKE version
                        ike_version = "IKEv1"  # Default assumption
                        if conn.ipsec_policies:
                            for policy in conn.ipsec_policies:
                                if hasattr(policy, 'ike_version'):
                                    ike_version = policy.ike_version
                                    break
                        # Also check connection protocol
                        if hasattr(conn, 'connection_protocol'):
                            if conn.connection_protocol == "IKEv2":
                                ike_version = "IKEv2"

                        uses_ikev2 = ike_version == "IKEv2"

                        raw_config: dict[str, Any] = {
                            "name": conn.name,
                            "location": conn.location,
                            "connection_type": conn.connection_type,
                            "connection_status": conn.connection_status,
                            "ike_version": ike_version,
                            "uses_ikev2": uses_ikev2,
                            "shared_key_set": conn.shared_key is not None,
                            "enable_bgp": conn.enable_bgp or False,
                            "use_policy_based_traffic_selectors": (
                                conn.use_policy_based_traffic_selectors or False
                            ),
                            "provisioning_state": conn.provisioning_state,
                            "virtual_network_gateway_id": (
                                conn.virtual_network_gateway1.id
                                if conn.virtual_network_gateway1 else None
                            ),
                        }

                        assets.append(
                            Asset(
                                id=conn_id,
                                cloud_provider="azure",
                                account_id=self._subscription_id,
                                region=conn.location or "unknown",
                                resource_type="azure_vpn_gateway_connection",
                                name=conn.name or "unknown",
                                network_exposure=NETWORK_EXPOSURE_INTERNET,
                                last_seen=now,
                                raw_config=raw_config,
                            )
                        )

                except Exception as e:
                    logger.debug(f"Could not get connections for gateway {gw.name}: {e}")

        except Exception as e:
            logger.error(f"Error listing VPN connections: {e}")

        return assets

    def _collect_expressroute_circuits(self) -> list[Asset]:
        """Collect ExpressRoute circuits."""
        client = self._get_network_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            circuits = client.express_route_circuits.list_all()

            for circuit in circuits:
                circuit_id = circuit.id or f"expressroute/{circuit.name}"

                # Check for MACsec configuration
                uses_macsec = False
                if hasattr(circuit, 'express_route_port'):
                    if circuit.express_route_port:
                        # MACsec is configured at the port level
                        # This is a simplified check
                        uses_macsec = True

                raw_config: dict[str, Any] = {
                    "name": circuit.name,
                    "location": circuit.location,
                    "sku_tier": circuit.sku.tier if circuit.sku else None,
                    "sku_family": circuit.sku.family if circuit.sku else None,
                    "service_provider_name": circuit.service_provider_properties.service_provider_name
                        if circuit.service_provider_properties else None,
                    "peering_location": circuit.service_provider_properties.peering_location
                        if circuit.service_provider_properties else None,
                    "bandwidth_in_mbps": circuit.service_provider_properties.bandwidth_in_mbps
                        if circuit.service_provider_properties else None,
                    "circuit_provisioning_state": circuit.circuit_provisioning_state,
                    "service_provider_provisioning_state": circuit.service_provider_provisioning_state,
                    "allow_classic_operations": circuit.allow_classic_operations or False,
                    "uses_macsec": uses_macsec,
                    "peerings_count": len(circuit.peerings or []),
                    "provisioning_state": circuit.provisioning_state,
                }

                assets.append(
                    Asset(
                        id=circuit_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=circuit.location or "unknown",
                        resource_type="azure_express_route",
                        name=circuit.name or "unknown",
                        network_exposure=NETWORK_EXPOSURE_INTERNAL,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing ExpressRoute circuits: {e}")

        return assets

    def _collect_azure_firewalls(self) -> list[Asset]:
        """Collect Azure Firewalls."""
        client = self._get_network_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            firewalls = client.azure_firewalls.list_all()

            for fw in firewalls:
                fw_id = fw.id or f"firewall/{fw.name}"

                # Check threat intelligence mode
                threat_intel_mode = fw.threat_intel_mode if hasattr(fw, 'threat_intel_mode') else None
                threat_intel_enabled = threat_intel_mode in ["Alert", "Deny"]

                raw_config: dict[str, Any] = {
                    "name": fw.name,
                    "location": fw.location,
                    "sku_name": fw.sku.name if fw.sku else None,
                    "sku_tier": fw.sku.tier if fw.sku else None,
                    "threat_intel_mode": threat_intel_mode,
                    "threat_intel_enabled": threat_intel_enabled,
                    "firewall_policy_id": fw.firewall_policy.id if fw.firewall_policy else None,
                    "ip_configurations_count": len(fw.ip_configurations or []),
                    "network_rule_collections_count": len(fw.network_rule_collections or []),
                    "application_rule_collections_count": len(fw.application_rule_collections or []),
                    "nat_rule_collections_count": len(fw.nat_rule_collections or []),
                    "provisioning_state": fw.provisioning_state,
                }

                assets.append(
                    Asset(
                        id=fw_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=fw.location or "unknown",
                        resource_type="azure_firewall",
                        name=fw.name or "unknown",
                        network_exposure=NETWORK_EXPOSURE_INTERNET,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Azure Firewalls: {e}")

        return assets

    def _collect_dns_zones(self) -> list[Asset]:
        """Collect DNS zones with DNSSEC status."""
        client = self._get_dns_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            zones = client.zones.list()

            for zone in zones:
                zone_id = zone.id or f"dnszone/{zone.name}"

                # Check DNSSEC status (available in Azure DNS)
                dnssec_enabled = False
                if hasattr(zone, 'dnssec_config'):
                    dnssec_enabled = zone.dnssec_config is not None

                raw_config: dict[str, Any] = {
                    "name": zone.name,
                    "location": zone.location,
                    "zone_type": zone.zone_type,
                    "dnssec_enabled": dnssec_enabled,
                    "max_number_of_record_sets": zone.max_number_of_record_sets,
                    "number_of_record_sets": zone.number_of_record_sets,
                    "name_servers": list(zone.name_servers) if zone.name_servers else [],
                }

                assets.append(
                    Asset(
                        id=zone_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region="global",
                        resource_type="azure_dns_zone",
                        name=zone.name or "unknown",
                        network_exposure=NETWORK_EXPOSURE_INTERNET,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing DNS zones: {e}")

        return assets

    def _collect_network_watchers(self) -> list[Asset]:
        """Collect Network Watchers."""
        client = self._get_network_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            watchers = client.network_watchers.list_all()
            watcher_list = list(watchers)

            # Get all Azure regions
            # Network Watcher should be enabled in all regions with resources
            enabled_regions = set()
            for watcher in watcher_list:
                if watcher.location:
                    enabled_regions.add(watcher.location.lower().replace(" ", ""))

            for watcher in watcher_list:
                watcher_id = watcher.id or f"networkwatcher/{watcher.name}"

                raw_config: dict[str, Any] = {
                    "name": watcher.name,
                    "location": watcher.location,
                    "provisioning_state": watcher.provisioning_state,
                    "enabled_regions": list(enabled_regions),
                    "enabled_in_all_regions": len(enabled_regions) >= 10,  # Simplified check
                }

                assets.append(
                    Asset(
                        id=watcher_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=watcher.location or "unknown",
                        resource_type="azure_network_watcher",
                        name=watcher.name or "unknown",
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Network Watchers: {e}")

        return assets

    def _collect_private_endpoints(self) -> list[Asset]:
        """Collect Private Endpoints."""
        client = self._get_network_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            endpoints = client.private_endpoints.list_by_subscription()

            for endpoint in endpoints:
                endpoint_id = endpoint.id or f"privateendpoint/{endpoint.name}"

                # Get connected service
                connected_service = None
                if endpoint.private_link_service_connections:
                    for conn in endpoint.private_link_service_connections:
                        if conn.private_link_service_id:
                            connected_service = conn.private_link_service_id
                            break

                raw_config: dict[str, Any] = {
                    "name": endpoint.name,
                    "location": endpoint.location,
                    "subnet_id": endpoint.subnet.id if endpoint.subnet else None,
                    "connected_service": connected_service,
                    "custom_dns_configs": [
                        {"fqdn": dns.fqdn, "ip_addresses": list(dns.ip_addresses or [])}
                        for dns in (endpoint.custom_dns_configs or [])
                    ],
                    "provisioning_state": endpoint.provisioning_state,
                    "uses_private_link": True,
                }

                assets.append(
                    Asset(
                        id=endpoint_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=endpoint.location or "unknown",
                        resource_type="azure_private_endpoint",
                        name=endpoint.name or "unknown",
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Private Endpoints: {e}")

        return assets
