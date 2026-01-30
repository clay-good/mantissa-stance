"""
GCP Network collector for Mantissa Stance.

Collects GCP network resources including load balancers, SSL policies,
Cloud NAT, Cloud DNS, VPN tunnels, and Cloud Interconnect
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

# Optional GCP imports
try:
    from google.cloud import compute_v1
    from google.cloud import dns_v1

    GCP_NETWORK_AVAILABLE = True
except ImportError:
    GCP_NETWORK_AVAILABLE = False


class GCPNetworkCollector(BaseCollector):
    """
    Collects GCP advanced network resources.

    Gathers load balancers, SSL policies, Cloud NAT, Cloud DNS,
    VPN tunnels, and Cloud Interconnect. All API calls are read-only.
    """

    collector_name = "gcp_network"
    resource_types = [
        "gcp_compute_backend_service",
        "gcp_compute_url_map",
        "gcp_compute_ssl_policy",
        "gcp_compute_router_nat",
        "gcp_dns_managed_zone",
        "gcp_compute_vpn_tunnel",
        "gcp_compute_interconnect",
        "gcp_compute_disk",
        "gcp_api_key",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP Network collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            **kwargs: Additional configuration.
        """
        if not GCP_NETWORK_AVAILABLE:
            raise ImportError(
                "google-cloud-compute and google-cloud-dns are required for GCP network collector. "
                "Install with: pip install google-cloud-compute google-cloud-dns"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._clients: dict[str, Any] = {}

    def _get_backend_services_client(self) -> compute_v1.BackendServicesClient:
        """Get or create Backend Services client."""
        if "backend_services" not in self._clients:
            self._clients["backend_services"] = compute_v1.BackendServicesClient(
                credentials=self._credentials
            )
        return self._clients["backend_services"]

    def _get_url_maps_client(self) -> compute_v1.UrlMapsClient:
        """Get or create URL Maps client."""
        if "url_maps" not in self._clients:
            self._clients["url_maps"] = compute_v1.UrlMapsClient(
                credentials=self._credentials
            )
        return self._clients["url_maps"]

    def _get_ssl_policies_client(self) -> compute_v1.SslPoliciesClient:
        """Get or create SSL Policies client."""
        if "ssl_policies" not in self._clients:
            self._clients["ssl_policies"] = compute_v1.SslPoliciesClient(
                credentials=self._credentials
            )
        return self._clients["ssl_policies"]

    def _get_routers_client(self) -> compute_v1.RoutersClient:
        """Get or create Routers client."""
        if "routers" not in self._clients:
            self._clients["routers"] = compute_v1.RoutersClient(
                credentials=self._credentials
            )
        return self._clients["routers"]

    def _get_vpn_tunnels_client(self) -> compute_v1.VpnTunnelsClient:
        """Get or create VPN Tunnels client."""
        if "vpn_tunnels" not in self._clients:
            self._clients["vpn_tunnels"] = compute_v1.VpnTunnelsClient(
                credentials=self._credentials
            )
        return self._clients["vpn_tunnels"]

    def _get_interconnects_client(self) -> compute_v1.InterconnectsClient:
        """Get or create Interconnects client."""
        if "interconnects" not in self._clients:
            self._clients["interconnects"] = compute_v1.InterconnectsClient(
                credentials=self._credentials
            )
        return self._clients["interconnects"]

    def _get_disks_client(self) -> compute_v1.DisksClient:
        """Get or create Disks client."""
        if "disks" not in self._clients:
            self._clients["disks"] = compute_v1.DisksClient(
                credentials=self._credentials
            )
        return self._clients["disks"]

    def _get_dns_client(self) -> dns_v1.ManagedZonesClient:
        """Get or create DNS client."""
        if "dns" not in self._clients:
            self._clients["dns"] = dns_v1.ManagedZonesClient(
                credentials=self._credentials
            )
        return self._clients["dns"]

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all GCP network resources.

        Returns:
            Collection of network assets
        """
        assets: list[Asset] = []

        # Collect backend services (for Cloud Armor)
        try:
            assets.extend(self._collect_backend_services())
        except Exception as e:
            logger.warning(f"Failed to collect backend services: {e}")

        # Collect URL maps (for HTTPS frontends)
        try:
            assets.extend(self._collect_url_maps())
        except Exception as e:
            logger.warning(f"Failed to collect URL maps: {e}")

        # Collect SSL policies
        try:
            assets.extend(self._collect_ssl_policies())
        except Exception as e:
            logger.warning(f"Failed to collect SSL policies: {e}")

        # Collect Cloud NAT
        try:
            assets.extend(self._collect_cloud_nat())
        except Exception as e:
            logger.warning(f"Failed to collect Cloud NAT: {e}")

        # Collect Cloud DNS zones
        try:
            assets.extend(self._collect_dns_zones())
        except Exception as e:
            logger.warning(f"Failed to collect DNS zones: {e}")

        # Collect VPN tunnels
        try:
            assets.extend(self._collect_vpn_tunnels())
        except Exception as e:
            logger.warning(f"Failed to collect VPN tunnels: {e}")

        # Collect Cloud Interconnects
        try:
            assets.extend(self._collect_interconnects())
        except Exception as e:
            logger.warning(f"Failed to collect Interconnects: {e}")

        # Collect Compute disks
        try:
            assets.extend(self._collect_disks())
        except Exception as e:
            logger.warning(f"Failed to collect Compute disks: {e}")

        return AssetCollection(assets)

    def _collect_backend_services(self) -> list[Asset]:
        """Collect backend services with Cloud Armor configuration."""
        client = self._get_backend_services_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = compute_v1.AggregatedListBackendServicesRequest(
                project=self._project_id
            )
            response = client.aggregated_list(request=request)

            for region, scoped_list in response:
                if not scoped_list.backend_services:
                    continue

                for bs in scoped_list.backend_services:
                    bs_id = f"projects/{self._project_id}/global/backendServices/{bs.name}"

                    # Check for Cloud Armor (security policy)
                    has_cloud_armor = bs.security_policy is not None

                    # Check for IAP (Identity-Aware Proxy)
                    has_iap = False
                    if bs.iap:
                        has_iap = bs.iap.enabled

                    raw_config: dict[str, Any] = {
                        "name": bs.name,
                        "description": bs.description or "",
                        "protocol": bs.protocol,
                        "port": bs.port,
                        "port_name": bs.port_name,
                        "timeout_sec": bs.timeout_sec,
                        "security_policy": bs.security_policy,
                        "has_cloud_armor": has_cloud_armor,
                        "iap_enabled": has_iap,
                        "load_balancing_scheme": bs.load_balancing_scheme,
                        "backends_count": len(bs.backends or []),
                        "health_checks": list(bs.health_checks or []),
                        "cdn_enabled": bs.enable_cdn if hasattr(bs, 'enable_cdn') else False,
                        "connection_draining_timeout_sec": (
                            bs.connection_draining.draining_timeout_sec
                            if bs.connection_draining else None
                        ),
                    }

                    assets.append(
                        Asset(
                            id=bs_id,
                            cloud_provider="gcp",
                            account_id=self._project_id,
                            region="global",
                            resource_type="gcp_compute_backend_service",
                            name=bs.name,
                            network_exposure=NETWORK_EXPOSURE_INTERNET,
                            last_seen=now,
                            raw_config=raw_config,
                        )
                    )

        except Exception as e:
            logger.error(f"Error listing backend services: {e}")

        return assets

    def _collect_url_maps(self) -> list[Asset]:
        """Collect URL maps (load balancer configurations)."""
        client = self._get_url_maps_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = compute_v1.ListUrlMapsRequest(project=self._project_id)
            response = client.list(request=request)

            for url_map in response:
                url_map_id = f"projects/{self._project_id}/global/urlMaps/{url_map.name}"

                # Check if using HTTPS frontend (requires target HTTPS proxy check)
                # This is a simplified check
                uses_https = "https" in url_map.name.lower()

                raw_config: dict[str, Any] = {
                    "name": url_map.name,
                    "description": url_map.description or "",
                    "default_service": url_map.default_service,
                    "host_rules_count": len(url_map.host_rules or []),
                    "path_matchers_count": len(url_map.path_matchers or []),
                    "tests_count": len(url_map.tests or []),
                    "uses_https_frontend": uses_https,
                }

                assets.append(
                    Asset(
                        id=url_map_id,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region="global",
                        resource_type="gcp_compute_url_map",
                        name=url_map.name,
                        network_exposure=NETWORK_EXPOSURE_INTERNET,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing URL maps: {e}")

        return assets

    def _collect_ssl_policies(self) -> list[Asset]:
        """Collect SSL policies."""
        client = self._get_ssl_policies_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = compute_v1.ListSslPoliciesRequest(project=self._project_id)
            response = client.list(request=request)

            for policy in response:
                policy_id = f"projects/{self._project_id}/global/sslPolicies/{policy.name}"

                # Check if using modern profile
                profile = policy.profile or "COMPATIBLE"
                uses_modern_profile = profile in ["MODERN", "RESTRICTED"]

                # Check minimum TLS version
                min_tls = policy.min_tls_version or "TLS_1_0"
                uses_tls_1_2 = min_tls in ["TLS_1_2", "TLS_1_3"]

                raw_config: dict[str, Any] = {
                    "name": policy.name,
                    "description": policy.description or "",
                    "profile": profile,
                    "min_tls_version": min_tls,
                    "uses_modern_profile": uses_modern_profile,
                    "uses_tls_1_2_or_higher": uses_tls_1_2,
                    "custom_features": list(policy.custom_features or []),
                    "enabled_features": list(policy.enabled_features or []),
                    "warnings": [str(w) for w in (policy.warnings or [])],
                }

                assets.append(
                    Asset(
                        id=policy_id,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region="global",
                        resource_type="gcp_compute_ssl_policy",
                        name=policy.name,
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing SSL policies: {e}")

        return assets

    def _collect_cloud_nat(self) -> list[Asset]:
        """Collect Cloud NAT configurations."""
        client = self._get_routers_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = compute_v1.AggregatedListRoutersRequest(project=self._project_id)
            response = client.aggregated_list(request=request)

            for region, scoped_list in response:
                if not scoped_list.routers:
                    continue

                for router in scoped_list.routers:
                    if not router.nats:
                        continue

                    for nat in router.nats:
                        nat_id = f"projects/{self._project_id}/regions/{region}/routers/{router.name}/nats/{nat.name}"

                        # Check logging configuration
                        logging_enabled = False
                        log_filter = None
                        if nat.log_config:
                            logging_enabled = nat.log_config.enable
                            log_filter = nat.log_config.filter_

                        raw_config: dict[str, Any] = {
                            "name": nat.name,
                            "router_name": router.name,
                            "region": region.replace("regions/", ""),
                            "nat_ip_allocate_option": nat.nat_ip_allocate_option,
                            "source_subnetwork_ip_ranges_to_nat": nat.source_subnetwork_ip_ranges_to_nat,
                            "min_ports_per_vm": nat.min_ports_per_vm,
                            "udp_idle_timeout_sec": nat.udp_idle_timeout_sec,
                            "icmp_idle_timeout_sec": nat.icmp_idle_timeout_sec,
                            "tcp_established_idle_timeout_sec": nat.tcp_established_idle_timeout_sec,
                            "tcp_transitory_idle_timeout_sec": nat.tcp_transitory_idle_timeout_sec,
                            "logging_enabled": logging_enabled,
                            "log_filter": log_filter,
                        }

                        assets.append(
                            Asset(
                                id=nat_id,
                                cloud_provider="gcp",
                                account_id=self._project_id,
                                region=region.replace("regions/", ""),
                                resource_type="gcp_compute_router_nat",
                                name=nat.name,
                                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                                last_seen=now,
                                raw_config=raw_config,
                            )
                        )

        except Exception as e:
            logger.error(f"Error listing Cloud NAT: {e}")

        return assets

    def _collect_dns_zones(self) -> list[Asset]:
        """Collect Cloud DNS managed zones."""
        client = self._get_dns_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = dns_v1.ListManagedZonesRequest(project=self._project_id)
            zones = client.list(request=request)

            for zone in zones:
                zone_id = f"projects/{self._project_id}/managedZones/{zone.name}"

                # Check DNSSEC status
                dnssec_enabled = False
                dnssec_state = None
                if zone.dnssec_config:
                    dnssec_state = zone.dnssec_config.state
                    dnssec_enabled = dnssec_state == "on"

                raw_config: dict[str, Any] = {
                    "name": zone.name,
                    "dns_name": zone.dns_name,
                    "description": zone.description or "",
                    "visibility": zone.visibility,
                    "dnssec_enabled": dnssec_enabled,
                    "dnssec_state": dnssec_state,
                    "name_servers": list(zone.name_servers or []),
                }

                assets.append(
                    Asset(
                        id=zone_id,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region="global",
                        resource_type="gcp_dns_managed_zone",
                        name=zone.name,
                        network_exposure=NETWORK_EXPOSURE_INTERNET,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing DNS zones: {e}")

        return assets

    def _collect_vpn_tunnels(self) -> list[Asset]:
        """Collect Cloud VPN tunnels."""
        client = self._get_vpn_tunnels_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = compute_v1.AggregatedListVpnTunnelsRequest(project=self._project_id)
            response = client.aggregated_list(request=request)

            for region, scoped_list in response:
                if not scoped_list.vpn_tunnels:
                    continue

                for tunnel in scoped_list.vpn_tunnels:
                    tunnel_id = tunnel.self_link or f"projects/{self._project_id}/regions/{region}/vpnTunnels/{tunnel.name}"

                    # Check IKE version
                    ike_version = tunnel.ike_version or 1
                    uses_ikev2 = ike_version >= 2

                    raw_config: dict[str, Any] = {
                        "name": tunnel.name,
                        "description": tunnel.description or "",
                        "region": region.replace("regions/", ""),
                        "status": tunnel.status,
                        "peer_ip": tunnel.peer_ip,
                        "ike_version": ike_version,
                        "uses_ikev2": uses_ikev2,
                        "vpn_gateway": tunnel.vpn_gateway,
                        "peer_external_gateway": tunnel.peer_external_gateway,
                        "router": tunnel.router,
                        "local_traffic_selector": list(tunnel.local_traffic_selector or []),
                        "remote_traffic_selector": list(tunnel.remote_traffic_selector or []),
                    }

                    assets.append(
                        Asset(
                            id=tunnel_id,
                            cloud_provider="gcp",
                            account_id=self._project_id,
                            region=region.replace("regions/", ""),
                            resource_type="gcp_compute_vpn_tunnel",
                            name=tunnel.name,
                            network_exposure=NETWORK_EXPOSURE_INTERNET,
                            last_seen=now,
                            raw_config=raw_config,
                        )
                    )

        except Exception as e:
            logger.error(f"Error listing VPN tunnels: {e}")

        return assets

    def _collect_interconnects(self) -> list[Asset]:
        """Collect Cloud Interconnects."""
        client = self._get_interconnects_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = compute_v1.ListInterconnectsRequest(project=self._project_id)
            response = client.list(request=request)

            for interconnect in response:
                interconnect_id = interconnect.self_link or f"projects/{self._project_id}/global/interconnects/{interconnect.name}"

                # Check for MACsec
                uses_macsec = False
                if hasattr(interconnect, 'macsec_enabled'):
                    uses_macsec = interconnect.macsec_enabled

                raw_config: dict[str, Any] = {
                    "name": interconnect.name,
                    "description": interconnect.description or "",
                    "location": interconnect.location,
                    "interconnect_type": interconnect.interconnect_type,
                    "link_type": interconnect.link_type,
                    "requested_link_count": interconnect.requested_link_count,
                    "admin_enabled": interconnect.admin_enabled,
                    "operational_status": interconnect.operational_status,
                    "state": interconnect.state,
                    "uses_macsec": uses_macsec,
                    "google_ip_address": interconnect.google_ip_address,
                    "customer_name": interconnect.customer_name,
                }

                assets.append(
                    Asset(
                        id=interconnect_id,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region="global",
                        resource_type="gcp_compute_interconnect",
                        name=interconnect.name,
                        network_exposure=NETWORK_EXPOSURE_INTERNAL,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Interconnects: {e}")

        return assets

    def _collect_disks(self) -> list[Asset]:
        """Collect Compute Engine disks with encryption configuration."""
        client = self._get_disks_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = compute_v1.AggregatedListDisksRequest(project=self._project_id)
            response = client.aggregated_list(request=request)

            for zone, scoped_list in response:
                if not scoped_list.disks:
                    continue

                for disk in scoped_list.disks:
                    disk_id = disk.self_link or f"projects/{self._project_id}/zones/{zone}/disks/{disk.name}"

                    # Check encryption type
                    uses_cmek = False
                    encryption_key_type = "google-managed"
                    if disk.disk_encryption_key:
                        if disk.disk_encryption_key.kms_key_name:
                            uses_cmek = True
                            encryption_key_type = "customer-managed"
                        elif disk.disk_encryption_key.raw_key:
                            encryption_key_type = "customer-supplied"

                    raw_config: dict[str, Any] = {
                        "name": disk.name,
                        "description": disk.description or "",
                        "zone": zone.replace("zones/", ""),
                        "size_gb": disk.size_gb,
                        "type": disk.type_,
                        "status": disk.status,
                        "source_image": disk.source_image,
                        "source_snapshot": disk.source_snapshot,
                        "uses_cmek": uses_cmek,
                        "encryption_key_type": encryption_key_type,
                        "kms_key_name": (
                            disk.disk_encryption_key.kms_key_name
                            if disk.disk_encryption_key else None
                        ),
                    }

                    assets.append(
                        Asset(
                            id=disk_id,
                            cloud_provider="gcp",
                            account_id=self._project_id,
                            region=zone.replace("zones/", ""),
                            resource_type="gcp_compute_disk",
                            name=disk.name,
                            network_exposure=NETWORK_EXPOSURE_ISOLATED,
                            last_seen=now,
                            raw_config=raw_config,
                        )
                    )

        except Exception as e:
            logger.error(f"Error listing Compute disks: {e}")

        return assets
