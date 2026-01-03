"""
GCP Cloud SQL collector for Mantissa Stance.

Collects Cloud SQL instances, databases, and their security configurations
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

# Optional GCP imports - Cloud SQL uses the discovery-based API client
try:
    from googleapiclient import discovery
    from google.oauth2 import service_account
    import google.auth

    GCP_SQL_AVAILABLE = True
except ImportError:
    GCP_SQL_AVAILABLE = False


class GCPCloudSQLCollector(BaseCollector):
    """
    Collects GCP Cloud SQL resources and configuration.

    Gathers Cloud SQL instances with their security settings including:
    - Encryption configuration (CMEK vs Google-managed)
    - Public IP and authorized networks
    - SSL/TLS requirements
    - Backup configuration
    - Database flags for security settings

    All API calls are read-only.
    """

    collector_name = "gcp_sql"
    resource_types = [
        "gcp_sql_instance",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP Cloud SQL collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            **kwargs: Additional configuration.
        """
        if not GCP_SQL_AVAILABLE:
            raise ImportError(
                "google-api-python-client and google-auth are required for "
                "GCP Cloud SQL collector. Install with: "
                "pip install google-api-python-client google-auth"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._service: Any | None = None

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    def _get_service(self) -> Any:
        """Get or create the Cloud SQL Admin API service."""
        if self._service is None:
            if self._credentials:
                self._service = discovery.build(
                    "sqladmin",
                    "v1",
                    credentials=self._credentials,
                    cache_discovery=False,
                )
            else:
                # Use Application Default Credentials
                credentials, _ = google.auth.default()
                self._service = discovery.build(
                    "sqladmin",
                    "v1",
                    credentials=credentials,
                    cache_discovery=False,
                )
        return self._service

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Cloud SQL resources.

        Returns:
            Collection of Cloud SQL assets
        """
        assets: list[Asset] = []

        # Collect SQL instances
        try:
            assets.extend(self._collect_instances())
        except Exception as e:
            logger.warning(f"Failed to collect Cloud SQL instances: {e}")

        return AssetCollection(assets)

    def _collect_instances(self) -> list[Asset]:
        """Collect Cloud SQL instances."""
        service = self._get_service()
        assets: list[Asset] = []
        now = self._now()

        try:
            # List all Cloud SQL instances in the project
            request = service.instances().list(project=self._project_id)
            response = request.execute()

            instances = response.get("items", [])

            for instance in instances:
                instance_name = instance.get("name", "")
                self_link = instance.get("selfLink", "")

                # Build resource ID
                resource_id = (
                    f"projects/{self._project_id}/instances/{instance_name}"
                )

                # Extract settings
                settings = instance.get("settings", {})
                ip_configuration = settings.get("ipConfiguration", {})
                backup_configuration = settings.get("backupConfiguration", {})
                database_flags = settings.get("databaseFlags", [])

                # Check for public IP
                ip_addresses = instance.get("ipAddresses", [])
                has_public_ip = False
                public_ip = None
                private_ip = None

                for ip_addr in ip_addresses:
                    ip_type = ip_addr.get("type", "")
                    ip_value = ip_addr.get("ipAddress", "")
                    if ip_type == "PRIMARY":
                        has_public_ip = True
                        public_ip = ip_value
                    elif ip_type == "PRIVATE":
                        private_ip = ip_value

                # Check authorized networks (who can connect)
                authorized_networks = ip_configuration.get("authorizedNetworks", [])
                allows_any_ip = False
                authorized_network_cidrs = []

                for network in authorized_networks:
                    cidr = network.get("value", "")
                    authorized_network_cidrs.append(cidr)
                    if cidr == "0.0.0.0/0":
                        allows_any_ip = True

                # SSL configuration
                require_ssl = ip_configuration.get("requireSsl", False)
                ssl_mode = ip_configuration.get("sslMode", "")

                # Private network configuration
                private_network = ip_configuration.get("privateNetwork", "")
                has_private_network = bool(private_network)
                ipv4_enabled = ip_configuration.get("ipv4Enabled", True)

                # Encryption configuration
                disk_encryption_configuration = instance.get(
                    "diskEncryptionConfiguration", {}
                )
                disk_encryption_key_name = disk_encryption_configuration.get(
                    "kmsKeyName", ""
                )
                uses_cmek = bool(disk_encryption_key_name)

                # Backup configuration
                backup_enabled = backup_configuration.get("enabled", False)
                binary_log_enabled = backup_configuration.get(
                    "binaryLogEnabled", False
                )
                point_in_time_recovery = backup_configuration.get(
                    "pointInTimeRecoveryEnabled", False
                )
                backup_retention_days = backup_configuration.get(
                    "transactionLogRetentionDays", 7
                )

                # Parse database flags into dict for easier access
                db_flags_dict = {}
                for flag in database_flags:
                    flag_name = flag.get("name", "")
                    flag_value = flag.get("value", "")
                    db_flags_dict[flag_name] = flag_value

                # Security-relevant database flags
                log_connections = db_flags_dict.get("log_connections", "off")
                log_disconnections = db_flags_dict.get("log_disconnections", "off")
                log_lock_waits = db_flags_dict.get("log_lock_waits", "off")
                log_temp_files = db_flags_dict.get("log_temp_files", "-1")

                # Extract instance metadata
                region = instance.get("region", "")
                database_version = instance.get("databaseVersion", "")
                instance_type = instance.get("instanceType", "")
                state = instance.get("state", "")
                tier = settings.get("tier", "")

                # Maintenance window
                maintenance_window = settings.get("maintenanceWindow", {})

                # Availability type (ZONAL or REGIONAL)
                availability_type = settings.get("availabilityType", "ZONAL")

                # User labels (tags)
                labels = settings.get("userLabels", {})

                # Replica configuration
                replica_configuration = instance.get("replicaConfiguration", {})
                is_replica = bool(instance.get("masterInstanceName", ""))
                master_instance = instance.get("masterInstanceName", "")

                # Server CA cert
                server_ca_cert = instance.get("serverCaCert", {})
                ca_cert_expiration = server_ca_cert.get("expirationTime", "")

                raw_config = {
                    "name": instance_name,
                    "database_version": database_version,
                    "instance_type": instance_type,
                    "state": state,
                    "region": region,
                    "tier": tier,
                    "availability_type": availability_type,
                    # Network configuration
                    "has_public_ip": has_public_ip,
                    "public_ip": public_ip,
                    "private_ip": private_ip,
                    "ipv4_enabled": ipv4_enabled,
                    "has_private_network": has_private_network,
                    "private_network": private_network,
                    "authorized_networks": authorized_network_cidrs,
                    "allows_any_ip": allows_any_ip,
                    # SSL configuration
                    "require_ssl": require_ssl,
                    "ssl_mode": ssl_mode,
                    # Encryption
                    "uses_cmek": uses_cmek,
                    "disk_encryption_key_name": disk_encryption_key_name,
                    # Backup configuration
                    "backup_enabled": backup_enabled,
                    "binary_log_enabled": binary_log_enabled,
                    "point_in_time_recovery_enabled": point_in_time_recovery,
                    "backup_retention_days": backup_retention_days,
                    # Database flags
                    "database_flags": db_flags_dict,
                    "log_connections": log_connections,
                    "log_disconnections": log_disconnections,
                    "log_lock_waits": log_lock_waits,
                    "log_temp_files": log_temp_files,
                    # Maintenance
                    "maintenance_window": maintenance_window,
                    # Replication
                    "is_replica": is_replica,
                    "master_instance": master_instance,
                    # CA cert
                    "ca_cert_expiration": ca_cert_expiration,
                    # Labels
                    "labels": labels,
                    # Self link for reference
                    "self_link": self_link,
                }

                # Determine network exposure
                network_exposure = NETWORK_EXPOSURE_ISOLATED

                if has_public_ip:
                    if allows_any_ip:
                        network_exposure = NETWORK_EXPOSURE_INTERNET
                    elif len(authorized_network_cidrs) > 0:
                        network_exposure = NETWORK_EXPOSURE_INTERNET
                    else:
                        # Public IP but no authorized networks - unusual but possible
                        network_exposure = NETWORK_EXPOSURE_INTERNAL
                elif has_private_network:
                    network_exposure = NETWORK_EXPOSURE_INTERNAL

                # Parse creation timestamp
                created_at = None
                create_time = instance.get("createTime", "")
                if create_time:
                    try:
                        # GCP uses RFC 3339 format
                        created_at = datetime.fromisoformat(
                            create_time.replace("Z", "+00:00")
                        )
                    except (ValueError, AttributeError):
                        pass

                assets.append(
                    Asset(
                        id=resource_id,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region=region,
                        resource_type="gcp_sql_instance",
                        name=instance_name,
                        tags=labels,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Cloud SQL instances: {e}")
            raise

        return assets
