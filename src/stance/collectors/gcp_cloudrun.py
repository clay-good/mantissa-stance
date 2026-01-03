"""
GCP Cloud Run collector for Mantissa Stance.

Collects Cloud Run services and revisions with their security configurations
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

# Optional GCP imports - Cloud Run uses the discovery-based API client
try:
    from googleapiclient import discovery
    from google.oauth2 import service_account
    import google.auth

    GCP_CLOUDRUN_AVAILABLE = True
except ImportError:
    GCP_CLOUDRUN_AVAILABLE = False


class GCPCloudRunCollector(BaseCollector):
    """
    Collects GCP Cloud Run resources and configuration.

    Gathers Cloud Run services and revisions with their security settings including:
    - Ingress settings (all traffic, internal only, internal and Cloud Load Balancing)
    - VPC access connector configuration
    - Service account and IAM bindings
    - Container configuration and environment variables (names only)
    - Binary authorization configuration
    - CPU and memory limits
    - Scaling configuration (min/max instances)
    - Traffic split across revisions

    All API calls are read-only.
    """

    collector_name = "gcp_cloudrun"
    resource_types = [
        "gcp_cloud_run_service",
        "gcp_cloud_run_revision",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        region: str | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP Cloud Run collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            region: Optional specific region to collect from (default: all regions).
            **kwargs: Additional configuration.
        """
        if not GCP_CLOUDRUN_AVAILABLE:
            raise ImportError(
                "google-api-python-client and google-auth are required for "
                "GCP Cloud Run collector. Install with: "
                "pip install google-api-python-client google-auth"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._region = region
        self._service: Any | None = None

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    def _get_service(self) -> Any:
        """Get or create the Cloud Run API service."""
        if self._service is None:
            if self._credentials:
                self._service = discovery.build(
                    "run",
                    "v2",
                    credentials=self._credentials,
                    cache_discovery=False,
                )
            else:
                credentials, _ = google.auth.default()
                self._service = discovery.build(
                    "run",
                    "v2",
                    credentials=credentials,
                    cache_discovery=False,
                )
        return self._service

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Cloud Run resources.

        Returns:
            Collection of Cloud Run assets (services and revisions)
        """
        assets: list[Asset] = []

        # Collect services
        try:
            assets.extend(self._collect_services())
        except Exception as e:
            logger.warning(f"Failed to collect Cloud Run services: {e}")

        return AssetCollection(assets)

    def _collect_services(self) -> list[Asset]:
        """Collect Cloud Run services."""
        service = self._get_service()
        assets: list[Asset] = []
        now = self._now()

        try:
            # List all services in the project
            if self._region:
                parent = f"projects/{self._project_id}/locations/{self._region}"
                request = service.projects().locations().services().list(parent=parent)

                while request is not None:
                    response = request.execute()
                    services = response.get("services", [])

                    for svc in services:
                        asset = self._parse_service(svc, now)
                        if asset:
                            assets.append(asset)

                    # Handle pagination
                    request = (
                        service.projects()
                        .locations()
                        .services()
                        .list_next(previous_request=request, previous_response=response)
                    )
            else:
                # List across all regions using wildcard
                parent = f"projects/{self._project_id}/locations/-"
                request = service.projects().locations().services().list(parent=parent)

                while request is not None:
                    response = request.execute()
                    services = response.get("services", [])

                    for svc in services:
                        asset = self._parse_service(svc, now)
                        if asset:
                            assets.append(asset)

                    # Handle pagination
                    request = (
                        service.projects()
                        .locations()
                        .services()
                        .list_next(previous_request=request, previous_response=response)
                    )

        except Exception as e:
            logger.error(f"Error listing Cloud Run services: {e}")
            raise

        return assets

    def _parse_service(self, svc: dict, now: datetime) -> Asset | None:
        """Parse a Cloud Run service into an Asset."""
        try:
            name = svc.get("name", "")
            # Extract service name from full path
            # Format: projects/{project}/locations/{location}/services/{serviceName}
            parts = name.split("/")
            service_name = parts[-1] if parts else name
            region = parts[3] if len(parts) > 3 else ""

            # Build resource ID
            resource_id = name

            # Ingress settings
            ingress = svc.get("ingress", "INGRESS_TRAFFIC_ALL")
            allows_all_traffic = ingress == "INGRESS_TRAFFIC_ALL"
            allows_internal_only = ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY"
            allows_internal_and_gclb = ingress == "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

            # Launch stage
            launch_stage = svc.get("launchStage", "GA")

            # Binary authorization
            binary_authorization = svc.get("binaryAuthorization", {})
            binary_auth_enabled = binary_authorization.get("useDefault", False) or bool(
                binary_authorization.get("policy", "")
            )
            binary_auth_policy = binary_authorization.get("policy", "")
            breakglass_justification = binary_authorization.get(
                "breakglassJustification", ""
            )

            # Template configuration
            template = svc.get("template", {})

            # Service account
            service_account_email = template.get("serviceAccount", "")
            uses_default_sa = (
                "@appspot.gserviceaccount.com" in service_account_email
                or "-compute@developer.gserviceaccount.com" in service_account_email
                or service_account_email == ""
            )

            # VPC access
            vpc_access = template.get("vpcAccess", {})
            vpc_connector = vpc_access.get("connector", "")
            has_vpc_connector = bool(vpc_connector)
            vpc_egress = vpc_access.get("egress", "PRIVATE_RANGES_ONLY")
            network_interfaces = vpc_access.get("networkInterfaces", [])
            has_direct_vpc = bool(network_interfaces)

            # Scaling
            scaling = template.get("scaling", {})
            min_instance_count = scaling.get("minInstanceCount", 0)
            max_instance_count = scaling.get("maxInstanceCount", 100)

            # Execution environment
            execution_environment = template.get(
                "executionEnvironment", "EXECUTION_ENVIRONMENT_GEN2"
            )

            # Encryption key (CMEK)
            encryption_key = template.get("encryptionKey", "")
            has_cmek = bool(encryption_key)

            # Timeout
            timeout = template.get("timeout", "300s")

            # Session affinity
            session_affinity = template.get("sessionAffinity", False)

            # Containers
            containers = template.get("containers", [])
            container_info = []
            all_env_var_names: list[str] = []
            has_secrets = False

            for container in containers:
                image = container.get("image", "")
                ports = container.get("ports", [])
                resources = container.get("resources", {})
                env_vars = container.get("env", [])
                volume_mounts = container.get("volumeMounts", [])

                # Extract environment variable names (not values for security)
                env_names = []
                for env in env_vars:
                    env_name = env.get("name", "")
                    if env_name:
                        env_names.append(env_name)
                    # Check if using secrets
                    if env.get("valueSource", {}).get("secretKeyRef"):
                        has_secrets = True

                all_env_var_names.extend(env_names)

                container_info.append(
                    {
                        "image": image,
                        "ports": [
                            {
                                "name": p.get("name", ""),
                                "container_port": p.get("containerPort", 8080),
                            }
                            for p in ports
                        ],
                        "resources": {
                            "limits": resources.get("limits", {}),
                            "cpu_idle": resources.get("cpuIdle", False),
                            "startup_cpu_boost": resources.get("startupCpuBoost", False),
                        },
                        "environment_variable_names": env_names,
                        "volume_mount_count": len(volume_mounts),
                    }
                )

            # Volumes (check for secrets)
            volumes = template.get("volumes", [])
            secret_volumes = []
            for vol in volumes:
                if vol.get("secret"):
                    has_secrets = True
                    secret_volumes.append(
                        {
                            "name": vol.get("name", ""),
                            "secret": vol.get("secret", {}).get("secret", ""),
                        }
                    )

            # Labels
            labels = svc.get("labels", {})

            # Annotations
            annotations = svc.get("annotations", {})

            # Traffic
            traffic = svc.get("traffic", [])
            traffic_info = [
                {
                    "type": t.get("type", ""),
                    "revision": t.get("revision", ""),
                    "percent": t.get("percent", 0),
                    "tag": t.get("tag", ""),
                }
                for t in traffic
            ]

            # Traffic status
            traffic_statuses = svc.get("trafficStatuses", [])

            # URI
            uri = svc.get("uri", "")
            has_public_uri = bool(uri)

            # URLs
            urls = svc.get("urls", [])

            # Conditions
            conditions = svc.get("conditions", [])
            ready_condition = next(
                (c for c in conditions if c.get("type") == "Ready"), {}
            )
            is_ready = ready_condition.get("state") == "CONDITION_SUCCEEDED"

            # Latest revision
            latest_ready_revision = svc.get("latestReadyRevision", "")
            latest_created_revision = svc.get("latestCreatedRevision", "")

            # Timestamps
            create_time = svc.get("createTime", "")
            update_time = svc.get("updateTime", "")

            raw_config = {
                "name": service_name,
                "full_name": name,
                "description": svc.get("description", ""),
                "region": region,
                "uri": uri,
                "has_public_uri": has_public_uri,
                "urls": urls,
                # Ingress settings
                "ingress": ingress,
                "allows_all_traffic": allows_all_traffic,
                "allows_internal_only": allows_internal_only,
                "allows_internal_and_gclb": allows_internal_and_gclb,
                # Launch stage
                "launch_stage": launch_stage,
                # Binary authorization
                "binary_authorization_enabled": binary_auth_enabled,
                "binary_authorization_policy": binary_auth_policy,
                "breakglass_justification": breakglass_justification,
                # Service account
                "service_account": service_account_email,
                "uses_default_service_account": uses_default_sa,
                # VPC configuration
                "vpc_connector": vpc_connector,
                "has_vpc_connector": has_vpc_connector,
                "vpc_egress": vpc_egress,
                "has_direct_vpc": has_direct_vpc,
                "network_interfaces": network_interfaces,
                # Scaling
                "min_instance_count": min_instance_count,
                "max_instance_count": max_instance_count,
                # Execution environment
                "execution_environment": execution_environment,
                # Encryption
                "encryption_key": encryption_key,
                "has_cmek": has_cmek,
                # Timeout and session
                "timeout": timeout,
                "session_affinity": session_affinity,
                # Containers
                "containers": container_info,
                "container_count": len(containers),
                "environment_variable_names": all_env_var_names,
                "has_environment_variables": bool(all_env_var_names),
                # Secrets
                "has_secrets": has_secrets,
                "secret_volumes": secret_volumes,
                # Traffic
                "traffic": traffic_info,
                "traffic_statuses": traffic_statuses,
                # Status
                "is_ready": is_ready,
                "latest_ready_revision": latest_ready_revision,
                "latest_created_revision": latest_created_revision,
                # Metadata
                "labels": labels,
                "annotations": annotations,
                # Timestamps
                "create_time": create_time,
                "update_time": update_time,
            }

            # Determine network exposure
            network_exposure = self._determine_network_exposure(
                ingress, has_vpc_connector, has_direct_vpc
            )

            # Parse create timestamp
            created_at = None
            if create_time:
                try:
                    created_at = datetime.fromisoformat(
                        create_time.replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    pass

            return Asset(
                id=resource_id,
                cloud_provider="gcp",
                account_id=self._project_id,
                region=region,
                resource_type="gcp_cloud_run_service",
                name=service_name,
                tags=labels,
                network_exposure=network_exposure,
                created_at=created_at,
                last_seen=now,
                raw_config=raw_config,
            )

        except Exception as e:
            logger.warning(f"Failed to parse Cloud Run service: {e}")
            return None

    def _determine_network_exposure(
        self,
        ingress: str,
        has_vpc_connector: bool,
        has_direct_vpc: bool,
    ) -> str:
        """
        Determine network exposure for a Cloud Run service.

        Args:
            ingress: Ingress setting (INGRESS_TRAFFIC_ALL, INGRESS_TRAFFIC_INTERNAL_ONLY,
                    INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER)
            has_vpc_connector: Whether service has a VPC connector
            has_direct_vpc: Whether service has direct VPC egress

        Returns:
            Network exposure classification
        """
        if ingress == "INGRESS_TRAFFIC_ALL":
            return NETWORK_EXPOSURE_INTERNET
        elif ingress == "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER":
            # Can be exposed via Cloud Load Balancer
            return NETWORK_EXPOSURE_INTERNET
        elif ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY":
            return NETWORK_EXPOSURE_INTERNAL

        # Fallback based on VPC configuration
        if has_vpc_connector or has_direct_vpc:
            return NETWORK_EXPOSURE_INTERNAL

        return NETWORK_EXPOSURE_ISOLATED
