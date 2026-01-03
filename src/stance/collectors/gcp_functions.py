"""
GCP Cloud Functions collector for Mantissa Stance.

Collects Cloud Functions (1st and 2nd gen) and their security configurations
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

# Optional GCP imports - Cloud Functions uses the discovery-based API client
try:
    from googleapiclient import discovery
    from google.oauth2 import service_account
    import google.auth

    GCP_FUNCTIONS_AVAILABLE = True
except ImportError:
    GCP_FUNCTIONS_AVAILABLE = False


# Deprecated runtimes that may have security implications
DEPRECATED_RUNTIMES = {
    "python37",
    "python38",
    "nodejs10",
    "nodejs12",
    "nodejs14",
    "go111",
    "go113",
    "dotnetcore3",
    "ruby26",
    "ruby27",
}

# Runtimes approaching end of support
EOL_APPROACHING_RUNTIMES = {
    "nodejs16",
    "python39",
    "go116",
    "java11",
    "ruby30",
}


class GCPCloudFunctionsCollector(BaseCollector):
    """
    Collects GCP Cloud Functions resources and configuration.

    Gathers Cloud Functions with their security settings including:
    - Ingress settings (all traffic, internal only, internal and GCLB)
    - VPC connector configuration
    - Service account and IAM bindings
    - Environment variables (names only)
    - Runtime and deprecated runtime detection
    - HTTPS trigger configuration
    - Secret references

    Supports both Cloud Functions 1st gen and 2nd gen.
    All API calls are read-only.
    """

    collector_name = "gcp_functions"
    resource_types = [
        "gcp_cloud_function",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        region: str | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP Cloud Functions collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            region: Optional specific region to collect from (default: all regions).
            **kwargs: Additional configuration.
        """
        if not GCP_FUNCTIONS_AVAILABLE:
            raise ImportError(
                "google-api-python-client and google-auth are required for "
                "GCP Cloud Functions collector. Install with: "
                "pip install google-api-python-client google-auth"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._region = region
        self._service_v1: Any | None = None
        self._service_v2: Any | None = None

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    def _get_service_v1(self) -> Any:
        """Get or create the Cloud Functions v1 API service (1st gen)."""
        if self._service_v1 is None:
            if self._credentials:
                self._service_v1 = discovery.build(
                    "cloudfunctions",
                    "v1",
                    credentials=self._credentials,
                    cache_discovery=False,
                )
            else:
                credentials, _ = google.auth.default()
                self._service_v1 = discovery.build(
                    "cloudfunctions",
                    "v1",
                    credentials=credentials,
                    cache_discovery=False,
                )
        return self._service_v1

    def _get_service_v2(self) -> Any:
        """Get or create the Cloud Functions v2 API service (2nd gen)."""
        if self._service_v2 is None:
            if self._credentials:
                self._service_v2 = discovery.build(
                    "cloudfunctions",
                    "v2",
                    credentials=self._credentials,
                    cache_discovery=False,
                )
            else:
                credentials, _ = google.auth.default()
                self._service_v2 = discovery.build(
                    "cloudfunctions",
                    "v2",
                    credentials=credentials,
                    cache_discovery=False,
                )
        return self._service_v2

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Cloud Functions resources.

        Returns:
            Collection of Cloud Functions assets
        """
        assets: list[Asset] = []

        # Collect 1st gen functions
        try:
            assets.extend(self._collect_functions_v1())
        except Exception as e:
            logger.warning(f"Failed to collect Cloud Functions v1: {e}")

        # Collect 2nd gen functions
        try:
            assets.extend(self._collect_functions_v2())
        except Exception as e:
            logger.warning(f"Failed to collect Cloud Functions v2: {e}")

        return AssetCollection(assets)

    def _collect_functions_v1(self) -> list[Asset]:
        """Collect 1st gen Cloud Functions."""
        service = self._get_service_v1()
        assets: list[Asset] = []
        now = self._now()

        try:
            # List all functions in the project
            if self._region:
                parent = f"projects/{self._project_id}/locations/{self._region}"
            else:
                parent = f"projects/{self._project_id}/locations/-"

            request = service.projects().locations().functions().list(parent=parent)

            while request is not None:
                response = request.execute()
                functions = response.get("functions", [])

                for func in functions:
                    asset = self._parse_function_v1(func, now)
                    if asset:
                        assets.append(asset)

                # Handle pagination
                request = service.projects().locations().functions().list_next(
                    previous_request=request, previous_response=response
                )

        except Exception as e:
            logger.error(f"Error listing Cloud Functions v1: {e}")
            raise

        return assets

    def _collect_functions_v2(self) -> list[Asset]:
        """Collect 2nd gen Cloud Functions."""
        service = self._get_service_v2()
        assets: list[Asset] = []
        now = self._now()

        try:
            # List all functions in the project
            if self._region:
                parent = f"projects/{self._project_id}/locations/{self._region}"
            else:
                parent = f"projects/{self._project_id}/locations/-"

            request = service.projects().locations().functions().list(parent=parent)

            while request is not None:
                response = request.execute()
                functions = response.get("functions", [])

                for func in functions:
                    asset = self._parse_function_v2(func, now)
                    if asset:
                        assets.append(asset)

                # Handle pagination
                request = service.projects().locations().functions().list_next(
                    previous_request=request, previous_response=response
                )

        except Exception as e:
            logger.error(f"Error listing Cloud Functions v2: {e}")
            raise

        return assets

    def _parse_function_v1(self, func: dict, now: datetime) -> Asset | None:
        """Parse a 1st gen Cloud Function into an Asset."""
        try:
            name = func.get("name", "")
            # Extract function name from full path
            # Format: projects/{project}/locations/{location}/functions/{functionName}
            parts = name.split("/")
            function_name = parts[-1] if parts else name
            region = parts[3] if len(parts) > 3 else ""

            # Build resource ID
            resource_id = name

            # Extract runtime
            runtime = func.get("runtime", "")
            runtime_deprecated = runtime in DEPRECATED_RUNTIMES
            runtime_eol_approaching = runtime in EOL_APPROACHING_RUNTIMES

            # HTTP trigger configuration
            https_trigger = func.get("httpsTrigger", {})
            has_https_trigger = bool(https_trigger)
            trigger_url = https_trigger.get("url", "")
            security_level = https_trigger.get("securityLevel", "SECURE_OPTIONAL")

            # Event trigger configuration
            event_trigger = func.get("eventTrigger", {})
            has_event_trigger = bool(event_trigger)
            event_type = event_trigger.get("eventType", "")
            event_resource = event_trigger.get("resource", "")

            # Ingress settings
            ingress_settings = func.get("ingressSettings", "ALLOW_ALL")
            allows_all_traffic = ingress_settings == "ALLOW_ALL"
            allows_internal_only = ingress_settings == "ALLOW_INTERNAL_ONLY"
            allows_internal_and_gclb = ingress_settings == "ALLOW_INTERNAL_AND_GCLB"

            # VPC connector
            vpc_connector = func.get("vpcConnector", "")
            has_vpc_connector = bool(vpc_connector)
            vpc_connector_egress_settings = func.get(
                "vpcConnectorEgressSettings", "PRIVATE_RANGES_ONLY"
            )

            # Service account
            service_account_email = func.get("serviceAccountEmail", "")
            uses_default_sa = (
                "@appspot.gserviceaccount.com" in service_account_email
                or "-compute@developer.gserviceaccount.com" in service_account_email
            )

            # Environment variables (names only for security)
            env_vars = func.get("environmentVariables", {})
            env_var_names = list(env_vars.keys())
            has_env_vars = bool(env_vars)

            # Build config environment variables
            build_env_vars = func.get("buildEnvironmentVariables", {})
            build_env_var_names = list(build_env_vars.keys())

            # Secret environment variables
            secret_env_vars = func.get("secretEnvironmentVariables", [])
            secret_refs = [
                {
                    "key": s.get("key", ""),
                    "secret": s.get("secret", ""),
                    "version": s.get("version", ""),
                }
                for s in secret_env_vars
            ]
            has_secrets = bool(secret_env_vars)

            # Secret volumes
            secret_volumes = func.get("secretVolumes", [])
            has_secret_volumes = bool(secret_volumes)

            # Labels
            labels = func.get("labels", {})

            # Status
            status = func.get("status", "")

            # Resource limits
            available_memory_mb = func.get("availableMemoryMb", 256)
            timeout = func.get("timeout", "60s")
            max_instances = func.get("maxInstances", 0)
            min_instances = func.get("minInstances", 0)

            # Source
            source_archive_url = func.get("sourceArchiveUrl", "")
            source_repository = func.get("sourceRepository", {})
            source_upload_url = func.get("sourceUploadUrl", "")

            raw_config = {
                "name": function_name,
                "full_name": name,
                "description": func.get("description", ""),
                "status": status,
                "region": region,
                "generation": "1st",
                # Runtime
                "runtime": runtime,
                "runtime_deprecated": runtime_deprecated,
                "runtime_eol_approaching": runtime_eol_approaching,
                "entry_point": func.get("entryPoint", ""),
                # Trigger configuration
                "has_https_trigger": has_https_trigger,
                "trigger_url": trigger_url,
                "security_level": security_level,
                "has_event_trigger": has_event_trigger,
                "event_type": event_type,
                "event_resource": event_resource,
                # Ingress settings
                "ingress_settings": ingress_settings,
                "allows_all_traffic": allows_all_traffic,
                "allows_internal_only": allows_internal_only,
                "allows_internal_and_gclb": allows_internal_and_gclb,
                # VPC configuration
                "vpc_connector": vpc_connector,
                "has_vpc_connector": has_vpc_connector,
                "vpc_connector_egress_settings": vpc_connector_egress_settings,
                # Service account
                "service_account_email": service_account_email,
                "uses_default_service_account": uses_default_sa,
                # Environment variables
                "environment_variable_names": env_var_names,
                "has_environment_variables": has_env_vars,
                "build_environment_variable_names": build_env_var_names,
                # Secrets
                "secret_references": secret_refs,
                "has_secrets": has_secrets,
                "has_secret_volumes": has_secret_volumes,
                # Resource limits
                "available_memory_mb": available_memory_mb,
                "timeout": timeout,
                "max_instances": max_instances,
                "min_instances": min_instances,
                # Source
                "source_archive_url": source_archive_url,
                "has_source_repository": bool(source_repository),
                # Labels
                "labels": labels,
                # Timestamps
                "update_time": func.get("updateTime", ""),
                "version_id": func.get("versionId", ""),
                "build_id": func.get("buildId", ""),
            }

            # Determine network exposure
            network_exposure = self._determine_network_exposure_v1(
                has_https_trigger, ingress_settings, has_vpc_connector
            )

            # Parse update timestamp as created_at
            created_at = None
            update_time = func.get("updateTime", "")
            if update_time:
                try:
                    created_at = datetime.fromisoformat(
                        update_time.replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    pass

            return Asset(
                id=resource_id,
                cloud_provider="gcp",
                account_id=self._project_id,
                region=region,
                resource_type="gcp_cloud_function",
                name=function_name,
                tags=labels,
                network_exposure=network_exposure,
                created_at=created_at,
                last_seen=now,
                raw_config=raw_config,
            )

        except Exception as e:
            logger.warning(f"Failed to parse Cloud Function v1: {e}")
            return None

    def _parse_function_v2(self, func: dict, now: datetime) -> Asset | None:
        """Parse a 2nd gen Cloud Function into an Asset."""
        try:
            name = func.get("name", "")
            # Extract function name from full path
            parts = name.split("/")
            function_name = parts[-1] if parts else name
            region = parts[3] if len(parts) > 3 else ""

            # Build resource ID
            resource_id = name

            # Build config (contains runtime, entry point, source)
            build_config = func.get("buildConfig", {})
            runtime = build_config.get("runtime", "")
            runtime_deprecated = runtime in DEPRECATED_RUNTIMES
            runtime_eol_approaching = runtime in EOL_APPROACHING_RUNTIMES
            entry_point = build_config.get("entryPoint", "")

            # Service config (contains resources, VPC, service account)
            service_config = func.get("serviceConfig", {})

            # Service account
            service_account_email = service_config.get("serviceAccountEmail", "")
            uses_default_sa = (
                "@appspot.gserviceaccount.com" in service_account_email
                or "-compute@developer.gserviceaccount.com" in service_account_email
            )

            # Ingress settings
            ingress_settings = service_config.get("ingressSettings", "ALLOW_ALL")
            allows_all_traffic = ingress_settings == "ALLOW_ALL"
            allows_internal_only = ingress_settings == "ALLOW_INTERNAL_ONLY"
            allows_internal_and_gclb = ingress_settings == "ALLOW_INTERNAL_AND_GCLB"

            # VPC connector
            vpc_connector = service_config.get("vpcConnector", "")
            has_vpc_connector = bool(vpc_connector)
            vpc_connector_egress_settings = service_config.get(
                "vpcConnectorEgressSettings", "PRIVATE_RANGES_ONLY"
            )

            # Environment variables
            env_vars = service_config.get("environmentVariables", {})
            env_var_names = list(env_vars.keys())
            has_env_vars = bool(env_vars)

            # Secret environment variables
            secret_env_vars = service_config.get("secretEnvironmentVariables", [])
            secret_refs = [
                {
                    "key": s.get("key", ""),
                    "secret": s.get("secret", ""),
                    "version": s.get("version", ""),
                }
                for s in secret_env_vars
            ]
            has_secrets = bool(secret_env_vars)

            # Secret volumes
            secret_volumes = service_config.get("secretVolumes", [])
            has_secret_volumes = bool(secret_volumes)

            # Resource limits
            available_memory = service_config.get("availableMemory", "256M")
            timeout_seconds = service_config.get("timeoutSeconds", 60)
            max_instance_count = service_config.get("maxInstanceCount", 0)
            min_instance_count = service_config.get("minInstanceCount", 0)
            available_cpu = service_config.get("availableCpu", "")

            # Event trigger (2nd gen)
            event_trigger = func.get("eventTrigger", {})
            has_event_trigger = bool(event_trigger)
            event_type = event_trigger.get("eventType", "")
            trigger_region = event_trigger.get("triggerRegion", "")
            pubsub_topic = event_trigger.get("pubsubTopic", "")

            # URI (for HTTP triggers)
            uri = service_config.get("uri", "")
            has_https_trigger = bool(uri)

            # Labels
            labels = func.get("labels", {})

            # State
            state = func.get("state", "")

            # Environment (GEN_1 or GEN_2)
            environment = func.get("environment", "GEN_2")

            raw_config = {
                "name": function_name,
                "full_name": name,
                "description": func.get("description", ""),
                "state": state,
                "region": region,
                "generation": "2nd",
                "environment": environment,
                # Runtime
                "runtime": runtime,
                "runtime_deprecated": runtime_deprecated,
                "runtime_eol_approaching": runtime_eol_approaching,
                "entry_point": entry_point,
                # Trigger configuration
                "has_https_trigger": has_https_trigger,
                "uri": uri,
                "has_event_trigger": has_event_trigger,
                "event_type": event_type,
                "trigger_region": trigger_region,
                "pubsub_topic": pubsub_topic,
                # Ingress settings
                "ingress_settings": ingress_settings,
                "allows_all_traffic": allows_all_traffic,
                "allows_internal_only": allows_internal_only,
                "allows_internal_and_gclb": allows_internal_and_gclb,
                # VPC configuration
                "vpc_connector": vpc_connector,
                "has_vpc_connector": has_vpc_connector,
                "vpc_connector_egress_settings": vpc_connector_egress_settings,
                # Service account
                "service_account_email": service_account_email,
                "uses_default_service_account": uses_default_sa,
                # Environment variables
                "environment_variable_names": env_var_names,
                "has_environment_variables": has_env_vars,
                # Secrets
                "secret_references": secret_refs,
                "has_secrets": has_secrets,
                "has_secret_volumes": has_secret_volumes,
                # Resource limits
                "available_memory": available_memory,
                "available_cpu": available_cpu,
                "timeout_seconds": timeout_seconds,
                "max_instance_count": max_instance_count,
                "min_instance_count": min_instance_count,
                # Build config
                "docker_repository": build_config.get("dockerRepository", ""),
                "source": build_config.get("source", {}),
                # Labels
                "labels": labels,
                # Timestamps
                "update_time": func.get("updateTime", ""),
                "create_time": func.get("createTime", ""),
            }

            # Determine network exposure
            network_exposure = self._determine_network_exposure_v2(
                has_https_trigger, ingress_settings, has_vpc_connector
            )

            # Parse create timestamp
            created_at = None
            create_time = func.get("createTime", "")
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
                resource_type="gcp_cloud_function",
                name=function_name,
                tags=labels,
                network_exposure=network_exposure,
                created_at=created_at,
                last_seen=now,
                raw_config=raw_config,
            )

        except Exception as e:
            logger.warning(f"Failed to parse Cloud Function v2: {e}")
            return None

    def _determine_network_exposure_v1(
        self,
        has_https_trigger: bool,
        ingress_settings: str,
        has_vpc_connector: bool,
    ) -> str:
        """Determine network exposure for a 1st gen function."""
        if has_https_trigger:
            if ingress_settings == "ALLOW_ALL":
                return NETWORK_EXPOSURE_INTERNET
            elif ingress_settings == "ALLOW_INTERNAL_AND_GCLB":
                # Can be exposed via load balancer
                return NETWORK_EXPOSURE_INTERNET
            elif ingress_settings == "ALLOW_INTERNAL_ONLY":
                return NETWORK_EXPOSURE_INTERNAL

        # Event-triggered functions with VPC connector
        if has_vpc_connector:
            return NETWORK_EXPOSURE_INTERNAL

        # Event-triggered functions without VPC connector
        return NETWORK_EXPOSURE_ISOLATED

    def _determine_network_exposure_v2(
        self,
        has_https_trigger: bool,
        ingress_settings: str,
        has_vpc_connector: bool,
    ) -> str:
        """Determine network exposure for a 2nd gen function."""
        # Same logic as v1 for now
        return self._determine_network_exposure_v1(
            has_https_trigger, ingress_settings, has_vpc_connector
        )
