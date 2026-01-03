"""
Azure Functions collector for Mantissa Stance.

Collects Azure Function Apps and their security configurations
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
    from azure.mgmt.web import WebSiteManagementClient
    from azure.identity import DefaultAzureCredential

    AZURE_FUNCTIONS_AVAILABLE = True
except ImportError:
    AZURE_FUNCTIONS_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore


# Deprecated runtimes that may have security implications
DEPRECATED_RUNTIMES = {
    "~1",  # Functions v1 (end of life)
    "~2",  # Functions v2 (end of extended support)
    "python|3.6",
    "python|3.7",
    "node|8",
    "node|10",
    "node|12",
    "dotnet|2.1",
    "dotnet|3.1",
    "java|8",
    "powershell|6",
}

# Runtimes approaching end of support
EOL_APPROACHING_RUNTIMES = {
    "~3",  # Functions v3 (approaching end of support)
    "python|3.8",
    "node|14",
    "node|16",
    "dotnet|5.0",
    "java|11",
    "powershell|7.0",
}


class AzureFunctionsCollector(BaseCollector):
    """
    Collects Azure Function App resources and configuration.

    Gathers Function Apps with their security settings including:
    - Runtime and deprecated runtime detection
    - HTTPS-only configuration
    - Authentication/authorization settings
    - Network access restrictions (IP rules, VNet integration)
    - Managed identity configuration
    - App settings (names only, not values for security)
    - TLS/SSL configuration
    - CORS settings
    - Slots and deployment configuration

    All API calls are read-only.
    """

    collector_name = "azure_functions"
    resource_types = [
        "azure_function_app",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure Functions collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_FUNCTIONS_AVAILABLE:
            raise ImportError(
                "azure-mgmt-web is required for Azure Functions collector. "
                "Install with: pip install azure-mgmt-web azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._client: WebSiteManagementClient | None = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_web_client(self) -> WebSiteManagementClient:
        """Get or create Web Site Management client."""
        if self._client is None:
            self._client = WebSiteManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Azure Functions resources.

        Returns:
            Collection of Azure Functions assets
        """
        assets: list[Asset] = []

        # Collect Function Apps
        try:
            assets.extend(self._collect_function_apps())
        except Exception as e:
            logger.warning(f"Failed to collect Function Apps: {e}")

        return AssetCollection(assets)

    def _collect_function_apps(self) -> list[Asset]:
        """Collect Azure Function Apps with their configurations."""
        client = self._get_web_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            # List all web apps and filter for Function Apps
            for app in client.web_apps.list():
                # Filter for Function Apps only (kind contains "functionapp")
                kind = app.kind or ""
                if "functionapp" not in kind.lower():
                    continue

                app_id = app.id
                app_name = app.name
                resource_group = self._extract_resource_group(app_id)
                location = app.location

                # Extract tags
                tags = dict(app.tags) if app.tags else {}

                # Basic configuration
                raw_config: dict[str, Any] = {
                    "app_id": app_id,
                    "app_name": app_name,
                    "resource_group": resource_group,
                    "location": location,
                    "kind": kind,
                    "state": app.state,
                    "default_host_name": app.default_host_name,
                    "enabled": app.enabled,
                    "host_names": app.host_names or [],
                    "host_name_ssl_states": [
                        {
                            "name": ssl.name,
                            "ssl_state": ssl.ssl_state,
                            "thumbprint": ssl.thumbprint,
                            "host_type": ssl.host_type,
                        }
                        for ssl in (app.host_name_ssl_states or [])
                    ],
                    "repository_site_name": app.repository_site_name,
                    "usage_state": app.usage_state,
                    "availability_state": app.availability_state,
                    "last_modified_time_utc": (
                        app.last_modified_time_utc.isoformat()
                        if app.last_modified_time_utc
                        else None
                    ),
                }

                # HTTPS only
                https_only = app.https_only or False
                raw_config["https_only"] = https_only

                # Client certificate mode
                client_cert_enabled = app.client_cert_enabled or False
                client_cert_mode = app.client_cert_mode
                raw_config["client_cert_enabled"] = client_cert_enabled
                raw_config["client_cert_mode"] = client_cert_mode

                # Managed identity
                identity = app.identity
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
                    raw_config["has_managed_identity"] = True
                    raw_config["uses_system_assigned_identity"] = (
                        "SystemAssigned" in (identity.type or "")
                    )
                else:
                    raw_config["identity"] = None
                    raw_config["has_managed_identity"] = False
                    raw_config["uses_system_assigned_identity"] = False

                # Virtual network integration
                vnet_info = app.virtual_network_subnet_id
                raw_config["virtual_network_subnet_id"] = vnet_info
                raw_config["has_vnet_integration"] = bool(vnet_info)

                # Get site config for more details
                try:
                    site_config = client.web_apps.get_configuration(
                        resource_group, app_name
                    )
                    config_details = self._extract_site_config(site_config)
                    raw_config.update(config_details)
                except Exception as e:
                    logger.debug(f"Could not get config for {app_name}: {e}")

                # Get auth settings
                try:
                    auth_settings = self._collect_auth_settings(
                        resource_group, app_name
                    )
                    raw_config["auth_settings"] = auth_settings
                    raw_config["auth_enabled"] = auth_settings.get("enabled", False)
                except Exception as e:
                    logger.debug(f"Could not get auth settings for {app_name}: {e}")
                    raw_config["auth_settings"] = None
                    raw_config["auth_enabled"] = False

                # Get app settings (names only)
                try:
                    app_settings = self._collect_app_settings(
                        resource_group, app_name
                    )
                    raw_config["app_setting_names"] = app_settings
                    raw_config["has_app_settings"] = len(app_settings) > 0
                except Exception as e:
                    logger.debug(f"Could not get app settings for {app_name}: {e}")
                    raw_config["app_setting_names"] = []

                # Get connection strings (names only)
                try:
                    conn_strings = self._collect_connection_string_names(
                        resource_group, app_name
                    )
                    raw_config["connection_string_names"] = conn_strings
                    raw_config["has_connection_strings"] = len(conn_strings) > 0
                except Exception as e:
                    logger.debug(f"Could not get conn strings for {app_name}: {e}")
                    raw_config["connection_string_names"] = []

                # Get network access restrictions
                try:
                    ip_restrictions = self._collect_ip_restrictions(
                        resource_group, app_name
                    )
                    raw_config["ip_security_restrictions"] = ip_restrictions
                    raw_config["has_ip_restrictions"] = len(ip_restrictions) > 0
                except Exception as e:
                    logger.debug(f"Could not get IP restrictions for {app_name}: {e}")
                    raw_config["ip_security_restrictions"] = []
                    raw_config["has_ip_restrictions"] = False

                # Get functions in the app
                try:
                    functions = self._collect_functions(resource_group, app_name)
                    raw_config["functions"] = functions
                    raw_config["function_count"] = len(functions)
                except Exception as e:
                    logger.debug(f"Could not get functions for {app_name}: {e}")
                    raw_config["functions"] = []
                    raw_config["function_count"] = 0

                # Determine runtime version and deprecation status
                runtime_version = raw_config.get("functions_runtime_version", "")
                linux_fx_version = raw_config.get("linux_fx_version", "")
                runtime_deprecated = self._is_runtime_deprecated(
                    runtime_version, linux_fx_version
                )
                runtime_eol_approaching = self._is_runtime_eol_approaching(
                    runtime_version, linux_fx_version
                )
                raw_config["runtime_deprecated"] = runtime_deprecated
                raw_config["runtime_eol_approaching"] = runtime_eol_approaching

                # Determine network exposure
                network_exposure = self._determine_network_exposure(raw_config)

                # Security summary
                raw_config["is_secure"] = (
                    https_only and
                    raw_config.get("min_tls_version") == "1.2" and
                    raw_config.get("has_managed_identity", False) and
                    not runtime_deprecated
                )

                # Parse creation time if available
                created_at = None

                assets.append(
                    Asset(
                        id=app_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=location,
                        resource_type="azure_function_app",
                        name=app_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Function Apps: {e}")
            raise

        return assets

    def _extract_site_config(self, config: Any) -> dict[str, Any]:
        """Extract site configuration details."""
        result: dict[str, Any] = {}

        # Runtime information
        result["net_framework_version"] = config.net_framework_version
        result["php_version"] = config.php_version
        result["python_version"] = config.python_version
        result["node_version"] = config.node_version
        result["java_version"] = config.java_version
        result["java_container"] = config.java_container
        result["java_container_version"] = config.java_container_version
        result["power_shell_version"] = config.power_shell_version
        result["linux_fx_version"] = config.linux_fx_version
        result["windows_fx_version"] = config.windows_fx_version

        # HTTP/HTTPS settings
        result["http20_enabled"] = config.http20_enabled
        result["min_tls_version"] = config.min_tls_version
        result["ftps_state"] = config.ftps_state
        result["uses_tls_1_2"] = config.min_tls_version == "1.2"

        # Remote debugging
        result["remote_debugging_enabled"] = config.remote_debugging_enabled
        result["remote_debugging_version"] = config.remote_debugging_version

        # CORS
        cors = config.cors
        if cors:
            result["cors"] = {
                "allowed_origins": cors.allowed_origins or [],
                "support_credentials": cors.support_credentials,
            }
            result["cors_allows_all"] = "*" in (cors.allowed_origins or [])
        else:
            result["cors"] = None
            result["cors_allows_all"] = False

        # Always On
        result["always_on"] = config.always_on

        # Web sockets
        result["web_sockets_enabled"] = config.web_sockets_enabled

        # Managed pipeline mode
        result["managed_pipeline_mode"] = config.managed_pipeline_mode

        # Local MySQL
        result["local_my_sql_enabled"] = config.local_my_sql_enabled

        # API definition
        result["api_definition_url"] = (
            config.api_definition.url if config.api_definition else None
        )

        # API management
        result["api_management_config_id"] = (
            config.api_management_config.id if config.api_management_config else None
        )

        # Auto heal
        result["auto_heal_enabled"] = config.auto_heal_enabled

        # App command line
        result["app_command_line"] = config.app_command_line

        # SCM site
        result["scm_type"] = config.scm_type
        result["scm_min_tls_version"] = config.scm_min_tls_version

        # Use 32-bit worker process
        result["use_32_bit_worker_process"] = config.use_32_bit_worker_process

        # Functions runtime version (from app settings in config)
        result["functions_runtime_version"] = None
        if config.app_settings:
            for setting in config.app_settings:
                if setting.name == "FUNCTIONS_EXTENSION_VERSION":
                    result["functions_runtime_version"] = setting.value
                    break

        # VNet route all
        result["vnet_route_all_enabled"] = config.vnet_route_all_enabled

        # IP restrictions are handled separately

        return result

    def _collect_auth_settings(
        self, resource_group: str, app_name: str
    ) -> dict[str, Any]:
        """Collect authentication settings for a Function App."""
        client = self._get_web_client()

        # Try v2 auth settings first
        try:
            auth_v2 = client.web_apps.get_auth_settings_v2(resource_group, app_name)
            return {
                "version": "v2",
                "enabled": auth_v2.global_validation is not None,
                "platform": {
                    "enabled": (
                        auth_v2.platform.enabled if auth_v2.platform else False
                    ),
                    "runtime_version": (
                        auth_v2.platform.runtime_version if auth_v2.platform else None
                    ),
                } if auth_v2.platform else None,
                "identity_providers": self._extract_identity_providers(auth_v2),
                "require_authentication": (
                    auth_v2.global_validation.require_authentication
                    if auth_v2.global_validation
                    else False
                ),
                "unauthenticated_client_action": (
                    auth_v2.global_validation.unauthenticated_client_action
                    if auth_v2.global_validation
                    else None
                ),
            }
        except Exception:
            pass

        # Fallback to v1 auth settings
        try:
            auth_v1 = client.web_apps.get_auth_settings(resource_group, app_name)
            return {
                "version": "v1",
                "enabled": auth_v1.enabled or False,
                "unauthenticated_client_action": auth_v1.unauthenticated_client_action,
                "token_store_enabled": auth_v1.token_store_enabled,
                "allowed_external_redirect_urls": (
                    auth_v1.allowed_external_redirect_urls or []
                ),
                "default_provider": auth_v1.default_provider,
                "client_id": auth_v1.client_id,
                "issuer": auth_v1.issuer,
            }
        except Exception as e:
            logger.debug(f"Could not get auth settings: {e}")
            return {"enabled": False}

    def _extract_identity_providers(self, auth_v2: Any) -> dict[str, bool]:
        """Extract which identity providers are configured."""
        providers = {}

        if auth_v2.identity_providers:
            idp = auth_v2.identity_providers
            providers["azure_active_directory"] = idp.azure_active_directory is not None
            providers["facebook"] = idp.facebook is not None
            providers["github"] = idp.git_hub is not None
            providers["google"] = idp.google is not None
            providers["twitter"] = idp.twitter is not None
            providers["apple"] = idp.apple is not None
            providers["custom_open_id_connect"] = bool(
                idp.custom_open_id_connect_providers
            )

        return providers

    def _collect_app_settings(
        self, resource_group: str, app_name: str
    ) -> list[str]:
        """Collect app setting names (not values) for a Function App."""
        client = self._get_web_client()

        settings = client.web_apps.list_application_settings(resource_group, app_name)
        if settings.properties:
            return list(settings.properties.keys())
        return []

    def _collect_connection_string_names(
        self, resource_group: str, app_name: str
    ) -> list[str]:
        """Collect connection string names (not values) for a Function App."""
        client = self._get_web_client()

        conn_strings = client.web_apps.list_connection_strings(
            resource_group, app_name
        )
        if conn_strings.properties:
            return list(conn_strings.properties.keys())
        return []

    def _collect_ip_restrictions(
        self, resource_group: str, app_name: str
    ) -> list[dict[str, Any]]:
        """Collect IP security restrictions for a Function App."""
        client = self._get_web_client()

        config = client.web_apps.get_configuration(resource_group, app_name)
        restrictions = []

        for rule in config.ip_security_restrictions or []:
            restrictions.append({
                "name": rule.name,
                "ip_address": rule.ip_address,
                "subnet_mask": rule.subnet_mask,
                "vnet_subnet_resource_id": rule.vnet_subnet_resource_id,
                "vnet_traffic_tag": rule.vnet_traffic_tag,
                "subnet_traffic_tag": rule.subnet_traffic_tag,
                "action": rule.action,
                "tag": rule.tag,
                "priority": rule.priority,
                "headers": rule.headers,
            })

        return restrictions

    def _collect_functions(
        self, resource_group: str, app_name: str
    ) -> list[dict[str, Any]]:
        """Collect individual functions in a Function App."""
        client = self._get_web_client()
        functions = []

        try:
            for func in client.web_apps.list_functions(resource_group, app_name):
                functions.append({
                    "id": func.id,
                    "name": func.name,
                    "function_app_id": func.function_app_id,
                    "script_root_path_href": func.script_root_path_href,
                    "script_href": func.script_href,
                    "config_href": func.config_href,
                    "test_data_href": func.test_data_href,
                    "secrets_file_href": func.secrets_file_href,
                    "href": func.href,
                    "invoke_url_template": func.invoke_url_template,
                    "language": func.language,
                    "is_disabled": func.is_disabled,
                })
        except Exception as e:
            logger.debug(f"Could not list functions for {app_name}: {e}")

        return functions

    def _is_runtime_deprecated(
        self, runtime_version: str | None, linux_fx_version: str | None
    ) -> bool:
        """Check if the runtime version is deprecated."""
        if runtime_version and runtime_version in DEPRECATED_RUNTIMES:
            return True

        if linux_fx_version:
            linux_fx_lower = linux_fx_version.lower()
            for deprecated in DEPRECATED_RUNTIMES:
                if deprecated.lower() in linux_fx_lower:
                    return True

        return False

    def _is_runtime_eol_approaching(
        self, runtime_version: str | None, linux_fx_version: str | None
    ) -> bool:
        """Check if the runtime version is approaching end of life."""
        if runtime_version and runtime_version in EOL_APPROACHING_RUNTIMES:
            return True

        if linux_fx_version:
            linux_fx_lower = linux_fx_version.lower()
            for eol in EOL_APPROACHING_RUNTIMES:
                if eol.lower() in linux_fx_lower:
                    return True

        return False

    def _determine_network_exposure(self, raw_config: dict[str, Any]) -> str:
        """
        Determine network exposure based on Function App configuration.

        Args:
            raw_config: Function App configuration dictionary

        Returns:
            Network exposure level
        """
        # Check for IP restrictions
        ip_restrictions = raw_config.get("ip_security_restrictions", [])

        # If there are deny-all rules with no allow rules, it's isolated
        if ip_restrictions:
            has_allow_rules = any(
                r.get("action", "").lower() == "allow"
                for r in ip_restrictions
            )
            has_deny_all = any(
                r.get("ip_address") == "0.0.0.0/0" and
                r.get("action", "").lower() == "deny"
                for r in ip_restrictions
            )

            # Check for VNet only access
            vnet_only = all(
                r.get("vnet_subnet_resource_id") for r in ip_restrictions
                if r.get("action", "").lower() == "allow"
            )

            if has_deny_all and not has_allow_rules:
                return NETWORK_EXPOSURE_ISOLATED

            if vnet_only and has_allow_rules:
                return NETWORK_EXPOSURE_INTERNAL

        # Check for VNet integration
        if raw_config.get("has_vnet_integration"):
            # VNet integration alone doesn't restrict inbound traffic
            # but it's often used with IP restrictions
            pass

        # Check if private endpoints are being used (would need separate check)
        # For now, if no restrictions, assume internet-facing

        # Default: Azure Functions are internet-facing unless restricted
        return NETWORK_EXPOSURE_INTERNET

    def _extract_resource_group(self, resource_id: str) -> str:
        """
        Extract resource group name from Azure resource ID.

        Args:
            resource_id: Full Azure resource ID

        Returns:
            Resource group name
        """
        parts = resource_id.split("/")
        try:
            rg_index = parts.index("resourceGroups")
            return parts[rg_index + 1]
        except (ValueError, IndexError):
            return ""
