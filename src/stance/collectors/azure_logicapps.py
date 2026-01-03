"""
Azure Logic Apps collector for Mantissa Stance.

Collects Azure Logic Apps (Workflows) and their security configurations
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
    from azure.mgmt.logic import LogicManagementClient
    from azure.identity import DefaultAzureCredential

    AZURE_LOGIC_AVAILABLE = True
except ImportError:
    AZURE_LOGIC_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore


class AzureLogicAppsCollector(BaseCollector):
    """
    Collects Azure Logic Apps (Workflows) resources and configuration.

    Gathers Logic Apps with their security settings including:
    - Workflow state (enabled/disabled)
    - Access control configuration (IP restrictions)
    - Trigger configuration (HTTP, recurrence, etc.)
    - Managed identity configuration
    - Integration service environment
    - Workflow definition analysis (connection references)
    - Diagnostic settings

    Supports both Consumption (multi-tenant) and Standard (single-tenant) Logic Apps.

    All API calls are read-only.
    """

    collector_name = "azure_logicapps"
    resource_types = [
        "azure_logic_app",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure Logic Apps collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_LOGIC_AVAILABLE:
            raise ImportError(
                "azure-mgmt-logic is required for Azure Logic Apps collector. "
                "Install with: pip install azure-mgmt-logic azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._client: LogicManagementClient | None = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_logic_client(self) -> LogicManagementClient:
        """Get or create Logic Management client."""
        if self._client is None:
            self._client = LogicManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Azure Logic Apps resources.

        Returns:
            Collection of Azure Logic Apps assets
        """
        assets: list[Asset] = []

        # Collect Logic Apps (workflows)
        try:
            assets.extend(self._collect_workflows())
        except Exception as e:
            logger.warning(f"Failed to collect Logic Apps: {e}")

        return AssetCollection(assets)

    def _collect_workflows(self) -> list[Asset]:
        """Collect Azure Logic Apps workflows with their configurations."""
        client = self._get_logic_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            # List all workflows in the subscription
            for workflow in client.workflows.list_by_subscription():
                workflow_id = workflow.id
                workflow_name = workflow.name
                resource_group = self._extract_resource_group(workflow_id)
                location = workflow.location

                # Extract tags
                tags = dict(workflow.tags) if workflow.tags else {}

                # Basic configuration
                raw_config: dict[str, Any] = {
                    "workflow_id": workflow_id,
                    "workflow_name": workflow_name,
                    "resource_group": resource_group,
                    "location": location,
                    "state": workflow.state,
                    "provisioning_state": workflow.provisioning_state,
                    "sku_name": workflow.sku.name if workflow.sku else None,
                    "version": workflow.version,
                    "access_endpoint": workflow.access_endpoint,
                }

                # Workflow state
                is_enabled = workflow.state == "Enabled"
                raw_config["is_enabled"] = is_enabled

                # Integration service environment
                ise_info = workflow.integration_service_environment
                if ise_info:
                    raw_config["integration_service_environment"] = {
                        "id": ise_info.id,
                        "name": ise_info.name,
                        "type": ise_info.type,
                    }
                    raw_config["has_ise"] = True
                    raw_config["uses_ise_isolation"] = True
                else:
                    raw_config["integration_service_environment"] = None
                    raw_config["has_ise"] = False
                    raw_config["uses_ise_isolation"] = False

                # Integration account
                integration_account = workflow.integration_account
                if integration_account:
                    raw_config["integration_account"] = {
                        "id": integration_account.id,
                        "name": integration_account.name,
                        "type": integration_account.type,
                    }
                    raw_config["has_integration_account"] = True
                else:
                    raw_config["integration_account"] = None
                    raw_config["has_integration_account"] = False

                # Managed identity
                identity = workflow.identity
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

                # Endpoint configuration (access control)
                endpoint_config = workflow.endpoints_configuration
                if endpoint_config:
                    raw_config["endpoints_configuration"] = self._parse_endpoints_config(
                        endpoint_config
                    )
                else:
                    raw_config["endpoints_configuration"] = None

                # Access control
                access_control = workflow.access_control
                if access_control:
                    raw_config["access_control"] = self._parse_access_control(
                        access_control
                    )
                    raw_config["has_access_control"] = True
                else:
                    raw_config["access_control"] = None
                    raw_config["has_access_control"] = False

                # Workflow definition analysis
                definition = workflow.definition
                if definition:
                    definition_analysis = self._analyze_definition(definition)
                    raw_config.update(definition_analysis)
                else:
                    raw_config["triggers"] = []
                    raw_config["actions"] = []
                    raw_config["has_http_trigger"] = False
                    raw_config["connections_used"] = []

                # Workflow parameters (names only, not values)
                parameters = workflow.parameters
                if parameters:
                    raw_config["parameter_names"] = list(parameters.keys())
                    raw_config["has_parameters"] = True
                else:
                    raw_config["parameter_names"] = []
                    raw_config["has_parameters"] = False

                # Timestamps
                raw_config["created_time"] = (
                    workflow.created_time.isoformat() if workflow.created_time else None
                )
                raw_config["changed_time"] = (
                    workflow.changed_time.isoformat() if workflow.changed_time else None
                )

                # Determine network exposure
                network_exposure = self._determine_network_exposure(raw_config)

                # Security summary
                raw_config["is_secure"] = (
                    raw_config.get("has_managed_identity", False) and
                    raw_config.get("has_access_control", False) and
                    not raw_config.get("allows_anonymous_access", True)
                )

                # Parse creation time if available
                created_at = None
                if workflow.created_time:
                    created_at = workflow.created_time

                assets.append(
                    Asset(
                        id=workflow_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region=location,
                        resource_type="azure_logic_app",
                        name=workflow_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing Logic Apps: {e}")
            raise

        return assets

    def _parse_endpoints_config(self, endpoints_config: Any) -> dict[str, Any]:
        """Parse endpoint configuration."""
        result: dict[str, Any] = {}

        # Workflow endpoints
        workflow_ep = endpoints_config.workflow
        if workflow_ep:
            result["workflow"] = {
                "outgoing_ip_addresses": [
                    {
                        "address": ip.address,
                    }
                    for ip in (workflow_ep.outgoing_ip_addresses or [])
                ],
                "access_endpoint_ip_addresses": [
                    {
                        "address": ip.address,
                    }
                    for ip in (workflow_ep.access_endpoint_ip_addresses or [])
                ],
            }

        # Connector endpoints
        connector_ep = endpoints_config.connector
        if connector_ep:
            result["connector"] = {
                "outgoing_ip_addresses": [
                    {
                        "address": ip.address,
                    }
                    for ip in (connector_ep.outgoing_ip_addresses or [])
                ],
            }

        return result

    def _parse_access_control(self, access_control: Any) -> dict[str, Any]:
        """Parse access control configuration."""
        result: dict[str, Any] = {}

        # Trigger access control
        triggers = access_control.triggers
        if triggers:
            result["triggers"] = {
                "allowed_caller_ip_addresses": [
                    {
                        "address_range": ip_range.address_range,
                    }
                    for ip_range in (triggers.allowed_caller_ip_addresses or [])
                ],
                "open_authentication_policies": self._parse_auth_policies(
                    triggers.open_authentication_policies
                ),
            }
            # Check if trigger access is restricted
            allowed_ips = triggers.allowed_caller_ip_addresses or []
            result["trigger_ip_restricted"] = len(allowed_ips) > 0
            # Check for wide-open access (any IP)
            result["trigger_allows_any_ip"] = any(
                ip_range.address_range in ["0.0.0.0-255.255.255.255", "0.0.0.0/0", "*"]
                for ip_range in allowed_ips
            )
        else:
            result["triggers"] = None
            result["trigger_ip_restricted"] = False
            result["trigger_allows_any_ip"] = True

        # Contents access control
        contents = access_control.contents
        if contents:
            result["contents"] = {
                "allowed_caller_ip_addresses": [
                    {
                        "address_range": ip_range.address_range,
                    }
                    for ip_range in (contents.allowed_caller_ip_addresses or [])
                ],
            }
            result["contents_ip_restricted"] = len(
                contents.allowed_caller_ip_addresses or []
            ) > 0
        else:
            result["contents"] = None
            result["contents_ip_restricted"] = False

        # Actions access control
        actions = access_control.actions
        if actions:
            result["actions"] = {
                "allowed_caller_ip_addresses": [
                    {
                        "address_range": ip_range.address_range,
                    }
                    for ip_range in (actions.allowed_caller_ip_addresses or [])
                ],
            }
            result["actions_ip_restricted"] = len(
                actions.allowed_caller_ip_addresses or []
            ) > 0
        else:
            result["actions"] = None
            result["actions_ip_restricted"] = False

        # Workflow management access control
        workflow_management = access_control.workflow_management
        if workflow_management:
            result["workflow_management"] = {
                "allowed_caller_ip_addresses": [
                    {
                        "address_range": ip_range.address_range,
                    }
                    for ip_range in (workflow_management.allowed_caller_ip_addresses or [])
                ],
            }
            result["management_ip_restricted"] = len(
                workflow_management.allowed_caller_ip_addresses or []
            ) > 0
        else:
            result["workflow_management"] = None
            result["management_ip_restricted"] = False

        return result

    def _parse_auth_policies(self, policies: Any) -> dict[str, Any]:
        """Parse open authentication policies."""
        if not policies:
            return {}

        result: dict[str, Any] = {"policies": {}}
        if policies.policies:
            for name, policy in policies.policies.items():
                result["policies"][name] = {
                    "type": policy.type,
                    "claims": [
                        {
                            "name": claim.name,
                            "value": claim.value,
                        }
                        for claim in (policy.claims or [])
                    ],
                }

        return result

    def _analyze_definition(self, definition: dict) -> dict[str, Any]:
        """
        Analyze workflow definition to extract security-relevant information.

        Args:
            definition: Workflow definition dictionary

        Returns:
            Dictionary with trigger/action analysis
        """
        result: dict[str, Any] = {
            "triggers": [],
            "actions": [],
            "has_http_trigger": False,
            "has_manual_trigger": False,
            "has_recurrence_trigger": False,
            "connections_used": [],
            "allows_anonymous_access": True,
        }

        # Analyze triggers
        triggers = definition.get("triggers", {})
        for trigger_name, trigger_config in triggers.items():
            trigger_type = trigger_config.get("type", "")
            trigger_kind = trigger_config.get("kind", "")

            trigger_info = {
                "name": trigger_name,
                "type": trigger_type,
                "kind": trigger_kind,
            }

            # Check for HTTP triggers
            if trigger_type.lower() in ["request", "http", "httpwebhook"]:
                result["has_http_trigger"] = True
                trigger_info["is_http"] = True

                # Check authentication on trigger
                auth_type = trigger_config.get("operationOptions", {})
                if auth_type:
                    trigger_info["operation_options"] = auth_type

                # Check for relative path (REST-like URLs)
                relative_path = trigger_config.get("relativePath")
                if relative_path:
                    trigger_info["relative_path"] = relative_path

                # Check authentication settings
                metadata = trigger_config.get("metadata", {})
                if metadata:
                    trigger_info["metadata"] = metadata

            # Check for manual triggers
            if trigger_type.lower() in ["manual", "request"]:
                result["has_manual_trigger"] = True

            # Check for recurrence triggers
            if trigger_type.lower() == "recurrence":
                result["has_recurrence_trigger"] = True
                recurrence = trigger_config.get("recurrence", {})
                trigger_info["recurrence"] = {
                    "frequency": recurrence.get("frequency"),
                    "interval": recurrence.get("interval"),
                }

            result["triggers"].append(trigger_info)

        # Analyze actions for connections used
        actions = definition.get("actions", {})
        connections_found: set[str] = set()

        for action_name, action_config in actions.items():
            action_type = action_config.get("type", "")

            action_info = {
                "name": action_name,
                "type": action_type,
            }

            # Check for API connections
            if action_type.lower() == "apiconnection":
                inputs = action_config.get("inputs", {})
                host = inputs.get("host", {})
                connection = host.get("connection", {})
                connection_name = connection.get("name", "")

                if connection_name:
                    # Extract connection reference
                    # Format: @parameters('$connections')['connection_name']['connectionId']
                    if "$connections" in connection_name:
                        # Parse the connection name from the reference
                        parts = connection_name.split("'")
                        if len(parts) >= 4:
                            connections_found.add(parts[3])
                    else:
                        connections_found.add(connection_name)

            # Check for HTTP actions
            if action_type.lower() == "http":
                action_info["is_http_action"] = True
                inputs = action_config.get("inputs", {})
                action_info["http_method"] = inputs.get("method")
                action_info["http_uri_has_parameters"] = (
                    "@" in inputs.get("uri", "")
                )

            result["actions"].append(action_info)

        result["connections_used"] = list(connections_found)
        result["connection_count"] = len(connections_found)

        # Determine if allows anonymous access based on trigger configuration
        # If there's an HTTP trigger without explicit auth requirements, it's anonymous
        for trigger in result["triggers"]:
            if trigger.get("is_http"):
                # Check for operation options that require auth
                op_options = trigger.get("operation_options", "")
                if op_options and "IncludeAuthorizationHeadersInOutputs" in str(op_options):
                    result["allows_anonymous_access"] = False
                break

        return result

    def _determine_network_exposure(self, raw_config: dict[str, Any]) -> str:
        """
        Determine network exposure based on Logic App configuration.

        Args:
            raw_config: Logic App configuration dictionary

        Returns:
            Network exposure level
        """
        # Check for Integration Service Environment (ISE)
        if raw_config.get("uses_ise_isolation"):
            # ISE provides VNet integration and isolation
            return NETWORK_EXPOSURE_INTERNAL

        # Check access control settings
        access_control = raw_config.get("access_control", {})
        if access_control:
            trigger_restricted = access_control.get("trigger_ip_restricted", False)
            trigger_allows_any = access_control.get("trigger_allows_any_ip", True)

            if trigger_restricted and not trigger_allows_any:
                # Has IP restrictions that aren't wide open
                return NETWORK_EXPOSURE_INTERNAL

        # Check if workflow has HTTP triggers
        has_http_trigger = raw_config.get("has_http_trigger", False)

        if not has_http_trigger:
            # No HTTP trigger means only scheduled or event-based
            # These are not directly accessible from the internet
            has_recurrence = raw_config.get("has_recurrence_trigger", False)
            if has_recurrence:
                return NETWORK_EXPOSURE_ISOLATED

        # Default: Logic Apps with HTTP triggers are internet-facing
        if has_http_trigger:
            return NETWORK_EXPOSURE_INTERNET

        # No HTTP trigger, not recurrence - likely event-based
        return NETWORK_EXPOSURE_INTERNAL

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
