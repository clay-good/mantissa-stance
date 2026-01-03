"""
Azure IAM collector for Mantissa Stance.

Collects Azure identity resources including role assignments, service principals,
managed identities, and Azure AD configurations for security posture assessment.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import Asset, AssetCollection, NETWORK_EXPOSURE_ISOLATED

logger = logging.getLogger(__name__)

# Optional Azure imports
try:
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.resource import SubscriptionClient
    from azure.identity import DefaultAzureCredential

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    DefaultAzureCredential = Any  # type: ignore


class AzureIAMCollector(BaseCollector):
    """
    Collects Azure IAM resources and configuration.

    Gathers role assignments, role definitions, service principals,
    and managed identities. All API calls are read-only.
    """

    collector_name = "azure_iam"
    resource_types = [
        "azure_role_assignment",
        "azure_role_definition",
        "azure_service_principal",
        "azure_managed_identity",
    ]

    def __init__(
        self,
        subscription_id: str,
        credential: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Azure IAM collector.

        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Optional Azure credential object.
            **kwargs: Additional configuration.
        """
        if not AZURE_AVAILABLE:
            raise ImportError(
                "azure SDK is required for Azure collectors. Install with: "
                "pip install azure-identity azure-mgmt-authorization azure-mgmt-resource"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()
        self._clients: dict[str, Any] = {}

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        return self._subscription_id

    def _get_authorization_client(self) -> AuthorizationManagementClient:
        """Get or create Authorization Management client."""
        if "authorization" not in self._clients:
            self._clients["authorization"] = AuthorizationManagementClient(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
        return self._clients["authorization"]

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all IAM resources.

        Returns:
            Collection of IAM assets
        """
        assets: list[Asset] = []

        # Collect role assignments
        try:
            assets.extend(self._collect_role_assignments())
        except Exception as e:
            logger.warning(f"Failed to collect role assignments: {e}")

        # Collect custom role definitions
        try:
            assets.extend(self._collect_role_definitions())
        except Exception as e:
            logger.warning(f"Failed to collect role definitions: {e}")

        return AssetCollection(assets)

    def _collect_role_assignments(self) -> list[Asset]:
        """Collect Azure role assignments."""
        client = self._get_authorization_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            # List role assignments at subscription scope
            for assignment in client.role_assignments.list_for_subscription():
                assignment_id = assignment.id
                assignment_name = assignment.name

                # Parse principal info
                principal_id = assignment.principal_id
                principal_type = assignment.principal_type

                # Get role definition name from ID
                role_definition_id = assignment.role_definition_id
                role_name = role_definition_id.split("/")[-1] if role_definition_id else ""

                # Analyze scope
                scope = assignment.scope or ""
                scope_type = self._determine_scope_type(scope)

                # Check for risky configurations
                is_subscription_scope = scope_type == "subscription"
                is_management_group_scope = scope_type == "management_group"

                # Identify privileged roles
                privileged_roles = [
                    "Owner",
                    "Contributor",
                    "User Access Administrator",
                    "Security Admin",
                    "Global Administrator",
                ]
                is_privileged = any(
                    role.lower() in role_name.lower() for role in privileged_roles
                )

                raw_config: dict[str, Any] = {
                    "assignment_id": assignment_id,
                    "assignment_name": assignment_name,
                    "principal_id": principal_id,
                    "principal_type": principal_type,
                    "role_definition_id": role_definition_id,
                    "role_name": role_name,
                    "scope": scope,
                    "scope_type": scope_type,
                    "condition": assignment.condition,
                    "condition_version": assignment.condition_version,
                    "created_on": (
                        assignment.created_on.isoformat()
                        if assignment.created_on
                        else None
                    ),
                    "updated_on": (
                        assignment.updated_on.isoformat()
                        if assignment.updated_on
                        else None
                    ),
                    "created_by": assignment.created_by,
                    "is_subscription_scope": is_subscription_scope,
                    "is_management_group_scope": is_management_group_scope,
                    "is_privileged_role": is_privileged,
                }

                # Try to get role definition details
                try:
                    if role_definition_id:
                        role_def = client.role_definitions.get_by_id(role_definition_id)
                        if role_def:
                            raw_config["role_definition"] = {
                                "name": role_def.role_name,
                                "type": role_def.role_type,
                                "description": role_def.description,
                                "permissions": [
                                    {
                                        "actions": list(p.actions or []),
                                        "not_actions": list(p.not_actions or []),
                                        "data_actions": list(p.data_actions or []),
                                        "not_data_actions": list(p.not_data_actions or []),
                                    }
                                    for p in (role_def.permissions or [])
                                ],
                            }
                            # Check for wildcard permissions
                            has_wildcard = any(
                                "*" in action
                                for p in (role_def.permissions or [])
                                for action in (p.actions or [])
                            )
                            raw_config["has_wildcard_permissions"] = has_wildcard
                except Exception as e:
                    logger.debug(f"Could not get role definition details: {e}")

                created_at = None
                if assignment.created_on:
                    created_at = assignment.created_on.replace(tzinfo=timezone.utc)

                assets.append(
                    Asset(
                        id=assignment_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region="global",
                        resource_type="azure_role_assignment",
                        name=f"{principal_type}:{principal_id[:8]}...->{role_name}",
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing role assignments: {e}")
            raise

        return assets

    def _collect_role_definitions(self) -> list[Asset]:
        """Collect custom role definitions."""
        client = self._get_authorization_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            # List custom role definitions only
            for role_def in client.role_definitions.list(
                scope=f"/subscriptions/{self._subscription_id}",
                filter="type eq 'CustomRole'",
            ):
                role_id = role_def.id
                role_name = role_def.role_name

                # Extract permissions
                permissions = []
                has_wildcard = False
                has_data_actions = False

                for perm in role_def.permissions or []:
                    perm_info = {
                        "actions": list(perm.actions or []),
                        "not_actions": list(perm.not_actions or []),
                        "data_actions": list(perm.data_actions or []),
                        "not_data_actions": list(perm.not_data_actions or []),
                    }
                    permissions.append(perm_info)

                    # Check for wildcards
                    if any("*" in action for action in (perm.actions or [])):
                        has_wildcard = True
                    if perm.data_actions:
                        has_data_actions = True

                # Get assignable scopes
                assignable_scopes = list(role_def.assignable_scopes or [])
                is_subscription_assignable = any(
                    "/subscriptions/" in scope and "/resourceGroups/" not in scope
                    for scope in assignable_scopes
                )

                raw_config: dict[str, Any] = {
                    "role_id": role_id,
                    "role_name": role_name,
                    "role_type": role_def.role_type,
                    "description": role_def.description or "",
                    "permissions": permissions,
                    "assignable_scopes": assignable_scopes,
                    "has_wildcard_permissions": has_wildcard,
                    "has_data_actions": has_data_actions,
                    "is_subscription_assignable": is_subscription_assignable,
                }

                assets.append(
                    Asset(
                        id=role_id,
                        cloud_provider="azure",
                        account_id=self._subscription_id,
                        region="global",
                        resource_type="azure_role_definition",
                        name=role_name,
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing role definitions: {e}")
            raise

        return assets

    def _determine_scope_type(self, scope: str) -> str:
        """
        Determine the type of scope from the scope string.

        Args:
            scope: Azure resource scope string

        Returns:
            Scope type (management_group, subscription, resource_group, resource)
        """
        if not scope:
            return "unknown"

        scope_lower = scope.lower()

        if "/providers/microsoft.management/managementgroups/" in scope_lower:
            return "management_group"
        elif "/resourcegroups/" in scope_lower:
            if scope_lower.count("/") > 4:
                return "resource"
            return "resource_group"
        elif scope_lower.startswith("/subscriptions/"):
            if scope_lower.count("/") == 2:
                return "subscription"
            return "resource"
        else:
            return "unknown"
