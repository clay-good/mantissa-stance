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
        "azure_conditional_access_policy",
        "azure_directory_settings",
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

        # Collect Conditional Access Policies (requires Graph API)
        try:
            assets.extend(self._collect_conditional_access_policies())
        except Exception as e:
            logger.warning(f"Failed to collect conditional access policies: {e}")

        # Collect Directory Settings (requires Graph API)
        try:
            assets.extend(self._collect_directory_settings())
        except Exception as e:
            logger.warning(f"Failed to collect directory settings: {e}")

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

    def _get_graph_client(self) -> Any:
        """Get or create Microsoft Graph client for Azure AD operations."""
        if "graph" not in self._clients:
            try:
                import requests

                # Use the credential to get an access token for Graph API
                token = self._credential.get_token("https://graph.microsoft.com/.default")
                self._clients["graph_token"] = token.token
            except Exception as e:
                logger.warning(f"Failed to get Graph API token: {e}")
                self._clients["graph_token"] = None
        return self._clients.get("graph_token")

    def _graph_request(self, endpoint: str) -> dict[str, Any] | None:
        """
        Make a request to Microsoft Graph API.

        Args:
            endpoint: API endpoint path (e.g., '/identity/conditionalAccess/policies')

        Returns:
            JSON response or None on error
        """
        import requests

        token = self._get_graph_client()
        if not token:
            return None

        url = f"https://graph.microsoft.com/v1.0{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.warning(f"Graph API request failed for {endpoint}: {e}")
            return None

    def _collect_conditional_access_policies(self) -> list[Asset]:
        """
        Collect Azure AD Conditional Access Policies.

        Requires Microsoft Graph API access with Policy.Read.All permission.
        """
        assets: list[Asset] = []
        now = self._now()

        # Fetch conditional access policies from Graph API
        response = self._graph_request("/identity/conditionalAccess/policies")
        if not response:
            logger.debug("Could not fetch conditional access policies (Graph API unavailable or no permissions)")
            return assets

        policies = response.get("value", [])

        for policy in policies:
            policy_id = policy.get("id", "")
            display_name = policy.get("displayName", "Unknown Policy")
            state = policy.get("state", "disabled")

            # Analyze policy conditions
            conditions = policy.get("conditions", {})
            grant_controls = policy.get("grantControls", {}) or {}

            # Check if policy enforces MFA
            built_in_controls = grant_controls.get("builtInControls", [])
            enforces_mfa = "mfa" in built_in_controls

            # Check user conditions
            users = conditions.get("users", {})
            include_users = users.get("includeUsers", [])
            include_groups = users.get("includeGroups", [])
            include_roles = users.get("includeRoles", [])

            # Check if applies to all users
            applies_to_all_users = "All" in include_users

            # Check if applies to admin roles
            # Common privileged role template IDs
            admin_role_ids = {
                "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
                "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
                "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
                "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
            }
            enforces_mfa_for_admins = (
                enforces_mfa
                and (any(role in admin_role_ids for role in include_roles) or "All" in include_roles)
            )

            # Check client app conditions for legacy auth blocking
            client_app_types = conditions.get("clientAppTypes", [])
            session_controls = policy.get("sessionControls", {})

            # Policy blocks legacy auth if it targets legacy clients and blocks access
            blocks_legacy_auth = (
                state == "enabled"
                and grant_controls.get("operator") == "OR"
                and "block" in built_in_controls
                and ("exchangeActiveSync" in client_app_types or "other" in client_app_types)
            )

            # Check cloud apps
            applications = conditions.get("applications", {})
            include_apps = applications.get("includeApplications", [])
            applies_to_all_apps = "All" in include_apps

            raw_config: dict[str, Any] = {
                "policy_id": policy_id,
                "display_name": display_name,
                "state": state,
                "is_enabled": state == "enabled",
                # MFA enforcement
                "enforces_mfa": enforces_mfa and state == "enabled",
                "applies_to_all_users": applies_to_all_users,
                "enforces_mfa_for_admins": enforces_mfa_for_admins and state == "enabled",
                # Legacy auth blocking
                "blocks_legacy_auth": blocks_legacy_auth,
                # Detailed conditions
                "conditions": conditions,
                "grant_controls": grant_controls,
                "session_controls": session_controls,
                "include_users": include_users,
                "include_groups": include_groups,
                "include_roles": include_roles,
                "include_applications": include_apps,
                "applies_to_all_apps": applies_to_all_apps,
                "client_app_types": client_app_types,
                "built_in_controls": built_in_controls,
                "created_date_time": policy.get("createdDateTime"),
                "modified_date_time": policy.get("modifiedDateTime"),
            }

            assets.append(
                Asset(
                    id=f"/policies/conditionalAccess/{policy_id}",
                    cloud_provider="azure",
                    account_id=self._subscription_id,
                    region="global",
                    resource_type="azure_conditional_access_policy",
                    name=display_name,
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _collect_directory_settings(self) -> list[Asset]:
        """
        Collect Azure AD Directory Settings.

        Requires Microsoft Graph API access with Directory.Read.All permission.
        """
        assets: list[Asset] = []
        now = self._now()

        # Fetch organization settings
        org_response = self._graph_request("/organization")
        if not org_response:
            logger.debug("Could not fetch organization settings")
            return assets

        orgs = org_response.get("value", [])
        if not orgs:
            return assets

        org = orgs[0]
        tenant_id = org.get("id", "")

        # Fetch external collaboration settings (authorization policy)
        auth_policy = self._graph_request("/policies/authorizationPolicy")

        # Fetch guest invite settings
        guest_settings: dict[str, Any] = {}
        if auth_policy:
            guest_settings = {
                "allow_invites_from": auth_policy.get("allowInvitesFrom", "everyone"),
                "guest_user_role_id": auth_policy.get("guestUserRoleId"),
                "allow_email_verified_users_to_join_organization": auth_policy.get(
                    "allowEmailVerifiedUsersToJoinOrganization", True
                ),
                "block_msol_powershell": auth_policy.get("blockMsolPowerShell", False),
            }

        raw_config: dict[str, Any] = {
            "tenant_id": tenant_id,
            "display_name": org.get("displayName", ""),
            "verified_domains": [d.get("name") for d in org.get("verifiedDomains", [])],
            # Guest user settings (for guest-user-access.yaml policy)
            "guest_user_role_id": guest_settings.get("guest_user_role_id"),
            "allow_invites_from": guest_settings.get("allow_invites_from", "everyone"),
            "allow_email_verified_users_to_join": guest_settings.get(
                "allow_email_verified_users_to_join_organization", True
            ),
            "block_msol_powershell": guest_settings.get("block_msol_powershell", False),
            # Security defaults status
            "security_defaults_enabled": org.get("securityDefaults", {}).get("isEnabled", False)
            if isinstance(org.get("securityDefaults"), dict)
            else False,
        }

        assets.append(
            Asset(
                id=f"/tenants/{tenant_id}/settings",
                cloud_provider="azure",
                account_id=self._subscription_id,
                region="global",
                resource_type="azure_directory_settings",
                name=f"Directory Settings - {org.get('displayName', tenant_id)}",
                network_exposure=NETWORK_EXPOSURE_ISOLATED,
                last_seen=now,
                raw_config=raw_config,
            )
        )

        return assets
