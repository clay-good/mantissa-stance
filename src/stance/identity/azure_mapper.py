"""
Azure Data Access Mapper for Identity Security.

Maps which Azure principals can access which resources by analyzing
RBAC role assignments and container access policies.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.identity.base import (
    BaseDataAccessMapper,
    IdentityConfig,
    Principal,
    PrincipalType,
    PermissionLevel,
    ResourceAccess,
    DataAccessMapping,
    DataAccessFinding,
    DataAccessResult,
)

logger = logging.getLogger(__name__)

# Import Azure libraries optionally
try:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient, ContainerClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.core.exceptions import (
        AzureError,
        ResourceNotFoundError,
        ClientAuthenticationError,
    )

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    DefaultAzureCredential = None  # type: ignore
    BlobServiceClient = None  # type: ignore
    ContainerClient = None  # type: ignore
    AuthorizationManagementClient = None  # type: ignore
    AzureError = Exception  # type: ignore
    ResourceNotFoundError = Exception  # type: ignore
    ClientAuthenticationError = Exception  # type: ignore


# Azure built-in role to permission level mapping
AZURE_ROLE_MAPPING = {
    # Admin roles
    "Owner": PermissionLevel.ADMIN,
    "Contributor": PermissionLevel.WRITE,
    "Storage Account Contributor": PermissionLevel.ADMIN,
    "Storage Blob Data Owner": PermissionLevel.ADMIN,
    # Write roles
    "Storage Blob Data Contributor": PermissionLevel.WRITE,
    # Read roles
    "Storage Blob Data Reader": PermissionLevel.READ,
    "Reader": PermissionLevel.READ,
    "Reader and Data Access": PermissionLevel.READ,
}


class AzureDataAccessMapper(BaseDataAccessMapper):
    """
    Azure data access mapper.

    Analyzes RBAC role assignments to determine which principals
    can access which Blob Storage containers.

    All operations are read-only.
    """

    cloud_provider = "azure"

    def __init__(
        self,
        config: IdentityConfig | None = None,
        subscription_id: str | None = None,
        connection_string: str | None = None,
        account_url: str | None = None,
        credential: Any | None = None,
    ):
        """
        Initialize Azure data access mapper.

        Args:
            config: Optional identity configuration
            subscription_id: Azure subscription ID
            connection_string: Storage account connection string
            account_url: Storage account URL
            credential: Optional credential object
        """
        super().__init__(config)

        if not AZURE_AVAILABLE:
            raise ImportError(
                "azure-storage-blob and azure-mgmt-authorization are required. "
                "Install with: pip install azure-storage-blob azure-mgmt-authorization azure-identity"
            )

        self._subscription_id = subscription_id
        self._credential = credential or DefaultAzureCredential()

        if connection_string:
            self._blob_service_client = BlobServiceClient.from_connection_string(
                connection_string
            )
        elif account_url:
            self._blob_service_client = BlobServiceClient(
                account_url=account_url,
                credential=self._credential,
            )
        else:
            raise ValueError(
                "Either connection_string or account_url must be provided"
            )

        # Authorization client for RBAC (optional, requires subscription_id)
        self._auth_client = None
        if subscription_id:
            try:
                self._auth_client = AuthorizationManagementClient(
                    credential=self._credential,
                    subscription_id=subscription_id,
                )
            except Exception as e:
                logger.warning(f"Could not initialize authorization client: {e}")

    def who_can_access(self, resource_id: str) -> DataAccessResult:
        """
        Determine who can access an Azure Blob container.

        Args:
            resource_id: Container name (with or without azure:// prefix)

        Returns:
            Data access result with mapping and findings
        """
        # Parse container name
        container_name = resource_id
        if container_name.startswith("azure://"):
            container_name = container_name[8:].split("/")[0]

        analysis_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting Azure data access analysis: container={container_name}, id={analysis_id}"
        )

        result = DataAccessResult(
            analysis_id=analysis_id,
            resource_id=container_name,
            config=self._config,
            started_at=started_at,
        )

        try:
            # Create mapping
            mapping = DataAccessMapping(
                resource_id=container_name,
                resource_type="azure_blob_container",
                cloud_provider="azure",
            )

            # Get role assignments for the storage account
            if self._auth_client and self._subscription_id:
                principals = self._get_role_assignments_for_container(container_name)

                # Filter by config
                filtered_principals = [
                    (p, a) for p, a in principals
                    if self._should_include_principal(p)
                ]

                mapping.principals = filtered_principals
                mapping.total_principals = len(filtered_principals)

                # Count by type and level
                for principal, access in mapping.principals:
                    ptype = principal.principal_type.value
                    mapping.principals_by_type[ptype] = (
                        mapping.principals_by_type.get(ptype, 0) + 1
                    )

                    plevel = access.permission_level.value
                    mapping.principals_by_level[plevel] = (
                        mapping.principals_by_level.get(plevel, 0) + 1
                    )
            else:
                logger.info(
                    "Subscription ID required for RBAC analysis. "
                    "Returning empty mapping."
                )

            result.mapping = mapping
            result.total_principals = mapping.total_principals

            # Generate findings
            result.findings = self._generate_findings(mapping)

        except AzureError as e:
            error_msg = f"Azure error: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Analysis error: {type(e).__name__}: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"Azure data access analysis complete: {result.total_principals} principals, "
            f"{len(result.findings)} findings"
        )

        return result

    def get_principal_access(self, principal_id: str) -> list[ResourceAccess]:
        """
        Get all containers a principal can access.

        Args:
            principal_id: Principal object ID or email

        Returns:
            List of resource access entries
        """
        access_list: list[ResourceAccess] = []

        if not self._auth_client:
            logger.warning("Authorization client not available")
            return access_list

        try:
            # Get role assignments for this principal
            assignments = self._auth_client.role_assignments.list(
                filter=f"principalId eq '{principal_id}'"
            )

            for assignment in assignments:
                # Get role definition
                role_def_id = assignment.role_definition_id
                role_name = self._get_role_name(role_def_id)

                if role_name and self._is_storage_role(role_name):
                    level = self._role_to_permission_level(role_name)
                    scope = assignment.scope or ""

                    # Extract resource info from scope
                    resource_id = self._extract_resource_from_scope(scope)
                    if resource_id:
                        access_list.append(
                            ResourceAccess(
                                resource_id=resource_id,
                                resource_type="azure_blob_container",
                                permission_level=level,
                                permission_source="rbac",
                                policy_ids=[role_name],
                            )
                        )

        except AzureError as e:
            logger.warning(f"Error getting principal access: {e}")

        return access_list

    def list_principals(self) -> Iterator[Principal]:
        """
        List all principals with storage access.

        Yields:
            Principal objects
        """
        if not self._auth_client:
            logger.warning("Authorization client not available")
            return

        seen: set[str] = set()

        try:
            # Get all role assignments
            assignments = self._auth_client.role_assignments.list()

            for assignment in assignments:
                principal_id = assignment.principal_id
                if not principal_id or principal_id in seen:
                    continue

                # Get role name
                role_def_id = assignment.role_definition_id
                role_name = self._get_role_name(role_def_id)

                # Only include storage-related roles
                if not role_name or not self._is_storage_role(role_name):
                    continue

                seen.add(principal_id)

                # Determine principal type from assignment
                principal_type = self._get_principal_type(assignment.principal_type)

                yield Principal(
                    id=principal_id,
                    name=principal_id,  # Would need Graph API for display name
                    principal_type=principal_type,
                    cloud_provider="azure",
                    account_id=self._subscription_id,
                )

        except AzureError as e:
            logger.warning(f"Error listing principals: {e}")

    def get_resource_policy(self, resource_id: str) -> dict[str, Any] | None:
        """
        Get RBAC role assignments for a container.

        Args:
            resource_id: Container name

        Returns:
            Dictionary with role assignments or None
        """
        if not self._auth_client:
            return None

        container_name = resource_id
        if container_name.startswith("azure://"):
            container_name = container_name[8:].split("/")[0]

        try:
            # Get all role assignments (scope filtering would require full resource ID)
            assignments = list(self._auth_client.role_assignments.list())

            relevant_assignments = []
            for assignment in assignments:
                scope = assignment.scope or ""
                if "blobServices/default/containers" in scope or self._is_storage_scope(scope):
                    role_name = self._get_role_name(assignment.role_definition_id)
                    relevant_assignments.append({
                        "principal_id": assignment.principal_id,
                        "principal_type": assignment.principal_type,
                        "role_definition_id": assignment.role_definition_id,
                        "role_name": role_name,
                        "scope": scope,
                    })

            return {"assignments": relevant_assignments} if relevant_assignments else None

        except AzureError as e:
            logger.debug(f"Error getting resource policy: {e}")
            return None

    def _get_role_assignments_for_container(
        self, container_name: str
    ) -> list[tuple[Principal, ResourceAccess]]:
        """
        Get role assignments that grant access to a container.

        Args:
            container_name: Container name

        Returns:
            List of (Principal, ResourceAccess) tuples
        """
        results: list[tuple[Principal, ResourceAccess]] = []

        if not self._auth_client:
            return results

        try:
            # Get all role assignments
            assignments = self._auth_client.role_assignments.list()

            for assignment in assignments:
                # Get role definition
                role_def_id = assignment.role_definition_id
                role_name = self._get_role_name(role_def_id)

                if not role_name or not self._is_storage_role(role_name):
                    continue

                # Check if scope applies to this container
                scope = assignment.scope or ""
                if not self._scope_applies_to_container(scope, container_name):
                    continue

                level = self._role_to_permission_level(role_name)
                principal_type = self._get_principal_type(assignment.principal_type)

                principal = Principal(
                    id=assignment.principal_id,
                    name=assignment.principal_id,
                    principal_type=principal_type,
                    cloud_provider="azure",
                    account_id=self._subscription_id,
                )

                access = ResourceAccess(
                    resource_id=container_name,
                    resource_type="azure_blob_container",
                    permission_level=level,
                    permission_source="rbac",
                    policy_ids=[role_name],
                )

                results.append((principal, access))

        except AzureError as e:
            logger.warning(f"Error getting role assignments: {e}")

        return results

    def _get_role_name(self, role_definition_id: str | None) -> str | None:
        """Get role name from role definition ID."""
        if not role_definition_id or not self._auth_client:
            return None

        try:
            # Extract role ID from full path
            role_id = role_definition_id.split("/")[-1]

            # Get role definition
            role_def = self._auth_client.role_definitions.get_by_id(role_definition_id)
            return role_def.role_name

        except AzureError:
            # Return extracted role ID as fallback
            return role_definition_id.split("/")[-1] if role_definition_id else None

    def _role_to_permission_level(self, role_name: str) -> PermissionLevel:
        """Map Azure role name to permission level."""
        if role_name in AZURE_ROLE_MAPPING:
            return AZURE_ROLE_MAPPING[role_name]

        # Check partial match
        role_lower = role_name.lower()
        if "owner" in role_lower:
            return PermissionLevel.ADMIN
        if "contributor" in role_lower:
            return PermissionLevel.WRITE
        if "reader" in role_lower:
            return PermissionLevel.READ

        return PermissionLevel.UNKNOWN

    def _is_storage_role(self, role_name: str | None) -> bool:
        """Check if role grants storage access."""
        if not role_name:
            return False

        storage_keywords = [
            "storage",
            "blob",
            "owner",
            "contributor",
            "reader",
        ]
        role_lower = role_name.lower()
        return any(kw in role_lower for kw in storage_keywords)

    def _is_storage_scope(self, scope: str) -> bool:
        """Check if scope is related to storage."""
        storage_indicators = [
            "Microsoft.Storage",
            "storageAccounts",
            "blobServices",
        ]
        return any(ind in scope for ind in storage_indicators)

    def _scope_applies_to_container(
        self, scope: str, container_name: str
    ) -> bool:
        """Check if a role assignment scope applies to a container."""
        # Scope at subscription level applies to all
        if scope.count("/") <= 4:  # /subscriptions/{id}
            return True

        # Scope at resource group level applies to all in group
        if "resourceGroups" in scope and "storageAccounts" not in scope:
            return True

        # Scope at storage account level applies to all containers
        if "storageAccounts" in scope and "containers" not in scope:
            return True

        # Scope at container level - check exact match
        if f"containers/{container_name}" in scope:
            return True

        return False

    def _extract_resource_from_scope(self, scope: str) -> str | None:
        """Extract resource name from scope."""
        if "containers/" in scope:
            parts = scope.split("containers/")
            if len(parts) > 1:
                return parts[1].split("/")[0]

        if "storageAccounts/" in scope:
            parts = scope.split("storageAccounts/")
            if len(parts) > 1:
                return parts[1].split("/")[0]

        return None

    def _get_principal_type(self, azure_principal_type: str | None) -> PrincipalType:
        """Map Azure principal type to PrincipalType."""
        if not azure_principal_type:
            return PrincipalType.UNKNOWN

        mapping = {
            "User": PrincipalType.USER,
            "Group": PrincipalType.GROUP,
            "ServicePrincipal": PrincipalType.SERVICE_PRINCIPAL,
            "MSI": PrincipalType.MANAGED_IDENTITY,
            "ManagedIdentity": PrincipalType.MANAGED_IDENTITY,
        }
        return mapping.get(azure_principal_type, PrincipalType.UNKNOWN)

    def list_containers(self) -> Iterator[str]:
        """List all containers in the storage account."""
        try:
            for container in self._blob_service_client.list_containers():
                yield container["name"]
        except AzureError as e:
            logger.warning(f"Error listing containers: {e}")
