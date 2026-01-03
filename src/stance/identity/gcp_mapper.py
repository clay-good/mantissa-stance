"""
GCP Data Access Mapper for Identity Security.

Maps which GCP principals can access which resources by analyzing
IAM policies and bindings.
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

# Import GCP libraries optionally
try:
    from google.cloud import storage
    from google.cloud import resourcemanager_v3
    from google.api_core.exceptions import GoogleAPIError, NotFound, Forbidden

    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False
    storage = None  # type: ignore
    resourcemanager_v3 = None  # type: ignore
    GoogleAPIError = Exception  # type: ignore
    NotFound = Exception  # type: ignore
    Forbidden = Exception  # type: ignore


# GCS role to permission level mapping
GCS_ROLE_MAPPING = {
    # Admin roles
    "roles/storage.admin": PermissionLevel.ADMIN,
    "roles/owner": PermissionLevel.ADMIN,
    "roles/editor": PermissionLevel.WRITE,
    # Write roles
    "roles/storage.objectAdmin": PermissionLevel.WRITE,
    "roles/storage.objectCreator": PermissionLevel.WRITE,
    "roles/storage.legacyBucketWriter": PermissionLevel.WRITE,
    # Read roles
    "roles/storage.objectViewer": PermissionLevel.READ,
    "roles/storage.legacyBucketReader": PermissionLevel.READ,
    "roles/viewer": PermissionLevel.READ,
}


class GCPDataAccessMapper(BaseDataAccessMapper):
    """
    GCP data access mapper.

    Analyzes IAM policies and bindings to determine which principals
    can access which GCS buckets.

    All operations are read-only.
    """

    cloud_provider = "gcp"

    def __init__(
        self,
        config: IdentityConfig | None = None,
        project: str | None = None,
        credentials: Any | None = None,
    ):
        """
        Initialize GCP data access mapper.

        Args:
            config: Optional identity configuration
            project: GCP project ID
            credentials: Optional credentials object
        """
        super().__init__(config)

        if not GCP_AVAILABLE:
            raise ImportError(
                "google-cloud-storage is required for GCP identity analysis. "
                "Install with: pip install google-cloud-storage google-cloud-resource-manager"
            )

        self._project = project
        self._credentials = credentials
        self._storage_client = storage.Client(
            project=project, credentials=credentials
        )

    def who_can_access(self, resource_id: str) -> DataAccessResult:
        """
        Determine who can access a GCS bucket.

        Args:
            resource_id: GCS bucket name (with or without gs:// prefix)

        Returns:
            Data access result with mapping and findings
        """
        # Parse bucket name
        bucket_name = resource_id
        if bucket_name.startswith("gs://"):
            bucket_name = bucket_name[5:].split("/")[0]

        analysis_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting GCP data access analysis: bucket={bucket_name}, id={analysis_id}"
        )

        result = DataAccessResult(
            analysis_id=analysis_id,
            resource_id=bucket_name,
            config=self._config,
            started_at=started_at,
        )

        try:
            # Create mapping
            mapping = DataAccessMapping(
                resource_id=bucket_name,
                resource_type="gcs_bucket",
                cloud_provider="gcp",
            )

            # Get bucket IAM policy
            bucket_policy = self.get_resource_policy(bucket_name)

            if bucket_policy:
                principals = self._extract_principals_from_bindings(
                    bucket_policy, bucket_name
                )

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

            result.mapping = mapping
            result.total_principals = mapping.total_principals

            # Generate findings
            result.findings = self._generate_findings(mapping)

        except GoogleAPIError as e:
            error_msg = f"GCP error: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Analysis error: {type(e).__name__}: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"GCP data access analysis complete: {result.total_principals} principals, "
            f"{len(result.findings)} findings"
        )

        return result

    def get_principal_access(self, principal_id: str) -> list[ResourceAccess]:
        """
        Get all GCS buckets a principal can access.

        Args:
            principal_id: Principal email or member string

        Returns:
            List of resource access entries
        """
        access_list: list[ResourceAccess] = []

        try:
            # List all buckets in project
            for bucket in self._storage_client.list_buckets():
                policy = bucket.get_iam_policy()

                for binding in policy.bindings:
                    role = binding.get("role", "")
                    members = binding.get("members", [])

                    for member in members:
                        # Check if principal matches
                        if self._member_matches_principal(member, principal_id):
                            level = self._role_to_permission_level(role)
                            if level != PermissionLevel.NONE:
                                access_list.append(
                                    ResourceAccess(
                                        resource_id=bucket.name,
                                        resource_type="gcs_bucket",
                                        permission_level=level,
                                        permission_source="bucket_iam",
                                        policy_ids=[role],
                                    )
                                )
                            break

        except GoogleAPIError as e:
            logger.warning(f"Error getting principal access: {e}")

        return access_list

    def list_principals(self) -> Iterator[Principal]:
        """
        List all principals with bucket access in the project.

        Yields:
            Principal objects
        """
        seen: set[str] = set()

        try:
            # Iterate through all buckets and collect principals
            for bucket in self._storage_client.list_buckets():
                try:
                    policy = bucket.get_iam_policy()

                    for binding in policy.bindings:
                        members = binding.get("members", [])

                        for member in members:
                            if member in seen:
                                continue
                            seen.add(member)

                            principal = self._parse_member_to_principal(member)
                            if principal and self._should_include_principal(principal):
                                yield principal

                except Forbidden:
                    logger.debug(f"Access denied to bucket IAM: {bucket.name}")
                except GoogleAPIError as e:
                    logger.debug(f"Error getting bucket IAM: {e}")

        except GoogleAPIError as e:
            logger.warning(f"Error listing buckets: {e}")

    def get_resource_policy(self, resource_id: str) -> dict[str, Any] | None:
        """
        Get the IAM policy for a GCS bucket.

        Args:
            resource_id: GCS bucket name

        Returns:
            Policy bindings or None
        """
        bucket_name = resource_id
        if bucket_name.startswith("gs://"):
            bucket_name = bucket_name[5:].split("/")[0]

        try:
            bucket = self._storage_client.bucket(bucket_name)
            policy = bucket.get_iam_policy()

            return {
                "bindings": [
                    {
                        "role": b.get("role", ""),
                        "members": list(b.get("members", [])),
                        "condition": b.get("condition"),
                    }
                    for b in policy.bindings
                ]
            }

        except NotFound:
            logger.debug(f"Bucket not found: {bucket_name}")
            return None
        except Forbidden:
            logger.debug(f"Access denied to bucket IAM: {bucket_name}")
            return None
        except GoogleAPIError as e:
            logger.debug(f"Error getting bucket policy: {e}")
            return None

    def _extract_principals_from_bindings(
        self,
        policy: dict[str, Any],
        bucket_name: str,
    ) -> list[tuple[Principal, ResourceAccess]]:
        """
        Extract principals from IAM bindings.

        Args:
            policy: Policy with bindings
            bucket_name: Bucket name

        Returns:
            List of (Principal, ResourceAccess) tuples
        """
        results: list[tuple[Principal, ResourceAccess]] = []

        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            members = binding.get("members", [])
            condition = binding.get("condition")

            level = self._role_to_permission_level(role)

            for member in members:
                # Skip public access indicators in this analysis
                if member in ("allUsers", "allAuthenticatedUsers"):
                    continue

                principal = self._parse_member_to_principal(member)
                if principal:
                    access = ResourceAccess(
                        resource_id=bucket_name,
                        resource_type="gcs_bucket",
                        permission_level=level,
                        permission_source="bucket_iam",
                        policy_ids=[role],
                        conditions={"condition": condition} if condition else {},
                    )
                    results.append((principal, access))

        return results

    def _parse_member_to_principal(self, member: str) -> Principal | None:
        """
        Parse a GCP member string to a Principal.

        Args:
            member: GCP member string (e.g., "user:alice@example.com")

        Returns:
            Principal or None
        """
        if ":" not in member:
            return None

        member_type, member_id = member.split(":", 1)
        ptype = self._member_type_to_principal_type(member_type)

        return Principal(
            id=member,
            name=member_id,
            principal_type=ptype,
            cloud_provider="gcp",
            account_id=self._project,
        )

    def _member_type_to_principal_type(self, member_type: str) -> PrincipalType:
        """Map GCP member type to PrincipalType."""
        mapping = {
            "user": PrincipalType.USER,
            "serviceAccount": PrincipalType.SERVICE_ACCOUNT,
            "group": PrincipalType.GROUP,
            "domain": PrincipalType.GROUP,
            "projectOwner": PrincipalType.ROLE,
            "projectEditor": PrincipalType.ROLE,
            "projectViewer": PrincipalType.ROLE,
        }
        return mapping.get(member_type, PrincipalType.UNKNOWN)

    def _role_to_permission_level(self, role: str) -> PermissionLevel:
        """Map GCP IAM role to permission level."""
        # Check exact match
        if role in GCS_ROLE_MAPPING:
            return GCS_ROLE_MAPPING[role]

        # Check partial match
        role_lower = role.lower()
        if "owner" in role_lower or "admin" in role_lower:
            return PermissionLevel.ADMIN
        if "writer" in role_lower or "creator" in role_lower or "editor" in role_lower:
            return PermissionLevel.WRITE
        if "viewer" in role_lower or "reader" in role_lower:
            return PermissionLevel.READ

        return PermissionLevel.UNKNOWN

    def _member_matches_principal(self, member: str, principal_id: str) -> bool:
        """Check if a member string matches a principal ID."""
        if member == principal_id:
            return True

        # Check if principal_id is just the email
        if ":" in member:
            _, member_id = member.split(":", 1)
            if member_id == principal_id:
                return True

        return False

    def list_buckets(self) -> Iterator[str]:
        """List all GCS buckets in the project."""
        try:
            for bucket in self._storage_client.list_buckets():
                yield bucket.name
        except GoogleAPIError as e:
            logger.warning(f"Error listing buckets: {e}")
