"""
GCP IAM collector for Mantissa Stance.

Collects IAM resources including service accounts, IAM policies and bindings,
and organization policies for security posture assessment.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import Asset, AssetCollection, NETWORK_EXPOSURE_ISOLATED

logger = logging.getLogger(__name__)

# Optional GCP imports
try:
    from google.cloud import iam_admin_v1
    from google.cloud import resourcemanager_v3
    from google.iam.v1 import iam_policy_pb2
    from google.auth.credentials import Credentials

    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False
    Credentials = Any  # type: ignore


class GCPIAMCollector(BaseCollector):
    """
    Collects GCP IAM resources and configuration.

    Gathers service accounts, IAM policies, role bindings, and
    organization policies. All API calls are read-only.
    """

    collector_name = "gcp_iam"
    resource_types = [
        "gcp_service_account",
        "gcp_iam_policy",
        "gcp_iam_binding",
        "gcp_project_iam_policy",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP IAM collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            **kwargs: Additional configuration.
        """
        if not GCP_AVAILABLE:
            raise ImportError(
                "google-cloud SDK is required for GCP collectors. Install with: "
                "pip install google-cloud-iam google-cloud-resource-manager"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._clients: dict[str, Any] = {}

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    def _get_iam_client(self) -> iam_admin_v1.IAMClient:
        """Get or create IAM client."""
        if "iam" not in self._clients:
            self._clients["iam"] = iam_admin_v1.IAMClient(
                credentials=self._credentials
            )
        return self._clients["iam"]

    def _get_resource_manager_client(self) -> resourcemanager_v3.ProjectsClient:
        """Get or create Resource Manager client."""
        if "resource_manager" not in self._clients:
            self._clients["resource_manager"] = resourcemanager_v3.ProjectsClient(
                credentials=self._credentials
            )
        return self._clients["resource_manager"]

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

        # Collect service accounts
        try:
            assets.extend(self._collect_service_accounts())
        except Exception as e:
            logger.warning(f"Failed to collect service accounts: {e}")

        # Collect project IAM policy
        try:
            policy_asset = self._collect_project_iam_policy()
            if policy_asset:
                assets.append(policy_asset)
        except Exception as e:
            logger.warning(f"Failed to collect project IAM policy: {e}")

        return AssetCollection(assets)

    def _collect_service_accounts(self) -> list[Asset]:
        """Collect GCP service accounts with their configurations."""
        client = self._get_iam_client()
        assets: list[Asset] = []
        now = self._now()

        request = iam_admin_v1.ListServiceAccountsRequest(
            name=f"projects/{self._project_id}"
        )

        try:
            for sa in client.list_service_accounts(request=request):
                sa_email = sa.email
                sa_name = sa.name  # projects/{project}/serviceAccounts/{email}
                unique_id = sa.unique_id

                raw_config: dict[str, Any] = {
                    "email": sa_email,
                    "name": sa_name,
                    "unique_id": unique_id,
                    "display_name": sa.display_name or "",
                    "description": sa.description or "",
                    "disabled": sa.disabled,
                    "oauth2_client_id": sa.oauth2_client_id or "",
                }

                # Get service account keys
                try:
                    keys_request = iam_admin_v1.ListServiceAccountKeysRequest(
                        name=sa_name,
                        key_types=[
                            iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED
                        ],
                    )
                    keys_response = client.list_service_account_keys(
                        request=keys_request
                    )
                    keys = []
                    for key in keys_response.keys:
                        key_age_days = None
                        if key.valid_after_time:
                            key_created = key.valid_after_time.replace(
                                tzinfo=timezone.utc
                            )
                            key_age = now - key_created
                            key_age_days = key_age.days

                        keys.append({
                            "key_id": key.name.split("/")[-1] if key.name else "",
                            "key_algorithm": str(key.key_algorithm),
                            "key_origin": str(key.key_origin),
                            "key_type": str(key.key_type),
                            "valid_after": (
                                key.valid_after_time.isoformat()
                                if key.valid_after_time
                                else None
                            ),
                            "valid_before": (
                                key.valid_before_time.isoformat()
                                if key.valid_before_time
                                else None
                            ),
                            "age_days": key_age_days,
                            "disabled": key.disabled,
                        })

                    raw_config["keys"] = keys
                    raw_config["user_managed_key_count"] = len(keys)
                    raw_config["has_user_managed_keys"] = len(keys) > 0

                    # Check for old keys (> 90 days)
                    old_keys = [k for k in keys if k.get("age_days", 0) > 90]
                    raw_config["has_old_keys"] = len(old_keys) > 0
                    raw_config["old_key_count"] = len(old_keys)

                except Exception as e:
                    logger.debug(f"Could not get keys for {sa_email}: {e}")
                    raw_config["keys"] = []
                    raw_config["user_managed_key_count"] = 0

                # Get IAM policy for this service account
                try:
                    iam_request = iam_policy_pb2.GetIamPolicyRequest(
                        resource=sa_name
                    )
                    policy = client.get_iam_policy(request=iam_request)
                    bindings = []
                    for binding in policy.bindings:
                        bindings.append({
                            "role": binding.role,
                            "members": list(binding.members),
                        })
                    raw_config["iam_bindings"] = bindings
                    raw_config["has_iam_bindings"] = len(bindings) > 0
                except Exception as e:
                    logger.debug(f"Could not get IAM policy for {sa_email}: {e}")

                # Check for risky configurations
                raw_config["is_default_compute_sa"] = (
                    "-compute@developer.gserviceaccount.com" in sa_email
                )
                raw_config["is_default_app_engine_sa"] = (
                    "@appspot.gserviceaccount.com" in sa_email
                )

                assets.append(
                    Asset(
                        id=sa_name,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region="global",
                        resource_type="gcp_service_account",
                        name=sa_email,
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing service accounts: {e}")
            raise

        return assets

    def _collect_project_iam_policy(self) -> Asset | None:
        """Collect project-level IAM policy."""
        client = self._get_resource_manager_client()
        now = self._now()

        try:
            request = iam_policy_pb2.GetIamPolicyRequest(
                resource=f"projects/{self._project_id}"
            )
            policy = client.get_iam_policy(request=request)

            bindings_list = []
            roles_used = set()
            all_members = set()
            external_members = set()
            public_access = False

            for binding in policy.bindings:
                role = binding.role
                members = list(binding.members)
                roles_used.add(role)

                for member in members:
                    all_members.add(member)

                    # Check for public access
                    if member in ("allUsers", "allAuthenticatedUsers"):
                        public_access = True
                        external_members.add(member)

                    # Check for external users/groups
                    if (
                        member.startswith("user:") or
                        member.startswith("group:")
                    ):
                        # External if not in project domain
                        # This is a simplified check
                        external_members.add(member)

                bindings_list.append({
                    "role": role,
                    "members": members,
                    "member_count": len(members),
                })

            # Analyze for risky roles
            risky_roles = [
                "roles/owner",
                "roles/editor",
                "roles/iam.securityAdmin",
                "roles/iam.serviceAccountAdmin",
                "roles/iam.serviceAccountKeyAdmin",
            ]
            has_risky_bindings = any(
                role in risky_roles for role in roles_used
            )

            raw_config = {
                "project_id": self._project_id,
                "bindings": bindings_list,
                "binding_count": len(bindings_list),
                "roles_used": list(roles_used),
                "roles_count": len(roles_used),
                "member_count": len(all_members),
                "has_public_access": public_access,
                "has_external_members": len(external_members) > 0,
                "external_members": list(external_members),
                "has_risky_bindings": has_risky_bindings,
                "etag": policy.etag.decode() if policy.etag else "",
                "version": policy.version,
            }

            return Asset(
                id=f"projects/{self._project_id}/iamPolicy",
                cloud_provider="gcp",
                account_id=self._project_id,
                region="global",
                resource_type="gcp_project_iam_policy",
                name=f"{self._project_id} IAM Policy",
                network_exposure=NETWORK_EXPOSURE_ISOLATED,
                last_seen=now,
                raw_config=raw_config,
            )

        except Exception as e:
            logger.error(f"Error getting project IAM policy: {e}")
            raise

    def _check_overly_permissive_binding(
        self,
        role: str,
        members: list[str],
    ) -> dict[str, Any]:
        """
        Check if a role binding is overly permissive.

        Args:
            role: IAM role name
            members: List of member identities

        Returns:
            Analysis result with issues found
        """
        issues = []

        # Check for public access
        if "allUsers" in members:
            issues.append("Allows public access (allUsers)")
        if "allAuthenticatedUsers" in members:
            issues.append("Allows any authenticated user (allAuthenticatedUsers)")

        # Check for overly broad roles
        broad_roles = {
            "roles/owner": "Owner role grants full access",
            "roles/editor": "Editor role grants broad write access",
        }
        if role in broad_roles:
            issues.append(broad_roles[role])

        # Check for service account impersonation roles
        if role in (
            "roles/iam.serviceAccountTokenCreator",
            "roles/iam.serviceAccountUser",
        ):
            issues.append(f"{role} allows service account impersonation")

        return {
            "is_permissive": len(issues) > 0,
            "issues": issues,
        }
