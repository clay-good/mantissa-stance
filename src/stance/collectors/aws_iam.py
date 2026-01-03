"""
AWS IAM collector for Mantissa Stance.

Collects IAM resources including users, roles, policies, groups,
password policy, and account summary for security posture assessment.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import Asset, AssetCollection, NETWORK_EXPOSURE_ISOLATED

logger = logging.getLogger(__name__)


class IAMCollector(BaseCollector):
    """
    Collects AWS IAM resources and configuration.

    Gathers IAM users, roles, policies, groups, password policy,
    and account summary. All API calls are read-only.
    """

    collector_name = "aws_iam"
    resource_types = [
        "aws_iam_user",
        "aws_iam_role",
        "aws_iam_policy",
        "aws_iam_group",
        "aws_iam_account_password_policy",
        "aws_iam_account_summary",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all IAM resources.

        Returns:
            Collection of IAM assets
        """
        assets: list[Asset] = []

        # Collect users
        try:
            assets.extend(self._collect_users())
        except Exception as e:
            logger.warning(f"Failed to collect IAM users: {e}")

        # Collect roles
        try:
            assets.extend(self._collect_roles())
        except Exception as e:
            logger.warning(f"Failed to collect IAM roles: {e}")

        # Collect customer managed policies
        try:
            assets.extend(self._collect_policies())
        except Exception as e:
            logger.warning(f"Failed to collect IAM policies: {e}")

        # Collect groups
        try:
            assets.extend(self._collect_groups())
        except Exception as e:
            logger.warning(f"Failed to collect IAM groups: {e}")

        # Collect password policy
        try:
            password_policy = self._collect_password_policy()
            if password_policy:
                assets.append(password_policy)
        except Exception as e:
            logger.warning(f"Failed to collect password policy: {e}")

        # Collect account summary
        try:
            assets.append(self._collect_account_summary())
        except Exception as e:
            logger.warning(f"Failed to collect account summary: {e}")

        return AssetCollection(assets)

    def _collect_users(self) -> list[Asset]:
        """Collect IAM users with their configurations."""
        iam = self._get_client("iam")
        assets: list[Asset] = []
        now = self._now()

        for user in self._paginate(iam, "list_users", "Users"):
            user_name = user["UserName"]
            user_arn = user["Arn"]

            # Get additional user details
            raw_config: dict[str, Any] = {
                "user_name": user_name,
                "user_id": user["UserId"],
                "arn": user_arn,
                "path": user.get("Path", "/"),
                "create_date": user["CreateDate"].isoformat(),
            }

            # Get access keys
            try:
                access_keys = []
                for key in self._paginate(
                    iam, "list_access_keys", "AccessKeyMetadata", UserName=user_name
                ):
                    key_age_days = None
                    if key.get("CreateDate"):
                        key_age = now - key["CreateDate"].replace(tzinfo=timezone.utc)
                        key_age_days = key_age.days

                    access_keys.append({
                        "access_key_id": key["AccessKeyId"],
                        "status": key["Status"],
                        "create_date": key["CreateDate"].isoformat(),
                        "age_days": key_age_days,
                    })
                raw_config["access_keys"] = access_keys
                raw_config["access_keys_count"] = len(access_keys)
                raw_config["has_active_access_keys"] = any(
                    k["status"] == "Active" for k in access_keys
                )
            except Exception as e:
                logger.debug(f"Could not get access keys for {user_name}: {e}")

            # Get MFA devices
            try:
                mfa_devices = list(
                    self._paginate(
                        iam, "list_mfa_devices", "MFADevices", UserName=user_name
                    )
                )
                raw_config["mfa_devices"] = [
                    {"serial_number": d["SerialNumber"]} for d in mfa_devices
                ]
                raw_config["mfa_enabled"] = len(mfa_devices) > 0
            except Exception as e:
                logger.debug(f"Could not get MFA devices for {user_name}: {e}")

            # Get groups
            try:
                groups = list(
                    self._paginate(
                        iam, "list_groups_for_user", "Groups", UserName=user_name
                    )
                )
                raw_config["groups"] = [g["GroupName"] for g in groups]
            except Exception as e:
                logger.debug(f"Could not get groups for {user_name}: {e}")

            # Get attached policies
            try:
                policies = list(
                    self._paginate(
                        iam,
                        "list_attached_user_policies",
                        "AttachedPolicies",
                        UserName=user_name,
                    )
                )
                raw_config["attached_policies"] = [
                    {"name": p["PolicyName"], "arn": p["PolicyArn"]} for p in policies
                ]
            except Exception as e:
                logger.debug(f"Could not get attached policies for {user_name}: {e}")

            # Get inline policies
            try:
                inline_policies = list(
                    self._paginate(
                        iam, "list_user_policies", "PolicyNames", UserName=user_name
                    )
                )
                raw_config["inline_policies"] = inline_policies
                raw_config["has_inline_policies"] = len(inline_policies) > 0
            except Exception as e:
                logger.debug(f"Could not get inline policies for {user_name}: {e}")

            # Get password last used (login info)
            try:
                user_detail = iam.get_user(UserName=user_name)
                if "PasswordLastUsed" in user_detail["User"]:
                    raw_config["password_last_used"] = user_detail["User"][
                        "PasswordLastUsed"
                    ].isoformat()
                    raw_config["has_console_access"] = True
                else:
                    raw_config["has_console_access"] = False
            except Exception as e:
                logger.debug(f"Could not get user detail for {user_name}: {e}")

            assets.append(
                Asset(
                    id=user_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region="global",
                    resource_type="aws_iam_user",
                    name=user_name,
                    tags=self._extract_tags(user.get("Tags")),
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    created_at=user["CreateDate"].replace(tzinfo=timezone.utc),
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _collect_roles(self) -> list[Asset]:
        """Collect IAM roles with their configurations."""
        iam = self._get_client("iam")
        assets: list[Asset] = []
        now = self._now()

        for role in self._paginate(iam, "list_roles", "Roles"):
            role_name = role["RoleName"]
            role_arn = role["Arn"]

            raw_config: dict[str, Any] = {
                "role_name": role_name,
                "role_id": role["RoleId"],
                "arn": role_arn,
                "path": role.get("Path", "/"),
                "create_date": role["CreateDate"].isoformat(),
                "assume_role_policy_document": role.get("AssumeRolePolicyDocument"),
                "max_session_duration": role.get("MaxSessionDuration", 3600),
            }

            # Get attached policies
            try:
                policies = list(
                    self._paginate(
                        iam,
                        "list_attached_role_policies",
                        "AttachedPolicies",
                        RoleName=role_name,
                    )
                )
                raw_config["attached_policies"] = [
                    {"name": p["PolicyName"], "arn": p["PolicyArn"]} for p in policies
                ]
            except Exception as e:
                logger.debug(f"Could not get attached policies for role {role_name}: {e}")

            # Get inline policies
            try:
                inline_policies = list(
                    self._paginate(
                        iam, "list_role_policies", "PolicyNames", RoleName=role_name
                    )
                )
                raw_config["inline_policies"] = inline_policies
                raw_config["has_inline_policies"] = len(inline_policies) > 0
            except Exception as e:
                logger.debug(f"Could not get inline policies for role {role_name}: {e}")

            # Get last used info
            try:
                role_detail = iam.get_role(RoleName=role_name)
                last_used = role_detail["Role"].get("RoleLastUsed", {})
                if "LastUsedDate" in last_used:
                    raw_config["last_used_date"] = last_used["LastUsedDate"].isoformat()
                    raw_config["last_used_region"] = last_used.get("Region")
            except Exception as e:
                logger.debug(f"Could not get role detail for {role_name}: {e}")

            # Analyze trust policy for risky configurations
            trust_policy = role.get("AssumeRolePolicyDocument", {})
            raw_config["allows_cross_account"] = self._check_cross_account_trust(
                trust_policy
            )
            raw_config["allows_external_principals"] = self._check_external_trust(
                trust_policy
            )

            assets.append(
                Asset(
                    id=role_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region="global",
                    resource_type="aws_iam_role",
                    name=role_name,
                    tags=self._extract_tags(role.get("Tags")),
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    created_at=role["CreateDate"].replace(tzinfo=timezone.utc),
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _collect_policies(self) -> list[Asset]:
        """Collect customer managed IAM policies."""
        iam = self._get_client("iam")
        assets: list[Asset] = []
        now = self._now()

        # Only get customer managed policies (Scope=Local)
        for policy in self._paginate(
            iam, "list_policies", "Policies", Scope="Local", OnlyAttached=False
        ):
            policy_name = policy["PolicyName"]
            policy_arn = policy["Arn"]

            raw_config: dict[str, Any] = {
                "policy_name": policy_name,
                "policy_id": policy["PolicyId"],
                "arn": policy_arn,
                "path": policy.get("Path", "/"),
                "default_version_id": policy.get("DefaultVersionId"),
                "attachment_count": policy.get("AttachmentCount", 0),
                "is_attachable": policy.get("IsAttachable", True),
                "create_date": policy["CreateDate"].isoformat(),
            }

            if policy.get("UpdateDate"):
                raw_config["update_date"] = policy["UpdateDate"].isoformat()

            assets.append(
                Asset(
                    id=policy_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region="global",
                    resource_type="aws_iam_policy",
                    name=policy_name,
                    tags=self._extract_tags(policy.get("Tags")),
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    created_at=policy["CreateDate"].replace(tzinfo=timezone.utc),
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _collect_groups(self) -> list[Asset]:
        """Collect IAM groups."""
        iam = self._get_client("iam")
        assets: list[Asset] = []
        now = self._now()

        for group in self._paginate(iam, "list_groups", "Groups"):
            group_name = group["GroupName"]
            group_arn = group["Arn"]

            raw_config: dict[str, Any] = {
                "group_name": group_name,
                "group_id": group["GroupId"],
                "arn": group_arn,
                "path": group.get("Path", "/"),
                "create_date": group["CreateDate"].isoformat(),
            }

            # Get group members
            try:
                members = list(
                    self._paginate(
                        iam, "get_group", "Users", GroupName=group_name
                    )
                )
                raw_config["members"] = [m["UserName"] for m in members]
                raw_config["member_count"] = len(members)
            except Exception as e:
                logger.debug(f"Could not get members for group {group_name}: {e}")

            # Get attached policies
            try:
                policies = list(
                    self._paginate(
                        iam,
                        "list_attached_group_policies",
                        "AttachedPolicies",
                        GroupName=group_name,
                    )
                )
                raw_config["attached_policies"] = [
                    {"name": p["PolicyName"], "arn": p["PolicyArn"]} for p in policies
                ]
            except Exception as e:
                logger.debug(f"Could not get attached policies for group {group_name}: {e}")

            assets.append(
                Asset(
                    id=group_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region="global",
                    resource_type="aws_iam_group",
                    name=group_name,
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    created_at=group["CreateDate"].replace(tzinfo=timezone.utc),
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _collect_password_policy(self) -> Asset | None:
        """Collect account password policy."""
        iam = self._get_client("iam")
        now = self._now()

        try:
            response = iam.get_account_password_policy()
            policy = response["PasswordPolicy"]

            raw_config = {
                "minimum_password_length": policy.get("MinimumPasswordLength", 0),
                "require_symbols": policy.get("RequireSymbols", False),
                "require_numbers": policy.get("RequireNumbers", False),
                "require_uppercase_characters": policy.get(
                    "RequireUppercaseCharacters", False
                ),
                "require_lowercase_characters": policy.get(
                    "RequireLowercaseCharacters", False
                ),
                "allow_users_to_change_password": policy.get(
                    "AllowUsersToChangePassword", False
                ),
                "expire_passwords": policy.get("ExpirePasswords", False),
                "max_password_age": policy.get("MaxPasswordAge"),
                "password_reuse_prevention": policy.get("PasswordReusePrevention"),
                "hard_expiry": policy.get("HardExpiry", False),
            }

            return Asset(
                id=f"arn:aws:iam::{self.account_id}:password-policy",
                cloud_provider="aws",
                account_id=self.account_id,
                region="global",
                resource_type="aws_iam_account_password_policy",
                name="Account Password Policy",
                network_exposure=NETWORK_EXPOSURE_ISOLATED,
                last_seen=now,
                raw_config=raw_config,
            )

        except iam.exceptions.NoSuchEntityException:
            logger.info("No password policy configured for account")
            # Return an asset indicating no password policy exists
            return Asset(
                id=f"arn:aws:iam::{self.account_id}:password-policy",
                cloud_provider="aws",
                account_id=self.account_id,
                region="global",
                resource_type="aws_iam_account_password_policy",
                name="Account Password Policy",
                network_exposure=NETWORK_EXPOSURE_ISOLATED,
                last_seen=now,
                raw_config={"exists": False},
            )

    def _collect_account_summary(self) -> Asset:
        """Collect IAM account summary."""
        iam = self._get_client("iam")
        now = self._now()

        response = iam.get_account_summary()
        summary = response["SummaryMap"]

        raw_config = {
            "users": summary.get("Users", 0),
            "groups": summary.get("Groups", 0),
            "roles": summary.get("Roles", 0),
            "policies": summary.get("Policies", 0),
            "account_mfa_enabled": summary.get("AccountMFAEnabled", 0) == 1,
            "account_access_keys_present": summary.get("AccountAccessKeysPresent", 0)
            == 1,
            "mfa_devices": summary.get("MFADevices", 0),
            "mfa_devices_in_use": summary.get("MFADevicesInUse", 0),
            "users_quota": summary.get("UsersQuota"),
            "groups_quota": summary.get("GroupsQuota"),
            "roles_quota": summary.get("RolesQuota"),
            "policies_quota": summary.get("PoliciesQuota"),
        }

        return Asset(
            id=f"arn:aws:iam::{self.account_id}:account-summary",
            cloud_provider="aws",
            account_id=self.account_id,
            region="global",
            resource_type="aws_iam_account_summary",
            name="Account Summary",
            network_exposure=NETWORK_EXPOSURE_ISOLATED,
            last_seen=now,
            raw_config=raw_config,
        )

    def _check_cross_account_trust(self, trust_policy: dict[str, Any]) -> bool:
        """Check if trust policy allows cross-account access."""
        for statement in trust_policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal", {})
            if isinstance(principal, str) and principal == "*":
                return True
            if isinstance(principal, dict):
                aws_principal = principal.get("AWS", [])
                if isinstance(aws_principal, str):
                    aws_principal = [aws_principal]
                for p in aws_principal:
                    if p == "*":
                        return True
                    # Check if it's a different account
                    if ":root" in p or ":user/" in p or ":role/" in p:
                        # Extract account ID from ARN
                        parts = p.split(":")
                        if len(parts) >= 5 and parts[4] != self.account_id:
                            return True
        return False

    def _check_external_trust(self, trust_policy: dict[str, Any]) -> bool:
        """Check if trust policy allows external (non-AWS) principals."""
        for statement in trust_policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal", {})
            if isinstance(principal, dict):
                # Check for federated principals
                if "Federated" in principal:
                    return True
                # Check for service principals (some are external)
                if "Service" in principal:
                    services = principal["Service"]
                    if isinstance(services, str):
                        services = [services]
                    # SAML providers are external
                    for s in services:
                        if "saml" in s.lower():
                            return True
        return False
