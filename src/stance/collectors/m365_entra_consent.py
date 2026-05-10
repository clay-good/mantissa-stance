"""Microsoft Entra application consent-policy collector.

Captures the tenant's user-consent posture (whether end users may consent to
third-party apps and, if so, in what permission classification) plus the
list of admin-consented OAuth2 permission grants per app.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class EntraConsentCollector(EntraCollector):
    collector_name = "m365_entra_consent"
    resource_types = ["entra_consent_policy", "entra_oauth2_grant"]

    def collect(self) -> AssetCollection:
        assets: list[Asset] = []
        assets.append(self._consent_policy())
        assets.extend(self._grants())
        return AssetCollection(assets)

    def _consent_policy(self) -> Asset:
        # /policies/authorizationPolicy returns a single object with the
        # default user-consent settings applied tenant-wide.
        policy = self._get("/v1.0/policies/authorizationPolicy") or {}
        # On older tenants the response is wrapped in `value: [...]`.
        if "value" in policy and isinstance(policy["value"], list) and policy["value"]:
            policy = policy["value"][0]
        default_user = (
            policy.get("defaultUserRolePermissions", {}) or {}
        )
        permissions = default_user.get("permissionGrantPoliciesAssigned", []) or []

        cfg: dict[str, Any] = {
            "user_consent_for_apps_enabled": bool(
                "ManagePermissionGrantPoliciesByName:user-default" not in permissions
                and any("user" in p.lower() for p in permissions)
            ),
            "permission_grant_policies_assigned": permissions,
            "allow_invites_from": policy.get("allowInvitesFrom", ""),
            "allow_user_consent_for_risky_apps": bool(
                policy.get("allowUserConsentForRiskyApps", True)
            ),
            "block_msol_powershell": bool(
                policy.get("blockMsolPowerShell", False)
            ),
            "user_consent_blocked": (
                permissions == []
                or "ManagePermissionGrantPoliciesByName:user-default-low" in permissions
                and "ManagePermissionGrantPoliciesByName:microsoft-user-default-low"
                in permissions
            ),
        }
        # Tighter derived flag: any "user-default" with non-low permissions
        # implies user consent is allowed for at least low-risk apps.
        cfg["admin_consent_only"] = (
            permissions == []
            or all("low" in p.lower() for p in permissions)
        ) and not cfg["user_consent_for_apps_enabled"]

        return Asset(
            id=f"entra:consent_policy:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_consent_policy",
            name="authorization-policy",
            last_seen=self._now(),
            raw_config=cfg,
        )

    def _grants(self) -> list[Asset]:
        out: list[Asset] = []
        for grant in self._iter("/v1.0/oauth2PermissionGrants"):
            gid = grant.get("id", "")
            cfg = {
                "grant_id": gid,
                "client_id": grant.get("clientId", ""),
                "consent_type": grant.get("consentType", ""),  # AllPrincipals|Principal
                "principal_id": grant.get("principalId", ""),
                "resource_id": grant.get("resourceId", ""),
                "scopes": (grant.get("scope") or "").split(),
                "is_admin_consent": grant.get("consentType") == "AllPrincipals",
            }
            out.append(
                Asset(
                    id=f"entra:oauth2_grant:{gid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="entra_oauth2_grant",
                    name=cfg["client_id"] or gid,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )
        return out
