"""Microsoft Entra directory collector — users, groups, and directory roles
with their assignments (active vs eligible)."""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


_PRIVILEGED_ROLE_NAMES: frozenset[str] = frozenset(
    {
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator",
        "Security Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "User Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Helpdesk Administrator",
        "Conditional Access Administrator",
        "Authentication Administrator",
    }
)


class EntraDirectoryCollector(EntraCollector):
    collector_name = "m365_entra_directory"
    resource_types = [
        "entra_user",
        "entra_group",
        "entra_directory_role",
        "entra_role_assignment",
        "entra_directory_summary",
    ]

    def collect(self) -> AssetCollection:
        assets: list[Asset] = []
        users = list(self._collect_users())
        assets.extend(users)
        assets.extend(self._collect_groups())
        roles, role_assignments = self._collect_roles_and_assignments()
        assets.extend(roles)
        assets.extend(role_assignments)
        assets.append(self._summary(users, roles, role_assignments))
        return AssetCollection(assets)

    # --------------------------------------------------------------- users

    def _collect_users(self) -> list[Asset]:
        out: list[Asset] = []
        for u in self._iter(
            "/v1.0/users?$select=id,userPrincipalName,displayName,accountEnabled,"
            "userType,createdDateTime,signInActivity"
        ):
            uid = u.get("id", "")
            sign_in = u.get("signInActivity") or {}
            cfg = {
                "user_id": uid,
                "user_principal_name": u.get("userPrincipalName", ""),
                "display_name": u.get("displayName", ""),
                "account_enabled": bool(u.get("accountEnabled", True)),
                "user_type": u.get("userType", "Member"),
                "is_guest": u.get("userType", "Member") == "Guest",
                "last_sign_in": (
                    sign_in.get("lastSignInDateTime")
                    or sign_in.get("lastSuccessfulSignInDateTime")
                    or ""
                ),
            }
            out.append(
                Asset(
                    id=f"entra:user:{uid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="entra_user",
                    name=cfg["user_principal_name"] or uid,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )
        return out

    # -------------------------------------------------------------- groups

    def _collect_groups(self) -> list[Asset]:
        out: list[Asset] = []
        for g in self._iter(
            "/v1.0/groups?$select=id,displayName,securityEnabled,mailEnabled,"
            "groupTypes,visibility"
        ):
            gid = g.get("id", "")
            cfg = {
                "group_id": gid,
                "display_name": g.get("displayName", ""),
                "security_enabled": bool(g.get("securityEnabled", False)),
                "mail_enabled": bool(g.get("mailEnabled", False)),
                "group_types": g.get("groupTypes", []) or [],
                "visibility": g.get("visibility", ""),
                "is_dynamic": "DynamicMembership" in (g.get("groupTypes") or []),
            }
            out.append(
                Asset(
                    id=f"entra:group:{gid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="entra_group",
                    name=cfg["display_name"] or gid,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )
        return out

    # ---------------------------------------------------- roles + assignments

    def _collect_roles_and_assignments(self) -> tuple[list[Asset], list[Asset]]:
        # Directory role definitions
        role_defs: dict[str, dict[str, Any]] = {}
        for rd in self._iter(
            "/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,"
            "templateId,isBuiltIn,isPrivileged"
        ):
            rid = rd.get("id", "")
            role_defs[rid] = {
                "role_id": rid,
                "template_id": rd.get("templateId", ""),
                "role_name": rd.get("displayName", ""),
                "is_built_in": bool(rd.get("isBuiltIn", True)),
                "is_privileged": bool(
                    rd.get("isPrivileged", False)
                )
                or rd.get("displayName") in _PRIVILEGED_ROLE_NAMES,
            }

        # Active assignments
        active = list(
            self._iter(
                "/v1.0/roleManagement/directory/roleAssignments?$select=id,"
                "roleDefinitionId,principalId,directoryScopeId"
            )
        )
        # Eligibility schedules (PIM eligible)
        eligible: list[dict[str, Any]] = []
        for path in (
            "/v1.0/roleManagement/directory/roleEligibilitySchedules",
            "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances",
        ):
            eligible.extend(self._iter(path))
            if eligible:
                break

        role_assets: list[Asset] = []
        for rid, meta in role_defs.items():
            role_assets.append(
                Asset(
                    id=f"entra:directory_role:{rid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="entra_directory_role",
                    name=meta["role_name"] or rid,
                    last_seen=self._now(),
                    raw_config=dict(meta),
                )
            )

        assignment_assets: list[Asset] = []
        for entry, status in [(a, "active") for a in active] + [
            (e, "eligible") for e in eligible
        ]:
            aid = entry.get("id", "")
            rdef_id = entry.get("roleDefinitionId", "")
            principal = entry.get("principalId", "")
            scope = entry.get("directoryScopeId", "/")
            meta = role_defs.get(rdef_id, {})
            cfg = {
                "assignment_id": aid,
                "status": status,  # "active" | "eligible"
                "role_id": rdef_id,
                "role_name": meta.get("role_name", ""),
                "is_privileged_role": bool(meta.get("is_privileged", False)),
                "principal_id": principal,
                "directory_scope_id": scope,
                "is_permanent": status == "active",
            }
            assignment_assets.append(
                Asset(
                    id=f"entra:role_assignment:{aid}:{status}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="entra_role_assignment",
                    name=cfg["role_name"] or rdef_id,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )
        return role_assets, assignment_assets

    # ------------------------------------------------------------- summary

    def _summary(
        self,
        users: list[Asset],
        roles: list[Asset],
        role_assignments: list[Asset],
    ) -> Asset:
        privileged_active = [
            a
            for a in role_assignments
            if a.raw_config.get("is_privileged_role")
            and a.raw_config.get("status") == "active"
        ]
        global_admin_active = [
            a
            for a in role_assignments
            if a.raw_config.get("role_name") == "Global Administrator"
            and a.raw_config.get("status") == "active"
        ]
        guests = [u for u in users if u.raw_config.get("is_guest")]

        cfg: dict[str, Any] = {
            "user_count": len(users),
            "guest_count": len(guests),
            "role_count": len(roles),
            "active_role_assignment_count": sum(
                1 for a in role_assignments if a.raw_config.get("status") == "active"
            ),
            "eligible_role_assignment_count": sum(
                1
                for a in role_assignments
                if a.raw_config.get("status") == "eligible"
            ),
            "privileged_active_assignment_count": len(privileged_active),
            "global_admin_active_count": len(global_admin_active),
            "permanent_global_admin_count": len(global_admin_active),
        }
        return Asset(
            id=f"entra:directory_summary:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_directory_summary",
            name="entra-directory",
            last_seen=self._now(),
            raw_config=cfg,
        )
