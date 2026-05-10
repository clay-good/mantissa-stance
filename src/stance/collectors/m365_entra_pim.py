"""Microsoft Entra Privileged Identity Management collector.

Reads PIM-eligible role assignments and the activation rules for those
roles. Emits per-role-eligibility assets and a tenant summary used by
``pim-required-for-privileged-roles`` and ``no-permanent-global-admin``
policies.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


PRIVILEGED_ROLE_NAMES: frozenset[str] = frozenset(
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
        "Conditional Access Administrator",
        "Authentication Administrator",
    }
)


class EntraPIMCollector(EntraCollector):
    collector_name = "m365_entra_pim"
    resource_types = [
        "entra_pim_eligibility",
        "entra_pim_role_setting",
        "entra_pim_summary",
    ]

    def collect(self) -> AssetCollection:
        eligibilities: list[Asset] = []
        for entry in self._iter(
            "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
        ):
            eligibilities.append(self._eligibility_asset(entry))

        # Active assignments to identify "permanent" privileged grants.
        active_privileged: list[dict[str, Any]] = []
        active_global_admin: list[dict[str, Any]] = []
        # Build a name lookup
        role_names: dict[str, str] = {}
        for rd in self._iter(
            "/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName"
        ):
            role_names[rd.get("id", "")] = rd.get("displayName", "")
        for a in self._iter(
            "/v1.0/roleManagement/directory/roleAssignments?$select=id,"
            "roleDefinitionId,principalId"
        ):
            rname = role_names.get(a.get("roleDefinitionId", ""), "")
            if rname in PRIVILEGED_ROLE_NAMES:
                active_privileged.append({**a, "role_name": rname})
            if rname == "Global Administrator":
                active_global_admin.append({**a, "role_name": rname})

        # Role policy settings (activation requirements per privileged role).
        role_settings: list[Asset] = []
        for s in self._iter(
            "/v1.0/policies/roleManagementPolicyAssignments?$filter="
            "scopeId+eq+'/'+and+scopeType+eq+'Directory'"
        ):
            role_settings.append(self._role_setting_asset(s))

        eligible_role_names = {
            a.raw_config.get("role_name") for a in eligibilities
        }
        privileged_active_role_names = {
            a["role_name"] for a in active_privileged
        }
        privileged_only_eligible_role_names = (
            (eligible_role_names & PRIVILEGED_ROLE_NAMES)
            - privileged_active_role_names
        )

        summary_cfg: dict[str, Any] = {
            "eligible_assignment_count": len(eligibilities),
            "active_privileged_assignment_count": len(active_privileged),
            "active_global_admin_count": len(active_global_admin),
            "permanent_global_admin_count": len(active_global_admin),
            "privileged_roles_with_only_eligible_assignments": sorted(
                privileged_only_eligible_role_names
            ),
            "privileged_roles_with_permanent_assignments": sorted(
                privileged_active_role_names
            ),
            "all_privileged_roles_via_pim": (
                len(privileged_active_role_names) == 0
                and bool(privileged_only_eligible_role_names)
            ),
        }
        summary = Asset(
            id=f"entra:pim_summary:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_pim_summary",
            name="entra-pim-summary",
            last_seen=self._now(),
            raw_config=summary_cfg,
        )
        return AssetCollection(eligibilities + role_settings + [summary])

    def _eligibility_asset(self, e: dict[str, Any]) -> Asset:
        eid = e.get("id", "")
        cfg = {
            "eligibility_id": eid,
            "principal_id": e.get("principalId", ""),
            "role_id": e.get("roleDefinitionId", ""),
            "role_name": e.get("roleDefinitionDisplayName", "")
            or e.get("roleName", ""),
            "directory_scope_id": e.get("directoryScopeId", "/"),
            "start_date_time": e.get("startDateTime", ""),
            "end_date_time": e.get("endDateTime", ""),
            "is_privileged_role": e.get("roleDefinitionDisplayName", "")
            in PRIVILEGED_ROLE_NAMES
            or e.get("roleName", "") in PRIVILEGED_ROLE_NAMES,
        }
        return Asset(
            id=f"entra:pim_eligibility:{eid}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_pim_eligibility",
            name=cfg["role_name"] or eid,
            last_seen=self._now(),
            raw_config=cfg,
        )

    def _role_setting_asset(self, s: dict[str, Any]) -> Asset:
        sid = s.get("id", "")
        rules = s.get("rules") or []
        # Activation requirement rules tell us if MFA / approval is required.
        requires_mfa = any(
            "MfaRule" in (r.get("@odata.type", "") or "") and r.get("isMfaRequired")
            for r in rules
        )
        requires_approval = any(
            "ApprovalRule" in (r.get("@odata.type", "") or "")
            and r.get("isApprovalRequired", False)
            for r in rules
        )
        max_activation_minutes: int | None = None
        for r in rules:
            if "ExpirationRule" in (r.get("@odata.type", "") or ""):
                duration = r.get("maximumDuration") or ""
                # ISO8601 duration → minutes for the simple "PTxH" / "PTxM" cases.
                try:
                    if duration.startswith("PT") and duration.endswith("H"):
                        max_activation_minutes = int(duration[2:-1]) * 60
                    elif duration.startswith("PT") and duration.endswith("M"):
                        max_activation_minutes = int(duration[2:-1])
                except (ValueError, TypeError):
                    pass
        cfg = {
            "policy_assignment_id": sid,
            "scope_id": s.get("scopeId", "/"),
            "role_definition_id": s.get("roleDefinitionId", ""),
            "requires_mfa_to_activate": requires_mfa,
            "requires_approval_to_activate": requires_approval,
            "max_activation_minutes": max_activation_minutes,
        }
        return Asset(
            id=f"entra:pim_role_setting:{sid}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_pim_role_setting",
            name=cfg["role_definition_id"] or sid,
            last_seen=self._now(),
            raw_config=cfg,
        )
