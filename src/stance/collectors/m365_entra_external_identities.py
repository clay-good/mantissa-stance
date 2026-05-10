"""Entra external-identities (B2B/B2C, cross-tenant access) collector."""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class EntraExternalIdentitiesCollector(EntraCollector):
    collector_name = "m365_entra_external_identities"
    resource_types = ["entra_external_identities", "entra_cross_tenant_access"]

    def collect(self) -> AssetCollection:
        ip = self._get("/beta/policies/externalIdentitiesPolicy") or {}
        # Authorization policy holds the legacy "allowInvitesFrom" knob.
        ap = self._get("/v1.0/policies/authorizationPolicy") or {}
        if "value" in ap and isinstance(ap["value"], list) and ap["value"]:
            ap = ap["value"][0]
        ext_cfg: dict[str, Any] = {
            "allow_invites_from": ap.get("allowInvitesFrom", ""),
            "guest_user_role_id": ap.get("guestUserRoleId", ""),
            "allow_external_identities_to_leave": bool(
                ip.get("allowExternalIdentitiesToLeave", True)
            ),
            "allow_deletion_of_oth_user_accounts": bool(
                ip.get("allowDeletionOfOthUserAccounts", False)
            ),
            "guest_invites_restricted": ap.get("allowInvitesFrom", "")
            in ("adminsAndGuestInviters", "none"),
        }
        ext = Asset(
            id=f"entra:external_identities:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_external_identities",
            name="external-identities",
            last_seen=self._now(),
            raw_config=ext_cfg,
        )

        # Cross-tenant access policy: per-partner inbound/outbound.
        partners: list[Asset] = []
        for partner in self._iter(
            "/v1.0/policies/crossTenantAccessPolicy/partners"
        ):
            tid = partner.get("tenantId", "")
            inbound = partner.get("b2bCollaborationInbound") or {}
            outbound = partner.get("b2bCollaborationOutbound") or {}
            cfg = {
                "tenant_id": tid,
                "is_service_provider": bool(
                    partner.get("isServiceProvider", False)
                ),
                "inbound_users_and_groups_apps_default": (
                    inbound.get("usersAndGroups", {}) or {}
                ).get("accessType", ""),
                "outbound_users_and_groups_apps_default": (
                    outbound.get("usersAndGroups", {}) or {}
                ).get("accessType", ""),
                "inbound_trust_settings": partner.get("inboundTrust") or {},
            }
            partners.append(
                Asset(
                    id=f"entra:cross_tenant_access:{tid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="entra_cross_tenant_access",
                    name=tid,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )

        return AssetCollection([ext] + partners)
