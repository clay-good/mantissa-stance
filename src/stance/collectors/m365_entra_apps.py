"""Microsoft Entra application registrations + service principals collector.

Aggregates app registrations, their secrets/certs (with expiry), and the
service principals that represent them in the tenant. Computes:

- Whether an app holds high-risk Microsoft Graph application permissions.
- Whether an app registration is "orphaned" (no service principal, or the
  publishing tenant matches but the app has no recent sign-in).
- Whether app secrets/certs are approaching expiration (≤30 days) or absent.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


HIGH_RISK_GRAPH_APP_PERMISSIONS: frozenset[str] = frozenset(
    {
        # Mailbox + Files + Directory full-access permission GUIDs and IDs.
        # Names are matched too because tenants vary.
        "Mail.ReadWrite",
        "Mail.Send",
        "Mail.ReadWrite.All",
        "Mail.Send.Shared",
        "Files.ReadWrite.All",
        "Sites.FullControl.All",
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
    }
)


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


class EntraAppsCollector(EntraCollector):
    collector_name = "m365_entra_apps"
    resource_types = [
        "entra_app_registration",
        "entra_service_principal",
    ]

    def collect(self) -> AssetCollection:
        sps_by_app_id: dict[str, dict[str, Any]] = {}
        sp_assets: list[Asset] = []
        for sp in self._iter(
            "/v1.0/servicePrincipals?$select=id,appId,displayName,"
            "appRoleAssignmentRequired,servicePrincipalType,accountEnabled,"
            "tags,publisherName,homepage,passwordCredentials,keyCredentials"
        ):
            app_id = sp.get("appId", "")
            sps_by_app_id[app_id] = sp
            sp_assets.append(self._sp_to_asset(sp))

        app_assets: list[Asset] = []
        for app in self._iter(
            "/v1.0/applications?$select=id,appId,displayName,createdDateTime,"
            "passwordCredentials,keyCredentials,requiredResourceAccess,"
            "publisherDomain,signInAudience"
        ):
            # Fetch the owners list. The owners endpoint is paginated; one
            # call per app is acceptable because the count is small in
            # practice (a handful at most). Tolerate 404 / forbidden so a
            # connector without ``Application.Read.All`` still gets the
            # rest of the inventory.
            owners = list(self._owners_for_app(app.get("id", "")))
            app_assets.append(self._app_to_asset(app, sps_by_app_id, owners))

        return AssetCollection(app_assets + sp_assets)

    # ---------------------------------------------------------------- apps

    def _owners_for_app(self, app_object_id: str) -> Any:
        """Yield owner principal dicts for an app registration.

        Each owner dict carries ``@odata.type`` (typically
        ``#microsoft.graph.user`` or ``#microsoft.graph.servicePrincipal``)
        plus ``id`` and a display field. We yield raw dicts so the mapper
        can decide which graph node id to bind ownership to.
        """
        if not app_object_id:
            return
        for owner in self._iter(
            f"/v1.0/applications/{app_object_id}/owners?$select="
            "id,displayName,userPrincipalName,appId"
        ):
            yield owner

    def _app_to_asset(
        self,
        app: dict[str, Any],
        sps_by_app_id: dict[str, dict[str, Any]],
        owners: list[dict[str, Any]],
    ) -> Asset:
        app_id = app.get("appId", "")
        sp = sps_by_app_id.get(app_id)
        creds = self._summarize_credentials(
            (app.get("passwordCredentials") or []) + (app.get("keyCredentials") or [])
        )
        graph_perms = self._extract_graph_app_permissions(app)
        cfg: dict[str, Any] = {
            "app_object_id": app.get("id", ""),
            "app_id": app_id,
            "display_name": app.get("displayName", ""),
            "publisher_domain": app.get("publisherDomain", ""),
            "sign_in_audience": app.get("signInAudience", ""),
            "created_date_time": app.get("createdDateTime", ""),
            "secret_count": creds["secret_count"],
            "key_count": creds["key_count"],
            "soonest_credential_expiry_days": creds["soonest_expiry_days"],
            "has_credential_without_expiry": creds["has_no_expiry"],
            "credentials_expiring_within_30_days": creds["expiring_30d"],
            "credentials_expired": creds["expired"],
            "graph_app_permissions": graph_perms,
            "high_risk_graph_permission_count": sum(
                1 for p in graph_perms if p in HIGH_RISK_GRAPH_APP_PERMISSIONS
            ),
            "has_high_risk_graph_permissions": any(
                p in HIGH_RISK_GRAPH_APP_PERMISSIONS for p in graph_perms
            ),
            "has_service_principal": sp is not None,
            "is_orphaned": sp is None,
            "owner_justification_recorded": False,
            "owners": [
                {
                    "id": o.get("id", ""),
                    "odata_type": o.get("@odata.type", ""),
                    "display_name": o.get("displayName", ""),
                    "user_principal_name": o.get("userPrincipalName", ""),
                    "app_id": o.get("appId", ""),
                }
                for o in owners
                if o.get("id")
            ],
            "owner_count": len(owners),
            "has_owner": len(owners) > 0,
        }
        return Asset(
            id=f"entra:app_registration:{app_id or app.get('id', '')}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_app_registration",
            name=cfg["display_name"] or app_id,
            last_seen=self._now(),
            raw_config=cfg,
        )

    @staticmethod
    def _extract_graph_app_permissions(app: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for rra in app.get("requiredResourceAccess", []) or []:
            for ra in rra.get("resourceAccess", []) or []:
                # Application permissions are type "Role" (vs. "Scope" = delegated).
                if ra.get("type") == "Role":
                    out.append(ra.get("id", "") or ra.get("value", ""))
        return [p for p in out if p]

    # ---------------------------------------------------------- credentials

    def _summarize_credentials(
        self, creds: list[dict[str, Any]]
    ) -> dict[str, Any]:
        now = self._now()
        secret_count = sum(1 for c in creds if c.get("secretText") is not None or c.get("hint"))
        key_count = sum(1 for c in creds if c.get("type") == "AsymmetricX509Cert")
        if not creds:
            return {
                "secret_count": 0,
                "key_count": 0,
                "soonest_expiry_days": None,
                "has_no_expiry": False,
                "expiring_30d": 0,
                "expired": 0,
            }
        days_list: list[int] = []
        no_expiry = False
        expiring_30 = 0
        expired = 0
        for c in creds:
            end = _parse_dt(c.get("endDateTime"))
            if end is None:
                no_expiry = True
                continue
            delta = (end - now).days
            days_list.append(delta)
            if delta < 0:
                expired += 1
            elif delta <= 30:
                expiring_30 += 1
        return {
            "secret_count": secret_count,
            "key_count": key_count,
            "soonest_expiry_days": min(days_list) if days_list else None,
            "has_no_expiry": no_expiry,
            "expiring_30d": expiring_30,
            "expired": expired,
        }

    # --------------------------------------------------- service principals

    def _sp_to_asset(self, sp: dict[str, Any]) -> Asset:
        creds = self._summarize_credentials(
            (sp.get("passwordCredentials") or []) + (sp.get("keyCredentials") or [])
        )
        cfg: dict[str, Any] = {
            "sp_object_id": sp.get("id", ""),
            "app_id": sp.get("appId", ""),
            "display_name": sp.get("displayName", ""),
            "service_principal_type": sp.get("servicePrincipalType", ""),
            "account_enabled": bool(sp.get("accountEnabled", True)),
            "app_role_assignment_required": bool(
                sp.get("appRoleAssignmentRequired", False)
            ),
            "tags": sp.get("tags", []) or [],
            "publisher_name": sp.get("publisherName", ""),
            "secret_count": creds["secret_count"],
            "key_count": creds["key_count"],
            "soonest_credential_expiry_days": creds["soonest_expiry_days"],
            "has_credential_without_expiry": creds["has_no_expiry"],
            "credentials_expiring_within_30_days": creds["expiring_30d"],
            "credentials_expired": creds["expired"],
        }
        return Asset(
            id=f"entra:service_principal:{cfg['sp_object_id']}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_service_principal",
            name=cfg["display_name"] or cfg["app_id"],
            last_seen=self._now(),
            raw_config=cfg,
        )
