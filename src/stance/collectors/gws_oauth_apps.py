"""
Google Workspace OAuth-app inventory collector.

Aggregates third-party OAuth grants (Admin SDK ``tokens.list``) into one
``gws_oauth_app`` asset per ``client_id``. Each asset carries the union of
scopes granted across users, the user count, the highest scope-risk tier
seen, the verification/trust state if known, and a domain-wide-delegation
flag.

Risk classification mirrors the retired vaulytica scanner so existing CIS
mappings carry over: scopes are bucketed into CRITICAL / HIGH / DATA / OTHER,
and the asset's ``scope_risk`` is the worst tier present.

This collector iterates users from a passed-in iterable (typically the
``primaryEmail`` of every active Workspace user) so it composes naturally
with ``GWSDirectoryCollector``. If ``users`` is omitted, it lists them
directly via the injected service.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Iterator

from stance.collectors.saas_base import SaaSCollector
from stance.models import Asset, AssetCollection

logger = logging.getLogger(__name__)


CRITICAL_SCOPES: frozenset[str] = frozenset(
    {
        "https://www.googleapis.com/auth/admin.directory.user",
        "https://www.googleapis.com/auth/admin.directory.group",
        "https://www.googleapis.com/auth/admin.directory.domain",
        "https://www.googleapis.com/auth/admin.directory.orgunit",
        "https://www.googleapis.com/auth/admin.directory.rolemanagement",
        "https://www.googleapis.com/auth/apps.groups.settings",
        "https://www.googleapis.com/auth/cloud-platform",
    }
)

HIGH_SCOPES: frozenset[str] = frozenset(
    {
        "https://www.googleapis.com/auth/drive",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/gmail.send",
        "https://mail.google.com/",
    }
)

DATA_SCOPES: frozenset[str] = frozenset(
    {
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/drive.file",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/calendar",
        "https://www.googleapis.com/auth/calendar.readonly",
        "https://www.googleapis.com/auth/contacts",
        "https://www.googleapis.com/auth/contacts.readonly",
    }
)

_RISK_RANK = {"none": 0, "other": 1, "data": 2, "high": 3, "critical": 4}


def _scope_tier(scope: str) -> str:
    if scope in CRITICAL_SCOPES:
        return "critical"
    if scope in HIGH_SCOPES:
        return "high"
    if scope in DATA_SCOPES:
        return "data"
    return "other"


class GWSOAuthAppsCollector(SaaSCollector):
    """Collects Google Workspace OAuth-app posture (third-party grants)."""

    collector_name = "gws_oauth_apps"
    resource_types = ["gws_oauth_app"]
    cloud_provider = "google_workspace"

    def __init__(
        self,
        service: Any,
        tenant_id: str,
        customer: str = "my_customer",
        primary_domain: str = "",
        users: Iterable[str] | None = None,
        trusted_client_ids: Iterable[str] | None = None,
        domain_wide_delegated_client_ids: Iterable[str] | None = None,
    ) -> None:
        super().__init__(service, tenant_id)
        self._customer = customer
        self._primary_domain = primary_domain.lower()
        self._users = users
        self._trusted_client_ids = set(trusted_client_ids or ())
        self._dwd_client_ids = set(domain_wide_delegated_client_ids or ())

    def collect(self) -> AssetCollection:
        apps: dict[str, dict[str, Any]] = {}

        for user_email in self._iter_users():
            try:
                self._merge_user_tokens(user_email, apps)
            except Exception as e:
                logger.debug(
                    "gws_oauth_apps: tokens.list(%s) failed: %s", user_email, e
                )

        assets = [self._app_to_asset(client_id, app) for client_id, app in apps.items()]
        return AssetCollection(assets)

    # ---------------------------------------------------------- user listing

    def _iter_users(self) -> Iterator[str]:
        if self._users is not None:
            for u in self._users:
                if u:
                    yield u
            return
        try:
            users_resource = self._service.users()
        except Exception:
            return
        request = users_resource.list(
            customer=self._customer, maxResults=500, projection="basic"
        )
        while request is not None:
            response = request.execute() or {}
            for user in response.get("users", []) or []:
                if user.get("suspended") or user.get("archived"):
                    continue
                email = user.get("primaryEmail")
                if email:
                    yield email
            list_next = getattr(users_resource, "list_next", None)
            request = list_next(request, response) if list_next else None

    # ----------------------------------------------------------- token merge

    def _merge_user_tokens(
        self, user_email: str, apps: dict[str, dict[str, Any]]
    ) -> None:
        tokens_resource = self._service.tokens()
        response = tokens_resource.list(userKey=user_email).execute() or {}
        for token in response.get("items", []) or []:
            client_id = token.get("clientId") or ""
            if not client_id:
                continue
            display_text = token.get("displayText") or token.get("displayName") or ""
            scopes = list(token.get("scopes", []) or [])
            anonymous = bool(token.get("anonymous", False))
            native_app = bool(token.get("nativeApp", False))

            entry = apps.setdefault(
                client_id,
                {
                    "client_id": client_id,
                    "display_text": display_text,
                    "scopes": set(),
                    "user_count": 0,
                    "users": [],
                    "is_google_app": client_id.endswith(".apps.googleusercontent.com"),
                    "anonymous": anonymous,
                    "native_app": native_app,
                },
            )
            entry["scopes"].update(scopes)
            entry["user_count"] += 1
            if len(entry["users"]) < 50:
                entry["users"].append(user_email)
            entry["display_text"] = entry["display_text"] or display_text

    # -------------------------------------------------------------- finalize

    def _app_to_asset(self, client_id: str, app: dict[str, Any]) -> Asset:
        scopes = sorted(app["scopes"])
        tiers = {_scope_tier(s) for s in scopes} or {"none"}
        scope_risk = max(tiers, key=lambda t: _RISK_RANK.get(t, 0))
        is_google = bool(app.get("is_google_app"))
        is_trusted = client_id in self._trusted_client_ids
        is_dwd = client_id in self._dwd_client_ids

        # Verification: Workspace exposes a verification flag for OAuth apps via
        # the "appAccess" admin API (not on tokens). Treat Google apps and
        # explicitly-trusted apps as verified; everything else, unverified
        # unless the caller injected the trusted-set.
        verified = is_google or is_trusted

        cfg: dict[str, Any] = {
            "client_id": client_id,
            "display_text": app.get("display_text", ""),
            "scopes": scopes,
            "scope_count": len(scopes),
            "scope_risk": scope_risk,
            "scope_tiers": sorted(tiers),
            "user_count": int(app.get("user_count", 0)),
            "users_sample": list(app.get("users", []))[:10],
            "is_google_app": is_google,
            "is_trusted": is_trusted,
            "verified": verified,
            "domain_wide_delegated": is_dwd,
            "anonymous": bool(app.get("anonymous", False)),
            "native_app": bool(app.get("native_app", False)),
            "has_drive_full_scope": (
                "https://www.googleapis.com/auth/drive" in scopes
            ),
            "has_gmail_full_scope": any(
                s in scopes
                for s in (
                    "https://mail.google.com/",
                    "https://www.googleapis.com/auth/gmail.modify",
                    "https://www.googleapis.com/auth/gmail.compose",
                    "https://www.googleapis.com/auth/gmail.send",
                )
            ),
            "has_admin_directory_scope": any(
                s.startswith("https://www.googleapis.com/auth/admin.directory")
                for s in scopes
            ),
        }

        return Asset(
            id=f"gws:oauth_app:{client_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="gws_oauth_app",
            name=cfg["display_text"] or client_id,
            last_seen=self._now(),
            raw_config=cfg,
        )
