"""
Google Workspace tenant-level security collector.

Snapshots the tenant security posture: 2-Step Verification enforcement,
password policy, session length, and account recovery settings. Emits a
single ``gws_tenant_security`` asset whose ``raw_config`` is the schema
that ``policies/saas/google_workspace/auth/*`` policies evaluate against.

Settings come from the Cloud Identity Policy API (``policies.list``) and,
where available, the Admin SDK ``customers.get`` endpoint. Both are stubbed
through duck-typed methods on the injected ``service`` so the collector is
trivially testable.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.collectors.saas_base import SaaSCollector
from stance.models import Asset, AssetCollection

logger = logging.getLogger(__name__)


# Map Google policy "settingType" strings to our normalized schema keys.
_POLICY_FIELD_MAP: dict[str, str] = {
    "settings/security.two_step_verification_enforcement": "two_sv_enforced",
    "settings/security.two_step_verification_grace_period": "two_sv_grace_period_days",
    "settings/security.password_strength": "password_strength_enforced",
    "settings/security.password_min_length": "password_min_length",
    "settings/security.password_reuse_prevention": "password_reuse_prevention",
    "settings/security.session_controls": "session_length_seconds",
    "settings/security.user_account_recovery": "account_recovery_enabled_for_users",
    "settings/security.super_admin_account_recovery": (
        "account_recovery_enabled_for_admins"
    ),
    "settings/security.sso": "sso_enforced",
    "settings/security.login_challenges": "login_challenges_enabled",
}


_DEFAULTS: dict[str, Any] = {
    "two_sv_enforced": False,
    "two_sv_grace_period_days": None,
    "password_strength_enforced": False,
    "password_min_length": 8,
    "password_reuse_prevention": 0,
    "session_length_seconds": None,
    "account_recovery_enabled_for_users": True,
    "account_recovery_enabled_for_admins": True,
    "sso_enforced": False,
    "login_challenges_enabled": True,
}


class GWSSecurityCollector(SaaSCollector):
    """Collects tenant-wide Google Workspace security settings."""

    collector_name = "gws_security"
    resource_types = ["gws_tenant_security"]
    cloud_provider = "google_workspace"

    def __init__(
        self,
        service: Any,
        tenant_id: str,
        customer: str = "my_customer",
    ) -> None:
        super().__init__(service, tenant_id)
        self._customer = customer

    def collect(self) -> AssetCollection:
        config: dict[str, Any] = dict(_DEFAULTS)

        # Pull policies from Cloud Identity Policy API (best-effort).
        try:
            self._merge_policies(config)
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("gws_security: policies.list failed: %s", e)

        # Customer-level metadata (domain, postal address, etc.) for context.
        try:
            customer_meta = self._fetch_customer()
            config["primary_domain"] = customer_meta.get("customerDomain", "")
            config["customer_id"] = customer_meta.get("id", self._tenant_id)
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("gws_security: customers.get failed: %s", e)
            config["primary_domain"] = ""
            config["customer_id"] = self._tenant_id

        # Compute user-side 2SV enrollment ratio if the directory is available.
        try:
            ratio = self._compute_2sv_enrollment_ratio()
            config["two_sv_enrolled_user_count"] = ratio["enrolled"]
            config["total_user_count"] = ratio["total"]
            config["two_sv_enrollment_percent"] = ratio["percent"]
            config["super_admin_count"] = ratio["super_admin_count"]
            config["super_admins_without_2sv"] = ratio["super_admins_without_2sv"]
            config["delegated_admin_count"] = ratio["delegated_admin_count"]
        except Exception as e:
            logger.debug("gws_security: 2SV enrollment compute failed: %s", e)
            config["two_sv_enrolled_user_count"] = 0
            config["total_user_count"] = 0
            config["two_sv_enrollment_percent"] = 0.0
            config["super_admin_count"] = 0
            config["super_admins_without_2sv"] = 0
            config["delegated_admin_count"] = 0

        asset = Asset(
            id=f"gws:tenant_security:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="gws_tenant_security",
            name=config.get("primary_domain") or self._tenant_id,
            last_seen=self._now(),
            raw_config=config,
        )
        return AssetCollection([asset])

    # ----------------------------------------------------------- policies API

    def _merge_policies(self, config: dict[str, Any]) -> None:
        policies_resource = self._service.policies()
        request = policies_resource.list(
            filter=f"customer=={self._customer}", pageSize=200
        )
        response = request.execute()
        for policy in response.get("policies", []) or []:
            setting = policy.get("setting", {}) or {}
            type_key = policy.get("type") or setting.get("type", "")
            value = setting.get("value", {}) or {}

            field = _POLICY_FIELD_MAP.get(type_key)
            if not field:
                continue

            config[field] = self._extract_policy_value(field, value)

    @staticmethod
    def _extract_policy_value(field: str, value: dict[str, Any]) -> Any:
        # Cloud Identity policy values are wrapped — pull out the field that
        # most closely maps to our normalized schema.
        if field == "two_sv_enforced":
            return bool(value.get("enforcement", value.get("enabled", False)))
        if field == "two_sv_grace_period_days":
            seconds = value.get("gracePeriod") or value.get("grace_period")
            try:
                return int(seconds) // 86400 if seconds else None
            except (TypeError, ValueError):
                return None
        if field == "password_strength_enforced":
            return bool(value.get("enforce", value.get("enforced", False)))
        if field == "password_min_length":
            return int(value.get("minimumLength", value.get("min_length", 8)) or 8)
        if field == "password_reuse_prevention":
            return int(value.get("reuse", value.get("history", 0)) or 0)
        if field == "session_length_seconds":
            try:
                return int(value.get("webSessionDuration") or 0) or None
            except (TypeError, ValueError):
                return None
        if field in (
            "account_recovery_enabled_for_users",
            "account_recovery_enabled_for_admins",
        ):
            return bool(value.get("enableUserRecovery", value.get("enabled", True)))
        if field == "sso_enforced":
            return bool(value.get("enforced", value.get("enabled", False)))
        if field == "login_challenges_enabled":
            return bool(value.get("enabled", True))
        return value

    # ------------------------------------------------------------- customers

    def _fetch_customer(self) -> dict[str, Any]:
        customers = self._service.customers()
        return customers.get(customerKey=self._customer).execute() or {}

    # ----------------------------------------------------- 2SV enrollment %

    def _compute_2sv_enrollment_ratio(self) -> dict[str, Any]:
        users = self._service.users()
        total = 0
        enrolled = 0
        super_admins = 0
        super_admins_without_2sv = 0
        delegated_admins = 0
        request = users.list(
            customer=self._customer, maxResults=500, projection="basic"
        )
        while request is not None:
            response = request.execute()
            for u in response.get("users", []) or []:
                if u.get("suspended") or u.get("archived"):
                    continue
                total += 1
                two_sv = bool(u.get("isEnrolledIn2Sv"))
                if two_sv:
                    enrolled += 1
                if u.get("isAdmin") and not u.get("isDelegatedAdmin"):
                    super_admins += 1
                    if not two_sv:
                        super_admins_without_2sv += 1
                if u.get("isDelegatedAdmin"):
                    delegated_admins += 1
            list_next = getattr(users, "list_next", None)
            request = list_next(request, response) if list_next else None
        percent = (enrolled / total * 100.0) if total else 0.0
        return {
            "enrolled": enrolled,
            "total": total,
            "percent": round(percent, 2),
            "super_admin_count": super_admins,
            "super_admins_without_2sv": super_admins_without_2sv,
            "delegated_admin_count": delegated_admins,
        }
