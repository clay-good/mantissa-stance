"""Microsoft Entra authentication-methods posture collector.

Reads the tenant authentication-methods policy plus per-method usage from
``reports/authenticationMethods/userRegistrationDetails``. Emits a single
``entra_auth_methods_summary`` asset that captures:

- Which methods are enabled tenant-wide (FIDO2, WHfB, passkey, SMS, etc.).
- The percentage of active users registered for any passwordless method.
- Whether SSPR is enabled and whether MFA is required to use it.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


PASSWORDLESS_METHODS: frozenset[str] = frozenset(
    {
        "fido2",
        "windowsHelloForBusiness",
        "microsoftAuthenticatorPasswordless",
        "microsoftAuthenticator",  # only when phoneSignInEnabled = true
        "passkey",
    }
)


class EntraAuthMethodsCollector(EntraCollector):
    collector_name = "m365_entra_auth_methods"
    resource_types = ["entra_auth_methods_summary"]

    def collect(self) -> AssetCollection:
        policy = self._get("/v1.0/policies/authenticationMethodsPolicy") or {}
        methods = {
            (m.get("id") or ""): m
            for m in policy.get("authenticationMethodConfigurations", []) or []
        }

        enabled = {mid: (m.get("state") == "enabled") for mid, m in methods.items()}
        passwordless_enabled_methods = sorted(
            mid
            for mid, en in enabled.items()
            if en and mid in PASSWORDLESS_METHODS
        )

        # Registration details — paginated. We only need totals.
        registered = 0
        total_active = 0
        passwordless_capable = 0
        for entry in self._iter(
            "/v1.0/reports/authenticationMethods/userRegistrationDetails"
        ):
            total_active += 1
            if entry.get("isMfaRegistered"):
                registered += 1
            if entry.get("isPasswordlessCapable") or entry.get(
                "isPasswordlessRegistered"
            ):
                passwordless_capable += 1

        sspr = self._get("/v1.0/policies/authenticationStrengthPolicies") or {}
        sspr_policy = self._get("/beta/policies/passwordResetPolicies") or {}

        cfg: dict[str, Any] = {
            "passwordless_methods_enabled": passwordless_enabled_methods,
            "any_passwordless_enabled": len(passwordless_enabled_methods) > 0,
            "user_count_with_registration_data": total_active,
            "users_mfa_registered": registered,
            "users_passwordless_capable": passwordless_capable,
            "passwordless_adoption_percent": (
                round(passwordless_capable / total_active * 100.0, 2)
                if total_active
                else 0.0
            ),
            "sspr_enabled": bool(sspr_policy.get("enabledForUsers", False)),
            "sspr_requires_mfa": bool(
                sspr_policy.get("registrationRequired", False)
                or sspr_policy.get("authenticationMethodRequiredCount", 0) >= 2
            ),
        }
        asset = Asset(
            id=f"entra:auth_methods_summary:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_auth_methods_summary",
            name="auth-methods",
            last_seen=self._now(),
            raw_config=cfg,
        )
        return AssetCollection([asset])
