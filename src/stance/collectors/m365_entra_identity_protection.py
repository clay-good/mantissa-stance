"""Entra Identity Protection policy-state collector.

Reports whether sign-in-risk and user-risk policies are enabled at the
tenant. Stance is point-in-time; the *events* belong to mantissa-log.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class EntraIdentityProtectionCollector(EntraCollector):
    collector_name = "m365_entra_identity_protection"
    resource_types = ["entra_identity_protection_policies"]

    def collect(self) -> AssetCollection:
        sign_in = self._get(
            "/beta/identityProtection/policies/signInRiskPolicy"
        ) or {}
        user_risk = self._get(
            "/beta/identityProtection/policies/userRiskPolicy"
        ) or {}
        mfa_reg = self._get(
            "/beta/identityProtection/policies/mfaRegistrationPolicy"
        ) or {}

        cfg: dict[str, Any] = {
            "sign_in_risk_policy_enabled": bool(sign_in.get("isEnabled", False)),
            "user_risk_policy_enabled": bool(user_risk.get("isEnabled", False)),
            "mfa_registration_policy_enabled": bool(mfa_reg.get("isEnabled", False)),
            "all_identity_protection_policies_enabled": bool(
                sign_in.get("isEnabled", False)
                and user_risk.get("isEnabled", False)
            ),
        }
        asset = Asset(
            id=f"entra:identity_protection_policies:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_identity_protection_policies",
            name="identity-protection",
            last_seen=self._now(),
            raw_config=cfg,
        )
        return AssetCollection([asset])
