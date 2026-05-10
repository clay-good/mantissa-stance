"""Entra federated-domain collector — domains with SAML/WS-Fed trust to an
external IdP. Wildcard or unverified federated domains are a known
account-takeover vector ("nOAuth"-style scenarios).
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class EntraFederationCollector(EntraCollector):
    collector_name = "m365_entra_federation"
    resource_types = ["entra_domain", "entra_federation_summary"]

    def collect(self) -> AssetCollection:
        domain_assets: list[Asset] = []
        federated_count = 0
        unverified_federated: list[str] = []

        for d in self._iter("/v1.0/domains"):
            name = d.get("id") or d.get("name", "")
            auth_type = d.get("authenticationType", "Managed")
            verified = bool(d.get("isVerified", False))
            cfg = {
                "domain": name,
                "authentication_type": auth_type,
                "is_default": bool(d.get("isDefault", False)),
                "is_initial": bool(d.get("isInitial", False)),
                "is_verified": verified,
                "is_federated": auth_type == "Federated",
                "supported_services": d.get("supportedServices", []) or [],
            }
            if cfg["is_federated"]:
                federated_count += 1
                if not verified:
                    unverified_federated.append(name)
            domain_assets.append(
                Asset(
                    id=f"entra:domain:{name}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="entra_domain",
                    name=name,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )

        summary = Asset(
            id=f"entra:federation_summary:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_federation_summary",
            name="federation",
            last_seen=self._now(),
            raw_config={
                "domain_count": len(domain_assets),
                "federated_domain_count": federated_count,
                "unverified_federated_domains": unverified_federated,
                "any_unverified_federated_domain": bool(unverified_federated),
            },
        )
        return AssetCollection(domain_assets + [summary])
