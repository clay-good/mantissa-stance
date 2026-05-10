"""Google Vault retention/legal-hold posture collector.

Sourced from the Google Vault API (``service.matters()``,
``service.retentionRules()``). Emits one ``gws_vault_retention`` asset per
tenant that summarizes which core services are covered by at least one
retention rule, plus the count of legal holds in effect.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.collectors.saas_base import SaaSCollector
from stance.models import Asset, AssetCollection

logger = logging.getLogger(__name__)


# Workspace "core services" we care about for default retention coverage.
CORE_SERVICES: frozenset[str] = frozenset(
    {"MAIL", "DRIVE", "GROUPS", "HANGOUTS_CHAT", "VOICE", "CALENDAR"}
)


class GWSVaultCollector(SaaSCollector):
    collector_name = "gws_vault"
    resource_types = ["gws_vault_retention"]
    cloud_provider = "google_workspace"

    def __init__(
        self,
        service: Any,
        tenant_id: str,
        primary_domain: str = "",
    ) -> None:
        super().__init__(service, tenant_id)
        self._primary_domain = primary_domain

    def collect(self) -> AssetCollection:
        rules = self._list_retention_rules()
        holds = self._list_legal_holds()

        services_covered: set[str] = set()
        for rule in rules:
            corpus = rule.get("corpus") or rule.get("service") or ""
            if corpus:
                services_covered.add(corpus.upper())

        cfg: dict[str, Any] = {
            "retention_rule_count": len(rules),
            "legal_hold_count": len(holds),
            "services_covered": sorted(services_covered),
            "core_services_covered": sorted(services_covered & CORE_SERVICES),
            "core_services_missing": sorted(CORE_SERVICES - services_covered),
            "all_core_services_covered": (
                CORE_SERVICES.issubset(services_covered) if services_covered else False
            ),
        }
        asset = Asset(
            id=f"gws:vault_retention:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="gws_vault_retention",
            name=self._primary_domain or self._tenant_id,
            last_seen=self._now(),
            raw_config=cfg,
        )
        return AssetCollection([asset])

    # --------------------------------------------------------------- listing

    def _list_retention_rules(self) -> list[dict[str, Any]]:
        try:
            resource = self._service.retentionRules()
        except Exception as e:
            logger.debug("gws_vault: retentionRules() unavailable: %s", e)
            return []
        try:
            response = resource.list().execute() or {}
        except Exception as e:
            logger.debug("gws_vault: retentionRules.list failed: %s", e)
            return []
        rules: list[dict[str, Any]] = []
        rules.extend(response.get("retentionRules", []) or [])
        rules.extend(response.get("rules", []) or [])
        return rules

    def _list_legal_holds(self) -> list[dict[str, Any]]:
        holds: list[dict[str, Any]] = []
        try:
            matters_resource = self._service.matters()
        except Exception as e:
            logger.debug("gws_vault: matters() unavailable: %s", e)
            return holds
        try:
            matters_response = matters_resource.list(view="FULL").execute() or {}
        except Exception as e:
            logger.debug("gws_vault: matters.list failed: %s", e)
            return holds
        for matter in matters_response.get("matters", []) or []:
            mid = matter.get("matterId") or matter.get("name", "")
            if not mid:
                continue
            try:
                holds_resource = matters_resource.holds()
                hold_response = holds_resource.list(matterId=mid).execute() or {}
            except Exception as e:
                logger.debug("gws_vault: holds.list(%s) failed: %s", mid, e)
                continue
            holds.extend(hold_response.get("holds", []) or [])
        return holds
