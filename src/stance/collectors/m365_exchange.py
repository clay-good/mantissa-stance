"""Exchange Online posture collector.

Captures the four Exchange CIS-baseline knobs reachable via Graph (or
Graph beta): modern-auth enforcement, mailbox audit defaults, transport
rules, and the org-wide RemoteDomain forwarding policy.

Most Exchange admin settings live behind Exchange Online PowerShell rather
than Graph. The collector reads what Graph exposes and exposes a minimal
schema; the connect flow can later layer EXO PowerShell sources behind the
same ``graph`` callable without changing the asset shape.

Emits one ``exchange_org_config`` asset (modern auth, audit defaults,
forwarding policy aggregated) plus one ``exchange_transport_rule`` per
rule for inventory.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class M365ExchangeCollector(EntraCollector):
    collector_name = "m365_exchange"
    resource_types = ["exchange_org_config", "exchange_transport_rule"]

    def collect(self) -> AssetCollection:
        org = self._get("/beta/admin/exchange/organizationConfig") or {}
        if "value" in org and isinstance(org["value"], list) and org["value"]:
            org = org["value"][0]

        # Default RemoteDomain governs org-wide auto-forwarding to external.
        remote = self._get(
            "/beta/admin/exchange/remoteDomains/Default"
        ) or {}
        if "value" in remote and isinstance(remote["value"], list) and remote["value"]:
            remote = remote["value"][0]

        modern_auth = bool(
            org.get("oAuth2ClientProfileEnabled", org.get("modernAuthEnabled", False))
        )
        mailbox_audit_default = bool(
            org.get("auditDisabled", True) is False
            and org.get("isMailboxAuditEnabledByDefault", False)
        )
        org_cfg: dict[str, Any] = {
            "modern_auth_enforced": modern_auth,
            "mailbox_audit_enabled_by_default": mailbox_audit_default,
            "auto_forward_enabled_default_remote_domain": bool(
                remote.get("autoForwardEnabled", True)
            ),
            "org_wide_mail_forwarding_allowed": bool(
                remote.get("autoForwardEnabled", True)
            ),
            "smtp_basic_auth_disabled": bool(
                org.get("smtpClientAuthenticationDisabled", False)
            ),
            "default_remote_domain_id": remote.get("identity")
            or remote.get("name", "Default"),
        }
        org_asset = Asset(
            id=f"exchange:org_config:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="exchange_org_config",
            name="exchange-org-config",
            last_seen=self._now(),
            raw_config=org_cfg,
        )

        # Transport rules: Graph beta exposes them as a list. Each rule
        # carries its enabled/disabled state, priority, and a high-level
        # description that we surface for the policy.
        rules: list[Asset] = []
        for r in self._iter("/beta/admin/exchange/transportRules"):
            rid = r.get("id") or r.get("identity") or r.get("name", "")
            cfg = {
                "rule_id": rid,
                "name": r.get("name", ""),
                "state": r.get("state", "Enabled"),
                "priority": r.get("priority", 0),
                "description": r.get("description", ""),
                "mode": r.get("mode", "Enforce"),
                "last_modified": r.get("whenChanged", ""),
                "is_enabled": r.get("state", "Enabled") == "Enabled",
            }
            rules.append(
                Asset(
                    id=f"exchange:transport_rule:{rid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="exchange_transport_rule",
                    name=cfg["name"] or rid,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )

        # Add transport-rule summary fields onto org_cfg so the
        # transport-rules-reviewed policy can evaluate it as a single check.
        org_cfg["transport_rule_count"] = len(rules)
        org_cfg["enabled_transport_rule_count"] = sum(
            1 for a in rules if a.raw_config.get("is_enabled")
        )
        org_cfg["transport_rules_reviewed"] = bool(
            org.get("transportRulesReviewed", False)
        )

        return AssetCollection([org_asset] + rules)
