"""Microsoft Secure Score collector — context for the rest of the
M365 posture. Emits a single ``m365_secure_score`` asset.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class M365SecureScoreCollector(EntraCollector):
    collector_name = "m365_secure_score"
    resource_types = ["m365_secure_score"]

    def collect(self) -> AssetCollection:
        score = self._get(
            "/v1.0/security/secureScores?$top=1&$orderby=createdDateTime desc"
        ) or {}
        first = (score.get("value", []) or [{}])[0]
        cfg: dict[str, Any] = {
            "current_score": first.get("currentScore", 0),
            "max_score": first.get("maxScore", 0),
            "score_percentage": (
                round((first.get("currentScore", 0) / first.get("maxScore", 1)) * 100.0, 2)
                if first.get("maxScore", 0)
                else 0.0
            ),
            "active_user_count": first.get("activeUserCount", 0),
            "licensed_user_count": first.get("licensedUserCount", 0),
            "created_date_time": first.get("createdDateTime", ""),
            "tenant_id": self._tenant_id,
        }
        asset = Asset(
            id=f"m365:secure_score:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="m365_secure_score",
            name="secure-score",
            last_seen=self._now(),
            raw_config=cfg,
        )
        return AssetCollection([asset])
