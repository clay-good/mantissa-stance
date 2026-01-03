"""
PagerDuty alert destination for Mantissa Stance.

Sends alerts to PagerDuty using the Events API v2.
"""

from __future__ import annotations

import hashlib
import json
import logging
import urllib.request
import urllib.error
from typing import Any

from stance.models.finding import Finding, Severity
from stance.alerting.destinations.base import BaseDestination

logger = logging.getLogger(__name__)

PAGERDUTY_EVENTS_API = "https://events.pagerduty.com/v2/enqueue"


class PagerDutyDestination(BaseDestination):
    """
    PagerDuty Events API v2 destination.

    Sends alerts to PagerDuty with proper severity mapping and
    deduplication key generation.

    Example config:
        {
            "routing_key": "your-routing-key",
            "service_name": "Mantissa Stance",
        }
    """

    def __init__(
        self, name: str = "pagerduty", config: dict[str, Any] | None = None
    ) -> None:
        """
        Initialize PagerDuty destination.

        Args:
            name: Destination name
            config: Configuration with routing_key
        """
        config = config or {}
        super().__init__(name, config)
        self._routing_key = config.get("routing_key", "")
        self._service_name = config.get("service_name", "Mantissa Stance")

    def send(self, finding: Finding, context: dict[str, Any]) -> bool:
        """Send alert to PagerDuty."""
        if not self._routing_key:
            logger.error("PagerDuty routing key not configured")
            return False

        try:
            payload = self._build_pagerduty_payload(finding, context)
            self._send_event(payload)
            logger.info(f"Sent PagerDuty alert for finding {finding.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send PagerDuty alert: {e}")
            return False

    def test_connection(self) -> bool:
        """Test PagerDuty connection."""
        if not self._routing_key:
            return False

        # PagerDuty doesn't have a test endpoint, so we just validate the key format
        # A real test would require sending an actual event
        return len(self._routing_key) == 32

    def resolve(self, finding: Finding) -> bool:
        """
        Resolve a PagerDuty incident for a finding.

        Args:
            finding: Finding to resolve

        Returns:
            True if resolution was successful
        """
        if not self._routing_key:
            return False

        try:
            payload = {
                "routing_key": self._routing_key,
                "event_action": "resolve",
                "dedup_key": self._generate_dedup_key(finding),
            }
            self._send_event(payload)
            logger.info(f"Resolved PagerDuty incident for finding {finding.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to resolve PagerDuty incident: {e}")
            return False

    def acknowledge(self, finding: Finding) -> bool:
        """
        Acknowledge a PagerDuty incident for a finding.

        Args:
            finding: Finding to acknowledge

        Returns:
            True if acknowledgment was successful
        """
        if not self._routing_key:
            return False

        try:
            payload = {
                "routing_key": self._routing_key,
                "event_action": "acknowledge",
                "dedup_key": self._generate_dedup_key(finding),
            }
            self._send_event(payload)
            logger.info(f"Acknowledged PagerDuty incident for finding {finding.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to acknowledge PagerDuty incident: {e}")
            return False

    def _build_pagerduty_payload(
        self, finding: Finding, context: dict[str, Any]
    ) -> dict[str, Any]:
        """Build PagerDuty event payload."""
        severity = self._map_severity(finding.severity)
        dedup_key = self._generate_dedup_key(finding)

        # Build custom details
        custom_details: dict[str, Any] = {
            "finding_id": finding.id,
            "finding_type": finding.finding_type.value,
            "status": finding.status.value,
        }

        if finding.asset_id:
            custom_details["asset_id"] = finding.asset_id

        if finding.rule_id:
            custom_details["rule_id"] = finding.rule_id

        if finding.cve_id:
            custom_details["cve_id"] = finding.cve_id
            if finding.cvss_score:
                custom_details["cvss_score"] = finding.cvss_score

        if finding.compliance_frameworks:
            custom_details["compliance_frameworks"] = finding.compliance_frameworks

        # Add context
        custom_details.update(context)

        return {
            "routing_key": self._routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": self.format_title(finding),
                "source": self._service_name,
                "severity": severity,
                "timestamp": finding.first_seen.isoformat() if finding.first_seen else None,
                "component": finding.asset_id or "unknown",
                "group": finding.rule_id or finding.cve_id or "ungrouped",
                "class": finding.finding_type.value,
                "custom_details": custom_details,
            },
            "links": self._build_links(finding),
        }

    def _send_event(self, payload: dict[str, Any]) -> None:
        """Send event to PagerDuty."""
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            PAGERDUTY_EVENTS_API,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status not in (200, 201, 202):
                raise Exception(f"PagerDuty returned status {response.status}")

    def _map_severity(self, severity: Severity) -> str:
        """Map Stance severity to PagerDuty severity."""
        mapping = {
            Severity.CRITICAL: "critical",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "info",
            Severity.INFO: "info",
        }
        return mapping.get(severity, "info")

    def _generate_dedup_key(self, finding: Finding) -> str:
        """Generate deduplication key for finding."""
        key_parts = [
            finding.rule_id or finding.cve_id or "",
            finding.asset_id,
            finding.severity.value,
        ]
        key_string = "|".join(str(p) for p in key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]

    def _build_links(self, finding: Finding) -> list[dict[str, str]]:
        """Build relevant links for the finding."""
        links = []

        if finding.cve_id:
            links.append({
                "href": f"https://nvd.nist.gov/vuln/detail/{finding.cve_id}",
                "text": f"NVD: {finding.cve_id}",
            })

        return links
