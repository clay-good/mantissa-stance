"""
Generic webhook alert destination for Mantissa Stance.

Sends alerts to configurable HTTP endpoints.
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.request
import urllib.error
from typing import Any

from stance.models.finding import Finding, Severity
from stance.alerting.destinations.base import BaseDestination

logger = logging.getLogger(__name__)


class WebhookDestination(BaseDestination):
    """
    Generic HTTP webhook destination.

    Sends alerts to any HTTP endpoint with configurable
    payload format and authentication.

    Example config:
        {
            "url": "https://api.example.com/alerts",
            "method": "POST",
            "headers": {"X-API-Key": "secret"},
            "auth_type": "bearer",  # none, basic, bearer
            "auth_token": "token",
            "payload_format": "json",  # json, form
            "custom_fields": {"source": "stance"},
        }
    """

    def __init__(
        self, name: str = "webhook", config: dict[str, Any] | None = None
    ) -> None:
        """
        Initialize webhook destination.

        Args:
            name: Destination name
            config: Webhook configuration
        """
        config = config or {}
        super().__init__(name, config)
        self._url = config.get("url", "")
        self._method = config.get("method", "POST")
        self._headers = config.get("headers", {})
        self._auth_type = config.get("auth_type", "none")
        self._auth_token = config.get("auth_token", "")
        self._auth_user = config.get("auth_user", "")
        self._auth_password = config.get("auth_password", "")
        self._payload_format = config.get("payload_format", "json")
        self._custom_fields = config.get("custom_fields", {})
        self._timeout = config.get("timeout", 30)

    def send(self, finding: Finding, context: dict[str, Any]) -> bool:
        """Send alert via webhook."""
        if not self._url:
            logger.error("Webhook URL not configured")
            return False

        try:
            payload = self._build_payload(finding, context)
            self._send_request(payload)
            logger.info(f"Sent webhook alert for finding {finding.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False

    def test_connection(self) -> bool:
        """Test webhook connection."""
        if not self._url:
            return False

        try:
            # Try a simple request to the URL
            test_payload = {"test": True, "source": "stance"}
            self._send_request(test_payload)
            return True
        except Exception as e:
            logger.error(f"Webhook connection test failed: {e}")
            return False

    def _build_payload(
        self, finding: Finding, context: dict[str, Any]
    ) -> dict[str, Any]:
        """Build webhook payload."""
        payload = {
            "finding": {
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "type": finding.finding_type.value,
                "status": finding.status.value,
                "asset_id": finding.asset_id,
                "rule_id": finding.rule_id,
                "cve_id": finding.cve_id,
                "cvss_score": finding.cvss_score,
                "compliance_frameworks": finding.compliance_frameworks,
                "remediation_guidance": finding.remediation_guidance,
                "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
                "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
            },
            "context": context,
            "source": "mantissa-stance",
        }

        # Add custom fields
        payload.update(self._custom_fields)

        return payload

    def _send_request(self, payload: dict[str, Any]) -> None:
        """Send HTTP request."""
        headers = dict(self._headers)

        # Add authentication
        if self._auth_type == "bearer":
            headers["Authorization"] = f"Bearer {self._auth_token}"
        elif self._auth_type == "basic":
            credentials = base64.b64encode(
                f"{self._auth_user}:{self._auth_password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"

        # Prepare request body
        if self._payload_format == "json":
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(payload).encode("utf-8")

        request = urllib.request.Request(
            self._url,
            data=data,
            headers=headers,
            method=self._method,
        )

        with urllib.request.urlopen(request, timeout=self._timeout) as response:
            if response.status >= 400:
                raise Exception(f"Webhook returned status {response.status}")


class TeamsDestination(BaseDestination):
    """
    Microsoft Teams webhook destination.

    Sends alerts using Adaptive Cards via incoming webhooks.

    Example config:
        {
            "webhook_url": "https://outlook.office.com/webhook/XXX",
        }
    """

    def __init__(
        self, name: str = "teams", config: dict[str, Any] | None = None
    ) -> None:
        """
        Initialize Teams destination.

        Args:
            name: Destination name
            config: Teams configuration
        """
        config = config or {}
        super().__init__(name, config)
        self._webhook_url = config.get("webhook_url", "")

    def send(self, finding: Finding, context: dict[str, Any]) -> bool:
        """Send alert to Teams."""
        if not self._webhook_url:
            logger.error("Teams webhook URL not configured")
            return False

        try:
            payload = self._build_teams_payload(finding, context)
            self._send_webhook(payload)
            logger.info(f"Sent Teams alert for finding {finding.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send Teams alert: {e}")
            return False

    def test_connection(self) -> bool:
        """Test Teams webhook connection."""
        if not self._webhook_url:
            return False

        try:
            payload = {
                "type": "message",
                "text": "Mantissa Stance connection test successful",
            }
            self._send_webhook(payload)
            return True
        except Exception as e:
            logger.error(f"Teams connection test failed: {e}")
            return False

    def _build_teams_payload(
        self, finding: Finding, context: dict[str, Any]
    ) -> dict[str, Any]:
        """Build Teams Adaptive Card payload."""
        severity_color = self.get_severity_color(finding.severity).lstrip("#")

        facts = [
            {"title": "Severity", "value": finding.severity.value.upper()},
            {"title": "Type", "value": finding.finding_type.value},
            {"title": "Status", "value": finding.status.value},
        ]

        if finding.asset_id:
            facts.append({"title": "Asset", "value": finding.asset_id})

        if finding.rule_id:
            facts.append({"title": "Rule", "value": finding.rule_id})

        if finding.cve_id:
            facts.append({"title": "CVE", "value": finding.cve_id})

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.2",
                        "body": [
                            {
                                "type": "Container",
                                "style": "emphasis",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": finding.title,
                                        "weight": "Bolder",
                                        "size": "Medium",
                                        "wrap": True,
                                    }
                                ],
                            },
                            {
                                "type": "FactSet",
                                "facts": facts,
                            },
                            {
                                "type": "TextBlock",
                                "text": finding.description[:500],
                                "wrap": True,
                            },
                        ],
                    },
                }
            ],
        }

        # Add remediation if available
        if finding.remediation_guidance:
            payload["attachments"][0]["content"]["body"].append({
                "type": "Container",
                "style": "accent",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": "Remediation",
                        "weight": "Bolder",
                    },
                    {
                        "type": "TextBlock",
                        "text": finding.remediation_guidance[:300],
                        "wrap": True,
                    },
                ],
            })

        return payload

    def _send_webhook(self, payload: dict[str, Any]) -> None:
        """Send payload to Teams webhook."""
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status not in (200, 201, 202):
                raise Exception(f"Teams returned status {response.status}")


class JiraDestination(BaseDestination):
    """
    Jira issue creation destination.

    Creates Jira issues for security findings.

    Example config:
        {
            "url": "https://your-domain.atlassian.net",
            "email": "user@example.com",
            "api_token": "your-api-token",
            "project_key": "SEC",
            "issue_type": "Bug",
        }
    """

    def __init__(
        self, name: str = "jira", config: dict[str, Any] | None = None
    ) -> None:
        """
        Initialize Jira destination.

        Args:
            name: Destination name
            config: Jira configuration
        """
        config = config or {}
        super().__init__(name, config)
        self._url = config.get("url", "").rstrip("/")
        self._email = config.get("email", "")
        self._api_token = config.get("api_token", "")
        self._project_key = config.get("project_key", "")
        self._issue_type = config.get("issue_type", "Bug")
        self._labels = config.get("labels", ["security", "stance"])
        self._priority_mapping = config.get("priority_mapping", {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        })

    def send(self, finding: Finding, context: dict[str, Any]) -> bool:
        """Create Jira issue for finding."""
        if not all([self._url, self._email, self._api_token, self._project_key]):
            logger.error("Jira configuration incomplete")
            return False

        try:
            payload = self._build_jira_payload(finding, context)
            self._create_issue(payload)
            logger.info(f"Created Jira issue for finding {finding.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to create Jira issue: {e}")
            return False

    def test_connection(self) -> bool:
        """Test Jira connection."""
        if not all([self._url, self._email, self._api_token]):
            return False

        try:
            # Try to get current user
            request = urllib.request.Request(
                f"{self._url}/rest/api/3/myself",
                headers=self._get_auth_headers(),
            )
            with urllib.request.urlopen(request, timeout=30):
                return True
        except Exception as e:
            logger.error(f"Jira connection test failed: {e}")
            return False

    def _build_jira_payload(
        self, finding: Finding, context: dict[str, Any]
    ) -> dict[str, Any]:
        """Build Jira issue payload."""
        priority = self._priority_mapping.get(
            finding.severity.value, "Medium"
        )

        description = [
            f"*Finding ID:* {finding.id}",
            f"*Type:* {finding.finding_type.value}",
            f"*Severity:* {finding.severity.value.upper()}",
            "",
            "*Description:*",
            finding.description,
        ]

        if finding.asset_id:
            description.extend(["", f"*Affected Asset:* {{code}}{finding.asset_id}{{code}}"])

        if finding.rule_id:
            description.extend(["", f"*Rule:* {finding.rule_id}"])

        if finding.cve_id:
            description.extend([
                "",
                f"*CVE:* [{finding.cve_id}|https://nvd.nist.gov/vuln/detail/{finding.cve_id}]"
            ])
            if finding.cvss_score:
                description.append(f"*CVSS:* {finding.cvss_score}")

        if finding.remediation_guidance:
            description.extend(["", "*Remediation:*", finding.remediation_guidance])

        if finding.compliance_frameworks:
            description.extend([
                "",
                f"*Compliance:* {', '.join(finding.compliance_frameworks)}"
            ])

        return {
            "fields": {
                "project": {"key": self._project_key},
                "summary": self.format_title(finding),
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": "\n".join(description)}
                            ]
                        }
                    ]
                },
                "issuetype": {"name": self._issue_type},
                "labels": self._labels + [finding.severity.value],
            }
        }

    def _create_issue(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create Jira issue."""
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self._url}/rest/api/3/issue",
            data=data,
            headers=self._get_auth_headers(),
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode())

    def _get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers."""
        credentials = base64.b64encode(
            f"{self._email}:{self._api_token}".encode()
        ).decode()
        return {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
        }
