"""
Slack alert destination for Mantissa Stance.

Sends alerts to Slack channels via incoming webhooks.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import urllib.parse
import urllib.request
import urllib.error
from typing import Any

from stance.models.finding import Finding, Severity
from stance.alerting.destinations.base import BaseDestination

logger = logging.getLogger(__name__)


class SSRFError(Exception):
    """Raised when a URL fails SSRF validation."""
    pass


def _is_production_environment() -> bool:
    """Check if running in a production environment."""
    return any([
        os.environ.get("STANCE_ENV", "").lower() == "production",
        os.environ.get("STANCE_PRODUCTION", "").lower() in ("1", "true", "yes"),
        os.environ.get("ENV", "").lower() == "production",
        os.environ.get("ENVIRONMENT", "").lower() == "production",
        os.environ.get("NODE_ENV", "").lower() == "production",
    ])


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            # AWS/Cloud metadata endpoints
            or ip_str.startswith("169.254.")
        )
    except ValueError:
        return False


def _validate_slack_webhook_url(url: str) -> None:
    """
    Validate a Slack webhook URL to prevent SSRF attacks.

    Slack webhooks should only be to hooks.slack.com domain.

    Args:
        url: The URL to validate

    Raises:
        SSRFError: If the URL fails validation
    """
    if not url:
        raise SSRFError("Webhook URL is empty")

    # Parse the URL
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise SSRFError(f"Invalid URL format: {e}")

    # Check scheme - only allow HTTPS
    if parsed.scheme != "https":
        raise SSRFError(f"Invalid URL scheme: {parsed.scheme}. Only https:// is allowed for Slack webhooks.")

    # Check for empty hostname
    if not parsed.hostname:
        raise SSRFError("URL must have a hostname")

    hostname = parsed.hostname.lower()

    # Slack webhooks should only go to hooks.slack.com or hooks.slack-gov.com
    allowed_hosts = {"hooks.slack.com", "hooks.slack-gov.com"}
    if hostname not in allowed_hosts:
        raise SSRFError(
            f"Invalid Slack webhook hostname: {hostname}. "
            f"Slack webhooks must use {', '.join(allowed_hosts)}"
        )

    # Block localhost and common local aliases (extra protection)
    blocked_hostnames = {
        "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]",
        "metadata.google.internal", "kubernetes.default",
    }
    if hostname in blocked_hostnames:
        raise SSRFError(f"Blocked hostname: {hostname}")

    # Resolve hostname and check all IPs (only in production or when not explicitly skipped)
    if _is_production_environment() or not os.environ.get("PYTEST_CURRENT_TEST"):
        try:
            addr_info = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
            for family, socktype, proto, canonname, sockaddr in addr_info:
                ip = sockaddr[0]
                if _is_private_ip(ip):
                    raise SSRFError(
                        f"Hostname {hostname} resolves to private/internal IP {ip}. "
                        "This is not allowed for security reasons."
                    )
        except socket.gaierror as e:
            raise SSRFError(f"Cannot resolve hostname {hostname}: {e}")


class SlackDestination(BaseDestination):
    """
    Slack webhook-based alert destination.

    Sends rich formatted messages to Slack using Block Kit.

    Example config:
        {
            "webhook_url": "https://hooks.slack.com/services/XXX/YYY/ZZZ",
            "channel": "#security-alerts",  # Optional override
            "username": "Stance Alerts",     # Optional
            "icon_emoji": ":shield:",        # Optional
        }
    """

    def __init__(self, name: str = "slack", config: dict[str, Any] | None = None) -> None:
        """
        Initialize Slack destination.

        Args:
            name: Destination name
            config: Configuration with webhook_url
        """
        config = config or {}
        super().__init__(name, config)
        self._webhook_url = config.get("webhook_url", "")
        self._channel = config.get("channel")
        self._username = config.get("username", "Stance Alerts")
        self._icon_emoji = config.get("icon_emoji", ":shield:")

    def send(self, finding: Finding, context: dict[str, Any]) -> bool:
        """Send alert to Slack."""
        if not self._webhook_url:
            logger.error("Slack webhook URL not configured")
            return False

        try:
            payload = self._build_slack_payload(finding, context)
            self._send_webhook(payload)
            logger.info(f"Sent Slack alert for finding {finding.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False

    def test_connection(self) -> bool:
        """Test Slack webhook connection."""
        if not self._webhook_url:
            return False

        try:
            payload = {
                "text": "Stance alert test - connection successful",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "This is a test message from Mantissa Stance."
                        }
                    }
                ]
            }
            self._send_webhook(payload)
            return True
        except Exception as e:
            logger.error(f"Slack connection test failed: {e}")
            return False

    def _build_slack_payload(
        self, finding: Finding, context: dict[str, Any]
    ) -> dict[str, Any]:
        """Build Slack Block Kit payload."""
        severity_emoji = self._get_severity_emoji(finding.severity)
        severity_color = self.get_severity_color(finding.severity)

        blocks = [
            # Header
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji} {finding.title}",
                    "emoji": True
                }
            },
            # Severity and type
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{finding.severity.value.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Type:*\n{finding.finding_type.value}"
                    }
                ]
            },
            # Description
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{finding.description[:500]}"
                }
            },
        ]

        # Add asset information
        if finding.asset_id:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Affected Asset:*\n`{finding.asset_id}`"
                }
            })

        # Add rule information for misconfigurations
        if finding.rule_id:
            blocks.append({
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Rule ID:*\n{finding.rule_id}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\n{finding.status.value}"
                    }
                ]
            })

        # Add CVE information for vulnerabilities
        if finding.cve_id:
            cve_fields = [
                {
                    "type": "mrkdwn",
                    "text": f"*CVE:*\n<https://nvd.nist.gov/vuln/detail/{finding.cve_id}|{finding.cve_id}>"
                }
            ]
            if finding.cvss_score:
                cve_fields.append({
                    "type": "mrkdwn",
                    "text": f"*CVSS Score:*\n{finding.cvss_score}"
                })
            blocks.append({
                "type": "section",
                "fields": cve_fields
            })

        # Add remediation if available
        if finding.remediation_guidance:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Remediation:*\n{finding.remediation_guidance[:500]}"
                }
            })

        # Add compliance frameworks
        if finding.compliance_frameworks:
            frameworks = ", ".join(finding.compliance_frameworks[:5])
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Compliance: {frameworks}"
                    }
                ]
            })

        # Add divider
        blocks.append({"type": "divider"})

        # Add context footer
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Finding ID: {finding.id}"
                }
            ]
        })

        payload: dict[str, Any] = {
            "blocks": blocks,
            "attachments": [
                {
                    "color": severity_color,
                    "fallback": self.format_title(finding),
                }
            ]
        }

        if self._channel:
            payload["channel"] = self._channel
        if self._username:
            payload["username"] = self._username
        if self._icon_emoji:
            payload["icon_emoji"] = self._icon_emoji

        return payload

    def _send_webhook(self, payload: dict[str, Any]) -> None:
        """Send payload to Slack webhook."""
        # Validate URL to prevent SSRF attacks
        try:
            _validate_slack_webhook_url(self._webhook_url)
        except SSRFError as e:
            logger.error(f"SSRF validation failed for Slack webhook: {e}")
            raise ValueError(f"Invalid webhook URL: {e}")

        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 200:
                raise urllib.error.HTTPError(
                    self._webhook_url,
                    response.status,
                    f"Slack returned status {response.status}",
                    response.headers,
                    None,
                )

    def _get_severity_emoji(self, severity: Severity) -> str:
        """Get emoji for severity level."""
        emojis = {
            Severity.CRITICAL: ":red_circle:",
            Severity.HIGH: ":large_orange_circle:",
            Severity.MEDIUM: ":large_yellow_circle:",
            Severity.LOW: ":large_green_circle:",
            Severity.INFO: ":large_blue_circle:",
        }
        return emojis.get(severity, ":white_circle:")
