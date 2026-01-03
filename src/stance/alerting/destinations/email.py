"""
Email alert destination for Mantissa Stance.

Sends alerts via SMTP with HTML formatting.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from stance.models.finding import Finding, Severity
from stance.alerting.destinations.base import BaseDestination

logger = logging.getLogger(__name__)


class EmailDestination(BaseDestination):
    """
    SMTP-based email alert destination.

    Sends formatted HTML emails for security findings.

    Example config:
        {
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "smtp_user": "user@example.com",
            "smtp_password": "password",
            "from_address": "stance@example.com",
            "to_addresses": ["security@example.com"],
            "use_tls": true,
        }
    """

    def __init__(
        self, name: str = "email", config: dict[str, Any] | None = None
    ) -> None:
        """
        Initialize email destination.

        Args:
            name: Destination name
            config: SMTP configuration
        """
        config = config or {}
        super().__init__(name, config)
        self._smtp_host = config.get("smtp_host", "localhost")
        self._smtp_port = config.get("smtp_port", 587)
        self._smtp_user = config.get("smtp_user")
        self._smtp_password = config.get("smtp_password")
        self._from_address = config.get("from_address", "stance@localhost")
        self._to_addresses = config.get("to_addresses", [])
        self._use_tls = config.get("use_tls", True)
        self._subject_prefix = config.get("subject_prefix", "[Stance Alert]")

    def send(self, finding: Finding, context: dict[str, Any]) -> bool:
        """Send alert via email."""
        if not self._to_addresses:
            logger.error("No email recipients configured")
            return False

        try:
            msg = self._build_email(finding, context)
            self._send_email(msg)
            logger.info(f"Sent email alert for finding {finding.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    def test_connection(self) -> bool:
        """Test SMTP connection."""
        try:
            if self._use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                    server.starttls(context=context)
                    if self._smtp_user and self._smtp_password:
                        server.login(self._smtp_user, self._smtp_password)
            else:
                with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                    if self._smtp_user and self._smtp_password:
                        server.login(self._smtp_user, self._smtp_password)
            return True
        except Exception as e:
            logger.error(f"Email connection test failed: {e}")
            return False

    def _build_email(
        self, finding: Finding, context: dict[str, Any]
    ) -> MIMEMultipart:
        """Build email message."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = self._build_subject(finding)
        msg["From"] = self._from_address
        msg["To"] = ", ".join(self._to_addresses)

        # Plain text version
        text_body = self._build_text_body(finding)
        msg.attach(MIMEText(text_body, "plain"))

        # HTML version
        html_body = self._build_html_body(finding, context)
        msg.attach(MIMEText(html_body, "html"))

        return msg

    def _build_subject(self, finding: Finding) -> str:
        """Build email subject."""
        severity = finding.severity.value.upper()
        return f"{self._subject_prefix} [{severity}] {finding.title}"

    def _build_text_body(self, finding: Finding) -> str:
        """Build plain text email body."""
        lines = [
            f"Security Finding: {finding.title}",
            "",
            f"Severity: {finding.severity.value.upper()}",
            f"Type: {finding.finding_type.value}",
            f"Status: {finding.status.value}",
            "",
            "Description:",
            finding.description,
            "",
        ]

        if finding.asset_id:
            lines.extend([f"Affected Asset: {finding.asset_id}", ""])

        if finding.rule_id:
            lines.extend([f"Rule ID: {finding.rule_id}", ""])

        if finding.cve_id:
            lines.append(f"CVE: {finding.cve_id}")
            if finding.cvss_score:
                lines.append(f"CVSS Score: {finding.cvss_score}")
            lines.append("")

        if finding.remediation_guidance:
            lines.extend([
                "Remediation:",
                finding.remediation_guidance,
                "",
            ])

        if finding.compliance_frameworks:
            lines.extend([
                "Compliance Frameworks:",
                ", ".join(finding.compliance_frameworks),
                "",
            ])

        lines.extend([
            "---",
            f"Finding ID: {finding.id}",
            "Generated by Mantissa Stance",
        ])

        return "\n".join(lines)

    def _build_html_body(
        self, finding: Finding, context: dict[str, Any]
    ) -> str:
        """Build HTML email body."""
        severity_color = self.get_severity_color(finding.severity)

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header {{ background-color: {severity_color}; color: #ffffff; padding: 20px; }}
                .header h1 {{ margin: 0; font-size: 18px; }}
                .content {{ padding: 20px; }}
                .field {{ margin-bottom: 15px; }}
                .field-label {{ font-weight: bold; color: #666; font-size: 12px; text-transform: uppercase; margin-bottom: 5px; }}
                .field-value {{ color: #333; }}
                .severity {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
                .remediation {{ background-color: #f9f9f9; padding: 15px; border-radius: 4px; margin-top: 15px; }}
                .footer {{ padding: 15px 20px; background-color: #f9f9f9; font-size: 12px; color: #666; }}
                code {{ background-color: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{finding.title}</h1>
                </div>
                <div class="content">
                    <div class="field">
                        <div class="field-label">Severity</div>
                        <div class="field-value">
                            <span class="severity" style="background-color: {severity_color}; color: white;">
                                {finding.severity.value.upper()}
                            </span>
                        </div>
                    </div>

                    <div class="field">
                        <div class="field-label">Type</div>
                        <div class="field-value">{finding.finding_type.value}</div>
                    </div>

                    <div class="field">
                        <div class="field-label">Description</div>
                        <div class="field-value">{finding.description}</div>
                    </div>
        """

        if finding.asset_id:
            html += f"""
                    <div class="field">
                        <div class="field-label">Affected Asset</div>
                        <div class="field-value"><code>{finding.asset_id}</code></div>
                    </div>
            """

        if finding.rule_id:
            html += f"""
                    <div class="field">
                        <div class="field-label">Rule ID</div>
                        <div class="field-value">{finding.rule_id}</div>
                    </div>
            """

        if finding.cve_id:
            html += f"""
                    <div class="field">
                        <div class="field-label">CVE</div>
                        <div class="field-value">
                            <a href="https://nvd.nist.gov/vuln/detail/{finding.cve_id}">{finding.cve_id}</a>
            """
            if finding.cvss_score:
                html += f" (CVSS: {finding.cvss_score})"
            html += """
                        </div>
                    </div>
            """

        if finding.remediation_guidance:
            html += f"""
                    <div class="remediation">
                        <div class="field-label">Remediation</div>
                        <div class="field-value">{finding.remediation_guidance}</div>
                    </div>
            """

        if finding.compliance_frameworks:
            frameworks = ", ".join(finding.compliance_frameworks)
            html += f"""
                    <div class="field">
                        <div class="field-label">Compliance Frameworks</div>
                        <div class="field-value">{frameworks}</div>
                    </div>
            """

        html += f"""
                </div>
                <div class="footer">
                    Finding ID: {finding.id}<br>
                    Generated by Mantissa Stance
                </div>
            </div>
        </body>
        </html>
        """

        return html

    def _send_email(self, msg: MIMEMultipart) -> None:
        """Send email via SMTP."""
        if self._use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                server.starttls(context=context)
                if self._smtp_user and self._smtp_password:
                    server.login(self._smtp_user, self._smtp_password)
                server.sendmail(
                    self._from_address,
                    self._to_addresses,
                    msg.as_string()
                )
        else:
            with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                if self._smtp_user and self._smtp_password:
                    server.login(self._smtp_user, self._smtp_password)
                server.sendmail(
                    self._from_address,
                    self._to_addresses,
                    msg.as_string()
                )
