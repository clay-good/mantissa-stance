"""
Report scheduling and distribution for Mantissa Stance.

Provides report scheduling, delivery channels, and distribution.

Part of Phase 91: Advanced Reporting & Dashboards
"""

from __future__ import annotations

import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union
from urllib.request import Request, urlopen
from urllib.error import URLError
import base64

from stance.dashboards.models import (
    ReportConfig,
    ReportFormat,
    ReportFrequency,
    ScheduledReport,
    ReportDelivery,
    GeneratedReport,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Schedule Status
# =============================================================================

class ScheduleStatus(Enum):
    """Status of a scheduled report."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DISABLED = "disabled"


@dataclass
class ScheduleEntry:
    """
    An entry in the scheduler.

    Attributes:
        schedule: The scheduled report configuration
        status: Current status
        last_error: Last error message if failed
        next_attempt: Next scheduled attempt
        retry_count: Number of retries
    """
    schedule: ScheduledReport
    status: ScheduleStatus = ScheduleStatus.PENDING
    last_error: Optional[str] = None
    next_attempt: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3

    def should_run(self) -> bool:
        """Check if this entry should run now."""
        if self.status == ScheduleStatus.DISABLED:
            return False
        if not self.schedule.enabled:
            return False
        return self.schedule.is_due()

    def mark_running(self) -> None:
        """Mark as currently running."""
        self.status = ScheduleStatus.RUNNING
        self.last_error = None

    def mark_completed(self) -> None:
        """Mark as completed successfully."""
        self.status = ScheduleStatus.COMPLETED
        self.retry_count = 0
        self.last_error = None
        self.schedule.update_after_run(True)

    def mark_failed(self, error: str) -> None:
        """Mark as failed."""
        self.status = ScheduleStatus.FAILED
        self.last_error = error
        self.retry_count += 1
        self.schedule.update_after_run(False)

        # Schedule retry with exponential backoff
        if self.retry_count < self.max_retries:
            backoff = min(300, 30 * (2 ** self.retry_count))  # Max 5 minutes
            self.next_attempt = datetime.utcnow() + timedelta(seconds=backoff)
            self.status = ScheduleStatus.PENDING
        else:
            self.status = ScheduleStatus.DISABLED

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "schedule_id": self.schedule.id,
            "schedule_name": self.schedule.name,
            "status": self.status.value,
            "last_error": self.last_error,
            "next_run": self.schedule.next_run.isoformat() if self.schedule.next_run else None,
            "retry_count": self.retry_count,
            "enabled": self.schedule.enabled,
        }


# =============================================================================
# Delivery Channels
# =============================================================================

class DeliveryChannel(ABC):
    """Abstract base class for report delivery channels."""

    @abstractmethod
    def deliver(self, report: GeneratedReport,
                recipients: List[str],
                settings: Dict[str, Any]) -> bool:
        """
        Deliver a report to recipients.

        Args:
            report: The generated report
            recipients: List of recipient identifiers
            settings: Channel-specific settings

        Returns:
            True if delivery succeeded
        """
        pass

    @abstractmethod
    def validate_settings(self, settings: Dict[str, Any]) -> List[str]:
        """
        Validate delivery settings.

        Args:
            settings: Settings to validate

        Returns:
            List of validation errors (empty if valid)
        """
        pass


class EmailDelivery(DeliveryChannel):
    """Email delivery channel."""

    def __init__(self, smtp_host: str = "localhost", smtp_port: int = 25,
                 username: Optional[str] = None, password: Optional[str] = None,
                 use_tls: bool = True):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_tls = use_tls

    def deliver(self, report: GeneratedReport,
                recipients: List[str],
                settings: Dict[str, Any]) -> bool:
        """Deliver report via email."""
        from_addr = settings.get("from_address", "noreply@mantissa-stance.local")
        subject = settings.get("subject", f"Report: {report.config.title}")

        # In production, this would use smtplib
        # For now, log the delivery attempt
        logger.info(
            f"Email delivery: {subject} to {recipients} from {from_addr}"
        )

        # Simulate email sending (in production, use smtplib)
        try:
            # Build email message
            message = self._build_message(report, from_addr, recipients, subject, settings)
            logger.info(f"Email prepared: {len(message)} bytes")

            # In real implementation:
            # import smtplib
            # with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            #     if self.use_tls:
            #         server.starttls()
            #     if self.username:
            #         server.login(self.username, self.password)
            #     server.sendmail(from_addr, recipients, message)

            return True
        except Exception as e:
            logger.error(f"Email delivery failed: {e}")
            return False

    def _build_message(self, report: GeneratedReport, from_addr: str,
                      recipients: List[str], subject: str,
                      settings: Dict[str, Any]) -> str:
        """Build email message."""
        boundary = "----=_Part_0_123456789"

        headers = [
            f"From: {from_addr}",
            f"To: {', '.join(recipients)}",
            f"Subject: {subject}",
            "MIME-Version: 1.0",
            f'Content-Type: multipart/mixed; boundary="{boundary}"',
        ]

        body = settings.get("body", "Please find attached the security report.")

        parts = [
            "\r\n".join(headers),
            "",
            f"--{boundary}",
            "Content-Type: text/plain; charset=utf-8",
            "",
            body,
            "",
            f"--{boundary}",
        ]

        # Add report as attachment
        filename = settings.get("filename", f"report.{report.format.value}")
        content = report.content

        if isinstance(content, str):
            content_b64 = base64.b64encode(content.encode('utf-8')).decode('ascii')
        else:
            content_b64 = base64.b64encode(content).decode('ascii')

        parts.extend([
            f'Content-Type: application/octet-stream; name="{filename}"',
            "Content-Transfer-Encoding: base64",
            f'Content-Disposition: attachment; filename="{filename}"',
            "",
            content_b64,
            "",
            f"--{boundary}--",
        ])

        return "\r\n".join(parts)

    def validate_settings(self, settings: Dict[str, Any]) -> List[str]:
        """Validate email settings."""
        errors = []

        if "from_address" not in settings:
            errors.append("Missing 'from_address' in email settings")

        from_addr = settings.get("from_address", "")
        if from_addr and "@" not in from_addr:
            errors.append("Invalid 'from_address' format")

        return errors


class WebhookDelivery(DeliveryChannel):
    """Webhook delivery channel."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def deliver(self, report: GeneratedReport,
                recipients: List[str],
                settings: Dict[str, Any]) -> bool:
        """Deliver report via webhook."""
        # Recipients are webhook URLs
        success = True

        for url in recipients:
            try:
                payload = self._build_payload(report, settings)

                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "Mantissa-Stance/1.0",
                }

                # Add custom headers
                custom_headers = settings.get("headers", {})
                headers.update(custom_headers)

                # Add authentication
                auth = settings.get("auth", {})
                if auth.get("type") == "bearer":
                    headers["Authorization"] = f"Bearer {auth.get('token', '')}"
                elif auth.get("type") == "basic":
                    creds = base64.b64encode(
                        f"{auth.get('username', '')}:{auth.get('password', '')}".encode()
                    ).decode()
                    headers["Authorization"] = f"Basic {creds}"

                request = Request(
                    url,
                    data=json.dumps(payload).encode('utf-8'),
                    headers=headers,
                    method="POST"
                )

                with urlopen(request, timeout=self.timeout) as response:
                    if response.status >= 400:
                        logger.error(f"Webhook delivery failed: {response.status}")
                        success = False
                    else:
                        logger.info(f"Webhook delivered to {url}")

            except URLError as e:
                logger.error(f"Webhook delivery failed to {url}: {e}")
                success = False
            except Exception as e:
                logger.error(f"Webhook delivery error: {e}")
                success = False

        return success

    def _build_payload(self, report: GeneratedReport,
                      settings: Dict[str, Any]) -> Dict[str, Any]:
        """Build webhook payload."""
        include_content = settings.get("include_content", False)

        payload = {
            "event": "report_generated",
            "timestamp": datetime.utcnow().isoformat(),
            "report": {
                "id": report.id,
                "title": report.config.title,
                "format": report.format.value,
                "generated_at": report.generated_at.isoformat(),
                "file_size": report.file_size,
                "sections": report.sections,
            }
        }

        if include_content:
            if isinstance(report.content, bytes):
                payload["report"]["content"] = base64.b64encode(report.content).decode()
                payload["report"]["content_encoding"] = "base64"
            else:
                payload["report"]["content"] = report.content

        # Add custom fields
        custom_fields = settings.get("custom_fields", {})
        payload.update(custom_fields)

        return payload

    def validate_settings(self, settings: Dict[str, Any]) -> List[str]:
        """Validate webhook settings."""
        errors = []

        auth = settings.get("auth", {})
        if auth:
            if auth.get("type") == "bearer" and not auth.get("token"):
                errors.append("Bearer auth requires 'token'")
            elif auth.get("type") == "basic":
                if not auth.get("username") or not auth.get("password"):
                    errors.append("Basic auth requires 'username' and 'password'")

        return errors


class StorageDelivery(DeliveryChannel):
    """Storage delivery channel (save to file system or cloud storage)."""

    def __init__(self, base_path: str = "/tmp/reports"):
        self.base_path = base_path

    def deliver(self, report: GeneratedReport,
                recipients: List[str],
                settings: Dict[str, Any]) -> bool:
        """Deliver report to storage."""
        import os

        # Recipients are storage paths or prefixes
        success = True

        for path_prefix in recipients:
            try:
                # Build full path
                timestamp = report.generated_at.strftime("%Y%m%d_%H%M%S")
                filename = f"{report.config.title.replace(' ', '_')}_{timestamp}.{report.format.value}"

                if path_prefix.startswith("s3://"):
                    # AWS S3 storage (would use boto3 in production)
                    full_path = f"{path_prefix}/{filename}"
                    logger.info(f"Would upload to S3: {full_path}")
                    # In production: s3_client.put_object(...)

                elif path_prefix.startswith("gs://"):
                    # GCS storage (would use google-cloud-storage)
                    full_path = f"{path_prefix}/{filename}"
                    logger.info(f"Would upload to GCS: {full_path}")

                else:
                    # Local filesystem
                    full_path = os.path.join(self.base_path, path_prefix, filename)
                    os.makedirs(os.path.dirname(full_path), exist_ok=True)

                    mode = 'wb' if isinstance(report.content, bytes) else 'w'
                    with open(full_path, mode) as f:
                        f.write(report.content)

                    logger.info(f"Report saved to: {full_path}")
                    report.file_path = full_path

            except Exception as e:
                logger.error(f"Storage delivery failed to {path_prefix}: {e}")
                success = False

        return success

    def validate_settings(self, settings: Dict[str, Any]) -> List[str]:
        """Validate storage settings."""
        return []  # No required settings


# =============================================================================
# Report Distributor
# =============================================================================

class ReportDistributor:
    """
    Distributes generated reports to configured channels.
    """

    def __init__(self):
        self.channels: Dict[str, DeliveryChannel] = {
            "email": EmailDelivery(),
            "webhook": WebhookDelivery(),
            "storage": StorageDelivery(),
        }

    def register_channel(self, name: str, channel: DeliveryChannel) -> None:
        """Register a custom delivery channel."""
        self.channels[name] = channel

    def distribute(self, report: GeneratedReport,
                  deliveries: List[ReportDelivery]) -> Dict[str, bool]:
        """
        Distribute a report to all configured channels.

        Args:
            report: The generated report
            deliveries: List of delivery configurations

        Returns:
            Dictionary of channel -> success status
        """
        results = {}

        for delivery in deliveries:
            channel_name = delivery.channel
            channel = self.channels.get(channel_name)

            if not channel:
                logger.warning(f"Unknown delivery channel: {channel_name}")
                results[channel_name] = False
                continue

            # Validate settings
            errors = channel.validate_settings(delivery.settings)
            if errors:
                logger.error(f"Invalid settings for {channel_name}: {errors}")
                results[channel_name] = False
                continue

            # Deliver
            try:
                success = channel.deliver(
                    report,
                    delivery.recipients,
                    delivery.settings
                )
                results[channel_name] = success
            except Exception as e:
                logger.error(f"Delivery failed for {channel_name}: {e}")
                results[channel_name] = False

        return results


# =============================================================================
# Report Scheduler
# =============================================================================

class ReportScheduler:
    """
    Schedules and manages report generation.

    Supports:
    - Scheduled report generation
    - Multiple delivery channels
    - Retry with backoff
    - Concurrent execution
    """

    def __init__(self, max_concurrent: int = 3):
        self.schedules: Dict[str, ScheduleEntry] = {}
        self.distributor = ReportDistributor()
        self.max_concurrent = max_concurrent
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._report_generator: Optional[Callable] = None
        self._data_provider: Optional[Callable] = None

    def set_report_generator(self, generator: Callable) -> None:
        """Set the report generator function."""
        self._report_generator = generator

    def set_data_provider(self, provider: Callable) -> None:
        """Set the data provider function."""
        self._data_provider = provider

    def add_schedule(self, schedule: ScheduledReport) -> ScheduleEntry:
        """Add a scheduled report."""
        with self._lock:
            entry = ScheduleEntry(schedule=schedule)
            self.schedules[schedule.id] = entry
            logger.info(f"Added schedule: {schedule.name} ({schedule.id})")
            return entry

    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a scheduled report."""
        with self._lock:
            if schedule_id in self.schedules:
                del self.schedules[schedule_id]
                logger.info(f"Removed schedule: {schedule_id}")
                return True
            return False

    def get_schedule(self, schedule_id: str) -> Optional[ScheduleEntry]:
        """Get a schedule entry by ID."""
        return self.schedules.get(schedule_id)

    def list_schedules(self) -> List[ScheduleEntry]:
        """List all schedules."""
        return list(self.schedules.values())

    def enable_schedule(self, schedule_id: str) -> bool:
        """Enable a schedule."""
        entry = self.schedules.get(schedule_id)
        if entry:
            entry.schedule.enabled = True
            entry.status = ScheduleStatus.PENDING
            entry.retry_count = 0
            return True
        return False

    def disable_schedule(self, schedule_id: str) -> bool:
        """Disable a schedule."""
        entry = self.schedules.get(schedule_id)
        if entry:
            entry.schedule.enabled = False
            entry.status = ScheduleStatus.DISABLED
            return True
        return False

    def run_now(self, schedule_id: str) -> Optional[GeneratedReport]:
        """Run a scheduled report immediately."""
        entry = self.schedules.get(schedule_id)
        if not entry:
            return None

        return self._execute_schedule(entry)

    def _execute_schedule(self, entry: ScheduleEntry) -> Optional[GeneratedReport]:
        """Execute a single scheduled report."""
        entry.mark_running()

        try:
            # Get data
            if self._data_provider:
                data = self._data_provider(entry.schedule.config)
            else:
                data = self._get_default_data()

            # Generate report
            if self._report_generator:
                report = self._report_generator(data, entry.schedule.config)
            else:
                # Use default generator
                from stance.dashboards.reports import ReportGenerator
                generator = ReportGenerator()
                report = generator.generate(data, entry.schedule.config)

            # Distribute
            if entry.schedule.delivery:
                results = self.distributor.distribute(report, entry.schedule.delivery)
                all_success = all(results.values())

                if not all_success:
                    failed = [k for k, v in results.items() if not v]
                    entry.mark_failed(f"Delivery failed for: {failed}")
                    return report

            entry.mark_completed()
            logger.info(f"Schedule completed: {entry.schedule.name}")
            return report

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Schedule execution failed: {error_msg}")
            entry.mark_failed(error_msg)
            return None

    def _get_default_data(self) -> Dict[str, Any]:
        """Get default report data."""
        return {
            "findings": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "assets": {"total": 0, "with_findings": 0},
            "compliance": {"average_score": 0, "frameworks": {}},
            "trends": {"direction": "stable"},
        }

    def start(self) -> None:
        """Start the scheduler background thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Report scheduler started")

    def stop(self) -> None:
        """Stop the scheduler background thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Report scheduler stopped")

    def _run_loop(self) -> None:
        """Main scheduler loop."""
        while self._running:
            try:
                self._check_schedules()
            except Exception as e:
                logger.error(f"Scheduler error: {e}")

            # Sleep before next check
            time.sleep(60)  # Check every minute

    def _check_schedules(self) -> None:
        """Check and run due schedules."""
        due_entries = []

        with self._lock:
            for entry in self.schedules.values():
                if entry.should_run():
                    due_entries.append(entry)

        # Limit concurrent executions
        due_entries = due_entries[:self.max_concurrent]

        for entry in due_entries:
            self._execute_schedule(entry)

    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status."""
        with self._lock:
            pending = sum(1 for e in self.schedules.values()
                         if e.status == ScheduleStatus.PENDING)
            running = sum(1 for e in self.schedules.values()
                         if e.status == ScheduleStatus.RUNNING)
            failed = sum(1 for e in self.schedules.values()
                        if e.status == ScheduleStatus.FAILED)

            return {
                "running": self._running,
                "total_schedules": len(self.schedules),
                "pending": pending,
                "running_now": running,
                "failed": failed,
                "schedules": [e.to_dict() for e in self.schedules.values()],
            }
