"""
GCP Cloud Logging collector for Mantissa Stance.

Collects GCP Cloud Logging resources including log sinks, log buckets,
and log-based metrics for security posture assessment.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_ISOLATED,
)

logger = logging.getLogger(__name__)

# Optional GCP imports
try:
    from google.cloud import logging_v2
    from google.cloud.logging_v2 import ConfigServiceV2Client
    from google.cloud.logging_v2 import MetricsServiceV2Client

    GCP_LOGGING_AVAILABLE = True
except ImportError:
    GCP_LOGGING_AVAILABLE = False


class GCPLoggingCollector(BaseCollector):
    """
    Collects GCP Cloud Logging resources.

    Gathers log sinks, log buckets, and log-based metrics.
    All API calls are read-only.
    """

    collector_name = "gcp_logging"
    resource_types = [
        "gcp_logging_sink",
        "gcp_logging_bucket",
        "gcp_logging_metric",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP Logging collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            **kwargs: Additional configuration.
        """
        if not GCP_LOGGING_AVAILABLE:
            raise ImportError(
                "google-cloud-logging is required for GCP logging collector. "
                "Install with: pip install google-cloud-logging"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._config_client: Any = None
        self._metrics_client: Any = None

    def _get_config_client(self) -> ConfigServiceV2Client:
        """Get or create Config Service client."""
        if self._config_client is None:
            self._config_client = ConfigServiceV2Client(credentials=self._credentials)
        return self._config_client

    def _get_metrics_client(self) -> MetricsServiceV2Client:
        """Get or create Metrics Service client."""
        if self._metrics_client is None:
            self._metrics_client = MetricsServiceV2Client(credentials=self._credentials)
        return self._metrics_client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all GCP Logging resources.

        Returns:
            Collection of Logging assets
        """
        assets: list[Asset] = []

        # Collect log sinks
        try:
            assets.extend(self._collect_log_sinks())
        except Exception as e:
            logger.warning(f"Failed to collect log sinks: {e}")

        # Collect log buckets
        try:
            assets.extend(self._collect_log_buckets())
        except Exception as e:
            logger.warning(f"Failed to collect log buckets: {e}")

        # Collect log-based metrics
        try:
            assets.extend(self._collect_log_metrics())
        except Exception as e:
            logger.warning(f"Failed to collect log metrics: {e}")

        return AssetCollection(assets)

    def _collect_log_sinks(self) -> list[Asset]:
        """Collect log sinks."""
        client = self._get_config_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            parent = f"projects/{self._project_id}"
            sinks = client.list_sinks(parent=parent)

            for sink in sinks:
                sink_name = sink.name
                sink_id = f"projects/{self._project_id}/sinks/{sink_name}"

                # Check destination type
                destination = sink.destination or ""
                destination_type = "unknown"
                if destination.startswith("bigquery.googleapis.com"):
                    destination_type = "bigquery"
                elif destination.startswith("storage.googleapis.com"):
                    destination_type = "cloud_storage"
                elif destination.startswith("pubsub.googleapis.com"):
                    destination_type = "pubsub"
                elif destination.startswith("logging.googleapis.com"):
                    destination_type = "logging_bucket"

                # Check if sink is for long-term retention (Storage or BigQuery)
                is_long_term_retention = destination_type in ["cloud_storage", "bigquery"]

                raw_config: dict[str, Any] = {
                    "name": sink_name,
                    "destination": destination,
                    "destination_type": destination_type,
                    "filter": sink.filter_ or "",
                    "is_long_term_retention": is_long_term_retention,
                    "include_children": getattr(sink, 'include_children', False),
                    "writer_identity": sink.writer_identity,
                    "disabled": getattr(sink, 'disabled', False),
                    "exclusions": [
                        {
                            "name": exc.name,
                            "filter": exc.filter_,
                            "disabled": exc.disabled,
                        }
                        for exc in (sink.exclusions or [])
                    ],
                }

                assets.append(
                    Asset(
                        id=sink_id,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region="global",
                        resource_type="gcp_logging_sink",
                        name=sink_name,
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing log sinks: {e}")

        return assets

    def _collect_log_buckets(self) -> list[Asset]:
        """Collect log buckets."""
        client = self._get_config_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            parent = f"projects/{self._project_id}/locations/-"
            buckets = client.list_buckets(parent=parent)

            for bucket in buckets:
                bucket_name = bucket.name
                # Extract just the bucket name from the full path
                short_name = bucket_name.split("/")[-1] if "/" in bucket_name else bucket_name

                # Check retention
                retention_days = bucket.retention_days or 30
                meets_compliance = retention_days >= 90

                raw_config: dict[str, Any] = {
                    "name": short_name,
                    "full_name": bucket_name,
                    "description": bucket.description or "",
                    "retention_days": retention_days,
                    "meets_compliance_retention": meets_compliance,
                    "locked": bucket.locked,
                    "lifecycle_state": str(bucket.lifecycle_state) if bucket.lifecycle_state else "ACTIVE",
                }

                assets.append(
                    Asset(
                        id=bucket_name,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region="global",
                        resource_type="gcp_logging_bucket",
                        name=short_name,
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing log buckets: {e}")

        return assets

    def _collect_log_metrics(self) -> list[Asset]:
        """
        Collect log-based metrics.

        Also checks for required security metrics.
        """
        client = self._get_metrics_client()
        assets: list[Asset] = []
        now = self._now()

        # Track which security metrics exist
        security_metrics = {
            "audit_config_changes": False,
            "iam_custom_role_changes": False,
            "vpc_network_firewall_changes": False,
            "vpc_network_route_changes": False,
            "vpc_network_changes": False,
            "cloud_storage_permission_changes": False,
            "cloud_sql_config_changes": False,
            "project_ownership_changes": False,
        }

        all_metrics: list[Any] = []

        try:
            parent = f"projects/{self._project_id}"
            metrics = client.list_log_metrics(parent=parent)
            all_metrics = list(metrics)

            # Analyze metrics for security monitoring
            for metric in all_metrics:
                filter_text = (metric.filter_ or "").lower()
                name_lower = metric.name.lower()

                # Check for audit config changes
                if "setIamPolicy" in filter_text or "auditconfig" in filter_text.lower():
                    security_metrics["audit_config_changes"] = True

                # Check for IAM custom role changes
                if "iam.roles" in filter_text or "custom_role" in name_lower:
                    security_metrics["iam_custom_role_changes"] = True

                # Check for VPC firewall changes
                if "compute.firewalls" in filter_text or "firewall" in name_lower:
                    security_metrics["vpc_network_firewall_changes"] = True

                # Check for VPC route changes
                if "compute.routes" in filter_text or "route" in name_lower:
                    security_metrics["vpc_network_route_changes"] = True

                # Check for VPC network changes
                if "compute.networks" in filter_text or "network" in name_lower:
                    security_metrics["vpc_network_changes"] = True

                # Check for Cloud Storage permission changes
                if "storage.setIamPermissions" in filter_text or "storage" in name_lower:
                    security_metrics["cloud_storage_permission_changes"] = True

                # Check for Cloud SQL config changes
                if "cloudsql" in filter_text or "sql" in name_lower:
                    security_metrics["cloud_sql_config_changes"] = True

                # Check for project ownership changes
                if "SetIamPolicy" in filter_text and "project" in filter_text:
                    security_metrics["project_ownership_changes"] = True

        except Exception as e:
            logger.error(f"Error listing log metrics: {e}")

        # Create assets for each metric
        for metric in all_metrics:
            metric_name = metric.name
            metric_id = f"projects/{self._project_id}/metrics/{metric_name}"

            raw_config: dict[str, Any] = {
                "name": metric_name,
                "description": metric.description or "",
                "filter": metric.filter_ or "",
                "metric_descriptor": {
                    "type": metric.metric_descriptor.type_ if metric.metric_descriptor else None,
                    "labels": [
                        {"key": label.key, "value_type": str(label.value_type)}
                        for label in (metric.metric_descriptor.labels or [])
                    ] if metric.metric_descriptor else [],
                } if metric.metric_descriptor else None,
                "disabled": getattr(metric, 'disabled', False),
                # Security metric flags - names match policy expressions
                "metric_for_audit_config_changes_exists": security_metrics["audit_config_changes"],
                "metric_for_iam_changes_exists": security_metrics["iam_custom_role_changes"],
                "metric_for_firewall_changes_exists": security_metrics["vpc_network_firewall_changes"],
                "metric_for_route_changes_exists": security_metrics["vpc_network_route_changes"],
                "metric_for_network_changes_exists": security_metrics["vpc_network_changes"],
                "metric_for_storage_permission_changes_exists": security_metrics["cloud_storage_permission_changes"],
                "metric_for_sql_config_changes_exists": security_metrics["cloud_sql_config_changes"],
                "metric_for_project_ownership_changes_exists": security_metrics["project_ownership_changes"],
            }

            assets.append(
                Asset(
                    id=metric_id,
                    cloud_provider="gcp",
                    account_id=self._project_id,
                    region="global",
                    resource_type="gcp_logging_metric",
                    name=metric_name,
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        # If no metrics exist, create synthetic asset to trigger findings
        if not all_metrics:
            assets.append(
                Asset(
                    id=f"projects/{self._project_id}/metrics/none",
                    cloud_provider="gcp",
                    account_id=self._project_id,
                    region="global",
                    resource_type="gcp_logging_metric",
                    name="no-log-metrics-configured",
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    last_seen=now,
                    raw_config={
                        "metric_for_audit_config_changes_exists": False,
                        "metric_for_iam_changes_exists": False,
                        "metric_for_firewall_changes_exists": False,
                        "metric_for_route_changes_exists": False,
                        "metric_for_network_changes_exists": False,
                        "metric_for_storage_permission_changes_exists": False,
                        "metric_for_sql_config_changes_exists": False,
                        "metric_for_project_ownership_changes_exists": False,
                        "is_synthetic": True,
                    },
                )
            )

        return assets
