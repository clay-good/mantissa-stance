"""
Plugin interfaces for Mantissa Stance.

Defines the abstract interfaces that specific plugin types must implement.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, TYPE_CHECKING

from stance.plugins.base import Plugin, PluginType, PluginMetadata

if TYPE_CHECKING:
    from stance.models import Asset, AssetCollection, Finding, FindingCollection


class CollectorPlugin(Plugin):
    """
    Interface for custom collector plugins.

    Collector plugins gather assets from cloud providers or other sources.
    """

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        """Get plugin metadata with collector type."""
        metadata = cls._get_collector_metadata()
        # Ensure correct plugin type
        return PluginMetadata(
            name=metadata.name,
            version=metadata.version,
            description=metadata.description,
            author=metadata.author,
            plugin_type=PluginType.COLLECTOR,
            tags=metadata.tags,
            dependencies=metadata.dependencies,
            config_schema=metadata.config_schema,
        )

    @classmethod
    @abstractmethod
    def _get_collector_metadata(cls) -> PluginMetadata:
        """
        Get collector-specific metadata.

        Subclasses should override this instead of get_metadata().

        Returns:
            PluginMetadata for this collector
        """
        pass

    @abstractmethod
    def collect(self, region: str | None = None) -> "AssetCollection":
        """
        Collect assets from the source.

        Args:
            region: Optional region to collect from

        Returns:
            AssetCollection with discovered assets
        """
        pass

    @abstractmethod
    def get_supported_resource_types(self) -> list[str]:
        """
        Get list of resource types this collector handles.

        Returns:
            List of resource type strings (e.g., ["aws_s3_bucket", "aws_ec2_instance"])
        """
        pass


class PolicyPlugin(Plugin):
    """
    Interface for custom policy plugins.

    Policy plugins define security rules and evaluation logic.
    """

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        """Get plugin metadata with policy type."""
        metadata = cls._get_policy_metadata()
        return PluginMetadata(
            name=metadata.name,
            version=metadata.version,
            description=metadata.description,
            author=metadata.author,
            plugin_type=PluginType.POLICY,
            tags=metadata.tags,
            dependencies=metadata.dependencies,
            config_schema=metadata.config_schema,
        )

    @classmethod
    @abstractmethod
    def _get_policy_metadata(cls) -> PluginMetadata:
        """
        Get policy-specific metadata.

        Returns:
            PluginMetadata for this policy
        """
        pass

    @abstractmethod
    def evaluate(self, asset: "Asset") -> list["Finding"]:
        """
        Evaluate an asset against this policy.

        Args:
            asset: Asset to evaluate

        Returns:
            List of findings (empty if asset passes)
        """
        pass

    @abstractmethod
    def get_resource_types(self) -> list[str]:
        """
        Get resource types this policy applies to.

        Returns:
            List of resource type strings
        """
        pass

    @abstractmethod
    def get_severity(self) -> str:
        """
        Get policy severity.

        Returns:
            Severity string ("critical", "high", "medium", "low", "info")
        """
        pass


class EnricherPlugin(Plugin):
    """
    Interface for custom enricher plugins.

    Enricher plugins add additional context to assets or findings.
    """

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        """Get plugin metadata with enricher type."""
        metadata = cls._get_enricher_metadata()
        return PluginMetadata(
            name=metadata.name,
            version=metadata.version,
            description=metadata.description,
            author=metadata.author,
            plugin_type=PluginType.ENRICHER,
            tags=metadata.tags,
            dependencies=metadata.dependencies,
            config_schema=metadata.config_schema,
        )

    @classmethod
    @abstractmethod
    def _get_enricher_metadata(cls) -> PluginMetadata:
        """
        Get enricher-specific metadata.

        Returns:
            PluginMetadata for this enricher
        """
        pass

    @abstractmethod
    def enrich_asset(self, asset: "Asset") -> "Asset":
        """
        Enrich an asset with additional context.

        Args:
            asset: Asset to enrich

        Returns:
            Enriched asset (may be same instance, modified)
        """
        pass

    @abstractmethod
    def enrich_finding(self, finding: "Finding", asset: "Asset") -> "Finding":
        """
        Enrich a finding with additional context.

        Args:
            finding: Finding to enrich
            asset: Related asset

        Returns:
            Enriched finding
        """
        pass

    def get_supported_resource_types(self) -> list[str]:
        """
        Get resource types this enricher handles.

        Returns:
            List of resource types, or empty for all types
        """
        return []


class AlertDestinationPlugin(Plugin):
    """
    Interface for custom alert destination plugins.

    Alert destination plugins send findings to external systems.
    """

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        """Get plugin metadata with alert destination type."""
        metadata = cls._get_alert_metadata()
        return PluginMetadata(
            name=metadata.name,
            version=metadata.version,
            description=metadata.description,
            author=metadata.author,
            plugin_type=PluginType.ALERT_DESTINATION,
            tags=metadata.tags,
            dependencies=metadata.dependencies,
            config_schema=metadata.config_schema,
        )

    @classmethod
    @abstractmethod
    def _get_alert_metadata(cls) -> PluginMetadata:
        """
        Get alert destination-specific metadata.

        Returns:
            PluginMetadata for this alert destination
        """
        pass

    @abstractmethod
    def send_alert(self, finding: "Finding", context: dict[str, Any]) -> bool:
        """
        Send an alert for a finding.

        Args:
            finding: Finding to alert about
            context: Additional context (snapshot_id, etc.)

        Returns:
            True if alert was sent successfully
        """
        pass

    @abstractmethod
    def send_batch_alerts(
        self,
        findings: list["Finding"],
        context: dict[str, Any],
    ) -> tuple[int, int]:
        """
        Send alerts for multiple findings.

        Args:
            findings: Findings to alert about
            context: Additional context

        Returns:
            Tuple of (successful_count, failed_count)
        """
        pass

    def test_connection(self) -> tuple[bool, str]:
        """
        Test connectivity to the alert destination.

        Returns:
            Tuple of (success, message)
        """
        return True, "Connection test not implemented"


class ReportFormatPlugin(Plugin):
    """
    Interface for custom report format plugins.

    Report format plugins generate reports in custom formats.
    """

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        """Get plugin metadata with report format type."""
        metadata = cls._get_report_metadata()
        return PluginMetadata(
            name=metadata.name,
            version=metadata.version,
            description=metadata.description,
            author=metadata.author,
            plugin_type=PluginType.REPORT_FORMAT,
            tags=metadata.tags,
            dependencies=metadata.dependencies,
            config_schema=metadata.config_schema,
        )

    @classmethod
    @abstractmethod
    def _get_report_metadata(cls) -> PluginMetadata:
        """
        Get report format-specific metadata.

        Returns:
            PluginMetadata for this report format
        """
        pass

    @abstractmethod
    def get_format_name(self) -> str:
        """
        Get the format name (used in CLI).

        Returns:
            Format name string (e.g., "pdf", "xlsx", "markdown")
        """
        pass

    @abstractmethod
    def get_file_extension(self) -> str:
        """
        Get the file extension for this format.

        Returns:
            File extension including dot (e.g., ".pdf", ".xlsx")
        """
        pass

    @abstractmethod
    def generate_report(
        self,
        findings: "FindingCollection",
        assets: "AssetCollection",
        context: dict[str, Any],
    ) -> bytes:
        """
        Generate a report in this format.

        Args:
            findings: Findings to include
            assets: Assets to include
            context: Additional context (snapshot_id, timestamp, etc.)

        Returns:
            Report content as bytes
        """
        pass

    def get_mime_type(self) -> str:
        """
        Get MIME type for this format.

        Returns:
            MIME type string
        """
        return "application/octet-stream"
