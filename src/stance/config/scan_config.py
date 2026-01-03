"""
Scan configuration for Mantissa Stance.

Provides configuration management for scan parameters including
collectors, regions, accounts, schedules, and policies.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class CloudProvider(Enum):
    """Supported cloud providers."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class ScanMode(Enum):
    """Scan operation modes."""

    FULL = "full"  # Complete scan of all resources
    INCREMENTAL = "incremental"  # Only scan changes since last snapshot
    TARGETED = "targeted"  # Scan specific resource types only


@dataclass
class CollectorConfig:
    """Configuration for a specific collector."""

    name: str
    enabled: bool = True
    regions: list[str] = field(default_factory=list)
    resource_types: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "regions": self.regions,
            "resource_types": self.resource_types,
            "options": self.options,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollectorConfig:
        """Create from dictionary."""
        return cls(
            name=data["name"],
            enabled=data.get("enabled", True),
            regions=data.get("regions", []),
            resource_types=data.get("resource_types", []),
            options=data.get("options", {}),
        )


@dataclass
class AccountConfig:
    """Configuration for a cloud account to scan."""

    account_id: str
    cloud_provider: CloudProvider
    name: str = ""
    regions: list[str] = field(default_factory=list)
    assume_role_arn: str = ""  # For cross-account access (AWS)
    project_id: str = ""  # For GCP
    subscription_id: str = ""  # For Azure
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "account_id": self.account_id,
            "cloud_provider": self.cloud_provider.value,
            "name": self.name,
            "regions": self.regions,
            "assume_role_arn": self.assume_role_arn,
            "project_id": self.project_id,
            "subscription_id": self.subscription_id,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AccountConfig:
        """Create from dictionary."""
        return cls(
            account_id=data["account_id"],
            cloud_provider=CloudProvider(data["cloud_provider"]),
            name=data.get("name", ""),
            regions=data.get("regions", []),
            assume_role_arn=data.get("assume_role_arn", ""),
            project_id=data.get("project_id", ""),
            subscription_id=data.get("subscription_id", ""),
            enabled=data.get("enabled", True),
        )


@dataclass
class ScheduleConfig:
    """Configuration for scheduled scans."""

    enabled: bool = True
    expression: str = "rate(1 hour)"  # Cron or rate expression
    timezone: str = "UTC"
    full_scan_expression: str = "cron(0 0 * * ? *)"  # Daily full scan
    incremental_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "enabled": self.enabled,
            "expression": self.expression,
            "timezone": self.timezone,
            "full_scan_expression": self.full_scan_expression,
            "incremental_enabled": self.incremental_enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScheduleConfig:
        """Create from dictionary."""
        return cls(
            enabled=data.get("enabled", True),
            expression=data.get("expression", "rate(1 hour)"),
            timezone=data.get("timezone", "UTC"),
            full_scan_expression=data.get("full_scan_expression", "cron(0 0 * * ? *)"),
            incremental_enabled=data.get("incremental_enabled", True),
        )


@dataclass
class PolicyConfig:
    """Configuration for policy evaluation."""

    policy_dirs: list[str] = field(default_factory=lambda: ["policies/"])
    enabled_policies: list[str] = field(default_factory=list)  # Empty = all
    disabled_policies: list[str] = field(default_factory=list)
    severity_threshold: str = "info"  # Minimum severity to report
    frameworks: list[str] = field(default_factory=list)  # Filter by frameworks

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "policy_dirs": self.policy_dirs,
            "enabled_policies": self.enabled_policies,
            "disabled_policies": self.disabled_policies,
            "severity_threshold": self.severity_threshold,
            "frameworks": self.frameworks,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyConfig:
        """Create from dictionary."""
        return cls(
            policy_dirs=data.get("policy_dirs", ["policies/"]),
            enabled_policies=data.get("enabled_policies", []),
            disabled_policies=data.get("disabled_policies", []),
            severity_threshold=data.get("severity_threshold", "info"),
            frameworks=data.get("frameworks", []),
        )


@dataclass
class StorageConfig:
    """Configuration for storage backends."""

    backend: str = "local"  # local, s3, gcs, azure_blob
    local_path: str = "~/.stance"
    s3_bucket: str = ""
    s3_prefix: str = "stance"
    gcs_bucket: str = ""
    gcs_prefix: str = "stance"
    azure_container: str = ""
    azure_prefix: str = "stance"
    retention_days: int = 90

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "backend": self.backend,
            "local_path": self.local_path,
            "s3_bucket": self.s3_bucket,
            "s3_prefix": self.s3_prefix,
            "gcs_bucket": self.gcs_bucket,
            "gcs_prefix": self.gcs_prefix,
            "azure_container": self.azure_container,
            "azure_prefix": self.azure_prefix,
            "retention_days": self.retention_days,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StorageConfig:
        """Create from dictionary."""
        return cls(
            backend=data.get("backend", "local"),
            local_path=data.get("local_path", "~/.stance"),
            s3_bucket=data.get("s3_bucket", ""),
            s3_prefix=data.get("s3_prefix", "stance"),
            gcs_bucket=data.get("gcs_bucket", ""),
            gcs_prefix=data.get("gcs_prefix", "stance"),
            azure_container=data.get("azure_container", ""),
            azure_prefix=data.get("azure_prefix", "stance"),
            retention_days=data.get("retention_days", 90),
        )


@dataclass
class NotificationConfig:
    """Configuration for notifications."""

    enabled: bool = False
    destinations: list[dict[str, Any]] = field(default_factory=list)
    severity_threshold: str = "high"  # Minimum severity to notify
    rate_limit_per_hour: int = 100

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "enabled": self.enabled,
            "destinations": self.destinations,
            "severity_threshold": self.severity_threshold,
            "rate_limit_per_hour": self.rate_limit_per_hour,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NotificationConfig:
        """Create from dictionary."""
        return cls(
            enabled=data.get("enabled", False),
            destinations=data.get("destinations", []),
            severity_threshold=data.get("severity_threshold", "high"),
            rate_limit_per_hour=data.get("rate_limit_per_hour", 100),
        )


@dataclass
class ScanConfiguration:
    """
    Complete scan configuration.

    This is the main configuration class that contains all settings
    for running Stance scans.
    """

    name: str = "default"
    description: str = ""
    mode: ScanMode = ScanMode.FULL
    collectors: list[CollectorConfig] = field(default_factory=list)
    accounts: list[AccountConfig] = field(default_factory=list)
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    policies: PolicyConfig = field(default_factory=PolicyConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def get_enabled_collectors(self) -> list[str]:
        """Get list of enabled collector names."""
        if not self.collectors:
            # Return default collectors if none configured
            return ["aws_iam", "aws_s3", "aws_ec2", "aws_security"]
        return [c.name for c in self.collectors if c.enabled]

    def get_enabled_accounts(self) -> list[AccountConfig]:
        """Get list of enabled accounts."""
        return [a for a in self.accounts if a.enabled]

    def get_regions_for_account(self, account_id: str) -> list[str]:
        """Get configured regions for an account."""
        for account in self.accounts:
            if account.account_id == account_id:
                return account.regions if account.regions else self._default_regions(
                    account.cloud_provider
                )
        return []

    def _default_regions(self, provider: CloudProvider) -> list[str]:
        """Get default regions for a cloud provider."""
        if provider == CloudProvider.AWS:
            return ["us-east-1"]
        elif provider == CloudProvider.GCP:
            return ["us-central1"]
        elif provider == CloudProvider.AZURE:
            return ["eastus"]
        return []

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "mode": self.mode.value,
            "collectors": [c.to_dict() for c in self.collectors],
            "accounts": [a.to_dict() for a in self.accounts],
            "schedule": self.schedule.to_dict(),
            "policies": self.policies.to_dict(),
            "storage": self.storage.to_dict(),
            "notifications": self.notifications.to_dict(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanConfiguration:
        """Create from dictionary."""
        return cls(
            name=data.get("name", "default"),
            description=data.get("description", ""),
            mode=ScanMode(data.get("mode", "full")),
            collectors=[
                CollectorConfig.from_dict(c) for c in data.get("collectors", [])
            ],
            accounts=[AccountConfig.from_dict(a) for a in data.get("accounts", [])],
            schedule=ScheduleConfig.from_dict(data.get("schedule", {})),
            policies=PolicyConfig.from_dict(data.get("policies", {})),
            storage=StorageConfig.from_dict(data.get("storage", {})),
            notifications=NotificationConfig.from_dict(data.get("notifications", {})),
            created_at=datetime.fromisoformat(data["created_at"])
            if "created_at" in data
            else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data["updated_at"])
            if "updated_at" in data
            else datetime.utcnow(),
        )

    @classmethod
    def from_json(cls, json_str: str) -> ScanConfiguration:
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_file(cls, path: str) -> ScanConfiguration:
        """Load configuration from file."""
        path = os.path.expanduser(path)
        with open(path, "r", encoding="utf-8") as f:
            if path.endswith(".json"):
                return cls.from_dict(json.load(f))
            else:
                # Try to import YAML
                try:
                    import yaml
                    return cls.from_dict(yaml.safe_load(f))
                except ImportError:
                    raise ValueError(
                        "YAML support requires PyYAML. Use JSON format instead."
                    )

    def save(self, path: str) -> None:
        """Save configuration to file."""
        path = os.path.expanduser(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            if path.endswith(".json"):
                json.dump(self.to_dict(), f, indent=2)
            else:
                try:
                    import yaml
                    yaml.safe_dump(self.to_dict(), f, default_flow_style=False)
                except ImportError:
                    raise ValueError(
                        "YAML support requires PyYAML. Use JSON format instead."
                    )


class ConfigurationManager:
    """
    Manages scan configurations.

    Provides methods for loading, saving, and managing multiple
    scan configurations.
    """

    def __init__(self, config_dir: str = "~/.stance/config"):
        """
        Initialize configuration manager.

        Args:
            config_dir: Directory for storing configurations
        """
        self.config_dir = os.path.expanduser(config_dir)
        Path(self.config_dir).mkdir(parents=True, exist_ok=True)

    def list_configurations(self) -> list[str]:
        """List available configuration names."""
        configs = []
        for file in Path(self.config_dir).glob("*.json"):
            configs.append(file.stem)
        for file in Path(self.config_dir).glob("*.yaml"):
            configs.append(file.stem)
        for file in Path(self.config_dir).glob("*.yml"):
            configs.append(file.stem)
        return sorted(set(configs))

    def load(self, name: str = "default") -> ScanConfiguration:
        """
        Load a configuration by name.

        Args:
            name: Configuration name

        Returns:
            ScanConfiguration instance
        """
        # Try different extensions
        for ext in [".json", ".yaml", ".yml"]:
            path = os.path.join(self.config_dir, f"{name}{ext}")
            if os.path.exists(path):
                return ScanConfiguration.from_file(path)

        # Return default configuration if not found
        return ScanConfiguration(name=name)

    def save(self, config: ScanConfiguration, format: str = "json") -> str:
        """
        Save a configuration.

        Args:
            config: Configuration to save
            format: Output format (json or yaml)

        Returns:
            Path to saved file
        """
        ext = ".yaml" if format == "yaml" else ".json"
        path = os.path.join(self.config_dir, f"{config.name}{ext}")
        config.updated_at = datetime.utcnow()
        config.save(path)
        return path

    def delete(self, name: str) -> bool:
        """
        Delete a configuration.

        Args:
            name: Configuration name

        Returns:
            True if deleted, False if not found
        """
        for ext in [".json", ".yaml", ".yml"]:
            path = os.path.join(self.config_dir, f"{name}{ext}")
            if os.path.exists(path):
                os.remove(path)
                return True
        return False

    def get_default(self) -> ScanConfiguration:
        """Get or create the default configuration."""
        return self.load("default")

    def set_default(self, config: ScanConfiguration) -> str:
        """
        Set a configuration as the default.

        Args:
            config: Configuration to set as default

        Returns:
            Path to saved file
        """
        config.name = "default"
        return self.save(config)


def load_config_from_env() -> ScanConfiguration:
    """
    Load configuration from environment variables.

    Environment variables:
        STANCE_CONFIG_FILE: Path to configuration file
        STANCE_COLLECTORS: Comma-separated list of collectors
        STANCE_REGIONS: Comma-separated list of regions
        STANCE_STORAGE_BACKEND: Storage backend (local, s3, gcs, azure_blob)
        STANCE_S3_BUCKET: S3 bucket name
        STANCE_GCS_BUCKET: GCS bucket name
        STANCE_AZURE_CONTAINER: Azure container name
        STANCE_POLICY_DIRS: Comma-separated policy directories
        STANCE_SEVERITY_THRESHOLD: Minimum severity to report

    Returns:
        ScanConfiguration instance
    """
    # Check for config file
    config_file = os.getenv("STANCE_CONFIG_FILE")
    if config_file and os.path.exists(config_file):
        return ScanConfiguration.from_file(config_file)

    # Build configuration from environment
    config = ScanConfiguration()

    # Collectors
    collectors_str = os.getenv("STANCE_COLLECTORS")
    if collectors_str:
        for name in collectors_str.split(","):
            config.collectors.append(CollectorConfig(name=name.strip()))

    # Storage
    backend = os.getenv("STANCE_STORAGE_BACKEND", "local")
    config.storage.backend = backend
    config.storage.s3_bucket = os.getenv("STANCE_S3_BUCKET", "")
    config.storage.gcs_bucket = os.getenv("STANCE_GCS_BUCKET", "")
    config.storage.azure_container = os.getenv("STANCE_AZURE_CONTAINER", "")

    # Policies
    policy_dirs = os.getenv("STANCE_POLICY_DIRS")
    if policy_dirs:
        config.policies.policy_dirs = [d.strip() for d in policy_dirs.split(",")]

    severity = os.getenv("STANCE_SEVERITY_THRESHOLD")
    if severity:
        config.policies.severity_threshold = severity

    return config


def create_default_config() -> ScanConfiguration:
    """
    Create a default scan configuration.

    Returns:
        ScanConfiguration with sensible defaults
    """
    return ScanConfiguration(
        name="default",
        description="Default Mantissa Stance configuration",
        mode=ScanMode.FULL,
        collectors=[
            CollectorConfig(name="aws_iam", enabled=True),
            CollectorConfig(name="aws_s3", enabled=True),
            CollectorConfig(name="aws_ec2", enabled=True),
            CollectorConfig(name="aws_security", enabled=True),
        ],
        schedule=ScheduleConfig(
            enabled=True,
            expression="rate(1 hour)",
            full_scan_expression="cron(0 0 * * ? *)",
        ),
        policies=PolicyConfig(
            policy_dirs=["policies/"],
            severity_threshold="info",
        ),
        storage=StorageConfig(
            backend="local",
            local_path="~/.stance",
        ),
    )
