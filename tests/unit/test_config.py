"""
Unit tests for configuration management module.
"""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from stance.config import (
    AccountConfig,
    CloudProvider,
    CollectorConfig,
    ConfigurationManager,
    NotificationConfig,
    PolicyConfig,
    ScanConfiguration,
    ScanMode,
    ScheduleConfig,
    StorageConfig,
    create_default_config,
    load_config_from_env,
)


class TestCloudProvider:
    """Tests for CloudProvider enum."""

    def test_cloud_provider_values(self):
        """Test CloudProvider enum has expected values."""
        assert CloudProvider.AWS.value == "aws"
        assert CloudProvider.GCP.value == "gcp"
        assert CloudProvider.AZURE.value == "azure"

    def test_cloud_provider_from_value(self):
        """Test creating CloudProvider from value."""
        assert CloudProvider("aws") == CloudProvider.AWS
        assert CloudProvider("gcp") == CloudProvider.GCP
        assert CloudProvider("azure") == CloudProvider.AZURE


class TestScanMode:
    """Tests for ScanMode enum."""

    def test_scan_mode_values(self):
        """Test ScanMode enum has expected values."""
        assert ScanMode.FULL.value == "full"
        assert ScanMode.INCREMENTAL.value == "incremental"
        assert ScanMode.TARGETED.value == "targeted"

    def test_scan_mode_from_value(self):
        """Test creating ScanMode from value."""
        assert ScanMode("full") == ScanMode.FULL
        assert ScanMode("incremental") == ScanMode.INCREMENTAL


class TestCollectorConfig:
    """Tests for CollectorConfig dataclass."""

    def test_collector_config_creation(self):
        """Test creating a CollectorConfig."""
        config = CollectorConfig(name="aws_iam")

        assert config.name == "aws_iam"
        assert config.enabled is True
        assert config.regions == []
        assert config.resource_types == []
        assert config.options == {}

    def test_collector_config_with_options(self):
        """Test CollectorConfig with all options."""
        config = CollectorConfig(
            name="aws_s3",
            enabled=True,
            regions=["us-east-1", "us-west-2"],
            resource_types=["aws_s3_bucket"],
            options={"max_buckets": 1000},
        )

        assert config.regions == ["us-east-1", "us-west-2"]
        assert config.resource_types == ["aws_s3_bucket"]
        assert config.options == {"max_buckets": 1000}

    def test_collector_config_disabled(self):
        """Test disabled CollectorConfig."""
        config = CollectorConfig(name="aws_ec2", enabled=False)
        assert config.enabled is False

    def test_collector_config_to_dict(self):
        """Test CollectorConfig serialization."""
        config = CollectorConfig(
            name="aws_iam",
            enabled=True,
            regions=["us-east-1"],
        )

        data = config.to_dict()

        assert data["name"] == "aws_iam"
        assert data["enabled"] is True
        assert data["regions"] == ["us-east-1"]

    def test_collector_config_from_dict(self):
        """Test CollectorConfig deserialization."""
        data = {
            "name": "aws_s3",
            "enabled": False,
            "regions": ["eu-west-1"],
            "options": {"key": "value"},
        }

        config = CollectorConfig.from_dict(data)

        assert config.name == "aws_s3"
        assert config.enabled is False
        assert config.regions == ["eu-west-1"]
        assert config.options == {"key": "value"}

    def test_collector_config_from_dict_minimal(self):
        """Test CollectorConfig from minimal dict."""
        data = {"name": "aws_iam"}
        config = CollectorConfig.from_dict(data)

        assert config.name == "aws_iam"
        assert config.enabled is True
        assert config.regions == []


class TestAccountConfig:
    """Tests for AccountConfig dataclass."""

    def test_account_config_creation(self):
        """Test creating an AccountConfig."""
        config = AccountConfig(
            account_id="123456789012",
            cloud_provider=CloudProvider.AWS,
        )

        assert config.account_id == "123456789012"
        assert config.cloud_provider == CloudProvider.AWS
        assert config.name == ""
        assert config.regions == []
        assert config.enabled is True

    def test_account_config_with_all_fields(self):
        """Test AccountConfig with all fields."""
        config = AccountConfig(
            account_id="123456789012",
            cloud_provider=CloudProvider.AWS,
            name="Production",
            regions=["us-east-1", "us-west-2"],
            assume_role_arn="arn:aws:iam::123456789012:role/StanceRole",
            enabled=True,
        )

        assert config.name == "Production"
        assert config.assume_role_arn == "arn:aws:iam::123456789012:role/StanceRole"

    def test_account_config_gcp(self):
        """Test AccountConfig for GCP."""
        config = AccountConfig(
            account_id="my-gcp-project",
            cloud_provider=CloudProvider.GCP,
            project_id="my-gcp-project",
        )

        assert config.cloud_provider == CloudProvider.GCP
        assert config.project_id == "my-gcp-project"

    def test_account_config_azure(self):
        """Test AccountConfig for Azure."""
        config = AccountConfig(
            account_id="subscription-123",
            cloud_provider=CloudProvider.AZURE,
            subscription_id="subscription-123",
        )

        assert config.cloud_provider == CloudProvider.AZURE
        assert config.subscription_id == "subscription-123"

    def test_account_config_to_dict(self):
        """Test AccountConfig serialization."""
        config = AccountConfig(
            account_id="123456789012",
            cloud_provider=CloudProvider.AWS,
            name="Test",
        )

        data = config.to_dict()

        assert data["account_id"] == "123456789012"
        assert data["cloud_provider"] == "aws"
        assert data["name"] == "Test"

    def test_account_config_from_dict(self):
        """Test AccountConfig deserialization."""
        data = {
            "account_id": "123456789012",
            "cloud_provider": "aws",
            "name": "Production",
            "regions": ["us-east-1"],
        }

        config = AccountConfig.from_dict(data)

        assert config.account_id == "123456789012"
        assert config.cloud_provider == CloudProvider.AWS
        assert config.name == "Production"


class TestScheduleConfig:
    """Tests for ScheduleConfig dataclass."""

    def test_schedule_config_defaults(self):
        """Test ScheduleConfig with default values."""
        config = ScheduleConfig()

        assert config.enabled is True
        assert config.expression == "rate(1 hour)"
        assert config.timezone == "UTC"
        assert config.incremental_enabled is True

    def test_schedule_config_custom(self):
        """Test ScheduleConfig with custom values."""
        config = ScheduleConfig(
            enabled=True,
            expression="rate(30 minutes)",
            timezone="US/Pacific",
            full_scan_expression="cron(0 6 * * ? *)",
            incremental_enabled=True,
        )

        assert config.expression == "rate(30 minutes)"
        assert config.timezone == "US/Pacific"

    def test_schedule_config_disabled(self):
        """Test disabled ScheduleConfig."""
        config = ScheduleConfig(enabled=False)
        assert config.enabled is False

    def test_schedule_config_to_dict(self):
        """Test ScheduleConfig serialization."""
        config = ScheduleConfig()
        data = config.to_dict()

        assert "enabled" in data
        assert "expression" in data
        assert "timezone" in data

    def test_schedule_config_from_dict(self):
        """Test ScheduleConfig deserialization."""
        data = {
            "enabled": False,
            "expression": "rate(2 hours)",
        }

        config = ScheduleConfig.from_dict(data)

        assert config.enabled is False
        assert config.expression == "rate(2 hours)"


class TestPolicyConfig:
    """Tests for PolicyConfig dataclass."""

    def test_policy_config_defaults(self):
        """Test PolicyConfig with default values."""
        config = PolicyConfig()

        assert config.policy_dirs == ["policies/"]
        assert config.enabled_policies == []
        assert config.disabled_policies == []
        assert config.severity_threshold == "info"
        assert config.frameworks == []

    def test_policy_config_custom(self):
        """Test PolicyConfig with custom values."""
        config = PolicyConfig(
            policy_dirs=["policies/", "custom_policies/"],
            enabled_policies=["aws-s3-001", "aws-iam-001"],
            severity_threshold="high",
            frameworks=["cis-aws", "pci-dss"],
        )

        assert len(config.policy_dirs) == 2
        assert "aws-s3-001" in config.enabled_policies
        assert config.severity_threshold == "high"

    def test_policy_config_to_dict(self):
        """Test PolicyConfig serialization."""
        config = PolicyConfig()
        data = config.to_dict()

        assert data["policy_dirs"] == ["policies/"]
        assert data["severity_threshold"] == "info"

    def test_policy_config_from_dict(self):
        """Test PolicyConfig deserialization."""
        data = {
            "severity_threshold": "critical",
            "frameworks": ["cis-aws"],
        }

        config = PolicyConfig.from_dict(data)

        assert config.severity_threshold == "critical"
        assert config.frameworks == ["cis-aws"]


class TestStorageConfig:
    """Tests for StorageConfig dataclass."""

    def test_storage_config_defaults(self):
        """Test StorageConfig with default values."""
        config = StorageConfig()

        assert config.backend == "local"
        assert config.local_path == "~/.stance"
        assert config.s3_bucket == ""
        assert config.retention_days == 90

    def test_storage_config_s3(self):
        """Test StorageConfig for S3."""
        config = StorageConfig(
            backend="s3",
            s3_bucket="my-stance-bucket",
            s3_prefix="production",
            retention_days=180,
        )

        assert config.backend == "s3"
        assert config.s3_bucket == "my-stance-bucket"
        assert config.s3_prefix == "production"

    def test_storage_config_gcs(self):
        """Test StorageConfig for GCS."""
        config = StorageConfig(
            backend="gcs",
            gcs_bucket="my-gcs-bucket",
        )

        assert config.backend == "gcs"
        assert config.gcs_bucket == "my-gcs-bucket"

    def test_storage_config_azure(self):
        """Test StorageConfig for Azure Blob."""
        config = StorageConfig(
            backend="azure_blob",
            azure_container="stance-container",
        )

        assert config.backend == "azure_blob"
        assert config.azure_container == "stance-container"

    def test_storage_config_to_dict(self):
        """Test StorageConfig serialization."""
        config = StorageConfig(backend="s3", s3_bucket="bucket")
        data = config.to_dict()

        assert data["backend"] == "s3"
        assert data["s3_bucket"] == "bucket"

    def test_storage_config_from_dict(self):
        """Test StorageConfig deserialization."""
        data = {
            "backend": "s3",
            "s3_bucket": "my-bucket",
            "retention_days": 365,
        }

        config = StorageConfig.from_dict(data)

        assert config.backend == "s3"
        assert config.s3_bucket == "my-bucket"
        assert config.retention_days == 365


class TestNotificationConfig:
    """Tests for NotificationConfig dataclass."""

    def test_notification_config_defaults(self):
        """Test NotificationConfig with default values."""
        config = NotificationConfig()

        assert config.enabled is False
        assert config.destinations == []
        assert config.severity_threshold == "high"
        assert config.rate_limit_per_hour == 100

    def test_notification_config_enabled(self):
        """Test enabled NotificationConfig."""
        config = NotificationConfig(
            enabled=True,
            destinations=[
                {"type": "slack", "webhook_url": "https://hooks.slack.com/test"},
            ],
            severity_threshold="critical",
            rate_limit_per_hour=50,
        )

        assert config.enabled is True
        assert len(config.destinations) == 1
        assert config.severity_threshold == "critical"

    def test_notification_config_to_dict(self):
        """Test NotificationConfig serialization."""
        config = NotificationConfig(enabled=True)
        data = config.to_dict()

        assert data["enabled"] is True
        assert "destinations" in data

    def test_notification_config_from_dict(self):
        """Test NotificationConfig deserialization."""
        data = {
            "enabled": True,
            "severity_threshold": "medium",
        }

        config = NotificationConfig.from_dict(data)

        assert config.enabled is True
        assert config.severity_threshold == "medium"


class TestScanConfiguration:
    """Tests for ScanConfiguration dataclass."""

    def test_scan_configuration_defaults(self):
        """Test ScanConfiguration with default values."""
        config = ScanConfiguration()

        assert config.name == "default"
        assert config.description == ""
        assert config.mode == ScanMode.FULL
        assert config.collectors == []
        assert config.accounts == []
        assert isinstance(config.schedule, ScheduleConfig)
        assert isinstance(config.policies, PolicyConfig)
        assert isinstance(config.storage, StorageConfig)
        assert isinstance(config.notifications, NotificationConfig)

    def test_scan_configuration_with_collectors(self):
        """Test ScanConfiguration with collectors."""
        config = ScanConfiguration(
            name="production",
            collectors=[
                CollectorConfig(name="aws_iam"),
                CollectorConfig(name="aws_s3"),
            ],
        )

        assert config.name == "production"
        assert len(config.collectors) == 2

    def test_scan_configuration_with_accounts(self):
        """Test ScanConfiguration with accounts."""
        config = ScanConfiguration(
            accounts=[
                AccountConfig(
                    account_id="123456789012",
                    cloud_provider=CloudProvider.AWS,
                ),
                AccountConfig(
                    account_id="987654321098",
                    cloud_provider=CloudProvider.AWS,
                    enabled=False,
                ),
            ],
        )

        assert len(config.accounts) == 2

    def test_get_enabled_collectors_with_config(self):
        """Test getting enabled collectors from config."""
        config = ScanConfiguration(
            collectors=[
                CollectorConfig(name="aws_iam", enabled=True),
                CollectorConfig(name="aws_s3", enabled=False),
                CollectorConfig(name="aws_ec2", enabled=True),
            ],
        )

        enabled = config.get_enabled_collectors()

        assert "aws_iam" in enabled
        assert "aws_ec2" in enabled
        assert "aws_s3" not in enabled

    def test_get_enabled_collectors_defaults(self):
        """Test getting default collectors when none configured."""
        config = ScanConfiguration()
        enabled = config.get_enabled_collectors()

        assert "aws_iam" in enabled
        assert "aws_s3" in enabled
        assert "aws_ec2" in enabled
        assert "aws_security" in enabled

    def test_get_enabled_accounts(self):
        """Test getting enabled accounts."""
        config = ScanConfiguration(
            accounts=[
                AccountConfig(
                    account_id="111111111111",
                    cloud_provider=CloudProvider.AWS,
                    enabled=True,
                ),
                AccountConfig(
                    account_id="222222222222",
                    cloud_provider=CloudProvider.AWS,
                    enabled=False,
                ),
                AccountConfig(
                    account_id="333333333333",
                    cloud_provider=CloudProvider.AWS,
                    enabled=True,
                ),
            ],
        )

        enabled = config.get_enabled_accounts()

        assert len(enabled) == 2
        assert enabled[0].account_id == "111111111111"
        assert enabled[1].account_id == "333333333333"

    def test_get_regions_for_account(self):
        """Test getting regions for a specific account."""
        config = ScanConfiguration(
            accounts=[
                AccountConfig(
                    account_id="123456789012",
                    cloud_provider=CloudProvider.AWS,
                    regions=["us-east-1", "us-west-2"],
                ),
            ],
        )

        regions = config.get_regions_for_account("123456789012")
        assert regions == ["us-east-1", "us-west-2"]

    def test_get_regions_for_account_defaults(self):
        """Test default regions when account has no regions configured."""
        config = ScanConfiguration(
            accounts=[
                AccountConfig(
                    account_id="123456789012",
                    cloud_provider=CloudProvider.AWS,
                    regions=[],
                ),
            ],
        )

        regions = config.get_regions_for_account("123456789012")
        assert regions == ["us-east-1"]

    def test_get_regions_for_nonexistent_account(self):
        """Test regions for non-existent account."""
        config = ScanConfiguration()
        regions = config.get_regions_for_account("000000000000")
        assert regions == []

    def test_scan_configuration_to_dict(self):
        """Test ScanConfiguration serialization."""
        config = ScanConfiguration(
            name="test",
            mode=ScanMode.INCREMENTAL,
            collectors=[CollectorConfig(name="aws_iam")],
        )

        data = config.to_dict()

        assert data["name"] == "test"
        assert data["mode"] == "incremental"
        assert len(data["collectors"]) == 1
        assert "schedule" in data
        assert "policies" in data
        assert "storage" in data

    def test_scan_configuration_to_json(self):
        """Test ScanConfiguration JSON serialization."""
        config = ScanConfiguration(name="test")
        json_str = config.to_json()

        assert isinstance(json_str, str)
        data = json.loads(json_str)
        assert data["name"] == "test"

    def test_scan_configuration_from_dict(self):
        """Test ScanConfiguration deserialization."""
        data = {
            "name": "production",
            "mode": "incremental",
            "collectors": [{"name": "aws_iam"}],
            "accounts": [
                {"account_id": "123456789012", "cloud_provider": "aws"},
            ],
        }

        config = ScanConfiguration.from_dict(data)

        assert config.name == "production"
        assert config.mode == ScanMode.INCREMENTAL
        assert len(config.collectors) == 1
        assert len(config.accounts) == 1

    def test_scan_configuration_from_json(self):
        """Test ScanConfiguration from JSON."""
        json_str = '{"name": "test", "mode": "full"}'
        config = ScanConfiguration.from_json(json_str)

        assert config.name == "test"
        assert config.mode == ScanMode.FULL

    def test_scan_configuration_roundtrip(self):
        """Test ScanConfiguration serialization roundtrip."""
        original = ScanConfiguration(
            name="roundtrip",
            mode=ScanMode.TARGETED,
            collectors=[CollectorConfig(name="aws_s3")],
            accounts=[
                AccountConfig(
                    account_id="123456789012",
                    cloud_provider=CloudProvider.AWS,
                ),
            ],
        )

        data = original.to_dict()
        restored = ScanConfiguration.from_dict(data)

        assert restored.name == original.name
        assert restored.mode == original.mode
        assert len(restored.collectors) == len(original.collectors)
        assert len(restored.accounts) == len(original.accounts)

    def test_scan_configuration_from_file_json(self, tmp_path):
        """Test loading configuration from JSON file."""
        config_path = tmp_path / "config.json"
        config_data = {
            "name": "from_file",
            "mode": "full",
        }
        config_path.write_text(json.dumps(config_data))

        config = ScanConfiguration.from_file(str(config_path))

        assert config.name == "from_file"

    def test_scan_configuration_save_json(self, tmp_path):
        """Test saving configuration to JSON file."""
        config = ScanConfiguration(name="save_test")
        config_path = tmp_path / "saved.json"

        config.save(str(config_path))

        assert config_path.exists()
        loaded = json.loads(config_path.read_text())
        assert loaded["name"] == "save_test"


class TestConfigurationManager:
    """Tests for ConfigurationManager."""

    @pytest.fixture
    def manager(self, tmp_path):
        """Create a ConfigurationManager with temporary directory."""
        return ConfigurationManager(config_dir=str(tmp_path))

    def test_manager_initialization(self, manager):
        """Test ConfigurationManager initialization."""
        assert os.path.exists(manager.config_dir)

    def test_list_configurations_empty(self, manager):
        """Test listing configurations when none exist."""
        configs = manager.list_configurations()
        assert configs == []

    def test_save_and_list_configurations(self, manager):
        """Test saving and listing configurations."""
        config1 = ScanConfiguration(name="config1")
        config2 = ScanConfiguration(name="config2")

        manager.save(config1)
        manager.save(config2)

        configs = manager.list_configurations()

        assert "config1" in configs
        assert "config2" in configs

    def test_save_and_load_configuration(self, manager):
        """Test saving and loading a configuration."""
        original = ScanConfiguration(
            name="test",
            mode=ScanMode.INCREMENTAL,
        )

        manager.save(original)
        loaded = manager.load("test")

        assert loaded.name == "test"
        assert loaded.mode == ScanMode.INCREMENTAL

    def test_load_nonexistent_returns_default(self, manager):
        """Test loading non-existent config returns default."""
        config = manager.load("nonexistent")

        assert config.name == "nonexistent"
        assert config.mode == ScanMode.FULL

    def test_delete_configuration(self, manager):
        """Test deleting a configuration."""
        config = ScanConfiguration(name="to_delete")
        manager.save(config)

        # Verify exists
        assert "to_delete" in manager.list_configurations()

        # Delete
        result = manager.delete("to_delete")
        assert result is True

        # Verify deleted
        assert "to_delete" not in manager.list_configurations()

    def test_delete_nonexistent_returns_false(self, manager):
        """Test deleting non-existent config returns False."""
        result = manager.delete("nonexistent")
        assert result is False

    def test_get_default(self, manager):
        """Test getting default configuration."""
        config = manager.get_default()
        assert config.name == "default"

    def test_set_default(self, manager):
        """Test setting a configuration as default."""
        config = ScanConfiguration(
            name="custom",
            mode=ScanMode.INCREMENTAL,
        )

        manager.set_default(config)

        default = manager.get_default()
        assert default.name == "default"
        assert default.mode == ScanMode.INCREMENTAL


class TestLoadConfigFromEnv:
    """Tests for load_config_from_env function."""

    def test_load_from_env_empty(self):
        """Test loading config from env with no vars set."""
        # Clear relevant env vars
        for key in ["STANCE_CONFIG_FILE", "STANCE_COLLECTORS", "STANCE_STORAGE_BACKEND"]:
            os.environ.pop(key, None)

        config = load_config_from_env()

        assert config.name == "default"
        assert config.storage.backend == "local"

    def test_load_from_env_collectors(self):
        """Test loading collectors from env."""
        os.environ["STANCE_COLLECTORS"] = "aws_iam,aws_s3,aws_ec2"

        try:
            config = load_config_from_env()
            collectors = [c.name for c in config.collectors]

            assert "aws_iam" in collectors
            assert "aws_s3" in collectors
            assert "aws_ec2" in collectors
        finally:
            os.environ.pop("STANCE_COLLECTORS", None)

    def test_load_from_env_storage(self):
        """Test loading storage config from env."""
        os.environ["STANCE_STORAGE_BACKEND"] = "s3"
        os.environ["STANCE_S3_BUCKET"] = "my-bucket"

        try:
            config = load_config_from_env()

            assert config.storage.backend == "s3"
            assert config.storage.s3_bucket == "my-bucket"
        finally:
            os.environ.pop("STANCE_STORAGE_BACKEND", None)
            os.environ.pop("STANCE_S3_BUCKET", None)

    def test_load_from_env_policies(self):
        """Test loading policy config from env."""
        os.environ["STANCE_POLICY_DIRS"] = "policies/,custom/"
        os.environ["STANCE_SEVERITY_THRESHOLD"] = "high"

        try:
            config = load_config_from_env()

            assert "policies/" in config.policies.policy_dirs
            assert "custom/" in config.policies.policy_dirs
            assert config.policies.severity_threshold == "high"
        finally:
            os.environ.pop("STANCE_POLICY_DIRS", None)
            os.environ.pop("STANCE_SEVERITY_THRESHOLD", None)

    def test_load_from_env_config_file(self, tmp_path):
        """Test loading from config file via env var."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "name": "from_env_file",
            "mode": "incremental",
        }))

        os.environ["STANCE_CONFIG_FILE"] = str(config_file)

        try:
            config = load_config_from_env()
            assert config.name == "from_env_file"
            assert config.mode == ScanMode.INCREMENTAL
        finally:
            os.environ.pop("STANCE_CONFIG_FILE", None)


class TestCreateDefaultConfig:
    """Tests for create_default_config function."""

    def test_create_default_config(self):
        """Test creating default configuration."""
        config = create_default_config()

        assert config.name == "default"
        assert config.description == "Default Mantissa Stance configuration"
        assert config.mode == ScanMode.FULL

    def test_default_config_has_collectors(self):
        """Test default config has collectors."""
        config = create_default_config()
        collector_names = [c.name for c in config.collectors]

        assert "aws_iam" in collector_names
        assert "aws_s3" in collector_names
        assert "aws_ec2" in collector_names
        assert "aws_security" in collector_names

    def test_default_config_all_collectors_enabled(self):
        """Test all default collectors are enabled."""
        config = create_default_config()

        for collector in config.collectors:
            assert collector.enabled is True

    def test_default_config_schedule_enabled(self):
        """Test default schedule is enabled."""
        config = create_default_config()

        assert config.schedule.enabled is True
        assert config.schedule.expression == "rate(1 hour)"

    def test_default_config_storage_local(self):
        """Test default storage is local."""
        config = create_default_config()

        assert config.storage.backend == "local"
        assert config.storage.local_path == "~/.stance"

    def test_default_config_policies(self):
        """Test default policy configuration."""
        config = create_default_config()

        assert "policies/" in config.policies.policy_dirs
        assert config.policies.severity_threshold == "info"
