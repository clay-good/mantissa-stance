"""
Unit tests for Config CLI commands.

Tests the CLI commands for configuration management including listing,
showing, creating, editing, validating, and deleting configurations.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from typing import Any
from unittest import mock

import pytest


class TestConfigListCommand:
    """Tests for config list command."""

    def test_list_empty(self, capsys):
        """Test listing configurations when none exist."""
        from stance.cli_config import _handle_list

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                config_dir=tmpdir,
                json=False,
            )
            result = _handle_list(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "No configurations found" in captured.out

    def test_list_with_configs(self, capsys):
        """Test listing configurations when they exist."""
        from stance.cli_config import _handle_list
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="test-config")
            manager.save(config)

            args = argparse.Namespace(
                config_dir=tmpdir,
                json=False,
            )
            result = _handle_list(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "test-config" in captured.out

    def test_list_json_output(self, capsys):
        """Test listing configurations with JSON output."""
        from stance.cli_config import _handle_list

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                config_dir=tmpdir,
                json=True,
            )
            result = _handle_list(args)
            assert result == 0

            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert "configurations" in output
            assert "total" in output


class TestConfigShowCommand:
    """Tests for config show command."""

    def test_show_default(self, capsys):
        """Test showing default configuration."""
        from stance.cli_config import _handle_show

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                name="default",
                config_dir=tmpdir,
                json=False,
                section=None,
            )
            result = _handle_show(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Configuration: default" in captured.out

    def test_show_json_output(self, capsys):
        """Test showing configuration with JSON output."""
        from stance.cli_config import _handle_show
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="test-show")
            manager.save(config)

            args = argparse.Namespace(
                name="test-show",
                config_dir=tmpdir,
                json=True,
                section=None,
            )
            result = _handle_show(args)
            assert result == 0

            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert output["name"] == "test-show"

    def test_show_section(self, capsys):
        """Test showing a specific section."""
        from stance.cli_config import _handle_show

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                name="default",
                config_dir=tmpdir,
                json=False,
                section="storage",
            )
            result = _handle_show(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Storage" in captured.out or "Backend" in captured.out


class TestConfigCreateCommand:
    """Tests for config create command."""

    def test_create_basic(self, capsys):
        """Test creating a basic configuration."""
        from stance.cli_config import _handle_create

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                name="new-config",
                config_dir=tmpdir,
                description="Test config",
                mode="full",
                from_default=False,
                format="json",
            )
            result = _handle_create(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Created configuration 'new-config'" in captured.out

    def test_create_from_default(self, capsys):
        """Test creating configuration from default template."""
        from stance.cli_config import _handle_create

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                name="from-default",
                config_dir=tmpdir,
                description="",
                mode="full",
                from_default=True,
                format="json",
            )
            result = _handle_create(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Created configuration 'from-default'" in captured.out

    def test_create_duplicate(self, capsys):
        """Test creating duplicate configuration fails."""
        from stance.cli_config import _handle_create
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="existing")
            manager.save(config)

            args = argparse.Namespace(
                name="existing",
                config_dir=tmpdir,
                description="",
                mode="full",
                from_default=False,
                format="json",
            )
            result = _handle_create(args)
            assert result == 1

            captured = capsys.readouterr()
            assert "already exists" in captured.out


class TestConfigDeleteCommand:
    """Tests for config delete command."""

    def test_delete_existing(self, capsys):
        """Test deleting an existing configuration."""
        from stance.cli_config import _handle_delete
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="to-delete")
            manager.save(config)

            args = argparse.Namespace(
                name="to-delete",
                config_dir=tmpdir,
                force=True,
            )
            result = _handle_delete(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Deleted configuration 'to-delete'" in captured.out

    def test_delete_nonexistent(self, capsys):
        """Test deleting non-existent configuration fails."""
        from stance.cli_config import _handle_delete

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                name="nonexistent",
                config_dir=tmpdir,
                force=True,
            )
            result = _handle_delete(args)
            assert result == 1

            captured = capsys.readouterr()
            assert "not found" in captured.out


class TestConfigEditCommand:
    """Tests for config edit command."""

    def test_edit_description(self, capsys):
        """Test editing configuration description."""
        from stance.cli_config import _handle_edit
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="to-edit")
            manager.save(config)

            args = argparse.Namespace(
                name="to-edit",
                config_dir=tmpdir,
                description="Updated description",
                mode=None,
                storage_backend=None,
                storage_path=None,
                s3_bucket=None,
                gcs_bucket=None,
                azure_container=None,
                severity_threshold=None,
                retention_days=None,
            )
            result = _handle_edit(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Updated configuration" in captured.out

    def test_edit_storage_backend(self, capsys):
        """Test editing storage backend."""
        from stance.cli_config import _handle_edit
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="edit-storage")
            manager.save(config)

            args = argparse.Namespace(
                name="edit-storage",
                config_dir=tmpdir,
                description=None,
                mode=None,
                storage_backend="s3",
                storage_path=None,
                s3_bucket="my-bucket",
                gcs_bucket=None,
                azure_container=None,
                severity_threshold=None,
                retention_days=None,
            )
            result = _handle_edit(args)
            assert result == 0

            # Verify the change
            updated_config = manager.load("edit-storage")
            assert updated_config.storage.backend == "s3"
            assert updated_config.storage.s3_bucket == "my-bucket"


class TestConfigValidateCommand:
    """Tests for config validate command."""

    def test_validate_valid_config(self, capsys):
        """Test validating a valid configuration."""
        from stance.cli_config import _handle_validate
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="valid-config")
            manager.save(config)

            args = argparse.Namespace(
                name="valid-config",
                config_dir=tmpdir,
                json=False,
            )
            result = _handle_validate(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "VALID" in captured.out

    def test_validate_invalid_s3_config(self, capsys):
        """Test validating configuration with missing S3 bucket."""
        from stance.cli_config import _handle_validate
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="invalid-s3")
            config.storage.backend = "s3"
            config.storage.s3_bucket = ""  # Missing bucket
            manager.save(config)

            args = argparse.Namespace(
                name="invalid-s3",
                config_dir=tmpdir,
                json=False,
            )
            result = _handle_validate(args)
            assert result == 1

            captured = capsys.readouterr()
            assert "INVALID" in captured.out

    def test_validate_json_output(self, capsys):
        """Test validating with JSON output."""
        from stance.cli_config import _handle_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                name="default",
                config_dir=tmpdir,
                json=True,
            )
            result = _handle_validate(args)
            assert result == 0

            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert "valid" in output
            assert "errors" in output


class TestConfigExportCommand:
    """Tests for config export command."""

    def test_export_json(self, capsys):
        """Test exporting configuration as JSON."""
        from stance.cli_config import _handle_export
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="to-export")
            manager.save(config)

            args = argparse.Namespace(
                name="to-export",
                config_dir=tmpdir,
                output=None,
                format="json",
            )
            result = _handle_export(args)
            assert result == 0

            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert output["name"] == "to-export"

    def test_export_to_file(self, capsys):
        """Test exporting configuration to file."""
        from stance.cli_config import _handle_export
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="export-to-file")
            manager.save(config)

            output_file = os.path.join(tmpdir, "exported.json")
            args = argparse.Namespace(
                name="export-to-file",
                config_dir=tmpdir,
                output=output_file,
                format="json",
            )
            result = _handle_export(args)
            assert result == 0

            # Verify file was created
            assert os.path.exists(output_file)
            with open(output_file) as f:
                data = json.load(f)
                assert data["name"] == "export-to-file"


class TestConfigImportCommand:
    """Tests for config import command."""

    def test_import_json(self, capsys):
        """Test importing configuration from JSON file."""
        from stance.cli_config import _handle_import
        from stance.config import ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a config file to import
            config = ScanConfiguration(name="imported-config")
            config_file = os.path.join(tmpdir, "import.json")
            config.save(config_file)

            args = argparse.Namespace(
                file=config_file,
                config_dir=tmpdir,
                name=None,
                force=False,
            )
            result = _handle_import(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Imported configuration" in captured.out

    def test_import_with_name_override(self, capsys):
        """Test importing with name override."""
        from stance.cli_config import _handle_import
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScanConfiguration(name="original-name")
            config_file = os.path.join(tmpdir, "import.json")
            config.save(config_file)

            args = argparse.Namespace(
                file=config_file,
                config_dir=tmpdir,
                name="overridden-name",
                force=False,
            )
            result = _handle_import(args)
            assert result == 0

            # Verify the name was overridden
            manager = ConfigurationManager(config_dir=tmpdir)
            assert "overridden-name" in manager.list_configurations()


class TestConfigDefaultCommand:
    """Tests for config default command."""

    def test_show_default(self, capsys):
        """Test showing default configuration."""
        from stance.cli_config import _handle_default

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                config_dir=tmpdir,
                set=None,
                json=False,
            )
            result = _handle_default(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Configuration: default" in captured.out

    def test_set_default(self, capsys):
        """Test setting a configuration as default."""
        from stance.cli_config import _handle_default
        from stance.config import ConfigurationManager, ScanConfiguration

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="new-default")
            manager.save(config)

            args = argparse.Namespace(
                config_dir=tmpdir,
                set="new-default",
                json=False,
            )
            result = _handle_default(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Set 'new-default' as default" in captured.out


class TestConfigModesCommand:
    """Tests for config modes command."""

    def test_list_modes(self, capsys):
        """Test listing scan modes."""
        from stance.cli_config import _handle_modes

        args = argparse.Namespace(json=False)
        result = _handle_modes(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "full" in captured.out
        assert "incremental" in captured.out
        assert "targeted" in captured.out

    def test_list_modes_json(self, capsys):
        """Test listing scan modes with JSON output."""
        from stance.cli_config import _handle_modes

        args = argparse.Namespace(json=True)
        result = _handle_modes(args)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "modes" in output
        assert len(output["modes"]) == 3


class TestConfigProvidersCommand:
    """Tests for config providers command."""

    def test_list_providers(self, capsys):
        """Test listing cloud providers."""
        from stance.cli_config import _handle_providers

        args = argparse.Namespace(json=False)
        result = _handle_providers(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "aws" in captured.out
        assert "gcp" in captured.out
        assert "azure" in captured.out

    def test_list_providers_json(self, capsys):
        """Test listing providers with JSON output."""
        from stance.cli_config import _handle_providers

        args = argparse.Namespace(json=True)
        result = _handle_providers(args)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "providers" in output
        assert len(output["providers"]) == 3


class TestConfigSchemaCommand:
    """Tests for config schema command."""

    def test_schema_all(self, capsys):
        """Test showing all schema."""
        from stance.cli_config import _handle_schema

        args = argparse.Namespace(section="all", json=False)
        result = _handle_schema(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Configuration Schema" in captured.out

    def test_schema_section(self, capsys):
        """Test showing specific section schema."""
        from stance.cli_config import _handle_schema

        args = argparse.Namespace(section="storage", json=False)
        result = _handle_schema(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "backend" in captured.out or "Storage" in captured.out

    def test_schema_json(self, capsys):
        """Test showing schema with JSON output."""
        from stance.cli_config import _handle_schema

        args = argparse.Namespace(section="all", json=True)
        result = _handle_schema(args)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "type" in output
        assert "properties" in output


class TestConfigEnvCommand:
    """Tests for config env command."""

    def test_show_env_vars(self, capsys):
        """Test showing environment variables."""
        from stance.cli_config import _handle_env

        args = argparse.Namespace(json=False)
        result = _handle_env(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "STANCE_CONFIG_FILE" in captured.out
        assert "STANCE_COLLECTORS" in captured.out

    def test_show_env_vars_json(self, capsys):
        """Test showing env vars with JSON output."""
        from stance.cli_config import _handle_env

        args = argparse.Namespace(json=True)
        result = _handle_env(args)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "environment_variables" in output
        assert len(output["environment_variables"]) >= 9


class TestCmdConfigMainHandler:
    """Tests for the main cmd_config handler."""

    def test_no_command(self, capsys):
        """Test calling config without subcommand."""
        from stance.cli_config import cmd_config

        args = argparse.Namespace()
        # Don't set config_command
        result = cmd_config(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Available commands" in captured.out

    def test_unknown_command(self, capsys):
        """Test calling config with unknown subcommand."""
        from stance.cli_config import cmd_config

        args = argparse.Namespace(config_command="unknown")
        result = cmd_config(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Unknown config command" in captured.out


class TestConfigIntegration:
    """Integration tests for config CLI."""

    def test_create_edit_validate_delete_flow(self, capsys):
        """Test full lifecycle of configuration management."""
        from stance.cli_config import _handle_create, _handle_edit, _handle_validate, _handle_delete
        from stance.config import ConfigurationManager

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create
            create_args = argparse.Namespace(
                name="lifecycle-test",
                config_dir=tmpdir,
                description="Test config",
                mode="full",
                from_default=False,
                format="json",
            )
            result = _handle_create(create_args)
            assert result == 0

            # Edit
            edit_args = argparse.Namespace(
                name="lifecycle-test",
                config_dir=tmpdir,
                description="Updated description",
                mode="incremental",
                storage_backend=None,
                storage_path=None,
                s3_bucket=None,
                gcs_bucket=None,
                azure_container=None,
                severity_threshold="high",
                retention_days=30,
            )
            result = _handle_edit(edit_args)
            assert result == 0

            # Validate
            validate_args = argparse.Namespace(
                name="lifecycle-test",
                config_dir=tmpdir,
                json=False,
            )
            result = _handle_validate(validate_args)
            assert result == 0

            # Verify edits
            manager = ConfigurationManager(config_dir=tmpdir)
            config = manager.load("lifecycle-test")
            assert config.description == "Updated description"
            assert config.mode.value == "incremental"
            assert config.policies.severity_threshold == "high"
            assert config.storage.retention_days == 30

            # Delete
            delete_args = argparse.Namespace(
                name="lifecycle-test",
                config_dir=tmpdir,
                force=True,
            )
            result = _handle_delete(delete_args)
            assert result == 0

            # Verify deletion
            assert "lifecycle-test" not in manager.list_configurations()
