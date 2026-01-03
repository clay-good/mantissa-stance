"""
Unit tests for Web API Config endpoints.

Tests the REST API endpoints for configuration management including listing,
showing, creating, editing, validating, and deleting configurations.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any
from unittest import mock

import pytest


class TestConfigListEndpoint:
    """Tests for /api/config/list endpoint."""

    def test_list_empty(self):
        """Test listing configurations when none exist."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_list = StanceRequestHandler._config_list.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = handler._config_list({"config_dir": [tmpdir]})

            assert "configurations" in result
            assert "total" in result
            assert result["total"] == 0

    def test_list_with_configs(self):
        """Test listing configurations when they exist."""
        from stance.web.server import StanceRequestHandler
        from stance.config import ConfigurationManager, ScanConfiguration

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_list = StanceRequestHandler._config_list.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="test-config")
            manager.save(config)

            result = handler._config_list({"config_dir": [tmpdir]})

            assert result["total"] == 1
            assert result["configurations"][0]["name"] == "test-config"


class TestConfigShowEndpoint:
    """Tests for /api/config/show endpoint."""

    def test_show_default(self):
        """Test showing default configuration."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_show = StanceRequestHandler._config_show.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = handler._config_show({"config_dir": [tmpdir]})

            assert result["name"] == "default"
            assert "mode" in result

    def test_show_specific_config(self):
        """Test showing a specific configuration."""
        from stance.web.server import StanceRequestHandler
        from stance.config import ConfigurationManager, ScanConfiguration

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_show = StanceRequestHandler._config_show.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="my-config", description="Test description")
            manager.save(config)

            result = handler._config_show({"config_dir": [tmpdir], "name": ["my-config"]})

            assert result["name"] == "my-config"
            assert result["description"] == "Test description"

    def test_show_section(self):
        """Test showing a specific section."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_show = StanceRequestHandler._config_show.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = handler._config_show({
                "config_dir": [tmpdir],
                "name": ["default"],
                "section": ["storage"],
            })

            assert "section" in result
            assert result["section"] == "storage"
            assert "data" in result


class TestConfigValidateEndpoint:
    """Tests for /api/config/validate endpoint."""

    def test_validate_valid_config(self):
        """Test validating a valid configuration."""
        from stance.web.server import StanceRequestHandler
        from stance.config import ConfigurationManager, ScanConfiguration

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_validate = StanceRequestHandler._config_validate.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="valid-config")
            manager.save(config)

            result = handler._config_validate({
                "config_dir": [tmpdir],
                "name": ["valid-config"],
            })

            assert result["valid"] is True
            assert result["errors"] == []

    def test_validate_invalid_config(self):
        """Test validating an invalid configuration."""
        from stance.web.server import StanceRequestHandler
        from stance.config import ConfigurationManager, ScanConfiguration

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_validate = StanceRequestHandler._config_validate.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="invalid-config")
            config.storage.backend = "s3"
            config.storage.s3_bucket = ""  # Missing required bucket
            manager.save(config)

            result = handler._config_validate({
                "config_dir": [tmpdir],
                "name": ["invalid-config"],
            })

            assert result["valid"] is False
            assert len(result["errors"]) > 0


class TestConfigDefaultEndpoint:
    """Tests for /api/config/default endpoint."""

    def test_get_default(self):
        """Test getting default configuration."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_default = StanceRequestHandler._config_default.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = handler._config_default({"config_dir": [tmpdir]})

            assert result["name"] == "default"
            assert "mode" in result


class TestConfigModesEndpoint:
    """Tests for /api/config/modes endpoint."""

    def test_list_modes(self):
        """Test listing scan modes."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_modes = StanceRequestHandler._config_modes.__get__(handler)

        result = handler._config_modes({})

        assert "modes" in result
        assert result["total"] == 3

        mode_names = [m["name"] for m in result["modes"]]
        assert "full" in mode_names
        assert "incremental" in mode_names
        assert "targeted" in mode_names


class TestConfigProvidersEndpoint:
    """Tests for /api/config/providers endpoint."""

    def test_list_providers(self):
        """Test listing cloud providers."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_providers = StanceRequestHandler._config_providers.__get__(handler)

        result = handler._config_providers({})

        assert "providers" in result
        assert result["total"] == 3

        provider_names = [p["name"] for p in result["providers"]]
        assert "aws" in provider_names
        assert "gcp" in provider_names
        assert "azure" in provider_names


class TestConfigSchemaEndpoint:
    """Tests for /api/config/schema endpoint."""

    def test_schema_all(self):
        """Test getting full schema."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_schema = StanceRequestHandler._config_schema.__get__(handler)

        result = handler._config_schema({"section": ["all"]})

        assert result["type"] == "object"
        assert "properties" in result

    def test_schema_section(self):
        """Test getting section schema."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_schema = StanceRequestHandler._config_schema.__get__(handler)

        result = handler._config_schema({"section": ["storage"]})

        assert result["type"] == "object"
        assert "properties" in result


class TestConfigEnvEndpoint:
    """Tests for /api/config/env endpoint."""

    def test_get_env_vars(self):
        """Test getting environment variables."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_env = StanceRequestHandler._config_env.__get__(handler)

        result = handler._config_env({})

        assert "environment_variables" in result
        assert result["total"] >= 9

        env_names = [e["name"] for e in result["environment_variables"]]
        assert "STANCE_CONFIG_FILE" in env_names
        assert "STANCE_COLLECTORS" in env_names


class TestConfigStatusEndpoint:
    """Tests for /api/config/status endpoint."""

    def test_get_status(self):
        """Test getting config module status."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_status = StanceRequestHandler._config_status.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = handler._config_status({"config_dir": [tmpdir]})

            assert result["module"] == "config"
            assert "components" in result
            assert "ScanConfiguration" in result["components"]


class TestConfigSummaryEndpoint:
    """Tests for /api/config/summary endpoint."""

    def test_get_summary(self):
        """Test getting config module summary."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_summary = StanceRequestHandler._config_summary.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = handler._config_summary({"config_dir": [tmpdir]})

            assert "overview" in result
            assert "features" in result
            assert "architecture" in result
            assert "scan_modes" in result


class TestConfigCreateEndpoint:
    """Tests for /api/config/create endpoint (POST)."""

    def test_create_config(self):
        """Test creating a configuration."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_create = StanceRequestHandler._config_create.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            body = json.dumps({
                "name": "new-config",
                "config_dir": tmpdir,
                "description": "Test config",
                "mode": "full",
            }).encode()

            result = handler._config_create(body)

            assert result["success"] is True
            assert result["name"] == "new-config"

    def test_create_duplicate_fails(self):
        """Test creating duplicate configuration fails."""
        from stance.web.server import StanceRequestHandler
        from stance.config import ConfigurationManager, ScanConfiguration

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_create = StanceRequestHandler._config_create.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="existing")
            manager.save(config)

            body = json.dumps({
                "name": "existing",
                "config_dir": tmpdir,
            }).encode()

            result = handler._config_create(body)

            assert "error" in result
            assert "already exists" in result["error"]


class TestConfigDeleteEndpoint:
    """Tests for /api/config/delete endpoint (POST)."""

    def test_delete_config(self):
        """Test deleting a configuration."""
        from stance.web.server import StanceRequestHandler
        from stance.config import ConfigurationManager, ScanConfiguration

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_delete = StanceRequestHandler._config_delete.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="to-delete")
            manager.save(config)

            body = json.dumps({
                "name": "to-delete",
                "config_dir": tmpdir,
            }).encode()

            result = handler._config_delete(body)

            assert result["success"] is True
            assert result["name"] == "to-delete"

    def test_delete_nonexistent_fails(self):
        """Test deleting non-existent configuration fails."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_delete = StanceRequestHandler._config_delete.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            body = json.dumps({
                "name": "nonexistent",
                "config_dir": tmpdir,
            }).encode()

            result = handler._config_delete(body)

            assert "error" in result
            assert "not found" in result["error"]


class TestConfigEditEndpoint:
    """Tests for /api/config/edit endpoint (POST)."""

    def test_edit_config(self):
        """Test editing a configuration."""
        from stance.web.server import StanceRequestHandler
        from stance.config import ConfigurationManager, ScanConfiguration

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_edit = StanceRequestHandler._config_edit.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="to-edit")
            manager.save(config)

            body = json.dumps({
                "name": "to-edit",
                "config_dir": tmpdir,
                "description": "Updated description",
                "mode": "incremental",
            }).encode()

            result = handler._config_edit(body)

            assert result["success"] is True

            # Verify changes
            updated = manager.load("to-edit")
            assert updated.description == "Updated description"
            assert updated.mode.value == "incremental"


class TestConfigImportEndpoint:
    """Tests for /api/config/import endpoint (POST)."""

    def test_import_config(self):
        """Test importing a configuration."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_import = StanceRequestHandler._config_import.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            body = json.dumps({
                "config": {
                    "name": "imported",
                    "mode": "full",
                    "collectors": [],
                    "accounts": [],
                    "schedule": {},
                    "policies": {},
                    "storage": {},
                    "notifications": {},
                },
                "config_dir": tmpdir,
            }).encode()

            result = handler._config_import(body)

            assert result["success"] is True
            assert result["name"] == "imported"


class TestConfigExportEndpoint:
    """Tests for /api/config/export endpoint (POST)."""

    def test_export_config(self):
        """Test exporting a configuration."""
        from stance.web.server import StanceRequestHandler
        from stance.config import ConfigurationManager, ScanConfiguration

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_export = StanceRequestHandler._config_export.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="to-export")
            manager.save(config)

            body = json.dumps({
                "name": "to-export",
                "config_dir": tmpdir,
                "format": "json",
            }).encode()

            result = handler._config_export(body)

            assert result["name"] == "to-export"
            assert result["format"] == "json"
            assert "content" in result


class TestConfigSetDefaultEndpoint:
    """Tests for /api/config/set-default endpoint (POST)."""

    def test_set_default(self):
        """Test setting a configuration as default."""
        from stance.web.server import StanceRequestHandler
        from stance.config import ConfigurationManager, ScanConfiguration

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._config_set_default = StanceRequestHandler._config_set_default.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigurationManager(config_dir=tmpdir)
            config = ScanConfiguration(name="new-default")
            manager.save(config)

            body = json.dumps({
                "name": "new-default",
                "config_dir": tmpdir,
            }).encode()

            result = handler._config_set_default(body)

            assert result["success"] is True
            assert result["name"] == "new-default"


class TestConfigApiIntegration:
    """Integration tests for config API endpoints."""

    def test_all_endpoints_callable(self):
        """Test all endpoints are callable."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        # Bind all methods
        handler._config_list = StanceRequestHandler._config_list.__get__(handler)
        handler._config_show = StanceRequestHandler._config_show.__get__(handler)
        handler._config_validate = StanceRequestHandler._config_validate.__get__(handler)
        handler._config_default = StanceRequestHandler._config_default.__get__(handler)
        handler._config_modes = StanceRequestHandler._config_modes.__get__(handler)
        handler._config_providers = StanceRequestHandler._config_providers.__get__(handler)
        handler._config_schema = StanceRequestHandler._config_schema.__get__(handler)
        handler._config_env = StanceRequestHandler._config_env.__get__(handler)
        handler._config_status = StanceRequestHandler._config_status.__get__(handler)
        handler._config_summary = StanceRequestHandler._config_summary.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            endpoints = [
                ("_config_list", {"config_dir": [tmpdir]}),
                ("_config_show", {"config_dir": [tmpdir]}),
                ("_config_validate", {"config_dir": [tmpdir]}),
                ("_config_default", {"config_dir": [tmpdir]}),
                ("_config_modes", {}),
                ("_config_providers", {}),
                ("_config_schema", {"section": ["all"]}),
                ("_config_env", {}),
                ("_config_status", {"config_dir": [tmpdir]}),
                ("_config_summary", {"config_dir": [tmpdir]}),
            ]

            for method_name, params in endpoints:
                method = getattr(handler, method_name)
                result = method(params)
                assert isinstance(result, dict), f"{method_name} should return dict"

    def test_json_serializable(self):
        """Test all endpoint responses are JSON serializable."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        # Bind all methods
        handler._config_list = StanceRequestHandler._config_list.__get__(handler)
        handler._config_show = StanceRequestHandler._config_show.__get__(handler)
        handler._config_validate = StanceRequestHandler._config_validate.__get__(handler)
        handler._config_default = StanceRequestHandler._config_default.__get__(handler)
        handler._config_modes = StanceRequestHandler._config_modes.__get__(handler)
        handler._config_providers = StanceRequestHandler._config_providers.__get__(handler)
        handler._config_schema = StanceRequestHandler._config_schema.__get__(handler)
        handler._config_env = StanceRequestHandler._config_env.__get__(handler)
        handler._config_status = StanceRequestHandler._config_status.__get__(handler)
        handler._config_summary = StanceRequestHandler._config_summary.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            endpoints = [
                ("_config_list", {"config_dir": [tmpdir]}),
                ("_config_show", {"config_dir": [tmpdir]}),
                ("_config_validate", {"config_dir": [tmpdir]}),
                ("_config_default", {"config_dir": [tmpdir]}),
                ("_config_modes", {}),
                ("_config_providers", {}),
                ("_config_schema", {"section": ["all"]}),
                ("_config_env", {}),
                ("_config_status", {"config_dir": [tmpdir]}),
                ("_config_summary", {"config_dir": [tmpdir]}),
            ]

            for method_name, params in endpoints:
                method = getattr(handler, method_name)
                result = method(params)
                try:
                    json.dumps(result, default=str)
                except (TypeError, ValueError) as e:
                    pytest.fail(f"{method_name} response not JSON serializable: {e}")
