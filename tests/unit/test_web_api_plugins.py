"""
Unit tests for Web API plugin endpoints.

Tests the Plugin System REST API endpoints including listing,
loading, unloading, enabling, disabling, and configuring plugins.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


class TestPluginsListEndpoint:
    """Tests for GET /api/plugins/list endpoint."""

    def test_list_all_plugins(self):
        """Test listing all plugins."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_list = StanceRequestHandler._plugins_list.__get__(handler)

        result = handler._plugins_list({})

        assert 'plugins' in result
        assert 'total' in result
        assert 'enabled_count' in result
        assert 'disabled_count' in result
        assert result['total'] == len(result['plugins'])

    def test_list_plugins_filter_by_type(self):
        """Test filtering plugins by type."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_list = StanceRequestHandler._plugins_list.__get__(handler)

        result = handler._plugins_list({'type': ['collector']})

        assert all(p['type'] == 'collector' for p in result['plugins'])

    def test_list_plugins_filter_by_enabled(self):
        """Test filtering plugins by enabled status."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_list = StanceRequestHandler._plugins_list.__get__(handler)

        result = handler._plugins_list({'enabled': ['true']})

        assert all(p['enabled'] for p in result['plugins'])

    def test_list_disabled_plugins(self):
        """Test filtering disabled plugins."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_list = StanceRequestHandler._plugins_list.__get__(handler)

        result = handler._plugins_list({'enabled': ['false']})

        assert all(not p['enabled'] for p in result['plugins'])


class TestPluginsInfoEndpoint:
    """Tests for GET /api/plugins/info endpoint."""

    def test_get_plugin_info(self):
        """Test getting plugin info."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._get_plugin_config_schema = StanceRequestHandler._get_plugin_config_schema.__get__(handler)
        handler._get_plugin_capabilities = StanceRequestHandler._get_plugin_capabilities.__get__(handler)
        handler._plugins_info = StanceRequestHandler._plugins_info.__get__(handler)

        result = handler._plugins_info({'name': ['aws_collector']})

        assert result['name'] == 'aws_collector'
        assert 'config_schema' in result
        assert 'capabilities' in result

    def test_get_plugin_info_not_found(self):
        """Test getting info for non-existent plugin."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_info = StanceRequestHandler._plugins_info.__get__(handler)

        result = handler._plugins_info({'name': ['nonexistent']})

        assert 'error' in result

    def test_get_plugin_info_missing_name(self):
        """Test getting info without name parameter."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_info = StanceRequestHandler._plugins_info.__get__(handler)

        result = handler._plugins_info({})

        assert 'error' in result
        assert 'name is required' in result['error'].lower()


class TestPluginsLoadEndpoint:
    """Tests for GET /api/plugins/load endpoint."""

    def test_load_plugin(self):
        """Test loading a plugin."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_load = StanceRequestHandler._plugins_load.__get__(handler)

        result = handler._plugins_load({'source': ['/path/to/plugin.py']})

        assert result['success'] is True
        assert 'name' in result
        assert 'warnings' in result

    def test_load_plugin_with_type(self):
        """Test loading plugin with specified type."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_load = StanceRequestHandler._plugins_load.__get__(handler)

        result = handler._plugins_load({
            'source': ['my_collector'],
            'type': ['collector'],
        })

        assert result['success'] is True
        assert result['type'] == 'collector'

    def test_load_plugin_missing_source(self):
        """Test loading plugin without source."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_load = StanceRequestHandler._plugins_load.__get__(handler)

        result = handler._plugins_load({})

        assert 'error' in result


class TestPluginsUnloadEndpoint:
    """Tests for GET /api/plugins/unload endpoint."""

    def test_unload_plugin(self):
        """Test unloading a plugin."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_unload = StanceRequestHandler._plugins_unload.__get__(handler)

        result = handler._plugins_unload({'name': ['my_plugin']})

        assert result['success'] is True
        assert result['name'] == 'my_plugin'

    def test_unload_plugin_force(self):
        """Test force unloading a plugin."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_unload = StanceRequestHandler._plugins_unload.__get__(handler)

        result = handler._plugins_unload({
            'name': ['my_plugin'],
            'force': ['true'],
        })

        assert result['success'] is True
        assert result['force'] is True

    def test_unload_plugin_missing_name(self):
        """Test unloading without name parameter."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_unload = StanceRequestHandler._plugins_unload.__get__(handler)

        result = handler._plugins_unload({})

        assert 'error' in result


class TestPluginsReloadEndpoint:
    """Tests for GET /api/plugins/reload endpoint."""

    def test_reload_plugin(self):
        """Test reloading a plugin."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_reload = StanceRequestHandler._plugins_reload.__get__(handler)

        result = handler._plugins_reload({'name': ['my_plugin']})

        assert result['success'] is True
        assert result['name'] == 'my_plugin'

    def test_reload_plugin_missing_name(self):
        """Test reloading without name parameter."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_reload = StanceRequestHandler._plugins_reload.__get__(handler)

        result = handler._plugins_reload({})

        assert 'error' in result


class TestPluginsEnableDisableEndpoints:
    """Tests for enable/disable plugin endpoints."""

    def test_enable_plugin(self):
        """Test enabling a plugin."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_enable = StanceRequestHandler._plugins_enable.__get__(handler)

        result = handler._plugins_enable({'name': ['my_plugin']})

        assert result['success'] is True
        assert result['enabled'] is True

    def test_disable_plugin(self):
        """Test disabling a plugin."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_disable = StanceRequestHandler._plugins_disable.__get__(handler)

        result = handler._plugins_disable({'name': ['my_plugin']})

        assert result['success'] is True
        assert result['enabled'] is False

    def test_enable_missing_name(self):
        """Test enabling without name parameter."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_enable = StanceRequestHandler._plugins_enable.__get__(handler)

        result = handler._plugins_enable({})

        assert 'error' in result


class TestPluginsConfigureEndpoint:
    """Tests for GET /api/plugins/configure endpoint."""

    def test_configure_show_current(self):
        """Test showing current plugin configuration."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._get_plugin_config_schema = StanceRequestHandler._get_plugin_config_schema.__get__(handler)
        handler._plugins_configure = StanceRequestHandler._plugins_configure.__get__(handler)

        result = handler._plugins_configure({
            'name': ['aws_collector'],
            'show': ['true'],
        })

        assert 'config_schema' in result
        assert 'current_config' in result

    def test_configure_with_json(self):
        """Test configuring plugin with JSON."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_configure = StanceRequestHandler._plugins_configure.__get__(handler)

        result = handler._plugins_configure({
            'name': ['aws_collector'],
            'config': ['{"region": "us-west-2"}'],
        })

        assert result['success'] is True

    def test_configure_invalid_json(self):
        """Test configuring with invalid JSON."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_configure = StanceRequestHandler._plugins_configure.__get__(handler)

        result = handler._plugins_configure({
            'name': ['aws_collector'],
            'config': ['{invalid}'],
        })

        assert 'error' in result

    def test_configure_missing_config(self):
        """Test configuring without config parameter."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_configure = StanceRequestHandler._plugins_configure.__get__(handler)

        result = handler._plugins_configure({
            'name': ['aws_collector'],
        })

        assert 'error' in result

    def test_configure_plugin_not_found(self):
        """Test configuring non-existent plugin."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_configure = StanceRequestHandler._plugins_configure.__get__(handler)

        result = handler._plugins_configure({
            'name': ['nonexistent'],
            'show': ['true'],
        })

        assert 'error' in result


class TestPluginsDiscoverEndpoint:
    """Tests for GET /api/plugins/discover endpoint."""

    def test_discover_plugins(self):
        """Test discovering available plugins."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_discover = StanceRequestHandler._plugins_discover.__get__(handler)

        result = handler._plugins_discover({})

        assert 'discovered' in result
        assert 'total' in result
        assert 'loaded' in result
        assert 'available' in result

    def test_discover_with_paths(self):
        """Test discovering with custom paths."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_discover = StanceRequestHandler._plugins_discover.__get__(handler)

        result = handler._plugins_discover({
            'paths': ['/custom/path'],
        })

        assert 'discovered' in result
        # Should include custom plugin from path
        custom = [p for p in result['discovered'] if p['name'] == 'custom_plugin']
        assert len(custom) == 1

    def test_discover_with_auto_load(self):
        """Test discovering with auto-load enabled."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_discover = StanceRequestHandler._plugins_discover.__get__(handler)

        result = handler._plugins_discover({
            'load': ['true'],
        })

        assert result['auto_load'] is True


class TestPluginsTypesEndpoint:
    """Tests for GET /api/plugins/types endpoint."""

    def test_list_plugin_types(self):
        """Test listing available plugin types."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_types = StanceRequestHandler._plugins_types.__get__(handler)

        result = handler._plugins_types({})

        assert 'types' in result
        assert 'total' in result
        assert result['total'] == 5  # 5 plugin types

        type_names = [t['type'] for t in result['types']]
        assert 'collector' in type_names
        assert 'policy' in type_names
        assert 'enricher' in type_names
        assert 'alert_destination' in type_names
        assert 'report_format' in type_names

    def test_plugin_types_have_details(self):
        """Test plugin types include descriptions and interfaces."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._plugins_types = StanceRequestHandler._plugins_types.__get__(handler)

        result = handler._plugins_types({})

        for ptype in result['types']:
            assert 'type' in ptype
            assert 'description' in ptype
            assert 'examples' in ptype
            assert 'interface' in ptype


class TestPluginsStatusEndpoint:
    """Tests for GET /api/plugins/status endpoint."""

    def test_get_plugins_status(self):
        """Test getting plugin system status."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_status = StanceRequestHandler._plugins_status.__get__(handler)

        result = handler._plugins_status({})

        assert result['module'] == 'plugins'
        assert 'version' in result
        assert 'total_plugins' in result
        assert 'enabled_plugins' in result
        assert 'disabled_plugins' in result
        assert 'plugins_by_type' in result
        assert result['registry_healthy'] is True

    def test_status_includes_capabilities(self):
        """Test status includes system capabilities."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_status = StanceRequestHandler._plugins_status.__get__(handler)

        result = handler._plugins_status({})

        assert 'capabilities' in result
        caps = result['capabilities']
        assert caps['dynamic_loading'] is True
        assert caps['hot_reload'] is True

    def test_status_plugins_by_type(self):
        """Test status counts plugins by type."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_status = StanceRequestHandler._plugins_status.__get__(handler)

        result = handler._plugins_status({})

        by_type = result['plugins_by_type']
        assert 'collector' in by_type
        assert 'policy' in by_type
        assert by_type['collector'] == 3  # 3 collector plugins in sample data


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_sample_plugins(self):
        """Test getting sample plugin data."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)

        plugins = handler._get_sample_plugins()

        assert len(plugins) > 0
        for plugin in plugins:
            assert 'name' in plugin
            assert 'version' in plugin
            assert 'type' in plugin
            assert 'enabled' in plugin

    def test_get_plugin_config_schema(self):
        """Test getting plugin config schema."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_plugin_config_schema = StanceRequestHandler._get_plugin_config_schema.__get__(handler)

        schema = handler._get_plugin_config_schema('collector')

        assert 'type' in schema
        assert schema['type'] == 'object'
        assert 'properties' in schema

    def test_get_plugin_config_schema_unknown_type(self):
        """Test getting schema for unknown plugin type."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_plugin_config_schema = StanceRequestHandler._get_plugin_config_schema.__get__(handler)

        schema = handler._get_plugin_config_schema('unknown_type')

        assert 'type' in schema
        assert schema['type'] == 'object'

    def test_get_plugin_capabilities(self):
        """Test getting plugin capabilities."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_plugin_capabilities = StanceRequestHandler._get_plugin_capabilities.__get__(handler)

        caps = handler._get_plugin_capabilities('collector')

        assert isinstance(caps, list)
        assert len(caps) > 0
        assert 'collect_resources' in caps

    def test_get_plugin_capabilities_all_types(self):
        """Test getting capabilities for all plugin types."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_plugin_capabilities = StanceRequestHandler._get_plugin_capabilities.__get__(handler)

        types = ['collector', 'policy', 'enricher', 'alert_destination', 'report_format']

        for ptype in types:
            caps = handler._get_plugin_capabilities(ptype)
            assert isinstance(caps, list)
            assert len(caps) > 0


class TestSamplePluginData:
    """Tests for sample plugin data structure."""

    def test_sample_plugins_have_all_types(self):
        """Test sample data includes all plugin types."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)

        plugins = handler._get_sample_plugins()
        types = set(p['type'] for p in plugins)

        assert 'collector' in types
        assert 'policy' in types
        assert 'enricher' in types
        assert 'alert_destination' in types
        assert 'report_format' in types

    def test_sample_plugins_have_enabled_and_disabled(self):
        """Test sample data includes both enabled and disabled plugins."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)

        plugins = handler._get_sample_plugins()

        enabled = [p for p in plugins if p['enabled']]
        disabled = [p for p in plugins if not p['enabled']]

        assert len(enabled) > 0
        assert len(disabled) > 0

    def test_sample_plugins_have_config(self):
        """Test sample plugins include configuration."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)

        plugins = handler._get_sample_plugins()

        for plugin in plugins:
            assert 'config' in plugin
            assert isinstance(plugin['config'], dict)


class TestEndpointRouting:
    """Tests for endpoint routing."""

    def test_plugins_endpoints_registered(self):
        """Test that plugin endpoints are in the routing."""
        # Read the server.py source to verify routing
        import stance.web.server as server_module
        import inspect

        source = inspect.getsource(server_module.StanceRequestHandler._handle_api)

        # Check all plugin endpoints are routed
        endpoints = [
            '/api/plugins/list',
            '/api/plugins/info',
            '/api/plugins/load',
            '/api/plugins/unload',
            '/api/plugins/reload',
            '/api/plugins/enable',
            '/api/plugins/disable',
            '/api/plugins/configure',
            '/api/plugins/discover',
            '/api/plugins/types',
            '/api/plugins/status',
        ]

        for endpoint in endpoints:
            assert endpoint in source, f"Missing endpoint routing: {endpoint}"

    def test_plugins_methods_exist(self):
        """Test that plugin handler methods exist."""
        from stance.web.server import StanceRequestHandler

        methods = [
            '_plugins_list',
            '_plugins_info',
            '_plugins_load',
            '_plugins_unload',
            '_plugins_reload',
            '_plugins_enable',
            '_plugins_disable',
            '_plugins_configure',
            '_plugins_discover',
            '_plugins_types',
            '_plugins_status',
        ]

        for method in methods:
            assert hasattr(StanceRequestHandler, method), f"Missing method: {method}"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_params(self):
        """Test handling of empty parameters."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_list = StanceRequestHandler._plugins_list.__get__(handler)

        result = handler._plugins_list(None)

        assert 'plugins' in result

    def test_empty_string_params(self):
        """Test handling of empty string parameters."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_list = StanceRequestHandler._plugins_list.__get__(handler)

        result = handler._plugins_list({'type': [''], 'enabled': ['']})

        assert 'plugins' in result

    def test_configure_special_characters_in_name(self):
        """Test configuring plugin with special characters in name."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_plugins = StanceRequestHandler._get_sample_plugins.__get__(handler)
        handler._plugins_configure = StanceRequestHandler._plugins_configure.__get__(handler)

        result = handler._plugins_configure({
            'name': ['plugin-with-dashes_and_underscores'],
            'show': ['true'],
        })

        # Should return not found error since it's not in sample data
        assert 'error' in result
