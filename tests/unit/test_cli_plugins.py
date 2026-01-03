"""
Unit tests for CLI plugins commands.

Tests the Plugin System CLI commands including listing,
loading, unloading, enabling, disabling, and configuring plugins.
"""

from __future__ import annotations

import argparse
import json
import sys
from io import StringIO
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


class TestPluginsListCommand:
    """Tests for 'stance plugins list' command."""

    def test_list_all_plugins(self):
        """Test listing all plugins."""
        from stance.cli_plugins import _handle_plugins_list

        args = argparse.Namespace(
            format='table',
            type=None,
            enabled=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.list_plugins.return_value = [
                {
                    'name': 'aws_collector',
                    'version': '1.0.0',
                    'type': 'collector',
                    'enabled': True,
                    'description': 'AWS resource collector',
                },
                {
                    'name': 'cis_benchmark',
                    'version': '2.0.0',
                    'type': 'policy',
                    'enabled': False,
                    'description': 'CIS Benchmark policies',
                },
            ]

            result = _handle_plugins_list(args)
            assert result == 0

    def test_list_plugins_json_format(self):
        """Test listing plugins in JSON format."""
        from stance.cli_plugins import _handle_plugins_list

        args = argparse.Namespace(
            format='json',
            type=None,
            enabled=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.list_plugins.return_value = [
                {
                    'name': 'aws_collector',
                    'type': 'collector',
                    'enabled': True,
                },
            ]

            result = _handle_plugins_list(args)
            assert result == 0

    def test_list_plugins_filter_by_type(self):
        """Test listing plugins filtered by type."""
        from stance.cli_plugins import _handle_plugins_list

        args = argparse.Namespace(
            format='table',
            type='collector',
            enabled=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.list_plugins.return_value = [
                {
                    'name': 'aws_collector',
                    'type': 'collector',
                    'enabled': True,
                },
                {
                    'name': 'cis_benchmark',
                    'type': 'policy',
                    'enabled': True,
                },
            ]

            result = _handle_plugins_list(args)
            assert result == 0

    def test_list_plugins_enabled_only(self):
        """Test listing only enabled plugins."""
        from stance.cli_plugins import _handle_plugins_list

        args = argparse.Namespace(
            format='table',
            type=None,
            enabled=True,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.list_plugins.return_value = [
                {
                    'name': 'aws_collector',
                    'type': 'collector',
                    'enabled': True,
                },
                {
                    'name': 'disabled_plugin',
                    'type': 'collector',
                    'enabled': False,
                },
            ]

            result = _handle_plugins_list(args)
            assert result == 0


class TestPluginsInfoCommand:
    """Tests for 'stance plugins info' command."""

    def test_info_existing_plugin(self):
        """Test getting info for existing plugin."""
        from stance.cli_plugins import _handle_plugins_info

        args = argparse.Namespace(
            name='aws_collector',
            format='text',
            verbose=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.get_plugin_info.return_value = {
                'name': 'aws_collector',
                'version': '1.0.0',
                'type': 'collector',
                'enabled': True,
                'description': 'AWS resource collector',
            }

            result = _handle_plugins_info(args)
            assert result == 0

    def test_info_plugin_not_found(self):
        """Test getting info for non-existent plugin."""
        from stance.cli_plugins import _handle_plugins_info, PluginNotFoundError

        args = argparse.Namespace(
            name='nonexistent',
            format='text',
            verbose=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.get_plugin_info.side_effect = PluginNotFoundError('Not found')

            result = _handle_plugins_info(args)
            assert result == 1

    def test_info_verbose_mode(self):
        """Test verbose info output."""
        from stance.cli_plugins import _handle_plugins_info

        args = argparse.Namespace(
            name='aws_collector',
            format='text',
            verbose=True,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.get_plugin_info.return_value = {
                'name': 'aws_collector',
                'version': '1.0.0',
                'type': 'collector',
                'enabled': True,
                'description': 'AWS resource collector',
                'author': 'Mantissa',
                'dependencies': ['boto3'],
                'config_schema': {'type': 'object'},
            }

            result = _handle_plugins_info(args)
            assert result == 0

    def test_info_json_format(self):
        """Test info in JSON format."""
        from stance.cli_plugins import _handle_plugins_info

        args = argparse.Namespace(
            name='aws_collector',
            format='json',
            verbose=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.get_plugin_info.return_value = {
                'name': 'aws_collector',
                'type': 'collector',
            }

            result = _handle_plugins_info(args)
            assert result == 0

    def test_info_missing_name(self):
        """Test info with missing plugin name."""
        from stance.cli_plugins import _handle_plugins_info

        args = argparse.Namespace(
            name=None,
            format='text',
            verbose=False,
        )

        result = _handle_plugins_info(args)
        assert result == 1


class TestPluginsLoadCommand:
    """Tests for 'stance plugins load' command."""

    def test_load_plugin_success(self):
        """Test loading a plugin successfully."""
        from stance.cli_plugins import _handle_plugins_load

        args = argparse.Namespace(
            source='/path/to/plugin.py',
            type=None,
            config=None,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.load_plugin.return_value = {
                'name': 'custom_plugin',
                'warnings': [],
            }

            result = _handle_plugins_load(args)
            assert result == 0

    def test_load_plugin_with_type(self):
        """Test loading a plugin with specified type."""
        from stance.cli_plugins import _handle_plugins_load

        args = argparse.Namespace(
            source='my.module.plugin',
            type='collector',
            config=None,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.load_plugin.return_value = {
                'name': 'plugin',
            }

            result = _handle_plugins_load(args)
            assert result == 0

    def test_load_plugin_with_config_file(self, tmp_path):
        """Test loading plugin with config file."""
        from stance.cli_plugins import _handle_plugins_load

        config_file = tmp_path / "config.json"
        config_file.write_text('{"key": "value"}')

        args = argparse.Namespace(
            source='/path/to/plugin.py',
            type=None,
            config=str(config_file),
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.load_plugin.return_value = {
                'name': 'plugin',
            }

            result = _handle_plugins_load(args)
            assert result == 0

    def test_load_plugin_missing_source(self):
        """Test loading plugin with missing source."""
        from stance.cli_plugins import _handle_plugins_load

        args = argparse.Namespace(
            source=None,
            type=None,
            config=None,
        )

        result = _handle_plugins_load(args)
        assert result == 1

    def test_load_plugin_failure(self):
        """Test handling plugin load failure."""
        from stance.cli_plugins import _handle_plugins_load, PluginLoadError

        args = argparse.Namespace(
            source='/path/to/invalid.py',
            type=None,
            config=None,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.load_plugin.side_effect = PluginLoadError('Invalid plugin')

            result = _handle_plugins_load(args)
            assert result == 1


class TestPluginsUnloadCommand:
    """Tests for 'stance plugins unload' command."""

    def test_unload_plugin_success(self):
        """Test unloading a plugin successfully."""
        from stance.cli_plugins import _handle_plugins_unload

        args = argparse.Namespace(
            name='my_plugin',
            force=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            result = _handle_plugins_unload(args)
            assert result == 0

    def test_unload_plugin_force(self):
        """Test force unloading a plugin."""
        from stance.cli_plugins import _handle_plugins_unload

        args = argparse.Namespace(
            name='my_plugin',
            force=True,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            result = _handle_plugins_unload(args)
            assert result == 0

    def test_unload_plugin_not_found(self):
        """Test unloading non-existent plugin."""
        from stance.cli_plugins import _handle_plugins_unload, PluginNotFoundError

        args = argparse.Namespace(
            name='nonexistent',
            force=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.unload_plugin.side_effect = PluginNotFoundError('Not found')

            result = _handle_plugins_unload(args)
            assert result == 1


class TestPluginsReloadCommand:
    """Tests for 'stance plugins reload' command."""

    def test_reload_plugin_success(self):
        """Test reloading a plugin successfully."""
        from stance.cli_plugins import _handle_plugins_reload

        args = argparse.Namespace(
            name='my_plugin',
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.reload_plugin.return_value = {
                'warnings': [],
            }

            result = _handle_plugins_reload(args)
            assert result == 0

    def test_reload_plugin_with_warnings(self):
        """Test reloading a plugin with warnings."""
        from stance.cli_plugins import _handle_plugins_reload

        args = argparse.Namespace(
            name='my_plugin',
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.reload_plugin.return_value = {
                'warnings': ['Config changed', 'Reconnect required'],
            }

            result = _handle_plugins_reload(args)
            assert result == 0


class TestPluginsEnableDisableCommands:
    """Tests for 'stance plugins enable/disable' commands."""

    def test_enable_plugin(self):
        """Test enabling a plugin."""
        from stance.cli_plugins import _handle_plugins_enable

        args = argparse.Namespace(
            name='my_plugin',
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            result = _handle_plugins_enable(args)
            assert result == 0

    def test_disable_plugin(self):
        """Test disabling a plugin."""
        from stance.cli_plugins import _handle_plugins_disable

        args = argparse.Namespace(
            name='my_plugin',
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            result = _handle_plugins_disable(args)
            assert result == 0

    def test_enable_nonexistent_plugin(self):
        """Test enabling non-existent plugin."""
        from stance.cli_plugins import _handle_plugins_enable, PluginNotFoundError

        args = argparse.Namespace(
            name='nonexistent',
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.enable_plugin.side_effect = PluginNotFoundError('Not found')

            result = _handle_plugins_enable(args)
            assert result == 1


class TestPluginsConfigureCommand:
    """Tests for 'stance plugins configure' command."""

    def test_configure_show_current(self):
        """Test showing current plugin configuration."""
        from stance.cli_plugins import _handle_plugins_configure

        args = argparse.Namespace(
            name='my_plugin',
            config=None,
            json=None,
            set=None,
            show=True,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.get_plugin_info.return_value = {
                'current_config': {'key': 'value'},
                'config_schema': {'type': 'object'},
            }

            result = _handle_plugins_configure(args)
            assert result == 0

    def test_configure_with_json(self):
        """Test configuring plugin with JSON string."""
        from stance.cli_plugins import _handle_plugins_configure

        args = argparse.Namespace(
            name='my_plugin',
            config=None,
            json='{"key": "value"}',
            set=None,
            show=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            result = _handle_plugins_configure(args)
            assert result == 0

    def test_configure_with_set_values(self):
        """Test configuring plugin with key=value pairs."""
        from stance.cli_plugins import _handle_plugins_configure

        args = argparse.Namespace(
            name='my_plugin',
            config=None,
            json=None,
            set=['key1=value1', 'key2=123'],
            show=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            result = _handle_plugins_configure(args)
            assert result == 0

    def test_configure_with_config_file(self, tmp_path):
        """Test configuring plugin with config file."""
        from stance.cli_plugins import _handle_plugins_configure

        config_file = tmp_path / "config.json"
        config_file.write_text('{"setting": true}')

        args = argparse.Namespace(
            name='my_plugin',
            config=str(config_file),
            json=None,
            set=None,
            show=False,
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            result = _handle_plugins_configure(args)
            assert result == 0

    def test_configure_invalid_json(self):
        """Test configuring with invalid JSON."""
        from stance.cli_plugins import _handle_plugins_configure

        args = argparse.Namespace(
            name='my_plugin',
            config=None,
            json='{invalid json}',
            set=None,
            show=False,
        )

        result = _handle_plugins_configure(args)
        assert result == 1


class TestPluginsDiscoverCommand:
    """Tests for 'stance plugins discover' command."""

    def test_discover_plugins(self):
        """Test discovering available plugins."""
        from stance.cli_plugins import _handle_plugins_discover

        args = argparse.Namespace(
            paths=None,
            load=False,
            format='table',
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.discover_plugins.return_value = [
                {
                    'name': 'aws_collector',
                    'type': 'collector',
                    'source': '/path/to/aws.py',
                    'loaded': False,
                },
            ]

            result = _handle_plugins_discover(args)
            assert result == 0

    def test_discover_with_custom_paths(self):
        """Test discovering plugins in custom paths."""
        from stance.cli_plugins import _handle_plugins_discover

        args = argparse.Namespace(
            paths=['/custom/path', '/another/path'],
            load=False,
            format='table',
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.discover_plugins.return_value = []

            result = _handle_plugins_discover(args)
            assert result == 0

    def test_discover_and_auto_load(self):
        """Test discovering and auto-loading plugins."""
        from stance.cli_plugins import _handle_plugins_discover

        args = argparse.Namespace(
            paths=None,
            load=True,
            format='table',
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.discover_plugins.return_value = [
                {
                    'name': 'new_plugin',
                    'type': 'collector',
                    'source': '/path/to/new.py',
                    'loaded': False,
                },
            ]
            mock_manager.return_value.load_plugin.return_value = {}

            result = _handle_plugins_discover(args)
            assert result == 0


class TestPluginsTypesCommand:
    """Tests for 'stance plugins types' command."""

    def test_list_plugin_types(self):
        """Test listing available plugin types."""
        from stance.cli_plugins import _handle_plugins_types

        args = argparse.Namespace(
            format='table',
        )

        result = _handle_plugins_types(args)
        assert result == 0

    def test_list_plugin_types_json(self):
        """Test listing plugin types in JSON format."""
        from stance.cli_plugins import _handle_plugins_types

        args = argparse.Namespace(
            format='json',
        )

        result = _handle_plugins_types(args)
        assert result == 0


class TestPluginsStatusCommand:
    """Tests for 'stance plugins status' command."""

    def test_get_plugins_status(self):
        """Test getting plugin system status."""
        from stance.cli_plugins import _handle_plugins_status

        args = argparse.Namespace(
            format='text',
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.list_plugins.return_value = [
                {'name': 'p1', 'type': 'collector', 'enabled': True},
                {'name': 'p2', 'type': 'policy', 'enabled': True},
                {'name': 'p3', 'type': 'collector', 'enabled': False},
            ]

            result = _handle_plugins_status(args)
            assert result == 0

    def test_get_plugins_status_json(self):
        """Test getting plugin status in JSON format."""
        from stance.cli_plugins import _handle_plugins_status

        args = argparse.Namespace(
            format='json',
        )

        with patch('stance.cli_plugins.get_plugin_manager') as mock_manager:
            mock_manager.return_value.list_plugins.return_value = []

            result = _handle_plugins_status(args)
            assert result == 0


class TestCmdPlugins:
    """Tests for main cmd_plugins function."""

    def test_cmd_plugins_no_action(self):
        """Test cmd_plugins with no action shows help."""
        from stance.cli_plugins import cmd_plugins

        args = argparse.Namespace(
            plugins_action=None,
        )

        result = cmd_plugins(args)
        assert result == 0

    def test_cmd_plugins_unknown_action(self):
        """Test cmd_plugins with unknown action."""
        from stance.cli_plugins import cmd_plugins

        args = argparse.Namespace(
            plugins_action='unknown_action',
        )

        result = cmd_plugins(args)
        assert result == 1


class TestAddPluginsParser:
    """Tests for add_plugins_parser function."""

    def test_add_plugins_parser(self):
        """Test adding plugins parser to subparsers."""
        from stance.cli_plugins import add_plugins_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        add_plugins_parser(subparsers)

        # Parse a valid plugins command
        args = parser.parse_args(['plugins', 'list'])
        assert args.plugins_action == 'list'

    def test_plugins_list_parser(self):
        """Test plugins list subparser."""
        from stance.cli_plugins import add_plugins_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_plugins_parser(subparsers)

        args = parser.parse_args(['plugins', 'list', '--type', 'collector', '--format', 'json'])
        assert args.plugins_action == 'list'
        assert args.type == 'collector'
        assert args.format == 'json'

    def test_plugins_info_parser(self):
        """Test plugins info subparser."""
        from stance.cli_plugins import add_plugins_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_plugins_parser(subparsers)

        args = parser.parse_args(['plugins', 'info', 'my_plugin', '--verbose'])
        assert args.plugins_action == 'info'
        assert args.name == 'my_plugin'
        assert args.verbose is True

    def test_plugins_load_parser(self):
        """Test plugins load subparser."""
        from stance.cli_plugins import add_plugins_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_plugins_parser(subparsers)

        args = parser.parse_args(['plugins', 'load', '/path/to/plugin.py', '--type', 'collector'])
        assert args.plugins_action == 'load'
        assert args.source == '/path/to/plugin.py'
        assert args.type == 'collector'

    def test_plugins_configure_parser(self):
        """Test plugins configure subparser."""
        from stance.cli_plugins import add_plugins_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_plugins_parser(subparsers)

        args = parser.parse_args(['plugins', 'configure', 'my_plugin', '--set', 'key=value', '--set', 'other=123'])
        assert args.plugins_action == 'configure'
        assert args.name == 'my_plugin'
        assert args.set == ['key=value', 'other=123']

    def test_plugins_discover_parser(self):
        """Test plugins discover subparser."""
        from stance.cli_plugins import add_plugins_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_plugins_parser(subparsers)

        args = parser.parse_args(['plugins', 'discover', '--paths', '/p1', '/p2', '--load'])
        assert args.plugins_action == 'discover'
        assert args.paths == ['/p1', '/p2']
        assert args.load is True


class TestFormatFunctions:
    """Tests for formatting helper functions."""

    def test_format_plugin_info(self):
        """Test formatting plugin info."""
        from stance.cli_plugins import _format_plugin_info

        plugin_info = {
            'name': 'my_plugin',
            'version': '1.0.0',
            'type': 'collector',
            'enabled': True,
            'description': 'Test plugin',
        }

        result = _format_plugin_info(plugin_info)
        assert 'my_plugin' in result
        assert '1.0.0' in result
        assert 'collector' in result

    def test_format_plugin_info_verbose(self):
        """Test formatting plugin info in verbose mode."""
        from stance.cli_plugins import _format_plugin_info

        plugin_info = {
            'name': 'my_plugin',
            'version': '1.0.0',
            'type': 'collector',
            'enabled': True,
            'description': 'Test plugin',
            'author': 'Test Author',
            'dependencies': ['dep1', 'dep2'],
            'config_schema': {'type': 'object'},
        }

        result = _format_plugin_info(plugin_info, verbose=True)
        assert 'Test Author' in result
        assert 'dep1' in result

    def test_format_plugin_table(self):
        """Test formatting plugins as table."""
        from stance.cli_plugins import _format_plugin_table

        plugins = [
            {
                'name': 'plugin1',
                'version': '1.0.0',
                'type': 'collector',
                'enabled': True,
                'description': 'First plugin',
            },
            {
                'name': 'plugin2',
                'version': '2.0.0',
                'type': 'policy',
                'enabled': False,
                'description': 'Second plugin',
            },
        ]

        result = _format_plugin_table(plugins)
        assert 'plugin1' in result
        assert 'plugin2' in result
        assert 'collector' in result
        assert 'policy' in result

    def test_format_plugin_table_empty(self):
        """Test formatting empty plugin list."""
        from stance.cli_plugins import _format_plugin_table

        result = _format_plugin_table([])
        assert 'No plugins found' in result


class TestPluginManagerIntegration:
    """Integration tests with PluginManager."""

    def test_get_plugin_manager_creates_singleton(self):
        """Test that get_plugin_manager creates/returns singleton."""
        from stance.cli_plugins import get_plugin_manager, _plugin_manager

        # Reset global
        import stance.cli_plugins
        stance.cli_plugins._plugin_manager = None

        with patch('stance.cli_plugins.PluginManager') as MockManager:
            MockManager.return_value = MagicMock()

            manager1 = get_plugin_manager()
            manager2 = get_plugin_manager()

            # Should create only once
            MockManager.assert_called_once()
            assert manager1 is manager2
