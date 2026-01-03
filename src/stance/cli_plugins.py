"""
CLI commands for Plugin System management.

Provides command-line interface for managing plugins including
listing, loading, unloading, enabling, disabling, and configuring.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from stance.plugins import (
    PluginManager,
    PluginRegistry,
    PluginType,
    PluginLoadError,
    PluginConfigError,
    PluginNotFoundError,
)


# Global plugin manager instance
_plugin_manager: PluginManager | None = None


def get_plugin_manager() -> PluginManager:
    """Get or create the global plugin manager instance."""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager


def _format_plugin_info(plugin_info: dict[str, Any], verbose: bool = False) -> str:
    """Format plugin information for display."""
    lines = []
    lines.append(f"  Name: {plugin_info.get('name', 'unknown')}")
    lines.append(f"  Version: {plugin_info.get('version', 'unknown')}")
    lines.append(f"  Type: {plugin_info.get('type', 'unknown')}")
    lines.append(f"  Enabled: {plugin_info.get('enabled', False)}")

    if plugin_info.get('description'):
        lines.append(f"  Description: {plugin_info.get('description')}")

    if verbose:
        if plugin_info.get('author'):
            lines.append(f"  Author: {plugin_info.get('author')}")
        if plugin_info.get('dependencies'):
            lines.append(f"  Dependencies: {', '.join(plugin_info.get('dependencies', []))}")
        if plugin_info.get('config_schema'):
            lines.append(f"  Config Schema: {json.dumps(plugin_info.get('config_schema'), indent=4)}")
        if plugin_info.get('current_config'):
            lines.append(f"  Current Config: {json.dumps(plugin_info.get('current_config'), indent=4)}")

    return "\n".join(lines)


def _format_plugin_table(plugins: list[dict[str, Any]]) -> str:
    """Format plugins as a table."""
    if not plugins:
        return "No plugins found."

    # Calculate column widths
    name_width = max(len(p.get('name', '')) for p in plugins)
    name_width = max(name_width, 4)  # Minimum "Name"

    type_width = max(len(p.get('type', '')) for p in plugins)
    type_width = max(type_width, 4)  # Minimum "Type"

    version_width = max(len(p.get('version', '')) for p in plugins)
    version_width = max(version_width, 7)  # Minimum "Version"

    # Build table
    lines = []
    header = f"{'Name':<{name_width}}  {'Type':<{type_width}}  {'Version':<{version_width}}  {'Enabled':<8}  Description"
    lines.append(header)
    lines.append("-" * len(header))

    for plugin in sorted(plugins, key=lambda p: p.get('name', '')):
        enabled = "Yes" if plugin.get('enabled', False) else "No"
        description = plugin.get('description', '')[:50]
        if len(plugin.get('description', '')) > 50:
            description += "..."

        line = f"{plugin.get('name', ''):<{name_width}}  {plugin.get('type', ''):<{type_width}}  {plugin.get('version', ''):<{version_width}}  {enabled:<8}  {description}"
        lines.append(line)

    return "\n".join(lines)


def cmd_plugins(args: argparse.Namespace) -> int:
    """Handle plugin commands."""
    action = getattr(args, 'plugins_action', None)

    if action is None:
        print("Usage: stance plugins <command>")
        print("\nCommands:")
        print("  list       List all registered plugins")
        print("  info       Get detailed plugin information")
        print("  load       Load a plugin from source")
        print("  unload     Unload a plugin")
        print("  reload     Reload a plugin")
        print("  enable     Enable a plugin")
        print("  disable    Disable a plugin")
        print("  configure  Configure a plugin")
        print("  discover   Discover available plugins")
        print("  types      List available plugin types")
        print("  status     Show plugin system status")
        return 0

    handlers = {
        'list': _handle_plugins_list,
        'info': _handle_plugins_info,
        'load': _handle_plugins_load,
        'unload': _handle_plugins_unload,
        'reload': _handle_plugins_reload,
        'enable': _handle_plugins_enable,
        'disable': _handle_plugins_disable,
        'configure': _handle_plugins_configure,
        'discover': _handle_plugins_discover,
        'types': _handle_plugins_types,
        'status': _handle_plugins_status,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown plugins action: {action}")
    return 1


def _handle_plugins_list(args: argparse.Namespace) -> int:
    """List all registered plugins."""
    manager = get_plugin_manager()
    output_format = getattr(args, 'format', 'table')
    plugin_type = getattr(args, 'type', None)
    enabled_only = getattr(args, 'enabled', False)

    try:
        # Get all plugins
        plugins = manager.list_plugins()

        # Filter by type if specified
        if plugin_type:
            plugins = [p for p in plugins if p.get('type') == plugin_type]

        # Filter by enabled status if specified
        if enabled_only:
            plugins = [p for p in plugins if p.get('enabled', False)]

        if output_format == 'json':
            print(json.dumps(plugins, indent=2))
        else:
            print(_format_plugin_table(plugins))
            print(f"\nTotal: {len(plugins)} plugin(s)")

        return 0

    except Exception as e:
        print(f"Error listing plugins: {e}", file=sys.stderr)
        return 1


def _handle_plugins_info(args: argparse.Namespace) -> int:
    """Get detailed information about a plugin."""
    manager = get_plugin_manager()
    name = getattr(args, 'name', None)
    output_format = getattr(args, 'format', 'text')
    verbose = getattr(args, 'verbose', False)

    if not name:
        print("Error: Plugin name is required", file=sys.stderr)
        return 1

    try:
        # Get plugin info
        plugin_info = manager.get_plugin_info(name)

        if plugin_info is None:
            print(f"Plugin not found: {name}", file=sys.stderr)
            return 1

        if output_format == 'json':
            print(json.dumps(plugin_info, indent=2))
        else:
            print(f"Plugin: {name}")
            print(_format_plugin_info(plugin_info, verbose=verbose))

        return 0

    except PluginNotFoundError:
        print(f"Plugin not found: {name}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error getting plugin info: {e}", file=sys.stderr)
        return 1


def _handle_plugins_load(args: argparse.Namespace) -> int:
    """Load a plugin from source."""
    manager = get_plugin_manager()
    source = getattr(args, 'source', None)
    plugin_type = getattr(args, 'type', None)
    config_file = getattr(args, 'config', None)

    if not source:
        print("Error: Plugin source is required", file=sys.stderr)
        return 1

    try:
        # Load config from file if specified
        config = None
        if config_file:
            with open(config_file) as f:
                config = json.load(f)

        # Load the plugin
        result = manager.load_plugin(
            source=source,
            plugin_type=plugin_type,
            config=config,
        )

        print(f"Successfully loaded plugin: {result.get('name', source)}")
        if result.get('warnings'):
            for warning in result['warnings']:
                print(f"  Warning: {warning}")

        return 0

    except PluginLoadError as e:
        print(f"Failed to load plugin: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"Config file not found: {config_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in config file: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error loading plugin: {e}", file=sys.stderr)
        return 1


def _handle_plugins_unload(args: argparse.Namespace) -> int:
    """Unload a plugin."""
    manager = get_plugin_manager()
    name = getattr(args, 'name', None)
    force = getattr(args, 'force', False)

    if not name:
        print("Error: Plugin name is required", file=sys.stderr)
        return 1

    try:
        manager.unload_plugin(name, force=force)
        print(f"Successfully unloaded plugin: {name}")
        return 0

    except PluginNotFoundError:
        print(f"Plugin not found: {name}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error unloading plugin: {e}", file=sys.stderr)
        return 1


def _handle_plugins_reload(args: argparse.Namespace) -> int:
    """Reload a plugin."""
    manager = get_plugin_manager()
    name = getattr(args, 'name', None)

    if not name:
        print("Error: Plugin name is required", file=sys.stderr)
        return 1

    try:
        result = manager.reload_plugin(name)
        print(f"Successfully reloaded plugin: {name}")
        if result.get('warnings'):
            for warning in result['warnings']:
                print(f"  Warning: {warning}")
        return 0

    except PluginNotFoundError:
        print(f"Plugin not found: {name}", file=sys.stderr)
        return 1
    except PluginLoadError as e:
        print(f"Failed to reload plugin: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error reloading plugin: {e}", file=sys.stderr)
        return 1


def _handle_plugins_enable(args: argparse.Namespace) -> int:
    """Enable a plugin."""
    manager = get_plugin_manager()
    name = getattr(args, 'name', None)

    if not name:
        print("Error: Plugin name is required", file=sys.stderr)
        return 1

    try:
        manager.enable_plugin(name)
        print(f"Successfully enabled plugin: {name}")
        return 0

    except PluginNotFoundError:
        print(f"Plugin not found: {name}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error enabling plugin: {e}", file=sys.stderr)
        return 1


def _handle_plugins_disable(args: argparse.Namespace) -> int:
    """Disable a plugin."""
    manager = get_plugin_manager()
    name = getattr(args, 'name', None)

    if not name:
        print("Error: Plugin name is required", file=sys.stderr)
        return 1

    try:
        manager.disable_plugin(name)
        print(f"Successfully disabled plugin: {name}")
        return 0

    except PluginNotFoundError:
        print(f"Plugin not found: {name}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error disabling plugin: {e}", file=sys.stderr)
        return 1


def _handle_plugins_configure(args: argparse.Namespace) -> int:
    """Configure a plugin."""
    manager = get_plugin_manager()
    name = getattr(args, 'name', None)
    config_file = getattr(args, 'config', None)
    config_json = getattr(args, 'json', None)
    set_value = getattr(args, 'set', None)
    show = getattr(args, 'show', False)

    if not name:
        print("Error: Plugin name is required", file=sys.stderr)
        return 1

    try:
        # Show current config
        if show:
            plugin_info = manager.get_plugin_info(name)
            if plugin_info is None:
                print(f"Plugin not found: {name}", file=sys.stderr)
                return 1

            current_config = plugin_info.get('current_config', {})
            config_schema = plugin_info.get('config_schema', {})

            print(f"Plugin: {name}")
            print(f"\nConfig Schema:")
            print(json.dumps(config_schema, indent=2))
            print(f"\nCurrent Configuration:")
            print(json.dumps(current_config, indent=2))
            return 0

        # Build config from various sources
        config = {}

        if config_file:
            with open(config_file) as f:
                config = json.load(f)

        if config_json:
            config.update(json.loads(config_json))

        if set_value:
            for kv in set_value:
                if '=' not in kv:
                    print(f"Invalid key=value format: {kv}", file=sys.stderr)
                    return 1
                key, value = kv.split('=', 1)
                # Try to parse as JSON, fallback to string
                try:
                    config[key] = json.loads(value)
                except json.JSONDecodeError:
                    config[key] = value

        if not config:
            print("Error: No configuration provided. Use --config, --json, or --set", file=sys.stderr)
            return 1

        # Apply configuration
        manager.configure_plugin(name, config)
        print(f"Successfully configured plugin: {name}")
        return 0

    except PluginNotFoundError:
        print(f"Plugin not found: {name}", file=sys.stderr)
        return 1
    except PluginConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"Config file not found: {config_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error configuring plugin: {e}", file=sys.stderr)
        return 1


def _handle_plugins_discover(args: argparse.Namespace) -> int:
    """Discover available plugins."""
    manager = get_plugin_manager()
    paths = getattr(args, 'paths', None)
    output_format = getattr(args, 'format', 'table')
    auto_load = getattr(args, 'load', False)

    try:
        # Discover plugins
        discovered = manager.discover_plugins(paths=paths)

        if output_format == 'json':
            print(json.dumps(discovered, indent=2))
        else:
            if not discovered:
                print("No plugins discovered.")
            else:
                print(f"Discovered {len(discovered)} plugin(s):\n")
                for plugin in discovered:
                    status = "loaded" if plugin.get('loaded', False) else "available"
                    print(f"  - {plugin.get('name', 'unknown')} ({plugin.get('type', 'unknown')}) [{status}]")
                    if plugin.get('source'):
                        print(f"    Source: {plugin.get('source')}")

        # Auto-load if requested
        if auto_load:
            loaded_count = 0
            for plugin in discovered:
                if not plugin.get('loaded', False) and plugin.get('source'):
                    try:
                        manager.load_plugin(source=plugin['source'])
                        loaded_count += 1
                        print(f"  Loaded: {plugin.get('name', 'unknown')}")
                    except Exception as e:
                        print(f"  Failed to load {plugin.get('name', 'unknown')}: {e}")

            if loaded_count > 0:
                print(f"\nLoaded {loaded_count} new plugin(s)")

        return 0

    except Exception as e:
        print(f"Error discovering plugins: {e}", file=sys.stderr)
        return 1


def _handle_plugins_types(args: argparse.Namespace) -> int:
    """List available plugin types."""
    output_format = getattr(args, 'format', 'table')

    types_info = [
        {
            "type": PluginType.COLLECTOR.value,
            "description": "Data collection plugins for gathering assets and configurations",
            "examples": "AWS collector, GCP collector, Azure collector",
        },
        {
            "type": PluginType.POLICY.value,
            "description": "Security policy plugins for evaluating compliance rules",
            "examples": "CIS Benchmarks, custom policies, SOC2 controls",
        },
        {
            "type": PluginType.ENRICHER.value,
            "description": "Data enrichment plugins for augmenting asset information",
            "examples": "Geo-IP lookup, threat intelligence, CVE enrichment",
        },
        {
            "type": PluginType.ALERT_DESTINATION.value,
            "description": "Alert destination plugins for sending notifications",
            "examples": "Slack, PagerDuty, Email, webhooks",
        },
        {
            "type": PluginType.REPORT_FORMAT.value,
            "description": "Report format plugins for generating output formats",
            "examples": "PDF, HTML, JSON, CSV exporters",
        },
    ]

    if output_format == 'json':
        print(json.dumps(types_info, indent=2))
    else:
        print("Available Plugin Types:\n")
        for type_info in types_info:
            print(f"  {type_info['type']}")
            print(f"    {type_info['description']}")
            print(f"    Examples: {type_info['examples']}")
            print()

    return 0


def _handle_plugins_status(args: argparse.Namespace) -> int:
    """Show plugin system status."""
    manager = get_plugin_manager()
    output_format = getattr(args, 'format', 'text')

    try:
        # Gather status information
        plugins = manager.list_plugins()

        status = {
            "total_plugins": len(plugins),
            "enabled_plugins": sum(1 for p in plugins if p.get('enabled', False)),
            "disabled_plugins": sum(1 for p in plugins if not p.get('enabled', False)),
            "plugins_by_type": {},
            "registry_healthy": True,
        }

        # Count by type
        for plugin in plugins:
            ptype = plugin.get('type', 'unknown')
            if ptype not in status['plugins_by_type']:
                status['plugins_by_type'][ptype] = 0
            status['plugins_by_type'][ptype] += 1

        if output_format == 'json':
            print(json.dumps(status, indent=2))
        else:
            print("Plugin System Status")
            print("=" * 40)
            print(f"\nTotal Plugins: {status['total_plugins']}")
            print(f"  Enabled: {status['enabled_plugins']}")
            print(f"  Disabled: {status['disabled_plugins']}")

            if status['plugins_by_type']:
                print("\nPlugins by Type:")
                for ptype, count in sorted(status['plugins_by_type'].items()):
                    print(f"  {ptype}: {count}")

            print(f"\nRegistry Status: {'Healthy' if status['registry_healthy'] else 'Unhealthy'}")

        return 0

    except Exception as e:
        print(f"Error getting plugin status: {e}", file=sys.stderr)
        return 1


def add_plugins_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add plugin management parser to CLI."""
    plugins_parser = subparsers.add_parser(
        'plugins',
        help='Plugin management commands',
        description='Manage plugins for extending Stance functionality',
    )

    plugins_subparsers = plugins_parser.add_subparsers(
        dest='plugins_action',
        title='Plugin Commands',
    )

    # list command
    list_parser = plugins_subparsers.add_parser(
        'list',
        help='List all registered plugins',
    )
    list_parser.add_argument(
        '--type', '-t',
        choices=[t.value for t in PluginType],
        help='Filter by plugin type',
    )
    list_parser.add_argument(
        '--enabled',
        action='store_true',
        help='Show only enabled plugins',
    )
    list_parser.add_argument(
        '--format', '-f',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)',
    )

    # info command
    info_parser = plugins_subparsers.add_parser(
        'info',
        help='Get detailed plugin information',
    )
    info_parser.add_argument(
        'name',
        help='Plugin name',
    )
    info_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show verbose information including config schema',
    )
    info_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )

    # load command
    load_parser = plugins_subparsers.add_parser(
        'load',
        help='Load a plugin from source',
    )
    load_parser.add_argument(
        'source',
        help='Plugin source (file path, module name, or URL)',
    )
    load_parser.add_argument(
        '--type', '-t',
        choices=[t.value for t in PluginType],
        help='Plugin type (auto-detected if not specified)',
    )
    load_parser.add_argument(
        '--config', '-c',
        metavar='FILE',
        help='Configuration file (JSON)',
    )

    # unload command
    unload_parser = plugins_subparsers.add_parser(
        'unload',
        help='Unload a plugin',
    )
    unload_parser.add_argument(
        'name',
        help='Plugin name',
    )
    unload_parser.add_argument(
        '--force',
        action='store_true',
        help='Force unload even if plugin is in use',
    )

    # reload command
    reload_parser = plugins_subparsers.add_parser(
        'reload',
        help='Reload a plugin',
    )
    reload_parser.add_argument(
        'name',
        help='Plugin name',
    )

    # enable command
    enable_parser = plugins_subparsers.add_parser(
        'enable',
        help='Enable a plugin',
    )
    enable_parser.add_argument(
        'name',
        help='Plugin name',
    )

    # disable command
    disable_parser = plugins_subparsers.add_parser(
        'disable',
        help='Disable a plugin',
    )
    disable_parser.add_argument(
        'name',
        help='Plugin name',
    )

    # configure command
    configure_parser = plugins_subparsers.add_parser(
        'configure',
        help='Configure a plugin',
    )
    configure_parser.add_argument(
        'name',
        help='Plugin name',
    )
    configure_parser.add_argument(
        '--config', '-c',
        metavar='FILE',
        help='Configuration file (JSON)',
    )
    configure_parser.add_argument(
        '--json', '-j',
        metavar='JSON',
        help='Configuration as JSON string',
    )
    configure_parser.add_argument(
        '--set', '-s',
        action='append',
        metavar='KEY=VALUE',
        help='Set individual config value (can be repeated)',
    )
    configure_parser.add_argument(
        '--show',
        action='store_true',
        help='Show current configuration',
    )

    # discover command
    discover_parser = plugins_subparsers.add_parser(
        'discover',
        help='Discover available plugins',
    )
    discover_parser.add_argument(
        '--paths', '-p',
        nargs='+',
        help='Paths to search for plugins',
    )
    discover_parser.add_argument(
        '--load',
        action='store_true',
        help='Auto-load discovered plugins',
    )
    discover_parser.add_argument(
        '--format', '-f',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)',
    )

    # types command
    types_parser = plugins_subparsers.add_parser(
        'types',
        help='List available plugin types',
    )
    types_parser.add_argument(
        '--format', '-f',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)',
    )

    # status command
    status_parser = plugins_subparsers.add_parser(
        'status',
        help='Show plugin system status',
    )
    status_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )
