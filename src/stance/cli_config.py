"""
CLI commands for configuration management.

Provides commands for managing scan configurations including
listing, viewing, creating, editing, and deleting configurations.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def add_config_parser(subparsers: Any) -> None:
    """Add config subcommands to the CLI."""
    config_parser = subparsers.add_parser(
        "config",
        help="Configuration management commands",
        description="Manage scan configurations for Mantissa Stance.",
    )

    config_subparsers = config_parser.add_subparsers(
        dest="config_command",
        title="config commands",
        description="Available configuration commands",
    )

    # List configurations
    list_parser = config_subparsers.add_parser(
        "list",
        help="List available configurations",
        description="List all saved scan configurations.",
    )
    list_parser.add_argument(
        "--config-dir",
        help="Configuration directory (default: ~/.stance/config)",
        default="~/.stance/config",
    )
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Show configuration
    show_parser = config_subparsers.add_parser(
        "show",
        help="Show configuration details",
        description="Display details of a specific configuration.",
    )
    show_parser.add_argument(
        "name",
        nargs="?",
        default="default",
        help="Configuration name (default: default)",
    )
    show_parser.add_argument(
        "--config-dir",
        help="Configuration directory (default: ~/.stance/config)",
        default="~/.stance/config",
    )
    show_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
    show_parser.add_argument(
        "--section",
        choices=["collectors", "accounts", "schedule", "policies", "storage", "notifications"],
        help="Show only a specific section",
    )

    # Create configuration
    create_parser = config_subparsers.add_parser(
        "create",
        help="Create a new configuration",
        description="Create a new scan configuration.",
    )
    create_parser.add_argument(
        "name",
        help="Configuration name",
    )
    create_parser.add_argument(
        "--config-dir",
        help="Configuration directory (default: ~/.stance/config)",
        default="~/.stance/config",
    )
    create_parser.add_argument(
        "--description",
        help="Configuration description",
        default="",
    )
    create_parser.add_argument(
        "--mode",
        choices=["full", "incremental", "targeted"],
        default="full",
        help="Scan mode (default: full)",
    )
    create_parser.add_argument(
        "--from-default",
        action="store_true",
        help="Create from default configuration template",
    )
    create_parser.add_argument(
        "--format",
        choices=["json", "yaml"],
        default="json",
        help="Output format (default: json)",
    )

    # Delete configuration
    delete_parser = config_subparsers.add_parser(
        "delete",
        help="Delete a configuration",
        description="Delete a scan configuration.",
    )
    delete_parser.add_argument(
        "name",
        help="Configuration name to delete",
    )
    delete_parser.add_argument(
        "--config-dir",
        help="Configuration directory (default: ~/.stance/config)",
        default="~/.stance/config",
    )
    delete_parser.add_argument(
        "--force",
        action="store_true",
        help="Delete without confirmation",
    )

    # Edit configuration
    edit_parser = config_subparsers.add_parser(
        "edit",
        help="Edit a configuration",
        description="Edit configuration settings.",
    )
    edit_parser.add_argument(
        "name",
        nargs="?",
        default="default",
        help="Configuration name (default: default)",
    )
    edit_parser.add_argument(
        "--config-dir",
        help="Configuration directory (default: ~/.stance/config)",
        default="~/.stance/config",
    )
    edit_parser.add_argument(
        "--description",
        help="Update description",
    )
    edit_parser.add_argument(
        "--mode",
        choices=["full", "incremental", "targeted"],
        help="Update scan mode",
    )
    edit_parser.add_argument(
        "--storage-backend",
        choices=["local", "s3", "gcs", "azure_blob"],
        help="Update storage backend",
    )
    edit_parser.add_argument(
        "--storage-path",
        help="Update storage path (for local backend)",
    )
    edit_parser.add_argument(
        "--s3-bucket",
        help="Update S3 bucket",
    )
    edit_parser.add_argument(
        "--gcs-bucket",
        help="Update GCS bucket",
    )
    edit_parser.add_argument(
        "--azure-container",
        help="Update Azure container",
    )
    edit_parser.add_argument(
        "--severity-threshold",
        choices=["info", "low", "medium", "high", "critical"],
        help="Update severity threshold",
    )
    edit_parser.add_argument(
        "--retention-days",
        type=int,
        help="Update retention days",
    )

    # Validate configuration
    validate_parser = config_subparsers.add_parser(
        "validate",
        help="Validate a configuration",
        description="Validate configuration settings.",
    )
    validate_parser.add_argument(
        "name",
        nargs="?",
        default="default",
        help="Configuration name (default: default)",
    )
    validate_parser.add_argument(
        "--config-dir",
        help="Configuration directory (default: ~/.stance/config)",
        default="~/.stance/config",
    )
    validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Export configuration
    export_parser = config_subparsers.add_parser(
        "export",
        help="Export a configuration",
        description="Export configuration to file.",
    )
    export_parser.add_argument(
        "name",
        nargs="?",
        default="default",
        help="Configuration name (default: default)",
    )
    export_parser.add_argument(
        "--config-dir",
        help="Configuration directory (default: ~/.stance/config)",
        default="~/.stance/config",
    )
    export_parser.add_argument(
        "--output", "-o",
        help="Output file path",
    )
    export_parser.add_argument(
        "--format",
        choices=["json", "yaml"],
        default="json",
        help="Output format (default: json)",
    )

    # Import configuration
    import_parser = config_subparsers.add_parser(
        "import",
        help="Import a configuration",
        description="Import configuration from file.",
    )
    import_parser.add_argument(
        "file",
        help="Configuration file to import",
    )
    import_parser.add_argument(
        "--config-dir",
        help="Configuration directory (default: ~/.stance/config)",
        default="~/.stance/config",
    )
    import_parser.add_argument(
        "--name",
        help="Override configuration name",
    )
    import_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing configuration",
    )

    # Show default configuration
    default_parser = config_subparsers.add_parser(
        "default",
        help="Show or set default configuration",
        description="Show or set the default configuration.",
    )
    default_parser.add_argument(
        "--config-dir",
        help="Configuration directory (default: ~/.stance/config)",
        default="~/.stance/config",
    )
    default_parser.add_argument(
        "--set",
        metavar="NAME",
        help="Set specified configuration as default",
    )
    default_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # List scan modes
    modes_parser = config_subparsers.add_parser(
        "modes",
        help="List available scan modes",
        description="List all available scan modes and their descriptions.",
    )
    modes_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # List cloud providers
    providers_parser = config_subparsers.add_parser(
        "providers",
        help="List available cloud providers",
        description="List all supported cloud providers.",
    )
    providers_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Configuration schema
    schema_parser = config_subparsers.add_parser(
        "schema",
        help="Show configuration schema",
        description="Display configuration schema information.",
    )
    schema_parser.add_argument(
        "--section",
        choices=["all", "collectors", "accounts", "schedule", "policies", "storage", "notifications"],
        default="all",
        help="Show schema for specific section (default: all)",
    )
    schema_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Configuration environment variables
    env_parser = config_subparsers.add_parser(
        "env",
        help="Show environment variables",
        description="Display configuration environment variables and their current values.",
    )
    env_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )


def cmd_config(args: argparse.Namespace) -> int:
    """Handle config commands."""
    if not hasattr(args, "config_command") or args.config_command is None:
        print("Usage: stance config <command> [options]")
        print("\nAvailable commands:")
        print("  list      - List available configurations")
        print("  show      - Show configuration details")
        print("  create    - Create a new configuration")
        print("  delete    - Delete a configuration")
        print("  edit      - Edit a configuration")
        print("  validate  - Validate a configuration")
        print("  export    - Export a configuration")
        print("  import    - Import a configuration")
        print("  default   - Show or set default configuration")
        print("  modes     - List available scan modes")
        print("  providers - List available cloud providers")
        print("  schema    - Show configuration schema")
        print("  env       - Show environment variables")
        print("\nUse 'stance config <command> --help' for more information.")
        return 0

    handlers = {
        "list": _handle_list,
        "show": _handle_show,
        "create": _handle_create,
        "delete": _handle_delete,
        "edit": _handle_edit,
        "validate": _handle_validate,
        "export": _handle_export,
        "import": _handle_import,
        "default": _handle_default,
        "modes": _handle_modes,
        "providers": _handle_providers,
        "schema": _handle_schema,
        "env": _handle_env,
    }

    handler = handlers.get(args.config_command)
    if handler:
        return handler(args)

    print(f"Unknown config command: {args.config_command}")
    return 1


def _handle_list(args: argparse.Namespace) -> int:
    """Handle list command."""
    from stance.config import ConfigurationManager

    manager = ConfigurationManager(config_dir=args.config_dir)
    configs = manager.list_configurations()

    if args.json:
        result = {
            "configurations": configs,
            "total": len(configs),
            "config_dir": manager.config_dir,
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"Configurations in {manager.config_dir}:")
        print()
        if configs:
            for name in configs:
                # Try to load and get basic info
                try:
                    config = manager.load(name)
                    mode = config.mode.value
                    collectors = len(config.collectors)
                    accounts = len(config.accounts)
                    print(f"  {name}")
                    print(f"    Mode: {mode}, Collectors: {collectors}, Accounts: {accounts}")
                except Exception:
                    print(f"  {name} (could not load)")
        else:
            print("  No configurations found.")
        print()
        print(f"Total: {len(configs)} configuration(s)")

    return 0


def _handle_show(args: argparse.Namespace) -> int:
    """Handle show command."""
    from stance.config import ConfigurationManager

    manager = ConfigurationManager(config_dir=args.config_dir)
    config = manager.load(args.name)

    if args.json:
        if args.section:
            section_data = _get_section(config, args.section)
            print(json.dumps(section_data, indent=2, default=str))
        else:
            print(json.dumps(config.to_dict(), indent=2, default=str))
    else:
        if args.section:
            _print_section(config, args.section)
        else:
            _print_full_config(config)

    return 0


def _get_section(config: Any, section: str) -> dict:
    """Get a specific section from configuration."""
    sections = {
        "collectors": [c.to_dict() for c in config.collectors],
        "accounts": [a.to_dict() for a in config.accounts],
        "schedule": config.schedule.to_dict(),
        "policies": config.policies.to_dict(),
        "storage": config.storage.to_dict(),
        "notifications": config.notifications.to_dict(),
    }
    return sections.get(section, {})


def _print_section(config: Any, section: str) -> None:
    """Print a specific section."""
    print(f"Configuration '{config.name}' - {section.title()}:")
    print()

    if section == "collectors":
        if config.collectors:
            for c in config.collectors:
                status = "enabled" if c.enabled else "disabled"
                print(f"  {c.name}: {status}")
                if c.regions:
                    print(f"    Regions: {', '.join(c.regions)}")
                if c.resource_types:
                    print(f"    Resource Types: {', '.join(c.resource_types)}")
        else:
            print("  No collectors configured (using defaults)")

    elif section == "accounts":
        if config.accounts:
            for a in config.accounts:
                status = "enabled" if a.enabled else "disabled"
                print(f"  {a.account_id} ({a.cloud_provider.value}): {status}")
                if a.name:
                    print(f"    Name: {a.name}")
                if a.regions:
                    print(f"    Regions: {', '.join(a.regions)}")
        else:
            print("  No accounts configured")

    elif section == "schedule":
        s = config.schedule
        status = "enabled" if s.enabled else "disabled"
        print(f"  Status: {status}")
        print(f"  Expression: {s.expression}")
        print(f"  Timezone: {s.timezone}")
        print(f"  Full Scan Expression: {s.full_scan_expression}")
        print(f"  Incremental Enabled: {s.incremental_enabled}")

    elif section == "policies":
        p = config.policies
        print(f"  Policy Directories: {', '.join(p.policy_dirs)}")
        print(f"  Severity Threshold: {p.severity_threshold}")
        if p.enabled_policies:
            print(f"  Enabled Policies: {', '.join(p.enabled_policies)}")
        if p.disabled_policies:
            print(f"  Disabled Policies: {', '.join(p.disabled_policies)}")
        if p.frameworks:
            print(f"  Frameworks: {', '.join(p.frameworks)}")

    elif section == "storage":
        st = config.storage
        print(f"  Backend: {st.backend}")
        print(f"  Local Path: {st.local_path}")
        if st.s3_bucket:
            print(f"  S3 Bucket: {st.s3_bucket}")
            print(f"  S3 Prefix: {st.s3_prefix}")
        if st.gcs_bucket:
            print(f"  GCS Bucket: {st.gcs_bucket}")
            print(f"  GCS Prefix: {st.gcs_prefix}")
        if st.azure_container:
            print(f"  Azure Container: {st.azure_container}")
            print(f"  Azure Prefix: {st.azure_prefix}")
        print(f"  Retention Days: {st.retention_days}")

    elif section == "notifications":
        n = config.notifications
        status = "enabled" if n.enabled else "disabled"
        print(f"  Status: {status}")
        print(f"  Severity Threshold: {n.severity_threshold}")
        print(f"  Rate Limit Per Hour: {n.rate_limit_per_hour}")
        if n.destinations:
            print(f"  Destinations: {len(n.destinations)}")


def _print_full_config(config: Any) -> None:
    """Print full configuration."""
    print(f"Configuration: {config.name}")
    print("=" * 60)
    print()

    print(f"Description: {config.description or '(none)'}")
    print(f"Mode: {config.mode.value}")
    print(f"Created: {config.created_at}")
    print(f"Updated: {config.updated_at}")
    print()

    print("Collectors:")
    if config.collectors:
        for c in config.collectors:
            status = "enabled" if c.enabled else "disabled"
            print(f"  - {c.name}: {status}")
    else:
        print("  (using defaults)")
    print()

    print("Accounts:")
    if config.accounts:
        for a in config.accounts:
            status = "enabled" if a.enabled else "disabled"
            print(f"  - {a.account_id} ({a.cloud_provider.value}): {status}")
    else:
        print("  (none configured)")
    print()

    print("Schedule:")
    s = config.schedule
    status = "enabled" if s.enabled else "disabled"
    print(f"  Status: {status}")
    print(f"  Expression: {s.expression}")
    print()

    print("Policies:")
    p = config.policies
    print(f"  Severity Threshold: {p.severity_threshold}")
    print(f"  Policy Directories: {', '.join(p.policy_dirs)}")
    print()

    print("Storage:")
    st = config.storage
    print(f"  Backend: {st.backend}")
    print(f"  Retention Days: {st.retention_days}")
    print()

    print("Notifications:")
    n = config.notifications
    status = "enabled" if n.enabled else "disabled"
    print(f"  Status: {status}")


def _handle_create(args: argparse.Namespace) -> int:
    """Handle create command."""
    from stance.config import ConfigurationManager, ScanConfiguration, ScanMode, create_default_config

    manager = ConfigurationManager(config_dir=args.config_dir)

    # Check if configuration already exists
    existing = manager.list_configurations()
    if args.name in existing:
        print(f"Error: Configuration '{args.name}' already exists.")
        print("Use 'stance config edit' to modify or 'stance config delete' to remove.")
        return 1

    if args.from_default:
        config = create_default_config()
        config.name = args.name
    else:
        config = ScanConfiguration(name=args.name)

    config.description = args.description
    config.mode = ScanMode(args.mode)

    path = manager.save(config, format=args.format)

    print(f"Created configuration '{args.name}' at {path}")
    return 0


def _handle_delete(args: argparse.Namespace) -> int:
    """Handle delete command."""
    from stance.config import ConfigurationManager

    manager = ConfigurationManager(config_dir=args.config_dir)

    # Check if configuration exists
    existing = manager.list_configurations()
    if args.name not in existing:
        print(f"Error: Configuration '{args.name}' not found.")
        return 1

    if not args.force:
        response = input(f"Delete configuration '{args.name}'? [y/N]: ")
        if response.lower() != "y":
            print("Cancelled.")
            return 0

    if manager.delete(args.name):
        print(f"Deleted configuration '{args.name}'")
        return 0
    else:
        print(f"Error: Failed to delete configuration '{args.name}'")
        return 1


def _handle_edit(args: argparse.Namespace) -> int:
    """Handle edit command."""
    from stance.config import ConfigurationManager, ScanMode

    manager = ConfigurationManager(config_dir=args.config_dir)
    config = manager.load(args.name)

    updated = False

    if args.description is not None:
        config.description = args.description
        updated = True

    if args.mode:
        config.mode = ScanMode(args.mode)
        updated = True

    if args.storage_backend:
        config.storage.backend = args.storage_backend
        updated = True

    if args.storage_path:
        config.storage.local_path = args.storage_path
        updated = True

    if args.s3_bucket:
        config.storage.s3_bucket = args.s3_bucket
        updated = True

    if args.gcs_bucket:
        config.storage.gcs_bucket = args.gcs_bucket
        updated = True

    if args.azure_container:
        config.storage.azure_container = args.azure_container
        updated = True

    if args.severity_threshold:
        config.policies.severity_threshold = args.severity_threshold
        updated = True

    if args.retention_days is not None:
        config.storage.retention_days = args.retention_days
        updated = True

    if updated:
        path = manager.save(config)
        print(f"Updated configuration '{args.name}' at {path}")
    else:
        print("No changes specified. Use --help to see available options.")

    return 0


def _handle_validate(args: argparse.Namespace) -> int:
    """Handle validate command."""
    from stance.config import ConfigurationManager

    manager = ConfigurationManager(config_dir=args.config_dir)

    try:
        config = manager.load(args.name)
    except Exception as e:
        if args.json:
            result = {
                "name": args.name,
                "valid": False,
                "errors": [str(e)],
            }
            print(json.dumps(result, indent=2))
        else:
            print(f"Configuration '{args.name}' is INVALID")
            print(f"Error: {e}")
        return 1

    errors = []
    warnings = []

    # Validate configuration
    if not config.name:
        errors.append("Configuration name is required")

    if config.mode is None:
        errors.append("Scan mode is required")

    # Storage validation
    if config.storage.backend == "s3" and not config.storage.s3_bucket:
        errors.append("S3 bucket is required when using s3 backend")

    if config.storage.backend == "gcs" and not config.storage.gcs_bucket:
        errors.append("GCS bucket is required when using gcs backend")

    if config.storage.backend == "azure_blob" and not config.storage.azure_container:
        errors.append("Azure container is required when using azure_blob backend")

    if config.storage.retention_days < 1:
        warnings.append("Retention days should be at least 1")

    # Collectors validation
    for c in config.collectors:
        if not c.name:
            errors.append("Collector name is required")

    # Accounts validation
    for a in config.accounts:
        if not a.account_id:
            errors.append("Account ID is required")

    is_valid = len(errors) == 0

    if args.json:
        result = {
            "name": args.name,
            "valid": is_valid,
            "errors": errors,
            "warnings": warnings,
        }
        print(json.dumps(result, indent=2))
    else:
        if is_valid:
            print(f"Configuration '{args.name}' is VALID")
            if warnings:
                print("\nWarnings:")
                for w in warnings:
                    print(f"  - {w}")
        else:
            print(f"Configuration '{args.name}' is INVALID")
            print("\nErrors:")
            for e in errors:
                print(f"  - {e}")
            if warnings:
                print("\nWarnings:")
                for w in warnings:
                    print(f"  - {w}")

    return 0 if is_valid else 1


def _handle_export(args: argparse.Namespace) -> int:
    """Handle export command."""
    from stance.config import ConfigurationManager

    manager = ConfigurationManager(config_dir=args.config_dir)
    config = manager.load(args.name)

    if args.format == "yaml":
        try:
            import yaml
            output = yaml.safe_dump(config.to_dict(), default_flow_style=False)
        except ImportError:
            print("Error: PyYAML is required for YAML export")
            print("Install with: pip install pyyaml")
            return 1
    else:
        output = json.dumps(config.to_dict(), indent=2, default=str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Exported configuration '{args.name}' to {args.output}")
    else:
        print(output)

    return 0


def _handle_import(args: argparse.Namespace) -> int:
    """Handle import command."""
    import os
    from stance.config import ConfigurationManager, ScanConfiguration

    manager = ConfigurationManager(config_dir=args.config_dir)

    try:
        config = ScanConfiguration.from_file(args.file)
    except Exception as e:
        print(f"Error: Failed to load configuration from {args.file}")
        print(f"  {e}")
        return 1

    if args.name:
        config.name = args.name

    # Check if configuration already exists
    existing = manager.list_configurations()
    if config.name in existing and not args.force:
        print(f"Error: Configuration '{config.name}' already exists.")
        print("Use --force to overwrite or --name to specify a different name.")
        return 1

    # Determine format from file extension
    ext = os.path.splitext(args.file)[1].lower()
    format_type = "yaml" if ext in [".yaml", ".yml"] else "json"

    path = manager.save(config, format=format_type)
    print(f"Imported configuration '{config.name}' to {path}")
    return 0


def _handle_default(args: argparse.Namespace) -> int:
    """Handle default command."""
    from stance.config import ConfigurationManager

    manager = ConfigurationManager(config_dir=args.config_dir)

    if args.set:
        # Set specified configuration as default
        existing = manager.list_configurations()
        if args.set not in existing:
            print(f"Error: Configuration '{args.set}' not found.")
            return 1

        config = manager.load(args.set)
        path = manager.set_default(config)
        print(f"Set '{args.set}' as default configuration at {path}")
        return 0

    # Show default configuration
    config = manager.get_default()

    if args.json:
        print(json.dumps(config.to_dict(), indent=2, default=str))
    else:
        _print_full_config(config)

    return 0


def _handle_modes(args: argparse.Namespace) -> int:
    """Handle modes command."""
    from stance.config import ScanMode

    modes = [
        {
            "name": "full",
            "description": "Complete scan of all resources",
            "use_case": "Initial scans, compliance audits, comprehensive assessments",
        },
        {
            "name": "incremental",
            "description": "Only scan changes since last snapshot",
            "use_case": "Regular scheduled scans, continuous monitoring",
        },
        {
            "name": "targeted",
            "description": "Scan specific resource types only",
            "use_case": "Focused investigations, specific resource audits",
        },
    ]

    if args.json:
        result = {
            "modes": modes,
            "total": len(modes),
        }
        print(json.dumps(result, indent=2))
    else:
        print("Available Scan Modes:")
        print()
        for mode in modes:
            print(f"  {mode['name']}")
            print(f"    Description: {mode['description']}")
            print(f"    Use Case: {mode['use_case']}")
            print()

    return 0


def _handle_providers(args: argparse.Namespace) -> int:
    """Handle providers command."""
    from stance.config import CloudProvider

    providers = [
        {
            "name": "aws",
            "display_name": "Amazon Web Services",
            "enum_value": CloudProvider.AWS.value,
        },
        {
            "name": "gcp",
            "display_name": "Google Cloud Platform",
            "enum_value": CloudProvider.GCP.value,
        },
        {
            "name": "azure",
            "display_name": "Microsoft Azure",
            "enum_value": CloudProvider.AZURE.value,
        },
    ]

    if args.json:
        result = {
            "providers": providers,
            "total": len(providers),
        }
        print(json.dumps(result, indent=2))
    else:
        print("Supported Cloud Providers:")
        print()
        for p in providers:
            print(f"  {p['name']} - {p['display_name']}")
        print()
        print(f"Total: {len(providers)} provider(s)")

    return 0


def _handle_schema(args: argparse.Namespace) -> int:
    """Handle schema command."""
    schemas = {
        "collectors": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Collector name"},
                    "enabled": {"type": "boolean", "default": True, "description": "Enable/disable collector"},
                    "regions": {"type": "array", "items": {"type": "string"}, "description": "Regions to scan"},
                    "resource_types": {"type": "array", "items": {"type": "string"}, "description": "Resource types to collect"},
                    "options": {"type": "object", "description": "Collector-specific options"},
                },
                "required": ["name"],
            },
        },
        "accounts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "account_id": {"type": "string", "description": "Cloud account ID"},
                    "cloud_provider": {"type": "string", "enum": ["aws", "gcp", "azure"], "description": "Cloud provider"},
                    "name": {"type": "string", "description": "Display name"},
                    "regions": {"type": "array", "items": {"type": "string"}, "description": "Regions to scan"},
                    "assume_role_arn": {"type": "string", "description": "AWS IAM role ARN for cross-account access"},
                    "project_id": {"type": "string", "description": "GCP project ID"},
                    "subscription_id": {"type": "string", "description": "Azure subscription ID"},
                    "enabled": {"type": "boolean", "default": True, "description": "Enable/disable account"},
                },
                "required": ["account_id", "cloud_provider"],
            },
        },
        "schedule": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "default": True, "description": "Enable scheduled scans"},
                "expression": {"type": "string", "default": "rate(1 hour)", "description": "Cron or rate expression"},
                "timezone": {"type": "string", "default": "UTC", "description": "Timezone for schedule"},
                "full_scan_expression": {"type": "string", "default": "cron(0 0 * * ? *)", "description": "Expression for full scans"},
                "incremental_enabled": {"type": "boolean", "default": True, "description": "Enable incremental scans"},
            },
        },
        "policies": {
            "type": "object",
            "properties": {
                "policy_dirs": {"type": "array", "items": {"type": "string"}, "default": ["policies/"], "description": "Policy directories"},
                "enabled_policies": {"type": "array", "items": {"type": "string"}, "description": "List of enabled policy IDs"},
                "disabled_policies": {"type": "array", "items": {"type": "string"}, "description": "List of disabled policy IDs"},
                "severity_threshold": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"], "default": "info", "description": "Minimum severity to report"},
                "frameworks": {"type": "array", "items": {"type": "string"}, "description": "Compliance frameworks to evaluate"},
            },
        },
        "storage": {
            "type": "object",
            "properties": {
                "backend": {"type": "string", "enum": ["local", "s3", "gcs", "azure_blob"], "default": "local", "description": "Storage backend"},
                "local_path": {"type": "string", "default": "~/.stance", "description": "Local storage path"},
                "s3_bucket": {"type": "string", "description": "S3 bucket name"},
                "s3_prefix": {"type": "string", "default": "stance", "description": "S3 key prefix"},
                "gcs_bucket": {"type": "string", "description": "GCS bucket name"},
                "gcs_prefix": {"type": "string", "default": "stance", "description": "GCS object prefix"},
                "azure_container": {"type": "string", "description": "Azure blob container name"},
                "azure_prefix": {"type": "string", "default": "stance", "description": "Azure blob prefix"},
                "retention_days": {"type": "integer", "default": 90, "description": "Data retention period in days"},
            },
        },
        "notifications": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "default": False, "description": "Enable notifications"},
                "destinations": {"type": "array", "items": {"type": "object"}, "description": "Notification destinations"},
                "severity_threshold": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"], "default": "high", "description": "Minimum severity to notify"},
                "rate_limit_per_hour": {"type": "integer", "default": 100, "description": "Maximum notifications per hour"},
            },
        },
    }

    if args.section == "all":
        output = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Configuration name"},
                "description": {"type": "string", "description": "Configuration description"},
                "mode": {"type": "string", "enum": ["full", "incremental", "targeted"], "description": "Scan mode"},
                "collectors": schemas["collectors"],
                "accounts": schemas["accounts"],
                "schedule": schemas["schedule"],
                "policies": schemas["policies"],
                "storage": schemas["storage"],
                "notifications": schemas["notifications"],
                "created_at": {"type": "string", "format": "datetime", "description": "Creation timestamp"},
                "updated_at": {"type": "string", "format": "datetime", "description": "Last update timestamp"},
            },
            "required": ["name"],
        }
    else:
        output = schemas.get(args.section, {})

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print(f"Configuration Schema{' - ' + args.section.title() if args.section != 'all' else ''}:")
        print()
        _print_schema(output, indent=0)

    return 0


def _print_schema(schema: dict, indent: int = 0) -> None:
    """Print schema in readable format."""
    prefix = "  " * indent

    schema_type = schema.get("type", "unknown")

    if schema_type == "object":
        props = schema.get("properties", {})
        required = schema.get("required", [])

        for name, prop in props.items():
            req_marker = " *" if name in required else ""
            prop_type = prop.get("type", "any")
            default = prop.get("default", "")
            desc = prop.get("description", "")

            if prop_type == "object":
                print(f"{prefix}{name}{req_marker}: object")
                if desc:
                    print(f"{prefix}  # {desc}")
                _print_schema(prop, indent + 1)
            elif prop_type == "array":
                items_type = prop.get("items", {}).get("type", "any")
                print(f"{prefix}{name}{req_marker}: array[{items_type}]")
                if desc:
                    print(f"{prefix}  # {desc}")
                if default:
                    print(f"{prefix}  default: {default}")
            else:
                enum_vals = prop.get("enum")
                if enum_vals:
                    print(f"{prefix}{name}{req_marker}: {prop_type} ({', '.join(enum_vals)})")
                else:
                    print(f"{prefix}{name}{req_marker}: {prop_type}")
                if desc:
                    print(f"{prefix}  # {desc}")
                if default != "":
                    print(f"{prefix}  default: {default}")

    elif schema_type == "array":
        items = schema.get("items", {})
        print(f"{prefix}items:")
        _print_schema(items, indent + 1)


def _handle_env(args: argparse.Namespace) -> int:
    """Handle env command."""
    import os

    env_vars = [
        {
            "name": "STANCE_CONFIG_FILE",
            "description": "Path to configuration file",
            "current": os.getenv("STANCE_CONFIG_FILE", ""),
        },
        {
            "name": "STANCE_COLLECTORS",
            "description": "Comma-separated list of collectors",
            "current": os.getenv("STANCE_COLLECTORS", ""),
        },
        {
            "name": "STANCE_REGIONS",
            "description": "Comma-separated list of regions",
            "current": os.getenv("STANCE_REGIONS", ""),
        },
        {
            "name": "STANCE_STORAGE_BACKEND",
            "description": "Storage backend (local, s3, gcs, azure_blob)",
            "current": os.getenv("STANCE_STORAGE_BACKEND", ""),
        },
        {
            "name": "STANCE_S3_BUCKET",
            "description": "S3 bucket name",
            "current": os.getenv("STANCE_S3_BUCKET", ""),
        },
        {
            "name": "STANCE_GCS_BUCKET",
            "description": "GCS bucket name",
            "current": os.getenv("STANCE_GCS_BUCKET", ""),
        },
        {
            "name": "STANCE_AZURE_CONTAINER",
            "description": "Azure container name",
            "current": os.getenv("STANCE_AZURE_CONTAINER", ""),
        },
        {
            "name": "STANCE_POLICY_DIRS",
            "description": "Comma-separated policy directories",
            "current": os.getenv("STANCE_POLICY_DIRS", ""),
        },
        {
            "name": "STANCE_SEVERITY_THRESHOLD",
            "description": "Minimum severity to report",
            "current": os.getenv("STANCE_SEVERITY_THRESHOLD", ""),
        },
    ]

    if args.json:
        result = {
            "environment_variables": env_vars,
            "total": len(env_vars),
        }
        print(json.dumps(result, indent=2))
    else:
        print("Configuration Environment Variables:")
        print()
        for var in env_vars:
            current = var["current"] or "(not set)"
            print(f"  {var['name']}")
            print(f"    Description: {var['description']}")
            print(f"    Current Value: {current}")
            print()

    return 0
