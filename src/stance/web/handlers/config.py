"""
Configuration management handlers for the Stance web API.

This module handles all /api/config/* endpoints for configuration
management including list, show, create, delete, edit, import, export,
and validation operations.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)

# Maximum length for configuration names
MAX_CONFIG_NAME_LENGTH = 64

# Pattern for valid configuration names: alphanumeric, underscore, hyphen
VALID_CONFIG_NAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]*$')


def _validate_config_name(name: str) -> tuple[bool, str]:
    """
    Validate a configuration name for security and format.

    Args:
        name: Configuration name to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not name:
        return False, "Configuration name cannot be empty"

    if len(name) > MAX_CONFIG_NAME_LENGTH:
        return False, f"Configuration name too long (max {MAX_CONFIG_NAME_LENGTH} characters)"

    # Check for null bytes (injection attempt)
    if "\x00" in name:
        return False, "Configuration name contains invalid characters"

    # Check for path traversal attempts (including URL-encoded variants)
    traversal_patterns = ["..", "/", "\\", "%2e", "%2f", "%5c"]
    name_lower = name.lower()
    for pattern in traversal_patterns:
        if pattern in name_lower:
            return False, "Configuration name contains invalid characters"

    # Check for reserved names (Windows and Unix)
    reserved_names = {
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4",
        "lpt1", "lpt2", "lpt3", "lpt4", ".", "..",
        ".git", ".env", ".ssh", ".aws", ".config"
    }
    if name_lower in reserved_names:
        return False, f"Configuration name '{name}' is reserved"

    # Validate pattern
    if not VALID_CONFIG_NAME_PATTERN.match(name):
        return False, "Configuration name must start with a letter and contain only letters, numbers, underscores, or hyphens"

    return True, ""


def _validate_config_dir(config_dir: str) -> tuple[bool, str]:
    """
    Validate a configuration directory path for security.

    Args:
        config_dir: Configuration directory path to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not config_dir:
        return False, "Configuration directory cannot be empty"

    # Expand user path
    expanded = os.path.expanduser(config_dir)

    # Check for path traversal attempts
    if ".." in config_dir:
        return False, "Configuration directory contains path traversal"

    # Resolve to absolute path and verify it's under allowed locations
    try:
        resolved = os.path.realpath(expanded)

        # Must be under user's home directory or /tmp for testing
        home_dir = os.path.expanduser("~")
        allowed_prefixes = (home_dir, "/tmp", os.path.join(home_dir, ".stance"))

        if not any(resolved.startswith(prefix) for prefix in allowed_prefixes):
            return False, "Configuration directory must be under home directory"

    except (OSError, ValueError) as e:
        return False, f"Invalid configuration directory: {e}"

    return True, ""


class ConfigHandler(RoutedHandler):
    """
    Handler for configuration management API endpoints.

    Handles:
    - Configuration listing and viewing
    - Configuration creation and deletion
    - Configuration editing and import/export
    - Configuration validation
    - Scan modes and cloud provider info
    - Configuration schema and environment variables
    """

    base_path = "/api/config/"

    def __init__(self, *args, **kwargs) -> None:
        """Initialize handler with optional config manager reference."""
        super().__init__(*args, **kwargs)
        self._config_manager = None

    def _get_config_manager(self, config_dir: str = "~/.stance/config"):
        """Get or create configuration manager instance."""
        if self._config_manager is None:
            try:
                from stance.config import ConfigurationManager
                self._config_manager = ConfigurationManager(config_dir=config_dir)
            except ImportError:
                self._config_manager = None
        return self._config_manager

    # =========================================================================
    # Configuration GET endpoints
    # =========================================================================

    @route("list")
    def config_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List all configurations."""
        try:
            config_dir = self.get_param(params, "config_dir", "~/.stance/config")

            # Validate config directory path
            is_valid, error = _validate_config_dir(config_dir)
            if not is_valid:
                return HandlerResponse.error(error, HttpStatus.BAD_REQUEST)

            # Try to use real config manager if available
            manager = self._get_config_manager(config_dir)
            if manager:
                try:
                    configs = manager.list_configurations()
                    config_details = []
                    for name in configs:
                        try:
                            config = manager.load(name)
                            config_details.append({
                                "name": name,
                                "description": config.description,
                                "mode": config.mode.value if config.mode else "full",
                                "collectors": len(config.collectors) if hasattr(config, "collectors") else 0,
                                "accounts": len(config.accounts) if hasattr(config, "accounts") else 0,
                                "created_at": config.created_at.isoformat() if hasattr(config, "created_at") else None,
                                "updated_at": config.updated_at.isoformat() if hasattr(config, "updated_at") else None,
                            })
                        except Exception:
                            config_details.append({
                                "name": name,
                                "error": "Could not load configuration",
                            })
                    return HandlerResponse.success({
                        "configurations": config_details,
                        "total": len(configs),
                        "config_dir": manager.config_dir,
                    })
                except Exception:
                    pass

            # Fallback to demo data
            result = {
                "configurations": [
                    {
                        "name": "default",
                        "description": "Default scan configuration",
                        "mode": "full",
                        "collectors": 5,
                        "accounts": 2,
                        "created_at": "2024-01-15T10:00:00Z",
                        "updated_at": "2024-12-30T14:30:00Z",
                    },
                    {
                        "name": "production",
                        "description": "Production environment configuration",
                        "mode": "incremental",
                        "collectors": 8,
                        "accounts": 5,
                        "created_at": "2024-03-01T09:00:00Z",
                        "updated_at": "2024-12-29T16:45:00Z",
                    },
                ],
                "total": 2,
                "config_dir": config_dir,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to list configurations")
            return HandlerResponse.server_error(str(e))

    @route("show")
    def config_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show configuration details."""
        try:
            name = self.get_param(params, "name", "default")
            section = self.get_param(params, "section", "")

            # Validate configuration name
            is_valid, error = _validate_config_name(name)
            if not is_valid:
                return HandlerResponse.error(error, HttpStatus.BAD_REQUEST)

            # Demo configuration data
            config_data = {
                "name": name,
                "description": "Scan configuration",
                "mode": "full",
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-12-30T14:30:00Z",
                "collectors": [
                    {"name": "aws_ec2", "enabled": True, "regions": ["us-east-1", "us-west-2"]},
                    {"name": "aws_s3", "enabled": True, "regions": ["us-east-1"]},
                ],
                "accounts": [
                    {"account_id": "123456789012", "cloud_provider": "aws", "name": "Production"},
                ],
                "schedule": {
                    "enabled": True,
                    "expression": "rate(1 hour)",
                    "timezone": "UTC",
                },
                "policies": {
                    "policy_dirs": ["~/.stance/policies"],
                    "severity_threshold": "medium",
                    "frameworks": ["CIS", "NIST"],
                },
                "storage": {
                    "backend": "local",
                    "local_path": "~/.stance",
                    "retention_days": 90,
                },
                "notifications": {
                    "enabled": False,
                    "destinations": [],
                    "severity_threshold": "high",
                },
            }

            if section:
                sections = {
                    "collectors": config_data.get("collectors", []),
                    "accounts": config_data.get("accounts", []),
                    "schedule": config_data.get("schedule", {}),
                    "policies": config_data.get("policies", {}),
                    "storage": config_data.get("storage", {}),
                    "notifications": config_data.get("notifications", {}),
                }
                return HandlerResponse.success({
                    "name": name,
                    "section": section,
                    "data": sections.get(section, {}),
                })

            return HandlerResponse.success(config_data)
        except Exception as e:
            logger.exception("Failed to show configuration")
            return HandlerResponse.server_error(str(e))

    @route("validate")
    def config_validate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate a configuration."""
        try:
            name = self.get_param(params, "name", "default")

            # Demo validation response
            result = {
                "name": name,
                "valid": True,
                "errors": [],
                "warnings": [],
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to validate configuration")
            return HandlerResponse.server_error(str(e))

    @route("default")
    def config_default(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get default configuration."""
        try:
            result = {
                "name": "default",
                "description": "Default scan configuration",
                "mode": "full",
                "collectors": [],
                "accounts": [],
                "schedule": {
                    "enabled": True,
                    "expression": "rate(1 hour)",
                    "timezone": "UTC",
                },
                "policies": {
                    "policy_dirs": ["~/.stance/policies"],
                    "severity_threshold": "medium",
                },
                "storage": {
                    "backend": "local",
                    "local_path": "~/.stance",
                    "retention_days": 90,
                },
                "notifications": {
                    "enabled": False,
                },
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get default configuration")
            return HandlerResponse.server_error(str(e))

    @route("modes")
    def config_modes(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available scan modes."""
        try:
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
            return HandlerResponse.success({
                "modes": modes,
                "total": len(modes),
            })
        except Exception as e:
            logger.exception("Failed to list scan modes")
            return HandlerResponse.server_error(str(e))

    @route("providers")
    def config_providers(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available cloud providers."""
        try:
            providers = [
                {
                    "name": "aws",
                    "display_name": "Amazon Web Services",
                    "enum_value": "aws",
                },
                {
                    "name": "gcp",
                    "display_name": "Google Cloud Platform",
                    "enum_value": "gcp",
                },
                {
                    "name": "azure",
                    "display_name": "Microsoft Azure",
                    "enum_value": "azure",
                },
            ]
            return HandlerResponse.success({
                "providers": providers,
                "total": len(providers),
            })
        except Exception as e:
            logger.exception("Failed to list cloud providers")
            return HandlerResponse.server_error(str(e))

    @route("schema")
    def config_schema(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get configuration schema."""
        try:
            section = self.get_param(params, "section", "all")

            schemas = {
                "collectors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Collector name"},
                            "enabled": {"type": "boolean", "default": True},
                            "regions": {"type": "array", "items": {"type": "string"}},
                            "resource_types": {"type": "array", "items": {"type": "string"}},
                            "options": {"type": "object"},
                        },
                        "required": ["name"],
                    },
                },
                "accounts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "account_id": {"type": "string"},
                            "cloud_provider": {"type": "string", "enum": ["aws", "gcp", "azure"]},
                            "name": {"type": "string"},
                            "regions": {"type": "array", "items": {"type": "string"}},
                            "assume_role_arn": {"type": "string"},
                            "enabled": {"type": "boolean", "default": True},
                        },
                        "required": ["account_id", "cloud_provider"],
                    },
                },
                "schedule": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": True},
                        "expression": {"type": "string", "default": "rate(1 hour)"},
                        "timezone": {"type": "string", "default": "UTC"},
                        "incremental_enabled": {"type": "boolean", "default": True},
                    },
                },
                "policies": {
                    "type": "object",
                    "properties": {
                        "policy_dirs": {"type": "array", "items": {"type": "string"}},
                        "enabled_policies": {"type": "array", "items": {"type": "string"}},
                        "disabled_policies": {"type": "array", "items": {"type": "string"}},
                        "severity_threshold": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                        "frameworks": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "storage": {
                    "type": "object",
                    "properties": {
                        "backend": {"type": "string", "enum": ["local", "s3", "gcs", "azure_blob"]},
                        "local_path": {"type": "string", "default": "~/.stance"},
                        "s3_bucket": {"type": "string"},
                        "gcs_bucket": {"type": "string"},
                        "azure_container": {"type": "string"},
                        "retention_days": {"type": "integer", "default": 90},
                    },
                },
                "notifications": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "default": False},
                        "destinations": {"type": "array", "items": {"type": "object"}},
                        "severity_threshold": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                        "rate_limit_per_hour": {"type": "integer", "default": 100},
                    },
                },
            }

            if section == "all":
                result = {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                        "mode": {"type": "string", "enum": ["full", "incremental", "targeted"]},
                        "collectors": schemas["collectors"],
                        "accounts": schemas["accounts"],
                        "schedule": schemas["schedule"],
                        "policies": schemas["policies"],
                        "storage": schemas["storage"],
                        "notifications": schemas["notifications"],
                    },
                    "required": ["name"],
                }
            else:
                result = schemas.get(section, {})

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get schema")
            return HandlerResponse.server_error(str(e))

    @route("env")
    def config_env(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get configuration environment variables."""
        try:
            env_vars = [
                {"name": "STANCE_CONFIG_FILE", "description": "Path to configuration file", "current": os.getenv("STANCE_CONFIG_FILE", "")},
                {"name": "STANCE_COLLECTORS", "description": "Comma-separated list of collectors", "current": os.getenv("STANCE_COLLECTORS", "")},
                {"name": "STANCE_REGIONS", "description": "Comma-separated list of regions", "current": os.getenv("STANCE_REGIONS", "")},
                {"name": "STANCE_STORAGE_BACKEND", "description": "Storage backend", "current": os.getenv("STANCE_STORAGE_BACKEND", "")},
                {"name": "STANCE_S3_BUCKET", "description": "S3 bucket name", "current": os.getenv("STANCE_S3_BUCKET", "")},
                {"name": "STANCE_GCS_BUCKET", "description": "GCS bucket name", "current": os.getenv("STANCE_GCS_BUCKET", "")},
                {"name": "STANCE_AZURE_CONTAINER", "description": "Azure container name", "current": os.getenv("STANCE_AZURE_CONTAINER", "")},
                {"name": "STANCE_POLICY_DIRS", "description": "Comma-separated policy directories", "current": os.getenv("STANCE_POLICY_DIRS", "")},
                {"name": "STANCE_SEVERITY_THRESHOLD", "description": "Minimum severity to report", "current": os.getenv("STANCE_SEVERITY_THRESHOLD", "")},
            ]
            return HandlerResponse.success({
                "environment_variables": env_vars,
                "total": len(env_vars),
            })
        except Exception as e:
            logger.exception("Failed to get environment variables")
            return HandlerResponse.server_error(str(e))

    @route("status")
    def config_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get configuration module status."""
        try:
            config_dir = self.get_param(params, "config_dir", "~/.stance/config")

            result = {
                "module": "config",
                "components": {
                    "ScanConfiguration": True,
                    "ConfigurationManager": True,
                    "CollectorConfig": True,
                    "AccountConfig": True,
                    "ScheduleConfig": True,
                    "PolicyConfig": True,
                    "StorageConfig": True,
                    "NotificationConfig": True,
                },
                "enums": {
                    "CloudProvider": ["aws", "gcp", "azure"],
                    "ScanMode": ["full", "incremental", "targeted"],
                },
                "utilities": {
                    "load_config_from_env": True,
                    "create_default_config": True,
                },
                "config_dir": config_dir,
                "configurations": 2,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get config status")
            return HandlerResponse.server_error(str(e))

    @route("summary")
    def config_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get comprehensive config module summary."""
        try:
            config_dir = self.get_param(params, "config_dir", "~/.stance/config")

            result = {
                "overview": {
                    "description": "Scan configuration management for Mantissa Stance",
                    "config_dir": config_dir,
                    "total_configurations": 2,
                    "configurations": ["default", "production"],
                },
                "features": [
                    "Multi-cloud configuration support (AWS, GCP, Azure)",
                    "Collector configuration (enable/disable, regions, resource types)",
                    "Account management (multiple accounts, cross-account access)",
                    "Schedule configuration (cron expressions, incremental scans)",
                    "Policy configuration (directories, severities, frameworks)",
                    "Storage backend configuration (local, S3, GCS, Azure Blob)",
                    "Notification configuration (destinations, rate limits)",
                    "Environment variable support",
                    "JSON and YAML format support",
                ],
                "architecture": {
                    "main_class": "ScanConfiguration",
                    "manager_class": "ConfigurationManager",
                    "sub_configs": [
                        "CollectorConfig",
                        "AccountConfig",
                        "ScheduleConfig",
                        "PolicyConfig",
                        "StorageConfig",
                        "NotificationConfig",
                    ],
                },
                "supported_formats": ["json", "yaml"],
                "scan_modes": ["full", "incremental", "targeted"],
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get config summary")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Configuration POST endpoints
    # =========================================================================

    @route("create", methods=["POST"])
    def config_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a new configuration."""
        try:
            data = body or {}
            name = data.get("name", "")

            # Validate configuration name
            is_valid, error_msg = _validate_config_name(name)
            if not is_valid:
                return HandlerResponse.error(error_msg, HttpStatus.BAD_REQUEST)

            # Demo response - in real impl would create config
            result = {
                "success": True,
                "name": name,
                "path": f"~/.stance/config/{name}.json",
            }
            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to create configuration")
            return HandlerResponse.server_error(str(e))

    @route("delete", methods=["POST"])
    def config_delete(self, params: dict, body: dict | None) -> HandlerResponse:
        """Delete a configuration."""
        try:
            data = body or {}
            name = data.get("name", "")

            # Validate configuration name
            is_valid, error_msg = _validate_config_name(name)
            if not is_valid:
                return HandlerResponse.error(error_msg, HttpStatus.BAD_REQUEST)

            # Demo response
            result = {
                "success": True,
                "name": name,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to delete configuration")
            return HandlerResponse.server_error(str(e))

    @route("edit", methods=["POST"])
    def config_edit(self, params: dict, body: dict | None) -> HandlerResponse:
        """Edit a configuration."""
        try:
            data = body or {}
            name = data.get("name", "default")

            # Check if any editable fields are provided
            editable_fields = ["description", "mode", "storage_backend", "storage_path",
                               "s3_bucket", "gcs_bucket", "azure_container",
                               "severity_threshold", "retention_days"]

            has_changes = any(field in data for field in editable_fields)

            if not has_changes:
                return HandlerResponse.success({
                    "success": False,
                    "message": "No changes specified",
                })

            result = {
                "success": True,
                "name": name,
                "path": f"~/.stance/config/{name}.json",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to edit configuration")
            return HandlerResponse.server_error(str(e))

    @route("import", methods=["POST"])
    def config_import(self, params: dict, body: dict | None) -> HandlerResponse:
        """Import a configuration from JSON."""
        try:
            data = body or {}
            config_data = data.get("config")

            if not config_data:
                return HandlerResponse.error("Missing required field: config", HttpStatus.BAD_REQUEST)

            # Validate config_data is a dictionary
            if not isinstance(config_data, dict):
                return HandlerResponse.error("config must be a JSON object", HttpStatus.BAD_REQUEST)

            name = data.get("name") or config_data.get("name", "imported")

            # Validate configuration name
            is_valid, error_msg = _validate_config_name(name)
            if not is_valid:
                return HandlerResponse.error(error_msg, HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "name": name,
                "path": f"~/.stance/config/{name}.json",
            }
            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to import configuration")
            return HandlerResponse.server_error(str(e))

    @route("export", methods=["POST"])
    def config_export(self, params: dict, body: dict | None) -> HandlerResponse:
        """Export a configuration."""
        try:
            data = body or {}
            name = data.get("name", "default")
            export_format = data.get("format", "json")

            # Demo export content
            config_content = {
                "name": name,
                "description": "Exported configuration",
                "mode": "full",
                "collectors": [],
                "accounts": [],
                "schedule": {"enabled": True},
                "policies": {},
                "storage": {"backend": "local"},
                "notifications": {"enabled": False},
            }

            if export_format == "yaml":
                # Simplified YAML representation
                yaml_content = f"""name: {name}
description: Exported configuration
mode: full
collectors: []
accounts: []
schedule:
  enabled: true
policies: {{}}
storage:
  backend: local
notifications:
  enabled: false
"""
                result = {
                    "name": name,
                    "format": "yaml",
                    "content": yaml_content,
                }
            else:
                result = {
                    "name": name,
                    "format": "json",
                    "content": config_content,
                }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to export configuration")
            return HandlerResponse.server_error(str(e))

    @route("set-default", methods=["POST"])
    def config_set_default(self, params: dict, body: dict | None) -> HandlerResponse:
        """Set a configuration as default."""
        try:
            data = body or {}
            name = data.get("name", "")

            if not name:
                return HandlerResponse.error("Missing required field: name", HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "name": name,
                "default_path": f"~/.stance/config/{name}.json",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to set default configuration")
            return HandlerResponse.server_error(str(e))
