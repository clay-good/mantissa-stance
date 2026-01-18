"""
Plugins handlers for the Stance web API.

This module handles all /api/plugins/* endpoints for plugin management,
discovery, configuration, and lifecycle operations.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class PluginsHandler(RoutedHandler):
    """
    Handler for plugins API endpoints.

    Handles:
    - Plugin listing and discovery
    - Plugin lifecycle (load, unload, reload)
    - Plugin configuration
    - Plugin enable/disable
    """

    base_path = "/api/plugins/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("list")
    def plugins_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List all registered plugins.

        Query params:
            type: Filter by plugin type (collector, policy, enricher, etc.)
            enabled: Filter by enabled status (true/false)
        """
        plugin_type = self.get_param(params, "type", "")
        enabled_filter = self.get_param(params, "enabled", "")

        plugins = self._get_sample_plugins()

        if plugin_type:
            plugins = [p for p in plugins if p.get("type") == plugin_type]

        if enabled_filter:
            enabled_bool = enabled_filter.lower() == "true"
            plugins = [p for p in plugins if p.get("enabled", False) == enabled_bool]

        return HandlerResponse.success({
            "plugins": plugins,
            "total": len(plugins),
            "enabled_count": sum(1 for p in plugins if p.get("enabled", False)),
            "disabled_count": sum(1 for p in plugins if not p.get("enabled", False)),
        })

    @route("info")
    def plugins_info(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get detailed information about a specific plugin.

        Query params:
            name: Plugin name (required)
        """
        name = self.get_param(params, "name", "")

        if not name:
            return HandlerResponse.error("Plugin name is required", HttpStatus.BAD_REQUEST)

        plugins = self._get_sample_plugins()
        plugin = next((p for p in plugins if p.get("name") == name), None)

        if not plugin:
            return HandlerResponse.not_found("Plugin")

        plugin = dict(plugin)
        plugin["config_schema"] = self._get_plugin_config_schema(plugin.get("type", ""))
        plugin["capabilities"] = self._get_plugin_capabilities(plugin.get("type", ""))

        return HandlerResponse.success(plugin)

    @route("types")
    def plugins_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List all plugin types."""
        types = [
            {
                "value": "collector",
                "name": "Collector",
                "description": "Collects cloud resource data from providers",
                "examples": ["aws_s3", "azure_storage", "gcp_compute"],
            },
            {
                "value": "policy",
                "name": "Policy",
                "description": "Defines security evaluation policies",
                "examples": ["cis_benchmark", "custom_policy"],
            },
            {
                "value": "enricher",
                "name": "Enricher",
                "description": "Enriches findings with additional context",
                "examples": ["cve_enricher", "ip_enricher"],
            },
            {
                "value": "alert_destination",
                "name": "Alert Destination",
                "description": "Sends alerts to external systems",
                "examples": ["slack", "pagerduty", "jira"],
            },
            {
                "value": "report_format",
                "name": "Report Format",
                "description": "Generates reports in specific formats",
                "examples": ["pdf_report", "csv_export"],
            },
            {
                "value": "scanner",
                "name": "Scanner",
                "description": "Performs security scanning",
                "examples": ["trivy", "iac_scanner", "secrets_scanner"],
            },
        ]

        return HandlerResponse.success({
            "types": types,
            "total": len(types),
        })

    @route("discover")
    def plugins_discover(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Discover available plugins.

        Query params:
            path: Path to search for plugins (optional)
        """
        path = self.get_param(params, "path", "")

        discovered = [
            {
                "name": "aws_additional_collectors",
                "source": "stance.plugins.aws",
                "type": "collector",
                "version": "1.0.0",
                "description": "Additional AWS resource collectors",
                "installed": False,
            },
            {
                "name": "custom_policies",
                "source": "stance.plugins.policies",
                "type": "policy",
                "version": "1.0.0",
                "description": "Custom security policies",
                "installed": True,
            },
            {
                "name": "teams_destination",
                "source": "stance.plugins.alerts.teams",
                "type": "alert_destination",
                "version": "1.0.0",
                "description": "Microsoft Teams alert destination",
                "installed": False,
            },
        ]

        return HandlerResponse.success({
            "discovered": discovered,
            "total": len(discovered),
            "search_path": path or "default",
        })

    @route("status")
    def plugins_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get plugins module status."""
        plugins = self._get_sample_plugins()

        by_type: dict[str, int] = {}
        for p in plugins:
            t = p.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        enabled_count = sum(1 for p in plugins if p.get("enabled", False))

        return HandlerResponse.success({
            "module": "plugins",
            "version": "1.0.0",
            "status": "active",
            "total_plugins": len(plugins),
            "enabled_count": enabled_count,
            "disabled_count": len(plugins) - enabled_count,
            "by_type": by_type,
            "capabilities": {
                "dynamic_loading": True,
                "hot_reload": True,
                "plugin_discovery": True,
                "configuration": True,
                "version_management": True,
            },
        })

    @route("summary")
    def plugins_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get plugins summary."""
        plugins = self._get_sample_plugins()

        by_type: dict[str, int] = {}
        for p in plugins:
            t = p.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        enabled_count = sum(1 for p in plugins if p.get("enabled", False))

        return HandlerResponse.success({
            "total_plugins": len(plugins),
            "enabled_count": enabled_count,
            "by_type": by_type,
        })

    # =========================================================================
    # POST-style endpoints (using GET for demo)
    # =========================================================================

    @route("load")
    def plugins_load(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Load a plugin from source.

        Query params:
            source: Plugin source (file path, module name, or URL)
            type: Plugin type (optional, auto-detected)
        """
        source = self.get_param(params, "source", "")
        plugin_type = self.get_param(params, "type", "")

        if not source:
            return HandlerResponse.error("Plugin source is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "success": True,
            "name": f"plugin_{source.split('/')[-1].replace('.py', '')}",
            "source": source,
            "type": plugin_type or "collector",
            "warnings": [
                "Demo mode: Plugin not actually loaded",
                "In production, the plugin would be dynamically loaded from the source",
            ],
        }, HttpStatus.CREATED)

    @route("unload")
    def plugins_unload(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Unload a plugin.

        Query params:
            name: Plugin name (required)
            force: Force unload even if in use (optional)
        """
        name = self.get_param(params, "name", "")
        force = self.get_param_bool(params, "force", False)

        if not name:
            return HandlerResponse.error("Plugin name is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "success": True,
            "name": name,
            "force": force,
            "message": f"Plugin '{name}' unloaded successfully (demo mode)",
        })

    @route("reload")
    def plugins_reload(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Reload a plugin.

        Query params:
            name: Plugin name (required)
        """
        name = self.get_param(params, "name", "")

        if not name:
            return HandlerResponse.error("Plugin name is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "success": True,
            "name": name,
            "message": f"Plugin '{name}' reloaded successfully (demo mode)",
            "warnings": [],
        })

    @route("enable")
    def plugins_enable(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Enable a plugin.

        Query params:
            name: Plugin name (required)
        """
        name = self.get_param(params, "name", "")

        if not name:
            return HandlerResponse.error("Plugin name is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "success": True,
            "name": name,
            "enabled": True,
            "message": f"Plugin '{name}' enabled successfully",
        })

    @route("disable")
    def plugins_disable(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Disable a plugin.

        Query params:
            name: Plugin name (required)
        """
        name = self.get_param(params, "name", "")

        if not name:
            return HandlerResponse.error("Plugin name is required", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "success": True,
            "name": name,
            "enabled": False,
            "message": f"Plugin '{name}' disabled successfully",
        })

    @route("configure")
    def plugins_configure(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Configure a plugin.

        Query params:
            name: Plugin name (required)
            config: JSON configuration string (optional)
            show: If true, show current config instead of setting
        """
        name = self.get_param(params, "name", "")
        config = self.get_param(params, "config", "")
        show = self.get_param_bool(params, "show", False)

        if not name:
            return HandlerResponse.error("Plugin name is required", HttpStatus.BAD_REQUEST)

        if show:
            return HandlerResponse.success({
                "name": name,
                "config": {
                    "enabled": True,
                    "timeout": 30,
                    "retries": 3,
                },
            })

        return HandlerResponse.success({
            "success": True,
            "name": name,
            "config": config or "{}",
            "message": f"Plugin '{name}' configured successfully (demo mode)",
        })

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _get_sample_plugins(self) -> list[dict[str, Any]]:
        """Get sample plugin data."""
        return [
            {
                "name": "aws_s3",
                "type": "collector",
                "version": "1.0.0",
                "description": "AWS S3 bucket collector",
                "enabled": True,
                "builtin": True,
            },
            {
                "name": "aws_ec2",
                "type": "collector",
                "version": "1.0.0",
                "description": "AWS EC2 instance collector",
                "enabled": True,
                "builtin": True,
            },
            {
                "name": "azure_storage",
                "type": "collector",
                "version": "1.0.0",
                "description": "Azure Storage account collector",
                "enabled": True,
                "builtin": True,
            },
            {
                "name": "cis_aws",
                "type": "policy",
                "version": "1.5.0",
                "description": "CIS AWS Foundations Benchmark policies",
                "enabled": True,
                "builtin": True,
            },
            {
                "name": "cve_enricher",
                "type": "enricher",
                "version": "1.0.0",
                "description": "CVE vulnerability enricher",
                "enabled": True,
                "builtin": True,
            },
            {
                "name": "slack_destination",
                "type": "alert_destination",
                "version": "1.0.0",
                "description": "Slack alert destination",
                "enabled": False,
                "builtin": True,
            },
            {
                "name": "pdf_report",
                "type": "report_format",
                "version": "1.0.0",
                "description": "PDF report generator",
                "enabled": True,
                "builtin": True,
            },
        ]

    def _get_plugin_config_schema(self, plugin_type: str) -> dict[str, Any]:
        """Get configuration schema for a plugin type."""
        schemas = {
            "collector": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean", "default": True},
                    "timeout": {"type": "integer", "default": 30},
                    "retries": {"type": "integer", "default": 3},
                    "regions": {"type": "array", "items": {"type": "string"}},
                },
            },
            "policy": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean", "default": True},
                    "severity_override": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                },
            },
            "enricher": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean", "default": True},
                    "cache_ttl": {"type": "integer", "default": 3600},
                    "timeout": {"type": "integer", "default": 10},
                },
            },
            "alert_destination": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean", "default": True},
                    "webhook_url": {"type": "string"},
                    "channel": {"type": "string"},
                },
            },
        }
        return schemas.get(plugin_type, {"type": "object", "properties": {}})

    def _get_plugin_capabilities(self, plugin_type: str) -> list[str]:
        """Get capabilities for a plugin type."""
        capabilities = {
            "collector": ["collect", "list_resources", "validate_credentials"],
            "policy": ["evaluate", "get_checks", "get_severity"],
            "enricher": ["enrich", "batch_enrich", "get_cache_status"],
            "alert_destination": ["send", "test", "validate_config"],
            "report_format": ["generate", "get_template", "validate"],
        }
        return capabilities.get(plugin_type, [])
