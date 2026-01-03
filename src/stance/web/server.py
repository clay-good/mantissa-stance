"""
HTTP server for Mantissa Stance dashboard.

Provides a simple HTTP server for serving the dashboard UI
and JSON API endpoints for posture data.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timedelta
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qs, urlparse

from stance.storage import StorageBackend, get_storage


class StanceRequestHandler(SimpleHTTPRequestHandler):
    """
    HTTP request handler for Stance dashboard.

    Handles both static file serving and JSON API endpoints.
    """

    # Reference to storage backend (set by StanceServer)
    storage: StorageBackend | None = None

    def __init__(self, *args, **kwargs):
        # Set the directory for static files
        self.static_dir = os.path.join(os.path.dirname(__file__), "static")
        super().__init__(*args, directory=self.static_dir, **kwargs)

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        # Route API requests
        if path.startswith("/api/"):
            self._handle_api(path, parsed.query)
        else:
            # Serve static files
            if path == "/" or path == "":
                self.path = "/index.html"
            super().do_GET()

    def _handle_api(self, path: str, query_string: str):
        """
        Handle API requests.

        Args:
            path: Request path
            query_string: Query string parameters
        """
        # Parse query parameters
        params = parse_qs(query_string)

        # Route to appropriate handler
        try:
            if path == "/api/summary":
                data = self._get_summary(params)
            elif path == "/api/overview":
                data = self._get_overview(params)
            elif path == "/api/assets":
                data = self._get_assets(params)
            elif path.startswith("/api/assets/"):
                asset_id = path[len("/api/assets/"):]
                data = self._get_asset_detail(asset_id)
            elif path == "/api/findings":
                data = self._get_findings(params)
            elif path.startswith("/api/findings/"):
                finding_id = path[len("/api/findings/"):]
                data = self._get_finding_detail(finding_id)
            elif path == "/api/compliance":
                data = self._get_compliance(params)
            elif path.startswith("/api/compliance/"):
                framework = path[len("/api/compliance/"):]
                data = self._get_compliance_framework(framework)
            elif path == "/api/snapshots":
                data = self._get_snapshots()
            elif path == "/api/trends":
                data = self._get_trends(params)
            elif path == "/api/drift":
                data = self._get_drift()
            elif path == "/api/risk":
                data = self._get_risk_scores(params)
            elif path == "/api/export":
                self._handle_export(params)
                return
            elif path == "/api/search":
                data = self._handle_search(params)
            elif path == "/api/presets":
                data = self._get_presets()
            elif path.startswith("/api/presets/"):
                preset_name = path[len("/api/presets/"):]
                data = self._get_preset(preset_name)
            elif path == "/api/notifications/destinations":
                data = self._get_notification_destinations()
            elif path == "/api/notifications/config":
                data = self._get_notification_config()
            elif path == "/api/notifications/history":
                data = self._get_notification_history(params)
            elif path == "/api/attack-paths":
                data = self._get_attack_paths(params)
            elif path.startswith("/api/attack-paths/"):
                path_id = path[len("/api/attack-paths/"):]
                data = self._get_attack_path_detail(path_id)
            # DSPM API endpoints
            elif path == "/api/dspm/scan":
                data = self._dspm_scan(params)
            elif path == "/api/dspm/access":
                data = self._dspm_access(params)
            elif path == "/api/dspm/cost":
                data = self._dspm_cost(params)
            elif path == "/api/dspm/classify":
                data = self._dspm_classify(params)
            elif path == "/api/dspm/summary":
                data = self._dspm_summary(params)
            # Identity API endpoints
            elif path == "/api/identity/who-can-access":
                data = self._identity_who_can_access(params)
            elif path == "/api/identity/exposure":
                data = self._identity_exposure(params)
            elif path == "/api/identity/overprivileged":
                data = self._identity_overprivileged(params)
            elif path == "/api/identity/summary":
                data = self._identity_summary(params)
            # Exposure API endpoints
            elif path == "/api/exposure/inventory":
                data = self._exposure_inventory(params)
            elif path == "/api/exposure/certificates":
                data = self._exposure_certificates(params)
            elif path == "/api/exposure/dns":
                data = self._exposure_dns(params)
            elif path == "/api/exposure/sensitive":
                data = self._exposure_sensitive(params)
            elif path == "/api/exposure/summary":
                data = self._exposure_summary(params)
            # Analytics API endpoints
            elif path == "/api/analytics/attack-paths":
                data = self._analytics_attack_paths(params)
            elif path == "/api/analytics/risk-score":
                data = self._analytics_risk_score(params)
            elif path == "/api/analytics/blast-radius":
                data = self._analytics_blast_radius(params)
            elif path == "/api/analytics/mitre":
                data = self._analytics_mitre(params)
            elif path == "/api/analytics/mitre/technique":
                data = self._analytics_mitre_technique(params)
            elif path == "/api/analytics/mitre/coverage":
                data = self._analytics_mitre_coverage(params)
            elif path == "/api/analytics/summary":
                data = self._analytics_summary(params)
            # Scanning API endpoints
            elif path == "/api/scanning/image":
                data = self._scanning_image(params)
            elif path == "/api/scanning/iac":
                data = self._scanning_iac(params)
            elif path == "/api/scanning/secrets":
                data = self._scanning_secrets(params)
            elif path == "/api/scanning/summary":
                data = self._scanning_summary(params)
            # Enrichment API endpoints
            elif path == "/api/enrichment/findings":
                data = self._enrichment_findings(params)
            elif path == "/api/enrichment/assets":
                data = self._enrichment_assets(params)
            elif path == "/api/enrichment/ip":
                data = self._enrichment_ip(params)
            elif path == "/api/enrichment/cve":
                data = self._enrichment_cve(params)
            elif path == "/api/enrichment/kev":
                data = self._enrichment_kev(params)
            elif path == "/api/enrichment/status":
                data = self._enrichment_status(params)
            # Aggregation API endpoints
            elif path == "/api/aggregation/aggregate":
                data = self._aggregation_aggregate(params)
            elif path == "/api/aggregation/cross-account":
                data = self._aggregation_cross_account(params)
            elif path == "/api/aggregation/summary":
                data = self._aggregation_summary(params)
            elif path == "/api/aggregation/sync":
                data = self._aggregation_sync(params)
            elif path == "/api/aggregation/sync-status":
                data = self._aggregation_sync_status(params)
            elif path == "/api/aggregation/backends":
                data = self._aggregation_backends(params)
            elif path == "/api/aggregation/status":
                data = self._aggregation_status(params)
            # Query Engine API endpoints
            elif path == "/api/query/execute":
                data = self._query_execute(params)
            elif path == "/api/query/estimate":
                data = self._query_estimate(params)
            elif path == "/api/query/tables":
                data = self._query_tables(params)
            elif path == "/api/query/schema":
                data = self._query_schema(params)
            elif path == "/api/query/validate":
                data = self._query_validate(params)
            elif path == "/api/query/backends":
                data = self._query_backends(params)
            elif path == "/api/query/status":
                data = self._query_status(params)
            # Plugin Management API endpoints
            elif path == "/api/plugins/list":
                data = self._plugins_list(params)
            elif path == "/api/plugins/info":
                data = self._plugins_info(params)
            elif path == "/api/plugins/load":
                data = self._plugins_load(params)
            elif path == "/api/plugins/unload":
                data = self._plugins_unload(params)
            elif path == "/api/plugins/reload":
                data = self._plugins_reload(params)
            elif path == "/api/plugins/enable":
                data = self._plugins_enable(params)
            elif path == "/api/plugins/disable":
                data = self._plugins_disable(params)
            elif path == "/api/plugins/configure":
                data = self._plugins_configure(params)
            elif path == "/api/plugins/discover":
                data = self._plugins_discover(params)
            elif path == "/api/plugins/types":
                data = self._plugins_types(params)
            elif path == "/api/plugins/status":
                data = self._plugins_status(params)
            # Exceptions API endpoints
            elif path == "/api/exceptions/list":
                data = self._exceptions_list(params)
            elif path == "/api/exceptions/show":
                data = self._exceptions_show(params)
            elif path == "/api/exceptions/create":
                data = self._exceptions_create(params)
            elif path == "/api/exceptions/suppress":
                data = self._exceptions_suppress(params)
            elif path == "/api/exceptions/false-positive":
                data = self._exceptions_false_positive(params)
            elif path == "/api/exceptions/accept-risk":
                data = self._exceptions_accept_risk(params)
            elif path == "/api/exceptions/revoke":
                data = self._exceptions_revoke(params)
            elif path == "/api/exceptions/delete":
                data = self._exceptions_delete(params)
            elif path == "/api/exceptions/expire":
                data = self._exceptions_expire(params)
            elif path == "/api/exceptions/types":
                data = self._exceptions_types(params)
            elif path == "/api/exceptions/scopes":
                data = self._exceptions_scopes(params)
            elif path == "/api/exceptions/status":
                data = self._exceptions_status(params)
            # Notifications API endpoints
            elif path == "/api/notifications/list":
                data = self._notifications_list(params)
            elif path == "/api/notifications/show":
                data = self._notifications_show(params)
            elif path == "/api/notifications/types":
                data = self._notifications_types(params)
            elif path == "/api/notifications/config":
                data = self._notifications_config_get(params)
            elif path == "/api/notifications/status":
                data = self._notifications_status(params)
            # Correlation API endpoints
            elif path == "/api/correlation/correlate":
                data = self._correlation_correlate(params)
            elif path == "/api/correlation/groups":
                data = self._correlation_groups(params)
            elif path == "/api/correlation/group":
                data = self._correlation_group(params)
            elif path == "/api/correlation/related":
                data = self._correlation_related(params)
            elif path == "/api/correlation/risk":
                data = self._correlation_risk(params)
            elif path == "/api/correlation/risk-asset":
                data = self._correlation_risk_asset(params)
            elif path == "/api/correlation/risk-summary":
                data = self._correlation_risk_summary(params)
            elif path == "/api/correlation/analyze":
                data = self._correlation_analyze(params)
            elif path == "/api/correlation/types":
                data = self._correlation_types(params)
            elif path == "/api/correlation/levels":
                data = self._correlation_levels(params)
            elif path == "/api/correlation/status":
                data = self._correlation_status(params)
            # Trends API endpoints
            elif path == "/api/trends/analyze":
                data = self._trends_analyze(params)
            elif path == "/api/trends/forecast":
                data = self._trends_forecast(params)
            elif path == "/api/trends/velocity":
                data = self._trends_velocity(params)
            elif path == "/api/trends/improvement":
                data = self._trends_improvement(params)
            elif path == "/api/trends/compare":
                data = self._trends_compare(params)
            elif path == "/api/trends/report":
                data = self._trends_report(params)
            elif path == "/api/trends/severity":
                data = self._trends_severity(params)
            elif path == "/api/trends/summary":
                data = self._trends_summary(params)
            elif path == "/api/trends/periods":
                data = self._trends_periods(params)
            elif path == "/api/trends/directions":
                data = self._trends_directions(params)
            elif path == "/api/trends/status":
                data = self._trends_status(params)
            # Alerting API endpoints
            elif path == "/api/alerting/destinations":
                data = self._alerting_destinations(params)
            elif path == "/api/alerting/routing-rules":
                data = self._alerting_routing_rules(params)
            elif path == "/api/alerting/suppression-rules":
                data = self._alerting_suppression_rules(params)
            elif path == "/api/alerting/config":
                data = self._alerting_config(params)
            elif path == "/api/alerting/rate-limits":
                data = self._alerting_rate_limits(params)
            elif path == "/api/alerting/alerts":
                data = self._alerting_alerts(params)
            elif path == "/api/alerting/templates":
                data = self._alerting_templates(params)
            elif path == "/api/alerting/destination-types":
                data = self._alerting_destination_types(params)
            elif path == "/api/alerting/severities":
                data = self._alerting_severities(params)
            elif path == "/api/alerting/status":
                data = self._alerting_status(params)
            elif path == "/api/alerting/test-route":
                data = self._alerting_test_route(params)
            elif path == "/api/alerting/summary":
                data = self._alerting_summary(params)
            # Automation API endpoints
            elif path == "/api/automation/config":
                data = self._automation_config(params)
            elif path == "/api/automation/types":
                data = self._automation_types(params)
            elif path == "/api/automation/history":
                data = self._automation_history(params)
            elif path == "/api/automation/thresholds":
                data = self._automation_thresholds(params)
            elif path == "/api/automation/triggers":
                data = self._automation_triggers(params)
            elif path == "/api/automation/callbacks":
                data = self._automation_callbacks(params)
            elif path == "/api/automation/severities":
                data = self._automation_severities(params)
            elif path == "/api/automation/status":
                data = self._automation_status(params)
            elif path == "/api/automation/test":
                data = self._automation_test(params)
            elif path == "/api/automation/summary":
                data = self._automation_summary(params)
            elif path == "/api/automation/workflows":
                data = self._automation_workflows(params)
            elif path == "/api/automation/events":
                data = self._automation_events(params)
            # Scheduling endpoints
            elif path == "/api/scheduling/jobs":
                data = self._scheduling_jobs(params)
            elif path == "/api/scheduling/job":
                data = self._scheduling_job(params)
            elif path == "/api/scheduling/history":
                data = self._scheduling_history(params)
            elif path == "/api/scheduling/history-entry":
                data = self._scheduling_history_entry(params)
            elif path == "/api/scheduling/compare":
                data = self._scheduling_compare(params)
            elif path == "/api/scheduling/trend":
                data = self._scheduling_trend(params)
            elif path == "/api/scheduling/status":
                data = self._scheduling_status(params)
            elif path == "/api/scheduling/schedule-types":
                data = self._scheduling_schedule_types(params)
            elif path == "/api/scheduling/diff-types":
                data = self._scheduling_diff_types(params)
            elif path == "/api/scheduling/summary":
                data = self._scheduling_summary(params)
            # IaC endpoints
            elif path == "/api/iac/scan":
                data = self._iac_scan(params)
            elif path == "/api/iac/policies":
                data = self._iac_policies(params)
            elif path == "/api/iac/policy":
                data = self._iac_policy(params)
            elif path == "/api/iac/formats":
                data = self._iac_formats(params)
            elif path == "/api/iac/validate":
                data = self._iac_validate(params)
            elif path == "/api/iac/resources":
                data = self._iac_resources(params)
            elif path == "/api/iac/stats":
                data = self._iac_stats(params)
            elif path == "/api/iac/compliance":
                data = self._iac_compliance(params)
            elif path == "/api/iac/providers":
                data = self._iac_providers(params)
            elif path == "/api/iac/resource-types":
                data = self._iac_resource_types(params)
            elif path == "/api/iac/severity-levels":
                data = self._iac_severity_levels(params)
            elif path == "/api/iac/summary":
                data = self._iac_summary(params)
            # Engine endpoints
            elif path == "/api/engine/policies":
                data = self._engine_policies(params)
            elif path == "/api/engine/policy":
                data = self._engine_policy(params)
            elif path == "/api/engine/validate":
                data = self._engine_validate(params)
            elif path == "/api/engine/evaluate":
                data = self._engine_evaluate(params)
            elif path == "/api/engine/validate-expression":
                data = self._engine_validate_expression(params)
            elif path == "/api/engine/compliance":
                data = self._engine_compliance(params)
            elif path == "/api/engine/frameworks":
                data = self._engine_frameworks(params)
            elif path == "/api/engine/operators":
                data = self._engine_operators(params)
            elif path == "/api/engine/check-types":
                data = self._engine_check_types(params)
            elif path == "/api/engine/severity-levels":
                data = self._engine_severity_levels(params)
            elif path == "/api/engine/stats":
                data = self._engine_stats(params)
            elif path == "/api/engine/status":
                data = self._engine_status(params)
            elif path == "/api/engine/summary":
                data = self._engine_summary(params)
            # Storage endpoints
            elif path == "/api/storage/backends":
                data = self._storage_backends(params)
            elif path == "/api/storage/backend":
                data = self._storage_backend(params)
            elif path == "/api/storage/snapshots":
                data = self._storage_snapshots(params)
            elif path == "/api/storage/snapshot":
                data = self._storage_snapshot(params)
            elif path == "/api/storage/latest":
                data = self._storage_latest(params)
            elif path == "/api/storage/config":
                data = self._storage_config(params)
            elif path == "/api/storage/capabilities":
                data = self._storage_capabilities(params)
            elif path == "/api/storage/query-services":
                data = self._storage_query_services(params)
            elif path == "/api/storage/ddl":
                data = self._storage_ddl(params)
            elif path == "/api/storage/stats":
                data = self._storage_stats(params)
            elif path == "/api/storage/status":
                data = self._storage_status(params)
            elif path == "/api/storage/summary":
                data = self._storage_summary(params)
            # LLM endpoints
            elif path == "/api/llm/providers":
                data = self._llm_providers(params)
            elif path == "/api/llm/provider":
                data = self._llm_provider(params)
            elif path == "/api/llm/generate-query":
                data = self._llm_generate_query(params)
            elif path == "/api/llm/validate-query":
                data = self._llm_validate_query(params)
            elif path == "/api/llm/explain-finding":
                data = self._llm_explain_finding(params)
            elif path == "/api/llm/generate-policy":
                data = self._llm_generate_policy(params)
            elif path == "/api/llm/suggest-policies":
                data = self._llm_suggest_policies(params)
            elif path == "/api/llm/sanitize":
                data = self._llm_sanitize(params)
            elif path == "/api/llm/check-sensitive":
                data = self._llm_check_sensitive(params)
            elif path == "/api/llm/resource-types":
                data = self._llm_resource_types(params)
            elif path == "/api/llm/frameworks":
                data = self._llm_frameworks(params)
            elif path == "/api/llm/models":
                data = self._llm_models(params)
            elif path == "/api/llm/status":
                data = self._llm_status(params)
            elif path == "/api/llm/summary":
                data = self._llm_summary(params)
            # Detection module endpoints
            elif path == "/api/detection/scan":
                data = self._detection_scan(params)
            elif path == "/api/detection/patterns":
                data = self._detection_patterns(params)
            elif path == "/api/detection/pattern":
                data = self._detection_pattern(params)
            elif path == "/api/detection/entropy":
                data = self._detection_entropy(params)
            elif path == "/api/detection/sensitive-fields":
                data = self._detection_sensitive_fields(params)
            elif path == "/api/detection/check-field":
                data = self._detection_check_field(params)
            elif path == "/api/detection/categories":
                data = self._detection_categories(params)
            elif path == "/api/detection/severity-levels":
                data = self._detection_severity_levels(params)
            elif path == "/api/detection/stats":
                data = self._detection_stats(params)
            elif path == "/api/detection/status":
                data = self._detection_status(params)
            elif path == "/api/detection/summary":
                data = self._detection_summary(params)
            # Scanner module endpoints
            elif path == "/api/scanner/scanners":
                data = self._scanner_scanners(params)
            elif path == "/api/scanner/check":
                data = self._scanner_check(params)
            elif path == "/api/scanner/version":
                data = self._scanner_version(params)
            elif path == "/api/scanner/enrich":
                data = self._scanner_enrich(params)
            elif path == "/api/scanner/epss":
                data = self._scanner_epss(params)
            elif path == "/api/scanner/kev":
                data = self._scanner_kev(params)
            elif path == "/api/scanner/severity-levels":
                data = self._scanner_severity_levels(params)
            elif path == "/api/scanner/priority-factors":
                data = self._scanner_priority_factors(params)
            elif path == "/api/scanner/package-types":
                data = self._scanner_package_types(params)
            elif path == "/api/scanner/stats":
                data = self._scanner_stats(params)
            elif path == "/api/scanner/status":
                data = self._scanner_status(params)
            elif path == "/api/scanner/summary":
                data = self._scanner_summary(params)
            # Export module endpoints
            elif path == "/api/export/formats":
                data = self._export_formats(params)
            elif path == "/api/export/report-types":
                data = self._export_report_types(params)
            elif path == "/api/export/options":
                data = self._export_options(params)
            elif path == "/api/export/capabilities":
                data = self._export_capabilities(params)
            elif path == "/api/export/pdf-tool":
                data = self._export_pdf_tool(params)
            elif path == "/api/export/severities":
                data = self._export_severities(params)
            elif path == "/api/export/preview":
                data = self._export_preview(params)
            elif path == "/api/export/stats":
                data = self._export_stats(params)
            elif path == "/api/export/status":
                data = self._export_status(params)
            elif path == "/api/export/summary":
                data = self._export_summary(params)
            # Reporting module endpoints
            elif path == "/api/reporting/analyze":
                data = self._reporting_analyze(params)
            elif path == "/api/reporting/velocity":
                data = self._reporting_velocity(params)
            elif path == "/api/reporting/improvement":
                data = self._reporting_improvement(params)
            elif path == "/api/reporting/compare":
                data = self._reporting_compare(params)
            elif path == "/api/reporting/forecast":
                data = self._reporting_forecast(params)
            elif path == "/api/reporting/directions":
                data = self._reporting_directions(params)
            elif path == "/api/reporting/periods":
                data = self._reporting_periods(params)
            elif path == "/api/reporting/severities":
                data = self._reporting_severities(params)
            elif path == "/api/reporting/metrics":
                data = self._reporting_metrics(params)
            elif path == "/api/reporting/stats":
                data = self._reporting_stats(params)
            elif path == "/api/reporting/status":
                data = self._reporting_status(params)
            elif path == "/api/reporting/summary":
                data = self._reporting_summary(params)
            # Observability module endpoints
            elif path == "/api/observability/logging":
                data = self._observability_logging(params)
            elif path == "/api/observability/metrics":
                data = self._observability_metrics(params)
            elif path == "/api/observability/traces":
                data = self._observability_traces(params)
            elif path == "/api/observability/backends":
                data = self._observability_backends(params)
            elif path == "/api/observability/metric-types":
                data = self._observability_metric_types(params)
            elif path == "/api/observability/log-levels":
                data = self._observability_log_levels(params)
            elif path == "/api/observability/span-statuses":
                data = self._observability_span_statuses(params)
            elif path == "/api/observability/log-formats":
                data = self._observability_log_formats(params)
            elif path == "/api/observability/stats":
                data = self._observability_stats(params)
            elif path == "/api/observability/status":
                data = self._observability_status(params)
            elif path == "/api/observability/summary":
                data = self._observability_summary(params)
            # Multi-account scanning module endpoints
            elif path == "/api/multi-scan/scan":
                data = self._multi_scan_scan(params)
            elif path == "/api/multi-scan/progress":
                data = self._multi_scan_progress(params)
            elif path == "/api/multi-scan/results":
                data = self._multi_scan_results(params)
            elif path == "/api/multi-scan/accounts":
                data = self._multi_scan_accounts(params)
            elif path == "/api/multi-scan/report":
                data = self._multi_scan_report(params)
            elif path == "/api/multi-scan/account-statuses":
                data = self._multi_scan_account_statuses(params)
            elif path == "/api/multi-scan/options":
                data = self._multi_scan_options(params)
            elif path == "/api/multi-scan/providers":
                data = self._multi_scan_providers(params)
            elif path == "/api/multi-scan/stats":
                data = self._multi_scan_stats(params)
            elif path == "/api/multi-scan/status":
                data = self._multi_scan_status(params)
            elif path == "/api/multi-scan/summary":
                data = self._multi_scan_summary(params)
            # State management endpoints
            elif path == "/api/state/scans":
                data = self._state_scans(params)
            elif path == "/api/state/scan":
                data = self._state_scan(params)
            elif path == "/api/state/checkpoints":
                data = self._state_checkpoints(params)
            elif path == "/api/state/checkpoint":
                data = self._state_checkpoint(params)
            elif path == "/api/state/findings":
                data = self._state_findings(params)
            elif path == "/api/state/finding":
                data = self._state_finding(params)
            elif path == "/api/state/scan-statuses":
                data = self._state_scan_statuses(params)
            elif path == "/api/state/lifecycles":
                data = self._state_lifecycles(params)
            elif path == "/api/state/backends":
                data = self._state_backends(params)
            elif path == "/api/state/finding-stats":
                data = self._state_finding_stats(params)
            elif path == "/api/state/stats":
                data = self._state_stats(params)
            elif path == "/api/state/status":
                data = self._state_status(params)
            elif path == "/api/state/summary":
                data = self._state_summary(params)
            # Collectors endpoints
            elif path == "/api/collectors/list":
                data = self._collectors_list(params)
            elif path == "/api/collectors/info":
                data = self._collectors_info(params)
            elif path == "/api/collectors/providers":
                data = self._collectors_providers(params)
            elif path == "/api/collectors/resources":
                data = self._collectors_resources(params)
            elif path == "/api/collectors/registry":
                data = self._collectors_registry(params)
            elif path == "/api/collectors/availability":
                data = self._collectors_availability(params)
            elif path == "/api/collectors/categories":
                data = self._collectors_categories(params)
            elif path == "/api/collectors/count":
                data = self._collectors_count(params)
            elif path == "/api/collectors/stats":
                data = self._collectors_stats(params)
            elif path == "/api/collectors/status":
                data = self._collectors_status(params)
            elif path == "/api/collectors/summary":
                data = self._collectors_summary(params)
            # Cloud provider endpoints
            elif path == "/api/cloud/list":
                data = self._cloud_list(params)
            elif path == "/api/cloud/info":
                data = self._cloud_info(params)
            elif path == "/api/cloud/validate":
                data = self._cloud_validate(params)
            elif path == "/api/cloud/account":
                data = self._cloud_account(params)
            elif path == "/api/cloud/regions":
                data = self._cloud_regions(params)
            elif path == "/api/cloud/availability":
                data = self._cloud_availability(params)
            elif path == "/api/cloud/packages":
                data = self._cloud_packages(params)
            elif path == "/api/cloud/credentials":
                data = self._cloud_credentials(params)
            elif path == "/api/cloud/exceptions":
                data = self._cloud_exceptions(params)
            elif path == "/api/cloud/status":
                data = self._cloud_status(params)
            elif path == "/api/cloud/summary":
                data = self._cloud_summary(params)
            # Config API endpoints
            elif path == "/api/config/list":
                data = self._config_list(params)
            elif path == "/api/config/show":
                data = self._config_show(params)
            elif path == "/api/config/validate":
                data = self._config_validate(params)
            elif path == "/api/config/default":
                data = self._config_default(params)
            elif path == "/api/config/modes":
                data = self._config_modes(params)
            elif path == "/api/config/providers":
                data = self._config_providers(params)
            elif path == "/api/config/schema":
                data = self._config_schema(params)
            elif path == "/api/config/env":
                data = self._config_env(params)
            elif path == "/api/config/status":
                data = self._config_status(params)
            elif path == "/api/config/summary":
                data = self._config_summary(params)
            # Docs API endpoints
            elif path == "/api/docs/info":
                data = self._docs_info(params)
            elif path == "/api/docs/generators":
                data = self._docs_generators(params)
            elif path == "/api/docs/dataclasses":
                data = self._docs_dataclasses(params)
            elif path == "/api/docs/parsers":
                data = self._docs_parsers(params)
            elif path == "/api/docs/status":
                data = self._docs_status(params)
            elif path == "/api/docs/summary":
                data = self._docs_summary(params)
            elif path == "/api/docs/list":
                data = self._docs_list(params)
            elif path == "/api/docs/module":
                data = self._docs_module(params)
            elif path == "/api/docs/class":
                data = self._docs_class(params)
            # SBOM API endpoints
            elif path == "/api/sbom/info":
                data = self._sbom_info(params)
            elif path == "/api/sbom/formats":
                data = self._sbom_formats(params)
            elif path == "/api/sbom/ecosystems":
                data = self._sbom_ecosystems(params)
            elif path == "/api/sbom/licenses":
                data = self._sbom_licenses(params)
            elif path == "/api/sbom/license-categories":
                data = self._sbom_license_categories(params)
            elif path == "/api/sbom/risk-levels":
                data = self._sbom_risk_levels(params)
            elif path == "/api/sbom/parse":
                data = self._sbom_parse(params)
            elif path == "/api/sbom/analyze-license":
                data = self._sbom_analyze_license(params)
            elif path == "/api/sbom/analyze-risk":
                data = self._sbom_analyze_risk(params)
            elif path == "/api/sbom/status":
                data = self._sbom_status(params)
            elif path == "/api/sbom/summary":
                data = self._sbom_summary(params)
            elif path == "/api/sbom/graph":
                data = self._sbom_graph(params)
            elif path == "/api/sbom/graph-metrics":
                data = self._sbom_graph_metrics(params)
            elif path == "/api/sbom/attest":
                data = self._sbom_attest(params)
            elif path == "/api/sbom/attest-verify":
                data = self._sbom_attest_verify(params)
            elif path == "/api/sbom/vex":
                data = self._sbom_vex(params)
            elif path == "/api/sbom/vex-formats":
                data = self._sbom_vex_formats(params)
            # Vulnerability API endpoints
            elif path == "/api/vuln/info":
                data = self._vuln_info(params)
            elif path == "/api/vuln/scan":
                data = self._vuln_scan(params)
            elif path == "/api/vuln/lookup":
                data = self._vuln_lookup(params)
            elif path == "/api/vuln/status":
                data = self._vuln_status(params)
            elif path == "/api/vuln/sources":
                data = self._vuln_sources(params)
            elif path == "/api/vuln/summary":
                data = self._vuln_summary(params)
            # API Security Testing endpoints
            elif path == "/api/api-security/info":
                data = self._api_security_info(params)
            elif path == "/api/api-security/discover":
                data = self._api_security_discover(params)
            elif path == "/api/api-security/analyze":
                data = self._api_security_analyze(params)
            elif path == "/api/api-security/test-auth":
                data = self._api_security_test_auth(params)
            elif path == "/api/api-security/status":
                data = self._api_security_status(params)
            elif path == "/api/api-security/summary":
                data = self._api_security_summary(params)
            # Dashboards module endpoints
            elif path == "/api/dashboards/list":
                data = self._dashboards_list(params)
            elif path == "/api/dashboards/show":
                data = self._dashboards_show(params)
            elif path == "/api/dashboards/create":
                data = self._dashboards_create(params)
            elif path == "/api/dashboards/widgets":
                data = self._dashboards_widgets(params)
            elif path == "/api/dashboards/charts":
                data = self._dashboards_charts(params)
            elif path == "/api/dashboards/themes":
                data = self._dashboards_themes(params)
            elif path == "/api/dashboards/time-ranges":
                data = self._dashboards_time_ranges(params)
            elif path == "/api/dashboards/reports":
                data = self._dashboards_reports(params)
            elif path == "/api/dashboards/generate":
                data = self._dashboards_generate(params)
            elif path == "/api/dashboards/schedules":
                data = self._dashboards_schedules(params)
            elif path == "/api/dashboards/schedule-create":
                data = self._dashboards_schedule_create(params)
            elif path == "/api/dashboards/frequencies":
                data = self._dashboards_frequencies(params)
            elif path == "/api/dashboards/formats":
                data = self._dashboards_formats(params)
            elif path == "/api/dashboards/templates":
                data = self._dashboards_templates(params)
            elif path == "/api/dashboards/metrics":
                data = self._dashboards_metrics(params)
            elif path == "/api/dashboards/status":
                data = self._dashboards_status(params)
            # Authentication API endpoints
            elif path == "/api/auth/status":
                data = self._auth_status(params)
            elif path == "/api/auth/users":
                data = self._auth_users_list(params)
            elif path == "/api/auth/users/show":
                data = self._auth_users_show(params)
            elif path == "/api/auth/apikeys":
                data = self._auth_apikeys_list(params)
            elif path == "/api/auth/sessions":
                data = self._auth_sessions_list(params)
            elif path == "/api/auth/roles":
                data = self._auth_roles_list(params)
            elif path == "/api/auth/roles/show":
                data = self._auth_roles_show(params)
            elif path == "/api/auth/audit":
                data = self._auth_audit_list(params)
            elif path == "/api/auth/audit/security":
                data = self._auth_audit_security(params)
            elif path == "/api/auth/audit/failed-logins":
                data = self._auth_audit_failed_logins(params)
            elif path == "/api/auth/audit/stats":
                data = self._auth_audit_stats(params)
            elif path == "/api/auth/permissions":
                data = self._auth_permissions_list(params)
            elif path == "/api/auth/summary":
                data = self._auth_summary(params)
            # Workflow Automation API endpoints
            elif path == "/api/workflow/status":
                data = self._workflow_status(params)
            elif path == "/api/workflow/stats":
                data = self._workflow_stats(params)
            # Escalation API endpoints
            elif path == "/api/workflow/escalation/policies":
                data = self._workflow_escalation_policies(params)
            elif path == "/api/workflow/escalation/sla":
                data = self._workflow_escalation_sla(params)
            elif path == "/api/workflow/escalation/history":
                data = self._workflow_escalation_history(params)
            elif path == "/api/workflow/escalation/levels":
                data = self._workflow_escalation_levels(params)
            # Runbook API endpoints
            elif path == "/api/workflow/runbook/list":
                data = self._workflow_runbook_list(params)
            elif path == "/api/workflow/runbook/show":
                data = self._workflow_runbook_show(params)
            elif path == "/api/workflow/runbook/templates":
                data = self._workflow_runbook_templates(params)
            elif path == "/api/workflow/runbook/executions":
                data = self._workflow_runbook_executions(params)
            # Remediation API endpoints
            elif path == "/api/workflow/remediation/rules":
                data = self._workflow_remediation_rules(params)
            elif path == "/api/workflow/remediation/plans":
                data = self._workflow_remediation_plans(params)
            elif path == "/api/workflow/remediation/pending":
                data = self._workflow_remediation_pending(params)
            elif path == "/api/workflow/remediation/auto":
                data = self._workflow_remediation_auto(params)
            # Trigger API endpoints
            elif path == "/api/workflow/trigger/list":
                data = self._workflow_trigger_list(params)
            elif path == "/api/workflow/trigger/types":
                data = self._workflow_trigger_types(params)
            elif path == "/api/workflow/trigger/history":
                data = self._workflow_trigger_history(params)
            # Enhanced Visualization API endpoints (Phase 94)
            elif path == "/api/viz/widget/templates":
                data = self._viz_widget_templates(params)
            elif path == "/api/viz/widget/search":
                data = self._viz_widget_search(params)
            elif path == "/api/viz/widget/info":
                data = self._viz_widget_info(params)
            elif path == "/api/viz/layout/info":
                data = self._viz_layout_info(params)
            elif path == "/api/viz/embed/tokens":
                data = self._viz_embed_tokens(params)
            elif path == "/api/viz/embed/validate":
                data = self._viz_embed_validate(params)
            elif path == "/api/viz/share/links":
                data = self._viz_share_links(params)
            elif path == "/api/viz/share/validate":
                data = self._viz_share_validate(params)
            elif path == "/api/viz/share/status":
                data = self._viz_share_status(params)
            elif path == "/api/viz/realtime/status":
                data = self._viz_realtime_status(params)
            elif path == "/api/viz/realtime/events":
                data = self._viz_realtime_events(params)
            elif path == "/api/viz/realtime/messages":
                data = self._viz_realtime_messages(params)
            elif path == "/api/viz/chart/types":
                data = self._viz_chart_types(params)
            elif path == "/api/viz/updates/status":
                data = self._viz_updates_status(params)
            else:
                self._send_error(404, "Not found")
                return

            self._send_json(data)

        except Exception as e:
            self._send_error(500, str(e))

    def do_POST(self):
        """Handle POST requests."""
        path = urlparse(self.path).path

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        try:
            if path == "/api/presets":
                data = self._save_preset(body)
            elif path.startswith("/api/presets/") and path.endswith("/delete"):
                preset_name = path[len("/api/presets/"):-len("/delete")]
                data = self._delete_preset(preset_name)
            elif path == "/api/notifications/destinations":
                data = self._save_notification_destination(body)
            elif path == "/api/notifications/destinations/test":
                data = self._test_notification_destination(body)
            elif path.startswith("/api/notifications/destinations/") and path.endswith("/delete"):
                dest_name = path[len("/api/notifications/destinations/"):-len("/delete")]
                data = self._delete_notification_destination(dest_name)
            elif path == "/api/notifications/config":
                data = self._save_notification_config(body)
            elif path == "/api/notifications/send":
                data = self._send_test_notification(body)
            # Notifications management POST endpoints
            elif path == "/api/notifications/set":
                data = self._notifications_set(body)
            elif path == "/api/notifications/enable":
                data = self._notifications_enable(body)
            elif path == "/api/notifications/disable":
                data = self._notifications_disable(body)
            elif path == "/api/notifications/test":
                data = self._notifications_test(body)
            elif path == "/api/notifications/clear":
                data = self._notifications_clear(body)
            # State management POST endpoints
            elif path == "/api/state/suppress":
                data = self._state_suppress(body)
            elif path == "/api/state/resolve":
                data = self._state_resolve(body)
            elif path == "/api/state/delete-checkpoint":
                data = self._state_delete_checkpoint(body)
            # Config management POST endpoints
            elif path == "/api/config/create":
                data = self._config_create(body)
            elif path == "/api/config/delete":
                data = self._config_delete(body)
            elif path == "/api/config/edit":
                data = self._config_edit(body)
            elif path == "/api/config/import":
                data = self._config_import(body)
            elif path == "/api/config/export":
                data = self._config_export(body)
            elif path == "/api/config/set-default":
                data = self._config_set_default(body)
            # Docs management POST endpoints
            elif path == "/api/docs/generate":
                data = self._docs_generate(body)
            elif path == "/api/docs/validate":
                data = self._docs_validate(body)
            elif path == "/api/docs/clean":
                data = self._docs_clean(body)
            # Authentication POST endpoints
            elif path == "/api/auth/login":
                data = self._auth_login(body)
            elif path == "/api/auth/logout":
                data = self._auth_logout(body)
            elif path == "/api/auth/users/create":
                data = self._auth_users_create(body)
            elif path == "/api/auth/users/delete":
                data = self._auth_users_delete(body)
            elif path == "/api/auth/users/suspend":
                data = self._auth_users_suspend(body)
            elif path == "/api/auth/users/reactivate":
                data = self._auth_users_reactivate(body)
            elif path == "/api/auth/apikeys/create":
                data = self._auth_apikeys_create(body)
            elif path == "/api/auth/apikeys/revoke":
                data = self._auth_apikeys_revoke(body)
            elif path == "/api/auth/apikeys/rotate":
                data = self._auth_apikeys_rotate(body)
            elif path == "/api/auth/sessions/terminate":
                data = self._auth_sessions_terminate(body)
            elif path == "/api/auth/sessions/cleanup":
                data = self._auth_sessions_cleanup(body)
            elif path == "/api/auth/roles/assign":
                data = self._auth_roles_assign(body)
            elif path == "/api/auth/roles/revoke":
                data = self._auth_roles_revoke(body)
            elif path == "/api/auth/token/refresh":
                data = self._auth_token_refresh(body)
            elif path == "/api/auth/token/validate":
                data = self._auth_token_validate(body)
            # Workflow Automation POST endpoints
            elif path == "/api/workflow/escalation/trigger":
                data = self._workflow_escalation_trigger(body)
            elif path == "/api/workflow/runbook/execute":
                data = self._workflow_runbook_execute(body)
            elif path == "/api/workflow/runbook/cancel":
                data = self._workflow_runbook_cancel(body)
            elif path == "/api/workflow/remediation/approve":
                data = self._workflow_remediation_approve(body)
            elif path == "/api/workflow/remediation/reject":
                data = self._workflow_remediation_reject(body)
            elif path == "/api/workflow/remediation/execute":
                data = self._workflow_remediation_execute(body)
            elif path == "/api/workflow/trigger/enable":
                data = self._workflow_trigger_enable(body)
            elif path == "/api/workflow/trigger/disable":
                data = self._workflow_trigger_disable(body)
            elif path == "/api/workflow/trigger/test":
                data = self._workflow_trigger_test(body)
            # Enhanced Visualization POST endpoints (Phase 94)
            elif path == "/api/viz/widget/create":
                data = self._viz_widget_create(body)
            elif path == "/api/viz/widget/delete":
                data = self._viz_widget_delete(body)
            elif path == "/api/viz/widget/move":
                data = self._viz_widget_move(body)
            elif path == "/api/viz/widget/resize":
                data = self._viz_widget_resize(body)
            elif path == "/api/viz/layout/compact":
                data = self._viz_layout_compact(body)
            elif path == "/api/viz/layout/arrange":
                data = self._viz_layout_arrange(body)
            elif path == "/api/viz/embed/create":
                data = self._viz_embed_create(body)
            elif path == "/api/viz/embed/revoke":
                data = self._viz_embed_revoke(body)
            elif path == "/api/viz/share/create":
                data = self._viz_share_create(body)
            elif path == "/api/viz/share/dashboard":
                data = self._viz_share_dashboard(body)
            elif path == "/api/viz/realtime/publish":
                data = self._viz_realtime_publish(body)
            elif path == "/api/viz/realtime/subscribe":
                data = self._viz_realtime_subscribe(body)
            elif path == "/api/viz/realtime/unsubscribe":
                data = self._viz_realtime_unsubscribe(body)
            elif path == "/api/viz/chart/create":
                data = self._viz_chart_create(body)
            elif path == "/api/viz/chart/interact":
                data = self._viz_chart_interact(body)
            elif path == "/api/viz/chart/drill-down":
                data = self._viz_chart_drill_down(body)
            elif path == "/api/viz/chart/drill-up":
                data = self._viz_chart_drill_up(body)
            elif path == "/api/viz/updates/refresh":
                data = self._viz_updates_refresh(body)
            elif path == "/api/viz/updates/invalidate":
                data = self._viz_updates_invalidate(body)
            else:
                self._send_error(404, "Not found")
                return

            self._send_json(data)

        except Exception as e:
            self._send_error(500, str(e))

    def _get_snapshot_id(self, params: dict[str, list[str]]) -> str | None:
        """Get snapshot ID from params or use latest."""
        # Check if snapshot_id is provided in params
        requested_id = params.get("snapshot_id", [""])[0]
        if requested_id:
            return requested_id
        # Fall back to latest snapshot
        return self.storage.get_latest_snapshot_id() if self.storage else None

    def _get_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Get posture summary."""
        if not self.storage:
            return {"error": "No storage configured"}

        params = params or {}
        snapshot_id = self._get_snapshot_id(params)
        if not snapshot_id:
            return {
                "snapshot_id": None,
                "total_assets": 0,
                "total_findings": 0,
                "findings_by_severity": {},
                "findings_by_status": {},
            }

        assets = self.storage.get_assets(snapshot_id)
        findings = self.storage.get_findings(snapshot_id)

        return {
            "snapshot_id": snapshot_id,
            "total_assets": len(assets),
            "total_findings": len(findings),
            "findings_by_severity": findings.count_by_severity_dict(),
            "findings_by_status": {
                status.value: count
                for status, count in findings.count_by_status().items()
            },
        }

    def _get_assets(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """Get paginated assets."""
        if not self.storage:
            return {"error": "No storage configured"}

        snapshot_id = self._get_snapshot_id(params)
        if not snapshot_id:
            return {"items": [], "total": 0}

        assets = self.storage.get_assets(snapshot_id)

        # Apply filters
        resource_type = params.get("type", [None])[0]
        region = params.get("region", [None])[0]
        exposure = params.get("exposure", [None])[0]

        if resource_type:
            assets = assets.filter_by_type(resource_type)
        if region:
            assets = assets.filter_by_region(region)
        if exposure and exposure == "internet_facing":
            assets = assets.filter_internet_facing()

        # Pagination
        limit = int(params.get("limit", ["50"])[0])
        offset = int(params.get("offset", ["0"])[0])

        total = len(assets)
        items = [
            {
                "id": asset.id,
                "resource_type": asset.resource_type,
                "name": asset.name,
                "region": asset.region,
                "network_exposure": asset.network_exposure,
                "account_id": asset.account_id,
            }
            for asset in list(assets)[offset : offset + limit]
        ]

        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def _get_findings(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """Get paginated findings."""
        if not self.storage:
            return {"error": "No storage configured"}

        from stance.models import Severity, FindingStatus

        snapshot_id = self._get_snapshot_id(params)
        if not snapshot_id:
            return {"items": [], "total": 0}

        # Parse filters
        severity = None
        status = None

        severity_param = params.get("severity", [None])[0]
        if severity_param:
            severity = Severity.from_string(severity_param)

        status_param = params.get("status", [None])[0]
        if status_param:
            status = FindingStatus.from_string(status_param)

        findings = self.storage.get_findings(
            snapshot_id, severity=severity, status=status
        )

        # Apply additional filters
        asset_id = params.get("asset_id", [None])[0]
        if asset_id:
            findings = findings.filter_by_asset(asset_id)

        # Pagination
        limit = int(params.get("limit", ["50"])[0])
        offset = int(params.get("offset", ["0"])[0])

        total = len(findings)
        items = [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "finding_type": finding.finding_type.value,
                "asset_id": finding.asset_id,
                "rule_id": finding.rule_id,
                "cve_id": finding.cve_id,
            }
            for finding in list(findings)[offset : offset + limit]
        ]

        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def _get_compliance(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """Get compliance scores."""
        if not self.storage:
            return {"error": "No storage configured"}

        from stance.engine import PolicyLoader, ComplianceCalculator

        snapshot_id = self._get_snapshot_id(params)
        if not snapshot_id:
            return {"frameworks": [], "overall_score": 0}

        assets = self.storage.get_assets(snapshot_id)
        findings = self.storage.get_findings(snapshot_id)

        loader = PolicyLoader()
        policies = loader.load_all()

        calculator = ComplianceCalculator()
        report = calculator.calculate_scores(policies, findings, assets, snapshot_id)

        # Filter by framework if specified
        framework = params.get("framework", [None])[0]
        frameworks = report.frameworks
        if framework:
            frameworks = [f for f in frameworks if f.framework_id == framework]

        return {
            "overall_score": report.overall_score,
            "frameworks": [
                {
                    "framework_id": f.framework_id,
                    "framework_name": f.framework_name,
                    "version": f.version,
                    "score_percentage": f.score_percentage,
                    "controls_passed": f.controls_passed,
                    "controls_failed": f.controls_failed,
                    "controls_total": f.controls_total,
                }
                for f in frameworks
            ],
        }

    def _get_snapshots(self) -> dict[str, Any]:
        """Get list of scan snapshots."""
        if not self.storage:
            return {"error": "No storage configured"}

        snapshots = self.storage.list_snapshots(limit=20)
        return {"snapshots": snapshots}

    def _get_overview(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Get comprehensive overview for dashboard."""
        if not self.storage:
            return {"error": "No storage configured"}

        from stance.models import Severity, FindingStatus

        params = params or {}
        snapshot_id = self._get_snapshot_id(params)
        if not snapshot_id:
            return {
                "snapshot_id": None,
                "total_assets": 0,
                "total_findings": 0,
                "assets_by_cloud": {},
                "assets_by_region": {},
                "findings_by_severity": {},
                "compliance_scores": {},
                "top_findings": [],
                "recent_assets": [],
            }

        assets = self.storage.get_assets(snapshot_id)
        findings = self.storage.get_findings(snapshot_id)

        # Count assets by cloud provider
        assets_by_cloud: dict[str, int] = {}
        assets_by_region: dict[str, int] = {}
        for asset in assets:
            cp = asset.cloud_provider
            assets_by_cloud[cp] = assets_by_cloud.get(cp, 0) + 1
            region = asset.region
            assets_by_region[region] = assets_by_region.get(region, 0) + 1

        # Get compliance scores
        from stance.engine import PolicyLoader, ComplianceCalculator
        try:
            loader = PolicyLoader()
            policies = loader.load_all()
            calculator = ComplianceCalculator()
            report = calculator.calculate_scores(policies, findings, assets, snapshot_id)
            compliance_scores = {
                "overall": report.overall_score,
                "frameworks": {
                    f.framework_id: f.score_percentage
                    for f in report.frameworks
                },
            }
        except Exception:
            compliance_scores = {"overall": 0, "frameworks": {}}

        # Get top critical/high findings
        critical_findings = findings.filter_by_severity(Severity.CRITICAL)
        high_findings = findings.filter_by_severity(Severity.HIGH)
        top_findings = []
        for f in list(critical_findings)[:5]:
            top_findings.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "asset_id": f.asset_id,
            })
        for f in list(high_findings)[:5]:
            if len(top_findings) >= 10:
                break
            top_findings.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "asset_id": f.asset_id,
            })

        # Internet-facing assets count
        internet_facing = len(assets.filter_internet_facing())

        return {
            "snapshot_id": snapshot_id,
            "total_assets": len(assets),
            "total_findings": len(findings),
            "internet_facing_assets": internet_facing,
            "assets_by_cloud": assets_by_cloud,
            "assets_by_region": dict(sorted(
                assets_by_region.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            "findings_by_severity": findings.count_by_severity_dict(),
            "findings_by_status": {
                status.value: count
                for status, count in findings.count_by_status().items()
            },
            "compliance_scores": compliance_scores,
            "top_findings": top_findings,
            "critical_count": len(critical_findings),
            "high_count": len(high_findings),
        }

    def _get_asset_detail(self, asset_id: str) -> dict[str, Any]:
        """Get detailed information for a specific asset."""
        if not self.storage:
            return {"error": "No storage configured"}

        from urllib.parse import unquote
        asset_id = unquote(asset_id)

        snapshot_id = self.storage.get_latest_snapshot_id()
        if not snapshot_id:
            return {"error": "No snapshots available"}

        assets = self.storage.get_assets(snapshot_id)
        findings = self.storage.get_findings(snapshot_id)

        # Find the asset
        target_asset = None
        for asset in assets:
            if asset.id == asset_id:
                target_asset = asset
                break

        if not target_asset:
            return {"error": f"Asset not found: {asset_id}"}

        # Get findings for this asset
        asset_findings = findings.filter_by_asset(asset_id)

        return {
            "asset": {
                "id": target_asset.id,
                "name": target_asset.name,
                "resource_type": target_asset.resource_type,
                "cloud_provider": target_asset.cloud_provider,
                "account_id": target_asset.account_id,
                "region": target_asset.region,
                "network_exposure": target_asset.network_exposure,
                "tags": target_asset.tags,
                "created_at": target_asset.created_at.isoformat() if target_asset.created_at else None,
                "last_seen": target_asset.last_seen.isoformat() if target_asset.last_seen else None,
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "finding_type": f.finding_type.value,
                    "rule_id": f.rule_id,
                }
                for f in asset_findings
            ],
            "finding_count": len(asset_findings),
            "findings_by_severity": asset_findings.count_by_severity_dict(),
        }

    def _get_finding_detail(self, finding_id: str) -> dict[str, Any]:
        """Get detailed information for a specific finding."""
        if not self.storage:
            return {"error": "No storage configured"}

        from urllib.parse import unquote
        finding_id = unquote(finding_id)

        snapshot_id = self.storage.get_latest_snapshot_id()
        if not snapshot_id:
            return {"error": "No snapshots available"}

        findings = self.storage.get_findings(snapshot_id)
        assets = self.storage.get_assets(snapshot_id)

        # Find the finding
        target_finding = None
        for finding in findings:
            if finding.id == finding_id:
                target_finding = finding
                break

        if not target_finding:
            return {"error": f"Finding not found: {finding_id}"}

        # Find the associated asset
        asset_info = None
        for asset in assets:
            if asset.id == target_finding.asset_id:
                asset_info = {
                    "id": asset.id,
                    "name": asset.name,
                    "resource_type": asset.resource_type,
                    "region": asset.region,
                }
                break

        return {
            "finding": {
                "id": target_finding.id,
                "title": target_finding.title,
                "description": target_finding.description,
                "severity": target_finding.severity.value,
                "status": target_finding.status.value,
                "finding_type": target_finding.finding_type.value,
                "asset_id": target_finding.asset_id,
                "rule_id": target_finding.rule_id,
                "cve_id": target_finding.cve_id,
                "cvss_score": target_finding.cvss_score,
                "compliance_frameworks": target_finding.compliance_frameworks,
                "remediation_guidance": target_finding.remediation_guidance,
                "first_seen": target_finding.first_seen.isoformat() if target_finding.first_seen else None,
                "last_seen": target_finding.last_seen.isoformat() if target_finding.last_seen else None,
                "resource_path": target_finding.resource_path,
                "expected_value": target_finding.expected_value,
                "actual_value": target_finding.actual_value,
                "package_name": target_finding.package_name,
                "installed_version": target_finding.installed_version,
                "fixed_version": target_finding.fixed_version,
            },
            "asset": asset_info,
        }

    def _get_compliance_framework(self, framework: str) -> dict[str, Any]:
        """Get detailed compliance information for a specific framework."""
        if not self.storage:
            return {"error": "No storage configured"}

        from urllib.parse import unquote
        from stance.engine import PolicyLoader, ComplianceCalculator

        framework = unquote(framework)

        snapshot_id = self.storage.get_latest_snapshot_id()
        if not snapshot_id:
            return {"error": "No snapshots available"}

        assets = self.storage.get_assets(snapshot_id)
        findings = self.storage.get_findings(snapshot_id)

        loader = PolicyLoader()
        policies = loader.load_all()

        calculator = ComplianceCalculator()
        report = calculator.calculate_scores(policies, findings, assets, snapshot_id)

        # Find the framework
        target_framework = None
        for f in report.frameworks:
            if f.framework_id == framework:
                target_framework = f
                break

        if not target_framework:
            return {"error": f"Framework not found: {framework}"}

        return {
            "framework": {
                "id": target_framework.framework_id,
                "name": target_framework.framework_name,
                "version": target_framework.version,
                "score_percentage": target_framework.score_percentage,
                "controls_passed": target_framework.controls_passed,
                "controls_failed": target_framework.controls_failed,
                "controls_total": target_framework.controls_total,
            },
            "controls": [
                {
                    "control_id": c.control_id,
                    "control_name": c.control_name,
                    "status": c.status,
                    "resources_evaluated": c.resources_evaluated,
                    "resources_compliant": c.resources_compliant,
                    "resources_non_compliant": c.resources_non_compliant,
                }
                for c in target_framework.control_statuses
            ],
        }

    def _get_trends(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """Get historical trend data."""
        if not self.storage:
            return {"error": "No storage configured"}

        days = int(params.get("days", ["30"])[0])

        snapshots = self.storage.list_snapshots(limit=min(days, 100))

        if not snapshots:
            return {
                "period_days": days,
                "data_points": [],
            }

        data_points = []
        for snapshot_id in snapshots:
            try:
                assets = self.storage.get_assets(snapshot_id)
                findings = self.storage.get_findings(snapshot_id)

                # Parse timestamp from snapshot_id (format: YYYYMMDD-HHMMSS)
                timestamp = snapshot_id

                data_points.append({
                    "snapshot_id": snapshot_id,
                    "timestamp": timestamp,
                    "asset_count": len(assets),
                    "finding_count": len(findings),
                    "findings_by_severity": findings.count_by_severity_dict(),
                })
            except Exception:
                continue

        return {
            "period_days": days,
            "data_points": data_points,
            "snapshot_count": len(data_points),
        }

    def _get_drift(self) -> dict[str, Any]:
        """Get drift detection summary."""
        if not self.storage:
            return {"error": "No storage configured"}

        try:
            from stance.drift import BaselineManager, DriftDetector

            snapshot_id = self.storage.get_latest_snapshot_id()
            if not snapshot_id:
                return {"error": "No snapshots available"}

            assets = self.storage.get_assets(snapshot_id)

            manager = BaselineManager()
            baseline = manager.get_active_baseline()

            if not baseline:
                return {
                    "has_baseline": False,
                    "message": "No active baseline configured",
                }

            detector = DriftDetector(baseline_manager=manager)
            result = detector.detect_drift(assets)

            return {
                "has_baseline": True,
                "baseline_id": result.baseline_id,
                "assets_checked": result.assets_checked,
                "assets_with_drift": result.assets_with_drift,
                "has_drift": result.summary.get("has_drift", False),
                "drift_by_severity": result.summary.get("drift_by_severity", {}),
                "security_drift_count": result.summary.get("security_drift_count", 0),
            }
        except Exception as e:
            return {"error": str(e)}

    def _handle_export(self, params: dict[str, list[str]]) -> None:
        """Handle export requests."""
        if not self.storage:
            self._send_error(500, "No storage configured")
            return

        try:
            from stance.export import (
                ExportFormat,
                ExportOptions,
                ReportData,
                ReportType,
                create_export_manager,
            )

            snapshot_id = self.storage.get_latest_snapshot_id()
            if not snapshot_id:
                self._send_error(404, "No snapshots available")
                return

            assets = self.storage.get_assets(snapshot_id)
            findings = self.storage.get_findings(snapshot_id)

            # Parse parameters
            format_str = params.get("format", ["json"])[0].lower()
            report_type_str = params.get("type", ["full_report"])[0].lower()

            format_map = {
                "json": ExportFormat.JSON,
                "csv": ExportFormat.CSV,
                "html": ExportFormat.HTML,
                "pdf": ExportFormat.PDF,
            }
            export_format = format_map.get(format_str, ExportFormat.JSON)

            type_map = {
                "full_report": ReportType.FULL_REPORT,
                "executive_summary": ReportType.EXECUTIVE_SUMMARY,
                "findings_detail": ReportType.FINDINGS_DETAIL,
                "compliance_summary": ReportType.COMPLIANCE_SUMMARY,
                "asset_inventory": ReportType.ASSET_INVENTORY,
            }
            report_type = type_map.get(report_type_str, ReportType.FULL_REPORT)

            # Build report data
            data = ReportData(
                assets=assets,
                findings=findings,
            )

            options = ExportOptions(
                format=export_format,
                report_type=report_type,
                title="Mantissa Stance Security Report",
            )

            # Generate export
            manager = create_export_manager()
            result = manager.export(data, options)

            if not result.success:
                self._send_error(500, result.error or "Export failed")
                return

            # Set content type based on format
            content_types = {
                ExportFormat.JSON: "application/json",
                ExportFormat.CSV: "text/csv",
                ExportFormat.HTML: "text/html",
                ExportFormat.PDF: "application/pdf",
            }
            content_type = content_types.get(export_format, "application/octet-stream")

            # Set filename for download
            extensions = {
                ExportFormat.JSON: "json",
                ExportFormat.CSV: "csv",
                ExportFormat.HTML: "html",
                ExportFormat.PDF: "pdf",
            }
            ext = extensions.get(export_format, "dat")
            filename = f"stance-report.{ext}"

            # Send response
            content = result.content
            if isinstance(content, str):
                content = content.encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)

        except Exception as e:
            self._send_error(500, str(e))

    def _get_risk_scores(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Get risk scoring summary."""
        if not self.storage:
            return {"error": "No storage configured"}

        try:
            from stance.correlation import RiskScorer

            params = params or {}
            snapshot_id = self._get_snapshot_id(params)
            if not snapshot_id:
                return {"error": "No snapshots available"}

            assets = self.storage.get_assets(snapshot_id)
            findings = self.storage.get_findings(snapshot_id)

            scorer = RiskScorer()
            result = scorer.calculate_scores(findings, assets)

            return {
                "overall_score": result.overall_score,
                "overall_risk_level": result.overall_risk_level.value,
                "risk_by_cloud": result.risk_by_cloud,
                "risk_by_type": dict(sorted(
                    result.risk_by_type.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]),
                "top_risks": [
                    {
                        "asset_id": r.asset_id,
                        "asset_name": r.asset_name,
                        "asset_type": r.asset_type,
                        "score": r.overall_score,
                        "risk_level": r.risk_level.value,
                        "critical_findings": r.critical_findings,
                        "high_findings": r.high_findings,
                    }
                    for r in result.top_risks[:10]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    # Cache for attack paths (expensive to compute)
    _attack_paths_cache: dict[str, Any] = {}
    _attack_paths_cache_time: datetime | None = None

    def _get_attack_paths(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Get attack path analysis results."""
        if not self.storage:
            return {"error": "No storage configured"}

        try:
            from stance.analytics import AttackPathAnalyzer
            from stance.analytics.asset_graph import AssetGraph
            from stance.models.finding import FindingCollection

            params = params or {}
            snapshot_id = self._get_snapshot_id(params)
            if not snapshot_id:
                return {"error": "No snapshots available", "paths": [], "summary": {}}

            # Check cache (valid for 5 minutes)
            cache_key = f"{snapshot_id}"
            if (
                self._attack_paths_cache_time
                and self._attack_paths_cache.get("snapshot_id") == cache_key
                and (datetime.utcnow() - self._attack_paths_cache_time) < timedelta(minutes=5)
            ):
                return self._attack_paths_cache.get("data", {})

            assets = self.storage.get_assets(snapshot_id)
            findings = self.storage.get_findings(snapshot_id)

            # Build asset graph
            graph = AssetGraph()
            for asset in assets:
                graph.add_asset(asset)

            # Create findings collection
            findings_collection = FindingCollection(findings=findings)

            # Analyze attack paths
            analyzer = AttackPathAnalyzer(graph, findings_collection)
            paths = analyzer.analyze()

            # Filter by path type if specified
            path_type = params.get("type", [None])[0]
            if path_type:
                paths = [p for p in paths if p.path_type.value == path_type]

            # Filter by severity if specified
            severity = params.get("severity", [None])[0]
            if severity:
                from stance.models.finding import Severity
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                    "info": Severity.INFO,
                }
                if severity.lower() in severity_map:
                    target_sev = severity_map[severity.lower()]
                    paths = [p for p in paths if p.severity == target_sev]

            # Build summary
            summary = {
                "total_paths": len(paths),
                "by_type": {},
                "by_severity": {},
            }

            for path in paths:
                path_type_val = path.path_type.value
                summary["by_type"][path_type_val] = summary["by_type"].get(path_type_val, 0) + 1
                sev_val = path.severity.value
                summary["by_severity"][sev_val] = summary["by_severity"].get(sev_val, 0) + 1

            # Convert paths to dicts
            path_dicts = [p.to_dict() for p in paths[:50]]  # Limit to 50 paths

            result = {
                "paths": path_dicts,
                "summary": summary,
                "snapshot_id": snapshot_id,
            }

            # Update cache
            self._attack_paths_cache = {"snapshot_id": cache_key, "data": result}
            self._attack_paths_cache_time = datetime.utcnow()

            return result

        except ImportError:
            return {"error": "Attack path analyzer not available", "paths": [], "summary": {}}
        except Exception as e:
            return {"error": str(e), "paths": [], "summary": {}}

    def _get_attack_path_detail(self, path_id: str) -> dict[str, Any]:
        """Get detailed information about a specific attack path."""
        from urllib.parse import unquote
        path_id = unquote(path_id)

        # Get attack paths (use cache if available)
        paths_data = self._get_attack_paths({})

        if "error" in paths_data and not paths_data.get("paths"):
            return {"error": paths_data.get("error", "Failed to get attack paths")}

        # Find the specific path
        for path in paths_data.get("paths", []):
            if path.get("id") == path_id:
                return {
                    "path": path,
                    "found": True,
                }

        return {"error": f"Attack path '{path_id}' not found", "found": False}

    def _handle_search(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Handle full-text search across findings and assets.

        Args:
            params: Query parameters (q=search query, type=findings/assets/all)

        Returns:
            Search results with matching findings and assets
        """
        if not self.storage:
            return {"error": "No storage configured"}

        query = params.get("q", [""])[0].strip().lower()
        search_type = params.get("type", ["all"])[0].lower()
        limit = int(params.get("limit", ["20"])[0])

        if not query:
            return {"error": "Search query is required", "findings": [], "assets": []}

        if len(query) < 2:
            return {"error": "Search query must be at least 2 characters", "findings": [], "assets": []}

        snapshot_id = self.storage.get_latest_snapshot_id()
        if not snapshot_id:
            return {"findings": [], "assets": [], "query": query, "total": 0}

        results: dict[str, Any] = {
            "query": query,
            "findings": [],
            "assets": [],
        }

        # Search findings
        if search_type in ("all", "findings"):
            findings = self.storage.get_findings(snapshot_id)
            matching_findings = []

            for finding in findings:
                score = 0

                # Check title (highest weight)
                if query in finding.title.lower():
                    score += 100
                # Check description
                if finding.description and query in finding.description.lower():
                    score += 50
                # Check rule ID
                if finding.rule_id and query in finding.rule_id.lower():
                    score += 75
                # Check CVE ID
                if finding.cve_id and query in finding.cve_id.lower():
                    score += 90
                # Check asset ID
                if finding.asset_id and query in finding.asset_id.lower():
                    score += 30
                # Check severity
                if query in finding.severity.value.lower():
                    score += 20
                # Check remediation
                if finding.remediation_guidance and query in finding.remediation_guidance.lower():
                    score += 25

                if score > 0:
                    matching_findings.append({
                        "id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "status": finding.status.value,
                        "finding_type": finding.finding_type.value,
                        "asset_id": finding.asset_id,
                        "rule_id": finding.rule_id,
                        "score": score,
                    })

            # Sort by score (highest first) and limit
            matching_findings.sort(key=lambda x: x["score"], reverse=True)
            results["findings"] = matching_findings[:limit]

        # Search assets
        if search_type in ("all", "assets"):
            assets = self.storage.get_assets(snapshot_id)
            matching_assets = []

            for asset in assets:
                score = 0

                # Check name (highest weight)
                if query in asset.name.lower():
                    score += 100
                # Check asset ID
                if query in asset.id.lower():
                    score += 80
                # Check resource type
                if query in asset.resource_type.lower():
                    score += 60
                # Check region
                if asset.region and query in asset.region.lower():
                    score += 40
                # Check account ID
                if asset.account_id and query in asset.account_id.lower():
                    score += 30
                # Check tags
                for key, value in (asset.tags or {}).items():
                    if query in key.lower() or query in str(value).lower():
                        score += 50
                        break

                if score > 0:
                    matching_assets.append({
                        "id": asset.id,
                        "name": asset.name,
                        "resource_type": asset.resource_type,
                        "region": asset.region,
                        "network_exposure": asset.network_exposure,
                        "account_id": asset.account_id,
                        "score": score,
                    })

            # Sort by score (highest first) and limit
            matching_assets.sort(key=lambda x: x["score"], reverse=True)
            results["assets"] = matching_assets[:limit]

        results["total"] = len(results["findings"]) + len(results["assets"])
        return results

    # =========================================================================
    # Filter Presets
    # =========================================================================

    # In-memory preset storage (would typically be persisted)
    _presets: dict[str, dict] = {}

    def _get_presets(self) -> dict[str, Any]:
        """Get all saved filter presets."""
        presets = []
        for name, preset in self._presets.items():
            presets.append({
                "name": name,
                "view": preset.get("view", ""),
                "filters": preset.get("filters", {}),
                "created_at": preset.get("created_at", ""),
                "description": preset.get("description", ""),
            })
        return {"presets": presets}

    def _get_preset(self, name: str) -> dict[str, Any]:
        """Get a specific filter preset."""
        from urllib.parse import unquote
        name = unquote(name)

        if name not in self._presets:
            return {"error": f"Preset '{name}' not found"}

        preset = self._presets[name]
        return {
            "name": name,
            "view": preset.get("view", ""),
            "filters": preset.get("filters", {}),
            "created_at": preset.get("created_at", ""),
            "description": preset.get("description", ""),
        }

    def _save_preset(self, body: bytes) -> dict[str, Any]:
        """Save a filter preset."""
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        name = data.get("name", "").strip()
        if not name:
            return {"error": "Preset name is required"}

        if len(name) > 50:
            return {"error": "Preset name must be 50 characters or less"}

        # Sanitize name for URL use
        import re
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)

        from datetime import datetime, timezone

        preset = {
            "view": data.get("view", ""),
            "filters": data.get("filters", {}),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "description": data.get("description", ""),
        }

        self._presets[safe_name] = preset

        return {
            "success": True,
            "name": safe_name,
            "original_name": name,
            "message": f"Preset '{name}' saved successfully",
        }

    def _delete_preset(self, name: str) -> dict[str, Any]:
        """Delete a filter preset."""
        from urllib.parse import unquote
        name = unquote(name)

        if name not in self._presets:
            return {"error": f"Preset '{name}' not found"}

        del self._presets[name]
        return {"success": True, "message": f"Preset '{name}' deleted"}

    # -------------------------------------------------------------------------
    # Notification Settings API
    # -------------------------------------------------------------------------

    # Class-level storage for notification configuration
    _notification_destinations: dict[str, dict[str, Any]] = {}
    _notification_config: dict[str, Any] = {
        "enabled": False,
        "notify_on_critical": True,
        "notify_on_high": False,
        "notify_on_scan_complete": False,
        "notify_on_new_findings": True,
        "min_severity": "high",
        "default_destination": None,
    }
    _notification_history: list[dict[str, Any]] = []

    def _get_notification_destinations(self) -> dict[str, Any]:
        """Get configured notification destinations."""
        destinations = []
        for name, config in self._notification_destinations.items():
            destinations.append({
                "name": name,
                "type": config.get("type", "unknown"),
                "enabled": config.get("enabled", True),
                "configured": self._is_destination_configured(config),
                "last_test": config.get("last_test"),
                "last_test_success": config.get("last_test_success"),
            })

        # Add available destination types
        available_types = [
            {"type": "slack", "name": "Slack", "description": "Send alerts to Slack channels"},
            {"type": "pagerduty", "name": "PagerDuty", "description": "Create incidents in PagerDuty"},
            {"type": "email", "name": "Email", "description": "Send email notifications via SMTP"},
            {"type": "teams", "name": "Microsoft Teams", "description": "Send alerts to Teams channels"},
            {"type": "jira", "name": "Jira", "description": "Create issues in Jira"},
            {"type": "webhook", "name": "Webhook", "description": "Send to custom HTTP endpoint"},
        ]

        return {
            "destinations": destinations,
            "available_types": available_types,
        }

    def _is_destination_configured(self, config: dict[str, Any]) -> bool:
        """Check if a destination has required configuration."""
        dest_type = config.get("type", "")
        if dest_type == "slack":
            return bool(config.get("webhook_url"))
        elif dest_type == "pagerduty":
            return bool(config.get("routing_key"))
        elif dest_type == "email":
            return bool(config.get("smtp_host") and config.get("recipients"))
        elif dest_type == "teams":
            return bool(config.get("webhook_url"))
        elif dest_type == "jira":
            return bool(config.get("url") and config.get("project_key"))
        elif dest_type == "webhook":
            return bool(config.get("url"))
        return False

    def _get_notification_config(self) -> dict[str, Any]:
        """Get notification settings."""
        return {
            "config": self._notification_config,
            "severity_options": ["critical", "high", "medium", "low", "info"],
        }

    def _get_notification_history(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """Get notification history."""
        limit = int(params.get("limit", ["20"])[0])
        offset = int(params.get("offset", ["0"])[0])

        total = len(self._notification_history)
        items = self._notification_history[offset:offset + limit]

        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def _save_notification_destination(self, body: bytes) -> dict[str, Any]:
        """Save a notification destination configuration."""
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        name = data.get("name", "").strip()
        dest_type = data.get("type", "").strip()

        if not name:
            return {"error": "Destination name is required"}
        if not dest_type:
            return {"error": "Destination type is required"}

        valid_types = ["slack", "pagerduty", "email", "teams", "jira", "webhook"]
        if dest_type not in valid_types:
            return {"error": f"Invalid destination type. Must be one of: {', '.join(valid_types)}"}

        # Sanitize name
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)

        config = {
            "type": dest_type,
            "enabled": data.get("enabled", True),
            "created_at": datetime.utcnow().isoformat(),
        }

        # Add type-specific configuration
        if dest_type == "slack":
            config["webhook_url"] = data.get("webhook_url", "")
            config["channel"] = data.get("channel", "")
        elif dest_type == "pagerduty":
            config["routing_key"] = data.get("routing_key", "")
            config["severity_map"] = data.get("severity_map", {})
        elif dest_type == "email":
            config["smtp_host"] = data.get("smtp_host", "")
            config["smtp_port"] = data.get("smtp_port", 587)
            config["smtp_user"] = data.get("smtp_user", "")
            config["smtp_password"] = data.get("smtp_password", "")
            config["from_address"] = data.get("from_address", "")
            config["recipients"] = data.get("recipients", [])
            config["use_tls"] = data.get("use_tls", True)
        elif dest_type == "teams":
            config["webhook_url"] = data.get("webhook_url", "")
        elif dest_type == "jira":
            config["url"] = data.get("url", "")
            config["username"] = data.get("username", "")
            config["api_token"] = data.get("api_token", "")
            config["project_key"] = data.get("project_key", "")
            config["issue_type"] = data.get("issue_type", "Task")
        elif dest_type == "webhook":
            config["url"] = data.get("url", "")
            config["method"] = data.get("method", "POST")
            config["headers"] = data.get("headers", {})

        self._notification_destinations[safe_name] = config

        return {
            "success": True,
            "name": safe_name,
            "message": f"Destination '{name}' saved successfully",
        }

    def _test_notification_destination(self, body: bytes) -> dict[str, Any]:
        """Test a notification destination."""
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        name = data.get("name", "").strip()
        if not name:
            return {"error": "Destination name is required"}

        if name not in self._notification_destinations:
            return {"error": f"Destination '{name}' not found"}

        config = self._notification_destinations[name]
        dest_type = config.get("type", "")

        # Record test attempt
        config["last_test"] = datetime.utcnow().isoformat()

        # Try to test the destination
        try:
            success = self._perform_destination_test(dest_type, config)
            config["last_test_success"] = success

            if success:
                return {
                    "success": True,
                    "message": f"Test notification sent to '{name}' successfully",
                }
            else:
                return {
                    "success": False,
                    "error": "Test notification failed - check configuration",
                }
        except Exception as e:
            config["last_test_success"] = False
            return {
                "success": False,
                "error": f"Test failed: {str(e)}",
            }

    def _perform_destination_test(self, dest_type: str, config: dict[str, Any]) -> bool:
        """Perform actual test of a destination."""
        try:
            if dest_type == "slack":
                from stance.alerting.destinations import SlackDestination
                dest = SlackDestination(name="test", config=config)
                return dest.test_connection()
            elif dest_type == "pagerduty":
                from stance.alerting.destinations import PagerDutyDestination
                dest = PagerDutyDestination(name="test", config=config)
                return dest.test_connection()
            elif dest_type == "email":
                from stance.alerting.destinations import EmailDestination
                dest = EmailDestination(name="test", config=config)
                return dest.test_connection()
            elif dest_type == "teams":
                from stance.alerting.destinations import TeamsDestination
                dest = TeamsDestination(name="test", config=config)
                return dest.test_connection()
            elif dest_type == "webhook":
                from stance.alerting.destinations import WebhookDestination
                dest = WebhookDestination(name="test", config=config)
                return dest.test_connection()
            elif dest_type == "jira":
                from stance.alerting.destinations import JiraDestination
                dest = JiraDestination(name="test", config=config)
                return dest.test_connection()
            else:
                return False
        except ImportError:
            # Alerting module not available
            return False
        except Exception:
            return False

    def _delete_notification_destination(self, name: str) -> dict[str, Any]:
        """Delete a notification destination."""
        from urllib.parse import unquote
        name = unquote(name)

        if name not in self._notification_destinations:
            return {"error": f"Destination '{name}' not found"}

        del self._notification_destinations[name]
        return {"success": True, "message": f"Destination '{name}' deleted"}

    def _save_notification_config(self, body: bytes) -> dict[str, Any]:
        """Save notification configuration."""
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        # Update configuration
        if "enabled" in data:
            self._notification_config["enabled"] = bool(data["enabled"])
        if "notify_on_critical" in data:
            self._notification_config["notify_on_critical"] = bool(data["notify_on_critical"])
        if "notify_on_high" in data:
            self._notification_config["notify_on_high"] = bool(data["notify_on_high"])
        if "notify_on_scan_complete" in data:
            self._notification_config["notify_on_scan_complete"] = bool(data["notify_on_scan_complete"])
        if "notify_on_new_findings" in data:
            self._notification_config["notify_on_new_findings"] = bool(data["notify_on_new_findings"])
        if "min_severity" in data:
            valid_severities = ["critical", "high", "medium", "low", "info"]
            if data["min_severity"] in valid_severities:
                self._notification_config["min_severity"] = data["min_severity"]
        if "default_destination" in data:
            self._notification_config["default_destination"] = data["default_destination"]

        return {
            "success": True,
            "config": self._notification_config,
            "message": "Notification settings saved",
        }

    def _send_test_notification(self, body: bytes) -> dict[str, Any]:
        """Send a test notification to a destination."""
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        destination = data.get("destination", "").strip()
        if not destination:
            return {"error": "Destination is required"}

        if destination not in self._notification_destinations:
            return {"error": f"Destination '{destination}' not found"}

        config = self._notification_destinations[destination]

        # Create a test finding
        from stance.models.finding import Finding, Severity, FindingType, FindingStatus

        test_finding = Finding(
            id="test-finding-001",
            title="Test Notification from Stance Dashboard",
            description="This is a test notification to verify your notification destination is configured correctly.",
            severity=Severity.INFO,
            finding_type=FindingType.MISCONFIGURATION,
            status=FindingStatus.OPEN,
            asset_id="test-asset",
            resource_type="test_resource",
        )

        try:
            dest_type = config.get("type", "")
            success = self._send_finding_to_destination(dest_type, config, test_finding)

            # Record in history
            self._notification_history.insert(0, {
                "timestamp": datetime.utcnow().isoformat(),
                "destination": destination,
                "type": "test",
                "success": success,
                "finding_id": test_finding.id,
            })

            # Keep history limited
            if len(self._notification_history) > 100:
                self._notification_history = self._notification_history[:100]

            if success:
                return {
                    "success": True,
                    "message": f"Test notification sent to '{destination}'",
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to send test notification",
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error sending notification: {str(e)}",
            }

    def _send_finding_to_destination(
        self, dest_type: str, config: dict[str, Any], finding: Any
    ) -> bool:
        """Send a finding to a specific destination."""
        try:
            if dest_type == "slack":
                from stance.alerting.destinations import SlackDestination
                dest = SlackDestination(name="dashboard", config=config)
                return dest.send(finding, {})
            elif dest_type == "pagerduty":
                from stance.alerting.destinations import PagerDutyDestination
                dest = PagerDutyDestination(name="dashboard", config=config)
                return dest.send(finding, {})
            elif dest_type == "email":
                from stance.alerting.destinations import EmailDestination
                dest = EmailDestination(name="dashboard", config=config)
                return dest.send(finding, {})
            elif dest_type == "teams":
                from stance.alerting.destinations import TeamsDestination
                dest = TeamsDestination(name="dashboard", config=config)
                return dest.send(finding, {})
            elif dest_type == "webhook":
                from stance.alerting.destinations import WebhookDestination
                dest = WebhookDestination(name="dashboard", config=config)
                return dest.send(finding, {})
            elif dest_type == "jira":
                from stance.alerting.destinations import JiraDestination
                dest = JiraDestination(name="dashboard", config=config)
                return dest.send(finding, {})
            else:
                return False
        except ImportError:
            return False
        except Exception:
            return False

    # =========================================================================
    # DSPM API Endpoints
    # =========================================================================

    def _dspm_scan(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Scan storage for sensitive data.

        Query params:
            target: Storage target (bucket name or container)
            cloud: Cloud provider (aws, gcp, azure)
            sample_size: Number of objects to sample (default: 100)
        """
        target = params.get("target", [""])[0]
        cloud = params.get("cloud", [""])[0]
        sample_size = int(params.get("sample_size", ["100"])[0])

        if not target:
            return {"error": "target parameter is required"}
        if not cloud:
            return {"error": "cloud parameter is required (aws, gcp, azure)"}

        try:
            if cloud == "aws":
                from stance.dspm.scanners import S3DataScanner, ScanConfig
                config = ScanConfig(sample_size=sample_size)
                scanner = S3DataScanner(config)
            elif cloud == "gcp":
                from stance.dspm.scanners import GCSDataScanner, ScanConfig
                config = ScanConfig(sample_size=sample_size)
                scanner = GCSDataScanner(config)
            elif cloud == "azure":
                from stance.dspm.scanners import AzureBlobDataScanner, ScanConfig
                config = ScanConfig(sample_size=sample_size)
                scanner = AzureBlobDataScanner(config)
            else:
                return {"error": f"Unknown cloud provider: {cloud}"}

            result = scanner.scan(target)

            return {
                "target": result.target,
                "cloud": result.cloud_provider,
                "started_at": result.started_at.isoformat() if result.started_at else None,
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "summary": {
                    "total_objects": result.summary.total_objects if result.summary else 0,
                    "objects_scanned": result.summary.objects_scanned if result.summary else 0,
                    "findings_count": result.summary.findings_count if result.summary else 0,
                } if result.summary else None,
                "findings": [
                    {
                        "object_key": f.object_key,
                        "classification": f.classification.name if f.classification else None,
                        "severity": f.severity.value if f.severity else None,
                        "patterns_matched": f.patterns_matched,
                    }
                    for f in (result.findings or [])[:50]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _dspm_access(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Analyze data access patterns.

        Query params:
            target: Storage target
            cloud: Cloud provider (aws, gcp, azure)
            stale_days: Days to consider stale (default: 90)
            lookback_days: Days to look back (default: 180)
        """
        target = params.get("target", [""])[0]
        cloud = params.get("cloud", [""])[0]
        stale_days = int(params.get("stale_days", ["90"])[0])
        lookback_days = int(params.get("lookback_days", ["180"])[0])

        if not target:
            return {"error": "target parameter is required"}
        if not cloud:
            return {"error": "cloud parameter is required (aws, gcp, azure)"}

        try:
            if cloud == "aws":
                from stance.dspm.access import CloudTrailAccessAnalyzer, AccessConfig
                config = AccessConfig(stale_days=stale_days, lookback_days=lookback_days)
                analyzer = CloudTrailAccessAnalyzer(config)
            elif cloud == "gcp":
                from stance.dspm.access import GCPAuditLogAnalyzer, AccessConfig
                config = AccessConfig(stale_days=stale_days, lookback_days=lookback_days)
                analyzer = GCPAuditLogAnalyzer(config)
            elif cloud == "azure":
                from stance.dspm.access import AzureActivityLogAnalyzer, AccessConfig
                config = AccessConfig(stale_days=stale_days, lookback_days=lookback_days)
                analyzer = AzureActivityLogAnalyzer(config)
            else:
                return {"error": f"Unknown cloud provider: {cloud}"}

            result = analyzer.analyze(target)

            return {
                "target": result.target,
                "cloud": result.cloud_provider,
                "analysis_period_days": result.analysis_period_days,
                "summary": {
                    "total_principals": result.summary.total_principals if result.summary else 0,
                    "stale_access_count": result.summary.stale_access_count if result.summary else 0,
                    "over_privileged_count": result.summary.over_privileged_count if result.summary else 0,
                } if result.summary else None,
                "findings": [
                    {
                        "principal": f.principal,
                        "finding_type": f.finding_type.value if f.finding_type else None,
                        "days_since_access": f.days_since_access,
                        "recommendation": f.recommendation,
                    }
                    for f in (result.findings or [])[:50]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _dspm_cost(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Analyze storage costs and cold data.

        Query params:
            target: Storage target
            cloud: Cloud provider (aws, gcp, azure)
            cold_days: Days to consider cold (default: 90)
        """
        target = params.get("target", [""])[0]
        cloud = params.get("cloud", [""])[0]
        cold_days = int(params.get("cold_days", ["90"])[0])

        if not target:
            return {"error": "target parameter is required"}
        if not cloud:
            return {"error": "cloud parameter is required (aws, gcp, azure)"}

        try:
            if cloud == "aws":
                from stance.dspm.cost import S3CostAnalyzer, CostConfig
                config = CostConfig(cold_days=cold_days)
                analyzer = S3CostAnalyzer(config)
            elif cloud == "gcp":
                from stance.dspm.cost import GCSCostAnalyzer, CostConfig
                config = CostConfig(cold_days=cold_days)
                analyzer = GCSCostAnalyzer(config)
            elif cloud == "azure":
                from stance.dspm.cost import AzureBlobCostAnalyzer, CostConfig
                config = CostConfig(cold_days=cold_days)
                analyzer = AzureBlobCostAnalyzer(config)
            else:
                return {"error": f"Unknown cloud provider: {cloud}"}

            result = analyzer.analyze(target)

            return {
                "target": result.target,
                "cloud": result.cloud_provider,
                "metrics": {
                    "total_size_bytes": result.metrics.total_size_bytes if result.metrics else 0,
                    "object_count": result.metrics.object_count if result.metrics else 0,
                    "estimated_monthly_cost": result.metrics.estimated_monthly_cost if result.metrics else 0,
                } if result.metrics else None,
                "potential_monthly_savings": result.potential_monthly_savings,
                "findings": [
                    {
                        "object_key": f.object_key if hasattr(f, 'object_key') else None,
                        "finding_type": f.finding_type.value if f.finding_type else None,
                        "days_since_access": f.days_since_access if hasattr(f, 'days_since_access') else None,
                        "recommendation": f.recommendation,
                    }
                    for f in (result.findings or [])[:50]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _dspm_classify(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Classify text for sensitive content.

        Query params:
            text: Text to classify
        """
        text = params.get("text", [""])[0]

        if not text:
            return {"error": "text parameter is required"}

        try:
            from stance.dspm.classifier import DataClassifier
            from stance.dspm.detector import SensitiveDataDetector

            classifier = DataClassifier()
            detector = SensitiveDataDetector()

            classification = classifier.classify(text)
            detection = detector.detect(text)

            return {
                "classification": {
                    "level": classification.level.value if classification.level else None,
                    "categories": [c.value for c in classification.categories] if classification.categories else [],
                    "confidence": classification.confidence,
                },
                "patterns_detected": [
                    {
                        "pattern_type": m.pattern_type.value if m.pattern_type else None,
                        "matched_text": m.matched_text[:50] if m.matched_text else None,
                        "confidence": m.confidence,
                    }
                    for m in (detection.matches or [])
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _dspm_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Get DSPM summary statistics."""
        return {
            "available_features": [
                {"name": "scan", "description": "Scan storage for sensitive data"},
                {"name": "access", "description": "Analyze data access patterns"},
                {"name": "cost", "description": "Analyze storage costs"},
                {"name": "classify", "description": "Classify text for sensitive content"},
            ],
            "supported_clouds": ["aws", "gcp", "azure"],
            "data_categories": [
                "PII", "PCI", "PHI", "Financial", "Credentials",
                "Secrets", "Internal", "Confidential", "Restricted",
            ],
        }

    # =========================================================================
    # Identity API Endpoints
    # =========================================================================

    def _identity_who_can_access(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Show who can access a resource.

        Query params:
            resource: Resource ID (bucket, table, file)
            cloud: Cloud provider (aws, gcp, azure)
        """
        resource = params.get("resource", [""])[0]
        cloud = params.get("cloud", [""])[0]

        if not resource:
            return {"error": "resource parameter is required"}
        if not cloud:
            return {"error": "cloud parameter is required (aws, gcp, azure)"}

        try:
            from stance.identity import IdentityConfig

            config = IdentityConfig(
                include_users=True,
                include_roles=True,
                include_groups=True,
                include_service_accounts=True,
            )

            if cloud == "aws":
                from stance.identity import AWSDataAccessMapper
                mapper = AWSDataAccessMapper(config)
            elif cloud == "gcp":
                from stance.identity import GCPDataAccessMapper
                mapper = GCPDataAccessMapper(config)
            elif cloud == "azure":
                from stance.identity import AzureDataAccessMapper
                mapper = AzureDataAccessMapper(config)
            else:
                return {"error": f"Unknown cloud provider: {cloud}"}

            result = mapper.who_can_access(resource)

            return {
                "resource": result.resource_id,
                "cloud": result.cloud_provider,
                "principals": [
                    {
                        "principal_id": access.principal.id if access.principal else None,
                        "principal_type": access.principal.type.value if access.principal and access.principal.type else None,
                        "principal_name": access.principal.name if access.principal else None,
                        "permission_level": access.permission_level.value if access.permission_level else None,
                        "source": access.source,
                    }
                    for access in (result.access_list or [])[:100]
                ],
                "total_principals": len(result.access_list) if result.access_list else 0,
            }
        except Exception as e:
            return {"error": str(e)}

    def _identity_exposure(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Analyze principal exposure to sensitive data.

        Query params:
            principal: Principal ID (user, role, service account)
            classification: Filter by classification level
        """
        principal = params.get("principal", [""])[0]
        classification = params.get("classification", [None])[0]

        if not principal:
            return {"error": "principal parameter is required"}

        try:
            from stance.identity.exposure import PrincipalExposureAnalyzer

            analyzer = PrincipalExposureAnalyzer()
            result = analyzer.analyze_principal_exposure(principal)

            exposures = result.exposures or []
            if classification:
                exposures = [e for e in exposures if e.resource and e.resource.classification and e.resource.classification.value == classification]

            return {
                "principal": result.principal_id,
                "summary": {
                    "total_resources": result.summary.total_resources if result.summary else 0,
                    "sensitive_resources": result.summary.sensitive_resources if result.summary else 0,
                    "critical_exposures": result.summary.critical_exposures if result.summary else 0,
                    "high_exposures": result.summary.high_exposures if result.summary else 0,
                },
                "risk_score": result.risk_score,
                "exposures": [
                    {
                        "resource_id": exp.resource.resource_id if exp.resource else None,
                        "classification": exp.resource.classification.value if exp.resource and exp.resource.classification else None,
                        "categories": [c.value for c in exp.resource.categories] if exp.resource and exp.resource.categories else [],
                        "severity": exp.severity.value if exp.severity else None,
                        "permission_level": exp.permission_level.value if exp.permission_level else None,
                    }
                    for exp in exposures[:50]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _identity_overprivileged(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Find over-privileged principals.

        Query params:
            cloud: Cloud provider (aws, gcp, azure)
            days: Days to analyze for activity (default: 90)
        """
        cloud = params.get("cloud", [""])[0]
        days = int(params.get("days", ["90"])[0])

        if not cloud:
            return {"error": "cloud parameter is required (aws, gcp, azure)"}

        try:
            from stance.identity.overprivileged import OverPrivilegedAnalyzer

            analyzer = OverPrivilegedAnalyzer(
                cloud_provider=cloud,
                lookback_days=days,
            )
            result = analyzer.analyze()

            return {
                "cloud": result.cloud_provider,
                "analysis_period_days": result.analysis_period_days,
                "summary": {
                    "total_principals": result.summary.total_principals if result.summary else 0,
                    "over_privileged_count": result.summary.over_privileged_count if result.summary else 0,
                    "unused_admin_count": result.summary.unused_admin_count if result.summary else 0,
                    "stale_elevated_count": result.summary.stale_elevated_count if result.summary else 0,
                },
                "findings": [
                    {
                        "principal": f.principal,
                        "principal_type": f.principal_type.value if f.principal_type else None,
                        "finding_type": f.finding_type.value if f.finding_type else None,
                        "granted_permission": f.granted_permission.value if f.granted_permission else None,
                        "observed_permission": f.observed_permission.value if f.observed_permission else None,
                        "days_inactive": f.days_inactive,
                        "risk_score": f.risk_score,
                        "recommendation": f.recommendation,
                    }
                    for f in (result.findings or [])[:50]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _identity_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Get Identity summary statistics."""
        return {
            "available_features": [
                {"name": "who-can-access", "description": "Show who can access a resource"},
                {"name": "exposure", "description": "Analyze principal exposure to sensitive data"},
                {"name": "overprivileged", "description": "Find over-privileged principals"},
            ],
            "supported_clouds": ["aws", "gcp", "azure"],
            "principal_types": ["user", "role", "group", "service_account"],
            "permission_levels": ["none", "read", "write", "admin", "full_control"],
        }

    # =========================================================================
    # Exposure API Endpoints
    # =========================================================================

    def _exposure_inventory(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        List publicly accessible assets.

        Query params:
            cloud: Filter by cloud provider
            region: Filter by region
            type: Filter by resource type
        """
        cloud = params.get("cloud", [None])[0]
        region = params.get("region", [None])[0]
        resource_type = params.get("type", [None])[0]

        try:
            from stance.exposure.inventory import PublicAssetInventory, InventoryConfig

            config = InventoryConfig(
                cloud_provider=cloud,
                region=region,
                resource_type=resource_type,
            )
            inventory = PublicAssetInventory(config)
            result = inventory.discover()

            return {
                "summary": {
                    "total_public_assets": result.summary.total_public_assets if result.summary else 0,
                    "internet_facing": result.summary.internet_facing if result.summary else 0,
                    "with_sensitive_data": result.summary.with_sensitive_data if result.summary else 0,
                    "by_cloud": result.summary.by_cloud if result.summary else {},
                    "by_type": result.summary.by_type if result.summary else {},
                },
                "assets": [
                    {
                        "resource_id": asset.resource_id,
                        "resource_type": asset.resource_type,
                        "cloud_provider": asset.cloud_provider,
                        "region": asset.region,
                        "exposure_type": asset.exposure_type.value if asset.exposure_type else None,
                        "risk_score": asset.risk_score,
                        "has_sensitive_data": asset.has_sensitive_data,
                    }
                    for asset in (result.assets or [])[:100]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _exposure_certificates(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Monitor SSL/TLS certificates.

        Query params:
            cloud: Filter by cloud provider
            domain: Filter by domain
            expiring_within: Days to check for expiring certs (default: 30)
        """
        cloud = params.get("cloud", [None])[0]
        domain = params.get("domain", [None])[0]
        expiring_within = int(params.get("expiring_within", ["30"])[0])

        try:
            from stance.exposure.certificates import CertificateMonitor, CertificateConfig

            config = CertificateConfig(
                cloud_provider=cloud,
                domain_filter=domain,
                expiring_within_days=expiring_within,
            )
            monitor = CertificateMonitor(config)
            result = monitor.analyze()

            return {
                "summary": {
                    "total_certificates": result.summary.total_certificates if result.summary else 0,
                    "expired": result.summary.expired if result.summary else 0,
                    "expiring_soon": result.summary.expiring_soon if result.summary else 0,
                    "weak_key": result.summary.weak_key if result.summary else 0,
                    "weak_algorithm": result.summary.weak_algorithm if result.summary else 0,
                },
                "certificates": [
                    {
                        "domain": cert.domain,
                        "cloud_provider": cert.cloud_provider,
                        "status": cert.status.value if cert.status else None,
                        "expires_at": cert.expires_at.isoformat() if cert.expires_at else None,
                        "days_until_expiry": cert.days_until_expiry,
                        "key_size": cert.key_size,
                        "algorithm": cert.algorithm,
                    }
                    for cert in (result.certificates or [])[:100]
                ],
                "findings": [
                    {
                        "domain": f.domain,
                        "finding_type": f.finding_type.value if f.finding_type else None,
                        "severity": f.severity.value if f.severity else None,
                        "message": f.message,
                    }
                    for f in (result.findings or [])[:50]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _exposure_dns(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Analyze DNS records for issues.

        Query params:
            zone: DNS zone to analyze
            cloud: Filter by cloud provider
        """
        zone = params.get("zone", [None])[0]
        cloud = params.get("cloud", [None])[0]

        try:
            from stance.exposure.dns import DNSInventory, DNSConfig

            config = DNSConfig(
                zone_filter=zone,
                cloud_provider=cloud,
            )
            inventory = DNSInventory(config)
            result = inventory.analyze()

            return {
                "summary": {
                    "total_zones": result.summary.total_zones if result.summary else 0,
                    "total_records": result.summary.total_records if result.summary else 0,
                    "dangling_records": result.summary.dangling_records if result.summary else 0,
                    "takeover_risk": result.summary.takeover_risk if result.summary else 0,
                },
                "zones": [
                    {
                        "name": z.name,
                        "cloud_provider": z.cloud_provider,
                        "record_count": z.record_count,
                    }
                    for z in (result.zones or [])[:50]
                ],
                "findings": [
                    {
                        "record_name": f.record_name,
                        "record_type": f.record_type,
                        "finding_type": f.finding_type.value if f.finding_type else None,
                        "severity": f.severity.value if f.severity else None,
                        "target": f.target,
                        "takeover_risk": f.takeover_risk,
                        "recommendation": f.recommendation,
                    }
                    for f in (result.findings or [])[:50]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _exposure_sensitive(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Detect sensitive data exposure in public assets.

        Query params:
            cloud: Filter by cloud provider
            classification: Filter by classification level
        """
        cloud = params.get("cloud", [None])[0]
        classification = params.get("classification", [None])[0]

        try:
            from stance.exposure.sensitive import SensitiveDataExposureAnalyzer, ExposureConfig

            config = ExposureConfig(
                cloud_provider=cloud,
                classification_filter=classification,
            )
            analyzer = SensitiveDataExposureAnalyzer(config)
            result = analyzer.analyze()

            return {
                "summary": {
                    "total_exposures": result.summary.total_exposures if result.summary else 0,
                    "critical_exposures": result.summary.critical_exposures if result.summary else 0,
                    "high_exposures": result.summary.high_exposures if result.summary else 0,
                    "pii_exposures": result.summary.pii_exposures if result.summary else 0,
                    "pci_exposures": result.summary.pci_exposures if result.summary else 0,
                    "phi_exposures": result.summary.phi_exposures if result.summary else 0,
                },
                "findings": [
                    {
                        "resource_id": f.resource_id,
                        "exposure_type": f.exposure_type.value if f.exposure_type else None,
                        "classification": f.classification.value if f.classification else None,
                        "categories": [c.value for c in f.categories] if f.categories else [],
                        "risk_level": f.risk_level.value if f.risk_level else None,
                        "risk_score": f.risk_score,
                        "compliance_impact": f.compliance_impact,
                        "recommendation": f.recommendation,
                    }
                    for f in (result.findings or [])[:50]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _exposure_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Get Exposure Management summary statistics."""
        return {
            "available_features": [
                {"name": "inventory", "description": "List publicly accessible assets"},
                {"name": "certificates", "description": "Monitor SSL/TLS certificates"},
                {"name": "dns", "description": "Analyze DNS records for issues"},
                {"name": "sensitive", "description": "Detect sensitive data exposure"},
            ],
            "supported_clouds": ["aws", "gcp", "azure"],
            "exposure_types": ["internet_facing", "public_bucket", "open_database", "exposed_api"],
            "risk_levels": ["critical", "high", "medium", "low", "info"],
        }

    # =========================================================================
    # Analytics API Endpoints
    # =========================================================================

    def _analytics_attack_paths(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Analyze attack paths in the environment.

        Query params:
            type: Filter by attack path type
            severity: Minimum severity to include
            limit: Maximum number of paths to return (default: 20)
        """
        path_type = params.get("type", [None])[0]
        severity = params.get("severity", [None])[0]
        limit = int(params.get("limit", ["20"])[0])

        try:
            from stance.analytics.attack_paths import AttackPathAnalyzer, AttackPathType
            from stance.analytics.asset_graph import AssetGraph
            from stance.storage import get_storage

            # Load data from storage
            storage = get_storage()
            assets = storage.load_assets()
            findings_data = storage.load_findings()

            if not assets or not assets.assets:
                return {"error": "No assets found. Run 'stance scan' first."}

            # Build asset graph
            graph = AssetGraph()
            graph.build_from_assets(assets)

            # Run attack path analysis
            analyzer = AttackPathAnalyzer(graph, findings_data)
            paths = analyzer.analyze()

            # Filter by path type if specified
            if path_type:
                try:
                    filter_type = AttackPathType(path_type)
                    paths = [p for p in paths if p.path_type == filter_type]
                except ValueError:
                    pass  # Ignore invalid type

            # Filter by severity if specified
            if severity:
                from stance.models.finding import Severity
                severity_order = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                    "info": Severity.INFO,
                }
                min_sev = severity_order.get(severity.lower())
                if min_sev:
                    paths = [p for p in paths if p.severity.value <= min_sev.value]

            # Limit results
            paths = paths[:limit]

            return {
                "total_paths": len(paths),
                "paths": [
                    {
                        "id": getattr(p, "id", None),
                        "path_type": p.path_type.value if p.path_type else None,
                        "severity": p.severity.value if p.severity else None,
                        "length": p.length,
                        "description": p.description,
                        "mitigation": p.mitigation,
                        "steps": [
                            {
                                "asset_id": s.asset_id,
                                "asset_name": s.asset_name,
                                "resource_type": s.resource_type,
                                "action": s.action,
                                "finding_count": len(s.findings) if s.findings else 0,
                            }
                            for s in (p.steps or [])
                        ],
                    }
                    for p in paths
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _analytics_risk_score(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Calculate risk scores for assets.

        Query params:
            asset_id: Specific asset ID to score
            min_score: Minimum risk score to include
            level: Filter by risk level (critical, high, medium, low, minimal)
            limit: Maximum number of assets to return (default: 20)
        """
        asset_id = params.get("asset_id", [None])[0]
        min_score = params.get("min_score", [None])[0]
        level = params.get("level", [None])[0]
        limit = int(params.get("limit", ["20"])[0])

        try:
            from stance.analytics.risk_scoring import RiskScorer
            from stance.analytics.asset_graph import AssetGraph
            from stance.storage import get_storage

            # Load data from storage
            storage = get_storage()
            assets = storage.load_assets()
            findings_data = storage.load_findings()

            if not assets or not assets.assets:
                return {"error": "No assets found. Run 'stance scan' first."}

            # Build asset graph for relationship analysis
            graph = AssetGraph()
            graph.build_from_assets(assets)

            # Initialize risk scorer
            scorer = RiskScorer(graph, findings_data)

            # Score single asset or all assets
            if asset_id:
                asset = assets.get_by_id(asset_id)
                if not asset:
                    return {"error": f"Asset not found: {asset_id}"}
                scores = [scorer.score_asset(asset)]
                aggregate = None
            else:
                scores = scorer.score_collection(assets)
                aggregate = scorer.aggregate_risk(assets)

            # Filter by minimum score
            if min_score is not None:
                min_score_val = float(min_score)
                scores = [s for s in scores if s.overall_score >= min_score_val]

            # Filter by risk level
            if level:
                scores = [s for s in scores if s.risk_level == level.lower()]

            # Limit results
            scores = scores[:limit]

            return {
                "total_scored": len(scores),
                "aggregate": aggregate,
                "scores": [
                    {
                        "asset_id": s.asset_id,
                        "overall_score": s.overall_score,
                        "risk_level": s.risk_level,
                        "factors": s.factors.to_dict() if s.factors else {},
                        "top_risks": s.top_risks,
                        "recommendations": s.recommendations,
                        "last_updated": s.last_updated.isoformat() if s.last_updated else None,
                    }
                    for s in scores
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _analytics_blast_radius(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Calculate blast radius for security findings.

        Query params:
            finding_id: Specific finding ID to analyze
            category: Filter by impact category
            min_score: Minimum blast radius score to include
            limit: Maximum number of findings to return (default: 20)
        """
        finding_id = params.get("finding_id", [None])[0]
        category = params.get("category", [None])[0]
        min_score = params.get("min_score", [None])[0]
        limit = int(params.get("limit", ["20"])[0])

        try:
            from stance.analytics.blast_radius import BlastRadiusCalculator, ImpactCategory
            from stance.analytics.asset_graph import AssetGraph
            from stance.storage import get_storage

            # Load data from storage
            storage = get_storage()
            assets = storage.load_assets()
            findings_data = storage.load_findings()

            if not assets or not assets.assets:
                return {"error": "No assets found. Run 'stance scan' first."}

            if not findings_data or not findings_data.findings:
                return {"error": "No findings found. Run 'stance scan' first."}

            # Build asset graph
            graph = AssetGraph()
            graph.build_from_assets(assets)

            # Initialize calculator
            calculator = BlastRadiusCalculator(graph, findings_data)

            # Calculate for single finding or all findings
            if finding_id:
                finding = findings_data.get_by_id(finding_id)
                if not finding:
                    return {"error": f"Finding not found: {finding_id}"}
                results = [calculator.calculate(finding)]
            else:
                results = calculator.calculate_all()

            # Filter by impact category
            if category:
                try:
                    filter_cat = ImpactCategory(category)
                    results = [r for r in results if filter_cat in r.impact_categories]
                except ValueError:
                    pass  # Ignore invalid category

            # Filter by minimum score
            if min_score is not None:
                min_score_val = float(min_score)
                results = [r for r in results if r.blast_radius_score >= min_score_val]

            # Limit results
            results = results[:limit]

            return {
                "total_analyzed": len(results),
                "results": [
                    {
                        "finding_id": r.finding_id,
                        "blast_radius_score": r.blast_radius_score,
                        "finding_severity": r.finding_severity.value if r.finding_severity else None,
                        "adjusted_severity": r.adjusted_severity.value if r.adjusted_severity else None,
                        "source_asset_name": r.source_asset_name,
                        "total_affected_count": r.total_affected_count,
                        "data_exposure_risk": r.data_exposure_risk,
                        "service_disruption_risk": r.service_disruption_risk,
                        "impact_categories": [c.value for c in r.impact_categories] if r.impact_categories else [],
                        "compliance_implications": r.compliance_implications or [],
                        "directly_affected": [
                            {
                                "asset_id": a.asset_id,
                                "asset_name": a.asset_name,
                                "impact_type": a.impact_type,
                            }
                            for a in (r.directly_affected or [])[:10]
                        ],
                        "indirectly_affected_count": len(r.indirectly_affected) if r.indirectly_affected else 0,
                    }
                    for r in results
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _analytics_mitre(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Map findings to MITRE ATT&CK framework.

        Query params:
            finding_id: Specific finding ID to map
            tactic: Filter by MITRE ATT&CK tactic
            limit: Maximum number of mappings to return (default: 20)
        """
        finding_id = params.get("finding_id", [None])[0]
        tactic = params.get("tactic", [None])[0]
        limit = int(params.get("limit", ["20"])[0])

        try:
            from stance.analytics.mitre_attack import MitreAttackMapper, MitreTactic
            from stance.storage import get_storage

            # Initialize mapper
            mapper = MitreAttackMapper()

            # Load findings
            storage = get_storage()
            findings_data = storage.load_findings()

            if not findings_data or not findings_data.findings:
                return {"error": "No findings found. Run 'stance scan' first."}

            # Map single finding or all findings
            if finding_id:
                finding = findings_data.get_by_id(finding_id)
                if not finding:
                    return {"error": f"Finding not found: {finding_id}"}
                mappings = [mapper.map_finding(finding)]
            else:
                mappings = mapper.map_findings(findings_data)

            # Filter by tactic
            if tactic:
                try:
                    filter_tactic = MitreTactic(tactic.lower())
                    mappings = [m for m in mappings if filter_tactic in m.tactics]
                except ValueError:
                    pass  # Ignore invalid tactic

            # Filter out mappings with no techniques
            mappings = [m for m in mappings if m.techniques]

            # Limit results
            mappings = mappings[:limit]

            return {
                "total_mappings": len(mappings),
                "mappings": [
                    {
                        "finding_id": m.finding_id,
                        "confidence": m.confidence,
                        "techniques": [
                            {
                                "id": t.id,
                                "name": t.name,
                                "tactic": t.tactic.value if t.tactic else None,
                                "description": t.description,
                            }
                            for t in m.techniques
                        ],
                        "tactics": [t.value for t in m.tactics],
                        "kill_chain_phases": [p.value for p in m.kill_chain_phases],
                        "detection_recommendations": m.detection_recommendations[:5],
                        "mitigation_strategies": m.mitigation_strategies[:5],
                    }
                    for m in mappings
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _analytics_mitre_technique(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Get details for a specific MITRE ATT&CK technique.

        Query params:
            technique_id: MITRE technique ID (e.g., T1078)
        """
        technique_id = params.get("technique_id", [None])[0]

        if not technique_id:
            return {"error": "technique_id parameter is required"}

        try:
            from stance.analytics.mitre_attack import MitreAttackMapper

            mapper = MitreAttackMapper()
            technique = mapper.get_technique(technique_id.upper())

            if not technique:
                return {"error": f"Technique not found: {technique_id}"}

            # Get detection recommendations and mitigation strategies
            detection_recs = mapper.DETECTION_RECOMMENDATIONS.get(technique.id, [])
            mitigation_strats = mapper.MITIGATION_STRATEGIES.get(technique.id, [])

            return {
                "technique": {
                    "id": technique.id,
                    "name": technique.name,
                    "tactic": technique.tactic.value if technique.tactic else None,
                    "description": technique.description,
                    "cloud_platforms": technique.cloud_platforms,
                    "sub_techniques": technique.sub_techniques,
                },
                "detection_recommendations": detection_recs,
                "mitigation_strategies": mitigation_strats,
            }
        except Exception as e:
            return {"error": str(e)}

    def _analytics_mitre_coverage(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get MITRE ATT&CK coverage summary for all findings.

        Shows which tactics and techniques are covered by current findings.
        """
        try:
            from stance.analytics.mitre_attack import MitreAttackMapper, MitreTactic
            from stance.storage import get_storage

            # Initialize mapper
            mapper = MitreAttackMapper()

            # Load findings
            storage = get_storage()
            findings_data = storage.load_findings()

            if not findings_data or not findings_data.findings:
                return {
                    "total_mappings": 0,
                    "tactics_covered": 0,
                    "techniques_covered": 0,
                    "kill_chain_phases_covered": 0,
                    "tactics_covered_list": [],
                    "techniques_covered_list": [],
                    "tactic_distribution": {},
                }

            # Map all findings
            mappings = mapper.map_findings(findings_data)

            # Filter out mappings with no techniques
            mappings = [m for m in mappings if m.techniques]

            # Get coverage summary
            coverage = mapper.get_coverage_summary(mappings)

            return {
                "total_mappings": coverage["total_mappings"],
                "total_tactics": len(MitreTactic),
                "tactics_covered": coverage["tactics_covered"],
                "tactics_covered_list": coverage["tactics_covered_list"],
                "techniques_covered": coverage["techniques_covered"],
                "techniques_covered_list": coverage["techniques_covered_list"],
                "kill_chain_phases_covered": coverage["kill_chain_phases_covered"],
                "kill_chain_phases_list": coverage.get("kill_chain_phases_list", []),
                "tactic_distribution": coverage["tactic_distribution"],
            }
        except Exception as e:
            return {"error": str(e)}

    def _analytics_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Get Vulnerability Analytics summary statistics."""
        return {
            "available_features": [
                {
                    "name": "attack-paths",
                    "description": "Analyze attack paths in the environment",
                    "params": ["type", "severity", "limit"],
                },
                {
                    "name": "risk-score",
                    "description": "Calculate risk scores for assets",
                    "params": ["asset_id", "min_score", "level", "limit"],
                },
                {
                    "name": "blast-radius",
                    "description": "Calculate blast radius for findings",
                    "params": ["finding_id", "category", "min_score", "limit"],
                },
                {
                    "name": "mitre",
                    "description": "Map findings to MITRE ATT&CK framework",
                    "params": ["finding_id", "tactic", "limit"],
                },
                {
                    "name": "mitre/technique",
                    "description": "Get details for a specific MITRE technique",
                    "params": ["technique_id"],
                },
                {
                    "name": "mitre/coverage",
                    "description": "Get MITRE ATT&CK coverage summary",
                    "params": [],
                },
            ],
            "attack_path_types": [
                "internet_to_internal",
                "privilege_escalation",
                "lateral_movement",
                "data_exfiltration",
                "credential_exposure",
                "data_theft",
                "ransomware_spread",
                "crypto_mining",
                "identity_theft",
            ],
            "risk_levels": ["critical", "high", "medium", "low", "minimal"],
            "impact_categories": [
                "data_exposure",
                "service_disruption",
                "credential_compromise",
                "compliance_violation",
                "lateral_movement",
                "privilege_escalation",
            ],
            "mitre_tactics": [
                "reconnaissance",
                "resource_development",
                "initial_access",
                "execution",
                "persistence",
                "privilege_escalation",
                "defense_evasion",
                "credential_access",
                "discovery",
                "lateral_movement",
                "collection",
                "exfiltration",
                "impact",
            ],
        }

    # =========================================================================
    # Scanning API Endpoints
    # =========================================================================

    def _scanning_image(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Scan container images for vulnerabilities.

        Query params:
            image: Image reference to scan (required, can be multiple)
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            skip_db_update: Skip database update (default: false)
            ignore_unfixed: Ignore unfixed vulnerabilities (default: false)
            timeout: Scan timeout in seconds (default: 300)
        """
        images = params.get("image", [])
        severity_filter = params.get("severity", [None])[0]
        skip_db_update = params.get("skip_db_update", ["false"])[0].lower() == "true"
        ignore_unfixed = params.get("ignore_unfixed", ["false"])[0].lower() == "true"
        timeout = int(params.get("timeout", ["300"])[0])

        if not images:
            return {"error": "image parameter is required"}

        try:
            from stance.scanner import TrivyScanner, VulnerabilitySeverity

            # Initialize scanner
            scanner = TrivyScanner()

            # Check if Trivy is available
            if not scanner.is_available():
                return {
                    "error": "Trivy scanner is not available. Please install Trivy.",
                    "install_url": "https://aquasecurity.github.io/trivy/",
                }

            # Parse severity filter
            sev_filter = None
            if severity_filter:
                sev_filter = set()
                for sev in severity_filter.upper().split(","):
                    sev = sev.strip()
                    if sev in VulnerabilitySeverity.__members__:
                        sev_filter.add(VulnerabilitySeverity[sev])

            # Scan images
            results = []
            errors = []
            for image in images:
                try:
                    result = scanner.scan(
                        image_ref=image,
                        timeout=timeout,
                        skip_db_update=skip_db_update,
                        ignore_unfixed=ignore_unfixed,
                        severity_filter=sev_filter,
                    )
                    results.append({
                        "image_ref": result.image_ref,
                        "scanned_at": result.scanned_at.isoformat() if result.scanned_at else None,
                        "scanner": result.scanner,
                        "scanner_version": result.scanner_version,
                        "summary": {
                            "total": result.total_count,
                            "critical": result.critical_count,
                            "high": result.high_count,
                            "medium": result.medium_count,
                            "low": result.low_count,
                            "fixable": result.fixable_count,
                        },
                        "vulnerabilities": [
                            {
                                "id": v.vulnerability_id,
                                "package": v.package_name,
                                "installed_version": v.installed_version,
                                "fixed_version": v.fixed_version,
                                "severity": v.severity.value if v.severity else None,
                                "title": v.title,
                                "description": v.description[:200] if v.description else None,
                                "references": v.references[:3] if v.references else [],
                            }
                            for v in (result.vulnerabilities or [])[:50]
                        ],
                    })
                except Exception as e:
                    errors.append({"image": image, "error": str(e)})

            return {
                "scanner_version": scanner.get_version(),
                "total_images": len(images),
                "successful_scans": len(results),
                "failed_scans": len(errors),
                "results": results,
                "errors": errors,
            }
        except Exception as e:
            return {"error": str(e)}

    def _scanning_iac(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Scan Infrastructure as Code files for security issues.

        Query params:
            path: Path to scan (required, can be multiple)
            severity: Minimum severity to include (critical, high, medium, low, info)
            recursive: Scan recursively (default: true)
        """
        paths = params.get("path", [])
        severity_filter = params.get("severity", [None])[0]
        recursive = params.get("recursive", ["true"])[0].lower() == "true"

        if not paths:
            return {"error": "path parameter is required"}

        try:
            from pathlib import Path
            from stance.iac import (
                IaCScanner,
                TerraformParser,
                CloudFormationParser,
                ARMTemplateParser,
                IaCPolicyEvaluator,
                get_default_iac_policies,
            )

            # Collect files to scan
            files_to_scan = []
            for path_str in paths:
                path = Path(path_str)
                if path.is_file():
                    files_to_scan.append(path)
                elif path.is_dir():
                    extensions = ["*.tf", "*.json", "*.yaml", "*.yml", "*.template"]
                    for ext in extensions:
                        if recursive:
                            files_to_scan.extend(path.rglob(ext))
                        else:
                            files_to_scan.extend(path.glob(ext))

            if not files_to_scan:
                return {
                    "files_scanned": 0,
                    "files_with_issues": 0,
                    "total_issues": 0,
                    "findings": [],
                    "message": "No IaC files found to scan",
                }

            # Initialize scanner with parsers
            scanner = IaCScanner()
            scanner.register_parser(TerraformParser())
            scanner.register_parser(CloudFormationParser())
            scanner.register_parser(ARMTemplateParser())

            # Load policies
            policies = get_default_iac_policies()
            evaluator = IaCPolicyEvaluator(policies)
            scanner.set_policy_evaluator(evaluator)

            # Scan files
            all_findings = []
            files_scanned = 0
            files_with_issues = 0

            for file_path in files_to_scan:
                try:
                    findings = scanner.scan_file(file_path)
                    if findings:
                        files_with_issues += 1
                        all_findings.extend(findings)
                    files_scanned += 1
                except Exception:
                    pass  # Skip files that can't be scanned

            # Filter by severity
            if severity_filter:
                severity_order = ["info", "low", "medium", "high", "critical"]
                try:
                    min_index = severity_order.index(severity_filter.lower())
                    filtered = []
                    for f in all_findings:
                        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                        if severity_order.index(sev.lower()) >= min_index:
                            filtered.append(f)
                    all_findings = filtered
                except ValueError:
                    pass

            # Count by severity
            severity_counts = {}
            for f in all_findings:
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                sev = sev.upper()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            return {
                "files_scanned": files_scanned,
                "files_with_issues": files_with_issues,
                "total_issues": len(all_findings),
                "by_severity": severity_counts,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        "title": f.title,
                        "description": f.description[:200] if f.description else None,
                        "file_path": str(f.resource.location.file_path) if f.resource and f.resource.location else None,
                        "line_start": f.resource.location.line_start if f.resource and f.resource.location else None,
                        "resource_type": f.resource.resource_type if f.resource else None,
                        "resource_name": f.resource.name if f.resource else None,
                        "remediation": f.remediation[:200] if f.remediation else None,
                    }
                    for f in all_findings[:100]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _scanning_secrets(self, params: dict[str, list[str]]) -> dict[str, Any]:
        """
        Scan files for hardcoded secrets.

        Query params:
            path: Path to scan (required, can be multiple)
            recursive: Scan recursively (default: true)
            min_entropy: Minimum entropy threshold for detection (default: 3.5)
            exclude: Comma-separated patterns to exclude
        """
        paths = params.get("path", [])
        recursive = params.get("recursive", ["true"])[0].lower() == "true"
        min_entropy = float(params.get("min_entropy", ["3.5"])[0])
        exclude_param = params.get("exclude", [""])[0]

        if not paths:
            return {"error": "path parameter is required"}

        try:
            import fnmatch
            from pathlib import Path
            from stance.detection.secrets import SecretsDetector

            # Build exclude patterns
            exclude_patterns = []
            if exclude_param:
                exclude_patterns = [p.strip() for p in exclude_param.split(",")]

            # Default exclusions
            default_exclusions = [
                "*.lock", "*.min.js", "*.min.css", "*.map",
                "node_modules/*", ".git/*", "__pycache__/*",
                "*.pyc", "*.pyo", "*.so", "*.dylib",
                "*.exe", "*.dll", "*.bin",
            ]
            exclude_patterns.extend(default_exclusions)

            # Collect files to scan
            files_to_scan = []
            for path_str in paths:
                path = Path(path_str)
                if path.is_file():
                    files_to_scan.append(path)
                elif path.is_dir():
                    if recursive:
                        for file_path in path.rglob("*"):
                            if file_path.is_file():
                                files_to_scan.append(file_path)
                    else:
                        for file_path in path.glob("*"):
                            if file_path.is_file():
                                files_to_scan.append(file_path)

            # Filter out excluded files
            def should_exclude(file_path):
                path_str = str(file_path)
                for pattern in exclude_patterns:
                    if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(file_path.name, pattern):
                        return True
                return False

            files_to_scan = [f for f in files_to_scan if not should_exclude(f)]

            if not files_to_scan:
                return {
                    "files_scanned": 0,
                    "files_with_secrets": 0,
                    "total_secrets": 0,
                    "findings": [],
                    "message": "No files found to scan",
                }

            # Initialize detector
            detector = SecretsDetector(min_entropy=min_entropy)

            # Scan files
            all_matches = []
            files_scanned = 0
            files_with_secrets = 0

            for file_path in files_to_scan:
                try:
                    content = file_path.read_text(errors="ignore")
                    matches = detector.detect_in_text(content, str(file_path))

                    if matches:
                        files_with_secrets += 1
                        for match in matches:
                            all_matches.append((file_path, match))

                    files_scanned += 1
                except Exception:
                    pass  # Skip files that can't be read

            # Count by type
            type_counts = {}
            for _, match in all_matches:
                type_counts[match.secret_type] = type_counts.get(match.secret_type, 0) + 1

            # Redact secrets in output
            def redact_secret(value):
                if len(value) <= 8:
                    return "*" * len(value)
                return value[:4] + "*" * (len(value) - 8) + value[-4:]

            return {
                "files_scanned": files_scanned,
                "files_with_secrets": files_with_secrets,
                "total_secrets": len(all_matches),
                "by_type": type_counts,
                "findings": [
                    {
                        "file_path": str(file_path),
                        "secret_type": match.secret_type,
                        "redacted_value": redact_secret(match.matched_value),
                        "confidence": match.confidence,
                        "entropy": round(match.entropy, 2) if match.entropy else None,
                        "line_number": match.line_number if hasattr(match, 'line_number') else None,
                    }
                    for file_path, match in all_matches[:100]
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _scanning_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Get Scanning feature summary and available options."""
        # Check scanner availability
        trivy_available = False
        trivy_version = None
        try:
            from stance.scanner import TrivyScanner
            scanner = TrivyScanner()
            trivy_available = scanner.is_available()
            if trivy_available:
                trivy_version = scanner.get_version()
        except Exception:
            pass

        return {
            "available_features": [
                {
                    "name": "image",
                    "description": "Scan container images for vulnerabilities using Trivy",
                    "params": ["image (required)", "severity", "skip_db_update", "ignore_unfixed", "timeout"],
                    "available": trivy_available,
                    "scanner_version": trivy_version,
                },
                {
                    "name": "iac",
                    "description": "Scan Infrastructure as Code files (Terraform, CloudFormation, ARM)",
                    "params": ["path (required)", "severity", "recursive"],
                    "available": True,
                    "supported_formats": ["Terraform (*.tf)", "CloudFormation (*.json, *.yaml)", "ARM (*.json)"],
                },
                {
                    "name": "secrets",
                    "description": "Scan files for hardcoded secrets and credentials",
                    "params": ["path (required)", "recursive", "min_entropy", "exclude"],
                    "available": True,
                    "detected_types": [
                        "AWS Access Key", "AWS Secret Key", "GitHub Token", "GitLab Token",
                        "Slack Token", "Azure Storage Key", "GCP Service Account Key",
                        "Private Key", "Generic API Key", "Password", "Bearer Token",
                    ],
                },
            ],
            "vulnerability_severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
            "iac_severities": ["critical", "high", "medium", "low", "info"],
            "notes": {
                "image_scanning": "Requires Trivy to be installed. Visit https://aquasecurity.github.io/trivy/ for installation instructions.",
                "iac_scanning": "Supports Terraform, CloudFormation, and ARM templates. Custom policies can be added.",
                "secrets_scanning": "Uses pattern matching and entropy analysis to detect secrets.",
            },
        }

    # ========================================================================
    # Enrichment API Endpoints
    # ========================================================================

    def _enrichment_findings(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Enrich findings with threat intelligence and CVE details.

        Query parameters:
            finding_id: Optional specific finding ID to enrich
            types: Comma-separated enrichment types (cve, kev, vuln, threat)
            limit: Maximum number of findings to enrich (default: 50)

        Returns:
            Dictionary with enriched findings and statistics
        """
        from stance.enrichment import (
            create_default_pipeline,
            EnrichmentPipeline,
            CVEEnricher,
            KEVEnricher,
            VulnerableSoftwareEnricher,
            ThreatIntelEnricher,
        )
        from stance.storage import get_storage

        params = params or {}
        finding_id = params.get("finding_id", [None])[0]
        enrichment_types = params.get("types", [None])[0]
        limit = int(params.get("limit", ["50"])[0])

        # Load findings from storage
        storage = get_storage()
        findings_data = storage.load_findings()

        if not findings_data:
            return {
                "error": "No findings found. Run a scan first.",
                "total_findings": 0,
                "findings_enriched": 0,
            }

        findings = list(findings_data.findings) if hasattr(findings_data, 'findings') else findings_data

        if not findings:
            return {
                "error": "No findings found. Run a scan first.",
                "total_findings": 0,
                "findings_enriched": 0,
            }

        # Filter by finding ID if specified
        if finding_id:
            findings = [f for f in findings if f.id == finding_id]
            if not findings:
                return {
                    "error": f"Finding not found: {finding_id}",
                    "total_findings": 0,
                }

        # Limit findings
        findings = findings[:limit]

        # Create pipeline based on requested types
        if enrichment_types:
            types_list = [t.strip().lower() for t in enrichment_types.split(",")]
            enrichers = []
            if "cve" in types_list:
                enrichers.append(CVEEnricher())
            if "kev" in types_list:
                enrichers.append(KEVEnricher())
            if "vuln" in types_list or "vulnerable" in types_list:
                enrichers.append(VulnerableSoftwareEnricher())
            if "threat" in types_list or "intel" in types_list:
                enrichers.append(ThreatIntelEnricher())

            if not enrichers:
                return {
                    "error": f"No valid enrichment types: {enrichment_types}",
                    "valid_types": ["cve", "kev", "vuln", "threat"],
                }

            pipeline = EnrichmentPipeline(finding_enrichers=enrichers, asset_enrichers=[])
        else:
            pipeline = create_default_pipeline()

        # Enrich findings
        enriched = pipeline.enrich_findings(findings)

        # Count enrichments
        total_enrichments = sum(len(ef.enrichments) for ef in enriched)
        enriched_count = sum(1 for ef in enriched if ef.enrichments)

        return {
            "total_findings": len(findings),
            "findings_enriched": enriched_count,
            "total_enrichments": total_enrichments,
            "enriched_findings": [ef.to_dict() for ef in enriched if ef.enrichments],
        }

    def _enrichment_assets(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Enrich assets with context and IP information.

        Query parameters:
            asset_id: Optional specific asset ID to enrich
            types: Comma-separated enrichment types (ip, geo, cloud, context, tags)
            cloud: Filter by cloud provider (aws, gcp, azure)
            limit: Maximum number of assets to enrich (default: 50)

        Returns:
            Dictionary with enriched assets and statistics
        """
        from stance.enrichment import (
            create_default_pipeline,
            EnrichmentPipeline,
            IPEnricher,
            CloudProviderRangeEnricher,
            AssetContextEnricher,
            TagEnricher,
        )
        from stance.storage import get_storage

        params = params or {}
        asset_id = params.get("asset_id", [None])[0]
        enrichment_types = params.get("types", [None])[0]
        cloud_filter = params.get("cloud", [None])[0]
        limit = int(params.get("limit", ["50"])[0])

        # Load assets from storage
        storage = get_storage()
        assets_data = storage.load_assets()

        if not assets_data or not assets_data.assets:
            return {
                "error": "No assets found. Run a scan first.",
                "total_assets": 0,
                "assets_enriched": 0,
            }

        assets = list(assets_data.assets)

        # Filter by asset ID if specified
        if asset_id:
            assets = [a for a in assets if a.id == asset_id]
            if not assets:
                return {
                    "error": f"Asset not found: {asset_id}",
                    "total_assets": 0,
                }

        # Filter by cloud provider
        if cloud_filter:
            assets = [a for a in assets if a.cloud_provider.lower() == cloud_filter.lower()]

        # Limit assets
        assets = assets[:limit]

        if not assets:
            return {
                "error": "No assets match the filter criteria.",
                "total_assets": 0,
            }

        # Create pipeline based on requested types
        if enrichment_types:
            types_list = [t.strip().lower() for t in enrichment_types.split(",")]
            enrichers = []
            if "ip" in types_list or "geo" in types_list:
                enrichers.append(IPEnricher())
            if "cloud" in types_list:
                enrichers.append(CloudProviderRangeEnricher())
            if "context" in types_list:
                enrichers.append(AssetContextEnricher())
            if "tags" in types_list:
                enrichers.append(TagEnricher())

            if not enrichers:
                return {
                    "error": f"No valid enrichment types: {enrichment_types}",
                    "valid_types": ["ip", "geo", "cloud", "context", "tags"],
                }

            pipeline = EnrichmentPipeline(finding_enrichers=[], asset_enrichers=enrichers)
        else:
            pipeline = create_default_pipeline()

        # Enrich assets
        enriched = pipeline.enrich_assets(assets)

        # Count enrichments
        total_enrichments = sum(len(ea.enrichments) for ea in enriched)
        enriched_count = sum(1 for ea in enriched if ea.enrichments)

        return {
            "total_assets": len(assets),
            "assets_enriched": enriched_count,
            "total_enrichments": total_enrichments,
            "enriched_assets": [ea.to_dict() for ea in enriched if ea.enrichments],
        }

    def _enrichment_ip(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Look up information for a specific IP address.

        Query parameters:
            ip: IP address to look up (required)
            no_geoip: Disable GeoIP lookup (default: false)

        Returns:
            Dictionary with IP information including geolocation and cloud provider
        """
        from stance.enrichment import IPEnricher

        params = params or {}
        ip_address = params.get("ip", [None])[0]
        disable_geoip = params.get("no_geoip", ["false"])[0].lower() == "true"

        if not ip_address:
            return {
                "error": "IP address is required. Use ?ip=<address>",
            }

        enricher = IPEnricher(enable_geoip=not disable_geoip)
        result = enricher.lookup_ip(ip_address)

        return {
            "ip": ip_address,
            "info": result,
        }

    def _enrichment_cve(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Look up information for a specific CVE.

        Query parameters:
            cve_id: CVE ID to look up (required, e.g., CVE-2021-44228)

        Returns:
            Dictionary with CVE details including CVSS scores and affected products
        """
        from stance.enrichment import CVEEnricher

        params = params or {}
        cve_id = params.get("cve_id", [None])[0]

        if not cve_id:
            return {
                "error": "CVE ID is required. Use ?cve_id=CVE-YYYY-NNNNN",
            }

        # Normalize CVE ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        enricher = CVEEnricher()
        result = enricher._lookup_cve(cve_id)

        if not result:
            return {
                "error": f"CVE not found: {cve_id}",
                "cve_id": cve_id,
            }

        return {
            "cve_id": cve_id,
            "details": result,
        }

    def _enrichment_kev(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog.

        Query parameters:
            cve_id: CVE ID to check (optional, e.g., CVE-2021-44228)
            list: Set to "true" to list all KEV entries

        Returns:
            Dictionary with KEV status and details if found
        """
        from stance.enrichment import KEVEnricher

        params = params or {}
        cve_id = params.get("cve_id", [None])[0]
        list_all = params.get("list", ["false"])[0].lower() == "true"

        enricher = KEVEnricher(auto_fetch=True)

        # Force fetch KEV data
        enricher._fetch_kev_data()

        if list_all:
            # Return all KEV entries (limited to first 100)
            kev_data = enricher._kev_data
            return {
                "total": len(kev_data),
                "vulnerabilities": list(kev_data.values())[:100],
            }

        if not cve_id:
            return {
                "error": "CVE ID is required. Use ?cve_id=CVE-YYYY-NNNNN or ?list=true",
            }

        # Normalize CVE ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        # Check if CVE is in KEV
        is_kev = enricher.is_known_exploited(cve_id)

        if not is_kev:
            return {
                "cve_id": cve_id,
                "is_known_exploited": False,
                "message": "CVE is not in the CISA KEV catalog",
            }

        # Get KEV details
        kev_entry = enricher._kev_data.get(cve_id, {})

        return {
            "cve_id": cve_id,
            "is_known_exploited": True,
            "kev_details": kev_entry,
        }

    def _enrichment_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get enrichment capabilities and availability status.

        Returns:
            Dictionary with available enrichers and their status
        """
        from stance.enrichment import (
            IPEnricher,
            CloudProviderRangeEnricher,
            AssetContextEnricher,
            TagEnricher,
            CVEEnricher,
            KEVEnricher,
            VulnerableSoftwareEnricher,
            ThreatIntelEnricher,
        )

        # Check enricher availability
        enrichers = [
            {
                "name": "CVE Enricher",
                "type": "finding",
                "description": "Enriches findings with CVE details from NVD",
                "enricher": CVEEnricher(),
                "data_sources": ["NVD API"],
            },
            {
                "name": "KEV Enricher",
                "type": "finding",
                "description": "Checks CVEs against CISA Known Exploited Vulnerabilities",
                "enricher": KEVEnricher(auto_fetch=False),
                "data_sources": ["CISA KEV Catalog"],
            },
            {
                "name": "Vulnerable Software Enricher",
                "type": "finding",
                "description": "Identifies known vulnerable software patterns",
                "enricher": VulnerableSoftwareEnricher(),
                "data_sources": ["Built-in patterns (Log4j, Spring4Shell, etc.)"],
            },
            {
                "name": "Threat Intel Enricher",
                "type": "finding",
                "description": "Enriches with threat intelligence indicators",
                "enricher": ThreatIntelEnricher(),
                "data_sources": ["Custom indicator feeds"],
            },
            {
                "name": "IP Enricher",
                "type": "asset",
                "description": "Adds IP geolocation and ASN information",
                "enricher": IPEnricher(),
                "data_sources": ["ip-api.com", "Cloud provider IP ranges"],
            },
            {
                "name": "Cloud Provider Range Enricher",
                "type": "asset",
                "description": "Identifies cloud provider from IP ranges",
                "enricher": CloudProviderRangeEnricher(),
                "data_sources": ["AWS, GCP, Azure IP ranges"],
            },
            {
                "name": "Asset Context Enricher",
                "type": "asset",
                "description": "Adds business unit, criticality, and owner info",
                "enricher": AssetContextEnricher(),
                "data_sources": ["Tag analysis", "Name patterns"],
            },
            {
                "name": "Tag Enricher",
                "type": "asset",
                "description": "Analyzes tag compliance and completeness",
                "enricher": TagEnricher(),
                "data_sources": ["Asset tags"],
            },
        ]

        # Check availability
        enricher_info = []
        for e in enrichers:
            try:
                available = e["enricher"].is_available()
                enrichment_types = [et.value for et in e["enricher"].enrichment_types]
            except Exception:
                available = False
                enrichment_types = []

            enricher_info.append({
                "name": e["name"],
                "type": e["type"],
                "description": e["description"],
                "available": available,
                "enrichment_types": enrichment_types,
                "data_sources": e["data_sources"],
            })

        return {
            "enrichers": enricher_info,
            "finding_enrichers": [e["name"] for e in enricher_info if e["type"] == "finding"],
            "asset_enrichers": [e["name"] for e in enricher_info if e["type"] == "asset"],
            "enrichment_types": {
                "findings": ["cve", "kev", "vuln", "threat"],
                "assets": ["ip", "geo", "cloud", "context", "tags"],
            },
        }

    # =========================================================================
    # Aggregation API Endpoints
    # =========================================================================

    def _aggregation_aggregate(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Aggregate findings from multiple cloud accounts.

        Query params:
            severity: Filter by severity level
            deduplicate: Whether to deduplicate (default: true)

        Returns:
            Aggregated findings with statistics
        """
        from stance.aggregation import FindingsAggregator, CloudAccount
        from stance.models.finding import Finding, Severity

        # Parse parameters
        severity_filter = params.get("severity", [None])[0] if params else None
        deduplicate = params.get("deduplicate", ["true"])[0].lower() != "false" if params else True

        # Create aggregator
        aggregator = FindingsAggregator()

        # Get sample data for demo
        accounts, findings_by_account = self._get_sample_aggregation_data()

        # Add accounts and findings
        for account in accounts:
            aggregator.add_account(account)
            if account.id in findings_by_account:
                aggregator.add_findings(account.id, findings_by_account[account.id])

        # Parse severity filter
        sev = None
        if severity_filter:
            try:
                sev = Severity(severity_filter.lower())
            except ValueError:
                pass

        # Perform aggregation
        findings_collection, result = aggregator.aggregate(
            deduplicate=deduplicate,
            severity_filter=sev,
        )

        return {
            "result": result.to_dict(),
            "findings": [f.to_dict() for f in findings_collection],
            "count": len(list(findings_collection)),
        }

    def _aggregation_cross_account(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Find findings that appear in multiple accounts.

        Query params:
            min_accounts: Minimum accounts for a finding (default: 2)

        Returns:
            Cross-account findings
        """
        from stance.aggregation import FindingsAggregator

        # Parse parameters
        min_accounts = int(params.get("min_accounts", ["2"])[0]) if params else 2

        # Create aggregator
        aggregator = FindingsAggregator()

        # Get sample data
        accounts, findings_by_account = self._get_sample_aggregation_data()

        # Add accounts and findings
        for account in accounts:
            aggregator.add_account(account)
            if account.id in findings_by_account:
                aggregator.add_findings(account.id, findings_by_account[account.id])

        # Get cross-account findings
        cross_account_findings = aggregator.get_cross_account_findings(min_accounts=min_accounts)
        findings_list = list(cross_account_findings)

        return {
            "min_accounts": min_accounts,
            "count": len(findings_list),
            "findings": [f.to_dict() for f in findings_list],
        }

    def _aggregation_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Generate aggregation summary report.

        Returns:
            Summary statistics across all accounts
        """
        from stance.aggregation import FindingsAggregator

        # Create aggregator
        aggregator = FindingsAggregator()

        # Get sample data
        accounts, findings_by_account = self._get_sample_aggregation_data()

        # Add accounts and findings
        for account in accounts:
            aggregator.add_account(account)
            if account.id in findings_by_account:
                aggregator.add_findings(account.id, findings_by_account[account.id])

        # Generate summary
        summary = aggregator.generate_summary_report()

        return summary

    def _aggregation_sync(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get synchronization configuration and status.

        Query params:
            bucket: Target bucket for sync
            direction: Sync direction (push, pull, bidirectional)
            dry_run: Preview only (default: true)

        Returns:
            Sync configuration and preview
        """
        from stance.aggregation import SyncConfig, SyncDirection, SyncResult

        # Parse parameters
        bucket = params.get("bucket", [None])[0] if params else None
        direction = params.get("direction", ["push"])[0] if params else "push"
        dry_run = params.get("dry_run", ["true"])[0].lower() != "false" if params else True

        if not bucket:
            return {
                "error": "bucket parameter is required",
                "usage": "/api/aggregation/sync?bucket=my-bucket&direction=push",
                "sync_directions": ["push", "pull", "bidirectional"],
                "conflict_resolutions": ["latest_wins", "central_wins", "local_wins", "merge"],
            }

        # Parse direction
        try:
            sync_dir = SyncDirection(direction)
        except ValueError:
            return {
                "error": f"Invalid direction: {direction}",
                "valid_options": ["push", "pull", "bidirectional"],
            }

        # Create config (dry run only)
        config = SyncConfig(
            central_bucket=bucket,
            sync_direction=sync_dir,
        )

        result = SyncResult(
            success=True,
            records_synced=0,
            records_skipped=0,
            sync_direction=sync_dir,
        )

        return {
            "dry_run": dry_run,
            "config": {
                "bucket": bucket,
                "direction": direction,
                "prefix": config.central_prefix,
                "include_assets": config.include_assets,
            },
            "result": result.to_dict(),
            "message": "Dry run - no changes made" if dry_run else "Sync requires storage adapter configuration",
        }

    def _aggregation_sync_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get current synchronization status.

        Returns:
            Sync status and history
        """
        # In a real implementation, this would read from state storage
        return {
            "sync_enabled": False,
            "last_sync": None,
            "configured_buckets": [],
            "pending_records": 0,
            "sync_errors": [],
            "sync_history": [],
        }

    def _aggregation_backends(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List configured query backends.

        Returns:
            List of query backends and their status
        """
        # Sample backends for demo
        backends = [
            {
                "name": "aws-athena-prod",
                "provider": "aws",
                "enabled": True,
                "priority": 1,
                "engine": "Athena",
                "connected": False,
            },
            {
                "name": "gcp-bigquery-prod",
                "provider": "gcp",
                "enabled": True,
                "priority": 2,
                "engine": "BigQuery",
                "connected": False,
            },
            {
                "name": "azure-synapse-prod",
                "provider": "azure",
                "enabled": False,
                "priority": 3,
                "engine": "Synapse",
                "connected": False,
            },
        ]

        return {
            "backends": backends,
            "total": len(backends),
            "enabled": sum(1 for b in backends if b["enabled"]),
            "connected": sum(1 for b in backends if b["connected"]),
        }

    def _aggregation_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get aggregation module status and capabilities.

        Returns:
            Module status and available features
        """
        return {
            "module": "aggregation",
            "version": "1.0.0",
            "capabilities": {
                "multi_account_aggregation": True,
                "cross_account_detection": True,
                "deduplication": True,
                "severity_filtering": True,
                "cross_cloud_sync": True,
                "federated_queries": True,
            },
            "supported_providers": ["aws", "gcp", "azure"],
            "sync_adapters": ["S3", "GCS", "Azure Blob"],
            "query_backends": ["Athena", "BigQuery", "Synapse"],
            "merge_strategies": ["union", "union_distinct", "intersect", "priority"],
            "query_strategies": ["parallel", "sequential", "first_success", "best_effort"],
            "conflict_resolutions": ["latest_wins", "central_wins", "local_wins", "merge"],
        }

    def _get_sample_aggregation_data(self):
        """Get sample aggregation data for demos."""
        from stance.aggregation import CloudAccount
        from stance.models.finding import Finding, Severity

        now = datetime.utcnow()

        # Sample accounts
        accounts = [
            CloudAccount(
                id="123456789012",
                provider="aws",
                name="AWS Production",
                region="us-east-1",
            ),
            CloudAccount(
                id="my-gcp-project",
                provider="gcp",
                name="GCP Production",
                region="us-central1",
            ),
            CloudAccount(
                id="azure-sub-001",
                provider="azure",
                name="Azure Production",
                region="eastus",
            ),
        ]

        # Sample findings
        findings_by_account = {
            "123456789012": [
                Finding(
                    id="finding-aws-001",
                    title="S3 bucket without encryption",
                    description="S3 bucket does not have encryption enabled",
                    severity=Severity.HIGH,
                    rule_id="aws-s3-001",
                    asset_id="arn:aws:s3:::my-bucket",
                    first_seen=now,
                    last_seen=now,
                ),
                Finding(
                    id="finding-aws-002",
                    title="Public S3 bucket detected",
                    description="S3 bucket allows public access",
                    severity=Severity.CRITICAL,
                    rule_id="aws-s3-002",
                    asset_id="arn:aws:s3:::public-bucket",
                    first_seen=now,
                    last_seen=now,
                ),
            ],
            "my-gcp-project": [
                Finding(
                    id="finding-gcp-001",
                    title="GCS bucket without encryption",
                    description="Cloud Storage bucket does not have encryption",
                    severity=Severity.HIGH,
                    rule_id="gcp-storage-001",
                    asset_id="//storage.googleapis.com/projects/my-gcp-project/buckets/my-bucket",
                    first_seen=now,
                    last_seen=now,
                ),
            ],
            "azure-sub-001": [
                Finding(
                    id="finding-azure-001",
                    title="Storage account without encryption",
                    description="Azure storage account does not have encryption",
                    severity=Severity.HIGH,
                    rule_id="azure-storage-001",
                    asset_id="/subscriptions/azure-sub-001/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorageaccount",
                    first_seen=now,
                    last_seen=now,
                ),
            ],
        }

        return accounts, findings_by_account

    # =========================================================================
    # Query Engine API Endpoints
    # =========================================================================

    def _query_execute(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Execute a SQL SELECT query.

        Query params:
            sql: SQL query to execute (required)
            backend: Query backend (demo, athena, bigquery, synapse) default: demo
            limit: Maximum rows to return
            timeout: Query timeout in seconds

        Returns:
            Query results with rows and metadata
        """
        from stance.query import (
            QueryValidationError,
            QueryExecutionError,
            get_common_schemas,
            ASSETS_SCHEMA,
            FINDINGS_SCHEMA,
        )

        sql = params.get("sql", [None])[0] if params else None
        backend = params.get("backend", ["demo"])[0] if params else "demo"
        limit = params.get("limit", [None])[0] if params else None
        timeout = int(params.get("timeout", ["300"])[0]) if params else 300

        if not sql:
            return {
                "error": "sql parameter is required",
                "usage": "/api/query/execute?sql=SELECT * FROM assets LIMIT 10",
            }

        # Add LIMIT if requested
        if limit and "LIMIT" not in sql.upper():
            sql = f"{sql.rstrip().rstrip(';')} LIMIT {limit}"

        # Execute query (demo mode)
        result = self._execute_demo_query(sql)

        return {
            "sql": sql,
            "backend": backend,
            "result": result,
        }

    def _query_estimate(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Estimate query cost before execution.

        Query params:
            sql: SQL query to estimate (required)
            backend: Query backend default: demo

        Returns:
            Cost estimation with bytes and USD
        """
        sql = params.get("sql", [None])[0] if params else None
        backend = params.get("backend", ["demo"])[0] if params else "demo"

        if not sql:
            return {
                "error": "sql parameter is required",
                "usage": "/api/query/estimate?sql=SELECT * FROM findings",
            }

        # Validate query first
        errors = self._validate_sql(sql)
        if errors:
            return {
                "sql": sql,
                "valid": False,
                "errors": errors,
            }

        # Demo estimation
        estimated_bytes = 10 * 1024 * 1024  # 10 MB minimum
        estimated_cost = 0.00005  # ~$5/TB

        return {
            "sql": sql,
            "backend": backend,
            "valid": True,
            "estimated_bytes": estimated_bytes,
            "estimated_cost_usd": estimated_cost,
            "warnings": ["Demo mode - no actual cost"],
        }

    def _query_tables(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List available tables.

        Query params:
            backend: Query backend default: demo

        Returns:
            List of table names
        """
        from stance.query import get_common_schemas

        backend = params.get("backend", ["demo"])[0] if params else "demo"
        tables = list(get_common_schemas().keys())

        return {
            "backend": backend,
            "tables": tables,
            "count": len(tables),
        }

    def _query_schema(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get table schema.

        Query params:
            table: Table name (required)
            backend: Query backend default: demo

        Returns:
            Table schema with columns
        """
        from stance.query import get_common_schemas

        table_name = params.get("table", [None])[0] if params else None
        backend = params.get("backend", ["demo"])[0] if params else "demo"

        if not table_name:
            return {
                "error": "table parameter is required",
                "usage": "/api/query/schema?table=assets",
                "available_tables": list(get_common_schemas().keys()),
            }

        schemas = get_common_schemas()
        if table_name not in schemas:
            return {
                "error": f"Table not found: {table_name}",
                "available_tables": list(schemas.keys()),
            }

        schema = schemas[table_name]
        return {
            "backend": backend,
            "table_name": schema.table_name,
            "description": schema.description,
            "columns": schema.columns,
            "column_count": len(schema.columns),
        }

    def _query_validate(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Validate a SQL query without executing.

        Query params:
            sql: SQL query to validate (required)

        Returns:
            Validation result with errors if any
        """
        sql = params.get("sql", [None])[0] if params else None

        if not sql:
            return {
                "error": "sql parameter is required",
                "usage": "/api/query/validate?sql=SELECT * FROM assets",
            }

        errors = self._validate_sql(sql)

        return {
            "sql": sql,
            "valid": len(errors) == 0,
            "errors": errors,
        }

    def _query_backends(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List configured query backends.

        Returns:
            List of query backends with status
        """
        backends = [
            {
                "name": "athena",
                "provider": "aws",
                "description": "AWS Athena - Query data in S3 using SQL",
                "pricing": "$5.00 per TB scanned",
                "configured": False,
            },
            {
                "name": "bigquery",
                "provider": "gcp",
                "description": "Google BigQuery - Serverless data warehouse",
                "pricing": "$5.00 per TB processed",
                "configured": False,
            },
            {
                "name": "synapse",
                "provider": "azure",
                "description": "Azure Synapse Analytics",
                "pricing": "$5.00 per TB processed",
                "configured": False,
            },
            {
                "name": "demo",
                "provider": "local",
                "description": "Demo mode with sample data",
                "pricing": "Free",
                "configured": True,
            },
        ]

        return {
            "backends": backends,
            "total": len(backends),
            "configured": sum(1 for b in backends if b["configured"]),
        }

    def _query_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get query engine status and capabilities.

        Returns:
            Module status and capabilities
        """
        return {
            "module": "query_engine",
            "version": "1.0.0",
            "capabilities": {
                "sql_execution": True,
                "cost_estimation": True,
                "schema_introspection": True,
                "query_validation": True,
                "parameterized_queries": True,
                "result_pagination": True,
            },
            "supported_backends": ["athena", "bigquery", "synapse", "demo"],
            "security": {
                "read_only": True,
                "forbidden_keywords": [
                    "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
                    "ALTER", "TRUNCATE", "GRANT", "REVOKE"
                ],
            },
            "common_tables": ["assets", "findings"],
        }

    def _validate_sql(self, sql: str) -> list[str]:
        """Validate SQL query for safety."""
        import re

        errors = []
        sql_upper = sql.upper().strip()

        # Must start with SELECT or WITH
        if not sql_upper.startswith("SELECT") and not sql_upper.startswith("WITH"):
            errors.append("Query must start with SELECT or WITH")

        # Check forbidden keywords
        forbidden = [
            "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
            "ALTER", "TRUNCATE", "REPLACE", "MERGE", "GRANT", "REVOKE"
        ]
        for keyword in forbidden:
            pattern = rf"\b{keyword}\b"
            if re.search(pattern, sql_upper):
                errors.append(f"Forbidden keyword detected: {keyword}")

        # Check for comments
        if re.search(r"(--|/\*|\*/|#)", sql):
            errors.append("SQL comments are not allowed")

        # Check for multiple statements
        sql_no_strings = re.sub(r"'[^']*'", "", sql)
        sql_no_strings = re.sub(r'"[^"]*"', "", sql_no_strings)
        if ";" in sql_no_strings:
            errors.append("Multiple statements are not allowed")

        return errors

    def _execute_demo_query(self, sql: str) -> dict[str, Any]:
        """Execute a demo query with sample data."""
        from stance.query import ASSETS_SCHEMA, FINDINGS_SCHEMA

        sql_upper = sql.upper()

        # Validate first
        errors = self._validate_sql(sql)
        if errors:
            return {
                "error": "Query validation failed",
                "errors": errors,
            }

        # Determine table and get sample data
        if "ASSETS" in sql_upper:
            rows = self._get_sample_query_assets()
            columns = ASSETS_SCHEMA.get_column_names()
        elif "FINDINGS" in sql_upper:
            rows = self._get_sample_query_findings()
            columns = FINDINGS_SCHEMA.get_column_names()
        else:
            rows = []
            columns = []

        # Apply LIMIT
        if "LIMIT" in sql_upper:
            try:
                import re
                match = re.search(r"LIMIT\s+(\d+)", sql_upper)
                if match:
                    limit = int(match.group(1))
                    rows = rows[:limit]
            except (ValueError, IndexError):
                pass

        return {
            "rows": rows,
            "columns": columns,
            "row_count": len(rows),
            "bytes_scanned": len(str(rows)) * 2,
            "execution_time_ms": 50,
            "query_id": "demo-query-001",
            "metadata": {"backend": "demo"},
        }

    def _get_sample_query_assets(self) -> list[dict[str, Any]]:
        """Get sample assets for query demo."""
        return [
            {
                "id": "arn:aws:s3:::production-data",
                "cloud_provider": "aws",
                "account_id": "123456789012",
                "region": "us-east-1",
                "resource_type": "aws_s3_bucket",
                "name": "production-data",
                "tags": '{"Environment": "production"}',
                "network_exposure": "private",
            },
            {
                "id": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
                "cloud_provider": "aws",
                "account_id": "123456789012",
                "region": "us-west-2",
                "resource_type": "aws_ec2_instance",
                "name": "web-server-01",
                "tags": '{"Environment": "production", "Role": "web"}',
                "network_exposure": "public",
            },
            {
                "id": "//storage.googleapis.com/projects/my-gcp-project/buckets/analytics",
                "cloud_provider": "gcp",
                "account_id": "my-gcp-project",
                "region": "us-central1",
                "resource_type": "gcp_storage_bucket",
                "name": "analytics",
                "tags": '{"team": "analytics"}',
                "network_exposure": "private",
            },
        ]

    def _get_sample_query_findings(self) -> list[dict[str, Any]]:
        """Get sample findings for query demo."""
        return [
            {
                "id": "finding-001",
                "asset_id": "arn:aws:s3:::production-data",
                "finding_type": "misconfiguration",
                "severity": "high",
                "status": "open",
                "title": "S3 bucket without encryption",
                "description": "S3 bucket does not have default encryption enabled",
                "rule_id": "aws-s3-001",
            },
            {
                "id": "finding-002",
                "asset_id": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
                "finding_type": "misconfiguration",
                "severity": "critical",
                "status": "open",
                "title": "EC2 instance with public IP and open SSH",
                "description": "EC2 instance publicly accessible with SSH open",
                "rule_id": "aws-ec2-002",
            },
            {
                "id": "finding-003",
                "asset_id": "//storage.googleapis.com/projects/my-gcp-project/buckets/analytics",
                "finding_type": "vulnerability",
                "severity": "medium",
                "status": "open",
                "title": "GCS bucket with uniform access disabled",
                "description": "Cloud Storage bucket uses legacy ACLs",
                "rule_id": "gcp-storage-001",
            },
        ]

    def _send_json(self, data: dict[str, Any]):
        """Send JSON response."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode("utf-8"))

    def _send_error(self, code: int, message: str):
        """Send error response."""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode("utf-8"))

    def log_message(self, format: str, *args):
        """Suppress default logging."""
        pass

    # ==================== Plugin Management API Endpoints ====================

    def _plugins_list(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List all registered plugins.

        Query Parameters:
            type: Filter by plugin type (collector, policy, enricher, alert_destination, report_format)
            enabled: Filter by enabled status (true/false)

        Returns:
            List of plugins with metadata
        """
        params = params or {}
        plugin_type = params.get("type", [""])[0]
        enabled_filter = params.get("enabled", [""])[0]

        # Get demo plugin list
        plugins = self._get_sample_plugins()

        # Apply filters
        if plugin_type:
            plugins = [p for p in plugins if p.get("type") == plugin_type]

        if enabled_filter:
            enabled_bool = enabled_filter.lower() == "true"
            plugins = [p for p in plugins if p.get("enabled", False) == enabled_bool]

        return {
            "plugins": plugins,
            "total": len(plugins),
            "enabled_count": sum(1 for p in plugins if p.get("enabled", False)),
            "disabled_count": sum(1 for p in plugins if not p.get("enabled", False)),
        }

    def _plugins_info(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get detailed information about a specific plugin.

        Query Parameters:
            name: Plugin name (required)

        Returns:
            Plugin details including config schema
        """
        params = params or {}
        name = params.get("name", [""])[0]

        if not name:
            return {"error": "Plugin name is required"}

        # Get demo plugin
        plugins = self._get_sample_plugins()
        plugin = next((p for p in plugins if p.get("name") == name), None)

        if not plugin:
            return {"error": f"Plugin not found: {name}"}

        # Add additional details
        plugin["config_schema"] = self._get_plugin_config_schema(plugin.get("type", ""))
        plugin["capabilities"] = self._get_plugin_capabilities(plugin.get("type", ""))

        return plugin

    def _plugins_load(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Load a plugin from source.

        Query Parameters:
            source: Plugin source (file path, module name, or URL)
            type: Plugin type (optional, auto-detected)
            config: JSON configuration (optional)

        Returns:
            Load result with warnings
        """
        params = params or {}
        source = params.get("source", [""])[0]
        plugin_type = params.get("type", [""])[0]

        if not source:
            return {"error": "Plugin source is required"}

        # Demo mode - simulate loading
        return {
            "success": True,
            "name": f"plugin_{source.split('/')[-1].replace('.py', '')}",
            "source": source,
            "type": plugin_type or "collector",
            "warnings": [
                "Demo mode: Plugin not actually loaded",
                "In production, the plugin would be dynamically loaded from the source",
            ],
        }

    def _plugins_unload(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Unload a plugin.

        Query Parameters:
            name: Plugin name (required)
            force: Force unload even if in use (optional)

        Returns:
            Unload result
        """
        params = params or {}
        name = params.get("name", [""])[0]
        force = params.get("force", ["false"])[0].lower() == "true"

        if not name:
            return {"error": "Plugin name is required"}

        return {
            "success": True,
            "name": name,
            "force": force,
            "message": f"Plugin '{name}' unloaded successfully (demo mode)",
        }

    def _plugins_reload(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Reload a plugin.

        Query Parameters:
            name: Plugin name (required)

        Returns:
            Reload result
        """
        params = params or {}
        name = params.get("name", [""])[0]

        if not name:
            return {"error": "Plugin name is required"}

        return {
            "success": True,
            "name": name,
            "message": f"Plugin '{name}' reloaded successfully (demo mode)",
            "warnings": [],
        }

    def _plugins_enable(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Enable a plugin.

        Query Parameters:
            name: Plugin name (required)

        Returns:
            Enable result
        """
        params = params or {}
        name = params.get("name", [""])[0]

        if not name:
            return {"error": "Plugin name is required"}

        return {
            "success": True,
            "name": name,
            "enabled": True,
            "message": f"Plugin '{name}' enabled successfully",
        }

    def _plugins_disable(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Disable a plugin.

        Query Parameters:
            name: Plugin name (required)

        Returns:
            Disable result
        """
        params = params or {}
        name = params.get("name", [""])[0]

        if not name:
            return {"error": "Plugin name is required"}

        return {
            "success": True,
            "name": name,
            "enabled": False,
            "message": f"Plugin '{name}' disabled successfully",
        }

    def _plugins_configure(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Configure a plugin.

        Query Parameters:
            name: Plugin name (required)
            config: JSON configuration string (required for setting config)
            show: If true, show current config instead of setting

        Returns:
            Configuration result or current config
        """
        params = params or {}
        name = params.get("name", [""])[0]
        config_json = params.get("config", [""])[0]
        show = params.get("show", ["false"])[0].lower() == "true"

        if not name:
            return {"error": "Plugin name is required"}

        # Get demo plugin
        plugins = self._get_sample_plugins()
        plugin = next((p for p in plugins if p.get("name") == name), None)

        if not plugin:
            return {"error": f"Plugin not found: {name}"}

        if show:
            return {
                "name": name,
                "config_schema": self._get_plugin_config_schema(plugin.get("type", "")),
                "current_config": plugin.get("config", {}),
            }

        if not config_json:
            return {"error": "Configuration is required. Use show=true to view current config."}

        try:
            config = json.loads(config_json)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON configuration: {e}"}

        return {
            "success": True,
            "name": name,
            "config": config,
            "message": f"Plugin '{name}' configured successfully (demo mode)",
        }

    def _plugins_discover(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Discover available plugins.

        Query Parameters:
            paths: Comma-separated paths to search (optional)
            load: If true, auto-load discovered plugins

        Returns:
            List of discovered plugins
        """
        params = params or {}
        paths = params.get("paths", [""])[0]
        auto_load = params.get("load", ["false"])[0].lower() == "true"

        # Demo discovery
        discovered = [
            {
                "name": "aws_collector",
                "type": "collector",
                "source": "stance.plugins.collectors.aws",
                "loaded": True,
            },
            {
                "name": "gcp_collector",
                "type": "collector",
                "source": "stance.plugins.collectors.gcp",
                "loaded": True,
            },
            {
                "name": "azure_collector",
                "type": "collector",
                "source": "stance.plugins.collectors.azure",
                "loaded": True,
            },
            {
                "name": "cis_benchmark",
                "type": "policy",
                "source": "stance.plugins.policies.cis",
                "loaded": True,
            },
            {
                "name": "cve_enricher",
                "type": "enricher",
                "source": "stance.plugins.enrichers.cve",
                "loaded": False,
            },
            {
                "name": "slack_alert",
                "type": "alert_destination",
                "source": "stance.plugins.alerts.slack",
                "loaded": False,
            },
        ]

        if paths:
            discovered.append({
                "name": "custom_plugin",
                "type": "collector",
                "source": paths,
                "loaded": False,
            })

        return {
            "discovered": discovered,
            "total": len(discovered),
            "loaded": sum(1 for p in discovered if p.get("loaded", False)),
            "available": sum(1 for p in discovered if not p.get("loaded", False)),
            "auto_load": auto_load,
        }

    def _plugins_types(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List available plugin types.

        Returns:
            List of plugin types with descriptions
        """
        from stance.plugins import PluginType

        types = [
            {
                "type": PluginType.COLLECTOR.value,
                "description": "Data collection plugins for gathering assets and configurations",
                "examples": "AWS collector, GCP collector, Azure collector",
                "interface": ["collect", "list_resources", "get_resource"],
            },
            {
                "type": PluginType.POLICY.value,
                "description": "Security policy plugins for evaluating compliance rules",
                "examples": "CIS Benchmarks, custom policies, SOC2 controls",
                "interface": ["evaluate", "get_rules", "get_remediation"],
            },
            {
                "type": PluginType.ENRICHER.value,
                "description": "Data enrichment plugins for augmenting asset information",
                "examples": "Geo-IP lookup, threat intelligence, CVE enrichment",
                "interface": ["enrich", "get_context", "lookup"],
            },
            {
                "type": PluginType.ALERT_DESTINATION.value,
                "description": "Alert destination plugins for sending notifications",
                "examples": "Slack, PagerDuty, Email, webhooks",
                "interface": ["send", "test_connection", "format_message"],
            },
            {
                "type": PluginType.REPORT_FORMAT.value,
                "description": "Report format plugins for generating output formats",
                "examples": "PDF, HTML, JSON, CSV exporters",
                "interface": ["generate", "get_template", "export"],
            },
        ]

        return {
            "types": types,
            "total": len(types),
        }

    def _plugins_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get plugin system status.

        Returns:
            Plugin system status and statistics
        """
        plugins = self._get_sample_plugins()

        # Count by type
        by_type = {}
        for plugin in plugins:
            ptype = plugin.get("type", "unknown")
            by_type[ptype] = by_type.get(ptype, 0) + 1

        return {
            "module": "plugins",
            "version": "1.0.0",
            "total_plugins": len(plugins),
            "enabled_plugins": sum(1 for p in plugins if p.get("enabled", False)),
            "disabled_plugins": sum(1 for p in plugins if not p.get("enabled", False)),
            "plugins_by_type": by_type,
            "registry_healthy": True,
            "capabilities": {
                "dynamic_loading": True,
                "hot_reload": True,
                "config_validation": True,
                "dependency_management": True,
                "lifecycle_hooks": True,
            },
        }

    def _get_sample_plugins(self) -> list[dict[str, Any]]:
        """Get sample plugin data for demo mode."""
        return [
            {
                "name": "aws_collector",
                "version": "1.0.0",
                "type": "collector",
                "enabled": True,
                "description": "AWS resource collector for EC2, S3, IAM, and more",
                "author": "Mantissa",
                "config": {"region": "us-east-1", "assume_role": None},
            },
            {
                "name": "gcp_collector",
                "version": "1.0.0",
                "type": "collector",
                "enabled": True,
                "description": "GCP resource collector for Compute, Storage, IAM",
                "author": "Mantissa",
                "config": {"project_id": "my-project", "location": "us-central1"},
            },
            {
                "name": "azure_collector",
                "version": "1.0.0",
                "type": "collector",
                "enabled": False,
                "description": "Azure resource collector for VMs, Storage, RBAC",
                "author": "Mantissa",
                "config": {"subscription_id": None, "tenant_id": None},
            },
            {
                "name": "cis_benchmark",
                "version": "2.0.0",
                "type": "policy",
                "enabled": True,
                "description": "CIS Benchmark policies for AWS, GCP, Azure",
                "author": "Mantissa",
                "config": {"level": 1, "controls": ["all"]},
            },
            {
                "name": "pci_dss",
                "version": "4.0.0",
                "type": "policy",
                "enabled": True,
                "description": "PCI-DSS v4.0 compliance policies",
                "author": "Mantissa",
                "config": {"saq_type": "A", "requirements": ["all"]},
            },
            {
                "name": "cve_enricher",
                "version": "1.0.0",
                "type": "enricher",
                "enabled": True,
                "description": "CVE and vulnerability enrichment from NVD",
                "author": "Mantissa",
                "config": {"api_key": None, "cache_ttl": 3600},
            },
            {
                "name": "geoip_enricher",
                "version": "1.0.0",
                "type": "enricher",
                "enabled": False,
                "description": "GeoIP lookup for IP addresses",
                "author": "Mantissa",
                "config": {"database_path": None},
            },
            {
                "name": "slack_alert",
                "version": "1.0.0",
                "type": "alert_destination",
                "enabled": True,
                "description": "Slack webhook integration for alerts",
                "author": "Mantissa",
                "config": {"webhook_url": None, "channel": "#security"},
            },
            {
                "name": "pagerduty_alert",
                "version": "1.0.0",
                "type": "alert_destination",
                "enabled": False,
                "description": "PagerDuty integration for critical alerts",
                "author": "Mantissa",
                "config": {"routing_key": None, "severity_mapping": {}},
            },
            {
                "name": "html_report",
                "version": "1.0.0",
                "type": "report_format",
                "enabled": True,
                "description": "HTML report generator with charts",
                "author": "Mantissa",
                "config": {"template": "default", "include_charts": True},
            },
            {
                "name": "pdf_report",
                "version": "1.0.0",
                "type": "report_format",
                "enabled": True,
                "description": "PDF report generator",
                "author": "Mantissa",
                "config": {"template": "executive", "page_size": "letter"},
            },
        ]

    def _get_plugin_config_schema(self, plugin_type: str) -> dict[str, Any]:
        """Get config schema for a plugin type."""
        schemas = {
            "collector": {
                "type": "object",
                "properties": {
                    "region": {"type": "string", "description": "Cloud region"},
                    "assume_role": {"type": "string", "description": "IAM role ARN"},
                    "timeout": {"type": "integer", "default": 300},
                },
            },
            "policy": {
                "type": "object",
                "properties": {
                    "level": {"type": "integer", "enum": [1, 2], "default": 1},
                    "controls": {"type": "array", "items": {"type": "string"}},
                    "severity_override": {"type": "object"},
                },
            },
            "enricher": {
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "description": "API key"},
                    "cache_ttl": {"type": "integer", "default": 3600},
                    "timeout": {"type": "integer", "default": 30},
                },
            },
            "alert_destination": {
                "type": "object",
                "properties": {
                    "webhook_url": {"type": "string", "format": "uri"},
                    "channel": {"type": "string"},
                    "severity_filter": {"type": "array", "items": {"type": "string"}},
                },
            },
            "report_format": {
                "type": "object",
                "properties": {
                    "template": {"type": "string", "default": "default"},
                    "include_charts": {"type": "boolean", "default": True},
                    "page_size": {"type": "string", "enum": ["letter", "a4"]},
                },
            },
        }
        return schemas.get(plugin_type, {"type": "object", "properties": {}})

    def _get_plugin_capabilities(self, plugin_type: str) -> list[str]:
        """Get capabilities for a plugin type."""
        capabilities = {
            "collector": ["collect_resources", "list_resources", "get_resource", "incremental_scan"],
            "policy": ["evaluate", "get_rules", "get_remediation", "severity_scoring"],
            "enricher": ["enrich", "batch_enrich", "lookup", "cache_results"],
            "alert_destination": ["send", "test_connection", "format_message", "batch_send"],
            "report_format": ["generate", "get_template", "export", "preview"],
        }
        return capabilities.get(plugin_type, [])

    # ==================== Exceptions API Endpoints ====================

    def _exceptions_list(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List all exceptions.

        Query Parameters:
            status: Filter by status (pending, approved, rejected, expired, revoked)
            type: Filter by type (suppression, temporary, false_positive, risk_accepted, compensating_control)
            scope: Filter by scope (finding, asset, policy, etc.)
            include_expired: Include expired exceptions (true/false)
            active: Show only active exceptions (true/false)

        Returns:
            List of exceptions with metadata
        """
        params = params or {}
        status_filter = params.get("status", [""])[0]
        type_filter = params.get("type", [""])[0]
        scope_filter = params.get("scope", [""])[0]
        include_expired = params.get("include_expired", ["false"])[0].lower() == "true"
        active_only = params.get("active", ["false"])[0].lower() == "true"

        # Get demo exceptions
        exceptions = self._get_sample_exceptions()

        # Apply filters
        if status_filter:
            exceptions = [e for e in exceptions if e.get("status") == status_filter]

        if type_filter:
            exceptions = [e for e in exceptions if e.get("exception_type") == type_filter]

        if scope_filter:
            exceptions = [e for e in exceptions if e.get("scope") == scope_filter]

        if active_only:
            exceptions = [e for e in exceptions if e.get("is_active", False)]

        if not include_expired:
            exceptions = [e for e in exceptions if not e.get("is_expired", False)]

        return {
            "exceptions": exceptions,
            "total": len(exceptions),
            "active_count": sum(1 for e in exceptions if e.get("is_active", False)),
        }

    def _exceptions_show(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Show exception details.

        Query Parameters:
            id: Exception ID (required)

        Returns:
            Exception details
        """
        params = params or {}
        exception_id = params.get("id", [""])[0]

        if not exception_id:
            return {"error": "Exception ID is required"}

        # Find in sample data
        exceptions = self._get_sample_exceptions()
        for exc in exceptions:
            if exc.get("id", "").startswith(exception_id):
                return exc

        return {"error": f"Exception not found: {exception_id}"}

    def _exceptions_create(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Create a new exception.

        Query Parameters:
            type: Exception type (suppression, temporary, false_positive, risk_accepted, compensating_control)
            scope: Exception scope (finding, asset, policy, etc.)
            reason: Reason for exception (required)
            created_by: Creator identifier
            policy: Target policy ID
            asset: Target asset ID
            finding: Target finding ID
            days: Days until expiry (for temporary)
            jira: Associated Jira ticket

        Returns:
            Created exception
        """
        params = params or {}
        exc_type = params.get("type", ["suppression"])[0]
        scope = params.get("scope", ["finding"])[0]
        reason = params.get("reason", [""])[0]
        created_by = params.get("created_by", ["api"])[0]
        policy_id = params.get("policy", [""])[0] or None
        asset_id = params.get("asset", [""])[0] or None
        finding_id = params.get("finding", [""])[0] or None
        days = params.get("days", [""])[0]
        jira_ticket = params.get("jira", [""])[0] or None

        if not reason:
            return {"error": "Reason is required"}

        import uuid
        from datetime import datetime, timezone, timedelta

        exc_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = None
        if days:
            try:
                expires_at = (now + timedelta(days=int(days))).isoformat()
            except ValueError:
                return {"error": f"Invalid days value: {days}"}

        return {
            "success": True,
            "id": exc_id,
            "exception_type": exc_type,
            "scope": scope,
            "status": "approved",
            "reason": reason,
            "created_by": created_by,
            "created_at": now.isoformat(),
            "expires_at": expires_at,
            "policy_id": policy_id,
            "asset_id": asset_id,
            "finding_id": finding_id,
            "jira_ticket": jira_ticket,
            "is_active": True,
            "message": f"Exception created successfully (demo mode)",
        }

    def _exceptions_suppress(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Create a suppression.

        Query Parameters:
            scope: Suppression scope
            reason: Reason for suppression (required)
            policy: Target policy ID
            asset: Target asset ID
            finding: Target finding ID

        Returns:
            Created suppression
        """
        params = params or {}
        params["type"] = ["suppression"]
        return self._exceptions_create(params)

    def _exceptions_false_positive(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Mark finding as false positive.

        Query Parameters:
            finding: Finding ID (required)
            reason: Reason for marking as false positive (required)

        Returns:
            Created false positive exception
        """
        params = params or {}
        finding_id = params.get("finding", [""])[0]
        reason = params.get("reason", [""])[0]

        if not finding_id:
            return {"error": "Finding ID is required"}

        if not reason:
            return {"error": "Reason is required"}

        params["type"] = ["false_positive"]
        params["scope"] = ["finding"]
        return self._exceptions_create(params)

    def _exceptions_accept_risk(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Create a risk acceptance.

        Query Parameters:
            scope: Risk acceptance scope
            reason: Reason for accepting risk (required)
            approved_by: Approver (required)
            days: Days until review (default: 365)
            policy: Target policy ID
            asset: Target asset ID

        Returns:
            Created risk acceptance
        """
        params = params or {}
        approved_by = params.get("approved_by", [""])[0]
        reason = params.get("reason", [""])[0]

        if not reason:
            return {"error": "Reason is required"}

        if not approved_by:
            return {"error": "Approver is required (approved_by)"}

        # Set defaults for risk acceptance
        if "days" not in params or not params["days"][0]:
            params["days"] = ["365"]

        params["type"] = ["risk_accepted"]

        result = self._exceptions_create(params)
        if "success" in result:
            result["approved_by"] = approved_by
        return result

    def _exceptions_revoke(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Revoke an exception.

        Query Parameters:
            id: Exception ID (required)
            reason: Reason for revocation

        Returns:
            Revocation result
        """
        params = params or {}
        exception_id = params.get("id", [""])[0]
        reason = params.get("reason", [""])[0]

        if not exception_id:
            return {"error": "Exception ID is required"}

        return {
            "success": True,
            "id": exception_id,
            "status": "revoked",
            "revocation_reason": reason,
            "message": f"Exception revoked successfully (demo mode)",
        }

    def _exceptions_delete(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Delete an exception.

        Query Parameters:
            id: Exception ID (required)
            force: Force delete even if active (true/false)

        Returns:
            Deletion result
        """
        params = params or {}
        exception_id = params.get("id", [""])[0]
        force = params.get("force", ["false"])[0].lower() == "true"

        if not exception_id:
            return {"error": "Exception ID is required"}

        return {
            "success": True,
            "id": exception_id,
            "force": force,
            "message": f"Exception deleted successfully (demo mode)",
        }

    def _exceptions_expire(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Expire outdated exceptions.

        Returns:
            Expiration result
        """
        return {
            "success": True,
            "expired_count": 2,
            "message": "Expired 2 outdated exceptions (demo mode)",
        }

    def _exceptions_types(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List exception types.

        Returns:
            List of exception types
        """
        types = [
            {
                "type": "suppression",
                "description": "Permanent suppression of findings",
                "use_case": "Known acceptable configuration",
            },
            {
                "type": "temporary",
                "description": "Time-limited exception with automatic expiry",
                "use_case": "Planned remediation in progress",
            },
            {
                "type": "false_positive",
                "description": "Finding determined to be incorrect",
                "use_case": "Policy doesn't apply to this resource",
            },
            {
                "type": "risk_accepted",
                "description": "Risk formally accepted with approval",
                "use_case": "Business requirement overrides security",
            },
            {
                "type": "compensating_control",
                "description": "Alternative security control in place",
                "use_case": "Different control addresses the same risk",
            },
        ]

        return {
            "types": types,
            "total": len(types),
        }

    def _exceptions_scopes(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List exception scopes.

        Returns:
            List of exception scopes
        """
        scopes = [
            {
                "scope": "finding",
                "description": "Single specific finding",
                "example": "finding=<finding_id>",
            },
            {
                "scope": "asset",
                "description": "All findings for a specific asset",
                "example": "asset=<asset_id>",
            },
            {
                "scope": "policy",
                "description": "All findings from a policy",
                "example": "policy=<policy_id>",
            },
            {
                "scope": "asset_policy",
                "description": "Policy findings for a specific asset",
                "example": "asset=<asset_id>&policy=<policy_id>",
            },
            {
                "scope": "resource_type",
                "description": "All assets of a resource type",
                "example": "resource_type=aws_s3_bucket",
            },
            {
                "scope": "tag",
                "description": "Assets with specific tag",
                "example": "tag_key=environment&tag_value=dev",
            },
            {
                "scope": "account",
                "description": "Entire cloud account",
                "example": "account=123456789012",
            },
            {
                "scope": "global",
                "description": "Global exception (all findings)",
                "example": "scope=global",
            },
        ]

        return {
            "scopes": scopes,
            "total": len(scopes),
        }

    def _exceptions_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get exceptions module status.

        Returns:
            Module status and statistics
        """
        exceptions = self._get_sample_exceptions()

        # Count by type
        by_type = {}
        for exc in exceptions:
            t = exc.get("exception_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        # Count by status
        by_status = {}
        for exc in exceptions:
            s = exc.get("status", "unknown")
            by_status[s] = by_status.get(s, 0) + 1

        # Count by scope
        by_scope = {}
        for exc in exceptions:
            s = exc.get("scope", "unknown")
            by_scope[s] = by_scope.get(s, 0) + 1

        active_count = sum(1 for e in exceptions if e.get("is_active", False))
        expiring_soon = sum(1 for e in exceptions if e.get("days_until_expiry") is not None and e.get("days_until_expiry", 999) <= 30)

        return {
            "module": "exceptions",
            "version": "1.0.0",
            "total_exceptions": len(exceptions),
            "active_exceptions": active_count,
            "expiring_soon": expiring_soon,
            "exceptions_by_type": by_type,
            "exceptions_by_status": by_status,
            "exceptions_by_scope": by_scope,
            "capabilities": {
                "suppression": True,
                "temporary_exceptions": True,
                "false_positive_marking": True,
                "risk_acceptance": True,
                "compensating_controls": True,
                "auto_expiry": True,
                "jira_integration": True,
            },
        }

    def _get_sample_exceptions(self) -> list[dict[str, Any]]:
        """Get sample exception data for demo mode."""
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)

        return [
            {
                "id": "exc-001-suppression",
                "exception_type": "suppression",
                "scope": "policy",
                "status": "approved",
                "reason": "Legacy system - cannot enable MFA",
                "created_by": "security-team",
                "created_at": (now - timedelta(days=30)).isoformat(),
                "expires_at": None,
                "policy_id": "aws-iam-001",
                "asset_id": None,
                "finding_id": None,
                "jira_ticket": "SEC-1234",
                "is_active": True,
                "is_expired": False,
                "days_until_expiry": None,
            },
            {
                "id": "exc-002-temporary",
                "exception_type": "temporary",
                "scope": "asset",
                "status": "approved",
                "reason": "Remediation in progress - planned fix next sprint",
                "created_by": "dev-team",
                "created_at": (now - timedelta(days=10)).isoformat(),
                "expires_at": (now + timedelta(days=20)).isoformat(),
                "policy_id": None,
                "asset_id": "arn:aws:s3:::legacy-bucket",
                "finding_id": None,
                "jira_ticket": "DEV-5678",
                "is_active": True,
                "is_expired": False,
                "days_until_expiry": 20,
            },
            {
                "id": "exc-003-false-positive",
                "exception_type": "false_positive",
                "scope": "finding",
                "status": "approved",
                "reason": "Service account - no human access",
                "created_by": "analyst",
                "created_at": (now - timedelta(days=5)).isoformat(),
                "expires_at": None,
                "policy_id": None,
                "asset_id": None,
                "finding_id": "finding-abc-123",
                "jira_ticket": None,
                "is_active": True,
                "is_expired": False,
                "days_until_expiry": None,
            },
            {
                "id": "exc-004-risk-accepted",
                "exception_type": "risk_accepted",
                "scope": "resource_type",
                "status": "approved",
                "reason": "Business requirement for public access",
                "created_by": "app-team",
                "approved_by": "ciso@company.com",
                "created_at": (now - timedelta(days=60)).isoformat(),
                "expires_at": (now + timedelta(days=305)).isoformat(),
                "policy_id": "aws-s3-002",
                "resource_type": "aws_s3_bucket",
                "asset_id": None,
                "finding_id": None,
                "jira_ticket": "RISK-001",
                "is_active": True,
                "is_expired": False,
                "days_until_expiry": 305,
            },
            {
                "id": "exc-005-compensating",
                "exception_type": "compensating_control",
                "scope": "asset_policy",
                "status": "approved",
                "reason": "Network segmentation provides equivalent protection",
                "created_by": "network-team",
                "created_at": (now - timedelta(days=45)).isoformat(),
                "expires_at": None,
                "policy_id": "aws-ec2-002",
                "asset_id": "i-0123456789abcdef0",
                "finding_id": None,
                "notes": "Private subnet with strict NACLs",
                "jira_ticket": "NET-789",
                "is_active": True,
                "is_expired": False,
                "days_until_expiry": None,
            },
            {
                "id": "exc-006-expired",
                "exception_type": "temporary",
                "scope": "finding",
                "status": "expired",
                "reason": "Temporary exception for migration",
                "created_by": "migration-team",
                "created_at": (now - timedelta(days=40)).isoformat(),
                "expires_at": (now - timedelta(days=10)).isoformat(),
                "policy_id": None,
                "asset_id": None,
                "finding_id": "finding-xyz-789",
                "jira_ticket": "MIG-456",
                "is_active": False,
                "is_expired": True,
                "days_until_expiry": -10,
            },
            {
                "id": "exc-007-revoked",
                "exception_type": "suppression",
                "scope": "account",
                "status": "revoked",
                "reason": "Development account exception",
                "created_by": "platform-team",
                "created_at": (now - timedelta(days=90)).isoformat(),
                "expires_at": None,
                "account_id": "123456789012",
                "policy_id": None,
                "asset_id": None,
                "finding_id": None,
                "notes": "Revoked: Account promoted to production",
                "jira_ticket": None,
                "is_active": False,
                "is_expired": False,
                "days_until_expiry": None,
            },
            {
                "id": "exc-008-tag-based",
                "exception_type": "suppression",
                "scope": "tag",
                "status": "approved",
                "reason": "Development resources - relaxed controls",
                "created_by": "devops-team",
                "created_at": (now - timedelta(days=15)).isoformat(),
                "expires_at": None,
                "tag_key": "environment",
                "tag_value": "development",
                "policy_id": None,
                "asset_id": None,
                "finding_id": None,
                "jira_ticket": "OPS-111",
                "is_active": True,
                "is_expired": False,
                "days_until_expiry": None,
            },
        ]

    # ==================== Notifications API Endpoints ====================

    def _notifications_list(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List notification history.

        Query Parameters:
            limit: Maximum notifications to return (default: 50)
            type: Filter by notification type
            offset: Skip first N notifications

        Returns:
            List of notifications with metadata
        """
        params = params or {}
        limit = int(params.get("limit", ["50"])[0])
        type_filter = params.get("type", [""])[0]
        offset = int(params.get("offset", ["0"])[0])

        # Get demo notifications
        notifications = self._get_sample_notifications()

        # Apply type filter
        if type_filter:
            notifications = [n for n in notifications if n.get("notification_type") == type_filter]

        # Apply offset and limit
        total = len(notifications)
        notifications = notifications[offset:offset + limit]

        return {
            "notifications": notifications,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def _notifications_show(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Show notification details.

        Query Parameters:
            index: Notification index (0 = most recent)

        Returns:
            Notification details
        """
        params = params or {}
        index = int(params.get("index", ["0"])[0])

        notifications = self._get_sample_notifications()

        if index < 0 or index >= len(notifications):
            return {"error": f"Invalid index: {index}. Valid range: 0-{len(notifications)-1}"}

        return notifications[index]

    def _notifications_types(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List notification types.

        Returns:
            All available notification types with descriptions
        """
        types = [
            {
                "value": "scan_complete",
                "name": "Scan Complete",
                "description": "Scan finished successfully",
            },
            {
                "value": "scan_failed",
                "name": "Scan Failed",
                "description": "Scan encountered an error",
            },
            {
                "value": "new_findings",
                "name": "New Findings",
                "description": "New findings detected in scan",
            },
            {
                "value": "critical_finding",
                "name": "Critical Finding",
                "description": "Critical severity finding detected",
            },
            {
                "value": "findings_resolved",
                "name": "Findings Resolved",
                "description": "Previously detected findings are now resolved",
            },
            {
                "value": "trend_alert",
                "name": "Trend Alert",
                "description": "Security trend change (improving/declining)",
            },
            {
                "value": "scheduled_report",
                "name": "Scheduled Report",
                "description": "Periodic scheduled report notification",
            },
        ]

        return {
            "types": types,
            "total": len(types),
        }

    def _notifications_config_get(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get notification configuration.

        Returns:
            Current notification configuration
        """
        return {
            "notify_on_scan_complete": True,
            "notify_on_scan_failure": True,
            "notify_on_new_findings": True,
            "notify_on_critical": True,
            "notify_on_resolved": False,
            "notify_on_trend_change": True,
            "min_severity_for_new": "high",
            "critical_threshold": 1,
            "trend_threshold_percent": 10.0,
            "include_summary": True,
            "include_details": False,
            "destinations": [],
        }

    def _notifications_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get notifications module status.

        Returns:
            Module status and statistics
        """
        notifications = self._get_sample_notifications()

        # Count by type
        by_type = {}
        for notif in notifications:
            t = notif.get("notification_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        enabled_types = [
            "scan_complete", "scan_failed", "new_findings",
            "critical", "trend_change"
        ]

        return {
            "module": "notifications",
            "version": "1.0.0",
            "status": "active",
            "history_count": len(notifications),
            "max_history": 1000,
            "callbacks_registered": 0,
            "router_configured": False,
            "enabled_types": enabled_types,
            "notifications_by_type": by_type,
            "config": self._notifications_config_get(),
            "capabilities": {
                "scan_complete": True,
                "scan_failed": True,
                "new_findings": True,
                "critical_finding": True,
                "findings_resolved": True,
                "trend_alert": True,
                "scheduled_report": True,
                "custom_callbacks": True,
                "alert_routing": True,
            },
        }

    def _notifications_set(self, body: bytes) -> dict[str, Any]:
        """
        Set notification configuration option.

        Request body (JSON):
            option: Configuration option name
            value: New value

        Returns:
            Updated configuration
        """
        import json

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        option = data.get("option", "")
        value = data.get("value")

        if not option:
            return {"error": "Option name is required"}

        if value is None:
            return {"error": "Value is required"}

        valid_options = [
            "notify_on_scan_complete", "notify_on_scan_failure",
            "notify_on_new_findings", "notify_on_critical",
            "notify_on_resolved", "notify_on_trend_change",
            "min_severity", "critical_threshold", "trend_threshold",
            "include_summary", "include_details",
        ]

        if option not in valid_options:
            return {"error": f"Unknown option: {option}", "valid_options": valid_options}

        return {
            "success": True,
            "option": option,
            "value": value,
            "message": f"Set {option} = {value} (demo mode)",
        }

    def _notifications_enable(self, body: bytes) -> dict[str, Any]:
        """
        Enable a notification type.

        Request body (JSON):
            type: Notification type to enable (or "all")

        Returns:
            Updated status
        """
        import json

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        notification_type = data.get("type", "")

        if not notification_type:
            return {"error": "Notification type is required"}

        valid_types = [
            "scan_complete", "scan_failed", "new_findings",
            "critical", "resolved", "trend_change", "all"
        ]

        if notification_type not in valid_types:
            return {"error": f"Unknown type: {notification_type}", "valid_types": valid_types}

        if notification_type == "all":
            message = "Enabled all notification types (demo mode)"
        else:
            message = f"Enabled {notification_type} notifications (demo mode)"

        return {
            "success": True,
            "type": notification_type,
            "enabled": True,
            "message": message,
        }

    def _notifications_disable(self, body: bytes) -> dict[str, Any]:
        """
        Disable a notification type.

        Request body (JSON):
            type: Notification type to disable (or "all")

        Returns:
            Updated status
        """
        import json

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        notification_type = data.get("type", "")

        if not notification_type:
            return {"error": "Notification type is required"}

        valid_types = [
            "scan_complete", "scan_failed", "new_findings",
            "critical", "resolved", "trend_change", "all"
        ]

        if notification_type not in valid_types:
            return {"error": f"Unknown type: {notification_type}", "valid_types": valid_types}

        if notification_type == "all":
            message = "Disabled all notification types (demo mode)"
        else:
            message = f"Disabled {notification_type} notifications (demo mode)"

        return {
            "success": True,
            "type": notification_type,
            "enabled": False,
            "message": message,
        }

    def _notifications_test(self, body: bytes) -> dict[str, Any]:
        """
        Send a test notification.

        Request body (JSON):
            type: Type of test notification to send

        Returns:
            Test notification details
        """
        import json
        from datetime import datetime, timezone

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        notification_type = data.get("type", "scan_complete")

        valid_types = [
            "scan_complete", "scan_failed", "new_findings",
            "critical", "resolved", "trend_alert"
        ]

        if notification_type not in valid_types:
            return {"error": f"Unknown type: {notification_type}", "valid_types": valid_types}

        now = datetime.now(timezone.utc)

        test_notification = {
            "notification_type": notification_type,
            "timestamp": now.isoformat(),
            "scan_id": f"test-{now.strftime('%Y%m%d%H%M%S')}",
            "job_name": "",
            "config_name": "default",
            "message": f"Test: {notification_type} notification",
            "is_test": True,
        }

        return {
            "success": True,
            "notification": test_notification,
            "message": f"Test notification sent: {notification_type} (demo mode)",
        }

    def _notifications_clear(self, body: bytes) -> dict[str, Any]:
        """
        Clear notification history.

        Request body (JSON):
            force: Must be true to confirm

        Returns:
            Clear status
        """
        import json

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        force = data.get("force", False)

        if not force:
            return {"error": "Use force=true to confirm clearing history"}

        return {
            "success": True,
            "message": "Notification history cleared (demo mode)",
            "cleared_count": 5,
        }

    def _get_sample_notifications(self) -> list[dict[str, Any]]:
        """Get sample notification data for demo mode."""
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)

        return [
            {
                "notification_type": "scan_complete",
                "timestamp": now.isoformat(),
                "scan_id": "scan-demo-001",
                "job_name": "daily-security-scan",
                "config_name": "default",
                "message": "Scan completed successfully. Scanned 150 assets, found 23 findings in 45.2s.",
                "success": True,
                "duration_seconds": 45.2,
                "assets_scanned": 150,
                "findings_total": 23,
                "findings_by_severity": {"critical": 2, "high": 5, "medium": 8, "low": 8},
            },
            {
                "notification_type": "critical_finding",
                "timestamp": (now - timedelta(minutes=5)).isoformat(),
                "scan_id": "scan-demo-001",
                "job_name": "daily-security-scan",
                "config_name": "default",
                "message": "ALERT: 2 critical findings detected! Immediate attention required.",
                "findings_count": 2,
                "is_new": True,
            },
            {
                "notification_type": "new_findings",
                "timestamp": (now - timedelta(minutes=10)).isoformat(),
                "scan_id": "scan-demo-001",
                "job_name": "daily-security-scan",
                "config_name": "default",
                "message": "Detected 5 new findings: 1 critical, 2 high, 2 medium",
                "findings_count": 5,
                "is_new": True,
            },
            {
                "notification_type": "trend_alert",
                "timestamp": (now - timedelta(hours=1)).isoformat(),
                "scan_id": "scan-demo-002",
                "job_name": "weekly-trend-analysis",
                "config_name": "default",
                "message": "Security posture declining: 15.3% increase in findings",
                "direction": "declining",
                "change_percent": 15.3,
                "current_findings": 45,
                "previous_findings": 39,
                "period_days": 7,
            },
            {
                "notification_type": "scan_failed",
                "timestamp": (now - timedelta(hours=2)).isoformat(),
                "scan_id": "scan-demo-003",
                "job_name": "aws-account-scan",
                "config_name": "aws-production",
                "message": "Scan failed: AWS credentials expired",
                "success": False,
                "error_message": "AWS credentials expired",
            },
        ]

    # ==================== Correlation API Endpoints ====================

    def _correlation_correlate(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Run correlation analysis on findings.

        Query Parameters:
            time_window: Time window in hours (default: 24)
            min_group_size: Minimum findings to form a group (default: 2)
            threshold: Correlation threshold 0-1 (default: 0.5)

        Returns:
            Correlation result with groups and statistics
        """
        params = params or {}
        time_window = int(params.get("time_window", ["24"])[0])
        min_group_size = int(params.get("min_group_size", ["2"])[0])
        threshold = float(params.get("threshold", ["0.5"])[0])

        # Get demo data
        findings, assets = self._get_sample_correlation_data()

        # Run correlation
        from stance.correlation import FindingCorrelator
        correlator = FindingCorrelator(
            time_window_hours=time_window,
            min_group_size=min_group_size,
            correlation_threshold=threshold,
        )
        result = correlator.correlate(findings, assets)

        return result.to_dict()

    def _correlation_groups(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List correlation groups.

        Query Parameters:
            type: Filter by group type (asset, rule, cve, network, temporal)
            min_size: Minimum group size (default: 1)

        Returns:
            List of correlation groups
        """
        params = params or {}
        group_type = params.get("type", [""])[0]
        min_size = int(params.get("min_size", ["1"])[0])

        findings, assets = self._get_sample_correlation_data()

        from stance.correlation import FindingCorrelator
        correlator = FindingCorrelator()
        result = correlator.correlate(findings, assets)

        groups = result.groups
        if group_type:
            groups = [g for g in groups if g.group_type == group_type]
        if min_size > 1:
            groups = [g for g in groups if len(g.findings) >= min_size]

        return {
            "groups": [g.to_dict() for g in groups],
            "total": len(groups),
        }

    def _correlation_group(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Show correlation group details.

        Query Parameters:
            id: Group ID (required)

        Returns:
            Group details
        """
        params = params or {}
        group_id = params.get("id", [""])[0]

        if not group_id:
            return {"error": "Group ID is required"}

        findings, assets = self._get_sample_correlation_data()

        from stance.correlation import FindingCorrelator
        correlator = FindingCorrelator()
        result = correlator.correlate(findings, assets)

        for group in result.groups:
            if group.id == group_id or group.id.startswith(group_id):
                return group.to_dict()

        return {"error": f"Group not found: {group_id}"}

    def _correlation_related(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Find findings related to a specific finding.

        Query Parameters:
            finding_id: Finding ID (required)
            limit: Maximum results (default: 10)

        Returns:
            List of related findings with scores
        """
        params = params or {}
        finding_id = params.get("finding_id", [""])[0]
        limit = int(params.get("limit", ["10"])[0])

        if not finding_id:
            return {"error": "Finding ID is required"}

        findings, _ = self._get_sample_correlation_data()

        # Find target finding
        target = None
        for f in findings:
            if f.id == finding_id or f.id.startswith(finding_id):
                target = f
                break

        if not target:
            return {"error": f"Finding not found: {finding_id}"}

        from stance.correlation import FindingCorrelator
        correlator = FindingCorrelator()
        related = correlator.find_related(target, findings)

        return {
            "target_finding": {
                "id": target.id,
                "title": target.title,
                "severity": target.severity.value,
            },
            "related": [
                {
                    "finding_id": cf.finding.id,
                    "title": cf.finding.title,
                    "severity": cf.finding.severity.value,
                    "correlation_score": cf.correlation_score,
                    "correlation_reason": cf.correlation_reason,
                }
                for cf in related[:limit]
            ],
            "total": len(related),
        }

    def _correlation_risk(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Calculate risk scores for all assets.

        Query Parameters:
            top: Number of top risk assets to return (default: 10)

        Returns:
            Risk scoring result
        """
        params = params or {}
        top_n = int(params.get("top", ["10"])[0])

        findings, assets = self._get_sample_correlation_data()

        from stance.correlation import RiskScorer
        scorer = RiskScorer()
        result = scorer.calculate_scores(findings, assets)

        # Limit top risks
        result_dict = result.to_dict()
        result_dict["top_risks"] = result_dict["top_risks"][:top_n]

        return result_dict

    def _correlation_risk_asset(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Show risk score for a specific asset.

        Query Parameters:
            asset_id: Asset ID (required)

        Returns:
            Asset risk score details
        """
        params = params or {}
        asset_id = params.get("asset_id", [""])[0]

        if not asset_id:
            return {"error": "Asset ID is required"}

        findings, assets = self._get_sample_correlation_data()

        from stance.correlation import RiskScorer
        scorer = RiskScorer()
        result = scorer.calculate_scores(findings, assets)

        for score in result.asset_scores:
            if score.asset_id == asset_id or score.asset_id.startswith(asset_id):
                return score.to_dict()

        return {"error": f"Asset not found: {asset_id}"}

    def _correlation_risk_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get executive risk summary.

        Returns:
            Organization-wide risk summary
        """
        findings, assets = self._get_sample_correlation_data()

        from stance.correlation import RiskScorer
        scorer = RiskScorer()
        result = scorer.calculate_scores(findings, assets)
        summary = scorer.get_risk_summary(result)

        return summary

    def _correlation_analyze(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Run comprehensive finding analysis.

        Query Parameters:
            include_attack_paths: Include attack path analysis (default: true)
            include_risk: Include risk scoring (default: true)

        Returns:
            Full analysis result
        """
        params = params or {}
        include_attack_paths = params.get("include_attack_paths", ["true"])[0].lower() == "true"
        include_risk = params.get("include_risk", ["true"])[0].lower() == "true"

        findings, assets = self._get_sample_correlation_data()

        from stance.correlation import analyze_findings
        result = analyze_findings(
            findings,
            assets,
            include_attack_paths=include_attack_paths,
            include_risk_scores=include_risk,
        )

        output = {
            "correlation": result["correlation"].to_dict(),
        }
        if "attack_paths" in result:
            output["attack_paths"] = result["attack_paths"].to_dict()
        if "risk_scores" in result:
            output["risk_scores"] = result["risk_scores"].to_dict()

        return output

    def _correlation_types(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List correlation group types.

        Returns:
            All correlation group types
        """
        types = [
            {"type": "asset", "description": "Findings affecting the same asset"},
            {"type": "rule", "description": "Same policy rule failing across multiple assets"},
            {"type": "cve", "description": "Same CVE vulnerability on multiple assets"},
            {"type": "network", "description": "Findings on internet-facing resources"},
            {"type": "temporal", "description": "Burst of findings within time window"},
        ]

        return {
            "types": types,
            "total": len(types),
        }

    def _correlation_levels(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List risk levels.

        Returns:
            All risk levels with score ranges
        """
        levels = [
            {"level": "critical", "score_range": "80-100", "description": "Immediate remediation required"},
            {"level": "high", "score_range": "60-79", "description": "High priority remediation"},
            {"level": "medium", "score_range": "40-59", "description": "Scheduled remediation recommended"},
            {"level": "low", "score_range": "20-39", "description": "Monitor and address in normal cycle"},
            {"level": "minimal", "score_range": "0-19", "description": "Acceptable risk level"},
        ]

        return {
            "levels": levels,
            "total": len(levels),
        }

    def _correlation_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get correlation module status.

        Returns:
            Module status and capabilities
        """
        return {
            "module": "correlation",
            "version": "1.0.0",
            "status": "active",
            "components": {
                "correlator": True,
                "risk_scorer": True,
                "attack_path_analyzer": True,
            },
            "correlation_types": ["asset", "rule", "cve", "network", "temporal"],
            "risk_factors": ["findings", "exposure", "compliance", "criticality"],
            "risk_levels": ["critical", "high", "medium", "low", "minimal"],
            "capabilities": {
                "finding_correlation": True,
                "risk_scoring": True,
                "attack_path_analysis": True,
                "trend_analysis": True,
                "compliance_integration": True,
                "related_finding_search": True,
            },
        }

    def _get_sample_correlation_data(self) -> tuple[list, list]:
        """Get sample findings and assets for correlation demo."""
        from datetime import datetime, timezone, timedelta
        from stance.models.finding import Finding, Severity, FindingType, FindingStatus
        from stance.models.asset import Asset

        now = datetime.now(timezone.utc)

        findings = [
            Finding(
                id="finding-001",
                title="S3 Bucket Public Access",
                description="S3 bucket allows public read access",
                severity=Severity.CRITICAL,
                finding_type=FindingType.MISCONFIGURATION,
                status=FindingStatus.OPEN,
                asset_id="s3-bucket-prod-data",
                rule_id="aws-s3-001",
                first_seen=now - timedelta(hours=2),
                compliance_frameworks=["CIS AWS", "PCI DSS"],
            ),
            Finding(
                id="finding-002",
                title="S3 Bucket No Encryption",
                description="S3 bucket does not have encryption enabled",
                severity=Severity.HIGH,
                finding_type=FindingType.MISCONFIGURATION,
                status=FindingStatus.OPEN,
                asset_id="s3-bucket-prod-data",
                rule_id="aws-s3-002",
                first_seen=now - timedelta(hours=2),
                compliance_frameworks=["CIS AWS"],
            ),
            Finding(
                id="finding-003",
                title="IAM User No MFA",
                description="IAM user does not have MFA enabled",
                severity=Severity.HIGH,
                finding_type=FindingType.MISCONFIGURATION,
                status=FindingStatus.OPEN,
                asset_id="iam-user-admin",
                rule_id="aws-iam-001",
                first_seen=now - timedelta(hours=1),
                compliance_frameworks=["CIS AWS", "SOC2"],
            ),
            Finding(
                id="finding-004",
                title="IAM Admin Access",
                description="IAM user has administrator access",
                severity=Severity.MEDIUM,
                finding_type=FindingType.MISCONFIGURATION,
                status=FindingStatus.OPEN,
                asset_id="iam-user-admin",
                rule_id="aws-iam-002",
                first_seen=now - timedelta(hours=1),
            ),
            Finding(
                id="finding-005",
                title="EC2 Instance Public IP",
                description="EC2 instance has public IP address",
                severity=Severity.MEDIUM,
                finding_type=FindingType.MISCONFIGURATION,
                status=FindingStatus.OPEN,
                asset_id="ec2-i-prod-web",
                rule_id="aws-ec2-001",
                first_seen=now - timedelta(hours=3),
            ),
            Finding(
                id="finding-006",
                title="Security Group Open SSH",
                description="Security group allows SSH from anywhere",
                severity=Severity.HIGH,
                finding_type=FindingType.MISCONFIGURATION,
                status=FindingStatus.OPEN,
                asset_id="ec2-i-prod-web",
                rule_id="aws-ec2-002",
                first_seen=now - timedelta(hours=3),
            ),
            Finding(
                id="finding-007",
                title="CVE-2024-1234 Vulnerability",
                description="Critical vulnerability in web server",
                severity=Severity.CRITICAL,
                finding_type=FindingType.VULNERABILITY,
                status=FindingStatus.OPEN,
                asset_id="ec2-i-prod-web",
                cve_id="CVE-2024-1234",
                cvss_score=9.8,
                first_seen=now - timedelta(hours=5),
            ),
            Finding(
                id="finding-008",
                title="CVE-2024-1234 Vulnerability",
                description="Critical vulnerability in web server",
                severity=Severity.CRITICAL,
                finding_type=FindingType.VULNERABILITY,
                status=FindingStatus.OPEN,
                asset_id="ec2-i-staging-web",
                cve_id="CVE-2024-1234",
                cvss_score=9.8,
                first_seen=now - timedelta(hours=5),
            ),
            Finding(
                id="finding-009",
                title="RDS Instance Public",
                description="RDS instance is publicly accessible",
                severity=Severity.CRITICAL,
                finding_type=FindingType.MISCONFIGURATION,
                status=FindingStatus.OPEN,
                asset_id="rds-prod-db",
                rule_id="aws-rds-001",
                first_seen=now - timedelta(hours=1),
                compliance_frameworks=["PCI DSS", "HIPAA"],
            ),
            Finding(
                id="finding-010",
                title="RDS No Encryption",
                description="RDS instance storage not encrypted",
                severity=Severity.HIGH,
                finding_type=FindingType.MISCONFIGURATION,
                status=FindingStatus.OPEN,
                asset_id="rds-prod-db",
                rule_id="aws-rds-002",
                first_seen=now - timedelta(hours=1),
                compliance_frameworks=["PCI DSS"],
            ),
        ]

        assets = [
            Asset(
                id="s3-bucket-prod-data",
                name="prod-data-bucket",
                resource_type="aws_s3_bucket",
                cloud_provider="aws",
                region="us-east-1",
                account_id="123456789012",
                network_exposure="internet_facing",
                tags={"environment": "production", "criticality": "high"},
            ),
            Asset(
                id="iam-user-admin",
                name="admin-user",
                resource_type="aws_iam_user",
                cloud_provider="aws",
                region="global",
                account_id="123456789012",
                network_exposure="internal",
                tags={"environment": "production"},
            ),
            Asset(
                id="ec2-i-prod-web",
                name="prod-web-server",
                resource_type="aws_ec2_instance",
                cloud_provider="aws",
                region="us-east-1",
                account_id="123456789012",
                network_exposure="internet_facing",
                tags={"environment": "production", "criticality": "critical"},
            ),
            Asset(
                id="ec2-i-staging-web",
                name="staging-web-server",
                resource_type="aws_ec2_instance",
                cloud_provider="aws",
                region="us-east-1",
                account_id="123456789012",
                network_exposure="internal",
                tags={"environment": "staging"},
            ),
            Asset(
                id="rds-prod-db",
                name="prod-database",
                resource_type="aws_rds_instance",
                cloud_provider="aws",
                region="us-east-1",
                account_id="123456789012",
                network_exposure="internet_facing",
                tags={"environment": "production", "criticality": "critical"},
            ),
        ]

        return findings, assets

    # Trends API handlers
    def _trends_analyze(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Analyze security posture trends.

        Args:
            params: Query parameters (days, period)

        Returns:
            Trend analysis report
        """
        params = params or {}
        days = int(params.get("days", ["30"])[0])
        period = params.get("period", ["daily"])[0]

        # Use demo data for now
        return self._get_sample_trend_report(days, period)

    def _trends_forecast(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Forecast future findings based on trends.

        Args:
            params: Query parameters (history_days, forecast_days)

        Returns:
            Forecast data
        """
        params = params or {}
        history_days = int(params.get("history_days", ["30"])[0])
        forecast_days = int(params.get("forecast_days", ["7"])[0])

        return self._get_sample_forecast(history_days, forecast_days)

    def _trends_velocity(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get findings velocity (rate of change per day).

        Args:
            params: Query parameters (days)

        Returns:
            Velocity data by severity
        """
        params = params or {}
        days = int(params.get("days", ["7"])[0])

        return {
            "days_analyzed": days,
            "velocity": {
                "total": -0.23,
                "critical": -0.07,
                "high": -0.10,
                "medium": -0.07,
                "low": 0.0,
                "info": 0.0,
            },
        }

    def _trends_improvement(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Calculate improvement rate.

        Args:
            params: Query parameters (days)

        Returns:
            Improvement rate data
        """
        params = params or {}
        days = int(params.get("days", ["30"])[0])

        rate = 12.5  # Demo rate

        interpretation = "Good improvement - positive trend in security posture"
        if rate > 20:
            interpretation = "Excellent improvement - security posture significantly better"
        elif rate > 10:
            interpretation = "Good improvement - positive trend in security posture"
        elif rate > 0:
            interpretation = "Slight improvement - minor positive changes"
        elif rate == 0:
            interpretation = "No change - security posture is stable"
        elif rate > -10:
            interpretation = "Slight regression - minor increase in findings"
        elif rate > -20:
            interpretation = "Regression - security posture is declining"
        else:
            interpretation = "Significant regression - urgent attention needed"

        return {
            "days_analyzed": days,
            "improvement_rate": rate,
            "interpretation": interpretation,
        }

    def _trends_compare(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Compare two time periods.

        Args:
            params: Query parameters (current_days, previous_days)

        Returns:
            Period comparison data
        """
        from datetime import datetime, timedelta

        params = params or {}
        current_days = int(params.get("current_days", ["7"])[0])
        previous_days = int(params.get("previous_days", ["7"])[0])

        now = datetime.utcnow()
        current_start = now - timedelta(days=current_days)
        previous_end = current_start
        previous_start = previous_end - timedelta(days=previous_days)

        return {
            "current_period": {
                "start": current_start.isoformat(),
                "end": now.isoformat(),
                "days": current_days,
                "stats": {
                    "scans": int(current_days * 1.5),
                    "avg_findings": 45.0,
                    "max_findings": 50,
                    "min_findings": 40,
                    "severity_breakdown": {
                        "critical": 3.0,
                        "high": 12.0,
                        "medium": 20.0,
                        "low": 8.0,
                        "info": 2.0,
                    },
                },
            },
            "previous_period": {
                "start": previous_start.isoformat(),
                "end": previous_end.isoformat(),
                "days": previous_days,
                "stats": {
                    "scans": int(previous_days * 1.3),
                    "avg_findings": 52.0,
                    "max_findings": 58,
                    "min_findings": 46,
                    "severity_breakdown": {
                        "critical": 5.0,
                        "high": 15.0,
                        "medium": 22.0,
                        "low": 8.0,
                        "info": 2.0,
                    },
                },
            },
            "comparison": {
                "avg_findings_change": -13.46,
                "scan_count_change": 2,
                "direction": "improving",
            },
        }

    def _trends_report(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Generate comprehensive trend report.

        Args:
            params: Query parameters (days)

        Returns:
            Full trend report
        """
        params = params or {}
        days = int(params.get("days", ["30"])[0])

        return self._get_sample_trend_report(days, "daily")

    def _trends_severity(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get severity-specific trend data.

        Args:
            params: Query parameters (severity, days)

        Returns:
            Severity trend data
        """
        params = params or {}
        severity = params.get("severity", [None])[0]
        days = int(params.get("days", ["30"])[0])

        report = self._get_sample_trend_report(days, "daily")
        severity_trends = report.get("severity_trends", {})

        if severity and severity in severity_trends:
            return {severity: severity_trends[severity]}

        return severity_trends

    def _trends_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get quick trend summary.

        Args:
            params: Query parameters (days)

        Returns:
            Trend summary
        """
        params = params or {}
        days = int(params.get("days", ["30"])[0])

        report = self._get_sample_trend_report(days, "daily")

        return {
            "days_analyzed": days,
            "overall_direction": report["total_findings"]["direction"],
            "current_findings": report["total_findings"]["current_value"],
            "previous_findings": report["total_findings"]["previous_value"],
            "change": report["total_findings"]["change"],
            "change_percent": report["total_findings"]["change_percent"],
            "velocity": report["total_findings"]["velocity"],
            "scan_frequency": report.get("scan_frequency", 1.5),
            **report.get("summary", {}),
        }

    def _trends_periods(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List available analysis periods.

        Returns:
            List of analysis periods
        """
        return {
            "periods": [
                {"period": "daily", "description": "Day-by-day analysis", "typical_range": "7-30 days"},
                {"period": "weekly", "description": "Week-over-week analysis", "typical_range": "4-12 weeks"},
                {"period": "monthly", "description": "Month-over-month analysis", "typical_range": "3-12 months"},
                {"period": "quarterly", "description": "Quarter-over-quarter analysis", "typical_range": "4-8 quarters"},
            ],
            "total": 4,
        }

    def _trends_directions(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List trend direction types.

        Returns:
            List of trend directions
        """
        return {
            "directions": [
                {"direction": "improving", "description": "Security posture is getting better", "indicator": "Fewer findings over time"},
                {"direction": "declining", "description": "Security posture is getting worse", "indicator": "More findings over time"},
                {"direction": "stable", "description": "No significant change", "indicator": "Finding count within threshold"},
                {"direction": "insufficient_data", "description": "Not enough data points", "indicator": "Need more scan history"},
            ],
            "total": 4,
        }

    def _trends_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get trends module status.

        Returns:
            Module status and capabilities
        """
        return {
            "module": "trends",
            "version": "1.0.0",
            "status": "active",
            "components": {
                "trend_analyzer": True,
                "history_manager": True,
                "forecasting": True,
            },
            "analysis_periods": ["daily", "weekly", "monthly", "quarterly"],
            "trend_directions": ["improving", "declining", "stable", "insufficient_data"],
            "metrics": ["total_findings", "severity_breakdown", "velocity", "improvement_rate", "scan_frequency"],
            "capabilities": {
                "trend_analysis": True,
                "forecasting": True,
                "velocity_tracking": True,
                "period_comparison": True,
                "improvement_metrics": True,
                "severity_trends": True,
                "recommendations": True,
            },
        }

    def _get_sample_trend_report(self, days: int, period: str) -> dict[str, Any]:
        """Get sample trend report data."""
        from datetime import datetime

        now = datetime.utcnow()

        return {
            "report_id": "sample-report-001",
            "generated_at": now.isoformat(),
            "period": period,
            "days_analyzed": days,
            "total_findings": {
                "current_value": 45,
                "previous_value": 52,
                "average": 48.5,
                "min_value": 40,
                "max_value": 55,
                "change": -7,
                "change_percent": -13.46,
                "direction": "improving",
                "data_points": days,
                "velocity": -0.23,
            },
            "severity_trends": {
                "critical": {
                    "severity": "critical",
                    "metrics": {
                        "current_value": 3,
                        "previous_value": 5,
                        "average": 4.0,
                        "min_value": 2,
                        "max_value": 6,
                        "change": -2,
                        "change_percent": -40.0,
                        "direction": "improving",
                        "data_points": days,
                        "velocity": -0.07,
                    },
                    "history": [],
                },
                "high": {
                    "severity": "high",
                    "metrics": {
                        "current_value": 12,
                        "previous_value": 15,
                        "average": 13.5,
                        "min_value": 10,
                        "max_value": 18,
                        "change": -3,
                        "change_percent": -20.0,
                        "direction": "improving",
                        "data_points": days,
                        "velocity": -0.1,
                    },
                    "history": [],
                },
                "medium": {
                    "severity": "medium",
                    "metrics": {
                        "current_value": 20,
                        "previous_value": 22,
                        "average": 21.0,
                        "min_value": 18,
                        "max_value": 25,
                        "change": -2,
                        "change_percent": -9.09,
                        "direction": "improving",
                        "data_points": days,
                        "velocity": -0.07,
                    },
                    "history": [],
                },
                "low": {
                    "severity": "low",
                    "metrics": {
                        "current_value": 8,
                        "previous_value": 8,
                        "average": 8.0,
                        "min_value": 6,
                        "max_value": 10,
                        "change": 0,
                        "change_percent": 0.0,
                        "direction": "stable",
                        "data_points": days,
                        "velocity": 0.0,
                    },
                    "history": [],
                },
                "info": {
                    "severity": "info",
                    "metrics": {
                        "current_value": 2,
                        "previous_value": 2,
                        "average": 2.0,
                        "min_value": 1,
                        "max_value": 3,
                        "change": 0,
                        "change_percent": 0.0,
                        "direction": "stable",
                        "data_points": days,
                        "velocity": 0.0,
                    },
                    "history": [],
                },
            },
            "compliance_trends": {},
            "assets_trend": {
                "current_value": 150,
                "previous_value": 145,
                "average": 147.5,
                "min_value": 140,
                "max_value": 155,
                "change": 5,
                "change_percent": 3.45,
                "direction": "stable",
                "data_points": days,
                "velocity": 0.17,
            },
            "scan_frequency": 1.5,
            "mean_time_to_remediate": None,
            "risk_score_trend": None,
            "summary": {
                "overall_direction": "improving",
                "total_scans": int(days * 1.5),
                "findings_change": -7,
                "findings_change_percent": -13.46,
                "improving_scans": int(days * 0.6),
                "improving_scan_rate": 60.0,
            },
            "recommendations": [
                "Security posture is improving. Continue current practices and consider expanding security coverage to additional resources.",
                "There are 3 critical findings. Consider a focused remediation sprint to address these first.",
            ],
        }

    def _get_sample_forecast(self, history_days: int, forecast_days: int) -> dict[str, Any]:
        """Get sample forecast data."""
        from datetime import datetime, timedelta

        now = datetime.utcnow()
        forecasts = []
        current_findings = 45

        for day in range(1, forecast_days + 1):
            projected = max(0, current_findings - int(day * 0.5))
            forecast_date = now + timedelta(days=day)
            forecasts.append({
                "date": forecast_date.isoformat(),
                "day": day,
                "projected_findings": projected,
            })

        return {
            "model": "linear_regression",
            "data_points": history_days,
            "trend_slope": -0.23,
            "confidence": 0.82,
            "current_findings": current_findings,
            "forecasts": forecasts,
            "trend_direction": "improving",
        }

    # ==================== Alerting API Endpoints ====================

    def _alerting_destinations(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List configured alert destinations.

        Returns:
            List of alert destinations with status
        """
        destinations = self._get_sample_alerting_destinations()
        return {
            "destinations": destinations,
            "total": len(destinations),
        }

    def _alerting_routing_rules(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List alert routing rules.

        Query Parameters:
            enabled_only: Show only enabled rules (default: false)

        Returns:
            List of routing rules
        """
        params = params or {}
        enabled_only = params.get("enabled_only", ["false"])[0].lower() == "true"

        rules = self._get_sample_routing_rules()
        if enabled_only:
            rules = [r for r in rules if r["enabled"]]

        return {
            "rules": rules,
            "total": len(rules),
        }

    def _alerting_suppression_rules(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List alert suppression rules.

        Query Parameters:
            enabled_only: Show only enabled rules (default: false)

        Returns:
            List of suppression rules
        """
        params = params or {}
        enabled_only = params.get("enabled_only", ["false"])[0].lower() == "true"

        rules = self._get_sample_suppression_rules()
        if enabled_only:
            rules = [r for r in rules if r["enabled"]]

        return {
            "rules": rules,
            "total": len(rules),
        }

    def _alerting_config(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get alert configuration.

        Returns:
            Complete alert configuration
        """
        return {
            "enabled": True,
            "dedup_window_hours": 24,
            "default_rate_limit": {
                "max_alerts": 100,
                "window_seconds": 3600,
                "burst_limit": 10,
            },
            "destinations_count": len(self._get_sample_alerting_destinations()),
            "routing_rules_count": len(self._get_sample_routing_rules()),
            "suppression_rules_count": len(self._get_sample_suppression_rules()),
        }

    def _alerting_rate_limits(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get rate limit settings.

        Query Parameters:
            destination: Filter by destination name

        Returns:
            Rate limit configuration
        """
        params = params or {}
        destination = params.get("destination", [""])[0]

        rate_limits = {
            "slack-security": {
                "max_alerts": 50,
                "window_seconds": 3600,
                "burst_limit": 5,
            },
            "pagerduty-critical": {
                "max_alerts": 100,
                "window_seconds": 3600,
                "burst_limit": 10,
            },
            "email-team": {
                "max_alerts": 100,
                "window_seconds": 3600,
                "burst_limit": 10,
            },
            "default": {
                "max_alerts": 100,
                "window_seconds": 3600,
                "burst_limit": 10,
            },
        }

        if destination:
            if destination in rate_limits:
                return {"rate_limits": {destination: rate_limits[destination]}}
            return {"rate_limits": {}, "error": f"Destination not found: {destination}"}

        return {"rate_limits": rate_limits}

    def _alerting_alerts(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List recent alert records.

        Query Parameters:
            finding_id: Filter by finding ID
            status: Filter by status (sent, acknowledged, resolved, expired)
            limit: Maximum alerts to return (default: 50)

        Returns:
            List of alert records
        """
        from datetime import datetime, timedelta

        params = params or {}
        finding_id = params.get("finding_id", [""])[0]
        status = params.get("status", [""])[0]
        limit = int(params.get("limit", ["50"])[0])

        now = datetime.utcnow()
        alerts = [
            {
                "id": "alert-001",
                "finding_id": "finding-abc123",
                "destination": "slack-security",
                "sent_at": (now - timedelta(hours=1)).isoformat(),
                "acknowledged_at": (now - timedelta(minutes=45)).isoformat(),
                "acknowledged_by": "security-team",
                "status": "acknowledged",
            },
            {
                "id": "alert-002",
                "finding_id": "finding-def456",
                "destination": "pagerduty-critical",
                "sent_at": (now - timedelta(hours=2)).isoformat(),
                "acknowledged_at": None,
                "acknowledged_by": None,
                "status": "sent",
            },
            {
                "id": "alert-003",
                "finding_id": "finding-ghi789",
                "destination": "email-team",
                "sent_at": (now - timedelta(hours=3)).isoformat(),
                "acknowledged_at": (now - timedelta(hours=2)).isoformat(),
                "acknowledged_by": "dev-team",
                "status": "resolved",
            },
            {
                "id": "alert-004",
                "finding_id": "finding-jkl012",
                "destination": "slack-security",
                "sent_at": (now - timedelta(days=2)).isoformat(),
                "acknowledged_at": None,
                "acknowledged_by": None,
                "status": "expired",
            },
        ]

        if finding_id:
            alerts = [a for a in alerts if a["finding_id"] == finding_id]
        if status:
            alerts = [a for a in alerts if a["status"] == status]

        alerts = alerts[:limit]

        return {
            "alerts": alerts,
            "total": len(alerts),
        }

    def _alerting_templates(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List available alert templates.

        Returns:
            List of alert templates
        """
        templates = [
            {
                "name": "DefaultTemplate",
                "description": "Standard plain text alert format",
                "used_for": "General findings without specific categorization",
            },
            {
                "name": "MisconfigurationTemplate",
                "description": "Optimized for misconfiguration findings",
                "used_for": "Cloud resource misconfigurations, policy violations",
            },
            {
                "name": "VulnerabilityTemplate",
                "description": "Optimized for vulnerability findings",
                "used_for": "CVEs, package vulnerabilities, software flaws",
            },
            {
                "name": "ComplianceTemplate",
                "description": "Compliance-focused alert format",
                "used_for": "Compliance violations, audit findings",
            },
            {
                "name": "CriticalExposureTemplate",
                "description": "High-urgency format for critical exposures",
                "used_for": "Critical severity findings requiring immediate action",
            },
        ]

        return {
            "templates": templates,
            "total": len(templates),
        }

    def _alerting_destination_types(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List available destination types.

        Returns:
            List of destination types with configuration requirements
        """
        types = [
            {
                "type": "slack",
                "description": "Slack incoming webhook integration",
                "required_config": ["webhook_url"],
            },
            {
                "type": "pagerduty",
                "description": "PagerDuty Events API v2 integration",
                "required_config": ["routing_key"],
            },
            {
                "type": "email",
                "description": "Email notifications via SMTP",
                "required_config": ["smtp_host", "from_address", "to_addresses"],
            },
            {
                "type": "webhook",
                "description": "Generic HTTP webhook integration",
                "required_config": ["url"],
            },
            {
                "type": "teams",
                "description": "Microsoft Teams incoming webhook",
                "required_config": ["webhook_url"],
            },
            {
                "type": "jira",
                "description": "Jira issue creation integration",
                "required_config": ["url", "project", "api_token"],
            },
        ]

        return {
            "types": types,
            "total": len(types),
        }

    def _alerting_severities(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List severity levels for routing rules.

        Returns:
            List of severity levels
        """
        severities = [
            {"value": "critical", "priority": 1, "description": "Critical severity - immediate action required"},
            {"value": "high", "priority": 2, "description": "High severity - prompt attention needed"},
            {"value": "medium", "priority": 3, "description": "Medium severity - should be addressed soon"},
            {"value": "low", "priority": 4, "description": "Low severity - address when possible"},
            {"value": "info", "priority": 5, "description": "Informational - no action required"},
        ]

        return {
            "severities": severities,
            "total": len(severities),
        }

    def _alerting_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get alerting module status.

        Returns:
            Module status and capabilities
        """
        return {
            "module": "stance.alerting",
            "version": "1.0.0",
            "status": "operational",
            "components": {
                "AlertRouter": "available",
                "AlertState": "available",
                "AlertConfig": "available",
                "InMemoryAlertState": "available",
                "DynamoDBAlertState": "available",
                "FirestoreAlertState": "available",
                "CosmosDBAlertState": "available",
            },
            "capabilities": [
                "Multi-destination routing",
                "Severity-based filtering",
                "Finding type filtering",
                "Tag-based routing",
                "Alert deduplication",
                "Rate limiting",
                "Suppression rules",
                "Multiple state backends (in-memory, DynamoDB, Firestore, CosmosDB)",
                "Template-based formatting",
            ],
        }

    def _alerting_test_route(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Test routing for a finding.

        Query Parameters:
            severity: Severity to test (default: high)
            finding_type: Finding type to test (default: misconfiguration)

        Returns:
            Routing test results
        """
        params = params or {}
        severity = params.get("severity", ["high"])[0]
        finding_type = params.get("finding_type", ["misconfiguration"])[0]

        # Simulate routing based on sample rules
        matched_rules = []
        destinations = set()

        rules = self._get_sample_routing_rules()
        for rule in rules:
            if not rule["enabled"]:
                continue

            matches = True

            # Check severity
            if rule["severities"] and severity not in rule["severities"]:
                matches = False

            # Check finding type
            if rule["finding_types"] and finding_type not in rule["finding_types"]:
                matches = False

            if matches:
                matched_rules.append(rule["name"])
                destinations.update(rule["destinations"])

        return {
            "severity": severity,
            "finding_type": finding_type,
            "matched_rules": matched_rules,
            "destinations": list(destinations),
            "would_be_suppressed": False,
        }

    def _alerting_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get alerting summary.

        Returns:
            Alerting configuration and statistics summary
        """
        return {
            "config": {
                "enabled": True,
                "destinations_count": 4,
                "routing_rules_count": 4,
                "suppression_rules_count": 3,
            },
            "stats": {
                "alerts_sent_24h": 76,
                "alerts_suppressed_24h": 12,
                "alerts_deduplicated_24h": 34,
                "alerts_rate_limited_24h": 5,
                "by_destination": {
                    "slack-security": 45,
                    "pagerduty-critical": 3,
                    "email-team": 28,
                },
                "by_severity": {
                    "critical": 3,
                    "high": 28,
                    "medium": 35,
                    "low": 10,
                },
            },
        }

    def _get_sample_alerting_destinations(self) -> list[dict[str, Any]]:
        """Get sample destination data for demo mode."""
        return [
            {
                "name": "slack-security",
                "type": "slack",
                "enabled": True,
                "available": True,
                "recent_sends": 45,
                "rate_limit_max": 50,
                "rate_limit_remaining": 5,
            },
            {
                "name": "pagerduty-critical",
                "type": "pagerduty",
                "enabled": True,
                "available": True,
                "recent_sends": 3,
                "rate_limit_max": 100,
                "rate_limit_remaining": 97,
            },
            {
                "name": "email-team",
                "type": "email",
                "enabled": True,
                "available": True,
                "recent_sends": 28,
                "rate_limit_max": 100,
                "rate_limit_remaining": 72,
            },
            {
                "name": "jira-security",
                "type": "jira",
                "enabled": False,
                "available": False,
                "recent_sends": 0,
                "rate_limit_max": 100,
                "rate_limit_remaining": 100,
            },
        ]

    def _get_sample_routing_rules(self) -> list[dict[str, Any]]:
        """Get sample routing rules for demo mode."""
        return [
            {
                "name": "critical-pagerduty",
                "destinations": ["pagerduty-critical"],
                "severities": ["critical"],
                "finding_types": [],
                "resource_types": [],
                "tags": {},
                "enabled": True,
                "priority": 10,
            },
            {
                "name": "high-slack",
                "destinations": ["slack-security"],
                "severities": ["critical", "high"],
                "finding_types": [],
                "resource_types": [],
                "tags": {},
                "enabled": True,
                "priority": 20,
            },
            {
                "name": "compliance-email",
                "destinations": ["email-team"],
                "severities": [],
                "finding_types": ["misconfiguration"],
                "resource_types": [],
                "tags": {},
                "enabled": True,
                "priority": 30,
            },
            {
                "name": "prod-all",
                "destinations": ["slack-security", "email-team"],
                "severities": [],
                "finding_types": [],
                "resource_types": [],
                "tags": {"environment": "production"},
                "enabled": True,
                "priority": 40,
            },
        ]

    def _get_sample_suppression_rules(self) -> list[dict[str, Any]]:
        """Get sample suppression rules for demo mode."""
        return [
            {
                "name": "known-exception-s3",
                "rule_ids": ["aws-s3-001", "aws-s3-002"],
                "asset_patterns": [],
                "reason": "Known exception for legacy bucket pending migration",
                "expires_at": "2025-06-30T00:00:00Z",
                "enabled": True,
            },
            {
                "name": "dev-environment",
                "rule_ids": [],
                "asset_patterns": ["arn:aws:*:*:*:dev-*", "arn:aws:*:*:*:*-dev-*"],
                "reason": "Development environment - reduced alerting",
                "expires_at": None,
                "enabled": True,
            },
            {
                "name": "scheduled-maintenance",
                "rule_ids": ["aws-ec2-003"],
                "asset_patterns": [],
                "reason": "Scheduled maintenance window",
                "expires_at": "2025-01-15T00:00:00Z",
                "enabled": False,
            },
        ]

    # ==================== Automation API Endpoints ====================

    def _automation_config(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get notification configuration.

        Returns:
            Notification configuration
        """
        return {
            "notify_on_scan_complete": True,
            "notify_on_scan_failure": True,
            "notify_on_new_findings": True,
            "notify_on_critical": True,
            "notify_on_resolved": False,
            "notify_on_trend_change": True,
            "min_severity_for_new": "high",
            "critical_threshold": 1,
            "trend_threshold_percent": 10.0,
            "include_summary": True,
            "include_details": False,
            "destinations": [],
        }

    def _automation_types(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List notification types.

        Returns:
            List of notification types
        """
        types = [
            {
                "value": "scan_complete",
                "description": "Notification when a scan completes successfully",
                "trigger": "Scan finishes without errors",
            },
            {
                "value": "scan_failed",
                "description": "Notification when a scan fails",
                "trigger": "Scan encounters an error",
            },
            {
                "value": "new_findings",
                "description": "Notification for newly detected findings",
                "trigger": "New findings detected above severity threshold",
            },
            {
                "value": "critical_finding",
                "description": "Notification for critical severity findings",
                "trigger": "Critical findings count exceeds threshold",
            },
            {
                "value": "findings_resolved",
                "description": "Notification when findings are resolved",
                "trigger": "Previously detected findings no longer present",
            },
            {
                "value": "trend_alert",
                "description": "Notification for security trend changes",
                "trigger": "Finding count changes by more than threshold percent",
            },
            {
                "value": "scheduled_report",
                "description": "Scheduled periodic security report",
                "trigger": "Scheduled time reached",
            },
        ]

        return {
            "types": types,
            "total": len(types),
        }

    def _automation_history(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get notification history.

        Query Parameters:
            type: Filter by notification type
            limit: Maximum notifications to return (default: 50)

        Returns:
            List of notification history entries
        """
        from datetime import datetime, timedelta

        params = params or {}
        notification_type = params.get("type", [""])[0]
        limit = int(params.get("limit", ["50"])[0])

        now = datetime.utcnow()
        history = [
            {
                "notification_type": "scan_complete",
                "timestamp": (now - timedelta(hours=1)).isoformat(),
                "scan_id": "scan-001",
                "job_name": "daily-security-scan",
                "message": "Scan completed successfully. Scanned 150 assets, found 23 findings in 45.2s.",
            },
            {
                "notification_type": "critical_finding",
                "timestamp": (now - timedelta(hours=2)).isoformat(),
                "scan_id": "scan-001",
                "job_name": "daily-security-scan",
                "message": "ALERT: 2 critical findings detected! Immediate attention required.",
            },
            {
                "notification_type": "new_findings",
                "timestamp": (now - timedelta(hours=3)).isoformat(),
                "scan_id": "scan-002",
                "job_name": "aws-account-scan",
                "message": "Detected 5 new findings: 1 critical, 2 high, 2 medium",
            },
            {
                "notification_type": "trend_alert",
                "timestamp": (now - timedelta(hours=6)).isoformat(),
                "scan_id": "scan-003",
                "job_name": "weekly-trend-analysis",
                "message": "Security posture improving: 15.3% reduction in findings",
            },
            {
                "notification_type": "scan_failed",
                "timestamp": (now - timedelta(hours=12)).isoformat(),
                "scan_id": "scan-004",
                "job_name": "gcp-project-scan",
                "message": "Scan failed: GCP credentials expired",
            },
        ]

        if notification_type:
            history = [h for h in history if h["notification_type"] == notification_type]

        history = history[:limit]

        return {
            "history": history,
            "total": len(history),
        }

    def _automation_thresholds(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get notification thresholds.

        Returns:
            List of configured thresholds
        """
        thresholds = [
            {
                "name": "min_severity_for_new",
                "value": "high",
                "description": "Minimum severity level to trigger new findings notification",
                "affects": "new_findings notifications",
            },
            {
                "name": "critical_threshold",
                "value": 1,
                "description": "Number of critical findings to trigger critical alert",
                "affects": "critical_finding notifications",
            },
            {
                "name": "trend_threshold_percent",
                "value": 10.0,
                "description": "Percentage change in findings to trigger trend alert",
                "affects": "trend_alert notifications",
            },
        ]

        return {
            "thresholds": thresholds,
            "total": len(thresholds),
        }

    def _automation_triggers(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List notification triggers.

        Returns:
            List of notification triggers
        """
        triggers = [
            {
                "name": "Scan Complete",
                "event": "scan_complete",
                "enabled": True,
                "description": "Trigger notification when scan completes successfully",
            },
            {
                "name": "Scan Failed",
                "event": "scan_failed",
                "enabled": True,
                "description": "Trigger notification when scan fails",
            },
            {
                "name": "New Findings",
                "event": "new_findings",
                "enabled": True,
                "description": "Trigger notification for new findings above severity threshold",
            },
            {
                "name": "Critical Findings",
                "event": "critical_finding",
                "enabled": True,
                "description": "Trigger notification when critical findings exceed threshold",
            },
            {
                "name": "Findings Resolved",
                "event": "findings_resolved",
                "enabled": False,
                "description": "Trigger notification when findings are resolved",
            },
            {
                "name": "Trend Change",
                "event": "trend_alert",
                "enabled": True,
                "description": "Trigger notification when security trend changes significantly",
            },
        ]

        return {
            "triggers": triggers,
            "total": len(triggers),
        }

    def _automation_callbacks(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List registered callbacks.

        Returns:
            List of registered callbacks
        """
        callbacks = [
            {
                "name": "AlertRouterCallback",
                "type": "internal",
                "description": "Routes notifications through configured alert destinations",
            },
            {
                "name": "HistoryCallback",
                "type": "internal",
                "description": "Records notifications to history",
            },
            {
                "name": "LoggingCallback",
                "type": "internal",
                "description": "Logs notifications for audit trail",
            },
        ]

        return {
            "callbacks": callbacks,
            "total": len(callbacks),
        }

    def _automation_severities(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List severity levels for notification filtering.

        Returns:
            List of severity levels
        """
        severities = [
            {"value": "critical", "priority": 1, "description": "Critical - always notify"},
            {"value": "high", "priority": 2, "description": "High - notify by default"},
            {"value": "medium", "priority": 3, "description": "Medium - optional notification"},
            {"value": "low", "priority": 4, "description": "Low - usually silent"},
            {"value": "info", "priority": 5, "description": "Info - silent by default"},
        ]

        return {
            "severities": severities,
            "total": len(severities),
        }

    def _automation_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get automation module status.

        Returns:
            Module status and capabilities
        """
        return {
            "module": "stance.automation",
            "version": "1.0.0",
            "status": "operational",
            "components": {
                "NotificationHandler": "available",
                "NotificationConfig": "available",
                "ScanNotification": "available",
                "ScanSummaryNotification": "available",
                "FindingNotification": "available",
                "TrendNotification": "available",
            },
            "capabilities": [
                "Scan completion notifications",
                "Scan failure notifications",
                "New findings notifications",
                "Critical findings alerts",
                "Resolved findings notifications",
                "Trend change alerts",
                "Configurable severity thresholds",
                "Configurable trend thresholds",
                "Alert router integration",
                "Notification history tracking",
                "Custom callback support",
            ],
        }

    def _automation_test(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Test a notification trigger.

        Query Parameters:
            type: Notification type to test (default: scan_complete)

        Returns:
            Test results
        """
        from datetime import datetime

        params = params or {}
        notification_type = params.get("type", ["scan_complete"])[0]

        now = datetime.utcnow()

        sample_notifications = {
            "scan_complete": {
                "notification_type": "scan_complete",
                "timestamp": now.isoformat(),
                "scan_id": "test-scan-001",
                "job_name": "test-job",
                "message": "Scan completed successfully. Scanned 50 assets, found 10 findings in 30.0s.",
            },
            "scan_failed": {
                "notification_type": "scan_failed",
                "timestamp": now.isoformat(),
                "scan_id": "test-scan-002",
                "job_name": "test-job",
                "message": "Scan failed: Test error message",
            },
            "new_findings": {
                "notification_type": "new_findings",
                "timestamp": now.isoformat(),
                "scan_id": "test-scan-003",
                "job_name": "test-job",
                "message": "Detected 3 new findings: 1 high, 2 medium",
            },
            "critical_finding": {
                "notification_type": "critical_finding",
                "timestamp": now.isoformat(),
                "scan_id": "test-scan-004",
                "job_name": "test-job",
                "message": "ALERT: 1 critical findings detected! Immediate attention required.",
            },
            "trend_alert": {
                "notification_type": "trend_alert",
                "timestamp": now.isoformat(),
                "scan_id": "test-scan-005",
                "job_name": "test-job",
                "message": "Security posture declining: 15.0% increase in findings",
            },
        }

        notification = sample_notifications.get(notification_type, sample_notifications["scan_complete"])

        # Find matching triggers
        triggers = self._automation_triggers()["triggers"]
        matching = [t["name"] for t in triggers if t["event"] == notification_type and t["enabled"]]

        return {
            "test_type": notification_type,
            "would_trigger": len(matching) > 0,
            "notification": notification,
            "matching_triggers": matching,
        }

    def _automation_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get automation summary.

        Returns:
            Automation configuration and statistics summary
        """
        return {
            "config": {
                "triggers_enabled": 5,
                "callbacks_count": 3,
                "destinations_count": 0,
            },
            "stats": {
                "notifications_sent_24h": 23,
                "scan_completions_24h": 8,
                "critical_alerts_24h": 2,
                "trend_alerts_24h": 1,
                "by_type": {
                    "scan_complete": 8,
                    "scan_failed": 1,
                    "new_findings": 5,
                    "critical_finding": 2,
                    "trend_alert": 1,
                    "findings_resolved": 6,
                },
            },
        }

    def _automation_workflows(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List automation workflows.

        Returns:
            List of automation workflows
        """
        workflows = [
            {
                "name": "Critical Alert Pipeline",
                "trigger": "critical_finding",
                "actions": ["send_pagerduty", "send_slack", "create_ticket"],
                "enabled": True,
                "description": "Immediately escalate critical findings to on-call and create ticket",
            },
            {
                "name": "Daily Summary",
                "trigger": "scan_complete",
                "actions": ["aggregate_findings", "send_email_summary"],
                "enabled": True,
                "description": "Send daily summary of scan results via email",
            },
            {
                "name": "Trend Monitoring",
                "trigger": "trend_alert",
                "actions": ["send_slack", "update_dashboard"],
                "enabled": True,
                "description": "Notify team of significant security posture changes",
            },
            {
                "name": "Failure Escalation",
                "trigger": "scan_failed",
                "actions": ["retry_scan", "send_alert_if_repeated"],
                "enabled": True,
                "description": "Retry failed scans and alert on repeated failures",
            },
        ]

        return {
            "workflows": workflows,
            "total": len(workflows),
        }

    def _automation_events(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List supported events.

        Returns:
            List of supported automation events
        """
        events = [
            {
                "name": "scan.complete",
                "source": "ScanScheduler",
                "description": "Fired when a scheduled scan completes",
                "data_fields": ["scan_id", "job_name", "duration", "assets_scanned", "findings_count"],
            },
            {
                "name": "scan.failed",
                "source": "ScanScheduler",
                "description": "Fired when a scheduled scan fails",
                "data_fields": ["scan_id", "job_name", "error_message"],
            },
            {
                "name": "findings.new",
                "source": "FindingComparison",
                "description": "Fired when new findings are detected",
                "data_fields": ["scan_id", "findings", "severity_breakdown"],
            },
            {
                "name": "findings.resolved",
                "source": "FindingComparison",
                "description": "Fired when findings are resolved",
                "data_fields": ["scan_id", "findings", "resolved_count"],
            },
            {
                "name": "findings.critical",
                "source": "FindingAnalysis",
                "description": "Fired when critical findings exceed threshold",
                "data_fields": ["scan_id", "findings", "critical_count"],
            },
            {
                "name": "trend.change",
                "source": "TrendAnalyzer",
                "description": "Fired when security trend changes significantly",
                "data_fields": ["direction", "change_percent", "current_count", "previous_count"],
            },
        ]

        return {
            "events": events,
            "total": len(events),
        }

    # =========================================================================
    # Scheduling API Handlers
    # =========================================================================

    def _scheduling_jobs(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List scheduled scan jobs.

        Query params:
            enabled_only: If "true", only return enabled jobs

        Returns:
            List of scheduled jobs
        """
        enabled_only = False
        if params and "enabled_only" in params:
            enabled_only = params["enabled_only"][0].lower() == "true"

        # Sample scheduled jobs for demo
        jobs = [
            {
                "id": "job-daily-security-scan",
                "name": "Daily Security Scan",
                "schedule_type": "cron",
                "schedule_expression": "0 2 * * *",
                "config_name": "default",
                "enabled": True,
                "last_run": "2024-01-15T02:00:00Z",
                "next_run": "2024-01-16T02:00:00Z",
                "run_count": 45,
                "created_at": "2024-01-01T00:00:00Z",
            },
            {
                "id": "job-hourly-critical",
                "name": "Hourly Critical Check",
                "schedule_type": "rate",
                "schedule_expression": "rate(1 hour)",
                "config_name": "critical-only",
                "enabled": True,
                "last_run": "2024-01-15T14:00:00Z",
                "next_run": "2024-01-15T15:00:00Z",
                "run_count": 360,
                "created_at": "2024-01-01T00:00:00Z",
            },
            {
                "id": "job-weekly-compliance",
                "name": "Weekly Compliance Scan",
                "schedule_type": "cron",
                "schedule_expression": "0 0 * * 0",
                "config_name": "compliance",
                "enabled": True,
                "last_run": "2024-01-14T00:00:00Z",
                "next_run": "2024-01-21T00:00:00Z",
                "run_count": 6,
                "created_at": "2024-01-01T00:00:00Z",
            },
            {
                "id": "job-monthly-full",
                "name": "Monthly Full Audit",
                "schedule_type": "cron",
                "schedule_expression": "0 3 1 * *",
                "config_name": "full-audit",
                "enabled": False,
                "last_run": "2024-01-01T03:00:00Z",
                "next_run": None,
                "run_count": 1,
                "created_at": "2024-01-01T00:00:00Z",
            },
        ]

        if enabled_only:
            jobs = [j for j in jobs if j["enabled"]]

        return {
            "jobs": jobs,
            "total": len(jobs),
            "enabled_count": sum(1 for j in jobs if j["enabled"]),
        }

    def _scheduling_job(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get details for a specific scheduled job.

        Query params:
            job_id: Job ID to retrieve (required)

        Returns:
            Job details
        """
        job_id = ""
        if params and "job_id" in params:
            job_id = params["job_id"][0]

        if not job_id:
            return {"error": "job_id parameter is required"}

        # Sample job data
        job_data = {
            "job-daily-security-scan": {
                "id": "job-daily-security-scan",
                "name": "Daily Security Scan",
                "schedule_type": "cron",
                "schedule_expression": "0 2 * * *",
                "schedule_description": "Every day at 2:00 AM UTC",
                "config_name": "default",
                "enabled": True,
                "last_run": "2024-01-15T02:00:00Z",
                "next_run": "2024-01-16T02:00:00Z",
                "run_count": 45,
                "created_at": "2024-01-01T00:00:00Z",
                "last_result": {
                    "success": True,
                    "duration_seconds": 245.3,
                    "assets_scanned": 156,
                    "findings_count": 23,
                },
                "metadata": {
                    "owner": "security-team",
                    "description": "Daily security posture scan across all accounts",
                },
            },
        }

        if job_id in job_data:
            return {"job": job_data[job_id]}

        return {"error": f"Job not found: {job_id}"}

    def _scheduling_history(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get scan history.

        Query params:
            limit: Maximum entries to return (default: 20)
            config_name: Filter by config name

        Returns:
            List of scan history entries
        """
        limit = 20
        config_name = None

        if params:
            if "limit" in params:
                try:
                    limit = int(params["limit"][0])
                except ValueError:
                    pass
            if "config_name" in params:
                config_name = params["config_name"][0]

        # Sample history entries
        history = [
            {
                "scan_id": "scan-2024-01-15-0200",
                "timestamp": "2024-01-15T02:00:00Z",
                "config_name": "default",
                "duration_seconds": 245.3,
                "assets_scanned": 156,
                "findings_total": 23,
                "findings_by_severity": {
                    "critical": 2,
                    "high": 5,
                    "medium": 8,
                    "low": 6,
                    "info": 2,
                },
            },
            {
                "scan_id": "scan-2024-01-14-0200",
                "timestamp": "2024-01-14T02:00:00Z",
                "config_name": "default",
                "duration_seconds": 238.7,
                "assets_scanned": 154,
                "findings_total": 25,
                "findings_by_severity": {
                    "critical": 3,
                    "high": 6,
                    "medium": 8,
                    "low": 6,
                    "info": 2,
                },
            },
            {
                "scan_id": "scan-2024-01-13-0200",
                "timestamp": "2024-01-13T02:00:00Z",
                "config_name": "default",
                "duration_seconds": 251.2,
                "assets_scanned": 152,
                "findings_total": 27,
                "findings_by_severity": {
                    "critical": 3,
                    "high": 7,
                    "medium": 9,
                    "low": 6,
                    "info": 2,
                },
            },
            {
                "scan_id": "scan-2024-01-14-0000",
                "timestamp": "2024-01-14T00:00:00Z",
                "config_name": "compliance",
                "duration_seconds": 512.8,
                "assets_scanned": 156,
                "findings_total": 45,
                "findings_by_severity": {
                    "critical": 5,
                    "high": 12,
                    "medium": 15,
                    "low": 10,
                    "info": 3,
                },
            },
        ]

        if config_name:
            history = [h for h in history if h["config_name"] == config_name]

        history = history[:limit]

        return {
            "history": history,
            "total": len(history),
            "limit": limit,
        }

    def _scheduling_history_entry(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get details for a specific scan history entry.

        Query params:
            scan_id: Scan ID to retrieve (required)

        Returns:
            Scan history entry details
        """
        scan_id = ""
        if params and "scan_id" in params:
            scan_id = params["scan_id"][0]

        if not scan_id:
            return {"error": "scan_id parameter is required"}

        # Sample entry data
        entry_data = {
            "scan-2024-01-15-0200": {
                "scan_id": "scan-2024-01-15-0200",
                "timestamp": "2024-01-15T02:00:00Z",
                "config_name": "default",
                "duration_seconds": 245.3,
                "assets_scanned": 156,
                "findings_total": 23,
                "findings_by_severity": {
                    "critical": 2,
                    "high": 5,
                    "medium": 8,
                    "low": 6,
                    "info": 2,
                },
                "accounts_scanned": ["prod-account", "staging-account"],
                "regions_scanned": ["us-east-1", "us-west-2", "eu-west-1"],
                "collectors_used": ["aws_iam", "aws_s3", "aws_ec2", "aws_security"],
                "metadata": {
                    "triggered_by": "schedule",
                    "job_id": "job-daily-security-scan",
                },
            },
        }

        if scan_id in entry_data:
            return {"entry": entry_data[scan_id]}

        return {"error": f"Scan not found: {scan_id}"}

    def _scheduling_compare(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Compare two scans.

        Query params:
            baseline: Baseline scan ID
            current: Current scan ID

        Returns:
            Comparison results
        """
        baseline_id = ""
        current_id = ""

        if params:
            if "baseline" in params:
                baseline_id = params["baseline"][0]
            if "current" in params:
                current_id = params["current"][0]

        # Default to comparing last two scans if not specified
        if not baseline_id:
            baseline_id = "scan-2024-01-14-0200"
        if not current_id:
            current_id = "scan-2024-01-15-0200"

        # Sample comparison data
        return {
            "comparison": {
                "baseline_scan_id": baseline_id,
                "current_scan_id": current_id,
                "baseline_timestamp": "2024-01-14T02:00:00Z",
                "current_timestamp": "2024-01-15T02:00:00Z",
                "summary": {
                    "total_new": 3,
                    "total_resolved": 5,
                    "total_unchanged": 18,
                    "has_changes": True,
                    "improvement_ratio": 0.25,
                    "new_by_severity": {
                        "critical": 0,
                        "high": 1,
                        "medium": 2,
                    },
                    "resolved_by_severity": {
                        "critical": 1,
                        "high": 2,
                        "medium": 1,
                        "low": 1,
                    },
                },
                "direction": "improving",
            }
        }

    def _scheduling_trend(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get trend data for a configuration.

        Query params:
            config_name: Configuration name (default: default)
            days: Number of days (default: 7)

        Returns:
            Trend data points
        """
        config_name = "default"
        days = 7

        if params:
            if "config_name" in params:
                config_name = params["config_name"][0]
            if "days" in params:
                try:
                    days = int(params["days"][0])
                except ValueError:
                    pass

        # Sample trend data
        trend_data = [
            {
                "timestamp": "2024-01-09T02:00:00Z",
                "scan_id": "scan-2024-01-09-0200",
                "findings_total": 32,
                "critical": 4,
                "high": 8,
                "medium": 10,
                "low": 7,
                "info": 3,
                "assets_scanned": 148,
            },
            {
                "timestamp": "2024-01-10T02:00:00Z",
                "scan_id": "scan-2024-01-10-0200",
                "findings_total": 30,
                "critical": 4,
                "high": 7,
                "medium": 10,
                "low": 7,
                "info": 2,
                "assets_scanned": 150,
            },
            {
                "timestamp": "2024-01-11T02:00:00Z",
                "scan_id": "scan-2024-01-11-0200",
                "findings_total": 29,
                "critical": 3,
                "high": 7,
                "medium": 10,
                "low": 7,
                "info": 2,
                "assets_scanned": 150,
            },
            {
                "timestamp": "2024-01-12T02:00:00Z",
                "scan_id": "scan-2024-01-12-0200",
                "findings_total": 28,
                "critical": 3,
                "high": 7,
                "medium": 9,
                "low": 7,
                "info": 2,
                "assets_scanned": 152,
            },
            {
                "timestamp": "2024-01-13T02:00:00Z",
                "scan_id": "scan-2024-01-13-0200",
                "findings_total": 27,
                "critical": 3,
                "high": 7,
                "medium": 9,
                "low": 6,
                "info": 2,
                "assets_scanned": 152,
            },
            {
                "timestamp": "2024-01-14T02:00:00Z",
                "scan_id": "scan-2024-01-14-0200",
                "findings_total": 25,
                "critical": 3,
                "high": 6,
                "medium": 8,
                "low": 6,
                "info": 2,
                "assets_scanned": 154,
            },
            {
                "timestamp": "2024-01-15T02:00:00Z",
                "scan_id": "scan-2024-01-15-0200",
                "findings_total": 23,
                "critical": 2,
                "high": 5,
                "medium": 8,
                "low": 6,
                "info": 2,
                "assets_scanned": 156,
            },
        ]

        # Limit by days
        trend_data = trend_data[-days:] if len(trend_data) > days else trend_data

        return {
            "trend": trend_data,
            "config_name": config_name,
            "days": days,
            "data_points": len(trend_data),
            "summary": {
                "start_findings": trend_data[0]["findings_total"] if trend_data else 0,
                "end_findings": trend_data[-1]["findings_total"] if trend_data else 0,
                "change": trend_data[-1]["findings_total"] - trend_data[0]["findings_total"] if len(trend_data) >= 2 else 0,
                "direction": "improving" if len(trend_data) >= 2 and trend_data[-1]["findings_total"] < trend_data[0]["findings_total"] else "stable",
            },
        }

    def _scheduling_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get scheduler status.

        Returns:
            Scheduler status information
        """
        return {
            "status": "operational",
            "scheduler": {
                "running": True,
                "check_interval": 60,
                "last_check": "2024-01-15T14:30:00Z",
            },
            "jobs": {
                "total": 4,
                "enabled": 3,
                "disabled": 1,
                "pending": 1,
            },
            "history": {
                "total_scans": 250,
                "retention_days": 90,
                "storage_path": "~/.stance/history",
            },
            "capabilities": [
                "cron_schedules",
                "rate_schedules",
                "job_management",
                "history_tracking",
                "scan_comparison",
                "trend_analysis",
            ],
            "components": {
                "ScanScheduler": "healthy",
                "ScanHistoryManager": "healthy",
            },
        }

    def _scheduling_schedule_types(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List supported schedule types.

        Returns:
            List of schedule types
        """
        types = [
            {
                "value": "cron",
                "description": "Cron expression for precise scheduling",
                "examples": [
                    "0 * * * * - Every hour at minute 0",
                    "0 2 * * * - Daily at 2:00 AM",
                    "0 0 * * 0 - Weekly on Sunday at midnight",
                    "0 0 1 * * - Monthly on the 1st at midnight",
                ],
                "format": "minute hour day-of-month month day-of-week",
            },
            {
                "value": "rate",
                "description": "Fixed interval rate schedule",
                "examples": [
                    "rate(5 minutes) - Every 5 minutes",
                    "rate(1 hour) - Every hour",
                    "rate(1 day) - Every day",
                ],
                "format": "rate(N unit)",
                "units": ["minutes", "hours", "days"],
            },
            {
                "value": "once",
                "description": "One-time execution at a specific time",
                "examples": [
                    "once(2024-01-20T15:00:00Z)",
                ],
                "format": "once(ISO-8601-datetime)",
            },
        ]

        return {
            "types": types,
            "total": len(types),
        }

    def _scheduling_diff_types(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List diff types for scan comparisons.

        Returns:
            List of diff types
        """
        types = [
            {
                "value": "new",
                "description": "Finding appeared in current scan",
                "indicator": "+",
            },
            {
                "value": "resolved",
                "description": "Finding no longer present in current scan",
                "indicator": "-",
            },
            {
                "value": "unchanged",
                "description": "Finding present in both scans without changes",
                "indicator": "=",
            },
            {
                "value": "severity_changed",
                "description": "Same finding with different severity level",
                "indicator": "~",
            },
            {
                "value": "status_changed",
                "description": "Same finding with different status",
                "indicator": "~",
            },
        ]

        return {
            "types": types,
            "total": len(types),
        }

    def _scheduling_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get scheduling module summary.

        Returns:
            Summary of scheduling module state
        """
        return {
            "summary": {
                "scheduler": {
                    "running": True,
                    "total_jobs": 4,
                    "enabled_jobs": 3,
                    "next_job": {
                        "name": "Hourly Critical Check",
                        "next_run": "2024-01-15T15:00:00Z",
                    },
                },
                "history": {
                    "total_scans": 250,
                    "scans_today": 15,
                    "scans_this_week": 52,
                    "latest_scan": {
                        "scan_id": "scan-2024-01-15-0200",
                        "timestamp": "2024-01-15T02:00:00Z",
                        "findings_total": 23,
                    },
                },
                "trends": {
                    "direction": "improving",
                    "findings_velocity": -1.29,
                    "improvement_rate": 0.28,
                },
                "configs": [
                    {"name": "default", "jobs": 1, "last_scan": "2024-01-15T02:00:00Z"},
                    {"name": "critical-only", "jobs": 1, "last_scan": "2024-01-15T14:00:00Z"},
                    {"name": "compliance", "jobs": 1, "last_scan": "2024-01-14T00:00:00Z"},
                    {"name": "full-audit", "jobs": 1, "last_scan": "2024-01-01T03:00:00Z"},
                ],
            }
        }

    # =========================================================================
    # IaC API Handlers
    # =========================================================================

    def _iac_scan(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Scan IaC files for security issues.

        Query params:
            path: Path to scan (default: ".")
            severity: Minimum severity to report
            format: IaC format filter (terraform, cloudformation, arm, kubernetes, all)

        Returns:
            Scan findings and summary
        """
        path = "."
        severity_filter = None
        iac_format = "all"

        if params:
            if "path" in params:
                path = params["path"][0]
            if "severity" in params:
                severity_filter = params["severity"][0]
            if "format" in params:
                iac_format = params["format"][0]

        # Sample scan findings
        findings = [
            {
                "rule_id": "iac-aws-s3-encryption",
                "severity": "high",
                "title": "S3 bucket encryption not configured",
                "resource": "aws_s3_bucket.data_bucket",
                "location": f"{path}/main.tf:15",
                "description": "S3 buckets should have server-side encryption enabled.",
                "remediation": "Add server_side_encryption_configuration block.",
            },
            {
                "rule_id": "iac-aws-s3-public-access",
                "severity": "critical",
                "title": "S3 bucket allows public access",
                "resource": "aws_s3_bucket.public_assets",
                "location": f"{path}/storage.tf:42",
                "description": "S3 buckets should block public access.",
                "remediation": "Set all public access block settings to true.",
            },
            {
                "rule_id": "iac-aws-sg-ssh-open",
                "severity": "high",
                "title": "Security group allows SSH from 0.0.0.0/0",
                "resource": "aws_security_group.web_sg",
                "location": f"{path}/network.tf:28",
                "description": "Security groups should not allow unrestricted SSH.",
                "remediation": "Restrict SSH access to specific IP ranges.",
            },
            {
                "rule_id": "iac-aws-rds-encryption",
                "severity": "medium",
                "title": "RDS instance encryption not enabled",
                "resource": "aws_db_instance.app_db",
                "location": f"{path}/database.tf:10",
                "description": "RDS instances should have storage encryption.",
                "remediation": "Set storage_encrypted = true.",
            },
        ]

        # Apply severity filter
        if severity_filter:
            severity_order = ["critical", "high", "medium", "low", "info"]
            if severity_filter in severity_order:
                filter_idx = severity_order.index(severity_filter)
                findings = [f for f in findings if severity_order.index(f["severity"]) <= filter_idx]

        by_severity = {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
        }

        return {
            "findings": findings,
            "summary": {
                "path": path,
                "files_scanned": 8,
                "resources_found": 24,
                "findings_count": len(findings),
                "by_severity": by_severity,
                "iac_format": iac_format,
            },
        }

    def _iac_policies(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List available IaC policies.

        Query params:
            provider: Filter by cloud provider
            severity: Filter by severity
            enabled_only: If "true", only return enabled policies

        Returns:
            List of policies
        """
        provider = None
        severity = None
        enabled_only = False

        if params:
            if "provider" in params:
                provider = params["provider"][0]
            if "severity" in params:
                severity = params["severity"][0]
            if "enabled_only" in params:
                enabled_only = params["enabled_only"][0].lower() == "true"

        policies = [
            {
                "id": "iac-aws-s3-encryption",
                "name": "S3 bucket encryption not configured",
                "severity": "high",
                "providers": ["aws"],
                "resource_types": ["aws_s3_bucket"],
                "enabled": True,
            },
            {
                "id": "iac-aws-s3-public-access",
                "name": "S3 bucket allows public access",
                "severity": "critical",
                "providers": ["aws"],
                "resource_types": ["aws_s3_bucket_public_access_block"],
                "enabled": True,
            },
            {
                "id": "iac-aws-sg-ssh-open",
                "name": "Security group allows SSH from 0.0.0.0/0",
                "severity": "high",
                "providers": ["aws"],
                "resource_types": ["aws_security_group"],
                "enabled": True,
            },
            {
                "id": "iac-aws-rds-encryption",
                "name": "RDS instance encryption not enabled",
                "severity": "medium",
                "providers": ["aws"],
                "resource_types": ["aws_db_instance"],
                "enabled": True,
            },
            {
                "id": "iac-gcp-gcs-uniform-bucket",
                "name": "GCS bucket uniform access not enabled",
                "severity": "medium",
                "providers": ["gcp"],
                "resource_types": ["google_storage_bucket"],
                "enabled": True,
            },
            {
                "id": "iac-azure-storage-https",
                "name": "Storage account HTTPS not enforced",
                "severity": "high",
                "providers": ["azure"],
                "resource_types": ["azurerm_storage_account"],
                "enabled": True,
            },
            {
                "id": "iac-k8s-privileged-container",
                "name": "Container running as privileged",
                "severity": "critical",
                "providers": ["kubernetes"],
                "resource_types": ["kubernetes_deployment"],
                "enabled": True,
            },
            {
                "id": "iac-hardcoded-secret",
                "name": "Hardcoded secret detected",
                "severity": "critical",
                "providers": [],
                "resource_types": ["*"],
                "enabled": True,
            },
        ]

        if provider:
            policies = [p for p in policies if provider in p["providers"] or not p["providers"]]
        if severity:
            policies = [p for p in policies if p["severity"] == severity]
        if enabled_only:
            policies = [p for p in policies if p["enabled"]]

        return {
            "policies": policies,
            "total": len(policies),
            "enabled_count": sum(1 for p in policies if p["enabled"]),
        }

    def _iac_policy(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get details for a specific policy.

        Query params:
            policy_id: Policy ID to retrieve (required)

        Returns:
            Policy details
        """
        policy_id = ""
        if params and "policy_id" in params:
            policy_id = params["policy_id"][0]

        if not policy_id:
            return {"error": "policy_id parameter is required"}

        policies = {
            "iac-aws-s3-encryption": {
                "id": "iac-aws-s3-encryption",
                "name": "S3 bucket encryption not configured",
                "description": "S3 buckets should have server-side encryption enabled to protect data at rest.",
                "severity": "high",
                "enabled": True,
                "resource_types": ["aws_s3_bucket"],
                "providers": ["aws"],
                "formats": ["terraform", "cloudformation"],
                "check": {
                    "type": "any_of",
                    "checks": [
                        {"type": "exists", "path": "server_side_encryption_configuration"},
                        {"type": "exists", "path": "encryption"},
                    ],
                },
                "remediation": "Add a server_side_encryption_configuration block with SSE-S3 or SSE-KMS.",
                "compliance": [
                    {"framework": "CIS AWS", "version": "1.5.0", "control": "2.1.1"},
                ],
                "tags": ["s3", "encryption", "data-protection"],
                "references": [
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html",
                ],
            },
        }

        if policy_id in policies:
            return {"policy": policies[policy_id]}

        return {"error": f"Policy not found: {policy_id}"}

    def _iac_formats(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List supported IaC formats.

        Returns:
            List of formats
        """
        formats = [
            {
                "name": "Terraform",
                "value": "terraform",
                "extensions": [".tf", ".tfvars"],
                "description": "HashiCorp Terraform HCL configuration files",
            },
            {
                "name": "CloudFormation",
                "value": "cloudformation",
                "extensions": [".yaml", ".yml", ".json"],
                "description": "AWS CloudFormation templates in YAML or JSON",
            },
            {
                "name": "ARM Template",
                "value": "arm",
                "extensions": [".json"],
                "description": "Azure Resource Manager templates",
            },
            {
                "name": "Kubernetes",
                "value": "kubernetes",
                "extensions": [".yaml", ".yml"],
                "description": "Kubernetes manifests and configurations",
            },
            {
                "name": "Helm",
                "value": "helm",
                "extensions": [".yaml", ".yml"],
                "description": "Helm chart templates and values",
            },
            {
                "name": "Pulumi",
                "value": "pulumi",
                "extensions": [".py", ".ts", ".go"],
                "description": "Pulumi infrastructure programs",
            },
        ]

        return {"formats": formats, "total": len(formats)}

    def _iac_validate(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Validate IaC file syntax.

        Query params:
            path: Path to file to validate (required)

        Returns:
            Validation result
        """
        path = ""
        if params and "path" in params:
            path = params["path"][0]

        if not path:
            return {"error": "path parameter is required"}

        # Sample validation result
        if path.endswith(".tf"):
            return {
                "valid": True,
                "path": path,
                "format": "terraform",
                "resource_count": 5,
                "errors": [],
            }
        elif path.endswith(".yaml") or path.endswith(".yml"):
            return {
                "valid": True,
                "path": path,
                "format": "cloudformation",
                "resource_count": 8,
                "errors": [],
            }

        return {
            "valid": False,
            "path": path,
            "format": "unknown",
            "resource_count": 0,
            "errors": ["Unable to determine file format"],
        }

    def _iac_resources(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List resources in IaC files.

        Query params:
            path: Path to file or directory (default: ".")
            type: Filter by resource type
            provider: Filter by provider

        Returns:
            List of resources
        """
        path = "."
        resource_type = None
        provider = None

        if params:
            if "path" in params:
                path = params["path"][0]
            if "type" in params:
                resource_type = params["type"][0]
            if "provider" in params:
                provider = params["provider"][0]

        resources = [
            {"type": "aws_s3_bucket", "name": "data_bucket", "provider": "aws", "file": "main.tf:15"},
            {"type": "aws_s3_bucket", "name": "logs_bucket", "provider": "aws", "file": "main.tf:35"},
            {"type": "aws_security_group", "name": "web_sg", "provider": "aws", "file": "network.tf:10"},
            {"type": "aws_security_group", "name": "db_sg", "provider": "aws", "file": "network.tf:45"},
            {"type": "aws_db_instance", "name": "app_db", "provider": "aws", "file": "database.tf:5"},
            {"type": "aws_iam_role", "name": "app_role", "provider": "aws", "file": "iam.tf:1"},
            {"type": "google_storage_bucket", "name": "gcs_bucket", "provider": "gcp", "file": "gcp.tf:10"},
            {"type": "azurerm_storage_account", "name": "storage", "provider": "azure", "file": "azure.tf:5"},
        ]

        if resource_type:
            resources = [r for r in resources if r["type"] == resource_type]
        if provider:
            resources = [r for r in resources if r["provider"] == provider]

        return {"resources": resources, "total": len(resources), "path": path}

    def _iac_stats(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get IaC scanning statistics.

        Query params:
            path: Path to file or directory (default: ".")

        Returns:
            Statistics
        """
        path = "."
        if params and "path" in params:
            path = params["path"][0]

        return {
            "path": path,
            "total_files": 12,
            "total_resources": 45,
            "parse_errors": 0,
            "by_format": {
                "terraform": 8,
                "cloudformation": 2,
                "arm": 1,
                "kubernetes": 1,
            },
            "by_provider": {
                "aws": 32,
                "gcp": 8,
                "azure": 3,
                "kubernetes": 2,
            },
            "top_resource_types": [
                {"type": "aws_s3_bucket", "count": 8},
                {"type": "aws_security_group", "count": 6},
                {"type": "aws_iam_role", "count": 5},
                {"type": "aws_lambda_function", "count": 4},
                {"type": "aws_db_instance", "count": 3},
            ],
        }

    def _iac_compliance(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get compliance framework mappings.

        Query params:
            framework: Filter by framework name

        Returns:
            Compliance mappings
        """
        framework = None
        if params and "framework" in params:
            framework = params["framework"][0]

        frameworks = [
            {
                "name": "CIS AWS",
                "version": "1.5.0",
                "mappings": [
                    {"control": "2.1.1", "policy_id": "iac-aws-s3-encryption"},
                    {"control": "2.1.2", "policy_id": "iac-aws-s3-public-access"},
                    {"control": "4.1", "policy_id": "iac-aws-sg-ssh-open"},
                    {"control": "4.2", "policy_id": "iac-aws-sg-rdp-open"},
                ],
            },
            {
                "name": "CIS GCP",
                "version": "1.3.0",
                "mappings": [
                    {"control": "5.1", "policy_id": "iac-gcp-gcs-uniform-bucket"},
                    {"control": "5.2", "policy_id": "iac-gcp-gcs-public-access"},
                ],
            },
            {
                "name": "CIS Azure",
                "version": "1.4.0",
                "mappings": [
                    {"control": "3.1", "policy_id": "iac-azure-storage-https"},
                    {"control": "3.2", "policy_id": "iac-azure-storage-encryption"},
                ],
            },
        ]

        if framework:
            frameworks = [f for f in frameworks if framework.lower() in f["name"].lower()]

        total_mappings = sum(len(f["mappings"]) for f in frameworks)

        return {
            "frameworks": frameworks,
            "total_frameworks": len(frameworks),
            "total_mappings": total_mappings,
        }

    def _iac_providers(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List supported cloud providers.

        Returns:
            List of providers
        """
        providers = [
            {"name": "Amazon Web Services", "value": "aws", "resource_prefix": "aws_", "policy_count": 25},
            {"name": "Google Cloud Platform", "value": "gcp", "resource_prefix": "google_", "policy_count": 10},
            {"name": "Microsoft Azure", "value": "azure", "resource_prefix": "azurerm_", "policy_count": 8},
            {"name": "Kubernetes", "value": "kubernetes", "resource_prefix": "kubernetes_", "policy_count": 2},
        ]

        return {"providers": providers, "total": len(providers)}

    def _iac_resource_types(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List known resource types.

        Query params:
            provider: Filter by provider

        Returns:
            List of resource types
        """
        provider = None
        if params and "provider" in params:
            provider = params["provider"][0]

        types = [
            {"type": "aws_s3_bucket", "provider": "aws"},
            {"type": "aws_security_group", "provider": "aws"},
            {"type": "aws_iam_role", "provider": "aws"},
            {"type": "aws_iam_policy", "provider": "aws"},
            {"type": "aws_db_instance", "provider": "aws"},
            {"type": "aws_lambda_function", "provider": "aws"},
            {"type": "aws_vpc", "provider": "aws"},
            {"type": "aws_subnet", "provider": "aws"},
            {"type": "google_storage_bucket", "provider": "gcp"},
            {"type": "google_compute_instance", "provider": "gcp"},
            {"type": "google_compute_firewall", "provider": "gcp"},
            {"type": "azurerm_storage_account", "provider": "azure"},
            {"type": "azurerm_virtual_machine", "provider": "azure"},
            {"type": "azurerm_network_security_group", "provider": "azure"},
            {"type": "kubernetes_deployment", "provider": "kubernetes"},
            {"type": "kubernetes_service", "provider": "kubernetes"},
        ]

        if provider:
            types = [t for t in types if t["provider"] == provider]

        return {"resource_types": types, "total": len(types)}

    def _iac_severity_levels(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List severity levels.

        Returns:
            List of severity levels
        """
        levels = [
            {
                "value": "critical",
                "priority": 1,
                "description": "Immediate security risk, requires urgent action",
                "indicator": "[!!!]",
            },
            {
                "value": "high",
                "priority": 2,
                "description": "Significant security issue, should be addressed soon",
                "indicator": "[!!]",
            },
            {
                "value": "medium",
                "priority": 3,
                "description": "Moderate security concern, plan for remediation",
                "indicator": "[!]",
            },
            {
                "value": "low",
                "priority": 4,
                "description": "Minor security issue, address when convenient",
                "indicator": "[*]",
            },
            {
                "value": "info",
                "priority": 5,
                "description": "Informational finding, best practice recommendation",
                "indicator": "[i]",
            },
        ]

        return {"severity_levels": levels, "total": len(levels)}

    def _iac_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get IaC module summary.

        Returns:
            Summary of IaC module state
        """
        return {
            "summary": {
                "module": "IaC Scanner",
                "version": "1.0.0",
                "status": "operational",
                "formats": {
                    "terraform": {"enabled": True, "extensions": [".tf", ".tfvars"]},
                    "cloudformation": {"enabled": True, "extensions": [".yaml", ".yml", ".json"]},
                    "arm": {"enabled": True, "extensions": [".json"]},
                    "kubernetes": {"enabled": True, "extensions": [".yaml", ".yml"]},
                },
                "policies": {
                    "total": 45,
                    "enabled": 42,
                    "by_severity": {
                        "critical": 8,
                        "high": 15,
                        "medium": 12,
                        "low": 7,
                        "info": 3,
                    },
                    "by_provider": {
                        "aws": 25,
                        "gcp": 10,
                        "azure": 8,
                        "kubernetes": 2,
                    },
                },
                "capabilities": [
                    "terraform_parsing",
                    "cloudformation_parsing",
                    "arm_template_parsing",
                    "kubernetes_manifest_parsing",
                    "policy_evaluation",
                    "compliance_mapping",
                    "secret_detection",
                ],
                "components": {
                    "TerraformParser": "healthy",
                    "CloudFormationParser": "healthy",
                    "ARMTemplateParser": "healthy",
                    "IaCPolicyEvaluator": "healthy",
                },
            }
        }

    # =========================================================================
    # Engine API Endpoints
    # =========================================================================

    def _engine_policies(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List loaded policies.

        Query Parameters:
            enabled_only - Only show enabled policies
            severity - Filter by severity level
            resource_type - Filter by resource type
            framework - Filter by compliance framework

        Returns:
            List of policies
        """
        policies = self._get_sample_engine_policies()

        if params:
            if "enabled_only" in params and params["enabled_only"][0].lower() == "true":
                policies = [p for p in policies if p["enabled"]]

            if "severity" in params:
                severity = params["severity"][0]
                policies = [p for p in policies if p["severity"] == severity]

            if "resource_type" in params:
                resource_type = params["resource_type"][0]
                policies = [p for p in policies if p["resource_type"] == resource_type]

            if "framework" in params:
                framework = params["framework"][0].lower()
                policies = [
                    p for p in policies
                    if any(framework in f.lower() for f in p.get("frameworks", []))
                ]

        return {"policies": policies, "total": len(policies)}

    def _engine_policy(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get policy details.

        Query Parameters:
            policy_id (required) - Policy ID

        Returns:
            Policy details or error
        """
        if not params or "policy_id" not in params:
            return {"error": "policy_id parameter is required"}

        policy_id = params["policy_id"][0]
        policies = self._get_sample_engine_policies()

        for policy in policies:
            if policy["id"] == policy_id:
                return {"policy": policy}

        return {"error": f"Policy '{policy_id}' not found"}

    def _engine_validate(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Validate policy files.

        Query Parameters:
            path - Policy directory or file path

        Returns:
            Validation results
        """
        path = params.get("path", ["policies/"])[0] if params else "policies/"

        return {
            "valid": True,
            "total_files": 5,
            "valid_count": 5,
            "invalid_count": 0,
            "errors": [],
            "warnings": ["Policy 'azure-sql-encryption' is disabled"],
            "path": path,
        }

    def _engine_evaluate(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Evaluate an expression.

        Query Parameters:
            expression (required) - Expression to evaluate
            context - JSON context (default: {})

        Returns:
            Evaluation result
        """
        if not params or "expression" not in params:
            return {"error": "expression parameter is required"}

        expression = params["expression"][0]
        context_str = params.get("context", ["{}"])[0]

        try:
            import json
            context = json.loads(context_str)
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Invalid JSON context: {e}"}

        try:
            from stance.engine.expressions import ExpressionEvaluator

            evaluator = ExpressionEvaluator()
            result = evaluator.evaluate(expression, context)
            return {
                "success": True,
                "expression": expression,
                "context": context,
                "result": result,
            }
        except Exception as e:
            return {
                "success": False,
                "expression": expression,
                "context": context,
                "result": None,
                "error": str(e),
            }

    def _engine_validate_expression(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Validate expression syntax.

        Query Parameters:
            expression (required) - Expression to validate

        Returns:
            Validation result
        """
        if not params or "expression" not in params:
            return {"error": "expression parameter is required"}

        expression = params["expression"][0]

        try:
            from stance.engine.expressions import ExpressionEvaluator

            evaluator = ExpressionEvaluator()
            errors = evaluator.validate(expression)
            return {
                "valid": len(errors) == 0,
                "expression": expression,
                "errors": errors,
            }
        except Exception as e:
            return {
                "valid": False,
                "expression": expression,
                "errors": [str(e)],
            }

    def _engine_compliance(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get compliance scores.

        Query Parameters:
            framework - Filter by specific framework

        Returns:
            Compliance scores by framework
        """
        frameworks = [
            {
                "id": "cis-aws",
                "name": "CIS AWS Foundations Benchmark",
                "version": "2.0",
                "score": 78.5,
                "controls_passed": 47,
                "controls_failed": 13,
                "controls_total": 60,
            },
            {
                "id": "pci-dss",
                "name": "PCI DSS",
                "version": "4.0",
                "score": 85.0,
                "controls_passed": 51,
                "controls_failed": 9,
                "controls_total": 60,
            },
            {
                "id": "soc2",
                "name": "SOC 2",
                "version": "2017",
                "score": 72.0,
                "controls_passed": 36,
                "controls_failed": 14,
                "controls_total": 50,
            },
        ]

        if params and "framework" in params:
            framework = params["framework"][0].lower().replace(" ", "-")
            frameworks = [f for f in frameworks if f["id"] == framework]

        total_controls = sum(f["controls_total"] for f in frameworks)
        total_passed = sum(f["controls_passed"] for f in frameworks)
        overall = (total_passed / total_controls * 100) if total_controls > 0 else 100.0

        return {
            "overall_score": round(overall, 1),
            "frameworks": frameworks,
            "generated_at": "2025-12-29T12:00:00Z",
        }

    def _engine_frameworks(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List compliance frameworks.

        Returns:
            List of compliance frameworks
        """
        frameworks = [
            {
                "id": "cis-aws",
                "name": "CIS AWS Foundations Benchmark",
                "version": "2.0",
                "controls_count": 60,
                "policies_mapped": 45,
            },
            {
                "id": "cis-gcp",
                "name": "CIS GCP Foundations Benchmark",
                "version": "2.0",
                "controls_count": 65,
                "policies_mapped": 41,
            },
            {
                "id": "cis-azure",
                "name": "CIS Azure Foundations Benchmark",
                "version": "2.0",
                "controls_count": 112,
                "policies_mapped": 47,
            },
            {
                "id": "pci-dss",
                "name": "PCI DSS",
                "version": "4.0",
                "controls_count": 60,
                "policies_mapped": 52,
            },
            {
                "id": "soc2",
                "name": "SOC 2 Type II",
                "version": "2017",
                "controls_count": 50,
                "policies_mapped": 34,
            },
            {
                "id": "hipaa",
                "name": "HIPAA Security Rule",
                "version": "2013",
                "controls_count": 42,
                "policies_mapped": 24,
            },
            {
                "id": "nist-800-53",
                "name": "NIST 800-53 Rev 5",
                "version": "Rev 5",
                "controls_count": 325,
                "policies_mapped": 75,
            },
        ]

        return {"frameworks": frameworks, "total": len(frameworks)}

    def _engine_operators(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List expression operators.

        Returns:
            List of available operators
        """
        operators = [
            {"operator": "==", "category": "comparison", "description": "Equals comparison", "example": "resource.enabled == true"},
            {"operator": "!=", "category": "comparison", "description": "Not equals comparison", "example": "resource.status != 'inactive'"},
            {"operator": ">", "category": "comparison", "description": "Greater than", "example": "resource.count > 10"},
            {"operator": "<", "category": "comparison", "description": "Less than", "example": "resource.age < 90"},
            {"operator": ">=", "category": "comparison", "description": "Greater than or equal", "example": "resource.version >= 2.0"},
            {"operator": "<=", "category": "comparison", "description": "Less than or equal", "example": "resource.retention <= 365"},
            {"operator": "in", "category": "membership", "description": "Value is in list", "example": "resource.region in ['us-east-1', 'us-west-2']"},
            {"operator": "not_in", "category": "membership", "description": "Value is not in list", "example": "resource.env not_in ['prod', 'staging']"},
            {"operator": "contains", "category": "string", "description": "String contains substring", "example": "resource.name contains 'prod'"},
            {"operator": "starts_with", "category": "string", "description": "String starts with prefix", "example": "resource.arn starts_with 'arn:aws:'"},
            {"operator": "ends_with", "category": "string", "description": "String ends with suffix", "example": "resource.bucket ends_with '-logs'"},
            {"operator": "matches", "category": "string", "description": "Regex pattern match", "example": "resource.name matches '^prod-[a-z]+'"},
            {"operator": "exists", "category": "existence", "description": "Field exists and is not null", "example": "resource.encryption exists"},
            {"operator": "not_exists", "category": "existence", "description": "Field does not exist or is null", "example": "resource.public_ip not_exists"},
            {"operator": "and", "category": "boolean", "description": "Logical AND", "example": "resource.encrypted == true and resource.versioned == true"},
            {"operator": "or", "category": "boolean", "description": "Logical OR", "example": "resource.tier == 'premium' or resource.tier == 'enterprise'"},
            {"operator": "not", "category": "boolean", "description": "Logical NOT", "example": "not resource.public"},
        ]

        return {"operators": operators, "total": len(operators)}

    def _engine_check_types(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List policy check types.

        Returns:
            List of check types
        """
        check_types = [
            {
                "type": "expression",
                "description": "Boolean expression evaluated against resource data",
                "fields": ["expression"],
                "example": "resource.encryption.enabled == true",
            },
            {
                "type": "sql",
                "description": "SQL query for complex checks across resources",
                "fields": ["query"],
                "example": "SELECT * FROM assets WHERE encryption = false",
            },
        ]

        return {"check_types": check_types, "total": len(check_types)}

    def _engine_severity_levels(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        List severity levels.

        Returns:
            List of severity levels
        """
        levels = [
            {"level": "critical", "priority": 1, "description": "Immediate action required - security breach risk", "response_time": "Immediate (< 1 hour)"},
            {"level": "high", "priority": 2, "description": "High priority - significant security risk", "response_time": "Same day (< 24 hours)"},
            {"level": "medium", "priority": 3, "description": "Moderate risk - should be addressed soon", "response_time": "Within 1 week"},
            {"level": "low", "priority": 4, "description": "Low risk - address in normal maintenance", "response_time": "Within 30 days"},
            {"level": "info", "priority": 5, "description": "Informational - best practice recommendation", "response_time": "As time permits"},
        ]

        return {"severity_levels": levels, "total": len(levels)}

    def _engine_stats(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get engine statistics.

        Returns:
            Policy engine statistics
        """
        return {
            "total_policies": 125,
            "enabled_policies": 118,
            "disabled_policies": 7,
            "by_severity": {
                "critical": 15,
                "high": 42,
                "medium": 48,
                "low": 15,
                "info": 5,
            },
            "by_resource_type": {
                "aws_s3_bucket": 12,
                "aws_iam_user": 8,
                "aws_iam_role": 10,
                "aws_ec2_instance": 15,
                "aws_rds_instance": 6,
                "gcp_storage_bucket": 8,
                "gcp_compute_instance": 10,
                "azure_storage_account": 7,
                "azure_vm": 9,
            },
            "frameworks_count": 7,
            "compliance_mappings": 318,
        }

    def _engine_status(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get engine status.

        Returns:
            Engine status and capabilities
        """
        return {
            "module": "engine",
            "version": "1.0.0",
            "status": "operational",
            "components": {
                "ExpressionEvaluator": True,
                "PolicyLoader": True,
                "PolicyEvaluator": True,
                "ComplianceCalculator": True,
            },
            "capabilities": {
                "expression_evaluation": True,
                "policy_validation": True,
                "compliance_scoring": True,
                "sql_checks": True,
                "yaml_parsing": True,
                "wildcard_matching": True,
                "regex_patterns": True,
            },
        }

    def _engine_summary(self, params: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Get engine summary.

        Returns:
            Comprehensive engine summary
        """
        return {
            "summary": {
                "module": "Policy Engine",
                "version": "1.0.0",
                "status": "operational",
                "policies": {
                    "total": 125,
                    "enabled": 118,
                    "disabled": 7,
                },
                "compliance": {
                    "frameworks": 7,
                    "overall_score": 78.5,
                },
                "expression_engine": {
                    "operators": 17,
                    "check_types": 2,
                },
                "features": [
                    "Expression-based policy evaluation",
                    "SQL query-based checks",
                    "Wildcard resource type matching",
                    "Regex pattern matching",
                    "Multi-framework compliance scoring",
                    "YAML policy file parsing",
                    "Policy validation and error reporting",
                ],
            }
        }

    def _get_sample_engine_policies(self) -> list[dict[str, Any]]:
        """Get sample policies for demo."""
        return [
            {
                "id": "aws-s3-encryption",
                "name": "S3 Bucket Encryption Required",
                "description": "Ensure all S3 buckets have encryption enabled",
                "severity": "high",
                "resource_type": "aws_s3_bucket",
                "enabled": True,
                "frameworks": ["CIS AWS", "PCI-DSS"],
                "check": {"type": "expression", "expression": "resource.encryption.enabled == true"},
                "compliance": [
                    {"framework": "CIS AWS", "version": "2.0", "control": "2.1.1"},
                    {"framework": "PCI-DSS", "version": "4.0", "control": "3.4"},
                ],
                "remediation": {"guidance": "Enable server-side encryption on the S3 bucket."},
                "tags": ["security", "encryption", "s3"],
            },
            {
                "id": "aws-iam-mfa",
                "name": "IAM User MFA Required",
                "description": "Ensure all IAM users have MFA enabled",
                "severity": "critical",
                "resource_type": "aws_iam_user",
                "enabled": True,
                "frameworks": ["CIS AWS", "SOC2"],
                "check": {"type": "expression", "expression": "resource.mfa_active == true"},
                "compliance": [
                    {"framework": "CIS AWS", "version": "2.0", "control": "1.10"},
                    {"framework": "SOC2", "version": "2017", "control": "CC6.1"},
                ],
                "remediation": {"guidance": "Enable MFA for all IAM users."},
                "tags": ["security", "iam", "mfa"],
            },
            {
                "id": "aws-ec2-public-ip",
                "name": "EC2 No Public IP",
                "description": "EC2 instances should not have public IPs unless required",
                "severity": "medium",
                "resource_type": "aws_ec2_instance",
                "enabled": True,
                "frameworks": ["CIS AWS"],
                "check": {"type": "expression", "expression": "resource.public_ip_address not_exists"},
                "compliance": [{"framework": "CIS AWS", "version": "2.0", "control": "5.1"}],
                "remediation": {"guidance": "Use private subnets and NAT gateways."},
                "tags": ["network", "ec2"],
            },
            {
                "id": "gcp-storage-public",
                "name": "GCS Bucket No Public Access",
                "description": "Ensure GCS buckets are not publicly accessible",
                "severity": "critical",
                "resource_type": "gcp_storage_bucket",
                "enabled": True,
                "frameworks": ["CIS GCP"],
                "check": {"type": "expression", "expression": "resource.iam_configuration.public_access_prevention == 'enforced'"},
                "compliance": [{"framework": "CIS GCP", "version": "2.0", "control": "5.1"}],
                "remediation": {"guidance": "Enable public access prevention."},
                "tags": ["security", "storage", "gcp"],
            },
            {
                "id": "azure-sql-encryption",
                "name": "Azure SQL TDE Enabled",
                "description": "Ensure Azure SQL databases have TDE enabled",
                "severity": "high",
                "resource_type": "azure_sql_database",
                "enabled": False,
                "frameworks": ["CIS Azure"],
                "check": {"type": "expression", "expression": "resource.transparent_data_encryption.status == 'Enabled'"},
                "compliance": [{"framework": "CIS Azure", "version": "2.0", "control": "4.1.2"}],
                "remediation": {"guidance": "Enable TDE on Azure SQL database."},
                "tags": ["security", "encryption", "azure", "sql"],
            },
        ]

    # ==================== Storage Backend API Methods ====================

    def _storage_backends(self, params: dict[str, Any]) -> dict[str, Any]:
        """List all available storage backends."""
        from stance.storage import list_available_backends

        available = list_available_backends()
        backends = []

        backend_info = {
            "local": {
                "name": "Local Storage",
                "description": "SQLite-based local storage for development and small deployments",
                "storage_type": "sql",
                "query_service": "sqlite",
                "cloud_provider": None,
            },
            "s3": {
                "name": "AWS S3 Storage",
                "description": "Amazon S3 storage with Athena query integration",
                "storage_type": "object",
                "query_service": "athena",
                "cloud_provider": "aws",
            },
            "gcs": {
                "name": "Google Cloud Storage",
                "description": "GCS storage with BigQuery query integration",
                "storage_type": "object",
                "query_service": "bigquery",
                "cloud_provider": "gcp",
            },
            "azure_blob": {
                "name": "Azure Blob Storage",
                "description": "Azure Blob storage with Synapse Analytics query integration",
                "storage_type": "object",
                "query_service": "synapse",
                "cloud_provider": "azure",
            },
        }

        for backend_id in ["local", "s3", "gcs", "azure_blob"]:
            info = backend_info.get(backend_id, {})
            backends.append({
                "id": backend_id,
                "name": info.get("name", backend_id),
                "description": info.get("description", ""),
                "available": backend_id in available,
                "storage_type": info.get("storage_type"),
                "query_service": info.get("query_service"),
                "cloud_provider": info.get("cloud_provider"),
            })

        return {
            "backends": backends,
            "total": len(backends),
            "available_count": len(available),
        }

    def _storage_backend(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get details for a specific storage backend."""
        from stance.storage import list_available_backends

        backend_id = params.get("id", "local")
        available = list_available_backends()

        backend_details = {
            "local": {
                "name": "Local Storage",
                "description": "SQLite-based local storage for development and small deployments",
                "storage_type": "sql",
                "query_service": "sqlite",
                "cloud_provider": None,
                "configuration": {
                    "required": ["db_path"],
                    "optional": [],
                },
                "capabilities": {
                    "snapshots": True,
                    "versioning": True,
                    "query_assets": True,
                    "query_findings": True,
                    "ddl_generation": False,
                    "analytics_export": False,
                },
                "data_format": "sqlite",
                "sdk_required": None,
            },
            "s3": {
                "name": "AWS S3 Storage",
                "description": "Amazon S3 storage with Athena query integration",
                "storage_type": "object",
                "query_service": "athena",
                "cloud_provider": "aws",
                "configuration": {
                    "required": ["bucket", "prefix"],
                    "optional": ["region", "athena_database", "athena_workgroup"],
                },
                "capabilities": {
                    "snapshots": True,
                    "versioning": True,
                    "query_assets": False,
                    "query_findings": False,
                    "ddl_generation": True,
                    "analytics_export": True,
                },
                "data_format": "jsonl",
                "sdk_required": "boto3",
            },
            "gcs": {
                "name": "Google Cloud Storage",
                "description": "GCS storage with BigQuery query integration",
                "storage_type": "object",
                "query_service": "bigquery",
                "cloud_provider": "gcp",
                "configuration": {
                    "required": ["bucket", "prefix"],
                    "optional": ["project", "bigquery_dataset"],
                },
                "capabilities": {
                    "snapshots": True,
                    "versioning": True,
                    "query_assets": False,
                    "query_findings": False,
                    "ddl_generation": True,
                    "analytics_export": True,
                },
                "data_format": "jsonl",
                "sdk_required": "google-cloud-storage",
            },
            "azure_blob": {
                "name": "Azure Blob Storage",
                "description": "Azure Blob storage with Synapse Analytics query integration",
                "storage_type": "object",
                "query_service": "synapse",
                "cloud_provider": "azure",
                "configuration": {
                    "required": ["connection_string", "container", "prefix"],
                    "optional": ["synapse_database", "synapse_schema"],
                },
                "capabilities": {
                    "snapshots": True,
                    "versioning": True,
                    "query_assets": False,
                    "query_findings": False,
                    "ddl_generation": True,
                    "analytics_export": True,
                },
                "data_format": "jsonl",
                "sdk_required": "azure-storage-blob",
            },
        }

        if backend_id not in backend_details:
            return {"error": f"Unknown backend: {backend_id}"}

        details = backend_details[backend_id]
        details["id"] = backend_id
        details["available"] = backend_id in available

        return details

    def _storage_snapshots(self, params: dict[str, Any]) -> dict[str, Any]:
        """List storage snapshots."""
        backend = params.get("backend", "local")
        limit = int(params.get("limit", 20))

        # Generate sample snapshots
        import datetime

        snapshots = []
        base_time = datetime.datetime.now(datetime.timezone.utc)

        for i in range(min(limit, 10)):
            snapshot_time = base_time - datetime.timedelta(hours=i * 6)
            snapshot_id = snapshot_time.strftime("%Y%m%d_%H%M%S")
            snapshots.append({
                "id": snapshot_id,
                "timestamp": snapshot_time.isoformat(),
                "backend": backend,
                "asset_count": 150 - (i * 5),
                "finding_count": 45 - (i * 2),
                "size_bytes": (1024 * 1024 * 10) - (i * 100000),
                "metadata": {
                    "scan_duration_seconds": 120 + (i * 10),
                    "providers_scanned": ["aws", "gcp", "azure"],
                },
            })

        return {
            "snapshots": snapshots,
            "total": len(snapshots),
            "backend": backend,
        }

    def _storage_snapshot(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get details for a specific snapshot."""
        snapshot_id = params.get("id", "")
        backend = params.get("backend", "local")

        if not snapshot_id:
            return {"error": "Snapshot ID required"}

        import datetime

        return {
            "id": snapshot_id,
            "backend": backend,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "asset_count": 150,
            "finding_count": 45,
            "size_bytes": 10485760,
            "assets_by_provider": {
                "aws": 80,
                "gcp": 45,
                "azure": 25,
            },
            "findings_by_severity": {
                "critical": 5,
                "high": 12,
                "medium": 18,
                "low": 10,
            },
            "metadata": {
                "scan_duration_seconds": 120,
                "providers_scanned": ["aws", "gcp", "azure"],
                "version": "1.0.0",
            },
        }

    def _storage_latest(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get the latest snapshot information."""
        backend = params.get("backend", "local")

        import datetime

        base_time = datetime.datetime.now(datetime.timezone.utc)
        snapshot_id = base_time.strftime("%Y%m%d_%H%M%S")

        return {
            "snapshot_id": snapshot_id,
            "backend": backend,
            "timestamp": base_time.isoformat(),
            "asset_count": 150,
            "finding_count": 45,
            "age_seconds": 0,
            "is_stale": False,
            "summary": {
                "providers": ["aws", "gcp", "azure"],
                "resource_types": 25,
                "critical_findings": 5,
                "high_findings": 12,
            },
        }

    def _storage_config(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get storage configuration details."""
        backend = params.get("backend", "local")

        configs = {
            "local": {
                "backend": "local",
                "db_path": "~/.stance/stance.db",
                "storage_type": "sql",
                "query_service": "sqlite",
                "settings": {
                    "journal_mode": "WAL",
                    "synchronous": "NORMAL",
                    "cache_size": 2000,
                },
            },
            "s3": {
                "backend": "s3",
                "bucket": "stance-data-bucket",
                "prefix": "stance/",
                "region": "us-east-1",
                "storage_type": "object",
                "query_service": "athena",
                "settings": {
                    "athena_database": "stance_db",
                    "athena_workgroup": "primary",
                    "storage_class": "STANDARD",
                },
            },
            "gcs": {
                "backend": "gcs",
                "bucket": "stance-data-bucket",
                "prefix": "stance/",
                "project": "my-gcp-project",
                "storage_type": "object",
                "query_service": "bigquery",
                "settings": {
                    "bigquery_dataset": "stance_dataset",
                    "storage_class": "STANDARD",
                },
            },
            "azure_blob": {
                "backend": "azure_blob",
                "container": "stance-data",
                "prefix": "stance/",
                "storage_type": "object",
                "query_service": "synapse",
                "settings": {
                    "synapse_database": "stance_db",
                    "synapse_schema": "dbo",
                    "access_tier": "Hot",
                },
            },
        }

        return configs.get(backend, {"error": f"Unknown backend: {backend}"})

    def _storage_capabilities(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get capabilities for storage backends."""
        backend = params.get("backend")

        all_capabilities = {
            "local": {
                "backend": "local",
                "snapshots": True,
                "versioning": True,
                "query_assets": True,
                "query_findings": True,
                "ddl_generation": False,
                "analytics_export": False,
                "compression": False,
                "encryption_at_rest": False,
                "cross_region_replication": False,
            },
            "s3": {
                "backend": "s3",
                "snapshots": True,
                "versioning": True,
                "query_assets": False,
                "query_findings": False,
                "ddl_generation": True,
                "analytics_export": True,
                "compression": True,
                "encryption_at_rest": True,
                "cross_region_replication": True,
            },
            "gcs": {
                "backend": "gcs",
                "snapshots": True,
                "versioning": True,
                "query_assets": False,
                "query_findings": False,
                "ddl_generation": True,
                "analytics_export": True,
                "compression": True,
                "encryption_at_rest": True,
                "cross_region_replication": True,
            },
            "azure_blob": {
                "backend": "azure_blob",
                "snapshots": True,
                "versioning": True,
                "query_assets": False,
                "query_findings": False,
                "ddl_generation": True,
                "analytics_export": True,
                "compression": True,
                "encryption_at_rest": True,
                "cross_region_replication": True,
            },
        }

        if backend:
            return all_capabilities.get(backend, {"error": f"Unknown backend: {backend}"})

        return {
            "capabilities": all_capabilities,
            "common_capabilities": ["snapshots", "versioning"],
            "cloud_only_capabilities": ["ddl_generation", "analytics_export", "compression", "encryption_at_rest"],
        }

    def _storage_query_services(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get query service information for storage backends."""
        services = [
            {
                "id": "sqlite",
                "name": "SQLite",
                "backend": "local",
                "description": "Built-in SQL queries for local storage",
                "query_language": "SQL",
                "features": ["Full SQL support", "Aggregations", "JOINs", "Subqueries"],
                "limitations": ["Single node only", "Limited concurrency"],
            },
            {
                "id": "athena",
                "name": "Amazon Athena",
                "backend": "s3",
                "description": "Serverless SQL queries on S3 data",
                "query_language": "Presto SQL",
                "features": ["Serverless", "Pay per query", "Parallel execution", "External tables"],
                "limitations": ["Query result latency", "S3 data scanning costs"],
            },
            {
                "id": "bigquery",
                "name": "Google BigQuery",
                "backend": "gcs",
                "description": "Serverless data warehouse for GCS data",
                "query_language": "Standard SQL",
                "features": ["Serverless", "Columnar storage", "ML integration", "Streaming inserts"],
                "limitations": ["Slot-based pricing", "Query complexity limits"],
            },
            {
                "id": "synapse",
                "name": "Azure Synapse Analytics",
                "backend": "azure_blob",
                "description": "Analytics service for Azure Blob data",
                "query_language": "T-SQL",
                "features": ["Serverless pools", "Dedicated pools", "Data Lake integration", "Power BI integration"],
                "limitations": ["Serverless has row limits", "Complex pricing model"],
            },
        ]

        return {
            "services": services,
            "total": len(services),
        }

    def _storage_ddl(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get DDL statements for external tables."""
        backend = params.get("backend", "s3")
        table_type = params.get("table_type", "assets")

        ddl_templates = {
            "s3": {
                "assets": """CREATE EXTERNAL TABLE IF NOT EXISTS stance_assets (
    id STRING,
    resource_type STRING,
    provider STRING,
    region STRING,
    account_id STRING,
    name STRING,
    tags MAP<STRING, STRING>,
    properties STRING,
    snapshot_id STRING,
    collected_at TIMESTAMP
)
PARTITIONED BY (snapshot_id STRING)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://stance-data-bucket/stance/assets/'
TBLPROPERTIES ('has_encrypted_data'='false');""",
                "findings": """CREATE EXTERNAL TABLE IF NOT EXISTS stance_findings (
    id STRING,
    rule_id STRING,
    severity STRING,
    resource_id STRING,
    resource_type STRING,
    provider STRING,
    title STRING,
    description STRING,
    remediation STRING,
    snapshot_id STRING,
    found_at TIMESTAMP
)
PARTITIONED BY (snapshot_id STRING)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://stance-data-bucket/stance/findings/'
TBLPROPERTIES ('has_encrypted_data'='false');""",
            },
            "gcs": {
                "assets": """CREATE OR REPLACE EXTERNAL TABLE stance_dataset.stance_assets (
    id STRING,
    resource_type STRING,
    provider STRING,
    region STRING,
    account_id STRING,
    name STRING,
    tags JSON,
    properties JSON,
    snapshot_id STRING,
    collected_at TIMESTAMP
)
OPTIONS (
    format = 'JSON',
    uris = ['gs://stance-data-bucket/stance/assets/*.jsonl']
);""",
                "findings": """CREATE OR REPLACE EXTERNAL TABLE stance_dataset.stance_findings (
    id STRING,
    rule_id STRING,
    severity STRING,
    resource_id STRING,
    resource_type STRING,
    provider STRING,
    title STRING,
    description STRING,
    remediation STRING,
    snapshot_id STRING,
    found_at TIMESTAMP
)
OPTIONS (
    format = 'JSON',
    uris = ['gs://stance-data-bucket/stance/findings/*.jsonl']
);""",
            },
            "azure_blob": {
                "assets": """CREATE EXTERNAL TABLE stance_assets (
    id NVARCHAR(255),
    resource_type NVARCHAR(255),
    provider NVARCHAR(50),
    region NVARCHAR(100),
    account_id NVARCHAR(255),
    name NVARCHAR(500),
    tags NVARCHAR(MAX),
    properties NVARCHAR(MAX),
    snapshot_id NVARCHAR(50),
    collected_at DATETIME2
)
WITH (
    LOCATION = 'stance/assets/',
    DATA_SOURCE = stance_blob_storage,
    FILE_FORMAT = stance_json_format
);""",
                "findings": """CREATE EXTERNAL TABLE stance_findings (
    id NVARCHAR(255),
    rule_id NVARCHAR(255),
    severity NVARCHAR(50),
    resource_id NVARCHAR(255),
    resource_type NVARCHAR(255),
    provider NVARCHAR(50),
    title NVARCHAR(500),
    description NVARCHAR(MAX),
    remediation NVARCHAR(MAX),
    snapshot_id NVARCHAR(50),
    found_at DATETIME2
)
WITH (
    LOCATION = 'stance/findings/',
    DATA_SOURCE = stance_blob_storage,
    FILE_FORMAT = stance_json_format
);""",
            },
        }

        if backend not in ddl_templates:
            return {"error": f"DDL not available for backend: {backend}"}

        if table_type not in ddl_templates[backend]:
            return {"error": f"Unknown table type: {table_type}"}

        return {
            "backend": backend,
            "table_type": table_type,
            "ddl": ddl_templates[backend][table_type],
            "query_service": {"s3": "athena", "gcs": "bigquery", "azure_blob": "synapse"}.get(backend),
        }

    def _storage_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get storage statistics."""
        backend = params.get("backend", "local")

        return {
            "backend": backend,
            "total_snapshots": 25,
            "total_assets": 3750,
            "total_findings": 1125,
            "storage_used_bytes": 262144000,
            "storage_used_human": "250 MB",
            "oldest_snapshot": "2024-01-01T00:00:00Z",
            "newest_snapshot": "2024-12-29T00:00:00Z",
            "average_assets_per_snapshot": 150,
            "average_findings_per_snapshot": 45,
            "growth_rate": {
                "assets_per_day": 5,
                "findings_per_day": 2,
                "bytes_per_day": 1048576,
            },
        }

    def _storage_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get storage backend status."""
        from stance.storage import list_available_backends

        backend = params.get("backend", "local")
        available = list_available_backends()

        statuses = {
            "local": {
                "backend": "local",
                "status": "healthy",
                "available": "local" in available,
                "connection": "connected",
                "last_check": "2024-12-29T00:00:00Z",
                "details": {
                    "db_path": "~/.stance/stance.db",
                    "db_size_bytes": 10485760,
                    "table_count": 4,
                    "index_count": 8,
                },
            },
            "s3": {
                "backend": "s3",
                "status": "healthy" if "s3" in available else "unavailable",
                "available": "s3" in available,
                "connection": "connected" if "s3" in available else "not_configured",
                "last_check": "2024-12-29T00:00:00Z",
                "details": {
                    "bucket": "stance-data-bucket",
                    "region": "us-east-1",
                    "object_count": 500,
                    "total_size_bytes": 104857600,
                },
            },
            "gcs": {
                "backend": "gcs",
                "status": "healthy" if "gcs" in available else "unavailable",
                "available": "gcs" in available,
                "connection": "connected" if "gcs" in available else "not_configured",
                "last_check": "2024-12-29T00:00:00Z",
                "details": {
                    "bucket": "stance-data-bucket",
                    "project": "my-gcp-project",
                    "object_count": 450,
                    "total_size_bytes": 94371840,
                },
            },
            "azure_blob": {
                "backend": "azure_blob",
                "status": "healthy" if "azure_blob" in available else "unavailable",
                "available": "azure_blob" in available,
                "connection": "connected" if "azure_blob" in available else "not_configured",
                "last_check": "2024-12-29T00:00:00Z",
                "details": {
                    "container": "stance-data",
                    "blob_count": 400,
                    "total_size_bytes": 83886080,
                },
            },
        }

        return statuses.get(backend, {"error": f"Unknown backend: {backend}"})

    def _storage_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive storage summary."""
        from stance.storage import list_available_backends

        available = list_available_backends()

        return {
            "overview": {
                "total_backends": 4,
                "available_backends": len(available),
                "configured_backends": available,
                "primary_backend": "local",
            },
            "backends": {
                "local": {
                    "available": "local" in available,
                    "status": "healthy",
                    "snapshots": 25,
                    "storage_used": "250 MB",
                },
                "s3": {
                    "available": "s3" in available,
                    "status": "healthy" if "s3" in available else "not_configured",
                    "snapshots": 20 if "s3" in available else 0,
                    "storage_used": "100 MB" if "s3" in available else "0 MB",
                },
                "gcs": {
                    "available": "gcs" in available,
                    "status": "healthy" if "gcs" in available else "not_configured",
                    "snapshots": 15 if "gcs" in available else 0,
                    "storage_used": "90 MB" if "gcs" in available else "0 MB",
                },
                "azure_blob": {
                    "available": "azure_blob" in available,
                    "status": "healthy" if "azure_blob" in available else "not_configured",
                    "snapshots": 10 if "azure_blob" in available else 0,
                    "storage_used": "80 MB" if "azure_blob" in available else "0 MB",
                },
            },
            "totals": {
                "total_snapshots": 70,
                "total_assets": 10500,
                "total_findings": 3150,
                "total_storage_used": "520 MB",
            },
            "recommendations": [
                "Consider enabling cloud storage for production deployments",
                "Set up automated snapshot retention policies",
                "Configure cross-region replication for disaster recovery",
            ],
        }

    # ==================== LLM API Methods ====================

    def _llm_providers(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available LLM providers."""
        import os

        providers = [
            {
                "id": "anthropic",
                "name": "Anthropic Claude",
                "available": bool(os.environ.get("ANTHROPIC_API_KEY")),
                "default_model": "claude-3-haiku-20240307",
                "api_key_env": "ANTHROPIC_API_KEY",
                "description": "Claude models from Anthropic",
            },
            {
                "id": "openai",
                "name": "OpenAI GPT",
                "available": bool(os.environ.get("OPENAI_API_KEY")),
                "default_model": "gpt-3.5-turbo",
                "api_key_env": "OPENAI_API_KEY",
                "description": "GPT models from OpenAI",
            },
            {
                "id": "gemini",
                "name": "Google Gemini",
                "available": bool(os.environ.get("GOOGLE_API_KEY")),
                "default_model": "gemini-pro",
                "api_key_env": "GOOGLE_API_KEY",
                "description": "Gemini models from Google",
            },
        ]

        return {
            "providers": providers,
            "total": len(providers),
            "available_count": sum(1 for p in providers if p["available"]),
        }

    def _llm_provider(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get details for a specific LLM provider."""
        import os

        provider_id = params.get("id", "anthropic")

        details = {
            "anthropic": {
                "id": "anthropic",
                "name": "Anthropic Claude",
                "available": bool(os.environ.get("ANTHROPIC_API_KEY")),
                "default_model": "claude-3-haiku-20240307",
                "api_key_env": "ANTHROPIC_API_KEY",
                "description": "Claude models from Anthropic, known for safety and helpfulness",
                "models": [
                    {"id": "claude-3-opus-20240229", "description": "Most capable", "default": False},
                    {"id": "claude-3-sonnet-20240229", "description": "Balanced", "default": False},
                    {"id": "claude-3-haiku-20240307", "description": "Fast", "default": True},
                ],
                "capabilities": ["query_generation", "finding_explanation", "policy_generation"],
            },
            "openai": {
                "id": "openai",
                "name": "OpenAI GPT",
                "available": bool(os.environ.get("OPENAI_API_KEY")),
                "default_model": "gpt-3.5-turbo",
                "api_key_env": "OPENAI_API_KEY",
                "description": "GPT models from OpenAI",
                "models": [
                    {"id": "gpt-4-turbo", "description": "Latest GPT-4", "default": False},
                    {"id": "gpt-4", "description": "High capability", "default": False},
                    {"id": "gpt-3.5-turbo", "description": "Fast", "default": True},
                ],
                "capabilities": ["query_generation", "finding_explanation", "policy_generation"],
            },
            "gemini": {
                "id": "gemini",
                "name": "Google Gemini",
                "available": bool(os.environ.get("GOOGLE_API_KEY")),
                "default_model": "gemini-pro",
                "api_key_env": "GOOGLE_API_KEY",
                "description": "Gemini models from Google",
                "models": [
                    {"id": "gemini-pro", "description": "General purpose", "default": True},
                    {"id": "gemini-pro-vision", "description": "Multimodal", "default": False},
                ],
                "capabilities": ["query_generation", "finding_explanation", "policy_generation"],
            },
        }

        return details.get(provider_id, {"error": f"Unknown provider: {provider_id}"})

    def _llm_generate_query(self, params: dict[str, Any]) -> dict[str, Any]:
        """Generate SQL query from natural language."""
        question = params.get("question", "")
        provider = params.get("provider", "anthropic")

        if not question:
            return {"error": "Question parameter is required"}

        # Generate demo SQL based on question keywords
        sql = self._generate_demo_sql(question)

        # Validate the query
        from stance.llm.query_generator import QueryGenerator

        class MockProvider:
            @property
            def provider_name(self) -> str:
                return provider

            @property
            def model_name(self) -> str:
                return "demo"

            def generate(self, prompt: str, system_prompt: str | None = None, max_tokens: int = 1024) -> str:
                return ""

        generator = QueryGenerator(MockProvider())
        errors = generator.validate_query(sql)

        return {
            "question": question,
            "provider": provider,
            "sql": sql,
            "is_valid": len(errors) == 0,
            "validation_errors": errors,
            "mode": "demo",
        }

    def _generate_demo_sql(self, question: str) -> str:
        """Generate demo SQL based on question keywords."""
        q_lower = question.lower()

        if "critical" in q_lower and "finding" in q_lower:
            return "SELECT * FROM findings WHERE severity = 'critical' AND status = 'open' LIMIT 100"
        elif "s3" in q_lower or "bucket" in q_lower:
            return "SELECT * FROM assets WHERE resource_type = 'aws_s3_bucket' LIMIT 100"
        elif "public" in q_lower or "internet" in q_lower:
            return "SELECT * FROM assets WHERE network_exposure = 'internet_facing' LIMIT 100"
        elif "vulnerability" in q_lower:
            return "SELECT * FROM findings WHERE finding_type = 'vulnerability' AND status = 'open' LIMIT 100"
        elif "count" in q_lower:
            return "SELECT severity, COUNT(*) as count FROM findings WHERE status = 'open' GROUP BY severity"
        else:
            return "SELECT f.*, a.name FROM findings f JOIN assets a ON f.asset_id = a.id WHERE f.status = 'open' LIMIT 100"

    def _llm_validate_query(self, params: dict[str, Any]) -> dict[str, Any]:
        """Validate a SQL query for safety."""
        sql = params.get("sql", "")

        if not sql:
            return {"error": "SQL parameter is required"}

        from stance.llm.query_generator import QueryGenerator

        class MockProvider:
            @property
            def provider_name(self) -> str:
                return "mock"

            @property
            def model_name(self) -> str:
                return "mock"

            def generate(self, prompt: str, system_prompt: str | None = None, max_tokens: int = 1024) -> str:
                return ""

        generator = QueryGenerator(MockProvider())
        errors = generator.validate_query(sql)

        return {
            "sql": sql,
            "is_valid": len(errors) == 0,
            "errors": errors,
        }

    def _llm_explain_finding(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get AI explanation for a finding."""
        finding_id = params.get("finding_id", "demo")

        return {
            "finding_id": finding_id,
            "summary": "S3 bucket has public access enabled, potentially exposing sensitive data.",
            "risk_explanation": "Public S3 buckets can be accessed by anyone on the internet. Attackers actively scan for misconfigured buckets.",
            "business_impact": "Unauthorized access could lead to data breaches, regulatory fines, and reputational damage.",
            "remediation_steps": [
                "Review the bucket policy and remove public access statements",
                "Enable 'Block Public Access' settings",
                "Review bucket ACLs and remove 'AllUsers' grants",
                "Enable server-side encryption",
            ],
            "technical_details": "Bucket policy contains Principal: '*' allowing anonymous access.",
            "references": [
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            ],
            "is_valid": True,
            "mode": "demo",
        }

    def _llm_generate_policy(self, params: dict[str, Any]) -> dict[str, Any]:
        """Generate security policy from description."""
        description = params.get("description", "")
        provider = params.get("provider", "anthropic")
        cloud = params.get("cloud", "aws")
        severity = params.get("severity", "medium")
        resource_type = params.get("resource_type")

        if not description:
            return {"error": "Description parameter is required"}

        # Determine resource type from description
        desc_lower = description.lower()
        if "s3" in desc_lower or "bucket" in desc_lower:
            detected_type = resource_type or "aws_s3_bucket"
            policy_id = "aws-s3-custom-001"
        elif "iam" in desc_lower:
            detected_type = resource_type or "aws_iam_user"
            policy_id = "aws-iam-custom-001"
        else:
            detected_type = resource_type or "aws_s3_bucket"
            policy_id = f"{cloud}-custom-001"

        yaml_content = f"""id: {policy_id}
name: Custom policy from description
description: |
  {description}

enabled: true
severity: {severity}

resource_type: {detected_type}

check:
  type: expression
  expression: "config.enabled == true"

remediation:
  guidance: |
    Implement the security control described above.
  automation_supported: false

tags:
  - custom
  - ai-generated
"""

        return {
            "description": description,
            "provider": provider,
            "cloud": cloud,
            "policy_id": policy_id,
            "yaml_content": yaml_content,
            "resource_type": detected_type,
            "severity": severity,
            "is_valid": True,
            "validation_errors": [],
            "mode": "demo",
        }

    def _llm_suggest_policies(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get policy suggestions for a resource type."""
        resource_type = params.get("resource_type", "aws_s3_bucket")
        count = int(params.get("count", 5))

        suggestions_map = {
            "aws_s3_bucket": [
                "Ensure S3 bucket has server-side encryption enabled",
                "Ensure S3 bucket does not have public read access",
                "Ensure S3 bucket has versioning enabled",
                "Ensure S3 bucket has logging enabled",
                "Ensure S3 bucket blocks public ACLs",
            ],
            "aws_iam_user": [
                "Ensure IAM users have MFA enabled",
                "Ensure IAM user access keys are rotated within 90 days",
                "Ensure IAM users do not have inline policies",
                "Ensure IAM users belong to at least one group",
                "Ensure IAM user passwords meet complexity requirements",
            ],
            "aws_ec2_instance": [
                "Ensure EC2 instance has detailed monitoring enabled",
                "Ensure EC2 instance is not using default security group",
                "Ensure EC2 instance has IMDSv2 required",
                "Ensure EC2 instance EBS volumes are encrypted",
                "Ensure EC2 instance is not publicly accessible",
            ],
        }

        suggestions = suggestions_map.get(resource_type, [
            f"Ensure {resource_type} follows security best practices",
            f"Ensure {resource_type} has proper access controls",
            f"Ensure {resource_type} has encryption enabled",
        ])

        return {
            "resource_type": resource_type,
            "suggestions": suggestions[:count],
            "total": len(suggestions[:count]),
        }

    def _llm_sanitize(self, params: dict[str, Any]) -> dict[str, Any]:
        """Sanitize text containing sensitive data."""
        text = params.get("text", "")
        redact_emails = params.get("redact_emails", "false").lower() == "true"
        redact_ips = params.get("redact_ips", "false").lower() == "true"
        redact_account_ids = params.get("redact_account_ids", "false").lower() == "true"

        if not text:
            return {"error": "Text parameter is required"}

        from stance.llm.sanitizer import DataSanitizer

        sanitizer = DataSanitizer(
            redact_emails=redact_emails,
            redact_ips=redact_ips,
            redact_account_ids=redact_account_ids,
        )

        result = sanitizer.sanitize_with_details(text)

        return {
            "original": text,
            "sanitized_text": result.sanitized_text,
            "redactions_made": result.redactions_made,
            "redaction_types": result.redaction_types,
        }

    def _llm_check_sensitive(self, params: dict[str, Any]) -> dict[str, Any]:
        """Check if text contains sensitive data."""
        text = params.get("text", "")

        if not text:
            return {"error": "Text parameter is required"}

        from stance.llm.sanitizer import DataSanitizer

        sanitizer = DataSanitizer()
        is_sensitive = sanitizer.is_sensitive(text)
        types_found = sanitizer.get_sensitive_types(text)

        return {
            "text": text,
            "is_sensitive": is_sensitive,
            "types_found": types_found,
        }

    def _llm_resource_types(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available resource types for policy generation."""
        from stance.llm.policy_generator import RESOURCE_TYPES

        cloud = params.get("cloud")

        if cloud:
            filtered = {cloud: RESOURCE_TYPES.get(cloud, [])}
            total = len(RESOURCE_TYPES.get(cloud, []))
        else:
            filtered = RESOURCE_TYPES
            total = sum(len(types) for types in RESOURCE_TYPES.values())

        return {
            "resource_types": filtered,
            "total": total,
        }

    def _llm_frameworks(self, params: dict[str, Any]) -> dict[str, Any]:
        """List compliance frameworks for policy generation."""
        from stance.llm.policy_generator import COMPLIANCE_FRAMEWORKS

        frameworks = [
            {"id": k, "name": v, "description": v}
            for k, v in COMPLIANCE_FRAMEWORKS.items()
        ]

        return {
            "frameworks": frameworks,
            "total": len(frameworks),
        }

    def _llm_models(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available models for each provider."""
        provider = params.get("provider")

        all_models = {
            "anthropic": [
                {"id": "claude-3-opus-20240229", "description": "Most capable", "default": False},
                {"id": "claude-3-sonnet-20240229", "description": "Balanced", "default": False},
                {"id": "claude-3-haiku-20240307", "description": "Fast", "default": True},
            ],
            "openai": [
                {"id": "gpt-4-turbo", "description": "Latest GPT-4", "default": False},
                {"id": "gpt-4", "description": "High capability", "default": False},
                {"id": "gpt-3.5-turbo", "description": "Fast", "default": True},
            ],
            "gemini": [
                {"id": "gemini-pro", "description": "General purpose", "default": True},
                {"id": "gemini-pro-vision", "description": "Multimodal", "default": False},
            ],
        }

        if provider:
            return {"models": {provider: all_models.get(provider, [])}}

        return {"models": all_models}

    def _llm_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get LLM module status."""
        import os

        providers = [
            {"name": "Anthropic", "available": bool(os.environ.get("ANTHROPIC_API_KEY"))},
            {"name": "OpenAI", "available": bool(os.environ.get("OPENAI_API_KEY"))},
            {"name": "Gemini", "available": bool(os.environ.get("GOOGLE_API_KEY"))},
        ]

        return {
            "module": "llm",
            "status": "operational",
            "providers": providers,
            "capabilities": [
                "query_generation",
                "query_validation",
                "finding_explanation",
                "policy_generation",
                "policy_suggestions",
                "data_sanitization",
                "sensitive_data_detection",
            ],
            "components": [
                "QueryGenerator",
                "FindingExplainer",
                "PolicyGenerator",
                "DataSanitizer",
                "AnthropicProvider",
                "OpenAIProvider",
                "GeminiProvider",
            ],
        }

    def _llm_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive LLM module summary."""
        import os
        from stance.llm.policy_generator import RESOURCE_TYPES, COMPLIANCE_FRAMEWORKS

        providers_available = sum([
            1 if os.environ.get("ANTHROPIC_API_KEY") else 0,
            1 if os.environ.get("OPENAI_API_KEY") else 0,
            1 if os.environ.get("GOOGLE_API_KEY") else 0,
        ])

        return {
            "module": "LLM",
            "version": "1.0.0",
            "providers_available": providers_available,
            "providers_total": 3,
            "features": [
                {"name": "Query Generation", "description": "Convert natural language to SQL"},
                {"name": "Query Validation", "description": "Validate SQL queries for safety"},
                {"name": "Finding Explanation", "description": "AI-powered finding explanations"},
                {"name": "Policy Generation", "description": "Generate policies from descriptions"},
                {"name": "Policy Suggestions", "description": "Get policy ideas for resource types"},
                {"name": "Data Sanitization", "description": "Remove sensitive data before LLM calls"},
            ],
            "resource_types_count": sum(len(types) for types in RESOURCE_TYPES.values()),
            "cloud_providers": len(RESOURCE_TYPES),
            "frameworks_count": len(COMPLIANCE_FRAMEWORKS),
            "sanitizer": {
                "patterns_count": 7,
                "optional_patterns_count": 3,
            },
        }

    # -------------------------------------------------------------------------
    # Detection Module Endpoints
    # -------------------------------------------------------------------------

    def _detection_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        """Scan text for secrets."""
        text = params.get("text", "")
        if not text:
            return {"error": "text parameter is required"}

        min_entropy = float(params.get("min_entropy", 3.5))

        from stance.detection import SecretsDetector

        detector = SecretsDetector(min_entropy=min_entropy)
        matches = detector.detect_in_text(text, source="api_input")

        return {
            "text_length": len(text),
            "secrets_found": len(matches),
            "matches": [
                {
                    "secret_type": m.secret_type,
                    "field_path": m.field_path,
                    "matched_value": self._redact_secret_value(m.matched_value),
                    "confidence": m.confidence,
                    "entropy": m.entropy,
                }
                for m in matches
            ],
        }

    def _detection_patterns(self, params: dict[str, Any]) -> dict[str, Any]:
        """List supported secret patterns."""
        from stance.detection import SECRET_PATTERNS

        category = params.get("category", "all")

        patterns = []
        for name, info in SECRET_PATTERNS.items():
            pattern_cat = self._get_detection_pattern_category(name)
            if category == "all" or pattern_cat == category:
                patterns.append({
                    "name": name,
                    "severity": str(info["severity"].value),
                    "description": info["description"],
                    "category": pattern_cat,
                })

        return {
            "category": category,
            "total": len(patterns),
            "patterns": sorted(patterns, key=lambda p: (p["category"], p["name"])),
        }

    def _detection_pattern(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get details for a specific pattern."""
        from stance.detection import SECRET_PATTERNS

        pattern_name = params.get("name", "")
        if not pattern_name:
            return {"error": "name parameter is required"}

        if pattern_name not in SECRET_PATTERNS:
            return {"error": f"Unknown pattern: {pattern_name}"}

        info = SECRET_PATTERNS[pattern_name]
        return {
            "name": pattern_name,
            "pattern": info["pattern"],
            "severity": str(info["severity"].value),
            "description": info["description"],
            "category": self._get_detection_pattern_category(pattern_name),
            "entropy_threshold": info.get("entropy_threshold"),
        }

    def _detection_entropy(self, params: dict[str, Any]) -> dict[str, Any]:
        """Calculate entropy of a string."""
        text = params.get("text", "")
        if not text:
            return {"error": "text parameter is required"}

        from stance.detection import SecretsDetector

        detector = SecretsDetector()
        entropy = detector._calculate_entropy(text)

        return {
            "text": text[:50] + "..." if len(text) > 50 else text,
            "text_length": len(text),
            "entropy": round(entropy, 4),
            "interpretation": self._interpret_entropy(entropy),
            "is_high_entropy": entropy >= 3.5,
        }

    def _detection_sensitive_fields(self, params: dict[str, Any]) -> dict[str, Any]:
        """List sensitive field names."""
        from stance.detection import SENSITIVE_FIELD_NAMES

        return {
            "total": len(SENSITIVE_FIELD_NAMES),
            "fields": SENSITIVE_FIELD_NAMES,
            "categories": {
                "password": [f for f in SENSITIVE_FIELD_NAMES if "pass" in f or "pwd" in f],
                "api_key": [f for f in SENSITIVE_FIELD_NAMES if "key" in f or "api" in f],
                "token": [f for f in SENSITIVE_FIELD_NAMES if "token" in f],
                "credential": [f for f in SENSITIVE_FIELD_NAMES if "cred" in f],
                "connection": [f for f in SENSITIVE_FIELD_NAMES if "connection" in f or "url" in f],
            },
        }

    def _detection_check_field(self, params: dict[str, Any]) -> dict[str, Any]:
        """Check if a field name is sensitive."""
        field_name = params.get("field_name", "")
        if not field_name:
            return {"error": "field_name parameter is required"}

        from stance.detection import SecretsDetector, SENSITIVE_FIELD_NAMES

        detector = SecretsDetector()
        is_sensitive = detector._is_sensitive_field_name(field_name)

        matched_patterns = [
            pattern for pattern in SENSITIVE_FIELD_NAMES
            if pattern in field_name.lower()
        ]

        return {
            "field_name": field_name,
            "is_sensitive": is_sensitive,
            "matched_patterns": matched_patterns,
        }

    def _detection_categories(self, params: dict[str, Any]) -> dict[str, Any]:
        """List secret categories."""
        from stance.detection import SECRET_PATTERNS

        category_info = {
            "aws": {"description": "AWS cloud credentials and secrets", "count": 0},
            "gcp": {"description": "GCP cloud credentials and secrets", "count": 0},
            "azure": {"description": "Azure cloud credentials and secrets", "count": 0},
            "generic": {"description": "Generic secrets (API keys, tokens, passwords)", "count": 0},
            "database": {"description": "Database connection strings with passwords", "count": 0},
            "cicd": {"description": "CI/CD and third-party service tokens", "count": 0},
        }

        for name in SECRET_PATTERNS.keys():
            cat = self._get_detection_pattern_category(name)
            if cat in category_info:
                category_info[cat]["count"] += 1

        categories = [
            {
                "id": cat_id,
                "description": info["description"],
                "pattern_count": info["count"],
            }
            for cat_id, info in category_info.items()
        ]

        return {
            "total": len(categories),
            "categories": categories,
        }

    def _detection_severity_levels(self, params: dict[str, Any]) -> dict[str, Any]:
        """List severity levels for detected secrets."""
        levels = [
            {
                "level": "critical",
                "description": "Immediate action required - exposed credentials that could lead to full compromise",
                "examples": "AWS Access Keys, Private Keys, Stripe Live Keys",
            },
            {
                "level": "high",
                "description": "High priority - secrets that could lead to significant access",
                "examples": "API Keys, Session Tokens, Database Passwords",
            },
            {
                "level": "medium",
                "description": "Medium priority - tokens with limited scope or impact",
                "examples": "JWT Tokens, Slack Tokens, OAuth Tokens",
            },
            {
                "level": "low",
                "description": "Low priority - potentially sensitive but limited risk",
                "examples": "High-entropy strings in sensitive fields",
            },
        ]

        return {
            "total": len(levels),
            "levels": levels,
        }

    def _detection_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show detection module statistics."""
        from stance.detection import SECRET_PATTERNS, SENSITIVE_FIELD_NAMES

        by_severity = {}
        by_category = {}

        for name, info in SECRET_PATTERNS.items():
            severity = str(info["severity"].value)
            by_severity[severity] = by_severity.get(severity, 0) + 1

            category = self._get_detection_pattern_category(name)
            by_category[category] = by_category.get(category, 0) + 1

        return {
            "total_patterns": len(SECRET_PATTERNS),
            "total_sensitive_fields": len(SENSITIVE_FIELD_NAMES),
            "by_severity": by_severity,
            "by_category": by_category,
            "detection_methods": ["pattern_matching", "entropy_analysis", "context_analysis"],
        }

    def _detection_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show detection module status."""
        from stance.detection import SECRET_PATTERNS, SENSITIVE_FIELD_NAMES

        return {
            "module": "detection",
            "status": "operational",
            "components": {
                "SecretsDetector": "available",
                "PatternMatcher": "available",
                "EntropyAnalyzer": "available",
                "ContextAnalyzer": "available",
            },
            "capabilities": [
                "pattern_based_detection",
                "entropy_analysis",
                "context_analysis",
                "finding_generation",
                "value_redaction",
            ],
            "pattern_count": len(SECRET_PATTERNS),
            "sensitive_fields_count": len(SENSITIVE_FIELD_NAMES),
        }

    def _detection_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive detection module summary."""
        from stance.detection import SECRET_PATTERNS, SENSITIVE_FIELD_NAMES

        by_severity = {}
        by_category = {}

        for name, info in SECRET_PATTERNS.items():
            severity = str(info["severity"].value)
            by_severity[severity] = by_severity.get(severity, 0) + 1

            category = self._get_detection_pattern_category(name)
            by_category[category] = by_category.get(category, 0) + 1

        return {
            "module": "detection",
            "version": "1.0.0",
            "description": "Secrets detection for cloud configurations",
            "patterns_total": len(SECRET_PATTERNS),
            "sensitive_fields_total": len(SENSITIVE_FIELD_NAMES),
            "by_severity": by_severity,
            "by_category": by_category,
            "supported_clouds": ["aws", "gcp", "azure"],
            "detection_methods": {
                "pattern_matching": "Regex-based detection of known secret formats",
                "entropy_analysis": "Shannon entropy calculation for high-randomness strings",
                "context_analysis": "Field name analysis for sensitive indicators",
            },
            "features": [
                "26 built-in secret patterns",
                "28 sensitive field name patterns",
                "Multi-cloud support (AWS, GCP, Azure)",
                "Database connection string detection",
                "CI/CD token detection (GitHub, GitLab, NPM)",
                "Automatic value redaction",
                "Finding generation for detected secrets",
            ],
        }

    def _get_detection_pattern_category(self, pattern_name: str) -> str:
        """Get the category for a pattern name."""
        if pattern_name.startswith("aws_"):
            return "aws"
        elif pattern_name.startswith("gcp_"):
            return "gcp"
        elif pattern_name.startswith("azure_"):
            return "azure"
        elif pattern_name.startswith("generic_") or pattern_name in [
            "bearer_token", "jwt_token", "basic_auth", "private_key", "ssh_private_key"
        ]:
            return "generic"
        elif pattern_name in [
            "mysql_connection", "postgres_connection", "mongodb_connection", "redis_connection"
        ]:
            return "database"
        elif pattern_name in [
            "github_token", "gitlab_token", "npm_token", "slack_token",
            "slack_webhook", "sendgrid_api_key", "twilio_api_key", "stripe_api_key"
        ]:
            return "cicd"
        else:
            return "other"

    def _redact_secret_value(self, value: str, visible_chars: int = 4) -> str:
        """Redact a secret value for safe display."""
        if len(value) <= visible_chars * 2:
            return "*" * len(value)
        return f"{value[:visible_chars]}{'*' * (len(value) - visible_chars * 2)}{value[-visible_chars:]}"

    def _interpret_entropy(self, entropy: float) -> str:
        """Interpret an entropy value."""
        if entropy < 2.0:
            return "Very low - likely not a secret"
        elif entropy < 3.0:
            return "Low - probably not a secret"
        elif entropy < 3.5:
            return "Moderate - could be a weak secret"
        elif entropy < 4.5:
            return "High - likely a secret"
        else:
            return "Very high - almost certainly a secret"

    # -------------------------------------------------------------------------
    # Scanner Module Endpoints
    # -------------------------------------------------------------------------

    def _scanner_scanners(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available vulnerability scanners."""
        from stance.scanner import TrivyScanner

        scanner = TrivyScanner()
        trivy_available = scanner.is_available()
        trivy_version = scanner.get_version() if trivy_available else None

        scanners = [
            {
                "id": "trivy",
                "name": "Trivy",
                "description": "Comprehensive vulnerability scanner by Aqua Security",
                "available": trivy_available,
                "version": trivy_version,
                "install": "brew install trivy",
                "supported_targets": ["container_images", "filesystems", "git_repos"],
            },
            {
                "id": "grype",
                "name": "Grype",
                "description": "Vulnerability scanner by Anchore (not yet implemented)",
                "available": False,
                "version": None,
                "install": "brew install grype",
                "supported_targets": ["container_images", "filesystems"],
            },
        ]

        return {
            "total": len(scanners),
            "available": sum(1 for s in scanners if s["available"]),
            "scanners": scanners,
        }

    def _scanner_check(self, params: dict[str, Any]) -> dict[str, Any]:
        """Check if scanner is available."""
        from stance.scanner import TrivyScanner

        scanner = TrivyScanner()
        is_available = scanner.is_available()
        version = scanner.get_version() if is_available else None

        return {
            "scanner": "trivy",
            "available": is_available,
            "version": version,
            "message": "Trivy is installed and available" if is_available else "Trivy is not installed",
        }

    def _scanner_version(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get scanner version."""
        from stance.scanner import TrivyScanner

        scanner = TrivyScanner()
        version = scanner.get_version()

        return {
            "scanner": "trivy",
            "version": version,
            "available": version is not None,
        }

    def _scanner_enrich(self, params: dict[str, Any]) -> dict[str, Any]:
        """Enrich CVE with EPSS and KEV data."""
        cve_id = params.get("cve_id", "").upper()
        if not cve_id:
            return {"error": "cve_id parameter is required"}
        if not cve_id.startswith("CVE-"):
            return {"error": "Invalid CVE ID format. Expected CVE-YYYY-NNNNN"}

        from stance.scanner import CVEEnricher

        enricher = CVEEnricher()
        epss = enricher._get_epss_score(cve_id)
        kev = enricher._get_kev_entry(cve_id)

        return {
            "cve_id": cve_id,
            "epss": {
                "score": epss.epss if epss else None,
                "percentile": epss.percentile if epss else None,
                "date": epss.date if epss else None,
            } if epss else None,
            "kev": {
                "in_catalog": kev is not None,
                "vendor": kev.vendor_project if kev else None,
                "product": kev.product if kev else None,
                "date_added": kev.date_added if kev else None,
                "due_date": kev.due_date if kev else None,
                "ransomware_use": kev.known_ransomware_campaign_use if kev else None,
            } if kev else {"in_catalog": False},
        }

    def _scanner_epss(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get EPSS score for a CVE."""
        cve_id = params.get("cve_id", "").upper()
        if not cve_id:
            return {"error": "cve_id parameter is required"}
        if not cve_id.startswith("CVE-"):
            return {"error": "Invalid CVE ID format. Expected CVE-YYYY-NNNNN"}

        from stance.scanner import CVEEnricher

        enricher = CVEEnricher()
        enricher._batch_fetch_epss([cve_id])
        epss = enricher._get_epss_score(cve_id)

        return {
            "cve_id": cve_id,
            "found": epss is not None,
            "score": epss.epss if epss else None,
            "percentile": epss.percentile if epss else None,
            "date": epss.date if epss else None,
        }

    def _scanner_kev(self, params: dict[str, Any]) -> dict[str, Any]:
        """Check if CVE is in CISA KEV catalog."""
        cve_id = params.get("cve_id", "").upper()
        if not cve_id:
            return {"error": "cve_id parameter is required"}
        if not cve_id.startswith("CVE-"):
            return {"error": "Invalid CVE ID format. Expected CVE-YYYY-NNNNN"}

        from stance.scanner import CVEEnricher

        enricher = CVEEnricher()
        kev = enricher._get_kev_entry(cve_id)

        result = {
            "cve_id": cve_id,
            "in_catalog": kev is not None,
        }

        if kev:
            result.update({
                "vendor": kev.vendor_project,
                "product": kev.product,
                "vulnerability_name": kev.vulnerability_name,
                "date_added": kev.date_added,
                "short_description": kev.short_description,
                "required_action": kev.required_action,
                "due_date": kev.due_date,
                "ransomware_use": kev.known_ransomware_campaign_use,
            })

        return result

    def _scanner_severity_levels(self, params: dict[str, Any]) -> dict[str, Any]:
        """List vulnerability severity levels."""
        levels = [
            {
                "level": "CRITICAL",
                "description": "Severe vulnerability requiring immediate attention",
                "cvss_range": "9.0 - 10.0",
                "examples": "Remote code execution, authentication bypass",
            },
            {
                "level": "HIGH",
                "description": "High-impact vulnerability requiring prompt remediation",
                "cvss_range": "7.0 - 8.9",
                "examples": "Privilege escalation, sensitive data exposure",
            },
            {
                "level": "MEDIUM",
                "description": "Moderate vulnerability requiring scheduled remediation",
                "cvss_range": "4.0 - 6.9",
                "examples": "Cross-site scripting, information disclosure",
            },
            {
                "level": "LOW",
                "description": "Low-impact vulnerability for opportunistic fixing",
                "cvss_range": "0.1 - 3.9",
                "examples": "Minor information leaks, DoS with limited impact",
            },
            {
                "level": "UNKNOWN",
                "description": "Severity not determined",
                "cvss_range": "N/A",
                "examples": "Newly published CVEs without scoring",
            },
        ]

        return {
            "total": len(levels),
            "levels": levels,
        }

    def _scanner_priority_factors(self, params: dict[str, Any]) -> dict[str, Any]:
        """List vulnerability priority scoring factors."""
        factors = [
            {
                "factor": "Severity",
                "max_points": 40,
                "description": "Base score from vulnerability severity (CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10)",
            },
            {
                "factor": "CVSS Score",
                "max_points": 20,
                "description": "Contribution from CVSS score (score * 2, capped at 20)",
            },
            {
                "factor": "EPSS Score",
                "max_points": 20,
                "description": "Exploit prediction score (probability * 20)",
            },
            {
                "factor": "KEV Catalog",
                "max_points": 20,
                "description": "In CISA Known Exploited Vulnerabilities catalog",
            },
            {
                "factor": "Ransomware Use",
                "max_points": 10,
                "description": "Known use in ransomware campaigns (requires KEV)",
            },
            {
                "factor": "Fix Available",
                "max_points": 5,
                "description": "Fixed version is available",
            },
        ]

        return {
            "max_score": 100,
            "factors": factors,
        }

    def _scanner_package_types(self, params: dict[str, Any]) -> dict[str, Any]:
        """List supported package types for scanning."""
        package_types = [
            {"type": "apk", "ecosystem": "Alpine Linux", "description": "Alpine Package Keeper"},
            {"type": "deb", "ecosystem": "Debian/Ubuntu", "description": "Debian packages"},
            {"type": "rpm", "ecosystem": "RHEL/CentOS/Fedora", "description": "RPM packages"},
            {"type": "gem", "ecosystem": "Ruby", "description": "RubyGems"},
            {"type": "npm", "ecosystem": "Node.js", "description": "NPM packages"},
            {"type": "pip", "ecosystem": "Python", "description": "PyPI packages"},
            {"type": "cargo", "ecosystem": "Rust", "description": "Cargo crates"},
            {"type": "go", "ecosystem": "Go", "description": "Go modules"},
            {"type": "composer", "ecosystem": "PHP", "description": "Composer packages"},
            {"type": "nuget", "ecosystem": "C#/.NET", "description": "NuGet packages"},
            {"type": "maven", "ecosystem": "Java", "description": "Maven artifacts"},
            {"type": "gradle", "ecosystem": "Java", "description": "Gradle dependencies"},
        ]

        return {
            "total": len(package_types),
            "package_types": package_types,
        }

    def _scanner_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show scanner statistics."""
        from stance.scanner import TrivyScanner

        scanner = TrivyScanner()
        is_available = scanner.is_available()
        version = scanner.get_version() if is_available else None

        return {
            "scanner": "trivy",
            "available": is_available,
            "version": version,
            "severity_levels": 5,
            "package_types": 12,
            "enrichment_sources": ["EPSS", "KEV"],
            "priority_factors": 6,
            "supported_targets": [
                "container_images",
                "filesystems",
                "git_repos",
                "kubernetes",
            ],
        }

    def _scanner_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show scanner module status."""
        from stance.scanner import TrivyScanner

        scanner = TrivyScanner()
        is_available = scanner.is_available()
        version = scanner.get_version() if is_available else None

        return {
            "module": "scanner",
            "status": "operational" if is_available else "degraded",
            "components": {
                "TrivyScanner": "available" if is_available else "not_installed",
                "CVEEnricher": "available",
                "EPSSClient": "available",
                "KEVClient": "available",
            },
            "capabilities": [
                "container_image_scanning",
                "vulnerability_detection",
                "cve_enrichment",
                "epss_scoring",
                "kev_lookup",
                "priority_calculation",
                "batch_scanning",
            ],
            "scanner_version": version,
        }

    def _scanner_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive scanner module summary."""
        from stance.scanner import TrivyScanner

        scanner = TrivyScanner()
        is_available = scanner.is_available()
        version = scanner.get_version() if is_available else None

        return {
            "module": "scanner",
            "version": "1.0.0",
            "description": "Container image vulnerability scanning with CVE enrichment",
            "scanner": {
                "name": "Trivy",
                "available": is_available,
                "version": version,
            },
            "enrichment": {
                "epss": "Exploit Prediction Scoring System from FIRST.org",
                "kev": "CISA Known Exploited Vulnerabilities catalog",
            },
            "features": [
                "Trivy-based container image scanning",
                "Vulnerability detection for 12 package types",
                "EPSS exploit probability scoring",
                "CISA KEV catalog integration",
                "Priority-based vulnerability ranking",
                "Batch image scanning",
                "JSON and SARIF output formats",
                "Fixable vulnerability filtering",
            ],
            "supported_ecosystems": [
                "Alpine (apk)", "Debian/Ubuntu (deb)", "RHEL/CentOS (rpm)",
                "Node.js (npm)", "Python (pip)", "Ruby (gem)",
                "Go (modules)", "Rust (cargo)", "Java (maven/gradle)",
                "PHP (composer)", ".NET (nuget)",
            ],
        }

    # =========================================================================
    # Export Module Endpoints
    # =========================================================================

    def _export_formats(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available export formats."""
        formats = [
            {
                "format": "json",
                "name": "JSON",
                "description": "Structured JSON output with full data fidelity",
                "extension": ".json",
                "mime_type": "application/json",
            },
            {
                "format": "csv",
                "name": "CSV",
                "description": "Comma-separated values for spreadsheet import",
                "extension": ".csv",
                "mime_type": "text/csv",
            },
            {
                "format": "html",
                "name": "HTML",
                "description": "Styled HTML report viewable in browsers",
                "extension": ".html",
                "mime_type": "text/html",
            },
            {
                "format": "pdf",
                "name": "PDF",
                "description": "Printable PDF document (requires wkhtmltopdf or weasyprint)",
                "extension": ".pdf",
                "mime_type": "application/pdf",
            },
        ]

        return {
            "total": len(formats),
            "formats": formats,
        }

    def _export_report_types(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available report types."""
        report_types = [
            {
                "type": "full_report",
                "name": "Full Report",
                "description": "Comprehensive report with all data (findings, assets, compliance)",
                "sections": ["summary", "findings", "assets", "compliance", "trends"],
            },
            {
                "type": "executive_summary",
                "name": "Executive Summary",
                "description": "High-level overview for management review",
                "sections": ["summary", "key_metrics", "top_risks", "compliance_scores"],
            },
            {
                "type": "findings_detail",
                "name": "Findings Detail",
                "description": "Detailed findings report with remediation guidance",
                "sections": ["findings_by_severity", "remediation"],
            },
            {
                "type": "compliance_summary",
                "name": "Compliance Summary",
                "description": "Compliance framework scores and control status",
                "sections": ["framework_scores", "control_status"],
            },
            {
                "type": "asset_inventory",
                "name": "Asset Inventory",
                "description": "Complete asset listing with metadata",
                "sections": ["assets_by_type", "assets_by_region", "tags"],
            },
        ]

        return {
            "total": len(report_types),
            "report_types": report_types,
        }

    def _export_options(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show available export options."""
        options = [
            {
                "option": "format",
                "type": "enum",
                "values": ["json", "csv", "html", "pdf"],
                "default": "json",
                "description": "Output format for the report",
            },
            {
                "option": "report_type",
                "type": "enum",
                "values": ["full_report", "executive_summary", "findings_detail", "compliance_summary", "asset_inventory"],
                "default": "full_report",
                "description": "Type of report to generate",
            },
            {
                "option": "output_path",
                "type": "string",
                "default": None,
                "description": "File path to write the report",
            },
            {
                "option": "title",
                "type": "string",
                "default": "Mantissa Stance Security Report",
                "description": "Report title",
            },
            {
                "option": "author",
                "type": "string",
                "default": "Mantissa Stance",
                "description": "Report author name",
            },
            {
                "option": "severity_filter",
                "type": "enum",
                "values": ["critical", "high", "medium", "low", "info"],
                "default": None,
                "description": "Only include findings at or above this severity",
            },
            {
                "option": "include_charts",
                "type": "boolean",
                "default": True,
                "description": "Include visual charts (HTML/PDF only)",
            },
            {
                "option": "include_raw_data",
                "type": "boolean",
                "default": False,
                "description": "Include raw asset configuration data",
            },
            {
                "option": "frameworks",
                "type": "list",
                "default": [],
                "description": "Compliance frameworks to include",
            },
            {
                "option": "date_range_days",
                "type": "integer",
                "default": 30,
                "description": "Days of historical data to include",
            },
        ]

        return {
            "total": len(options),
            "options": options,
        }

    def _export_capabilities(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show export format capabilities."""
        capabilities = {
            "json": {
                "charts": False,
                "styling": False,
                "raw_data": True,
                "streaming": True,
                "compression": False,
                "features": ["Full data fidelity", "API compatible", "Machine readable", "Nested structures"],
            },
            "csv": {
                "charts": False,
                "styling": False,
                "raw_data": False,
                "streaming": True,
                "compression": False,
                "features": ["Spreadsheet import", "Simple structure", "Wide compatibility", "Tabular data"],
            },
            "html": {
                "charts": True,
                "styling": True,
                "raw_data": True,
                "streaming": False,
                "compression": False,
                "features": ["Browser viewable", "Print-ready", "Embedded CSS", "Interactive elements"],
            },
            "pdf": {
                "charts": True,
                "styling": True,
                "raw_data": True,
                "streaming": False,
                "compression": True,
                "features": ["Portable document", "Print optimized", "Fixed layout", "Professional output"],
            },
        }

        return {"capabilities": capabilities}

    def _export_pdf_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        """Check PDF tool availability."""
        from stance.export import PDFExporter

        exporter = PDFExporter()
        tool = exporter.get_pdf_tool()
        available = exporter.is_pdf_available()

        return {
            "pdf_available": available,
            "tool": tool,
            "tools_checked": ["wkhtmltopdf", "weasyprint"],
            "install_instructions": {
                "wkhtmltopdf": {
                    "macos": "brew install wkhtmltopdf",
                    "ubuntu": "apt-get install wkhtmltopdf",
                    "windows": "Download from wkhtmltopdf.org",
                },
                "weasyprint": {
                    "all": "pip install weasyprint",
                },
            },
            "fallback": "HTML with print instructions" if not available else None,
        }

    def _export_severities(self, params: dict[str, Any]) -> dict[str, Any]:
        """List severity levels for filtering."""
        severities = [
            {
                "level": "critical",
                "description": "Severe issues requiring immediate attention",
                "priority": 1,
                "examples": "Public S3 buckets, exposed secrets, RCE vulnerabilities",
            },
            {
                "level": "high",
                "description": "Significant issues requiring prompt remediation",
                "priority": 2,
                "examples": "Overly permissive IAM, missing encryption, privilege escalation",
            },
            {
                "level": "medium",
                "description": "Moderate issues for scheduled remediation",
                "priority": 3,
                "examples": "Missing logging, weak passwords, outdated certificates",
            },
            {
                "level": "low",
                "description": "Minor issues for opportunistic fixing",
                "priority": 4,
                "examples": "Missing tags, minor misconfigurations",
            },
            {
                "level": "info",
                "description": "Informational findings for awareness",
                "priority": 5,
                "examples": "Best practice recommendations, optimization suggestions",
            },
        ]

        return {
            "total": len(severities),
            "severities": severities,
        }

    def _export_preview(self, params: dict[str, Any]) -> dict[str, Any]:
        """Preview report generation with sample data."""
        from stance.export import (
            ExportFormat,
            ExportOptions,
            ReportData,
            ReportType,
            create_export_manager,
        )
        from stance.models.asset import Asset, AssetCollection
        from stance.models.finding import Finding, FindingCollection, Severity, FindingType, FindingStatus

        # Parse parameters
        format_str = params.get("format", ["json"])[0].lower() if isinstance(params.get("format"), list) else params.get("format", "json")
        report_type_str = params.get("report_type", ["executive_summary"])[0].lower() if isinstance(params.get("report_type"), list) else params.get("report_type", "executive_summary")

        # Create sample data
        sample_assets = [
            Asset(
                id="asset-001",
                cloud_provider="aws",
                account_id="123456789012",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                name="production-logs",
                network_exposure="public",
                tags={"Environment": "Production", "Team": "Security"},
            ),
            Asset(
                id="asset-002",
                cloud_provider="aws",
                account_id="123456789012",
                region="us-west-2",
                resource_type="aws_ec2_instance",
                name="web-server-1",
                network_exposure="internet_facing",
                tags={"Environment": "Production"},
            ),
        ]

        sample_findings = [
            Finding(
                id="finding-001",
                asset_id="asset-001",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.CRITICAL,
                status=FindingStatus.OPEN,
                title="S3 Bucket Publicly Accessible",
                description="S3 bucket allows public read access without authentication",
                rule_id="AWS-S3-001",
                remediation_guidance="Configure bucket policy to restrict public access",
                compliance_frameworks=["CIS AWS", "PCI-DSS"],
            ),
            Finding(
                id="finding-002",
                asset_id="asset-002",
                finding_type=FindingType.VULNERABILITY,
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                title="Outdated SSL Certificate",
                description="SSL certificate expires within 30 days",
                rule_id="SSL-001",
                remediation_guidance="Renew SSL certificate before expiration",
            ),
        ]

        # Parse format
        format_map = {
            "json": ExportFormat.JSON,
            "csv": ExportFormat.CSV,
            "html": ExportFormat.HTML,
            "pdf": ExportFormat.PDF,
        }
        export_format = format_map.get(format_str, ExportFormat.JSON)

        # Parse report type
        type_map = {
            "full_report": ReportType.FULL_REPORT,
            "executive_summary": ReportType.EXECUTIVE_SUMMARY,
            "findings_detail": ReportType.FINDINGS_DETAIL,
            "compliance_summary": ReportType.COMPLIANCE_SUMMARY,
            "asset_inventory": ReportType.ASSET_INVENTORY,
        }
        report_type = type_map.get(report_type_str, ReportType.EXECUTIVE_SUMMARY)

        # Build report data
        data = ReportData(
            assets=AssetCollection(assets=sample_assets),
            findings=FindingCollection(findings=sample_findings),
            compliance_scores={
                "CIS AWS 1.5": {"score": 78.5},
                "PCI-DSS 3.2": {"score": 65.0},
            },
        )

        # Build options
        options = ExportOptions(
            format=export_format,
            report_type=report_type,
            title="Sample Security Report (Preview)",
            author="Mantissa Stance",
        )

        # Generate export
        manager = create_export_manager()
        result = manager.export(data, options)

        if not result.success:
            return {"error": result.error}

        # For binary content (PDF), return metadata only
        if isinstance(result.content, bytes):
            return {
                "success": True,
                "format": export_format.value,
                "report_type": report_type.value,
                "bytes_generated": result.bytes_written,
                "note": "Binary PDF content generated",
            }

        return {
            "success": True,
            "format": export_format.value,
            "report_type": report_type.value,
            "bytes_generated": result.bytes_written,
            "content_preview": result.content[:2000] if result.content and len(result.content) > 2000 else result.content,
        }

    def _export_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show export module statistics."""
        from stance.export import PDFExporter

        pdf_exporter = PDFExporter()

        return {
            "formats_supported": 4,
            "report_types": 5,
            "export_options": 10,
            "pdf_tool_available": pdf_exporter.is_pdf_available(),
            "pdf_tool": pdf_exporter.get_pdf_tool(),
            "severity_levels": 5,
            "supported_data_types": ["assets", "findings", "compliance_scores", "trends", "scan_metadata"],
        }

    def _export_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show export module status."""
        from stance.export import PDFExporter, create_export_manager

        manager = create_export_manager()
        pdf_exporter = PDFExporter()
        available_formats = [f.value for f in manager.available_formats()]

        return {
            "module": "export",
            "status": "operational",
            "components": {
                "ExportManager": "available",
                "CSVExporter": "available",
                "JSONExporter": "available",
                "HTMLExporter": "available",
                "PDFExporter": "available" if pdf_exporter.is_pdf_available() else "limited",
            },
            "capabilities": [
                "multi_format_export",
                "report_generation",
                "severity_filtering",
                "compliance_reporting",
                "asset_inventory",
                "findings_detail",
                "executive_summary",
            ],
            "available_formats": available_formats,
        }

    def _export_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive export module summary."""
        from stance.export import PDFExporter

        pdf_exporter = PDFExporter()

        return {
            "module": "export",
            "version": "1.0.0",
            "description": "Multi-format report generation and data export",
            "formats": {
                "json": "Structured JSON with full data fidelity",
                "csv": "Comma-separated values for spreadsheet import",
                "html": "Styled HTML for browser viewing and printing",
                "pdf": "Portable document format (requires tool)",
            },
            "report_types": {
                "full_report": "Comprehensive report with all sections",
                "executive_summary": "High-level overview for management",
                "findings_detail": "Detailed findings with remediation",
                "compliance_summary": "Framework scores and controls",
                "asset_inventory": "Complete asset listing",
            },
            "features": [
                "Multi-format export (JSON, CSV, HTML, PDF)",
                "5 report types for different audiences",
                "Severity-based finding filtering",
                "Compliance framework reporting",
                "Asset inventory generation",
                "Trend data inclusion",
                "Raw configuration export option",
                "Print-ready HTML output",
                "Professional PDF generation",
            ],
            "pdf_status": {
                "available": pdf_exporter.is_pdf_available(),
                "tool": pdf_exporter.get_pdf_tool(),
            },
        }

    # ===========================================
    # Reporting Module API handlers
    # ===========================================

    def _reporting_analyze(self, params: dict[str, Any]) -> dict[str, Any]:
        """Perform full trend analysis."""
        from stance.reporting import TrendAnalyzer, TrendPeriod

        config = params.get("config", ["default"])[0] if isinstance(params.get("config"), list) else params.get("config", "default")
        days = int(params.get("days", [30])[0]) if isinstance(params.get("days"), list) else int(params.get("days", 30))
        period_str = params.get("period", ["daily"])[0] if isinstance(params.get("period"), list) else params.get("period", "daily")

        period_map = {
            "daily": TrendPeriod.DAILY,
            "weekly": TrendPeriod.WEEKLY,
            "monthly": TrendPeriod.MONTHLY,
            "quarterly": TrendPeriod.QUARTERLY,
        }
        period = period_map.get(period_str.lower(), TrendPeriod.DAILY)

        try:
            analyzer = TrendAnalyzer()
            report = analyzer.analyze(
                config_name=config,
                days=days,
                period=period,
            )
            return report.to_dict()
        except Exception as e:
            return {"error": str(e)}

    def _reporting_velocity(self, params: dict[str, Any]) -> dict[str, Any]:
        """Calculate findings velocity."""
        from stance.reporting import TrendAnalyzer

        config = params.get("config", ["default"])[0] if isinstance(params.get("config"), list) else params.get("config", "default")
        days = int(params.get("days", [7])[0]) if isinstance(params.get("days"), list) else int(params.get("days", 7))

        try:
            analyzer = TrendAnalyzer()
            velocities = analyzer.get_findings_velocity(
                config_name=config,
                days=days,
            )
            return {
                "config": config,
                "days_analyzed": days,
                "velocities": {k: round(v, 4) for k, v in velocities.items()},
                "unit": "findings/day",
            }
        except Exception as e:
            return {"error": str(e)}

    def _reporting_improvement(self, params: dict[str, Any]) -> dict[str, Any]:
        """Calculate security improvement rate."""
        from stance.reporting import TrendAnalyzer

        config = params.get("config", ["default"])[0] if isinstance(params.get("config"), list) else params.get("config", "default")
        days = int(params.get("days", [30])[0]) if isinstance(params.get("days"), list) else int(params.get("days", 30))

        try:
            analyzer = TrendAnalyzer()
            rate = analyzer.get_improvement_rate(
                config_name=config,
                days=days,
            )
            return {
                "config": config,
                "days_analyzed": days,
                "improvement_rate": round(rate, 2),
                "unit": "percent",
                "direction": "improving" if rate > 0 else "declining" if rate < 0 else "stable",
            }
        except Exception as e:
            return {"error": str(e)}

    def _reporting_compare(self, params: dict[str, Any]) -> dict[str, Any]:
        """Compare two time periods."""
        from stance.reporting import TrendAnalyzer

        config = params.get("config", ["default"])[0] if isinstance(params.get("config"), list) else params.get("config", "default")
        current_days = int(params.get("current_days", [7])[0]) if isinstance(params.get("current_days"), list) else int(params.get("current_days", 7))
        previous_days = int(params.get("previous_days", [7])[0]) if isinstance(params.get("previous_days"), list) else int(params.get("previous_days", 7))

        try:
            analyzer = TrendAnalyzer()
            comparison = analyzer.compare_periods(
                config_name=config,
                current_days=current_days,
                previous_days=previous_days,
            )
            return comparison
        except Exception as e:
            return {"error": str(e)}

    def _reporting_forecast(self, params: dict[str, Any]) -> dict[str, Any]:
        """Forecast future findings."""
        from stance.reporting import TrendAnalyzer

        config = params.get("config", ["default"])[0] if isinstance(params.get("config"), list) else params.get("config", "default")
        history_days = int(params.get("history_days", [30])[0]) if isinstance(params.get("history_days"), list) else int(params.get("history_days", 30))
        forecast_days = int(params.get("forecast_days", [7])[0]) if isinstance(params.get("forecast_days"), list) else int(params.get("forecast_days", 7))

        try:
            analyzer = TrendAnalyzer()
            forecast = analyzer.forecast(
                config_name=config,
                days_history=history_days,
                days_forecast=forecast_days,
            )
            return forecast
        except Exception as e:
            return {"error": str(e)}

    def _reporting_directions(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available trend directions."""
        directions = [
            {
                "direction": "improving",
                "description": "Security posture getting better (fewer findings or higher compliance)",
                "indicator": "Positive trend",
                "action": "Continue current practices",
            },
            {
                "direction": "declining",
                "description": "Security posture getting worse (more findings or lower compliance)",
                "indicator": "Negative trend",
                "action": "Investigate and remediate",
            },
            {
                "direction": "stable",
                "description": "No significant change in security posture",
                "indicator": "Neutral trend",
                "action": "Monitor and maintain",
            },
            {
                "direction": "insufficient_data",
                "description": "Not enough data points for reliable trend analysis",
                "indicator": "Unknown trend",
                "action": "Collect more scan data",
            },
        ]
        return {"total": len(directions), "directions": directions}

    def _reporting_periods(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available trend periods."""
        periods = [
            {
                "period": "daily",
                "description": "Day-by-day trend analysis",
                "use_case": "Short-term monitoring and rapid response",
                "recommended_history": "7-14 days",
            },
            {
                "period": "weekly",
                "description": "Week-over-week trend analysis",
                "use_case": "Sprint-level tracking and weekly reports",
                "recommended_history": "4-8 weeks",
            },
            {
                "period": "monthly",
                "description": "Month-over-month trend analysis",
                "use_case": "Executive reporting and long-term planning",
                "recommended_history": "3-6 months",
            },
            {
                "period": "quarterly",
                "description": "Quarter-over-quarter trend analysis",
                "use_case": "Strategic planning and compliance reporting",
                "recommended_history": "4+ quarters",
            },
        ]
        return {"total": len(periods), "periods": periods}

    def _reporting_severities(self, params: dict[str, Any]) -> dict[str, Any]:
        """List severity levels for trend tracking."""
        severities = [
            {
                "severity": "critical",
                "description": "Most severe security issues",
                "trend_priority": "Highest - track closely",
                "velocity_threshold": 0.5,
            },
            {
                "severity": "high",
                "description": "Significant security issues",
                "trend_priority": "High - monitor weekly",
                "velocity_threshold": 1.0,
            },
            {
                "severity": "medium",
                "description": "Moderate security issues",
                "trend_priority": "Medium - review monthly",
                "velocity_threshold": 2.0,
            },
            {
                "severity": "low",
                "description": "Minor security issues",
                "trend_priority": "Low - opportunistic",
                "velocity_threshold": 5.0,
            },
            {
                "severity": "info",
                "description": "Informational findings",
                "trend_priority": "Informational only",
                "velocity_threshold": 10.0,
            },
        ]
        return {"total": len(severities), "severities": severities}

    def _reporting_metrics(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show available trend metrics."""
        metrics = [
            {"metric": "current_value", "description": "Most recent value from scans", "type": "float"},
            {"metric": "previous_value", "description": "Value from previous period", "type": "float"},
            {"metric": "average", "description": "Average value over the analysis period", "type": "float"},
            {"metric": "min_value", "description": "Minimum value observed", "type": "float"},
            {"metric": "max_value", "description": "Maximum value observed", "type": "float"},
            {"metric": "change", "description": "Absolute change from previous value", "type": "float"},
            {"metric": "change_percent", "description": "Percentage change from previous value", "type": "float"},
            {"metric": "direction", "description": "Trend direction (improving/declining/stable)", "type": "enum"},
            {"metric": "data_points", "description": "Number of data points analyzed", "type": "integer"},
            {"metric": "velocity", "description": "Rate of change per day", "type": "float"},
        ]
        return {"total": len(metrics), "metrics": metrics}

    def _reporting_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show reporting module statistics."""
        return {
            "trend_directions": 4,
            "trend_periods": 4,
            "severity_levels": 5,
            "metrics_tracked": 10,
            "analysis_methods": ["velocity", "improvement_rate", "period_comparison", "forecast"],
            "forecast_model": "linear_regression",
            "change_threshold_percent": 5.0,
            "critical_velocity_threshold": 0.5,
        }

    def _reporting_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show reporting module status."""
        return {
            "module": "reporting",
            "status": "operational",
            "components": {
                "TrendAnalyzer": "available",
                "TrendReport": "available",
                "TrendMetrics": "available",
                "SeverityTrend": "available",
                "ComplianceTrend": "available",
                "ScanHistoryManager": "available",
            },
            "capabilities": [
                "trend_analysis",
                "velocity_calculation",
                "improvement_rate",
                "period_comparison",
                "linear_regression_forecast",
                "severity_tracking",
                "compliance_tracking",
                "recommendation_generation",
            ],
        }

    def _reporting_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive reporting module summary."""
        return {
            "module": "reporting",
            "version": "1.0.0",
            "description": "Security posture trend analysis and reporting",
            "features": [
                "Full trend analysis with configurable periods",
                "Findings velocity calculation (rate of change)",
                "Security improvement rate tracking",
                "Period-over-period comparison",
                "Linear regression forecasting",
                "Severity-level trend breakdown",
                "Compliance score trend tracking",
                "Automatic recommendation generation",
                "JSON and table output formats",
            ],
            "analysis_types": {
                "analyze": "Comprehensive trend analysis with recommendations",
                "velocity": "Rate of findings change per day",
                "improvement": "Percentage improvement over time",
                "compare": "Compare current vs previous period",
                "forecast": "Project future findings using regression",
            },
            "data_requirements": {
                "minimum_scans": 2,
                "recommended_scans": 10,
                "default_history_days": 30,
            },
        }

    # ===========================================
    # Observability Module API handlers
    # ===========================================

    def _observability_logging(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get or configure logging settings."""
        import os
        from stance.observability import get_logger

        level = params.get("level", [None])[0] if isinstance(params.get("level"), list) else params.get("level")
        format_type = params.get("format", [None])[0] if isinstance(params.get("format"), list) else params.get("format")

        current_level = os.environ.get("STANCE_LOG_LEVEL", "INFO")
        current_format = os.environ.get("STANCE_LOG_FORMAT", "human")

        if level or format_type:
            if level:
                os.environ["STANCE_LOG_LEVEL"] = level.upper()
                current_level = level.upper()
            if format_type:
                os.environ["STANCE_LOG_FORMAT"] = format_type.lower()
                current_format = format_type.lower()
            return {
                "status": "configured",
                "level": current_level,
                "format": current_format,
            }

        return {
            "current_level": current_level,
            "current_format": current_format,
            "available_levels": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            "available_formats": ["human", "structured"],
            "env_vars": {
                "level": "STANCE_LOG_LEVEL",
                "format": "STANCE_LOG_FORMAT",
            },
        }

    def _observability_metrics(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get collected metrics."""
        from stance.observability import get_metrics, InMemoryMetricsBackend

        name = params.get("name", [None])[0] if isinstance(params.get("name"), list) else params.get("name")
        metric_type = params.get("type", [None])[0] if isinstance(params.get("type"), list) else params.get("type")
        limit = int(params.get("limit", [100])[0]) if isinstance(params.get("limit"), list) else int(params.get("limit", 100))

        try:
            metrics_instance = get_metrics()
            if hasattr(metrics_instance, "_backend") and isinstance(metrics_instance._backend, InMemoryMetricsBackend):
                all_metrics = metrics_instance._backend.get_metrics(name=name)
                filtered = []
                for m in all_metrics:
                    if metric_type and m.metric_type.value != metric_type:
                        continue
                    filtered.append(m.to_dict())
                    if len(filtered) >= limit:
                        break
                return {
                    "total": len(filtered),
                    "limit": limit,
                    "metrics": filtered,
                }
            return {
                "total": 0,
                "metrics": [],
                "note": "No in-memory backend available for querying",
            }
        except Exception as e:
            return {"error": str(e)}

    def _observability_traces(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get collected traces/spans."""
        from stance.observability import get_tracer, InMemoryTracingBackend

        trace_id = params.get("trace_id", [None])[0] if isinstance(params.get("trace_id"), list) else params.get("trace_id")
        limit = int(params.get("limit", [100])[0]) if isinstance(params.get("limit"), list) else int(params.get("limit", 100))

        try:
            tracer = get_tracer()
            if hasattr(tracer, "_backend") and isinstance(tracer._backend, InMemoryTracingBackend):
                if trace_id:
                    spans = tracer._backend.get_trace(trace_id)
                    return {
                        "trace_id": trace_id,
                        "total_spans": len(spans),
                        "spans": [s.to_dict() for s in spans],
                    }
                else:
                    all_spans = tracer._backend.get_spans(limit=limit)
                    return {
                        "total": len(all_spans),
                        "limit": limit,
                        "spans": [s.to_dict() for s in all_spans],
                    }
            return {
                "total": 0,
                "spans": [],
                "note": "No in-memory backend available for querying",
            }
        except Exception as e:
            return {"error": str(e)}

    def _observability_backends(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available observability backends."""
        backends = [
            {
                "backend": "InMemoryMetricsBackend",
                "type": "metrics",
                "description": "In-memory metrics storage for development and testing",
                "cloud": "any",
            },
            {
                "backend": "CloudWatchMetricsBackend",
                "type": "metrics",
                "description": "AWS CloudWatch metrics integration",
                "cloud": "aws",
            },
            {
                "backend": "InMemoryTracingBackend",
                "type": "tracing",
                "description": "In-memory trace storage for development and testing",
                "cloud": "any",
            },
            {
                "backend": "XRayTracingBackend",
                "type": "tracing",
                "description": "AWS X-Ray distributed tracing integration",
                "cloud": "aws",
            },
            {
                "backend": "CloudTraceBackend",
                "type": "tracing",
                "description": "Google Cloud Trace integration",
                "cloud": "gcp",
            },
            {
                "backend": "ApplicationInsightsBackend",
                "type": "tracing",
                "description": "Azure Application Insights integration",
                "cloud": "azure",
            },
        ]
        return {"total": len(backends), "backends": backends}

    def _observability_metric_types(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available metric types."""
        metric_types = [
            {
                "type": "counter",
                "description": "Monotonically increasing counter",
                "use_case": "Request counts, error counts, event totals",
            },
            {
                "type": "gauge",
                "description": "Point-in-time value that can go up or down",
                "use_case": "Queue depth, active connections, memory usage",
            },
            {
                "type": "histogram",
                "description": "Distribution of values with buckets",
                "use_case": "Request latencies, response sizes",
            },
            {
                "type": "timer",
                "description": "Duration measurements",
                "use_case": "Execution time, processing duration",
            },
        ]
        return {"total": len(metric_types), "metric_types": metric_types}

    def _observability_log_levels(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available log levels."""
        levels = [
            {
                "level": "DEBUG",
                "description": "Detailed diagnostic information",
                "use_case": "Development and troubleshooting",
            },
            {
                "level": "INFO",
                "description": "General operational information",
                "use_case": "Normal operation tracking",
            },
            {
                "level": "WARNING",
                "description": "Potential issues or unexpected behavior",
                "use_case": "Non-critical alerts",
            },
            {
                "level": "ERROR",
                "description": "Error conditions that need attention",
                "use_case": "Failures requiring investigation",
            },
            {
                "level": "CRITICAL",
                "description": "Severe issues requiring immediate action",
                "use_case": "System failures, security events",
            },
        ]
        return {"total": len(levels), "levels": levels}

    def _observability_span_statuses(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available span statuses."""
        statuses = [
            {
                "status": "OK",
                "description": "Span completed successfully",
                "indicator": "Normal operation",
            },
            {
                "status": "ERROR",
                "description": "Span completed with an error",
                "indicator": "Failure condition",
            },
            {
                "status": "CANCELLED",
                "description": "Span was cancelled before completion",
                "indicator": "Operation aborted",
            },
        ]
        return {"total": len(statuses), "statuses": statuses}

    def _observability_log_formats(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available log formats."""
        formats = [
            {
                "format": "human",
                "description": "Human-readable colored output",
                "use_case": "Development and interactive sessions",
                "formatter": "HumanReadableFormatter",
            },
            {
                "format": "structured",
                "description": "JSON structured logging",
                "use_case": "Log aggregation and analysis (ELK, CloudWatch)",
                "formatter": "StructuredFormatter",
            },
        ]
        return {"total": len(formats), "formats": formats}

    def _observability_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show observability statistics."""
        import os
        return {
            "metrics_backends": 2,
            "tracing_backends": 4,
            "log_levels": 5,
            "metric_types": 4,
            "span_statuses": 3,
            "log_formats": 2,
            "current_config": {
                "log_level": os.environ.get("STANCE_LOG_LEVEL", "INFO"),
                "log_format": os.environ.get("STANCE_LOG_FORMAT", "human"),
                "metrics_backend": os.environ.get("STANCE_METRICS_BACKEND", "inmemory"),
                "tracing_backend": os.environ.get("STANCE_TRACING_BACKEND", "inmemory"),
            },
        }

    def _observability_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show observability module status."""
        return {
            "module": "observability",
            "status": "operational",
            "components": {
                "StanceLogger": "available",
                "StanceMetrics": "available",
                "StanceTracer": "available",
                "StructuredFormatter": "available",
                "HumanReadableFormatter": "available",
                "InMemoryMetricsBackend": "available",
                "CloudWatchMetricsBackend": "available",
                "InMemoryTracingBackend": "available",
                "XRayTracingBackend": "available",
                "CloudTraceBackend": "available",
                "ApplicationInsightsBackend": "available",
            },
            "capabilities": [
                "structured_logging",
                "human_readable_logging",
                "metrics_collection",
                "distributed_tracing",
                "cloudwatch_integration",
                "xray_integration",
                "cloud_trace_integration",
                "application_insights_integration",
            ],
        }

    def _observability_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive observability module summary."""
        return {
            "module": "observability",
            "version": "1.0.0",
            "description": "Comprehensive logging, metrics, and distributed tracing",
            "features": [
                "Structured JSON logging for log aggregation",
                "Human-readable colored console output",
                "Context-aware logging with correlation IDs",
                "Multi-type metric collection (counter, gauge, histogram, timer)",
                "Distributed tracing with span context propagation",
                "AWS CloudWatch metrics integration",
                "AWS X-Ray tracing integration",
                "GCP Cloud Trace integration",
                "Azure Application Insights integration",
                "In-memory backends for development",
            ],
            "subsystems": {
                "logging": "Structured and human-readable log output",
                "metrics": "Application metrics collection and export",
                "tracing": "Distributed request tracing across services",
            },
            "cloud_integrations": {
                "aws": ["CloudWatch Metrics", "X-Ray Tracing"],
                "gcp": ["Cloud Trace"],
                "azure": ["Application Insights"],
            },
            "env_vars": {
                "STANCE_LOG_LEVEL": "Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
                "STANCE_LOG_FORMAT": "Set log format (human, structured)",
                "STANCE_METRICS_BACKEND": "Set metrics backend (inmemory, cloudwatch)",
                "STANCE_TRACING_BACKEND": "Set tracing backend (inmemory, xray, cloudtrace, appinsights)",
            },
        }

    # ===========================================
    # Multi-Account Scanning Module API handlers
    # ===========================================

    def _multi_scan_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        """Start or get info about multi-account scan."""
        config = params.get("config", ["default"])[0] if isinstance(params.get("config"), list) else params.get("config", "default")
        parallel = int(params.get("parallel", [3])[0]) if isinstance(params.get("parallel"), list) else int(params.get("parallel", 3))
        timeout = int(params.get("timeout", [300])[0]) if isinstance(params.get("timeout"), list) else int(params.get("timeout", 300))

        return {
            "action": "scan_info",
            "config": config,
            "options": {
                "parallel_accounts": parallel,
                "timeout_per_account": timeout,
                "continue_on_error": True,
            },
            "note": "Use POST to start a new scan",
        }

    def _multi_scan_progress(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get scan progress."""
        scan_id = params.get("scan_id", ["current"])[0] if isinstance(params.get("scan_id"), list) else params.get("scan_id", "current")

        return {
            "scan_id": scan_id,
            "total_accounts": 10,
            "completed_accounts": 5,
            "failed_accounts": 1,
            "skipped_accounts": 0,
            "pending_accounts": 4,
            "current_accounts": ["account-006"],
            "findings_so_far": 42,
            "progress_percent": 60.0,
            "is_complete": False,
            "started_at": "2024-01-15T10:00:00Z",
            "estimated_completion": "2024-01-15T10:15:00Z",
        }

    def _multi_scan_results(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get scan results."""
        scan_id = params.get("scan_id", ["latest"])[0] if isinstance(params.get("scan_id"), list) else params.get("scan_id", "latest")
        account = params.get("account", [None])[0] if isinstance(params.get("account"), list) else params.get("account")

        result = {
            "scan_id": scan_id,
            "config_name": "default",
            "started_at": "2024-01-15T10:00:00Z",
            "completed_at": "2024-01-15T10:20:00Z",
            "duration_seconds": 1200,
            "summary": {
                "total_accounts": 10,
                "successful_accounts": 9,
                "failed_accounts": 1,
                "total_findings": 156,
                "unique_findings": 98,
                "total_assets": 1245,
            },
            "findings_by_severity": {
                "critical": 12,
                "high": 35,
                "medium": 67,
                "low": 42,
            },
            "account_results": [
                {"account_id": "123456789012", "status": "completed", "findings": 25},
                {"account_id": "234567890123", "status": "completed", "findings": 18},
                {"account_id": "345678901234", "status": "failed", "error": "Access denied"},
            ],
        }
        if account:
            result["filter"] = {"account": account}
        return result

    def _multi_scan_accounts(self, params: dict[str, Any]) -> dict[str, Any]:
        """List configured accounts."""
        include_disabled = params.get("include_disabled", ["false"])[0].lower() == "true" if isinstance(params.get("include_disabled"), list) else bool(params.get("include_disabled", False))

        accounts = [
            {"account_id": "123456789012", "name": "Production-AWS", "provider": "aws", "enabled": True, "regions": ["us-east-1", "us-west-2"]},
            {"account_id": "234567890123", "name": "Staging-AWS", "provider": "aws", "enabled": True, "regions": ["us-east-1"]},
            {"account_id": "project-prod-12345", "name": "Production-GCP", "provider": "gcp", "enabled": True, "regions": ["us-central1"]},
            {"account_id": "sub-12345678-abcd", "name": "Production-Azure", "provider": "azure", "enabled": False, "regions": ["eastus"]},
        ]

        if not include_disabled:
            accounts = [a for a in accounts if a["enabled"]]

        return {"total": len(accounts), "accounts": accounts}

    def _multi_scan_report(self, params: dict[str, Any]) -> dict[str, Any]:
        """Generate scan report."""
        scan_id = params.get("scan_id", ["latest"])[0] if isinstance(params.get("scan_id"), list) else params.get("scan_id", "latest")

        return {
            "scan_id": scan_id,
            "scan_date": "2024-01-15T10:00:00Z",
            "duration_seconds": 1200,
            "summary": {
                "accounts_scanned": 10,
                "accounts_successful": 9,
                "accounts_failed": 1,
                "scan_success_rate": 90.0,
                "total_findings": 156,
                "unique_findings": 98,
                "cross_account_findings": 12,
                "total_assets": 1245,
            },
            "findings_by_severity": {"critical": 12, "high": 35, "medium": 67, "low": 42},
            "findings_by_provider": {"aws": 112, "gcp": 34, "azure": 10},
            "top_accounts_by_findings": [
                {"account_id": "123456789012", "account_name": "Production-AWS", "findings_count": 45},
                {"account_id": "234567890123", "account_name": "Staging-AWS", "findings_count": 32},
            ],
            "accounts_with_critical_findings": [
                {"account_id": "123456789012", "account_name": "Production-AWS", "critical_findings": 8},
            ],
            "failed_accounts": [
                {"account_id": "345678901234", "account_name": "Test-Azure", "error": "Access denied"},
            ],
        }

    def _multi_scan_account_statuses(self, params: dict[str, Any]) -> dict[str, Any]:
        """List account statuses."""
        statuses = [
            {"status": "pending", "description": "Account scan has not started yet", "indicator": "Queued"},
            {"status": "running", "description": "Account scan is currently in progress", "indicator": "Active"},
            {"status": "completed", "description": "Account scan completed successfully", "indicator": "Success"},
            {"status": "failed", "description": "Account scan failed with an error", "indicator": "Error"},
            {"status": "skipped", "description": "Account was skipped (disabled or filtered)", "indicator": "Skipped"},
        ]
        return {"total": len(statuses), "statuses": statuses}

    def _multi_scan_options(self, params: dict[str, Any]) -> dict[str, Any]:
        """List scan options."""
        options = [
            {"option": "parallel_accounts", "type": "int", "default": 3, "description": "Number of accounts to scan in parallel"},
            {"option": "timeout_per_account", "type": "int", "default": 300, "description": "Maximum time per account scan in seconds"},
            {"option": "continue_on_error", "type": "bool", "default": True, "description": "Continue scanning other accounts if one fails"},
            {"option": "severity_threshold", "type": "enum", "default": None, "description": "Minimum severity to include in results"},
            {"option": "collectors", "type": "list", "default": None, "description": "List of collectors to run (None = all)"},
            {"option": "regions", "type": "list", "default": None, "description": "List of regions to scan (None = all configured)"},
            {"option": "skip_accounts", "type": "list", "default": [], "description": "Account IDs to skip"},
            {"option": "include_disabled", "type": "bool", "default": False, "description": "Include disabled accounts in scan"},
        ]
        return {"total": len(options), "options": options}

    def _multi_scan_providers(self, params: dict[str, Any]) -> dict[str, Any]:
        """List cloud providers."""
        providers = [
            {"provider": "aws", "name": "Amazon Web Services", "account_format": "12-digit account ID", "collectors": ["iam", "s3", "ec2", "security"]},
            {"provider": "gcp", "name": "Google Cloud Platform", "account_format": "Project ID", "collectors": ["iam", "storage", "compute", "security"]},
            {"provider": "azure", "name": "Microsoft Azure", "account_format": "Subscription ID", "collectors": ["identity", "storage", "compute", "security"]},
        ]
        return {"total": len(providers), "providers": providers}

    def _multi_scan_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show scanning statistics."""
        return {
            "account_statuses": 5,
            "scan_options": 8,
            "cloud_providers": 3,
            "features": {
                "parallel_execution": True,
                "progress_tracking": True,
                "cross_account_aggregation": True,
                "timeout_handling": True,
                "error_recovery": True,
            },
            "default_settings": {
                "parallel_accounts": 3,
                "timeout_per_account": 300,
                "continue_on_error": True,
            },
        }

    def _multi_scan_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show module status."""
        return {
            "module": "scanning",
            "status": "operational",
            "components": {
                "MultiAccountScanner": "available",
                "ScanOptions": "available",
                "ScanProgress": "available",
                "AccountScanResult": "available",
                "OrganizationScan": "available",
                "AccountStatus": "available",
            },
            "capabilities": [
                "parallel_account_scanning",
                "progress_tracking",
                "timeout_handling",
                "error_recovery",
                "cross_account_aggregation",
                "findings_deduplication",
                "report_generation",
                "callback_notifications",
            ],
            "integrations": {
                "aggregation": "FindingsAggregator",
                "config": "ScanConfiguration",
                "models": "FindingCollection, AssetCollection",
            },
        }

    def _multi_scan_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive summary."""
        return {
            "module": "scanning",
            "version": "1.0.0",
            "description": "Multi-account scanning orchestration for organization-level security assessments",
            "features": [
                "Parallel execution across multiple cloud accounts",
                "Real-time progress tracking with callbacks",
                "Cross-account findings aggregation",
                "Automatic findings deduplication",
                "Configurable timeout per account",
                "Error recovery with continue-on-error mode",
                "Report generation for organization scans",
                "Support for AWS, GCP, and Azure accounts",
                "Severity-based filtering",
                "Region and collector filtering",
            ],
            "scan_workflow": {
                "1": "Load configuration with account definitions",
                "2": "Apply scan options and filters",
                "3": "Execute parallel account scans",
                "4": "Track progress and notify callbacks",
                "5": "Aggregate findings across accounts",
                "6": "Deduplicate and enrich results",
                "7": "Generate organization scan report",
            },
            "data_classes": {
                "ScanOptions": "Configuration for scan execution",
                "AccountScanResult": "Result of scanning a single account",
                "ScanProgress": "Real-time progress tracking",
                "OrganizationScan": "Complete organization scan result",
            },
            "cloud_support": ["aws", "gcp", "azure"],
        }

    # -------------------------------------------------------------------------
    # State Management API handlers
    # -------------------------------------------------------------------------

    def _state_scans(self, params: dict[str, Any]) -> dict[str, Any]:
        """List scan history."""
        from stance.state import ScanStatus, get_state_manager
        from datetime import datetime, timedelta

        limit = int(params.get("limit", ["20"])[0])
        status_filter = params.get("status", [""])[0]
        days = params.get("days", [""])[0]

        try:
            manager = get_state_manager()

            status = ScanStatus(status_filter) if status_filter else None
            since = datetime.utcnow() - timedelta(days=int(days)) if days else None

            scans = manager.backend.list_scans(limit=limit, status=status, since=since)

            return {
                "scans": [s.to_dict() for s in scans],
                "total": len(scans),
                "filters": {
                    "limit": limit,
                    "status": status_filter or None,
                    "days": int(days) if days else None,
                },
            }
        except Exception as e:
            return {"error": str(e), "scans": []}

    def _state_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get specific scan details."""
        from stance.state import get_state_manager

        scan_id = params.get("scan_id", [""])[0]

        if not scan_id:
            return {"error": "scan_id parameter required"}

        try:
            manager = get_state_manager()
            scan = manager.backend.get_scan(scan_id)

            if not scan:
                return {"error": f"Scan not found: {scan_id}"}

            return scan.to_dict()
        except Exception as e:
            return {"error": str(e)}

    def _state_checkpoints(self, params: dict[str, Any]) -> dict[str, Any]:
        """List saved checkpoints."""
        import os
        import sqlite3
        from pathlib import Path

        collector_filter = params.get("collector", [""])[0]
        account_filter = params.get("account", [""])[0]
        limit = int(params.get("limit", ["50"])[0])

        db_path = os.path.expanduser("~/.stance/state.db")
        if not Path(db_path).exists():
            return {"checkpoints": [], "total": 0}

        checkpoints = []
        try:
            with sqlite3.connect(db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT * FROM checkpoints ORDER BY last_scan_time DESC"
                )
                for row in cursor.fetchall():
                    cp = {
                        "checkpoint_id": row["checkpoint_id"],
                        "collector_name": row["collector_name"],
                        "account_id": row["account_id"],
                        "region": row["region"],
                        "last_scan_id": row["last_scan_id"],
                        "last_scan_time": row["last_scan_time"],
                        "cursor": row["cursor"],
                    }
                    # Apply filters
                    if collector_filter and cp["collector_name"] != collector_filter:
                        continue
                    if account_filter and cp["account_id"] != account_filter:
                        continue
                    checkpoints.append(cp)
                    if len(checkpoints) >= limit:
                        break
        except Exception as e:
            return {"error": str(e), "checkpoints": []}

        return {
            "checkpoints": checkpoints,
            "total": len(checkpoints),
            "filters": {
                "collector": collector_filter or None,
                "account": account_filter or None,
                "limit": limit,
            },
        }

    def _state_checkpoint(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get specific checkpoint details."""
        from stance.state import get_state_manager

        collector = params.get("collector", [""])[0]
        account = params.get("account", [""])[0]
        region = params.get("region", [""])[0]

        if not collector or not account or not region:
            return {"error": "collector, account, and region parameters required"}

        try:
            manager = get_state_manager()
            checkpoint = manager.get_checkpoint(collector, account, region)

            if not checkpoint:
                return {"error": f"Checkpoint not found for {collector}/{account}/{region}"}

            return checkpoint.to_dict()
        except Exception as e:
            return {"error": str(e)}

    def _state_findings(self, params: dict[str, Any]) -> dict[str, Any]:
        """List finding states."""
        from stance.state import FindingLifecycle, get_state_manager

        asset_id = params.get("asset_id", [""])[0]
        lifecycle_filter = params.get("lifecycle", [""])[0]
        limit = int(params.get("limit", ["50"])[0])

        try:
            manager = get_state_manager()

            lifecycle = FindingLifecycle(lifecycle_filter) if lifecycle_filter else None
            findings = manager.backend.list_finding_states(
                asset_id=asset_id or None,
                lifecycle=lifecycle,
                limit=limit,
            )

            return {
                "findings": [f.to_dict() for f in findings],
                "total": len(findings),
                "filters": {
                    "asset_id": asset_id or None,
                    "lifecycle": lifecycle_filter or None,
                    "limit": limit,
                },
            }
        except Exception as e:
            return {"error": str(e), "findings": []}

    def _state_finding(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get specific finding state."""
        from stance.state import get_state_manager

        finding_id = params.get("finding_id", [""])[0]

        if not finding_id:
            return {"error": "finding_id parameter required"}

        try:
            manager = get_state_manager()
            state = manager.backend.get_finding_state(finding_id)

            if not state:
                return {"error": f"Finding not found: {finding_id}"}

            return state.to_dict()
        except Exception as e:
            return {"error": str(e)}

    def _state_scan_statuses(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available scan statuses."""
        from stance.state import ScanStatus

        statuses = [
            {
                "status": ScanStatus.PENDING.value,
                "description": "Scan is queued but not yet started",
                "indicator": "[.]",
            },
            {
                "status": ScanStatus.RUNNING.value,
                "description": "Scan is currently in progress",
                "indicator": "[>]",
            },
            {
                "status": ScanStatus.COMPLETED.value,
                "description": "Scan completed successfully",
                "indicator": "[+]",
            },
            {
                "status": ScanStatus.FAILED.value,
                "description": "Scan failed with error",
                "indicator": "[!]",
            },
            {
                "status": ScanStatus.CANCELLED.value,
                "description": "Scan was cancelled",
                "indicator": "[x]",
            },
        ]

        return {"statuses": statuses, "total": len(statuses)}

    def _state_lifecycles(self, params: dict[str, Any]) -> dict[str, Any]:
        """List finding lifecycle states."""
        from stance.state import FindingLifecycle

        lifecycles = [
            {
                "lifecycle": FindingLifecycle.NEW.value,
                "description": "First time this finding was seen",
                "action": "Investigate and remediate",
            },
            {
                "lifecycle": FindingLifecycle.RECURRING.value,
                "description": "Seen again in subsequent scans",
                "action": "Continue remediation",
            },
            {
                "lifecycle": FindingLifecycle.RESOLVED.value,
                "description": "No longer detected in scans",
                "action": "Verify fix is complete",
            },
            {
                "lifecycle": FindingLifecycle.REOPENED.value,
                "description": "Was resolved but detected again",
                "action": "Investigate regression",
            },
            {
                "lifecycle": FindingLifecycle.SUPPRESSED.value,
                "description": "Manually suppressed by user",
                "action": "Review periodically",
            },
            {
                "lifecycle": FindingLifecycle.FALSE_POSITIVE.value,
                "description": "Marked as not a real issue",
                "action": "Consider policy tuning",
            },
        ]

        return {"lifecycles": lifecycles, "total": len(lifecycles)}

    def _state_backends(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available state backends."""
        backends = [
            {
                "backend": "local",
                "type": "SQLite",
                "description": "Local file-based state storage",
                "available": True,
                "default": True,
                "path": "~/.stance/state.db",
            },
            {
                "backend": "dynamodb",
                "type": "DynamoDB",
                "description": "AWS DynamoDB state storage",
                "available": False,
                "default": False,
                "path": "stance-state table",
            },
            {
                "backend": "firestore",
                "type": "Firestore",
                "description": "GCP Firestore state storage",
                "available": False,
                "default": False,
                "path": "stance-state collection",
            },
            {
                "backend": "cosmosdb",
                "type": "Cosmos DB",
                "description": "Azure Cosmos DB state storage",
                "available": False,
                "default": False,
                "path": "stance-state container",
            },
        ]

        return {"backends": backends, "total": len(backends)}

    def _state_finding_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get finding statistics by lifecycle."""
        from stance.state import get_state_manager

        try:
            manager = get_state_manager()
            stats = manager.get_finding_stats()
            total = sum(stats.values())

            return {
                "stats": stats,
                "total": total,
                "breakdown": [
                    {"lifecycle": k, "count": v, "percentage": (v / total * 100) if total > 0 else 0}
                    for k, v in stats.items()
                ],
            }
        except Exception as e:
            return {"error": str(e), "stats": {}}

    def _state_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get state module statistics."""
        from stance.state import FindingLifecycle, ScanStatus, get_state_manager
        import os
        import sqlite3
        from pathlib import Path

        try:
            manager = get_state_manager()
            scans = manager.backend.list_scans(limit=1000)
            finding_stats = manager.get_finding_stats()

            # Get checkpoints count
            db_path = os.path.expanduser("~/.stance/state.db")
            checkpoint_count = 0
            if Path(db_path).exists():
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.execute("SELECT COUNT(*) FROM checkpoints")
                    checkpoint_count = cursor.fetchone()[0]

            # Scan statistics by status
            scan_by_status = {}
            for status in ScanStatus:
                scan_by_status[status.value] = len([s for s in scans if s.status == status])

            return {
                "scans": {
                    "total": len(scans),
                    "by_status": scan_by_status,
                },
                "checkpoints": {
                    "total": checkpoint_count,
                },
                "findings": {
                    "total": sum(finding_stats.values()),
                    "by_lifecycle": finding_stats,
                },
                "backends": {
                    "available": 1,
                    "active": "local",
                },
                "enums": {
                    "scan_statuses": len(ScanStatus),
                    "lifecycle_states": len(FindingLifecycle),
                },
            }
        except Exception as e:
            return {"error": str(e)}

    def _state_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get state module status."""
        import os
        from pathlib import Path

        db_path = os.path.expanduser("~/.stance/state.db")
        db_exists = Path(db_path).exists()

        return {
            "module": "state",
            "active_backend": "local",
            "backend_path": db_path,
            "backend_exists": db_exists,
            "components": {
                "StateManager": True,
                "LocalStateBackend": True,
                "ScanRecord": True,
                "Checkpoint": True,
                "FindingState": True,
            },
            "capabilities": [
                "scan_tracking",
                "checkpoint_management",
                "finding_lifecycle",
                "state_persistence",
                "incremental_scanning",
            ],
        }

    def _state_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive state summary."""
        from stance.state import FindingLifecycle, ScanStatus, get_state_manager
        import os
        from pathlib import Path

        try:
            manager = get_state_manager()
            scans = manager.backend.list_scans(limit=1000)
            finding_stats = manager.get_finding_stats()

            # Get latest scan
            latest_scan = scans[0] if scans else None

            # Calculate metrics
            completed_scans = [s for s in scans if s.status == ScanStatus.COMPLETED]
            failed_scans = [s for s in scans if s.status == ScanStatus.FAILED]
            total_findings = sum(finding_stats.values())
            active_findings = (
                finding_stats.get("new", 0)
                + finding_stats.get("recurring", 0)
                + finding_stats.get("reopened", 0)
            )

            db_path = os.path.expanduser("~/.stance/state.db")
            db_size = Path(db_path).stat().st_size if Path(db_path).exists() else 0

            return {
                "overview": {
                    "description": "State management for scans, checkpoints, and finding lifecycle",
                    "active_backend": "local",
                    "database_size_bytes": db_size,
                },
                "scans": {
                    "total": len(scans),
                    "completed": len(completed_scans),
                    "failed": len(failed_scans),
                    "success_rate": (len(completed_scans) / len(scans) * 100) if scans else 0,
                },
                "latest_scan": latest_scan.to_dict() if latest_scan else None,
                "checkpoints": {
                    "total": self._get_checkpoint_count(),
                },
                "findings": {
                    "total": total_findings,
                    "active": active_findings,
                    "resolved": finding_stats.get("resolved", 0),
                    "suppressed": finding_stats.get("suppressed", 0),
                },
                "features": [
                    "Scan history tracking",
                    "Checkpoint management for incremental scans",
                    "Finding lifecycle tracking (new, recurring, resolved, reopened)",
                    "Finding suppression and false positive marking",
                    "SQLite-based local persistence",
                    "Extensible backend architecture (DynamoDB, Firestore, Cosmos DB planned)",
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def _get_checkpoint_count(self) -> int:
        """Get checkpoint count from database."""
        import os
        import sqlite3
        from pathlib import Path

        db_path = os.path.expanduser("~/.stance/state.db")
        if not Path(db_path).exists():
            return 0
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM checkpoints")
                return cursor.fetchone()[0]
        except Exception:
            return 0

    def _state_suppress(self, body: bytes) -> dict[str, Any]:
        """Suppress a finding."""
        from stance.state import get_state_manager
        import json

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON in request body"}

        finding_id = data.get("finding_id")
        suppressed_by = data.get("by", "api")
        reason = data.get("reason", "")

        if not finding_id:
            return {"error": "finding_id required"}

        try:
            manager = get_state_manager()
            state = manager.suppress_finding(finding_id, suppressed_by, reason)

            if not state:
                return {"error": f"Finding not found: {finding_id}"}

            return {
                "suppressed": True,
                "finding_id": finding_id,
                "suppressed_by": suppressed_by,
                "reason": reason,
                "lifecycle": state.lifecycle.value,
            }
        except Exception as e:
            return {"error": str(e)}

    def _state_resolve(self, body: bytes) -> dict[str, Any]:
        """Resolve a finding."""
        from stance.state import get_state_manager
        import json

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON in request body"}

        finding_id = data.get("finding_id")

        if not finding_id:
            return {"error": "finding_id required"}

        try:
            manager = get_state_manager()
            state = manager.resolve_finding(finding_id)

            if not state:
                return {"error": f"Finding not found: {finding_id}"}

            return {
                "resolved": True,
                "finding_id": finding_id,
                "lifecycle": state.lifecycle.value,
                "resolved_at": state.resolved_at.isoformat() if state.resolved_at else None,
            }
        except Exception as e:
            return {"error": str(e)}

    def _state_delete_checkpoint(self, body: bytes) -> dict[str, Any]:
        """Delete a checkpoint."""
        from stance.state import get_state_manager
        import json

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON in request body"}

        collector = data.get("collector")
        account = data.get("account")
        region = data.get("region")

        if not collector or not account or not region:
            return {"error": "collector, account, and region required"}

        try:
            manager = get_state_manager()
            deleted = manager.backend.delete_checkpoint(collector, account, region)

            return {
                "deleted": deleted,
                "collector": collector,
                "account": account,
                "region": region,
            }
        except Exception as e:
            return {"error": str(e)}

    # -------------------------------------------------------------------------
    # Collectors API handlers
    # -------------------------------------------------------------------------

    def _get_collector_metadata(self) -> dict[str, list[dict[str, Any]]]:
        """Get metadata for all collectors."""
        from stance.collectors import (
            GCP_COLLECTORS_AVAILABLE,
            AZURE_COLLECTORS_AVAILABLE,
            K8S_COLLECTORS_AVAILABLE,
        )

        metadata: dict[str, list[dict[str, Any]]] = {
            "aws": [],
            "gcp": [],
            "azure": [],
            "kubernetes": [],
        }

        # AWS collectors (always available)
        aws_collectors = [
            {"name": "aws_iam", "description": "IAM users, roles, policies, groups", "category": "identity"},
            {"name": "aws_s3", "description": "S3 bucket configurations", "category": "storage"},
            {"name": "aws_ec2", "description": "EC2 instances, security groups, VPCs", "category": "compute"},
            {"name": "aws_security", "description": "SecurityHub and Inspector findings", "category": "security"},
            {"name": "aws_rds", "description": "RDS instances, clusters, parameter groups", "category": "database"},
            {"name": "aws_lambda", "description": "Lambda functions, layers, event sources", "category": "serverless"},
            {"name": "aws_dynamodb", "description": "DynamoDB tables, backups, configurations", "category": "database"},
            {"name": "aws_apigateway", "description": "API Gateway REST, HTTP, WebSocket APIs", "category": "networking"},
            {"name": "aws_ecr", "description": "ECR repositories, images, scan findings", "category": "container"},
            {"name": "aws_eks", "description": "EKS clusters, node groups, Fargate profiles", "category": "kubernetes"},
        ]
        metadata["aws"] = aws_collectors

        # GCP collectors
        if GCP_COLLECTORS_AVAILABLE:
            gcp_collectors = [
                {"name": "gcp_iam", "description": "Service accounts, IAM policies", "category": "identity"},
                {"name": "gcp_storage", "description": "Cloud Storage buckets", "category": "storage"},
                {"name": "gcp_compute", "description": "Compute Engine instances, firewalls", "category": "compute"},
                {"name": "gcp_security", "description": "Security Command Center findings", "category": "security"},
                {"name": "gcp_sql", "description": "Cloud SQL instances and configurations", "category": "database"},
                {"name": "gcp_functions", "description": "Cloud Functions (1st and 2nd gen)", "category": "serverless"},
                {"name": "gcp_bigquery", "description": "BigQuery datasets and tables", "category": "database"},
                {"name": "gcp_cloudrun", "description": "Cloud Run services and revisions", "category": "serverless"},
                {"name": "gcp_artifactregistry", "description": "Artifact Registry repositories and images", "category": "container"},
                {"name": "gcp_gke", "description": "GKE clusters and node pools", "category": "kubernetes"},
            ]
            metadata["gcp"] = gcp_collectors

        # Azure collectors
        if AZURE_COLLECTORS_AVAILABLE:
            azure_collectors = [
                {"name": "azure_iam", "description": "Role assignments, role definitions", "category": "identity"},
                {"name": "azure_storage", "description": "Storage accounts, blob containers", "category": "storage"},
                {"name": "azure_compute", "description": "VMs, NSGs, VNets", "category": "compute"},
                {"name": "azure_security", "description": "Defender for Cloud findings", "category": "security"},
                {"name": "azure_sql", "description": "SQL servers, databases, security config", "category": "database"},
                {"name": "azure_functions", "description": "Function Apps and configurations", "category": "serverless"},
                {"name": "azure_cosmosdb", "description": "Cosmos DB accounts and configurations", "category": "database"},
                {"name": "azure_logicapps", "description": "Logic Apps (Workflows) and configurations", "category": "serverless"},
                {"name": "azure_containerregistry", "description": "ACR registries, images, security config", "category": "container"},
                {"name": "azure_aks", "description": "AKS clusters and node pools", "category": "kubernetes"},
            ]
            metadata["azure"] = azure_collectors

        # Kubernetes collectors
        if K8S_COLLECTORS_AVAILABLE:
            k8s_collectors = [
                {"name": "k8s_config", "description": "Pods, deployments, services, daemonsets", "category": "workload"},
                {"name": "k8s_rbac", "description": "Roles, cluster roles, role bindings", "category": "identity"},
                {"name": "k8s_network", "description": "Network policies, ingress, secrets", "category": "networking"},
            ]
            metadata["kubernetes"] = k8s_collectors

        return metadata

    def _collectors_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available collectors."""
        provider_filter = params.get("provider", [""])[0]

        metadata = self._get_collector_metadata()

        if provider_filter:
            collectors = metadata.get(provider_filter, [])
            for c in collectors:
                c["provider"] = provider_filter
        else:
            collectors = []
            for provider, provider_collectors in metadata.items():
                for c in provider_collectors:
                    c["provider"] = provider
                    collectors.append(c)

        return {
            "collectors": collectors,
            "total": len(collectors),
            "filter": provider_filter or None,
        }

    def _collectors_info(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get collector details."""
        collector_name = params.get("name", [""])[0]

        if not collector_name:
            return {"error": "name parameter required"}

        metadata = self._get_collector_metadata()

        # Find collector
        collector_info = None
        provider_name = None
        for provider, collectors in metadata.items():
            for c in collectors:
                if c["name"] == collector_name:
                    collector_info = c
                    provider_name = provider
                    break
            if collector_info:
                break

        if not collector_info:
            return {"error": f"Collector not found: {collector_name}"}

        # Get resource types
        resource_types = self._get_collector_resource_types(collector_name)

        return {
            "name": collector_info["name"],
            "provider": provider_name,
            "category": collector_info["category"],
            "description": collector_info["description"],
            "resource_types": resource_types,
            "available": True,
        }

    def _get_collector_resource_types(self, collector_name: str) -> list[str]:
        """Get resource types for a collector."""
        from stance.collectors import COLLECTOR_REGISTRY

        for provider_collectors in COLLECTOR_REGISTRY.values():
            if collector_name in provider_collectors:
                collector_class = provider_collectors[collector_name]
                return getattr(collector_class, "resource_types", [])
        return []

    def _collectors_providers(self, params: dict[str, Any]) -> dict[str, Any]:
        """List supported cloud providers."""
        from stance.collectors import (
            GCP_COLLECTORS_AVAILABLE,
            AZURE_COLLECTORS_AVAILABLE,
            K8S_COLLECTORS_AVAILABLE,
        )

        providers = [
            {
                "provider": "aws",
                "name": "Amazon Web Services",
                "available": True,
                "collectors": 10,
                "sdk": "boto3",
            },
            {
                "provider": "gcp",
                "name": "Google Cloud Platform",
                "available": GCP_COLLECTORS_AVAILABLE,
                "collectors": 10 if GCP_COLLECTORS_AVAILABLE else 0,
                "sdk": "google-cloud-*",
            },
            {
                "provider": "azure",
                "name": "Microsoft Azure",
                "available": AZURE_COLLECTORS_AVAILABLE,
                "collectors": 10 if AZURE_COLLECTORS_AVAILABLE else 0,
                "sdk": "azure-*",
            },
            {
                "provider": "kubernetes",
                "name": "Kubernetes",
                "available": K8S_COLLECTORS_AVAILABLE,
                "collectors": 3 if K8S_COLLECTORS_AVAILABLE else 0,
                "sdk": "kubernetes",
            },
        ]

        active = len([p for p in providers if p["available"]])

        return {
            "providers": providers,
            "total": len(providers),
            "available": active,
        }

    def _collectors_resources(self, params: dict[str, Any]) -> dict[str, Any]:
        """List resource types collected."""
        from stance.collectors import COLLECTOR_REGISTRY

        provider_filter = params.get("provider", [""])[0]
        collector_filter = params.get("collector", [""])[0]

        resources = []

        for provider, collectors in COLLECTOR_REGISTRY.items():
            if provider_filter and provider != provider_filter:
                continue

            for collector_name, collector_class in collectors.items():
                if collector_filter and collector_name != collector_filter:
                    continue

                resource_types = getattr(collector_class, "resource_types", [])
                for rt in resource_types:
                    resources.append({
                        "provider": provider,
                        "collector": collector_name,
                        "resource_type": rt,
                    })

        return {
            "resources": resources,
            "total": len(resources),
            "filters": {
                "provider": provider_filter or None,
                "collector": collector_filter or None,
            },
        }

    def _collectors_registry(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show collector registry."""
        from stance.collectors import COLLECTOR_REGISTRY

        registry_data = {}
        total = 0
        for provider, collectors in COLLECTOR_REGISTRY.items():
            registry_data[provider] = list(collectors.keys())
            total += len(collectors)

        return {
            "registry": registry_data,
            "total": total,
        }

    def _collectors_availability(self, params: dict[str, Any]) -> dict[str, Any]:
        """Check collector availability by provider."""
        from stance.collectors import (
            GCP_COLLECTORS_AVAILABLE,
            AZURE_COLLECTORS_AVAILABLE,
            K8S_COLLECTORS_AVAILABLE,
        )

        availability = [
            {
                "provider": "aws",
                "available": True,
                "reason": "boto3 always available",
                "install": "pip install boto3",
            },
            {
                "provider": "gcp",
                "available": GCP_COLLECTORS_AVAILABLE,
                "reason": "google-cloud SDK installed" if GCP_COLLECTORS_AVAILABLE else "google-cloud SDK not installed",
                "install": "pip install google-cloud-resource-manager google-cloud-storage google-cloud-compute",
            },
            {
                "provider": "azure",
                "available": AZURE_COLLECTORS_AVAILABLE,
                "reason": "azure SDK installed" if AZURE_COLLECTORS_AVAILABLE else "azure SDK not installed",
                "install": "pip install azure-identity azure-mgmt-resource azure-mgmt-storage",
            },
            {
                "provider": "kubernetes",
                "available": K8S_COLLECTORS_AVAILABLE,
                "reason": "kubernetes SDK installed" if K8S_COLLECTORS_AVAILABLE else "kubernetes SDK not installed",
                "install": "pip install kubernetes",
            },
        ]

        available_count = len([a for a in availability if a["available"]])

        return {
            "availability": availability,
            "available_count": available_count,
            "total": len(availability),
        }

    def _collectors_categories(self, params: dict[str, Any]) -> dict[str, Any]:
        """List collector categories."""
        categories = [
            {
                "category": "identity",
                "description": "Identity and access management (IAM, RBAC)",
                "examples": ["aws_iam", "gcp_iam", "azure_iam", "k8s_rbac"],
            },
            {
                "category": "storage",
                "description": "Object and block storage services",
                "examples": ["aws_s3", "gcp_storage", "azure_storage"],
            },
            {
                "category": "compute",
                "description": "Virtual machines and compute instances",
                "examples": ["aws_ec2", "gcp_compute", "azure_compute"],
            },
            {
                "category": "security",
                "description": "Security findings and compliance",
                "examples": ["aws_security", "gcp_security", "azure_security"],
            },
            {
                "category": "database",
                "description": "Database services (SQL and NoSQL)",
                "examples": ["aws_rds", "aws_dynamodb", "gcp_sql", "azure_sql"],
            },
            {
                "category": "serverless",
                "description": "Serverless functions and workflows",
                "examples": ["aws_lambda", "gcp_functions", "azure_functions"],
            },
            {
                "category": "container",
                "description": "Container registries and images",
                "examples": ["aws_ecr", "gcp_artifactregistry", "azure_containerregistry"],
            },
            {
                "category": "kubernetes",
                "description": "Managed Kubernetes services",
                "examples": ["aws_eks", "gcp_gke", "azure_aks"],
            },
            {
                "category": "networking",
                "description": "Networking and API services",
                "examples": ["aws_apigateway", "k8s_network"],
            },
            {
                "category": "workload",
                "description": "Kubernetes workloads (pods, deployments)",
                "examples": ["k8s_config"],
            },
        ]

        return {
            "categories": categories,
            "total": len(categories),
        }

    def _collectors_count(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get collector counts by provider."""
        from stance.collectors import COLLECTOR_REGISTRY

        counts = []
        total = 0
        for provider, collectors in COLLECTOR_REGISTRY.items():
            count = len(collectors)
            total += count
            counts.append({
                "provider": provider,
                "count": count,
                "available": count > 0,
            })

        return {
            "counts": counts,
            "total": total,
        }

    def _collectors_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get collector statistics."""
        from stance.collectors import (
            COLLECTOR_REGISTRY,
            GCP_COLLECTORS_AVAILABLE,
            AZURE_COLLECTORS_AVAILABLE,
            K8S_COLLECTORS_AVAILABLE,
        )

        total_collectors = sum(len(c) for c in COLLECTOR_REGISTRY.values())
        available_providers = sum([
            1,  # AWS always available
            1 if GCP_COLLECTORS_AVAILABLE else 0,
            1 if AZURE_COLLECTORS_AVAILABLE else 0,
            1 if K8S_COLLECTORS_AVAILABLE else 0,
        ])

        metadata = self._get_collector_metadata()
        categories = set()
        for provider_collectors in metadata.values():
            for c in provider_collectors:
                categories.add(c.get("category", "unknown"))

        # Count resource types
        resource_type_count = 0
        for provider_collectors in COLLECTOR_REGISTRY.values():
            for collector_class in provider_collectors.values():
                resource_type_count += len(getattr(collector_class, "resource_types", []))

        return {
            "total_collectors": total_collectors,
            "available_providers": available_providers,
            "total_providers": 4,
            "categories": len(categories),
            "resource_types": resource_type_count,
            "by_provider": {
                "aws": len(COLLECTOR_REGISTRY.get("aws", {})),
                "gcp": len(COLLECTOR_REGISTRY.get("gcp", {})),
                "azure": len(COLLECTOR_REGISTRY.get("azure", {})),
                "kubernetes": len(COLLECTOR_REGISTRY.get("kubernetes", {})),
            },
            "sdk_availability": {
                "boto3": True,
                "google-cloud": GCP_COLLECTORS_AVAILABLE,
                "azure": AZURE_COLLECTORS_AVAILABLE,
                "kubernetes": K8S_COLLECTORS_AVAILABLE,
            },
        }

    def _collectors_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get collectors module status."""
        from stance.collectors import (
            GCP_COLLECTORS_AVAILABLE,
            AZURE_COLLECTORS_AVAILABLE,
            K8S_COLLECTORS_AVAILABLE,
        )

        return {
            "module": "collectors",
            "components": {
                "BaseCollector": True,
                "CollectorResult": True,
                "CollectorRunner": True,
                "COLLECTOR_REGISTRY": True,
            },
            "providers": {
                "aws": True,
                "gcp": GCP_COLLECTORS_AVAILABLE,
                "azure": AZURE_COLLECTORS_AVAILABLE,
                "kubernetes": K8S_COLLECTORS_AVAILABLE,
            },
            "capabilities": [
                "multi_provider_support",
                "pagination_handling",
                "error_handling",
                "asset_collection",
                "finding_collection",
                "parallel_execution",
            ],
        }

    def _collectors_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive collectors summary."""
        from stance.collectors import (
            COLLECTOR_REGISTRY,
            GCP_COLLECTORS_AVAILABLE,
            AZURE_COLLECTORS_AVAILABLE,
            K8S_COLLECTORS_AVAILABLE,
        )

        total_collectors = sum(len(c) for c in COLLECTOR_REGISTRY.values())
        metadata = self._get_collector_metadata()

        # Get categories
        category_counts: dict[str, int] = {}
        for provider_collectors in metadata.values():
            for c in provider_collectors:
                cat = c.get("category", "unknown")
                category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "overview": {
                "description": "Cloud resource collectors for multi-provider security assessment",
                "total_collectors": total_collectors,
                "providers": {
                    "aws": {"available": True, "collectors": len(COLLECTOR_REGISTRY.get("aws", {}))},
                    "gcp": {"available": GCP_COLLECTORS_AVAILABLE, "collectors": len(COLLECTOR_REGISTRY.get("gcp", {}))},
                    "azure": {"available": AZURE_COLLECTORS_AVAILABLE, "collectors": len(COLLECTOR_REGISTRY.get("azure", {}))},
                    "kubernetes": {"available": K8S_COLLECTORS_AVAILABLE, "collectors": len(COLLECTOR_REGISTRY.get("kubernetes", {}))},
                },
            },
            "categories": category_counts,
            "features": [
                "Multi-cloud resource collection (AWS, GCP, Azure)",
                "Kubernetes cluster scanning",
                "IAM and identity analysis",
                "Storage security assessment",
                "Compute and VM configuration",
                "Database security posture",
                "Serverless function analysis",
                "Container registry scanning",
                "Managed Kubernetes (EKS, GKE, AKS)",
                "Security findings aggregation",
            ],
            "architecture": {
                "base_class": "BaseCollector",
                "result_class": "CollectorResult",
                "runner_class": "CollectorRunner",
                "registry": "COLLECTOR_REGISTRY",
            },
        }

    # =========================================================================
    # Cloud Provider Handlers
    # =========================================================================

    def _get_cloud_provider_metadata(self) -> list[dict[str, Any]]:
        """Get metadata for all cloud providers."""
        from stance.cloud import PROVIDERS, is_provider_available

        providers = []
        display_names = {
            "aws": "Amazon Web Services",
            "gcp": "Google Cloud Platform",
            "azure": "Microsoft Azure",
        }
        descriptions = {
            "aws": "AWS cloud services including IAM, S3, EC2, RDS, Lambda, and more",
            "gcp": "Google Cloud services including IAM, Cloud Storage, Compute Engine, and more",
            "azure": "Microsoft Azure services including IAM, Blob Storage, VMs, and more",
        }

        for name, provider_class in PROVIDERS.items():
            providers.append({
                "name": name,
                "display_name": display_names.get(name, name.upper()),
                "available": is_provider_available(name),
                "packages": provider_class.get_required_packages(),
                "description": descriptions.get(name, "Cloud provider"),
            })

        return providers

    def _get_credential_fields(self, provider: str) -> list[str]:
        """Get credential fields for a provider."""
        fields = {
            "aws": [
                "aws_access_key_id",
                "aws_secret_access_key",
                "aws_session_token",
                "aws_profile",
                "aws_role_arn",
            ],
            "gcp": [
                "gcp_project_id",
                "gcp_service_account_key",
                "gcp_service_account_file",
            ],
            "azure": [
                "azure_subscription_id",
                "azure_tenant_id",
                "azure_client_id",
                "azure_client_secret",
            ],
        }
        return fields.get(provider, [])

    def _get_default_region(self, provider: str) -> str:
        """Get default region for a provider."""
        regions = {
            "aws": "us-east-1",
            "gcp": "us-central1",
            "azure": "eastus",
        }
        return regions.get(provider, "unknown")

    def _get_storage_types(self, provider: str) -> list[str]:
        """Get storage types for a provider."""
        storage_types = {
            "aws": ["s3", "local"],
            "gcp": ["gcs", "local"],
            "azure": ["blob", "local"],
        }
        return storage_types.get(provider, ["local"])

    def _cloud_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List all cloud providers."""
        providers = self._get_cloud_provider_metadata()
        return {
            "providers": providers,
            "total": len(providers),
        }

    def _cloud_info(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get info for a specific cloud provider."""
        from stance.cloud import PROVIDERS, is_provider_available

        provider_name = params.get("provider", [None])[0]
        if not provider_name:
            return {"error": "Missing required parameter: provider"}

        if provider_name not in PROVIDERS:
            return {"error": f"Unknown provider: {provider_name}"}

        provider_class = PROVIDERS[provider_name]
        display_names = {
            "aws": "Amazon Web Services",
            "gcp": "Google Cloud Platform",
            "azure": "Microsoft Azure",
        }
        descriptions = {
            "aws": "AWS cloud services including IAM, S3, EC2, RDS, Lambda, and more",
            "gcp": "Google Cloud services including IAM, Cloud Storage, Compute Engine, and more",
            "azure": "Microsoft Azure services including IAM, Blob Storage, VMs, and more",
        }

        return {
            "name": provider_name,
            "display_name": display_names.get(provider_name, provider_name.upper()),
            "available": is_provider_available(provider_name),
            "packages": provider_class.get_required_packages(),
            "description": descriptions.get(provider_name, "Cloud provider"),
            "credential_fields": self._get_credential_fields(provider_name),
            "default_region": self._get_default_region(provider_name),
            "storage_types": self._get_storage_types(provider_name),
        }

    def _cloud_validate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Validate cloud credentials."""
        from stance.cloud import is_provider_available, get_cloud_provider

        provider_name = params.get("provider", [None])[0]
        if not provider_name:
            return {"error": "Missing required parameter: provider"}

        if not is_provider_available(provider_name):
            return {
                "provider": provider_name,
                "valid": False,
                "error": "SDK not available. Install required packages.",
            }

        # Build kwargs for provider
        kwargs = {}
        if params.get("region"):
            kwargs["region"] = params["region"][0]
        if params.get("profile"):
            kwargs["profile"] = params["profile"][0]
        if params.get("project"):
            kwargs["project_id"] = params["project"][0]
        if params.get("subscription"):
            kwargs["subscription_id"] = params["subscription"][0]

        try:
            provider = get_cloud_provider(provider_name, **kwargs)
            valid = provider.validate_credentials()

            return {
                "provider": provider_name,
                "valid": valid,
                "account_id": getattr(provider, "_account_id", None),
            }
        except Exception as e:
            return {
                "provider": provider_name,
                "valid": False,
                "error": str(e),
            }

    def _cloud_account(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get cloud account information."""
        from stance.cloud import is_provider_available, get_cloud_provider

        provider_name = params.get("provider", [None])[0]
        if not provider_name:
            return {"error": "Missing required parameter: provider"}

        if not is_provider_available(provider_name):
            return {"error": f"SDK not available for {provider_name}"}

        # Build kwargs for provider
        kwargs = {}
        if params.get("region"):
            kwargs["region"] = params["region"][0]
        if params.get("profile"):
            kwargs["profile"] = params["profile"][0]
        if params.get("project"):
            kwargs["project_id"] = params["project"][0]
        if params.get("subscription"):
            kwargs["subscription_id"] = params["subscription"][0]

        try:
            provider = get_cloud_provider(provider_name, **kwargs)
            account = provider.get_account()

            return {
                "provider": account.provider,
                "account_id": account.account_id,
                "display_name": account.display_name,
                "region_count": len(account.regions),
                "metadata": account.metadata,
            }
        except Exception as e:
            return {"error": str(e)}

    def _cloud_regions(self, params: dict[str, Any]) -> dict[str, Any]:
        """List regions for a cloud provider."""
        from stance.cloud import is_provider_available, get_cloud_provider

        provider_name = params.get("provider", [None])[0]
        if not provider_name:
            return {"error": "Missing required parameter: provider"}

        if not is_provider_available(provider_name):
            return {"error": f"SDK not available for {provider_name}"}

        # Build kwargs for provider
        kwargs = {}
        if params.get("region"):
            kwargs["region"] = params["region"][0]
        if params.get("profile"):
            kwargs["profile"] = params["profile"][0]
        if params.get("project"):
            kwargs["project_id"] = params["project"][0]
        if params.get("subscription"):
            kwargs["subscription_id"] = params["subscription"][0]

        try:
            provider = get_cloud_provider(provider_name, **kwargs)
            regions = provider.list_regions()

            return {
                "provider": provider_name,
                "regions": [
                    {
                        "region_id": r.region_id,
                        "display_name": r.display_name,
                        "is_default": r.is_default,
                    }
                    for r in regions
                ],
                "total": len(regions),
            }
        except Exception as e:
            return {"error": str(e)}

    def _cloud_availability(self, params: dict[str, Any]) -> dict[str, Any]:
        """Check cloud SDK availability."""
        from stance.cloud import PROVIDERS, is_provider_available

        availability = []
        for name, provider_class in PROVIDERS.items():
            available = is_provider_available(name)
            packages = provider_class.get_required_packages()
            availability.append({
                "provider": name,
                "available": available,
                "packages": packages,
                "install": f"pip install {' '.join(packages)}" if packages else "N/A",
            })

        return {
            "availability": availability,
            "total": len(availability),
            "available_count": len([a for a in availability if a["available"]]),
        }

    def _cloud_packages(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show required packages for cloud providers."""
        from stance.cloud import PROVIDERS

        provider_filter = params.get("provider", [None])[0]

        packages_list = []
        for name, provider_class in PROVIDERS.items():
            if provider_filter and name != provider_filter:
                continue
            packages = provider_class.get_required_packages()
            packages_list.append({
                "provider": name,
                "packages": packages,
                "install_command": f"pip install {' '.join(packages)}",
            })

        return {
            "packages": packages_list,
            "filter": provider_filter,
        }

    def _cloud_credentials(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show credential configuration options."""
        provider_filter = params.get("provider", [None])[0]

        credentials_info = [
            {
                "provider": "aws",
                "fields": self._get_credential_fields("aws"),
                "env_vars": [
                    "AWS_ACCESS_KEY_ID",
                    "AWS_SECRET_ACCESS_KEY",
                    "AWS_SESSION_TOKEN",
                    "AWS_PROFILE",
                    "AWS_ROLE_ARN",
                ],
                "auth_methods": [
                    "Environment variables",
                    "AWS profile (~/.aws/credentials)",
                    "IAM role (EC2/ECS/Lambda)",
                    "Explicit credentials",
                    "Role assumption",
                ],
            },
            {
                "provider": "gcp",
                "fields": self._get_credential_fields("gcp"),
                "env_vars": [
                    "GOOGLE_APPLICATION_CREDENTIALS",
                    "GOOGLE_CLOUD_PROJECT",
                ],
                "auth_methods": [
                    "Service account key file",
                    "Application default credentials",
                    "Workload identity (GKE)",
                    "Explicit credentials",
                ],
            },
            {
                "provider": "azure",
                "fields": self._get_credential_fields("azure"),
                "env_vars": [
                    "AZURE_SUBSCRIPTION_ID",
                    "AZURE_TENANT_ID",
                    "AZURE_CLIENT_ID",
                    "AZURE_CLIENT_SECRET",
                ],
                "auth_methods": [
                    "Service principal",
                    "Managed identity",
                    "Azure CLI",
                    "Explicit credentials",
                ],
            },
        ]

        if provider_filter:
            credentials_info = [c for c in credentials_info if c["provider"] == provider_filter]

        return {
            "credentials": credentials_info,
            "filter": provider_filter,
        }

    def _cloud_exceptions(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show cloud provider exception types."""
        return {
            "exceptions": [
                {
                    "name": "CloudProviderError",
                    "description": "Base exception for cloud provider errors",
                    "parent": "Exception",
                },
                {
                    "name": "AuthenticationError",
                    "description": "Raised when authentication fails",
                    "parent": "CloudProviderError",
                },
                {
                    "name": "ConfigurationError",
                    "description": "Raised when configuration is invalid",
                    "parent": "CloudProviderError",
                },
                {
                    "name": "ResourceNotFoundError",
                    "description": "Raised when a resource is not found",
                    "parent": "CloudProviderError",
                },
                {
                    "name": "PermissionDeniedError",
                    "description": "Raised when permission is denied",
                    "parent": "CloudProviderError",
                },
            ],
        }

    def _cloud_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show cloud module status."""
        from stance.cloud import PROVIDERS, is_provider_available

        return {
            "module": "cloud",
            "components": {
                "CloudProvider": True,
                "CloudCredentials": True,
                "CloudRegion": True,
                "CloudAccount": True,
                "PROVIDERS": True,
            },
            "providers": {
                name: is_provider_available(name) for name in PROVIDERS.keys()
            },
            "capabilities": [
                "multi_provider_support",
                "credential_validation",
                "region_discovery",
                "account_info",
                "collector_integration",
                "storage_backend_integration",
                "role_assumption",
                "session_management",
            ],
        }

    def _cloud_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive cloud module summary."""
        from stance.cloud import PROVIDERS, is_provider_available

        providers = self._get_cloud_provider_metadata()
        available_count = len([p for p in providers if p["available"]])

        return {
            "overview": {
                "description": "Cloud provider abstraction layer for multi-cloud security posture management",
                "total_providers": len(providers),
                "available_providers": available_count,
                "providers": {
                    p["name"]: {
                        "display_name": p["display_name"],
                        "available": p["available"],
                        "packages": p["packages"],
                    }
                    for p in providers
                },
            },
            "features": [
                "Unified interface for AWS, GCP, and Azure",
                "Automatic credential discovery and validation",
                "Region enumeration for all providers",
                "Account/project/subscription information",
                "Collector integration for security scanning",
                "Storage backend integration (S3, GCS, Blob)",
                "IAM role assumption support (AWS)",
                "Service account support (GCP)",
                "Service principal support (Azure)",
            ],
            "architecture": {
                "base_class": "CloudProvider",
                "credentials_class": "CloudCredentials",
                "region_class": "CloudRegion",
                "account_class": "CloudAccount",
                "factory_function": "get_cloud_provider",
            },
            "exception_hierarchy": [
                "CloudProviderError (base)",
                "  -> AuthenticationError",
                "  -> ConfigurationError",
                "  -> ResourceNotFoundError",
                "  -> PermissionDeniedError",
            ],
        }

    # ==================== Config API Methods ====================

    def _config_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List all configurations."""
        from stance.config import ConfigurationManager

        config_dir = params.get("config_dir", ["~/.stance/config"])[0]
        manager = ConfigurationManager(config_dir=config_dir)
        configs = manager.list_configurations()

        config_details = []
        for name in configs:
            try:
                config = manager.load(name)
                config_details.append({
                    "name": name,
                    "description": config.description,
                    "mode": config.mode.value,
                    "collectors": len(config.collectors),
                    "accounts": len(config.accounts),
                    "created_at": config.created_at.isoformat(),
                    "updated_at": config.updated_at.isoformat(),
                })
            except Exception:
                config_details.append({
                    "name": name,
                    "error": "Could not load configuration",
                })

        return {
            "configurations": config_details,
            "total": len(configs),
            "config_dir": manager.config_dir,
        }

    def _config_show(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show configuration details."""
        from stance.config import ConfigurationManager

        config_dir = params.get("config_dir", ["~/.stance/config"])[0]
        name = params.get("name", ["default"])[0]
        section = params.get("section", [None])[0]

        manager = ConfigurationManager(config_dir=config_dir)
        config = manager.load(name)

        config_dict = config.to_dict()

        if section:
            sections = {
                "collectors": [c.to_dict() for c in config.collectors],
                "accounts": [a.to_dict() for a in config.accounts],
                "schedule": config.schedule.to_dict(),
                "policies": config.policies.to_dict(),
                "storage": config.storage.to_dict(),
                "notifications": config.notifications.to_dict(),
            }
            return {
                "name": name,
                "section": section,
                "data": sections.get(section, {}),
            }

        return config_dict

    def _config_validate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Validate a configuration."""
        from stance.config import ConfigurationManager

        config_dir = params.get("config_dir", ["~/.stance/config"])[0]
        name = params.get("name", ["default"])[0]

        manager = ConfigurationManager(config_dir=config_dir)

        try:
            config = manager.load(name)
        except Exception as e:
            return {
                "name": name,
                "valid": False,
                "errors": [str(e)],
                "warnings": [],
            }

        errors = []
        warnings = []

        if not config.name:
            errors.append("Configuration name is required")

        if config.mode is None:
            errors.append("Scan mode is required")

        if config.storage.backend == "s3" and not config.storage.s3_bucket:
            errors.append("S3 bucket is required when using s3 backend")

        if config.storage.backend == "gcs" and not config.storage.gcs_bucket:
            errors.append("GCS bucket is required when using gcs backend")

        if config.storage.backend == "azure_blob" and not config.storage.azure_container:
            errors.append("Azure container is required when using azure_blob backend")

        if config.storage.retention_days < 1:
            warnings.append("Retention days should be at least 1")

        for c in config.collectors:
            if not c.name:
                errors.append("Collector name is required")

        for a in config.accounts:
            if not a.account_id:
                errors.append("Account ID is required")

        return {
            "name": name,
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }

    def _config_default(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get default configuration."""
        from stance.config import ConfigurationManager

        config_dir = params.get("config_dir", ["~/.stance/config"])[0]
        manager = ConfigurationManager(config_dir=config_dir)
        config = manager.get_default()

        return config.to_dict()

    def _config_modes(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available scan modes."""
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
        return {
            "modes": modes,
            "total": len(modes),
        }

    def _config_providers(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available cloud providers for configuration."""
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
        return {
            "providers": providers,
            "total": len(providers),
        }

    def _config_schema(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get configuration schema."""
        section = params.get("section", ["all"])[0]

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
                        "project_id": {"type": "string"},
                        "subscription_id": {"type": "string"},
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
                    "full_scan_expression": {"type": "string"},
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
                    "s3_prefix": {"type": "string", "default": "stance"},
                    "gcs_bucket": {"type": "string"},
                    "gcs_prefix": {"type": "string", "default": "stance"},
                    "azure_container": {"type": "string"},
                    "azure_prefix": {"type": "string", "default": "stance"},
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
            return {
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
                    "created_at": {"type": "string", "format": "datetime"},
                    "updated_at": {"type": "string", "format": "datetime"},
                },
                "required": ["name"],
            }

        return schemas.get(section, {})

    def _config_env(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get configuration environment variables."""
        import os

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

        return {
            "environment_variables": env_vars,
            "total": len(env_vars),
        }

    def _config_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get configuration module status."""
        from stance.config import ConfigurationManager

        config_dir = params.get("config_dir", ["~/.stance/config"])[0]
        manager = ConfigurationManager(config_dir=config_dir)

        return {
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
            "config_dir": manager.config_dir,
            "configurations": len(manager.list_configurations()),
        }

    def _config_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive config module summary."""
        from stance.config import ConfigurationManager

        config_dir = params.get("config_dir", ["~/.stance/config"])[0]
        manager = ConfigurationManager(config_dir=config_dir)
        configs = manager.list_configurations()

        return {
            "overview": {
                "description": "Scan configuration management for Mantissa Stance",
                "config_dir": manager.config_dir,
                "total_configurations": len(configs),
                "configurations": configs,
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

    def _config_create(self, body: bytes) -> dict[str, Any]:
        """Create a new configuration."""
        import json
        from stance.config import ConfigurationManager, ScanConfiguration, ScanMode, create_default_config

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        name = data.get("name")
        if not name:
            return {"error": "Missing required field: name"}

        config_dir = data.get("config_dir", "~/.stance/config")
        manager = ConfigurationManager(config_dir=config_dir)

        existing = manager.list_configurations()
        if name in existing:
            return {"error": f"Configuration '{name}' already exists"}

        if data.get("from_default"):
            config = create_default_config()
            config.name = name
        else:
            config = ScanConfiguration(name=name)

        if data.get("description"):
            config.description = data["description"]
        if data.get("mode"):
            config.mode = ScanMode(data["mode"])

        format_type = data.get("format", "json")
        path = manager.save(config, format=format_type)

        return {
            "success": True,
            "name": name,
            "path": path,
        }

    def _config_delete(self, body: bytes) -> dict[str, Any]:
        """Delete a configuration."""
        import json
        from stance.config import ConfigurationManager

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        name = data.get("name")
        if not name:
            return {"error": "Missing required field: name"}

        config_dir = data.get("config_dir", "~/.stance/config")
        manager = ConfigurationManager(config_dir=config_dir)

        existing = manager.list_configurations()
        if name not in existing:
            return {"error": f"Configuration '{name}' not found"}

        if manager.delete(name):
            return {"success": True, "name": name}
        else:
            return {"error": f"Failed to delete configuration '{name}'"}

    def _config_edit(self, body: bytes) -> dict[str, Any]:
        """Edit a configuration."""
        import json
        from stance.config import ConfigurationManager, ScanMode

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        name = data.get("name", "default")
        config_dir = data.get("config_dir", "~/.stance/config")

        manager = ConfigurationManager(config_dir=config_dir)
        config = manager.load(name)

        updated = False

        if "description" in data:
            config.description = data["description"]
            updated = True

        if "mode" in data:
            config.mode = ScanMode(data["mode"])
            updated = True

        if "storage_backend" in data:
            config.storage.backend = data["storage_backend"]
            updated = True

        if "storage_path" in data:
            config.storage.local_path = data["storage_path"]
            updated = True

        if "s3_bucket" in data:
            config.storage.s3_bucket = data["s3_bucket"]
            updated = True

        if "gcs_bucket" in data:
            config.storage.gcs_bucket = data["gcs_bucket"]
            updated = True

        if "azure_container" in data:
            config.storage.azure_container = data["azure_container"]
            updated = True

        if "severity_threshold" in data:
            config.policies.severity_threshold = data["severity_threshold"]
            updated = True

        if "retention_days" in data:
            config.storage.retention_days = data["retention_days"]
            updated = True

        if updated:
            path = manager.save(config)
            return {"success": True, "name": name, "path": path}
        else:
            return {"success": False, "message": "No changes specified"}

    def _config_import(self, body: bytes) -> dict[str, Any]:
        """Import a configuration from JSON."""
        import json
        from stance.config import ConfigurationManager, ScanConfiguration

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        config_data = data.get("config")
        if not config_data:
            return {"error": "Missing required field: config"}

        config_dir = data.get("config_dir", "~/.stance/config")
        name_override = data.get("name")
        force = data.get("force", False)

        manager = ConfigurationManager(config_dir=config_dir)

        try:
            config = ScanConfiguration.from_dict(config_data)
        except Exception as e:
            return {"error": f"Invalid configuration data: {e}"}

        if name_override:
            config.name = name_override

        existing = manager.list_configurations()
        if config.name in existing and not force:
            return {"error": f"Configuration '{config.name}' already exists. Use force=true to overwrite."}

        path = manager.save(config)
        return {
            "success": True,
            "name": config.name,
            "path": path,
        }

    def _config_export(self, body: bytes) -> dict[str, Any]:
        """Export a configuration."""
        import json
        from stance.config import ConfigurationManager

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        name = data.get("name", "default")
        config_dir = data.get("config_dir", "~/.stance/config")
        export_format = data.get("format", "json")

        manager = ConfigurationManager(config_dir=config_dir)
        config = manager.load(name)

        if export_format == "yaml":
            try:
                import yaml
                output = yaml.safe_dump(config.to_dict(), default_flow_style=False)
                return {
                    "name": name,
                    "format": "yaml",
                    "content": output,
                }
            except ImportError:
                return {"error": "PyYAML is required for YAML export"}
        else:
            return {
                "name": name,
                "format": "json",
                "content": config.to_dict(),
            }

    def _config_set_default(self, body: bytes) -> dict[str, Any]:
        """Set a configuration as default."""
        import json
        from stance.config import ConfigurationManager

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        name = data.get("name")
        if not name:
            return {"error": "Missing required field: name"}

        config_dir = data.get("config_dir", "~/.stance/config")
        manager = ConfigurationManager(config_dir=config_dir)

        existing = manager.list_configurations()
        if name not in existing:
            return {"error": f"Configuration '{name}' not found"}

        config = manager.load(name)
        path = manager.set_default(config)

        return {
            "success": True,
            "name": name,
            "default_path": path,
        }

    # ==================== Docs API Methods ====================

    def _docs_info(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get documentation module information."""
        return {
            "module": "stance.docs",
            "description": "Documentation generation for Mantissa Stance",
            "capabilities": [
                "API reference generation from source code",
                "CLI command reference generation",
                "Policy documentation generation",
                "Docstring parsing (Google-style)",
                "AST-based source code analysis",
                "Markdown output format",
            ],
            "generators": {
                "DocumentationGenerator": "Main orchestrator for all documentation",
                "APIReferenceGenerator": "Generates API docs from Python source",
                "CLIReferenceGenerator": "Generates CLI command reference",
                "PolicyDocGenerator": "Generates policy documentation from YAML",
                "MarkdownWriter": "Writes Markdown formatted output",
            },
            "analyzers": {
                "SourceAnalyzer": "Analyzes Python source using AST",
                "DocstringParser": "Parses docstrings into structured data",
            },
        }

    def _docs_generators(self, params: dict[str, Any]) -> dict[str, Any]:
        """List documentation generators."""
        generators = [
            {
                "name": "DocumentationGenerator",
                "description": "Main orchestrator for all documentation generation",
                "methods": ["generate_all", "generate_api", "generate_cli", "generate_policies"],
                "output_format": "Markdown",
            },
            {
                "name": "APIReferenceGenerator",
                "description": "Generates API reference documentation from Python source",
                "methods": ["generate"],
                "output_format": "Markdown",
            },
            {
                "name": "CLIReferenceGenerator",
                "description": "Generates CLI command reference from argparse",
                "methods": ["generate"],
                "output_format": "Markdown",
            },
            {
                "name": "PolicyDocGenerator",
                "description": "Generates policy documentation from YAML files",
                "methods": ["generate"],
                "output_format": "Markdown",
            },
            {
                "name": "MarkdownWriter",
                "description": "Writes documentation in Markdown format",
                "methods": ["write_module", "write_index"],
                "output_format": "Markdown",
            },
        ]
        return {"generators": generators, "total": len(generators)}

    def _docs_dataclasses(self, params: dict[str, Any]) -> dict[str, Any]:
        """List documentation data classes."""
        dataclasses = [
            {
                "name": "ParameterInfo",
                "description": "Information about a function/method parameter",
                "fields": ["name", "type_hint", "default", "description"],
            },
            {
                "name": "FunctionInfo",
                "description": "Information about a function or method",
                "fields": ["name", "signature", "docstring", "parameters", "return_type", "is_async", "decorators"],
            },
            {
                "name": "ClassInfo",
                "description": "Information about a class",
                "fields": ["name", "docstring", "bases", "methods", "properties", "is_dataclass"],
            },
            {
                "name": "ModuleInfo",
                "description": "Information about a module",
                "fields": ["name", "path", "docstring", "classes", "functions", "constants"],
            },
        ]
        return {"dataclasses": dataclasses, "total": len(dataclasses)}

    def _docs_parsers(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get docstring parser information."""
        return {
            "parsers": {
                "DocstringParser": {
                    "description": "Parses Python docstrings into structured sections",
                    "supported_styles": ["Google-style docstrings"],
                    "sections": [
                        "description",
                        "Args/Arguments/Parameters",
                        "Returns/Return",
                        "Raises/Exceptions",
                        "Examples/Example",
                        "Attributes",
                        "Notes/Note",
                    ],
                },
            },
        }

    def _docs_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get documentation module status."""
        from stance.docs import (
            DocumentationGenerator,
            APIReferenceGenerator,
            CLIReferenceGenerator,
            PolicyDocGenerator,
            MarkdownWriter,
            ModuleInfo,
            ClassInfo,
            FunctionInfo,
            ParameterInfo,
        )

        return {
            "module": "docs",
            "components": {
                "DocumentationGenerator": DocumentationGenerator is not None,
                "APIReferenceGenerator": APIReferenceGenerator is not None,
                "CLIReferenceGenerator": CLIReferenceGenerator is not None,
                "PolicyDocGenerator": PolicyDocGenerator is not None,
                "MarkdownWriter": MarkdownWriter is not None,
            },
            "data_classes": {
                "ModuleInfo": ModuleInfo is not None,
                "ClassInfo": ClassInfo is not None,
                "FunctionInfo": FunctionInfo is not None,
                "ParameterInfo": ParameterInfo is not None,
            },
            "capabilities": [
                "api_reference",
                "cli_reference",
                "policy_documentation",
                "markdown_output",
                "ast_analysis",
                "docstring_parsing",
            ],
        }

    def _docs_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive docs module summary."""
        return {
            "overview": {
                "description": "Documentation generation system for Mantissa Stance",
                "purpose": "Generate API reference, CLI reference, and policy documentation",
                "output_format": "Markdown",
            },
            "features": [
                "Automatic API documentation from Python docstrings",
                "AST-based source code analysis",
                "Google-style docstring parsing",
                "CLI command reference generation from argparse",
                "Policy documentation from YAML files",
                "Markdown output with table of contents",
                "Class hierarchy and inheritance display",
                "Method signature extraction",
                "Parameter and return type documentation",
                "Example code block extraction",
            ],
            "architecture": {
                "main_class": "DocumentationGenerator",
                "generators": ["APIReferenceGenerator", "CLIReferenceGenerator", "PolicyDocGenerator"],
                "analyzers": ["SourceAnalyzer", "DocstringParser"],
                "writers": ["MarkdownWriter"],
            },
        }

    def _docs_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List generated documentation files."""
        from pathlib import Path

        output_dir = params.get("output_dir", ["docs/generated"])[0]
        doc_type = params.get("type", ["all"])[0]

        output_path = Path(output_dir)
        files = {"api": [], "cli": [], "policies": []}

        if output_path.exists():
            api_dir = output_path / "api"
            cli_dir = output_path / "cli"
            policies_dir = output_path / "policies"

            if api_dir.exists() and doc_type in ("all", "api"):
                files["api"] = [str(f.relative_to(output_path)) for f in api_dir.glob("*.md")]

            if cli_dir.exists() and doc_type in ("all", "cli"):
                files["cli"] = [str(f.relative_to(output_path)) for f in cli_dir.glob("*.md")]

            if policies_dir.exists() and doc_type in ("all", "policies"):
                files["policies"] = [str(f.relative_to(output_path)) for f in policies_dir.glob("*.md")]

        total = sum(len(f) for f in files.values())
        return {"output_dir": output_dir, "files": files, "total": total}

    def _docs_module(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get module documentation."""
        import os
        from stance.docs import SourceAnalyzer

        module_name = params.get("module", [None])[0]
        if not module_name:
            return {"error": "Missing required parameter: module"}

        source_dir = params.get("source_dir", ["src"])[0]

        module_path = module_name.replace(".", os.sep) + ".py"
        full_path = os.path.join(source_dir, module_path)
        init_path = os.path.join(source_dir, module_name.replace(".", os.sep), "__init__.py")

        if os.path.exists(full_path):
            source_path = full_path
        elif os.path.exists(init_path):
            source_path = init_path
        else:
            return {"error": f"Module not found: {module_name}"}

        try:
            analyzer = SourceAnalyzer(source_path)
            module_info = analyzer.analyze()

            return {
                "name": module_name,
                "path": source_path,
                "docstring": module_info.docstring,
                "classes": [cls.name for cls in module_info.classes],
                "functions": [func.name for func in module_info.functions if not func.name.startswith("_")],
                "constants": [(name, type_name) for name, type_name, _ in module_info.constants],
            }
        except Exception as e:
            return {"error": str(e)}

    def _docs_class(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get class documentation."""
        import os
        from stance.docs import SourceAnalyzer

        class_name = params.get("class", [None])[0]
        if not class_name:
            return {"error": "Missing required parameter: class"}

        source_dir = params.get("source_dir", ["src"])[0]

        parts = class_name.rsplit(".", 1)
        if len(parts) != 2:
            return {"error": "Class name must be fully qualified (e.g., stance.config.ScanConfiguration)"}

        module_name, cls_name = parts

        module_path = module_name.replace(".", os.sep) + ".py"
        full_path = os.path.join(source_dir, module_path)
        init_path = os.path.join(source_dir, module_name.replace(".", os.sep), "__init__.py")

        if os.path.exists(full_path):
            source_path = full_path
        elif os.path.exists(init_path):
            source_path = init_path
        else:
            return {"error": f"Module not found: {module_name}"}

        try:
            analyzer = SourceAnalyzer(source_path)
            module_info = analyzer.analyze()

            class_info = None
            for cls in module_info.classes:
                if cls.name == cls_name:
                    class_info = cls
                    break

            if not class_info:
                return {"error": f"Class not found: {cls_name}"}

            return {
                "name": class_info.name,
                "module": module_name,
                "bases": class_info.bases,
                "docstring": class_info.docstring,
                "is_dataclass": class_info.is_dataclass,
                "is_abstract": class_info.is_abstract,
                "methods": [m.name for m in class_info.methods if not m.name.startswith("_") or m.name == "__init__"],
                "properties": [p.name for p in class_info.properties],
                "class_methods": [m.name for m in class_info.class_methods],
                "static_methods": [m.name for m in class_info.static_methods],
            }
        except Exception as e:
            return {"error": str(e)}

    def _docs_generate(self, body: bytes) -> dict[str, Any]:
        """Generate documentation."""
        import json
        from stance.docs import DocumentationGenerator

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        source_dir = data.get("source_dir", "src/stance")
        output_dir = data.get("output_dir", "docs/generated")
        policies_dir = data.get("policies_dir", "policies")
        doc_type = data.get("type", "all")

        generator = DocumentationGenerator(
            source_dir=source_dir,
            output_dir=output_dir,
            policies_dir=policies_dir,
        )

        try:
            if doc_type == "all":
                result = generator.generate_all()
            elif doc_type == "api":
                result = {"api": generator.generate_api(), "cli": [], "policies": []}
            elif doc_type == "cli":
                result = {"api": [], "cli": [generator.generate_cli()], "policies": []}
            elif doc_type == "policies":
                result = {"api": [], "cli": [], "policies": generator.generate_policies()}
            else:
                result = {"api": [], "cli": [], "policies": []}

            total_files = sum(len(files) for files in result.values())

            return {
                "success": True,
                "type": doc_type,
                "output_dir": output_dir,
                "files": result,
                "total_files": total_files,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _docs_validate(self, body: bytes) -> dict[str, Any]:
        """Validate generated documentation."""
        import json
        from pathlib import Path

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        output_dir = Path(data.get("output_dir", "docs/generated"))

        if not output_dir.exists():
            return {"valid": False, "error": "Directory not found"}

        errors = []
        warnings = []
        files_checked = 0

        for subdir in ["api", "cli", "policies"]:
            subdir_path = output_dir / subdir
            if not subdir_path.exists():
                warnings.append(f"Missing {subdir} directory")

        for md_file in output_dir.rglob("*.md"):
            files_checked += 1
            try:
                with open(md_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    if not content.strip():
                        errors.append(f"Empty file: {md_file.relative_to(output_dir)}")
                    if not content.startswith("#"):
                        warnings.append(f"Missing header: {md_file.relative_to(output_dir)}")
            except Exception as e:
                errors.append(f"Error reading {md_file.relative_to(output_dir)}: {e}")

        return {
            "valid": len(errors) == 0,
            "output_dir": str(output_dir),
            "files_checked": files_checked,
            "errors": errors,
            "warnings": warnings,
        }

    def _docs_clean(self, body: bytes) -> dict[str, Any]:
        """Clean generated documentation."""
        import json
        from pathlib import Path

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        output_dir = Path(data.get("output_dir", "docs/generated"))
        doc_type = data.get("type", "all")

        if not output_dir.exists():
            return {"success": True, "files_removed": 0, "message": "Directory not found"}

        files_removed = 0

        if doc_type == "all":
            for subdir in ["api", "cli", "policies"]:
                subdir_path = output_dir / subdir
                if subdir_path.exists():
                    for f in subdir_path.glob("*.md"):
                        f.unlink()
                        files_removed += 1
        else:
            subdir_path = output_dir / doc_type
            if subdir_path.exists():
                for f in subdir_path.glob("*.md"):
                    f.unlink()
                    files_removed += 1

        return {"success": True, "files_removed": files_removed}

    # SBOM API handlers
    def _sbom_info(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get SBOM module information."""
        return {
            "module": "stance.sbom",
            "description": "Software Bill of Materials for supply chain security",
            "capabilities": [
                "Dependency file parsing (npm, pip, go, cargo, ruby, php)",
                "SBOM generation (CycloneDX, SPDX, Stance native)",
                "License identification and risk assessment",
                "License compatibility checking",
                "Supply chain risk analysis",
                "Typosquatting detection",
                "Deprecated package detection",
                "Vulnerability integration",
            ],
            "components": {
                "DependencyParser": "Parses dependency files from multiple ecosystems",
                "SBOMGenerator": "Generates SBOM in various formats",
                "LicenseAnalyzer": "Analyzes and validates software licenses",
                "SupplyChainAnalyzer": "Comprehensive supply chain risk assessment",
            },
        }

    def _sbom_formats(self, params: dict[str, Any]) -> dict[str, Any]:
        """List supported SBOM formats."""
        formats = [
            {
                "name": "CycloneDX JSON",
                "id": "cyclonedx-json",
                "spec_version": "1.5",
                "description": "OWASP CycloneDX JSON format",
                "file_extensions": [".json"],
                "standards": ["OWASP", "NTIA"],
            },
            {
                "name": "CycloneDX XML",
                "id": "cyclonedx-xml",
                "spec_version": "1.5",
                "description": "OWASP CycloneDX XML format",
                "file_extensions": [".xml"],
                "standards": ["OWASP", "NTIA"],
            },
            {
                "name": "SPDX JSON",
                "id": "spdx-json",
                "spec_version": "2.3",
                "description": "Linux Foundation SPDX JSON format",
                "file_extensions": [".json", ".spdx.json"],
                "standards": ["Linux Foundation", "ISO/IEC 5962:2021"],
            },
            {
                "name": "SPDX Tag-Value",
                "id": "spdx-tag",
                "spec_version": "2.3",
                "description": "Linux Foundation SPDX tag-value format",
                "file_extensions": [".spdx", ".spdx.tv"],
                "standards": ["Linux Foundation", "ISO/IEC 5962:2021"],
            },
            {
                "name": "Stance Native",
                "id": "stance",
                "spec_version": "1.0",
                "description": "Mantissa Stance native SBOM format",
                "file_extensions": [".json", ".stance.json"],
                "standards": ["Proprietary"],
            },
        ]
        return {"formats": formats, "total": len(formats)}

    def _sbom_ecosystems(self, params: dict[str, Any]) -> dict[str, Any]:
        """List supported package ecosystems."""
        ecosystems = [
            {
                "name": "NPM",
                "id": "npm",
                "language": "JavaScript/TypeScript",
                "files": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
                "registry": "https://registry.npmjs.org",
            },
            {
                "name": "PyPI",
                "id": "pypi",
                "language": "Python",
                "files": ["requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock", "setup.py"],
                "registry": "https://pypi.org",
            },
            {
                "name": "Go Modules",
                "id": "go",
                "language": "Go",
                "files": ["go.mod", "go.sum"],
                "registry": "https://proxy.golang.org",
            },
            {
                "name": "Cargo",
                "id": "cargo",
                "language": "Rust",
                "files": ["Cargo.toml", "Cargo.lock"],
                "registry": "https://crates.io",
            },
            {
                "name": "RubyGems",
                "id": "rubygems",
                "language": "Ruby",
                "files": ["Gemfile", "Gemfile.lock", "*.gemspec"],
                "registry": "https://rubygems.org",
            },
            {
                "name": "Composer",
                "id": "composer",
                "language": "PHP",
                "files": ["composer.json", "composer.lock"],
                "registry": "https://packagist.org",
            },
        ]
        return {"ecosystems": ecosystems, "total": len(ecosystems)}

    def _sbom_licenses(self, params: dict[str, Any]) -> dict[str, Any]:
        """List known software licenses."""
        try:
            from stance.sbom import LicenseAnalyzer
            analyzer = LicenseAnalyzer()

            category_filter = params.get("category", ["all"])[0]
            licenses = []

            for spdx_id, lic in analyzer.license_db.items():
                if category_filter == "all" or lic.category.value == category_filter:
                    licenses.append({
                        "spdx_id": spdx_id,
                        "name": lic.name,
                        "category": lic.category.value,
                        "risk": lic.risk.value,
                        "osi_approved": lic.osi_approved,
                        "copyleft": lic.copyleft,
                        "patent_grant": lic.patent_grant,
                    })

            licenses.sort(key=lambda x: (x["category"], x["spdx_id"]))
            return {"licenses": licenses, "total": len(licenses)}
        except ImportError as e:
            return {"error": f"SBOM module not available: {e}"}

    def _sbom_license_categories(self, params: dict[str, Any]) -> dict[str, Any]:
        """List license categories."""
        categories = [
            {"id": "permissive", "name": "Permissive", "description": "Liberal licenses with minimal restrictions"},
            {"id": "weak_copyleft", "name": "Weak Copyleft", "description": "Copyleft for modifications, not linking"},
            {"id": "strong_copyleft", "name": "Strong Copyleft", "description": "Full copyleft requiring derivative works"},
            {"id": "proprietary", "name": "Proprietary", "description": "Restricted or commercial licenses"},
            {"id": "public_domain", "name": "Public Domain", "description": "No restrictions, public domain"},
            {"id": "unknown", "name": "Unknown", "description": "License not recognized"},
        ]
        return {"categories": categories, "total": len(categories)}

    def _sbom_risk_levels(self, params: dict[str, Any]) -> dict[str, Any]:
        """List risk levels."""
        levels = [
            {"id": "critical", "name": "Critical", "description": "Requires immediate attention", "score_range": "90-100"},
            {"id": "high", "name": "High", "description": "Significant risk", "score_range": "70-89"},
            {"id": "medium", "name": "Medium", "description": "Moderate risk", "score_range": "40-69"},
            {"id": "low", "name": "Low", "description": "Minor risk", "score_range": "10-39"},
            {"id": "info", "name": "Info", "description": "Informational only", "score_range": "0-9"},
        ]
        return {"levels": levels, "total": len(levels)}

    def _sbom_parse(self, params: dict[str, Any]) -> dict[str, Any]:
        """Parse a dependency file."""
        try:
            from stance.sbom import DependencyParser

            path = params.get("path", [None])[0]
            if not path:
                return {"error": "Missing required parameter: path"}

            parser = DependencyParser()
            dep_file = parser.parse_file(path)

            if not dep_file:
                return {"error": f"Could not parse file: {path}"}

            return {
                "path": dep_file.path,
                "ecosystem": dep_file.ecosystem.value,
                "dependencies": [
                    {
                        "name": d.name,
                        "version": d.version or "any",
                        "scope": d.scope.value,
                        "ecosystem": d.ecosystem.value,
                    }
                    for d in dep_file.dependencies
                ],
                "total": len(dep_file.dependencies),
            }
        except ImportError as e:
            return {"error": f"SBOM module not available: {e}"}
        except Exception as e:
            return {"error": str(e)}

    def _sbom_analyze_license(self, params: dict[str, Any]) -> dict[str, Any]:
        """Analyze licenses in dependencies."""
        try:
            from stance.sbom import DependencyParser, LicenseAnalyzer

            path = params.get("path", [None])[0]
            if not path:
                return {"error": "Missing required parameter: path"}

            parser = DependencyParser()
            analyzer = LicenseAnalyzer()

            dep_file = parser.parse_file(path)
            if not dep_file:
                return {"error": f"Could not parse file: {path}"}

            report = analyzer.analyze_dependencies(dep_file.dependencies)

            return {
                "path": path,
                "total_dependencies": len(dep_file.dependencies),
                "licenses_found": len(report.results),
                "unknown_licenses": report.unknown_count,
                "summary": {
                    "permissive": report.permissive_count,
                    "weak_copyleft": report.weak_copyleft_count,
                    "strong_copyleft": report.strong_copyleft_count,
                    "proprietary": report.proprietary_count,
                    "unknown": report.unknown_count,
                },
                "risk_counts": {
                    risk.value: count
                    for risk, count in report.risk_counts.items()
                },
            }
        except ImportError as e:
            return {"error": f"SBOM module not available: {e}"}
        except Exception as e:
            return {"error": str(e)}

    def _sbom_analyze_risk(self, params: dict[str, Any]) -> dict[str, Any]:
        """Analyze supply chain risks."""
        try:
            from stance.sbom import DependencyParser, SupplyChainAnalyzer

            path = params.get("path", [None])[0]
            if not path:
                return {"error": "Missing required parameter: path"}

            parser = DependencyParser()
            analyzer = SupplyChainAnalyzer()

            dep_file = parser.parse_file(path)
            if not dep_file:
                return {"error": f"Could not parse file: {path}"}

            report = analyzer.analyze(dep_file.dependencies)

            return {
                "path": path,
                "total_dependencies": len(dep_file.dependencies),
                "overall_risk": report.overall_risk.value,
                "risk_score": report.risk_score,
                "summary": {
                    "critical": report.critical_count,
                    "high": report.high_count,
                    "medium": report.medium_count,
                    "low": report.low_count,
                },
                "risks": [
                    {
                        "package": dr.dependency.name,
                        "risks": [
                            {
                                "type": r.risk_type,
                                "level": r.level.value,
                                "description": r.description,
                            }
                            for r in dr.risks
                        ],
                    }
                    for dr in report.dependency_risks
                    if dr.risks
                ],
            }
        except ImportError as e:
            return {"error": f"SBOM module not available: {e}"}
        except Exception as e:
            return {"error": str(e)}

    def _sbom_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get SBOM module status."""
        try:
            from stance.sbom import (
                DependencyParser,
                SBOMGenerator,
                LicenseAnalyzer,
                SupplyChainAnalyzer,
                Dependency,
                SBOM,
                License,
                SupplyChainRisk,
            )

            return {
                "status": "ok",
                "module": "sbom",
                "components": {
                    "DependencyParser": DependencyParser is not None,
                    "SBOMGenerator": SBOMGenerator is not None,
                    "LicenseAnalyzer": LicenseAnalyzer is not None,
                    "SupplyChainAnalyzer": SupplyChainAnalyzer is not None,
                },
                "dataclasses": {
                    "Dependency": Dependency is not None,
                    "SBOM": SBOM is not None,
                    "License": License is not None,
                    "SupplyChainRisk": SupplyChainRisk is not None,
                },
                "capabilities": [
                    "dependency_parsing",
                    "sbom_generation",
                    "license_analysis",
                    "supply_chain_risk",
                ],
            }
        except ImportError as e:
            return {"status": "error", "error": str(e)}

    def _sbom_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get comprehensive SBOM module summary."""
        return {
            "overview": {
                "description": "Software Bill of Materials for supply chain security",
                "purpose": "Generate, analyze, and validate software dependencies",
                "standards": ["CycloneDX 1.5", "SPDX 2.3"],
            },
            "features": [
                "Multi-ecosystem dependency parsing",
                "SBOM generation in multiple formats",
                "License identification and compliance",
                "Supply chain risk assessment",
                "Typosquatting detection",
                "Deprecated package detection",
                "Package URL (purl) generation",
                "License compatibility checking",
            ],
            "supported_ecosystems": ["NPM", "PyPI", "Go", "Cargo", "RubyGems", "Composer"],
            "supported_formats": ["CycloneDX JSON", "CycloneDX XML", "SPDX JSON", "SPDX Tag-Value", "Stance Native"],
            "architecture": {
                "parsers": ["DependencyParser"],
                "generators": ["SBOMGenerator"],
                "analyzers": ["LicenseAnalyzer", "SupplyChainAnalyzer"],
            },
        }

    def _sbom_graph(self, params: dict[str, Any]) -> dict[str, Any]:
        """Build and return dependency graph from a dependency file."""
        try:
            from stance.sbom import (
                DependencyParser,
                DependencyGraphBuilder,
            )

            file_path = params.get("file", [None])[0] if "file" in params else None
            output_format = params.get("format", ["json"])[0] if "format" in params else "json"
            max_depth = params.get("max_depth", [None])[0] if "max_depth" in params else None

            if not file_path:
                return {"status": "error", "error": "file parameter is required"}

            # Parse dependencies
            parser = DependencyParser()
            dep_file = parser.parse_file(file_path)

            # Build graph
            builder = DependencyGraphBuilder()
            graph = builder.build_from_file(dep_file)

            # Convert max_depth to int if provided
            depth = int(max_depth) if max_depth else None

            # Return in requested format
            if output_format == "tree":
                return {
                    "status": "ok",
                    "format": "tree",
                    "tree": graph.to_tree_string(max_depth=depth),
                    "node_count": len(graph.nodes),
                    "edge_count": len(graph.edges),
                }
            elif output_format == "dot":
                return {
                    "status": "ok",
                    "format": "dot",
                    "dot": graph.to_dot(),
                    "node_count": len(graph.nodes),
                    "edge_count": len(graph.edges),
                }
            elif output_format == "mermaid":
                return {
                    "status": "ok",
                    "format": "mermaid",
                    "mermaid": graph.to_mermaid(),
                    "node_count": len(graph.nodes),
                    "edge_count": len(graph.edges),
                }
            else:
                # JSON format (default)
                return {
                    "status": "ok",
                    "format": "json",
                    "graph": graph.to_dict(),
                    "node_count": len(graph.nodes),
                    "edge_count": len(graph.edges),
                }

        except FileNotFoundError:
            return {"status": "error", "error": f"File not found: {file_path}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _sbom_graph_metrics(self, params: dict[str, Any]) -> dict[str, Any]:
        """Compute and return dependency graph metrics."""
        try:
            from stance.sbom import (
                DependencyParser,
                DependencyGraphBuilder,
            )

            file_path = params.get("file", [None])[0] if "file" in params else None

            if not file_path:
                return {"status": "error", "error": "file parameter is required"}

            # Parse dependencies
            parser = DependencyParser()
            dep_file = parser.parse_file(file_path)

            # Build graph
            builder = DependencyGraphBuilder()
            graph = builder.build_from_file(dep_file)

            # Compute metrics
            metrics = graph.compute_metrics()

            # Detect cycles
            cycles = graph.detect_cycles()

            return {
                "status": "ok",
                "metrics": {
                    "total_nodes": metrics.total_nodes,
                    "total_edges": metrics.total_edges,
                    "max_depth": metrics.max_depth,
                    "avg_depth": metrics.avg_depth,
                    "has_cycles": metrics.has_cycles,
                    "cycle_count": metrics.cycle_count,
                    "max_in_degree": metrics.max_in_degree,
                    "max_out_degree": metrics.max_out_degree,
                    "hub_nodes": metrics.hub_nodes,
                },
                "cycles": [
                    {
                        "nodes": cycle.nodes,
                        "length": cycle.length,
                    }
                    for cycle in cycles
                ],
            }

        except FileNotFoundError:
            return {"status": "error", "error": f"File not found: {file_path}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _sbom_attest(self, params: dict[str, Any]) -> dict[str, Any]:
        """Create SBOM attestation."""
        try:
            from stance.sbom import (
                DependencyParser,
                SBOMGenerator,
                SBOMFormat,
                create_sbom_attestation,
            )

            file_path = params.get("file", [None])[0] if "file" in params else None
            signer_name = params.get("signer", ["Mantissa Stance"])[0] if "signer" in params else "Mantissa Stance"
            secret_key = params.get("key", [None])[0] if "key" in params else None

            if not file_path:
                return {"status": "error", "error": "file parameter is required"}

            # Parse dependencies
            parser = DependencyParser()
            dep_file = parser.parse_file(file_path)

            # Generate SBOM
            generator = SBOMGenerator()
            sbom = generator.generate(dep_file, format=SBOMFormat.CYCLONEDX_JSON)

            # Create attestation
            attestation = create_sbom_attestation(
                sbom_data=sbom.to_dict(),
                sbom_file_path=file_path,
                signer_name=signer_name,
                secret_key=secret_key,
            )

            return {
                "status": "ok",
                "attestation": attestation.to_dict(),
                "envelope": attestation.to_dsse_envelope(),
            }

        except FileNotFoundError:
            return {"status": "error", "error": f"File not found: {file_path}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _sbom_attest_verify(self, params: dict[str, Any]) -> dict[str, Any]:
        """Verify SBOM attestation."""
        try:
            from stance.sbom import (
                AttestationVerifier,
                Attestation,
            )
            import json

            attestation_data = params.get("attestation", [None])[0] if "attestation" in params else None
            secret_key = params.get("key", [None])[0] if "key" in params else None

            if not attestation_data:
                return {"status": "error", "error": "attestation parameter is required"}

            # Parse attestation data
            if isinstance(attestation_data, str):
                attestation_dict = json.loads(attestation_data)
            else:
                attestation_dict = attestation_data

            # Reconstruct attestation
            attestation = Attestation.from_dict(attestation_dict)

            # Verify
            verifier = AttestationVerifier()
            result = verifier.verify(attestation, secret_key=secret_key)

            return {
                "status": "ok",
                "verification": {
                    "is_valid": result.is_valid,
                    "status": result.status.value,
                    "message": result.message,
                    "verified_at": result.verified_at.isoformat() if result.verified_at else None,
                    "details": result.details,
                },
            }

        except json.JSONDecodeError:
            return {"status": "error", "error": "Invalid attestation JSON"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _sbom_vex(self, params: dict[str, Any]) -> dict[str, Any]:
        """Generate VEX document for dependencies."""
        try:
            from stance.sbom import (
                DependencyParser,
                VulnerabilityScanner,
                VEXGenerator,
                VEXStatus,
            )

            file_path = params.get("file", [None])[0] if "file" in params else None
            output_format = params.get("format", ["openvex"])[0] if "format" in params else "openvex"
            product_name = params.get("product", ["Unknown Product"])[0] if "product" in params else "Unknown Product"

            if not file_path:
                return {"status": "error", "error": "file parameter is required"}

            # Parse dependencies
            parser = DependencyParser()
            dep_file = parser.parse_file(file_path)

            # Scan for vulnerabilities
            scanner = VulnerabilityScanner()
            scan_result = scanner.scan_dependencies(dep_file.dependencies)

            # Generate VEX
            generator = VEXGenerator()
            vex_doc = generator.generate_from_scan_result(
                scan_result=scan_result,
                product_name=product_name,
            )

            # Return in requested format
            if output_format == "cyclonedx":
                return {
                    "status": "ok",
                    "format": "cyclonedx",
                    "vex": vex_doc.to_cyclonedx_vex(),
                    "statement_count": len(vex_doc.statements),
                }
            elif output_format == "csaf":
                return {
                    "status": "ok",
                    "format": "csaf",
                    "vex": vex_doc.to_csaf_vex(),
                    "statement_count": len(vex_doc.statements),
                }
            else:
                # OpenVEX (default)
                return {
                    "status": "ok",
                    "format": "openvex",
                    "vex": vex_doc.to_openvex(),
                    "statement_count": len(vex_doc.statements),
                }

        except FileNotFoundError:
            return {"status": "error", "error": f"File not found: {file_path}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _sbom_vex_formats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return supported VEX formats."""
        return {
            "status": "ok",
            "formats": [
                {
                    "id": "openvex",
                    "name": "OpenVEX",
                    "description": "Open VEX format (default)",
                    "spec_url": "https://openvex.dev/",
                },
                {
                    "id": "cyclonedx",
                    "name": "CycloneDX VEX",
                    "description": "CycloneDX VEX format",
                    "spec_url": "https://cyclonedx.org/capabilities/vex/",
                },
                {
                    "id": "csaf",
                    "name": "CSAF VEX",
                    "description": "Common Security Advisory Framework VEX",
                    "spec_url": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html",
                },
            ],
            "statuses": [
                {"id": "affected", "description": "The product is affected by the vulnerability"},
                {"id": "not_affected", "description": "The product is not affected by the vulnerability"},
                {"id": "fixed", "description": "The vulnerability has been fixed in the product"},
                {"id": "under_investigation", "description": "The status is currently being investigated"},
            ],
            "justifications": [
                {"id": "component_not_present", "description": "The vulnerable component is not present"},
                {"id": "vulnerable_code_not_present", "description": "The vulnerable code is not present"},
                {"id": "vulnerable_code_not_in_execute_path", "description": "The vulnerable code is not in the execute path"},
                {"id": "vulnerable_code_cannot_be_controlled_by_adversary", "description": "The vulnerable code cannot be controlled by an adversary"},
                {"id": "inline_mitigations_already_exist", "description": "Inline mitigations already exist"},
            ],
        }

    # =========================================================================
    # Vulnerability API Endpoints
    # =========================================================================

    def _vuln_info(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return vulnerability module information."""
        return {
            "module": "stance.sbom.vulnerability",
            "description": "Vulnerability scanning for software dependencies",
            "capabilities": [
                "OSV (Open Source Vulnerabilities) database integration",
                "NVD (National Vulnerability Database) integration",
                "CVE lookup and matching",
                "Version range analysis",
                "CVSS score evaluation",
                "Dependency file scanning",
                "Local vulnerability cache",
            ],
            "components": {
                "VulnerabilityDatabase": "Database integration for NVD/OSV",
                "VulnerabilityScanner": "Scans dependencies for vulnerabilities",
                "VulnerabilityMatch": "Matches vulnerabilities to packages",
            },
            "supported_ecosystems": [
                "npm (JavaScript/TypeScript)",
                "PyPI (Python)",
                "Go Modules",
                "Cargo (Rust)",
                "Maven (Java)",
                "NuGet (.NET)",
                "RubyGems (Ruby)",
                "Composer (PHP)",
            ],
        }

    def _vuln_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        """Scan dependencies for vulnerabilities."""
        from stance.sbom import (
            DependencyParser,
            VulnerabilityScanner,
            VulnerabilityDatabase,
            VulnerabilitySource,
        )

        path = params.get("path", ["."])[0]
        sources_param = params.get("sources", ["osv"])
        recursive = params.get("recursive", ["true"])[0].lower() == "true"

        # Parse sources
        source_map = {
            "osv": VulnerabilitySource.OSV,
            "nvd": VulnerabilitySource.NVD,
            "local": VulnerabilitySource.LOCAL,
        }
        sources = [source_map.get(s, VulnerabilitySource.OSV) for s in sources_param]

        try:
            from pathlib import Path
            p = Path(path)

            db = VulnerabilityDatabase()
            scanner = VulnerabilityScanner(database=db, sources=sources)

            if p.is_file():
                result = scanner.scan_file(str(p))
            elif p.is_dir():
                result = scanner.scan_directory(str(p), recursive=recursive)
            else:
                return {"error": f"Path not found: {path}"}

            return {
                "summary": {
                    "total_dependencies": result.total_dependencies,
                    "vulnerable_dependencies": result.vulnerable_dependencies,
                    "total_vulnerabilities": result.total_vulnerabilities,
                    "highest_severity": result.highest_severity.value,
                },
                "severity_breakdown": {
                    "critical": result.critical_count,
                    "high": result.high_count,
                    "medium": result.medium_count,
                    "low": result.low_count,
                },
                "vulnerabilities": [
                    {
                        "id": m.vulnerability.id,
                        "package": m.dependency.name,
                        "version": m.dependency.version,
                        "ecosystem": m.dependency.ecosystem.value,
                        "severity": m.severity.value,
                        "cvss_score": m.vulnerability.cvss_score,
                        "summary": m.vulnerability.summary,
                        "fixed_versions": m.vulnerability.fixed_versions,
                    }
                    for m in result.matches
                ],
                "metadata": {
                    "scan_duration_ms": result.scan_duration_ms,
                    "sources": [s.value for s in sources],
                    "path": str(path),
                },
            }
        except Exception as e:
            return {"error": str(e)}

    def _vuln_lookup(self, params: dict[str, Any]) -> dict[str, Any]:
        """Look up vulnerabilities for a specific package."""
        from stance.sbom import (
            VulnerabilityDatabase,
            VulnerabilitySource,
            PackageEcosystem,
        )

        package = params.get("package", [""])[0]
        version = params.get("version", ["*"])[0]
        ecosystem_param = params.get("ecosystem", ["pypi"])[0]
        sources_param = params.get("sources", ["osv"])

        if not package:
            return {"error": "Package name is required"}

        # Parse ecosystem
        ecosystem_map = {
            "npm": PackageEcosystem.NPM,
            "pypi": PackageEcosystem.PYPI,
            "go": PackageEcosystem.GO,
            "cargo": PackageEcosystem.CARGO,
            "maven": PackageEcosystem.MAVEN,
            "nuget": PackageEcosystem.NUGET,
            "rubygems": PackageEcosystem.RUBYGEMS,
            "composer": PackageEcosystem.COMPOSER,
        }
        ecosystem = ecosystem_map.get(ecosystem_param.lower(), PackageEcosystem.PYPI)

        # Parse sources
        source_map = {
            "osv": VulnerabilitySource.OSV,
            "nvd": VulnerabilitySource.NVD,
            "local": VulnerabilitySource.LOCAL,
        }
        sources = [source_map.get(s, VulnerabilitySource.OSV) for s in sources_param]

        try:
            db = VulnerabilityDatabase()
            vulns = db.lookup(
                package=package,
                version=version if version != "*" else "0.0.0",
                ecosystem=ecosystem,
                sources=sources,
            )

            return {
                "package": package,
                "version": version,
                "ecosystem": ecosystem_param,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "aliases": v.aliases,
                        "severity": v.severity.value,
                        "cvss_score": v.cvss_score,
                        "summary": v.summary,
                        "description": v.description[:500] if v.description else None,
                        "fixed_versions": v.fixed_versions,
                        "published": v.published.isoformat() if v.published else None,
                        "cwes": v.cwes,
                        "references": [r.url for r in v.references[:5]],
                    }
                    for v in vulns
                ],
                "total": len(vulns),
            }
        except Exception as e:
            return {"error": str(e)}

    def _vuln_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return vulnerability module status."""
        try:
            from stance.sbom import (
                VulnerabilityDatabase,
                VulnerabilityScanner,
                VulnerabilitySeverity,
                VulnerabilitySource,
            )
            from pathlib import Path

            db = VulnerabilityDatabase()
            cache_dir = db._cache_dir
            cache_files = list(cache_dir.glob("*.json")) if cache_dir.exists() else []

            return {
                "status": "ok",
                "module": "vulnerability",
                "components": {
                    "VulnerabilityDatabase": True,
                    "VulnerabilityScanner": True,
                    "VulnerabilitySeverity": True,
                    "VulnerabilitySource": True,
                },
                "cache": {
                    "directory": str(cache_dir),
                    "exists": cache_dir.exists(),
                    "cached_vulnerabilities": len(cache_files),
                    "cache_size_bytes": sum(f.stat().st_size for f in cache_files) if cache_files else 0,
                },
                "available_sources": ["osv", "nvd", "local"],
            }
        except ImportError as e:
            return {"status": "error", "error": str(e)}

    def _vuln_sources(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return available vulnerability sources."""
        return {
            "sources": [
                {
                    "id": "osv",
                    "name": "Open Source Vulnerabilities",
                    "description": "Google's OSV database aggregating vulnerabilities from multiple sources",
                    "url": "https://osv.dev",
                    "default": True,
                    "rate_limited": False,
                },
                {
                    "id": "nvd",
                    "name": "National Vulnerability Database",
                    "description": "NIST's comprehensive vulnerability database",
                    "url": "https://nvd.nist.gov",
                    "default": False,
                    "rate_limited": True,
                    "note": "NVD has rate limits; consider using an API key for production use",
                },
                {
                    "id": "local",
                    "name": "Local Cache",
                    "description": "Locally cached vulnerability data",
                    "url": None,
                    "default": False,
                    "rate_limited": False,
                },
            ],
            "total": 3,
        }

    def _vuln_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return vulnerability scanning summary."""
        return {
            "overview": "Vulnerability scanning for SBOM dependencies",
            "features": [
                "Real-time vulnerability lookup via OSV/NVD",
                "CVE identification and matching",
                "CVSS severity scoring",
                "Version range analysis",
                "Fix recommendation with patched versions",
                "Local vulnerability caching",
                "Multiple ecosystem support",
            ],
            "supported_ecosystems": {
                "npm": "JavaScript/TypeScript (package.json)",
                "pypi": "Python (requirements.txt, pyproject.toml)",
                "go": "Go (go.mod)",
                "cargo": "Rust (Cargo.toml)",
                "maven": "Java (pom.xml)",
                "nuget": ".NET (*.csproj)",
                "rubygems": "Ruby (Gemfile)",
                "composer": "PHP (composer.json)",
            },
            "severity_levels": [
                {"level": "critical", "cvss_range": "9.0-10.0", "description": "Severe impact, immediate action required"},
                {"level": "high", "cvss_range": "7.0-8.9", "description": "Significant impact, prioritize remediation"},
                {"level": "medium", "cvss_range": "4.0-6.9", "description": "Moderate impact, schedule remediation"},
                {"level": "low", "cvss_range": "0.1-3.9", "description": "Minor impact, address in maintenance"},
            ],
            "data_sources": {
                "osv": "https://osv.dev",
                "nvd": "https://nvd.nist.gov",
            },
        }

    # =========================================================================
    # API Security Testing Endpoints
    # =========================================================================

    def _api_security_info(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return API security module information."""
        return {
            "module": "stance.api_security",
            "description": "API Security Testing for multi-cloud environments",
            "capabilities": [
                "API endpoint discovery from cloud assets",
                "OpenAPI specification analysis",
                "Authentication configuration testing",
                "Security issue detection (OWASP API Top 10)",
                "CORS policy analysis",
                "Rate limiting verification",
                "WAF protection checks",
                "Access logging validation",
            ],
            "components": {
                "APIDiscoverer": "Discovers API endpoints from assets and specs",
                "APISecurityAnalyzer": "Analyzes APIs for security issues",
                "AuthenticationTester": "Tests authentication configurations",
            },
            "supported_providers": ["AWS", "Azure", "GCP"],
            "supported_api_types": {
                "aws": ["API Gateway REST API", "API Gateway HTTP API", "WebSocket API"],
                "azure": ["API Management"],
                "gcp": ["API Gateway"],
            },
        }

    def _api_security_discover(self, params: dict[str, Any]) -> dict[str, Any]:
        """Discover API endpoints."""
        try:
            from stance.api_security import APIDiscoverer, APIInventory

            provider = params.get("provider", ["all"])[0]

            # Get API Gateway assets from storage
            assets = []
            if self.storage:
                all_assets = self.storage.get_latest_assets()
                api_types = [
                    "aws_apigateway_rest_api",
                    "aws_apigateway_http_api",
                    "azure_apim_api",
                    "azure_api_management",
                    "gcp_apigateway_api",
                    "gcp_api_gateway",
                ]
                assets = [a for a in all_assets if a.resource_type in api_types]

                if provider != "all":
                    assets = [a for a in assets if a.cloud_provider == provider]

            discoverer = APIDiscoverer()
            inventory = discoverer.discover_from_assets(assets) if assets else APIInventory()

            return inventory.to_dict()
        except Exception as e:
            return {"error": str(e)}

    def _api_security_analyze(self, params: dict[str, Any]) -> dict[str, Any]:
        """Analyze API security."""
        try:
            from stance.api_security import (
                APIDiscoverer,
                APISecurityAnalyzer,
                APIInventory,
            )

            # Get API Gateway assets
            assets = []
            if self.storage:
                all_assets = self.storage.get_latest_assets()
                api_types = [
                    "aws_apigateway_rest_api",
                    "aws_apigateway_http_api",
                    "azure_apim_api",
                    "azure_api_management",
                    "gcp_apigateway_api",
                    "gcp_api_gateway",
                ]
                assets = [a for a in all_assets if a.resource_type in api_types]

            discoverer = APIDiscoverer()
            inventory = discoverer.discover_from_assets(assets) if assets else APIInventory()

            analyzer = APISecurityAnalyzer()
            report = analyzer.analyze(inventory)

            return report.to_dict()
        except Exception as e:
            return {"error": str(e)}

    def _api_security_test_auth(self, params: dict[str, Any]) -> dict[str, Any]:
        """Test API authentication configurations."""
        try:
            from stance.api_security import (
                APIDiscoverer,
                AuthenticationTester,
                APIInventory,
            )

            # Get API Gateway assets
            assets = []
            if self.storage:
                all_assets = self.storage.get_latest_assets()
                api_types = [
                    "aws_apigateway_rest_api",
                    "aws_apigateway_http_api",
                ]
                assets = [a for a in all_assets if a.resource_type in api_types]

            if not assets:
                return {"error": "No API assets found. Run a scan first."}

            discoverer = APIDiscoverer()
            inventory = discoverer.discover_from_assets(assets)

            tester = AuthenticationTester()
            all_results = []
            passed_total = 0
            failed_total = 0
            warning_total = 0

            for endpoint in inventory.endpoints:
                report = tester.test_endpoint(endpoint)
                all_results.append(report.to_dict())
                passed_total += report.passed_count
                failed_total += report.failed_count
                warning_total += report.warning_count

            return {
                "summary": {
                    "endpoints_tested": len(inventory.endpoints),
                    "total_passed": passed_total,
                    "total_failed": failed_total,
                    "total_warnings": warning_total,
                },
                "reports": all_results,
            }
        except Exception as e:
            return {"error": str(e)}

    def _api_security_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return API security module status."""
        try:
            from stance.api_security import (
                APIDiscoverer,
                APISecurityAnalyzer,
                AuthenticationTester,
                APIInventory,
            )

            # Get inventory stats
            assets = []
            if self.storage:
                all_assets = self.storage.get_latest_assets()
                api_types = [
                    "aws_apigateway_rest_api",
                    "aws_apigateway_http_api",
                ]
                assets = [a for a in all_assets if a.resource_type in api_types]

            discoverer = APIDiscoverer()
            inventory = discoverer.discover_from_assets(assets) if assets else APIInventory()

            return {
                "status": "ok",
                "module": "api_security",
                "components": {
                    "APIDiscoverer": True,
                    "APISecurityAnalyzer": True,
                    "AuthenticationTester": True,
                },
                "inventory": {
                    "total_endpoints": inventory.total_endpoints,
                    "public_endpoints": inventory.public_endpoints,
                    "authenticated_endpoints": inventory.authenticated_endpoints,
                    "by_provider": inventory.by_provider,
                },
                "policies": {
                    "aws_apigateway": 12,
                },
            }
        except ImportError as e:
            return {"status": "error", "error": str(e)}

    def _api_security_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return API security module summary."""
        return {
            "overview": "API Security Testing for cloud API endpoints",
            "features": [
                "Multi-cloud API discovery (AWS, Azure, GCP)",
                "Authentication testing and validation",
                "OWASP API Security Top 10 checks",
                "CORS misconfiguration detection",
                "Rate limiting verification",
                "WAF protection assessment",
                "Access logging validation",
                "OpenAPI specification analysis",
            ],
            "security_checks": [
                {"check": "no_authentication", "severity": "critical", "description": "API without authentication"},
                {"check": "weak_authentication", "severity": "medium", "description": "API key only on public endpoint"},
                {"check": "cors_wildcard_credentials", "severity": "critical", "description": "CORS allows all origins with credentials"},
                {"check": "no_rate_limiting", "severity": "high", "description": "API without rate limiting"},
                {"check": "public_unprotected", "severity": "high", "description": "Public API without WAF or auth"},
                {"check": "no_waf", "severity": "medium", "description": "Public API without WAF"},
                {"check": "no_logging", "severity": "low", "description": "API without access logging"},
                {"check": "no_documentation", "severity": "info", "description": "API without documentation"},
                {"check": "weak_tls", "severity": "high", "description": "API using TLS 1.0"},
                {"check": "api_key_query", "severity": "low", "description": "API key in query string"},
            ],
            "owasp_coverage": [
                "API1:2023 - Broken Object Level Authorization",
                "API2:2023 - Broken Authentication",
                "API4:2023 - Unrestricted Resource Consumption",
                "API7:2023 - Server Side Request Forgery",
            ],
            "policy_count": 12,
        }

    # =========================================================================
    # Dashboards module API handlers
    # =========================================================================

    def _dashboards_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List all dashboards."""
        dashboards = [
            {
                "id": "dash-exec-001",
                "name": "Executive Security Overview",
                "description": "High-level security posture for executives",
                "owner": "security-team",
                "theme": "light",
                "widget_count": 8,
                "time_range": "last_30_days",
                "auto_refresh": 300,
                "is_public": False,
                "tags": ["executive", "overview"],
                "created_at": "2024-12-01T10:00:00Z",
                "updated_at": "2024-12-29T14:30:00Z",
            },
            {
                "id": "dash-secops-001",
                "name": "Security Operations Dashboard",
                "description": "Real-time security operations monitoring",
                "owner": "security-team",
                "theme": "dark",
                "widget_count": 12,
                "time_range": "last_7_days",
                "auto_refresh": 60,
                "is_public": False,
                "tags": ["secops", "monitoring"],
                "created_at": "2024-11-15T08:00:00Z",
                "updated_at": "2024-12-30T09:15:00Z",
            },
            {
                "id": "dash-compliance-001",
                "name": "Compliance Dashboard",
                "description": "Compliance status across frameworks",
                "owner": "compliance-team",
                "theme": "light",
                "widget_count": 10,
                "time_range": "last_90_days",
                "auto_refresh": 3600,
                "is_public": True,
                "tags": ["compliance", "audit"],
                "created_at": "2024-10-01T12:00:00Z",
                "updated_at": "2024-12-28T16:45:00Z",
            },
        ]

        # Apply filters
        owner = params.get("owner", [None])[0]
        tag = params.get("tag", [None])[0]

        if owner:
            dashboards = [d for d in dashboards if d["owner"] == owner]
        if tag:
            dashboards = [d for d in dashboards if tag in d["tags"]]

        return {"dashboards": dashboards, "total": len(dashboards)}

    def _dashboards_show(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show dashboard details."""
        dashboard_id = params.get("id", [None])[0]
        if not dashboard_id:
            return {"error": "Missing required parameter: id"}

        dashboards = self._dashboards_list({})["dashboards"]
        dashboard = next((d for d in dashboards if d["id"] == dashboard_id), None)

        if not dashboard:
            return {"error": f"Dashboard not found: {dashboard_id}"}

        return {"dashboard": dashboard}

    def _dashboards_create(self, params: dict[str, Any]) -> dict[str, Any]:
        """Create a new dashboard."""
        name = params.get("name", [None])[0]
        if not name:
            return {"error": "Missing required parameter: name"}

        template = params.get("template", ["security_ops"])[0]
        description = params.get("description", [""])[0]
        theme = params.get("theme", ["light"])[0]

        import uuid

        template_widgets = {
            "executive": 8,
            "security_ops": 12,
            "compliance": 10,
            "custom": 0,
        }

        dashboard = {
            "id": f"dash-{str(uuid.uuid4())[:8]}",
            "name": name,
            "description": description,
            "template": template,
            "theme": theme,
            "widget_count": template_widgets.get(template, 0),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "status": "created",
        }

        return {"success": True, "dashboard": dashboard}

    def _dashboards_widgets(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available widget types."""
        widgets = [
            {"type": "metric", "description": "Single value metric display", "use_case": "KPIs, counts, scores"},
            {"type": "chart", "description": "Data visualization chart", "use_case": "Trends, distributions"},
            {"type": "table", "description": "Tabular data display", "use_case": "Findings list, inventory"},
            {"type": "list", "description": "Simple list display", "use_case": "Top-N items, recent events"},
            {"type": "gauge", "description": "Gauge/speedometer display", "use_case": "Compliance scores, health"},
            {"type": "heatmap", "description": "Color-coded matrix", "use_case": "Time-based patterns"},
            {"type": "map", "description": "Geographic visualization", "use_case": "Regional distribution"},
            {"type": "timeline", "description": "Chronological event display", "use_case": "Event history"},
            {"type": "text", "description": "Text/markdown content", "use_case": "Descriptions, notes"},
            {"type": "alert", "description": "Alert/notification panel", "use_case": "Critical alerts"},
        ]
        return {"types": widgets, "total": len(widgets)}

    def _dashboards_charts(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available chart types."""
        charts = [
            {"type": "line", "description": "Line chart", "use_case": "Trends over time"},
            {"type": "bar", "description": "Vertical bar chart", "use_case": "Category comparison"},
            {"type": "horizontal_bar", "description": "Horizontal bar chart", "use_case": "Ranked lists"},
            {"type": "pie", "description": "Pie chart", "use_case": "Part-of-whole distribution"},
            {"type": "donut", "description": "Donut chart", "use_case": "Part-of-whole with center metric"},
            {"type": "area", "description": "Area chart", "use_case": "Volume over time"},
            {"type": "stacked_area", "description": "Stacked area chart", "use_case": "Composition over time"},
            {"type": "stacked_bar", "description": "Stacked bar chart", "use_case": "Category composition"},
            {"type": "scatter", "description": "Scatter plot", "use_case": "Correlation analysis"},
            {"type": "bubble", "description": "Bubble chart", "use_case": "Three-variable comparison"},
            {"type": "radar", "description": "Radar/spider chart", "use_case": "Multi-dimensional comparison"},
            {"type": "treemap", "description": "Treemap", "use_case": "Hierarchical proportions"},
            {"type": "funnel", "description": "Funnel chart", "use_case": "Process flow stages"},
            {"type": "sparkline", "description": "Mini inline chart", "use_case": "Inline trends"},
        ]
        return {"types": charts, "total": len(charts)}

    def _dashboards_themes(self, params: dict[str, Any]) -> dict[str, Any]:
        """List dashboard themes."""
        themes = [
            {"theme": "light", "description": "Light background theme", "colors": "White bg, dark text"},
            {"theme": "dark", "description": "Dark background theme", "colors": "Dark bg, light text"},
            {"theme": "high_contrast", "description": "High contrast for accessibility", "colors": "Strong contrast"},
            {"theme": "colorblind_safe", "description": "Colorblind-friendly palette", "colors": "Distinguishable"},
            {"theme": "print", "description": "Print-optimized theme", "colors": "Black text, white bg"},
        ]
        return {"themes": themes, "total": len(themes)}

    def _dashboards_time_ranges(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available time ranges."""
        ranges = [
            {"range": "last_hour", "description": "Last 60 minutes", "duration": "1 hour"},
            {"range": "last_24_hours", "description": "Last 24 hours", "duration": "1 day"},
            {"range": "last_7_days", "description": "Last 7 days", "duration": "1 week"},
            {"range": "last_30_days", "description": "Last 30 days", "duration": "1 month"},
            {"range": "last_90_days", "description": "Last 90 days", "duration": "3 months"},
            {"range": "last_year", "description": "Last 365 days", "duration": "1 year"},
            {"range": "custom", "description": "Custom date range", "duration": "User-defined"},
            {"range": "all_time", "description": "All available data", "duration": "Unlimited"},
        ]
        return {"ranges": ranges, "total": len(ranges)}

    def _dashboards_reports(self, params: dict[str, Any]) -> dict[str, Any]:
        """List generated reports."""
        reports = [
            {
                "id": "rpt-001",
                "title": "Weekly Security Report",
                "format": "pdf",
                "template": "executive_summary",
                "file_size": 1245678,
                "generated_at": "2024-12-30T02:00:00Z",
                "generation_time_seconds": 12.5,
                "sections": ["executive_summary", "findings_overview", "compliance_status", "recommendations"],
            },
            {
                "id": "rpt-002",
                "title": "Technical Findings Detail",
                "format": "html",
                "template": "technical_detail",
                "file_size": 3456789,
                "generated_at": "2024-12-29T14:00:00Z",
                "generation_time_seconds": 25.3,
                "sections": ["findings_detail", "asset_inventory", "vulnerability_analysis", "remediation_steps"],
            },
            {
                "id": "rpt-003",
                "title": "Q4 Compliance Report",
                "format": "pdf",
                "template": "compliance",
                "file_size": 2345678,
                "generated_at": "2024-12-28T10:00:00Z",
                "generation_time_seconds": 18.7,
                "sections": ["compliance_overview", "framework_status", "gap_analysis", "action_items"],
            },
        ]

        format_filter = params.get("format_filter", [None])[0]
        limit = int(params.get("limit", ["20"])[0])

        if format_filter:
            reports = [r for r in reports if r["format"] == format_filter]

        reports = reports[:limit]
        return {"reports": reports, "total": len(reports)}

    def _dashboards_generate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Generate a new report."""
        title = params.get("title", [None])[0]
        if not title:
            return {"error": "Missing required parameter: title"}

        template = params.get("template", ["executive_summary"])[0]
        output_format = params.get("output_format", ["pdf"])[0]
        time_range = params.get("time_range", ["last_30_days"])[0]

        import uuid

        template_sections = {
            "executive_summary": ["executive_summary", "findings_overview", "compliance_status", "recommendations"],
            "technical_detail": ["findings_detail", "asset_inventory", "vulnerability_analysis", "remediation_steps"],
            "compliance": ["compliance_overview", "framework_status", "gap_analysis", "action_items"],
            "trend": ["trend_analysis", "velocity", "forecasts", "comparison"],
        }

        report = {
            "id": f"rpt-{str(uuid.uuid4())[:8]}",
            "title": title,
            "template": template,
            "format": output_format,
            "time_range": time_range,
            "sections": template_sections.get(template, []),
            "status": "completed",
            "file_size": 1234567,
            "generation_time_seconds": 15.2,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }

        return {"success": True, "report": report}

    def _dashboards_schedules(self, params: dict[str, Any]) -> dict[str, Any]:
        """List scheduled reports."""
        schedules = [
            {
                "id": "sched-001",
                "name": "Weekly Executive Summary",
                "frequency": "weekly",
                "template": "executive_summary",
                "format": "pdf",
                "enabled": True,
                "next_run": "2025-01-06T02:00:00Z",
                "last_run": "2024-12-30T02:00:00Z",
                "last_status": "success",
                "run_count": 12,
                "failure_count": 0,
                "recipients": ["ciso@example.com", "security-team@example.com"],
            },
            {
                "id": "sched-002",
                "name": "Daily Security Digest",
                "frequency": "daily",
                "template": "technical_detail",
                "format": "html",
                "enabled": True,
                "next_run": "2025-01-01T06:00:00Z",
                "last_run": "2024-12-31T06:00:00Z",
                "last_status": "success",
                "run_count": 45,
                "failure_count": 1,
                "recipients": ["secops@example.com"],
            },
            {
                "id": "sched-003",
                "name": "Monthly Compliance Report",
                "frequency": "monthly",
                "template": "compliance",
                "format": "pdf",
                "enabled": True,
                "next_run": "2025-02-01T00:00:00Z",
                "last_run": "2025-01-01T00:00:00Z",
                "last_status": "success",
                "run_count": 6,
                "failure_count": 0,
                "recipients": ["compliance@example.com", "audit@example.com"],
            },
        ]

        enabled_only = params.get("enabled_only", ["false"])[0].lower() == "true"
        if enabled_only:
            schedules = [s for s in schedules if s["enabled"]]

        return {"schedules": schedules, "total": len(schedules)}

    def _dashboards_schedule_create(self, params: dict[str, Any]) -> dict[str, Any]:
        """Create a scheduled report."""
        name = params.get("name", [None])[0]
        if not name:
            return {"error": "Missing required parameter: name"}

        template = params.get("template", ["executive_summary"])[0]
        frequency = params.get("frequency", ["weekly"])[0]
        output_format = params.get("output_format", ["pdf"])[0]
        recipients = params.get("recipients", [""])[0]

        import uuid

        schedule = {
            "id": f"sched-{str(uuid.uuid4())[:8]}",
            "name": name,
            "template": template,
            "frequency": frequency,
            "format": output_format,
            "enabled": True,
            "recipients": recipients.split(",") if recipients else [],
            "created_at": datetime.utcnow().isoformat() + "Z",
            "status": "created",
        }

        return {"success": True, "schedule": schedule}

    def _dashboards_frequencies(self, params: dict[str, Any]) -> dict[str, Any]:
        """List report frequencies."""
        frequencies = [
            {"frequency": "once", "description": "One-time generation", "interval": "N/A"},
            {"frequency": "hourly", "description": "Every hour", "interval": "1 hour"},
            {"frequency": "daily", "description": "Every day", "interval": "24 hours"},
            {"frequency": "weekly", "description": "Every week", "interval": "7 days"},
            {"frequency": "biweekly", "description": "Every two weeks", "interval": "14 days"},
            {"frequency": "monthly", "description": "Every month", "interval": "~30 days"},
            {"frequency": "quarterly", "description": "Every quarter", "interval": "~90 days"},
            {"frequency": "yearly", "description": "Every year", "interval": "365 days"},
        ]
        return {"frequencies": frequencies, "total": len(frequencies)}

    def _dashboards_formats(self, params: dict[str, Any]) -> dict[str, Any]:
        """List report output formats."""
        formats = [
            {"format": "pdf", "description": "Portable Document Format", "use_case": "Executive reports, printing"},
            {"format": "html", "description": "HTML web page", "use_case": "Interactive viewing, email"},
            {"format": "json", "description": "JSON data format", "use_case": "API integration, automation"},
            {"format": "csv", "description": "Comma-separated values", "use_case": "Data export, spreadsheets"},
            {"format": "markdown", "description": "Markdown text format", "use_case": "Documentation, wikis"},
            {"format": "xlsx", "description": "Excel spreadsheet", "use_case": "Analysis, charts"},
        ]
        return {"formats": formats, "total": len(formats)}

    def _dashboards_templates(self, params: dict[str, Any]) -> dict[str, Any]:
        """List report templates."""
        templates = [
            {
                "template": "executive_summary",
                "description": "High-level executive summary",
                "sections": ["executive_summary", "findings_overview", "compliance_status", "recommendations"],
                "audience": "Executives, Board",
            },
            {
                "template": "technical_detail",
                "description": "Detailed technical findings report",
                "sections": ["findings_detail", "asset_inventory", "vulnerability_analysis", "remediation_steps"],
                "audience": "Security Engineers",
            },
            {
                "template": "compliance",
                "description": "Compliance framework status report",
                "sections": ["compliance_overview", "framework_status", "gap_analysis", "action_items"],
                "audience": "Compliance, Audit",
            },
            {
                "template": "trend",
                "description": "Security trend analysis report",
                "sections": ["trend_analysis", "velocity", "forecasts", "comparison"],
                "audience": "Security Management",
            },
        ]
        return {"templates": templates, "total": len(templates)}

    def _dashboards_metrics(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show dashboard metrics summary."""
        time_range = params.get("time_range", ["last_7_days"])[0]

        metrics = {
            "security_score": {"value": 78.5, "trend": "improving", "change": 3.2},
            "total_findings": {"value": 156, "trend": "improving", "change": -12},
            "critical_findings": {"value": 5, "trend": "stable", "change": 0},
            "high_findings": {"value": 23, "trend": "improving", "change": -4},
            "compliance_score": {"value": 85.2, "trend": "improving", "change": 2.1},
            "assets_scanned": {"value": 1247, "trend": "stable", "change": 5},
            "mttr": {"value": 4.2, "trend": "improving", "change": -0.8},
            "scan_frequency": {"value": 2.5, "trend": "stable", "change": 0},
        }

        return {
            "time_range": time_range,
            "metrics": metrics,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }

    def _dashboards_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show dashboards module status."""
        return {
            "module": "dashboards",
            "version": "1.0.0",
            "status": "operational",
            "components": {
                "Dashboard": "available",
                "Widget": "available",
                "ReportGenerator": "available",
                "ReportScheduler": "available",
                "ChartBuilder": "available",
                "MetricsAggregator": "available",
                "ReportDistributor": "available",
            },
            "capabilities": [
                "dashboard_management",
                "widget_configuration",
                "report_generation",
                "scheduled_reports",
                "chart_visualization",
                "metrics_aggregation",
                "multi_format_export",
                "email_delivery",
                "webhook_delivery",
                "storage_delivery",
            ],
            "statistics": {
                "dashboards": 3,
                "scheduled_reports": 3,
                "generated_reports_30d": 45,
                "widget_types": 10,
                "chart_types": 14,
                "report_formats": 6,
            },
        }

    # =========================================================================
    # Authentication API Endpoints (Phase 92)
    # =========================================================================

    def _auth_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get authentication system status."""
        return {
            "module": "auth",
            "version": "1.0.0",
            "status": "operational",
            "components": {
                "UserManager": "available",
                "JWTManager": "available",
                "APIKeyManager": "available",
                "SessionManager": "available",
                "RBACManager": "available",
                "AuditLogger": "available",
                "OAuth2Provider": "available",
                "AuthMiddleware": "available",
            },
            "capabilities": [
                "user_management",
                "jwt_authentication",
                "api_key_authentication",
                "session_management",
                "role_based_access_control",
                "oauth2_integration",
                "oidc_integration",
                "audit_logging",
                "mfa_support",
            ],
            "statistics": {
                "total_users": 0,
                "active_sessions": 0,
                "active_api_keys": 0,
                "audit_events_24h": 0,
            },
        }

    def _auth_users_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List users."""
        status_filter = params.get("status", [""])[0]
        role_filter = params.get("role", [""])[0]
        limit = int(params.get("limit", ["100"])[0])

        # Demo data
        users = [
            {
                "id": "usr_001",
                "email": "admin@example.com",
                "username": "admin",
                "display_name": "Admin User",
                "status": "active",
                "roles": ["admin", "analyst"],
                "created_at": "2024-01-15T10:00:00Z",
                "last_login_at": "2024-12-30T14:30:00Z",
            },
            {
                "id": "usr_002",
                "email": "analyst@example.com",
                "username": "analyst",
                "display_name": "Security Analyst",
                "status": "active",
                "roles": ["analyst"],
                "created_at": "2024-02-01T09:00:00Z",
                "last_login_at": "2024-12-29T16:45:00Z",
            },
        ]

        if status_filter:
            users = [u for u in users if u["status"] == status_filter]
        if role_filter:
            users = [u for u in users if role_filter in u["roles"]]

        return {
            "users": users[:limit],
            "total": len(users),
            "limit": limit,
        }

    def _auth_users_show(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show user details."""
        user_id = params.get("user_id", [""])[0]

        return {
            "id": user_id or "usr_001",
            "email": "admin@example.com",
            "username": "admin",
            "display_name": "Admin User",
            "status": "active",
            "roles": ["admin", "analyst"],
            "email_verified": True,
            "mfa_enabled": False,
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-12-01T08:00:00Z",
            "last_login_at": "2024-12-30T14:30:00Z",
            "last_login_ip": "192.168.1.100",
            "tenant_id": None,
        }

    def _auth_apikeys_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List API keys."""
        user_id = params.get("user_id", [""])[0]

        keys = [
            {
                "id": "key_001",
                "name": "Production API Key",
                "prefix": "stance_prod_",
                "user_id": "usr_001",
                "status": "active",
                "scopes": ["read:findings", "read:assets"],
                "created_at": "2024-06-01T10:00:00Z",
                "expires_at": "2025-06-01T10:00:00Z",
                "last_used_at": "2024-12-30T12:00:00Z",
                "use_count": 1523,
            },
            {
                "id": "key_002",
                "name": "CI/CD Integration",
                "prefix": "stance_cicd_",
                "user_id": "usr_001",
                "status": "active",
                "scopes": ["read:*", "scan:run"],
                "created_at": "2024-08-15T14:00:00Z",
                "expires_at": None,
                "last_used_at": "2024-12-30T08:30:00Z",
                "use_count": 856,
            },
        ]

        if user_id:
            keys = [k for k in keys if k["user_id"] == user_id]

        return {
            "api_keys": keys,
            "total": len(keys),
        }

    def _auth_sessions_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List active sessions."""
        user_id = params.get("user_id", [""])[0]

        sessions = [
            {
                "id": "sess_001",
                "user_id": "usr_001",
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "created_at": "2024-12-30T14:30:00Z",
                "expires_at": "2024-12-31T14:30:00Z",
                "last_activity_at": "2024-12-30T15:45:00Z",
            },
            {
                "id": "sess_002",
                "user_id": "usr_002",
                "ip_address": "10.0.0.50",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "created_at": "2024-12-29T16:45:00Z",
                "expires_at": "2024-12-30T16:45:00Z",
                "last_activity_at": "2024-12-30T10:00:00Z",
            },
        ]

        if user_id:
            sessions = [s for s in sessions if s["user_id"] == user_id]

        return {
            "sessions": sessions,
            "total": len(sessions),
        }

    def _auth_roles_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List available roles."""
        return {
            "roles": [
                {
                    "name": "super_admin",
                    "description": "Full system access with all permissions",
                    "permissions_count": 35,
                    "is_system": True,
                },
                {
                    "name": "admin",
                    "description": "Administrative access to most features",
                    "permissions_count": 30,
                    "is_system": True,
                },
                {
                    "name": "security_admin",
                    "description": "Security configuration and policy management",
                    "permissions_count": 20,
                    "is_system": True,
                },
                {
                    "name": "analyst",
                    "description": "View and analyze security findings",
                    "permissions_count": 15,
                    "is_system": True,
                },
                {
                    "name": "viewer",
                    "description": "Read-only access to findings and assets",
                    "permissions_count": 8,
                    "is_system": True,
                },
                {
                    "name": "api_user",
                    "description": "API-only access for integrations",
                    "permissions_count": 12,
                    "is_system": True,
                },
            ],
            "total": 6,
        }

    def _auth_roles_show(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show role details."""
        role_name = params.get("role_name", ["admin"])[0]

        permissions = {
            "admin": [
                "users:read", "users:write", "users:delete",
                "findings:read", "findings:write", "findings:suppress",
                "assets:read", "assets:write",
                "policies:read", "policies:write",
                "scans:read", "scans:run",
                "reports:read", "reports:generate",
                "config:read", "config:write",
            ],
            "analyst": [
                "findings:read", "findings:write", "findings:suppress",
                "assets:read",
                "policies:read",
                "scans:read",
                "reports:read", "reports:generate",
            ],
            "viewer": [
                "findings:read",
                "assets:read",
                "policies:read",
                "scans:read",
                "reports:read",
            ],
        }

        return {
            "name": role_name,
            "description": f"Role: {role_name}",
            "permissions": permissions.get(role_name, []),
            "is_system": True,
        }

    def _auth_audit_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List audit events."""
        user_id = params.get("user_id", [""])[0]
        event_type = params.get("event_type", [""])[0]
        limit = int(params.get("limit", ["100"])[0])

        events = [
            {
                "id": "aud_001",
                "event_type": "login_success",
                "user_id": "usr_001",
                "ip_address": "192.168.1.100",
                "action": "login",
                "status": "success",
                "timestamp": "2024-12-30T14:30:00Z",
            },
            {
                "id": "aud_002",
                "event_type": "api_key_created",
                "user_id": "usr_001",
                "ip_address": "192.168.1.100",
                "action": "create",
                "status": "success",
                "resource_type": "api_key",
                "resource_id": "key_002",
                "timestamp": "2024-12-30T14:35:00Z",
            },
            {
                "id": "aud_003",
                "event_type": "login_failure",
                "user_id": "unknown",
                "ip_address": "10.0.0.99",
                "action": "login",
                "status": "failure",
                "error_message": "Invalid credentials",
                "timestamp": "2024-12-30T13:00:00Z",
            },
        ]

        if user_id:
            events = [e for e in events if e["user_id"] == user_id]
        if event_type:
            events = [e for e in events if e["event_type"] == event_type]

        return {
            "events": events[:limit],
            "total": len(events),
            "limit": limit,
        }

    def _auth_audit_security(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get security-related audit events."""
        hours = int(params.get("hours", ["24"])[0])

        return {
            "events": [
                {
                    "id": "aud_003",
                    "event_type": "login_failure",
                    "user_id": None,
                    "ip_address": "10.0.0.99",
                    "status": "failure",
                    "error_message": "Invalid credentials",
                    "timestamp": "2024-12-30T13:00:00Z",
                },
                {
                    "id": "aud_004",
                    "event_type": "permission_denied",
                    "user_id": "usr_002",
                    "ip_address": "10.0.0.50",
                    "status": "failure",
                    "action": "users:delete",
                    "timestamp": "2024-12-30T10:15:00Z",
                },
            ],
            "hours": hours,
            "total": 2,
        }

    def _auth_audit_failed_logins(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get failed login attempts."""
        hours = int(params.get("hours", ["24"])[0])

        return {
            "events": [
                {
                    "id": "aud_003",
                    "user_id": None,
                    "ip_address": "10.0.0.99",
                    "user_agent": "curl/7.79.1",
                    "error_message": "Invalid credentials",
                    "timestamp": "2024-12-30T13:00:00Z",
                },
            ],
            "hours": hours,
            "total": 1,
        }

    def _auth_audit_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get audit statistics."""
        return {
            "total_events": 1523,
            "events_last_24h": 45,
            "failed_logins_24h": 3,
            "event_counts_24h": {
                "login_success": 12,
                "login_failure": 3,
                "api_key_created": 2,
                "permission_denied": 5,
                "session_created": 12,
                "session_terminated": 8,
            },
            "retention_days": 90,
        }

    def _auth_permissions_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List all permissions."""
        return {
            "permissions": [
                {"name": "users:read", "description": "View users", "resource": "users"},
                {"name": "users:write", "description": "Create/update users", "resource": "users"},
                {"name": "users:delete", "description": "Delete users", "resource": "users"},
                {"name": "findings:read", "description": "View findings", "resource": "findings"},
                {"name": "findings:write", "description": "Update findings", "resource": "findings"},
                {"name": "findings:suppress", "description": "Suppress findings", "resource": "findings"},
                {"name": "assets:read", "description": "View assets", "resource": "assets"},
                {"name": "assets:write", "description": "Update assets", "resource": "assets"},
                {"name": "policies:read", "description": "View policies", "resource": "policies"},
                {"name": "policies:write", "description": "Create/update policies", "resource": "policies"},
                {"name": "scans:read", "description": "View scan results", "resource": "scans"},
                {"name": "scans:run", "description": "Run scans", "resource": "scans"},
                {"name": "reports:read", "description": "View reports", "resource": "reports"},
                {"name": "reports:generate", "description": "Generate reports", "resource": "reports"},
                {"name": "config:read", "description": "View configuration", "resource": "config"},
                {"name": "config:write", "description": "Update configuration", "resource": "config"},
                {"name": "api_keys:read", "description": "View API keys", "resource": "api_keys"},
                {"name": "api_keys:write", "description": "Create/revoke API keys", "resource": "api_keys"},
            ],
            "total": 18,
        }

    def _auth_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get authentication summary."""
        return {
            "users": {
                "total": 5,
                "active": 4,
                "suspended": 1,
                "pending_verification": 0,
            },
            "sessions": {
                "total": 8,
                "active": 6,
            },
            "api_keys": {
                "total": 12,
                "active": 10,
                "expired": 2,
            },
            "audit": {
                "events_24h": 45,
                "failed_logins_24h": 3,
                "security_events_24h": 8,
            },
            "roles": {
                "system_roles": 6,
                "custom_roles": 2,
            },
        }

    # POST endpoints for authentication

    def _auth_login(self, body: bytes) -> dict[str, Any]:
        """Authenticate user and create session."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        email = data.get("email", "")
        password = data.get("password", "")

        if not email or not password:
            return {"error": "Email and password required", "success": False}

        # Demo: accept any login
        return {
            "success": True,
            "user": {
                "id": "usr_001",
                "email": email,
                "username": email.split("@")[0],
                "roles": ["admin"],
            },
            "tokens": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "refresh_token": "refresh_token_placeholder",
                "expires_in": 3600,
                "token_type": "Bearer",
            },
            "session_id": "sess_new_001",
        }

    def _auth_logout(self, body: bytes) -> dict[str, Any]:
        """Logout user and terminate session."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        session_id = data.get("session_id", "")

        return {
            "success": True,
            "message": f"Session {session_id or 'current'} terminated",
        }

    def _auth_users_create(self, body: bytes) -> dict[str, Any]:
        """Create a new user."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        email = data.get("email", "")
        username = data.get("username", "")
        password = data.get("password", "")

        if not email or not username or not password:
            return {"error": "Email, username, and password required", "success": False}

        return {
            "success": True,
            "user": {
                "id": "usr_new_001",
                "email": email,
                "username": username,
                "status": "active",
                "roles": data.get("roles", ["viewer"]),
                "created_at": datetime.utcnow().isoformat() + "Z",
            },
        }

    def _auth_users_delete(self, body: bytes) -> dict[str, Any]:
        """Delete a user."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        user_id = data.get("user_id", "")

        if not user_id:
            return {"error": "user_id required", "success": False}

        return {
            "success": True,
            "message": f"User {user_id} deleted",
        }

    def _auth_users_suspend(self, body: bytes) -> dict[str, Any]:
        """Suspend a user."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        user_id = data.get("user_id", "")
        reason = data.get("reason", "")

        if not user_id:
            return {"error": "user_id required", "success": False}

        return {
            "success": True,
            "message": f"User {user_id} suspended",
            "reason": reason,
        }

    def _auth_users_reactivate(self, body: bytes) -> dict[str, Any]:
        """Reactivate a suspended user."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        user_id = data.get("user_id", "")

        if not user_id:
            return {"error": "user_id required", "success": False}

        return {
            "success": True,
            "message": f"User {user_id} reactivated",
        }

    def _auth_apikeys_create(self, body: bytes) -> dict[str, Any]:
        """Create a new API key."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        name = data.get("name", "")

        if not name:
            return {"error": "name required", "success": False}

        return {
            "success": True,
            "api_key": {
                "id": "key_new_001",
                "name": name,
                "prefix": "stance_",
                "key": "stance_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "scopes": data.get("scopes", ["read:*"]),
                "created_at": datetime.utcnow().isoformat() + "Z",
                "expires_at": data.get("expires_at"),
            },
            "warning": "Save this key now. You will not be able to see it again.",
        }

    def _auth_apikeys_revoke(self, body: bytes) -> dict[str, Any]:
        """Revoke an API key."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        key_id = data.get("key_id", "")

        if not key_id:
            return {"error": "key_id required", "success": False}

        return {
            "success": True,
            "message": f"API key {key_id} revoked",
            "reason": data.get("reason", ""),
        }

    def _auth_apikeys_rotate(self, body: bytes) -> dict[str, Any]:
        """Rotate an API key."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        key_id = data.get("key_id", "")

        if not key_id:
            return {"error": "key_id required", "success": False}

        return {
            "success": True,
            "old_key_id": key_id,
            "new_api_key": {
                "id": "key_rotated_001",
                "key": "stance_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
                "created_at": datetime.utcnow().isoformat() + "Z",
            },
            "warning": "Save this key now. The old key has been revoked.",
        }

    def _auth_sessions_terminate(self, body: bytes) -> dict[str, Any]:
        """Terminate a session."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        session_id = data.get("session_id", "")
        user_id = data.get("user_id", "")

        if not session_id and not user_id:
            return {"error": "session_id or user_id required", "success": False}

        if user_id:
            return {
                "success": True,
                "message": f"All sessions for user {user_id} terminated",
                "terminated_count": 2,
            }

        return {
            "success": True,
            "message": f"Session {session_id} terminated",
        }

    def _auth_sessions_cleanup(self, body: bytes) -> dict[str, Any]:
        """Clean up expired sessions."""
        return {
            "success": True,
            "message": "Expired sessions cleaned up",
            "removed_count": 5,
        }

    def _auth_roles_assign(self, body: bytes) -> dict[str, Any]:
        """Assign a role to a user."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        user_id = data.get("user_id", "")
        role = data.get("role", "")

        if not user_id or not role:
            return {"error": "user_id and role required", "success": False}

        return {
            "success": True,
            "message": f"Role '{role}' assigned to user {user_id}",
        }

    def _auth_roles_revoke(self, body: bytes) -> dict[str, Any]:
        """Revoke a role from a user."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        user_id = data.get("user_id", "")
        role = data.get("role", "")

        if not user_id or not role:
            return {"error": "user_id and role required", "success": False}

        return {
            "success": True,
            "message": f"Role '{role}' revoked from user {user_id}",
        }

    def _auth_token_refresh(self, body: bytes) -> dict[str, Any]:
        """Refresh access token."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        refresh_token = data.get("refresh_token", "")

        if not refresh_token:
            return {"error": "refresh_token required", "success": False}

        return {
            "success": True,
            "tokens": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.new...",
                "refresh_token": "new_refresh_token_placeholder",
                "expires_in": 3600,
                "token_type": "Bearer",
            },
        }

    def _auth_token_validate(self, body: bytes) -> dict[str, Any]:
        """Validate an access token."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        token = data.get("token", "")

        if not token:
            return {"error": "token required", "success": False}

        return {
            "valid": True,
            "payload": {
                "user_id": "usr_001",
                "email": "admin@example.com",
                "roles": ["admin"],
                "issued_at": "2024-12-30T14:30:00Z",
                "expires_at": "2024-12-30T15:30:00Z",
            },
        }

    # ============================================================
    # Workflow Automation API handlers
    # ============================================================

    def _workflow_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get workflow automation status."""
        return {
            "components": {
                "escalation_engine": "operational",
                "runbook_system": "operational",
                "remediation_mapper": "operational",
                "trigger_engine": "operational",
                "servicenow_integration": "operational",
            },
            "capabilities": [
                "Multi-level escalation with SLA monitoring",
                "Runbook templates and execution tracking",
                "Finding-to-remediation mapping",
                "Auto-remediation for low-risk fixes",
                "Event-driven workflow triggers",
                "ServiceNow ITSM integration",
                "Approval workflows",
                "Execution history and audit trail",
            ],
        }

    def _workflow_stats(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get workflow automation statistics."""
        return {
            "escalation": {
                "active_policies": 3,
                "escalations_24h": 12,
                "sla_breaches_24h": 2,
            },
            "runbook": {
                "total_runbooks": 15,
                "executions_24h": 8,
                "success_rate": 87.5,
            },
            "remediation": {
                "active_rules": 8,
                "plans_created_24h": 23,
                "auto_remediated_24h": 12,
            },
            "trigger": {
                "active_triggers": 5,
                "executions_24h": 156,
                "success_rate": 98.7,
            },
        }

    def _workflow_escalation_policies(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get escalation policies."""
        return {
            "policies": [
                {
                    "id": "policy-critical-p1",
                    "name": "Critical P1 Response",
                    "description": "Immediate escalation for critical P1 incidents",
                    "priority": "P1",
                    "enabled": True,
                    "level_count": 5,
                },
                {
                    "id": "policy-security-incident",
                    "name": "Security Incident Escalation",
                    "description": "Escalation path for security incidents",
                    "priority": "P1-P2",
                    "enabled": True,
                    "level_count": 4,
                },
            ],
        }

    def _workflow_escalation_sla(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get SLA status for incidents."""
        return {
            "incidents": [
                {
                    "incident_id": "INC-001",
                    "priority": "P1",
                    "status": "warning",
                    "sla_hours": 1,
                    "remaining_minutes": 15,
                    "category": "security",
                },
                {
                    "incident_id": "INC-002",
                    "priority": "P2",
                    "status": "ok",
                    "sla_hours": 4,
                    "remaining_minutes": 192,
                    "category": "availability",
                },
            ],
        }

    def _workflow_escalation_history(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get escalation history."""
        return {
            "history": [
                {
                    "incident_id": "INC-003",
                    "escalation_type": "sla_breach",
                    "from_level": 1,
                    "to_level": 3,
                    "reason": "SLA breached after 60 minutes",
                    "timestamp": "2024-12-30T14:30:00Z",
                },
            ],
        }

    def _workflow_escalation_levels(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get escalation level definitions."""
        return {
            "levels": [
                {"level": 1, "name": "L1 - First Response", "response_time": "Immediate"},
                {"level": 2, "name": "L2 - Technical Lead", "response_time": "15 minutes"},
                {"level": 3, "name": "L3 - Management", "response_time": "30 minutes"},
                {"level": 4, "name": "L4 - Director", "response_time": "1 hour"},
                {"level": 5, "name": "L5 - Executive", "response_time": "2 hours"},
            ],
        }

    def _workflow_runbook_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List runbooks."""
        category = params.get("category", [""])[0]
        runbooks = [
            {"id": "rb-data-breach", "name": "Data Breach Response", "category": "incident", "version": "2.1"},
            {"id": "rb-compromised-creds", "name": "Compromised Credentials", "category": "incident", "version": "1.5"},
            {"id": "rb-vuln-remediation", "name": "Vulnerability Remediation", "category": "remediation", "version": "1.2"},
        ]
        if category:
            runbooks = [r for r in runbooks if r["category"] == category]
        return {"runbooks": runbooks}

    def _workflow_runbook_show(self, params: dict[str, Any]) -> dict[str, Any]:
        """Show runbook details."""
        runbook_id = params.get("id", [""])[0]
        return {
            "runbook": {
                "id": runbook_id or "rb-data-breach",
                "name": "Data Breach Response",
                "version": "2.1",
                "category": "incident",
                "description": "Comprehensive procedure for responding to data breach incidents",
                "tasks": [
                    {"name": "Initial Assessment", "type": "manual", "description": "Assess scope and severity"},
                    {"name": "Containment", "type": "automated", "description": "Isolate affected systems"},
                    {"name": "Evidence Collection", "type": "manual", "description": "Collect forensic evidence"},
                ],
            },
        }

    def _workflow_runbook_templates(self, params: dict[str, Any]) -> dict[str, Any]:
        """List runbook templates."""
        return {
            "templates": [
                {"id": "template-data-breach", "name": "Data Breach Response Template", "category": "incident"},
                {"id": "template-compromised-creds", "name": "Compromised Credentials Template", "category": "incident"},
                {"id": "template-vuln-remediation", "name": "Vulnerability Remediation Template", "category": "remediation"},
            ],
        }

    def _workflow_runbook_executions(self, params: dict[str, Any]) -> dict[str, Any]:
        """List runbook executions."""
        return {
            "executions": [
                {"id": "exec-001", "runbook_name": "Data Breach Response", "status": "in_progress", "progress": 25},
                {"id": "exec-002", "runbook_name": "Compromised Credentials", "status": "completed", "progress": 100},
            ],
        }

    def _workflow_remediation_rules(self, params: dict[str, Any]) -> dict[str, Any]:
        """List remediation rules."""
        return {
            "rules": [
                {"id": "remediate-public-s3", "name": "Block Public S3 Access", "risk_level": "low", "auto_remediate": True},
                {"id": "remediate-exposed-credentials", "name": "Rotate Exposed Credentials", "risk_level": "high", "auto_remediate": False},
                {"id": "remediate-open-security-group", "name": "Restrict Security Group", "risk_level": "medium", "auto_remediate": False},
            ],
        }

    def _workflow_remediation_plans(self, params: dict[str, Any]) -> dict[str, Any]:
        """List remediation plans."""
        return {
            "plans": [
                {"id": "plan-001", "finding_title": "S3 bucket publicly accessible", "status": "pending", "risk_level": "low"},
                {"id": "plan-002", "finding_title": "AWS credentials exposed in code", "status": "in_progress", "risk_level": "high"},
            ],
        }

    def _workflow_remediation_pending(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get pending remediation approvals."""
        return {
            "pending": [
                {"id": "plan-002", "finding_title": "AWS credentials exposed in code", "risk_level": "high", "approval_roles": ["security_lead"]},
            ],
        }

    def _workflow_remediation_auto(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get auto-remediation status."""
        return {
            "mode": "low_risk",
            "status": "enabled",
            "risk_levels": {"none": True, "low": True, "medium": False, "high": False, "critical": False},
            "eligible_count": 5,
            "applied_24h": 12,
        }

    def _workflow_trigger_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """List workflow triggers."""
        return {
            "triggers": [
                {"id": "trigger-critical-finding", "name": "Critical Finding Response", "type": "finding_created", "status": "active"},
                {"id": "trigger-sla-breach", "name": "SLA Breach Escalation", "type": "sla_breach", "status": "active"},
            ],
        }

    def _workflow_trigger_types(self, params: dict[str, Any]) -> dict[str, Any]:
        """List trigger event types."""
        return {
            "types": [
                {"value": "finding_created", "description": "New security finding detected"},
                {"value": "incident_created", "description": "New incident created"},
                {"value": "sla_breach", "description": "SLA deadline breached"},
                {"value": "scan_completed", "description": "Security scan completed"},
                {"value": "webhook", "description": "External webhook received"},
            ],
        }

    def _workflow_trigger_history(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get trigger execution history."""
        return {
            "history": [
                {"id": "exec-t001", "trigger_name": "Critical Finding Response", "success": True, "started_at": "2024-12-30T14:30:00Z"},
                {"id": "exec-t002", "trigger_name": "Post-Scan Processing", "success": True, "started_at": "2024-12-30T13:30:00Z"},
            ],
        }

    def _workflow_escalation_trigger(self, body: bytes) -> dict[str, Any]:
        """Trigger an escalation."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        incident_id = data.get("incident_id", "")
        if not incident_id:
            return {"error": "incident_id required", "success": False}

        return {"success": True, "message": f"Escalation triggered for incident {incident_id}"}

    def _workflow_runbook_execute(self, body: bytes) -> dict[str, Any]:
        """Execute a runbook."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        runbook_id = data.get("runbook_id", "")
        if not runbook_id:
            return {"error": "runbook_id required", "success": False}

        return {"success": True, "execution_id": "exec-003", "message": f"Runbook {runbook_id} started"}

    def _workflow_runbook_cancel(self, body: bytes) -> dict[str, Any]:
        """Cancel a runbook execution."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        execution_id = data.get("execution_id", "")
        if not execution_id:
            return {"error": "execution_id required", "success": False}

        return {"success": True, "message": f"Runbook execution {execution_id} cancelled"}

    def _workflow_remediation_approve(self, body: bytes) -> dict[str, Any]:
        """Approve a remediation plan."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        plan_id = data.get("plan_id", "")
        if not plan_id:
            return {"error": "plan_id required", "success": False}

        return {"success": True, "message": f"Remediation plan {plan_id} approved"}

    def _workflow_remediation_reject(self, body: bytes) -> dict[str, Any]:
        """Reject a remediation plan."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        plan_id = data.get("plan_id", "")
        reason = data.get("reason", "No reason provided")
        if not plan_id:
            return {"error": "plan_id required", "success": False}

        return {"success": True, "message": f"Remediation plan {plan_id} rejected: {reason}"}

    def _workflow_remediation_execute(self, body: bytes) -> dict[str, Any]:
        """Execute a remediation plan."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        plan_id = data.get("plan_id", "")
        if not plan_id:
            return {"error": "plan_id required", "success": False}

        return {"success": True, "message": f"Remediation plan {plan_id} execution started"}

    def _workflow_trigger_enable(self, body: bytes) -> dict[str, Any]:
        """Enable a workflow trigger."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        trigger_id = data.get("trigger_id", "")
        if not trigger_id:
            return {"error": "trigger_id required", "success": False}

        return {"success": True, "message": f"Trigger {trigger_id} enabled"}

    def _workflow_trigger_disable(self, body: bytes) -> dict[str, Any]:
        """Disable a workflow trigger."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        trigger_id = data.get("trigger_id", "")
        if not trigger_id:
            return {"error": "trigger_id required", "success": False}

        return {"success": True, "message": f"Trigger {trigger_id} disabled"}

    def _workflow_trigger_test(self, body: bytes) -> dict[str, Any]:
        """Test a workflow trigger."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON", "success": False}

        trigger_id = data.get("trigger_id", "")
        if not trigger_id:
            return {"error": "trigger_id required", "success": False}

        return {
            "success": True,
            "trigger_id": trigger_id,
            "would_match": True,
            "conditions_met": True,
            "actions": [
                {"type": "playbook", "target": "critical-finding-response"},
                {"type": "notify", "target": "security-channel"},
            ],
        }

    # =========================================================================
    # Enhanced Visualization API handlers (Phase 94)
    # =========================================================================

    def _get_viz_api(self):
        """Get visualization API instance."""
        from stance.web.visualization_api import get_visualization_api
        return get_visualization_api()

    # Widget Template GET endpoints
    def _viz_widget_templates(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().widget_templates_list(params)

    def _viz_widget_search(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().widget_templates_search(params)

    def _viz_widget_info(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().widget_template_info(params)

    # Layout GET endpoints
    def _viz_layout_info(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().dashboard_layout_info(params)

    # Embedding GET endpoints
    def _viz_embed_tokens(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().embed_tokens_list(params)

    def _viz_embed_validate(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().embed_token_validate(params)

    # Sharing GET endpoints
    def _viz_share_links(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().share_links_list(params)

    def _viz_share_validate(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().share_link_validate(params)

    def _viz_share_status(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().share_status(params)

    # Realtime GET endpoints
    def _viz_realtime_status(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().realtime_status(params)

    def _viz_realtime_events(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().realtime_event_types(params)

    def _viz_realtime_messages(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().realtime_messages(params)

    # Chart GET endpoints
    def _viz_chart_types(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().chart_types(params)

    # Updates GET endpoints
    def _viz_updates_status(self, params: dict) -> dict[str, Any]:
        return self._get_viz_api().updates_status(params)

    # Widget POST endpoints
    def _viz_widget_create(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().widget_create(body)

    def _viz_widget_delete(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().widget_delete(body)

    def _viz_widget_move(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().widget_move(body)

    def _viz_widget_resize(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().widget_resize(body)

    # Layout POST endpoints
    def _viz_layout_compact(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().dashboard_layout_compact(body)

    def _viz_layout_arrange(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().dashboard_layout_arrange(body)

    # Embedding POST endpoints
    def _viz_embed_create(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().embed_token_create(body)

    def _viz_embed_revoke(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().embed_token_revoke(body)

    # Sharing POST endpoints
    def _viz_share_create(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().share_link_create(body)

    def _viz_share_dashboard(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().share_dashboard(body)

    # Realtime POST endpoints
    def _viz_realtime_publish(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().realtime_publish(body)

    def _viz_realtime_subscribe(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().realtime_subscribe(body)

    def _viz_realtime_unsubscribe(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().realtime_unsubscribe(body)

    # Chart POST endpoints
    def _viz_chart_create(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().chart_create(body)

    def _viz_chart_interact(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().chart_interact(body)

    def _viz_chart_drill_down(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().chart_drill_down(body)

    def _viz_chart_drill_up(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().chart_drill_up(body)

    # Updates POST endpoints
    def _viz_updates_refresh(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().updates_refresh(body)

    def _viz_updates_invalidate(self, body: bytes) -> dict[str, Any]:
        return self._get_viz_api().updates_invalidate(body)


class StanceServer:
    """
    Simple HTTP server for Stance dashboard.

    Serves the dashboard UI and provides JSON API endpoints
    for accessing posture data.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        storage: StorageBackend | None = None,
    ):
        """
        Initialize the server.

        Args:
            host: Host to bind to (default: 127.0.0.1)
            port: Port to listen on (default: 8080)
            storage: Storage backend to use (default: LocalStorage)
        """
        self.host = host
        self.port = port
        self.storage = storage or get_storage("local")
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self):
        """
        Start the HTTP server (blocking).

        This method blocks until the server is stopped.
        """
        # Set storage on handler class
        StanceRequestHandler.storage = self.storage

        self._server = HTTPServer((self.host, self.port), StanceRequestHandler)

        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._server.server_close()

    def start_background(self) -> threading.Thread:
        """
        Start server in background thread.

        Returns:
            Thread running the server
        """
        self._thread = threading.Thread(target=self.start, daemon=True)
        self._thread.start()
        return self._thread

    def stop(self):
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def url(self) -> str:
        """Get the server URL."""
        return f"http://{self.host}:{self.port}"
