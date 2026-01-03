"""
Tests for Web API aggregation endpoints.
"""

import json
from datetime import datetime
from io import BytesIO
from unittest import TestCase
from unittest.mock import patch, MagicMock

from stance.web.server import StanceRequestHandler


class MockRequest:
    """Mock HTTP request for testing."""

    def __init__(self, path: str = "/", method: str = "GET"):
        self.path = path
        self.method = method


class MockResponse(BytesIO):
    """Mock HTTP response for testing."""

    def __init__(self):
        super().__init__()
        self.status_code = None
        self.headers = {}


class TestAggregationAggregateEndpoint(TestCase):
    """Tests for /api/aggregation/aggregate endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_aggregate_basic(self):
        """Test basic aggregation endpoint."""
        result = self.handler._aggregation_aggregate({})

        self.assertIn("result", result)
        self.assertIn("findings", result)
        self.assertIn("count", result)
        self.assertIn("total_findings", result["result"])
        self.assertIn("unique_findings", result["result"])
        self.assertIn("duplicates_removed", result["result"])

    def test_aggregate_with_severity_filter(self):
        """Test aggregation with severity filter."""
        result = self.handler._aggregation_aggregate({"severity": ["critical"]})

        self.assertIn("findings", result)
        for finding in result["findings"]:
            self.assertEqual(finding["severity"], "critical")

    def test_aggregate_with_high_severity(self):
        """Test aggregation with high severity filter."""
        result = self.handler._aggregation_aggregate({"severity": ["high"]})

        self.assertIn("findings", result)
        # Should have high severity findings
        for finding in result["findings"]:
            self.assertEqual(finding["severity"], "high")

    def test_aggregate_without_deduplication(self):
        """Test aggregation without deduplication."""
        result = self.handler._aggregation_aggregate({"deduplicate": ["false"]})

        self.assertIn("result", result)
        # Without dedup, total == unique
        self.assertEqual(
            result["result"]["total_findings"],
            result["result"]["unique_findings"]
        )

    def test_aggregate_with_deduplication(self):
        """Test aggregation with deduplication."""
        result = self.handler._aggregation_aggregate({"deduplicate": ["true"]})

        self.assertIn("result", result)
        # With dedup, duplicates may be removed
        self.assertGreaterEqual(
            result["result"]["total_findings"],
            result["result"]["unique_findings"]
        )

    def test_aggregate_result_structure(self):
        """Test aggregation result structure."""
        result = self.handler._aggregation_aggregate({})

        self.assertIn("findings_by_severity", result["result"])
        self.assertIn("findings_by_provider", result["result"])
        self.assertIn("findings_by_account", result["result"])
        self.assertIn("source_accounts", result["result"])
        self.assertIn("aggregated_at", result["result"])


class TestAggregationCrossAccountEndpoint(TestCase):
    """Tests for /api/aggregation/cross-account endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_cross_account_default(self):
        """Test cross-account with default threshold."""
        result = self.handler._aggregation_cross_account({})

        self.assertIn("min_accounts", result)
        self.assertIn("count", result)
        self.assertIn("findings", result)
        self.assertEqual(result["min_accounts"], 2)

    def test_cross_account_custom_threshold(self):
        """Test cross-account with custom threshold."""
        result = self.handler._aggregation_cross_account({"min_accounts": ["3"]})

        self.assertEqual(result["min_accounts"], 3)

    def test_cross_account_high_threshold(self):
        """Test cross-account with high threshold."""
        result = self.handler._aggregation_cross_account({"min_accounts": ["10"]})

        # With only 3 sample accounts, no findings appear in 10+
        self.assertEqual(result["count"], 0)
        self.assertEqual(len(result["findings"]), 0)

    def test_cross_account_findings_structure(self):
        """Test cross-account findings structure."""
        result = self.handler._aggregation_cross_account({})

        for finding in result["findings"]:
            self.assertIn("id", finding)
            self.assertIn("title", finding)
            self.assertIn("severity", finding)


class TestAggregationSummaryEndpoint(TestCase):
    """Tests for /api/aggregation/summary endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_summary_basic(self):
        """Test summary endpoint."""
        result = self.handler._aggregation_summary({})

        self.assertIn("summary", result)
        self.assertIn("by_severity", result)
        self.assertIn("by_provider", result)

    def test_summary_structure(self):
        """Test summary result structure."""
        result = self.handler._aggregation_summary({})

        summary = result["summary"]
        self.assertIn("total_accounts", summary)
        self.assertIn("total_findings", summary)
        self.assertIn("unique_findings", summary)
        self.assertIn("duplicates_removed", summary)
        self.assertIn("cross_account_findings", summary)

    def test_summary_by_severity(self):
        """Test summary severity breakdown."""
        result = self.handler._aggregation_summary({})

        self.assertIn("by_severity", result)
        # Should have at least some severity categories
        by_severity = result["by_severity"]
        self.assertIsInstance(by_severity, dict)

    def test_summary_by_provider(self):
        """Test summary provider breakdown."""
        result = self.handler._aggregation_summary({})

        self.assertIn("by_provider", result)
        by_provider = result["by_provider"]
        # Should have aws, gcp, azure
        self.assertIn("aws", by_provider)
        self.assertIn("gcp", by_provider)
        self.assertIn("azure", by_provider)


class TestAggregationSyncEndpoint(TestCase):
    """Tests for /api/aggregation/sync endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_sync_requires_bucket(self):
        """Test sync requires bucket parameter."""
        result = self.handler._aggregation_sync({})

        self.assertIn("error", result)
        self.assertIn("bucket parameter is required", result["error"])

    def test_sync_with_bucket(self):
        """Test sync with bucket parameter."""
        result = self.handler._aggregation_sync({
            "bucket": ["my-bucket"],
            "direction": ["push"],
        })

        self.assertIn("config", result)
        self.assertEqual(result["config"]["bucket"], "my-bucket")
        self.assertEqual(result["config"]["direction"], "push")

    def test_sync_dry_run(self):
        """Test sync dry run mode."""
        result = self.handler._aggregation_sync({
            "bucket": ["my-bucket"],
            "dry_run": ["true"],
        })

        self.assertTrue(result["dry_run"])
        self.assertIn("Dry run", result["message"])

    def test_sync_invalid_direction(self):
        """Test sync with invalid direction."""
        result = self.handler._aggregation_sync({
            "bucket": ["my-bucket"],
            "direction": ["invalid"],
        })

        self.assertIn("error", result)
        self.assertIn("Invalid direction", result["error"])

    def test_sync_valid_directions(self):
        """Test sync with all valid directions."""
        for direction in ["push", "pull", "bidirectional"]:
            result = self.handler._aggregation_sync({
                "bucket": ["my-bucket"],
                "direction": [direction],
            })
            self.assertEqual(result["config"]["direction"], direction)

    def test_sync_result_structure(self):
        """Test sync result structure."""
        result = self.handler._aggregation_sync({
            "bucket": ["my-bucket"],
        })

        self.assertIn("config", result)
        self.assertIn("result", result)
        self.assertIn("message", result)

        config = result["config"]
        self.assertIn("bucket", config)
        self.assertIn("direction", config)
        self.assertIn("prefix", config)
        self.assertIn("include_assets", config)


class TestAggregationSyncStatusEndpoint(TestCase):
    """Tests for /api/aggregation/sync-status endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_sync_status_basic(self):
        """Test sync status endpoint."""
        result = self.handler._aggregation_sync_status({})

        self.assertIn("sync_enabled", result)
        self.assertIn("last_sync", result)
        self.assertIn("configured_buckets", result)
        self.assertIn("pending_records", result)
        self.assertIn("sync_errors", result)

    def test_sync_status_initial_state(self):
        """Test sync status shows initial state."""
        result = self.handler._aggregation_sync_status({})

        self.assertFalse(result["sync_enabled"])
        self.assertIsNone(result["last_sync"])
        self.assertEqual(result["pending_records"], 0)
        self.assertEqual(len(result["configured_buckets"]), 0)


class TestAggregationBackendsEndpoint(TestCase):
    """Tests for /api/aggregation/backends endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_backends_basic(self):
        """Test backends endpoint."""
        result = self.handler._aggregation_backends({})

        self.assertIn("backends", result)
        self.assertIn("total", result)
        self.assertIn("enabled", result)
        self.assertIn("connected", result)

    def test_backends_structure(self):
        """Test backends list structure."""
        result = self.handler._aggregation_backends({})

        backends = result["backends"]
        self.assertIsInstance(backends, list)
        self.assertTrue(len(backends) > 0)

        backend = backends[0]
        self.assertIn("name", backend)
        self.assertIn("provider", backend)
        self.assertIn("enabled", backend)
        self.assertIn("priority", backend)
        self.assertIn("engine", backend)
        self.assertIn("connected", backend)

    def test_backends_providers(self):
        """Test backends include all providers."""
        result = self.handler._aggregation_backends({})

        providers = [b["provider"] for b in result["backends"]]
        self.assertIn("aws", providers)
        self.assertIn("gcp", providers)
        self.assertIn("azure", providers)

    def test_backends_counts(self):
        """Test backends counts are correct."""
        result = self.handler._aggregation_backends({})

        total = result["total"]
        enabled = result["enabled"]
        connected = result["connected"]

        self.assertEqual(total, len(result["backends"]))
        self.assertEqual(
            enabled,
            sum(1 for b in result["backends"] if b["enabled"])
        )
        self.assertEqual(
            connected,
            sum(1 for b in result["backends"] if b["connected"])
        )


class TestAggregationStatusEndpoint(TestCase):
    """Tests for /api/aggregation/status endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_status_basic(self):
        """Test status endpoint."""
        result = self.handler._aggregation_status({})

        self.assertEqual(result["module"], "aggregation")
        self.assertIn("version", result)
        self.assertIn("capabilities", result)

    def test_status_capabilities(self):
        """Test status capabilities structure."""
        result = self.handler._aggregation_status({})

        capabilities = result["capabilities"]
        self.assertTrue(capabilities["multi_account_aggregation"])
        self.assertTrue(capabilities["cross_account_detection"])
        self.assertTrue(capabilities["deduplication"])
        self.assertTrue(capabilities["severity_filtering"])
        self.assertTrue(capabilities["cross_cloud_sync"])
        self.assertTrue(capabilities["federated_queries"])

    def test_status_supported_providers(self):
        """Test status supported providers."""
        result = self.handler._aggregation_status({})

        providers = result["supported_providers"]
        self.assertIn("aws", providers)
        self.assertIn("gcp", providers)
        self.assertIn("azure", providers)

    def test_status_sync_adapters(self):
        """Test status sync adapters."""
        result = self.handler._aggregation_status({})

        adapters = result["sync_adapters"]
        self.assertIn("S3", adapters)
        self.assertIn("GCS", adapters)
        self.assertIn("Azure Blob", adapters)

    def test_status_query_backends(self):
        """Test status query backends."""
        result = self.handler._aggregation_status({})

        backends = result["query_backends"]
        self.assertIn("Athena", backends)
        self.assertIn("BigQuery", backends)
        self.assertIn("Synapse", backends)

    def test_status_strategies(self):
        """Test status strategies."""
        result = self.handler._aggregation_status({})

        merge_strategies = result["merge_strategies"]
        self.assertIn("union", merge_strategies)
        self.assertIn("union_distinct", merge_strategies)
        self.assertIn("intersect", merge_strategies)
        self.assertIn("priority", merge_strategies)

        query_strategies = result["query_strategies"]
        self.assertIn("parallel", query_strategies)
        self.assertIn("sequential", query_strategies)
        self.assertIn("first_success", query_strategies)
        self.assertIn("best_effort", query_strategies)


class TestSampleAggregationData(TestCase):
    """Tests for sample aggregation data generation."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_sample_data_accounts(self):
        """Test sample data has correct accounts."""
        accounts, findings = self.handler._get_sample_aggregation_data()

        self.assertEqual(len(accounts), 3)

        providers = [a.provider for a in accounts]
        self.assertIn("aws", providers)
        self.assertIn("gcp", providers)
        self.assertIn("azure", providers)

    def test_sample_data_findings(self):
        """Test sample data has findings for each account."""
        accounts, findings_by_account = self.handler._get_sample_aggregation_data()

        for account in accounts:
            self.assertIn(account.id, findings_by_account)
            self.assertTrue(len(findings_by_account[account.id]) > 0)

    def test_sample_data_finding_structure(self):
        """Test sample data findings have correct structure."""
        _, findings_by_account = self.handler._get_sample_aggregation_data()

        for account_id, findings in findings_by_account.items():
            for finding in findings:
                self.assertIsNotNone(finding.id)
                self.assertIsNotNone(finding.title)
                self.assertIsNotNone(finding.severity)
                self.assertIsNotNone(finding.rule_id)


class TestAggregationEndpointEdgeCases(TestCase):
    """Edge case tests for aggregation endpoints."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_aggregate_empty_params(self):
        """Test aggregate with None params."""
        result = self.handler._aggregation_aggregate(None)
        self.assertIn("result", result)

    def test_cross_account_empty_params(self):
        """Test cross-account with None params."""
        result = self.handler._aggregation_cross_account(None)
        self.assertIn("min_accounts", result)
        self.assertEqual(result["min_accounts"], 2)

    def test_summary_empty_params(self):
        """Test summary with None params."""
        result = self.handler._aggregation_summary(None)
        self.assertIn("summary", result)

    def test_sync_empty_params(self):
        """Test sync with None params."""
        result = self.handler._aggregation_sync(None)
        self.assertIn("error", result)

    def test_sync_status_empty_params(self):
        """Test sync-status with None params."""
        result = self.handler._aggregation_sync_status(None)
        self.assertIn("sync_enabled", result)

    def test_backends_empty_params(self):
        """Test backends with None params."""
        result = self.handler._aggregation_backends(None)
        self.assertIn("backends", result)

    def test_status_empty_params(self):
        """Test status with None params."""
        result = self.handler._aggregation_status(None)
        self.assertEqual(result["module"], "aggregation")


class TestAggregationAPIRouting(TestCase):
    """Tests for API routing of aggregation endpoints."""

    def test_aggregation_endpoints_exist(self):
        """Test that all aggregation endpoints are routed."""
        endpoints = [
            "/api/aggregation/aggregate",
            "/api/aggregation/cross-account",
            "/api/aggregation/summary",
            "/api/aggregation/sync",
            "/api/aggregation/sync-status",
            "/api/aggregation/backends",
            "/api/aggregation/status",
        ]

        # These are the method names that should exist
        method_names = [
            "_aggregation_aggregate",
            "_aggregation_cross_account",
            "_aggregation_summary",
            "_aggregation_sync",
            "_aggregation_sync_status",
            "_aggregation_backends",
            "_aggregation_status",
        ]

        for method_name in method_names:
            self.assertTrue(
                hasattr(StanceRequestHandler, method_name),
                f"Method {method_name} should exist"
            )


class TestAggregationIntegration(TestCase):
    """Integration tests for aggregation API endpoints."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = StanceRequestHandler.__new__(StanceRequestHandler)
        self.handler.storage = None

    def test_full_aggregation_workflow(self):
        """Test complete aggregation workflow via API."""
        # Step 1: Check module status
        status = self.handler._aggregation_status({})
        self.assertTrue(status["capabilities"]["multi_account_aggregation"])

        # Step 2: List backends
        backends = self.handler._aggregation_backends({})
        self.assertTrue(backends["total"] > 0)

        # Step 3: Run aggregation
        aggregation = self.handler._aggregation_aggregate({})
        self.assertIn("result", aggregation)
        self.assertGreater(aggregation["result"]["total_findings"], 0)

        # Step 4: Get cross-account findings
        cross_account = self.handler._aggregation_cross_account({})
        self.assertIn("findings", cross_account)

        # Step 5: Get summary
        summary = self.handler._aggregation_summary({})
        self.assertIn("summary", summary)
        self.assertIn("by_severity", summary)
        self.assertIn("by_provider", summary)

    def test_sync_configuration_workflow(self):
        """Test sync configuration workflow via API."""
        # Step 1: Check sync status
        sync_status = self.handler._aggregation_sync_status({})
        self.assertFalse(sync_status["sync_enabled"])

        # Step 2: Configure sync (dry run)
        sync_config = self.handler._aggregation_sync({
            "bucket": ["my-central-bucket"],
            "direction": ["push"],
            "dry_run": ["true"],
        })
        self.assertTrue(sync_config["dry_run"])
        self.assertEqual(sync_config["config"]["bucket"], "my-central-bucket")

    def test_aggregation_with_filters(self):
        """Test aggregation with various filters."""
        # Filter by severity
        critical_only = self.handler._aggregation_aggregate({
            "severity": ["critical"],
        })
        for finding in critical_only["findings"]:
            self.assertEqual(finding["severity"], "critical")

        # Filter by severity and dedup
        high_dedup = self.handler._aggregation_aggregate({
            "severity": ["high"],
            "deduplicate": ["true"],
        })
        self.assertIn("result", high_dedup)

    def test_cross_account_thresholds(self):
        """Test cross-account with different thresholds."""
        # Low threshold
        low = self.handler._aggregation_cross_account({"min_accounts": ["1"]})
        self.assertEqual(low["min_accounts"], 1)

        # Default threshold
        default = self.handler._aggregation_cross_account({})
        self.assertEqual(default["min_accounts"], 2)

        # High threshold (should return fewer/no results)
        high = self.handler._aggregation_cross_account({"min_accounts": ["5"]})
        self.assertEqual(high["min_accounts"], 5)
        self.assertEqual(high["count"], 0)
