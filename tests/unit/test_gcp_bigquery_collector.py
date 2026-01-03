"""
Unit tests for GCPBigQueryCollector.

Tests cover:
- BigQuery dataset collection with mocked GCP responses
- Table collection within datasets
- Access control / public dataset detection
- CMEK encryption configuration
- Network exposure determination
- Table metadata (partitioning, clustering, external tables)
- Error handling for API failures
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from stance.models import (
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)


# Mock the GCP dependencies at module level before importing the collector
mock_googleapiclient = MagicMock()
mock_discovery = MagicMock()
mock_google_auth = MagicMock()
mock_google_oauth2 = MagicMock()
mock_service_account = MagicMock()

sys.modules["googleapiclient"] = mock_googleapiclient
sys.modules["googleapiclient.discovery"] = mock_discovery
sys.modules["google"] = MagicMock()
sys.modules["google.auth"] = mock_google_auth
sys.modules["google.oauth2"] = mock_google_oauth2
sys.modules["google.oauth2.service_account"] = mock_service_account


class TestGCPBigQueryCollector:
    """Tests for GCPBigQueryCollector."""

    def test_gcp_bigquery_collector_init(self):
        """Test GCPBigQueryCollector can be initialized."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )
        assert collector.collector_name == "gcp_bigquery"
        assert collector.project_id == "test-project"
        assert "gcp_bigquery_dataset" in collector.resource_types
        assert "gcp_bigquery_table" in collector.resource_types

    def test_gcp_bigquery_collector_collect_datasets(
        self, mock_gcp_bigquery_service
    ):
        """Test BigQuery dataset collection with mock response."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector, "_get_service", return_value=mock_gcp_bigquery_service
        ):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            # Should have 1 dataset + tables
            dataset_assets = [
                a for a in assets if a.resource_type == "gcp_bigquery_dataset"
            ]
            assert len(dataset_assets) == 1

            dataset = dataset_assets[0]
            assert dataset.name == "analytics_data"
            assert dataset.cloud_provider == "gcp"
            assert dataset.account_id == "test-project"
            assert dataset.region == "US"

    def test_gcp_bigquery_collector_public_dataset(
        self, mock_gcp_bigquery_service_public
    ):
        """Test detection of public BigQuery dataset."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector, "_get_service", return_value=mock_gcp_bigquery_service_public
        ):
            assets = collector.collect()

            dataset_assets = [
                a for a in assets if a.resource_type == "gcp_bigquery_dataset"
            ]
            assert len(dataset_assets) == 1

            dataset = dataset_assets[0]
            assert dataset.network_exposure == NETWORK_EXPOSURE_INTERNET
            assert dataset.raw_config["is_public"] is True

    def test_gcp_bigquery_collector_all_authenticated_users(
        self, mock_gcp_bigquery_service_all_authenticated
    ):
        """Test detection of dataset accessible to all authenticated users."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector,
            "_get_service",
            return_value=mock_gcp_bigquery_service_all_authenticated,
        ):
            assets = collector.collect()

            dataset_assets = [
                a for a in assets if a.resource_type == "gcp_bigquery_dataset"
            ]
            assert len(dataset_assets) == 1

            dataset = dataset_assets[0]
            assert dataset.network_exposure == NETWORK_EXPOSURE_INTERNET
            assert dataset.raw_config["allows_all_authenticated_users"] is True

    def test_gcp_bigquery_collector_private_dataset(
        self, mock_gcp_bigquery_service
    ):
        """Test private BigQuery dataset collection."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector, "_get_service", return_value=mock_gcp_bigquery_service
        ):
            assets = collector.collect()

            dataset_assets = [
                a for a in assets if a.resource_type == "gcp_bigquery_dataset"
            ]
            assert len(dataset_assets) == 1

            dataset = dataset_assets[0]
            assert dataset.network_exposure == NETWORK_EXPOSURE_INTERNAL
            assert dataset.raw_config["is_public"] is False

    def test_gcp_bigquery_collector_cmek_encryption(
        self, mock_gcp_bigquery_service_cmek
    ):
        """Test detection of CMEK encryption configuration."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector, "_get_service", return_value=mock_gcp_bigquery_service_cmek
        ):
            assets = collector.collect()

            dataset_assets = [
                a for a in assets if a.resource_type == "gcp_bigquery_dataset"
            ]
            assert len(dataset_assets) == 1

            dataset = dataset_assets[0]
            assert dataset.raw_config["uses_cmek"] is True
            assert "keyRings" in dataset.raw_config["kms_key_name"]

    def test_gcp_bigquery_collector_collect_tables(
        self, mock_gcp_bigquery_service_with_tables
    ):
        """Test BigQuery table collection within dataset."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector,
            "_get_service",
            return_value=mock_gcp_bigquery_service_with_tables,
        ):
            assets = collector.collect()

            table_assets = [
                a for a in assets if a.resource_type == "gcp_bigquery_table"
            ]
            assert len(table_assets) >= 1

            table = table_assets[0]
            assert "events" in table.name
            assert table.raw_config["type"] == "TABLE"

    def test_gcp_bigquery_collector_partitioned_table(
        self, mock_gcp_bigquery_service_partitioned
    ):
        """Test collection of partitioned table metadata."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector,
            "_get_service",
            return_value=mock_gcp_bigquery_service_partitioned,
        ):
            assets = collector.collect()

            table_assets = [
                a for a in assets if a.resource_type == "gcp_bigquery_table"
            ]
            assert len(table_assets) >= 1

            table = table_assets[0]
            assert table.raw_config["time_partitioning"] is not None
            assert table.raw_config["time_partitioning"]["type"] == "DAY"

    def test_gcp_bigquery_collector_external_table(
        self, mock_gcp_bigquery_service_external
    ):
        """Test collection of external table metadata."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector,
            "_get_service",
            return_value=mock_gcp_bigquery_service_external,
        ):
            assets = collector.collect()

            table_assets = [
                a for a in assets if a.resource_type == "gcp_bigquery_table"
            ]
            assert len(table_assets) >= 1

            table = table_assets[0]
            assert table.raw_config["is_external"] is True
            assert table.raw_config["source_format"] == "PARQUET"

    def test_gcp_bigquery_collector_handles_empty_response(
        self, mock_gcp_bigquery_service_empty
    ):
        """Test graceful handling of empty dataset list."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector, "_get_service", return_value=mock_gcp_bigquery_service_empty
        ):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_gcp_bigquery_collector_handles_api_error(
        self, mock_gcp_bigquery_service_error
    ):
        """Test graceful handling of API errors."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector, "_get_service", return_value=mock_gcp_bigquery_service_error
        ):
            # Should handle error and return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)

    def test_gcp_bigquery_collector_labels_extraction(
        self, mock_gcp_bigquery_service
    ):
        """Test proper extraction of dataset labels."""
        import importlib
        import stance.collectors.gcp_bigquery as gcp_bigquery_module
        importlib.reload(gcp_bigquery_module)

        collector = gcp_bigquery_module.GCPBigQueryCollector(
            project_id="test-project"
        )

        with patch.object(
            collector, "_get_service", return_value=mock_gcp_bigquery_service
        ):
            assets = collector.collect()

            dataset_assets = [
                a for a in assets if a.resource_type == "gcp_bigquery_dataset"
            ]
            assert len(dataset_assets) == 1

            dataset = dataset_assets[0]
            assert dataset.tags.get("environment") == "production"
            assert dataset.tags.get("team") == "data-engineering"


# Fixtures


@pytest.fixture
def mock_gcp_bigquery_service():
    """Create a mock BigQuery service with a private dataset."""
    mock_service = MagicMock()

    # Mock datasets().list()
    mock_datasets = MagicMock()
    mock_service.datasets.return_value = mock_datasets

    mock_list = MagicMock()
    mock_datasets.list.return_value = mock_list
    mock_list.execute.return_value = {
        "datasets": [
            {
                "datasetReference": {
                    "datasetId": "analytics_data",
                    "projectId": "test-project",
                }
            }
        ]
    }
    mock_datasets.list_next.return_value = None

    # Mock datasets().get()
    mock_get = MagicMock()
    mock_datasets.get.return_value = mock_get
    mock_get.execute.return_value = {
        "datasetReference": {
            "datasetId": "analytics_data",
            "projectId": "test-project",
        },
        "location": "US",
        "description": "Analytics dataset",
        "creationTime": "1704067200000",  # 2024-01-01
        "labels": {
            "environment": "production",
            "team": "data-engineering",
        },
        "access": [
            {
                "role": "OWNER",
                "userByEmail": "admin@example.com",
            },
            {
                "role": "READER",
                "groupByEmail": "data-readers@example.com",
            },
        ],
    }

    # Mock tables().list() - empty tables
    mock_tables = MagicMock()
    mock_service.tables.return_value = mock_tables

    mock_tables_list = MagicMock()
    mock_tables.list.return_value = mock_tables_list
    mock_tables_list.execute.return_value = {"tables": []}
    mock_tables.list_next.return_value = None

    return mock_service


@pytest.fixture
def mock_gcp_bigquery_service_public():
    """Create a mock BigQuery service with a public dataset."""
    mock_service = MagicMock()

    mock_datasets = MagicMock()
    mock_service.datasets.return_value = mock_datasets

    mock_list = MagicMock()
    mock_datasets.list.return_value = mock_list
    mock_list.execute.return_value = {
        "datasets": [
            {
                "datasetReference": {
                    "datasetId": "public_data",
                    "projectId": "test-project",
                }
            }
        ]
    }
    mock_datasets.list_next.return_value = None

    mock_get = MagicMock()
    mock_datasets.get.return_value = mock_get
    mock_get.execute.return_value = {
        "datasetReference": {
            "datasetId": "public_data",
            "projectId": "test-project",
        },
        "location": "US",
        "access": [
            {
                "role": "READER",
                "specialGroup": "allUsers",  # Public access
            },
        ],
    }

    mock_tables = MagicMock()
    mock_service.tables.return_value = mock_tables
    mock_tables_list = MagicMock()
    mock_tables.list.return_value = mock_tables_list
    mock_tables_list.execute.return_value = {"tables": []}
    mock_tables.list_next.return_value = None

    return mock_service


@pytest.fixture
def mock_gcp_bigquery_service_all_authenticated():
    """Create a mock BigQuery service with allAuthenticatedUsers access."""
    mock_service = MagicMock()

    mock_datasets = MagicMock()
    mock_service.datasets.return_value = mock_datasets

    mock_list = MagicMock()
    mock_datasets.list.return_value = mock_list
    mock_list.execute.return_value = {
        "datasets": [
            {
                "datasetReference": {
                    "datasetId": "shared_data",
                    "projectId": "test-project",
                }
            }
        ]
    }
    mock_datasets.list_next.return_value = None

    mock_get = MagicMock()
    mock_datasets.get.return_value = mock_get
    mock_get.execute.return_value = {
        "datasetReference": {
            "datasetId": "shared_data",
            "projectId": "test-project",
        },
        "location": "US",
        "access": [
            {
                "role": "READER",
                "specialGroup": "allAuthenticatedUsers",
            },
        ],
    }

    mock_tables = MagicMock()
    mock_service.tables.return_value = mock_tables
    mock_tables_list = MagicMock()
    mock_tables.list.return_value = mock_tables_list
    mock_tables_list.execute.return_value = {"tables": []}
    mock_tables.list_next.return_value = None

    return mock_service


@pytest.fixture
def mock_gcp_bigquery_service_cmek():
    """Create a mock BigQuery service with CMEK encryption."""
    mock_service = MagicMock()

    mock_datasets = MagicMock()
    mock_service.datasets.return_value = mock_datasets

    mock_list = MagicMock()
    mock_datasets.list.return_value = mock_list
    mock_list.execute.return_value = {
        "datasets": [
            {
                "datasetReference": {
                    "datasetId": "encrypted_data",
                    "projectId": "test-project",
                }
            }
        ]
    }
    mock_datasets.list_next.return_value = None

    mock_get = MagicMock()
    mock_datasets.get.return_value = mock_get
    mock_get.execute.return_value = {
        "datasetReference": {
            "datasetId": "encrypted_data",
            "projectId": "test-project",
        },
        "location": "US",
        "defaultEncryptionConfiguration": {
            "kmsKeyName": "projects/test-project/locations/us/keyRings/my-ring/cryptoKeys/my-key",
        },
        "access": [
            {
                "role": "OWNER",
                "userByEmail": "admin@example.com",
            },
        ],
    }

    mock_tables = MagicMock()
    mock_service.tables.return_value = mock_tables
    mock_tables_list = MagicMock()
    mock_tables.list.return_value = mock_tables_list
    mock_tables_list.execute.return_value = {"tables": []}
    mock_tables.list_next.return_value = None

    return mock_service


@pytest.fixture
def mock_gcp_bigquery_service_with_tables():
    """Create a mock BigQuery service with tables."""
    mock_service = MagicMock()

    mock_datasets = MagicMock()
    mock_service.datasets.return_value = mock_datasets

    mock_list = MagicMock()
    mock_datasets.list.return_value = mock_list
    mock_list.execute.return_value = {
        "datasets": [
            {
                "datasetReference": {
                    "datasetId": "analytics_data",
                    "projectId": "test-project",
                }
            }
        ]
    }
    mock_datasets.list_next.return_value = None

    mock_get = MagicMock()
    mock_datasets.get.return_value = mock_get
    mock_get.execute.return_value = {
        "datasetReference": {
            "datasetId": "analytics_data",
            "projectId": "test-project",
        },
        "location": "US",
        "access": [],
    }

    # Mock tables
    mock_tables = MagicMock()
    mock_service.tables.return_value = mock_tables

    mock_tables_list = MagicMock()
    mock_tables.list.return_value = mock_tables_list
    mock_tables_list.execute.return_value = {
        "tables": [
            {
                "tableReference": {
                    "tableId": "events",
                    "datasetId": "analytics_data",
                    "projectId": "test-project",
                }
            }
        ]
    }
    mock_tables.list_next.return_value = None

    mock_tables_get = MagicMock()
    mock_tables.get.return_value = mock_tables_get
    mock_tables_get.execute.return_value = {
        "tableReference": {
            "tableId": "events",
            "datasetId": "analytics_data",
            "projectId": "test-project",
        },
        "type": "TABLE",
        "location": "US",
        "creationTime": "1704067200000",
        "numBytes": "1000000",
        "numRows": "10000",
        "schema": {
            "fields": [
                {"name": "event_id", "type": "STRING", "mode": "REQUIRED"},
                {"name": "timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
            ]
        },
    }

    return mock_service


@pytest.fixture
def mock_gcp_bigquery_service_partitioned():
    """Create a mock BigQuery service with partitioned table."""
    mock_service = MagicMock()

    mock_datasets = MagicMock()
    mock_service.datasets.return_value = mock_datasets

    mock_list = MagicMock()
    mock_datasets.list.return_value = mock_list
    mock_list.execute.return_value = {
        "datasets": [
            {
                "datasetReference": {
                    "datasetId": "analytics_data",
                    "projectId": "test-project",
                }
            }
        ]
    }
    mock_datasets.list_next.return_value = None

    mock_get = MagicMock()
    mock_datasets.get.return_value = mock_get
    mock_get.execute.return_value = {
        "datasetReference": {
            "datasetId": "analytics_data",
            "projectId": "test-project",
        },
        "location": "US",
        "access": [],
    }

    mock_tables = MagicMock()
    mock_service.tables.return_value = mock_tables

    mock_tables_list = MagicMock()
    mock_tables.list.return_value = mock_tables_list
    mock_tables_list.execute.return_value = {
        "tables": [
            {
                "tableReference": {
                    "tableId": "events_partitioned",
                    "datasetId": "analytics_data",
                    "projectId": "test-project",
                }
            }
        ]
    }
    mock_tables.list_next.return_value = None

    mock_tables_get = MagicMock()
    mock_tables.get.return_value = mock_tables_get
    mock_tables_get.execute.return_value = {
        "tableReference": {
            "tableId": "events_partitioned",
            "datasetId": "analytics_data",
            "projectId": "test-project",
        },
        "type": "TABLE",
        "location": "US",
        "timePartitioning": {
            "type": "DAY",
            "field": "event_date",
            "expirationMs": "7776000000",  # 90 days
        },
        "clustering": {
            "fields": ["user_id", "event_type"],
        },
        "requirePartitionFilter": True,
    }

    return mock_service


@pytest.fixture
def mock_gcp_bigquery_service_external():
    """Create a mock BigQuery service with external table."""
    mock_service = MagicMock()

    mock_datasets = MagicMock()
    mock_service.datasets.return_value = mock_datasets

    mock_list = MagicMock()
    mock_datasets.list.return_value = mock_list
    mock_list.execute.return_value = {
        "datasets": [
            {
                "datasetReference": {
                    "datasetId": "external_data",
                    "projectId": "test-project",
                }
            }
        ]
    }
    mock_datasets.list_next.return_value = None

    mock_get = MagicMock()
    mock_datasets.get.return_value = mock_get
    mock_get.execute.return_value = {
        "datasetReference": {
            "datasetId": "external_data",
            "projectId": "test-project",
        },
        "location": "US",
        "access": [],
    }

    mock_tables = MagicMock()
    mock_service.tables.return_value = mock_tables

    mock_tables_list = MagicMock()
    mock_tables.list.return_value = mock_tables_list
    mock_tables_list.execute.return_value = {
        "tables": [
            {
                "tableReference": {
                    "tableId": "external_events",
                    "datasetId": "external_data",
                    "projectId": "test-project",
                }
            }
        ]
    }
    mock_tables.list_next.return_value = None

    mock_tables_get = MagicMock()
    mock_tables.get.return_value = mock_tables_get
    mock_tables_get.execute.return_value = {
        "tableReference": {
            "tableId": "external_events",
            "datasetId": "external_data",
            "projectId": "test-project",
        },
        "type": "EXTERNAL",
        "location": "US",
        "externalDataConfiguration": {
            "sourceUris": ["gs://my-bucket/data/*.parquet"],
            "sourceFormat": "PARQUET",
        },
    }

    return mock_service


@pytest.fixture
def mock_gcp_bigquery_service_empty():
    """Create a mock BigQuery service with no datasets."""
    mock_service = MagicMock()

    mock_datasets = MagicMock()
    mock_service.datasets.return_value = mock_datasets

    mock_list = MagicMock()
    mock_datasets.list.return_value = mock_list
    mock_list.execute.return_value = {"datasets": []}
    mock_datasets.list_next.return_value = None

    return mock_service


@pytest.fixture
def mock_gcp_bigquery_service_error():
    """Create a mock BigQuery service that raises an error."""
    mock_service = MagicMock()

    mock_datasets = MagicMock()
    mock_service.datasets.return_value = mock_datasets

    mock_list = MagicMock()
    mock_datasets.list.return_value = mock_list
    mock_list.execute.side_effect = Exception("API Error: Access Denied")

    return mock_service
