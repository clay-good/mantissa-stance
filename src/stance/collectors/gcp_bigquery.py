"""
GCP BigQuery collector for Mantissa Stance.

Collects BigQuery datasets, tables, and their security configurations
for security posture assessment.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)

logger = logging.getLogger(__name__)

# Optional GCP imports - BigQuery uses the discovery-based API client
try:
    from googleapiclient import discovery
    from google.oauth2 import service_account
    import google.auth

    GCP_BIGQUERY_AVAILABLE = True
except ImportError:
    GCP_BIGQUERY_AVAILABLE = False


class GCPBigQueryCollector(BaseCollector):
    """
    Collects GCP BigQuery resources and configuration.

    Gathers BigQuery datasets and tables with their security settings including:
    - Access control lists (dataset and table level)
    - Encryption configuration (CMEK vs Google-managed)
    - Default table expiration settings
    - Labels and metadata
    - Public dataset detection

    All API calls are read-only.
    """

    collector_name = "gcp_bigquery"
    resource_types = [
        "gcp_bigquery_dataset",
        "gcp_bigquery_table",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP BigQuery collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            **kwargs: Additional configuration.
        """
        if not GCP_BIGQUERY_AVAILABLE:
            raise ImportError(
                "google-api-python-client and google-auth are required for "
                "GCP BigQuery collector. Install with: "
                "pip install google-api-python-client google-auth"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._service: Any | None = None

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    def _get_service(self) -> Any:
        """Get or create the BigQuery API service."""
        if self._service is None:
            if self._credentials:
                self._service = discovery.build(
                    "bigquery",
                    "v2",
                    credentials=self._credentials,
                    cache_discovery=False,
                )
            else:
                # Use Application Default Credentials
                credentials, _ = google.auth.default()
                self._service = discovery.build(
                    "bigquery",
                    "v2",
                    credentials=credentials,
                    cache_discovery=False,
                )
        return self._service

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all BigQuery resources.

        Returns:
            Collection of BigQuery assets
        """
        assets: list[Asset] = []

        # Collect datasets
        try:
            assets.extend(self._collect_datasets())
        except Exception as e:
            logger.warning(f"Failed to collect BigQuery datasets: {e}")

        return AssetCollection(assets)

    def _collect_datasets(self) -> list[Asset]:
        """Collect BigQuery datasets and their tables."""
        service = self._get_service()
        assets: list[Asset] = []
        now = self._now()

        try:
            # List all datasets in the project
            request = service.datasets().list(projectId=self._project_id)

            while request is not None:
                response = request.execute()
                datasets = response.get("datasets", [])

                for dataset_ref in datasets:
                    dataset_id = dataset_ref.get("datasetReference", {}).get(
                        "datasetId", ""
                    )

                    if not dataset_id:
                        continue

                    # Get detailed dataset information
                    try:
                        dataset = service.datasets().get(
                            projectId=self._project_id,
                            datasetId=dataset_id
                        ).execute()

                        dataset_asset = self._process_dataset(dataset, now)
                        if dataset_asset:
                            assets.append(dataset_asset)

                        # Collect tables in this dataset
                        table_assets = self._collect_tables(dataset_id, now)
                        assets.extend(table_assets)

                    except Exception as e:
                        logger.warning(
                            f"Failed to get dataset {dataset_id}: {e}"
                        )

                # Handle pagination
                request = service.datasets().list_next(
                    previous_request=request,
                    previous_response=response
                )

        except Exception as e:
            logger.error(f"Error listing BigQuery datasets: {e}")
            raise

        return assets

    def _process_dataset(
        self, dataset: dict[str, Any], now: datetime
    ) -> Asset | None:
        """Process a dataset and create an Asset."""
        dataset_ref = dataset.get("datasetReference", {})
        dataset_id = dataset_ref.get("datasetId", "")
        project_id = dataset_ref.get("projectId", self._project_id)

        if not dataset_id:
            return None

        # Build resource ID
        resource_id = f"projects/{project_id}/datasets/{dataset_id}"

        # Extract access controls
        access_entries = dataset.get("access", [])
        access_list = []
        is_public = False
        allows_all_authenticated = False

        for entry in access_entries:
            role = entry.get("role", "")
            entity_type = None
            entity_id = None

            # Determine entity type and ID
            if "userByEmail" in entry:
                entity_type = "user"
                entity_id = entry["userByEmail"]
            elif "groupByEmail" in entry:
                entity_type = "group"
                entity_id = entry["groupByEmail"]
            elif "domain" in entry:
                entity_type = "domain"
                entity_id = entry["domain"]
            elif "specialGroup" in entry:
                entity_type = "specialGroup"
                entity_id = entry["specialGroup"]
                # Check for public access
                if entry["specialGroup"] == "allUsers":
                    is_public = True
                elif entry["specialGroup"] == "allAuthenticatedUsers":
                    allows_all_authenticated = True
            elif "iamMember" in entry:
                entity_type = "iamMember"
                entity_id = entry["iamMember"]
                # Check for public IAM member
                if entry["iamMember"] == "allUsers":
                    is_public = True
                elif entry["iamMember"] == "allAuthenticatedUsers":
                    allows_all_authenticated = True
            elif "view" in entry:
                entity_type = "view"
                view_ref = entry["view"]
                entity_id = (
                    f"{view_ref.get('projectId', '')}."
                    f"{view_ref.get('datasetId', '')}."
                    f"{view_ref.get('tableId', '')}"
                )
            elif "routine" in entry:
                entity_type = "routine"
                routine_ref = entry["routine"]
                entity_id = (
                    f"{routine_ref.get('projectId', '')}."
                    f"{routine_ref.get('datasetId', '')}."
                    f"{routine_ref.get('routineId', '')}"
                )
            elif "dataset" in entry:
                entity_type = "dataset"
                ds_ref = entry["dataset"].get("dataset", {})
                entity_id = (
                    f"{ds_ref.get('projectId', '')}."
                    f"{ds_ref.get('datasetId', '')}"
                )

            access_list.append({
                "role": role,
                "entity_type": entity_type,
                "entity_id": entity_id,
            })

        # Default encryption configuration
        default_encryption = dataset.get("defaultEncryptionConfiguration", {})
        kms_key_name = default_encryption.get("kmsKeyName", "")
        uses_cmek = bool(kms_key_name)

        # Default table expiration
        default_table_expiration_ms = dataset.get(
            "defaultTableExpirationMs", None
        )
        if default_table_expiration_ms:
            default_table_expiration_days = (
                int(default_table_expiration_ms) / (1000 * 60 * 60 * 24)
            )
        else:
            default_table_expiration_days = None

        # Default partition expiration
        default_partition_expiration_ms = dataset.get(
            "defaultPartitionExpirationMs", None
        )
        if default_partition_expiration_ms:
            default_partition_expiration_days = (
                int(default_partition_expiration_ms) / (1000 * 60 * 60 * 24)
            )
        else:
            default_partition_expiration_days = None

        # Labels
        labels = dataset.get("labels", {})

        # Location
        location = dataset.get("location", "")

        # Storage billing model
        storage_billing_model = dataset.get("storageBillingModel", "")

        # Max time travel hours (data retention for time travel)
        max_time_travel_hours = dataset.get("maxTimeTravelHours", "")

        # Is case insensitive
        is_case_insensitive = dataset.get("isCaseInsensitive", False)

        # Default collation
        default_collation = dataset.get("defaultCollation", "")

        raw_config = {
            "dataset_id": dataset_id,
            "project_id": project_id,
            "location": location,
            "description": dataset.get("description", ""),
            "friendly_name": dataset.get("friendlyName", ""),
            # Access controls
            "access": access_list,
            "is_public": is_public,
            "allows_all_authenticated_users": allows_all_authenticated,
            # Encryption
            "uses_cmek": uses_cmek,
            "kms_key_name": kms_key_name,
            # Expiration settings
            "default_table_expiration_days": default_table_expiration_days,
            "default_partition_expiration_days": default_partition_expiration_days,
            # Storage settings
            "storage_billing_model": storage_billing_model,
            "max_time_travel_hours": max_time_travel_hours,
            # Other settings
            "is_case_insensitive": is_case_insensitive,
            "default_collation": default_collation,
            # Labels
            "labels": labels,
            # Self link
            "self_link": dataset.get("selfLink", ""),
            # Etag for versioning
            "etag": dataset.get("etag", ""),
        }

        # Determine network exposure
        # BigQuery datasets are accessed via API, but public datasets are internet-facing
        if is_public:
            network_exposure = NETWORK_EXPOSURE_INTERNET
        elif allows_all_authenticated:
            # All authenticated GCP users can access - still exposed
            network_exposure = NETWORK_EXPOSURE_INTERNET
        else:
            network_exposure = NETWORK_EXPOSURE_INTERNAL

        # Parse creation time
        created_at = None
        creation_time = dataset.get("creationTime", "")
        if creation_time:
            try:
                # BigQuery uses milliseconds since epoch
                created_at = datetime.fromtimestamp(
                    int(creation_time) / 1000, tz=timezone.utc
                )
            except (ValueError, TypeError):
                pass

        return Asset(
            id=resource_id,
            cloud_provider="gcp",
            account_id=self._project_id,
            region=location,
            resource_type="gcp_bigquery_dataset",
            name=dataset_id,
            tags=labels,
            network_exposure=network_exposure,
            created_at=created_at,
            last_seen=now,
            raw_config=raw_config,
        )

    def _collect_tables(
        self, dataset_id: str, now: datetime
    ) -> list[Asset]:
        """Collect tables in a dataset."""
        service = self._get_service()
        assets: list[Asset] = []

        try:
            # List all tables in the dataset
            request = service.tables().list(
                projectId=self._project_id,
                datasetId=dataset_id
            )

            while request is not None:
                response = request.execute()
                tables = response.get("tables", [])

                for table_ref in tables:
                    table_id = table_ref.get("tableReference", {}).get(
                        "tableId", ""
                    )

                    if not table_id:
                        continue

                    # Get detailed table information
                    try:
                        table = service.tables().get(
                            projectId=self._project_id,
                            datasetId=dataset_id,
                            tableId=table_id
                        ).execute()

                        table_asset = self._process_table(
                            table, dataset_id, now
                        )
                        if table_asset:
                            assets.append(table_asset)

                    except Exception as e:
                        logger.debug(
                            f"Failed to get table {dataset_id}.{table_id}: {e}"
                        )

                # Handle pagination
                request = service.tables().list_next(
                    previous_request=request,
                    previous_response=response
                )

        except Exception as e:
            logger.debug(f"Error listing tables in {dataset_id}: {e}")

        return assets

    def _process_table(
        self,
        table: dict[str, Any],
        dataset_id: str,
        now: datetime,
    ) -> Asset | None:
        """Process a table and create an Asset."""
        table_ref = table.get("tableReference", {})
        table_id = table_ref.get("tableId", "")
        project_id = table_ref.get("projectId", self._project_id)

        if not table_id:
            return None

        # Build resource ID
        resource_id = (
            f"projects/{project_id}/datasets/{dataset_id}/tables/{table_id}"
        )

        # Table type (TABLE, VIEW, MATERIALIZED_VIEW, EXTERNAL, SNAPSHOT)
        table_type = table.get("type", "TABLE")

        # Encryption configuration
        encryption_config = table.get("encryptionConfiguration", {})
        kms_key_name = encryption_config.get("kmsKeyName", "")
        uses_cmek = bool(kms_key_name)

        # Time partitioning
        time_partitioning = table.get("timePartitioning", {})
        partition_type = time_partitioning.get("type", "")
        partition_field = time_partitioning.get("field", "")
        partition_expiration_ms = time_partitioning.get("expirationMs", "")

        # Range partitioning
        range_partitioning = table.get("rangePartitioning", {})

        # Clustering
        clustering = table.get("clustering", {})
        clustering_fields = clustering.get("fields", [])

        # Schema information
        schema = table.get("schema", {})
        schema_fields = schema.get("fields", [])
        num_columns = len(schema_fields)

        # Size information
        num_bytes = table.get("numBytes", "0")
        num_rows = table.get("numRows", "0")
        num_long_term_bytes = table.get("numLongTermBytes", "0")

        # Expiration time
        expiration_time = table.get("expirationTime", "")

        # Labels
        labels = table.get("labels", {})

        # Location
        location = table.get("location", "")

        # Require partition filter (important for cost control)
        require_partition_filter = table.get("requirePartitionFilter", False)

        # External data configuration (if external table)
        external_data_config = table.get("externalDataConfiguration", {})
        is_external = bool(external_data_config)
        source_uris = external_data_config.get("sourceUris", [])
        source_format = external_data_config.get("sourceFormat", "")

        # Materialized view config
        materialized_view = table.get("materializedView", {})
        is_materialized_view = bool(materialized_view)
        mv_query = materialized_view.get("query", "")
        mv_enable_refresh = materialized_view.get("enableRefresh", False)
        mv_refresh_interval_ms = materialized_view.get(
            "refreshIntervalMs", ""
        )

        # View definition (if view)
        view = table.get("view", {})
        is_view = bool(view)
        view_query = view.get("query", "")
        use_legacy_sql = view.get("useLegacySql", False)

        # Snapshot definition (if snapshot)
        snapshot_definition = table.get("snapshotDefinition", {})
        is_snapshot = bool(snapshot_definition)
        snapshot_time = snapshot_definition.get("snapshotTime", "")
        base_table_ref = snapshot_definition.get("baseTableReference", {})

        raw_config = {
            "table_id": table_id,
            "dataset_id": dataset_id,
            "project_id": project_id,
            "location": location,
            "type": table_type,
            "description": table.get("description", ""),
            "friendly_name": table.get("friendlyName", ""),
            # Encryption
            "uses_cmek": uses_cmek,
            "kms_key_name": kms_key_name,
            # Partitioning
            "time_partitioning": {
                "type": partition_type,
                "field": partition_field,
                "expiration_ms": partition_expiration_ms,
            } if time_partitioning else None,
            "range_partitioning": range_partitioning if range_partitioning else None,
            "require_partition_filter": require_partition_filter,
            # Clustering
            "clustering_fields": clustering_fields,
            # Schema
            "num_columns": num_columns,
            "schema_fields": [
                {
                    "name": f.get("name", ""),
                    "type": f.get("type", ""),
                    "mode": f.get("mode", ""),
                    "description": f.get("description", ""),
                }
                for f in schema_fields[:50]  # Limit to first 50 fields
            ],
            # Size
            "num_bytes": num_bytes,
            "num_rows": num_rows,
            "num_long_term_bytes": num_long_term_bytes,
            # Expiration
            "expiration_time": expiration_time,
            # External table
            "is_external": is_external,
            "source_uris": source_uris[:10],  # Limit URIs
            "source_format": source_format,
            # View
            "is_view": is_view,
            "view_query": view_query[:1000] if view_query else "",  # Truncate
            "use_legacy_sql": use_legacy_sql,
            # Materialized view
            "is_materialized_view": is_materialized_view,
            "mv_enable_refresh": mv_enable_refresh,
            "mv_refresh_interval_ms": mv_refresh_interval_ms,
            # Snapshot
            "is_snapshot": is_snapshot,
            "snapshot_time": snapshot_time,
            "base_table": (
                f"{base_table_ref.get('projectId', '')}."
                f"{base_table_ref.get('datasetId', '')}."
                f"{base_table_ref.get('tableId', '')}"
            ) if base_table_ref else "",
            # Labels
            "labels": labels,
            # Self link
            "self_link": table.get("selfLink", ""),
            # Etag
            "etag": table.get("etag", ""),
        }

        # Tables inherit access from dataset, so we mark as internal
        # unless the table has specific public sharing (rare)
        network_exposure = NETWORK_EXPOSURE_INTERNAL

        # Parse creation time
        created_at = None
        creation_time = table.get("creationTime", "")
        if creation_time:
            try:
                created_at = datetime.fromtimestamp(
                    int(creation_time) / 1000, tz=timezone.utc
                )
            except (ValueError, TypeError):
                pass

        return Asset(
            id=resource_id,
            cloud_provider="gcp",
            account_id=self._project_id,
            region=location,
            resource_type="gcp_bigquery_table",
            name=f"{dataset_id}.{table_id}",
            tags=labels,
            network_exposure=network_exposure,
            created_at=created_at,
            last_seen=now,
            raw_config=raw_config,
        )
