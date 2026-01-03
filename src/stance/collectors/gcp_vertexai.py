"""
GCP Vertex AI collector for Mantissa Stance.

Collects Vertex AI endpoints, models, notebooks, pipelines, datasets,
and feature stores for AI/ML security posture assessment.
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

# Optional GCP AI Platform imports
try:
    from google.cloud import aiplatform_v1
    from google.cloud.aiplatform_v1.types import (
        Endpoint,
        Model,
        NotebookRuntimeTemplate,
    )

    GCP_AIPLATFORM_AVAILABLE = True
except ImportError:
    GCP_AIPLATFORM_AVAILABLE = False


class GCPVertexAICollector(BaseCollector):
    """
    Collects GCP Vertex AI resources and configuration.

    Gathers Vertex AI endpoints, models, notebooks, training pipelines,
    datasets, and feature stores with their security configurations.
    All API calls are read-only.
    """

    collector_name = "gcp_vertexai"
    resource_types = [
        "gcp_vertexai_endpoint",
        "gcp_vertexai_model",
        "gcp_vertexai_notebook",
        "gcp_vertexai_training_pipeline",
        "gcp_vertexai_dataset",
        "gcp_vertexai_featurestore",
    ]

    def __init__(
        self,
        project_id: str,
        location: str = "us-central1",
        credentials: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP Vertex AI collector.

        Args:
            project_id: GCP project ID to collect from.
            location: GCP region for Vertex AI resources.
            credentials: Optional google-auth credentials object.
            **kwargs: Additional configuration.
        """
        if not GCP_AIPLATFORM_AVAILABLE:
            raise ImportError(
                "google-cloud-aiplatform is required for Vertex AI collector. "
                "Install with: pip install google-cloud-aiplatform"
            )

        self._project_id = project_id
        self._location = location
        self._credentials = credentials
        self._clients: dict[str, Any] = {}
        self._parent = f"projects/{project_id}/locations/{location}"

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    @property
    def location(self) -> str:
        """Get the GCP location/region."""
        return self._location

    def _get_endpoint_client(self) -> aiplatform_v1.EndpointServiceClient:
        """Get or create Endpoint service client."""
        if "endpoints" not in self._clients:
            client_options = {"api_endpoint": f"{self._location}-aiplatform.googleapis.com"}
            self._clients["endpoints"] = aiplatform_v1.EndpointServiceClient(
                credentials=self._credentials,
                client_options=client_options,
            )
        return self._clients["endpoints"]

    def _get_model_client(self) -> aiplatform_v1.ModelServiceClient:
        """Get or create Model service client."""
        if "models" not in self._clients:
            client_options = {"api_endpoint": f"{self._location}-aiplatform.googleapis.com"}
            self._clients["models"] = aiplatform_v1.ModelServiceClient(
                credentials=self._credentials,
                client_options=client_options,
            )
        return self._clients["models"]

    def _get_notebook_client(self) -> aiplatform_v1.NotebookServiceClient:
        """Get or create Notebook service client."""
        if "notebooks" not in self._clients:
            client_options = {"api_endpoint": f"{self._location}-aiplatform.googleapis.com"}
            self._clients["notebooks"] = aiplatform_v1.NotebookServiceClient(
                credentials=self._credentials,
                client_options=client_options,
            )
        return self._clients["notebooks"]

    def _get_pipeline_client(self) -> aiplatform_v1.PipelineServiceClient:
        """Get or create Pipeline service client."""
        if "pipelines" not in self._clients:
            client_options = {"api_endpoint": f"{self._location}-aiplatform.googleapis.com"}
            self._clients["pipelines"] = aiplatform_v1.PipelineServiceClient(
                credentials=self._credentials,
                client_options=client_options,
            )
        return self._clients["pipelines"]

    def _get_dataset_client(self) -> aiplatform_v1.DatasetServiceClient:
        """Get or create Dataset service client."""
        if "datasets" not in self._clients:
            client_options = {"api_endpoint": f"{self._location}-aiplatform.googleapis.com"}
            self._clients["datasets"] = aiplatform_v1.DatasetServiceClient(
                credentials=self._credentials,
                client_options=client_options,
            )
        return self._clients["datasets"]

    def _get_featurestore_client(self) -> aiplatform_v1.FeaturestoreServiceClient:
        """Get or create Featurestore service client."""
        if "featurestores" not in self._clients:
            client_options = {"api_endpoint": f"{self._location}-aiplatform.googleapis.com"}
            self._clients["featurestores"] = aiplatform_v1.FeaturestoreServiceClient(
                credentials=self._credentials,
                client_options=client_options,
            )
        return self._clients["featurestores"]

    def collect(self) -> AssetCollection:
        """
        Collect all Vertex AI resources.

        Returns:
            Collection of Vertex AI assets
        """
        assets: list[Asset] = []

        # Collect endpoints
        try:
            assets.extend(self._collect_endpoints())
        except Exception as e:
            logger.warning(f"Failed to collect Vertex AI endpoints: {e}")

        # Collect models
        try:
            assets.extend(self._collect_models())
        except Exception as e:
            logger.warning(f"Failed to collect Vertex AI models: {e}")

        # Collect notebooks
        try:
            assets.extend(self._collect_notebooks())
        except Exception as e:
            logger.warning(f"Failed to collect Vertex AI notebooks: {e}")

        # Collect training pipelines
        try:
            assets.extend(self._collect_training_pipelines())
        except Exception as e:
            logger.warning(f"Failed to collect Vertex AI training pipelines: {e}")

        # Collect datasets
        try:
            assets.extend(self._collect_datasets())
        except Exception as e:
            logger.warning(f"Failed to collect Vertex AI datasets: {e}")

        # Collect feature stores
        try:
            assets.extend(self._collect_featurestores())
        except Exception as e:
            logger.warning(f"Failed to collect Vertex AI feature stores: {e}")

        return AssetCollection(assets)

    def _collect_endpoints(self) -> list[Asset]:
        """Collect Vertex AI prediction endpoints."""
        client = self._get_endpoint_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = aiplatform_v1.ListEndpointsRequest(parent=self._parent)
            endpoints = list(client.list_endpoints(request=request))
        except Exception as e:
            logger.warning(f"Failed to list endpoints: {e}")
            return assets

        for endpoint in endpoints:
            endpoint_name = endpoint.name
            display_name = endpoint.display_name

            # Encryption spec
            encryption_spec = endpoint.encryption_spec
            has_cmek = bool(encryption_spec and encryption_spec.kms_key_name)

            # Network configuration
            network = endpoint.network
            has_private_endpoint = bool(network)

            # Deployed models
            deployed_models = endpoint.deployed_models

            # Traffic split
            traffic_split = dict(endpoint.traffic_split) if endpoint.traffic_split else {}

            raw_config: dict[str, Any] = {
                "name": endpoint_name,
                "display_name": display_name,
                "description": endpoint.description,
                "create_time": str(endpoint.create_time),
                "update_time": str(endpoint.update_time),
                # Security configurations
                "encryption_spec": {
                    "kms_key_name": encryption_spec.kms_key_name if encryption_spec else None,
                },
                "has_cmek": has_cmek,
                # Network configuration
                "network": network,
                "has_private_endpoint": has_private_endpoint,
                # Deployed models
                "deployed_models": [
                    {
                        "id": dm.id,
                        "model": dm.model,
                        "display_name": dm.display_name,
                        "dedicated_resources": {
                            "machine_type": dm.dedicated_resources.machine_spec.machine_type if dm.dedicated_resources else None,
                            "min_replica_count": dm.dedicated_resources.min_replica_count if dm.dedicated_resources else None,
                            "max_replica_count": dm.dedicated_resources.max_replica_count if dm.dedicated_resources else None,
                        } if dm.dedicated_resources else None,
                        "automatic_resources": {
                            "min_replica_count": dm.automatic_resources.min_replica_count if dm.automatic_resources else None,
                            "max_replica_count": dm.automatic_resources.max_replica_count if dm.automatic_resources else None,
                        } if dm.automatic_resources else None,
                        "enable_access_logging": dm.enable_access_logging,
                        "enable_container_logging": dm.enable_container_logging,
                    }
                    for dm in deployed_models
                ],
                "deployed_models_count": len(deployed_models),
                "traffic_split": traffic_split,
                # Labels
                "labels": dict(endpoint.labels) if endpoint.labels else {},
            }

            network_exposure = NETWORK_EXPOSURE_INTERNAL if has_private_endpoint else NETWORK_EXPOSURE_INTERNET

            asset = Asset(
                asset_id=endpoint_name,
                asset_type="gcp_vertexai_endpoint",
                name=display_name,
                region=self._location,
                account_id=self._project_id,
                tags=dict(endpoint.labels) if endpoint.labels else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=network_exposure,
            )
            assets.append(asset)

        return assets

    def _collect_models(self) -> list[Asset]:
        """Collect Vertex AI models."""
        client = self._get_model_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = aiplatform_v1.ListModelsRequest(parent=self._parent)
            models = list(client.list_models(request=request))
        except Exception as e:
            logger.warning(f"Failed to list models: {e}")
            return assets

        for model in models:
            model_name = model.name
            display_name = model.display_name

            # Encryption spec
            encryption_spec = model.encryption_spec
            has_cmek = bool(encryption_spec and encryption_spec.kms_key_name)

            # Container spec
            container_spec = model.container_spec
            container_image = container_spec.image_uri if container_spec else None

            # Artifact URI
            artifact_uri = model.artifact_uri

            # Supported deployment resources
            supported_resources = model.supported_deployment_resources_types

            raw_config: dict[str, Any] = {
                "name": model_name,
                "display_name": display_name,
                "description": model.description,
                "version_id": model.version_id,
                "version_aliases": list(model.version_aliases) if model.version_aliases else [],
                "create_time": str(model.create_time),
                "update_time": str(model.update_time),
                # Artifact
                "artifact_uri": artifact_uri,
                # Container
                "container_spec": {
                    "image_uri": container_image,
                    "command": list(container_spec.command) if container_spec and container_spec.command else [],
                    "args": list(container_spec.args) if container_spec and container_spec.args else [],
                    "env": [{"name": e.name} for e in container_spec.env] if container_spec and container_spec.env else [],
                    "ports": [p.container_port for p in container_spec.ports] if container_spec and container_spec.ports else [],
                } if container_spec else None,
                # Training info
                "training_pipeline": model.training_pipeline,
                "metadata_schema_uri": model.metadata_schema_uri,
                # Encryption
                "encryption_spec": {
                    "kms_key_name": encryption_spec.kms_key_name if encryption_spec else None,
                },
                "has_cmek": has_cmek,
                # Deployment resources
                "supported_deployment_resources_types": [str(r) for r in supported_resources] if supported_resources else [],
                # Labels
                "labels": dict(model.labels) if model.labels else {},
            }

            asset = Asset(
                asset_id=model_name,
                asset_type="gcp_vertexai_model",
                name=display_name,
                region=self._location,
                account_id=self._project_id,
                tags=dict(model.labels) if model.labels else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_notebooks(self) -> list[Asset]:
        """Collect Vertex AI Workbench notebooks (notebook runtime templates)."""
        client = self._get_notebook_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = aiplatform_v1.ListNotebookRuntimeTemplatesRequest(parent=self._parent)
            templates = list(client.list_notebook_runtime_templates(request=request))
        except Exception as e:
            logger.warning(f"Failed to list notebook runtime templates: {e}")
            return assets

        for template in templates:
            template_name = template.name
            display_name = template.display_name

            # Machine spec
            machine_spec = template.machine_spec
            machine_type = machine_spec.machine_type if machine_spec else None

            # Network spec
            network_spec = template.network_spec
            network = network_spec.network if network_spec else None
            subnetwork = network_spec.subnetwork if network_spec else None
            enable_internet_access = network_spec.enable_internet_access if network_spec else True

            # Data persistent disk spec
            data_disk_spec = template.data_persistent_disk_spec
            disk_type = data_disk_spec.disk_type if data_disk_spec else None
            disk_size_gb = data_disk_spec.disk_size_gb if data_disk_spec else None

            # Encryption spec
            encryption_spec = template.encryption_spec
            has_cmek = bool(encryption_spec and encryption_spec.kms_key_name)

            raw_config: dict[str, Any] = {
                "name": template_name,
                "display_name": display_name,
                "description": template.description,
                "is_default": template.is_default,
                "create_time": str(template.create_time),
                "update_time": str(template.update_time),
                # Machine configuration
                "machine_spec": {
                    "machine_type": machine_type,
                    "accelerator_type": str(machine_spec.accelerator_type) if machine_spec else None,
                    "accelerator_count": machine_spec.accelerator_count if machine_spec else 0,
                },
                # Network configuration
                "network_spec": {
                    "network": network,
                    "subnetwork": subnetwork,
                    "enable_internet_access": enable_internet_access,
                },
                "has_internet_access": enable_internet_access,
                "in_vpc": bool(network or subnetwork),
                # Disk configuration
                "data_persistent_disk_spec": {
                    "disk_type": disk_type,
                    "disk_size_gb": disk_size_gb,
                },
                # Encryption
                "encryption_spec": {
                    "kms_key_name": encryption_spec.kms_key_name if encryption_spec else None,
                },
                "has_cmek": has_cmek,
                # Service account
                "service_account": template.service_account,
                # Idle shutdown config
                "idle_shutdown_config": {
                    "idle_timeout": str(template.idle_shutdown_config.idle_timeout) if template.idle_shutdown_config else None,
                } if template.idle_shutdown_config else None,
                # Labels
                "labels": dict(template.labels) if template.labels else {},
            }

            network_exposure = NETWORK_EXPOSURE_INTERNET if enable_internet_access else NETWORK_EXPOSURE_INTERNAL

            asset = Asset(
                asset_id=template_name,
                asset_type="gcp_vertexai_notebook",
                name=display_name,
                region=self._location,
                account_id=self._project_id,
                tags=dict(template.labels) if template.labels else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=network_exposure,
            )
            assets.append(asset)

        return assets

    def _collect_training_pipelines(self) -> list[Asset]:
        """Collect Vertex AI training pipelines."""
        client = self._get_pipeline_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = aiplatform_v1.ListTrainingPipelinesRequest(parent=self._parent)
            pipelines = list(client.list_training_pipelines(request=request))
        except Exception as e:
            logger.warning(f"Failed to list training pipelines: {e}")
            return assets

        for pipeline in pipelines:
            pipeline_name = pipeline.name
            display_name = pipeline.display_name

            # Encryption spec
            encryption_spec = pipeline.encryption_spec
            has_cmek = bool(encryption_spec and encryption_spec.kms_key_name)

            # Training task inputs (keys only for security)
            training_task_definition = pipeline.training_task_definition

            raw_config: dict[str, Any] = {
                "name": pipeline_name,
                "display_name": display_name,
                "state": str(pipeline.state),
                "create_time": str(pipeline.create_time),
                "start_time": str(pipeline.start_time) if pipeline.start_time else None,
                "end_time": str(pipeline.end_time) if pipeline.end_time else None,
                "update_time": str(pipeline.update_time),
                # Training task
                "training_task_definition": training_task_definition,
                # Input data config
                "input_data_config": {
                    "dataset_id": pipeline.input_data_config.dataset_id if pipeline.input_data_config else None,
                    "gcs_destination": {
                        "output_uri_prefix": pipeline.input_data_config.gcs_destination.output_uri_prefix
                    } if pipeline.input_data_config and pipeline.input_data_config.gcs_destination else None,
                } if pipeline.input_data_config else None,
                # Model to upload
                "model_to_upload": {
                    "display_name": pipeline.model_to_upload.display_name if pipeline.model_to_upload else None,
                } if pipeline.model_to_upload else None,
                # Encryption
                "encryption_spec": {
                    "kms_key_name": encryption_spec.kms_key_name if encryption_spec else None,
                },
                "has_cmek": has_cmek,
                # Error
                "error": {
                    "code": pipeline.error.code if pipeline.error else None,
                    "message": pipeline.error.message if pipeline.error else None,
                } if pipeline.error else None,
                # Labels
                "labels": dict(pipeline.labels) if pipeline.labels else {},
            }

            asset = Asset(
                asset_id=pipeline_name,
                asset_type="gcp_vertexai_training_pipeline",
                name=display_name,
                region=self._location,
                account_id=self._project_id,
                tags=dict(pipeline.labels) if pipeline.labels else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_datasets(self) -> list[Asset]:
        """Collect Vertex AI datasets."""
        client = self._get_dataset_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = aiplatform_v1.ListDatasetsRequest(parent=self._parent)
            datasets = list(client.list_datasets(request=request))
        except Exception as e:
            logger.warning(f"Failed to list datasets: {e}")
            return assets

        for dataset in datasets:
            dataset_name = dataset.name
            display_name = dataset.display_name

            # Encryption spec
            encryption_spec = dataset.encryption_spec
            has_cmek = bool(encryption_spec and encryption_spec.kms_key_name)

            raw_config: dict[str, Any] = {
                "name": dataset_name,
                "display_name": display_name,
                "description": dataset.description,
                "metadata_schema_uri": dataset.metadata_schema_uri,
                "create_time": str(dataset.create_time),
                "update_time": str(dataset.update_time),
                # Data item count
                "data_item_count": dataset.data_item_count,
                # Encryption
                "encryption_spec": {
                    "kms_key_name": encryption_spec.kms_key_name if encryption_spec else None,
                },
                "has_cmek": has_cmek,
                # Labels
                "labels": dict(dataset.labels) if dataset.labels else {},
            }

            asset = Asset(
                asset_id=dataset_name,
                asset_type="gcp_vertexai_dataset",
                name=display_name,
                region=self._location,
                account_id=self._project_id,
                tags=dict(dataset.labels) if dataset.labels else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_featurestores(self) -> list[Asset]:
        """Collect Vertex AI Feature Store instances."""
        client = self._get_featurestore_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            request = aiplatform_v1.ListFeaturestoresRequest(parent=self._parent)
            featurestores = list(client.list_featurestores(request=request))
        except Exception as e:
            logger.warning(f"Failed to list feature stores: {e}")
            return assets

        for featurestore in featurestores:
            fs_name = featurestore.name
            # Extract display name from resource name
            display_name = fs_name.split("/")[-1]

            # Encryption spec
            encryption_spec = featurestore.encryption_spec
            has_cmek = bool(encryption_spec and encryption_spec.kms_key_name)

            # Online serving config
            online_serving_config = featurestore.online_serving_config

            raw_config: dict[str, Any] = {
                "name": fs_name,
                "display_name": display_name,
                "state": str(featurestore.state),
                "create_time": str(featurestore.create_time),
                "update_time": str(featurestore.update_time),
                # Online serving config
                "online_serving_config": {
                    "fixed_node_count": online_serving_config.fixed_node_count if online_serving_config else 0,
                    "scaling": {
                        "min_node_count": online_serving_config.scaling.min_node_count if online_serving_config and online_serving_config.scaling else 0,
                        "max_node_count": online_serving_config.scaling.max_node_count if online_serving_config and online_serving_config.scaling else 0,
                    } if online_serving_config else None,
                } if online_serving_config else None,
                # Encryption
                "encryption_spec": {
                    "kms_key_name": encryption_spec.kms_key_name if encryption_spec else None,
                },
                "has_cmek": has_cmek,
                # Labels
                "labels": dict(featurestore.labels) if featurestore.labels else {},
            }

            asset = Asset(
                asset_id=fs_name,
                asset_type="gcp_vertexai_featurestore",
                name=display_name,
                region=self._location,
                account_id=self._project_id,
                tags=dict(featurestore.labels) if featurestore.labels else {},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _now(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
