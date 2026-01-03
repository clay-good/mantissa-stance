"""
Collector framework for Mantissa Stance.

This package provides collectors for gathering cloud resource
configuration and security findings from multiple cloud providers
and Kubernetes clusters.

Supported Cloud Providers:
    - AWS (Amazon Web Services)
    - GCP (Google Cloud Platform) - requires google-cloud SDK
    - Azure (Microsoft Azure) - requires azure SDK
    - Kubernetes (Native) - requires kubernetes SDK

AWS Collectors:
    - IAMCollector: Collects IAM users, roles, policies, groups
    - S3Collector: Collects S3 bucket configurations
    - EC2Collector: Collects EC2 instances, security groups, VPCs
    - SecurityCollector: Collects findings from SecurityHub and Inspector
    - RDSCollector: Collects RDS instances, clusters, parameter groups
    - LambdaCollector: Collects Lambda functions, layers, event source mappings
    - DynamoDBCollector: Collects DynamoDB tables, backups, configurations
    - APIGatewayCollector: Collects API Gateway REST, HTTP, and WebSocket APIs
    - ECRCollector: Collects ECR repositories, images, and scan findings
    - EKSCollector: Collects EKS clusters, node groups, Fargate profiles, and add-ons
    - SageMakerCollector: Collects SageMaker notebooks, endpoints, models, training jobs
    - BedrockCollector: Collects Bedrock models, guardrails, agents, knowledge bases

GCP Collectors:
    - GCPVertexAICollector: Collects Vertex AI endpoints, models, notebooks, pipelines
    - GCPIAMCollector: Collects service accounts, IAM policies
    - GCPStorageCollector: Collects Cloud Storage buckets
    - GCPComputeCollector: Collects Compute Engine instances, firewalls
    - GCPSecurityCollector: Collects Security Command Center findings
    - GCPCloudSQLCollector: Collects Cloud SQL instances and configurations
    - GCPCloudFunctionsCollector: Collects Cloud Functions (1st and 2nd gen)
    - GCPBigQueryCollector: Collects BigQuery datasets and tables
    - GCPCloudRunCollector: Collects Cloud Run services and revisions
    - GCPArtifactRegistryCollector: Collects Artifact Registry repositories and images
    - GKECollector: Collects GKE clusters and node pools

Azure Collectors:
    - AzureMLCollector: Collects Azure ML workspaces, compute, endpoints, models
    - AzureIAMCollector: Collects role assignments, role definitions
    - AzureStorageCollector: Collects storage accounts, blob containers
    - AzureComputeCollector: Collects VMs, NSGs, VNets
    - AzureSecurityCollector: Collects Defender for Cloud findings
    - AzureSQLCollector: Collects SQL servers, databases, and security config
    - AzureFunctionsCollector: Collects Function Apps and their configurations
    - AzureCosmosDBCollector: Collects Cosmos DB accounts and configurations
    - AzureLogicAppsCollector: Collects Logic Apps (Workflows) and configurations
    - AzureContainerRegistryCollector: Collects ACR registries, images, and security config
    - AzureAKSCollector: Collects AKS clusters and node pools

Kubernetes Collectors:
    - K8sConfigCollector: Collects pods, deployments, services, daemonsets, statefulsets
    - K8sRBACCollector: Collects roles, cluster roles, role bindings, service accounts
    - K8sNetworkCollector: Collects network policies, ingress, secrets, limit ranges, quotas
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from stance.collectors.base import (
    BaseCollector,
    CollectorResult,
    CollectorRunner,
)
from stance.collectors.aws_iam import IAMCollector
from stance.collectors.aws_s3 import S3Collector
from stance.collectors.aws_ec2 import EC2Collector
from stance.collectors.aws_security import SecurityCollector
from stance.collectors.aws_rds import RDSCollector
from stance.collectors.aws_lambda import LambdaCollector
from stance.collectors.aws_dynamodb import DynamoDBCollector
from stance.collectors.aws_apigateway import APIGatewayCollector
from stance.collectors.aws_ecr import ECRCollector
from stance.collectors.aws_eks import EKSCollector
from stance.collectors.aws_sagemaker import SageMakerCollector
from stance.collectors.aws_bedrock import BedrockCollector

if TYPE_CHECKING:
    from stance.models import AssetCollection, FindingCollection

logger = logging.getLogger(__name__)

# Try to import GCP collectors (optional dependency)
try:
    from stance.collectors.gcp_iam import GCPIAMCollector
    from stance.collectors.gcp_storage import GCPStorageCollector
    from stance.collectors.gcp_compute import GCPComputeCollector
    from stance.collectors.gcp_security import GCPSecurityCollector
    from stance.collectors.gcp_sql import GCPCloudSQLCollector
    from stance.collectors.gcp_functions import GCPCloudFunctionsCollector
    from stance.collectors.gcp_bigquery import GCPBigQueryCollector
    from stance.collectors.gcp_cloudrun import GCPCloudRunCollector
    from stance.collectors.gcp_artifactregistry import GCPArtifactRegistryCollector
    from stance.collectors.gcp_gke import GKECollector
    from stance.collectors.gcp_vertexai import GCPVertexAICollector

    GCP_COLLECTORS_AVAILABLE = True
except ImportError:
    GCP_COLLECTORS_AVAILABLE = False
    GCPIAMCollector = None  # type: ignore
    GCPStorageCollector = None  # type: ignore
    GCPComputeCollector = None  # type: ignore
    GCPSecurityCollector = None  # type: ignore
    GCPCloudSQLCollector = None  # type: ignore
    GCPCloudFunctionsCollector = None  # type: ignore
    GCPBigQueryCollector = None  # type: ignore
    GCPCloudRunCollector = None  # type: ignore
    GCPArtifactRegistryCollector = None  # type: ignore
    GKECollector = None  # type: ignore
    GCPVertexAICollector = None  # type: ignore

# Try to import Azure collectors (optional dependency)
try:
    from stance.collectors.azure_iam import AzureIAMCollector
    from stance.collectors.azure_storage import AzureStorageCollector
    from stance.collectors.azure_compute import AzureComputeCollector
    from stance.collectors.azure_security import AzureSecurityCollector
    from stance.collectors.azure_sql import AzureSQLCollector
    from stance.collectors.azure_functions import AzureFunctionsCollector
    from stance.collectors.azure_cosmosdb import AzureCosmosDBCollector
    from stance.collectors.azure_logicapps import AzureLogicAppsCollector
    from stance.collectors.azure_containerregistry import AzureContainerRegistryCollector
    from stance.collectors.azure_aks import AzureAKSCollector
    from stance.collectors.azure_ml import AzureMLCollector

    AZURE_COLLECTORS_AVAILABLE = True
except ImportError:
    AZURE_COLLECTORS_AVAILABLE = False
    AzureIAMCollector = None  # type: ignore
    AzureStorageCollector = None  # type: ignore
    AzureComputeCollector = None  # type: ignore
    AzureSecurityCollector = None  # type: ignore
    AzureSQLCollector = None  # type: ignore
    AzureFunctionsCollector = None  # type: ignore
    AzureCosmosDBCollector = None  # type: ignore
    AzureLogicAppsCollector = None  # type: ignore
    AzureContainerRegistryCollector = None  # type: ignore
    AzureAKSCollector = None  # type: ignore
    AzureMLCollector = None  # type: ignore

# Try to import Kubernetes collectors (optional dependency)
try:
    from stance.collectors.k8s_config import K8sConfigCollector, K8sCollectorResult
    from stance.collectors.k8s_rbac import K8sRBACCollector, K8sRBACCollectorResult
    from stance.collectors.k8s_network import K8sNetworkCollector, K8sNetworkCollectorResult

    K8S_COLLECTORS_AVAILABLE = True
except ImportError:
    K8S_COLLECTORS_AVAILABLE = False
    K8sConfigCollector = None  # type: ignore
    K8sRBACCollector = None  # type: ignore
    K8sCollectorResult = None  # type: ignore
    K8sRBACCollectorResult = None  # type: ignore
    K8sNetworkCollector = None  # type: ignore
    K8sNetworkCollectorResult = None  # type: ignore

# Registry of collectors by cloud provider
COLLECTOR_REGISTRY: dict[str, dict[str, type[BaseCollector]]] = {
    "aws": {
        "aws_iam": IAMCollector,
        "aws_s3": S3Collector,
        "aws_ec2": EC2Collector,
        "aws_security": SecurityCollector,
        "aws_rds": RDSCollector,
        "aws_lambda": LambdaCollector,
        "aws_dynamodb": DynamoDBCollector,
        "aws_apigateway": APIGatewayCollector,
        "aws_ecr": ECRCollector,
        "aws_eks": EKSCollector,
        "aws_sagemaker": SageMakerCollector,
        "aws_bedrock": BedrockCollector,
    },
    "gcp": {},
    "azure": {},
    "kubernetes": {},
}

# Register GCP collectors if available
if GCP_COLLECTORS_AVAILABLE:
    COLLECTOR_REGISTRY["gcp"] = {
        "gcp_iam": GCPIAMCollector,
        "gcp_storage": GCPStorageCollector,
        "gcp_compute": GCPComputeCollector,
        "gcp_security": GCPSecurityCollector,
        "gcp_sql": GCPCloudSQLCollector,
        "gcp_functions": GCPCloudFunctionsCollector,
        "gcp_bigquery": GCPBigQueryCollector,
        "gcp_cloudrun": GCPCloudRunCollector,
        "gcp_artifactregistry": GCPArtifactRegistryCollector,
        "gcp_gke": GKECollector,
        "gcp_vertexai": GCPVertexAICollector,
    }

# Register Azure collectors if available
if AZURE_COLLECTORS_AVAILABLE:
    COLLECTOR_REGISTRY["azure"] = {
        "azure_iam": AzureIAMCollector,
        "azure_storage": AzureStorageCollector,
        "azure_compute": AzureComputeCollector,
        "azure_security": AzureSecurityCollector,
        "azure_sql": AzureSQLCollector,
        "azure_functions": AzureFunctionsCollector,
        "azure_cosmosdb": AzureCosmosDBCollector,
        "azure_logicapps": AzureLogicAppsCollector,
        "azure_containerregistry": AzureContainerRegistryCollector,
        "azure_aks": AzureAKSCollector,
        "azure_ml": AzureMLCollector,
    }

# Register Kubernetes collectors if available
if K8S_COLLECTORS_AVAILABLE:
    COLLECTOR_REGISTRY["kubernetes"] = {
        "k8s_config": K8sConfigCollector,
        "k8s_rbac": K8sRBACCollector,
        "k8s_network": K8sNetworkCollector,
    }

__all__ = [
    # Base classes
    "BaseCollector",
    "CollectorResult",
    "CollectorRunner",
    # AWS Collectors
    "IAMCollector",
    "S3Collector",
    "EC2Collector",
    "SecurityCollector",
    "RDSCollector",
    "LambdaCollector",
    "DynamoDBCollector",
    "APIGatewayCollector",
    "ECRCollector",
    "EKSCollector",
    "SageMakerCollector",
    "BedrockCollector",
    # GCP Collectors (conditionally available)
    "GCPIAMCollector",
    "GCPStorageCollector",
    "GCPComputeCollector",
    "GCPSecurityCollector",
    "GCPCloudSQLCollector",
    "GCPCloudFunctionsCollector",
    "GCPBigQueryCollector",
    "GCPCloudRunCollector",
    "GCPArtifactRegistryCollector",
    "GKECollector",
    "GCPVertexAICollector",
    "GCP_COLLECTORS_AVAILABLE",
    # Azure Collectors (conditionally available)
    "AzureIAMCollector",
    "AzureStorageCollector",
    "AzureComputeCollector",
    "AzureSecurityCollector",
    "AzureSQLCollector",
    "AzureFunctionsCollector",
    "AzureCosmosDBCollector",
    "AzureLogicAppsCollector",
    "AzureContainerRegistryCollector",
    "AzureAKSCollector",
    "AzureMLCollector",
    "AZURE_COLLECTORS_AVAILABLE",
    # Kubernetes Collectors (conditionally available)
    "K8sConfigCollector",
    "K8sRBACCollector",
    "K8sNetworkCollector",
    "K8sCollectorResult",
    "K8sRBACCollectorResult",
    "K8sNetworkCollectorResult",
    "K8S_COLLECTORS_AVAILABLE",
    # Factory functions
    "get_default_collectors",
    "get_collectors_for_provider",
    "run_collection",
    "list_collector_names",
    "list_supported_providers",
    # Registry
    "COLLECTOR_REGISTRY",
]


def list_supported_providers() -> list[str]:
    """
    List supported cloud providers.

    Returns:
        List of provider names with available collectors
    """
    return [p for p, collectors in COLLECTOR_REGISTRY.items() if collectors]


def get_collectors_for_provider(
    provider: str,
    session: Any | None = None,
    **kwargs: Any,
) -> list[BaseCollector]:
    """
    Get collectors for a specific cloud provider.

    Args:
        provider: Cloud provider name ("aws", "gcp", "azure")
        session: Optional session/credentials object
        **kwargs: Provider-specific configuration

    Returns:
        List of collector instances for the provider

    Raises:
        ValueError: If provider is not supported
    """
    provider = provider.lower()

    if provider not in COLLECTOR_REGISTRY:
        supported = ", ".join(list_supported_providers())
        raise ValueError(
            f"Unknown cloud provider: {provider}. "
            f"Supported providers: {supported}"
        )

    collectors = []
    for name, collector_class in COLLECTOR_REGISTRY[provider].items():
        try:
            collector = collector_class(session=session, **kwargs)
            collectors.append(collector)
        except Exception:
            pass  # Skip collectors that fail to initialize

    return collectors


def get_default_collectors(
    session: Any | None = None,
    region: str = "us-east-1",
    provider: str = "aws",
) -> list[BaseCollector]:
    """
    Return list of all default collectors for a provider.

    Args:
        session: Optional boto3 session to use
        region: Region to collect from
        provider: Cloud provider (default: "aws")

    Returns:
        List of initialized collectors
    """
    if provider == "aws":
        return [
            IAMCollector(session=session, region=region),
            S3Collector(session=session, region=region),
            EC2Collector(session=session, region=region),
            SecurityCollector(session=session, region=region),
            RDSCollector(session=session, region=region),
            LambdaCollector(session=session, region=region),
            DynamoDBCollector(session=session, region=region),
            APIGatewayCollector(session=session, region=region),
            ECRCollector(session=session, region=region),
            EKSCollector(session=session, region=region),
            SageMakerCollector(session=session, region=region),
            BedrockCollector(session=session, region=region),
        ]
    else:
        return get_collectors_for_provider(provider, session=session, region=region)


def run_collection(
    session: Any | None = None,
    region: str = "us-east-1",
    collectors: list[str] | None = None,
    provider: str = "aws",
) -> tuple[AssetCollection, FindingCollection, list[CollectorResult]]:
    """
    Run collection with specified or all collectors.

    Args:
        session: Optional session object
        region: Region to collect from
        collectors: List of collector names to run, or None for all
        provider: Cloud provider to collect from

    Returns:
        Tuple of (assets, findings, results)

    Example:
        >>> assets, findings, results = run_collection()
        >>> print(f"Found {len(assets)} assets and {len(findings)} findings")

        >>> # Run only specific collectors
        >>> assets, findings, results = run_collection(
        ...     collectors=["aws_iam", "aws_s3"]
        ... )

        >>> # Run for a specific provider
        >>> assets, findings, results = run_collection(provider="gcp")
    """
    from stance.models import FindingCollection

    # Get all default collectors for the provider
    all_collectors = get_default_collectors(
        session=session, region=region, provider=provider
    )

    # Filter by name if specified
    if collectors:
        all_collectors = [
            c for c in all_collectors if c.collector_name in collectors
        ]

    # Run collectors
    runner = CollectorRunner(all_collectors)
    assets, results = runner.run_all()

    # Collect security findings separately from security-focused collectors
    findings = FindingCollection()
    for collector in all_collectors:
        # AWS SecurityCollector
        if isinstance(collector, SecurityCollector):
            try:
                security_findings = collector.collect_findings()
                findings = findings.merge(security_findings)
            except Exception:
                pass  # Errors already logged by collector
        # AWS ECRCollector (container vulnerability findings)
        elif isinstance(collector, ECRCollector):
            try:
                ecr_findings = collector.collect_findings()
                findings = findings.merge(ecr_findings)
            except Exception:
                pass  # Errors already logged by collector
        # GCP SecurityCollector
        elif GCP_COLLECTORS_AVAILABLE and isinstance(collector, GCPSecurityCollector):
            try:
                security_findings = collector.collect_findings()
                findings = findings.merge(security_findings)
            except Exception:
                pass  # Errors already logged by collector
        # GCP ArtifactRegistryCollector (container vulnerability findings)
        elif GCP_COLLECTORS_AVAILABLE and isinstance(collector, GCPArtifactRegistryCollector):
            try:
                ar_findings = collector.collect_findings()
                findings = findings.merge(ar_findings)
            except Exception:
                pass  # Errors already logged by collector
        # Azure SecurityCollector
        elif AZURE_COLLECTORS_AVAILABLE and isinstance(collector, AzureSecurityCollector):
            try:
                security_findings = collector.collect_findings()
                findings = findings.merge(security_findings)
            except Exception:
                pass  # Errors already logged by collector
        # Azure ContainerRegistryCollector (container security findings)
        elif AZURE_COLLECTORS_AVAILABLE and isinstance(collector, AzureContainerRegistryCollector):
            try:
                acr_findings = collector.collect_findings()
                findings = findings.merge(acr_findings)
            except Exception:
                pass  # Errors already logged by collector

    return assets, findings, results


def get_collector_by_name(
    name: str,
    session: Any | None = None,
    region: str = "us-east-1",
) -> BaseCollector | None:
    """
    Get a specific collector by name.

    Args:
        name: Collector name (e.g., "aws_iam", "aws_s3")
        session: Optional boto3 session
        region: Region

    Returns:
        Collector instance or None if not found
    """
    # Search across all providers
    for provider_collectors in COLLECTOR_REGISTRY.values():
        if name in provider_collectors:
            collector_class = provider_collectors[name]
            return collector_class(session=session, region=region)
    return None


def list_collector_names(provider: str | None = None) -> list[str]:
    """
    List all available collector names.

    Args:
        provider: Optional provider to filter by

    Returns:
        List of collector names
    """
    if provider:
        provider = provider.lower()
        if provider in COLLECTOR_REGISTRY:
            return list(COLLECTOR_REGISTRY[provider].keys())
        return []

    # Return all collectors across all providers
    all_names = []
    for provider_collectors in COLLECTOR_REGISTRY.values():
        all_names.extend(provider_collectors.keys())
    return all_names
