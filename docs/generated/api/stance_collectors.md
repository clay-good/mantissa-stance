# stance.collectors

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

GCP Collectors:
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

## Contents

### Functions

- [list_supported_providers](#list_supported_providers)
- [get_collectors_for_provider](#get_collectors_for_provider)
- [get_default_collectors](#get_default_collectors)
- [run_collection](#run_collection)
- [get_collector_by_name](#get_collector_by_name)
- [list_collector_names](#list_collector_names)

### `list_supported_providers() -> list[str]`

List supported cloud providers.

**Returns:**

`list[str]` - List of provider names with available collectors

### `get_collectors_for_provider(provider: str, session: Any | None, **kwargs: Any) -> list[BaseCollector]`

Get collectors for a specific cloud provider.

**Parameters:**

- `provider` (`str`) - Cloud provider name ("aws", "gcp", "azure")
- `session` (`Any | None`) - Optional session/credentials object **kwargs: Provider-specific configuration
- `**kwargs` (`Any`)

**Returns:**

`list[BaseCollector]` - List of collector instances for the provider

**Raises:**

- `ValueError`: If provider is not supported

### `get_default_collectors(session: Any | None, region: str = us-east-1, provider: str = aws) -> list[BaseCollector]`

Return list of all default collectors for a provider.

**Parameters:**

- `session` (`Any | None`) - Optional boto3 session to use
- `region` (`str`) - default: `us-east-1` - Region to collect from
- `provider` (`str`) - default: `aws` - Cloud provider (default: "aws")

**Returns:**

`list[BaseCollector]` - List of initialized collectors

### `run_collection(session: Any | None, region: str = us-east-1, collectors: list[str] | None, provider: str = aws) -> tuple[(AssetCollection, FindingCollection, list[CollectorResult])]`

Run collection with specified or all collectors.

**Parameters:**

- `session` (`Any | None`) - Optional session object
- `region` (`str`) - default: `us-east-1` - Region to collect from
- `collectors` (`list[str] | None`) - List of collector names to run, or None for all
- `provider` (`str`) - default: `aws` - Cloud provider to collect from

**Returns:**

`tuple[(AssetCollection, FindingCollection, list[CollectorResult])]` - Tuple of (assets, findings, results)

**Examples:**

```python
>>> assets, findings, results = run_collection()
    >>> print(f"Found {len(assets)} assets and {len(findings)} findings")

    >>> # Run only specific collectors
    >>> assets, findings, results = run_collection(
    ...     collectors=["aws_iam", "aws_s3"]
    ... )

    >>> # Run for a specific provider
    >>> assets, findings, results = run_collection(provider="gcp")
```

### `get_collector_by_name(name: str, session: Any | None, region: str = us-east-1) -> BaseCollector | None`

Get a specific collector by name.

**Parameters:**

- `name` (`str`) - Collector name (e.g., "aws_iam", "aws_s3")
- `session` (`Any | None`) - Optional boto3 session
- `region` (`str`) - default: `us-east-1` - Region

**Returns:**

`BaseCollector | None` - Collector instance or None if not found

### `list_collector_names(provider: str | None) -> list[str]`

List all available collector names.

**Parameters:**

- `provider` (`str | None`) - Optional provider to filter by

**Returns:**

`list[str]` - List of collector names
