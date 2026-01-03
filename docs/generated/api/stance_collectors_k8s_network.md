# stance.collectors.k8s_network

Kubernetes Network and Security Resource Collector for Mantissa Stance.

Collects network-related and secret resources from Kubernetes clusters:
- NetworkPolicies
- Ingress resources
- Secrets (metadata only, not values)
- LimitRanges
- ResourceQuotas

## Contents

### Classes

- [K8sNetworkCollectorResult](#k8snetworkcollectorresult)
- [K8sNetworkCollector](#k8snetworkcollector)

## K8sNetworkCollectorResult

**Tags:** dataclass

Result from K8sNetworkCollector.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `collector_name` | `str` | - |
| `assets` | `AssetCollection` | - |
| `duration_seconds` | `float` | - |
| `errors` | `list[str]` | `field(...)` |

### Properties

#### `success(self) -> bool`

Return True if no errors occurred.

**Returns:**

`bool`

#### `asset_count(self) -> int`

Return number of assets collected.

**Returns:**

`int`

## K8sNetworkCollector

Kubernetes Network and Security Resource Collector.

Collects network-related resources:
- NetworkPolicies: Network segmentation rules
- Ingress: External HTTP(S) access
- Secrets: Secret resources (metadata only)
- LimitRanges: Resource constraints per namespace
- ResourceQuotas: Namespace resource quotas

### Attributes

| Name | Type | Default |
|------|------|---------|
| `collector_name` | `str` | `k8s_network` |
| `resource_types` | `list[str]` | `['k8s_network_policy', 'k8s_ingress', 'k8s_secret', 'k8s_limit_range', 'k8s_resource_quota']` |

### Properties

#### `cluster_name(self) -> str`

Return cluster name.

**Returns:**

`str`

### Methods

#### `__init__(self, kubeconfig: str | None, context: str | None, in_cluster: bool = False, namespaces: list[str] | None) -> None`

Initialize K8sNetworkCollector.

**Parameters:**

- `kubeconfig` (`str | None`) - Path to kubeconfig file
- `context` (`str | None`) - Kubernetes context to use
- `in_cluster` (`bool`) - default: `False` - Use in-cluster configuration
- `namespaces` (`list[str] | None`) - List of namespaces to scan (None = all)

**Returns:**

`None`

#### `collect(self) -> K8sNetworkCollectorResult`

Collect network and security resources from Kubernetes.

**Returns:**

`K8sNetworkCollectorResult` - K8sNetworkCollectorResult with collected assets
