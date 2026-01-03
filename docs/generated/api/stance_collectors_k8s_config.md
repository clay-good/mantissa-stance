# stance.collectors.k8s_config

Kubernetes workload configuration collector.

This collector gathers Kubernetes workload resources including
deployments, pods, services, daemonsets, statefulsets, and more.

## Contents

### Classes

- [K8sCollectorResult](#k8scollectorresult)
- [K8sConfigCollector](#k8sconfigcollector)

## K8sCollectorResult

**Tags:** dataclass

Result from running a Kubernetes collector.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `collector_name` | `str` | - |
| `assets` | `AssetCollection` | - |
| `duration_seconds` | `float` | - |
| `errors` | `list[str]` | - |

### Properties

#### `success(self) -> bool`

Check if collection completed without errors.

**Returns:**

`bool`

#### `asset_count(self) -> int`

Get number of assets collected.

**Returns:**

`int`

## K8sConfigCollector

Collector for Kubernetes workload configuration resources.

Collects security-relevant configuration for:
- Deployments
- Pods
- Services
- DaemonSets
- StatefulSets
- ReplicaSets
- Jobs
- CronJobs
- ConfigMaps (metadata only, not data)
- Namespaces

Resource types collected:
- k8s_deployment
- k8s_pod
- k8s_service
- k8s_daemonset
- k8s_statefulset
- k8s_replicaset
- k8s_job
- k8s_cronjob
- k8s_configmap
- k8s_namespace

### Attributes

| Name | Type | Default |
|------|------|---------|
| `collector_name` | `str` | `k8s_config` |
| `resource_types` | `list[str]` | `['k8s_deployment', 'k8s_pod', 'k8s_service', 'k8s_daemonset', 'k8s_statefulset', 'k8s_replicaset', 'k8s_job', 'k8s_cronjob', 'k8s_configmap', 'k8s_namespace']` |

### Properties

#### `cluster_name(self) -> str`

Get the cluster name.

**Returns:**

`str`

### Methods

#### `__init__(self, kubeconfig: str | None, context: str | None, in_cluster: bool = False, namespaces: list[str] | None) -> None`

Initialize the Kubernetes config collector.

**Parameters:**

- `kubeconfig` (`str | None`) - Path to kubeconfig file (default: ~/.kube/config)
- `context` (`str | None`) - Kubernetes context to use (default: current context)
- `in_cluster` (`bool`) - default: `False` - If True, use in-cluster configuration
- `namespaces` (`list[str] | None`) - List of namespaces to collect from (default: all)

**Returns:**

`None`

#### `collect(self) -> K8sCollectorResult`

Collect Kubernetes workload configuration.

**Returns:**

`K8sCollectorResult` - K8sCollectorResult with collected assets
