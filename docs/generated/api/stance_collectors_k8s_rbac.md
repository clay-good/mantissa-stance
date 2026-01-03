# stance.collectors.k8s_rbac

Kubernetes RBAC (Role-Based Access Control) collector.

This collector gathers Kubernetes RBAC resources including
roles, cluster roles, role bindings, cluster role bindings,
and service accounts.

## Contents

### Classes

- [K8sRBACCollectorResult](#k8srbaccollectorresult)
- [K8sRBACCollector](#k8srbaccollector)

## Constants

### `HIGH_RISK_VERBS`

Type: `str`

Value: `"Set(elts=[Constant(value='*'), Constant(value='create'), Constant(value='delete'), Constant(value='deletecollection'), Constant(value='patch'), Constant(value='update')])"`

### `HIGH_RISK_RESOURCES`

Type: `str`

Value: `"Set(elts=[Constant(value='*'), Constant(value='secrets'), Constant(value='pods/exec'), Constant(value='pods/attach'), Constant(value='serviceaccounts'), Constant(value='clusterroles'), Constant(value='clusterrolebindings'), Constant(value='roles'), Constant(value='rolebindings'), Constant(value='persistentvolumes'), Constant(value='nodes'), Constant(value='nodes/proxy')])"`

### `ADMIN_CLUSTER_ROLES`

Type: `str`

Value: `"Set(elts=[Constant(value='cluster-admin'), Constant(value='admin'), Constant(value='edit'), Constant(value='system:masters')])"`

## K8sRBACCollectorResult

**Tags:** dataclass

Result from running the Kubernetes RBAC collector.

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

## K8sRBACCollector

Collector for Kubernetes RBAC resources.

Collects security-relevant configuration for:
- Roles (namespace-scoped)
- ClusterRoles (cluster-scoped)
- RoleBindings (namespace-scoped)
- ClusterRoleBindings (cluster-scoped)
- ServiceAccounts

Resource types collected:
- k8s_role
- k8s_cluster_role
- k8s_role_binding
- k8s_cluster_role_binding
- k8s_service_account

### Attributes

| Name | Type | Default |
|------|------|---------|
| `collector_name` | `str` | `k8s_rbac` |
| `resource_types` | `list[str]` | `['k8s_role', 'k8s_cluster_role', 'k8s_role_binding', 'k8s_cluster_role_binding', 'k8s_service_account']` |

### Properties

#### `cluster_name(self) -> str`

Get the cluster name.

**Returns:**

`str`

### Methods

#### `__init__(self, kubeconfig: str | None, context: str | None, in_cluster: bool = False, namespaces: list[str] | None) -> None`

Initialize the Kubernetes RBAC collector.

**Parameters:**

- `kubeconfig` (`str | None`) - Path to kubeconfig file (default: ~/.kube/config)
- `context` (`str | None`) - Kubernetes context to use (default: current context)
- `in_cluster` (`bool`) - default: `False` - If True, use in-cluster configuration
- `namespaces` (`list[str] | None`) - List of namespaces to collect from (default: all)

**Returns:**

`None`

#### `collect(self) -> K8sRBACCollectorResult`

Collect Kubernetes RBAC configuration.

**Returns:**

`K8sRBACCollectorResult` - K8sRBACCollectorResult with collected assets
