# stance.identity.gcp_mapper

GCP Data Access Mapper for Identity Security.

Maps which GCP principals can access which resources by analyzing
IAM policies and bindings.

## Contents

### Classes

- [GCPDataAccessMapper](#gcpdataaccessmapper)

## Constants

### `GCS_ROLE_MAPPING`

Type: `dict`

Value: `{'roles/storage.admin': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 'roles/owner': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 'roles/editor': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 'roles/storage.objectAdmin': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 'roles/storage.objectCreator': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 'roles/storage.legacyBucketWriter': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 'roles/storage.objectViewer': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'READ\', ctx=Load())"', 'roles/storage.legacyBucketReader': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'READ\', ctx=Load())"', 'roles/viewer': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'READ\', ctx=Load())"'}`

## GCPDataAccessMapper

**Inherits from:** BaseDataAccessMapper

GCP data access mapper.

Analyzes IAM policies and bindings to determine which principals
can access which GCS buckets.

All operations are read-only.

### Methods

#### `__init__(self, config: IdentityConfig | None, project: str | None, credentials: Any | None)`

Initialize GCP data access mapper.

**Parameters:**

- `config` (`IdentityConfig | None`) - Optional identity configuration
- `project` (`str | None`) - GCP project ID
- `credentials` (`Any | None`) - Optional credentials object

#### `who_can_access(self, resource_id: str) -> DataAccessResult`

Determine who can access a GCS bucket.

**Parameters:**

- `resource_id` (`str`) - GCS bucket name (with or without gs:// prefix)

**Returns:**

`DataAccessResult` - Data access result with mapping and findings

#### `get_principal_access(self, principal_id: str) -> list[ResourceAccess]`

Get all GCS buckets a principal can access.

**Parameters:**

- `principal_id` (`str`) - Principal email or member string

**Returns:**

`list[ResourceAccess]` - List of resource access entries

#### `list_principals(self) -> Iterator[Principal]`

List all principals with bucket access in the project.  Yields: Principal objects

**Returns:**

`Iterator[Principal]`

#### `get_resource_policy(self, resource_id: str) -> dict[(str, Any)] | None`

Get the IAM policy for a GCS bucket.

**Parameters:**

- `resource_id` (`str`) - GCS bucket name

**Returns:**

`dict[(str, Any)] | None` - Policy bindings or None

#### `list_buckets(self) -> Iterator[str]`

List all GCS buckets in the project.

**Returns:**

`Iterator[str]`
