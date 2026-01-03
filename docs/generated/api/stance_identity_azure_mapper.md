# stance.identity.azure_mapper

Azure Data Access Mapper for Identity Security.

Maps which Azure principals can access which resources by analyzing
RBAC role assignments and container access policies.

## Contents

### Classes

- [AzureDataAccessMapper](#azuredataaccessmapper)

## Constants

### `AZURE_ROLE_MAPPING`

Type: `dict`

Value: `{'Owner': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 'Contributor': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 'Storage Account Contributor': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 'Storage Blob Data Owner': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 'Storage Blob Data Contributor': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 'Storage Blob Data Reader': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'READ\', ctx=Load())"', 'Reader': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'READ\', ctx=Load())"', 'Reader and Data Access': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'READ\', ctx=Load())"'}`

## AzureDataAccessMapper

**Inherits from:** BaseDataAccessMapper

Azure data access mapper.

Analyzes RBAC role assignments to determine which principals
can access which Blob Storage containers.

All operations are read-only.

### Methods

#### `__init__(self, config: IdentityConfig | None, subscription_id: str | None, connection_string: str | None, account_url: str | None, credential: Any | None)`

Initialize Azure data access mapper.

**Parameters:**

- `config` (`IdentityConfig | None`) - Optional identity configuration
- `subscription_id` (`str | None`) - Azure subscription ID
- `connection_string` (`str | None`) - Storage account connection string
- `account_url` (`str | None`) - Storage account URL
- `credential` (`Any | None`) - Optional credential object

#### `who_can_access(self, resource_id: str) -> DataAccessResult`

Determine who can access an Azure Blob container.

**Parameters:**

- `resource_id` (`str`) - Container name (with or without azure:// prefix)

**Returns:**

`DataAccessResult` - Data access result with mapping and findings

#### `get_principal_access(self, principal_id: str) -> list[ResourceAccess]`

Get all containers a principal can access.

**Parameters:**

- `principal_id` (`str`) - Principal object ID or email

**Returns:**

`list[ResourceAccess]` - List of resource access entries

#### `list_principals(self) -> Iterator[Principal]`

List all principals with storage access.  Yields: Principal objects

**Returns:**

`Iterator[Principal]`

#### `get_resource_policy(self, resource_id: str) -> dict[(str, Any)] | None`

Get RBAC role assignments for a container.

**Parameters:**

- `resource_id` (`str`) - Container name

**Returns:**

`dict[(str, Any)] | None` - Dictionary with role assignments or None

#### `list_containers(self) -> Iterator[str]`

List all containers in the storage account.

**Returns:**

`Iterator[str]`
