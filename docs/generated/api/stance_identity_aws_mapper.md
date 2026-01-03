# stance.identity.aws_mapper

AWS Data Access Mapper for Identity Security.

Maps which AWS principals can access which resources by analyzing
IAM policies, bucket policies, and access control lists.

## Contents

### Classes

- [AWSDataAccessMapper](#awsdataaccessmapper)

## Constants

### `S3_ACTION_MAPPING`

Type: `dict`

Value: `{'s3:*': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 's3:DeleteBucket': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 's3:PutBucketPolicy': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 's3:DeleteBucketPolicy': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 's3:PutBucketAcl': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 's3:PutBucketOwnershipControls': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'ADMIN\', ctx=Load())"', 's3:PutObject': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 's3:DeleteObject': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 's3:PutObjectAcl': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 's3:AbortMultipartUpload': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 's3:DeleteObjectVersion': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'WRITE\', ctx=Load())"', 's3:GetObject': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'READ\', ctx=Load())"', 's3:GetObjectVersion': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'READ\', ctx=Load())"', 's3:GetObjectAcl': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'READ\', ctx=Load())"', 's3:GetBucketLocation': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'READ\', ctx=Load())"', 's3:ListBucket': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'LIST\', ctx=Load())"', 's3:ListBucketVersions': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'LIST\', ctx=Load())"', 's3:ListBucketMultipartUploads': '"Attribute(value=Name(id=\'PermissionLevel\', ctx=Load()), attr=\'LIST\', ctx=Load())"'}`

## AWSDataAccessMapper

**Inherits from:** BaseDataAccessMapper

AWS data access mapper.

Analyzes IAM policies, S3 bucket policies, and ACLs to determine
which principals can access which resources.

All operations are read-only.

### Methods

#### `__init__(self, config: IdentityConfig | None, session: Any | None, region: str = us-east-1)`

Initialize AWS data access mapper.

**Parameters:**

- `config` (`IdentityConfig | None`) - Optional identity configuration
- `session` (`Any | None`) - Optional boto3 Session
- `region` (`str`) - default: `us-east-1` - AWS region

#### `who_can_access(self, resource_id: str) -> DataAccessResult`

Determine who can access an S3 bucket.

**Parameters:**

- `resource_id` (`str`) - S3 bucket name (with or without s3:// prefix)

**Returns:**

`DataAccessResult` - Data access result with mapping and findings

#### `get_principal_access(self, principal_id: str) -> list[ResourceAccess]`

Get all S3 buckets a principal can access.

**Parameters:**

- `principal_id` (`str`) - IAM user ARN, role ARN, etc.

**Returns:**

`list[ResourceAccess]` - List of resource access entries

#### `list_principals(self) -> Iterator[Principal]`

List all IAM principals in the account.  Yields: Principal objects

**Returns:**

`Iterator[Principal]`

#### `get_resource_policy(self, resource_id: str) -> dict[(str, Any)] | None`

Get the bucket policy for an S3 bucket.

**Parameters:**

- `resource_id` (`str`) - S3 bucket name

**Returns:**

`dict[(str, Any)] | None` - Policy document or None

#### `list_buckets(self) -> Iterator[str]`

List all S3 buckets in the account.

**Returns:**

`Iterator[str]`
