"""
AWS Data Access Mapper for Identity Security.

Maps which AWS principals can access which resources by analyzing
IAM policies, bucket policies, and access control lists.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.identity.base import (
    BaseDataAccessMapper,
    IdentityConfig,
    Principal,
    PrincipalType,
    PermissionLevel,
    ResourceAccess,
    DataAccessMapping,
    DataAccessFinding,
    DataAccessResult,
)

logger = logging.getLogger(__name__)

# Import boto3 optionally
try:
    import boto3
    from botocore.exceptions import ClientError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore


# S3 action to permission level mapping
S3_ACTION_MAPPING = {
    # Admin actions
    "s3:*": PermissionLevel.ADMIN,
    "s3:DeleteBucket": PermissionLevel.ADMIN,
    "s3:PutBucketPolicy": PermissionLevel.ADMIN,
    "s3:DeleteBucketPolicy": PermissionLevel.ADMIN,
    "s3:PutBucketAcl": PermissionLevel.ADMIN,
    "s3:PutBucketOwnershipControls": PermissionLevel.ADMIN,
    # Write actions
    "s3:PutObject": PermissionLevel.WRITE,
    "s3:DeleteObject": PermissionLevel.WRITE,
    "s3:PutObjectAcl": PermissionLevel.WRITE,
    "s3:AbortMultipartUpload": PermissionLevel.WRITE,
    "s3:DeleteObjectVersion": PermissionLevel.WRITE,
    # Read actions
    "s3:GetObject": PermissionLevel.READ,
    "s3:GetObjectVersion": PermissionLevel.READ,
    "s3:GetObjectAcl": PermissionLevel.READ,
    "s3:GetBucketLocation": PermissionLevel.READ,
    # List actions
    "s3:ListBucket": PermissionLevel.LIST,
    "s3:ListBucketVersions": PermissionLevel.LIST,
    "s3:ListBucketMultipartUploads": PermissionLevel.LIST,
}


class AWSDataAccessMapper(BaseDataAccessMapper):
    """
    AWS data access mapper.

    Analyzes IAM policies, S3 bucket policies, and ACLs to determine
    which principals can access which resources.

    All operations are read-only.
    """

    cloud_provider = "aws"

    def __init__(
        self,
        config: IdentityConfig | None = None,
        session: Any | None = None,
        region: str = "us-east-1",
    ):
        """
        Initialize AWS data access mapper.

        Args:
            config: Optional identity configuration
            session: Optional boto3 Session
            region: AWS region
        """
        super().__init__(config)

        if not BOTO3_AVAILABLE:
            raise ImportError(
                "boto3 is required for AWS identity analysis. "
                "Install with: pip install boto3"
            )

        self._session = session or boto3.Session()
        self._region = region
        self._iam_client = self._session.client("iam")
        self._s3_client = self._session.client("s3", region_name=region)
        self._sts_client = self._session.client("sts")

        # Get account ID
        try:
            self._account_id = self._sts_client.get_caller_identity()["Account"]
        except Exception:
            self._account_id = None

    def who_can_access(self, resource_id: str) -> DataAccessResult:
        """
        Determine who can access an S3 bucket.

        Args:
            resource_id: S3 bucket name (with or without s3:// prefix)

        Returns:
            Data access result with mapping and findings
        """
        # Parse bucket name
        bucket_name = resource_id
        if bucket_name.startswith("s3://"):
            bucket_name = bucket_name[5:].split("/")[0]
        if bucket_name.startswith("arn:aws:s3:::"):
            bucket_name = bucket_name[13:].split("/")[0]

        analysis_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting AWS data access analysis: bucket={bucket_name}, id={analysis_id}"
        )

        result = DataAccessResult(
            analysis_id=analysis_id,
            resource_id=bucket_name,
            config=self._config,
            started_at=started_at,
        )

        try:
            # Create mapping
            mapping = DataAccessMapping(
                resource_id=bucket_name,
                resource_type="s3_bucket",
                cloud_provider="aws",
            )

            # Get bucket policy principals
            bucket_policy = self.get_resource_policy(bucket_name)
            policy_principals = self._extract_principals_from_policy(
                bucket_policy, bucket_name
            )

            # Get IAM principals with S3 access
            iam_principals = self._get_iam_principals_with_access(bucket_name)

            # Combine and dedupe
            all_principals: dict[str, tuple[Principal, ResourceAccess]] = {}

            for principal, access in policy_principals + iam_principals:
                if not self._should_include_principal(principal):
                    continue

                key = principal.id
                if key in all_principals:
                    # Keep higher permission level
                    existing_access = all_principals[key][1]
                    if access.permission_level > existing_access.permission_level:
                        all_principals[key] = (principal, access)
                else:
                    all_principals[key] = (principal, access)

            mapping.principals = list(all_principals.values())
            mapping.total_principals = len(mapping.principals)

            # Count by type and level
            for principal, access in mapping.principals:
                ptype = principal.principal_type.value
                mapping.principals_by_type[ptype] = (
                    mapping.principals_by_type.get(ptype, 0) + 1
                )

                plevel = access.permission_level.value
                mapping.principals_by_level[plevel] = (
                    mapping.principals_by_level.get(plevel, 0) + 1
                )

            result.mapping = mapping
            result.total_principals = mapping.total_principals

            # Generate findings
            result.findings = self._generate_findings(mapping)

        except ClientError as e:
            error_msg = f"AWS error: {e.response.get('Error', {}).get('Message', str(e))}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Analysis error: {type(e).__name__}: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"AWS data access analysis complete: {result.total_principals} principals, "
            f"{len(result.findings)} findings"
        )

        return result

    def get_principal_access(self, principal_id: str) -> list[ResourceAccess]:
        """
        Get all S3 buckets a principal can access.

        Args:
            principal_id: IAM user ARN, role ARN, etc.

        Returns:
            List of resource access entries
        """
        access_list: list[ResourceAccess] = []

        try:
            # List all buckets
            buckets = self._s3_client.list_buckets().get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]

                # Check if principal has access via bucket policy
                bucket_policy = self.get_resource_policy(bucket_name)
                if bucket_policy:
                    level = self._check_principal_in_policy(principal_id, bucket_policy)
                    if level != PermissionLevel.NONE:
                        access_list.append(
                            ResourceAccess(
                                resource_id=bucket_name,
                                resource_type="s3_bucket",
                                permission_level=level,
                                permission_source="bucket_policy",
                            )
                        )

        except ClientError as e:
            logger.warning(f"Error getting principal access: {e}")

        return access_list

    def list_principals(self) -> Iterator[Principal]:
        """
        List all IAM principals in the account.

        Yields:
            Principal objects
        """
        # List users
        if self._config.include_users:
            try:
                paginator = self._iam_client.get_paginator("list_users")
                for page in paginator.paginate():
                    for user in page.get("Users", []):
                        yield Principal(
                            id=user["Arn"],
                            name=user["UserName"],
                            principal_type=PrincipalType.USER,
                            cloud_provider="aws",
                            account_id=self._account_id,
                            created_at=user.get("CreateDate"),
                        )
            except ClientError as e:
                logger.warning(f"Error listing users: {e}")

        # List roles
        if self._config.include_roles:
            try:
                paginator = self._iam_client.get_paginator("list_roles")
                for page in paginator.paginate():
                    for role in page.get("Roles", []):
                        # Determine if it's a service-linked role
                        path = role.get("Path", "")
                        if "/service-role/" in path or "/aws-service-role/" in path:
                            ptype = PrincipalType.SERVICE_ACCOUNT
                        else:
                            ptype = PrincipalType.ROLE

                        yield Principal(
                            id=role["Arn"],
                            name=role["RoleName"],
                            principal_type=ptype,
                            cloud_provider="aws",
                            account_id=self._account_id,
                            created_at=role.get("CreateDate"),
                        )
            except ClientError as e:
                logger.warning(f"Error listing roles: {e}")

        # List groups
        if self._config.include_groups:
            try:
                paginator = self._iam_client.get_paginator("list_groups")
                for page in paginator.paginate():
                    for group in page.get("Groups", []):
                        yield Principal(
                            id=group["Arn"],
                            name=group["GroupName"],
                            principal_type=PrincipalType.GROUP,
                            cloud_provider="aws",
                            account_id=self._account_id,
                            created_at=group.get("CreateDate"),
                        )
            except ClientError as e:
                logger.warning(f"Error listing groups: {e}")

    def get_resource_policy(self, resource_id: str) -> dict[str, Any] | None:
        """
        Get the bucket policy for an S3 bucket.

        Args:
            resource_id: S3 bucket name

        Returns:
            Policy document or None
        """
        bucket_name = resource_id
        if bucket_name.startswith("s3://"):
            bucket_name = bucket_name[5:].split("/")[0]

        try:
            response = self._s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_str = response.get("Policy", "{}")
            return json.loads(policy_str)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchBucketPolicy":
                return None
            logger.debug(f"Error getting bucket policy for {bucket_name}: {e}")
            return None

    def _extract_principals_from_policy(
        self,
        policy: dict[str, Any] | None,
        bucket_name: str,
    ) -> list[tuple[Principal, ResourceAccess]]:
        """
        Extract principals from a bucket policy.

        Args:
            policy: Bucket policy document
            bucket_name: Bucket name

        Returns:
            List of (Principal, ResourceAccess) tuples
        """
        if not policy:
            return []

        results: list[tuple[Principal, ResourceAccess]] = []

        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            # Extract principals
            principals = self._parse_policy_principals(statement)

            # Extract actions
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            # Determine permission level
            level = self._get_permission_level_from_actions(actions)

            for principal in principals:
                results.append(
                    (
                        principal,
                        ResourceAccess(
                            resource_id=bucket_name,
                            resource_type="s3_bucket",
                            permission_level=level,
                            permission_source="bucket_policy",
                        ),
                    )
                )

        return results

    def _parse_policy_principals(
        self, statement: dict[str, Any]
    ) -> list[Principal]:
        """Parse principals from a policy statement."""
        principals: list[Principal] = []

        principal_block = statement.get("Principal", {})

        if principal_block == "*":
            principals.append(
                Principal(
                    id="*",
                    name="Everyone",
                    principal_type=PrincipalType.UNKNOWN,
                    cloud_provider="aws",
                )
            )
            return principals

        if isinstance(principal_block, dict):
            # AWS principals
            aws_principals = principal_block.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for arn in aws_principals:
                if arn == "*":
                    principals.append(
                        Principal(
                            id="*",
                            name="Everyone",
                            principal_type=PrincipalType.UNKNOWN,
                            cloud_provider="aws",
                        )
                    )
                else:
                    ptype = self._get_principal_type_from_arn(arn)
                    name = self._get_name_from_arn(arn)
                    principals.append(
                        Principal(
                            id=arn,
                            name=name,
                            principal_type=ptype,
                            cloud_provider="aws",
                        )
                    )

            # Service principals
            service_principals = principal_block.get("Service", [])
            if isinstance(service_principals, str):
                service_principals = [service_principals]

            for service in service_principals:
                principals.append(
                    Principal(
                        id=service,
                        name=service,
                        principal_type=PrincipalType.SERVICE_ACCOUNT,
                        cloud_provider="aws",
                    )
                )

            # Federated principals
            federated_principals = principal_block.get("Federated", [])
            if isinstance(federated_principals, str):
                federated_principals = [federated_principals]

            for fed in federated_principals:
                principals.append(
                    Principal(
                        id=fed,
                        name=fed.split("/")[-1] if "/" in fed else fed,
                        principal_type=PrincipalType.FEDERATED,
                        cloud_provider="aws",
                    )
                )

        return principals

    def _get_principal_type_from_arn(self, arn: str) -> PrincipalType:
        """Determine principal type from ARN."""
        if ":user/" in arn:
            return PrincipalType.USER
        if ":role/" in arn:
            return PrincipalType.ROLE
        if ":group/" in arn:
            return PrincipalType.GROUP
        if ":root" in arn:
            return PrincipalType.USER  # Root is effectively a user
        if ":assumed-role/" in arn:
            return PrincipalType.ROLE
        return PrincipalType.UNKNOWN

    def _get_name_from_arn(self, arn: str) -> str:
        """Extract name from ARN."""
        if "/" in arn:
            return arn.split("/")[-1]
        if ":root" in arn:
            return "root"
        return arn.split(":")[-1]

    def _get_permission_level_from_actions(
        self, actions: list[str]
    ) -> PermissionLevel:
        """Get permission level from S3 actions."""
        highest = PermissionLevel.NONE

        for action in actions:
            # Normalize action
            action_normalized = action.lower()

            # Check for wildcard
            if action == "*" or action == "s3:*":
                return PermissionLevel.ADMIN

            # Check mapping
            for mapped_action, level in S3_ACTION_MAPPING.items():
                if action_normalized == mapped_action.lower():
                    if level > highest:
                        highest = level
                    break
            else:
                # Infer from action name
                inferred = self._parse_permission_level([action])
                if inferred > highest:
                    highest = inferred

        return highest

    def _get_iam_principals_with_access(
        self, bucket_name: str
    ) -> list[tuple[Principal, ResourceAccess]]:
        """
        Get IAM principals with S3 access via IAM policies.

        This checks attached policies for S3 permissions.

        Args:
            bucket_name: Bucket name

        Returns:
            List of (Principal, ResourceAccess) tuples
        """
        results: list[tuple[Principal, ResourceAccess]] = []
        bucket_arn = f"arn:aws:s3:::{bucket_name}"

        # Check users
        if self._config.include_users:
            try:
                paginator = self._iam_client.get_paginator("list_users")
                for page in paginator.paginate():
                    for user in page.get("Users", []):
                        access = self._check_iam_entity_access(
                            "user", user["UserName"], bucket_arn
                        )
                        if access and access.permission_level != PermissionLevel.NONE:
                            principal = Principal(
                                id=user["Arn"],
                                name=user["UserName"],
                                principal_type=PrincipalType.USER,
                                cloud_provider="aws",
                                account_id=self._account_id,
                                created_at=user.get("CreateDate"),
                            )
                            results.append((principal, access))
            except ClientError as e:
                logger.debug(f"Error checking users: {e}")

        # Check roles
        if self._config.include_roles:
            try:
                paginator = self._iam_client.get_paginator("list_roles")
                for page in paginator.paginate():
                    for role in page.get("Roles", []):
                        access = self._check_iam_entity_access(
                            "role", role["RoleName"], bucket_arn
                        )
                        if access and access.permission_level != PermissionLevel.NONE:
                            path = role.get("Path", "")
                            if "/service-role/" in path or "/aws-service-role/" in path:
                                ptype = PrincipalType.SERVICE_ACCOUNT
                            else:
                                ptype = PrincipalType.ROLE

                            principal = Principal(
                                id=role["Arn"],
                                name=role["RoleName"],
                                principal_type=ptype,
                                cloud_provider="aws",
                                account_id=self._account_id,
                                created_at=role.get("CreateDate"),
                            )
                            results.append((principal, access))
            except ClientError as e:
                logger.debug(f"Error checking roles: {e}")

        return results

    def _check_iam_entity_access(
        self,
        entity_type: str,
        entity_name: str,
        resource_arn: str,
    ) -> ResourceAccess | None:
        """
        Check if an IAM entity has access to a resource.

        Args:
            entity_type: "user" or "role"
            entity_name: Entity name
            resource_arn: Resource ARN

        Returns:
            ResourceAccess if access found, None otherwise
        """
        try:
            # Get attached policies
            if entity_type == "user":
                policies = list(self._paginate(
                    self._iam_client,
                    "list_attached_user_policies",
                    "AttachedPolicies",
                    UserName=entity_name,
                ))
            else:
                policies = list(self._paginate(
                    self._iam_client,
                    "list_attached_role_policies",
                    "AttachedPolicies",
                    RoleName=entity_name,
                ))

            highest_level = PermissionLevel.NONE
            policy_ids: list[str] = []

            for policy in policies:
                policy_arn = policy["PolicyArn"]

                # Check for AWS managed admin policies
                if "AdministratorAccess" in policy_arn or "AmazonS3FullAccess" in policy_arn:
                    return ResourceAccess(
                        resource_id=resource_arn.split(":::")[-1],
                        resource_type="s3_bucket",
                        permission_level=PermissionLevel.ADMIN,
                        permission_source="iam_policy",
                        policy_ids=[policy_arn],
                    )

                # Check for read-only policies
                if "AmazonS3ReadOnlyAccess" in policy_arn:
                    if PermissionLevel.READ > highest_level:
                        highest_level = PermissionLevel.READ
                        policy_ids.append(policy_arn)

            if highest_level != PermissionLevel.NONE:
                return ResourceAccess(
                    resource_id=resource_arn.split(":::")[-1],
                    resource_type="s3_bucket",
                    permission_level=highest_level,
                    permission_source="iam_policy",
                    policy_ids=policy_ids,
                )

        except ClientError as e:
            logger.debug(f"Error checking {entity_type} {entity_name}: {e}")

        return None

    def _check_principal_in_policy(
        self,
        principal_id: str,
        policy: dict[str, Any],
    ) -> PermissionLevel:
        """
        Check if a principal is granted access in a policy.

        Args:
            principal_id: Principal ARN
            policy: Policy document

        Returns:
            Permission level
        """
        highest = PermissionLevel.NONE

        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            principals = statement.get("Principal", {})

            # Check if principal matches
            matches = False

            if principals == "*":
                matches = True
            elif isinstance(principals, dict):
                aws_principals = principals.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]

                for p in aws_principals:
                    if p == "*" or p == principal_id:
                        matches = True
                        break
                    # Check account-level match
                    if ":root" in p:
                        account = p.split(":")[4]
                        if f":{account}:" in principal_id:
                            matches = True
                            break

            if matches:
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                level = self._get_permission_level_from_actions(actions)
                if level > highest:
                    highest = level

        return highest

    def _paginate(
        self,
        client: Any,
        method: str,
        key: str,
        **kwargs: Any,
    ) -> Iterator[Any]:
        """Paginate through API results."""
        try:
            paginator = client.get_paginator(method)
            for page in paginator.paginate(**kwargs):
                for item in page.get(key, []):
                    yield item
        except ClientError:
            # Method may not support pagination
            try:
                method_func = getattr(client, method)
                response = method_func(**kwargs)
                for item in response.get(key, []):
                    yield item
            except ClientError:
                pass

    def list_buckets(self) -> Iterator[str]:
        """List all S3 buckets in the account."""
        try:
            response = self._s3_client.list_buckets()
            for bucket in response.get("Buckets", []):
                yield bucket["Name"]
        except ClientError as e:
            logger.warning(f"Error listing buckets: {e}")
