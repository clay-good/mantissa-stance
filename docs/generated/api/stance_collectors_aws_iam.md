# stance.collectors.aws_iam

AWS IAM collector for Mantissa Stance.

Collects IAM resources including users, roles, policies, groups,
password policy, and account summary for security posture assessment.

## Contents

### Classes

- [IAMCollector](#iamcollector)

## IAMCollector

**Inherits from:** BaseCollector

Collects AWS IAM resources and configuration.

Gathers IAM users, roles, policies, groups, password policy,
and account summary. All API calls are read-only.

### Methods

#### `collect(self) -> AssetCollection`

Collect all IAM resources.

**Returns:**

`AssetCollection` - Collection of IAM assets
