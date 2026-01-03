# stance.collectors.aws_ecr

AWS ECR collector for Mantissa Stance.

Collects Elastic Container Registry repositories, images, and their
security configurations for posture assessment.

## Contents

### Classes

- [ECRCollector](#ecrcollector)

## ECRCollector

**Inherits from:** BaseCollector

Collects AWS ECR repositories, images, and security configurations.

Gathers ECR repositories with their security settings including
image scanning results, lifecycle policies, repository policies,
and encryption configuration. All API calls are read-only.

### Methods

#### `collect(self) -> AssetCollection`

Collect all ECR resources.

**Returns:**

`AssetCollection` - Collection of ECR assets

#### `collect_findings(self) -> FindingCollection`

Collect security findings from ECR image scans.

**Returns:**

`FindingCollection` - Collection of vulnerability findings from image scans
