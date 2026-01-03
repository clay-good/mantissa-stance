# stance.collectors.aws_eks

AWS EKS collector for Mantissa Stance.

Collects Elastic Kubernetes Service clusters, node groups, and their
security configurations for posture assessment.

## Contents

### Classes

- [EKSCollector](#ekscollector)

## EKSCollector

**Inherits from:** BaseCollector

Collects AWS EKS clusters, node groups, and security configurations.

Gathers EKS cluster configurations including networking, logging,
encryption, authentication, and node group settings.
All API calls are read-only.

### Methods

#### `collect(self) -> AssetCollection`

Collect all EKS resources.

**Returns:**

`AssetCollection` - Collection of EKS assets
