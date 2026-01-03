# stance.collectors.aws_rds

AWS RDS collector for Mantissa Stance.

Collects RDS database instances, clusters, and their configurations
for security posture assessment.

## Contents

### Classes

- [RDSCollector](#rdscollector)

## RDSCollector

**Inherits from:** BaseCollector

Collects AWS RDS database instances, clusters, and related configurations.

Gathers RDS instances, Aurora clusters, parameter groups, subnet groups,
and security configurations. All API calls are read-only.

### Methods

#### `collect(self) -> AssetCollection`

Collect all RDS resources.

**Returns:**

`AssetCollection` - Collection of RDS assets
