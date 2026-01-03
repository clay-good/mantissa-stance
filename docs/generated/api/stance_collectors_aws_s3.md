# stance.collectors.aws_s3

AWS S3 collector for Mantissa Stance.

Collects S3 bucket resources and configuration for security posture assessment.

## Contents

### Classes

- [S3Collector](#s3collector)

## S3Collector

**Inherits from:** BaseCollector

Collects AWS S3 bucket resources and configuration.

Gathers bucket encryption, public access settings, policies,
ACLs, versioning, logging, and tags. All API calls are read-only.

### Methods

#### `collect(self) -> AssetCollection`

Collect all S3 buckets with their configurations.

**Returns:**

`AssetCollection` - Collection of S3 bucket assets
