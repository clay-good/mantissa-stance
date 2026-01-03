# stance.collectors.aws_dynamodb

AWS DynamoDB collector for Mantissa Stance.

Collects DynamoDB tables, global tables, and their configurations
for security posture assessment.

## Contents

### Classes

- [DynamoDBCollector](#dynamodbcollector)

## DynamoDBCollector

**Inherits from:** BaseCollector

Collects AWS DynamoDB tables and related configurations.

Gathers DynamoDB tables, global tables, backups, and security configurations.
All API calls are read-only.

### Methods

#### `collect(self) -> AssetCollection`

Collect all DynamoDB resources.

**Returns:**

`AssetCollection` - Collection of DynamoDB assets
