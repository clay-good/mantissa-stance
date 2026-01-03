# stance.collectors.aws_apigateway

AWS API Gateway collector for Mantissa Stance.

Collects API Gateway REST APIs (v1), HTTP APIs (v2), and WebSocket APIs
for security posture assessment.

## Contents

### Classes

- [APIGatewayCollector](#apigatewaycollector)

## APIGatewayCollector

**Inherits from:** BaseCollector

Collects AWS API Gateway resources and configurations.

Gathers API Gateway REST APIs, HTTP APIs, and WebSocket APIs with their
security configurations including:
- API endpoint types (EDGE, REGIONAL, PRIVATE)
- Authorization settings (IAM, Cognito, Lambda authorizers)
- WAF associations
- Resource policies
- Stage configurations
- Throttling settings
- Client certificates
- VPC endpoint associations

All API calls are read-only.

### Methods

#### `collect(self) -> AssetCollection`

Collect all API Gateway resources.

**Returns:**

`AssetCollection` - Collection of API Gateway assets
