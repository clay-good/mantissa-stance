# stance.collectors.aws_lambda

AWS Lambda collector for Mantissa Stance.

Collects Lambda functions, layers, and their configurations
for security posture assessment.

## Contents

### Classes

- [LambdaCollector](#lambdacollector)

## Constants

### `DEPRECATED_RUNTIMES`

Type: `str`

Value: `"Set(elts=[Constant(value='python2.7'), Constant(value='python3.6'), Constant(value='nodejs8.10'), Constant(value='nodejs10.x'), Constant(value='dotnetcore2.1'), Constant(value='ruby2.5'), Constant(value='java8')])"`

### `EOL_APPROACHING_RUNTIMES`

Type: `str`

Value: `"Set(elts=[Constant(value='nodejs12.x'), Constant(value='nodejs14.x'), Constant(value='python3.7'), Constant(value='python3.8'), Constant(value='dotnetcore3.1'), Constant(value='ruby2.7')])"`

## LambdaCollector

**Inherits from:** BaseCollector

Collects AWS Lambda functions, layers, and configurations.

Gathers Lambda functions with their security configurations including
VPC settings, environment variables (names only, not values),
execution roles, and resource policies. All API calls are read-only.

### Methods

#### `collect(self) -> AssetCollection`

Collect all Lambda resources.

**Returns:**

`AssetCollection` - Collection of Lambda assets
