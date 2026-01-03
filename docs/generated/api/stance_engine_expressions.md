# stance.engine.expressions

Expression evaluator for Mantissa Stance policy engine.

Provides safe evaluation of boolean expressions against resource data
without using eval() or other dangerous constructs.

## Contents

### Classes

- [TokenType](#tokentype)
- [Token](#token)
- [ASTNode](#astnode)
- [LiteralNode](#literalnode)
- [PathNode](#pathnode)
- [UnaryOpNode](#unaryopnode)
- [BinaryOpNode](#binaryopnode)
- [ExistsNode](#existsnode)
- [ExpressionError](#expressionerror)
- [ExpressionEvaluator](#expressionevaluator)

## TokenType

**Inherits from:** Enum

Token types for expression parsing.

## Token

**Tags:** dataclass

Represents a token in the expression.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `token_type` | `TokenType` | - |
| `value` | `Any` | - |
| `position` | `int` | - |

## ASTNode

**Tags:** dataclass

Base class for AST nodes.

## LiteralNode

**Inherits from:** ASTNode

**Tags:** dataclass

Literal value node.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `value` | `Any` | - |

## PathNode

**Inherits from:** ASTNode

**Tags:** dataclass

Path access node (e.g., resource.field.subfield).

### Attributes

| Name | Type | Default |
|------|------|---------|
| `path` | `str` | - |

## UnaryOpNode

**Inherits from:** ASTNode

**Tags:** dataclass

Unary operator node (not, exists, not_exists).

### Attributes

| Name | Type | Default |
|------|------|---------|
| `operator` | `str` | - |
| `operand` | `ASTNode` | - |

## BinaryOpNode

**Inherits from:** ASTNode

**Tags:** dataclass

Binary operator node.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `operator` | `str` | - |
| `left` | `ASTNode` | - |
| `right` | `ASTNode` | - |

## ExistsNode

**Inherits from:** ASTNode

**Tags:** dataclass

Existence check node.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `path` | `str` | - |
| `negate` | `bool` | `False` |

## ExpressionError

**Inherits from:** Exception

Exception raised for expression parsing or evaluation errors.

### Methods

#### `__init__(self, message: str, position: int = 'UnaryOp(op=USub(), operand=Constant(value=1))')`

**Parameters:**

- `message` (`str`)
- `position` (`int`) - default: `'UnaryOp(op=USub(), operand=Constant(value=1))'`

## ExpressionEvaluator

Evaluates simple boolean expressions against resource data.

Supports path access, comparison operators, membership tests,
string operations, existence checks, and boolean logic.

All evaluation is done safely without using eval() or exec().

### Methods

#### `evaluate(self, expression: str, context: dict[(str, Any)]) -> bool`

Evaluate expression against context.

**Parameters:**

- `expression` (`str`) - Boolean expression string
- `context` (`dict[(str, Any)]`) - Dictionary with 'resource' key containing asset data

**Returns:**

`bool` - True if expression evaluates to true

**Raises:**

- `ExpressionError`: If expression is invalid

#### `validate(self, expression: str) -> list[str]`

Validate expression syntax without evaluating.

**Parameters:**

- `expression` (`str`) - Expression string to validate

**Returns:**

`list[str]` - List of errors (empty if valid)
