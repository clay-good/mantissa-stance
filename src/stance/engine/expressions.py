"""
Expression evaluator for Mantissa Stance policy engine.

Provides safe evaluation of boolean expressions against resource data
without using eval() or other dangerous constructs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any


class TokenType(Enum):
    """Token types for expression parsing."""

    # Literals
    STRING = auto()
    NUMBER = auto()
    TRUE = auto()
    FALSE = auto()
    NULL = auto()

    # Identifiers and paths
    IDENTIFIER = auto()

    # Operators
    EQ = auto()  # ==
    NE = auto()  # !=
    GT = auto()  # >
    LT = auto()  # <
    GE = auto()  # >=
    LE = auto()  # <=
    IN = auto()  # in
    NOT_IN = auto()  # not_in
    CONTAINS = auto()  # contains
    STARTS_WITH = auto()  # starts_with
    ENDS_WITH = auto()  # ends_with
    MATCHES = auto()  # matches
    EXISTS = auto()  # exists
    NOT_EXISTS = auto()  # not_exists

    # Boolean operators
    AND = auto()
    OR = auto()
    NOT = auto()

    # Grouping
    LPAREN = auto()
    RPAREN = auto()

    # End of expression
    EOF = auto()


@dataclass
class Token:
    """Represents a token in the expression."""

    token_type: TokenType
    value: Any
    position: int


@dataclass
class ASTNode:
    """Base class for AST nodes."""

    pass


@dataclass
class LiteralNode(ASTNode):
    """Literal value node."""

    value: Any


@dataclass
class PathNode(ASTNode):
    """Path access node (e.g., resource.field.subfield)."""

    path: str


@dataclass
class UnaryOpNode(ASTNode):
    """Unary operator node (not, exists, not_exists)."""

    operator: str
    operand: ASTNode


@dataclass
class BinaryOpNode(ASTNode):
    """Binary operator node."""

    operator: str
    left: ASTNode
    right: ASTNode


@dataclass
class ExistsNode(ASTNode):
    """Existence check node."""

    path: str
    negate: bool = False


class ExpressionError(Exception):
    """Exception raised for expression parsing or evaluation errors."""

    def __init__(self, message: str, position: int = -1):
        self.position = position
        super().__init__(f"{message}" + (f" at position {position}" if position >= 0 else ""))


class ExpressionEvaluator:
    """
    Evaluates simple boolean expressions against resource data.

    Supports path access, comparison operators, membership tests,
    string operations, existence checks, and boolean logic.

    All evaluation is done safely without using eval() or exec().
    """

    # Keywords that map to token types
    KEYWORDS = {
        "true": TokenType.TRUE,
        "false": TokenType.FALSE,
        "null": TokenType.NULL,
        "and": TokenType.AND,
        "or": TokenType.OR,
        "not": TokenType.NOT,
        "in": TokenType.IN,
        "not_in": TokenType.NOT_IN,
        "contains": TokenType.CONTAINS,
        "starts_with": TokenType.STARTS_WITH,
        "ends_with": TokenType.ENDS_WITH,
        "matches": TokenType.MATCHES,
        "exists": TokenType.EXISTS,
        "not_exists": TokenType.NOT_EXISTS,
    }

    # Operator precedence (higher = binds tighter)
    PRECEDENCE = {
        "or": 1,
        "and": 2,
        "not": 3,
        "==": 4,
        "!=": 4,
        ">": 4,
        "<": 4,
        ">=": 4,
        "<=": 4,
        "in": 4,
        "not_in": 4,
        "contains": 4,
        "starts_with": 4,
        "ends_with": 4,
        "matches": 4,
        "exists": 5,
        "not_exists": 5,
    }

    def evaluate(self, expression: str, context: dict[str, Any]) -> bool:
        """
        Evaluate expression against context.

        Args:
            expression: Boolean expression string
            context: Dictionary with 'resource' key containing asset data

        Returns:
            True if expression evaluates to true

        Raises:
            ExpressionError: If expression is invalid
        """
        if not expression or not expression.strip():
            raise ExpressionError("Empty expression")

        tokens = self._tokenize(expression)
        ast = self._parse(tokens)
        result = self._eval_node(ast, context)

        return bool(result)

    def validate(self, expression: str) -> list[str]:
        """
        Validate expression syntax without evaluating.

        Args:
            expression: Expression string to validate

        Returns:
            List of errors (empty if valid)
        """
        errors: list[str] = []

        if not expression or not expression.strip():
            errors.append("Empty expression")
            return errors

        try:
            tokens = self._tokenize(expression)
            self._parse(tokens)
        except ExpressionError as e:
            errors.append(str(e))
        except Exception as e:
            errors.append(f"Unexpected error: {e}")

        return errors

    def _tokenize(self, expression: str) -> list[Token]:
        """
        Tokenize the expression string.

        Args:
            expression: Expression to tokenize

        Returns:
            List of tokens
        """
        tokens: list[Token] = []
        pos = 0
        length = len(expression)

        while pos < length:
            # Skip whitespace
            while pos < length and expression[pos].isspace():
                pos += 1

            if pos >= length:
                break

            start_pos = pos
            char = expression[pos]

            # String literal (single or double quotes)
            if char in ('"', "'"):
                quote = char
                pos += 1
                value = ""
                while pos < length and expression[pos] != quote:
                    if expression[pos] == "\\" and pos + 1 < length:
                        pos += 1
                        escape_char = expression[pos]
                        if escape_char == "n":
                            value += "\n"
                        elif escape_char == "t":
                            value += "\t"
                        else:
                            value += escape_char
                    else:
                        value += expression[pos]
                    pos += 1
                if pos >= length:
                    raise ExpressionError(f"Unterminated string", start_pos)
                pos += 1  # Skip closing quote
                tokens.append(Token(TokenType.STRING, value, start_pos))

            # Number
            elif char.isdigit() or (char == "-" and pos + 1 < length and expression[pos + 1].isdigit()):
                while pos < length and (expression[pos].isdigit() or expression[pos] in ".-"):
                    pos += 1
                value_str = expression[start_pos:pos]
                try:
                    if "." in value_str:
                        value = float(value_str)
                    else:
                        value = int(value_str)
                    tokens.append(Token(TokenType.NUMBER, value, start_pos))
                except ValueError:
                    raise ExpressionError(f"Invalid number: {value_str}", start_pos)

            # Operators
            elif char == "=" and pos + 1 < length and expression[pos + 1] == "=":
                tokens.append(Token(TokenType.EQ, "==", pos))
                pos += 2
            elif char == "!" and pos + 1 < length and expression[pos + 1] == "=":
                tokens.append(Token(TokenType.NE, "!=", pos))
                pos += 2
            elif char == ">" and pos + 1 < length and expression[pos + 1] == "=":
                tokens.append(Token(TokenType.GE, ">=", pos))
                pos += 2
            elif char == "<" and pos + 1 < length and expression[pos + 1] == "=":
                tokens.append(Token(TokenType.LE, "<=", pos))
                pos += 2
            elif char == ">":
                tokens.append(Token(TokenType.GT, ">", pos))
                pos += 1
            elif char == "<":
                tokens.append(Token(TokenType.LT, "<", pos))
                pos += 1
            elif char == "(":
                tokens.append(Token(TokenType.LPAREN, "(", pos))
                pos += 1
            elif char == ")":
                tokens.append(Token(TokenType.RPAREN, ")", pos))
                pos += 1

            # Identifier or keyword
            elif char.isalpha() or char == "_":
                while pos < length and (expression[pos].isalnum() or expression[pos] in "_."):
                    pos += 1
                ident = expression[start_pos:pos]
                lower_ident = ident.lower()

                if lower_ident in self.KEYWORDS:
                    tokens.append(Token(self.KEYWORDS[lower_ident], lower_ident, start_pos))
                else:
                    tokens.append(Token(TokenType.IDENTIFIER, ident, start_pos))

            else:
                raise ExpressionError(f"Unexpected character: {char}", pos)

        tokens.append(Token(TokenType.EOF, None, pos))
        return tokens

    def _parse(self, tokens: list[Token]) -> ASTNode:
        """
        Parse tokens into an AST.

        Args:
            tokens: List of tokens

        Returns:
            Root AST node
        """
        self._tokens = tokens
        self._pos = 0

        result = self._parse_or()

        if self._current().token_type != TokenType.EOF:
            raise ExpressionError(
                f"Unexpected token: {self._current().value}",
                self._current().position,
            )

        return result

    def _current(self) -> Token:
        """Get current token."""
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        """Advance to next token and return previous."""
        token = self._current()
        if self._pos < len(self._tokens) - 1:
            self._pos += 1
        return token

    def _parse_or(self) -> ASTNode:
        """Parse OR expressions."""
        left = self._parse_and()

        while self._current().token_type == TokenType.OR:
            self._advance()
            right = self._parse_and()
            left = BinaryOpNode("or", left, right)

        return left

    def _parse_and(self) -> ASTNode:
        """Parse AND expressions."""
        left = self._parse_not()

        while self._current().token_type == TokenType.AND:
            self._advance()
            right = self._parse_not()
            left = BinaryOpNode("and", left, right)

        return left

    def _parse_not(self) -> ASTNode:
        """Parse NOT expressions."""
        if self._current().token_type == TokenType.NOT:
            self._advance()
            operand = self._parse_not()
            return UnaryOpNode("not", operand)

        return self._parse_comparison()

    def _parse_comparison(self) -> ASTNode:
        """Parse comparison expressions."""
        left = self._parse_primary()

        # Handle existence checks (unary postfix)
        if self._current().token_type == TokenType.EXISTS:
            self._advance()
            if isinstance(left, PathNode):
                return ExistsNode(left.path, negate=False)
            raise ExpressionError("exists operator requires a path", self._current().position)

        if self._current().token_type == TokenType.NOT_EXISTS:
            self._advance()
            if isinstance(left, PathNode):
                return ExistsNode(left.path, negate=True)
            raise ExpressionError("not_exists operator requires a path", self._current().position)

        # Handle binary comparison operators
        op_map = {
            TokenType.EQ: "==",
            TokenType.NE: "!=",
            TokenType.GT: ">",
            TokenType.LT: "<",
            TokenType.GE: ">=",
            TokenType.LE: "<=",
            TokenType.IN: "in",
            TokenType.NOT_IN: "not_in",
            TokenType.CONTAINS: "contains",
            TokenType.STARTS_WITH: "starts_with",
            TokenType.ENDS_WITH: "ends_with",
            TokenType.MATCHES: "matches",
        }

        if self._current().token_type in op_map:
            op = op_map[self._current().token_type]
            self._advance()
            right = self._parse_primary()
            return BinaryOpNode(op, left, right)

        return left

    def _parse_primary(self) -> ASTNode:
        """Parse primary expressions (literals, paths, parenthesized)."""
        token = self._current()

        if token.token_type == TokenType.LPAREN:
            self._advance()
            expr = self._parse_or()
            if self._current().token_type != TokenType.RPAREN:
                raise ExpressionError("Expected closing parenthesis", self._current().position)
            self._advance()
            return expr

        if token.token_type == TokenType.STRING:
            self._advance()
            return LiteralNode(token.value)

        if token.token_type == TokenType.NUMBER:
            self._advance()
            return LiteralNode(token.value)

        if token.token_type == TokenType.TRUE:
            self._advance()
            return LiteralNode(True)

        if token.token_type == TokenType.FALSE:
            self._advance()
            return LiteralNode(False)

        if token.token_type == TokenType.NULL:
            self._advance()
            return LiteralNode(None)

        if token.token_type == TokenType.IDENTIFIER:
            self._advance()
            return PathNode(token.value)

        raise ExpressionError(f"Unexpected token: {token.value}", token.position)

    def _eval_node(self, node: ASTNode, context: dict[str, Any]) -> Any:
        """
        Evaluate an AST node.

        Args:
            node: AST node to evaluate
            context: Evaluation context

        Returns:
            Evaluation result
        """
        if isinstance(node, LiteralNode):
            return node.value

        if isinstance(node, PathNode):
            return self._get_path_value(node.path, context)

        if isinstance(node, ExistsNode):
            try:
                value = self._get_path_value(node.path, context)
                exists = value is not None
            except (KeyError, TypeError):
                exists = False
            return not exists if node.negate else exists

        if isinstance(node, UnaryOpNode):
            if node.operator == "not":
                return not self._eval_node(node.operand, context)
            raise ExpressionError(f"Unknown unary operator: {node.operator}")

        if isinstance(node, BinaryOpNode):
            left = self._eval_node(node.left, context)
            right = self._eval_node(node.right, context)
            return self._compare(left, node.operator, right)

        raise ExpressionError(f"Unknown node type: {type(node)}")

    def _get_path_value(self, path: str, context: dict[str, Any]) -> Any:
        """
        Get value at path from context.

        Args:
            path: Dot-separated path (e.g., "resource.field.subfield")
            context: Context dictionary

        Returns:
            Value at path

        Raises:
            ExpressionError: If path is invalid
        """
        parts = path.split(".")
        value: Any = context

        for part in parts:
            if isinstance(value, dict):
                if part not in value:
                    return None
                value = value[part]
            elif hasattr(value, part):
                value = getattr(value, part)
            else:
                return None

        return value

    def _compare(self, left: Any, operator: str, right: Any) -> bool:
        """
        Perform comparison operation.

        Args:
            left: Left operand
            operator: Comparison operator
            right: Right operand

        Returns:
            Comparison result
        """
        try:
            if operator == "==":
                return left == right
            elif operator == "!=":
                return left != right
            elif operator == ">":
                return left > right
            elif operator == "<":
                return left < right
            elif operator == ">=":
                return left >= right
            elif operator == "<=":
                return left <= right
            elif operator == "in":
                if isinstance(right, (list, tuple, set)):
                    return left in right
                elif isinstance(right, str):
                    return str(left) in right
                return False
            elif operator == "not_in":
                if isinstance(right, (list, tuple, set)):
                    return left not in right
                elif isinstance(right, str):
                    return str(left) not in right
                return True
            elif operator == "contains":
                if isinstance(left, (list, tuple, set)):
                    return right in left
                elif isinstance(left, str):
                    return str(right) in left
                return False
            elif operator == "starts_with":
                if isinstance(left, str) and isinstance(right, str):
                    return left.startswith(right)
                return False
            elif operator == "ends_with":
                if isinstance(left, str) and isinstance(right, str):
                    return left.endswith(right)
                return False
            elif operator == "matches":
                if isinstance(left, str) and isinstance(right, str):
                    try:
                        return bool(re.search(right, left))
                    except re.error:
                        raise ExpressionError(f"Invalid regex pattern: {right}")
                return False
            elif operator == "and":
                return bool(left) and bool(right)
            elif operator == "or":
                return bool(left) or bool(right)
            else:
                raise ExpressionError(f"Unknown operator: {operator}")

        except TypeError as e:
            raise ExpressionError(f"Type error in comparison: {e}")
