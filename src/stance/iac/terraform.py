"""
Terraform HCL parser for Mantissa Stance.

Provides parsing of Terraform (.tf) files without external dependencies.
This is a minimal HCL parser that handles the core syntax needed for
security policy evaluation.

Supported HCL constructs:
- resource blocks
- data blocks
- variable blocks
- output blocks
- locals blocks
- module blocks
- provider blocks
- Nested blocks and attributes
- String interpolation (parsed but not evaluated)
- Comments (single-line # and //, multi-line /* */)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Iterator

from stance.iac.base import (
    IaCFile,
    IaCFormat,
    IaCLocation,
    IaCParser,
    IaCResource,
)

logger = logging.getLogger(__name__)


class TokenType(Enum):
    """Token types for HCL lexer."""

    IDENTIFIER = auto()
    STRING = auto()
    NUMBER = auto()
    BOOL = auto()
    NULL = auto()
    LBRACE = auto()
    RBRACE = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    LPAREN = auto()
    RPAREN = auto()
    EQUALS = auto()
    COMMA = auto()
    DOT = auto()
    COLON = auto()
    NEWLINE = auto()
    HEREDOC = auto()
    COMMENT = auto()
    EOF = auto()


@dataclass
class Token:
    """A lexer token."""

    type: TokenType
    value: Any
    line: int
    column: int


class HCLLexer:
    """
    Lexer for HCL (HashiCorp Configuration Language).

    Tokenizes HCL content into a stream of tokens for parsing.
    """

    def __init__(self, content: str) -> None:
        """Initialize the lexer with content."""
        self._content = content
        self._pos = 0
        self._line = 1
        self._column = 1
        self._tokens: list[Token] = []

    def tokenize(self) -> list[Token]:
        """Tokenize the content and return list of tokens."""
        while self._pos < len(self._content):
            self._skip_whitespace_and_comments()
            if self._pos >= len(self._content):
                break

            char = self._current()

            if char == "\n":
                self._tokens.append(Token(TokenType.NEWLINE, "\n", self._line, self._column))
                self._advance()
                continue

            if char == "{":
                self._tokens.append(Token(TokenType.LBRACE, "{", self._line, self._column))
                self._advance()
            elif char == "}":
                self._tokens.append(Token(TokenType.RBRACE, "}", self._line, self._column))
                self._advance()
            elif char == "[":
                self._tokens.append(Token(TokenType.LBRACKET, "[", self._line, self._column))
                self._advance()
            elif char == "]":
                self._tokens.append(Token(TokenType.RBRACKET, "]", self._line, self._column))
                self._advance()
            elif char == "(":
                self._tokens.append(Token(TokenType.LPAREN, "(", self._line, self._column))
                self._advance()
            elif char == ")":
                self._tokens.append(Token(TokenType.RPAREN, ")", self._line, self._column))
                self._advance()
            elif char == "=":
                self._tokens.append(Token(TokenType.EQUALS, "=", self._line, self._column))
                self._advance()
            elif char == ",":
                self._tokens.append(Token(TokenType.COMMA, ",", self._line, self._column))
                self._advance()
            elif char == ".":
                self._tokens.append(Token(TokenType.DOT, ".", self._line, self._column))
                self._advance()
            elif char == ":":
                self._tokens.append(Token(TokenType.COLON, ":", self._line, self._column))
                self._advance()
            elif char == '"':
                self._read_string()
            elif char == "<" and self._peek(1) == "<":
                self._read_heredoc()
            elif char.isdigit() or (char == "-" and self._peek(1).isdigit()):
                self._read_number()
            elif char.isalpha() or char == "_":
                self._read_identifier()
            else:
                # Skip unknown characters
                self._advance()

        self._tokens.append(Token(TokenType.EOF, None, self._line, self._column))
        return self._tokens

    def _current(self) -> str:
        """Get current character."""
        if self._pos < len(self._content):
            return self._content[self._pos]
        return ""

    def _peek(self, offset: int = 1) -> str:
        """Peek ahead at characters."""
        pos = self._pos + offset
        if pos < len(self._content):
            return self._content[pos]
        return ""

    def _advance(self) -> str:
        """Advance position and return current character."""
        char = self._current()
        self._pos += 1
        if char == "\n":
            self._line += 1
            self._column = 1
        else:
            self._column += 1
        return char

    def _skip_whitespace_and_comments(self) -> None:
        """Skip whitespace and comments."""
        while self._pos < len(self._content):
            char = self._current()

            if char in " \t\r":
                self._advance()
            elif char == "#":
                self._skip_line_comment()
            elif char == "/" and self._peek(1) == "/":
                self._skip_line_comment()
            elif char == "/" and self._peek(1) == "*":
                self._skip_block_comment()
            else:
                break

    def _skip_line_comment(self) -> None:
        """Skip a line comment."""
        while self._current() and self._current() != "\n":
            self._advance()

    def _skip_block_comment(self) -> None:
        """Skip a block comment /* ... */."""
        self._advance()  # /
        self._advance()  # *
        while self._pos < len(self._content):
            if self._current() == "*" and self._peek(1) == "/":
                self._advance()  # *
                self._advance()  # /
                break
            self._advance()

    def _read_string(self) -> None:
        """Read a quoted string."""
        line = self._line
        column = self._column
        self._advance()  # Opening quote

        value = ""
        while self._current() and self._current() != '"':
            if self._current() == "\\" and self._peek(1):
                self._advance()
                escape_char = self._advance()
                if escape_char == "n":
                    value += "\n"
                elif escape_char == "t":
                    value += "\t"
                elif escape_char == "r":
                    value += "\r"
                elif escape_char == '"':
                    value += '"'
                elif escape_char == "\\":
                    value += "\\"
                else:
                    value += escape_char
            else:
                value += self._advance()

        if self._current() == '"':
            self._advance()  # Closing quote

        self._tokens.append(Token(TokenType.STRING, value, line, column))

    def _read_heredoc(self) -> None:
        """Read a heredoc string <<EOF ... EOF."""
        line = self._line
        column = self._column

        self._advance()  # <
        self._advance()  # <

        # Check for indented heredoc <<-
        indented = False
        if self._current() == "-":
            indented = True
            self._advance()

        # Read delimiter
        delimiter = ""
        while self._current() and self._current() not in "\n\r":
            delimiter += self._advance()
        delimiter = delimiter.strip()

        if self._current() == "\n":
            self._advance()

        # Read content until delimiter
        value = ""
        while self._pos < len(self._content):
            line_start = self._pos
            line_content = ""
            while self._current() and self._current() != "\n":
                line_content += self._advance()

            stripped = line_content.strip() if indented else line_content

            if stripped == delimiter:
                break

            if indented:
                # Remove leading whitespace for indented heredocs
                line_content = line_content.lstrip()

            value += line_content
            if self._current() == "\n":
                value += self._advance()

        self._tokens.append(Token(TokenType.HEREDOC, value.rstrip("\n"), line, column))

    def _read_number(self) -> None:
        """Read a number (int or float)."""
        line = self._line
        column = self._column
        value = ""

        if self._current() == "-":
            value += self._advance()

        while self._current() and (self._current().isdigit() or self._current() in ".eE+-"):
            value += self._advance()

        # Parse as int or float
        try:
            if "." in value or "e" in value.lower():
                num_value = float(value)
            else:
                num_value = int(value)
            self._tokens.append(Token(TokenType.NUMBER, num_value, line, column))
        except ValueError:
            self._tokens.append(Token(TokenType.IDENTIFIER, value, line, column))

    def _read_identifier(self) -> None:
        """Read an identifier or keyword."""
        line = self._line
        column = self._column
        value = ""

        while self._current() and (self._current().isalnum() or self._current() in "_-"):
            value += self._advance()

        # Check for boolean and null keywords
        if value == "true":
            self._tokens.append(Token(TokenType.BOOL, True, line, column))
        elif value == "false":
            self._tokens.append(Token(TokenType.BOOL, False, line, column))
        elif value == "null":
            self._tokens.append(Token(TokenType.NULL, None, line, column))
        else:
            self._tokens.append(Token(TokenType.IDENTIFIER, value, line, column))


class HCLParser:
    """
    Parser for HCL (HashiCorp Configuration Language).

    Parses tokenized HCL content into an AST-like structure.
    """

    def __init__(self, tokens: list[Token]) -> None:
        """Initialize the parser with tokens."""
        self._tokens = tokens
        self._pos = 0
        self._errors: list[str] = []

    def parse(self) -> dict[str, Any]:
        """
        Parse tokens into a structured dictionary.

        Returns:
            Dictionary with parsed HCL structure
        """
        result: dict[str, Any] = {
            "resource": {},
            "data": {},
            "variable": {},
            "output": {},
            "locals": {},
            "module": {},
            "provider": {},
            "terraform": {},
        }

        while not self._is_at_end():
            self._skip_newlines()
            if self._is_at_end():
                break

            try:
                block = self._parse_block()
                if block:
                    block_type, block_data = block
                    if block_type in result:
                        if isinstance(result[block_type], dict):
                            self._deep_merge(result[block_type], block_data)
                        else:
                            result[block_type] = block_data
            except Exception as e:
                self._errors.append(f"Parse error at line {self._current().line}: {e}")
                self._skip_to_next_block()

        return result

    @property
    def errors(self) -> list[str]:
        """Get parsing errors."""
        return self._errors

    def _current(self) -> Token:
        """Get current token."""
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return Token(TokenType.EOF, None, 0, 0)

    def _peek(self, offset: int = 1) -> Token:
        """Peek at future tokens."""
        pos = self._pos + offset
        if pos < len(self._tokens):
            return self._tokens[pos]
        return Token(TokenType.EOF, None, 0, 0)

    def _advance(self) -> Token:
        """Advance to next token and return current."""
        token = self._current()
        self._pos += 1
        return token

    def _is_at_end(self) -> bool:
        """Check if at end of tokens."""
        return self._current().type == TokenType.EOF

    def _skip_newlines(self) -> None:
        """Skip newline tokens."""
        while self._current().type == TokenType.NEWLINE:
            self._advance()

    def _skip_to_next_block(self) -> None:
        """Skip to the next top-level block after an error."""
        depth = 0
        while not self._is_at_end():
            if self._current().type == TokenType.LBRACE:
                depth += 1
            elif self._current().type == TokenType.RBRACE:
                depth -= 1
                if depth <= 0:
                    self._advance()
                    self._skip_newlines()
                    break
            self._advance()

    def _deep_merge(self, target: dict[str, Any], source: dict[str, Any]) -> None:
        """Deep merge source dict into target dict."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value

    def _expect(self, token_type: TokenType) -> Token:
        """Expect a specific token type."""
        if self._current().type != token_type:
            raise ValueError(f"Expected {token_type}, got {self._current().type}")
        return self._advance()

    def _parse_block(self) -> tuple[str, dict[str, Any]] | None:
        """Parse a top-level block."""
        if self._current().type != TokenType.IDENTIFIER:
            self._advance()
            return None

        block_type = self._advance().value

        # Collect block labels
        labels: list[str] = []
        while self._current().type in (TokenType.IDENTIFIER, TokenType.STRING):
            labels.append(self._advance().value)

        self._skip_newlines()

        # Expect opening brace
        if self._current().type != TokenType.LBRACE:
            return None

        self._advance()  # {
        self._skip_newlines()

        # Parse block body
        body = self._parse_body()

        # Expect closing brace
        if self._current().type == TokenType.RBRACE:
            self._advance()

        self._skip_newlines()

        # Structure the result based on block type
        if block_type == "resource" and len(labels) >= 2:
            resource_type = labels[0]
            resource_name = labels[1]
            return (block_type, {resource_type: {resource_name: body}})
        elif block_type == "data" and len(labels) >= 2:
            data_type = labels[0]
            data_name = labels[1]
            return (block_type, {data_type: {data_name: body}})
        elif block_type == "variable" and len(labels) >= 1:
            var_name = labels[0]
            return (block_type, {var_name: body})
        elif block_type == "output" and len(labels) >= 1:
            output_name = labels[0]
            return (block_type, {output_name: body})
        elif block_type == "module" and len(labels) >= 1:
            module_name = labels[0]
            return (block_type, {module_name: body})
        elif block_type == "provider" and len(labels) >= 1:
            provider_name = labels[0]
            return (block_type, {provider_name: body})
        elif block_type == "locals":
            return (block_type, body)
        elif block_type == "terraform":
            return (block_type, body)
        else:
            # Generic block
            if labels:
                return (block_type, {".".join(labels): body})
            return (block_type, body)

    def _parse_body(self) -> dict[str, Any]:
        """Parse a block body (between braces)."""
        body: dict[str, Any] = {}

        while not self._is_at_end() and self._current().type != TokenType.RBRACE:
            self._skip_newlines()
            if self._current().type == TokenType.RBRACE:
                break

            if self._current().type == TokenType.IDENTIFIER:
                key = self._advance().value

                # Check if this is a nested block or an attribute
                self._skip_newlines()

                if self._current().type == TokenType.EQUALS:
                    # Attribute assignment
                    self._advance()  # =
                    self._skip_newlines()
                    value = self._parse_value()
                    body[key] = value
                elif self._current().type == TokenType.LBRACE:
                    # Nested block without labels
                    self._advance()  # {
                    self._skip_newlines()
                    nested_body = self._parse_body()
                    if self._current().type == TokenType.RBRACE:
                        self._advance()

                    # Merge or append to existing
                    if key in body:
                        if isinstance(body[key], list):
                            body[key].append(nested_body)
                        else:
                            body[key] = [body[key], nested_body]
                    else:
                        body[key] = nested_body
                elif self._current().type in (TokenType.IDENTIFIER, TokenType.STRING):
                    # Nested block with label(s)
                    labels = []
                    while self._current().type in (TokenType.IDENTIFIER, TokenType.STRING):
                        labels.append(self._advance().value)

                    self._skip_newlines()

                    if self._current().type == TokenType.LBRACE:
                        self._advance()  # {
                        self._skip_newlines()
                        nested_body = self._parse_body()
                        if self._current().type == TokenType.RBRACE:
                            self._advance()

                        # Store with labels as key
                        label_key = ".".join(labels) if labels else "default"
                        if key not in body:
                            body[key] = {}
                        if isinstance(body[key], dict):
                            body[key][label_key] = nested_body
                else:
                    # Skip unknown construct
                    self._advance()
            else:
                self._advance()

            self._skip_newlines()

        return body

    def _parse_value(self) -> Any:
        """Parse a value (string, number, bool, list, object, expression)."""
        token = self._current()

        if token.type == TokenType.STRING:
            return self._advance().value
        elif token.type == TokenType.HEREDOC:
            return self._advance().value
        elif token.type == TokenType.NUMBER:
            return self._advance().value
        elif token.type == TokenType.BOOL:
            return self._advance().value
        elif token.type == TokenType.NULL:
            self._advance()
            return None
        elif token.type == TokenType.LBRACKET:
            return self._parse_list()
        elif token.type == TokenType.LBRACE:
            return self._parse_object()
        elif token.type == TokenType.IDENTIFIER:
            return self._parse_expression()
        else:
            self._advance()
            return None

    def _parse_list(self) -> list[Any]:
        """Parse a list [...]."""
        self._advance()  # [
        self._skip_newlines()

        items: list[Any] = []
        while not self._is_at_end() and self._current().type != TokenType.RBRACKET:
            value = self._parse_value()
            items.append(value)

            self._skip_newlines()
            if self._current().type == TokenType.COMMA:
                self._advance()
            self._skip_newlines()

        if self._current().type == TokenType.RBRACKET:
            self._advance()

        return items

    def _parse_object(self) -> dict[str, Any]:
        """Parse an object {...}."""
        self._advance()  # {
        self._skip_newlines()

        obj: dict[str, Any] = {}
        while not self._is_at_end() and self._current().type != TokenType.RBRACE:
            if self._current().type in (TokenType.IDENTIFIER, TokenType.STRING):
                key = self._advance().value

                self._skip_newlines()

                # Handle both = and : for object key-value pairs
                if self._current().type in (TokenType.EQUALS, TokenType.COLON):
                    self._advance()
                    self._skip_newlines()
                    value = self._parse_value()
                    obj[key] = value

            self._skip_newlines()
            if self._current().type == TokenType.COMMA:
                self._advance()
            self._skip_newlines()

        if self._current().type == TokenType.RBRACE:
            self._advance()

        return obj

    def _parse_expression(self) -> Any:
        """Parse an expression (variable reference, function call, etc.)."""
        # Start collecting the expression as a string
        parts: list[str] = []

        while not self._is_at_end():
            token = self._current()

            if token.type == TokenType.IDENTIFIER:
                parts.append(self._advance().value)
            elif token.type == TokenType.DOT:
                parts.append(self._advance().value)
            elif token.type == TokenType.LBRACKET:
                # Index access
                self._advance()
                parts.append("[")
                if self._current().type in (TokenType.NUMBER, TokenType.STRING):
                    parts.append(str(self._advance().value))
                elif self._current().type == TokenType.IDENTIFIER:
                    # Expression inside brackets
                    inner = self._parse_expression()
                    parts.append(str(inner))
                if self._current().type == TokenType.RBRACKET:
                    self._advance()
                parts.append("]")
            elif token.type == TokenType.LPAREN:
                # Function call
                self._advance()
                parts.append("(")
                args = []
                while not self._is_at_end() and self._current().type != TokenType.RPAREN:
                    arg = self._parse_value()
                    args.append(str(arg) if arg is not None else "")
                    if self._current().type == TokenType.COMMA:
                        self._advance()
                    self._skip_newlines()
                if self._current().type == TokenType.RPAREN:
                    self._advance()
                parts.append(",".join(args))
                parts.append(")")
            else:
                break

        return "".join(parts) if parts else None


@dataclass
class TerraformResource(IaCResource):
    """
    A Terraform resource with additional metadata.

    Extends IaCResource with Terraform-specific attributes.
    """

    # Terraform-specific fields can be added here
    pass


class TerraformParser(IaCParser):
    """
    Parser for Terraform (.tf) files.

    Parses HCL syntax and extracts resources, variables, outputs,
    and other Terraform constructs.
    """

    PROVIDER_PREFIXES = {
        "aws_": "aws",
        "azurerm_": "azure",
        "google_": "gcp",
        "kubernetes_": "kubernetes",
        "helm_": "kubernetes",
        "null_": "null",
        "random_": "random",
        "local_": "local",
        "template_": "template",
        "tls_": "tls",
        "oci_": "oci",
        "alicloud_": "alicloud",
        "digitalocean_": "digitalocean",
    }

    @property
    def format(self) -> IaCFormat:
        """Return Terraform format."""
        return IaCFormat.TERRAFORM

    @property
    def file_extensions(self) -> list[str]:
        """Return Terraform file extensions."""
        return [".tf"]

    def parse_file(self, file_path: str | Path) -> IaCFile:
        """
        Parse a Terraform file.

        Args:
            file_path: Path to the .tf file

        Returns:
            Parsed IaCFile object
        """
        path = Path(file_path)

        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            return IaCFile(
                file_path=str(path),
                format=IaCFormat.TERRAFORM,
                parse_errors=[f"Failed to read file: {e}"],
            )

        return self.parse_content(content, str(path))

    def parse_content(self, content: str, file_path: str = "<string>") -> IaCFile:
        """
        Parse Terraform content from a string.

        Args:
            content: The HCL content to parse
            file_path: Virtual file path for error reporting

        Returns:
            Parsed IaCFile object
        """
        iac_file = IaCFile(
            file_path=file_path,
            format=IaCFormat.TERRAFORM,
            raw_content=content,
        )

        try:
            # Tokenize
            lexer = HCLLexer(content)
            tokens = lexer.tokenize()

            # Parse
            parser = HCLParser(tokens)
            parsed = parser.parse()

            if parser.errors:
                iac_file.parse_errors.extend(parser.errors)

            # Extract resources
            for resource_type, resources in parsed.get("resource", {}).items():
                for resource_name, config in resources.items():
                    location = self._find_resource_location(
                        content, "resource", resource_type, resource_name
                    )
                    provider = self._detect_provider(resource_type)

                    resource = TerraformResource(
                        resource_type=resource_type,
                        name=resource_name,
                        provider=provider,
                        config=config if isinstance(config, dict) else {},
                        location=location,
                        labels=self._extract_tags(config),
                        dependencies=self._extract_dependencies(config),
                    )
                    iac_file.resources.append(resource)

            # Extract data sources
            for data_type, data_sources in parsed.get("data", {}).items():
                for data_name, config in data_sources.items():
                    location = self._find_resource_location(
                        content, "data", data_type, data_name
                    )
                    provider = self._detect_provider(data_type)

                    data_source = IaCResource(
                        resource_type=f"data.{data_type}",
                        name=data_name,
                        provider=provider,
                        config=config if isinstance(config, dict) else {},
                        location=location,
                    )
                    iac_file.data_sources.append(data_source)

            # Extract variables
            iac_file.variables = parsed.get("variable", {})

            # Extract outputs
            iac_file.outputs = parsed.get("output", {})

            # Extract locals
            iac_file.locals = parsed.get("locals", {})

            # Extract modules
            iac_file.modules = parsed.get("module", {})

            # Extract providers
            iac_file.providers = parsed.get("provider", {})

        except Exception as e:
            iac_file.parse_errors.append(f"Parse error: {e}")

        return iac_file

    def _detect_provider(self, resource_type: str) -> str:
        """Detect cloud provider from resource type."""
        for prefix, provider in self.PROVIDER_PREFIXES.items():
            if resource_type.startswith(prefix):
                return provider
        return "unknown"

    def _find_resource_location(
        self,
        content: str,
        block_type: str,
        resource_type: str,
        resource_name: str,
    ) -> IaCLocation:
        """Find the location of a resource in the source content."""
        # Pattern to find the resource block
        patterns = [
            rf'{block_type}\s+"{resource_type}"\s+"{resource_name}"\s*\{{',
            rf'{block_type}\s+{resource_type}\s+"{resource_name}"\s*\{{',
            rf'{block_type}\s+"{resource_type}"\s+{resource_name}\s*\{{',
            rf"{block_type}\s+{resource_type}\s+{resource_name}\s*\{{",
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                # Count newlines to find line number
                line_start = content[: match.start()].count("\n") + 1

                # Find the end of the block
                brace_count = 1
                pos = match.end()
                while pos < len(content) and brace_count > 0:
                    if content[pos] == "{":
                        brace_count += 1
                    elif content[pos] == "}":
                        brace_count -= 1
                    pos += 1

                line_end = content[:pos].count("\n") + 1

                return IaCLocation(
                    file_path="",  # Will be set by caller
                    line_start=line_start,
                    line_end=line_end,
                )

        # Default location if not found
        return IaCLocation(file_path="", line_start=1)

    def _extract_tags(self, config: Any) -> dict[str, str]:
        """Extract tags/labels from resource config."""
        if not isinstance(config, dict):
            return {}

        tags: dict[str, str] = {}

        # Common tag attribute names
        for key in ["tags", "labels", "tag"]:
            if key in config and isinstance(config[key], dict):
                for k, v in config[key].items():
                    if isinstance(v, str):
                        tags[k] = v
                    else:
                        tags[k] = str(v)

        return tags

    def _extract_dependencies(self, config: Any) -> list[str]:
        """Extract resource dependencies from config."""
        if not isinstance(config, dict):
            return []

        deps: list[str] = []

        # Explicit depends_on
        if "depends_on" in config:
            depends_on = config["depends_on"]
            if isinstance(depends_on, list):
                deps.extend(str(d) for d in depends_on)

        # Implicit dependencies from references (simplified)
        # A full implementation would parse all string values for references

        return deps


def parse_terraform_file(file_path: str | Path) -> IaCFile:
    """
    Convenience function to parse a single Terraform file.

    Args:
        file_path: Path to the .tf file

    Returns:
        Parsed IaCFile object
    """
    parser = TerraformParser()
    return parser.parse_file(file_path)


def parse_terraform_directory(
    directory: str | Path,
    recursive: bool = True,
) -> IaCParseResult:
    """
    Convenience function to parse all Terraform files in a directory.

    Args:
        directory: Directory to scan
        recursive: Whether to scan subdirectories

    Returns:
        IaCParseResult with all parsed files
    """
    parser = TerraformParser()
    return parser.parse_directory(directory, recursive)
