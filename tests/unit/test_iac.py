"""
Unit tests for Mantissa Stance IaC scanning.

Tests cover:
- HCL lexer tokenization
- HCL parser for Terraform files
- TerraformParser resource extraction
- IaCFile data structure
- IaCScanner functionality
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from stance.iac.base import (
    IaCFile,
    IaCFormat,
    IaCLocation,
    IaCResource,
    IaCParseResult,
    IaCFinding,
    IaCScanner,
)
from stance.iac.terraform import (
    HCLLexer,
    HCLParser,
    TerraformParser,
    TerraformResource,
    TokenType,
    parse_terraform_file,
    parse_terraform_directory,
)
from stance.models import Severity


class TestHCLLexer:
    """Tests for HCL lexer tokenization."""

    def test_lexer_empty_content(self):
        """Test lexer handles empty content."""
        lexer = HCLLexer("")
        tokens = lexer.tokenize()
        assert len(tokens) == 1
        assert tokens[0].type == TokenType.EOF

    def test_lexer_simple_identifier(self):
        """Test lexer tokenizes identifiers."""
        lexer = HCLLexer("resource")
        tokens = lexer.tokenize()
        assert len(tokens) == 2
        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[0].value == "resource"

    def test_lexer_string_literal(self):
        """Test lexer tokenizes quoted strings."""
        lexer = HCLLexer('"hello world"')
        tokens = lexer.tokenize()
        assert len(tokens) == 2
        assert tokens[0].type == TokenType.STRING
        assert tokens[0].value == "hello world"

    def test_lexer_string_with_escapes(self):
        """Test lexer handles escape sequences in strings."""
        lexer = HCLLexer(r'"line1\nline2\ttab"')
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.STRING
        assert tokens[0].value == "line1\nline2\ttab"

    def test_lexer_number_integer(self):
        """Test lexer tokenizes integers."""
        lexer = HCLLexer("42")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == 42

    def test_lexer_number_float(self):
        """Test lexer tokenizes floats."""
        lexer = HCLLexer("3.14")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == 3.14

    def test_lexer_number_negative(self):
        """Test lexer tokenizes negative numbers."""
        lexer = HCLLexer("-100")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == -100

    def test_lexer_boolean_true(self):
        """Test lexer tokenizes true."""
        lexer = HCLLexer("true")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.BOOL
        assert tokens[0].value is True

    def test_lexer_boolean_false(self):
        """Test lexer tokenizes false."""
        lexer = HCLLexer("false")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.BOOL
        assert tokens[0].value is False

    def test_lexer_null(self):
        """Test lexer tokenizes null."""
        lexer = HCLLexer("null")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.NULL
        assert tokens[0].value is None

    def test_lexer_braces(self):
        """Test lexer tokenizes braces."""
        lexer = HCLLexer("{}")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.LBRACE
        assert tokens[1].type == TokenType.RBRACE

    def test_lexer_brackets(self):
        """Test lexer tokenizes brackets."""
        lexer = HCLLexer("[]")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.LBRACKET
        assert tokens[1].type == TokenType.RBRACKET

    def test_lexer_equals(self):
        """Test lexer tokenizes equals sign."""
        lexer = HCLLexer("=")
        tokens = lexer.tokenize()
        assert tokens[0].type == TokenType.EQUALS

    def test_lexer_line_comment_hash(self):
        """Test lexer skips hash comments."""
        lexer = HCLLexer("# this is a comment\nresource")
        tokens = lexer.tokenize()
        # Should have NEWLINE, IDENTIFIER, EOF
        identifiers = [t for t in tokens if t.type == TokenType.IDENTIFIER]
        assert len(identifiers) == 1
        assert identifiers[0].value == "resource"

    def test_lexer_line_comment_slash(self):
        """Test lexer skips // comments."""
        lexer = HCLLexer("// this is a comment\nresource")
        tokens = lexer.tokenize()
        identifiers = [t for t in tokens if t.type == TokenType.IDENTIFIER]
        assert len(identifiers) == 1
        assert identifiers[0].value == "resource"

    def test_lexer_block_comment(self):
        """Test lexer skips block comments."""
        lexer = HCLLexer("/* multi\nline\ncomment */ resource")
        tokens = lexer.tokenize()
        identifiers = [t for t in tokens if t.type == TokenType.IDENTIFIER]
        assert len(identifiers) == 1
        assert identifiers[0].value == "resource"

    def test_lexer_heredoc(self):
        """Test lexer tokenizes heredocs."""
        content = '<<EOF\nline1\nline2\nEOF'
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        heredocs = [t for t in tokens if t.type == TokenType.HEREDOC]
        assert len(heredocs) == 1
        assert "line1" in heredocs[0].value
        assert "line2" in heredocs[0].value

    def test_lexer_tracks_line_numbers(self):
        """Test lexer tracks line numbers correctly."""
        content = "first\nsecond\nthird"
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        identifiers = [t for t in tokens if t.type == TokenType.IDENTIFIER]
        assert identifiers[0].line == 1
        assert identifiers[1].line == 2
        assert identifiers[2].line == 3


class TestHCLParser:
    """Tests for HCL parser."""

    def test_parser_empty_content(self):
        """Test parser handles empty content."""
        lexer = HCLLexer("")
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()
        assert isinstance(result, dict)
        assert "resource" in result

    def test_parser_simple_resource(self):
        """Test parser parses simple resource block."""
        content = '''
        resource "aws_s3_bucket" "my_bucket" {
            bucket = "my-bucket-name"
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        assert "resource" in result
        assert "aws_s3_bucket" in result["resource"]
        assert "my_bucket" in result["resource"]["aws_s3_bucket"]
        assert result["resource"]["aws_s3_bucket"]["my_bucket"]["bucket"] == "my-bucket-name"

    def test_parser_resource_with_nested_block(self):
        """Test parser handles nested blocks."""
        content = '''
        resource "aws_s3_bucket" "example" {
            bucket = "example"
            versioning {
                enabled = true
            }
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        bucket_config = result["resource"]["aws_s3_bucket"]["example"]
        assert "versioning" in bucket_config
        assert bucket_config["versioning"]["enabled"] is True

    def test_parser_data_block(self):
        """Test parser parses data blocks."""
        content = '''
        data "aws_ami" "amazon_linux" {
            most_recent = true
            owners      = ["amazon"]
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        assert "data" in result
        assert "aws_ami" in result["data"]
        assert "amazon_linux" in result["data"]["aws_ami"]

    def test_parser_variable_block(self):
        """Test parser parses variable blocks."""
        content = '''
        variable "region" {
            type        = string
            default     = "us-east-1"
            description = "AWS region"
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        assert "variable" in result
        assert "region" in result["variable"]
        assert result["variable"]["region"]["default"] == "us-east-1"

    def test_parser_output_block(self):
        """Test parser parses output blocks."""
        content = '''
        output "bucket_arn" {
            value       = aws_s3_bucket.example.arn
            description = "The ARN of the bucket"
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        assert "output" in result
        assert "bucket_arn" in result["output"]

    def test_parser_locals_block(self):
        """Test parser parses locals blocks."""
        content = '''
        locals {
            project_name = "my-project"
            environment  = "dev"
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        assert "locals" in result
        assert result["locals"]["project_name"] == "my-project"
        assert result["locals"]["environment"] == "dev"

    def test_parser_module_block(self):
        """Test parser parses module blocks."""
        content = '''
        module "vpc" {
            source = "./modules/vpc"
            cidr   = "10.0.0.0/16"
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        assert "module" in result
        assert "vpc" in result["module"]
        assert result["module"]["vpc"]["source"] == "./modules/vpc"

    def test_parser_provider_block(self):
        """Test parser parses provider blocks."""
        content = '''
        provider "aws" {
            region = "us-west-2"
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        assert "provider" in result
        assert "aws" in result["provider"]
        assert result["provider"]["aws"]["region"] == "us-west-2"

    def test_parser_list_values(self):
        """Test parser handles list values."""
        content = '''
        resource "aws_security_group" "example" {
            ingress_ports = [80, 443, 8080]
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        ports = result["resource"]["aws_security_group"]["example"]["ingress_ports"]
        assert isinstance(ports, list)
        assert 80 in ports
        assert 443 in ports
        assert 8080 in ports

    def test_parser_object_values(self):
        """Test parser handles object values."""
        content = '''
        resource "aws_s3_bucket" "example" {
            tags = {
                Name        = "example-bucket"
                Environment = "production"
            }
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        tags = result["resource"]["aws_s3_bucket"]["example"]["tags"]
        assert isinstance(tags, dict)
        assert tags["Name"] == "example-bucket"
        assert tags["Environment"] == "production"

    def test_parser_multiple_resources(self):
        """Test parser handles multiple resources."""
        content = '''
        resource "aws_s3_bucket" "bucket1" {
            bucket = "bucket-one"
        }

        resource "aws_s3_bucket" "bucket2" {
            bucket = "bucket-two"
        }
        '''
        lexer = HCLLexer(content)
        tokens = lexer.tokenize()
        parser = HCLParser(tokens)
        result = parser.parse()

        assert "bucket1" in result["resource"]["aws_s3_bucket"]
        assert "bucket2" in result["resource"]["aws_s3_bucket"]


class TestTerraformParser:
    """Tests for TerraformParser."""

    def test_parser_format(self):
        """Test parser returns correct format."""
        parser = TerraformParser()
        assert parser.format == IaCFormat.TERRAFORM

    def test_parser_file_extensions(self):
        """Test parser returns correct extensions."""
        parser = TerraformParser()
        assert ".tf" in parser.file_extensions

    def test_parser_can_parse(self):
        """Test can_parse method."""
        parser = TerraformParser()
        assert parser.can_parse("main.tf")
        assert parser.can_parse("/path/to/file.tf")
        assert not parser.can_parse("template.yaml")
        assert not parser.can_parse("script.py")

    def test_parse_content_simple_resource(self):
        """Test parsing simple resource content."""
        content = '''
        resource "aws_s3_bucket" "my_bucket" {
            bucket = "my-bucket-name"
            acl    = "private"
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content, "test.tf")

        assert isinstance(result, IaCFile)
        assert result.file_path == "test.tf"
        assert result.format == IaCFormat.TERRAFORM
        assert len(result.resources) == 1
        assert result.resources[0].resource_type == "aws_s3_bucket"
        assert result.resources[0].name == "my_bucket"
        assert result.resources[0].provider == "aws"

    def test_parse_content_extracts_config(self):
        """Test parser extracts resource configuration."""
        content = '''
        resource "aws_s3_bucket" "example" {
            bucket = "example-bucket"
            versioning {
                enabled = true
            }
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content)

        resource = result.resources[0]
        assert resource.config["bucket"] == "example-bucket"
        assert resource.config["versioning"]["enabled"] is True

    def test_parse_content_extracts_tags(self):
        """Test parser extracts tags from resources."""
        content = '''
        resource "aws_s3_bucket" "example" {
            bucket = "example"
            tags = {
                Name        = "Example"
                Environment = "production"
            }
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content)

        resource = result.resources[0]
        assert resource.labels["Name"] == "Example"
        assert resource.labels["Environment"] == "production"

    def test_parse_content_extracts_dependencies(self):
        """Test parser extracts depends_on."""
        content = '''
        resource "aws_instance" "example" {
            ami = "ami-12345"
            depends_on = [aws_vpc.main, aws_subnet.primary]
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content)

        resource = result.resources[0]
        assert "aws_vpc.main" in resource.dependencies
        assert "aws_subnet.primary" in resource.dependencies

    def test_parse_content_data_sources(self):
        """Test parser extracts data sources."""
        content = '''
        data "aws_ami" "amazon_linux" {
            most_recent = true
            owners      = ["amazon"]
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content)

        assert len(result.data_sources) == 1
        assert result.data_sources[0].resource_type == "data.aws_ami"
        assert result.data_sources[0].name == "amazon_linux"

    def test_parse_content_variables(self):
        """Test parser extracts variables."""
        content = '''
        variable "region" {
            type    = string
            default = "us-east-1"
        }

        variable "instance_type" {
            type    = string
            default = "t3.micro"
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content)

        assert "region" in result.variables
        assert "instance_type" in result.variables
        assert result.variables["region"]["default"] == "us-east-1"

    def test_parse_content_outputs(self):
        """Test parser extracts outputs."""
        content = '''
        output "bucket_arn" {
            value = aws_s3_bucket.example.arn
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content)

        assert "bucket_arn" in result.outputs

    def test_parse_content_locals(self):
        """Test parser extracts locals."""
        content = '''
        locals {
            project = "my-project"
            env     = "dev"
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content)

        assert result.locals["project"] == "my-project"
        assert result.locals["env"] == "dev"

    def test_parse_content_modules(self):
        """Test parser extracts modules."""
        content = '''
        module "vpc" {
            source = "./modules/vpc"
            cidr   = "10.0.0.0/16"
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content)

        assert "vpc" in result.modules
        assert result.modules["vpc"]["source"] == "./modules/vpc"

    def test_parse_content_providers(self):
        """Test parser extracts providers."""
        content = '''
        provider "aws" {
            region = "us-west-2"
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content)

        assert "aws" in result.providers
        assert result.providers["aws"]["region"] == "us-west-2"

    def test_detect_provider_aws(self):
        """Test AWS provider detection."""
        parser = TerraformParser()
        assert parser._detect_provider("aws_s3_bucket") == "aws"
        assert parser._detect_provider("aws_instance") == "aws"
        assert parser._detect_provider("aws_lambda_function") == "aws"

    def test_detect_provider_gcp(self):
        """Test GCP provider detection."""
        parser = TerraformParser()
        assert parser._detect_provider("google_storage_bucket") == "gcp"
        assert parser._detect_provider("google_compute_instance") == "gcp"

    def test_detect_provider_azure(self):
        """Test Azure provider detection."""
        parser = TerraformParser()
        assert parser._detect_provider("azurerm_storage_account") == "azure"
        assert parser._detect_provider("azurerm_virtual_machine") == "azure"

    def test_detect_provider_unknown(self):
        """Test unknown provider detection."""
        parser = TerraformParser()
        assert parser._detect_provider("custom_resource") == "unknown"

    def test_parse_file(self, tmp_path):
        """Test parsing a file from disk."""
        content = '''
        resource "aws_s3_bucket" "test" {
            bucket = "test-bucket"
        }
        '''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(content)

        parser = TerraformParser()
        result = parser.parse_file(tf_file)

        assert result.file_path == str(tf_file)
        assert len(result.resources) == 1
        assert not result.has_errors

    def test_parse_file_not_found(self):
        """Test parsing non-existent file."""
        parser = TerraformParser()
        result = parser.parse_file("/nonexistent/path/main.tf")

        assert result.has_errors
        assert len(result.parse_errors) > 0

    def test_parse_directory(self, tmp_path):
        """Test parsing multiple files in directory."""
        # Create multiple .tf files
        (tmp_path / "main.tf").write_text('''
            resource "aws_s3_bucket" "bucket1" {
                bucket = "bucket-1"
            }
        ''')
        (tmp_path / "variables.tf").write_text('''
            variable "region" {
                default = "us-east-1"
            }
        ''')
        (tmp_path / "outputs.tf").write_text('''
            output "bucket_name" {
                value = aws_s3_bucket.bucket1.bucket
            }
        ''')

        parser = TerraformParser()
        result = parser.parse_directory(tmp_path)

        assert isinstance(result, IaCParseResult)
        assert len(result.files) == 3
        assert result.total_resources >= 1

    def test_parse_directory_recursive(self, tmp_path):
        """Test recursive directory parsing."""
        # Create nested structure
        subdir = tmp_path / "modules" / "vpc"
        subdir.mkdir(parents=True)

        (tmp_path / "main.tf").write_text('''
            resource "aws_instance" "main" {
                ami = "ami-12345"
            }
        ''')
        (subdir / "main.tf").write_text('''
            resource "aws_vpc" "main" {
                cidr_block = "10.0.0.0/16"
            }
        ''')

        parser = TerraformParser()
        result = parser.parse_directory(tmp_path, recursive=True)

        assert len(result.files) == 2
        assert result.total_resources == 2

    def test_parse_directory_non_recursive(self, tmp_path):
        """Test non-recursive directory parsing."""
        subdir = tmp_path / "modules"
        subdir.mkdir()

        (tmp_path / "main.tf").write_text('''
            resource "aws_instance" "main" {
                ami = "ami-12345"
            }
        ''')
        (subdir / "module.tf").write_text('''
            resource "aws_vpc" "main" {
                cidr_block = "10.0.0.0/16"
            }
        ''')

        parser = TerraformParser()
        result = parser.parse_directory(tmp_path, recursive=False)

        assert len(result.files) == 1

    def test_parse_content_with_comments(self):
        """Test parsing content with various comment styles."""
        content = '''
        # This is a line comment
        resource "aws_s3_bucket" "example" {
            // Another line comment
            bucket = "example" # inline comment
            /* Block comment
               spanning multiple lines */
            acl = "private"
        }
        '''
        parser = TerraformParser()
        result = parser.parse_content(content)

        assert len(result.resources) == 1
        assert result.resources[0].config["bucket"] == "example"
        assert result.resources[0].config["acl"] == "private"


class TestIaCResource:
    """Tests for IaCResource data class."""

    def test_resource_full_address(self):
        """Test full_address property."""
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="my_bucket",
            provider="aws",
            config={},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        assert resource.full_address == "aws_s3_bucket.my_bucket"

    def test_get_config_value_simple(self):
        """Test simple config value retrieval."""
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={"bucket": "test-bucket", "acl": "private"},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        assert resource.get_config_value("bucket") == "test-bucket"
        assert resource.get_config_value("acl") == "private"

    def test_get_config_value_nested(self):
        """Test nested config value retrieval."""
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={
                "versioning": {"enabled": True},
                "encryption": {"sse_algorithm": "AES256"},
            },
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        assert resource.get_config_value("versioning.enabled") is True
        assert resource.get_config_value("encryption.sse_algorithm") == "AES256"

    def test_get_config_value_default(self):
        """Test default value for missing config."""
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        assert resource.get_config_value("missing", "default") == "default"
        assert resource.get_config_value("nested.missing") is None

    def test_has_config(self):
        """Test has_config method."""
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={"bucket": "test", "versioning": {"enabled": True}},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        assert resource.has_config("bucket")
        assert resource.has_config("versioning.enabled")
        assert not resource.has_config("missing")
        assert not resource.has_config("versioning.missing")


class TestIaCFile:
    """Tests for IaCFile data class."""

    def test_file_has_errors(self):
        """Test has_errors property."""
        file_ok = IaCFile(file_path="main.tf", format=IaCFormat.TERRAFORM)
        file_err = IaCFile(
            file_path="main.tf",
            format=IaCFormat.TERRAFORM,
            parse_errors=["Syntax error"],
        )

        assert not file_ok.has_errors
        assert file_err.has_errors

    def test_file_resource_count(self):
        """Test resource_count property."""
        iac_file = IaCFile(
            file_path="main.tf",
            format=IaCFormat.TERRAFORM,
            resources=[
                IaCResource(
                    resource_type="aws_s3_bucket",
                    name="bucket1",
                    provider="aws",
                    config={},
                    location=IaCLocation(file_path="main.tf", line_start=1),
                ),
                IaCResource(
                    resource_type="aws_s3_bucket",
                    name="bucket2",
                    provider="aws",
                    config={},
                    location=IaCLocation(file_path="main.tf", line_start=5),
                ),
            ],
        )
        assert iac_file.resource_count == 2

    def test_get_resources_by_type(self):
        """Test filtering resources by type."""
        iac_file = IaCFile(
            file_path="main.tf",
            format=IaCFormat.TERRAFORM,
            resources=[
                IaCResource(
                    resource_type="aws_s3_bucket",
                    name="bucket1",
                    provider="aws",
                    config={},
                    location=IaCLocation(file_path="main.tf", line_start=1),
                ),
                IaCResource(
                    resource_type="aws_instance",
                    name="instance1",
                    provider="aws",
                    config={},
                    location=IaCLocation(file_path="main.tf", line_start=5),
                ),
            ],
        )
        buckets = iac_file.get_resources_by_type("aws_s3_bucket")
        assert len(buckets) == 1
        assert buckets[0].name == "bucket1"

    def test_get_resources_by_provider(self):
        """Test filtering resources by provider."""
        iac_file = IaCFile(
            file_path="main.tf",
            format=IaCFormat.TERRAFORM,
            resources=[
                IaCResource(
                    resource_type="aws_s3_bucket",
                    name="bucket1",
                    provider="aws",
                    config={},
                    location=IaCLocation(file_path="main.tf", line_start=1),
                ),
                IaCResource(
                    resource_type="google_storage_bucket",
                    name="bucket2",
                    provider="gcp",
                    config={},
                    location=IaCLocation(file_path="main.tf", line_start=5),
                ),
            ],
        )
        aws_resources = iac_file.get_resources_by_provider("aws")
        assert len(aws_resources) == 1
        assert aws_resources[0].resource_type == "aws_s3_bucket"


class TestIaCLocation:
    """Tests for IaCLocation data class."""

    def test_location_str_single_line(self):
        """Test location string for single line."""
        loc = IaCLocation(file_path="main.tf", line_start=10)
        assert str(loc) == "main.tf:10"

    def test_location_str_line_range(self):
        """Test location string for line range."""
        loc = IaCLocation(file_path="main.tf", line_start=10, line_end=15)
        assert str(loc) == "main.tf:10-15"

    def test_location_str_same_line(self):
        """Test location string when start equals end."""
        loc = IaCLocation(file_path="main.tf", line_start=10, line_end=10)
        assert str(loc) == "main.tf:10"


class TestIaCParseResult:
    """Tests for IaCParseResult data class."""

    def test_add_file(self):
        """Test adding files to result."""
        result = IaCParseResult()
        iac_file = IaCFile(
            file_path="main.tf",
            format=IaCFormat.TERRAFORM,
            resources=[
                IaCResource(
                    resource_type="aws_s3_bucket",
                    name="test",
                    provider="aws",
                    config={},
                    location=IaCLocation(file_path="main.tf", line_start=1),
                ),
            ],
        )
        result.add_file(iac_file)

        assert len(result.files) == 1
        assert result.total_resources == 1
        assert result.total_errors == 0

    def test_get_all_resources(self):
        """Test getting all resources across files."""
        result = IaCParseResult()
        result.add_file(IaCFile(
            file_path="main.tf",
            format=IaCFormat.TERRAFORM,
            resources=[
                IaCResource(
                    resource_type="aws_s3_bucket",
                    name="bucket1",
                    provider="aws",
                    config={},
                    location=IaCLocation(file_path="main.tf", line_start=1),
                ),
            ],
        ))
        result.add_file(IaCFile(
            file_path="other.tf",
            format=IaCFormat.TERRAFORM,
            resources=[
                IaCResource(
                    resource_type="aws_instance",
                    name="instance1",
                    provider="aws",
                    config={},
                    location=IaCLocation(file_path="other.tf", line_start=1),
                ),
            ],
        ))

        all_resources = list(result.get_all_resources())
        assert len(all_resources) == 2

    def test_get_resources_by_type(self):
        """Test getting resources by type across files."""
        result = IaCParseResult()
        result.add_file(IaCFile(
            file_path="main.tf",
            format=IaCFormat.TERRAFORM,
            resources=[
                IaCResource(
                    resource_type="aws_s3_bucket",
                    name="bucket1",
                    provider="aws",
                    config={},
                    location=IaCLocation(file_path="main.tf", line_start=1),
                ),
                IaCResource(
                    resource_type="aws_instance",
                    name="instance1",
                    provider="aws",
                    config={},
                    location=IaCLocation(file_path="main.tf", line_start=5),
                ),
            ],
        ))

        buckets = result.get_resources_by_type("aws_s3_bucket")
        assert len(buckets) == 1


class TestIaCFinding:
    """Tests for IaCFinding data class."""

    def test_to_finding(self):
        """Test converting IaCFinding to Finding."""
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="insecure_bucket",
            provider="aws",
            config={"bucket": "test"},
            location=IaCLocation(file_path="main.tf", line_start=10, line_end=15),
        )
        iac_finding = IaCFinding(
            rule_id="aws-s3-encryption",
            resource=resource,
            severity=Severity.HIGH,
            title="S3 bucket encryption not enabled",
            description="The S3 bucket does not have encryption enabled.",
            remediation="Add server_side_encryption_configuration block.",
            expected_value="encryption = true",
            actual_value="encryption not configured",
        )

        finding = iac_finding.to_finding()

        assert "iac-aws-s3-encryption" in finding.id
        assert finding.severity == Severity.HIGH
        assert finding.title == "S3 bucket encryption not enabled"
        assert finding.rule_id == "aws-s3-encryption"


class TestIaCScanner:
    """Tests for IaCScanner."""

    def test_scanner_register_parser(self):
        """Test registering parsers with scanner."""
        scanner = IaCScanner()
        parser = TerraformParser()
        scanner.register_parser(parser)

        assert len(scanner._parsers) == 1

    def test_scanner_get_parser_for_file(self):
        """Test getting appropriate parser for file."""
        scanner = IaCScanner()
        scanner.register_parser(TerraformParser())

        assert scanner.get_parser_for_file("main.tf") is not None
        assert scanner.get_parser_for_file("template.yaml") is None

    def test_scanner_scan_file(self, tmp_path):
        """Test scanning a single file."""
        content = '''
        resource "aws_s3_bucket" "test" {
            bucket = "test-bucket"
        }
        '''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(content)

        scanner = IaCScanner()
        scanner.register_parser(TerraformParser())

        findings = scanner.scan_file(tf_file)
        assert isinstance(findings, list)

    def test_scanner_scan_directory(self, tmp_path):
        """Test scanning a directory."""
        (tmp_path / "main.tf").write_text('''
            resource "aws_s3_bucket" "test" {
                bucket = "test-bucket"
            }
        ''')

        scanner = IaCScanner()
        scanner.register_parser(TerraformParser())

        result, findings = scanner.scan_directory(tmp_path)
        assert isinstance(result, IaCParseResult)
        assert isinstance(findings, list)


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_parse_terraform_file(self, tmp_path):
        """Test parse_terraform_file function."""
        content = '''
        resource "aws_s3_bucket" "test" {
            bucket = "test-bucket"
        }
        '''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(content)

        result = parse_terraform_file(tf_file)

        assert isinstance(result, IaCFile)
        assert len(result.resources) == 1

    def test_parse_terraform_directory(self, tmp_path):
        """Test parse_terraform_directory function."""
        (tmp_path / "main.tf").write_text('''
            resource "aws_s3_bucket" "test" {
                bucket = "test-bucket"
            }
        ''')

        result = parse_terraform_directory(tmp_path)

        assert isinstance(result, IaCParseResult)
        assert result.total_resources == 1


# ==============================================================================
# IaC Policy Tests
# ==============================================================================

from stance.iac.policies import (
    IaCPolicy,
    IaCPolicyCheck,
    IaCPolicyCollection,
    IaCPolicyCompliance,
    IaCPolicyLoader,
    IaCPolicyEvaluator,
    get_default_iac_policies,
)


class TestIaCPolicy:
    """Tests for IaCPolicy data class."""

    def test_policy_creation(self):
        """Test creating a policy."""
        policy = IaCPolicy(
            id="test-policy-001",
            name="Test Policy",
            description="A test policy",
            enabled=True,
            severity=Severity.HIGH,
            resource_types=["aws_s3_bucket"],
            check=IaCPolicyCheck(check_type="exists", path="encryption"),
        )
        assert policy.id == "test-policy-001"
        assert policy.enabled is True
        assert policy.severity == Severity.HIGH

    def test_policy_matches_resource_type(self):
        """Test policy matching by resource type."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.HIGH,
            resource_types=["aws_s3_bucket"],
            check=IaCPolicyCheck(check_type="exists", path="encryption"),
        )
        resource_match = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_no_match = IaCResource(
            resource_type="aws_instance",
            name="test",
            provider="aws",
            config={},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        assert policy.matches_resource(resource_match) is True
        assert policy.matches_resource(resource_no_match) is False

    def test_policy_matches_provider(self):
        """Test policy matching by provider."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.HIGH,
            resource_types=["aws_s3_bucket"],
            providers=["aws"],
            check=IaCPolicyCheck(check_type="exists", path="encryption"),
        )
        resource_aws = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_gcp = IaCResource(
            resource_type="aws_s3_bucket",  # Same type but wrong provider
            name="test",
            provider="gcp",
            config={},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        assert policy.matches_resource(resource_aws) is True
        assert policy.matches_resource(resource_gcp) is False

    def test_policy_wildcard_resource_type(self):
        """Test policy matching with wildcard resource types."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.HIGH,
            resource_types=["aws_s3_*"],
            check=IaCPolicyCheck(check_type="exists", path="encryption"),
        )
        resource_bucket = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_policy = IaCResource(
            resource_type="aws_s3_bucket_policy",
            name="test",
            provider="aws",
            config={},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_ec2 = IaCResource(
            resource_type="aws_instance",
            name="test",
            provider="aws",
            config={},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        assert policy.matches_resource(resource_bucket) is True
        assert policy.matches_resource(resource_policy) is True
        assert policy.matches_resource(resource_ec2) is False


class TestIaCPolicyCollection:
    """Tests for IaCPolicyCollection."""

    def test_collection_add_and_iterate(self):
        """Test adding and iterating policies."""
        collection = IaCPolicyCollection()
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.HIGH,
            resource_types=["aws_s3_bucket"],
            check=IaCPolicyCheck(check_type="exists", path="encryption"),
        )
        collection.add(policy)

        assert len(collection) == 1
        assert list(collection)[0].id == "test-001"

    def test_collection_filter_enabled(self):
        """Test filtering by enabled status."""
        collection = IaCPolicyCollection(policies=[
            IaCPolicy(
                id="enabled-001",
                name="Enabled",
                description="Test",
                enabled=True,
                severity=Severity.HIGH,
                resource_types=[],
                check=IaCPolicyCheck(check_type="exists", path="test"),
            ),
            IaCPolicy(
                id="disabled-001",
                name="Disabled",
                description="Test",
                enabled=False,
                severity=Severity.HIGH,
                resource_types=[],
                check=IaCPolicyCheck(check_type="exists", path="test"),
            ),
        ])

        enabled = collection.filter_enabled()
        assert len(enabled) == 1
        assert enabled.policies[0].id == "enabled-001"

    def test_collection_filter_by_severity(self):
        """Test filtering by severity."""
        collection = IaCPolicyCollection(policies=[
            IaCPolicy(
                id="critical-001",
                name="Critical",
                description="Test",
                enabled=True,
                severity=Severity.CRITICAL,
                resource_types=[],
                check=IaCPolicyCheck(check_type="exists", path="test"),
            ),
            IaCPolicy(
                id="low-001",
                name="Low",
                description="Test",
                enabled=True,
                severity=Severity.LOW,
                resource_types=[],
                check=IaCPolicyCheck(check_type="exists", path="test"),
            ),
        ])

        critical = collection.filter_by_severity(Severity.CRITICAL)
        assert len(critical) == 1
        assert critical.policies[0].id == "critical-001"

    def test_collection_get_by_id(self):
        """Test getting policy by ID."""
        collection = IaCPolicyCollection(policies=[
            IaCPolicy(
                id="test-001",
                name="Test",
                description="Test",
                enabled=True,
                severity=Severity.HIGH,
                resource_types=[],
                check=IaCPolicyCheck(check_type="exists", path="test"),
            ),
        ])

        policy = collection.get_by_id("test-001")
        assert policy is not None
        assert policy.name == "Test"

        missing = collection.get_by_id("nonexistent")
        assert missing is None


class TestIaCPolicyLoader:
    """Tests for IaCPolicyLoader."""

    def test_load_from_string(self):
        """Test loading policy from YAML string."""
        yaml_content = """
id: test-s3-encryption
name: S3 Encryption Required
description: S3 buckets must have encryption enabled
enabled: true
severity: high
resource_types:
  - aws_s3_bucket
check:
  type: exists
  path: server_side_encryption_configuration
remediation: Add server_side_encryption_configuration block
tags:
  - s3
  - encryption
"""
        loader = IaCPolicyLoader()
        policy = loader.load_from_string(yaml_content)

        assert policy is not None
        assert policy.id == "test-s3-encryption"
        assert policy.name == "S3 Encryption Required"
        assert policy.severity == Severity.HIGH
        assert "aws_s3_bucket" in policy.resource_types
        assert policy.check.check_type == "exists"
        assert policy.check.path == "server_side_encryption_configuration"

    def test_load_policy_from_file(self, tmp_path):
        """Test loading policy from YAML file."""
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
id: file-test-001
name: Test File Policy
description: Testing file loading
enabled: true
severity: medium
resource_types:
  - aws_instance
check:
  type: attribute
  path: encrypted
  operator: eq
  value: true
""")

        loader = IaCPolicyLoader()
        policy = loader.load_policy(policy_file)

        assert policy is not None
        assert policy.id == "file-test-001"
        assert policy.severity == Severity.MEDIUM

    def test_load_all_from_directory(self, tmp_path):
        """Test loading all policies from a directory."""
        (tmp_path / "policy1.yaml").write_text("""
id: policy-001
name: Policy One
description: First policy
enabled: true
severity: high
resource_types:
  - aws_s3_bucket
check:
  type: exists
  path: encryption
""")
        (tmp_path / "policy2.yaml").write_text("""
id: policy-002
name: Policy Two
description: Second policy
enabled: true
severity: medium
resource_types:
  - aws_instance
check:
  type: attribute
  path: encrypted
  operator: eq
  value: true
""")

        loader = IaCPolicyLoader(policy_dirs=[tmp_path])
        collection = loader.load_all()

        assert len(collection) == 2


class TestIaCPolicyEvaluator:
    """Tests for IaCPolicyEvaluator."""

    def test_evaluate_exists_check_pass(self):
        """Test exists check when attribute exists."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.HIGH,
            resource_types=["aws_s3_bucket"],
            check=IaCPolicyCheck(check_type="exists", path="encryption"),
        )
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={"encryption": {"enabled": True}},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        evaluator = IaCPolicyEvaluator(IaCPolicyCollection(policies=[policy]))
        findings = evaluator.evaluate_resource(resource)

        assert len(findings) == 0  # Compliant

    def test_evaluate_exists_check_fail(self):
        """Test exists check when attribute missing."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test description",
            enabled=True,
            severity=Severity.HIGH,
            resource_types=["aws_s3_bucket"],
            check=IaCPolicyCheck(check_type="exists", path="encryption"),
        )
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={"bucket": "test-bucket"},  # No encryption
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        evaluator = IaCPolicyEvaluator(IaCPolicyCollection(policies=[policy]))
        findings = evaluator.evaluate_resource(resource)

        assert len(findings) == 1
        assert findings[0].rule_id == "test-001"
        assert findings[0].severity == Severity.HIGH

    def test_evaluate_attribute_check_eq(self):
        """Test attribute check with equals operator."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.HIGH,
            resource_types=["aws_s3_bucket"],
            check=IaCPolicyCheck(
                check_type="attribute",
                path="versioning.enabled",
                operator="eq",
                value=True,
            ),
        )
        resource_pass = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={"versioning": {"enabled": True}},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_fail = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            provider="aws",
            config={"versioning": {"enabled": False}},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        evaluator = IaCPolicyEvaluator(IaCPolicyCollection(policies=[policy]))

        assert len(evaluator.evaluate_resource(resource_pass)) == 0
        assert len(evaluator.evaluate_resource(resource_fail)) == 1

    def test_evaluate_attribute_check_gte(self):
        """Test attribute check with gte operator."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.MEDIUM,
            resource_types=["aws_db_instance"],
            check=IaCPolicyCheck(
                check_type="attribute",
                path="backup_retention_period",
                operator="gte",
                value=7,
            ),
        )
        resource_pass = IaCResource(
            resource_type="aws_db_instance",
            name="test",
            provider="aws",
            config={"backup_retention_period": 14},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_fail = IaCResource(
            resource_type="aws_db_instance",
            name="test",
            provider="aws",
            config={"backup_retention_period": 3},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        evaluator = IaCPolicyEvaluator(IaCPolicyCollection(policies=[policy]))

        assert len(evaluator.evaluate_resource(resource_pass)) == 0
        assert len(evaluator.evaluate_resource(resource_fail)) == 1

    def test_evaluate_not_exists_check(self):
        """Test not_exists check."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.MEDIUM,
            resource_types=["google_compute_instance"],
            check=IaCPolicyCheck(
                check_type="not_exists",
                path="network_interface.access_config",
            ),
        )
        resource_pass = IaCResource(
            resource_type="google_compute_instance",
            name="test",
            provider="gcp",
            config={"network_interface": {}},  # No access_config
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_fail = IaCResource(
            resource_type="google_compute_instance",
            name="test",
            provider="gcp",
            config={"network_interface": {"access_config": {}}},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        evaluator = IaCPolicyEvaluator(IaCPolicyCollection(policies=[policy]))

        assert len(evaluator.evaluate_resource(resource_pass)) == 0
        assert len(evaluator.evaluate_resource(resource_fail)) == 1

    def test_evaluate_all_of_check(self):
        """Test all_of composite check."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.HIGH,
            resource_types=["aws_s3_bucket_public_access_block"],
            check=IaCPolicyCheck(
                check_type="all_of",
                checks=[
                    IaCPolicyCheck(check_type="attribute", path="block_public_acls", operator="eq", value=True),
                    IaCPolicyCheck(check_type="attribute", path="block_public_policy", operator="eq", value=True),
                ],
            ),
        )
        resource_pass = IaCResource(
            resource_type="aws_s3_bucket_public_access_block",
            name="test",
            provider="aws",
            config={"block_public_acls": True, "block_public_policy": True},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_fail = IaCResource(
            resource_type="aws_s3_bucket_public_access_block",
            name="test",
            provider="aws",
            config={"block_public_acls": True, "block_public_policy": False},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        evaluator = IaCPolicyEvaluator(IaCPolicyCollection(policies=[policy]))

        assert len(evaluator.evaluate_resource(resource_pass)) == 0
        assert len(evaluator.evaluate_resource(resource_fail)) == 1

    def test_evaluate_any_of_check(self):
        """Test any_of composite check."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.HIGH,
            resource_types=["aws_s3_bucket"],
            check=IaCPolicyCheck(
                check_type="any_of",
                checks=[
                    IaCPolicyCheck(check_type="exists", path="server_side_encryption_configuration"),
                    IaCPolicyCheck(check_type="exists", path="encryption"),
                ],
            ),
        )
        resource_pass_1 = IaCResource(
            resource_type="aws_s3_bucket",
            name="test1",
            provider="aws",
            config={"server_side_encryption_configuration": {}},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_pass_2 = IaCResource(
            resource_type="aws_s3_bucket",
            name="test2",
            provider="aws",
            config={"encryption": {}},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_fail = IaCResource(
            resource_type="aws_s3_bucket",
            name="test3",
            provider="aws",
            config={"bucket": "test"},  # Neither encryption option
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        evaluator = IaCPolicyEvaluator(IaCPolicyCollection(policies=[policy]))

        assert len(evaluator.evaluate_resource(resource_pass_1)) == 0
        assert len(evaluator.evaluate_resource(resource_pass_2)) == 0
        assert len(evaluator.evaluate_resource(resource_fail)) == 1

    def test_evaluate_expression_check(self):
        """Test expression-based check."""
        policy = IaCPolicy(
            id="test-001",
            name="Test",
            description="Test",
            enabled=True,
            severity=Severity.MEDIUM,
            resource_types=["aws_instance"],
            check=IaCPolicyCheck(
                check_type="expression",
                path="resource.metadata_options.http_tokens == required",
            ),
        )
        resource_pass = IaCResource(
            resource_type="aws_instance",
            name="test",
            provider="aws",
            config={"metadata_options": {"http_tokens": "required"}},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )
        resource_fail = IaCResource(
            resource_type="aws_instance",
            name="test",
            provider="aws",
            config={"metadata_options": {"http_tokens": "optional"}},
            location=IaCLocation(file_path="main.tf", line_start=1),
        )

        evaluator = IaCPolicyEvaluator(IaCPolicyCollection(policies=[policy]))

        assert len(evaluator.evaluate_resource(resource_pass)) == 0
        assert len(evaluator.evaluate_resource(resource_fail)) == 1

    def test_evaluate_file(self):
        """Test evaluating an entire IaC file."""
        policies = IaCPolicyCollection(policies=[
            IaCPolicy(
                id="test-encryption",
                name="Test Encryption",
                description="Test",
                enabled=True,
                severity=Severity.HIGH,
                resource_types=["aws_s3_bucket"],
                check=IaCPolicyCheck(check_type="exists", path="encryption"),
            ),
        ])
        iac_file = IaCFile(
            file_path="main.tf",
            format=IaCFormat.TERRAFORM,
            resources=[
                IaCResource(
                    resource_type="aws_s3_bucket",
                    name="good_bucket",
                    provider="aws",
                    config={"encryption": {"enabled": True}},
                    location=IaCLocation(file_path="main.tf", line_start=1),
                ),
                IaCResource(
                    resource_type="aws_s3_bucket",
                    name="bad_bucket",
                    provider="aws",
                    config={"bucket": "test"},  # No encryption
                    location=IaCLocation(file_path="main.tf", line_start=5),
                ),
            ],
        )

        evaluator = IaCPolicyEvaluator(policies)
        findings = evaluator.evaluate_file(iac_file)

        assert len(findings) == 1
        assert findings[0].resource.name == "bad_bucket"


class TestDefaultIaCPolicies:
    """Tests for default built-in IaC policies."""

    def test_get_default_policies(self):
        """Test getting default policies."""
        policies = get_default_iac_policies()

        assert len(policies) > 0
        assert len(policies) >= 20  # We defined 25 default policies

    def test_default_policies_have_required_fields(self):
        """Test all default policies have required fields."""
        policies = get_default_iac_policies()

        for policy in policies:
            assert policy.id, "Policy must have an ID"
            assert policy.name, "Policy must have a name"
            assert policy.description, "Policy must have a description"
            assert policy.severity is not None, "Policy must have severity"
            assert policy.check is not None, "Policy must have a check"

    def test_default_policies_cover_major_providers(self):
        """Test default policies cover AWS, GCP, and Azure."""
        policies = get_default_iac_policies()

        providers_covered = set()
        for policy in policies:
            providers_covered.update(policy.providers)

        assert "aws" in providers_covered
        assert "gcp" in providers_covered
        assert "azure" in providers_covered

    def test_default_policies_include_critical_checks(self):
        """Test critical security checks are included."""
        policies = get_default_iac_policies()
        policy_ids = [p.id for p in policies]

        # Check for key policies
        assert "iac-aws-s3-encryption" in policy_ids
        assert "iac-aws-s3-public-access" in policy_ids
        assert "iac-aws-rds-encryption" in policy_ids
        assert "iac-aws-rds-public" in policy_ids


class TestIaCScannerWithPolicies:
    """Tests for IaCScanner with policy integration."""

    def test_scanner_with_policy_evaluator(self, tmp_path):
        """Test scanner using policy evaluator."""
        content = '''
        resource "aws_s3_bucket" "test" {
            bucket = "test-bucket"
        }
        '''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(content)

        policies = IaCPolicyCollection(policies=[
            IaCPolicy(
                id="test-encryption",
                name="S3 Encryption",
                description="S3 buckets must have encryption",
                enabled=True,
                severity=Severity.HIGH,
                resource_types=["aws_s3_bucket"],
                check=IaCPolicyCheck(check_type="exists", path="encryption"),
            ),
        ])
        evaluator = IaCPolicyEvaluator(policies)

        scanner = IaCScanner()
        scanner.register_parser(TerraformParser())
        scanner.set_policy_evaluator(evaluator)

        findings = scanner.scan_file(tf_file)

        assert len(findings) >= 1  # At least one finding for missing encryption

    def test_scanner_detects_hardcoded_secrets(self, tmp_path):
        """Test scanner detects hardcoded secrets."""
        # Test with AWS access key pattern which is more reliably detected
        content = '''
        resource "aws_iam_access_key" "test" {
            secret = "AKIAIOSFODNN7EXAMPLE"
        }
        '''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(content)

        scanner = IaCScanner()
        scanner.register_parser(TerraformParser())

        findings = scanner.scan_file(tf_file)

        # Should detect AWS access key pattern
        secret_findings = [f for f in findings if "hardcoded" in f.rule_id.lower() or "secret" in f.title.lower()]
        assert len(secret_findings) >= 1


# ==============================================================================
# CloudFormation Parser Tests
# ==============================================================================

from stance.iac.cloudformation import (
    CloudFormationParser,
    CloudFormationResource,
    SimpleYAMLParser,
    parse_cloudformation_file,
    parse_cloudformation_content,
)


class TestSimpleYAMLParser:
    """Tests for the minimal YAML parser."""

    def test_parse_empty_content(self):
        """Test parsing empty content."""
        parser = SimpleYAMLParser("")
        result = parser.parse()
        # Empty content returns empty dict or wrapper
        assert result.get("_value") is None or result == {}

    def test_parse_simple_key_value(self):
        """Test parsing simple key-value pairs."""
        content = """
key1: value1
key2: value2
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["key1"] == "value1"
        assert result["key2"] == "value2"

    def test_parse_nested_objects(self):
        """Test parsing nested objects."""
        content = """
parent:
  child1: value1
  child2: value2
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["parent"]["child1"] == "value1"
        assert result["parent"]["child2"] == "value2"

    def test_parse_list(self):
        """Test parsing lists."""
        content = """
items:
  - item1
  - item2
  - item3
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["items"] == ["item1", "item2", "item3"]

    def test_parse_list_of_objects(self):
        """Test parsing list of objects."""
        content = """
items:
  - name: item1
    value: 1
  - name: item2
    value: 2
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert len(result["items"]) == 2
        assert result["items"][0]["name"] == "item1"
        assert result["items"][1]["value"] == 2

    def test_parse_boolean_values(self):
        """Test parsing boolean values."""
        content = """
enabled: true
disabled: false
yes_value: yes
no_value: no
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["enabled"] is True
        assert result["disabled"] is False
        assert result["yes_value"] is True
        assert result["no_value"] is False

    def test_parse_numeric_values(self):
        """Test parsing numeric values."""
        content = """
integer: 42
float: 3.14
negative: -10
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["integer"] == 42
        assert result["float"] == 3.14
        assert result["negative"] == -10

    def test_parse_quoted_strings(self):
        """Test parsing quoted strings."""
        content = """
double_quoted: "hello world"
single_quoted: 'hello world'
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["double_quoted"] == "hello world"
        assert result["single_quoted"] == "hello world"

    def test_parse_inline_list(self):
        """Test parsing inline lists."""
        content = """
items: [a, b, c]
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["items"] == ["a", "b", "c"]

    def test_parse_inline_mapping(self):
        """Test parsing inline mappings."""
        content = """
mapping: {key1: value1, key2: value2}
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["mapping"]["key1"] == "value1"
        assert result["mapping"]["key2"] == "value2"

    def test_parse_cfn_ref_tag(self):
        """Test parsing CloudFormation !Ref tag."""
        content = """
BucketArn: !Ref MyBucket
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["BucketArn"] == {"Ref": "MyBucket"}

    def test_parse_cfn_sub_tag(self):
        """Test parsing CloudFormation !Sub tag."""
        content = """
Name: !Sub "${AWS::StackName}-bucket"
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["Name"] == {"Fn::Sub": "${AWS::StackName}-bucket"}

    def test_parse_cfn_getatt_tag(self):
        """Test parsing CloudFormation !GetAtt tag."""
        content = """
Arn: !GetAtt MyBucket.Arn
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["Arn"] == {"Fn::GetAtt": "MyBucket.Arn"}

    def test_parse_null_values(self):
        """Test parsing null values."""
        content = """
null_value: null
tilde_null: ~
empty:
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["null_value"] is None
        assert result["tilde_null"] is None

    def test_parse_with_comments(self):
        """Test parsing with comments."""
        content = """
# This is a comment
key1: value1  # inline comment
key2: value2
"""
        parser = SimpleYAMLParser(content)
        result = parser.parse()
        assert result["key1"] == "value1"
        assert result["key2"] == "value2"


class TestCloudFormationParser:
    """Tests for CloudFormation template parser."""

    def test_parser_format(self):
        """Test parser returns correct format."""
        parser = CloudFormationParser()
        assert parser.format == IaCFormat.CLOUDFORMATION

    def test_parser_file_extensions(self):
        """Test parser handles CloudFormation extensions."""
        parser = CloudFormationParser()
        extensions = parser.file_extensions
        assert ".json" in extensions
        assert ".yaml" in extensions
        assert ".yml" in extensions
        assert ".template" in extensions

    def test_parse_json_template(self):
        """Test parsing JSON CloudFormation template."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Test template",
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BucketName": "my-test-bucket"
            }
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        assert result.format == IaCFormat.CLOUDFORMATION
        assert len(result.resources) == 1
        assert result.resources[0].name == "MyBucket"
        assert result.resources[0].provider == "aws"

    def test_parse_yaml_template(self):
        """Test parsing YAML CloudFormation template."""
        content = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Test template

Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-test-bucket
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.yaml")

        assert result.format == IaCFormat.CLOUDFORMATION
        assert len(result.resources) == 1
        assert result.resources[0].name == "MyBucket"
        assert result.resources[0].provider == "aws"

    def test_parse_multiple_resources(self):
        """Test parsing template with multiple resources."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {}
        },
        "Queue": {
            "Type": "AWS::SQS::Queue",
            "Properties": {}
        },
        "Topic": {
            "Type": "AWS::SNS::Topic",
            "Properties": {}
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        assert len(result.resources) == 3

    def test_resource_type_normalization(self):
        """Test resource type is normalized."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {}
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        # AWS::S3::Bucket -> aws_s3_bucket
        assert result.resources[0].resource_type == "aws_s3_bucket"

    def test_extract_tags(self):
        """Test extracting resource tags."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "Tags": [
                    {"Key": "Environment", "Value": "Production"},
                    {"Key": "Team", "Value": "Security"}
                ]
            }
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        assert result.resources[0].labels["Environment"] == "Production"
        assert result.resources[0].labels["Team"] == "Security"

    def test_extract_depends_on(self):
        """Test extracting DependsOn dependencies."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "BucketPolicy": {
            "Type": "AWS::S3::BucketPolicy",
            "DependsOn": "MyBucket",
            "Properties": {}
        },
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {}
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        bucket_policy = next(r for r in result.resources if r.name == "BucketPolicy")
        assert "MyBucket" in bucket_policy.dependencies

    def test_extract_depends_on_list(self):
        """Test extracting DependsOn with multiple dependencies."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "MyFunction": {
            "Type": "AWS::Lambda::Function",
            "DependsOn": ["MyRole", "MyBucket"],
            "Properties": {}
        },
        "MyRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {}
        },
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {}
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        function = next(r for r in result.resources if r.name == "MyFunction")
        assert "MyRole" in function.dependencies
        assert "MyBucket" in function.dependencies

    def test_extract_parameters(self):
        """Test extracting template parameters."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "Environment": {
            "Type": "String",
            "Default": "dev",
            "AllowedValues": ["dev", "staging", "prod"]
        },
        "BucketName": {
            "Type": "String",
            "Description": "Name of the S3 bucket"
        }
    },
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {}
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        assert "Environment" in result.variables
        assert result.variables["Environment"]["Type"] == "String"
        assert result.variables["Environment"]["Default"] == "dev"
        assert "BucketName" in result.variables

    def test_extract_outputs(self):
        """Test extracting template outputs."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {}
        }
    },
    "Outputs": {
        "BucketArn": {
            "Description": "ARN of the bucket",
            "Value": {"Fn::GetAtt": ["MyBucket", "Arn"]}
        },
        "BucketName": {
            "Value": {"Ref": "MyBucket"},
            "Export": {"Name": "MyBucketName"}
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        assert "BucketArn" in result.outputs
        assert "BucketName" in result.outputs

    def test_extract_conditions(self):
        """Test extracting conditions."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Conditions": {
        "IsProduction": {"Fn::Equals": [{"Ref": "Environment"}, "prod"]},
        "CreateBucket": {"Fn::Not": [{"Condition": "IsProduction"}]}
    },
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Condition": "CreateBucket",
            "Properties": {}
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        assert "Conditions" in result.locals
        assert "IsProduction" in result.locals["Conditions"]

    def test_resource_with_condition(self):
        """Test resource with conditional creation."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Condition": "CreateBucket",
            "Properties": {}
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        resource = result.resources[0]
        assert isinstance(resource, CloudFormationResource)
        assert resource.condition == "CreateBucket"

    def test_resource_deletion_policy(self):
        """Test resource with DeletionPolicy."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "DeletionPolicy": "Retain",
            "Properties": {}
        }
    }
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        resource = result.resources[0]
        assert isinstance(resource, CloudFormationResource)
        assert resource.deletion_policy == "Retain"

    def test_parse_yaml_with_cfn_tags(self):
        """Test parsing YAML with CloudFormation intrinsic function tags."""
        content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AWS::StackName}-bucket"
      Tags:
        - Key: Environment
          Value: !Ref Environment
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.yaml")

        assert len(result.resources) == 1
        bucket = result.resources[0]
        # The intrinsic functions should be parsed into dict structures
        assert isinstance(bucket.config.get("BucketName"), dict)

    def test_parse_invalid_json(self):
        """Test handling invalid JSON."""
        content = "{ invalid json }"
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        assert len(result.parse_errors) > 0

    def test_parse_invalid_cloudformation(self):
        """Test handling content that is not CloudFormation."""
        content = """
{
    "not": "cloudformation",
    "just": "json"
}
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.json")

        assert len(result.parse_errors) > 0
        assert "not appear to be a valid CloudFormation template" in result.parse_errors[0]

    def test_parse_file_not_found(self):
        """Test handling non-existent file."""
        parser = CloudFormationParser()
        result = parser.parse_file("/nonexistent/path/template.json")

        assert len(result.parse_errors) > 0

    def test_parse_sam_template(self):
        """Test parsing SAM (Serverless Application Model) template."""
        content = """
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: SAM Template

Resources:
  MyFunction:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: python3.9
      Handler: app.handler
      CodeUri: ./src
"""
        parser = CloudFormationParser()
        result = parser.parse_content(content, "template.yaml")

        assert len(result.resources) == 1
        assert result.resources[0].name == "MyFunction"

    def test_can_parse_checks_content(self, tmp_path):
        """Test can_parse checks file content for ambiguous extensions."""
        # Create a CloudFormation JSON file
        cfn_file = tmp_path / "template.json"
        cfn_file.write_text("""
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {}
}
""")

        # Create a non-CloudFormation JSON file
        other_file = tmp_path / "config.json"
        other_file.write_text("""
{
    "setting": "value"
}
""")

        parser = CloudFormationParser()

        # Explicit CFN extension should always work
        assert parser.can_parse(tmp_path / "template.cfn.json")

        # Generic JSON should check content
        assert parser.can_parse(cfn_file) is True
        assert parser.can_parse(other_file) is False


class TestCloudFormationResource:
    """Tests for CloudFormationResource data class."""

    def test_cloudformation_resource_creation(self):
        """Test creating CloudFormationResource."""
        resource = CloudFormationResource(
            resource_type="aws_s3_bucket",
            name="MyBucket",
            provider="aws",
            config={"BucketName": "test-bucket"},
            location=IaCLocation(file_path="template.yaml", line_start=10),
            logical_id="MyBucket",
            condition="CreateBucket",
            deletion_policy="Retain",
        )

        assert resource.resource_type == "aws_s3_bucket"
        assert resource.logical_id == "MyBucket"
        assert resource.condition == "CreateBucket"
        assert resource.deletion_policy == "Retain"

    def test_cloudformation_resource_full_address(self):
        """Test full_address property."""
        resource = CloudFormationResource(
            resource_type="aws_s3_bucket",
            name="MyBucket",
            provider="aws",
            config={},
            location=IaCLocation(file_path="template.yaml", line_start=1),
        )

        assert resource.full_address == "aws_s3_bucket.MyBucket"


class TestCloudFormationConvenienceFunctions:
    """Tests for CloudFormation convenience functions."""

    def test_parse_cloudformation_file(self, tmp_path):
        """Test parse_cloudformation_file function."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {}
        }
    }
}
"""
        cfn_file = tmp_path / "template.json"
        cfn_file.write_text(content)

        result = parse_cloudformation_file(cfn_file)

        assert isinstance(result, IaCFile)
        assert len(result.resources) == 1

    def test_parse_cloudformation_content(self):
        """Test parse_cloudformation_content function."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {}
        }
    }
}
"""
        result = parse_cloudformation_content(content, "test-template.json")

        assert isinstance(result, IaCFile)
        assert len(result.resources) == 1
        assert result.file_path == "test-template.json"


class TestCloudFormationWithPolicies:
    """Tests for CloudFormation parser integration with IaC policies."""

    def test_evaluate_cfn_resources_with_policies(self):
        """Test evaluating CloudFormation resources against IaC policies."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "UnencryptedBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BucketName": "unencrypted-bucket"
            }
        }
    }
}
"""
        parser = CloudFormationParser()
        iac_file = parser.parse_content(content, "template.json")

        # Create a policy that requires encryption
        policies = IaCPolicyCollection(policies=[
            IaCPolicy(
                id="cfn-s3-encryption",
                name="S3 Bucket Encryption",
                description="S3 buckets must have encryption configured",
                enabled=True,
                severity=Severity.HIGH,
                resource_types=["aws_s3_bucket"],
                check=IaCPolicyCheck(check_type="exists", path="BucketEncryption"),
            ),
        ])

        evaluator = IaCPolicyEvaluator(policies)
        findings = evaluator.evaluate_file(iac_file)

        assert len(findings) == 1
        assert findings[0].rule_id == "cfn-s3-encryption"

    def test_compliant_cfn_resource(self):
        """Test compliant CloudFormation resource passes policy."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "EncryptedBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BucketName": "encrypted-bucket",
                "BucketEncryption": {
                    "ServerSideEncryptionConfiguration": [
                        {
                            "ServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                }
            }
        }
    }
}
"""
        parser = CloudFormationParser()
        iac_file = parser.parse_content(content, "template.json")

        policies = IaCPolicyCollection(policies=[
            IaCPolicy(
                id="cfn-s3-encryption",
                name="S3 Bucket Encryption",
                description="S3 buckets must have encryption configured",
                enabled=True,
                severity=Severity.HIGH,
                resource_types=["aws_s3_bucket"],
                check=IaCPolicyCheck(check_type="exists", path="BucketEncryption"),
            ),
        ])

        evaluator = IaCPolicyEvaluator(policies)
        findings = evaluator.evaluate_file(iac_file)

        assert len(findings) == 0  # Compliant


class TestCloudFormationScannerIntegration:
    """Tests for CloudFormation with IaCScanner."""

    def test_scanner_with_cfn_parser(self, tmp_path):
        """Test IaCScanner with CloudFormation parser registered."""
        content = """
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "MyBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {}
        }
    }
}
"""
        cfn_file = tmp_path / "template.cfn.json"
        cfn_file.write_text(content)

        scanner = IaCScanner()
        scanner.register_parser(CloudFormationParser())

        findings = scanner.scan_file(cfn_file)
        assert isinstance(findings, list)

    def test_scanner_directory_with_cfn(self, tmp_path):
        """Test scanning directory with CloudFormation templates."""
        (tmp_path / "bucket.cfn.yaml").write_text("""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
""")

        (tmp_path / "queue.cfn.json").write_text("""
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "MyQueue": {
            "Type": "AWS::SQS::Queue",
            "Properties": {}
        }
    }
}
""")

        scanner = IaCScanner()
        scanner.register_parser(CloudFormationParser())

        result, findings = scanner.scan_directory(tmp_path)

        # Should find both templates
        assert result.total_resources >= 2


# ==============================================================================
# ARM Template Parser Tests
# ==============================================================================

from stance.iac.arm import (
    ARMTemplateParser,
    ARMTemplateResource,
    parse_arm_template_file,
    parse_arm_template_content,
)


class TestARMTemplateParser:
    """Tests for ARM template parser."""

    def test_parser_format(self):
        """Test parser returns correct format."""
        parser = ARMTemplateParser()
        assert parser.format == IaCFormat.ARM

    def test_parser_file_extensions(self):
        """Test parser handles ARM template extensions."""
        parser = ARMTemplateParser()
        extensions = parser.file_extensions
        assert ".json" in extensions
        assert ".arm.json" in extensions
        assert ".azuredeploy.json" in extensions

    def test_parse_simple_template(self):
        """Test parsing a simple ARM template."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "location": "[resourceGroup().location]",
            "sku": {
                "name": "Standard_LRS"
            },
            "kind": "StorageV2",
            "properties": {
                "supportsHttpsTrafficOnly": true,
                "minimumTlsVersion": "TLS1_2"
            }
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        assert result.format == IaCFormat.ARM
        assert len(result.resources) == 1
        assert result.resources[0].name == "mystorageaccount"
        assert result.resources[0].provider == "azure"

    def test_parse_multiple_resources(self):
        """Test parsing template with multiple resources."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "storage1",
            "location": "eastus",
            "properties": {}
        },
        {
            "type": "Microsoft.Network/virtualNetworks",
            "apiVersion": "2021-02-01",
            "name": "vnet1",
            "location": "eastus",
            "properties": {}
        },
        {
            "type": "Microsoft.Compute/virtualMachines",
            "apiVersion": "2021-03-01",
            "name": "vm1",
            "location": "eastus",
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        assert len(result.resources) == 3

    def test_resource_type_normalization(self):
        """Test resource type is normalized."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "myaccount",
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        # Microsoft.Storage/storageAccounts -> azure_storage_storageaccounts
        assert result.resources[0].resource_type == "azure_storage_storageaccounts"

    def test_extract_tags(self):
        """Test extracting resource tags."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "tags": {
                "Environment": "Production",
                "Team": "Security"
            },
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        assert result.resources[0].labels["Environment"] == "Production"
        assert result.resources[0].labels["Team"] == "Security"

    def test_extract_depends_on(self):
        """Test extracting dependsOn dependencies."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "properties": {}
        },
        {
            "type": "Microsoft.Web/sites",
            "apiVersion": "2021-02-01",
            "name": "mywebsite",
            "dependsOn": [
                "mystorageaccount"
            ],
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        website = next(r for r in result.resources if "mywebsite" in r.name)
        assert "mystorageaccount" in website.dependencies

    def test_extract_depends_on_with_resourceid(self):
        """Test extracting dependsOn with resourceId expressions."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Web/sites",
            "apiVersion": "2021-02-01",
            "name": "mywebsite",
            "dependsOn": [
                "[resourceId('Microsoft.Storage/storageAccounts', 'mystorageaccount')]"
            ],
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        assert len(result.resources[0].dependencies) >= 1

    def test_extract_parameters(self):
        """Test extracting template parameters."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "storageAccountName": {
            "type": "string",
            "metadata": {
                "description": "Name of the storage account"
            }
        },
        "location": {
            "type": "string",
            "defaultValue": "eastus"
        }
    },
    "resources": []
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        assert "storageAccountName" in result.variables
        assert result.variables["storageAccountName"]["type"] == "string"
        assert "location" in result.variables
        assert result.variables["location"]["defaultValue"] == "eastus"

    def test_extract_variables(self):
        """Test extracting template variables."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "variables": {
        "storageAccountName": "[concat('storage', uniqueString(resourceGroup().id))]",
        "location": "eastus"
    },
    "resources": []
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        assert "storageAccountName" in result.locals
        assert "location" in result.locals
        assert result.locals["location"] == "eastus"

    def test_extract_outputs(self):
        """Test extracting template outputs."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [],
    "outputs": {
        "storageEndpoint": {
            "type": "string",
            "value": "[reference('mystorageaccount').primaryEndpoints.blob]"
        }
    }
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        assert "storageEndpoint" in result.outputs
        assert result.outputs["storageEndpoint"]["type"] == "string"

    def test_resource_with_condition(self):
        """Test resource with conditional deployment."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "deployStorage": {
            "type": "bool",
            "defaultValue": true
        }
    },
    "resources": [
        {
            "condition": "[parameters('deployStorage')]",
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        resource = result.resources[0]
        assert isinstance(resource, ARMTemplateResource)
        assert resource.condition == "parameters('deployStorage')"

    def test_resource_with_copy(self):
        """Test resource with copy loop."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "[concat('storage', copyIndex())]",
            "copy": {
                "name": "storageCopy",
                "count": 3
            },
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        resource = result.resources[0]
        assert isinstance(resource, ARMTemplateResource)
        assert resource.copy is not None
        assert resource.copy["name"] == "storageCopy"
        assert resource.copy["count"] == 3

    def test_resource_api_version(self):
        """Test extracting resource API version."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        resource = result.resources[0]
        assert isinstance(resource, ARMTemplateResource)
        assert resource.api_version == "2021-02-01"

    def test_resource_sku_and_kind(self):
        """Test extracting SKU and kind."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "sku": {
                "name": "Standard_LRS"
            },
            "kind": "StorageV2",
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        resource = result.resources[0]
        assert isinstance(resource, ARMTemplateResource)
        assert resource.sku == {"name": "Standard_LRS"}
        assert resource.kind == "StorageV2"

    def test_nested_resources(self):
        """Test parsing nested resources."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "properties": {},
            "resources": [
                {
                    "type": "blobServices/containers",
                    "apiVersion": "2021-02-01",
                    "name": "default/mycontainer",
                    "dependsOn": ["mystorageaccount"],
                    "properties": {}
                }
            ]
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        # Should have parent and nested resource
        assert len(result.resources) == 2

    def test_resource_identity(self):
        """Test extracting managed identity."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Web/sites",
            "apiVersion": "2021-02-01",
            "name": "mywebsite",
            "identity": {
                "type": "SystemAssigned"
            },
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        resource = result.resources[0]
        assert isinstance(resource, ARMTemplateResource)
        assert resource.identity == {"type": "SystemAssigned"}

    def test_parse_invalid_json(self):
        """Test handling invalid JSON."""
        content = "{ invalid json }"
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        assert len(result.parse_errors) > 0

    def test_parse_non_arm_template(self):
        """Test handling content that is not an ARM template."""
        content = """
{
    "not": "arm_template",
    "just": "json"
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        assert len(result.parse_errors) > 0
        assert "not appear to be a valid ARM template" in result.parse_errors[0]

    def test_parse_file_not_found(self):
        """Test handling non-existent file."""
        parser = ARMTemplateParser()
        result = parser.parse_file("/nonexistent/path/template.json")

        assert len(result.parse_errors) > 0

    def test_parameter_expression_in_name(self):
        """Test handling parameter expressions in resource names."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "storageAccountName": {
            "type": "string"
        }
    },
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "[parameters('storageAccountName')]",
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        # Should extract a meaningful name from the expression
        assert "storageAccountName" in result.resources[0].name or "param:" in result.resources[0].name

    def test_can_parse_checks_content(self, tmp_path):
        """Test can_parse checks file content for ambiguous extensions."""
        # Create an ARM template file
        arm_file = tmp_path / "template.json"
        arm_file.write_text("""
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": []
}
""")

        # Create a non-ARM JSON file
        other_file = tmp_path / "config.json"
        other_file.write_text("""
{
    "setting": "value"
}
""")

        parser = ARMTemplateParser()

        # Explicit ARM extension should always work
        assert parser.can_parse(tmp_path / "template.arm.json")
        assert parser.can_parse(tmp_path / "azuredeploy.json")

        # Generic JSON should check content
        assert parser.can_parse(arm_file) is True
        assert parser.can_parse(other_file) is False

    def test_zones_extraction(self):
        """Test extracting availability zones."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Compute/virtualMachines",
            "apiVersion": "2021-03-01",
            "name": "myvm",
            "zones": ["1", "2"],
            "properties": {}
        }
    ]
}
"""
        parser = ARMTemplateParser()
        result = parser.parse_content(content, "template.json")

        resource = result.resources[0]
        assert isinstance(resource, ARMTemplateResource)
        assert resource.zones == ["1", "2"]


class TestARMTemplateResource:
    """Tests for ARMTemplateResource data class."""

    def test_arm_resource_creation(self):
        """Test creating ARMTemplateResource."""
        resource = ARMTemplateResource(
            resource_type="azure_storage_storageaccounts",
            name="mystorageaccount",
            provider="azure",
            config={"supportsHttpsTrafficOnly": True},
            location=IaCLocation(file_path="template.json", line_start=10),
            api_version="2021-02-01",
            kind="StorageV2",
            sku={"name": "Standard_LRS"},
        )

        assert resource.resource_type == "azure_storage_storageaccounts"
        assert resource.api_version == "2021-02-01"
        assert resource.kind == "StorageV2"
        assert resource.sku == {"name": "Standard_LRS"}

    def test_arm_resource_full_address(self):
        """Test full_address property."""
        resource = ARMTemplateResource(
            resource_type="azure_storage_storageaccounts",
            name="mystorageaccount",
            provider="azure",
            config={},
            location=IaCLocation(file_path="template.json", line_start=1),
        )

        assert resource.full_address == "azure_storage_storageaccounts.mystorageaccount"


class TestARMTemplateConvenienceFunctions:
    """Tests for ARM template convenience functions."""

    def test_parse_arm_template_file(self, tmp_path):
        """Test parse_arm_template_file function."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "properties": {}
        }
    ]
}
"""
        arm_file = tmp_path / "template.json"
        arm_file.write_text(content)

        result = parse_arm_template_file(arm_file)

        assert isinstance(result, IaCFile)
        assert len(result.resources) == 1

    def test_parse_arm_template_content(self):
        """Test parse_arm_template_content function."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "properties": {}
        }
    ]
}
"""
        result = parse_arm_template_content(content, "test-template.json")

        assert isinstance(result, IaCFile)
        assert len(result.resources) == 1
        assert result.file_path == "test-template.json"


class TestARMTemplateWithPolicies:
    """Tests for ARM template parser integration with IaC policies."""

    def test_evaluate_arm_resources_with_policies(self):
        """Test evaluating ARM template resources against IaC policies."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "properties": {
                "supportsHttpsTrafficOnly": false
            }
        }
    ]
}
"""
        parser = ARMTemplateParser()
        iac_file = parser.parse_content(content, "template.json")

        # Create a policy that requires HTTPS
        policies = IaCPolicyCollection(policies=[
            IaCPolicy(
                id="arm-storage-https",
                name="Storage HTTPS Required",
                description="Storage accounts must require HTTPS",
                enabled=True,
                severity=Severity.HIGH,
                resource_types=["azure_storage_storageaccounts"],
                check=IaCPolicyCheck(
                    check_type="attribute",
                    path="supportsHttpsTrafficOnly",
                    operator="eq",
                    value=True,
                ),
            ),
        ])

        evaluator = IaCPolicyEvaluator(policies)
        findings = evaluator.evaluate_file(iac_file)

        assert len(findings) == 1
        assert findings[0].rule_id == "arm-storage-https"

    def test_compliant_arm_resource(self):
        """Test compliant ARM template resource passes policy."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "properties": {
                "supportsHttpsTrafficOnly": true,
                "minimumTlsVersion": "TLS1_2"
            }
        }
    ]
}
"""
        parser = ARMTemplateParser()
        iac_file = parser.parse_content(content, "template.json")

        policies = IaCPolicyCollection(policies=[
            IaCPolicy(
                id="arm-storage-https",
                name="Storage HTTPS Required",
                description="Storage accounts must require HTTPS",
                enabled=True,
                severity=Severity.HIGH,
                resource_types=["azure_storage_storageaccounts"],
                check=IaCPolicyCheck(
                    check_type="attribute",
                    path="supportsHttpsTrafficOnly",
                    operator="eq",
                    value=True,
                ),
            ),
        ])

        evaluator = IaCPolicyEvaluator(policies)
        findings = evaluator.evaluate_file(iac_file)

        assert len(findings) == 0  # Compliant


class TestARMTemplateScannerIntegration:
    """Tests for ARM template with IaCScanner."""

    def test_scanner_with_arm_parser(self, tmp_path):
        """Test IaCScanner with ARM template parser registered."""
        content = """
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "mystorageaccount",
            "properties": {}
        }
    ]
}
"""
        arm_file = tmp_path / "template.arm.json"
        arm_file.write_text(content)

        scanner = IaCScanner()
        scanner.register_parser(ARMTemplateParser())

        findings = scanner.scan_file(arm_file)
        assert isinstance(findings, list)

    def test_scanner_directory_with_arm(self, tmp_path):
        """Test scanning directory with ARM templates."""
        (tmp_path / "storage.arm.json").write_text("""
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-02-01",
            "name": "storage1",
            "properties": {}
        }
    ]
}
""")

        (tmp_path / "azuredeploy.json").write_text("""
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Network/virtualNetworks",
            "apiVersion": "2021-02-01",
            "name": "vnet1",
            "properties": {}
        }
    ]
}
""")

        scanner = IaCScanner()
        scanner.register_parser(ARMTemplateParser())

        result, findings = scanner.scan_directory(tmp_path)

        # Should find both templates
        assert result.total_resources >= 2
