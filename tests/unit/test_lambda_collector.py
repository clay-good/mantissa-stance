"""
Unit tests for LambdaCollector.

Tests cover:
- Lambda function collection with mocked AWS responses
- Lambda layer collection
- Event source mapping collection
- Network exposure determination (function URLs, resource policies)
- Deprecated runtime detection
- Error handling for AWS access denied scenarios
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from stance.collectors.aws_lambda import LambdaCollector
from stance.models import AssetCollection, NETWORK_EXPOSURE_INTERNET, NETWORK_EXPOSURE_INTERNAL


class TestLambdaCollector:
    """Tests for LambdaCollector."""

    def test_lambda_collector_init(self):
        """Test LambdaCollector can be initialized."""
        collector = LambdaCollector()
        assert collector.collector_name == "aws_lambda"
        assert "aws_lambda_function" in collector.resource_types
        assert "aws_lambda_layer" in collector.resource_types
        assert "aws_lambda_event_source_mapping" in collector.resource_types

    def test_lambda_collector_collect_functions(self, mock_lambda_client):
        """Test Lambda function collection with mock response."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            # Configure paginator to return different results based on method
            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_functions":
                    mock_paginator.paginate.return_value = [{
                        "Functions": [
                            {
                                "FunctionName": "my-function",
                                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
                                "Runtime": "python3.11",
                                "Handler": "index.handler",
                                "CodeSize": 1024,
                                "Description": "Test function",
                                "Timeout": 30,
                                "MemorySize": 256,
                                "LastModified": "2024-01-01T00:00:00.000+0000",
                                "Role": "arn:aws:iam::123456789012:role/lambda-role",
                                "VpcConfig": {},
                                "Environment": {"Variables": {"ENV": "prod"}},
                                "TracingConfig": {"Mode": "Active"},
                                "KMSKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
                            }
                        ]
                    }]
                elif method_name == "list_layers":
                    mock_paginator.paginate.return_value = [{"Layers": []}]
                elif method_name == "list_event_source_mappings":
                    mock_paginator.paginate.return_value = [{"EventSourceMappings": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_lambda_client.get_paginator.side_effect = get_paginator_side_effect
            mock_lambda_client.list_tags.return_value = {"Tags": {"Environment": "prod"}}
            mock_lambda_client.get_policy.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetPolicy")
            mock_lambda_client.get_function_url_config.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetFunctionUrlConfig")

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            func_assets = [a for a in assets if a.resource_type == "aws_lambda_function"]
            assert len(func_assets) == 1

            func = func_assets[0]
            assert func.name == "my-function"
            assert func.raw_config["runtime"] == "python3.11"
            assert func.raw_config["has_kms_encryption"] is True
            assert func.raw_config["xray_tracing_enabled"] is True
            assert func.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_lambda_collector_deprecated_runtime(self, mock_lambda_client):
        """Test detection of deprecated runtime."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_functions":
                    mock_paginator.paginate.return_value = [{
                        "Functions": [
                            {
                                "FunctionName": "old-function",
                                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:old-function",
                                "Runtime": "python2.7",  # Deprecated
                                "Handler": "index.handler",
                                "Role": "arn:aws:iam::123456789012:role/lambda-role",
                            }
                        ]
                    }]
                elif method_name == "list_layers":
                    mock_paginator.paginate.return_value = [{"Layers": []}]
                elif method_name == "list_event_source_mappings":
                    mock_paginator.paginate.return_value = [{"EventSourceMappings": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_lambda_client.get_paginator.side_effect = get_paginator_side_effect
            mock_lambda_client.list_tags.return_value = {"Tags": {}}
            mock_lambda_client.get_policy.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetPolicy")
            mock_lambda_client.get_function_url_config.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetFunctionUrlConfig")

            assets = collector.collect()

            func_assets = [a for a in assets if a.resource_type == "aws_lambda_function"]
            assert len(func_assets) == 1

            func = func_assets[0]
            assert func.raw_config["runtime_deprecated"] is True

    def test_lambda_collector_public_function_url(self, mock_lambda_client):
        """Test detection of publicly accessible function URL."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_functions":
                    mock_paginator.paginate.return_value = [{
                        "Functions": [
                            {
                                "FunctionName": "public-function",
                                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:public-function",
                                "Runtime": "python3.11",
                                "Handler": "index.handler",
                                "Role": "arn:aws:iam::123456789012:role/lambda-role",
                            }
                        ]
                    }]
                elif method_name == "list_layers":
                    mock_paginator.paginate.return_value = [{"Layers": []}]
                elif method_name == "list_event_source_mappings":
                    mock_paginator.paginate.return_value = [{"EventSourceMappings": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_lambda_client.get_paginator.side_effect = get_paginator_side_effect
            mock_lambda_client.list_tags.return_value = {"Tags": {}}
            mock_lambda_client.get_policy.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetPolicy")
            # Function URL with no auth (public) - clear side_effect first
            mock_lambda_client.get_function_url_config.side_effect = None
            mock_lambda_client.get_function_url_config.return_value = {
                "FunctionUrl": "https://abc123.lambda-url.us-east-1.on.aws/",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:public-function",
                "AuthType": "NONE",  # Public access
                "Cors": {},
            }

            assets = collector.collect()

            func_assets = [a for a in assets if a.resource_type == "aws_lambda_function"]
            assert len(func_assets) == 1

            func = func_assets[0]
            assert func.raw_config["has_function_url"] is True
            assert func.raw_config["function_url_auth_type"] == "NONE"
            assert func.network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_lambda_collector_public_resource_policy(self, mock_lambda_client):
        """Test detection of publicly invocable function via resource policy."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_functions":
                    mock_paginator.paginate.return_value = [{
                        "Functions": [
                            {
                                "FunctionName": "policy-public-function",
                                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:policy-public-function",
                                "Runtime": "python3.11",
                                "Handler": "index.handler",
                                "Role": "arn:aws:iam::123456789012:role/lambda-role",
                            }
                        ]
                    }]
                elif method_name == "list_layers":
                    mock_paginator.paginate.return_value = [{"Layers": []}]
                elif method_name == "list_event_source_mappings":
                    mock_paginator.paginate.return_value = [{"EventSourceMappings": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_lambda_client.get_paginator.side_effect = get_paginator_side_effect
            mock_lambda_client.list_tags.return_value = {"Tags": {}}
            # Public resource policy - clear side_effect first
            mock_lambda_client.get_policy.side_effect = None
            mock_lambda_client.get_policy.return_value = {
                "Policy": json.dumps({
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "lambda:InvokeFunction",
                        }
                    ]
                })
            }
            mock_lambda_client.get_function_url_config.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetFunctionUrlConfig")

            assets = collector.collect()

            func_assets = [a for a in assets if a.resource_type == "aws_lambda_function"]
            assert len(func_assets) == 1

            func = func_assets[0]
            assert func.raw_config["is_publicly_invocable"] is True
            assert func.network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_lambda_collector_collect_layers(self, mock_lambda_client):
        """Test Lambda layer collection."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_functions":
                    mock_paginator.paginate.return_value = [{"Functions": []}]
                elif method_name == "list_layers":
                    mock_paginator.paginate.return_value = [{
                        "Layers": [
                            {
                                "LayerName": "my-layer",
                                "LayerArn": "arn:aws:lambda:us-east-1:123456789012:layer:my-layer",
                                "LatestMatchingVersion": {
                                    "LayerVersionArn": "arn:aws:lambda:us-east-1:123456789012:layer:my-layer:1",
                                    "Version": 1,
                                    "Description": "Test layer",
                                    "CompatibleRuntimes": ["python3.11"],
                                    "CreatedDate": "2024-01-01T00:00:00.000+0000",
                                }
                            }
                        ]
                    }]
                elif method_name == "list_event_source_mappings":
                    mock_paginator.paginate.return_value = [{"EventSourceMappings": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_lambda_client.get_paginator.side_effect = get_paginator_side_effect
            mock_lambda_client.get_layer_version_policy.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetLayerVersionPolicy")

            assets = collector.collect()

            layer_assets = [a for a in assets if a.resource_type == "aws_lambda_layer"]
            assert len(layer_assets) == 1

            layer = layer_assets[0]
            assert layer.name == "my-layer"
            assert layer.raw_config["latest_version"] == 1
            assert layer.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_lambda_collector_public_layer(self, mock_lambda_client):
        """Test detection of publicly shared layer."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_functions":
                    mock_paginator.paginate.return_value = [{"Functions": []}]
                elif method_name == "list_layers":
                    mock_paginator.paginate.return_value = [{
                        "Layers": [
                            {
                                "LayerName": "public-layer",
                                "LayerArn": "arn:aws:lambda:us-east-1:123456789012:layer:public-layer",
                                "LatestMatchingVersion": {
                                    "LayerVersionArn": "arn:aws:lambda:us-east-1:123456789012:layer:public-layer:1",
                                    "Version": 1,
                                }
                            }
                        ]
                    }]
                elif method_name == "list_event_source_mappings":
                    mock_paginator.paginate.return_value = [{"EventSourceMappings": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_lambda_client.get_paginator.side_effect = get_paginator_side_effect
            # Public layer policy - clear side_effect first
            mock_lambda_client.get_layer_version_policy.side_effect = None
            mock_lambda_client.get_layer_version_policy.return_value = {
                "Policy": json.dumps({
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "lambda:GetLayerVersion",
                        }
                    ]
                })
            }

            assets = collector.collect()

            layer_assets = [a for a in assets if a.resource_type == "aws_lambda_layer"]
            assert len(layer_assets) == 1

            layer = layer_assets[0]
            assert layer.raw_config["is_publicly_shared"] is True
            assert layer.network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_lambda_collector_collect_event_source_mappings(self, mock_lambda_client):
        """Test event source mapping collection."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_functions":
                    mock_paginator.paginate.return_value = [{"Functions": []}]
                elif method_name == "list_layers":
                    mock_paginator.paginate.return_value = [{"Layers": []}]
                elif method_name == "list_event_source_mappings":
                    mock_paginator.paginate.return_value = [{
                        "EventSourceMappings": [
                            {
                                "UUID": "12345678-1234-1234-1234-123456789012",
                                "EventSourceArn": "arn:aws:sqs:us-east-1:123456789012:my-queue",
                                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
                                "BatchSize": 10,
                                "State": "Enabled",
                                "LastModified": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            }
                        ]
                    }]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_lambda_client.get_paginator.side_effect = get_paginator_side_effect

            assets = collector.collect()

            esm_assets = [a for a in assets if a.resource_type == "aws_lambda_event_source_mapping"]
            assert len(esm_assets) == 1

            esm = esm_assets[0]
            assert esm.raw_config["event_source_type"] == "sqs"
            assert esm.raw_config["batch_size"] == 10
            assert esm.raw_config["state"] == "Enabled"

    def test_lambda_collector_handles_access_denied(self, mock_lambda_client):
        """Test graceful handling of AccessDenied errors."""
        from botocore.exceptions import ClientError

        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            # All paginators raise AccessDenied
            mock_paginator = MagicMock()
            mock_paginator.paginate.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "ListFunctions"
            )
            mock_lambda_client.get_paginator.return_value = mock_paginator

            # Should handle gracefully and return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)

    def test_lambda_collector_vpc_config(self, mock_lambda_client):
        """Test Lambda function with VPC configuration."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_functions":
                    mock_paginator.paginate.return_value = [{
                        "Functions": [
                            {
                                "FunctionName": "vpc-function",
                                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:vpc-function",
                                "Runtime": "python3.11",
                                "Handler": "index.handler",
                                "Role": "arn:aws:iam::123456789012:role/lambda-role",
                                "VpcConfig": {
                                    "VpcId": "vpc-12345678",
                                    "SubnetIds": ["subnet-11111111", "subnet-22222222"],
                                    "SecurityGroupIds": ["sg-12345678"],
                                }
                            }
                        ]
                    }]
                elif method_name == "list_layers":
                    mock_paginator.paginate.return_value = [{"Layers": []}]
                elif method_name == "list_event_source_mappings":
                    mock_paginator.paginate.return_value = [{"EventSourceMappings": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_lambda_client.get_paginator.side_effect = get_paginator_side_effect
            mock_lambda_client.list_tags.return_value = {"Tags": {}}
            mock_lambda_client.get_policy.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetPolicy")
            mock_lambda_client.get_function_url_config.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetFunctionUrlConfig")

            assets = collector.collect()

            func_assets = [a for a in assets if a.resource_type == "aws_lambda_function"]
            assert len(func_assets) == 1

            func = func_assets[0]
            assert func.raw_config["in_vpc"] is True
            assert func.raw_config["vpc_config"]["vpc_id"] == "vpc-12345678"
            assert len(func.raw_config["vpc_config"]["subnet_ids"]) == 2

    def test_lambda_collector_environment_variables(self, mock_lambda_client):
        """Test environment variable name extraction (not values)."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_functions":
                    mock_paginator.paginate.return_value = [{
                        "Functions": [
                            {
                                "FunctionName": "env-function",
                                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:env-function",
                                "Runtime": "python3.11",
                                "Handler": "index.handler",
                                "Role": "arn:aws:iam::123456789012:role/lambda-role",
                                "Environment": {
                                    "Variables": {
                                        "DATABASE_URL": "secret-connection-string",
                                        "API_KEY": "secret-key",
                                        "LOG_LEVEL": "INFO",
                                    }
                                }
                            }
                        ]
                    }]
                elif method_name == "list_layers":
                    mock_paginator.paginate.return_value = [{"Layers": []}]
                elif method_name == "list_event_source_mappings":
                    mock_paginator.paginate.return_value = [{"EventSourceMappings": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_lambda_client.get_paginator.side_effect = get_paginator_side_effect
            mock_lambda_client.list_tags.return_value = {"Tags": {}}
            mock_lambda_client.get_policy.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetPolicy")
            mock_lambda_client.get_function_url_config.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetFunctionUrlConfig")

            assets = collector.collect()

            func_assets = [a for a in assets if a.resource_type == "aws_lambda_function"]
            assert len(func_assets) == 1

            func = func_assets[0]
            assert func.raw_config["has_environment_variables"] is True
            # Only names, not values
            env_names = func.raw_config["environment_variables"]
            assert "DATABASE_URL" in env_names
            assert "API_KEY" in env_names
            # Values should not be stored
            assert "secret-connection-string" not in str(func.raw_config)
            assert "secret-key" not in str(func.raw_config)

    def test_lambda_collector_full_collection(self, mock_lambda_client):
        """Test full collection with all resource types."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_functions":
                    mock_paginator.paginate.return_value = [{
                        "Functions": [
                            {
                                "FunctionName": "test-function",
                                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-function",
                                "Runtime": "python3.11",
                                "Handler": "index.handler",
                                "Role": "arn:aws:iam::123456789012:role/lambda-role",
                            }
                        ]
                    }]
                elif method_name == "list_layers":
                    mock_paginator.paginate.return_value = [{
                        "Layers": [
                            {
                                "LayerName": "test-layer",
                                "LayerArn": "arn:aws:lambda:us-east-1:123456789012:layer:test-layer",
                                "LatestMatchingVersion": {"Version": 1},
                            }
                        ]
                    }]
                elif method_name == "list_event_source_mappings":
                    mock_paginator.paginate.return_value = [{
                        "EventSourceMappings": [
                            {
                                "UUID": "12345678-1234-1234-1234-123456789012",
                                "EventSourceArn": "arn:aws:dynamodb:us-east-1:123456789012:table/my-table/stream/123",
                                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-function",
                                "State": "Enabled",
                            }
                        ]
                    }]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_lambda_client.get_paginator.side_effect = get_paginator_side_effect
            mock_lambda_client.list_tags.return_value = {"Tags": {}}
            mock_lambda_client.get_policy.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetPolicy")
            mock_lambda_client.get_function_url_config.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetFunctionUrlConfig")
            mock_lambda_client.get_layer_version_policy.side_effect = mock_lambda_client.exceptions.ResourceNotFoundException({}, "GetLayerVersionPolicy")

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)

            # Should have all resource types
            resource_types = set(a.resource_type for a in assets)
            assert "aws_lambda_function" in resource_types
            assert "aws_lambda_layer" in resource_types
            assert "aws_lambda_event_source_mapping" in resource_types

    def test_lambda_collector_event_source_type_detection(self, mock_lambda_client):
        """Test detection of different event source types."""
        with patch.object(LambdaCollector, "_get_client", return_value=mock_lambda_client):
            collector = LambdaCollector()

            # Test different ARN patterns
            test_cases = [
                ("arn:aws:sqs:us-east-1:123:queue", "sqs"),
                ("arn:aws:kinesis:us-east-1:123:stream/mystream", "kinesis"),
                ("arn:aws:dynamodb:us-east-1:123:table/t/stream/s", "dynamodb"),
                ("arn:aws:kafka:us-east-1:123:cluster/c", "kafka"),
                ("arn:aws:mq:us-east-1:123:broker:b", "mq"),
                ("", "unknown"),
            ]

            for arn, expected_type in test_cases:
                result = collector._determine_event_source_type(arn)
                assert result == expected_type, f"Expected {expected_type} for {arn}, got {result}"
