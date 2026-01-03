"""
AWS Bedrock collector for Mantissa Stance.

Collects Bedrock model access, custom models, provisioned throughput,
guardrails, and agent configurations for AI/ML security posture assessment.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)

logger = logging.getLogger(__name__)

# Foundation models with known security considerations
HIGH_RISK_MODELS = {
    # Models with potentially less restrictive content policies
    "anthropic.claude-instant-v1",
    "anthropic.claude-v1",
    "meta.llama2-13b-v1",
    "meta.llama2-70b-v1",
}

# Models with enhanced safety features
RECOMMENDED_MODELS = {
    "anthropic.claude-3-haiku-20240307-v1:0",
    "anthropic.claude-3-sonnet-20240229-v1:0",
    "anthropic.claude-3-opus-20240229-v1:0",
    "amazon.titan-text-express-v1",
    "amazon.titan-text-lite-v1",
}


class BedrockCollector(BaseCollector):
    """
    Collects AWS Bedrock resources and configurations.

    Gathers Bedrock model access permissions, custom models, provisioned
    throughput, guardrails, knowledge bases, and agent configurations
    for security posture assessment. All API calls are read-only.
    """

    collector_name = "aws_bedrock"
    resource_types = [
        "aws_bedrock_model_access",
        "aws_bedrock_custom_model",
        "aws_bedrock_provisioned_throughput",
        "aws_bedrock_guardrail",
        "aws_bedrock_knowledge_base",
        "aws_bedrock_agent",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all Bedrock resources.

        Returns:
            Collection of Bedrock assets
        """
        assets: list[Asset] = []

        # Collect foundation model access
        try:
            assets.extend(self._collect_foundation_model_access())
        except Exception as e:
            logger.warning(f"Failed to collect Bedrock foundation model access: {e}")

        # Collect custom models
        try:
            assets.extend(self._collect_custom_models())
        except Exception as e:
            logger.warning(f"Failed to collect Bedrock custom models: {e}")

        # Collect provisioned throughput
        try:
            assets.extend(self._collect_provisioned_throughput())
        except Exception as e:
            logger.warning(f"Failed to collect Bedrock provisioned throughput: {e}")

        # Collect guardrails
        try:
            assets.extend(self._collect_guardrails())
        except Exception as e:
            logger.warning(f"Failed to collect Bedrock guardrails: {e}")

        # Collect knowledge bases
        try:
            assets.extend(self._collect_knowledge_bases())
        except Exception as e:
            logger.warning(f"Failed to collect Bedrock knowledge bases: {e}")

        # Collect agents
        try:
            assets.extend(self._collect_agents())
        except Exception as e:
            logger.warning(f"Failed to collect Bedrock agents: {e}")

        return AssetCollection(assets)

    def _collect_foundation_model_access(self) -> list[Asset]:
        """Collect foundation models that are accessible."""
        bedrock_client = self._get_client("bedrock")
        assets: list[Asset] = []
        now = self._now()

        try:
            # List accessible foundation models
            response = bedrock_client.list_foundation_models()
            models = response.get("modelSummaries", [])
        except Exception as e:
            logger.warning(f"Failed to list foundation models: {e}")
            return assets

        for model in models:
            model_id = model.get("modelId", "")
            model_arn = model.get("modelArn", "")
            provider_name = model.get("providerName", "")
            model_name = model.get("modelName", model_id)

            # Check security considerations
            is_high_risk = model_id in HIGH_RISK_MODELS
            is_recommended = model_id in RECOMMENDED_MODELS

            # Input/output modalities
            input_modalities = model.get("inputModalities", [])
            output_modalities = model.get("outputModalities", [])

            # Inference types supported
            inference_types = model.get("inferenceTypesSupported", [])

            # Customization support
            customizations_supported = model.get("customizationsSupported", [])

            raw_config: dict[str, Any] = {
                "model_id": model_id,
                "model_arn": model_arn,
                "model_name": model_name,
                "provider_name": provider_name,
                # Security assessment
                "is_high_risk_model": is_high_risk,
                "is_recommended_model": is_recommended,
                # Model capabilities
                "input_modalities": input_modalities,
                "output_modalities": output_modalities,
                "inference_types_supported": inference_types,
                "customizations_supported": customizations_supported,
                # Model lifecycle
                "model_lifecycle": model.get("modelLifecycle", {}),
                # Response streaming
                "response_streaming_supported": model.get("responseStreamingSupported", False),
            }

            asset = Asset(
                asset_id=model_arn or f"arn:aws:bedrock:{self.region}::foundation-model/{model_id}",
                asset_type="aws_bedrock_model_access",
                name=model_name,
                region=self.region,
                account_id=self.account_id,
                tags={},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_custom_models(self) -> list[Asset]:
        """Collect custom/fine-tuned models."""
        bedrock_client = self._get_client("bedrock")
        assets: list[Asset] = []
        now = self._now()

        try:
            response = bedrock_client.list_custom_models()
            models = response.get("modelSummaries", [])
        except Exception as e:
            logger.warning(f"Failed to list custom models: {e}")
            return assets

        for model in models:
            model_arn = model.get("modelArn", "")
            model_name = model.get("modelName", "")

            # Get detailed configuration
            try:
                details = bedrock_client.get_custom_model(modelIdentifier=model_arn)
            except Exception as e:
                logger.warning(f"Failed to describe custom model {model_name}: {e}")
                details = model

            # Base model info
            base_model_arn = details.get("baseModelArn", "")

            # Training data config
            training_data_config = details.get("trainingDataConfig", {})
            training_data_s3_uri = training_data_config.get("s3Uri", "")

            # Output data config
            output_data_config = details.get("outputDataConfig", {})
            output_s3_uri = output_data_config.get("s3Uri", "")

            # Hyperparameters (keys only)
            hyperparameters = list(details.get("hyperParameters", {}).keys())

            # Validation data config
            validation_data_config = details.get("validationDataConfig", {})

            # VPC config for training
            vpc_config = details.get("vpcConfig", {})
            in_vpc = bool(vpc_config.get("subnetIds"))

            raw_config: dict[str, Any] = {
                "model_arn": model_arn,
                "model_name": model_name,
                "base_model_arn": base_model_arn,
                "creation_time": str(details.get("creationTime", "")),
                # Customization type
                "customization_type": details.get("customizationType"),
                # Job info
                "job_name": details.get("jobName"),
                "job_arn": details.get("jobArn"),
                # Training data
                "training_data_config": {
                    "s3_uri": training_data_s3_uri,
                },
                # Output data
                "output_data_config": {
                    "s3_uri": output_s3_uri,
                },
                # Validation data
                "has_validation_data": bool(validation_data_config.get("validators")),
                # Hyperparameters (keys only for security)
                "hyperparameters": hyperparameters,
                # VPC configuration
                "vpc_config": {
                    "subnet_ids": vpc_config.get("subnetIds", []),
                    "security_group_ids": vpc_config.get("securityGroupIds", []),
                },
                "in_vpc": in_vpc,
            }

            asset = Asset(
                asset_id=model_arn,
                asset_type="aws_bedrock_custom_model",
                name=model_name,
                region=self.region,
                account_id=self.account_id,
                tags={},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_provisioned_throughput(self) -> list[Asset]:
        """Collect provisioned model throughput."""
        bedrock_client = self._get_client("bedrock")
        assets: list[Asset] = []
        now = self._now()

        try:
            response = bedrock_client.list_provisioned_model_throughputs()
            throughputs = response.get("provisionedModelSummaries", [])
        except Exception as e:
            logger.warning(f"Failed to list provisioned throughputs: {e}")
            return assets

        for throughput in throughputs:
            throughput_arn = throughput.get("provisionedModelArn", "")
            throughput_name = throughput.get("provisionedModelName", "")

            # Get detailed configuration
            try:
                details = bedrock_client.get_provisioned_model_throughput(
                    provisionedModelId=throughput_arn
                )
            except Exception as e:
                logger.warning(f"Failed to describe provisioned throughput {throughput_name}: {e}")
                details = throughput

            raw_config: dict[str, Any] = {
                "provisioned_model_arn": throughput_arn,
                "provisioned_model_name": throughput_name,
                "status": details.get("status"),
                "creation_time": str(details.get("creationTime", "")),
                "last_modified_time": str(details.get("lastModifiedTime", "")),
                # Model info
                "model_arn": details.get("modelArn"),
                "desired_model_arn": details.get("desiredModelArn"),
                "foundation_model_arn": details.get("foundationModelArn"),
                # Capacity
                "model_units": details.get("modelUnits"),
                "desired_model_units": details.get("desiredModelUnits"),
                # Commitment
                "commitment_duration": details.get("commitmentDuration"),
                "commitment_expiration_time": str(details.get("commitmentExpirationTime", "")),
                # Failure reason if any
                "failure_message": details.get("failureMessage"),
            }

            asset = Asset(
                asset_id=throughput_arn,
                asset_type="aws_bedrock_provisioned_throughput",
                name=throughput_name,
                region=self.region,
                account_id=self.account_id,
                tags={},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_guardrails(self) -> list[Asset]:
        """Collect Bedrock guardrails."""
        bedrock_client = self._get_client("bedrock")
        assets: list[Asset] = []
        now = self._now()

        try:
            response = bedrock_client.list_guardrails()
            guardrails = response.get("guardrails", [])
        except Exception as e:
            logger.warning(f"Failed to list guardrails: {e}")
            return assets

        for guardrail in guardrails:
            guardrail_id = guardrail.get("id", "")
            guardrail_arn = guardrail.get("arn", "")
            guardrail_name = guardrail.get("name", "")

            # Get detailed configuration
            try:
                details = bedrock_client.get_guardrail(
                    guardrailIdentifier=guardrail_id
                )
            except Exception as e:
                logger.warning(f"Failed to describe guardrail {guardrail_name}: {e}")
                details = guardrail

            # Topic policy
            topic_policy = details.get("topicPolicy", {})
            topics_config = topic_policy.get("topics", [])

            # Content policy
            content_policy = details.get("contentPolicy", {})
            filters_config = content_policy.get("filters", [])

            # Word policy
            word_policy = details.get("wordPolicy", {})
            managed_word_lists = word_policy.get("managedWordListsConfig", [])
            words_config = word_policy.get("wordsConfig", [])

            # Sensitive information policy
            sensitive_info_policy = details.get("sensitiveInformationPolicy", {})
            pii_entities = sensitive_info_policy.get("piiEntities", [])
            regexes = sensitive_info_policy.get("regexes", [])

            raw_config: dict[str, Any] = {
                "guardrail_id": guardrail_id,
                "guardrail_arn": guardrail_arn,
                "guardrail_name": guardrail_name,
                "version": details.get("version"),
                "status": details.get("status"),
                "creation_time": str(details.get("createdAt", "")),
                "updated_time": str(details.get("updatedAt", "")),
                # KMS encryption
                "kms_key_arn": details.get("kmsKeyArn"),
                "has_kms_encryption": bool(details.get("kmsKeyArn")),
                # Topic policy
                "topic_policy": {
                    "topics_count": len(topics_config),
                    "topics": [
                        {
                            "name": t.get("name"),
                            "type": t.get("type"),
                            "definition": t.get("definition", "")[:100],  # Truncate for security
                        }
                        for t in topics_config[:10]  # Limit to first 10
                    ],
                },
                # Content policy
                "content_policy": {
                    "filters_count": len(filters_config),
                    "filters": [
                        {
                            "type": f.get("type"),
                            "input_strength": f.get("inputStrength"),
                            "output_strength": f.get("outputStrength"),
                        }
                        for f in filters_config
                    ],
                },
                # Word policy
                "word_policy": {
                    "managed_word_lists_count": len(managed_word_lists),
                    "custom_words_count": len(words_config),
                },
                # Sensitive information policy
                "sensitive_info_policy": {
                    "pii_entities_count": len(pii_entities),
                    "pii_entity_types": [p.get("type") for p in pii_entities],
                    "regexes_count": len(regexes),
                },
                # Blocked messages
                "blocked_input_messaging": details.get("blockedInputMessaging", "")[:100],
                "blocked_outputs_messaging": details.get("blockedOutputsMessaging", "")[:100],
                # Failure reasons
                "failure_recommendations": details.get("failureRecommendations", []),
            }

            asset = Asset(
                asset_id=guardrail_arn,
                asset_type="aws_bedrock_guardrail",
                name=guardrail_name,
                region=self.region,
                account_id=self.account_id,
                tags={},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_knowledge_bases(self) -> list[Asset]:
        """Collect Bedrock knowledge bases."""
        bedrock_agent_client = self._get_client("bedrock-agent")
        assets: list[Asset] = []
        now = self._now()

        try:
            response = bedrock_agent_client.list_knowledge_bases()
            knowledge_bases = response.get("knowledgeBaseSummaries", [])
        except Exception as e:
            logger.warning(f"Failed to list knowledge bases: {e}")
            return assets

        for kb in knowledge_bases:
            kb_id = kb.get("knowledgeBaseId", "")
            kb_name = kb.get("name", "")

            # Get detailed configuration
            try:
                details = bedrock_agent_client.get_knowledge_base(
                    knowledgeBaseId=kb_id
                )
                kb_details = details.get("knowledgeBase", {})
            except Exception as e:
                logger.warning(f"Failed to describe knowledge base {kb_name}: {e}")
                kb_details = kb

            # Knowledge base configuration
            kb_config = kb_details.get("knowledgeBaseConfiguration", {})
            vector_config = kb_config.get("vectorKnowledgeBaseConfiguration", {})

            # Storage configuration
            storage_config = kb_details.get("storageConfiguration", {})
            storage_type = storage_config.get("type", "")

            raw_config: dict[str, Any] = {
                "knowledge_base_id": kb_id,
                "knowledge_base_arn": kb_details.get("knowledgeBaseArn"),
                "name": kb_name,
                "description": kb_details.get("description", ""),
                "status": kb_details.get("status"),
                "creation_time": str(kb_details.get("createdAt", "")),
                "updated_time": str(kb_details.get("updatedAt", "")),
                # Role
                "role_arn": kb_details.get("roleArn"),
                # Configuration
                "knowledge_base_configuration": {
                    "type": kb_config.get("type"),
                    "embedding_model_arn": vector_config.get("embeddingModelArn"),
                },
                # Storage
                "storage_configuration": {
                    "type": storage_type,
                },
                # Failure reasons
                "failure_reasons": kb_details.get("failureReasons", []),
            }

            asset = Asset(
                asset_id=kb_details.get("knowledgeBaseArn", f"arn:aws:bedrock:{self.region}:{self.account_id}:knowledge-base/{kb_id}"),
                asset_type="aws_bedrock_knowledge_base",
                name=kb_name,
                region=self.region,
                account_id=self.account_id,
                tags={},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_agents(self) -> list[Asset]:
        """Collect Bedrock agents."""
        bedrock_agent_client = self._get_client("bedrock-agent")
        assets: list[Asset] = []
        now = self._now()

        try:
            response = bedrock_agent_client.list_agents()
            agents = response.get("agentSummaries", [])
        except Exception as e:
            logger.warning(f"Failed to list agents: {e}")
            return assets

        for agent in agents:
            agent_id = agent.get("agentId", "")
            agent_name = agent.get("agentName", "")

            # Get detailed configuration
            try:
                details = bedrock_agent_client.get_agent(agentId=agent_id)
                agent_details = details.get("agent", {})
            except Exception as e:
                logger.warning(f"Failed to describe agent {agent_name}: {e}")
                agent_details = agent

            # Prompt override configuration
            prompt_override = agent_details.get("promptOverrideConfiguration", {})

            # Guardrail configuration
            guardrail_config = agent_details.get("guardrailConfiguration", {})

            raw_config: dict[str, Any] = {
                "agent_id": agent_id,
                "agent_arn": agent_details.get("agentArn"),
                "agent_name": agent_name,
                "agent_version": agent_details.get("agentVersion"),
                "status": agent_details.get("agentStatus"),
                "creation_time": str(agent_details.get("createdAt", "")),
                "updated_time": str(agent_details.get("updatedAt", "")),
                "prepared_at": str(agent_details.get("preparedAt", "")),
                # Model and instruction
                "foundation_model": agent_details.get("foundationModel"),
                "instruction": agent_details.get("instruction", "")[:200],  # Truncate
                "idle_session_ttl_seconds": agent_details.get("idleSessionTTLInSeconds"),
                # Role
                "agent_resource_role_arn": agent_details.get("agentResourceRoleArn"),
                # KMS encryption
                "customer_encryption_key_arn": agent_details.get("customerEncryptionKeyArn"),
                "has_customer_encryption": bool(agent_details.get("customerEncryptionKeyArn")),
                # Guardrail
                "guardrail_configuration": {
                    "guardrail_identifier": guardrail_config.get("guardrailIdentifier"),
                    "guardrail_version": guardrail_config.get("guardrailVersion"),
                },
                "has_guardrail": bool(guardrail_config.get("guardrailIdentifier")),
                # Prompt override
                "has_prompt_override": bool(prompt_override),
                # Failure reasons
                "failure_reasons": agent_details.get("failureReasons", []),
                # Recommended actions
                "recommended_actions": agent_details.get("recommendedActions", []),
            }

            asset = Asset(
                asset_id=agent_details.get("agentArn", f"arn:aws:bedrock:{self.region}:{self.account_id}:agent/{agent_id}"),
                asset_type="aws_bedrock_agent",
                name=agent_name,
                region=self.region,
                account_id=self.account_id,
                tags={},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _now(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
