"""
Cloud-native query engines for Mantissa Stance.

Provides unified query interface across AWS Athena, Google BigQuery,
and Azure Synapse Analytics for querying assets and findings data.
"""

from stance.query.base import (
    QueryEngine,
    QueryResult,
    TableSchema,
    CostEstimate,
    QueryExecutionError,
    QueryValidationError,
    ASSETS_SCHEMA,
    FINDINGS_SCHEMA,
    get_common_schemas,
)
from stance.query.athena import AthenaQueryEngine
from stance.query.bigquery import BigQueryEngine
from stance.query.synapse import SynapseQueryEngine

__all__ = [
    # Base classes and types
    "QueryEngine",
    "QueryResult",
    "TableSchema",
    "CostEstimate",
    # Exceptions
    "QueryExecutionError",
    "QueryValidationError",
    # Engine implementations
    "AthenaQueryEngine",
    "BigQueryEngine",
    "SynapseQueryEngine",
    # Common schemas
    "ASSETS_SCHEMA",
    "FINDINGS_SCHEMA",
    "get_common_schemas",
    # Factory function
    "get_query_engine",
]


def get_query_engine(
    provider: str,
    **kwargs,
) -> QueryEngine:
    """
    Factory function to get appropriate query engine for cloud provider.

    Args:
        provider: Cloud provider name ("aws", "gcp", "azure")
        **kwargs: Provider-specific configuration

    Returns:
        Configured QueryEngine instance

    Raises:
        ValueError: If provider is not supported

    Examples:
        # AWS Athena
        engine = get_query_engine(
            "aws",
            database="stance_data",
            workgroup="stance-workgroup",
            output_location="s3://bucket/results/"
        )

        # GCP BigQuery
        engine = get_query_engine(
            "gcp",
            project_id="my-project",
            dataset_id="stance_data"
        )

        # Azure Synapse
        engine = get_query_engine(
            "azure",
            server="workspace.sql.azuresynapse.net",
            database="stance_db"
        )
    """
    provider = provider.lower()

    if provider == "aws":
        return AthenaQueryEngine(
            database=kwargs.get("database", "default"),
            workgroup=kwargs.get("workgroup", "primary"),
            output_location=kwargs.get("output_location"),
            region=kwargs.get("region", "us-east-1"),
            session=kwargs.get("session"),
        )

    elif provider == "gcp":
        return BigQueryEngine(
            project_id=kwargs["project_id"],
            dataset_id=kwargs["dataset_id"],
            location=kwargs.get("location", "US"),
            credentials=kwargs.get("credentials"),
        )

    elif provider == "azure":
        return SynapseQueryEngine(
            server=kwargs["server"],
            database=kwargs["database"],
            credential=kwargs.get("credential"),
            connection_string=kwargs.get("connection_string"),
        )

    else:
        raise ValueError(
            f"Unsupported provider: {provider}. "
            f"Supported providers: aws, gcp, azure"
        )
