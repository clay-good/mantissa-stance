# stance.query

Cloud-native query engines for Mantissa Stance.

Provides unified query interface across AWS Athena, Google BigQuery,
and Azure Synapse Analytics for querying assets and findings data.

## Contents

### Functions

- [get_query_engine](#get_query_engine)

### `get_query_engine(provider: str, **kwargs) -> QueryEngine`

Factory function to get appropriate query engine for cloud provider.

**Parameters:**

- `provider` (`str`) - Cloud provider name ("aws", "gcp", "azure") **kwargs: Provider-specific configuration
- `**kwargs`

**Returns:**

`QueryEngine` - Configured QueryEngine instance

**Raises:**

- `ValueError`: If provider is not supported

**Examples:**

```python
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
```
