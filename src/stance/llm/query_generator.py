"""
Query generator for Mantissa Stance.

Generates SQL queries from natural language questions using LLM providers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from stance.llm.base import LLMProvider, LLMError


@dataclass
class GeneratedQuery:
    """Result of query generation."""

    question: str
    sql: str
    explanation: str
    is_valid: bool
    validation_errors: list[str]


# Default schema context for posture queries
POSTURE_SCHEMA = """
Available tables:

1. assets
   - id: Resource ARN/ID (string)
   - cloud_provider: aws|azure|gcp (string)
   - account_id: Cloud account (string)
   - region: Geographic region (string)
   - resource_type: aws_s3_bucket, aws_ec2_instance, etc. (string)
   - name: Resource name (string)
   - network_exposure: internet_facing|internal|isolated (string)
   - tags: Key-value pairs (JSON)
   - raw_config: Full configuration (JSON)

2. findings
   - id: Finding ID (string)
   - asset_id: FK to assets (string)
   - finding_type: misconfiguration|vulnerability (string)
   - severity: critical|high|medium|low|info (string)
   - status: open|resolved|suppressed|false_positive (string)
   - title: Finding title (string)
   - description: Finding description (string)
   - rule_id: Policy rule ID (string)
   - cve_id: CVE identifier for vulns (string)
   - cvss_score: CVSS score for vulns (float)
   - compliance_frameworks: Array of framework controls (JSON)
   - remediation_guidance: Fix guidance (string)

Common query patterns:
- Critical findings: WHERE severity = 'critical' AND status = 'open'
- Internet-facing: WHERE network_exposure = 'internet_facing'
- By resource type: WHERE resource_type = 'aws_s3_bucket'
- Join for context: SELECT f.*, a.name FROM findings f JOIN assets a ON f.asset_id = a.id
"""

# System prompt for SQL generation
SYSTEM_PROMPT = """You are a SQL query generator for a cloud security posture database.

Rules:
1. Generate only SELECT queries - never INSERT, UPDATE, DELETE, or DROP
2. Use standard SQL syntax compatible with SQLite
3. Return only the SQL query, no explanation or markdown
4. Use lowercase for SQL keywords (select, from, where, etc.)
5. Always include appropriate WHERE clauses based on the question
6. Use JOINs when relating findings to assets
7. Limit results when counting or listing (use LIMIT 100 unless specified)

Common mappings:
- "critical" findings -> severity = 'critical' AND status = 'open'
- "vulnerabilities" -> finding_type = 'vulnerability'
- "misconfigurations" -> finding_type = 'misconfiguration'
- "internet facing" / "public" -> network_exposure = 'internet_facing'
- "S3 buckets" -> resource_type = 'aws_s3_bucket'
- "EC2 instances" -> resource_type = 'aws_ec2_instance'
- "IAM users" -> resource_type = 'aws_iam_user'
"""


class QueryGenerator:
    """
    Generates SQL queries from natural language questions.

    Uses an LLM provider to translate natural language into
    SQL queries, then validates the generated SQL for safety.
    """

    def __init__(
        self,
        llm_provider: LLMProvider,
        schema_context: str | None = None,
    ):
        """
        Initialize the query generator.

        Args:
            llm_provider: LLM provider for generation
            schema_context: Optional custom schema context.
                          Defaults to POSTURE_SCHEMA.
        """
        self._llm = llm_provider
        self._schema = schema_context or POSTURE_SCHEMA

    def generate_query(
        self,
        question: str,
        context: dict[str, Any] | None = None,
    ) -> GeneratedQuery:
        """
        Generate SQL query from natural language question.

        Args:
            question: Natural language question
            context: Optional additional context

        Returns:
            GeneratedQuery with SQL and validation results
        """
        # Build the prompt
        prompt = self._build_prompt(question, context)

        try:
            # Generate SQL using LLM
            sql = self._llm.generate(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT,
                max_tokens=500,
            )

            # Clean up the response
            sql = self._clean_sql(sql)

            # Validate the generated SQL
            validation_errors = self.validate_query(sql)
            is_valid = len(validation_errors) == 0

            return GeneratedQuery(
                question=question,
                sql=sql,
                explanation="",  # Could ask LLM for explanation if needed
                is_valid=is_valid,
                validation_errors=validation_errors,
            )

        except LLMError as e:
            return GeneratedQuery(
                question=question,
                sql="",
                explanation="",
                is_valid=False,
                validation_errors=[f"LLM error: {e}"],
            )

    def validate_query(self, sql: str) -> list[str]:
        """
        Validate that generated SQL is safe to execute.

        Args:
            sql: SQL query to validate

        Returns:
            List of validation errors (empty if safe)
        """
        errors: list[str] = []

        if not sql or not sql.strip():
            errors.append("Empty query")
            return errors

        # Normalize for checking
        normalized = " ".join(sql.split()).upper()

        # Must start with SELECT
        if not normalized.startswith("SELECT"):
            errors.append("Query must start with SELECT")

        # Check for dangerous keywords
        dangerous_keywords = [
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "ALTER",
            "CREATE",
            "TRUNCATE",
            "REPLACE",
            "GRANT",
            "REVOKE",
            "EXEC",
            "EXECUTE",
        ]

        for keyword in dangerous_keywords:
            pattern = r"\b" + keyword + r"\b"
            if re.search(pattern, normalized):
                errors.append(f"Query cannot contain {keyword}")

        # Check for comment sequences that could hide malicious SQL
        if "--" in sql:
            errors.append("Query cannot contain SQL comments (--)")
        if "/*" in sql or "*/" in sql:
            errors.append("Query cannot contain block comments (/* */)")

        # Check for multiple statements
        # Allow trailing semicolon but no semicolons in the middle
        sql_stripped = sql.strip().rstrip(";")
        if ";" in sql_stripped:
            errors.append("Query cannot contain multiple statements")

        # Check for UNION-based injection attempts
        if re.search(r"\bUNION\b.*\bSELECT\b", normalized):
            # Allow UNION but warn if it looks suspicious
            if "UNION ALL" not in normalized and "UNION SELECT" in normalized:
                # Simple UNION SELECT might be injection
                pass  # For now, allow it - complex to validate

        return errors

    def _build_prompt(
        self,
        question: str,
        context: dict[str, Any] | None,
    ) -> str:
        """
        Build the prompt for the LLM.

        Args:
            question: User's question
            context: Optional additional context

        Returns:
            Formatted prompt string
        """
        prompt_parts = [
            "Database schema:",
            self._schema,
            "",
            "Question:",
            question,
        ]

        if context:
            prompt_parts.extend([
                "",
                "Additional context:",
                str(context),
            ])

        prompt_parts.extend([
            "",
            "Generate a SQL query to answer this question. Return only the SQL, nothing else.",
        ])

        return "\n".join(prompt_parts)

    def _clean_sql(self, sql: str) -> str:
        """
        Clean up LLM-generated SQL.

        Args:
            sql: Raw SQL from LLM

        Returns:
            Cleaned SQL string
        """
        # Remove markdown code blocks
        sql = re.sub(r"```sql\s*", "", sql)
        sql = re.sub(r"```\s*", "", sql)

        # Remove leading/trailing whitespace
        sql = sql.strip()

        # Remove any "SQL:" or similar prefixes
        sql = re.sub(r"^(?:SQL|Query|Answer):\s*", "", sql, flags=re.IGNORECASE)

        return sql.strip()
