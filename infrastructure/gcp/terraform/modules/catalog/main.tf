# GCP Catalog Module for Mantissa Stance
#
# Creates BigQuery tables for assets and findings data,
# views for compliance reporting, and scheduled queries for aggregations.

# BigQuery table for assets
resource "google_bigquery_table" "assets" {
  dataset_id          = var.dataset_id
  table_id            = "assets"
  project             = var.project_id
  deletion_protection = var.deletion_protection

  time_partitioning {
    type  = "DAY"
    field = "last_seen"
  }

  clustering = ["cloud_provider", "resource_type", "region"]

  schema = jsonencode([
    {
      name        = "id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Unique asset identifier (ARN, resource path, etc.)"
    },
    {
      name        = "cloud_provider"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Cloud provider (aws, gcp, azure)"
    },
    {
      name        = "account_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Cloud account identifier"
    },
    {
      name        = "region"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Cloud region"
    },
    {
      name        = "resource_type"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Resource type (e.g., aws_s3_bucket, gcp_compute_instance)"
    },
    {
      name        = "name"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Resource name"
    },
    {
      name        = "network_exposure"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Network exposure level (internet_facing, internal, isolated)"
    },
    {
      name        = "tags"
      type        = "JSON"
      mode        = "NULLABLE"
      description = "Resource tags as JSON"
    },
    {
      name        = "created_at"
      type        = "TIMESTAMP"
      mode        = "NULLABLE"
      description = "Resource creation timestamp"
    },
    {
      name        = "last_seen"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Last scan timestamp"
    },
    {
      name        = "raw_config"
      type        = "JSON"
      mode        = "NULLABLE"
      description = "Full resource configuration as JSON"
    },
    {
      name        = "snapshot_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Scan snapshot identifier"
    }
  ])

  labels = var.labels
}

# BigQuery table for findings
resource "google_bigquery_table" "findings" {
  dataset_id          = var.dataset_id
  table_id            = "findings"
  project             = var.project_id
  deletion_protection = var.deletion_protection

  time_partitioning {
    type  = "DAY"
    field = "last_seen"
  }

  clustering = ["severity", "finding_type", "status"]

  schema = jsonencode([
    {
      name        = "id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Unique finding identifier"
    },
    {
      name        = "asset_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Reference to affected asset"
    },
    {
      name        = "finding_type"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Finding type (misconfiguration, vulnerability)"
    },
    {
      name        = "severity"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Severity level (critical, high, medium, low, info)"
    },
    {
      name        = "status"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Finding status (open, resolved, suppressed, false_positive)"
    },
    {
      name        = "title"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Short finding description"
    },
    {
      name        = "description"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Detailed finding description"
    },
    {
      name        = "rule_id"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Policy rule that triggered the finding"
    },
    {
      name        = "cve_id"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "CVE identifier for vulnerabilities"
    },
    {
      name        = "cvss_score"
      type        = "FLOAT64"
      mode        = "NULLABLE"
      description = "CVSS score for vulnerabilities"
    },
    {
      name        = "compliance_frameworks"
      type        = "JSON"
      mode        = "NULLABLE"
      description = "Mapped compliance controls as JSON array"
    },
    {
      name        = "remediation_guidance"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Remediation guidance text"
    },
    {
      name        = "first_seen"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "First detection timestamp"
    },
    {
      name        = "last_seen"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Last detection timestamp"
    },
    {
      name        = "snapshot_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Scan snapshot identifier"
    }
  ])

  labels = var.labels
}

# View for compliance summary by framework
resource "google_bigquery_table" "compliance_summary_view" {
  dataset_id          = var.dataset_id
  table_id            = "compliance_summary"
  project             = var.project_id
  deletion_protection = false

  view {
    query          = <<-SQL
      SELECT
        JSON_EXTRACT_SCALAR(framework, '$.framework') AS framework,
        JSON_EXTRACT_SCALAR(framework, '$.control') AS control,
        COUNT(DISTINCT f.id) AS finding_count,
        COUNTIF(f.status = 'open') AS open_findings,
        COUNTIF(f.severity = 'critical') AS critical_count,
        COUNTIF(f.severity = 'high') AS high_count,
        COUNTIF(f.severity = 'medium') AS medium_count,
        COUNTIF(f.severity = 'low') AS low_count,
        MAX(f.last_seen) AS last_scan
      FROM
        `${var.project_id}.${var.dataset_id}.findings` f,
        UNNEST(JSON_EXTRACT_ARRAY(f.compliance_frameworks)) AS framework
      WHERE
        f.last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
      GROUP BY
        framework, control
      ORDER BY
        framework, control
    SQL
    use_legacy_sql = false
  }

  labels = var.labels

  depends_on = [google_bigquery_table.findings]
}

# View for asset inventory by cloud provider
resource "google_bigquery_table" "asset_inventory_view" {
  dataset_id          = var.dataset_id
  table_id            = "asset_inventory"
  project             = var.project_id
  deletion_protection = false

  view {
    query          = <<-SQL
      SELECT
        cloud_provider,
        resource_type,
        region,
        network_exposure,
        COUNT(*) AS asset_count,
        COUNTIF(network_exposure = 'internet_facing') AS internet_facing_count,
        MAX(last_seen) AS last_scan
      FROM
        `${var.project_id}.${var.dataset_id}.assets`
      WHERE
        last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
      GROUP BY
        cloud_provider, resource_type, region, network_exposure
      ORDER BY
        cloud_provider, resource_type
    SQL
    use_legacy_sql = false
  }

  labels = var.labels

  depends_on = [google_bigquery_table.assets]
}

# View for findings by severity trend
resource "google_bigquery_table" "severity_trend_view" {
  dataset_id          = var.dataset_id
  table_id            = "severity_trend"
  project             = var.project_id
  deletion_protection = false

  view {
    query          = <<-SQL
      SELECT
        DATE(last_seen) AS scan_date,
        severity,
        status,
        COUNT(*) AS finding_count
      FROM
        `${var.project_id}.${var.dataset_id}.findings`
      WHERE
        last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
      GROUP BY
        scan_date, severity, status
      ORDER BY
        scan_date DESC, severity
    SQL
    use_legacy_sql = false
  }

  labels = var.labels

  depends_on = [google_bigquery_table.findings]
}

# View for internet-facing assets with findings
resource "google_bigquery_table" "exposed_assets_view" {
  dataset_id          = var.dataset_id
  table_id            = "exposed_assets"
  project             = var.project_id
  deletion_protection = false

  view {
    query          = <<-SQL
      SELECT
        a.id AS asset_id,
        a.name AS asset_name,
        a.cloud_provider,
        a.resource_type,
        a.region,
        COUNT(f.id) AS finding_count,
        COUNTIF(f.severity = 'critical') AS critical_findings,
        COUNTIF(f.severity = 'high') AS high_findings,
        MAX(f.last_seen) AS last_scan
      FROM
        `${var.project_id}.${var.dataset_id}.assets` a
      LEFT JOIN
        `${var.project_id}.${var.dataset_id}.findings` f
        ON a.id = f.asset_id AND f.status = 'open'
      WHERE
        a.network_exposure = 'internet_facing'
        AND a.last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
      GROUP BY
        a.id, a.name, a.cloud_provider, a.resource_type, a.region
      HAVING
        critical_findings > 0 OR high_findings > 0
      ORDER BY
        critical_findings DESC, high_findings DESC
    SQL
    use_legacy_sql = false
  }

  labels = var.labels

  depends_on = [
    google_bigquery_table.assets,
    google_bigquery_table.findings
  ]
}

# Scheduled query for daily aggregation
resource "google_bigquery_data_transfer_config" "daily_aggregation" {
  count = var.enable_scheduled_queries ? 1 : 0

  display_name           = "stance-daily-aggregation"
  project                = var.project_id
  location               = var.location
  data_source_id         = "scheduled_query"
  schedule               = "every 24 hours"
  destination_dataset_id = var.dataset_id

  params = {
    query = <<-SQL
      MERGE `${var.project_id}.${var.dataset_id}.daily_summary` T
      USING (
        SELECT
          CURRENT_DATE() AS report_date,
          COUNT(DISTINCT a.id) AS total_assets,
          COUNTIF(a.network_exposure = 'internet_facing') AS internet_facing_assets,
          COUNT(DISTINCT f.id) AS total_findings,
          COUNTIF(f.severity = 'critical' AND f.status = 'open') AS critical_open,
          COUNTIF(f.severity = 'high' AND f.status = 'open') AS high_open,
          COUNTIF(f.severity = 'medium' AND f.status = 'open') AS medium_open,
          COUNTIF(f.severity = 'low' AND f.status = 'open') AS low_open,
          COUNTIF(f.status = 'resolved') AS resolved_today
        FROM
          `${var.project_id}.${var.dataset_id}.assets` a
        LEFT JOIN
          `${var.project_id}.${var.dataset_id}.findings` f
          ON DATE(a.last_seen) = CURRENT_DATE()
             AND DATE(f.last_seen) = CURRENT_DATE()
      ) S
      ON T.report_date = S.report_date
      WHEN MATCHED THEN UPDATE SET
        total_assets = S.total_assets,
        internet_facing_assets = S.internet_facing_assets,
        total_findings = S.total_findings,
        critical_open = S.critical_open,
        high_open = S.high_open,
        medium_open = S.medium_open,
        low_open = S.low_open,
        resolved_today = S.resolved_today
      WHEN NOT MATCHED THEN INSERT ROW
    SQL
  }

  service_account_name = var.service_account_email
}

# Daily summary table for scheduled query results
resource "google_bigquery_table" "daily_summary" {
  count = var.enable_scheduled_queries ? 1 : 0

  dataset_id          = var.dataset_id
  table_id            = "daily_summary"
  project             = var.project_id
  deletion_protection = var.deletion_protection

  schema = jsonencode([
    {
      name        = "report_date"
      type        = "DATE"
      mode        = "REQUIRED"
      description = "Report date"
    },
    {
      name        = "total_assets"
      type        = "INT64"
      mode        = "REQUIRED"
      description = "Total number of assets"
    },
    {
      name        = "internet_facing_assets"
      type        = "INT64"
      mode        = "REQUIRED"
      description = "Number of internet-facing assets"
    },
    {
      name        = "total_findings"
      type        = "INT64"
      mode        = "REQUIRED"
      description = "Total number of findings"
    },
    {
      name        = "critical_open"
      type        = "INT64"
      mode        = "REQUIRED"
      description = "Open critical severity findings"
    },
    {
      name        = "high_open"
      type        = "INT64"
      mode        = "REQUIRED"
      description = "Open high severity findings"
    },
    {
      name        = "medium_open"
      type        = "INT64"
      mode        = "REQUIRED"
      description = "Open medium severity findings"
    },
    {
      name        = "low_open"
      type        = "INT64"
      mode        = "REQUIRED"
      description = "Open low severity findings"
    },
    {
      name        = "resolved_today"
      type        = "INT64"
      mode        = "REQUIRED"
      description = "Findings resolved today"
    }
  ])

  labels = var.labels
}
