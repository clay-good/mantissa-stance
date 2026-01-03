# Azure Catalog Module for Mantissa Stance
#
# Creates Synapse serverless SQL pools with external tables for assets
# and findings data, and views for compliance reporting.

# Synapse Workspace
resource "azurerm_synapse_workspace" "stance" {
  name                                 = "${var.name_prefix}-synapse"
  resource_group_name                  = var.resource_group_name
  location                             = var.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.stance.id
  sql_administrator_login              = var.sql_admin_login
  sql_administrator_login_password     = var.sql_admin_password

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

# Data Lake Gen2 filesystem for Synapse
resource "azurerm_storage_data_lake_gen2_filesystem" "stance" {
  name               = "synapse"
  storage_account_id = var.storage_account_id
}

# Firewall rule to allow Azure services
resource "azurerm_synapse_firewall_rule" "allow_azure" {
  name                 = "AllowAllWindowsAzureIps"
  synapse_workspace_id = azurerm_synapse_workspace.stance.id
  start_ip_address     = "0.0.0.0"
  end_ip_address       = "0.0.0.0"
}

# SQL Pool for Stance queries (serverless)
# Note: Synapse serverless SQL is available by default with the workspace

# Role assignment for Synapse to access storage
resource "azurerm_role_assignment" "synapse_storage" {
  scope                = var.storage_account_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_synapse_workspace.stance.identity[0].principal_id
}

# SQL Script to create database and external tables
# This is deployed via a null_resource with local-exec
resource "null_resource" "create_database" {
  count = var.deploy_sql_objects ? 1 : 0

  triggers = {
    workspace_id = azurerm_synapse_workspace.stance.id
  }

  provisioner "local-exec" {
    command = <<-EOT
      az synapse sql script create \
        --workspace-name ${azurerm_synapse_workspace.stance.name} \
        --name create-stance-database \
        --file ${path.module}/sql/create_database.sql \
        --resource-group ${var.resource_group_name}
    EOT
  }

  depends_on = [azurerm_synapse_firewall_rule.allow_azure]
}

# Create SQL scripts directory structure
resource "local_file" "create_database_sql" {
  count    = var.deploy_sql_objects ? 1 : 0
  filename = "${path.module}/sql/create_database.sql"
  content  = <<-SQL
    -- Create Stance database
    IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'stance')
    BEGIN
        CREATE DATABASE stance;
    END
    GO

    USE stance;
    GO

    -- Create master key for external data source
    IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    BEGIN
        CREATE MASTER KEY ENCRYPTION BY PASSWORD = '${var.sql_admin_password}';
    END
    GO

    -- Create database scoped credential
    IF NOT EXISTS (SELECT * FROM sys.database_scoped_credentials WHERE name = 'StanceStorageCredential')
    BEGIN
        CREATE DATABASE SCOPED CREDENTIAL StanceStorageCredential
        WITH IDENTITY = 'Managed Identity';
    END
    GO

    -- Create external data source
    IF NOT EXISTS (SELECT * FROM sys.external_data_sources WHERE name = 'StanceDataSource')
    BEGIN
        CREATE EXTERNAL DATA SOURCE StanceDataSource
        WITH (
            LOCATION = 'https://${var.storage_account_name}.blob.core.windows.net/stance',
            CREDENTIAL = StanceStorageCredential
        );
    END
    GO

    -- Create external file format for JSON
    IF NOT EXISTS (SELECT * FROM sys.external_file_formats WHERE name = 'JsonFormat')
    BEGIN
        CREATE EXTERNAL FILE FORMAT JsonFormat
        WITH (
            FORMAT_TYPE = JSON
        );
    END
    GO
  SQL
}

resource "local_file" "create_tables_sql" {
  count    = var.deploy_sql_objects ? 1 : 0
  filename = "${path.module}/sql/create_tables.sql"
  content  = <<-SQL
    USE stance;
    GO

    -- External table for assets
    IF NOT EXISTS (SELECT * FROM sys.external_tables WHERE name = 'assets')
    BEGIN
        CREATE EXTERNAL TABLE assets (
            id NVARCHAR(500),
            cloud_provider NVARCHAR(50),
            account_id NVARCHAR(100),
            region NVARCHAR(100),
            resource_type NVARCHAR(200),
            name NVARCHAR(500),
            network_exposure NVARCHAR(50),
            tags NVARCHAR(MAX),
            created_at DATETIME2,
            last_seen DATETIME2,
            raw_config NVARCHAR(MAX),
            snapshot_id NVARCHAR(100)
        )
        WITH (
            LOCATION = 'assets/',
            DATA_SOURCE = StanceDataSource,
            FILE_FORMAT = JsonFormat
        );
    END
    GO

    -- External table for findings
    IF NOT EXISTS (SELECT * FROM sys.external_tables WHERE name = 'findings')
    BEGIN
        CREATE EXTERNAL TABLE findings (
            id NVARCHAR(500),
            asset_id NVARCHAR(500),
            finding_type NVARCHAR(50),
            severity NVARCHAR(50),
            status NVARCHAR(50),
            title NVARCHAR(500),
            description NVARCHAR(MAX),
            rule_id NVARCHAR(100),
            cve_id NVARCHAR(50),
            cvss_score FLOAT,
            compliance_frameworks NVARCHAR(MAX),
            remediation_guidance NVARCHAR(MAX),
            first_seen DATETIME2,
            last_seen DATETIME2,
            snapshot_id NVARCHAR(100)
        )
        WITH (
            LOCATION = 'findings/',
            DATA_SOURCE = StanceDataSource,
            FILE_FORMAT = JsonFormat
        );
    END
    GO
  SQL
}

resource "local_file" "create_views_sql" {
  count    = var.deploy_sql_objects ? 1 : 0
  filename = "${path.module}/sql/create_views.sql"
  content  = <<-SQL
    USE stance;
    GO

    -- View for compliance summary
    CREATE OR ALTER VIEW compliance_summary AS
    SELECT
        JSON_VALUE(framework.value, '$.framework') AS framework,
        JSON_VALUE(framework.value, '$.control') AS control,
        COUNT(DISTINCT f.id) AS finding_count,
        SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) AS open_findings,
        SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
        SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_count,
        SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS medium_count,
        SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS low_count,
        MAX(f.last_seen) AS last_scan
    FROM
        findings f
    CROSS APPLY OPENJSON(f.compliance_frameworks) AS framework
    WHERE
        f.last_seen >= DATEADD(hour, -24, GETUTCDATE())
    GROUP BY
        JSON_VALUE(framework.value, '$.framework'),
        JSON_VALUE(framework.value, '$.control');
    GO

    -- View for asset inventory
    CREATE OR ALTER VIEW asset_inventory AS
    SELECT
        cloud_provider,
        resource_type,
        region,
        network_exposure,
        COUNT(*) AS asset_count,
        SUM(CASE WHEN network_exposure = 'internet_facing' THEN 1 ELSE 0 END) AS internet_facing_count,
        MAX(last_seen) AS last_scan
    FROM
        assets
    WHERE
        last_seen >= DATEADD(hour, -24, GETUTCDATE())
    GROUP BY
        cloud_provider, resource_type, region, network_exposure;
    GO

    -- View for severity trend
    CREATE OR ALTER VIEW severity_trend AS
    SELECT
        CAST(last_seen AS DATE) AS scan_date,
        severity,
        status,
        COUNT(*) AS finding_count
    FROM
        findings
    WHERE
        last_seen >= DATEADD(day, -30, GETUTCDATE())
    GROUP BY
        CAST(last_seen AS DATE), severity, status;
    GO

    -- View for exposed assets with findings
    CREATE OR ALTER VIEW exposed_assets AS
    SELECT
        a.id AS asset_id,
        a.name AS asset_name,
        a.cloud_provider,
        a.resource_type,
        a.region,
        COUNT(f.id) AS finding_count,
        SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_findings,
        SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_findings,
        MAX(f.last_seen) AS last_scan
    FROM
        assets a
    LEFT JOIN
        findings f ON a.id = f.asset_id AND f.status = 'open'
    WHERE
        a.network_exposure = 'internet_facing'
        AND a.last_seen >= DATEADD(hour, -24, GETUTCDATE())
    GROUP BY
        a.id, a.name, a.cloud_provider, a.resource_type, a.region
    HAVING
        SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) > 0
        OR SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) > 0;
    GO

    -- View for daily summary
    CREATE OR ALTER VIEW daily_summary AS
    SELECT
        CAST(GETUTCDATE() AS DATE) AS report_date,
        (SELECT COUNT(DISTINCT id) FROM assets WHERE last_seen >= DATEADD(hour, -24, GETUTCDATE())) AS total_assets,
        (SELECT COUNT(*) FROM assets WHERE network_exposure = 'internet_facing' AND last_seen >= DATEADD(hour, -24, GETUTCDATE())) AS internet_facing_assets,
        (SELECT COUNT(DISTINCT id) FROM findings WHERE last_seen >= DATEADD(hour, -24, GETUTCDATE())) AS total_findings,
        (SELECT COUNT(*) FROM findings WHERE severity = 'critical' AND status = 'open' AND last_seen >= DATEADD(hour, -24, GETUTCDATE())) AS critical_open,
        (SELECT COUNT(*) FROM findings WHERE severity = 'high' AND status = 'open' AND last_seen >= DATEADD(hour, -24, GETUTCDATE())) AS high_open,
        (SELECT COUNT(*) FROM findings WHERE severity = 'medium' AND status = 'open' AND last_seen >= DATEADD(hour, -24, GETUTCDATE())) AS medium_open,
        (SELECT COUNT(*) FROM findings WHERE severity = 'low' AND status = 'open' AND last_seen >= DATEADD(hour, -24, GETUTCDATE())) AS low_open,
        (SELECT COUNT(*) FROM findings WHERE status = 'resolved' AND last_seen >= DATEADD(hour, -24, GETUTCDATE())) AS resolved_today;
    GO
  SQL
}
