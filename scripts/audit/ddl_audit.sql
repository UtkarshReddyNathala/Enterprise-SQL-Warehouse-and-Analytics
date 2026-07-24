/*
===============================================================================
DDL Script: Create Audit Schema and Logging Tables
===============================================================================

Purpose:
- Create the audit schema used by the ETL pipeline.
- Create logging tables for execution tracking and data quality monitoring.
- Create metadata tables for incremental loading and ETL configuration.
- Initialize watermark tracking for incremental processing.
- Seed metadata required for the metadata-driven ETL framework.

Objects Created:
1. audit.etl_log
2. audit.data_quality_issues
3. audit.etl_config
4. audit.watermark_thresholds
5. audit.etl_execution_log
6. audit.table_statistics

===============================================================================
*/

-- Create the audit schema if it does not already exist
IF SCHEMA_ID('audit') IS NULL
    EXEC ('CREATE SCHEMA audit');
GO

-- =============================================================================
-- 1. Create ETL Process Log
-- =============================================================================
IF OBJECT_ID('audit.etl_log', 'U') IS NOT NULL
    DROP TABLE audit.etl_log;
GO

CREATE TABLE audit.etl_log (
    log_id        INT IDENTITY(1,1) PRIMARY KEY,
    batch_id      INT,                           -- Batch identifier for a pipeline execution
    table_name    NVARCHAR(100),                 -- Table or process name
    start_time    DATETIME DEFAULT GETDATE(),    -- Execution start time
    end_time      DATETIME,                      -- Execution end time
    row_count     BIGINT,                        -- Number of processed rows
    status        NVARCHAR(20),                  -- Execution status
    error_message NVARCHAR(MAX)                  -- Error details, if any
);
GO

-- =============================================================================
-- 2. Create Data Quality Log
-- =============================================================================
IF OBJECT_ID('audit.data_quality_issues', 'U') IS NOT NULL
    DROP TABLE audit.data_quality_issues;
GO

CREATE TABLE audit.data_quality_issues (
    issue_id          INT IDENTITY(1,1) PRIMARY KEY,
    batch_id          INT,                          -- Pipeline execution identifier
    table_name        NVARCHAR(100),                -- Table being validated
    check_name        NVARCHAR(100),                -- Validation rule name
    expected_value    NVARCHAR(MAX),                -- Expected value
    actual_value      NVARCHAR(MAX),                -- Actual value
    failed_rows       INT DEFAULT 0,                -- Number of rows that failed validation
    issue_description NVARCHAR(MAX),                -- Description of the validation issue
    check_layer       NVARCHAR(20),                 -- Validation layer (Silver or Gold)
    check_date        DATETIME DEFAULT GETDATE()    -- Validation timestamp
);
GO

-- =============================================================================
-- 3. Create ETL Metadata Configuration
-- =============================================================================
IF OBJECT_ID('audit.etl_config', 'U') IS NOT NULL
    DROP TABLE audit.etl_config;
GO

CREATE TABLE audit.etl_config (
    config_id           INT IDENTITY(1,1) PRIMARY KEY,
    source_table        NVARCHAR(255),         -- Source table
    target_table        NVARCHAR(255) UNIQUE,  -- Target table
    load_type           NVARCHAR(50),          -- FULL or INCREMENTAL
    watermark_column    NVARCHAR(100) NULL,    -- Watermark column used for incremental loading
    primary_key_column  NVARCHAR(100) NULL,    -- Primary key column used during validation
    hash_column         NVARCHAR(100) NULL,    -- Hash column used for change detection
    is_active           BIT DEFAULT 1,         -- Indicates whether the configuration is enabled
    priority            INT DEFAULT 10         -- Execution order (lower value executes first)
);
GO

-- =============================================================================
-- 4. Create Watermark Tracking Table
-- =============================================================================
IF OBJECT_ID('audit.watermark_thresholds', 'U') IS NOT NULL
    DROP TABLE audit.watermark_thresholds;
GO

CREATE TABLE audit.watermark_thresholds (
    table_name       NVARCHAR(100) PRIMARY KEY,
    last_load_date   DATETIME,
    watermark_column NVARCHAR(50)              -- Column used for incremental filtering
);
GO

-- Initialize watermark values for incremental CRM loads
INSERT INTO audit.watermark_thresholds (table_name, last_load_date, watermark_column)
VALUES
('silver.crm_cust_info', '1900-01-01', 'cst_create_date'),
('silver.crm_sales_details', '1900-01-01', 'sls_order_dt');

-- Seed metadata used by the metadata-driven ERP load process
INSERT INTO audit.etl_config (
    source_table,
    target_table,
    load_type,
    watermark_column,
    primary_key_column,
    hash_column,
    is_active,
    priority
)
VALUES
('bronze.erp_loc_a101',    'silver.erp_loc_a101',    'FULL', NULL, 'cid', 'dwh_hash_full', 1, 10),
('bronze.erp_cust_az12',   'silver.erp_cust_az12',   'FULL', NULL, 'cid', 'dwh_hash_full', 1, 20),
('bronze.erp_px_cat_g1v2', 'silver.erp_px_cat_g1v2', 'FULL', NULL, 'id',  'dwh_hash_full', 1, 30);
GO

-- =============================================================================
-- 5. Create ETL Execution Log
-- =============================================================================
IF OBJECT_ID('audit.etl_execution_log', 'U') IS NOT NULL
    DROP TABLE audit.etl_execution_log;
GO

CREATE TABLE audit.etl_execution_log (
    execution_id     INT IDENTITY(1,1) PRIMARY KEY,      -- Unique execution identifier
    procedure_name   NVARCHAR(200) NOT NULL,             -- Stored procedure name
    layer            NVARCHAR(20)  NOT NULL,             -- Pipeline layer (Bronze, Silver, Gold, Master)
    batch_id         INT,                                -- Associated batch identifier
    start_time       DATETIME NOT NULL DEFAULT GETDATE(),-- Execution start time
    end_time         DATETIME,                           -- Execution end time
    duration_seconds INT,                                -- Execution duration in seconds
    rows_inserted    BIGINT DEFAULT 0,                   -- Rows inserted
    rows_updated     BIGINT DEFAULT 0,                   -- Rows updated
    rows_rejected    BIGINT DEFAULT 0,                   -- Rows rejected
    status           NVARCHAR(20) DEFAULT 'RUNNING',     -- Execution status
    error_message    NVARCHAR(MAX)                       -- Error details, if any
);
GO

CREATE NONCLUSTERED INDEX ix_audit_etl_execution_log_batch_id
    ON audit.etl_execution_log (batch_id);
GO

-- =============================================================================
-- 6. Create Table Statistics
-- =============================================================================
IF OBJECT_ID('audit.table_statistics', 'U') IS NOT NULL
    DROP TABLE audit.table_statistics;
GO

CREATE TABLE audit.table_statistics (
    stat_id           INT IDENTITY(1,1) PRIMARY KEY,
    batch_id          INT,
    table_name        NVARCHAR(200),    -- Table being processed
    rows_before       BIGINT,           -- Row count before loading
    rows_after        BIGINT,           -- Row count after loading
    rows_inserted     BIGINT DEFAULT 0, -- Rows inserted
    rows_updated      BIGINT DEFAULT 0, -- Rows updated
    rows_deleted      BIGINT DEFAULT 0, -- Rows deleted
    load_time_seconds INT,              -- Load duration in seconds
    log_date          DATETIME2 DEFAULT GETDATE()
);
GO

PRINT '------------------------------------------------';
PRINT 'Audit schema created successfully.';
PRINT 'Objects: etl_log, data_quality_issues, etl_config, watermark_thresholds, etl_execution_log, table_statistics';
PRINT '------------------------------------------------';
