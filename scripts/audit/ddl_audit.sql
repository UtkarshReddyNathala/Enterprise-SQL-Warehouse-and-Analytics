/*
===============================================================================
DDL Script: Create Audit Schema and Logging Tables 
===============================================================================
Script Purpose:
1. **audit.etl_log** – Records when the system runs and what data it handled.
2. **audit.data_quality_issues** – Keeps track of data problems or errors found in the data.
3. **audit.etl_config** – Stores setup details that help the system move and process data automatically.
4. **audit.watermark_thresholds** – Remembers the last data processed so only new data is added next time.
5. **audit.etl_execution_log** – NEW! Step-level monitoring: one row per stored procedure run.
6. **audit.table_statistics** – NEW! Before/after row counts for every table load (incremental proof).

===============================================================================
*/

-- Create the Audit Schema if it doesn't exist
IF SCHEMA_ID('audit') IS NULL 
    EXEC ('CREATE SCHEMA audit');
GO

-- =============================================================================
-- 1. Create the Process Logging Table (Execution Tracking)
-- =============================================================================
IF OBJECT_ID('audit.etl_log', 'U') IS NOT NULL
    DROP TABLE audit.etl_log;
GO

CREATE TABLE audit.etl_log (
    log_id        INT IDENTITY(1,1) PRIMARY KEY,
    batch_id      INT,                           -- Links all table loads in one run
    table_name    NVARCHAR(100),                 -- Name of the table or process
    start_time    DATETIME DEFAULT GETDATE(),    -- Execution start
    end_time      DATETIME,                      -- Execution end
    row_count     BIGINT,                        -- Upgraded to BIGINT for large datasets
    status        NVARCHAR(20),                  -- 'Success' or 'Failed'
    error_message NVARCHAR(MAX)                  -- System error details
);
GO

-- =============================================================================
-- 2. Create the Data Quality Table (Validation Tracking)
-- =============================================================================
IF OBJECT_ID('audit.data_quality_issues', 'U') IS NOT NULL
    DROP TABLE audit.data_quality_issues;
GO

CREATE TABLE audit.data_quality_issues (
    issue_id          INT IDENTITY(1,1) PRIMARY KEY,
    batch_id          INT,                         -- Groups errors by pipeline run
    table_name        NVARCHAR(100),               -- Table being validated (TableName)
    check_name        NVARCHAR(100),               -- Rule that failed, e.g., 'Null Check - CustomerID' (RuleName)
    expected_value    NVARCHAR(MAX),               -- Source Value (Bronze)
    actual_value      NVARCHAR(MAX),               -- Target Value (Silver)
    failed_rows       INT DEFAULT 0,               -- NEW: Count of rows that failed the rule (FailedRows)
    issue_description NVARCHAR(MAX),               -- MODIFIED: Upgraded to MAX to prevent truncation crashes
    check_layer        NVARCHAR(20),                -- 'Silver' or 'Gold'
    check_date        DATETIME DEFAULT GETDATE()   -- Timestamp of validation (ExecutionTime)
);
GO

-- =============================================================================
-- 3. Create the ETL Configuration Table (Metadata Framework)
-- =============================================================================
IF OBJECT_ID('audit.etl_config', 'U') IS NOT NULL
    DROP TABLE audit.etl_config;
GO

CREATE TABLE audit.etl_config (
    config_id           INT IDENTITY(1,1) PRIMARY KEY,
    source_table         NVARCHAR(255),        -- e.g., 'bronze.erp_loc_a101'
    target_table         NVARCHAR(255) UNIQUE, -- Added UNIQUE to prevent duplicate processing
    load_type            NVARCHAR(50),         -- 'FULL' or 'INCREMENTAL'
    watermark_column     NVARCHAR(100) NULL,   -- NEW: Column used for delta filtering on INCREMENTAL loads
    primary_key_column   NVARCHAR(100) NULL,   -- NEW: Business key column, used for NULL-key rejection checks
    hash_column           NVARCHAR(100) NULL,   -- NEW: Column that stores the change-detection hash, if any
    is_active            BIT DEFAULT 1,        -- Enabled: 1 = Active, 0 = Skip this table
    priority             INT DEFAULT 10        -- Load Order: order of execution (lower numbers first)
);
GO

-- =============================================================================
-- 4. Create the Watermark Tracking Table (Delta Load Framework)
-- =============================================================================
IF OBJECT_ID('audit.watermark_thresholds', 'U') IS NOT NULL
    DROP TABLE audit.watermark_thresholds;
GO

CREATE TABLE audit.watermark_thresholds (
    table_name       NVARCHAR(100) PRIMARY KEY,
    last_load_date   DATETIME,
    watermark_column NVARCHAR(50)  -- The column name used for filtering
);
GO

-- Seed the initial thresholds for CRM tables to enable Delta Loading
INSERT INTO audit.watermark_thresholds (table_name, last_load_date, watermark_column)
VALUES 
('silver.crm_cust_info', '1900-01-01', 'cst_create_date'),
('silver.crm_sales_details', '1900-01-01', 'sls_order_dt');

-- Seed the metadata configuration for ERP tables (Required for Metadata-Driven Engine)
-- NOTE: primary_key_column drives the generic NULL-key rejection check in silver.load_metadata_driven.
INSERT INTO audit.etl_config (source_table, target_table, load_type, watermark_column, primary_key_column, hash_column, is_active, priority)
VALUES 
('bronze.erp_loc_a101',    'silver.erp_loc_a101',    'FULL', NULL, 'cid', 'dwh_hash_full', 1, 10),
('bronze.erp_cust_az12',   'silver.erp_cust_az12',   'FULL', NULL, 'cid', 'dwh_hash_full', 1, 20),
('bronze.erp_px_cat_g1v2', 'silver.erp_px_cat_g1v2', 'FULL', NULL, 'id',  'dwh_hash_full', 1, 30);
GO

-- =============================================================================
-- 5. Create the ETL Execution Log Table (Step-Level Procedure Monitoring)
-- =============================================================================
-- Upgrade 1 (Priority 1): One row per stored procedure execution, giving a
-- clear step-level view on top of the existing table-level audit.etl_log.
IF OBJECT_ID('audit.etl_execution_log', 'U') IS NOT NULL
    DROP TABLE audit.etl_execution_log;
GO

CREATE TABLE audit.etl_execution_log (
    execution_id     INT IDENTITY(1,1) PRIMARY KEY,      -- ExecutionID
    procedure_name   NVARCHAR(200) NOT NULL,              -- ProcedureName
    layer            NVARCHAR(20)  NOT NULL,              -- Layer: Bronze / Silver / Gold / Master
    batch_id         INT,                                 -- Links back to the master run in audit.etl_log
    start_time       DATETIME NOT NULL DEFAULT GETDATE(), -- StartTime
    end_time         DATETIME,                            -- EndTime
    duration_seconds INT,                                 -- Duration (seconds)
    rows_inserted    BIGINT DEFAULT 0,                    -- RowsInserted
    rows_updated     BIGINT DEFAULT 0,                    -- RowsUpdated
    rows_rejected    BIGINT DEFAULT 0,                    -- RowsRejected
    status           NVARCHAR(20) DEFAULT 'RUNNING',      -- Status: RUNNING / SUCCESS / FAILED
    error_message    NVARCHAR(MAX)                        -- ErrorMessage
);
GO

CREATE NONCLUSTERED INDEX ix_audit_etl_execution_log_batch_id
    ON audit.etl_execution_log (batch_id);
GO

-- =============================================================================
-- 6. Create the Table Statistics Table (Load Volume Tracking)
-- =============================================================================
-- Priority 2 Upgrade 6: Rows before/after every load, to make incremental
-- loading easy to demonstrate and audit.
IF OBJECT_ID('audit.table_statistics', 'U') IS NOT NULL
    DROP TABLE audit.table_statistics;
GO

CREATE TABLE audit.table_statistics (
    stat_id           INT IDENTITY(1,1) PRIMARY KEY,
    batch_id          INT,
    table_name        NVARCHAR(200),   -- Table being loaded
    rows_before       BIGINT,          -- Rows Before
    rows_after        BIGINT,          -- Rows After
    rows_inserted     BIGINT DEFAULT 0,-- Inserted
    rows_updated      BIGINT DEFAULT 0,-- Updated
    rows_deleted      BIGINT DEFAULT 0,-- Deleted
    load_time_seconds INT,             -- Load Time
    log_date          DATETIME2 DEFAULT GETDATE()
);
GO

PRINT '------------------------------------------------';
PRINT 'Audit Schema Ready: etl_log, data_quality_issues, etl_config, watermark_thresholds, etl_execution_log, table_statistics';
PRINT '------------------------------------------------';
