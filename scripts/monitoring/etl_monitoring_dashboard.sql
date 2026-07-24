/*
===============================================================================
ETL Monitoring Dashboard
===============================================================================
Script Purpose:
    Priority 1, Upgrade 4 - ETL Dashboard Query.

    A read-only SQL dashboard for monitoring pipeline health. Point a BI tool
    at these queries, or run them directly, for a snapshot of the most recent
    ETL run: Last Load, Status, Rows Loaded, Execution Time, Failed Loads,
    and Rejected Records.

Usage Notes:
    - Run after init.load_all has completed at least once.
    - Each section is independent and can be run on its own.
===============================================================================
*/

-- =============================================================================
-- 1. LAST LOAD SUMMARY (Master Pipeline)
-- =============================================================================
SELECT TOP 1
    log_id                                              AS batch_id,
    table_name                                          AS pipeline,
    start_time                                          AS last_load_start,
    end_time                                            AS last_load_end,
    DATEDIFF(SECOND, start_time, end_time)              AS execution_time_seconds,
    status,
    error_message
FROM audit.etl_log
WHERE table_name = 'MASTER_PIPELINE'
ORDER BY log_id DESC;

-- =============================================================================
-- 2. STEP-LEVEL STATUS FOR THE LATEST BATCH (audit.etl_execution_log)
-- =============================================================================
SELECT
    e.execution_id,
    e.procedure_name,
    e.layer,
    e.start_time,
    e.end_time,
    e.duration_seconds                                  AS execution_time_seconds,
    e.rows_inserted,
    e.rows_updated,
    e.rows_rejected,
    e.status,
    e.error_message
FROM audit.etl_execution_log e
WHERE e.batch_id = (SELECT MAX(log_id) FROM audit.etl_log WHERE table_name = 'MASTER_PIPELINE')
ORDER BY e.execution_id;

-- =============================================================================
-- 3. ROWS LOADED PER TABLE (Latest Batch)
-- =============================================================================
SELECT
    batch_id,
    table_name,
    row_count                                           AS rows_loaded,
    start_time,
    end_time,
    DATEDIFF(SECOND, start_time, end_time)              AS execution_time_seconds,
    status
FROM audit.etl_log
WHERE batch_id = (SELECT MAX(log_id) FROM audit.etl_log WHERE table_name = 'MASTER_PIPELINE')
  AND table_name <> 'MASTER_PIPELINE'
ORDER BY start_time;

-- =============================================================================
-- 4. FAILED LOADS (All Time)
-- =============================================================================
SELECT
    batch_id,
    table_name,
    start_time,
    end_time,
    status,
    error_message
FROM audit.etl_log
WHERE status = 'Failed'
ORDER BY start_time DESC;

-- =============================================================================
-- 5. REJECTED RECORDS SUMMARY (silver.rejected_records)
-- =============================================================================
SELECT
    source_table,
    reject_reason,
    COUNT(*)         AS rejected_count,
    MAX(load_date)   AS last_rejected
FROM silver.rejected_records
GROUP BY source_table, reject_reason
ORDER BY rejected_count DESC;

-- =============================================================================
-- 6. DATA QUALITY ISSUES (Latest Batch)
-- =============================================================================
SELECT
    table_name,
    check_name          AS rule_name,
    failed_rows,
    check_layer          AS layer,
    check_date            AS execution_time
FROM audit.data_quality_issues
WHERE batch_id = (SELECT MAX(log_id) FROM audit.etl_log WHERE table_name = 'MASTER_PIPELINE')
ORDER BY check_date;

-- =============================================================================
-- 7. LOAD VOLUME TREND (audit.table_statistics, Latest Batch)
-- =============================================================================
SELECT
    table_name,
    rows_before,
    rows_after,
    rows_inserted,
    rows_updated,
    rows_deleted,
    load_time_seconds,
    log_date
FROM audit.table_statistics
WHERE batch_id = (SELECT MAX(log_id) FROM audit.etl_log WHERE table_name = 'MASTER_PIPELINE')
ORDER BY log_date;
