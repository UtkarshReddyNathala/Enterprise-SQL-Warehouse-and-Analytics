/*
===============================================================================
Stored Procedure: Master ETL Pipeline (Load All Layers)
===============================================================================
Script Purpose:
    This procedure controls the complete ETL workflow for the data warehouse.
    It executes the ETL pipeline in the required sequence:
    Bronze -> Silver -> Gold.

    Features:
    - Centralized execution of all ETL layers.
    - Error handling across the complete pipeline.
    - Identity-based batch ID generation.
    - Validates metadata before execution.
===============================================================================
*/

CREATE OR ALTER PROCEDURE init.load_all AS
BEGIN
    DECLARE @batch_start_time DATETIME = GETDATE();
    DECLARE @batch_end_time DATETIME;
    DECLARE @batch_id INT;
    DECLARE @execution_id INT; -- Execution log identifier for the master pipeline

    BEGIN TRY
        -- ======================================================
        -- 0. Generate Batch ID
        -- ======================================================

        -- Insert an initial record to reserve the batch ID
        INSERT INTO audit.etl_log (table_name, start_time, status)
        VALUES ('MASTER_PIPELINE', @batch_start_time, 'In Progress');

        -- Capture the generated batch ID
        SET @batch_id = SCOPE_IDENTITY();

        -- Create execution log entry
        EXEC audit.usp_execution_start
            @procedure_name = 'init.load_all',
            @layer          = 'Master',
            @batch_id       = @batch_id,
            @execution_id   = @execution_id OUTPUT;

        PRINT '================================================';
        PRINT 'STARTING MASTER ETL PIPELINE | BATCH ID: ' + CAST(@batch_id AS NVARCHAR);
        PRINT '================================================';
        PRINT '>> Start Time: ' + CAST(@batch_start_time AS NVARCHAR);

        -- ======================================================
        -- 1. Metadata Validation
        -- ======================================================
        IF NOT EXISTS (
            SELECT 1
            FROM audit.etl_config
            WHERE is_active = 1
        )
        BEGIN
            THROW 50001,
                'CRITICAL ERROR: No active metadata found in audit.etl_config. Pipeline aborted to prevent incomplete data load.',
                1;
        END

        -- ======================================================
        -- 2. Bronze Layer
        -- ======================================================
        PRINT '------------------------------------------------';
        PRINT 'STEP 1: LOADING BRONZE LAYER';
        PRINT '------------------------------------------------';

        EXEC bronze.load_bronze
            @batch_id = @batch_id;

        -- ======================================================
        -- 3. Silver Layer
        -- ======================================================
        PRINT '------------------------------------------------';
        PRINT 'STEP 2: LOADING SILVER LAYER';
        PRINT '------------------------------------------------';

        EXEC silver.load_silver
            @batch_id = @batch_id;

        -- ======================================================
        -- 4. Gold Layer
        -- ======================================================
        PRINT '------------------------------------------------';
        PRINT 'STEP 3: LOADING GOLD LAYER';
        PRINT '------------------------------------------------';

        EXEC gold.load_gold
            @batch_id = @batch_id;

        SET @batch_end_time = GETDATE();

        -- ======================================================
        -- Update Audit Log (Success)
        -- ======================================================
        UPDATE audit.etl_log
        SET end_time = @batch_end_time,
            status = 'Success'
        WHERE log_id = @batch_id;

        -- Update execution log
        EXEC audit.usp_execution_end
            @execution_id = @execution_id,
            @status       = 'SUCCESS';

        PRINT '================================================';
        PRINT 'MASTER ETL PIPELINE COMPLETED SUCCESSFULLY';
        PRINT ' - Total Duration: ' +
              CAST(DATEDIFF(SECOND, @batch_start_time, @batch_end_time) AS NVARCHAR) +
              ' seconds';
        PRINT ' - Run scripts/monitoring/etl_monitoring_dashboard.sql for a full status report.';
        PRINT '================================================';

    END TRY
    BEGIN CATCH

        -- Capture end time if execution fails
        SET @batch_end_time = GETDATE();

        PRINT '================================================';
        PRINT 'MASTER PIPELINE FAILED!';
        PRINT 'Error Message: ' + ERROR_MESSAGE();
        PRINT '================================================';

        -- Update audit log with failure details
        IF @batch_id IS NOT NULL
        BEGIN
            UPDATE audit.etl_log
            SET end_time = @batch_end_time,
                status = 'Failed',
                error_message = ERROR_MESSAGE()
            WHERE log_id = @batch_id;
        END

        -- Update execution log
        EXEC audit.usp_execution_end
            @execution_id  = @execution_id,
            @status        = 'FAILED',
            @error_message = 'Error ' + CAST(ERROR_NUMBER() AS NVARCHAR) + ': ' + ERROR_MESSAGE();

        -- Re-throw the error if required
        -- THROW;

    END CATCH
END
GO
