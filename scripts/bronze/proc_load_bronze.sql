/*
===============================================================================
Stored Procedure: Load Bronze Layer
===============================================================================

Description:
Loads CRM and ERP source data from CSV files into the Bronze layer.

The procedure:
- Truncates existing Bronze tables
- Loads data using BULK INSERT
- Records execution details
- Captures table load statistics
- Handles and logs errors

Usage:
    EXEC bronze.load_bronze @batch_id = 1;
===============================================================================
*/

CREATE OR ALTER PROCEDURE bronze.load_bronze
    @batch_id INT = NULL
AS
BEGIN
    DECLARE @start_time DATETIME,
            @end_time DATETIME,
            @batch_start_time DATETIME,
            @batch_end_time DATETIME;

    DECLARE @rows_inserted BIGINT;
    DECLARE @rows_before BIGINT;
    DECLARE @total_rows_inserted BIGINT = 0;

    -- Start execution logging
    DECLARE @execution_id INT;

    EXEC audit.usp_execution_start
        @procedure_name = 'bronze.load_bronze',
        @layer          = 'Bronze',
        @batch_id       = @batch_id,
        @execution_id   = @execution_id OUTPUT;

    BEGIN TRY

        SET @batch_start_time = GETDATE();

        PRINT '================================================';
        PRINT 'Loading Bronze Layer';
        PRINT '================================================';

        PRINT '------------------------------------------------';
        PRINT 'Loading CRM Tables';
        PRINT '------------------------------------------------';

        -----------------------------------------------------------------------
        -- Customer Information
        -----------------------------------------------------------------------

        SET @start_time = GETDATE();

        SELECT @rows_before = COUNT(*)
        FROM bronze.crm_cust_info;

        PRINT '>> Truncating Table: bronze.crm_cust_info';

        TRUNCATE TABLE bronze.crm_cust_info;

        PRINT '>> Inserting Data Into: bronze.crm_cust_info';

        BULK INSERT bronze.crm_cust_info
        FROM 'C:\sql\dwh_project\datasets\source_crm\cust_info.csv'
        WITH
        (
            FIRSTROW = 2,
            FIELDTERMINATOR = ',',
            TABLOCK
        );

        SET @rows_inserted = @@ROWCOUNT;

        SET @end_time = GETDATE();

        PRINT '>> Load Duration: '
            + CAST(DATEDIFF(SECOND, @start_time, @end_time) AS NVARCHAR)
            + ' seconds';

        PRINT '>> -------------';

        INSERT INTO audit.etl_log
        (
            batch_id,
            table_name,
            start_time,
            end_time,
            row_count,
            status
        )
        VALUES
        (
            @batch_id,
            'bronze.crm_cust_info',
            @start_time,
            @end_time,
            @rows_inserted,
            'Success'
        );

        EXEC audit.usp_log_table_statistics
            @batch_id,
            'bronze.crm_cust_info',
            @rows_before,
            @rows_inserted,
            @rows_inserted,
            0,
            0,
            DATEDIFF(SECOND, @start_time, @end_time);

        SET @total_rows_inserted += @rows_inserted;

        -----------------------------------------------------------------------
        -- Product Information
        -----------------------------------------------------------------------

        SET @start_time = GETDATE();

        SELECT @rows_before = COUNT(*)
        FROM bronze.crm_prd_info;

        PRINT '>> Truncating Table: bronze.crm_prd_info';

        TRUNCATE TABLE bronze.crm_prd_info;

        PRINT '>> Inserting Data Into: bronze.crm_prd_info';

        BULK INSERT bronze.crm_prd_info
        FROM 'C:\sql\dwh_project\datasets\source_crm\prd_info.csv'
        WITH
        (
            FIRSTROW = 2,
            FIELDTERMINATOR = ',',
            TABLOCK
        );

        SET @rows_inserted = @@ROWCOUNT;

        SET @end_time = GETDATE();

        PRINT '>> Load Duration: '
            + CAST(DATEDIFF(SECOND, @start_time, @end_time) AS NVARCHAR)
            + ' seconds';

        PRINT '>> -------------';

        INSERT INTO audit.etl_log
        (
            batch_id,
            table_name,
            start_time,
            end_time,
            row_count,
            status
        )
        VALUES
        (
            @batch_id,
            'bronze.crm_prd_info',
            @start_time,
            @end_time,
            @rows_inserted,
            'Success'
        );

        EXEC audit.usp_log_table_statistics
            @batch_id,
            'bronze.crm_prd_info',
            @rows_before,
            @rows_inserted,
            @rows_inserted,
            0,
            0,
            DATEDIFF(SECOND, @start_time, @end_time);

        SET @total_rows_inserted += @rows_inserted;

        -----------------------------------------------------------------------
        -- Sales Information
        -----------------------------------------------------------------------

        SET @start_time = GETDATE();

        SELECT @rows_before = COUNT(*)
        FROM bronze.crm_sales_details;

        PRINT '>> Truncating Table: bronze.crm_sales_details';

        TRUNCATE TABLE bronze.crm_sales_details;

        PRINT '>> Inserting Data Into: bronze.crm_sales_details';

        BULK INSERT bronze.crm_sales_details
        FROM 'C:\sql\dwh_project\datasets\source_crm\sales_details.csv'
        WITH
        (
            FIRSTROW = 2,
            FIELDTERMINATOR = ',',
            TABLOCK
        );

        SET @rows_inserted = @@ROWCOUNT;

        SET @end_time = GETDATE();

        PRINT '>> Load Duration: '
            + CAST(DATEDIFF(SECOND, @start_time, @end_time) AS NVARCHAR)
            + ' seconds';

        PRINT '>> -------------';

        INSERT INTO audit.etl_log
        (
            batch_id,
            table_name,
            start_time,
            end_time,
            row_count,
            status
        )
        VALUES
        (
            @batch_id,
            'bronze.crm_sales_details',
            @start_time,
            @end_time,
            @rows_inserted,
            'Success'
        );

        EXEC audit.usp_log_table_statistics
            @batch_id,
            'bronze.crm_sales_details',
            @rows_before,
            @rows_inserted,
            @rows_inserted,
            0,
            0,
            DATEDIFF(SECOND, @start_time, @end_time);

        SET @total_rows_inserted += @rows_inserted;

        PRINT '------------------------------------------------';
        PRINT 'Loading ERP Tables';
        PRINT '------------------------------------------------';

        -----------------------------------------------------------------------
        -- ERP Location Data
        -----------------------------------------------------------------------

        SET @start_time = GETDATE();

        SELECT @rows_before = COUNT(*)
        FROM bronze.erp_loc_a101;

        PRINT '>> Truncating Table: bronze.erp_loc_a101';

        TRUNCATE TABLE bronze.erp_loc_a101;

        PRINT '>> Inserting Data Into: bronze.erp_loc_a101';

        BULK INSERT bronze.erp_loc_a101
        FROM 'C:\sql\dwh_project\datasets\source_erp\loc_a101.csv'
        WITH
        (
            FIRSTROW = 2,
            FIELDTERMINATOR = ',',
            TABLOCK
        );

        SET @rows_inserted = @@ROWCOUNT;

        SET @end_time = GETDATE();

        PRINT '>> Load Duration: '
            + CAST(DATEDIFF(SECOND, @start_time, @end_time) AS NVARCHAR)
            + ' seconds';

        PRINT '>> -------------';

        INSERT INTO audit.etl_log
        (
            batch_id,
            table_name,
            start_time,
            end_time,
            row_count,
            status
        )
        VALUES
        (
            @batch_id,
            'bronze.erp_loc_a101',
            @start_time,
            @end_time,
            @rows_inserted,
            'Success'
        );

        EXEC audit.usp_log_table_statistics
            @batch_id,
            'bronze.erp_loc_a101',
            @rows_before,
            @rows_inserted,
            @rows_inserted,
            0,
            0,
            DATEDIFF(SECOND, @start_time, @end_time);

        SET @total_rows_inserted += @rows_inserted;

        -----------------------------------------------------------------------
        -- ERP Customer Data
        -----------------------------------------------------------------------

        SET @start_time = GETDATE();

        SELECT @rows_before = COUNT(*)
        FROM bronze.erp_cust_az12;

        PRINT '>> Truncating Table: bronze.erp_cust_az12';

        TRUNCATE TABLE bronze.erp_cust_az12;

        PRINT '>> Inserting Data Into: bronze.erp_cust_az12';

        BULK INSERT bronze.erp_cust_az12
        FROM 'C:\sql\dwh_project\datasets\source_erp\cust_az12.csv'
        WITH
        (
            FIRSTROW = 2,
            FIELDTERMINATOR = ',',
            TABLOCK
        );

        SET @rows_inserted = @@ROWCOUNT;

        SET @end_time = GETDATE();

        PRINT '>> Load Duration: '
            + CAST(DATEDIFF(SECOND, @start_time, @end_time) AS NVARCHAR)
            + ' seconds';

        PRINT '>> -------------';

        INSERT INTO audit.etl_log
        (
            batch_id,
            table_name,
            start_time,
            end_time,
            row_count,
            status
        )
        VALUES
        (
            @batch_id,
            'bronze.erp_cust_az12',
            @start_time,
            @end_time,
            @rows_inserted,
            'Success'
        );

        EXEC audit.usp_log_table_statistics
            @batch_id,
            'bronze.erp_cust_az12',
            @rows_before,
            @rows_inserted,
            @rows_inserted,
            0,
            0,
            DATEDIFF(SECOND, @start_time, @end_time);

        SET @total_rows_inserted += @rows_inserted;

        -----------------------------------------------------------------------
        -- ERP Product Category Data
        -----------------------------------------------------------------------

        SET @start_time = GETDATE();

        SELECT @rows_before = COUNT(*)
        FROM bronze.erp_px_cat_g1v2;

        PRINT '>> Truncating Table: bronze.erp_px_cat_g1v2';

        TRUNCATE TABLE bronze.erp_px_cat_g1v2;

        PRINT '>> Inserting Data Into: bronze.erp_px_cat_g1v2';

        BULK INSERT bronze.erp_px_cat_g1v2
        FROM 'C:\sql\dwh_project\datasets\source_erp\px_cat_g1v2.csv'
        WITH
        (
            FIRSTROW = 2,
            FIELDTERMINATOR = ',',
            TABLOCK
        );

        SET @rows_inserted = @@ROWCOUNT;

        SET @end_time = GETDATE();

        PRINT '>> Load Duration: '
            + CAST(DATEDIFF(SECOND, @start_time, @end_time) AS NVARCHAR)
            + ' seconds';

        PRINT '>> -------------';

        INSERT INTO audit.etl_log
        (
            batch_id,
            table_name,
            start_time,
            end_time,
            row_count,
            status
        )
        VALUES
        (
            @batch_id,
            'bronze.erp_px_cat_g1v2',
            @start_time,
            @end_time,
            @rows_inserted,
            'Success'
        );

        EXEC audit.usp_log_table_statistics
            @batch_id,
            'bronze.erp_px_cat_g1v2',
            @rows_before,
            @rows_inserted,
            @rows_inserted,
            0,
            0,
            DATEDIFF(SECOND, @start_time, @end_time);

        SET @total_rows_inserted += @rows_inserted;

        SET @batch_end_time = GETDATE();

        PRINT '==========================================';
        PRINT 'Loading Bronze Layer Completed';
        PRINT '   - Total Load Duration: '
            + CAST(DATEDIFF(SECOND, @batch_start_time, @batch_end_time) AS NVARCHAR)
            + ' seconds';
        PRINT '==========================================';

        -- Complete execution logging
        EXEC audit.usp_execution_end
            @execution_id  = @execution_id,
            @rows_inserted = @total_rows_inserted,
            @status        = 'SUCCESS';

    END TRY

    BEGIN CATCH

        PRINT '==========================================';
        PRINT 'ERROR OCCURRED DURING BRONZE LOAD';
        PRINT 'Error Message: ' + ERROR_MESSAGE();
        PRINT 'Error Number : ' + CAST(ERROR_NUMBER() AS NVARCHAR);
        PRINT 'Error State  : ' + CAST(ERROR_STATE() AS NVARCHAR);
        PRINT '==========================================';

        INSERT INTO audit.etl_log
        (
            batch_id,
            table_name,
            start_time,
            end_time,
            status,
            error_message
        )
        VALUES
        (
            @batch_id,
            'BRONZE_LAYER_FAILED',
            @batch_start_time,
            GETDATE(),
            'Failed',
            ERROR_MESSAGE()
        );

        -- Mark execution as failed
        EXEC audit.usp_execution_end
            @execution_id  = @execution_id,
            @rows_inserted = @total_rows_inserted,
            @status        = 'FAILED',
            @error_message = 'Error '
                             + CAST(ERROR_NUMBER() AS NVARCHAR)
                             + ': '
                             + ERROR_MESSAGE();

    END CATCH

END;
GO
