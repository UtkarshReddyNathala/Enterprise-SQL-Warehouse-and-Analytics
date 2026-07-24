/*
===============================================================================
Stored Procedure: Load Bronze Layer (Source -> Bronze)
===============================================================================
Script Purpose:
    This stored procedure loads data into the 'bronze' schema from external CSV files. 
    It performs the following actions:
    - Truncates the bronze tables before loading data.
    - Uses the `BULK INSERT` command to load data from csv Files to bronze tables.
    - UPGRADE: Writes one step-level row to audit.etl_execution_log for this run.
    - UPGRADE: Logs before/after row counts per table to audit.table_statistics.

Parameters:
    @batch_id INT: The unique identifier for the current ETL execution.

Usage Example:
    EXEC bronze.load_bronze @batch_id = 1;
===============================================================================
*/
CREATE OR ALTER PROCEDURE bronze.load_bronze @batch_id INT = NULL AS
BEGIN
	DECLARE @start_time DATETIME, @end_time DATETIME, @batch_start_time DATETIME, @batch_end_time DATETIME; 
	DECLARE @rows_inserted BIGINT;      -- Added variable to track row counts
	DECLARE @rows_before BIGINT;        -- NEW: Row count captured before truncate/load
	DECLARE @total_rows_inserted BIGINT = 0; -- NEW: Running total for execution log

	-- NEW: Open a step-level execution record (Upgrade 1: ETL Execution Logging)
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

		SET @start_time = GETDATE();
		SELECT @rows_before = COUNT(*) FROM bronze.crm_cust_info;
		PRINT '>> Truncating Table: bronze.crm_cust_info';
		TRUNCATE TABLE bronze.crm_cust_info;
		PRINT '>> Inserting Data Into: bronze.crm_cust_info';
		BULK INSERT bronze.crm_cust_info
		FROM 'C:\sql\dwh_project\datasets\source_crm\cust_info.csv'
		WITH (
			FIRSTROW = 2,
			FIELDTERMINATOR = ',',
			TABLOCK
		);
		SET @rows_inserted = @@ROWCOUNT; -- Capture rows inserted
		SET @end_time = GETDATE();
		PRINT '>> Load Duration: ' + CAST(DATEDIFF(second, @start_time, @end_time) AS NVARCHAR) + ' seconds';
		PRINT '>> -------------';
		INSERT INTO audit.etl_log (batch_id, table_name, start_time, end_time, row_count, status)
		VALUES (@batch_id, 'bronze.crm_cust_info', @start_time, @end_time, @rows_inserted, 'Success');
		EXEC audit.usp_log_table_statistics @batch_id, 'bronze.crm_cust_info', @rows_before, @rows_inserted, @rows_inserted, 0, 0, DATEDIFF(SECOND, @start_time, @end_time);
		SET @total_rows_inserted += @rows_inserted;

        SET @start_time = GETDATE();
		SELECT @rows_before = COUNT(*) FROM bronze.crm_prd_info;
		PRINT '>> Truncating Table: bronze.crm_prd_info';
		TRUNCATE TABLE bronze.crm_prd_info;
		PRINT '>> Inserting Data Into: bronze.crm_prd_info';
		BULK INSERT bronze.crm_prd_info
		FROM 'C:\sql\dwh_project\datasets\source_crm\prd_info.csv'
		WITH (
			FIRSTROW = 2,
			FIELDTERMINATOR = ',',
			TABLOCK
		);
		SET @rows_inserted = @@ROWCOUNT; -- Capture rows inserted
		SET @end_time = GETDATE();
		PRINT '>> Load Duration: ' + CAST(DATEDIFF(second, @start_time, @end_time) AS NVARCHAR) + ' seconds';
		PRINT '>> -------------';
		INSERT INTO audit.etl_log (batch_id, table_name, start_time, end_time, row_count, status)
		VALUES (@batch_id, 'bronze.crm_prd_info', @start_time, @end_time, @rows_inserted, 'Success');
		EXEC audit.usp_log_table_statistics @batch_id, 'bronze.crm_prd_info', @rows_before, @rows_inserted, @rows_inserted, 0, 0, DATEDIFF(SECOND, @start_time, @end_time);
		SET @total_rows_inserted += @rows_inserted;

        SET @start_time = GETDATE();
		SELECT @rows_before = COUNT(*) FROM bronze.crm_sales_details;
		PRINT '>> Truncating Table: bronze.crm_sales_details';
		TRUNCATE TABLE bronze.crm_sales_details;
		PRINT '>> Inserting Data Into: bronze.crm_sales_details';
		BULK INSERT bronze.crm_sales_details
		FROM 'C:\sql\dwh_project\datasets\source_crm\sales_details.csv'
		WITH (
			FIRSTROW = 2,
			FIELDTERMINATOR = ',',
			TABLOCK
		);
		SET @rows_inserted = @@ROWCOUNT; -- Capture rows inserted
		SET @end_time = GETDATE();
		PRINT '>> Load Duration: ' + CAST(DATEDIFF(second, @start_time, @end_time) AS NVARCHAR) + ' seconds';
		PRINT '>> -------------';
		INSERT INTO audit.etl_log (batch_id, table_name, start_time, end_time, row_count, status)
		VALUES (@batch_id, 'bronze.crm_sales_details', @start_time, @end_time, @rows_inserted, 'Success');
		EXEC audit.usp_log_table_statistics @batch_id, 'bronze.crm_sales_details', @rows_before, @rows_inserted, @rows_inserted, 0, 0, DATEDIFF(SECOND, @start_time, @end_time);
		SET @total_rows_inserted += @rows_inserted;

		PRINT '------------------------------------------------';
		PRINT 'Loading ERP Tables';
		PRINT '------------------------------------------------';
		
		SET @start_time = GETDATE();
		SELECT @rows_before = COUNT(*) FROM bronze.erp_loc_a101;
		PRINT '>> Truncating Table: bronze.erp_loc_a101';
		TRUNCATE TABLE bronze.erp_loc_a101;
		PRINT '>> Inserting Data Into: bronze.erp_loc_a101';
		BULK INSERT bronze.erp_loc_a101
		FROM 'C:\sql\dwh_project\datasets\source_erp\loc_a101.csv'
		WITH (
			FIRSTROW = 2,
			FIELDTERMINATOR = ',',
			TABLOCK
		);
		SET @rows_inserted = @@ROWCOUNT; -- Capture rows inserted
		SET @end_time = GETDATE();
		PRINT '>> Load Duration: ' + CAST(DATEDIFF(second, @start_time, @end_time) AS NVARCHAR) + ' seconds';
		PRINT '>> -------------';
		INSERT INTO audit.etl_log (batch_id, table_name, start_time, end_time, row_count, status)
		VALUES (@batch_id, 'bronze.erp_loc_a101', @start_time, @end_time, @rows_inserted, 'Success');
		EXEC audit.usp_log_table_statistics @batch_id, 'bronze.erp_loc_a101', @rows_before, @rows_inserted, @rows_inserted, 0, 0, DATEDIFF(SECOND, @start_time, @end_time);
		SET @total_rows_inserted += @rows_inserted;

		SET @start_time = GETDATE();
		SELECT @rows_before = COUNT(*) FROM bronze.erp_cust_az12;
		PRINT '>> Truncating Table: bronze.erp_cust_az12';
		TRUNCATE TABLE bronze.erp_cust_az12;
		PRINT '>> Inserting Data Into: bronze.erp_cust_az12';
		BULK INSERT bronze.erp_cust_az12
		FROM 'C:\sql\dwh_project\datasets\source_erp\cust_az12.csv'
		WITH (
			FIRSTROW = 2,
			FIELDTERMINATOR = ',',
			TABLOCK
		);
		SET @rows_inserted = @@ROWCOUNT; -- Capture rows inserted
		SET @end_time = GETDATE();
		PRINT '>> Load Duration: ' + CAST(DATEDIFF(second, @start_time, @end_time) AS NVARCHAR) + ' seconds';
		PRINT '>> -------------';
		INSERT INTO audit.etl_log (batch_id, table_name, start_time, end_time, row_count, status)
		VALUES (@batch_id, 'bronze.erp_cust_az12', @start_time, @end_time, @rows_inserted, 'Success');
		EXEC audit.usp_log_table_statistics @batch_id, 'bronze.erp_cust_az12', @rows_before, @rows_inserted, @rows_inserted, 0, 0, DATEDIFF(SECOND, @start_time, @end_time);
		SET @total_rows_inserted += @rows_inserted;

		SET @start_time = GETDATE();
		SELECT @rows_before = COUNT(*) FROM bronze.erp_px_cat_g1v2;
		PRINT '>> Truncating Table: bronze.erp_px_cat_g1v2';
		TRUNCATE TABLE bronze.erp_px_cat_g1v2;
		PRINT '>> Inserting Data Into: bronze.erp_px_cat_g1v2';
		BULK INSERT bronze.erp_px_cat_g1v2
		FROM 'C:\sql\dwh_project\datasets\source_erp\px_cat_g1v2.csv'
		WITH (
			FIRSTROW = 2,
			FIELDTERMINATOR = ',',
			TABLOCK
		);
		SET @rows_inserted = @@ROWCOUNT; -- Capture rows inserted
		SET @end_time = GETDATE();
		PRINT '>> Load Duration: ' + CAST(DATEDIFF(second, @start_time, @end_time) AS NVARCHAR) + ' seconds';
		PRINT '>> -------------';
		INSERT INTO audit.etl_log (batch_id, table_name, start_time, end_time, row_count, status)
		VALUES (@batch_id, 'bronze.erp_px_cat_g1v2', @start_time, @end_time, @rows_inserted, 'Success');
		EXEC audit.usp_log_table_statistics @batch_id, 'bronze.erp_px_cat_g1v2', @rows_before, @rows_inserted, @rows_inserted, 0, 0, DATEDIFF(SECOND, @start_time, @end_time);
		SET @total_rows_inserted += @rows_inserted;

		SET @batch_end_time = GETDATE();
		PRINT '=========================================='
		PRINT 'Loading Bronze Layer is Completed';
        PRINT '   - Total Load Duration: ' + CAST(DATEDIFF(SECOND, @batch_start_time, @batch_end_time) AS NVARCHAR) + ' seconds';
		PRINT '=========================================='

		-- NEW: Close the step-level execution record as a success
		EXEC audit.usp_execution_end
			@execution_id  = @execution_id,
			@rows_inserted = @total_rows_inserted,
			@status        = 'SUCCESS';
	END TRY
	BEGIN CATCH
		PRINT '=========================================='
		PRINT 'ERROR OCCURRED DURING LOADING BRONZE LAYER'
		PRINT 'Error Message' + ERROR_MESSAGE();
		PRINT 'Error Number' + CAST (ERROR_NUMBER() AS NVARCHAR);
		PRINT 'Error State' + CAST (ERROR_STATE() AS NVARCHAR);
		PRINT '=========================================='

		INSERT INTO audit.etl_log (batch_id, table_name, start_time, end_time, status, error_message)
		VALUES (@batch_id, 'BRONZE_LAYER_FAILED', @batch_start_time, GETDATE(), 'Failed', ERROR_MESSAGE());

		-- NEW: Close the step-level execution record as a failure
		-- Logs Procedure (via execution_id), Error Number, Error Message and Execution Time.
		EXEC audit.usp_execution_end
			@execution_id  = @execution_id,
			@rows_inserted = @total_rows_inserted,
			@status        = 'FAILED',
			@error_message = 'Error ' + CAST(ERROR_NUMBER() AS NVARCHAR) + ': ' + ERROR_MESSAGE();
	END CATCH
END
GO
