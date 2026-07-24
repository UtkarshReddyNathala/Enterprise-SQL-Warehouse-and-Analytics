/*
===============================================================================
Stored Procedure: Load Silver Layer (Metadata-Driven Full Load)
===============================================================================
Purpose:
    Dynamically loads data from source tables to Silver tables
    based on the configuration stored in audit.etl_config.

    Uses the configured primary key column to identify and reject
    rows with NULL keys.

    Rejected rows are stored in silver.rejected_records.

Output:
    @total_rejected OUTPUT : Total rows rejected across all configured tables,
                              returned to the calling procedure.
===============================================================================
*/

CREATE OR ALTER PROCEDURE silver.load_metadata_driven 
    @batch_id       INT = NULL,
    @total_rejected BIGINT = 0 OUTPUT
AS
BEGIN
    -- Variable declarations
    DECLARE @src NVARCHAR(255),        -- Source table name
            @tgt NVARCHAR(255),        -- Target table name
            @pk  NVARCHAR(100),        -- Configured primary key column
            @sql NVARCHAR(MAX);        -- Dynamic SQL statement

    DECLARE @start_time DATETIME;      -- Load start time
    DECLARE @rows_affected BIGINT;     -- Inserted row count
    DECLARE @rows_rejected BIGINT;     -- Rejected row count for the current table

    SET @total_rejected = 0;

    ---------------------------------------------------------------------------
    -- Cursor to process active FULL load tables from the configuration
    ---------------------------------------------------------------------------
    DECLARE table_cursor CURSOR FOR 
    SELECT source_table, target_table, primary_key_column 
    FROM audit.etl_config 
    WHERE is_active = 1 
      AND load_type = 'FULL'
    ORDER BY priority;

    OPEN table_cursor;
    FETCH NEXT FROM table_cursor INTO @src, @tgt, @pk;

    ---------------------------------------------------------------------------
    -- Process each configured table
    ---------------------------------------------------------------------------
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @start_time = GETDATE();   -- Capture load start time
        SET @rows_rejected = 0;
        PRINT '>> Dynamic Framework Loading: ' + @tgt;
        
        BEGIN TRY
            DECLARE @column_list NVARCHAR(MAX);

            -------------------------------------------------------------------
            -- Get matching column names between source and target tables
            -------------------------------------------------------------------
            SELECT @column_list = STRING_AGG(QUOTENAME(s.name), ', ') 
            FROM sys.columns s
            JOIN sys.columns t 
                ON s.name = t.name
            WHERE s.object_id = OBJECT_ID(@src)
              AND t.object_id = OBJECT_ID(@tgt);

            -- Stop execution if no matching columns are found
            IF @column_list IS NULL
                THROW 50000, 
                'No matching columns found between Source and Target.', 1;

            -------------------------------------------------------------------
            -- Capture rows where the configured primary key is NULL
            -------------------------------------------------------------------
            IF @pk IS NOT NULL
            BEGIN
                DECLARE @reject_sql NVARCHAR(MAX);
                SET @reject_sql =
                    N'INSERT INTO silver.rejected_records (batch_id, source_table, record_data, reject_reason) ' +
                    N'SELECT ' + CAST(ISNULL(@batch_id, 0) AS NVARCHAR) + N', ''' + @src + N''', ' +
                    N'''Row rejected from ' + @src + N' - configured primary key column [' + @pk + N'] is NULL'', ' +
                    N'''NULL ' + @pk + N''' ' +
                    N'FROM ' + @src + N' WHERE ' + QUOTENAME(@pk) + N' IS NULL;';

                EXEC sp_executesql @reject_sql;
                SET @rows_rejected = @@ROWCOUNT;
                SET @total_rejected += @rows_rejected;
            END

            -------------------------------------------------------------------
            -- Build dynamic SQL
            -- 1. Start transaction
            -- 2. Truncate target table
            -- 3. Insert matching columns from source
            -- 4. Capture inserted row count
            -- 5. Commit transaction
            -------------------------------------------------------------------
            SET @sql = 
                'BEGIN TRANSACTION; ' +
                'TRUNCATE TABLE ' + @tgt + '; ' +
                'INSERT INTO ' + @tgt + ' (' + @column_list + ') ' +
                'SELECT ' + @column_list + ' FROM ' + @src +
                CASE WHEN @pk IS NOT NULL THEN ' WHERE ' + QUOTENAME(@pk) + ' IS NOT NULL' ELSE '' END + '; ' +
                'SELECT @rows = @@ROWCOUNT; ' +
                'COMMIT;';

            -------------------------------------------------------------------
            -- Execute dynamic SQL and capture inserted row count
            -------------------------------------------------------------------
            EXEC sp_executesql 
                @sql, 
                N'@rows BIGINT OUTPUT', 
                @rows = @rows_affected OUTPUT;

            -------------------------------------------------------------------
            -- Log successful execution
            -------------------------------------------------------------------
            INSERT INTO audit.etl_log 
                (batch_id, table_name, start_time, end_time, row_count, status)
            VALUES 
                (@batch_id, @tgt, @start_time, GETDATE(), 
                 @rows_affected, 'Success');

            -- Log table statistics
            EXEC audit.usp_log_table_statistics
                @batch_id, @tgt, 0, @rows_affected, @rows_affected, 0, 0, DATEDIFF(SECOND, @start_time, GETDATE());
            
        END TRY
        BEGIN CATCH
            -------------------------------------------------------------------
            -- Roll back the transaction if an error occurs
            -------------------------------------------------------------------
            IF @@TRANCOUNT > 0 
                ROLLBACK TRANSACTION;

            -------------------------------------------------------------------
            -- Log failure details
            -------------------------------------------------------------------
            INSERT INTO audit.etl_log 
                (batch_id, table_name, start_time, end_time, status, error_message)
            VALUES 
                (@batch_id, @tgt, @start_time, GETDATE(), 
                 'Failed', 'Error ' + CAST(ERROR_NUMBER() AS NVARCHAR) + ': ' + ERROR_MESSAGE());
            
            PRINT '!! ERROR loading ' + @tgt + ': ' + ERROR_MESSAGE();
        END CATCH

        -- Move to the next table
        FETCH NEXT FROM table_cursor INTO @src, @tgt, @pk;
    END

    ---------------------------------------------------------------------------
    -- Close and release cursor resources
    ---------------------------------------------------------------------------
    CLOSE table_cursor;
    DEALLOCATE table_cursor;
END;
GO
