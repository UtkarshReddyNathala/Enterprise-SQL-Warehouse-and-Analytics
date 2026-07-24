/*
===============================================================================
Stored Procedure: Load Silver Layer (Metadata-Driven Full Load)
===============================================================================
Purpose:
    Dynamically loads data from Source tables to Silver tables
    based on configuration stored in audit.etl_config.

    UPGRADE (Priority 2, #8 - ETL Configuration Table): Now reads the expanded
    config columns (primary_key_column) so a generic NULL-key rejection check
    runs for every metadata-driven table, without any code changes per table.

    UPGRADE (Priority 1, #3 - Reject Records): Rows whose configured primary
    key column is NULL are captured into silver.rejected_records instead of
    being silently loaded or dropped.

Output:
    @total_rejected OUTPUT : Total rows rejected across all configured tables,
                              so the calling procedure can roll it into its own
                              step-level execution log.
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
            @pk  NVARCHAR(100),        -- NEW: Configured primary key column
            @sql NVARCHAR(MAX);        -- Dynamic SQL statement

    DECLARE @start_time DATETIME;      -- Load start time
    DECLARE @rows_affected BIGINT;     -- Stores inserted row count
    DECLARE @rows_rejected BIGINT;     -- NEW: Stores rejected row count per table

    SET @total_rejected = 0;

    ---------------------------------------------------------------------------
    -- Cursor to loop through active FULL load tables from metadata config
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
    -- Loop through each configured table
    ---------------------------------------------------------------------------
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @start_time = GETDATE();   -- Capture load start time
        SET @rows_rejected = 0;
        PRINT '>> Dynamic Framework Loading: ' + @tgt;
        
        BEGIN TRY
            DECLARE @column_list NVARCHAR(MAX);

            -------------------------------------------------------------------
            -- Get matching column names between Source and Target tables
            -- This avoids inserting audit or extra columns accidentally
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
            -- NEW: Generic reject gate - capture rows where the configured
            -- primary key column is NULL, tagging each with its source table
            -- and the primary key column that failed the check.
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
            -- Build Dynamic SQL:
            -- 1. Start Transaction
            -- 2. Truncate Target Table
            -- 3. Insert Matching Columns from Source (excluding rejected NULL keys)
            -- 4. Capture Row Count
            -- 5. Commit Transaction
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
            -- Execute Dynamic SQL and capture affected row count
            -------------------------------------------------------------------
            EXEC sp_executesql 
                @sql, 
                N'@rows BIGINT OUTPUT', 
                @rows = @rows_affected OUTPUT;

            -------------------------------------------------------------------
            -- Log successful execution into audit table
            -------------------------------------------------------------------
            INSERT INTO audit.etl_log 
                (batch_id, table_name, start_time, end_time, row_count, status)
            VALUES 
                (@batch_id, @tgt, @start_time, GETDATE(), 
                 @rows_affected, 'Success');

            -- NEW: Before/after row counts for this table (Priority 2, #6)
            EXEC audit.usp_log_table_statistics
                @batch_id, @tgt, 0, @rows_affected, @rows_affected, 0, 0, DATEDIFF(SECOND, @start_time, GETDATE());
            
        END TRY
        BEGIN CATCH
            -------------------------------------------------------------------
            -- Rollback transaction if error occurs
            -------------------------------------------------------------------
            IF @@TRANCOUNT > 0 
                ROLLBACK TRANSACTION;

            -------------------------------------------------------------------
            -- Log failure details into audit table
            -------------------------------------------------------------------
            INSERT INTO audit.etl_log 
                (batch_id, table_name, start_time, end_time, status, error_message)
            VALUES 
                (@batch_id, @tgt, @start_time, GETDATE(), 
                 'Failed', 'Error ' + CAST(ERROR_NUMBER() AS NVARCHAR) + ': ' + ERROR_MESSAGE());
            
            PRINT '!! ERROR loading ' + @tgt + ': ' + ERROR_MESSAGE();
        END CATCH

        -- Move to next table in cursor
        FETCH NEXT FROM table_cursor INTO @src, @tgt, @pk;
    END

    ---------------------------------------------------------------------------
    -- Close and release cursor resources
    ---------------------------------------------------------------------------
    CLOSE table_cursor;
    DEALLOCATE table_cursor;
END;
GO
