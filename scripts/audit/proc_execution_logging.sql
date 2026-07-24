/*
===============================================================================
Stored Procedures: ETL Execution Logging
===============================================================================

Purpose:
- Record the start and end of stored procedure execution.
- Maintain step-level execution details for the ETL pipeline.
- Provide reusable logging procedures across Bronze, Silver, Gold, and Master layers.

Stored Procedures:
- audit.usp_execution_start
- audit.usp_execution_end

Example:

DECLARE @exec_id INT;

EXEC audit.usp_execution_start
    @procedure_name = 'bronze.load_bronze',
    @layer = 'Bronze',
    @batch_id = 1,
    @execution_id = @exec_id OUTPUT;

...

EXEC audit.usp_execution_end
    @execution_id = @exec_id,
    @rows_inserted = 24500,
    @status = 'SUCCESS';

===============================================================================
*/

CREATE OR ALTER PROCEDURE audit.usp_execution_start
    @procedure_name NVARCHAR(200),
    @layer          NVARCHAR(20),
    @batch_id       INT = NULL,
    @execution_id   INT OUTPUT
AS
BEGIN
    BEGIN TRY

        INSERT INTO audit.etl_execution_log
            (procedure_name, layer, batch_id, start_time, status)
        VALUES
            (@procedure_name, @layer, @batch_id, GETDATE(), 'RUNNING');

        SET @execution_id = SCOPE_IDENTITY();

    END TRY

    BEGIN CATCH

        -- Logging errors should not interrupt pipeline execution.
        PRINT 'WARNING: Failed to create execution log for '
              + @procedure_name + ' - ' + ERROR_MESSAGE();

        SET @execution_id = NULL;

    END CATCH
END;
GO

CREATE OR ALTER PROCEDURE audit.usp_execution_end
    @execution_id   INT,
    @rows_inserted  BIGINT = 0,
    @rows_updated   BIGINT = 0,
    @rows_rejected  BIGINT = 0,
    @status         NVARCHAR(20) = 'SUCCESS',
    @error_message  NVARCHAR(MAX) = NULL
AS
BEGIN
    BEGIN TRY

        IF @execution_id IS NOT NULL
            UPDATE audit.etl_execution_log
            SET end_time         = GETDATE(),
                duration_seconds = DATEDIFF(SECOND, start_time, GETDATE()),
                rows_inserted    = ISNULL(@rows_inserted, 0),
                rows_updated     = ISNULL(@rows_updated, 0),
                rows_rejected    = ISNULL(@rows_rejected, 0),
                status           = @status,
                error_message    = @error_message
            WHERE execution_id = @execution_id;

    END TRY

    BEGIN CATCH

        -- Logging errors should not interrupt pipeline execution.
        PRINT 'WARNING: Failed to update execution log '
              + CAST(ISNULL(@execution_id, -1) AS NVARCHAR)
              + ' - ' + ERROR_MESSAGE();

    END CATCH
END;
GO

/*
===============================================================================
Stored Procedure: audit.usp_log_table_statistics
===============================================================================

Purpose:
- Record table-level loading statistics for each ETL execution.
- Capture row counts before and after loading.
- Track inserted, updated, and deleted records.

===============================================================================
*/

CREATE OR ALTER PROCEDURE audit.usp_log_table_statistics
    @batch_id          INT,
    @table_name        NVARCHAR(200),
    @rows_before       BIGINT,
    @rows_after        BIGINT,
    @rows_inserted     BIGINT = 0,
    @rows_updated      BIGINT = 0,
    @rows_deleted      BIGINT = 0,
    @load_time_seconds INT = 0
AS
BEGIN
    BEGIN TRY

        INSERT INTO audit.table_statistics
            (
                batch_id,
                table_name,
                rows_before,
                rows_after,
                rows_inserted,
                rows_updated,
                rows_deleted,
                load_time_seconds
            )
        VALUES
            (
                @batch_id,
                @table_name,
                @rows_before,
                @rows_after,
                @rows_inserted,
                @rows_updated,
                @rows_deleted,
                @load_time_seconds
            );

    END TRY

    BEGIN CATCH

        -- Logging errors should not interrupt pipeline execution.
        PRINT 'WARNING: Failed to log table statistics for '
              + @table_name + ' - ' + ERROR_MESSAGE();

    END CATCH
END;
GO
