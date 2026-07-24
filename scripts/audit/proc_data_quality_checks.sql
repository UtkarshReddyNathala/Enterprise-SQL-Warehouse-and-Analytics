/*
===============================================================================
Stored Procedure: audit.usp_run_data_quality_checks
===============================================================================

Purpose:
- Execute data quality validation rules for the ETL pipeline.
- Record validation failures in audit.data_quality_issues.
- Support data quality monitoring across the Silver and Gold layers.

Validation Rules:
- Null Checks
- Negative Value Checks
- Future Date Validation
- Business Rule Validation (Sales = Quantity × Price)

Parameter:
    @batch_id INT - Batch identifier used for audit tracking.

Example:
    EXEC audit.usp_run_data_quality_checks @batch_id = 1;

===============================================================================
*/

CREATE OR ALTER PROCEDURE audit.usp_run_data_quality_checks
    @batch_id INT = NULL
AS
BEGIN
    DECLARE @failed_rows INT;

    BEGIN TRY
        PRINT '------------------------------------------------';
        PRINT 'Running Data Quality Checks';
        PRINT '------------------------------------------------';

        -- =====================================================================
        -- Null Checks
        -- =====================================================================

        -- Customer ID must not be NULL
        SELECT @failed_rows = COUNT(*) FROM silver.crm_sales_details WHERE sls_cust_id IS NULL;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'silver.crm_sales_details', 'Null Check - CustomerID', @failed_rows, 'Rows found with a NULL customer id', 'Silver');

        -- Product ID must not be NULL
        SELECT @failed_rows = COUNT(*) FROM silver.crm_sales_details WHERE sls_prd_key IS NULL;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'silver.crm_sales_details', 'Null Check - ProductID', @failed_rows, 'Rows found with a NULL product key', 'Silver');

        -- Order Date must not be NULL
        SELECT @failed_rows = COUNT(*) FROM silver.crm_sales_details WHERE sls_order_dt IS NULL;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'silver.crm_sales_details', 'Null Check - OrderDate', @failed_rows, 'Rows found with a NULL order date', 'Silver');

        -- Fact table keys must not be NULL
        SELECT @failed_rows = COUNT(*) FROM gold.fact_sales WHERE customer_key IS NULL OR product_key IS NULL OR order_date IS NULL;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Null Check - Fact Keys', @failed_rows, 'Rows found with a NULL customer_key, product_key or order_date', 'Gold');

        -- =====================================================================
        -- Negative Value Checks
        -- =====================================================================

        -- Sales amount must not be negative
        SELECT @failed_rows = COUNT(*) FROM gold.fact_sales WHERE sales_amount < 0;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Negative Value - Sales', @failed_rows, 'Rows found with a negative sales_amount', 'Gold');

        -- Quantity must not be negative
        SELECT @failed_rows = COUNT(*) FROM gold.fact_sales WHERE quantity < 0;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Negative Value - Quantity', @failed_rows, 'Rows found with a negative quantity', 'Gold');

        -- Price must not be negative
        SELECT @failed_rows = COUNT(*) FROM gold.fact_sales WHERE price < 0;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Negative Value - Price', @failed_rows, 'Rows found with a negative price', 'Gold');

        -- =====================================================================
        -- Future Date Validation
        -- =====================================================================

        -- Order Date must not be later than the current date
        SELECT @failed_rows = COUNT(*) FROM gold.fact_sales WHERE order_date > GETDATE();
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Future Date - OrderDate', @failed_rows, 'Rows found with an order_date later than today', 'Gold');

        -- =====================================================================
        -- Business Rule Validation
        -- =====================================================================

        -- Sales amount must equal Quantity × Price
        SELECT @failed_rows = COUNT(*)
        FROM gold.fact_sales
        WHERE sales_amount IS NOT NULL
          AND quantity IS NOT NULL
          AND price IS NOT NULL
          AND sales_amount <> quantity * price;

        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Business Rule - Sales = Qty * Price', @failed_rows, 'Rows found where sales_amount does not equal quantity * price', 'Gold');

        PRINT 'Data quality checks completed.';
        PRINT 'Review audit.data_quality_issues for validation results.';
        PRINT '------------------------------------------------';

    END TRY

    BEGIN CATCH

        PRINT 'Error while running data quality checks: ' + ERROR_MESSAGE();

        INSERT INTO audit.etl_log (batch_id, table_name, start_time, end_time, status, error_message)
        VALUES (@batch_id, 'DATA_QUALITY_CHECKS', GETDATE(), GETDATE(), 'Failed', ERROR_MESSAGE());

    END CATCH
END;
GO
