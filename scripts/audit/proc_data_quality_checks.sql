/*
===============================================================================
Stored Procedure: audit.usp_run_data_quality_checks
===============================================================================
Script Purpose:
    Priority 1, Upgrade 2 - Better Data Quality Framework.

    Runs beyond the existing duplicate-key / missing-foreign-key checks and
    logs every rule failure (with a row count) into audit.data_quality_issues,
    instead of only checking and printing them.

    Rules covered:
    - Null Checks        : CustomerID, ProductID, OrderDate must never be NULL
    - Negative Values     : Sales, Quantity, Price must never be negative
    - Future Dates        : OrderDate must never be later than today
    - Invalid Business Rule: Sales must equal Quantity * Price

Parameters:
    @batch_id INT : Current pipeline batch, used to tag every issue found.

Usage Example:
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
        PRINT 'Running Extended Data Quality Checks';
        PRINT '------------------------------------------------';

        -- =====================================================================
        -- NULL CHECKS
        -- =====================================================================

        -- Rule: CustomerID should never be NULL (silver.crm_sales_details)
        SELECT @failed_rows = COUNT(*) FROM silver.crm_sales_details WHERE sls_cust_id IS NULL;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'silver.crm_sales_details', 'Null Check - CustomerID', @failed_rows, 'Rows found with a NULL customer id', 'Silver');

        -- Rule: ProductID should never be NULL (silver.crm_sales_details)
        SELECT @failed_rows = COUNT(*) FROM silver.crm_sales_details WHERE sls_prd_key IS NULL;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'silver.crm_sales_details', 'Null Check - ProductID', @failed_rows, 'Rows found with a NULL product key', 'Silver');

        -- Rule: OrderDate should never be NULL (silver.crm_sales_details)
        SELECT @failed_rows = COUNT(*) FROM silver.crm_sales_details WHERE sls_order_dt IS NULL;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'silver.crm_sales_details', 'Null Check - OrderDate', @failed_rows, 'Rows found with a NULL order date', 'Silver');

        -- Rule: Gold fact table keys should never be NULL
        SELECT @failed_rows = COUNT(*) FROM gold.fact_sales WHERE customer_key IS NULL OR product_key IS NULL OR order_date IS NULL;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Null Check - Fact Keys', @failed_rows, 'Rows found with a NULL customer_key, product_key or order_date', 'Gold');

        -- =====================================================================
        -- NEGATIVE VALUE CHECKS
        -- =====================================================================

        -- Rule: Sales must never be negative
        SELECT @failed_rows = COUNT(*) FROM gold.fact_sales WHERE sales_amount < 0;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Negative Value - Sales', @failed_rows, 'Rows found with a negative sales_amount', 'Gold');

        -- Rule: Quantity must never be negative
        SELECT @failed_rows = COUNT(*) FROM gold.fact_sales WHERE quantity < 0;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Negative Value - Quantity', @failed_rows, 'Rows found with a negative quantity', 'Gold');

        -- Rule: Price must never be negative
        SELECT @failed_rows = COUNT(*) FROM gold.fact_sales WHERE price < 0;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Negative Value - Price', @failed_rows, 'Rows found with a negative price', 'Gold');

        -- =====================================================================
        -- FUTURE DATE CHECK
        -- =====================================================================

        -- Rule: OrderDate must never be later than today
        SELECT @failed_rows = COUNT(*) FROM gold.fact_sales WHERE order_date > GETDATE();
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Future Date - OrderDate', @failed_rows, 'Rows found with an order_date later than today', 'Gold');

        -- =====================================================================
        -- INVALID BUSINESS RULE CHECK
        -- =====================================================================

        -- Rule: Sales must equal Quantity * Price
        SELECT @failed_rows = COUNT(*)
        FROM gold.fact_sales
        WHERE sales_amount IS NOT NULL
          AND quantity IS NOT NULL
          AND price IS NOT NULL
          AND sales_amount <> quantity * price;
        IF @failed_rows > 0
            INSERT INTO audit.data_quality_issues (batch_id, table_name, check_name, failed_rows, issue_description, check_layer)
            VALUES (@batch_id, 'gold.fact_sales', 'Business Rule - Sales = Qty * Price', @failed_rows, 'Rows found where sales_amount does not equal quantity * price', 'Gold');

        PRINT '>> Data Quality Checks Completed. Review audit.data_quality_issues for details.';
        PRINT '------------------------------------------------';
    END TRY
    BEGIN CATCH
        PRINT '!! ERROR while running data quality checks: ' + ERROR_MESSAGE();

        INSERT INTO audit.etl_log (batch_id, table_name, start_time, end_time, status, error_message)
        VALUES (@batch_id, 'DATA_QUALITY_CHECKS', GETDATE(), GETDATE(), 'Failed', ERROR_MESSAGE());
    END CATCH
END;
GO
