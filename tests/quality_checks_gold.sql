/* 
===============================================================================
Quality Checks 
===============================================================================
Script Purpose:
    This script performs quality checks to validate the integrity, consistency, 
    and accuracy of the Gold Layer. These checks ensure:
    - Uniqueness of surrogate keys in dimension tables.
    - Referential integrity between fact and dimension tables.
    - Validation of relationships in the data model for analytical purposes.

Usage Notes:
    - Investigate and resolve any discrepancies found during the checks.
===============================================================================
*/

-- ====================================================================
-- Checking 'gold.dim_customers'
-- ====================================================================
-- Check for Uniqueness of Customer Key in gold.dim_customers
-- Expectation: No results 
SELECT 
    customer_key,
    COUNT(*) AS duplicate_count
FROM gold.dim_customers
GROUP BY customer_key
HAVING COUNT(*) > 1;

-- ====================================================================
-- Checking 'gold.product_key'
-- ====================================================================
-- Check for Uniqueness of Product Key in gold.dim_products
-- Expectation: No results 
SELECT 
    product_key,
    COUNT(*) AS duplicate_count
FROM gold.dim_products
GROUP BY product_key
HAVING COUNT(*) > 1;

-- ====================================================================
-- Checking 'gold.fact_sales'
-- ====================================================================
-- Check the data model connectivity between fact and dimensions
SELECT * 
FROM gold.fact_sales f
LEFT JOIN gold.dim_customers c
ON c.customer_key = f.customer_key
LEFT JOIN gold.dim_products p
ON p.product_key = f.product_key
WHERE p.product_key IS NULL OR c.customer_key IS NULL  

-- ====================================================================
-- Extended Data Quality Framework (Priority 1, Upgrade 2)
-- These same rules are also logged automatically (with failure counts)
-- into audit.data_quality_issues via audit.usp_run_data_quality_checks.
-- ====================================================================

-- Null Check: Fact table keys and OrderDate should never be NULL
-- Expectation: No Results
SELECT * FROM gold.fact_sales
WHERE customer_key IS NULL OR product_key IS NULL OR order_date IS NULL;

-- Negative Value Check: Sales, Quantity, Price must never be negative
-- Expectation: No Results
SELECT * FROM gold.fact_sales
WHERE sales_amount < 0 OR quantity < 0 OR price < 0;

-- Future Date Check: OrderDate must never be later than today
-- Expectation: No Results
SELECT * FROM gold.fact_sales WHERE order_date > GETDATE();

-- Invalid Business Rule: Sales must equal Quantity * Price
-- Expectation: No Results
SELECT * FROM gold.fact_sales
WHERE sales_amount IS NOT NULL AND quantity IS NOT NULL AND price IS NOT NULL
  AND sales_amount <> quantity * price;

