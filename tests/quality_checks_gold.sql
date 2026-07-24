/* 
===============================================================================
Quality Checks
===============================================================================
Script Purpose:
    This script performs quality checks to validate the integrity, consistency,
    and accuracy of the Gold layer. These checks verify:
    - Uniqueness of surrogate keys in dimension tables.
    - Referential integrity between fact and dimension tables.
    - Data validation for reporting and analytics.

Usage Notes:
    - Review and resolve any issues identified by these checks.
===============================================================================
*/

-- ====================================================================
-- Checking 'gold.dim_customers'
-- ====================================================================

-- Verify Customer Key uniqueness
-- Expectation: No results
SELECT 
    customer_key,
    COUNT(*) AS duplicate_count
FROM gold.dim_customers
GROUP BY customer_key
HAVING COUNT(*) > 1;

-- ====================================================================
-- Checking 'gold.dim_products'
-- ====================================================================

-- Verify Product Key uniqueness
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

-- Verify relationships between fact and dimension tables
SELECT *
FROM gold.fact_sales f
LEFT JOIN gold.dim_customers c
    ON c.customer_key = f.customer_key
LEFT JOIN gold.dim_products p
    ON p.product_key = f.product_key
WHERE p.product_key IS NULL
   OR c.customer_key IS NULL;

-- ====================================================================
-- Additional Data Quality Checks
-- These checks are also recorded in audit.data_quality_issues
-- by audit.usp_run_data_quality_checks.
-- ====================================================================

-- Null Check: Required keys and OrderDate
-- Expectation: No results
SELECT *
FROM gold.fact_sales
WHERE customer_key IS NULL
   OR product_key IS NULL
   OR order_date IS NULL;

-- Negative Value Check
-- Expectation: No results
SELECT *
FROM gold.fact_sales
WHERE sales_amount < 0
   OR quantity < 0
   OR price < 0;

-- Future Date Check
-- Expectation: No results
SELECT *
FROM gold.fact_sales
WHERE order_date > GETDATE();

-- Business Rule Validation: Sales = Quantity × Price
-- Expectation: No results
SELECT *
FROM gold.fact_sales
WHERE sales_amount IS NOT NULL
  AND quantity IS NOT NULL
  AND price IS NOT NULL
  AND sales_amount <> quantity * price;
