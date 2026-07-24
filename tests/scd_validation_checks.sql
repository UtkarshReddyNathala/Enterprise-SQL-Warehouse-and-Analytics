/*
===============================================================================
SCD Type 2 Validation Checks (silver.crm_prd_info)
===============================================================================
Script Purpose:
    Priority 2, Upgrade 5 - Slowly Changing Dimension Validation.

    silver.crm_prd_info implements SCD Type 2 history tracking (effective_date,
    expiry_date, is_current). This script validates that the history logic is
    behaving correctly.

Usage Notes:
    - Run after silver.load_silver.
    - Every query below should return NO rows. Any result is a defect.
===============================================================================
*/

-- ====================================================================
-- 1. Only ONE active (Current Flag = 1) record per product
-- Expectation: No Results
-- ====================================================================
SELECT 
    prd_id, 
    COUNT(*) AS active_versions
FROM silver.crm_prd_info
WHERE is_current = 1
GROUP BY prd_id
HAVING COUNT(*) > 1;

-- ====================================================================
-- 2. Expiry Date must always be later than Start Date (Effective Date)
-- Expectation: No Results
-- ====================================================================
SELECT 
    prd_id, 
    effective_date, 
    expiry_date
FROM silver.crm_prd_info
WHERE expiry_date IS NOT NULL
  AND expiry_date <= effective_date;

-- ====================================================================
-- 3. No Overlapping History between consecutive versions of the same product
--    (One version's Expiry Date must not run past the next version's Start Date)
-- Expectation: No Results
-- ====================================================================
SELECT 
    a.prd_id, 
    a.effective_date AS current_start, 
    a.expiry_date    AS current_end,
    b.effective_date AS next_start
FROM silver.crm_prd_info a
JOIN silver.crm_prd_info b
    ON a.prd_id = b.prd_id
   AND a.effective_date < b.effective_date
WHERE a.expiry_date IS NULL
   OR a.expiry_date > b.effective_date;

-- ====================================================================
-- 4. Every historical (expired) record must have an Expiry Date set
-- Expectation: No Results
-- ====================================================================
SELECT 
    prd_id, 
    effective_date, 
    expiry_date, 
    is_current
FROM silver.crm_prd_info
WHERE is_current = 0
  AND expiry_date IS NULL;
