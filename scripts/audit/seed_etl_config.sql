/*
===============================================================================
Seed Script: ETL Metadata Configuration
===============================================================================

Purpose:
- Populate the ETL metadata configuration table.
- Register source-to-target mappings for metadata-driven ERP loads.
- Define load settings and execution order for each table.

===============================================================================
*/

-- Clear existing configuration before loading the latest metadata
TRUNCATE TABLE audit.etl_config;

INSERT INTO audit.etl_config (
    source_table,
    target_table,
    load_type,
    watermark_column,
    primary_key_column,
    hash_column,
    is_active,
    priority
)
VALUES
('bronze.erp_loc_a101',    'silver.erp_loc_a101',    'FULL', NULL, 'cid', 'dwh_hash_full', 1, 10),
('bronze.erp_cust_az12',   'silver.erp_cust_az12',   'FULL', NULL, 'cid', 'dwh_hash_full', 1, 20),
('bronze.erp_px_cat_g1v2', 'silver.erp_px_cat_g1v2', 'FULL', NULL, 'id',  'dwh_hash_full', 1, 30);

PRINT 'ETL metadata configuration loaded successfully.';
