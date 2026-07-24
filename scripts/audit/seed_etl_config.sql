/*
===============================================================================
Seed Script: Populate ETL Configuration (Metadata)
===============================================================================
Script Purpose:
    Re-seeds audit.etl_config for the metadata-driven ERP load.
    Upgrade 8: Config now also carries watermark_column, primary_key_column,
    and hash_column, so adding a new table only ever needs one config row.
===============================================================================
*/

-- Clear existing config to avoid duplicates during testing
TRUNCATE TABLE audit.etl_config;

INSERT INTO audit.etl_config (source_table, target_table, load_type, watermark_column, primary_key_column, hash_column, is_active, priority)
VALUES 
('bronze.erp_loc_a101',    'silver.erp_loc_a101',    'FULL', NULL, 'cid', 'dwh_hash_full', 1, 10),
('bronze.erp_cust_az12',   'silver.erp_cust_az12',   'FULL', NULL, 'cid', 'dwh_hash_full', 1, 20),
('bronze.erp_px_cat_g1v2', 'silver.erp_px_cat_g1v2', 'FULL', NULL, 'id',  'dwh_hash_full', 1, 30);

PRINT '>> ETL Configuration Seeded Successfully.';
