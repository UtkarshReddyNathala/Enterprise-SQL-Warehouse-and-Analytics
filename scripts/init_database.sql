/*
=============================================================
Create Database and Schemas
=============================================================
Script Purpose:
This script creates the 'DataWarehouse' database and initializes
the required schemas used by the data warehouse.

WARNING:
Running this script will drop the existing 'DataWarehouse' database,
if it already exists. Proceed with caution.
*/

USE master;
GO

-- Drop and recreate the 'DataWarehouse' database
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = 'DataWarehouse')
BEGIN
    ALTER DATABASE DataWarehouse SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE DataWarehouse;
END;
GO

-- Create the 'DataWarehouse' database
CREATE DATABASE DataWarehouse;
GO

USE DataWarehouse;
GO

-- =============================================================
-- Create Schemas
-- =============================================================

-- Data Layer Schemas
CREATE SCHEMA bronze;
GO

CREATE SCHEMA silver;
GO

CREATE SCHEMA gold;
GO

-- Supporting Schemas
CREATE SCHEMA audit; -- Stores audit logs and configuration tables
GO

CREATE SCHEMA init;  -- Stores initialization and master load procedures
GO

PRINT '------------------------------------------------';
PRINT 'Database and Schemas Created Successfully';
PRINT '------------------------------------------------';
