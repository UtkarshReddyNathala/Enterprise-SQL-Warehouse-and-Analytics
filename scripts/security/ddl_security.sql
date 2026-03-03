/* ============================================================
   ENTERPRISE SECURITY LAYER
   - Row-Level Security (Region Based)
   - Multi-Tenant Isolation
   - Column-Level Masking
   - Block Predicate Protection
   ============================================================ */

---------------------------------------------------------------
-- 1️ CREATE SECURITY SCHEMA
---------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'Security')
    EXEC('CREATE SCHEMA Security');
GO

---------------------------------------------------------------
-- 2️ USER-REGION MAPPING TABLE
---------------------------------------------------------------
IF OBJECT_ID('Security.UserRegionMapping') IS NOT NULL
    DROP TABLE Security.UserRegionMapping;
GO

CREATE TABLE Security.UserRegionMapping (
    UserName SYSNAME NOT NULL,
    Region NVARCHAR(50) NOT NULL,
    CONSTRAINT PK_UserRegion PRIMARY KEY (UserName, Region)
);
GO

CREATE INDEX IX_UserRegion_UserName
ON Security.UserRegionMapping(UserName);
GO

---------------------------------------------------------------
-- 3️ USER-TENANT MAPPING TABLE
---------------------------------------------------------------
IF OBJECT_ID('Security.UserTenantMapping') IS NOT NULL
    DROP TABLE Security.UserTenantMapping;
GO

CREATE TABLE Security.UserTenantMapping (
    UserName SYSNAME NOT NULL PRIMARY KEY,
    TenantID INT NOT NULL
);
GO

CREATE INDEX IX_UserTenant_UserName
ON Security.UserTenantMapping(UserName);
GO

---------------------------------------------------------------
-- 4️ SAMPLE MAPPINGS (FOR TESTING)
---------------------------------------------------------------
INSERT INTO Security.UserRegionMapping VALUES
('NorthUser', 'North'),
('SouthUser', 'South'),
('ManagerUser', 'North'),
('ManagerUser', 'South');

INSERT INTO Security.UserTenantMapping VALUES
('TenantUser1', 1),
('TenantUser2', 2);
GO

---------------------------------------------------------------
-- 5️ ENSURE FACT TABLE HAS TENANT COLUMN
---------------------------------------------------------------
IF COL_LENGTH('dbo.FactSales', 'TenantID') IS NULL
BEGIN
    ALTER TABLE dbo.FactSales
    ADD TenantID INT NOT NULL DEFAULT 1;
END
GO

---------------------------------------------------------------
-- 6️ REGION FILTER FUNCTION
---------------------------------------------------------------
IF OBJECT_ID('Security.fn_FilterSalesByRegion') IS NOT NULL
    DROP FUNCTION Security.fn_FilterSalesByRegion;
GO

CREATE FUNCTION Security.fn_FilterSalesByRegion(@Region NVARCHAR(50))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
(
    SELECT 1 AS fn_result
    FROM Security.UserRegionMapping urm
    WHERE urm.UserName = USER_NAME()
      AND urm.Region = @Region
);
GO

---------------------------------------------------------------
-- 7️ TENANT FILTER FUNCTION
---------------------------------------------------------------
IF OBJECT_ID('Security.fn_FilterByTenant') IS NOT NULL
    DROP FUNCTION Security.fn_FilterByTenant;
GO

CREATE FUNCTION Security.fn_FilterByTenant(@TenantID INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
(
    SELECT 1 AS fn_result
    FROM Security.UserTenantMapping utm
    WHERE utm.UserName = USER_NAME()
      AND utm.TenantID = @TenantID
);
GO

---------------------------------------------------------------
-- 8️ DROP OLD POLICIES IF EXIST
---------------------------------------------------------------
IF EXISTS (SELECT * FROM sys.security_policies WHERE name = 'SalesRegionPolicy')
    DROP SECURITY POLICY Security.SalesRegionPolicy;
GO

IF EXISTS (SELECT * FROM sys.security_policies WHERE name = 'TenantIsolationPolicy')
    DROP SECURITY POLICY Security.TenantIsolationPolicy;
GO

---------------------------------------------------------------
-- 9️ CREATE SECURITY POLICIES
---------------------------------------------------------------
CREATE SECURITY POLICY Security.SalesRegionPolicy
ADD FILTER PREDICATE 
Security.fn_FilterSalesByRegion(Region)
ON dbo.FactSales
WITH (STATE = ON);
GO

CREATE SECURITY POLICY Security.TenantIsolationPolicy
ADD FILTER PREDICATE 
Security.fn_FilterByTenant(TenantID)
ON dbo.FactSales,
ADD BLOCK PREDICATE 
Security.fn_FilterByTenant(TenantID)
ON dbo.FactSales AFTER INSERT
WITH (STATE = ON);
GO

---------------------------------------------------------------
-- 10 COLUMN-LEVEL MASKING (OPTIONAL SENSITIVE COLUMN)
---------------------------------------------------------------
BEGIN TRY
    ALTER TABLE dbo.FactSales
    ALTER COLUMN SalesAmount 
    ADD MASKED WITH (FUNCTION = 'default()');
END TRY
BEGIN CATCH
    -- Ignore if already masked
END CATCH
GO

---------------------------------------------------------------
-- 11 GRANT UNMASK TO MANAGER
---------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'ManagerUser')
    CREATE USER ManagerUser WITHOUT LOGIN;
GO

GRANT UNMASK TO ManagerUser;
GO

/* ============================================================
   END OF ENTERPRISE SECURITY SCRIPT
   ============================================================ */
