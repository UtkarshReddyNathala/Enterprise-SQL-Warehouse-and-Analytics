# Enterprise SQL Data Warehouse and Analytics Project

An end-to-end SQL Server Data Warehouse and Analytics platform built using Medallion Architecture, ETL pipelines, Star Schema, and advanced SQL analytics.

The project integrates data from ERP and CRM source systems, processes it through Bronze, Silver, and Gold layers, and transforms it into business-ready data for customer, product, and sales analysis.

It also includes metadata-driven ETL, ETL monitoring, data quality testing, and SQL-based reporting to demonstrate an enterprise-style data engineering workflow.

---


<img width="1772" height="1222" alt="data_architecture (5)" src="https://github.com/user-attachments/assets/84c703cf-b446-4e29-8afb-f5ef2d28bf0a" />

---

# Data Model

The Gold layer follows a **Star Schema** consisting of dimension tables and fact tables designed for reporting and analytical workloads.

![Data Model](docs/data_model.png)

---

## 🏗️ Data Architecture

The project follows a **Medallion Architecture**:

```text
Source Data
    ↓
 Bronze Layer
    ↓
 Silver Layer
    ↓
  Gold Layer
    ↓
Analytics & Reports
    ↓
ETL Monitoring
````

### 🥉 Bronze Layer

The Bronze layer stores the raw data with minimal transformation.

Files:

* `ddl_bronze.sql` – Creates Bronze layer tables
* `proc_load_bronze.sql` – Loads data into the Bronze layer

### 🥈 Silver Layer

The Silver layer cleans and transforms the raw data into a structured format.

Files:

* `ddl_silver.sql` – Creates Silver layer tables
* `proc_load_silver.sql` – Loads and transforms Silver data
* `proc_load_metadata_driven.sql` – Supports metadata-driven data loading

### 🥇 Gold Layer

The Gold layer contains business-ready data used for analytics and reporting.

Files:

* `ddl_gold.sql` – Creates Gold layer tables
* `proc_load_gold.sql` – Loads the Gold layer

---

## 📊 Analytics

The project contains a dedicated **Data Analytics** section with SQL scripts for analyzing the warehouse data.

The analytics cover areas such as:

* Database exploration
* Dimensions exploration
* Date-range analysis
* Measures and metrics
* Magnitude analysis
* Ranking analysis
* Change-over-time analysis
* Cumulative analysis
* Performance analysis
* Data segmentation
* Part-to-whole analysis
* Customer reporting
* Product reporting

---

## 📈 ETL Monitoring

The project includes an ETL monitoring component:

```text
scripts/monitoring/etl_monitoring_dashboard.sql
```

It is used to monitor ETL pipeline execution and track pipeline activity.

---

## 📂 Repository Structure

```text
Enterprise-SQL-Warehouse-and-Analytics/
│
├── docs/
│
├── scripts/
│   │
│   ├── Data Analytics/
│   │
│   ├── bronze/
│   │   ├── ddl_bronze.sql
│   │   └── proc_load_bronze.sql
│   │
│   ├── silver/
│   │   ├── ddl_silver.sql
│   │   ├── proc_load_metadata_driven.sql
│   │   └── proc_load_silver.sql
│   │
│   ├── gold/
│   │   ├── ddl_gold.sql
│   │   └── proc_load_gold.sql
│   │
│   ├── monitoring/
│   │   └── etl_monitoring_dashboard.sql
│   │
│   ├── init_database.sql
│   └── init_load_all.sql
│
├── tests/
│
├── .gitignore
└── README.md
```

---

## ⚙️ ETL Workflow

The complete ETL process follows:

```text
Initialize Database
        ↓
   Bronze Layer
        ↓
   Silver Layer
        ↓
    Gold Layer
        ↓
Data Analytics
        ↓
ETL Monitoring
```

The `init_load_all.sql` script is used to run the overall loading process.

---

## 🛠️ Technologies Used

* SQL Server
* T-SQL
* SQL Server Management Studio (SSMS)
* ETL
* Medallion Architecture
* Data Warehousing
* Star Schema
* Metadata-Driven ETL
* SQL Analytics
* ETL Monitoring

---

## 🎯 Key Concepts Demonstrated

* Data Warehouse Design
* Bronze, Silver and Gold Architecture
* ETL Pipeline Development
* Data Transformation
* Star Schema
* SQL Analytics
* Customer & Product Reporting
* ETL Monitoring
* Data Quality and Testing

---

## 🚀 How to Run

### 1. Open the project in SQL Server Management Studio

Connect to your SQL Server instance.

### 2. Initialize the database

Run:

```text
scripts/init_database.sql
```

### 3. Load the Bronze Layer

Run:

```text
scripts/bronze/ddl_bronze.sql
scripts/bronze/proc_load_bronze.sql
```

### 4. Load the Silver Layer

Run:

```text
scripts/silver/ddl_silver.sql
scripts/silver/proc_load_silver.sql
```

### 5. Load the Gold Layer

Run:

```text
scripts/gold/ddl_gold.sql
scripts/gold/proc_load_gold.sql
```

### 6. Run Analytics

Use the SQL scripts inside:

```text
scripts/Data Analytics/
```

### 7. Monitor ETL

Run:

```text
scripts/monitoring/etl_monitoring_dashboard.sql
```

---

## 👤 Author

**Utkarsh Reddy Nathala**




