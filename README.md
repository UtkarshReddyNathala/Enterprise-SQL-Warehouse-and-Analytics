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
# Enterprise SQL Warehouse and Analytics 🚀

An end-to-end **SQL Server Data Warehouse and Analytics platform** built using **Medallion Architecture**, **ETL pipelines**, **Star Schema**, and advanced SQL analytics.

The project integrates data from ERP and CRM source systems, processes it through **Bronze, Silver, and Gold layers**, and transforms it into business-ready data for customer, product, and sales analysis.

It also includes **metadata-driven ETL, ETL monitoring, data quality testing, and SQL-based reporting** to demonstrate an enterprise-style data engineering workflow.

---

## 🏗️ Data Architecture

The project follows the **Medallion Architecture**:

```text
                 ERP / CRM CSV Files
                         │
                         ▼
                  ┌─────────────┐
                  │   BRONZE    │
                  │  Raw Data   │
                  └──────┬──────┘
                         │
                         ▼
                  ┌─────────────┐
                  │   SILVER    │
                  │ Cleaned &   │
                  │ Transformed │
                  └──────┬──────┘
                         │
                         ▼
                  ┌─────────────┐
                  │    GOLD     │
                  │ Star Schema │
                  └──────┬──────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
       SQL Analytics          ETL Monitoring
       & Reporting            & Data Quality
```

### 🥉 Bronze Layer

Stores raw source data with minimal transformation.

* Loads ERP and CRM data
* Preserves source information
* Provides the initial staging layer
* Handles raw data ingestion

### 🥈 Silver Layer

Cleans, standardizes, and transforms the Bronze data.

* Data cleansing
* Data type standardization
* Duplicate handling
* Data validation
* ERP and CRM integration
* Metadata-driven processing

### 🥇 Gold Layer

Contains business-ready analytical data.

* Fact tables
* Dimension tables
* Star Schema
* Business-ready datasets
* Optimized analytical models

---

## 📊 Data Warehouse Workflow

```text
ERP CSV ──────┐
              │
              ├──► Bronze
              │      │
CRM CSV ──────┘      ▼
                  Silver
                    │
                    ▼
                   Gold
                    │
                    ▼
              Star Schema
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
   SQL Analytics       Business Reports
          │
          ▼
    Customer / Product
    / Sales Insights
```

---

## 📖 Project Overview

The project implements a complete data warehouse workflow:

1. **Source Data Ingestion**

   * ERP and CRM data is provided through CSV files.

2. **Bronze Layer**

   * Raw data is loaded into SQL Server.

3. **Silver Layer**

   * Raw data is cleaned, standardized, validated, and integrated.

4. **Gold Layer**

   * Clean data is transformed into business-ready fact and dimension tables.

5. **Data Modeling**

   * A Star Schema is created for analytical queries.

6. **SQL Analytics**

   * Customer, product, sales, trend, ranking, and performance analysis is performed.

7. **ETL Monitoring**

   * Pipeline execution and ETL activity are monitored.

8. **Testing**

   * Data quality and validation checks are performed.

---

## 🛠️ Technologies Used

* **SQL Server**
* **T-SQL**
* **SQL Server Management Studio (SSMS)**
* **Medallion Architecture**
* **ETL / ELT**
* **Metadata-Driven ETL**
* **Star Schema**
* **Data Modeling**
* **Data Quality**
* **ETL Monitoring**
* **SQL Analytics**
* **Git & GitHub**

---

## 📂 Repository Structure

```text
Enterprise-SQL-Warehouse-and-Analytics/
│
├── docs/
│   └── Project documentation and architecture diagrams
│
├── scripts/
│   │
│   ├── Data Analytics/
│   │   ├── 00_init_database.sql
│   │   ├── 01_database_exploration.sql
│   │   ├── 02_dimensions_exploration.sql
│   │   ├── 03_date_range_exploration.sql
│   │   ├── 04_measures_exploration.sql
│   │   ├── 05_magnitude_analysis.sql
│   │   ├── 06_ranking_analysis.sql
│   │   ├── 07_change_over_time_analysis.sql
│   │   ├── 08_cumulative_analysis.sql
│   │   ├── 09_performance_analysis.sql
│   │   ├── 10_data_segmentation.sql
│   │   ├── 11_part_to_whole_analysis.sql
│   │   ├── 12_report_customers.sql
│   │   └── 13_report_products.sql
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
│   └── Data quality and validation tests
│
├── .gitignore
└── README.md
```

---

# 🔄 ETL Pipeline

The ETL process is divided into three major layers.

### 1. Bronze Loading

Scripts:

```text
scripts/bronze/ddl_bronze.sql
scripts/bronze/proc_load_bronze.sql
```

The Bronze layer creates the raw staging tables and loads the source data.

### 2. Silver Transformation

Scripts:

```text
scripts/silver/ddl_silver.sql
scripts/silver/proc_load_silver.sql
scripts/silver/proc_load_metadata_driven.sql
```

The Silver layer performs data cleaning, transformation, standardization, and integration.

The **metadata-driven procedure** helps make the loading process reusable instead of creating completely separate logic for every dataset.

### 3. Gold Loading

Scripts:

```text
scripts/gold/ddl_gold.sql
scripts/gold/proc_load_gold.sql
```

The Gold layer creates the analytical model and loads business-ready data.

---

# ⚙️ Initialization

The project contains database initialization scripts:

```text
scripts/init_database.sql
scripts/init_load_all.sql
```

`init_database.sql` initializes the required database objects.

`init_load_all.sql` can be used to execute the overall loading workflow across the warehouse layers.

---

# ⭐ Data Modeling

The Gold layer uses a **Star Schema**.

```text
                 Dim Customer
                      │
                      │
Dim Product ───── Fact Sales ───── Dim Date
                      │
                      │
                 Other Dimensions
```

### Fact Tables

Store measurable business events such as:

* Sales
* Revenue
* Quantity
* Orders

### Dimension Tables

Provide descriptive information such as:

* Customers
* Products
* Dates
* Other business entities

The Star Schema makes analytical queries easier and more efficient.

---

# 📈 SQL Analytics

The `Data Analytics` directory contains SQL scripts covering different analytical techniques.

### Database Exploration

Explores:

* Database structure
* Tables
* Dimensions
* Available data

### Measures & Metrics

Analyzes:

* Sales
* Revenue
* Quantity
* Orders
* Business metrics

### Time-Based Analysis

Analyzes:

* Sales over time
* Monthly trends
* Yearly trends
* Changes over time

### Ranking Analysis

Identifies:

* Top customers
* Top products
* Highest-performing entities

### Cumulative Analysis

Calculates:

* Running totals
* Cumulative sales
* Cumulative revenue

### Performance Analysis

Evaluates:

* Customer performance
* Product performance
* Sales performance

### Segmentation

Groups customers or products based on business characteristics and performance.

### Part-to-Whole Analysis

Determines how individual customers, products, or categories contribute to overall business results.

---

# 👥 Customer Reporting

The customer analytics report is generated using:

```text
scripts/Data Analytics/12_report_customers.sql
```

It provides insights into:

* Customer purchasing behavior
* Customer revenue
* Customer performance
* Customer contribution to sales

---

# 📦 Product Reporting

The product analytics report is generated using:

```text
scripts/Data Analytics/13_report_products.sql
```

It provides insights into:

* Product sales
* Product revenue
* Product performance
* Top-performing products
* Product contribution to total sales

---

# 📊 ETL Monitoring

The project includes an ETL monitoring component:

```text
scripts/monitoring/etl_monitoring_dashboard.sql
```

It can be used to monitor:

* ETL execution
* Pipeline status
* Successful runs
* Failed runs
* Execution information
* Processing activity

This helps identify pipeline failures and monitor the health of the data warehouse.

---

# 🧪 Data Quality & Testing

The `tests/` directory contains validation and data quality scripts.

Typical checks include:

* Missing values
* Duplicate records
* Invalid values
* Data type validation
* Referential integrity
* Source-to-target validation

These checks help ensure that only reliable data reaches the analytical layer.

---

# 🎯 Project Objectives

The main objectives of this project are to:

* Build a centralized SQL Server Data Warehouse
* Integrate ERP and CRM source data
* Implement Bronze, Silver, and Gold layers
* Build reusable ETL procedures
* Implement metadata-driven processing
* Clean and standardize source data
* Create a Star Schema
* Perform advanced SQL analytics
* Generate customer and product reports
* Monitor ETL pipeline execution
* Implement data quality validation

---

# 🚀 How to Run

### 1. Install SQL Server

Install:

* SQL Server
* SQL Server Management Studio (SSMS)

### 2. Clone the Repository

```bash
git clone https://github.com/UtkarshReddyNathala/Enterprise-SQL-Warehouse-and-Analytics.git
```

### 3. Open SQL Server Management Studio

Connect to your SQL Server instance.

### 4. Initialize the Database

Run:

```text
scripts/init_database.sql
```

### 5. Create Bronze Layer

Run:

```text
scripts/bronze/ddl_bronze.sql
```

Then load the raw data using:

```text
scripts/bronze/proc_load_bronze.sql
```

### 6. Create and Load Silver Layer

Run:

```text
scripts/silver/ddl_silver.sql
scripts/silver/proc_load_silver.sql
```

The metadata-driven procedure can also be used:

```text
scripts/silver/proc_load_metadata_driven.sql
```

### 7. Create and Load Gold Layer

Run:

```text
scripts/gold/ddl_gold.sql
scripts/gold/proc_load_gold.sql
```

### 8. Run Analytics

Execute the required scripts inside:

```text
scripts/Data Analytics/
```

### 9. Monitor ETL

Run:

```text
scripts/monitoring/etl_monitoring_dashboard.sql
```

### Alternative

The complete loading workflow can be executed using:

```text
scripts/init_load_all.sql
```

---

# 📚 Skills Demonstrated

This project demonstrates practical experience in:

* SQL Development
* T-SQL
* Data Engineering
* Data Warehousing
* ETL Pipelines
* Metadata-Driven ETL
* Medallion Architecture
* Star Schema
* Data Modeling
* Data Quality
* SQL Analytics
* ETL Monitoring
* Business Intelligence
* Analytical Reporting

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## 👤 Author

**Utkarsh Reddy Nathala**

GitHub: [UtkarshReddyNathala](https://github.com/UtkarshReddyNathala)

Project: [Enterprise-SQL-Warehouse-and-Analytics](https://github.com/UtkarshReddyNathala/Enterprise-SQL-Warehouse-and-Analytics)
