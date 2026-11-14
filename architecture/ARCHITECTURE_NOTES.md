# Hybrid Edge-to-Cloud Architecture Notes

This document accompanies [`hybrid_edge_to_cloud_blueprint.drawio`](./hybrid_edge_to_cloud_blueprint.drawio), [`hybrid_edge_to_cloud_blueprint.svg`](./hybrid_edge_to_cloud_blueprint.svg), and [`hybrid_edge_to_cloud_blueprint.png`](./hybrid_edge_to_cloud_blueprint.png) ([High-Res version](./hybrid_edge_to_cloud_blueprint_highres.png)).

## Design Principles for GCC Adoption

1. **Zero Data Movement for Operational PII (`Zone 1` -> `Zone 3`)**
   - Legacy systems (`Oracle DB 19c/23ai` and the local PoC `Legacy On-Prem CRM`) remain inside the GCC Sovereign Enclave.
   - The **Zero-Trust MCP Gateway** computes KPI aggregations locally (compute-to-data), enforces an anti-exfiltration 15-row cap, strips blocked columns (`pan_or_tax_id`, `internal_notes`), tokenizes identities (`[EMAIL_TOKEN_x]`), and records an immutable SHA-256 audit log before returning payloads to Vertex AI over private mTLS.

2. **Zero-Copy Analytical Layer (`Zone 2`: Azure Databricks)**
   - **Lakehouse Federation** queries Oracle schemas without duplicating raw transactional databases.
   - **Unity Catalog** enforces Row-Level Security (RLS) and dynamic column masking across Bronze -> Silver -> Gold Medallion views stored on CMEK-encrypted ADLS Gen2.
   - **Delta Sharing & Iceberg Uniform** expose Gold views directly to GCP (Vertex AI / BigQuery Omni) and Salesforce Data Cloud via signed short-lived access grants—eliminating shadow ETL copies.

3. **FinOps-Driven Tiered Inference (`Zone 3`: GCP Vertex AI)**
   - Protected by **VPC Service Controls (VPC-SC)**, **Private Service Connect**, and **Zero Data Retention (ZDR)**.
   - The Python **LLM Router** intercepts incoming prompts in `<2ms` at `$0` external LLM cost:
     - **85% Simple Retrieval / Status Checks** -> **Gemini 1.5 Flash** (`$0.075 / 1M` input tokens)
     - **15% Multi-Hop Root Cause / Strategy** -> **Gemini 1.5 Pro** (`$1.25 / 1M` input tokens)

4. **Enterprise SaaS Grounding (`Zone 4`: Salesforce Agentforce)**
   - **Salesforce Data Cloud Zero-Copy Federation** reads Databricks Unity Catalog Gold views without ingesting copies into Salesforce storage.
   - **Einstein Trust Layer** adds dynamic grounding and PII/toxicity checks, invoking Vertex AI and Edge MCP Actions securely via **Salesforce Private Connect** + Named Credentials (OAuth 2.0 JWT Bearer / mTLS).

