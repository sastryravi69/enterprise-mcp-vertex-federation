# Zero-Trust Agentic AI PoC

A three-part enterprise proof-of-concept demonstrating how Global Capability Centers (GCCs) can deploy **Agentic AI** on proprietary CRM/ERP data **without moving raw data or exposing PII to public LLMs**, while optimizing token spend by **~80%+** through tiered model routing.

---

## Overview

### 1. The "Zero-Trust" MCP Gateway (Data Privacy Flex)
- **Files:** `src/gcc_poc/crm_db.py`, `src/gcc_poc/mcp_gateway/{server.py,privacy.py,policy.py,audit.py}`, `src/gcc_poc/vertex_bridge.py`
- **Local Mock Legacy CRM (`data/legacy_crm.db`)**: SQLite database simulating an on-premises CRM (`customers`, `deals`, `support_tickets`, `audit_log`) containing sensitive PAN/Tax IDs, emails, phone numbers, internal escalation notes, and leaked secret fragments.
- **Official Python MCP Server (`mcp.server.MCPServer` over stdio)**:
  - **Least-Privilege Parameterized Tools**: `crm_get_account_summary`, `crm_search_deals`, `crm_check_sla_risks`, `crm_get_pipeline_kpis` (compute-to-data local SQL aggregation), `crm_get_audit_trail`.
  - **ABAC & Anti-Exfiltration Policy Engine**: Enforces role checks, a 15-row ceiling per call, and hard blocks raw SQL or bulk exports.
  - **In-Transit PII Tokenizer & Secret Scrubber**: Drops blocked columns (`pan_or_tax_id`, `internal_notes`), generates deterministic HMAC tokens (`[EMAIL_TOKEN_...]`, `[CONTACT_TOKEN_...]`), and scrubs inline secrets/phones/IPs/PANs inside unstructured ticket summaries.
  - **Immutable Audit Trail**: Every allowed and denied MCP call is logged to SQLite + `data/audit_trail.jsonl` with redaction counts and SHA-256 payload digests.
  - **Vertex AI <-> MCP Bridge (`vertex_bridge.py`)**: Connects over live MCP stdio `ClientSession`, translates MCP schemas to Gemini `FunctionDeclaration`s, and supports both **Live Vertex AI** (via `google-genai` + GCP ADC) and **Zero-Credential Local Sandbox Mode**.

### 2. The LLM Routing & FinOps Simulator (Cost Flex)
- **Files:** `src/gcc_poc/router/{classifier.py,finops.py,simulator.py}`
- **Pre-Inference Complexity Router (`PromptRouter`)**: Intercepts prompts in `<2ms` at `$0` external LLM cost:
  - Simple data retrieval / KPI / lookup queries -> **Gemini 1.5 Flash** (`$0.075 / 1M` input tokens, `~420ms`)
  - Multi-hop root-cause, margin vs churn trade-off, and strategic synthesis -> **Gemini 1.5 Pro** (`$1.25 / 1M` input tokens, `~1850ms`)
- **20-Prompt Enterprise FinOps Simulator**: Benchmarks a realistic 85% Flash / 15% Pro GCC query distribution and calculates per-query savings (66.0% blended / 94.0% on Flash tier), latency reduction (65.7% faster), and projected annual run-rate savings at `500,000 queries/month`.

### 3. The Hybrid Edge-to-Cloud Blueprint (Architecture Flex)
- **Files:** [`architecture/hybrid_edge_to_cloud_blueprint.drawio`](architecture/hybrid_edge_to_cloud_blueprint.drawio), [`architecture/hybrid_edge_to_cloud_blueprint.svg`](architecture/hybrid_edge_to_cloud_blueprint.svg), [`architecture/ARCHITECTURE_NOTES.md`](architecture/ARCHITECTURE_NOTES.md), [`scripts/generate_blueprint.py`](scripts/generate_blueprint.py)
- Native **Draw.io XML** diagram mapping:
  1. **Zone 1 (On-Prem GCC Enclave)**: Oracle DB + Legacy CRM + Azure Arc/SHIR + Zero-Trust MCP Gateway.
  2. **Zone 2 (Azure Databricks Zero-Copy Layer)**: ExpressRoute/Private Link -> ADLS Gen2 Medallion -> Unity Catalog (Lakehouse Federation, RLS/Masking, **Delta Sharing / Iceberg Uniform** Zero-Copy).
  3. **Zone 3 (GCP Vertex AI & FinOps)**: VPC-SC + Private Service Connect (ZDR) -> Python LLM Router -> Gemini 1.5 Flash & Pro + Vertex AI MCP Bridge.
  4. **Zone 4 (Salesforce Agentforce)**: Data Cloud Zero-Copy Federation + Einstein Trust Layer + Agentforce Atlas Reasoning via Private Connect.

---

## Quickstart

Run directly via `.venv\Scripts\` (works on PowerShell even when `.ps1` script execution is disabled):

```powershell
# 1. Run the full interactive PoC demo (MCP stdio + Privacy checks + FinOps Simulator)
.\.venv\Scripts\gcc-poc.exe demo

# 2. Route a single prompt
.\.venv\Scripts\gcc-poc.exe route "Analyze why EMEA high-risk accounts are demanding >20% discounts and propose a renewal plan."

# 3. Ask a question end-to-end through Router -> Vertex Bridge -> Zero-Trust MCP Server
.\.venv\Scripts\gcc-poc.exe ask "List all open P1 support tickets in EMEA."

# 4. Run the 20-prompt FinOps workload simulation
.\.venv\Scripts\gcc-poc.exe finops-sim

# 5. Regenerate and validate the Draw.io + SVG blueprint
.\.venv\Scripts\python.exe scripts/generate_blueprint.py

# 6. Run the automated test suite
.\.venv\Scripts\pytest.exe -v
```

*(Optional: if you prefer activating the venv in PowerShell first, use `.\.venv\Scripts\activate.bat` in Command Prompt, or enable local PowerShell scripts via `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`.)*

## Enabling Live Google Cloud Vertex AI (Optional)
Copy `.env.example` to `.env`, set `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, and authenticate via Application Default Credentials (`gcloud auth application-default login`). Without cloud credentials, the PoC defaults cleanly to `local_mcp_sandbox` while still executing the real MCP stdio server and privacy boundary checks.

