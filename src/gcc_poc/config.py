"""Configuration, Zero-Trust defaults, and Vertex AI FinOps pricing tables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_DB_PATH = DATA_DIR / "legacy_crm.db"
DEFAULT_AUDIT_LOG_PATH = DATA_DIR / "audit_trail.jsonl"

load_dotenv(PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class ModelTierSpec:
    """Metadata and FinOps pricing spec for a Vertex AI Gemini tier."""

    tier: str
    model_id: str
    display_name: str
    input_cost_per_1m_usd: float
    output_cost_per_1m_usd: float
    avg_latency_ms: int
    context_window_tokens: int
    intended_workload: str


# Reference pricing modeled on Gemini 1.5 Flash vs Gemini 1.5 Pro (<=128k prompt tier)
MODEL_CATALOG: dict[str, ModelTierSpec] = {
    "flash": ModelTierSpec(
        tier="flash",
        model_id=os.getenv("GCC_POC_FAST_MODEL", "gemini-1.5-flash"),
        display_name="Gemini 1.5 Flash",
        input_cost_per_1m_usd=0.075,
        output_cost_per_1m_usd=0.30,
        avg_latency_ms=420,
        context_window_tokens=1_000_000,
        intended_workload="Simple retrieval, entity lookups, counts, status checks, structured summaries",
    ),
    "pro": ModelTierSpec(
        tier="pro",
        model_id=os.getenv("GCC_POC_PRO_MODEL", "gemini-1.5-pro"),
        display_name="Gemini 1.5 Pro",
        input_cost_per_1m_usd=1.25,
        output_cost_per_1m_usd=5.00,
        avg_latency_ms=1_850,
        context_window_tokens=2_000_000,
        intended_workload="Multi-hop root-cause analysis, margin/risk trade-offs, forecasting, strategic synthesis",
    ),
}


@dataclass(frozen=True)
class ZeroTrustConfig:
    """Zero-Trust enforcement parameters for the MCP Gateway."""

    strict_pii_masking: bool = os.getenv("GCC_POC_STRICT_PII_MASKING", "true").lower() == "true"
    max_rows_per_call: int = int(os.getenv("GCC_POC_MAX_ROWS_PER_CALL", "15"))
    default_caller_role: str = os.getenv("GCC_POC_CALLER_ROLE", "vertex_agent")
    allow_bulk_export: bool = False
    allow_raw_sql: bool = False
    data_residency_zone: str = "ON_PREM_GCC_ENCLAVE"
    allowed_roles: tuple[str, ...] = ("vertex_agent", "agentforce_bridge", "security_auditor")
    blocked_columns: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"pan_or_tax_id", "internal_notes", "raw_ssn", "bank_routing_number"}
        )
    )


@dataclass(frozen=True)
class VertexConfig:
    """Vertex AI / Gemini connection mode."""

    llm_mode: str = os.getenv("GCC_POC_LLM_MODE", "auto").lower()
    gcp_project: str = os.getenv("GOOGLE_CLOUD_PROJECT", "")
    gcp_location: str = os.getenv("GOOGLE_CLOUD_LOCATION", "asia-south1")
    use_vertexai: bool = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "true").lower() == "true"
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")

    @property
    def has_live_credentials(self) -> bool:
        if self.llm_mode == "local_sim":
            return False
        if self.use_vertexai and self.gcp_project:
            return True
        if self.gemini_api_key:
            return True
        return False

