"""FinOps cost, latency, and ROI ledger for tiered Gemini routing."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import MODEL_CATALOG, ModelTierSpec
from .classifier import RoutingDecision


@dataclass(frozen=True)
class QueryCostRecord:
    """Per-request FinOps accounting comparing Routed vs All-Pro baseline."""

    prompt: str
    selected_tier: str
    model_id: str
    input_tokens: int
    output_tokens: int
    routed_cost_usd: float
    all_pro_cost_usd: float
    savings_usd: float
    savings_pct: float
    estimated_latency_ms: int
    baseline_latency_ms: int


@dataclass(frozen=True)
class FinOpsSummary:
    """Aggregate FinOps performance across a batch or live session."""

    total_requests: int
    flash_requests: int
    pro_requests: int
    flash_share_pct: float
    total_input_tokens: int
    total_output_tokens: int
    total_routed_cost_usd: float
    total_all_pro_cost_usd: float
    total_savings_usd: float
    total_savings_pct: float
    avg_routed_latency_ms: float
    avg_baseline_latency_ms: float
    latency_reduction_pct: float
    projected_annual_savings_500k_monthly_usd: float


def calculate_token_cost(
    spec: ModelTierSpec, input_tokens: int, output_tokens: int
) -> float:
    """Compute USD cost given input/output token counts and model rates."""
    in_cost = (input_tokens / 1_000_000.0) * spec.input_cost_per_1m_usd
    out_cost = (output_tokens / 1_000_000.0) * spec.output_cost_per_1m_usd
    return in_cost + out_cost


def estimate_tokens(text: str) -> int:
    """Approximate token count (~1.33 tokens per word) when live API metadata is absent."""
    words = len(text.split())
    return max(16, int(round(words * 1.35)) + 120)


class FinOpsTracker:
    """Tracks routed vs baseline All-Pro token economics and latency."""

    def __init__(self, catalog: dict[str, ModelTierSpec] | None = None) -> None:
        self.catalog = catalog or MODEL_CATALOG
        self.records: list[QueryCostRecord] = field(default_factory=list) if False else []

    def record(
        self,
        decision: RoutingDecision,
        input_tokens: int,
        output_tokens: int,
    ) -> QueryCostRecord:
        routed_spec = self.catalog[decision.selected_tier]
        pro_spec = self.catalog["pro"]

        routed_cost = calculate_token_cost(routed_spec, input_tokens, output_tokens)
        all_pro_cost = calculate_token_cost(pro_spec, input_tokens, output_tokens)
        savings = max(0.0, all_pro_cost - routed_cost)
        savings_pct = (savings / all_pro_cost * 100.0) if all_pro_cost > 0 else 0.0

        rec = QueryCostRecord(
            prompt=decision.prompt,
            selected_tier=decision.selected_tier,
            model_id=routed_spec.model_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            routed_cost_usd=round(routed_cost, 6),
            all_pro_cost_usd=round(all_pro_cost, 6),
            savings_usd=round(savings, 6),
            savings_pct=round(savings_pct, 2),
            estimated_latency_ms=routed_spec.avg_latency_ms,
            baseline_latency_ms=pro_spec.avg_latency_ms,
        )
        self.records.append(rec)
        return rec

    def summarize(self) -> FinOpsSummary:
        total = len(self.records)
        if total == 0:
            return FinOpsSummary(0, 0, 0, 0.0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        flash_count = sum(1 for r in self.records if r.selected_tier == "flash")
        pro_count = total - flash_count
        total_in = sum(r.input_tokens for r in self.records)
        total_out = sum(r.output_tokens for r in self.records)
        routed_total = sum(r.routed_cost_usd for r in self.records)
        baseline_total = sum(r.all_pro_cost_usd for r in self.records)
        savings_total = max(0.0, baseline_total - routed_total)
        savings_pct = (savings_total / baseline_total * 100.0) if baseline_total > 0 else 0.0

        avg_lat = sum(r.estimated_latency_ms for r in self.records) / total
        base_lat = sum(r.baseline_latency_ms for r in self.records) / total
        lat_red = ((base_lat - avg_lat) / base_lat * 100.0) if base_lat > 0 else 0.0

        # Extrapolate to a realistic GCC enterprise volume of 500,000 queries/month (6M/year)
        avg_savings_per_query = savings_total / total
        projected_annual = avg_savings_per_query * 500_000 * 12

        return FinOpsSummary(
            total_requests=total,
            flash_requests=flash_count,
            pro_requests=pro_count,
            flash_share_pct=round(flash_count / total * 100.0, 1),
            total_input_tokens=total_in,
            total_output_tokens=total_out,
            total_routed_cost_usd=round(routed_total, 6),
            total_all_pro_cost_usd=round(baseline_total, 6),
            total_savings_usd=round(savings_total, 6),
            total_savings_pct=round(savings_pct, 2),
            avg_routed_latency_ms=round(avg_lat, 1),
            avg_baseline_latency_ms=round(base_lat, 1),
            latency_reduction_pct=round(lat_red, 1),
            projected_annual_savings_500k_monthly_usd=round(projected_annual, 2),
        )

