"""Tests for the LLM Prompt Router and FinOps Simulator."""

from __future__ import annotations

from gcc_poc.router.classifier import PromptRouter
from gcc_poc.router.simulator import run_finops_simulation


def test_simple_queries_route_to_flash() -> None:
    router = PromptRouter()
    simple_prompts = [
        "Get account summary for BharatFin Systems Ltd.",
        "List all open P1 support tickets in EMEA.",
        "What is the renewal date for C-107?",
        "Fetch pipeline KPIs grouped by region.",
    ]
    for p in simple_prompts:
        dec = router.route(p)
        assert dec.selected_tier == "flash", f"Expected flash for: {p} (got {dec})"
        assert "flash" in dec.model_id


def test_complex_queries_route_to_pro() -> None:
    router = PromptRouter()
    complex_prompts = [
        "Analyze why EMEA high-risk accounts are requesting >20% discounts and propose a margin-preserving renewal strategy.",
        "Correlate Q4 SLA breaches with stalled negotiations and recommend executive remediation priorities.",
        "Compare risk-adjusted BFSI vs Energy pipeline and forecast Q4 exposure.",
    ]
    for p in complex_prompts:
        dec = router.route(p)
        assert dec.selected_tier == "pro", f"Expected pro for: {p} (got {dec})"
        assert "pro" in dec.model_id


def test_finops_simulation_delivers_high_savings_and_accuracy() -> None:
    report = run_finops_simulation()
    assert report.routing_accuracy_pct >= 95.0
    assert report.summary.total_requests == 20
    assert report.summary.flash_requests == 17
    assert report.summary.pro_requests == 3
    assert report.summary.total_savings_pct >= 65.0
    assert report.summary.total_routed_cost_usd < report.summary.total_all_pro_cost_usd
    assert report.summary.avg_routed_latency_ms < report.summary.avg_baseline_latency_ms

