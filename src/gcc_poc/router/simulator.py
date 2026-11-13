"""Enterprise GCC workload simulator for LLM Routing & FinOps benchmarking."""

from __future__ import annotations

from dataclasses import dataclass

from .classifier import PromptRouter, RoutingDecision
from .finops import FinOpsSummary, FinOpsTracker, QueryCostRecord


@dataclass(frozen=True)
class BenchmarkPrompt:
    prompt: str
    expected_tier: str
    input_tokens: int
    output_tokens: int


# 20 realistic GCC CRM/ERP queries: 85% routine retrieval (Flash), 15% complex synthesis (Pro)
BENCHMARK_WORKLOAD: tuple[BenchmarkPrompt, ...] = (
    BenchmarkPrompt("Get account summary for BharatFin Systems Ltd.", "flash", 1_650, 290),
    BenchmarkPrompt("List all open P1 support tickets in EMEA.", "flash", 1_720, 310),
    BenchmarkPrompt("Check SLA breach status for customer C-105.", "flash", 1_480, 240),
    BenchmarkPrompt("Show deals currently in Legal Review stage.", "flash", 1_640, 280),
    BenchmarkPrompt("What is the renewal date and ACV for Thames Clearing House?", "flash", 1_510, 235),
    BenchmarkPrompt("Fetch pipeline KPIs grouped by region.", "flash", 1_580, 270),
    BenchmarkPrompt("Count open support tickets for Indus Telecom Infrastructure.", "flash", 1_450, 220),
    BenchmarkPrompt("Lookup deals with discount requested above 15%.", "flash", 1_690, 290),
    BenchmarkPrompt("Retrieve the last 10 Zero-Trust MCP audit trail entries.", "flash", 1_520, 300),
    BenchmarkPrompt("Show active negotiations in India region.", "flash", 1_610, 260),
    BenchmarkPrompt("Check approval status for deal D-2003.", "flash", 1_420, 210),
    BenchmarkPrompt("List high-risk accounts across APAC and EMEA.", "flash", 1_620, 275),
    BenchmarkPrompt("Get pipeline summary by customer tier.", "flash", 1_490, 245),
    BenchmarkPrompt("Find P2 tickets opened for EuroGrid Energy GmbH.", "flash", 1_560, 265),
    BenchmarkPrompt("Display open deals for Meridian Health Partners.", "flash", 1_540, 250),
    BenchmarkPrompt("Get SLA compliance summary for Apex Semiconductor Foundry.", "flash", 1_500, 240),
    BenchmarkPrompt("List resolved P3 tickets in November.", "flash", 1_460, 225),
    BenchmarkPrompt(
        "Analyze why EMEA high-risk accounts are requesting >20% discounts and propose a margin-preserving renewal negotiation plan balancing SLA credits vs churn risk.",
        "pro",
        3_100,
        780,
    ),
    BenchmarkPrompt(
        "Correlate Q4 P1 SLA breaches with stalled Negotiation-stage deals across India and EMEA, and recommend executive remediation priorities.",
        "pro",
        3_250,
        820,
    ),
    BenchmarkPrompt(
        "Compare the risk-adjusted weighted pipeline in BFSI vs Energy and forecast Q4 closing exposure if GoldenGate CDC latency persists.",
        "pro",
        2_950,
        740,
    ),
)


@dataclass(frozen=True)
class WorkloadSimulationItem:
    expected_tier: str
    decision: RoutingDecision
    cost: QueryCostRecord
    matched_expected: bool


@dataclass(frozen=True)
class WorkloadSimulationReport:
    items: list[WorkloadSimulationItem]
    summary: FinOpsSummary
    routing_accuracy_pct: float


def run_finops_simulation(
    workload: tuple[BenchmarkPrompt, ...] = BENCHMARK_WORKLOAD,
) -> WorkloadSimulationReport:
    """Execute the full benchmark workload through PromptRouter + FinOpsTracker."""
    router = PromptRouter()
    tracker = FinOpsTracker()
    items: list[WorkloadSimulationItem] = []

    for sample in workload:
        decision = router.route(sample.prompt)
        cost = tracker.record(
            decision=decision,
            input_tokens=sample.input_tokens,
            output_tokens=sample.output_tokens,
        )
        items.append(
            WorkloadSimulationItem(
                expected_tier=sample.expected_tier,
                decision=decision,
                cost=cost,
                matched_expected=(decision.selected_tier == sample.expected_tier),
            )
        )

    matches = sum(1 for item in items if item.matched_expected)
    accuracy = round((matches / len(items) * 100.0), 1) if items else 0.0
    return WorkloadSimulationReport(
        items=items,
        summary=tracker.summarize(),
        routing_accuracy_pct=accuracy,
    )

