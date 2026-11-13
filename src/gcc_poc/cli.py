"""Unified CLI for the Zero-Trust GCC AI PoC."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import DEFAULT_DB_PATH
from .crm_db import init_database
from .mcp_gateway.policy import PolicyViolationError
from .mcp_gateway.server import CrmGatewayService, main as run_mcp_stdio
from .router.classifier import PromptRouter
from .router.simulator import run_finops_simulation
from .vertex_bridge import run_routed_mcp_query

console = Console()


def cmd_demo(db_path: Path) -> None:
    init_database(db_path, reset=True)
    console.print(
        Panel.fit(
            "[bold cyan]GCC Agentic AI PoC: Zero-Trust MCP Gateway + FinOps Router[/bold cyan]\n"
            "Demonstrating live MCP stdio protocol, PII tokenization, anti-exfiltration policy,\n"
            "and Gemini 1.5 Flash vs Pro cost-optimized routing.",
            border_style="cyan",
        )
    )

    prompts = [
        "Get account summary for BharatFin Systems Ltd.",
        "List all open P1 support tickets in EMEA.",
        "Analyze why EMEA high-risk accounts are requesting >20% discounts and propose a margin-preserving renewal negotiation plan balancing SLA credits vs churn risk.",
    ]

    async def _run_all() -> None:
        for idx, prompt in enumerate(prompts, start=1):
            res = await run_routed_mcp_query(prompt, db_path=db_path)
            console.print(f"\n[bold yellow]Query {idx}:[/bold yellow] {prompt}")
            console.print(
                f"  [green]Router ->[/green] {res.routing.display_name} ({res.routing.model_id}) | "
                f"score={res.routing.complexity_score} | engine={res.engine_mode}"
            )
            console.print(
                f"  [magenta]Zero-Trust MCP ->[/magenta] tools={[c['tool'] for c in res.tool_calls_executed]} | "
                f"PII redactions={res.total_pii_redactions} | "
                f"Cost=${res.finops.routed_cost_usd:.6f} (vs Pro ${res.finops.all_pro_cost_usd:.6f}, saved {res.finops.savings_pct}%)"
            )
            console.print(Panel(res.answer, border_style="green"))

    asyncio.run(_run_all())

    # Demonstrate Zero-Trust Policy Deny (Anti-Exfiltration & Raw SQL Block)
    svc = CrmGatewayService(db_path=db_path)
    console.print("\n[bold red]Zero-Trust Boundary Penetration Checks:[/bold red]")
    for label, fn in (
        ("Bulk Exfiltration (limit=500)", lambda: svc.search_deals(limit=500)),
        ("Forbidden Raw SQL Tool", lambda: svc.policy.authorize_tool("crm_raw_sql_query")),
        ("Untrusted Role", lambda: svc.get_account_summary("C-101", caller_role="public_llm")),
    ):
        try:
            fn()
        except PolicyViolationError as exc:
            console.print(f"  [green]BLOCKED ({label}):[/green] {exc}")

    # Run 20-prompt FinOps Simulator
    cmd_finops_sim()


def cmd_route(prompt: str) -> None:
    decision = PromptRouter().route(prompt)
    console.print_json(json.dumps(decision.__dict__, indent=2))


def cmd_finops_sim(as_json: bool = False) -> None:
    report = run_finops_simulation()
    if as_json:
        payload = {
            "routing_accuracy_pct": report.routing_accuracy_pct,
            "summary": report.summary.__dict__,
            "items": [
                {
                    "prompt": i.decision.prompt,
                    "expected_tier": i.expected_tier,
                    "routed_tier": i.decision.selected_tier,
                    "model_id": i.decision.model_id,
                    "score": i.decision.complexity_score,
                    "routed_cost_usd": i.cost.routed_cost_usd,
                    "all_pro_cost_usd": i.cost.all_pro_cost_usd,
                    "savings_pct": i.cost.savings_pct,
                }
                for i in report.items
            ],
        }
        print(json.dumps(payload, indent=2))
        return

    table = Table(title="LLM Routing & FinOps Workload Simulator (20 Enterprise Queries)")
    table.add_column("#", style="dim", width=3)
    table.add_column("Prompt", overflow="fold", max_width=52)
    table.add_column("Tier", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Routed ($)", justify="right", style="green")
    table.add_column("All-Pro ($)", justify="right", style="red")
    table.add_column("Saved", justify="right", style="bold green")

    for idx, item in enumerate(report.items, start=1):
        tier_label = "Flash" if item.decision.selected_tier == "flash" else "[bold yellow]Pro[/bold yellow]"
        table.add_row(
            str(idx),
            item.decision.prompt,
            tier_label,
            f"{item.decision.complexity_score:.2f}",
            f"${item.cost.routed_cost_usd:.5f}",
            f"${item.cost.all_pro_cost_usd:.5f}",
            f"{item.cost.savings_pct:.1f}%",
        )

    console.print(table)
    s = report.summary
    console.print(
        Panel.fit(
            f"[bold]Routing Accuracy vs Benchmark:[/bold] {report.routing_accuracy_pct}% ({s.flash_requests} Flash / {s.pro_requests} Pro)\n"
            f"[bold]Batch Cost (Routed vs All-Pro):[/bold] ${s.total_routed_cost_usd:.5f} vs ${s.total_all_pro_cost_usd:.5f} "
            f"([bold green]{s.total_savings_pct}% Cost Reduction[/bold green])\n"
            f"[bold]Avg Latency:[/bold] {s.avg_routed_latency_ms} ms vs {s.avg_baseline_latency_ms} ms "
            f"([bold cyan]{s.latency_reduction_pct}% Faster[/bold cyan])\n"
            f"[bold]Projected Annual Enterprise Savings (@ 500k queries/mo):[/bold] "
            f"[bold green]${s.projected_annual_savings_500k_monthly_usd:,.2f} / year[/bold green]",
            title="FinOps Executive Summary",
            border_style="green",
        )
    )


def cmd_audit(db_path: Path, limit: int = 10) -> None:
    svc = CrmGatewayService(db_path=db_path)
    res = svc.get_audit_trail(limit=limit, caller_role="security_auditor")
    console.print_json(json.dumps(res, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Zero-Trust GCC Agentic AI PoC CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_demo = sub.add_parser("demo", help="Run full end-to-end Zero-Trust MCP + Router + FinOps demo")
    p_demo.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)

    sub.add_parser("mcp-server", help="Start the Zero-Trust MCP stdio server")

    p_route = sub.add_parser("route", help="Classify and route a single prompt")
    p_route.add_argument("prompt", type=str)

    p_query = sub.add_parser("ask", help="Run a prompt through Router -> Vertex Bridge -> MCP Server")
    p_query.add_argument("prompt", type=str)
    p_query.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)

    p_sim = sub.add_parser("finops-sim", help="Run the 20-prompt FinOps workload simulation")
    p_sim.add_argument("--json", action="store_true")

    p_audit = sub.add_parser("audit", help="Display recent Zero-Trust MCP audit logs")
    p_audit.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    p_audit.add_argument("--limit", type=int, default=10)

    args = parser.parse_args()
    if args.command == "demo":
        cmd_demo(args.db)
    elif args.command == "mcp-server":
        run_mcp_stdio()
    elif args.command == "route":
        cmd_route(args.prompt)
    elif args.command == "ask":
        init_database(args.db)
        res = asyncio.run(run_routed_mcp_query(args.prompt, db_path=args.db))
        console.print(Panel(res.answer, title=f"{res.routing.display_name} | {res.engine_mode}", border_style="cyan"))
        console.print(f"FinOps: ${res.finops.routed_cost_usd:.6f} (saved {res.finops.savings_pct}%), Redactions: {res.total_pii_redactions}")
    elif args.command == "finops-sim":
        cmd_finops_sim(as_json=args.json)
    elif args.command == "audit":
        cmd_audit(args.db, limit=args.limit)


if __name__ == "__main__":
    main()

