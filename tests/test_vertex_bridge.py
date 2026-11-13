"""End-to-end tests for the Vertex AI <-> Zero-Trust MCP bridge + FinOps router."""

from __future__ import annotations

from pathlib import Path

import pytest

from gcc_poc.config import VertexConfig
from gcc_poc.crm_db import init_database
from gcc_poc.router.finops import FinOpsTracker
from gcc_poc.vertex_bridge import run_routed_mcp_query


@pytest.mark.asyncio
async def test_routed_mcp_queries_flash_and_pro_end_to_end(tmp_path: Path) -> None:
    db_path = tmp_path / "bridge_e2e.db"
    init_database(db_path, reset=True)

    cfg = VertexConfig(llm_mode="local_sim")
    tracker = FinOpsTracker()

    res_flash = await run_routed_mcp_query(
        "List all open P1 support tickets in EMEA.",
        db_path=db_path,
        vertex_config=cfg,
        tracker=tracker,
    )
    assert res_flash.routing.selected_tier == "flash"
    assert res_flash.engine_mode == "local_mcp_sandbox"
    assert res_flash.total_pii_redactions >= 1
    assert "l.weber@eurogrid.de" not in res_flash.answer
    assert "+49-171-8834201" not in res_flash.answer
    assert res_flash.finops.savings_pct > 90.0

    res_pro = await run_routed_mcp_query(
        "Analyze why EMEA high-risk accounts are requesting >20% discounts and propose a margin-preserving renewal strategy balancing SLA credits vs churn risk.",
        db_path=db_path,
        vertex_config=cfg,
        tracker=tracker,
    )
    assert res_pro.routing.selected_tier == "pro"
    assert len(res_pro.tool_calls_executed) >= 2
    assert "Executive Multi-Hop Synthesis" in res_pro.answer
    assert tracker.summarize().total_requests == 2

