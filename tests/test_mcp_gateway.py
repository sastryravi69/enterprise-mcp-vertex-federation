"""End-to-end tests over real MCP stdio ClientSession <-> MCPServer subprocess."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from gcc_poc.crm_db import init_database


@pytest.mark.asyncio
async def test_real_mcp_stdio_protocol_and_privacy(tmp_path: Path) -> None:
    db_path = tmp_path / "mcp_e2e.db"
    init_database(db_path, reset=True)

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gcc_poc.mcp_gateway.server", str(db_path)],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools_res = await session.list_tools()
            tool_names = {t.name for t in tools_res.tools}
            assert {
                "crm_get_account_summary",
                "crm_search_deals",
                "crm_check_sla_risks",
                "crm_get_pipeline_kpis",
                "crm_get_audit_trail",
            }.issubset(tool_names)

            policy_res = await session.read_resource("crm://policy/zero-trust")
            policy_text = "".join(getattr(c, "text", "") for c in policy_res.contents)
            assert "ON_PREM_GCC_ENCLAVE" in policy_text

            kpi_res = await session.call_tool("crm_get_pipeline_kpis", arguments={"group_by": "region"})
            kpi_text = "".join(getattr(c, "text", "") for c in kpi_res.content)
            kpi_data = json.loads(kpi_text)
            assert kpi_data["zero_trust_enforced"] is True
            assert kpi_data["rows_returned"] >= 3

            acct_res = await session.call_tool(
                "crm_get_account_summary", arguments={"customer_query": "EuroGrid"}
            )
            acct_text = "".join(getattr(c, "text", "") for c in acct_res.content)
            assert "DE-298471022" not in acct_text
            assert "l.weber@eurogrid.de" not in acct_text
            assert "[EMAIL_TOKEN_" in acct_text

